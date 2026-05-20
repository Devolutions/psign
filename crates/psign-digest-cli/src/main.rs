// Cross-platform helper over `psign_sip_digest` — no WinVerifyTrust.
//
// Use this on Linux/macOS to compute PE image digests or to check PKCS#7 indirect-data consistency
// for formats implemented in `psign-sip-digest`. This does not replace full `psign` verify.

use anyhow::{Context, Result, anyhow};
#[cfg(feature = "azure-kv-sign-portable")]
use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};
use psign_authenticode_trust::{
    AuthenticodeTrustPolicy, TrustVerifyPeOptions, TrustVerifyPeReport,
    inspect_authenticode_pkcs7_der, inspect_pe_authenticode, parse_verification_date_ymd,
    policy::{OnlineTrustOptions, RevocationMode},
    trust_verify_cab_bytes, trust_verify_catalog_bytes, trust_verify_detached_bytes,
    trust_verify_msi_bytes, trust_verify_pe_bytes, trust_verify_wim_esd_path,
};
#[cfg(feature = "azure-kv-sign-portable")]
use psign_azure_kv_rest::{
    KvAuthParams, KvHashAlg, acquire_kv_access_token, fetch_kv_certificate,
    kv_sign_digest_from_certificate,
};
#[cfg(feature = "artifact-signing-rest")]
use psign_codesigning_rest::{
    CodesigningAuth, CodesigningSubmitParams, submit_codesign_hash_blocking,
};
use psign_opc_sign::{nuget, vsix};
use psign_sip_digest::cab_digest::{self,
    cab_rsa_sha256_signer_prehash_digest, cab_signature_pkcs7_der, compute_cab_authenticode_digest,
    parse_cab_context, verify_cab_digest_consistency,
};
use psign_sip_digest::catalog_digest;
use psign_sip_digest::esd_digest;
use psign_sip_digest::msi_digest;
use psign_sip_digest::msix_digest;
use psign_sip_digest::page_hashes::{self, PageHashAttrKind};
use psign_sip_digest::pe_digest::{
    PeAuthenticodeHashKind, pe_authenticode_digest, pe_authenticode_digest_file_ranges,
};
use psign_sip_digest::pe_embed;
use psign_sip_digest::pkcs7;
use psign_sip_digest::pkcs7_wire;
use psign_sip_digest::rdp;
use psign_sip_digest::timestamp::{
    Rfc3161PkiStatus, Rfc3161TimestampRequestPlan, build_timestamp_request_bytes,
    parse_time_stamp_resp_der, parse_time_stamp_token_tst_info,
    pkifailure_info_flag_labels_from_bit_string_tlv,
};
use psign_sip_digest::verify_pe;
use psign_sip_digest::verify_script_digest_consistency;
use serde::Deserialize;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "psign-tool")]
#[command(version, about = "Portable Authenticode SIP digest utilities (no Windows CryptoAPI)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone, Debug)]
struct TrustVerifySharedArgs {
    #[arg(long, value_name = "DIR")]
    anchor_dir: Option<PathBuf>,
    /// Trust this CA certificate file as an anchor (repeatable, PEM or DER).
    #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
    trusted_ca: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    authroot_cab: Option<PathBuf>,
    /// Require **`--authroot-cab`** file SHA-256 (64 lowercase hex chars) to match before ingest.
    #[arg(long, value_name = "HEX64")]
    expect_authroot_cab_sha256: Option<String>,
    #[arg(long)]
    verbose_chain: bool,
    /// Skip picky’s strict **code signing** checks on the signing certificate (`ignore_signing_certificate_check`).
    #[arg(long)]
    allow_loose_signing_cert: bool,
    /// Prefer nested RFC3161 **`TSTInfo.genTime`** (unsigned attrs) and PKCS#9 **`signing-time`** for picky **`exact_date`** (timestamp token signatures are **not** verified).
    #[arg(long)]
    prefer_timestamp_signing_time: bool,
    /// With **`--prefer-timestamp-signing-time`**, fail when no usable timestamp token exists.
    #[arg(long)]
    require_valid_timestamp: bool,
    /// Use this UTC date (YYYY-MM-DD) for **`exact_date`** instead of wall clock (for expired fixtures / reproducible CI).
    #[arg(long, value_name = "YYYY-MM-DD")]
    as_of: Option<String>,
    /// Fetch missing issuer certificates from AIA `caIssuers` HTTP URLs while building the chain.
    #[arg(long)]
    online_aia: bool,
    /// Deterministic AIA issuer URL override for local tests.
    #[arg(long, value_name = "URL")]
    aia_url_override: Option<String>,
    /// Query OCSP responders while applying online revocation policy.
    #[arg(long)]
    online_ocsp: bool,
    /// Deterministic OCSP responder URL override for local tests.
    #[arg(long, value_name = "URL")]
    ocsp_url_override: Option<String>,
    /// Online revocation policy for CRL checks.
    #[arg(long, value_enum, default_value_t = CliRevocationMode::Off)]
    revocation_mode: CliRevocationMode,
    /// Deterministic CRL URL override for local tests.
    #[arg(long, value_name = "URL")]
    crl_url_override: Option<String>,
    /// Timeout for online trust HTTP requests.
    #[arg(long, default_value_t = 5)]
    online_timeout_secs: u64,
    /// Maximum bytes accepted for an online issuer certificate download.
    #[arg(long, default_value_t = 1024 * 1024)]
    online_max_download_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CliRevocationMode {
    Off,
    BestEffort,
    Require,
}

impl From<CliRevocationMode> for RevocationMode {
    fn from(value: CliRevocationMode) -> Self {
        match value {
            CliRevocationMode::Off => Self::Off,
            CliRevocationMode::BestEffort => Self::BestEffort,
            CliRevocationMode::Require => Self::Require,
        }
    }
}

fn trust_verify_options_from_shared(a: &TrustVerifySharedArgs) -> Result<TrustVerifyPeOptions> {
    let expect_authroot_cab_sha256 = match &a.expect_authroot_cab_sha256 {
        Some(s) => Some(parse_sha256_hex(s)?),
        None => None,
    };
    let verification_instant_override = match &a.as_of {
        Some(s) => Some(parse_verification_date_ymd(s)?),
        None => None,
    };
    Ok(TrustVerifyPeOptions {
        anchor_dir: a.anchor_dir.clone(),
        trusted_ca_files: a.trusted_ca.clone(),
        authroot_cab: a.authroot_cab.clone(),
        expect_authroot_cab_sha256,
        verification_instant_override,
        verbose_chain: a.verbose_chain,
        online: OnlineTrustOptions {
            enable_aia: a.online_aia,
            aia_url_override: a.aia_url_override.clone(),
            enable_ocsp: a.online_ocsp,
            ocsp_url_override: a.ocsp_url_override.clone(),
            revocation_mode: a.revocation_mode.into(),
            crl_url_override: a.crl_url_override.clone(),
            timeout: std::time::Duration::from_secs(a.online_timeout_secs),
            max_download_bytes: a.online_max_download_bytes,
        },
        policy: AuthenticodeTrustPolicy {
            strict_code_signing_eku: !a.allow_loose_signing_cert,
            prefer_timestamp_signing_time: a.prefer_timestamp_signing_time,
            require_valid_timestamp: a.require_valid_timestamp,
        },
    })
}

fn digest_byte_len_for_hash_alg(alg: HashAlg) -> usize {
    match alg {
        HashAlg::Sha1 => 20,
        HashAlg::Sha256 => 32,
        HashAlg::Sha384 => 48,
        HashAlg::Sha512 => 64,
    }
}

fn hash_alg_timestamp_oid(alg: HashAlg) -> &'static str {
    match alg {
        HashAlg::Sha1 => "1.3.14.3.2.26",
        HashAlg::Sha256 => "2.16.840.1.101.3.4.2.1",
        HashAlg::Sha384 => "2.16.840.1.101.3.4.2.2",
        HashAlg::Sha512 => "2.16.840.1.101.3.4.2.3",
    }
}

fn parse_hex_digest_fixed(s: &str, byte_len: usize) -> Result<Vec<u8>> {
    let t = s.trim();
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if hex.len() != byte_len * 2 {
        return Err(anyhow!(
            "expect {} hex chars for this digest size, got {}",
            byte_len * 2,
            hex.len()
        ));
    }
    let mut out = vec![0u8; byte_len];
    for i in 0..byte_len {
        out[i] =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("invalid hex"))?;
    }
    Ok(out)
}

fn load_timestamp_imprint_preimage(
    digest_hex: Option<&String>,
    digest_file: Option<&PathBuf>,
    alg: HashAlg,
) -> Result<Vec<u8>> {
    let n = digest_byte_len_for_hash_alg(alg);
    match (digest_hex, digest_file) {
        (Some(h), None) => parse_hex_digest_fixed(h, n),
        (None, Some(p)) => {
            let b = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
            if b.len() != n {
                return Err(anyhow!(
                    "digest file must be exactly {} bytes for {:?}, got {}",
                    n,
                    alg,
                    b.len()
                ));
            }
            Ok(b)
        }
        _ => Err(anyhow!(
            "provide exactly one of --digest-hex or --digest-file"
        )),
    }
}

fn pki_status_label(s: Rfc3161PkiStatus) -> &'static str {
    match s {
        Rfc3161PkiStatus::Granted => "granted",
        Rfc3161PkiStatus::GrantedWithMods => "granted-with-mods",
        Rfc3161PkiStatus::Rejection => "rejection",
        Rfc3161PkiStatus::Waiting => "waiting",
        Rfc3161PkiStatus::RevocationWarning => "revocation-warning",
        Rfc3161PkiStatus::RevocationNotification => "revocation-notification",
        Rfc3161PkiStatus::Unknown(_) => "unknown",
    }
}

fn run_rfc3161_timestamp_req(
    algorithm: HashAlg,
    digest_file: Option<PathBuf>,
    digest_hex: Option<String>,
    nonce: Option<u64>,
    cert_req: bool,
    output: TimestampReqOutput,
) -> Result<()> {
    use std::io::Write;
    let preimage =
        load_timestamp_imprint_preimage(digest_hex.as_ref(), digest_file.as_ref(), algorithm)?;
    let plan = Rfc3161TimestampRequestPlan {
        digest_alg_oid: hash_alg_timestamp_oid(algorithm),
        nonce,
        cert_req,
    };
    let der = build_timestamp_request_bytes(&plan, &preimage).ok_or_else(|| {
        anyhow!("unsupported digest OID / preimage length for RFC3161 TimeStampReq")
    })?;
    match output {
        TimestampReqOutput::Der => {
            std::io::stdout().write_all(&der).context("write DER")?;
        }
        TimestampReqOutput::Hex => {
            println!("{}", hex_lower(&der));
        }
    }
    Ok(())
}

fn run_rfc3161_timestamp_resp_inspect(
    path: &Path,
    expect_digest_hex: Option<&str>,
    expect_nonce: Option<u64>,
) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let expected_digest = expect_digest_hex
        .map(normalize_even_hex)
        .transpose()
        .context("parse --expect-digest-hex")?;
    let expected_nonce = expect_nonce.map(rfc3161_nonce_hex);
    let p = parse_time_stamp_resp_der(&bytes).ok_or_else(|| {
        anyhow!("could not parse TimeStampResp DER (definite ASN.1 subset or trailing garbage)")
    })?;
    let tok_len = p.time_stamp_token.map(|t| t.len()).unwrap_or(0);
    println!(
        "pki_status={} pki_status_int={} granted={} time_stamp_token_len={}",
        pki_status_label(p.pki_status),
        p.pki_status.as_raw_integer(),
        if p.pki_status.granted() { "yes" } else { "no" },
        tok_len
    );
    println!(
        "time_stamp_token_prefix_hex={}",
        time_stamp_token_prefix_hex(p.time_stamp_token)
    );
    println!(
        "status_strings_json={}",
        serde_json::to_string(&p.status_strings).context("encode PKIStatusInfo.statusString")?
    );
    match p.fail_info_tlv {
        Some(fi) => println!("fail_info_tlv_hex={}", hex_lower(fi)),
        None => println!("fail_info_tlv_hex=-"),
    }
    let flags_json = match p.fail_info_tlv {
        None => serde_json::Value::Array(vec![]),
        Some(fi) => match pkifailure_info_flag_labels_from_bit_string_tlv(fi) {
            Some(labels) => serde_json::to_value(&labels).context("encode failInfo flags")?,
            None => serde_json::Value::Null,
        },
    };
    println!("fail_info_flags_json={flags_json}");
    if let Some(tst) = p.time_stamp_token.and_then(parse_time_stamp_token_tst_info) {
        println!("tst_info_present=yes");
        println!("tst_info_policy_oid={}", tst.policy_oid);
        println!(
            "tst_info_message_imprint_digest_alg_oid={}",
            tst.message_imprint_digest_alg_oid
        );
        println!(
            "tst_info_message_imprint_hashed_message_hex={}",
            hex_lower(&tst.message_imprint_hashed_message)
        );
        println!("tst_info_serial_hex={}", tst.serial_number_hex);
        println!("tst_info_gen_time={}", tst.gen_time);
        println!(
            "tst_info_nonce_hex={}",
            tst.nonce_hex.as_deref().unwrap_or("-")
        );
        if let Some(expected) = expected_digest.as_deref() {
            println!(
                "tst_info_message_imprint_match={}",
                if hex_lower(&tst.message_imprint_hashed_message) == expected {
                    "yes"
                } else {
                    "no"
                }
            );
        }
        if let Some(expected) = expected_nonce.as_deref() {
            println!(
                "tst_info_nonce_match={}",
                if tst.nonce_hex.as_deref() == Some(expected) {
                    "yes"
                } else {
                    "no"
                }
            );
        }
    } else {
        println!("tst_info_present=no");
        if expected_digest.is_some() {
            println!("tst_info_message_imprint_match=no");
        }
        if expected_nonce.is_some() {
            println!("tst_info_nonce_match=no");
        }
    }
    Ok(())
}

#[cfg(feature = "timestamp-http")]
fn run_rfc3161_timestamp_http_post(
    url: String,
    algorithm: HashAlg,
    digest_file: Option<PathBuf>,
    digest_hex: Option<String>,
    nonce: Option<u64>,
    cert_req: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    use std::io::Write;
    let preimage =
        load_timestamp_imprint_preimage(digest_hex.as_ref(), digest_file.as_ref(), algorithm)?;
    let plan = Rfc3161TimestampRequestPlan {
        digest_alg_oid: hash_alg_timestamp_oid(algorithm),
        nonce,
        cert_req,
    };
    let der = build_timestamp_request_bytes(&plan, &preimage).ok_or_else(|| {
        anyhow!("unsupported digest OID / preimage length for RFC3161 TimeStampReq")
    })?;
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("build HTTP client (timestamp-http feature)")?;
    let resp = client
        .post(url.trim())
        .header("Content-Type", "application/timestamp-query")
        .header(
            "Accept",
            "application/timestamp-reply, application/timestamp-response",
        )
        .body(der)
        .send()
        .with_context(|| format!("POST TimeStampReq to {}", url.trim()))?;
    let status = resp.status();
    let body = resp.bytes().context("read TSA response body")?;
    if !status.is_success() {
        return Err(anyhow!(
            "TSA HTTP {} — first {} body bytes (hex): {}",
            status,
            body.len().min(256),
            hex_lower(&body[..body.len().min(256)])
        ));
    }
    match output.as_ref() {
        Some(p) => std::fs::write(p, &body).with_context(|| format!("write {}", p.display()))?,
        None => std::io::stdout()
            .write_all(&body)
            .context("write TimeStampResp DER to stdout")?,
    }
    Ok(())
}

fn parse_sha256_hex(s: &str) -> Result<[u8; 32]> {
    let hex = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let hex = hex.strip_prefix("0X").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(anyhow!(
            "expect 64 hex chars for SHA-256, got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("invalid hex"))?;
        out[i] = byte;
    }
    Ok(out)
}

fn print_trust_ok(prefix: &str, report: &TrustVerifyPeReport) {
    println!(
        "{prefix}: ok — verified {} PKCS#7 entr(y/ies); {} anchor thumbprint(s)",
        report.pkcs7_entries_verified, report.anchor_thumbprints
    );
}

#[derive(Subcommand)]
enum Command {
    /// Print lowercase hex of the PE/WinMD **Authenticode image digest** (unsigned PE is OK).
    PeDigest {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
        /// **`hex`** (default): one lowercase hex line. **`raw`**: raw digest bytes (e.g. for **`artifact-signing-submit`** `--digest-file`).
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        /// Write output here instead of stdout.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Compare PE **`Optional Header.CheckSum`** to **`pe_compute_image_checksum`** (Windows **`CheckSumMappedFile`** style).
    ///
    /// Prints one line each: **`stored=0x…`**, **`computed=0x…`**, **`match=yes|no`**, **`file_bytes=N`**. **`--strict`**: exit with failure when **`match=no`** (CI / parity gate).
    PeChecksum {
        path: PathBuf,
        #[arg(long)]
        strict: bool,
    },
    /// Require embedded PKCS#7; compare indirect digest to Rust PE recomputation for each Authenticode cert.
    VerifyPe { path: PathBuf },
    /// Verify PE Authenticode **trust**: PKCS#7 CMS validation + certificate chain to **explicit** anchors (no OS store).
    ///
    /// Supply **`--anchor-dir`** (Phase A: `.crt`/`.cer`/`.pem`) and/or **`--authroot-cab`** (extract certs + CTL thumbs from AuthRoot-style CAB `.stl` payloads). **`verify-pe`** remains digest-only; this subcommand adds chain + policy checks.
    TrustVerifyPe {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Same trust pipeline as **`trust-verify-pe`** after CAB SIP digest consistency (**`verify-cab`**).
    TrustVerifyCab {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Same trust pipeline as **`trust-verify-pe`** after MSI/MSP SIP digest consistency (**`verify-msi`**).
    TrustVerifyMsi {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Same trust pipeline as **`trust-verify-pe`** after WIM/ESD SIP digest consistency (**`verify-esd`**).
    TrustVerifyEsd {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// CMS catalog digest consistency (**`verify-catalog`**) plus PKCS#7 chain to anchors when Authenticode-wrapped.
    TrustVerifyCatalog {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Detached PKCS#7 vs raw **`content`** bytes (digest inferred from PKCS#7 indirect length); PKCS#7 blob normalized like Win32 `CryptVerifyDetachedMessageSignature` helpers.
    TrustVerifyDetached {
        content: PathBuf,
        signature: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Print whether embedded PKCS#7 bytes contain **SPC_PE_IMAGE_PAGE_HASHES** attribute OIDs (V1/V2 DER scan).
    ///
    /// Outputs `yes` or `no` (does **not** validate page segments vs file bytes — use **`verify-pe-page-hashes`** for the experimental Rust check).
    PeHasPageHashes { path: PathBuf },
    /// Print structured **`SPC_PE_IMAGE_PAGE_HASHES`** rows from CMS **signed** attributes (one line per signer location).
    ///
    /// Includes **`parsed_page_hash_pairs`** when DER peeling + flat-table parsing succeeds (`-` otherwise).
    /// Empty stdout means no matching authenticated attributes were found. Does **not** validate pages vs file bytes.
    PePageHashInfo { path: PathBuf },
    /// **Experimental:** parse embedded page-hash tables and verify **contiguous raw file ranges** (see `psign_sip_digest::page_hashes::verify_pe_embedded_page_hash_tables`).
    ///
    /// Not a full `WinVerifyTrust` `/ph` clone — checksum / cert-directory exclusions may differ from native.
    VerifyPePageHashes { path: PathBuf },
    /// Print ordered **[`start`,`end`)** file byte ranges included in **PE Authenticode image digest** (same layout as `authenticode-rs` / `pe_authenticode_digest`).
    ///
    /// One line per range: `start=N end=M` (half-open end). Useful on Linux for tooling / future page-hash alignment vs `WinTrust`.
    PeAuthenticodeRanges { path: PathBuf },
    /// Decode **`SpcIndirectDataContent`** from an embedded Authenticode PKCS#7 (**JSON** to stdout; certificate-table order; default **`--index`** **`0`**).
    ///
    /// Intended for Linux-side inspection and PKCS#7 rebuild experiments (Rust **`pkcs7`** module in **`psign-sip-digest`**); does **not** sign or embed signatures.
    InspectPeSpcIndirect {
        path: PathBuf,
        /// **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row index (**`0`** = first; same order as **`extract-pe-pkcs7`** / **`list-pe-pkcs7`**).
        #[arg(long, default_value_t = 0)]
        index: usize,
        /// Include lowercase hex of **`image_data.value`** DER (**`SpcPeImageData`**) — output can be large.
        #[arg(long)]
        include_image_value_der_hex: bool,
    },
    /// Write an embedded Authenticode PKCS#7 (**raw DER**) to stdout or **`--output`** (certificate-table order; default **`--index`** **`0`**).
    ExtractPePkcs7 {
        path: PathBuf,
        /// **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row index (**`0`** = first).
        #[arg(long, default_value_t = 0)]
        index: usize,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// List **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** PKCS#7 rows in the PE certificate table (**`pkcs7_entries=N`** then **`index=i byte_len=L`** per line).
    ListPePkcs7 { path: PathBuf },
    /// **SHA-256** (**32** octets) over a signer’s authenticated-attribute **`SET OF Attribute`** DER (**RFC 5652** §5.4).
    ///
    /// Same raw digest Azure Key Vault **`keys/sign`** expects for **`RS256`** (base64 **`value`** in JSON) when re-signing **CMS `SignerInfo`** on **RSA SHA-256** Authenticode. Differs from **`pe-digest`** (PE **image** hash). Requires **`SignerInfo.digestAlgorithm`** **SHA-256** and **`signedAttrs`**. **`--index`**: **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row (**`0`** = first). **`--signer-index`**: **`SignerInfo`** within that PKCS#7’s **`SignedData`** (**`0`** = first; same as **`pkcs7-signer-rs256-prehash --signer-index`** after **`extract-pe-pkcs7`**).
    PeSignerRs256Prehash {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        index: usize,
        #[arg(long, default_value_t = 0)]
        signer_index: usize,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Same digest as **`pe-signer-rs256-prehash`**, but **`path`** is **PKCS#7** DER (**`ContentInfo`** wrapping **`SignedData`**, or bare **`SignedData`** normalized like **`extract-pe-pkcs7`** output).
    ///
    /// **`--signer-index`**: **`SignerInfo`** within this **`SignedData`** (**`0`** = first). For PE workflows, extract PKCS#7 first (**`extract-pe-pkcs7`**) then run this command.
    Pkcs7SignerRs256Prehash {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        signer_index: usize,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// **Experimental:** Append raw PKCS#7 (**`SignedData`**) DER as a new **`WIN_CERTIFICATE`** row (**`pe_embed`**).
    ///
    /// Updates the PE security directory and recomputes **`Optional Header.CheckSum`** (**`pe_compute_image_checksum`**). Does **not** validate PKCS#7 ↔ image digest or replace **`SignerSignEx3`**. For hybrid tooling and future portable sign pipelines.
    AppendPePkcs7 {
        /// Input PE path (**read fully** before writing **`--output`**; same path allowed).
        #[arg(long = "pe", value_name = "PATH")]
        pe_path: PathBuf,
        /// PKCS#7 DER file (**bare `SignedData`** is normalized like other portable PKCS#7 paths).
        #[arg(long = "pkcs7", value_name = "PATH")]
        pkcs7_path: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Sign an unsigned PE image with portable Authenticode CMS + `WIN_CERTIFICATE` embedding.
    ///
    /// This is the first production-oriented portable Authenticode signing path. It supports local RSA
    /// PKCS#1 v1.5 keys and SHA-2 digests; timestamp embedding and non-PE formats remain separate backlog.
    SignPe {
        /// Input PE path.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// File digest algorithm for the PE Authenticode indirect digest and CMS signer.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Output signed PE path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Sign an unsigned CAB file with portable Authenticode CMS and CAB reserve-header embedding.
    ///
    /// Supports single-volume unsigned CABs without an existing reserve header.
    SignCab {
        /// Input CAB path.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// File digest algorithm for the CAB Authenticode indirect digest and CMS signer.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Output signed CAB path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Sign an MSI/MSP OLE package with portable Authenticode CMS and a DigitalSignature stream.
    SignMsi {
        /// Input MSI/MSP path.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// File digest algorithm for the MSI Authenticode indirect digest and CMS signer.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Output signed MSI/MSP path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Sign a portable generic file catalog (`.cat`) with CTL members and CMS `SignedData`.
    ///
    /// This authors explicit file membership entries for the provided subjects. It does not implement
    /// driver/INF policy, OS catalog database installation/search, or MakeCat byte-for-byte output.
    SignCatalog {
        /// Subject file(s) to include as catalog members.
        #[arg(required = true, value_name = "PATH")]
        files: Vec<PathBuf>,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// File digest algorithm for catalog member digests and CMS signer.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Output signed catalog path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Attach an RFC3161 timestamp token to an existing embedded PE Authenticode signature.
    ///
    /// Accepts either a raw `timeStampToken` `ContentInfo` DER file or a `TimeStampResp` DER file containing one.
    TimestampPeRfc3161 {
        /// Signed PE path to mutate.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Embedded PKCS#7 row index in the PE certificate table.
        #[arg(long, default_value_t = 0)]
        index: usize,
        /// SignerInfo index inside the selected PKCS#7 SignedData.
        #[arg(long, default_value_t = 0)]
        signer_index: usize,
        /// Raw RFC3161 timeStampToken ContentInfo DER.
        #[arg(long, value_name = "PATH", conflicts_with = "response")]
        token: Option<PathBuf>,
        /// RFC3161 TimeStampResp DER containing a granted timeStampToken.
        #[arg(long, value_name = "PATH", conflicts_with = "token")]
        response: Option<PathBuf>,
        /// Output PE path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Sign `.rdp` files using portable RDP SignScope/SecureSettingsBlob logic.
    ///
    /// Supply either **`--cert`** + **`--key`** for local RSA/SHA-256 PKCS#7 creation, or
    /// **`--signature-pkcs7`** to embed an externally-created detached PKCS#7 for a single input.
    Rdp {
        /// Signer certificate as DER or PEM.
        #[arg(
            long,
            value_name = "PATH",
            requires = "key",
            conflicts_with = "signature_pkcs7"
        )]
        cert: Option<PathBuf>,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(
            long,
            value_name = "PATH",
            requires = "cert",
            conflicts_with = "signature_pkcs7"
        )]
        key: Option<PathBuf>,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(
            long = "chain-cert",
            value_name = "PATH",
            requires = "cert",
            conflicts_with = "signature_pkcs7"
        )]
        chain_certs: Vec<PathBuf>,
        /// Detached PKCS#7 DER to serialize into the RDP `Signature` record.
        #[arg(long = "signature-pkcs7", value_name = "PATH", conflicts_with_all = ["cert", "key", "chain_certs"])]
        signature_pkcs7: Option<PathBuf>,
        /// Build and validate the signed shape without writing files.
        #[arg(long)]
        dry_run: bool,
        /// Write output here instead of overwriting the input. Only valid with one input file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// `.rdp` file(s) to sign.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Write embedded Authenticode PKCS#7 (**raw DER**) from a signed **`.cab`** tail to stdout or **`--output`**.
    ///
    /// Layout: **`cab_digest::cab_signature_pkcs7_der`** (same bytes you would pass to **`pkcs7-signer-rs256-prehash`**).
    ExtractCabPkcs7 {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Same digest as **`pkcs7-signer-rs256-prehash`** on PKCS#7 embedded at the end of a signed **`.cab`** (after **`extract-cab-pkcs7`**).
    ///
    /// **`--signer-index`**: **`SignerInfo`** within that **`SignedData`**. For AzureSignTool-style **KV `RS256`**, use **`--encoding raw`** (distinct from **`cab-digest`** MSCF subject hash).
    CabSignerRs256Prehash {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        signer_index: usize,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// CAB with embedded PKCS#7: compare indirect digest to Rust CAB hash.
    VerifyCab { path: PathBuf },
    /// Write **`\\u{5}DigitalSignature`** stream (**raw PKCS#7 DER**) from an **`.msi`** to stdout or **`--output`**.
    ///
    /// Same blob as **`pkcs7-signer-rs256-prehash`** input for that signature. For real signed MSIs only; see **`tests/fixtures/msi-authenticode-upstream/README.md`** for the PKCS#7-only stub used in CI.
    ExtractMsiPkcs7 {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Same digest as **`pkcs7-signer-rs256-prehash`** on PKCS#7 from **`\\u{5}DigitalSignature`** (after **`extract-msi-pkcs7`**).
    ///
    /// **`--signer-index`**: **`SignerInfo`** within **`SignedData`**. **`--encoding raw`** for Azure KV **`RS256`** (distinct from MSI SIP fingerprint / **`verify-msi`** subject hash).
    MsiSignerRs256Prehash {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        signer_index: usize,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Signed MSI: compare PKCS#7 indirect digest to Rust OLE fingerprint (and extended stream if present).
    VerifyMsi { path: PathBuf },
    /// Signed WIM/ESD: compare PKCS#7 indirect digest to Rust prefix hash.
    VerifyEsd { path: PathBuf },
    /// Cleartext MSIX/APPX/bundle: compare PKCS#7 indirect digest to Rust ZIP rehash (encrypted extensions rejected).
    VerifyMsix { path: PathBuf },
    /// Same digest as **`pkcs7-signer-rs256-prehash`** when **`path`** is raw PKCS#7 **`SignedData`** (typical **`.cat`** body — CTL or other CMS **`ContentInfo`**).
    ///
    /// For **KV `RS256`** over **`SignerInfo.signedAttrs`**, use **`--encoding raw`**. Does **not** run **`verify-catalog`** (CTL **`messageDigest`** vs **`eContent`** rules differ from Authenticode PE PKCS#7).
    CatalogSignerRs256Prehash {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        signer_index: usize,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Signed catalog `.cat`: compare PKCS#7 indirect digest to Rust catalog digest scan.
    VerifyCatalog { path: PathBuf },
    /// Verify that a subject file is represented by a MakeCat-style CTL member in a signed catalog.
    VerifyCatalogMember {
        /// Catalog `.cat` file.
        #[arg(long, value_name = "PATH")]
        catalog: PathBuf,
        /// Subject file whose catalog membership should be checked.
        #[arg(value_name = "PATH")]
        subject: PathBuf,
    },
    /// Script signed file (PowerShell-class or WSH): compare PKCS#7 indirect digest to Rust heuristic strip/hash.
    VerifyScript { path: PathBuf },
    /// Inspect PKCS#7 layers: signers, timestamp-related attribute OIDs, nested signatures (`1.3.6.1.4.1.311.2.4.1`). JSON to stdout.
    InspectAuthenticode {
        path: PathBuf,
        /// Treat **`path`** as a PE image (**embedded** attribute certs) vs raw PKCS#7 bytes.
        #[arg(long, value_enum, default_value_t = InspectInputKind::Pe)]
        input: InspectInputKind,
    },
    /// Validate JSON metadata shape for Microsoft Artifact Signing (`Endpoint`, `CodeSigningAccountName`, `CertificateProfileName`; optional `ExcludeCredentials` string array). No network / no signing.
    ///
    /// Reads **`--path`** or stdin when omitted (use `-` for stdin explicitly).
    ArtifactSigningMetadataCheck {
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Azure Code Signing **`…:sign`** LRO (same REST contract as **`psign-tool artifact-signing-submit`**). Requires **`--features artifact-signing-rest`** at build time.
    #[cfg(feature = "artifact-signing-rest")]
    ArtifactSigningSubmit {
        #[command(flatten)]
        args: ArtifactSigningSubmitPortableArgs,
    },
    /// Azure Key Vault **`keys/sign`** over a **precomputed digest file** (RSA PKCS#1 or ECDSA). Requires **`--features azure-kv-sign-portable`**. Does **not** embed Authenticode — use **`psign-tool`** for that.
    #[cfg(feature = "azure-kv-sign-portable")]
    AzureKeyVaultSignDigest {
        #[command(flatten)]
        args: AzureKvSignDigestPortableArgs,
    },
    /// Build **RFC 3161** **`TimeStampReq`** DER from a **message imprint** preimage (raw digest bytes for **`MessageImprint.hashedMessage`** — not a second hash). For **`curl`** / OpenSSL **`ts -query`** against a TSA (**`application/timestamp-query`**).
    ///
    /// Supply exactly one of **`--digest-hex`** or **`--digest-file`**. Does **not** POST to a TSA.
    Rfc3161TimestampReq {
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
        /// Raw digest bytes; length must match **`--algorithm`** (e.g. 32 for SHA-256).
        #[arg(long, value_name = "PATH")]
        digest_file: Option<PathBuf>,
        /// Lowercase hex digest (no **`0x`**); length must match **`--algorithm`**.
        #[arg(long, value_name = "HEX")]
        digest_hex: Option<String>,
        /// Optional **`nonce`** (**`INTEGER`**) in the request.
        #[arg(long)]
        nonce: Option<u64>,
        /// Set **`certReq`** to **TRUE** (request certs inside **`TimeStampToken`**).
        #[arg(long, default_value_t = false)]
        cert_req: bool,
        #[arg(long, value_enum, default_value_t = TimestampReqOutput::Der)]
        output: TimestampReqOutput,
    },
    /// Parse **RFC 3161** **`TimeStampResp`** DER (**`application/timestamp-reply`**) and print **`pki_status`**, **`pki_status_int`**, **`granted`**, optional **`time_stamp_token`** length, first **16** octets of the token TLV as hex (**`time_stamp_token_prefix_hex`**, for CMS **`ContentInfo`** sniffing), **`status_strings_json`**, **`fail_info_tlv_hex`**, **`fail_info_flags_json`**. Does **not** verify CMS / TSA crypto.
    Rfc3161TimestampRespInspect {
        path: PathBuf,
        /// Expected **`TSTInfo.messageImprint.hashedMessage`** hex for request-binding diagnostics.
        #[arg(long, value_name = "HEX")]
        expect_digest_hex: Option<String>,
        /// Expected **`TSTInfo.nonce`** integer for request-binding diagnostics.
        #[arg(long)]
        expect_nonce: Option<u64>,
    },
    /// POST **`TimeStampReq`** DER to a TSA (**`Content-Type: application/timestamp-query`**) and write **`TimeStampResp`** DER to stdout or **`--output`**. Requires **`--features timestamp-http`**. Does **not** verify the timestamp token.
    #[cfg(feature = "timestamp-http")]
    Rfc3161TimestampHttpPost {
        /// TSA endpoint (**HTTPS** URL; POST body is raw **`TimeStampReq`** DER).
        #[arg(long, value_name = "URL")]
        url: String,
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
        #[arg(long, value_name = "PATH")]
        digest_file: Option<PathBuf>,
        #[arg(long, value_name = "HEX")]
        digest_hex: Option<String>,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = false)]
        cert_req: bool,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Print CAB Authenticode digest **without** requiring PKCS#7 (unsigned / structural check).
    ///
    /// Algorithm must match what will be used at signing time (default SHA-256). **`--encoding raw`** matches **`pe-digest`** for hash-file workflows.
    CabDigest {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Inspect NuGet package-signature marker state (`.signature.p7s`) without validating CMS.
    NupkgSignatureInfo { path: PathBuf },
    /// Hash an unsigned NuGet package exactly as the package-signature properties document records it.
    ///
    /// This is the unsigned ZIP byte hash used before adding `.signature.p7s`; signed packages are rejected.
    NupkgDigest {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Inspect VSIX OPC signature marker state without validating XMLDSig.
    VsixSignatureInfo { path: PathBuf },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum InspectInputKind {
    Pe,
    Pkcs7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PortableSignDigest {
    Sha256,
    Sha384,
    Sha512,
}

impl From<PortableSignDigest> for pkcs7::AuthenticodeSigningDigest {
    fn from(value: PortableSignDigest) -> Self {
        match value {
            PortableSignDigest::Sha256 => Self::Sha256,
            PortableSignDigest::Sha384 => Self::Sha384,
            PortableSignDigest::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum DigestEncoding {
    Hex,
    Raw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum TimestampReqOutput {
    /// Raw DER bytes to stdout.
    Der,
    /// One lowercase hex line (no line break after last nibble in typical terminals — still ends with newline for consistency).
    Hex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum NugetHashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl From<NugetHashAlg> for nuget::NuGetHashAlgorithm {
    fn from(value: NugetHashAlg) -> Self {
        match value {
            NugetHashAlg::Sha256 => Self::Sha256,
            NugetHashAlg::Sha384 => Self::Sha384,
            NugetHashAlg::Sha512 => Self::Sha512,
        }
    }
}

impl From<HashAlg> for PeAuthenticodeHashKind {
    fn from(value: HashAlg) -> Self {
        match value {
            HashAlg::Sha1 => Self::Sha1,
            HashAlg::Sha256 => Self::Sha256,
            HashAlg::Sha384 => Self::Sha384,
            HashAlg::Sha512 => Self::Sha512,
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn normalize_even_hex(s: &str) -> Result<String> {
    let hex = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let hex = hex.strip_prefix("0X").unwrap_or(hex);
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(anyhow!("expected a non-empty even-length hex string"));
    }
    if !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(anyhow!("invalid hex"));
    }
    Ok(hex.to_ascii_lowercase())
}

fn rfc3161_nonce_hex(nonce: u64) -> String {
    if nonce == 0 {
        return "00".to_string();
    }
    let bytes = nonce.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    let mut value = bytes[first..].to_vec();
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    hex_lower(&value)
}

/// Lowercase hex of the first **16** octets of the raw **`timeStampToken`** TLV (**`-`** when absent).
fn time_stamp_token_prefix_hex(token_tlv: Option<&[u8]>) -> String {
    const PREFIX_MAX: usize = 16;
    match token_tlv {
        None => "-".to_string(),
        Some(t) => hex_lower(&t[..t.len().min(PREFIX_MAX)]),
    }
}

fn write_digest_output(
    encoding: DigestEncoding,
    digest: &[u8],
    output: Option<&Path>,
) -> Result<()> {
    use std::io::Write;
    let write_hex_line = |w: &mut dyn Write| -> Result<()> {
        writeln!(w, "{}", hex_lower(digest)).context("write digest hex")
    };
    match output {
        Some(path) => {
            let mut f = std::fs::File::create(path)
                .with_context(|| format!("create {}", path.display()))?;
            match encoding {
                DigestEncoding::Hex => write_hex_line(&mut f)?,
                DigestEncoding::Raw => f.write_all(digest).context("write raw digest")?,
            }
        }
        None => match encoding {
            DigestEncoding::Hex => write_hex_line(&mut std::io::stdout())?,
            DigestEncoding::Raw => std::io::stdout()
                .write_all(digest)
                .context("write raw digest to stdout")?,
        },
    }
    Ok(())
}

#[cfg(feature = "artifact-signing-rest")]
#[derive(Args, Debug, Clone)]
struct ArtifactSigningSubmitPortableArgs {
    #[arg(long)]
    region: String,
    #[arg(long)]
    account_name: String,
    #[arg(long)]
    profile_name: String,
    #[arg(long)]
    digest_file: PathBuf,
    #[arg(long, default_value = "RS256")]
    signature_algorithm: String,
    #[arg(long, default_value = "2023-06-15-preview")]
    api_version: String,
    #[arg(long)]
    correlation_id: Option<String>,
    #[arg(long)]
    access_token: Option<String>,
    #[arg(long)]
    managed_identity: bool,
    #[arg(long)]
    tenant_id: Option<String>,
    #[arg(long)]
    client_id: Option<String>,
    #[arg(long)]
    client_secret: Option<String>,
    #[arg(long)]
    authority: Option<String>,
}

#[cfg(feature = "artifact-signing-rest")]
fn validate_portable_submit_args(args: &ArtifactSigningSubmitPortableArgs) -> Result<()> {
    let has_tok = args
        .access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let sp_count = (args
        .tenant_id
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false) as u8)
        + (args
            .client_id
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false) as u8)
        + (args
            .client_secret
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false) as u8);
    if args.managed_identity {
        if has_tok || sp_count != 0 {
            return Err(anyhow!(
                "use either --managed-identity or access token / client credentials, not multiple"
            ));
        }
        return Ok(());
    }
    if has_tok {
        if sp_count != 0 {
            return Err(anyhow!(
                "use either --access-token or client credentials tenant/id/secret, not both"
            ));
        }
        return Ok(());
    }
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "client credentials require all of --tenant-id, --client-id, and --client-secret"
        ));
    }
    if sp_count == 0 {
        return Err(anyhow!(
            "choose authentication: --managed-identity, --access-token, or tenant/client-id/client-secret"
        ));
    }
    Ok(())
}

#[cfg(feature = "artifact-signing-rest")]
fn portable_submit_auth(args: &ArtifactSigningSubmitPortableArgs) -> Result<CodesigningAuth> {
    let has_tok = args
        .access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if args.managed_identity {
        return Ok(CodesigningAuth::ManagedIdentity);
    }
    if has_tok {
        return Ok(CodesigningAuth::Bearer(
            args.access_token.as_ref().unwrap().trim().to_string(),
        ));
    }
    Ok(CodesigningAuth::ClientCredentials {
        tenant_id: args.tenant_id.as_ref().unwrap().trim().to_string(),
        client_id: args.client_id.as_ref().unwrap().trim().to_string(),
        client_secret: args.client_secret.as_ref().unwrap().trim().to_string(),
    })
}

#[cfg(feature = "artifact-signing-rest")]
fn run_portable_artifact_signing_submit(args: ArtifactSigningSubmitPortableArgs) -> Result<()> {
    validate_portable_submit_args(&args)?;
    let digest = std::fs::read(&args.digest_file)
        .with_context(|| format!("read digest file {}", args.digest_file.display()))?;
    if digest.is_empty() {
        return Err(anyhow!("digest file is empty"));
    }
    let auth = portable_submit_auth(&args)?;
    let params = CodesigningSubmitParams {
        region: args.region,
        account_name: args.account_name,
        profile_name: args.profile_name,
        digest,
        signature_algorithm: args.signature_algorithm,
        api_version: args.api_version,
        correlation_id: args.correlation_id,
        authority: args.authority,
        auth,
        endpoint_base_url: None,
    };
    let debug_portable = std::env::var_os("SIGNTOOL_PORTABLE_DEBUG").is_some();
    let v = submit_codesign_hash_blocking(&params, |msg| {
        if debug_portable {
            eprintln!("[debug] {msg}");
        }
    })?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

#[cfg(feature = "azure-kv-sign-portable")]
#[derive(Args, Debug, Clone)]
struct AzureKvSignDigestPortableArgs {
    #[arg(long = "azure-key-vault-url", visible_alias = "kvu")]
    vault_url: String,
    #[arg(long = "azure-key-vault-certificate", visible_alias = "kvc")]
    certificate: String,
    #[arg(long = "azure-key-vault-certificate-version", visible_alias = "kvcv")]
    certificate_version: Option<String>,
    #[arg(long)]
    digest_file: PathBuf,
    #[arg(long, value_enum, default_value_t = KvPortableHashAlg::Sha256)]
    digest_algorithm: KvPortableHashAlg,
    #[arg(long = "azure-key-vault-accesstoken")]
    azure_key_vault_access_token: Option<String>,
    #[arg(long = "azure-key-vault-managed-identity")]
    azure_key_vault_managed_identity: bool,
    #[arg(long = "azure-key-vault-tenant-id")]
    azure_key_vault_tenant_id: Option<String>,
    #[arg(long = "azure-key-vault-client-id")]
    azure_key_vault_client_id: Option<String>,
    #[arg(long = "azure-key-vault-client-secret")]
    azure_key_vault_client_secret: Option<String>,
    #[arg(long = "azure-authority")]
    azure_authority: Option<String>,
    /// Write raw signature bytes to this path. If omitted, prints **standard base64** (one line, no PEM).
    #[arg(long, value_name = "PATH")]
    signature_output: Option<PathBuf>,
}

#[cfg(feature = "azure-kv-sign-portable")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KvPortableHashAlg {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(feature = "azure-kv-sign-portable")]
impl From<KvPortableHashAlg> for KvHashAlg {
    fn from(value: KvPortableHashAlg) -> Self {
        match value {
            KvPortableHashAlg::Sha256 => KvHashAlg::Sha256,
            KvPortableHashAlg::Sha384 => KvHashAlg::Sha384,
            KvPortableHashAlg::Sha512 => KvHashAlg::Sha512,
        }
    }
}

#[cfg(feature = "azure-kv-sign-portable")]
fn validate_kv_portable_auth(args: &AzureKvSignDigestPortableArgs) -> Result<()> {
    let has_sp = args
        .azure_key_vault_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        == Some(true);
    let has_tenant = args
        .azure_key_vault_tenant_id
        .as_ref()
        .map(|s| !s.trim().is_empty())
        == Some(true);
    let has_client = args
        .azure_key_vault_client_id
        .as_ref()
        .map(|s| !s.trim().is_empty())
        == Some(true);
    let has_token = args
        .azure_key_vault_access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        == Some(true);

    let sp_count = has_sp as u8 + has_tenant as u8 + has_client as u8;
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "Azure AD client credentials require all of --azure-key-vault-client-id, --azure-key-vault-client-secret, and --azure-key-vault-tenant-id"
        ));
    }

    if has_token && (args.azure_key_vault_managed_identity || sp_count == 3) {
        return Err(anyhow!(
            "use either --azure-key-vault-accesstoken or managed identity / client credentials, not multiple"
        ));
    }
    if args.azure_key_vault_managed_identity && (has_token || sp_count == 3) {
        return Err(anyhow!(
            "--azure-key-vault-managed-identity cannot be combined with access tokens or client secrets"
        ));
    }
    if !has_token && !args.azure_key_vault_managed_identity && sp_count != 3 {
        return Err(anyhow!(
            "choose authentication: --azure-key-vault-accesstoken, --azure-key-vault-managed-identity, or client id/secret/tenant"
        ));
    }
    Ok(())
}

#[cfg(feature = "azure-kv-sign-portable")]
fn run_portable_azure_kv_sign_digest(args: AzureKvSignDigestPortableArgs) -> Result<()> {
    use std::time::Duration;
    validate_kv_portable_auth(&args)?;
    let digest = std::fs::read(&args.digest_file)
        .with_context(|| format!("read digest file {}", args.digest_file.display()))?;
    if digest.is_empty() {
        return Err(anyhow!("digest file is empty"));
    }
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let auth = KvAuthParams {
        access_token: args.azure_key_vault_access_token.as_deref(),
        managed_identity: args.azure_key_vault_managed_identity,
        tenant_id: args.azure_key_vault_tenant_id.as_deref(),
        client_id: args.azure_key_vault_client_id.as_deref(),
        client_secret: args.azure_key_vault_client_secret.as_deref(),
        authority: args.azure_authority.as_deref(),
    };
    let token = acquire_kv_access_token(&auth)?;
    let cert = fetch_kv_certificate(
        &http,
        args.vault_url.trim(),
        args.certificate.trim(),
        args.certificate_version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        &token,
    )?;
    let hash = KvHashAlg::from(args.digest_algorithm);
    let sig = kv_sign_digest_from_certificate(&http, &token, &cert, hash, &digest)?;
    if let Some(path) = args.signature_output {
        std::fs::write(&path, &sig).with_context(|| format!("write {}", path.display()))?;
    } else {
        println!(
            "{}",
            base64::engine::general_purpose::STANDARD.encode(sig.as_slice())
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct ArtifactSigningMetadataDoc {
    Endpoint: String,
    CodeSigningAccountName: String,
    CertificateProfileName: String,
    #[serde(default)]
    ExcludeCredentials: Option<Vec<String>>,
}

fn read_json_input(path: Option<&Path>) -> Result<Vec<u8>> {
    use std::io::Read;
    match path {
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read JSON from stdin")?;
            Ok(buf)
        }
        Some(p) if p.as_os_str() == "-" => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read JSON from stdin")?;
            Ok(buf)
        }
        Some(p) => std::fs::read(p).with_context(|| format!("read {}", p.display())),
    }
}

fn run_artifact_signing_metadata_check(path: Option<PathBuf>) -> Result<()> {
    let raw = read_json_input(path.as_deref())?;
    if raw.is_empty() {
        return Err(anyhow!("metadata JSON is empty"));
    }
    let doc: ArtifactSigningMetadataDoc =
        serde_json::from_slice(&raw).context("parse Artifact Signing metadata JSON")?;
    if doc.Endpoint.trim().is_empty() {
        return Err(anyhow!("Endpoint must be a non-empty string"));
    }
    if doc.CodeSigningAccountName.trim().is_empty() {
        return Err(anyhow!("CodeSigningAccountName must be a non-empty string"));
    }
    if doc.CertificateProfileName.trim().is_empty() {
        return Err(anyhow!("CertificateProfileName must be a non-empty string"));
    }
    if let Some(exc) = &doc.ExcludeCredentials {
        for (i, s) in exc.iter().enumerate() {
            if s.trim().is_empty() {
                return Err(anyhow!(
                    "ExcludeCredentials[{i}] must be a non-empty string"
                ));
            }
        }
    }
    println!("artifact-signing-metadata-check: ok");
    Ok(())
}

fn run_rdp_portable(
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    chain_certs: Vec<PathBuf>,
    signature_pkcs7: Option<PathBuf>,
    dry_run: bool,
    output: Option<PathBuf>,
    files: Vec<PathBuf>,
) -> Result<()> {
    if files.is_empty() {
        return Err(anyhow!("rdp requires at least one input file"));
    }
    if output.is_some() && files.len() != 1 {
        return Err(anyhow!("--output is only valid with one input file"));
    }
    if dry_run && output.is_some() {
        return Err(anyhow!("--dry-run cannot be combined with --output"));
    }
    if signature_pkcs7.is_some() && files.len() != 1 {
        return Err(anyhow!(
            "--signature-pkcs7 is only valid with one input file because it signs one secure blob"
        ));
    }

    let external_pkcs7 = signature_pkcs7
        .as_ref()
        .map(|path| std::fs::read(path).with_context(|| format!("read {}", path.display())))
        .transpose()?;

    let signer = match (cert, key) {
        (Some(cert), Some(key)) => {
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes =
                std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let mut parsed_chain = Vec::with_capacity(chain_certs.len());
            for chain_cert in chain_certs {
                let bytes = std::fs::read(&chain_cert)
                    .with_context(|| format!("read {}", chain_cert.display()))?;
                parsed_chain.push(rdp::parse_certificate(&bytes).with_context(|| {
                    format!("parse chain certificate {}", chain_cert.display())
                })?);
            }
            Some((signer_cert, parsed_chain, private_key))
        }
        (None, None) if external_pkcs7.is_some() => None,
        _ => {
            return Err(anyhow!(
                "rdp requires either --cert and --key, or --signature-pkcs7"
            ));
        }
    };

    for path in files {
        let input = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let text = rdp::decode_rdp_text(&input);
        let records = rdp::parse_records(&text);
        let mut prepared = rdp::prepare_for_signature(records)
            .with_context(|| format!("prepare RDP signature scope for {}", path.display()))?;
        let pkcs7 = if let Some(pkcs7) = external_pkcs7.as_ref() {
            pkcs7.clone()
        } else {
            let (cert, chain, key) = signer
                .as_ref()
                .expect("signer exists when external PKCS#7 is absent");
            rdp::sign_secure_blob_rsa_sha256(
                &prepared.secure_blob,
                cert.clone(),
                chain.clone(),
                key.clone(),
            )
            .with_context(|| format!("sign {}", path.display()))?
        };
        rdp::apply_pkcs7_signature(&mut prepared.records, &pkcs7);

        if dry_run {
            println!("Test signed {}", path.display());
            continue;
        }

        let destination = output.as_ref().unwrap_or(&path);
        let output_bytes = rdp::encode_native_unicode(&rdp::records_to_text(&prepared.records));
        std::fs::write(destination, output_bytes)
            .with_context(|| format!("write {}", destination.display()))?;
        println!("Signed {}", destination.display());
    }

    Ok(())
}

fn script_ext_from_path(path: &Path) -> Result<&str> {
    let ext = path
        .extension()
        .and_then(OsStr::to_str)
        .filter(|e| !e.is_empty())
        .with_context(|| format!("could not infer script extension from {}", path.display()))?;
    Ok(ext)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    run_from(std::env::args_os())
}

pub fn run_from<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    match cli.command {
        Command::PeDigest {
            path,
            algorithm,
            encoding,
            output,
        } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let digest = pe_authenticode_digest(&bytes, algorithm.into())?;
            write_digest_output(encoding, &digest, output.as_deref())?;
        }
        Command::PeChecksum { path, strict } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let stored = pe_embed::pe_read_image_checksum(&bytes)
                .with_context(|| format!("pe-checksum {}", path.display()))?;
            let computed = pe_embed::pe_compute_image_checksum(&bytes)
                .with_context(|| format!("pe-checksum {}", path.display()))?;
            let matches = stored == computed;
            println!("stored=0x{stored:08x}");
            println!("computed=0x{computed:08x}");
            println!("match={}", if matches { "yes" } else { "no" });
            println!("file_bytes={}", bytes.len());
            if strict && !matches {
                return Err(anyhow!(
                    "pe-checksum {}: stored != computed (pass without --strict to only print)",
                    path.display()
                ));
            }
        }
        Command::VerifyPe { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            verify_pe::verify_pe_authenticode_digest_consistency(&bytes)
                .with_context(|| format!("verify-pe {}", path.display()))?;
        }
        Command::TrustVerifyPe { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_pe_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-pe {}", path.display()))?;
            print_trust_ok("trust-verify-pe", &report);
        }
        Command::TrustVerifyCab { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_cab_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-cab {}", path.display()))?;
            print_trust_ok("trust-verify-cab", &report);
        }
        Command::TrustVerifyMsi { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_msi_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-msi {}", path.display()))?;
            print_trust_ok("trust-verify-msi", &report);
        }
        Command::TrustVerifyEsd { path, shared } => {
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_wim_esd_path(&path, &opts)
                .with_context(|| format!("trust-verify-esd {}", path.display()))?;
            print_trust_ok("trust-verify-esd", &report);
        }
        Command::TrustVerifyCatalog { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_catalog_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-catalog {}", path.display()))?;
            print_trust_ok("trust-verify-catalog", &report);
        }
        Command::TrustVerifyDetached {
            content,
            signature,
            shared,
        } => {
            let content_bytes =
                std::fs::read(&content).with_context(|| format!("read {}", content.display()))?;
            let sig_bytes = std::fs::read(&signature)
                .with_context(|| format!("read {}", signature.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_detached_bytes(&content_bytes, &sig_bytes, &opts)
                .with_context(|| format!("trust-verify-detached {}", content.display()))?;
            print_trust_ok("trust-verify-detached", &report);
        }
        Command::PeHasPageHashes { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let present = page_hashes::pe_embedded_pkcs7_contains_page_hash_attribute(&bytes)
                .with_context(|| format!("pe-has-page-hashes {}", path.display()))?;
            println!("{}", if present { "yes" } else { "no" });
        }
        Command::PePageHashInfo { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let rows = page_hashes::pe_collect_page_hash_auth_attributes(&bytes)
                .with_context(|| format!("pe-page-hash-info {}", path.display()))?;
            for loc in rows {
                let v1 = loc
                    .values
                    .iter()
                    .filter(|v| v.kind == PageHashAttrKind::V1)
                    .count();
                let v2 = loc
                    .values
                    .iter()
                    .filter(|v| v.kind == PageHashAttrKind::V2)
                    .count();
                let total_bytes: usize = loc.values.iter().map(|v| v.value_der.len()).sum();
                let mut parsed_pairs = 0usize;
                let mut parse_ok = true;
                for v in &loc.values {
                    match page_hashes::parse_page_hash_attribute_entries(&v.value_der, v.kind) {
                        Ok(entries) => parsed_pairs += entries.len(),
                        Err(_) => parse_ok = false,
                    }
                }
                let parsed_field = if parse_ok {
                    parsed_pairs.to_string()
                } else {
                    "-".to_string()
                };
                println!(
                    "pkcs7_index={} signer_index={} v1_values={} v2_values={} value_bytes_total={} parsed_page_hash_pairs={}",
                    loc.pkcs7_index, loc.signer_index, v1, v2, total_bytes, parsed_field
                );
            }
        }
        Command::VerifyPePageHashes { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            page_hashes::verify_pe_embedded_page_hash_tables(&bytes)
                .with_context(|| format!("verify-pe-page-hashes {}", path.display()))?;
        }
        Command::PeAuthenticodeRanges { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let ranges = pe_authenticode_digest_file_ranges(&bytes)
                .with_context(|| format!("pe-authenticode-ranges {}", path.display()))?;
            for r in ranges {
                println!("start={} end={}", r.start, r.end);
            }
        }
        Command::InspectPeSpcIndirect {
            path,
            index,
            include_image_value_der_hex,
        } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let indirect = pkcs7::parse_pe_pkcs7_spc_indirect_data_at(&bytes, index)
                .with_context(|| {
                    format!(
                        "inspect-pe-spc-indirect {} --index {index} (need PKCS#7 row and SpcIndirectData)",
                        path.display()
                    )
                })?;
            let kind = PeAuthenticodeHashKind::from_digest_byte_len(
                indirect.message_digest.digest.as_bytes().len(),
            )
            .with_context(|| format!("inspect-pe-spc-indirect {}", path.display()))?;
            let sip = pe_authenticode_digest(&bytes, kind)
                .with_context(|| format!("inspect-pe-spc-indirect {}", path.display()))?;
            let indirect_der_len =
                pkcs7::encode_spc_indirect_data_der(&indirect).map(|v| v.len())?;
            let digest_oid = indirect.message_digest.digest_algorithm.oid.to_string();
            let matches = sip.as_slice() == indirect.message_digest.digest.as_bytes();
            let mut report = serde_json::json!({
                "image_data_value_type_oid": indirect.data.value_type.to_string(),
                "digest_algorithm_oid": digest_oid,
                "message_digest_hex": hex_lower(indirect.message_digest.digest.as_bytes()),
                "message_digest_byte_len": indirect.message_digest.digest.as_bytes().len(),
                "spc_indirect_der_byte_len": indirect_der_len,
                "pe_image_digest_hex": hex_lower(&sip),
                "message_digest_matches_pe_image_digest": matches,
            });
            if include_image_value_der_hex {
                report.as_object_mut().expect("json object").insert(
                    "image_data_value_der_hex".to_string(),
                    serde_json::Value::String(hex_lower(indirect.data.value.value())),
                );
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::ExtractPePkcs7 {
            path,
            index,
            output,
        } => {
            use std::io::Write;
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let der =
                verify_pe::pe_nth_pkcs7_signed_data_der(&bytes, index).with_context(|| {
                    format!(
                        "extract-pe-pkcs7 {} --index {index} (need PKCS#7 row at this index)",
                        path.display()
                    )
                })?;
            match output.as_ref() {
                Some(p) => std::fs::write(p, &der)
                    .with_context(|| format!("write PKCS#7 to {}", p.display()))?,
                None => std::io::stdout()
                    .write_all(&der)
                    .context("write PKCS#7 to stdout")?,
            }
        }
        Command::ListPePkcs7 { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let lens = verify_pe::pe_pkcs7_signed_data_byte_lens(&bytes)
                .with_context(|| format!("list-pe-pkcs7 {}", path.display()))?;
            println!("pkcs7_entries={}", lens.len());
            for (i, len) in lens.iter().enumerate() {
                println!("index={i} byte_len={len}");
            }
        }
        Command::PeSignerRs256Prehash {
            path,
            index,
            signer_index,
            encoding,
            output,
        } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let pkcs7 =
                verify_pe::pe_nth_pkcs7_signed_data_der(&bytes, index).with_context(|| {
                    format!(
                        "pe-signer-rs256-prehash {} --index {index} (need PKCS#7 row)",
                        path.display()
                    )
                })?;
            let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7)
                .with_context(|| format!("parse PKCS#7 SignedData ({})", path.display()))?;
            let prehash = pkcs7::signed_data_rsa_sha256_signer_prehash_digest(&sd, signer_index)
                .with_context(|| {
                    format!(
                        "pe-signer-rs256-prehash {} --signer-index {signer_index}",
                        path.display()
                    )
                })?;
            write_digest_output(encoding, &prehash, output.as_deref()).with_context(|| {
                format!("write pe-signer-rs256-prehash output ({})", path.display())
            })?;
        }
        Command::Pkcs7SignerRs256Prehash {
            path,
            signer_index,
            encoding,
            output,
        } => {
            let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let pkcs7_der = pkcs7_wire::normalize_pkcs7_der_for_authenticode(&raw);
            let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7_der.as_ref()).with_context(|| {
                format!(
                    "pkcs7-signer-rs256-prehash {} (need PKCS#7 SignedData)",
                    path.display()
                )
            })?;
            let prehash = pkcs7::signed_data_rsa_sha256_signer_prehash_digest(&sd, signer_index)
                .with_context(|| format!("pkcs7-signer-rs256-prehash {}", path.display()))?;
            write_digest_output(encoding, &prehash, output.as_deref()).with_context(|| {
                format!(
                    "write pkcs7-signer-rs256-prehash output ({})",
                    path.display()
                )
            })?;
        }
        Command::AppendPePkcs7 {
            pe_path,
            pkcs7_path,
            output,
        } => {
            let pe_image = std::fs::read(&pe_path)
                .with_context(|| format!("read PE {}", pe_path.display()))?;
            let pkcs7_raw = std::fs::read(&pkcs7_path)
                .with_context(|| format!("read {}", pkcs7_path.display()))?;
            let pkcs7_der = pkcs7_wire::normalize_pkcs7_der_for_authenticode(&pkcs7_raw);
            let out_image =
                pe_embed::pe_append_authenticode_pkcs7_certificate(pe_image, pkcs7_der.as_ref())
                    .with_context(|| {
                        format!(
                            "append-pe-pkcs7 {} + {}",
                            pe_path.display(),
                            pkcs7_path.display()
                        )
                    })?;
            std::fs::write(&output, &out_image)
                .with_context(|| format!("write {}", output.display()))?;
        }
        Command::SignPe {
            path,
            cert,
            key,
            chain_certs,
            digest,
            output,
        } => {
            let pe = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes = std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let mut chain = Vec::with_capacity(chain_certs.len());
            for chain_cert in chain_certs {
                let bytes = std::fs::read(&chain_cert)
                    .with_context(|| format!("read {}", chain_cert.display()))?;
                chain.push(
                    rdp::parse_certificate(&bytes)
                        .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
                );
            }
            let pkcs7 = pkcs7::create_pe_authenticode_pkcs7_der_rsa(
                &pe,
                digest.into(),
                signer_cert,
                chain,
                private_key,
            )
            .with_context(|| {
                format!(
                    "create portable Authenticode signature for {}",
                    path.display()
                )
            })?;
            let signed = pe_embed::pe_append_authenticode_pkcs7_certificate(pe, &pkcs7)
                .with_context(|| format!("embed Authenticode signature in {}", path.display()))?;
            std::fs::write(&output, signed).with_context(|| format!("write {}", output.display()))?;
            println!(
                "sign-pe: ok output={} digest={:?} pkcs7_len={}",
                output.display(),
                digest,
                pkcs7.len()
            );
        }
        Command::SignCab {
            path,
            cert,
            key,
            chain_certs,
            digest,
            output,
        } => {
            let cab = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes = std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let mut chain = Vec::with_capacity(chain_certs.len());
            for chain_cert in chain_certs {
                let bytes = std::fs::read(&chain_cert)
                    .with_context(|| format!("read {}", chain_cert.display()))?;
                chain.push(
                    rdp::parse_certificate(&bytes)
                        .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
                );
            }
            let pkcs7 = pkcs7::create_cab_authenticode_pkcs7_der_rsa(
                &cab,
                digest.into(),
                signer_cert,
                chain,
                private_key,
            )
            .with_context(|| {
                format!(
                    "create portable CAB Authenticode signature for {}",
                    path.display()
                )
            })?;
            let signed = cab_digest::cab_append_authenticode_pkcs7_signature(&cab, &pkcs7)
                .with_context(|| format!("embed Authenticode signature in {}", path.display()))?;
            std::fs::write(&output, signed).with_context(|| format!("write {}", output.display()))?;
            println!(
                "sign-cab: ok output={} digest={:?} pkcs7_len={}",
                output.display(),
                digest,
                pkcs7.len()
            );
        }
        Command::SignMsi {
            path,
            cert,
            key,
            chain_certs,
            digest,
            output,
        } => {
            let msi = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes = std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let mut chain = Vec::with_capacity(chain_certs.len());
            for chain_cert in chain_certs {
                let bytes = std::fs::read(&chain_cert)
                    .with_context(|| format!("read {}", chain_cert.display()))?;
                chain.push(
                    rdp::parse_certificate(&bytes)
                        .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
                );
            }
            let pkcs7 = pkcs7::create_msi_authenticode_pkcs7_der_rsa(
                &msi,
                digest.into(),
                signer_cert,
                chain,
                private_key,
            )
            .with_context(|| {
                format!(
                    "create portable MSI Authenticode signature for {}",
                    path.display()
                )
            })?;
            msi_digest::msi_embed_authenticode_pkcs7_signature(&path, &output, &pkcs7)
                .with_context(|| format!("embed Authenticode signature in {}", path.display()))?;
            println!(
                "sign-msi: ok output={} digest={:?} pkcs7_len={}",
                output.display(),
                digest,
                pkcs7.len()
            );
        }
        Command::SignCatalog {
            files,
            cert,
            key,
            chain_certs,
            digest,
            output,
        } => {
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes = std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let mut chain = Vec::with_capacity(chain_certs.len());
            for chain_cert in chain_certs {
                let bytes = std::fs::read(&chain_cert)
                    .with_context(|| format!("read {}", chain_cert.display()))?;
                chain.push(
                    rdp::parse_certificate(&bytes)
                        .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
                );
            }
            let mut subjects = Vec::with_capacity(files.len());
            for file in &files {
                let name = file
                    .file_name()
                    .and_then(OsStr::to_str)
                    .ok_or_else(|| anyhow!("catalog subject path has no UTF-8 file name: {}", file.display()))?
                    .to_owned();
                let bytes =
                    std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
                subjects.push(catalog_digest::CatalogSubjectInput { name, bytes });
            }
            let catalog = catalog_digest::create_catalog_pkcs7_der_rsa(
                &subjects,
                digest.into(),
                signer_cert,
                chain,
                private_key,
            )
            .with_context(|| format!("create portable catalog {}", output.display()))?;
            std::fs::write(&output, &catalog.pkcs7_der)
                .with_context(|| format!("write {}", output.display()))?;
            println!(
                "sign-catalog: ok output={} digest={:?} members={} pkcs7_len={}",
                output.display(),
                digest,
                catalog.members.len(),
                catalog.pkcs7_der.len()
            );
        }
        Command::TimestampPeRfc3161 {
            path,
            index,
            signer_index,
            token,
            response,
            output,
        } => {
            let pe = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let token_der = match (token, response) {
                (Some(token), None) => {
                    std::fs::read(&token).with_context(|| format!("read {}", token.display()))?
                }
                (None, Some(response)) => {
                    let bytes = std::fs::read(&response)
                        .with_context(|| format!("read {}", response.display()))?;
                    let parsed = parse_time_stamp_resp_der(&bytes).ok_or_else(|| {
                        anyhow!("could not parse TimeStampResp DER from {}", response.display())
                    })?;
                    if !parsed.pki_status.granted() {
                        return Err(anyhow!(
                            "TimeStampResp status is not granted (status={})",
                            parsed.pki_status.as_raw_integer()
                        ));
                    }
                    parsed
                        .time_stamp_token
                        .map(|t| t.to_vec())
                        .ok_or_else(|| anyhow!("TimeStampResp has no timeStampToken"))?
                }
                _ => return Err(anyhow!("provide exactly one of --token or --response")),
            };
            let pkcs7_der = verify_pe::pe_nth_pkcs7_signed_data_der(&pe, index)
                .with_context(|| format!("extract PE PKCS#7 row {index} from {}", path.display()))?;
            let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_der)
                .with_context(|| format!("parse PE PKCS#7 row {index} from {}", path.display()))?;
            let stamped = pkcs7::signed_data_add_rfc3161_timestamp_token(
                &sd,
                signer_index,
                &token_der,
            )
            .with_context(|| {
                format!(
                    "attach RFC3161 timestamp to {} row {index} signer {signer_index}",
                    path.display()
                )
            })?;
            let stamped_pkcs7 = pkcs7::encode_pkcs7_content_info_signed_data_der(&stamped)?;
            let out_image =
                pe_embed::pe_replace_authenticode_pkcs7_certificate_at(pe, index, &stamped_pkcs7)
                    .with_context(|| {
                        format!("replace PE PKCS#7 row {index} in {}", path.display())
                    })?;
            std::fs::write(&output, out_image)
                .with_context(|| format!("write {}", output.display()))?;
            println!(
                "timestamp-pe-rfc3161: ok output={} index={} signer_index={}",
                output.display(),
                index,
                signer_index
            );
        }
        Command::Rdp {
            cert,
            key,
            chain_certs,
            signature_pkcs7,
            dry_run,
            output,
            files,
        } => {
            run_rdp_portable(
                cert,
                key,
                chain_certs,
                signature_pkcs7,
                dry_run,
                output,
                files,
            )?;
        }
        Command::ExtractCabPkcs7 { path, output } => {
            use std::io::Write;
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let der = cab_signature_pkcs7_der(&bytes).with_context(|| {
                format!(
                    "extract-cab-pkcs7 {} (need signed CAB with PKCS#7 tail)",
                    path.display()
                )
            })?;
            match output.as_ref() {
                Some(p) => std::fs::write(p, der)
                    .with_context(|| format!("write PKCS#7 to {}", p.display()))?,
                None => std::io::stdout()
                    .write_all(der)
                    .context("write PKCS#7 to stdout")?,
            }
        }
        Command::CabSignerRs256Prehash {
            path,
            signer_index,
            encoding,
            output,
        } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let prehash =
                cab_rsa_sha256_signer_prehash_digest(&bytes, signer_index).with_context(|| {
                    format!(
                        "cab-signer-rs256-prehash {} --signer-index {signer_index}",
                        path.display()
                    )
                })?;
            write_digest_output(encoding, &prehash, output.as_deref()).with_context(|| {
                format!("write cab-signer-rs256-prehash output ({})", path.display())
            })?;
        }
        Command::VerifyCab { path } => {
            verify_cab_digest_consistency(&path)
                .with_context(|| format!("verify-cab {}", path.display()))?;
        }
        Command::ExtractMsiPkcs7 { path, output } => {
            use std::io::Write;
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let der = msi_digest::msi_digital_signature_pkcs7_der(&bytes).with_context(|| {
                format!(
                    "extract-msi-pkcs7 {} (need OLE compound with DigitalSignature stream)",
                    path.display()
                )
            })?;
            match output.as_ref() {
                Some(p) => std::fs::write(p, &der)
                    .with_context(|| format!("write PKCS#7 to {}", p.display()))?,
                None => std::io::stdout()
                    .write_all(&der)
                    .context("write PKCS#7 to stdout")?,
            }
        }
        Command::MsiSignerRs256Prehash {
            path,
            signer_index,
            encoding,
            output,
        } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let prehash = msi_digest::msi_rsa_sha256_signer_prehash_digest(&bytes, signer_index)
                .with_context(|| {
                    format!(
                        "msi-signer-rs256-prehash {} --signer-index {signer_index}",
                        path.display()
                    )
                })?;
            write_digest_output(encoding, &prehash, output.as_deref()).with_context(|| {
                format!("write msi-signer-rs256-prehash output ({})", path.display())
            })?;
        }
        Command::VerifyMsi { path } => {
            msi_digest::verify_msi_digest_consistency(&path)
                .with_context(|| format!("verify-msi {}", path.display()))?;
        }
        Command::VerifyEsd { path } => {
            esd_digest::verify_wim_esd_digest_consistency(&path)
                .with_context(|| format!("verify-esd {}", path.display()))?;
        }
        Command::VerifyMsix { path } => {
            msix_digest::verify_msix_digest_consistency(&path)
                .with_context(|| format!("verify-msix {}", path.display()))?;
        }
        Command::CatalogSignerRs256Prehash {
            path,
            signer_index,
            encoding,
            output,
        } => {
            let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let prehash =
                catalog_digest::catalog_rsa_sha256_signer_prehash_digest(&raw, signer_index)
                    .with_context(|| {
                        format!(
                            "catalog-signer-rs256-prehash {} --signer-index {signer_index}",
                            path.display()
                        )
                    })?;
            write_digest_output(encoding, &prehash, output.as_deref()).with_context(|| {
                format!(
                    "write catalog-signer-rs256-prehash output ({})",
                    path.display()
                )
            })?;
        }
        Command::VerifyCatalog { path } => {
            catalog_digest::verify_catalog_digest_consistency(&path)
                .with_context(|| format!("verify-catalog {}", path.display()))?;
        }
        Command::VerifyCatalogMember { catalog, subject } => {
            let m = catalog_digest::verify_catalog_member(&catalog, &subject).with_context(|| {
                format!(
                    "verify-catalog-member --catalog {} {}",
                    catalog.display(),
                    subject.display()
                )
            })?;
            println!(
                "verify-catalog-member: ok catalog={} subject={} member_index={} member_name={} digest_alg_oid={} data_oid={} digest={}",
                catalog.display(),
                subject.display(),
                m.member_index,
                m.member.subject_name.as_deref().unwrap_or("-"),
                m.member.digest_algorithm_oid,
                m.member.data_oid,
                hex_lower(&m.computed_digest)
            );
        }
        Command::VerifyScript { path } => {
            let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let ext = script_ext_from_path(&path)?;
            verify_script_digest_consistency(&raw, ext)
                .with_context(|| format!("verify-script {}", path.display()))?;
        }
        Command::InspectAuthenticode { path, input } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let json = match input {
                InspectInputKind::Pe => {
                    serde_json::to_string_pretty(&inspect_pe_authenticode(&bytes)?)?
                }
                InspectInputKind::Pkcs7 => {
                    serde_json::to_string_pretty(&inspect_authenticode_pkcs7_der(&bytes)?)?
                }
            };
            println!("{json}");
        }
        Command::ArtifactSigningMetadataCheck { path } => {
            run_artifact_signing_metadata_check(path)?;
        }
        #[cfg(feature = "artifact-signing-rest")]
        Command::ArtifactSigningSubmit { args } => {
            run_portable_artifact_signing_submit(args)?;
        }
        #[cfg(feature = "azure-kv-sign-portable")]
        Command::AzureKeyVaultSignDigest { args } => {
            run_portable_azure_kv_sign_digest(args)?;
        }
        Command::Rfc3161TimestampReq {
            algorithm,
            digest_file,
            digest_hex,
            nonce,
            cert_req,
            output,
        } => {
            run_rfc3161_timestamp_req(algorithm, digest_file, digest_hex, nonce, cert_req, output)?;
        }
        Command::Rfc3161TimestampRespInspect {
            path,
            expect_digest_hex,
            expect_nonce,
        } => {
            run_rfc3161_timestamp_resp_inspect(&path, expect_digest_hex.as_deref(), expect_nonce)?;
        }
        #[cfg(feature = "timestamp-http")]
        Command::Rfc3161TimestampHttpPost {
            url,
            algorithm,
            digest_file,
            digest_hex,
            nonce,
            cert_req,
            output,
        } => {
            run_rfc3161_timestamp_http_post(
                url,
                algorithm,
                digest_file,
                digest_hex,
                nonce,
                cert_req,
                output,
            )?;
        }
        Command::CabDigest {
            path,
            algorithm,
            encoding,
            output,
        } => {
            let data = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let ctx = parse_cab_context(&data)?;
            let digest = compute_cab_authenticode_digest(&data, &ctx, algorithm.into())?;
            write_digest_output(encoding, &digest, output.as_deref())?;
        }
        Command::NupkgSignatureInfo { path } => {
            let info = nuget::inspect_nupkg_path(&path)
                .with_context(|| format!("nupkg-signature-info {}", path.display()))?;
            println!("signed={}", if info.signed { "yes" } else { "no" });
            println!(
                "signature_file={}",
                if info.signed {
                    nuget::PACKAGE_SIGNATURE_FILE_NAME
                } else {
                    "-"
                }
            );
            println!(
                "signature_len={}",
                info.signature_len
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
            println!(
                "signature_stored={}",
                info.signature_is_stored
                    .map(|v| if v { "yes" } else { "no" })
                    .unwrap_or("-")
            );
            println!("entries={}", info.package.entries.len());
        }
        Command::NupkgDigest {
            path,
            algorithm,
            encoding,
            output,
        } => {
            let digest = nuget::unsigned_package_digest_path(&path, algorithm.into())
                .with_context(|| format!("nupkg-digest {}", path.display()))?;
            write_digest_output(encoding, &digest, output.as_deref())?;
        }
        Command::VsixSignatureInfo { path } => {
            let info = vsix::inspect_vsix_path(&path)
                .with_context(|| format!("vsix-signature-info {}", path.display()))?;
            println!(
                "opc_signature={}",
                if info.has_opc_signature { "yes" } else { "no" }
            );
            println!(
                "signature_origin={}",
                if info.package.has_opc_signature_origin {
                    psign_opc_sign::opc::OPC_SIGNATURE_ORIGIN_PART
                } else {
                    "-"
                }
            );
            println!("signature_parts={}", info.package.opc_signature_parts.len());
            for part in info.package.opc_signature_parts {
                println!("signature_part={part}");
            }
            println!("entries={}", info.package.entries.len());
        }
    }
    Ok(())
}
