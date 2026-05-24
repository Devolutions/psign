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
    trust_verify_zip_bytes,
    trust_verify_pe::load_trust_material,
};
#[cfg(feature = "azure-kv-sign-portable")]
use psign_azure_kv_rest::{
    KvAuthParams, KvHashAlg, acquire_kv_access_token, fetch_kv_certificate,
    kv_decode_cer_b64, kv_sign_digest_from_certificate,
};
#[cfg(feature = "artifact-signing-rest")]
use psign_codesigning_rest::{
    CodesigningAuth, CodesigningSubmitParams, DEFAULT_API_VERSION,
    submit_codesign_hash_blocking, submit_codesign_hash_signature_blocking,
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
use psign_sip_digest::zip_authenticode;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::{
    SignatureEncoding as _, Signer as _, Verifier as _, hazmat::PrehashSigner as _,
};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use x509_cert::der::{
    Encode as _,
    asn1::{ObjectIdentifier, OctetString},
};

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

fn trust_verify_args_present(a: &TrustVerifySharedArgs) -> bool {
    a.anchor_dir.is_some()
        || !a.trusted_ca.is_empty()
        || a.authroot_cab.is_some()
        || a.expect_authroot_cab_sha256.is_some()
        || a.as_of.is_some()
        || a.online_aia
        || a.online_ocsp
        || a.revocation_mode != CliRevocationMode::Off
        || a.crl_url_override.is_some()
        || a.aia_url_override.is_some()
        || a.ocsp_url_override.is_some()
}

fn verify_xml_signer_certificate_trust(cert_der: &[u8], shared: &TrustVerifySharedArgs) -> Result<usize> {
    let opts = trust_verify_options_from_shared(shared)?;
    let (anchors, anchor_certs) = load_trust_material(&opts)?;
    let leaf = psign_authenticode_trust::anchor::parse_cert_bytes(cert_der)
        .context("parse XMLDSig signer certificate for trust verification")?;
    let mut merged =
        psign_authenticode_trust::chain::merge_unique_certs(vec![leaf.clone()], anchor_certs)?;
    let chain_owned = psign_authenticode_trust::chain::issuer_chain_excluding_leaf_online(
        &leaf,
        &mut merged,
        &opts.online,
    )?;
    let root = psign_authenticode_trust::chain::terminal_root_cert_owned(&leaf, &chain_owned);
    let root_thumb = psign_authenticode_trust::anchor::cert_sha1_thumbprint(root)?;
    if !anchors.contains_thumbprint(&root_thumb) {
        return Err(anyhow!(
            "XMLDSig terminal root certificate is not in the anchor store (SHA-1 thumbprint {:02x}{:02x}...)",
            root_thumb[0],
            root_thumb[1]
        ));
    }
    psign_authenticode_trust::online::check_revocation_chain(&leaf, &chain_owned, &opts.online)?;

    let verification_instant = match opts.verification_instant_override.as_ref() {
        Some(instant) => instant.clone(),
        None if opts.policy.prefer_timestamp_signing_time && opts.policy.require_valid_timestamp => {
            return Err(anyhow!(
                "VSIX XMLDSig timestamp trust verification is not implemented; use --as-of for deterministic certificate-chain validation"
            ));
        }
        None => psign_authenticode_trust::verification_instant::resolve_verification_utc_date(
            b"",
            &opts.policy,
        )?,
    };

    let chain_refs: Vec<_> = chain_owned.iter().collect();
    let leaf_verifier = leaf.verifier();
    let verifier = leaf_verifier
        .chain(chain_refs.iter().copied())
        .exact_date(&verification_instant);
    verifier
        .verify()
        .map_err(|e| anyhow!("XMLDSig certificate chain verification: {e}"))?;

    if opts.verbose_chain {
        let thumb_hex: String = root_thumb.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("xml-trust: leaf subject: {}", leaf.subject_name());
        for (i, cert) in chain_refs.iter().enumerate() {
            eprintln!(
                "xml-trust:   chain[{i}] subject: {} issuer: {}",
                cert.subject_name(),
                cert.issuer_name()
            );
        }
        eprintln!(
            "xml-trust:   root subject: {} (thumb SHA-1 {thumb_hex})",
            root.subject_name()
        );
    }

    Ok(anchors.thumbprint_count())
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

fn digest_bytes_for_hash_alg(alg: HashAlg, input: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => Sha1::digest(input).to_vec(),
        HashAlg::Sha256 => Sha256::digest(input).to_vec(),
        HashAlg::Sha384 => Sha384::digest(input).to_vec(),
        HashAlg::Sha512 => Sha512::digest(input).to_vec(),
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

#[derive(Debug, Eq, PartialEq)]
struct AppInstallerDescriptorInfo {
    root: &'static str,
    namespace: Option<String>,
    has_main_package: bool,
    has_main_bundle: bool,
    publisher: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct BusinessCentralAppInfo {
    is_navx: bool,
    len: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct MsixManifestInfo {
    package_name: Option<String>,
    publisher: Option<String>,
    version: Option<String>,
    processor_architecture: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct ClickOnceDeployInfo {
    deployed: bool,
    content_name: Option<String>,
    len: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct ClickOnceManifestHashEntry {
    path: String,
    algorithm: HashAlg,
    expected_size: Option<u64>,
    actual_size: u64,
    expected_digest_b64: String,
    actual_digest_b64: String,
}

impl ClickOnceManifestHashEntry {
    fn status(&self) -> &'static str {
        if self.expected_size.is_some_and(|size| size != self.actual_size) {
            "mismatch"
        } else if self.expected_digest_b64 == self.actual_digest_b64 {
            "valid"
        } else {
            "mismatch"
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ClickOnceManifestSignatureReport {
    digest: PortableSignDigest,
    manifest_digest_b64: String,
    signature_len: usize,
}

fn inspect_clickonce_deploy_payload(path: &Path) -> Result<ClickOnceDeployInfo> {
    let metadata = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let content_name = clickonce_deploy_content_name(path);
    Ok(ClickOnceDeployInfo {
        deployed: content_name.is_some(),
        content_name,
        len: metadata.len(),
    })
}

fn clickonce_deploy_content_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_string_lossy();
    file_name
        .strip_suffix(".deploy")
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn copy_clickonce_deploy_payload(input: &Path, output: &Path) -> Result<u64> {
    let Some(_) = clickonce_deploy_content_name(input) else {
        return Err(anyhow!(
            "ClickOnce deploy payload name must end with .deploy: {}",
            input.display()
        ));
    };
    std::fs::copy(input, output)
        .with_context(|| format!("copy {} to {}", input.display(), output.display()))
}

fn clickonce_manifest_hashes(
    manifest_path: &Path,
    base_directory: Option<&Path>,
) -> Result<Vec<ClickOnceManifestHashEntry>> {
    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("read ClickOnce manifest {}", manifest_path.display()))?;
    let base = base_directory
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    clickonce_manifest_hashes_from_text(&text, &base)
}

fn clickonce_manifest_hashes_from_text(
    text: &str,
    base_directory: &Path,
) -> Result<Vec<ClickOnceManifestHashEntry>> {
    let entries = clickonce_manifest_reference_spans(text)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let file_path = resolve_clickonce_manifest_path(base_directory, &entry.path)?;
        let bytes =
            std::fs::read(&file_path).with_context(|| format!("read {}", file_path.display()))?;
        let digest = digest_bytes_for_hash_alg(entry.algorithm, &bytes);
        out.push(ClickOnceManifestHashEntry {
            path: entry.path,
            algorithm: entry.algorithm,
            expected_size: entry.size,
            actual_size: bytes.len() as u64,
            expected_digest_b64: entry.digest_value,
            actual_digest_b64: base64_encode(&digest),
        });
    }
    Ok(out)
}

fn update_clickonce_manifest_hashes(
    manifest_path: &Path,
    base_directory: Option<&Path>,
    output: &Path,
    algorithm: HashAlg,
) -> Result<usize> {
    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("read ClickOnce manifest {}", manifest_path.display()))?;
    let base = base_directory
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    let updated = update_clickonce_manifest_hashes_in_text(&text, &base, algorithm)?;
    std::fs::write(output, updated.text)
        .with_context(|| format!("write ClickOnce manifest {}", output.display()))?;
    Ok(updated.updated)
}

#[derive(Debug)]
struct ClickOnceManifestReference {
    tag_start: usize,
    tag_end: usize,
    path: String,
    size: Option<u64>,
    algorithm: HashAlg,
    digest_value: String,
    digest_method_tag_start: usize,
    digest_method_tag_end: usize,
    digest_value_content_start: usize,
    digest_value_content_end: usize,
}

#[derive(Debug)]
struct UpdatedClickOnceManifest {
    text: String,
    updated: usize,
}

fn update_clickonce_manifest_hashes_in_text(
    text: &str,
    base_directory: &Path,
    algorithm: HashAlg,
) -> Result<UpdatedClickOnceManifest> {
    let entries = clickonce_manifest_reference_spans(text)?;
    let mut replacements = Vec::with_capacity(entries.len() * 3);
    for entry in &entries {
        let file_path = resolve_clickonce_manifest_path(base_directory, &entry.path)?;
        let bytes =
            std::fs::read(&file_path).with_context(|| format!("read {}", file_path.display()))?;
        let digest = digest_bytes_for_hash_alg(algorithm, &bytes);
        let size = bytes.len().to_string();
        replacements.push((
            entry.tag_start,
            entry.tag_end + 1,
            replace_or_insert_xml_attr(&text[entry.tag_start..=entry.tag_end], "size", &size)?,
        ));
        replacements.push((
            entry.digest_method_tag_start,
            entry.digest_method_tag_end + 1,
            replace_or_insert_xml_attr(
                &text[entry.digest_method_tag_start..=entry.digest_method_tag_end],
                "Algorithm",
                clickonce_digest_algorithm_uri(algorithm),
            )?,
        ));
        replacements.push((
            entry.digest_value_content_start,
            entry.digest_value_content_end,
            base64_encode(&digest),
        ));
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end, replacement) in replacements {
        if start < cursor {
            return Err(anyhow!("internal ClickOnce manifest replacement overlap"));
        }
        out.push_str(&text[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Ok(UpdatedClickOnceManifest {
        text: out,
        updated: entries.len(),
    })
}

fn clickonce_manifest_reference_spans(text: &str) -> Result<Vec<ClickOnceManifestReference>> {
    let mut refs = Vec::new();
    collect_clickonce_manifest_references(text, "file", "name", &mut refs)?;
    collect_clickonce_manifest_references(text, "dependentAssembly", "codebase", &mut refs)?;
    refs.sort_by_key(|entry| entry.tag_start);
    Ok(refs)
}

fn collect_clickonce_manifest_references(
    text: &str,
    tag: &str,
    path_attr: &str,
    refs: &mut Vec<ClickOnceManifestReference>,
) -> Result<()> {
    let mut cursor = 0usize;
    while let Some(start) = find_xml_start_tag(text, tag, cursor) {
        let tag_end = text[start..]
            .find('>')
            .map(|offset| start + offset)
            .ok_or_else(|| anyhow!("ClickOnce manifest <{tag}> tag is not closed"))?;
        let start_tag = &text[start..=tag_end];
        cursor = tag_end + 1;
        if start_tag.ends_with("/>") {
            continue;
        }
        let Some(path) = xml_attr(start_tag, path_attr) else {
            continue;
        };
        let close = format!("</{tag}>");
        let Some(close_start) = text[cursor..].find(&close).map(|offset| cursor + offset) else {
            continue;
        };
        let block_end = close_start + close.len();
        let block = &text[tag_end + 1..close_start];
        let Some(method) = find_xml_start_tag_by_local_name(block, "DigestMethod", 0)? else {
            continue;
        };
        let Some(value) = find_xml_element_by_local_name(block, "DigestValue", 0)? else {
            continue;
        };
        let method_tag = &block[method.start..=method.end];
        let algorithm = xml_attr(method_tag, "Algorithm")
            .as_deref()
            .map(clickonce_hash_alg_from_uri)
            .transpose()?
            .unwrap_or(HashAlg::Sha256);
        refs.push(ClickOnceManifestReference {
            tag_start: start,
            tag_end,
            path,
            size: xml_attr(start_tag, "size")
                .map(|s| s.parse::<u64>())
                .transpose()
                .context("parse ClickOnce manifest size attribute")?,
            algorithm,
            digest_value: block[value.content_start..value.content_end]
                .trim()
                .to_owned(),
            digest_method_tag_start: tag_end + 1 + method.start,
            digest_method_tag_end: tag_end + 1 + method.end,
            digest_value_content_start: tag_end + 1 + value.content_start,
            digest_value_content_end: tag_end + 1 + value.content_end,
        });
        cursor = block_end;
    }
    Ok(())
}

#[derive(Debug)]
struct XmlStartTagSpan {
    start: usize,
    end: usize,
    name: String,
}

#[derive(Debug)]
struct XmlElementSpan {
    content_start: usize,
    content_end: usize,
}

fn find_xml_start_tag(text: &str, tag: &str, from: usize) -> Option<usize> {
    let needle = format!("<{tag}");
    let mut cursor = from;
    while let Some(rel) = text[cursor..].find(&needle) {
        let start = cursor + rel;
        let next = text[start + needle.len()..].chars().next();
        if matches!(next, Some(' ' | '\t' | '\r' | '\n' | '>' | '/')) {
            return Some(start);
        }
        cursor = start + needle.len();
    }
    None
}

fn find_xml_start_tag_by_local_name(
    text: &str,
    local_name: &str,
    from: usize,
) -> Result<Option<XmlStartTagSpan>> {
    let mut cursor = from;
    while let Some(rel) = text[cursor..].find('<') {
        let start = cursor + rel;
        let Some(first) = text[start + 1..].chars().next() else {
            return Ok(None);
        };
        if matches!(first, '/' | '!' | '?') {
            cursor = start + 1;
            continue;
        }
        let end = text[start..]
            .find('>')
            .map(|offset| start + offset)
            .ok_or_else(|| anyhow!("ClickOnce XML tag is not closed"))?;
        let name_start = start + 1;
        let name_end = text[name_start..=end]
            .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
            .map(|offset| name_start + offset)
            .unwrap_or(end);
        let name = &text[name_start..name_end];
        let name_local = name.rsplit_once(':').map(|(_, local)| local).unwrap_or(name);
        if name_local == local_name {
            return Ok(Some(XmlStartTagSpan {
                start,
                end,
                name: name.to_owned(),
            }));
        }
        cursor = end + 1;
    }
    Ok(None)
}

fn find_xml_element_by_local_name(
    text: &str,
    local_name: &str,
    from: usize,
) -> Result<Option<XmlElementSpan>> {
    let Some(start_tag) = find_xml_start_tag_by_local_name(text, local_name, from)? else {
        return Ok(None);
    };
    let close = format!("</{}>", start_tag.name);
    let content_start = start_tag.end + 1;
    let content_end = text[content_start..]
        .find(&close)
        .map(|offset| content_start + offset)
        .ok_or_else(|| anyhow!("ClickOnce XML </{}> tag is not closed", start_tag.name))?;
    Ok(Some(XmlElementSpan {
        content_start,
        content_end,
    }))
}

fn find_xml_element_span_by_local_name(
    text: &str,
    local_name: &str,
    from: usize,
) -> Result<Option<(usize, usize)>> {
    let Some(start_tag) = find_xml_start_tag_by_local_name(text, local_name, from)? else {
        return Ok(None);
    };
    let close = format!("</{}>", start_tag.name);
    let content_start = start_tag.end + 1;
    let close_start = text[content_start..]
        .find(&close)
        .map(|offset| content_start + offset)
        .ok_or_else(|| anyhow!("ClickOnce XML </{}> tag is not closed", start_tag.name))?;
    Ok(Some((start_tag.start, close_start + close.len())))
}

fn find_xml_root_start_tag(text: &str) -> Result<XmlStartTagSpan> {
    let mut cursor = 0usize;
    while let Some(rel) = text[cursor..].find('<') {
        let start = cursor + rel;
        let Some(first) = text[start + 1..].chars().next() else {
            break;
        };
        if matches!(first, '?' | '!') {
            let end = text[start..]
                .find('>')
                .map(|offset| start + offset)
                .ok_or_else(|| anyhow!("ClickOnce XML declaration/comment is not closed"))?;
            cursor = end + 1;
            continue;
        }
        if first == '/' {
            return Err(anyhow!("ClickOnce XML starts with an unexpected closing tag"));
        }
        let end = text[start..]
            .find('>')
            .map(|offset| start + offset)
            .ok_or_else(|| anyhow!("ClickOnce XML root tag is not closed"))?;
        let name_start = start + 1;
        let name_end = text[name_start..=end]
            .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
            .map(|offset| name_start + offset)
            .unwrap_or(end);
        return Ok(XmlStartTagSpan {
            start,
            end,
            name: text[name_start..name_end].to_owned(),
        });
    }
    Err(anyhow!("ClickOnce manifest does not contain a root XML element"))
}

fn resolve_clickonce_manifest_path(base_directory: &Path, manifest_path: &str) -> Result<PathBuf> {
    let relative = Path::new(manifest_path);
    let mut safe = PathBuf::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => safe.push(part),
            std::path::Component::CurDir => {}
            _ => {
                return Err(anyhow!(
                    "ClickOnce manifest path must be relative and stay under the base directory: {manifest_path}"
                ));
            }
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(anyhow!("ClickOnce manifest path is empty"));
    }
    Ok(base_directory.join(safe))
}

fn clickonce_hash_alg_from_uri(uri: &str) -> Result<HashAlg> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Ok(HashAlg::Sha1),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(HashAlg::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(HashAlg::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(HashAlg::Sha512),
        other => Err(anyhow!(
            "unsupported ClickOnce digest method Algorithm: {other}"
        )),
    }
}

fn clickonce_digest_algorithm_uri(algorithm: HashAlg) -> &'static str {
    match algorithm {
        HashAlg::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        HashAlg::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        HashAlg::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        HashAlg::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    }
}

fn clickonce_signature_algorithm_uri(digest: PortableSignDigest) -> &'static str {
    match digest {
        PortableSignDigest::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        PortableSignDigest::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        PortableSignDigest::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    }
}

fn clickonce_signature_digest_uri(digest: PortableSignDigest) -> &'static str {
    match digest {
        PortableSignDigest::Sha256 => clickonce_digest_algorithm_uri(HashAlg::Sha256),
        PortableSignDigest::Sha384 => clickonce_digest_algorithm_uri(HashAlg::Sha384),
        PortableSignDigest::Sha512 => clickonce_digest_algorithm_uri(HashAlg::Sha512),
    }
}

fn clickonce_signature_digest_bytes(digest: PortableSignDigest, bytes: &[u8]) -> Vec<u8> {
    match digest {
        PortableSignDigest::Sha256 => Sha256::digest(bytes).to_vec(),
        PortableSignDigest::Sha384 => Sha384::digest(bytes).to_vec(),
        PortableSignDigest::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

fn unsigned_clickonce_manifest_text(text: &str) -> Result<String> {
    let Some((start, end)) = find_xml_element_span_by_local_name(text, "Signature", 0)? else {
        return Ok(text.to_owned());
    };
    let mut out = String::with_capacity(text.len() - (end - start));
    out.push_str(&text[..start]);
    out.push_str(&text[end..]);
    Ok(out)
}

fn clickonce_manifest_signed_info_xml(
    unsigned_manifest_text: &str,
    digest: PortableSignDigest,
) -> Vec<u8> {
    let manifest_digest = clickonce_signature_digest_bytes(digest, unsigned_manifest_text.as_bytes());
    let digest_b64 = base64_encode(&manifest_digest);
    format!(
        r#"<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="{}"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="{}"/><DigestValue>{digest_b64}</DigestValue></Reference></SignedInfo>"#,
        clickonce_signature_algorithm_uri(digest),
        clickonce_signature_digest_uri(digest),
    )
    .into_bytes()
}

fn clickonce_manifest_signature_xml(
    signed_info: &[u8],
    signature: &[u8],
    cert_der: &[u8],
) -> String {
    let signed_info = String::from_utf8_lossy(signed_info);
    format!(
        r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{signed_info}<SignatureValue>{}</SignatureValue><KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo></Signature>"#,
        base64_encode(signature),
        base64_encode(cert_der)
    )
}

fn insert_clickonce_signature_xml(unsigned_manifest_text: &str, signature_xml: &str) -> Result<String> {
    let root = find_xml_root_start_tag(unsigned_manifest_text)?;
    let close = format!("</{}>", root.name);
    let close_start = unsigned_manifest_text
        .rfind(&close)
        .ok_or_else(|| anyhow!("ClickOnce manifest root </{}> tag is not closed", root.name))?;
    let mut out = String::with_capacity(unsigned_manifest_text.len() + signature_xml.len());
    out.push_str(&unsigned_manifest_text[..close_start]);
    out.push_str(signature_xml);
    out.push_str(&unsigned_manifest_text[close_start..]);
    Ok(out)
}

fn clickonce_signed_info_from_signature_xml(signature_xml: &str) -> Result<Vec<u8>> {
    let Some((start, end)) = find_xml_element_span_by_local_name(signature_xml, "SignedInfo", 0)? else {
        return Err(anyhow!("ClickOnce manifest signature is missing SignedInfo"));
    };
    Ok(signature_xml.as_bytes()[start..end].to_vec())
}

fn clickonce_signature_value_from_signature_xml(signature_xml: &str) -> Result<Vec<u8>> {
    let value = find_xml_element_by_local_name(signature_xml, "SignatureValue", 0)?
        .ok_or_else(|| anyhow!("ClickOnce manifest signature is missing SignatureValue"))?;
    let text = &signature_xml[value.content_start..value.content_end];
    let signature = base64_decode(text.trim()).context("decode ClickOnce SignatureValue")?;
    if signature.is_empty() {
        return Err(anyhow!("ClickOnce manifest SignatureValue is empty"));
    }
    Ok(signature)
}

fn clickonce_signer_certificate_from_signature_xml(signature_xml: &str) -> Result<Vec<u8>> {
    let value = find_xml_element_by_local_name(signature_xml, "X509Certificate", 0)?
        .ok_or_else(|| anyhow!("ClickOnce manifest signature is missing X509Certificate"))?;
    let text = &signature_xml[value.content_start..value.content_end];
    let cert = base64_decode(text.trim()).context("decode ClickOnce X509Certificate")?;
    if cert.is_empty() {
        return Err(anyhow!("ClickOnce manifest X509Certificate is empty"));
    }
    Ok(cert)
}

fn sign_clickonce_manifest_path(
    path: &Path,
    cert: &Path,
    key: &Path,
    digest: PortableSignDigest,
    output: &Path,
) -> Result<ClickOnceManifestSignatureReport> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read ClickOnce manifest {}", path.display()))?;
    let unsigned = unsigned_clickonce_manifest_text(&text)?;
    let cert_bytes = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    rdp::parse_certificate(&cert_bytes)
        .with_context(|| format!("parse signer certificate {}", cert.display()))?;
    let key_bytes = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
    let private_key = rdp::parse_rsa_private_key(&key_bytes)
        .with_context(|| format!("parse RSA private key {}", key.display()))?;
    let signed_info = clickonce_manifest_signed_info_xml(&unsigned, digest);
    let signature = sign_clickonce_signed_info(digest, private_key, &signed_info)?;
    let signature_xml = clickonce_manifest_signature_xml(&signed_info, &signature, &cert_bytes);
    let signed_manifest = insert_clickonce_signature_xml(&unsigned, &signature_xml)?;
    std::fs::write(output, signed_manifest)
        .with_context(|| format!("write ClickOnce manifest {}", output.display()))?;
    Ok(ClickOnceManifestSignatureReport {
        digest,
        manifest_digest_b64: base64_encode(&clickonce_signature_digest_bytes(
            digest,
            unsigned.as_bytes(),
        )),
        signature_len: signature.len(),
    })
}

fn clickonce_signed_info_remote_prehash(
    digest: PortableSignDigest,
    signed_info: &[u8],
) -> Vec<u8> {
    clickonce_signature_digest_bytes(digest, signed_info)
}

fn sign_clickonce_manifest_from_external_signature_path(
    path: &Path,
    cert: &Path,
    signature: &Path,
    digest: PortableSignDigest,
    output: &Path,
) -> Result<ClickOnceManifestSignatureReport> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read ClickOnce manifest {}", path.display()))?;
    let unsigned = unsigned_clickonce_manifest_text(&text)?;
    let cert_bytes = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    rdp::parse_certificate(&cert_bytes)
        .with_context(|| format!("parse signer certificate {}", cert.display()))?;
    let signature = std::fs::read(signature).with_context(|| format!("read {}", signature.display()))?;
    let signed_info = clickonce_manifest_signed_info_xml(&unsigned, digest);
    let signature_xml = clickonce_manifest_signature_xml(&signed_info, &signature, &cert_bytes);
    let signed_manifest = insert_clickonce_signature_xml(&unsigned, &signature_xml)?;
    std::fs::write(output, signed_manifest)
        .with_context(|| format!("write ClickOnce manifest {}", output.display()))?;
    Ok(ClickOnceManifestSignatureReport {
        digest,
        manifest_digest_b64: base64_encode(&clickonce_signature_digest_bytes(
            digest,
            unsigned.as_bytes(),
        )),
        signature_len: signature.len(),
    })
}

fn verify_clickonce_manifest_signature_path(
    path: &Path,
    cert: Option<&Path>,
    digest: PortableSignDigest,
    shared: &TrustVerifySharedArgs,
) -> Result<ClickOnceManifestSignatureReport> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read ClickOnce manifest {}", path.display()))?;
    let unsigned = unsigned_clickonce_manifest_text(&text)?;
    let (signature_start, signature_end) = find_xml_element_span_by_local_name(&text, "Signature", 0)?
        .ok_or_else(|| anyhow!("ClickOnce manifest is missing XMLDSig Signature"))?;
    let signature_xml = &text[signature_start..signature_end];
    let signed_info = clickonce_signed_info_from_signature_xml(signature_xml)?;
    let signature = clickonce_signature_value_from_signature_xml(signature_xml)?;
    let embedded_cert = clickonce_signer_certificate_from_signature_xml(signature_xml)?;
    let cert_bytes = match cert {
        Some(path) => std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        None => embedded_cert,
    };
    let signer_cert = rdp::parse_certificate(&cert_bytes).context("parse ClickOnce signer certificate")?;
    let expected_signed_info = clickonce_manifest_signed_info_xml(&unsigned, digest);
    if signed_info != expected_signed_info {
        return Err(anyhow!("ClickOnce manifest SignedInfo does not match manifest digest"));
    }
    verify_clickonce_signed_info(digest, &signer_cert, &signed_info, &signature)?;
    if trust_verify_args_present(shared) {
        verify_xml_signer_certificate_trust(&cert_bytes, shared)?;
    }
    Ok(ClickOnceManifestSignatureReport {
        digest,
        manifest_digest_b64: base64_encode(&clickonce_signature_digest_bytes(
            digest,
            unsigned.as_bytes(),
        )),
        signature_len: signature.len(),
    })
}

fn hash_alg_label(algorithm: HashAlg) -> &'static str {
    match algorithm {
        HashAlg::Sha1 => "sha1",
        HashAlg::Sha256 => "sha256",
        HashAlg::Sha384 => "sha384",
        HashAlg::Sha512 => "sha512",
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut chunk = [0u8; 4];
    let mut chunk_len = 0usize;
    let mut padding = 0usize;
    for ch in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                0
            }
            _ => return Err(anyhow!("invalid base64 character in XMLDSig value")),
        };
        chunk[chunk_len] = value;
        chunk_len += 1;
        if chunk_len == 4 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            if padding < 2 {
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
            }
            if padding == 0 {
                out.push((chunk[2] << 6) | chunk[3]);
            }
            chunk_len = 0;
            padding = 0;
        }
    }
    if chunk_len != 0 {
        return Err(anyhow!("truncated base64 XMLDSig value"));
    }
    Ok(out)
}

fn inspect_business_central_app(path: &Path) -> Result<BusinessCentralAppInfo> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(BusinessCentralAppInfo {
        is_navx: bytes.starts_with(b"NAVX"),
        len: bytes.len() as u64,
    })
}

fn inspect_msix_manifest_path(path: &Path) -> Result<MsixManifestInfo> {
    reject_encrypted_msix_path(path)?;
    let manifest = read_msix_manifest(path)?;
    let identity = first_tag(&manifest, "Identity")
        .ok_or_else(|| anyhow!("MSIX/AppX AppxManifest.xml is missing Identity"))?;
    Ok(MsixManifestInfo {
        package_name: xml_attr(identity, "Name"),
        publisher: xml_attr(identity, "Publisher"),
        version: xml_attr(identity, "Version"),
        processor_architecture: xml_attr(identity, "ProcessorArchitecture"),
    })
}

fn set_msix_manifest_publisher_path(input: &Path, output: &Path, publisher: &str) -> Result<()> {
    reject_encrypted_msix_path(input)?;
    if publisher.is_empty() {
        return Err(anyhow!("MSIX/AppX publisher cannot be empty"));
    }
    let reader = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let writer = File::create(output).with_context(|| format!("create {}", output.display()))?;
    set_msix_manifest_publisher(reader, writer, publisher)
        .with_context(|| format!("set MSIX/AppX manifest publisher in {}", input.display()))
}

fn reject_encrypted_msix_path(path: &Path) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if psign_sip_digest::msix_digest::is_encrypted_msix_extension(&ext) {
        return Err(anyhow!(
            "encrypted MSIX/AppX packages (.eappx/.emsix) require Windows AppxSip OS delegation; portable cleartext package helpers cannot inspect or update {}",
            path.display()
        ));
    }
    Ok(())
}

fn read_msix_manifest(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("open MSIX/AppX ZIP")?;
    let mut manifest = archive
        .by_name("AppxManifest.xml")
        .context("read AppxManifest.xml")?;
    let mut text = String::new();
    manifest
        .read_to_string(&mut text)
        .context("read AppxManifest.xml as UTF-8")?;
    Ok(text)
}

fn set_msix_manifest_publisher<R, W>(reader: R, writer: W, publisher: &str) -> Result<()>
where
    R: std::io::Read + std::io::Seek,
    W: std::io::Write + std::io::Seek,
{
    let escaped = xml_escape_attr(publisher);
    let mut input = zip::ZipArchive::new(reader).context("open MSIX/AppX ZIP")?;
    if input.by_name("AppxSignature.p7x").is_ok() {
        return Err(anyhow!(
            "MSIX/AppX package already contains AppxSignature.p7x; update the unsigned package before final signing"
        ));
    }
    let mut output = zip::ZipWriter::new(writer);
    let mut updated_manifest = false;

    for i in 0..input.len() {
        let mut file = input.by_index(i).context("read MSIX/AppX ZIP entry")?;
        let name = psign_opc_sign::opc::normalize_zip_part_name(file.name())?;
        let options = zip::write::FileOptions::default().compression_method(file.compression());
        if file.is_dir() {
            output.add_directory(name, options)?;
            continue;
        }
        output.start_file(&name, options)?;
        if name == "AppxManifest.xml" {
            let mut text = String::new();
            file.read_to_string(&mut text)
                .context("read AppxManifest.xml as UTF-8")?;
            let updated = update_attr_for_tags(&text, "Identity", "Publisher", &escaped)?;
            output.write_all(updated.as_bytes())?;
            updated_manifest = true;
        } else {
            std::io::copy(&mut file, &mut output)?;
        }
    }

    if !updated_manifest {
        return Err(anyhow!("MSIX/AppX package is missing AppxManifest.xml"));
    }
    output.finish()?;
    Ok(())
}

fn parse_appinstaller_descriptor(text: &str) -> Result<AppInstallerDescriptorInfo> {
    let root_start = text
        .find("<AppInstaller")
        .ok_or_else(|| anyhow!("App Installer descriptor root <AppInstaller> not found"))?;
    let root_end = text[root_start..]
        .find('>')
        .map(|offset| root_start + offset)
        .ok_or_else(|| anyhow!("App Installer root tag is not closed"))?;
    let root_tag = &text[root_start..=root_end];
    let namespace = xml_attr(root_tag, "xmlns");
    let main_package =
        first_start_tag_by_local_name(text, "MainPackage").context("parse MainPackage tag")?;
    let main_bundle =
        first_start_tag_by_local_name(text, "MainBundle").context("parse MainBundle tag")?;
    let has_main_package = main_package.is_some();
    let has_main_bundle = main_bundle.is_some();
    let publisher = main_package
        .and_then(|tag| xml_attr(tag, "Publisher"))
        .or_else(|| main_bundle.and_then(|tag| xml_attr(tag, "Publisher")));
    Ok(AppInstallerDescriptorInfo {
        root: "AppInstaller",
        namespace,
        has_main_package,
        has_main_bundle,
        publisher,
    })
}

fn update_appinstaller_publisher(text: &str, publisher: &str) -> Result<String> {
    if publisher.is_empty() {
        return Err(anyhow!("App Installer publisher cannot be empty"));
    }
    let info = parse_appinstaller_descriptor(text)?;
    if !info.has_main_package && !info.has_main_bundle {
        return Err(anyhow!(
            "App Installer descriptor does not contain MainPackage or MainBundle"
        ));
    }

    let escaped = xml_escape_attr(publisher);
    let mut updated = text.to_owned();
    for tag in ["MainPackage", "MainBundle"] {
        updated = update_attr_for_local_tags(&updated, tag, "Publisher", &escaped)?;
    }
    Ok(updated)
}

fn sign_pkcs7_id_data(
    content: &[u8],
    cert: &Path,
    key: &Path,
    chain_certs: Vec<PathBuf>,
    digest: PortableSignDigest,
    content_mode: pkcs7::Pkcs7ContentMode,
    signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile,
) -> Result<Vec<u8>> {
    let (signer_cert, chain) = load_cms_signer_material(cert, chain_certs)?;
    let key_bytes = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
    let private_key = rdp::parse_rsa_private_key(&key_bytes)
        .with_context(|| format!("parse RSA private key {}", key.display()))?;
    let econtent_der = id_data_econtent_der(content)?;
    let signed_attrs = pkcs7::pkcs7_signed_attrs(
        pkcs7_id_data_oid()?,
        &econtent_der,
        digest.into(),
        signed_attribute_profile,
        Some(&signer_cert),
    )?;
    let prehash = pkcs7::pkcs7_signed_attrs_digest(&signed_attrs, digest.into())?;
    let signature = sign_pkcs7_signed_attrs_digest(digest.into(), private_key, &prehash)?;
    pkcs7::create_pkcs7_signed_data_der_with_signed_attrs_and_rsa_signature(
        pkcs7::Pkcs7SignedDataDerInput {
            econtent_type: pkcs7_id_data_oid()?,
            econtent_der: &econtent_der,
            digest_algorithm: digest.into(),
            signer_cert,
            chain_certs: chain,
            encrypted_digest: &signature,
            content_mode,
            signed_attrs,
        },
    )
}

fn load_cms_signer_material(
    cert: &Path,
    chain_certs: Vec<PathBuf>,
) -> Result<(x509_cert::Certificate, Vec<x509_cert::Certificate>)> {
    let cert_bytes = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    let signer_cert = rdp::parse_certificate(&cert_bytes)
        .with_context(|| format!("parse signer certificate {}", cert.display()))?;
    let mut chain = Vec::with_capacity(chain_certs.len());
    for chain_cert in chain_certs {
        let bytes =
            std::fs::read(&chain_cert).with_context(|| format!("read {}", chain_cert.display()))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
        );
    }
    Ok((signer_cert, chain))
}

fn id_data_econtent_der(content: &[u8]) -> Result<Vec<u8>> {
    OctetString::new(content.to_vec())
        .map_err(|e| anyhow!("encode CMS id-data OCTET STRING: {e}"))?
        .to_der()
        .map_err(|e| anyhow!("encode CMS id-data DER: {e}"))
}

fn pkcs7_id_data_oid() -> Result<ObjectIdentifier> {
    ObjectIdentifier::new(pkcs7::PKCS7_ID_DATA_OID)
        .map_err(|e| anyhow!("parse CMS id-data OID: {e}"))
}

fn sign_pkcs7_signed_attrs_digest(
    digest: pkcs7::AuthenticodeSigningDigest,
    private_key: rsa::RsaPrivateKey,
    signed_attrs_digest: &[u8],
) -> Result<Vec<u8>> {
    let signature = match digest {
        pkcs7::AuthenticodeSigningDigest::Sha256 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
            key.sign_prehash(signed_attrs_digest)
                .map_err(|e| anyhow!("RSA/SHA-256 signed attributes prehash sign: {e}"))?
                .to_bytes()
                .to_vec()
        }
        pkcs7::AuthenticodeSigningDigest::Sha384 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha384>::new(private_key);
            key.sign_prehash(signed_attrs_digest)
                .map_err(|e| anyhow!("RSA/SHA-384 signed attributes prehash sign: {e}"))?
                .to_bytes()
                .to_vec()
        }
        pkcs7::AuthenticodeSigningDigest::Sha512 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha512>::new(private_key);
            key.sign_prehash(signed_attrs_digest)
                .map_err(|e| anyhow!("RSA/SHA-512 signed attributes prehash sign: {e}"))?
                .to_bytes()
                .to_vec()
        }
    };
    Ok(signature)
}

fn pkcs7_id_data_remote_prehash(
    content: &[u8],
    digest: PortableSignDigest,
    signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile,
    signer_cert: Option<&x509_cert::Certificate>,
) -> Result<Vec<u8>> {
    let econtent_der = id_data_econtent_der(content)?;
    pkcs7::pkcs7_remote_rsa_signed_attrs_digest_with_profile(
        pkcs7_id_data_oid()?,
        &econtent_der,
        digest.into(),
        signed_attribute_profile,
        signer_cert,
    )
}

fn sign_pkcs7_id_data_with_external_signature(
    content: &[u8],
    cert: &Path,
    chain_certs: Vec<PathBuf>,
    digest: PortableSignDigest,
    signature: &[u8],
    content_mode: pkcs7::Pkcs7ContentMode,
    signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile,
) -> Result<Vec<u8>> {
    let (signer_cert, chain) = load_cms_signer_material(cert, chain_certs)?;
    let econtent_der = id_data_econtent_der(content)?;
    let signed_attrs = pkcs7::pkcs7_signed_attrs(
        pkcs7_id_data_oid()?,
        &econtent_der,
        digest.into(),
        signed_attribute_profile,
        Some(&signer_cert),
    )?;
    pkcs7::create_pkcs7_signed_data_der_with_signed_attrs_and_rsa_signature(
        pkcs7::Pkcs7SignedDataDerInput {
            econtent_type: pkcs7_id_data_oid()?,
            econtent_der: &econtent_der,
            digest_algorithm: digest.into(),
            signer_cert,
            chain_certs: chain,
            encrypted_digest: signature,
            content_mode,
            signed_attrs,
        },
    )
}

fn update_attr_for_tags(text: &str, tag: &str, attr: &str, escaped_value: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let needle = format!("<{tag}");
    while let Some(rel_start) = text[cursor..].find(&needle) {
        let start = cursor + rel_start;
        let end = text[start..]
            .find('>')
            .map(|offset| start + offset)
            .ok_or_else(|| anyhow!("App Installer <{tag}> tag is not closed"))?;
        out.push_str(&text[cursor..start]);
        out.push_str(&replace_or_insert_xml_attr(
            &text[start..=end],
            attr,
            escaped_value,
        )?);
        cursor = end + 1;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

fn update_attr_for_local_tags(
    text: &str,
    local_name: &str,
    attr: &str,
    escaped_value: &str,
) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while let Some(tag) = find_xml_start_tag_by_local_name(text, local_name, cursor)? {
        out.push_str(&text[cursor..tag.start]);
        out.push_str(&replace_or_insert_xml_attr(
            &text[tag.start..=tag.end],
            attr,
            escaped_value,
        )?);
        cursor = tag.end + 1;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

fn replace_or_insert_xml_attr(tag: &str, attr: &str, escaped_value: &str) -> Result<String> {
    let needle = format!("{attr}=\"");
    if let Some(value_start) = tag.find(&needle).map(|idx| idx + needle.len()) {
        let value_end = tag[value_start..]
            .find('"')
            .map(|offset| value_start + offset)
            .ok_or_else(|| anyhow!("App Installer {attr} attribute is not closed"))?;
        let mut out = String::with_capacity(tag.len() + escaped_value.len());
        out.push_str(&tag[..value_start]);
        out.push_str(escaped_value);
        out.push_str(&tag[value_end..]);
        return Ok(out);
    }

    let insert_at = tag
        .rfind("/>")
        .or_else(|| tag.rfind('>'))
        .ok_or_else(|| anyhow!("App Installer tag is not closed"))?;
    let mut out = String::with_capacity(tag.len() + attr.len() + escaped_value.len() + 4);
    out.push_str(&tag[..insert_at]);
    out.push(' ');
    out.push_str(attr);
    out.push_str("=\"");
    out.push_str(escaped_value);
    out.push('"');
    out.push_str(&tag[insert_at..]);
    Ok(out)
}

fn xml_escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn first_tag<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let start = text.find(&format!("<{tag}"))?;
    let end = text[start..].find('>').map(|offset| start + offset)?;
    Some(&text[start..=end])
}

fn first_start_tag_by_local_name<'a>(text: &'a str, local_name: &str) -> Result<Option<&'a str>> {
    Ok(find_xml_start_tag_by_local_name(text, local_name, 0)?
        .map(|tag| &text[tag.start..=tag.end]))
}

fn xml_attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_owned())
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

#[cfg(feature = "timestamp-http")]
fn post_rfc3161_timestamp_request(
    url: &str,
    algorithm: HashAlg,
    message_imprint: &[u8],
) -> Result<Vec<u8>> {
    if message_imprint.len() != digest_byte_len_for_hash_alg(algorithm) {
        return Err(anyhow!(
            "timestamp message imprint must be exactly {} bytes for {:?}, got {}",
            digest_byte_len_for_hash_alg(algorithm),
            algorithm,
            message_imprint.len()
        ));
    }
    let plan = Rfc3161TimestampRequestPlan {
        digest_alg_oid: hash_alg_timestamp_oid(algorithm),
        nonce: None,
        cert_req: true,
    };
    let der = build_timestamp_request_bytes(&plan, message_imprint).ok_or_else(|| {
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
    Ok(body.to_vec())
}

#[cfg(feature = "timestamp-http")]
fn timestamp_pkcs7_der_rfc3161(
    pkcs7_der: &[u8],
    timestamp_url: &str,
    timestamp_digest: HashAlg,
    timestamp_attribute: Rfc3161TimestampAttribute,
) -> Result<Vec<u8>> {
    let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7_der).context("parse PKCS#7 SignedData")?;
    let signer = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("PKCS#7 SignedData has no SignerInfo to timestamp"))?;
    let imprint = digest_bytes_for_hash_alg(timestamp_digest, signer.signature.as_bytes());
    let response = post_rfc3161_timestamp_request(timestamp_url, timestamp_digest, &imprint)?;
    let parsed = parse_time_stamp_resp_der(&response)
        .ok_or_else(|| anyhow!("could not parse TimeStampResp DER from TSA response"))?;
    if !parsed.pki_status.granted() {
        return Err(anyhow!(
            "TimeStampResp status is not granted (status={})",
            parsed.pki_status.as_raw_integer()
        ));
    }
    let token = parsed
        .time_stamp_token
        .ok_or_else(|| anyhow!("TimeStampResp has no timeStampToken"))?;
    let stamped = match timestamp_attribute {
        Rfc3161TimestampAttribute::MicrosoftAuthenticode => {
            pkcs7::signed_data_add_rfc3161_timestamp_token(&sd, 0, token)
        }
        Rfc3161TimestampAttribute::CmsTimeStampToken => {
            pkcs7::signed_data_add_pkcs9_rfc3161_timestamp_token(&sd, 0, token)
        }
    }
    .context("attach RFC3161 timestamp token")?;
    pkcs7::encode_pkcs7_content_info_signed_data_der(&stamped)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rfc3161TimestampAttribute {
    MicrosoftAuthenticode,
    CmsTimeStampToken,
}

fn timestamp_pkcs7_if_requested(
    pkcs7_der: &[u8],
    timestamp_url: Option<String>,
    timestamp_digest: Option<HashAlg>,
    timestamp_attribute: Rfc3161TimestampAttribute,
    context: &str,
) -> Result<Vec<u8>> {
    match (timestamp_url, timestamp_digest) {
        (Some(url), Some(timestamp_digest)) => {
            #[cfg(feature = "timestamp-http")]
            {
                timestamp_pkcs7_der_rfc3161(pkcs7_der, &url, timestamp_digest, timestamp_attribute)
                    .with_context(|| format!("RFC3161 timestamp {context}"))
            }
            #[cfg(not(feature = "timestamp-http"))]
            {
                let _ = (url, timestamp_digest, timestamp_attribute);
                Err(anyhow!(
                    "{context} RFC3161 timestamping requires the timestamp-http feature"
                ))
            }
        }
        (Some(_), None) => Err(anyhow!("{context} requires --timestamp-digest with --timestamp-url")),
        (None, Some(_)) => Err(anyhow!("{context} requires --timestamp-url with --timestamp-digest")),
        (None, None) => Ok(pkcs7_der.to_vec()),
    }
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
    /// Custom ZIP Authenticode comment signature: verify ZIP digest binding plus PKCS#7 chain to anchors.
    TrustVerifyZip {
        path: PathBuf,
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
    /// PKCS#1 v1.5 keys or Azure Key Vault RSA signing and SHA-2 digests; timestamp embedding and
    /// non-PE formats remain separate backlog.
    SignPe {
        /// Input PE path.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: Option<PathBuf>,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// File digest algorithm for the PE Authenticode indirect digest and CMS signer.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// RFC3161 timestamp URL to timestamp the primary PE signature after signing.
        #[arg(long = "timestamp-url", visible_alias = "tr")]
        timestamp_url: Option<String>,
        /// RFC3161 timestamp digest algorithm.
        #[arg(long = "timestamp-digest", visible_alias = "td", value_enum)]
        timestamp_digest: Option<HashAlg>,
        /// Azure Key Vault URL for remote RSA signing.
        #[arg(long = "azure-key-vault-url", visible_alias = "kvu")]
        azure_key_vault_url: Option<String>,
        /// Azure Key Vault certificate name for remote RSA signing.
        #[arg(long = "azure-key-vault-certificate", visible_alias = "kvc")]
        azure_key_vault_certificate: Option<String>,
        /// Optional Azure Key Vault certificate version.
        #[arg(long = "azure-key-vault-certificate-version", visible_alias = "kvcv")]
        azure_key_vault_certificate_version: Option<String>,
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
        #[command(flatten)]
        artifact_signing: Box<ArtifactSigningPortableOptions>,
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
    /// Custom ZIP Authenticode comment signature: compare ZIP digest binding and reconstructed script digest.
    VerifyZip { path: PathBuf },
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
    /// Inspect cleartext MSIX/AppX `AppxManifest.xml` Identity metadata.
    MsixManifestInfo { path: PathBuf },
    /// Update cleartext MSIX/AppX `AppxManifest.xml` Identity Publisher before final signing.
    MsixSetPublisher {
        path: PathBuf,
        #[arg(long, value_name = "SUBJECT")]
        publisher: String,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Inspect a ClickOnce `.deploy` payload and report the undeployed content name.
    ClickonceDeployInfo { path: PathBuf },
    /// Copy a ClickOnce `.deploy` payload to an explicit undeployed output path.
    ClickonceCopyDeployPayload {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Verify file hashes recorded in a ClickOnce application or deployment manifest.
    ClickonceManifestHashes {
        path: PathBuf,
        #[arg(long, value_name = "DIR")]
        base_directory: Option<PathBuf>,
    },
    /// Update file size and digest values in a ClickOnce application or deployment manifest.
    ClickonceUpdateManifestHashes {
        path: PathBuf,
        #[arg(long, value_name = "DIR")]
        base_directory: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Add a deterministic portable XMLDSig signature to a ClickOnce manifest.
    ///
    /// This is a portable structural helper for tests and non-Mage workflows; it does not claim
    /// byte-for-byte Mage output or ClickOnce policy validation.
    ClickonceSignManifest {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Compute the SignedInfo digest for externally signing ClickOnce manifest XMLDSig.
    ClickonceSignManifestPrehash {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Add a deterministic ClickOnce manifest XMLDSig from externally produced RSA signature bytes.
    ClickonceSignManifestFromSignature {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// Raw RSA PKCS#1 v1.5 signature bytes produced over `clickonce-sign-manifest-prehash`.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Verify the deterministic portable XMLDSig signature in a ClickOnce manifest.
    ClickonceVerifyManifestSignature {
        path: PathBuf,
        /// Signer certificate as DER or PEM. Defaults to the embedded KeyInfo certificate.
        #[arg(long, value_name = "PATH")]
        cert: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
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
    /// Write NuGet signature content bytes (`Version` + package hash property) for an unsigned package.
    ///
    /// This is the CMS encapsulated content used by NuGet author signatures before `.signature.p7s` is embedded.
    NupkgSignatureContent {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Create local RSA/SHA-2 CMS for NuGet signature content bytes.
    NupkgSignaturePkcs7 {
        path: PathBuf,
        /// Package hash and CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// RFC3161 timestamp URL to timestamp the NuGet CMS signature after signing.
        #[arg(long = "timestamp-url", visible_alias = "tr")]
        timestamp_url: Option<String>,
        /// RFC3161 timestamp digest algorithm.
        #[arg(long = "timestamp-digest", visible_alias = "td", value_enum)]
        timestamp_digest: Option<HashAlg>,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Compute the signed-attributes digest for externally signing NuGet CMS.
    ///
    /// Sign this digest with RSA PKCS#1 v1.5 using the selected SHA-2 algorithm, then pass the
    /// signature bytes to `nupkg-signature-pkcs7-from-signature`. Split NuGet signing uses stable
    /// author attributes (`commitmentTypeIndication` and `signingCertificateV2`) without
    /// `signingTime` so both CLI steps can reconstruct the same signed attributes.
    NupkgSignaturePkcs7Prehash {
        path: PathBuf,
        /// Package hash and CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        /// Signer certificate as DER or PEM. Required because NuGet author signatures sign ESSCertIDv2.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Create NuGet CMS from externally produced RSA PKCS#1 v1.5 signature bytes.
    NupkgSignaturePkcs7FromSignature {
        path: PathBuf,
        /// Package hash and CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// Raw RSA PKCS#1 v1.5 signature bytes produced over `nupkg-signature-pkcs7-prehash`.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        /// RFC3161 timestamp URL to timestamp the NuGet CMS signature after assembly.
        #[arg(long = "timestamp-url", visible_alias = "tr")]
        timestamp_url: Option<String>,
        /// RFC3161 timestamp digest algorithm.
        #[arg(long = "timestamp-digest", visible_alias = "td", value_enum)]
        timestamp_digest: Option<HashAlg>,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Create and embed a local RSA/SHA-2 NuGet `.signature.p7s` signature.
    NupkgSign {
        path: PathBuf,
        /// Package hash and CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// RFC3161 timestamp URL to timestamp the NuGet CMS signature after signing.
        #[arg(long = "timestamp-url", visible_alias = "tr")]
        timestamp_url: Option<String>,
        /// RFC3161 timestamp digest algorithm.
        #[arg(long = "timestamp-digest", visible_alias = "td", value_enum)]
        timestamp_digest: Option<HashAlg>,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Verify NuGet signature content bytes against an unsigned package hash.
    NupkgVerifySignatureContent {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        content: PathBuf,
    },
    /// Verify an embedded NuGet `.signature.p7s` against package content and explicit trust anchors.
    NupkgVerifySignature {
        path: PathBuf,
        /// Package hash and CMS signer digest algorithm used to reconstruct NuGet signature content.
        #[arg(long, value_enum, default_value_t = NugetHashAlg::Sha256)]
        algorithm: NugetHashAlg,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Embed a NuGet package author signature blob as root `.signature.p7s`.
    ///
    /// This is a package-native write primitive for split signing workflows; it does not create CMS.
    NupkgEmbedSignature {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Inspect VSIX OPC signature marker state without validating XMLDSig.
    VsixSignatureInfo { path: PathBuf },
    /// Embed a VSIX OPC signature XML part and signature-origin marker.
    ///
    /// This is a structural write primitive for split XMLDSig workflows; it does not create XMLDSig.
    VsixEmbedSignatureXml {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        signature_xml: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Write deterministic VSIX XMLDSig Reference/DigestValue XML for package parts.
    VsixSignatureReferenceXml {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Create deterministic VSIX XMLDSig XML with local RSA/SHA-2 SignatureValue.
    VsixSignatureXml {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Compute the SignedInfo digest for externally signing VSIX XMLDSig.
    ///
    /// Sign this digest with RSA PKCS#1 v1.5 using the selected SHA-2 algorithm, then pass the
    /// signature bytes to `vsix-signature-xml-from-signature`.
    VsixSignatureXmlPrehash {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Create deterministic VSIX XMLDSig XML from externally produced RSA signature bytes.
    VsixSignatureXmlFromSignature {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// Raw RSA PKCS#1 v1.5 signature bytes produced over `vsix-signature-xml-prehash`.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Create and embed deterministic VSIX XMLDSig XML with local RSA/SHA-2 SignatureValue.
    VsixSign {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Verify VSIX XMLDSig Reference/DigestValue XML against package parts.
    VsixVerifySignatureReferenceXml {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        signature_xml: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
    },
    /// Verify deterministic VSIX XMLDSig references and local RSA/SHA-2 SignatureValue.
    VsixVerifySignatureXml {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        signature_xml: PathBuf,
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Verify an embedded VSIX OPC XMLDSig signature part.
    VsixVerifySignature {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        cert: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = VsixHashAlg::Sha256)]
        algorithm: VsixHashAlg,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Inspect an App Installer descriptor and optional detached PKCS#7 companion signature.
    AppinstallerInfo {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        signature: Option<PathBuf>,
    },
    /// Verify an App Installer XML descriptor against its detached PKCS#7 companion signature.
    AppinstallerVerifyCompanion {
        path: PathBuf,
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Create a detached PKCS#7 companion signature for an App Installer XML descriptor.
    AppinstallerSignCompanion {
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
        /// CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// RFC3161 timestamp URL to timestamp the companion CMS signature after signing.
        #[arg(long = "timestamp-url", visible_alias = "tr")]
        timestamp_url: Option<String>,
        /// RFC3161 timestamp digest algorithm.
        #[arg(long = "timestamp-digest", visible_alias = "td", value_enum)]
        timestamp_digest: Option<HashAlg>,
        /// Output detached PKCS#7 companion path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Compute the CMS authenticated-attributes digest for externally signing an App Installer companion.
    AppinstallerSignCompanionPrehash {
        path: PathBuf,
        /// CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        #[arg(long, value_enum, default_value_t = DigestEncoding::Hex)]
        encoding: DigestEncoding,
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Create an App Installer companion PKCS#7 from externally produced RSA signature bytes.
    AppinstallerSignCompanionFromSignature {
        path: PathBuf,
        /// Signer certificate as DER or PEM.
        #[arg(long, value_name = "PATH")]
        cert: PathBuf,
        /// Additional certificate to include in the PKCS#7 certificate set.
        #[arg(long = "chain-cert", value_name = "PATH")]
        chain_certs: Vec<PathBuf>,
        /// CMS signer digest algorithm.
        #[arg(long, value_enum, default_value_t = PortableSignDigest::Sha256)]
        digest: PortableSignDigest,
        /// Raw RSA PKCS#1 v1.5 signature bytes produced over `appinstaller-sign-companion-prehash`.
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        /// RFC3161 timestamp URL to timestamp the companion CMS signature after assembly.
        #[arg(long = "timestamp-url", visible_alias = "tr")]
        timestamp_url: Option<String>,
        /// RFC3161 timestamp digest algorithm.
        #[arg(long = "timestamp-digest", visible_alias = "td", value_enum)]
        timestamp_digest: Option<HashAlg>,
        /// Output detached PKCS#7 companion path.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Update MainPackage/MainBundle Publisher attributes in an App Installer descriptor.
    AppinstallerSetPublisher {
        path: PathBuf,
        #[arg(long, value_name = "SUBJECT")]
        publisher: String,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Inspect a Dynamics 365 Business Central `.app` package header.
    BusinessCentralAppInfo { path: PathBuf },
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

#[cfg(feature = "azure-kv-sign-portable")]
impl From<PortableSignDigest> for KvHashAlg {
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

impl From<NugetHashAlg> for PortableSignDigest {
    fn from(value: NugetHashAlg) -> Self {
        match value {
            NugetHashAlg::Sha256 => Self::Sha256,
            NugetHashAlg::Sha384 => Self::Sha384,
            NugetHashAlg::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum VsixHashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl From<VsixHashAlg> for vsix::VsixHashAlgorithm {
    fn from(value: VsixHashAlg) -> Self {
        match value {
            VsixHashAlg::Sha256 => Self::Sha256,
            VsixHashAlg::Sha384 => Self::Sha384,
            VsixHashAlg::Sha512 => Self::Sha512,
        }
    }
}

fn nuget_hash_alg_label(value: nuget::NuGetHashAlgorithm) -> &'static str {
    match value {
        nuget::NuGetHashAlgorithm::Sha256 => "sha256",
        nuget::NuGetHashAlgorithm::Sha384 => "sha384",
        nuget::NuGetHashAlgorithm::Sha512 => "sha512",
    }
}

fn vsix_hash_alg_label(value: vsix::VsixHashAlgorithm) -> &'static str {
    match value {
        vsix::VsixHashAlgorithm::Sha256 => "sha256",
        vsix::VsixHashAlgorithm::Sha384 => "sha384",
        vsix::VsixHashAlgorithm::Sha512 => "sha512",
    }
}

fn sign_xml_signed_info(
    algorithm: vsix::VsixHashAlgorithm,
    private_key: rsa::RsaPrivateKey,
    signed_info: &[u8],
) -> Result<Vec<u8>> {
    let signature = match algorithm {
        vsix::VsixHashAlgorithm::Sha256 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
            key.sign(signed_info).to_vec()
        }
        vsix::VsixHashAlgorithm::Sha384 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha384>::new(private_key);
            key.sign(signed_info).to_vec()
        }
        vsix::VsixHashAlgorithm::Sha512 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha512>::new(private_key);
            key.sign(signed_info).to_vec()
        }
    };
    Ok(signature)
}

fn sign_clickonce_signed_info(
    digest: PortableSignDigest,
    private_key: rsa::RsaPrivateKey,
    signed_info: &[u8],
) -> Result<Vec<u8>> {
    let signature = match digest {
        PortableSignDigest::Sha256 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
            key.sign(signed_info).to_vec()
        }
        PortableSignDigest::Sha384 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha384>::new(private_key);
            key.sign(signed_info).to_vec()
        }
        PortableSignDigest::Sha512 => {
            let key = rsa::pkcs1v15::SigningKey::<Sha512>::new(private_key);
            key.sign(signed_info).to_vec()
        }
    };
    Ok(signature)
}

fn xml_signed_info_remote_prehash(
    algorithm: vsix::VsixHashAlgorithm,
    signed_info: &[u8],
) -> Vec<u8> {
    match algorithm {
        vsix::VsixHashAlgorithm::Sha256 => Sha256::digest(signed_info).to_vec(),
        vsix::VsixHashAlgorithm::Sha384 => Sha384::digest(signed_info).to_vec(),
        vsix::VsixHashAlgorithm::Sha512 => Sha512::digest(signed_info).to_vec(),
    }
}

fn verify_xml_signed_info(
    algorithm: vsix::VsixHashAlgorithm,
    signer_cert: &x509_cert::Certificate,
    signed_info: &[u8],
    signature: &[u8],
) -> Result<()> {
    let spki_der = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("encode signer certificate SubjectPublicKeyInfo: {e}"))?;
    let public_key = rsa::RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| anyhow!("RSA public key from signer certificate: {e}"))?;
    match algorithm {
        vsix::VsixHashAlgorithm::Sha256 => {
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| anyhow!("VSIX SignatureValue PKCS#1 v1.5 octets: {e}"))?;
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key)
                .verify(signed_info, &signature)
                .map_err(|e| anyhow!("verify VSIX SignatureValue: {e}"))?;
        }
        vsix::VsixHashAlgorithm::Sha384 => {
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| anyhow!("VSIX SignatureValue PKCS#1 v1.5 octets: {e}"))?;
            rsa::pkcs1v15::VerifyingKey::<Sha384>::new(public_key)
                .verify(signed_info, &signature)
                .map_err(|e| anyhow!("verify VSIX SignatureValue: {e}"))?;
        }
        vsix::VsixHashAlgorithm::Sha512 => {
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| anyhow!("VSIX SignatureValue PKCS#1 v1.5 octets: {e}"))?;
            rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public_key)
                .verify(signed_info, &signature)
                .map_err(|e| anyhow!("verify VSIX SignatureValue: {e}"))?;
        }
    }
    Ok(())
}

fn verify_clickonce_signed_info(
    digest: PortableSignDigest,
    signer_cert: &x509_cert::Certificate,
    signed_info: &[u8],
    signature: &[u8],
) -> Result<()> {
    let spki_der = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("encode signer certificate SubjectPublicKeyInfo: {e}"))?;
    let public_key = rsa::RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| anyhow!("RSA public key from signer certificate: {e}"))?;
    match digest {
        PortableSignDigest::Sha256 => {
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| anyhow!("ClickOnce SignatureValue PKCS#1 v1.5 octets: {e}"))?;
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key)
                .verify(signed_info, &signature)
                .map_err(|e| anyhow!("verify ClickOnce SignatureValue: {e}"))?;
        }
        PortableSignDigest::Sha384 => {
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| anyhow!("ClickOnce SignatureValue PKCS#1 v1.5 octets: {e}"))?;
            rsa::pkcs1v15::VerifyingKey::<Sha384>::new(public_key)
                .verify(signed_info, &signature)
                .map_err(|e| anyhow!("verify ClickOnce SignatureValue: {e}"))?;
        }
        PortableSignDigest::Sha512 => {
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| anyhow!("ClickOnce SignatureValue PKCS#1 v1.5 octets: {e}"))?;
            rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public_key)
                .verify(signed_info, &signature)
                .map_err(|e| anyhow!("verify ClickOnce SignatureValue: {e}"))?;
        }
    }
    Ok(())
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
    #[arg(long, default_value = DEFAULT_API_VERSION)]
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
    /// Override data-plane origin for deterministic local tests.
    #[arg(long, hide = true)]
    endpoint_base_url: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
struct ArtifactSigningPortableOptions {
    /// Artifact Signing metadata JSON (same shape as Microsoft's dlib /dmdf file).
    #[arg(long = "artifact-signing-metadata", value_name = "PATH")]
    metadata: Option<PathBuf>,
    /// Regional hostname segment, e.g. `westus`, when not using metadata Endpoint.
    #[arg(long = "artifact-signing-region")]
    region: Option<String>,
    /// Explicit data-plane endpoint, e.g. `https://wus2.codesigning.azure.net`.
    #[arg(long = "artifact-signing-endpoint")]
    endpoint: Option<String>,
    #[arg(long = "artifact-signing-account-name")]
    account_name: Option<String>,
    #[arg(long = "artifact-signing-profile-name")]
    profile_name: Option<String>,
    #[arg(long = "artifact-signing-signature-algorithm")]
    signature_algorithm: Option<String>,
    #[arg(long = "artifact-signing-api-version")]
    api_version: Option<String>,
    #[arg(long = "artifact-signing-correlation-id")]
    correlation_id: Option<String>,
    #[arg(long = "artifact-signing-access-token")]
    access_token: Option<String>,
    #[arg(long = "artifact-signing-managed-identity")]
    managed_identity: bool,
    #[arg(long = "artifact-signing-tenant-id")]
    tenant_id: Option<String>,
    #[arg(long = "artifact-signing-client-id")]
    client_id: Option<String>,
    #[arg(long = "artifact-signing-client-secret")]
    client_secret: Option<String>,
    #[arg(long = "artifact-signing-authority")]
    authority: Option<String>,
    /// Override data-plane origin for deterministic local tests.
    #[arg(long = "artifact-signing-endpoint-base-url", hide = true)]
    endpoint_base_url: Option<String>,
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
        endpoint_base_url: args.endpoint_base_url,
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
#[derive(Clone, Copy)]
struct KvPortableAuthInputs<'a> {
    access_token: Option<&'a str>,
    managed_identity: bool,
    tenant_id: Option<&'a str>,
    client_id: Option<&'a str>,
    client_secret: Option<&'a str>,
}

#[cfg(feature = "azure-kv-sign-portable")]
fn validate_kv_portable_auth_inputs(args: KvPortableAuthInputs<'_>) -> Result<()> {
    let has_sp = args.client_secret.map(|s| !s.trim().is_empty()) == Some(true);
    let has_tenant = args.tenant_id.map(|s| !s.trim().is_empty()) == Some(true);
    let has_client = args.client_id.map(|s| !s.trim().is_empty()) == Some(true);
    let has_token = args.access_token.map(|s| !s.trim().is_empty()) == Some(true);

    let sp_count = has_sp as u8 + has_tenant as u8 + has_client as u8;
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "Azure AD client credentials require all of --azure-key-vault-client-id, --azure-key-vault-client-secret, and --azure-key-vault-tenant-id"
        ));
    }

    if has_token && (args.managed_identity || sp_count == 3) {
        return Err(anyhow!(
            "use either --azure-key-vault-accesstoken or managed identity / client credentials, not multiple"
        ));
    }
    if args.managed_identity && (has_token || sp_count == 3) {
        return Err(anyhow!(
            "--azure-key-vault-managed-identity cannot be combined with access tokens or client secrets"
        ));
    }
    if !has_token && !args.managed_identity && sp_count != 3 {
        return Err(anyhow!(
            "choose authentication: --azure-key-vault-accesstoken, --azure-key-vault-managed-identity, or client id/secret/tenant"
        ));
    }
    Ok(())
}

#[cfg(feature = "azure-kv-sign-portable")]
fn validate_kv_portable_auth(args: &AzureKvSignDigestPortableArgs) -> Result<()> {
    validate_kv_portable_auth_inputs(KvPortableAuthInputs {
        access_token: args.azure_key_vault_access_token.as_deref(),
        managed_identity: args.azure_key_vault_managed_identity,
        tenant_id: args.azure_key_vault_tenant_id.as_deref(),
        client_id: args.azure_key_vault_client_id.as_deref(),
        client_secret: args.azure_key_vault_client_secret.as_deref(),
    })
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

#[cfg(feature = "azure-kv-sign-portable")]
struct SignPeAzureKvOptions<'a> {
    vault_url: Option<&'a str>,
    certificate: Option<&'a str>,
    certificate_version: Option<&'a str>,
    access_token: Option<&'a str>,
    managed_identity: bool,
    tenant_id: Option<&'a str>,
    client_id: Option<&'a str>,
    client_secret: Option<&'a str>,
    authority: Option<&'a str>,
}

#[cfg(feature = "azure-kv-sign-portable")]
fn create_pe_authenticode_pkcs7_der_azure_kv(
    pe: &[u8],
    digest: PortableSignDigest,
    chain_certs: Vec<PathBuf>,
    args: SignPeAzureKvOptions<'_>,
) -> Result<Vec<u8>> {
    use std::time::Duration;

    let vault_url = args
        .vault_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("portable sign-pe Azure Key Vault signing requires --azure-key-vault-url"))?;
    let certificate = args
        .certificate
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "portable sign-pe Azure Key Vault signing requires --azure-key-vault-certificate"
            )
        })?;
    validate_kv_portable_auth_inputs(KvPortableAuthInputs {
        access_token: args.access_token,
        managed_identity: args.managed_identity,
        tenant_id: args.tenant_id,
        client_id: args.client_id,
        client_secret: args.client_secret,
    })?;

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let auth = KvAuthParams {
        access_token: args.access_token,
        managed_identity: args.managed_identity,
        tenant_id: args.tenant_id,
        client_id: args.client_id,
        client_secret: args.client_secret,
        authority: args.authority,
    };
    let token = acquire_kv_access_token(&auth)?;
    let kv_cert = fetch_kv_certificate(
        &http,
        vault_url,
        certificate,
        args.certificate_version
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        &token,
    )?;
    let signer_cert_der = kv_decode_cer_b64(&kv_cert.cer)?;
    let signer_cert =
        rdp::parse_certificate(&signer_cert_der).context("parse Key Vault signer certificate")?;
    let mut chain = Vec::with_capacity(chain_certs.len());
    for chain_cert in chain_certs {
        let bytes =
            std::fs::read(&chain_cert).with_context(|| format!("read {}", chain_cert.display()))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
        );
    }

    let digest_algorithm: pkcs7::AuthenticodeSigningDigest = digest.into();
    let pe_digest = pe_authenticode_digest(pe, digest_algorithm.pe_hash_kind())?;
    let indirect = pkcs7::pe_spc_indirect_data(digest_algorithm, &pe_digest)?;
    let signer_prehash =
        pkcs7::authenticode_remote_rsa_signed_attrs_digest(&indirect, digest_algorithm)?;
    let signature = kv_sign_digest_from_certificate(
        &http,
        &token,
        &kv_cert,
        KvHashAlg::from(digest),
        &signer_prehash,
    )?;

    pkcs7::create_authenticode_pkcs7_der_with_rsa_signature(
        indirect,
        digest_algorithm,
        signer_cert,
        chain,
        &signature,
    )
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct ArtifactSigningMetadataDoc {
    Endpoint: String,
    CodeSigningAccountName: String,
    CertificateProfileName: String,
    #[serde(default)]
    CorrelationId: Option<String>,
    #[serde(default)]
    ExcludeCredentials: Option<Vec<String>>,
}

fn text_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(feature = "artifact-signing-rest")]
fn artifact_signature_algorithm_for_digest(digest: PortableSignDigest) -> &'static str {
    match digest {
        PortableSignDigest::Sha256 => "RS256",
        PortableSignDigest::Sha384 => "RS384",
        PortableSignDigest::Sha512 => "RS512",
    }
}

fn artifact_signing_requested(args: &ArtifactSigningPortableOptions) -> bool {
    args.metadata.is_some()
        || text_opt(args.region.as_deref()).is_some()
        || text_opt(args.endpoint.as_deref()).is_some()
        || text_opt(args.account_name.as_deref()).is_some()
        || text_opt(args.profile_name.as_deref()).is_some()
        || text_opt(args.signature_algorithm.as_deref()).is_some()
        || text_opt(args.api_version.as_deref()).is_some()
        || text_opt(args.correlation_id.as_deref()).is_some()
        || text_opt(args.access_token.as_deref()).is_some()
        || args.managed_identity
        || text_opt(args.tenant_id.as_deref()).is_some()
        || text_opt(args.client_id.as_deref()).is_some()
        || text_opt(args.client_secret.as_deref()).is_some()
        || text_opt(args.authority.as_deref()).is_some()
        || text_opt(args.endpoint_base_url.as_deref()).is_some()
}

#[cfg(feature = "artifact-signing-rest")]
fn portable_submit_auth_parts(
    access_token: Option<&str>,
    managed_identity: bool,
    tenant_id: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> Result<CodesigningAuth> {
    let has_tok = text_opt(access_token).is_some();
    let tenant = text_opt(tenant_id);
    let client = text_opt(client_id);
    let secret = text_opt(client_secret);
    let sp_count = tenant.is_some() as u8 + client.is_some() as u8 + secret.is_some() as u8;
    if managed_identity {
        if has_tok || sp_count != 0 {
            return Err(anyhow!(
                "use either Artifact Signing managed identity, access token, or client credentials, not multiple"
            ));
        }
        return Ok(CodesigningAuth::ManagedIdentity);
    }
    if let Some(tok) = text_opt(access_token) {
        if sp_count != 0 {
            return Err(anyhow!(
                "use either Artifact Signing access token or client credentials, not both"
            ));
        }
        return Ok(CodesigningAuth::Bearer(tok));
    }
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "Artifact Signing client credentials require all of tenant-id, client-id, and client-secret"
        ));
    }
    if sp_count == 0 {
        return Err(anyhow!(
            "choose Artifact Signing authentication: managed identity, access token, or tenant/client-id/client-secret"
        ));
    }
    Ok(CodesigningAuth::ClientCredentials {
        tenant_id: tenant.unwrap(),
        client_id: client.unwrap(),
        client_secret: secret.unwrap(),
    })
}

#[cfg(feature = "artifact-signing-rest")]
fn artifact_signing_params_for_digest(
    args: &ArtifactSigningPortableOptions,
    digest: Vec<u8>,
    default_signature_algorithm: &str,
) -> Result<CodesigningSubmitParams> {
    let metadata = if let Some(path) = args.metadata.as_deref() {
        let raw = read_json_input(Some(path))?;
        Some(
            serde_json::from_slice::<ArtifactSigningMetadataDoc>(&raw)
                .context("parse Artifact Signing metadata JSON")?,
        )
    } else {
        None
    };
    let endpoint = text_opt(args.endpoint_base_url.as_deref())
        .or_else(|| text_opt(args.endpoint.as_deref()))
        .or_else(|| metadata.as_ref().and_then(|m| text_opt(Some(&m.Endpoint))));
    let region = text_opt(args.region.as_deref()).unwrap_or_else(|| "unused".to_string());
    let account_name = text_opt(args.account_name.as_deref())
        .or_else(|| {
            metadata
                .as_ref()
                .and_then(|m| text_opt(Some(&m.CodeSigningAccountName)))
        })
        .ok_or_else(|| anyhow!("Artifact Signing requires --artifact-signing-account-name or metadata CodeSigningAccountName"))?;
    let profile_name = text_opt(args.profile_name.as_deref())
        .or_else(|| {
            metadata
                .as_ref()
                .and_then(|m| text_opt(Some(&m.CertificateProfileName)))
        })
        .ok_or_else(|| anyhow!("Artifact Signing requires --artifact-signing-profile-name or metadata CertificateProfileName"))?;
    let auth = portable_submit_auth_parts(
        args.access_token.as_deref(),
        args.managed_identity,
        args.tenant_id.as_deref(),
        args.client_id.as_deref(),
        args.client_secret.as_deref(),
    )?;
    Ok(CodesigningSubmitParams {
        region,
        account_name,
        profile_name,
        digest,
        signature_algorithm: text_opt(args.signature_algorithm.as_deref())
            .unwrap_or_else(|| default_signature_algorithm.to_string()),
        api_version: text_opt(args.api_version.as_deref())
            .unwrap_or_else(|| DEFAULT_API_VERSION.to_string()),
        correlation_id: text_opt(args.correlation_id.as_deref())
            .or_else(|| metadata.as_ref().and_then(|m| text_opt(m.CorrelationId.as_deref()))),
        authority: text_opt(args.authority.as_deref()),
        auth,
        endpoint_base_url: endpoint,
    })
}

#[cfg(feature = "artifact-signing-rest")]
fn create_pe_authenticode_pkcs7_der_artifact_signing(
    pe: &[u8],
    digest: PortableSignDigest,
    chain_certs: Vec<PathBuf>,
    args: &ArtifactSigningPortableOptions,
) -> Result<Vec<u8>> {
    let digest_algorithm: pkcs7::AuthenticodeSigningDigest = digest.into();
    let pe_digest = pe_authenticode_digest(pe, digest_algorithm.pe_hash_kind())?;
    let indirect = pkcs7::pe_spc_indirect_data(digest_algorithm, &pe_digest)?;
    let signer_prehash =
        pkcs7::authenticode_remote_rsa_signed_attrs_digest(&indirect, digest_algorithm)?;
    let params = artifact_signing_params_for_digest(
        args,
        signer_prehash,
        artifact_signature_algorithm_for_digest(digest),
    )?;
    let debug_portable = std::env::var_os("SIGNTOOL_PORTABLE_DEBUG").is_some();
    let signed = submit_codesign_hash_signature_blocking(&params, |msg| {
        if debug_portable {
            eprintln!("[debug] {msg}");
        }
    })?;
    let (signer_cert, mut chain) =
        pkcs7::parse_artifact_signing_certificates(&signed.signing_certificate)?;
    for chain_cert in chain_certs {
        let bytes =
            std::fs::read(&chain_cert).with_context(|| format!("read {}", chain_cert.display()))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
        );
    }
    pkcs7::create_authenticode_pkcs7_der_with_rsa_signature(
        indirect,
        digest_algorithm,
        signer_cert,
        chain,
        &signed.signature,
    )
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
        Command::TrustVerifyZip { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_zip_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-zip {}", path.display()))?;
            print_trust_ok("trust-verify-zip", &report);
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
            timestamp_url,
            timestamp_digest,
            azure_key_vault_url,
            azure_key_vault_certificate,
            azure_key_vault_certificate_version,
            azure_key_vault_access_token,
            azure_key_vault_managed_identity,
            azure_key_vault_tenant_id,
            azure_key_vault_client_id,
            azure_key_vault_client_secret,
            azure_authority,
            artifact_signing,
            output,
        } => {
            let pe = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let has_local = cert.is_some() || key.is_some();
            let has_kv = azure_key_vault_url
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
                || azure_key_vault_certificate
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                || azure_key_vault_certificate_version
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                || azure_key_vault_access_token
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                || azure_key_vault_managed_identity
                || azure_key_vault_tenant_id
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                || azure_key_vault_client_id
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                || azure_key_vault_client_secret
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                || azure_authority
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty());
            let has_artifact = artifact_signing_requested(&artifact_signing);
            if [has_local, has_kv, has_artifact]
                .into_iter()
                .filter(|x| *x)
                .count()
                > 1
            {
                return Err(anyhow!(
                    "portable sign-pe accepts only one signing source: --cert/--key, --azure-key-vault-*, or --artifact-signing-*"
                ));
            }
            let pkcs7 = if has_artifact {
                #[cfg(feature = "artifact-signing-rest")]
                {
                    create_pe_authenticode_pkcs7_der_artifact_signing(
                        &pe,
                        digest,
                        chain_certs,
                        &artifact_signing,
                    )
                    .with_context(|| {
                        format!(
                            "create portable Azure Artifact Signing Authenticode signature for {}",
                            path.display()
                        )
                    })?
                }
                #[cfg(not(feature = "artifact-signing-rest"))]
                {
                    return Err(anyhow!(
                        "portable sign-pe Artifact Signing support requires the artifact-signing-rest feature"
                    ));
                }
            } else if has_kv {
                #[cfg(feature = "azure-kv-sign-portable")]
                {
                    create_pe_authenticode_pkcs7_der_azure_kv(
                        &pe,
                        digest,
                        chain_certs,
                        SignPeAzureKvOptions {
                            vault_url: azure_key_vault_url.as_deref(),
                            certificate: azure_key_vault_certificate.as_deref(),
                            certificate_version: azure_key_vault_certificate_version.as_deref(),
                            access_token: azure_key_vault_access_token.as_deref(),
                            managed_identity: azure_key_vault_managed_identity,
                            tenant_id: azure_key_vault_tenant_id.as_deref(),
                            client_id: azure_key_vault_client_id.as_deref(),
                            client_secret: azure_key_vault_client_secret.as_deref(),
                            authority: azure_authority.as_deref(),
                        },
                    )
                    .with_context(|| {
                        format!(
                            "create portable Azure Key Vault Authenticode signature for {}",
                            path.display()
                        )
                    })?
                }
                #[cfg(not(feature = "azure-kv-sign-portable"))]
                {
                    return Err(anyhow!(
                        "portable sign-pe Azure Key Vault support requires the azure-kv-sign-portable feature"
                    ));
                }
            } else {
                let (cert, key) = match (cert, key) {
                    (Some(cert), Some(key)) => (cert, key),
                    _ => {
                        return Err(anyhow!(
                            "portable sign-pe requires --cert and --key, --azure-key-vault-url and --azure-key-vault-certificate, or --artifact-signing-* options"
                        ));
                    }
                };
                let cert_bytes =
                    std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
                let signer_cert = rdp::parse_certificate(&cert_bytes)
                    .with_context(|| format!("parse signer certificate {}", cert.display()))?;
                let key_bytes =
                    std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
                let private_key = rdp::parse_rsa_private_key(&key_bytes)
                    .with_context(|| format!("parse RSA private key {}", key.display()))?;
                let mut chain = Vec::with_capacity(chain_certs.len());
                for chain_cert in chain_certs {
                    let bytes = std::fs::read(&chain_cert)
                        .with_context(|| format!("read {}", chain_cert.display()))?;
                    chain.push(rdp::parse_certificate(&bytes).with_context(|| {
                        format!("parse chain certificate {}", chain_cert.display())
                    })?);
                }
                pkcs7::create_pe_authenticode_pkcs7_der_rsa(
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
                })?
            };
            let pkcs7 = match (timestamp_url, timestamp_digest) {
                (Some(url), Some(timestamp_digest)) => {
                    #[cfg(feature = "timestamp-http")]
                    {
                        timestamp_pkcs7_der_rfc3161(
                            &pkcs7,
                            &url,
                            timestamp_digest,
                            Rfc3161TimestampAttribute::MicrosoftAuthenticode,
                        )
                        .with_context(|| {
                                format!(
                                    "RFC3161 timestamp portable Authenticode signature for {}",
                                    path.display()
                                )
                            })?
                    }
                    #[cfg(not(feature = "timestamp-http"))]
                    {
                        let _ = (url, timestamp_digest);
                        return Err(anyhow!(
                            "portable sign-pe RFC3161 timestamping requires the timestamp-http feature"
                        ));
                    }
                }
                (Some(_), None) => {
                    return Err(anyhow!(
                        "portable sign-pe requires --timestamp-digest with --timestamp-url"
                    ));
                }
                (None, Some(_)) => {
                    return Err(anyhow!(
                        "portable sign-pe requires --timestamp-url with --timestamp-digest"
                    ));
                }
                (None, None) => pkcs7,
            };
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
        Command::VerifyZip { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let sig = zip_authenticode::verify_zip_digest_binding(&bytes)
                .with_context(|| format!("verify-zip {}", path.display()))?;
            let script =
                zip_authenticode::signature_script_from_parts(&sig.digest, &sig.pkcs7_base64);
            verify_script_digest_consistency(script.as_bytes(), "ps1")
                .with_context(|| format!("verify-zip reconstructed signature {}", path.display()))?;
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
        Command::MsixManifestInfo { path } => {
            let info = inspect_msix_manifest_path(&path)
                .with_context(|| format!("msix-manifest-info {}", path.display()))?;
            println!("package_name={}", info.package_name.unwrap_or("-".to_string()));
            println!("publisher={}", info.publisher.unwrap_or("-".to_string()));
            println!("version={}", info.version.unwrap_or("-".to_string()));
            println!(
                "processor_architecture={}",
                info.processor_architecture.unwrap_or("-".to_string())
            );
        }
        Command::MsixSetPublisher {
            path,
            publisher,
            output,
        } => {
            set_msix_manifest_publisher_path(&path, &output, &publisher)
                .with_context(|| format!("msix-set-publisher {}", path.display()))?;
            println!("output={}", output.display());
            println!("publisher={publisher}");
        }
        Command::ClickonceDeployInfo { path } => {
            let info = inspect_clickonce_deploy_payload(&path)
                .with_context(|| format!("clickonce-deploy-info {}", path.display()))?;
            println!("deployed={}", if info.deployed { "yes" } else { "no" });
            println!(
                "content_name={}",
                info.content_name.unwrap_or("-".to_string())
            );
            println!("len={}", info.len);
        }
        Command::ClickonceCopyDeployPayload { path, output } => {
            let content_name = clickonce_deploy_content_name(&path).ok_or_else(|| {
                anyhow!(
                    "ClickOnce deploy payload name must end with .deploy: {}",
                    path.display()
                )
            })?;
            let bytes = copy_clickonce_deploy_payload(&path, &output)
                .with_context(|| format!("clickonce-copy-deploy-payload {}", path.display()))?;
            println!("content_name={content_name}");
            println!("output={}", output.display());
            println!("bytes={bytes}");
        }
        Command::ClickonceManifestHashes {
            path,
            base_directory,
        } => {
            let entries = clickonce_manifest_hashes(&path, base_directory.as_deref())
                .with_context(|| format!("clickonce-manifest-hashes {}", path.display()))?;
            println!("references={}", entries.len());
            let mut mismatches = 0usize;
            for entry in entries {
                if entry.status() != "valid" {
                    mismatches += 1;
                }
                println!(
                    "path={} algorithm={} expected_size={} actual_size={} status={}",
                    entry.path,
                    hash_alg_label(entry.algorithm),
                    entry
                        .expected_size
                        .map(|size| size.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    entry.actual_size,
                    entry.status()
                );
                println!("expected_digest_b64={}", entry.expected_digest_b64);
                println!("actual_digest_b64={}", entry.actual_digest_b64);
            }
            println!("mismatches={mismatches}");
            if mismatches > 0 {
                return Err(anyhow!(
                    "ClickOnce manifest file hash verification failed ({mismatches} mismatch(es))"
                ));
            }
        }
        Command::ClickonceUpdateManifestHashes {
            path,
            base_directory,
            algorithm,
            output,
        } => {
            let updated =
                update_clickonce_manifest_hashes(&path, base_directory.as_deref(), &output, algorithm)
                    .with_context(|| {
                        format!("clickonce-update-manifest-hashes {}", path.display())
                    })?;
            println!("output={}", output.display());
            println!("updated={updated}");
            println!("algorithm={}", hash_alg_label(algorithm));
        }
        Command::ClickonceSignManifest {
            path,
            digest,
            cert,
            key,
            output,
        } => {
            let report = sign_clickonce_manifest_path(&path, &cert, &key, digest, &output)
                .with_context(|| format!("clickonce-sign-manifest {}", path.display()))?;
            println!("output={}", output.display());
            println!("digest={:?}", report.digest);
            println!("manifest_digest_b64={}", report.manifest_digest_b64);
            println!("signature_len={}", report.signature_len);
        }
        Command::ClickonceSignManifestPrehash {
            path,
            digest,
            encoding,
            output,
        } => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read ClickOnce manifest {}", path.display()))?;
            let unsigned = unsigned_clickonce_manifest_text(&text)?;
            let signed_info = clickonce_manifest_signed_info_xml(&unsigned, digest);
            let prehash = clickonce_signed_info_remote_prehash(digest, &signed_info);
            write_digest_output(encoding, &prehash, output.as_deref())
                .with_context(|| format!("clickonce-sign-manifest-prehash {}", path.display()))?;
        }
        Command::ClickonceSignManifestFromSignature {
            path,
            digest,
            cert,
            signature,
            output,
        } => {
            let report = sign_clickonce_manifest_from_external_signature_path(
                &path, &cert, &signature, digest, &output,
            )
            .with_context(|| {
                format!(
                    "clickonce-sign-manifest-from-signature {}",
                    path.display()
                )
            })?;
            println!("output={}", output.display());
            println!("digest={:?}", report.digest);
            println!("manifest_digest_b64={}", report.manifest_digest_b64);
            println!("signature_len={}", report.signature_len);
        }
        Command::ClickonceVerifyManifestSignature {
            path,
            cert,
            digest,
            shared,
        } => {
            let report =
                verify_clickonce_manifest_signature_path(&path, cert.as_deref(), digest, &shared)
                    .with_context(|| {
                        format!("clickonce-verify-manifest-signature {}", path.display())
                    })?;
            println!("clickonce-verify-manifest-signature: ok");
            println!("digest={:?}", report.digest);
            println!("manifest_digest_b64={}", report.manifest_digest_b64);
            println!("manifest_digest_match=yes");
            println!("signature_value_match=yes");
            println!("signature_len={}", report.signature_len);
            if trust_verify_args_present(&shared) {
                println!("signer_trust_chain=yes");
            }
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
        Command::NupkgSignatureContent {
            path,
            algorithm,
            output,
        } => {
            use std::io::Write;
            let content = nuget::unsigned_package_signature_content_path(&path, algorithm.into())
                .with_context(|| format!("nupkg-signature-content {}", path.display()))?;
            match output {
                Some(path) => std::fs::write(&path, &content)
                    .with_context(|| format!("write {}", path.display()))?,
                None => std::io::stdout()
                    .write_all(&content)
                    .context("write NuGet signature content to stdout")?,
            }
        }
        Command::NupkgSignaturePkcs7 {
            path,
            algorithm,
            cert,
            key,
            chain_certs,
            timestamp_url,
            timestamp_digest,
            output,
        } => {
            let content = nuget::unsigned_package_signature_content_path(&path, algorithm.into())
                .with_context(|| format!("nupkg-signature-pkcs7 {}", path.display()))?;
            let pkcs7 = sign_pkcs7_id_data(
                &content,
                &cert,
                &key,
                chain_certs,
                algorithm.into(),
                pkcs7::Pkcs7ContentMode::Attached,
                pkcs7::Pkcs7SignedAttributeProfile::NuGetAuthor,
            )
            .with_context(|| {
                format!(
                    "nupkg-signature-pkcs7 create CMS for {}",
                    path.display()
                )
            })?;
            let pkcs7 = timestamp_pkcs7_if_requested(
                &pkcs7,
                timestamp_url,
                timestamp_digest,
                Rfc3161TimestampAttribute::CmsTimeStampToken,
                "nupkg-signature-pkcs7",
            )?;
            std::fs::write(&output, &pkcs7).with_context(|| format!("write {}", output.display()))?;
            println!("output={}", output.display());
            println!("package_hash_algorithm={}", nuget_hash_alg_label(algorithm.into()));
            println!("signature_len={}", pkcs7.len());
        }
        Command::NupkgSignaturePkcs7Prehash {
            path,
            algorithm,
            cert,
            encoding,
            output,
        } => {
            let content = nuget::unsigned_package_signature_content_path(&path, algorithm.into())
                .with_context(|| {
                    format!("nupkg-signature-pkcs7-prehash {}", path.display())
                })?;
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let prehash = pkcs7_id_data_remote_prehash(
                &content,
                algorithm.into(),
                pkcs7::Pkcs7SignedAttributeProfile::NuGetAuthorWithoutSigningTime,
                Some(&signer_cert),
            )?;
            write_digest_output(encoding, &prehash, output.as_deref())?;
        }
        Command::NupkgSignaturePkcs7FromSignature {
            path,
            algorithm,
            cert,
            chain_certs,
            signature,
            timestamp_url,
            timestamp_digest,
            output,
        } => {
            let content = nuget::unsigned_package_signature_content_path(&path, algorithm.into())
                .with_context(|| {
                    format!(
                        "nupkg-signature-pkcs7-from-signature {}",
                        path.display()
                    )
                })?;
            let signature_bytes = std::fs::read(&signature)
                .with_context(|| format!("read {}", signature.display()))?;
            let pkcs7 = sign_pkcs7_id_data_with_external_signature(
                &content,
                &cert,
                chain_certs,
                algorithm.into(),
                &signature_bytes,
                pkcs7::Pkcs7ContentMode::Attached,
                pkcs7::Pkcs7SignedAttributeProfile::NuGetAuthorWithoutSigningTime,
            )
            .with_context(|| {
                format!(
                    "nupkg-signature-pkcs7-from-signature create CMS for {}",
                    path.display()
                )
            })?;
            let pkcs7 = timestamp_pkcs7_if_requested(
                &pkcs7,
                timestamp_url,
                timestamp_digest,
                Rfc3161TimestampAttribute::CmsTimeStampToken,
                "nupkg-signature-pkcs7-from-signature",
            )?;
            std::fs::write(&output, &pkcs7).with_context(|| format!("write {}", output.display()))?;
            println!("output={}", output.display());
            println!("package_hash_algorithm={}", nuget_hash_alg_label(algorithm.into()));
            println!("signature_len={}", pkcs7.len());
        }
        Command::NupkgSign {
            path,
            algorithm,
            cert,
            key,
            chain_certs,
            timestamp_url,
            timestamp_digest,
            output,
            overwrite,
        } => {
            let content = nuget::unsigned_package_signature_content_path(&path, algorithm.into())
                .with_context(|| format!("nupkg-sign {}", path.display()))?;
            let pkcs7 = sign_pkcs7_id_data(
                &content,
                &cert,
                &key,
                chain_certs,
                algorithm.into(),
                pkcs7::Pkcs7ContentMode::Attached,
                pkcs7::Pkcs7SignedAttributeProfile::NuGetAuthor,
            )
            .with_context(|| format!("nupkg-sign create CMS for {}", path.display()))?;
            let pkcs7 = timestamp_pkcs7_if_requested(
                &pkcs7,
                timestamp_url,
                timestamp_digest,
                Rfc3161TimestampAttribute::CmsTimeStampToken,
                "nupkg-sign",
            )?;
            nuget::embed_signature_path(&path, &output, &pkcs7, overwrite)
                .with_context(|| format!("nupkg-sign embed signature into {}", output.display()))?;
            println!("output={}", output.display());
            println!("package_hash_algorithm={}", nuget_hash_alg_label(algorithm.into()));
            println!("embedded_signature={}", nuget::PACKAGE_SIGNATURE_FILE_NAME);
            println!("signature_len={}", pkcs7.len());
        }
        Command::NupkgVerifySignatureContent { path, content } => {
            let content_bytes =
                std::fs::read(&content).with_context(|| format!("read {}", content.display()))?;
            let parsed = nuget::verify_unsigned_package_signature_content_path(&path, &content_bytes)
                .with_context(|| format!("nupkg-verify-signature-content {}", path.display()))?;
            println!(
                "package_hash_algorithm={}",
                nuget_hash_alg_label(parsed.hash_algorithm)
            );
            println!("package_hash={}", hex_lower(&parsed.package_hash));
            println!("package_hash_match=yes");
        }
        Command::NupkgVerifySignature {
            path,
            algorithm,
            shared,
        } => {
            let alg = algorithm.into();
            let signature_der = nuget::extract_signature_path(&path)
                .with_context(|| format!("nupkg-verify-signature {}", path.display()))?;
            let content = nuget::signed_package_signature_content_path(&path, alg)
                .with_context(|| format!("nupkg-verify-signature {}", path.display()))?;
            let parsed = nuget::parse_signature_content(&content)
                .context("parse reconstructed NuGet signature content")?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_detached_bytes(&content, &signature_der, &opts)
                .with_context(|| format!("nupkg-verify-signature {}", path.display()))?;
            print_trust_ok("nupkg-verify-signature", &report);
            println!("signature_present=yes");
            println!("package_hash_algorithm={}", nuget_hash_alg_label(alg));
            println!("package_hash={}", hex_lower(&parsed.package_hash));
            println!("package_hash_match=yes");
            println!("signature_len={}", signature_der.len());
        }
        Command::NupkgEmbedSignature {
            path,
            signature,
            output,
            overwrite,
        } => {
            let signature_der =
                std::fs::read(&signature).with_context(|| format!("read {}", signature.display()))?;
            nuget::embed_signature_path(&path, &output, &signature_der, overwrite)
                .with_context(|| format!("nupkg-embed-signature {}", path.display()))?;
            println!(
                "embedded_signature={}\noutput={}\nsignature_len={}",
                nuget::PACKAGE_SIGNATURE_FILE_NAME,
                output.display(),
                signature_der.len()
            );
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
        Command::VsixEmbedSignatureXml {
            path,
            signature_xml,
            output,
            overwrite,
        } => {
            let xml = std::fs::read(&signature_xml)
                .with_context(|| format!("read {}", signature_xml.display()))?;
            vsix::embed_signature_xml_path(&path, &output, &xml, overwrite)
                .with_context(|| format!("vsix-embed-signature-xml {}", path.display()))?;
            println!(
                "embedded_signature_xml={}\noutput={}\nsignature_xml_len={}",
                vsix::DEFAULT_VSIX_SIGNATURE_PART,
                output.display(),
                xml.len()
            );
        }
        Command::VsixSignatureReferenceXml {
            path,
            algorithm,
            output,
        } => {
            use std::io::Write;
            let xml = vsix::signature_reference_xml_path(&path, algorithm.into())
                .with_context(|| format!("vsix-signature-reference-xml {}", path.display()))?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &xml).with_context(|| format!("write {}", path.display()))?
                }
                None => std::io::stdout()
                    .write_all(&xml)
                    .context("write VSIX signature reference XML to stdout")?,
            }
        }
        Command::VsixSignatureXml {
            path,
            algorithm,
            cert,
            key,
            output,
        } => {
            use std::io::Write;
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let cert_bytes = std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes =
                std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let signed_info = vsix::signed_info_xml_path(&path, algorithm)
                .with_context(|| format!("vsix-signature-xml {}", path.display()))?;
            let signature = sign_xml_signed_info(algorithm, private_key, &signed_info)?;
            let xml = vsix::signature_xml_from_signed_info(&signed_info, &signature, Some(&cert_bytes))
                .into_bytes();
            match output {
                Some(path) => {
                    std::fs::write(&path, &xml).with_context(|| format!("write {}", path.display()))?
                }
                None => std::io::stdout()
                    .write_all(&xml)
                    .context("write VSIX signature XML to stdout")?,
            }
        }
        Command::VsixSignatureXmlPrehash {
            path,
            algorithm,
            encoding,
            output,
        } => {
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let signed_info = vsix::signed_info_xml_path(&path, algorithm)
                .with_context(|| format!("vsix-signature-xml-prehash {}", path.display()))?;
            let prehash = xml_signed_info_remote_prehash(algorithm, &signed_info);
            write_digest_output(encoding, &prehash, output.as_deref())?;
        }
        Command::VsixSignatureXmlFromSignature {
            path,
            algorithm,
            cert,
            signature,
            output,
        } => {
            use std::io::Write;
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let cert_bytes =
                std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let signature_bytes = std::fs::read(&signature)
                .with_context(|| format!("read {}", signature.display()))?;
            let signed_info = vsix::signed_info_xml_path(&path, algorithm).with_context(|| {
                format!("vsix-signature-xml-from-signature {}", path.display())
            })?;
            let xml =
                vsix::signature_xml_from_signed_info(&signed_info, &signature_bytes, Some(&cert_bytes))
                    .into_bytes();
            match output {
                Some(path) => {
                    std::fs::write(&path, &xml).with_context(|| format!("write {}", path.display()))?
                }
                None => std::io::stdout()
                    .write_all(&xml)
                    .context("write VSIX signature XML to stdout")?,
            }
        }
        Command::VsixSign {
            path,
            algorithm,
            cert,
            key,
            output,
            overwrite,
        } => {
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let cert_bytes = std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes =
                std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let signed_info = vsix::signed_info_xml_path(&path, algorithm)
                .with_context(|| format!("vsix-sign {}", path.display()))?;
            let signature = sign_xml_signed_info(algorithm, private_key, &signed_info)?;
            let xml =
                vsix::signature_xml_from_signed_info(&signed_info, &signature, Some(&cert_bytes))
                    .into_bytes();
            vsix::embed_signature_xml_path(&path, &output, &xml, overwrite)
                .with_context(|| format!("vsix-sign embed signature XML into {}", output.display()))?;
            println!("output={}", output.display());
            println!("signature_xml_part={}", vsix::DEFAULT_VSIX_SIGNATURE_PART);
            println!("reference_digest_algorithm={}", vsix_hash_alg_label(algorithm));
            println!("signature_xml_len={}", xml.len());
        }
        Command::VsixVerifySignatureReferenceXml {
            path,
            signature_xml,
            algorithm,
        } => {
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let xml = std::fs::read(&signature_xml)
                .with_context(|| format!("read {}", signature_xml.display()))?;
            let references = vsix::verify_signature_reference_xml_path(&path, &xml, algorithm)
                .with_context(|| {
                    format!(
                        "vsix-verify-signature-reference-xml {}",
                        path.display()
                    )
                })?;
            println!("reference_digest_algorithm={}", vsix_hash_alg_label(algorithm));
            println!("reference_count={references}");
            println!("reference_digest_match=yes");
        }
        Command::VsixVerifySignatureXml {
            path,
            signature_xml,
            cert,
            algorithm,
            shared,
        } => {
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let xml = std::fs::read(&signature_xml)
                .with_context(|| format!("read {}", signature_xml.display()))?;
            let references = vsix::verify_signature_reference_xml_path(&path, &xml, algorithm)
                .with_context(|| format!("vsix-verify-signature-xml {}", path.display()))?;
            let cert_bytes = std::fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let signed_info = vsix::signed_info_xml_from_signature_xml(&xml)?;
            let signature = vsix::signature_value_from_signature_xml(&xml)?;
            verify_xml_signed_info(algorithm, &signer_cert, &signed_info, &signature)?;
            let trust_anchor_count = if trust_verify_args_present(&shared) {
                Some(verify_xml_signer_certificate_trust(&cert_bytes, &shared)?)
            } else {
                None
            };
            println!("reference_digest_algorithm={}", vsix_hash_alg_label(algorithm));
            println!("reference_count={references}");
            println!("reference_digest_match=yes");
            println!("signature_value_match=yes");
            if let Some(count) = trust_anchor_count {
                println!("signer_trust_chain=yes");
                println!("trust_anchor_count={count}");
            }
        }
        Command::VsixVerifySignature {
            path,
            cert,
            algorithm,
            shared,
        } => {
            let algorithm = vsix::VsixHashAlgorithm::from(algorithm);
            let xml = vsix::extract_signature_xml_path(&path)
                .with_context(|| format!("vsix-verify-signature {}", path.display()))?;
            let references = vsix::verify_signature_reference_xml_path(&path, &xml, algorithm)
                .with_context(|| format!("vsix-verify-signature {}", path.display()))?;
            let cert_bytes = match cert {
                Some(cert) => std::fs::read(&cert)
                    .with_context(|| format!("read {}", cert.display()))?,
                None => vsix::signer_certificate_from_signature_xml(&xml)
                    .context("read embedded VSIX signer certificate")?,
            };
            let signer_cert =
                rdp::parse_certificate(&cert_bytes).context("parse VSIX signer certificate")?;
            let signed_info = vsix::signed_info_xml_from_signature_xml(&xml)?;
            let signature = vsix::signature_value_from_signature_xml(&xml)?;
            verify_xml_signed_info(algorithm, &signer_cert, &signed_info, &signature)?;
            let trust_anchor_count = if trust_verify_args_present(&shared) {
                Some(verify_xml_signer_certificate_trust(&cert_bytes, &shared)?)
            } else {
                None
            };
            println!("vsix-verify-signature: ok");
            println!("signature_xml_present=yes");
            println!("signature_xml_part={}", vsix::DEFAULT_VSIX_SIGNATURE_PART);
            println!("reference_digest_algorithm={}", vsix_hash_alg_label(algorithm));
            println!("reference_count={references}");
            println!("reference_digest_match=yes");
            println!("signature_value_match=yes");
            if let Some(count) = trust_anchor_count {
                println!("signer_trust_chain=yes");
                println!("trust_anchor_count={count}");
            }
        }
        Command::AppinstallerInfo { path, signature } => {
            let text =
                std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let info = parse_appinstaller_descriptor(&text)
                .with_context(|| format!("appinstaller-info {}", path.display()))?;
            println!("root={}", info.root);
            println!("namespace={}", info.namespace.unwrap_or("-".to_string()));
            println!(
                "main_package={}",
                if info.has_main_package { "yes" } else { "no" }
            );
            println!(
                "main_bundle={}",
                if info.has_main_bundle { "yes" } else { "no" }
            );
            println!("publisher={}", info.publisher.unwrap_or("-".to_string()));
            if let Some(signature) = signature {
                let metadata = std::fs::metadata(&signature)
                    .with_context(|| format!("stat {}", signature.display()))?;
                println!("companion_signature={}", signature.display());
                println!("companion_signature_len={}", metadata.len());
            } else {
                println!("companion_signature=-");
                println!("companion_signature_len=-");
            }
        }
        Command::AppinstallerVerifyCompanion {
            path,
            signature,
            shared,
        } => {
            let text =
                std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            parse_appinstaller_descriptor(&text)
                .with_context(|| format!("appinstaller-verify-companion {}", path.display()))?;
            let sig_bytes = std::fs::read(&signature)
                .with_context(|| format!("read {}", signature.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_detached_bytes(text.as_bytes(), &sig_bytes, &opts)
                .with_context(|| format!("appinstaller-verify-companion {}", path.display()))?;
            print_trust_ok("appinstaller-verify-companion", &report);
        }
        Command::AppinstallerSignCompanion {
            path,
            cert,
            key,
            chain_certs,
            digest,
            timestamp_url,
            timestamp_digest,
            output,
        } => {
            let text =
                std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            parse_appinstaller_descriptor(&text)
                .with_context(|| format!("appinstaller-sign-companion {}", path.display()))?;
            let pkcs7 = sign_pkcs7_id_data(
                text.as_bytes(),
                &cert,
                &key,
                chain_certs,
                digest,
                pkcs7::Pkcs7ContentMode::Detached,
                pkcs7::Pkcs7SignedAttributeProfile::Basic,
            )
            .with_context(|| {
                format!(
                    "appinstaller-sign-companion create detached PKCS#7 for {}",
                    path.display()
                )
            })?;
            let pkcs7 = timestamp_pkcs7_if_requested(
                &pkcs7,
                timestamp_url,
                timestamp_digest,
                Rfc3161TimestampAttribute::MicrosoftAuthenticode,
                "appinstaller-sign-companion",
            )?;
            std::fs::write(&output, &pkcs7).with_context(|| format!("write {}", output.display()))?;
            println!("output={}", output.display());
            println!("digest={digest:?}");
            println!("companion_signature_len={}", pkcs7.len());
        }
        Command::AppinstallerSignCompanionPrehash {
            path,
            digest,
            encoding,
            output,
        } => {
            let text =
                std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            parse_appinstaller_descriptor(&text)
                .with_context(|| format!("appinstaller-sign-companion-prehash {}", path.display()))?;
            let prehash = pkcs7_id_data_remote_prehash(
                text.as_bytes(),
                digest,
                pkcs7::Pkcs7SignedAttributeProfile::Basic,
                None,
            )?;
            write_digest_output(encoding, &prehash, output.as_deref())?;
        }
        Command::AppinstallerSignCompanionFromSignature {
            path,
            cert,
            chain_certs,
            digest,
            signature,
            timestamp_url,
            timestamp_digest,
            output,
        } => {
            let text =
                std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            parse_appinstaller_descriptor(&text).with_context(|| {
                format!(
                    "appinstaller-sign-companion-from-signature {}",
                    path.display()
                )
            })?;
            let signature_bytes = std::fs::read(&signature)
                .with_context(|| format!("read {}", signature.display()))?;
            let pkcs7 = sign_pkcs7_id_data_with_external_signature(
                text.as_bytes(),
                &cert,
                chain_certs,
                digest,
                &signature_bytes,
                pkcs7::Pkcs7ContentMode::Detached,
                pkcs7::Pkcs7SignedAttributeProfile::Basic,
            )
            .with_context(|| {
                format!(
                    "appinstaller-sign-companion-from-signature create detached PKCS#7 for {}",
                    path.display()
                )
            })?;
            let pkcs7 = timestamp_pkcs7_if_requested(
                &pkcs7,
                timestamp_url,
                timestamp_digest,
                Rfc3161TimestampAttribute::MicrosoftAuthenticode,
                "appinstaller-sign-companion-from-signature",
            )?;
            std::fs::write(&output, &pkcs7).with_context(|| format!("write {}", output.display()))?;
            println!("output={}", output.display());
            println!("digest={digest:?}");
            println!("companion_signature_len={}", pkcs7.len());
        }
        Command::AppinstallerSetPublisher {
            path,
            publisher,
            output,
        } => {
            let text =
                std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let updated = update_appinstaller_publisher(&text, &publisher)
                .with_context(|| format!("appinstaller-set-publisher {}", path.display()))?;
            std::fs::write(&output, updated).with_context(|| format!("write {}", output.display()))?;
            println!("output={}", output.display());
            println!("publisher={publisher}");
        }
        Command::BusinessCentralAppInfo { path } => {
            let info = inspect_business_central_app(&path)
                .with_context(|| format!("business-central-app-info {}", path.display()))?;
            println!("business_central_app={}", if info.is_navx { "yes" } else { "no" });
            println!("header={}", if info.is_navx { "NAVX" } else { "-" });
            println!("len={}", info.len);
        }
    }
    Ok(())
}
