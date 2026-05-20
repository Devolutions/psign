use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::{ObjectIdentifier, SetOfVec};
use der::{Decode, Encode};
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::signature::{Keypair, SignatureEncoding, Signer};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

const OID_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const OID_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const DEFAULT_POLICY_OID: &str = "1.3.6.1.4.1.311.97.99.1";
const SHA256_WITH_RSA_ENCRYPTION_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];
const SHA1_ALGORITHM_IDENTIFIER_DER: &[u8] = &[
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
];
const OID_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

#[derive(Parser, Debug)]
#[command(name = "psign-server", version, about = "Local psign test services")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve a local RFC 3161 timestamp authority for deterministic tests.
    TimestampServer(TimestampServerArgs),
    /// Serve local code-signing PKI material for online certificate feature tests.
    PkiServer(PkiServerArgs),
}

#[derive(Parser, Debug)]
struct TimestampServerArgs {
    /// Address to bind, for example 127.0.0.1:0 for an ephemeral port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    /// RFC 3161 PKIStatus to return.
    #[arg(long, value_enum, default_value_t = ServerStatus::Granted)]
    status: ServerStatus,
    /// Deterministic response variant for negative-path tests.
    #[arg(long, value_enum, default_value_t = ResponseMode::Valid)]
    response_mode: ResponseMode,
    /// Deterministic GeneralizedTime value for TSTInfo.genTime.
    #[arg(long, default_value = "20240102030405Z")]
    gen_time: String,
    /// Write the generated TSA root certificate as DER for local trust-store setup.
    #[arg(long, value_name = "PATH")]
    cert_output: Option<PathBuf>,
    /// Write the generated TSA leaf certificate as DER for local trust-store setup.
    #[arg(long, value_name = "PATH")]
    tsa_cert_output: Option<PathBuf>,
    /// Exit after serving this many requests. Zero means run until interrupted.
    #[arg(long, default_value_t = 0)]
    max_requests: u64,
}

#[derive(Parser, Debug)]
struct PkiServerArgs {
    /// Address to bind, for example 127.0.0.1:0 for an ephemeral port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
    /// Write the generated root certificate as DER for local trust-anchor setup.
    #[arg(long, value_name = "PATH")]
    root_cert_output: Option<PathBuf>,
    /// Write the generated code-signing leaf certificate as DER.
    #[arg(long, value_name = "PATH")]
    leaf_cert_output: Option<PathBuf>,
    /// Write the generated code-signing leaf private key as unencrypted PKCS#8 DER.
    #[arg(long, value_name = "PATH")]
    leaf_key_output: Option<PathBuf>,
    /// Include the generated code-signing leaf serial in the served CRL.
    #[arg(long)]
    crl_revoke_leaf: bool,
    /// OCSP certificate status to return for the generated code-signing leaf.
    #[arg(long, value_enum, default_value_t = PkiOcspStatus::Good)]
    ocsp_status: PkiOcspStatus,
    /// Exit after serving this many requests. Zero means run until interrupted.
    #[arg(long, default_value_t = 0)]
    max_requests: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ServerStatus {
    Granted,
    Rejection,
    Waiting,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PkiOcspStatus {
    Good,
    Revoked,
    Unknown,
}

impl ServerStatus {
    fn pki_status(self) -> u32 {
        match self {
            Self::Granted => 0,
            Self::Rejection => 2,
            Self::Waiting => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ResponseMode {
    /// Return a normal RFC 3161 response for the selected PKIStatus.
    Valid,
    /// Return rejection + PKIFailureInfo badAlg.
    BadAlg,
    /// Return HTTP 500 instead of a TimeStampResp body.
    HttpError,
    /// Return malformed DER with HTTP 200.
    MalformedDer,
    /// Return a granted token whose TSTInfo messageImprint differs from the request.
    MismatchedImprint,
    /// Return a granted token with one byte flipped after signing.
    InvalidSignature,
}

struct TimestampAuthority {
    cert: Certificate,
    root_cert: Certificate,
    key: SigningKey<Sha256>,
    serial: AtomicU64,
}

#[derive(Debug)]
struct TimestampRequest {
    digest_alg_tlv: Vec<u8>,
    hashed_message: Vec<u8>,
    nonce_tlv: Option<Vec<u8>>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::TimestampServer(args) => run_timestamp_server(args),
        Command::PkiServer(args) => run_pki_server(args),
    }
}

fn run_timestamp_server(args: TimestampServerArgs) -> Result<()> {
    validate_generalized_time_z(&args.gen_time)?;
    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("bind {}", args.listen))?;
    let local = listener.local_addr().context("read listener address")?;
    let tsa = TimestampAuthority::new()?;
    if let Some(path) = &args.cert_output {
        std::fs::write(
            path,
            tsa.root_cert
                .to_der()
                .context("encode generated TSA root certificate")?,
        )
        .with_context(|| format!("write generated TSA root certificate {}", path.display()))?;
    }
    if let Some(path) = &args.tsa_cert_output {
        std::fs::write(
            path,
            tsa.cert
                .to_der()
                .context("encode generated TSA leaf certificate")?,
        )
        .with_context(|| format!("write generated TSA leaf certificate {}", path.display()))?;
    }
    println!("psign-server timestamp-server listening on http://{local}/");
    std::io::stdout().flush().ok();

    for (served, stream) in listener.incoming().enumerate() {
        let stream = stream.context("accept HTTP client")?;
        if let Err(e) = handle_client(stream, &tsa, &args) {
            eprintln!("request failed: {e:#}");
        }
        if args.max_requests != 0 && (served as u64 + 1) >= args.max_requests {
            break;
        }
    }
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    tsa: &TimestampAuthority,
    args: &TimestampServerArgs,
) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("set read timeout")?;
    let request = read_http_request(&mut stream)?;
    if request.method != "POST" {
        return write_http_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain",
            b"timestamp server expects POST",
        );
    }
    if matches!(args.response_mode, ResponseMode::HttpError) {
        return write_http_response(
            &mut stream,
            500,
            "Internal Server Error",
            "text/plain",
            b"psign-server configured HTTP error",
        );
    }
    let response_der = match args.response_mode {
        ResponseMode::Valid => {
            if args.status.pki_status() == 0 {
                let ts_req = parse_timestamp_request_der(&request.body)?;
                tsa.build_time_stamp_response(&ts_req, &args.gen_time)?
            } else {
                build_status_only_response(
                    args.status.pki_status(),
                    Some("psign-server configured failure"),
                    None,
                )
            }
        }
        ResponseMode::BadAlg => {
            build_status_only_response(2, Some("psign-server configured badAlg"), Some(0))
        }
        ResponseMode::MalformedDer => vec![0x30, 0x80, 0x00, 0x00],
        ResponseMode::MismatchedImprint => {
            let mut ts_req = parse_timestamp_request_der(&request.body)?;
            if let Some(first) = ts_req.hashed_message.first_mut() {
                *first ^= 0xff;
            }
            tsa.build_time_stamp_response(&ts_req, &args.gen_time)?
        }
        ResponseMode::InvalidSignature => {
            let ts_req = parse_timestamp_request_der(&request.body)?;
            let mut der = tsa.build_time_stamp_response(&ts_req, &args.gen_time)?;
            if let Some(last) = der.last_mut() {
                *last ^= 0x01;
            }
            der
        }
        ResponseMode::HttpError => unreachable!("handled before TimeStampResp construction"),
    };
    write_http_response(
        &mut stream,
        200,
        "OK",
        "application/timestamp-reply",
        &response_der,
    )
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).context("read HTTP request")?;
        if n == 0 {
            return Err(anyhow!("client closed before HTTP headers completed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(anyhow!("HTTP headers too large"));
        }
    }

    let headers = std::str::from_utf8(&buf[..header_end]).context("HTTP headers are not UTF-8")?;
    let request_line = headers
        .lines()
        .next()
        .ok_or_else(|| anyhow!("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?
        .to_string();
    let content_len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buf.len() < body_start + content_len {
        let n = stream.read(&mut tmp).context("read HTTP body")?;
        if n == 0 {
            return Err(anyhow!("client closed before HTTP body completed"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(HttpRequest {
        method,
        path,
        body: buf[body_start..body_start + content_len].to_vec(),
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .context("write HTTP response headers")?;
    stream.write_all(body).context("write HTTP response body")
}

struct PkiAuthority {
    root_cert: Certificate,
    leaf_cert: Certificate,
    leaf_key_der: Vec<u8>,
    crl_der: Vec<u8>,
    ocsp_der: Vec<u8>,
}

fn run_pki_server(args: PkiServerArgs) -> Result<()> {
    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("bind {}", args.listen))?;
    let local = listener.local_addr().context("read listener address")?;
    let pki = PkiAuthority::new(args.crl_revoke_leaf, args.ocsp_status)?;

    if let Some(path) = &args.root_cert_output {
        std::fs::write(
            path,
            pki.root_cert
                .to_der()
                .context("encode generated PKI root certificate")?,
        )
        .with_context(|| format!("write generated PKI root certificate {}", path.display()))?;
    }
    if let Some(path) = &args.leaf_cert_output {
        std::fs::write(
            path,
            pki.leaf_cert
                .to_der()
                .context("encode generated PKI leaf certificate")?,
        )
        .with_context(|| format!("write generated PKI leaf certificate {}", path.display()))?;
    }
    if let Some(path) = &args.leaf_key_output {
        std::fs::write(path, &pki.leaf_key_der)
            .with_context(|| format!("write generated PKI leaf private key {}", path.display()))?;
    }

    println!("psign-server pki-server listening on http://{local}/");
    println!("psign-server pki-server root http://{local}/root.der");
    println!("psign-server pki-server issuer http://{local}/issuer.der");
    println!("psign-server pki-server leaf http://{local}/leaf.der");
    println!("psign-server pki-server crl http://{local}/crl.der");
    println!("psign-server pki-server ocsp http://{local}/ocsp");
    std::io::stdout().flush().ok();

    for (served, stream) in listener.incoming().enumerate() {
        let stream = stream.context("accept HTTP client")?;
        if let Err(e) = handle_pki_client(stream, &pki) {
            eprintln!("request failed: {e:#}");
        }
        if args.max_requests != 0 && (served as u64 + 1) >= args.max_requests {
            break;
        }
    }
    Ok(())
}

fn handle_pki_client(mut stream: TcpStream, pki: &PkiAuthority) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("set read timeout")?;
    let request = read_http_request(&mut stream)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/" | "/health") => {
            write_http_response(&mut stream, 200, "OK", "text/plain", b"ok\n")
        }
        ("GET", "/root.der" | "/issuer.der") => write_http_response(
            &mut stream,
            200,
            "OK",
            "application/pkix-cert",
            &pki.root_cert
                .to_der()
                .context("encode PKI root certificate")?,
        ),
        ("GET", "/leaf.der") => write_http_response(
            &mut stream,
            200,
            "OK",
            "application/pkix-cert",
            &pki.leaf_cert
                .to_der()
                .context("encode PKI leaf certificate")?,
        ),
        ("GET", "/crl.der") => {
            write_http_response(&mut stream, 200, "OK", "application/pkix-crl", &pki.crl_der)
        }
        ("POST", "/ocsp") => write_http_response(
            &mut stream,
            200,
            "OK",
            "application/ocsp-response",
            &pki.ocsp_der,
        ),
        _ => write_http_response(&mut stream, 404, "Not Found", "text/plain", b"not found\n"),
    }
}

impl PkiAuthority {
    fn new(revoke_leaf: bool, ocsp_status: PkiOcspStatus) -> Result<Self> {
        let root_private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).context("generate PKI root RSA key")?;
        let root_key = SigningKey::<Sha256>::new(root_private_key);
        let root_subject = Name::from_str("CN=psign local online certificate test root CA")
            .context("PKI root subject")?;
        let root_spki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key())
            .context("PKI root subject public key info")?;
        let root_builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(10u32),
            Validity::from_now(Duration::from_secs(86_400 * 365)).context("PKI root validity")?,
            root_subject.clone(),
            root_spki,
            &root_key,
        )
        .context("PKI root certificate builder")?;
        let root_cert = root_builder
            .build::<rsa::pkcs1v15::Signature>()
            .context("self-sign PKI root certificate")?;

        let leaf_private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).context("generate code-signing leaf RSA key")?;
        let leaf_key_der = leaf_private_key
            .to_pkcs8_der()
            .context("encode code-signing leaf private key")?
            .as_bytes()
            .to_vec();
        let leaf_key = SigningKey::<Sha256>::new(leaf_private_key);
        let leaf_subject = Name::from_str("CN=psign local online code signing leaf")
            .context("PKI leaf subject")?;
        let leaf_spki = SubjectPublicKeyInfoOwned::from_key(leaf_key.verifying_key())
            .context("PKI leaf subject public key info")?;
        let mut leaf_builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_subject,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(11u32),
            Validity::from_now(Duration::from_secs(86_400 * 365)).context("PKI leaf validity")?,
            leaf_subject,
            leaf_spki,
            &root_key,
        )
        .context("PKI leaf certificate builder")?;
        leaf_builder
            .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
            .context("add code-signing EKU")?;
        let leaf_cert = leaf_builder
            .build::<rsa::pkcs1v15::Signature>()
            .context("sign PKI leaf certificate")?;
        let crl_der = build_crl_der(&root_cert, &root_key, revoke_leaf.then_some(&leaf_cert))?;
        let ocsp_der = build_ocsp_response_der(&root_cert, &root_key, &leaf_cert, ocsp_status)?;

        Ok(Self {
            root_cert,
            leaf_cert,
            leaf_key_der,
            crl_der,
            ocsp_der,
        })
    }
}

fn build_ocsp_response_der(
    issuer: &Certificate,
    issuer_key: &SigningKey<Sha256>,
    leaf: &Certificate,
    status: PkiOcspStatus,
) -> Result<Vec<u8>> {
    let mut cert_id_body = Vec::new();
    cert_id_body.extend_from_slice(SHA1_ALGORITHM_IDENTIFIER_DER);
    cert_id_body.extend_from_slice(&octet_string_der(&Sha1::digest(
        issuer
            .tbs_certificate
            .subject
            .to_der()
            .context("encode OCSP issuer subject")?,
    )));
    cert_id_body.extend_from_slice(&octet_string_der(&Sha1::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )));
    cert_id_body.extend_from_slice(
        &leaf
            .tbs_certificate
            .serial_number
            .to_der()
            .context("encode OCSP leaf serial")?,
    );
    let mut cert_id = Vec::new();
    push_sequence(&mut cert_id, &cert_id_body);

    let mut single_body = Vec::new();
    single_body.extend_from_slice(&cert_id);
    match status {
        PkiOcspStatus::Good => push_tlv(&mut single_body, 0x80, &[]),
        PkiOcspStatus::Revoked => {
            let mut revoked = Vec::new();
            push_generalized_time(&mut revoked, "20240101000000Z")?;
            push_tlv(&mut single_body, 0xa1, &revoked);
        }
        PkiOcspStatus::Unknown => push_tlv(&mut single_body, 0x82, &[]),
    }
    push_generalized_time(&mut single_body, "20240101000000Z")?;
    let mut next_update = Vec::new();
    push_generalized_time(&mut next_update, "20490101000000Z")?;
    push_tlv(&mut single_body, 0xa0, &next_update);
    let mut single = Vec::new();
    push_sequence(&mut single, &single_body);

    let mut responses = Vec::new();
    push_sequence(&mut responses, &single);

    let mut response_data_body = Vec::new();
    response_data_body.extend_from_slice(&context_constructed_der(
        0xa1,
        &issuer
            .tbs_certificate
            .subject
            .to_der()
            .context("encode OCSP responder name")?,
    ));
    push_generalized_time(&mut response_data_body, "20240101000000Z")?;
    response_data_body.extend_from_slice(&responses);
    let mut response_data = Vec::new();
    push_sequence(&mut response_data, &response_data_body);

    let sig = issuer_key.sign(&response_data).to_bytes();
    let mut sig_bits = Vec::with_capacity(sig.len() + 1);
    sig_bits.push(0);
    sig_bits.extend_from_slice(&sig);

    let mut basic_body = Vec::new();
    basic_body.extend_from_slice(&response_data);
    basic_body.extend_from_slice(SHA256_WITH_RSA_ENCRYPTION_DER);
    push_tlv(&mut basic_body, 0x03, &sig_bits);
    let mut basic = Vec::new();
    push_sequence(&mut basic, &basic_body);

    let mut response_bytes_body = Vec::new();
    push_oid(&mut response_bytes_body, OID_OCSP_BASIC)?;
    push_octet_string(&mut response_bytes_body, &basic);
    let mut response_bytes = Vec::new();
    push_sequence(&mut response_bytes, &response_bytes_body);

    let mut ocsp_response_body = Vec::new();
    push_tlv(&mut ocsp_response_body, 0x0a, &[0]);
    push_tlv(&mut ocsp_response_body, 0xa0, &response_bytes);
    let mut ocsp_response = Vec::new();
    push_sequence(&mut ocsp_response, &ocsp_response_body);
    Ok(ocsp_response)
}

fn build_crl_der(
    issuer: &Certificate,
    issuer_key: &SigningKey<Sha256>,
    revoked_leaf: Option<&Certificate>,
) -> Result<Vec<u8>> {
    let mut tbs_body = Vec::new();
    push_integer_u64(&mut tbs_body, 1);
    tbs_body.extend_from_slice(SHA256_WITH_RSA_ENCRYPTION_DER);
    tbs_body.extend_from_slice(
        &issuer
            .tbs_certificate
            .subject
            .to_der()
            .context("encode CRL issuer subject")?,
    );
    push_utctime(&mut tbs_body, "240101000000Z");
    push_utctime(&mut tbs_body, "490101000000Z");

    if let Some(cert) = revoked_leaf {
        let mut entry = Vec::new();
        entry.extend_from_slice(
            &cert
                .tbs_certificate
                .serial_number
                .to_der()
                .context("encode revoked certificate serial")?,
        );
        push_utctime(&mut entry, "240101000000Z");
        let mut entry_seq = Vec::new();
        push_sequence(&mut entry_seq, &entry);

        let mut revoked = Vec::new();
        revoked.extend_from_slice(&entry_seq);
        push_sequence(&mut tbs_body, &revoked);
    }

    let mut tbs = Vec::new();
    push_sequence(&mut tbs, &tbs_body);
    let sig = issuer_key.sign(&tbs).to_bytes();
    let mut sig_bits = Vec::with_capacity(sig.len() + 1);
    sig_bits.push(0);
    sig_bits.extend_from_slice(&sig);

    let mut crl_body = Vec::new();
    crl_body.extend_from_slice(&tbs);
    crl_body.extend_from_slice(SHA256_WITH_RSA_ENCRYPTION_DER);
    push_tlv(&mut crl_body, 0x03, &sig_bits);
    let mut crl = Vec::new();
    push_sequence(&mut crl, &crl_body);
    Ok(crl)
}

impl TimestampAuthority {
    fn new() -> Result<Self> {
        let root_private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).context("generate TSA root RSA key")?;
        let root_key = SigningKey::<Sha256>::new(root_private_key);
        let root_subject =
            Name::from_str("CN=psign local timestamp test root CA").context("TSA root subject")?;
        let root_spki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key())
            .context("TSA root subject public key info")?;
        let root_builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(86_400 * 365)).context("TSA root validity")?,
            root_subject.clone(),
            root_spki,
            &root_key,
        )
        .context("TSA root certificate builder")?;
        let root_cert = root_builder
            .build::<rsa::pkcs1v15::Signature>()
            .context("self-sign TSA root certificate")?;

        let private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).context("generate TSA leaf RSA key")?;
        let key = SigningKey::<Sha256>::new(private_key);
        let subject = Name::from_str("CN=psign local timestamp test TSA").context("TSA subject")?;
        let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key())
            .context("TSA subject public key info")?;
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_subject,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            Validity::from_now(Duration::from_secs(86_400 * 365)).context("TSA validity")?,
            subject,
            spki,
            &root_key,
        )
        .context("TSA certificate builder")?;
        builder
            .add_extension(&ExtendedKeyUsage(vec![OID_TIME_STAMPING]))
            .context("add TSA EKU")?;
        let cert = builder
            .build::<rsa::pkcs1v15::Signature>()
            .context("sign TSA certificate")?;
        Ok(Self {
            cert,
            root_cert,
            key,
            serial: AtomicU64::new(1),
        })
    }

    fn build_time_stamp_response(&self, req: &TimestampRequest, gen_time: &str) -> Result<Vec<u8>> {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        let tst_info = build_tst_info(req, serial, gen_time)?;
        let token = self.build_time_stamp_token(&tst_info)?;
        build_granted_response(&token)
    }

    fn build_time_stamp_token(&self, tst_info: &[u8]) -> Result<Vec<u8>> {
        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: None,
        };
        let econtent = der::asn1::Any::new(der::Tag::OctetString, tst_info)
            .map_err(|e| anyhow!("TSTInfo eContent: {e}"))?;
        let content = EncapsulatedContentInfo {
            econtent_type: OID_TSTINFO,
            econtent: Some(econtent),
        };
        let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: self.cert.tbs_certificate.issuer.clone(),
            serial_number: self.cert.tbs_certificate.serial_number.clone(),
        });
        let mut signer_info = SignerInfoBuilder::new(
            &self.key,
            signer_id,
            digest_algorithm.clone(),
            &content,
            None,
        )
        .map_err(|e| anyhow!("build timestamp token SignerInfo: {e}"))?;
        signer_info
            .add_signed_attribute(signing_certificate_v2_attribute(&self.cert)?)
            .map_err(|e| anyhow!("add timestamp SigningCertificateV2 attribute: {e}"))?;
        let mut builder = SignedDataBuilder::new(&content);
        let signed_data = builder
            .add_digest_algorithm(digest_algorithm)
            .map_err(|e| anyhow!("add timestamp digest algorithm: {e}"))?
            .add_certificate(CertificateChoices::Certificate(self.cert.clone()))
            .map_err(|e| anyhow!("add timestamp TSA certificate: {e}"))?
            .add_certificate(CertificateChoices::Certificate(self.root_cert.clone()))
            .map_err(|e| anyhow!("add timestamp TSA root certificate: {e}"))?
            .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info)
            .map_err(|e| anyhow!("sign timestamp token signed attributes: {e}"))?
            .build()
            .map_err(|e| anyhow!("build timestamp token SignedData: {e}"))?;
        signed_data
            .to_der()
            .map_err(|e| anyhow!("encode timestamp token ContentInfo: {e}"))
    }
}

fn signing_certificate_v2_attribute(cert: &Certificate) -> Result<Attribute> {
    let cert_der = cert
        .to_der()
        .context("encode TSA certificate for ESSCertIDv2")?;
    let cert_hash = Sha256::digest(&cert_der);

    let mut ess_cert_id_v2_body = Vec::new();
    push_octet_string(&mut ess_cert_id_v2_body, &cert_hash);
    ess_cert_id_v2_body.extend_from_slice(&issuer_serial_der(cert)?);
    let mut ess_cert_id_v2 = Vec::new();
    push_sequence(&mut ess_cert_id_v2, &ess_cert_id_v2_body);

    let mut certs_body = Vec::new();
    certs_body.extend_from_slice(&ess_cert_id_v2);
    let mut certs = Vec::new();
    push_sequence(&mut certs, &certs_body);

    let mut signing_certificate_v2_body = Vec::new();
    signing_certificate_v2_body.extend_from_slice(&certs);
    let mut signing_certificate_v2 = Vec::new();
    push_sequence(&mut signing_certificate_v2, &signing_certificate_v2_body);

    let mut values = SetOfVec::new();
    values
        .insert(AttributeValue::from_der(&signing_certificate_v2)?)
        .map_err(|e| anyhow!("insert SigningCertificateV2 attribute value: {e}"))?;
    Ok(Attribute {
        oid: OID_SIGNING_CERTIFICATE_V2,
        values,
    })
}

fn issuer_serial_der(cert: &Certificate) -> Result<Vec<u8>> {
    let issuer_der = cert
        .tbs_certificate
        .issuer
        .to_der()
        .context("encode TSA issuer name")?;
    let mut general_names_body = Vec::new();
    push_tlv(&mut general_names_body, 0xa4, &issuer_der);
    let mut general_names = Vec::new();
    push_sequence(&mut general_names, &general_names_body);

    let serial_der = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .context("encode TSA serial number")?;
    let mut issuer_serial_body = Vec::new();
    issuer_serial_body.extend_from_slice(&general_names);
    issuer_serial_body.extend_from_slice(&serial_der);
    let mut issuer_serial = Vec::new();
    push_sequence(&mut issuer_serial, &issuer_serial_body);
    Ok(issuer_serial)
}

fn parse_timestamp_request_der(input: &[u8]) -> Result<TimestampRequest> {
    let outer = expect_tlv(input, 0x30).context("TimeStampReq SEQUENCE")?;
    let mut pos = 0usize;
    let version = read_tlv(outer, &mut pos).context("TimeStampReq.version")?;
    if version != [0x02, 0x01, 0x01] {
        return Err(anyhow!("unsupported TimeStampReq version"));
    }
    let imprint_tlv = read_tlv(outer, &mut pos).context("TimeStampReq.messageImprint")?;
    let imprint = expect_tlv(imprint_tlv, 0x30).context("MessageImprint SEQUENCE")?;
    let mut ipos = 0usize;
    let digest_alg_tlv = read_tlv(imprint, &mut ipos)
        .context("MessageImprint.hashAlgorithm")?
        .to_vec();
    let hashed_tlv = read_tlv(imprint, &mut ipos).context("MessageImprint.hashedMessage")?;
    if ipos != imprint.len() {
        return Err(anyhow!("MessageImprint has trailing fields"));
    }
    let hashed_message = expect_tlv(hashed_tlv, 0x04)
        .context("hashedMessage OCTET STRING")?
        .to_vec();
    let mut nonce_tlv = None;
    while pos < outer.len() {
        let tlv = read_tlv(outer, &mut pos).context("TimeStampReq optional field")?;
        match tlv.first().copied() {
            Some(0x02) => nonce_tlv = Some(tlv.to_vec()),
            Some(0x01) => {}
            Some(0x06) => {}
            Some(0xa0) => {}
            _ => return Err(anyhow!("unsupported TimeStampReq optional field")),
        }
    }
    Ok(TimestampRequest {
        digest_alg_tlv,
        hashed_message,
        nonce_tlv,
    })
}

fn build_tst_info(req: &TimestampRequest, serial: u64, gen_time: &str) -> Result<Vec<u8>> {
    let mut imprint = Vec::new();
    imprint.extend_from_slice(&req.digest_alg_tlv);
    push_octet_string(&mut imprint, &req.hashed_message);

    let mut body = Vec::new();
    push_integer_u64(&mut body, 1);
    push_oid(&mut body, DEFAULT_POLICY_OID)?;
    push_sequence(&mut body, &imprint);
    push_integer_u64(&mut body, serial);
    push_generalized_time(&mut body, gen_time)?;
    if let Some(nonce) = &req.nonce_tlv {
        body.extend_from_slice(nonce);
    }
    let mut out = Vec::new();
    push_sequence(&mut out, &body);
    Ok(out)
}

fn build_granted_response(token: &[u8]) -> Result<Vec<u8>> {
    let mut status_info = Vec::new();
    push_integer_u64(&mut status_info, 0);
    let mut body = Vec::new();
    push_sequence(&mut body, &status_info);
    body.extend_from_slice(token);
    let mut out = Vec::new();
    push_sequence(&mut out, &body);
    Ok(out)
}

fn build_status_only_response(
    status: u32,
    text: Option<&str>,
    fail_info_bit: Option<u8>,
) -> Vec<u8> {
    let mut status_info = Vec::new();
    push_integer_u64(&mut status_info, status as u64);
    if let Some(text) = text {
        let mut strings = Vec::new();
        push_utf8_string(&mut strings, text);
        push_sequence(&mut status_info, &strings);
    }
    if let Some(bit) = fail_info_bit {
        push_pkifailure_info(&mut status_info, bit);
    }
    let mut body = Vec::new();
    push_sequence(&mut body, &status_info);
    let mut out = Vec::new();
    push_sequence(&mut out, &body);
    out
}

fn push_pkifailure_info(out: &mut Vec<u8>, bit: u8) {
    let byte = 0x80u8 >> (bit % 8);
    let unused = 7 - (bit % 8);
    out.extend_from_slice(&[0x03, 0x02, unused, byte]);
}

fn expect_tlv(input: &[u8], tag: u8) -> Result<&[u8]> {
    if input.first().copied() != Some(tag) {
        return Err(anyhow!("unexpected tag"));
    }
    let (body_start, len) = read_len(input, 1)?;
    let end = body_start
        .checked_add(len)
        .ok_or_else(|| anyhow!("TLV length overflow"))?;
    if end != input.len() {
        return Err(anyhow!("TLV trailing bytes"));
    }
    Ok(&input[body_start..end])
}

fn read_tlv<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let start = *pos;
    let tag_pos = *pos;
    if tag_pos >= input.len() {
        return Err(anyhow!("missing TLV tag"));
    }
    *pos += 1;
    let (body_start, len) = read_len(input, *pos)?;
    let end = body_start
        .checked_add(len)
        .ok_or_else(|| anyhow!("TLV length overflow"))?;
    if end > input.len() {
        return Err(anyhow!("TLV length exceeds input"));
    }
    *pos = end;
    Ok(&input[start..end])
}

fn read_len(input: &[u8], mut pos: usize) -> Result<(usize, usize)> {
    let first = *input.get(pos).ok_or_else(|| anyhow!("missing length"))?;
    pos += 1;
    if first < 0x80 {
        return Ok((pos, first as usize));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 3 {
        return Err(anyhow!("unsupported DER length form"));
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | (*input.get(pos).ok_or_else(|| anyhow!("truncated length"))? as usize);
        pos += 1;
    }
    Ok((pos, len))
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len <= 0xffff {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    push_len(out, body.len());
    out.extend_from_slice(body);
}

fn push_sequence(out: &mut Vec<u8>, body: &[u8]) {
    push_tlv(out, 0x30, body);
}

fn push_octet_string(out: &mut Vec<u8>, body: &[u8]) {
    push_tlv(out, 0x04, body);
}

fn octet_string_der(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_octet_string(&mut out, body);
    out
}

fn context_constructed_der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_tlv(&mut out, tag, body);
    out
}

fn push_utf8_string(out: &mut Vec<u8>, body: &str) {
    push_tlv(out, 0x0c, body.as_bytes());
}

fn push_generalized_time(out: &mut Vec<u8>, value: &str) -> Result<()> {
    validate_generalized_time_z(value)?;
    push_tlv(out, 0x18, value.as_bytes());
    Ok(())
}

fn push_utctime(out: &mut Vec<u8>, value: &str) {
    push_tlv(out, 0x17, value.as_bytes());
}

fn validate_generalized_time_z(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 15 || !bytes[..14].iter().all(u8::is_ascii_digit) || bytes[14] != b'Z' {
        return Err(anyhow!(
            "--gen-time must be DER GeneralizedTime in YYYYMMDDhhmmssZ form"
        ));
    }
    Ok(())
}

fn push_integer_u64(out: &mut Vec<u8>, value: u64) {
    let mut tmp = [0u8; 9];
    let mut n = value;
    let mut pos = tmp.len();
    if n == 0 {
        pos -= 1;
        tmp[pos] = 0;
    } else {
        while n != 0 {
            pos -= 1;
            tmp[pos] = (n & 0xff) as u8;
            n >>= 8;
        }
        if tmp[pos] & 0x80 != 0 {
            pos -= 1;
            tmp[pos] = 0;
        }
    }
    push_tlv(out, 0x02, &tmp[pos..]);
}

fn push_oid(out: &mut Vec<u8>, oid: &str) -> Result<()> {
    let oid = ObjectIdentifier::new(oid).map_err(|e| anyhow!("invalid OID {oid}: {e}"))?;
    out.extend_from_slice(&oid.to_der().map_err(|e| anyhow!("encode OID {oid}: {e}"))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psign_sip_digest::timestamp::{
        Rfc3161TimestampRequestPlan, build_timestamp_request_bytes, parse_time_stamp_resp_der,
        parse_time_stamp_token_tst_info,
    };

    #[test]
    fn parse_request_extracts_imprint_and_nonce() {
        let req = build_timestamp_request_bytes(
            &Rfc3161TimestampRequestPlan {
                digest_alg_oid: "2.16.840.1.101.3.4.2.1",
                nonce: Some(7),
                cert_req: true,
            },
            &[0xabu8; 32],
        )
        .expect("request");
        let parsed = parse_timestamp_request_der(&req).expect("parse request");
        assert_eq!(parsed.hashed_message, vec![0xab; 32]);
        assert!(parsed.nonce_tlv.is_some());
    }

    #[test]
    fn status_only_rejection_is_inspectable_timestamp_response() {
        let der = build_status_only_response(2, Some("nope"), None);
        let parsed = parse_time_stamp_resp_der(&der).expect("response parse");
        assert_eq!(parsed.pki_status.as_raw_integer(), 2);
        assert_eq!(parsed.status_strings, vec!["nope"]);
        assert!(parsed.time_stamp_token.is_none());
    }

    #[test]
    fn status_only_bad_alg_sets_fail_info_bit() {
        let der = build_status_only_response(2, Some("bad"), Some(0));
        let parsed = parse_time_stamp_resp_der(&der).expect("response parse");
        assert_eq!(parsed.pki_status.as_raw_integer(), 2);
        let labels = psign_sip_digest::timestamp::pkifailure_info_flag_labels_from_bit_string_tlv(
            parsed.fail_info_tlv.expect("failInfo"),
        )
        .expect("failInfo labels");
        assert_eq!(labels, vec!["badAlg"]);
    }

    #[test]
    fn granted_response_contains_timestamp_token() {
        let req = build_timestamp_request_bytes(
            &Rfc3161TimestampRequestPlan {
                nonce: Some(7),
                ..Default::default()
            },
            &[0x11u8; 32],
        )
        .expect("request");
        let parsed = parse_timestamp_request_der(&req).expect("parse request");
        let tsa = TimestampAuthority::new().expect("tsa");
        let der = tsa
            .build_time_stamp_response(&parsed, "20240102030405Z")
            .expect("response");
        let parsed_resp = parse_time_stamp_resp_der(&der).expect("response parse");
        assert_eq!(parsed_resp.pki_status.as_raw_integer(), 0);
        assert!(
            parsed_resp
                .time_stamp_token
                .map(|t| t.len() > 128)
                .unwrap_or(false)
        );
        let token = parsed_resp.time_stamp_token.expect("token");
        let tst = parse_time_stamp_token_tst_info(token).expect("TSTInfo");
        assert_eq!(tst.gen_time, "20240102030405Z");
        assert_eq!(tst.message_imprint_hashed_message, vec![0x11; 32]);
        assert_eq!(tst.nonce_hex.as_deref(), Some("07"));
    }
}
