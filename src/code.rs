use crate::CommandOutput;
use crate::cli::{AzureCredentialType, CodeArgs, DigestAlgorithm};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
#[cfg(feature = "azure-kv-sign")]
use psign_azure_kv_rest::{
    KeyVaultCertificate, KvAuthParams, KvHashAlg, KvPublicKeyKind, acquire_kv_access_token,
    fetch_kv_certificate, kv_decode_cer_b64, kv_public_key_kind_from_cer_der,
    kv_sign_digest_from_certificate,
};
#[cfg(feature = "artifact-signing-rest")]
use psign_codesigning_rest::{
    CodesigningAuth, CodesigningAuthInput, CodesigningCredentialType, CodesigningSubmitParams,
    DEFAULT_API_VERSION, resolve_codesigning_auth, submit_codesign_hash_signature_blocking,
};
use psign_opc_sign::{nuget, opc, vsix};
use psign_sip_digest::timestamp::{build_timestamp_request_bytes, parse_time_stamp_resp_der};
use psign_sip_digest::{pe_digest, pe_embed, pkcs7, rdp, verify_pe};
use rsa::signature::{SignatureEncoding as _, Signer as _, hazmat::PrehashSigner as _};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::der::{
    Encode as _,
    asn1::{ObjectIdentifier, OctetString},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeFormat {
    Pe,
    Winmd,
    Cab,
    Msi,
    Msp,
    Mst,
    Catalog,
    Script,
    Msix,
    Appx,
    MsixBundle,
    AppxBundle,
    AppxUpload,
    MsixUpload,
    EncryptedMsix,
    Nuget,
    Snupkg,
    Vsix,
    ClickOnceApplication,
    Vsto,
    Manifest,
    Deploy,
    AppInstaller,
    BusinessCentralApp,
    Zip,
    Unknown,
}

impl CodeFormat {
    fn is_container(&self) -> bool {
        matches!(
            self,
            Self::Nuget
                | Self::Snupkg
                | Self::Vsix
                | Self::Msix
                | Self::Appx
                | Self::MsixBundle
                | Self::AppxBundle
                | Self::AppxUpload
                | Self::MsixUpload
                | Self::Zip
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CodePlan {
    pub base_directory: String,
    pub output: Option<String>,
    pub recurse_containers: bool,
    pub max_concurrency: Option<usize>,
    pub file_digest: String,
    pub timestamp_digest: Option<String>,
    pub timestamp_url: Option<String>,
    pub continue_on_error: bool,
    pub skip_signed: bool,
    pub nodes: Vec<CodePlanNode>,
    pub edges: Vec<CodePlanEdge>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CodePlanNode {
    pub id: usize,
    pub path: String,
    pub output_path: String,
    pub format: CodeFormat,
    pub depth: usize,
    pub container: bool,
    pub signer: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CodePlanEdge {
    pub before: usize,
    pub after: usize,
}

#[derive(Clone, Debug)]
struct PatternRule {
    include: bool,
    pattern: String,
}

#[derive(Default)]
struct PlanBuilder {
    nodes: Vec<CodePlanNode>,
    edges: Vec<CodePlanEdge>,
    node_ids: BTreeMap<String, usize>,
    nested_excludes: Vec<String>,
    output: Option<PathBuf>,
    top_level_count: usize,
}

pub fn code_command(args: &CodeArgs) -> Result<CommandOutput> {
    let plan = build_code_plan(args)?;
    if args.dry_run {
        let stdout = if args.plan_json {
            format!("{}\n", serde_json::to_string_pretty(&plan)?)
        } else {
            render_text_plan(&plan)
        };
        Ok(CommandOutput::ok(stdout))
    } else {
        execute_code_plan(args, &plan)
    }
}

pub fn build_code_plan(args: &CodeArgs) -> Result<CodePlan> {
    if args.max_concurrency == Some(0) {
        return Err(anyhow!("--max-concurrency must be greater than zero"));
    }
    match (args.timestamp_url.as_ref(), args.timestamp_digest) {
        (Some(_), None) => {
            return Err(anyhow!(
                "`psign-tool code` requires --timestamp-digest with --timestamp-url"
            ));
        }
        (None, Some(_)) => {
            return Err(anyhow!(
                "`psign-tool code` requires --timestamp-url with --timestamp-digest"
            ));
        }
        _ => {}
    }

    let base = args
        .base_directory
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let base = std::fs::canonicalize(&base)
        .with_context(|| format!("resolve base directory {}", base.display()))?;
    if !base.is_dir() {
        return Err(anyhow!(
            "base directory is not a directory: {}",
            base.display()
        ));
    }

    let rules = selection_rules(&base, args)?;
    let selected = select_inputs(&base, &rules)?;
    let nested_excludes = rules
        .iter()
        .filter(|rule| !rule.include)
        .map(|rule| rule.pattern.clone())
        .collect();
    let mut builder = PlanBuilder {
        nested_excludes,
        output: args.output.clone(),
        top_level_count: selected.len(),
        ..Default::default()
    };
    for path in selected {
        builder.add_path(&path, &base, 0, args.recurse_containers)?;
    }

    Ok(CodePlan {
        base_directory: display_path(&base),
        output: args.output.as_ref().map(|p| display_path(p)),
        recurse_containers: args.recurse_containers,
        max_concurrency: args.max_concurrency,
        file_digest: digest_name(args.file_digest).to_owned(),
        timestamp_digest: args.timestamp_digest.map(digest_name).map(str::to_owned),
        timestamp_url: args.timestamp_url.clone(),
        continue_on_error: args.continue_on_error,
        skip_signed: args.skip_signed,
        nodes: builder.nodes,
        edges: builder.edges,
    })
}

fn execute_code_plan(args: &CodeArgs, plan: &CodePlan) -> Result<CommandOutput> {
    let signer = resolve_code_signer(args)?;
    if args.output.is_none() {
        return Err(anyhow!(
            "`psign-tool code` signing execution currently requires --output to avoid in-place package mutation"
        ));
    }

    let digest = nuget_hash_algorithm(args.file_digest)?;
    let signing_digest = signing_digest_algorithm(args.file_digest)?;
    let base = PathBuf::from(&plan.base_directory);
    let vsix_digest = vsix_hash_algorithm(args.file_digest)?;
    let nested_excludes = nested_exclude_patterns(&base, args)?;

    let execute_node = |node: &CodePlanNode| -> Result<String> {
        let input = base.join(display_to_path(&node.path));
        match node.format {
            CodeFormat::Pe | CodeFormat::Winmd => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                if args.skip_signed && pe_has_signature(&input_bytes) {
                    std::fs::write(&output, input_bytes).with_context(|| {
                        format!("write skipped Authenticode payload {}", output.display())
                    })?;
                    Ok(format!(
                        "skipped {} -> {} (already signed)",
                        node.path,
                        display_path(&output)
                    ))
                } else {
                    let signed = sign_pe_bytes(
                        &input_bytes,
                        &node.path,
                        &signer,
                        signing_digest,
                        false,
                        args.timestamp_url.as_deref(),
                        args.timestamp_digest,
                    )
                    .with_context(|| format!("sign Authenticode payload {}", input.display()))?;
                    std::fs::write(&output, signed).with_context(|| {
                        format!("write signed Authenticode payload {}", output.display())
                    })?;
                    Ok(format!(
                        "signed {} -> {} (Authenticode PE/WinMD)",
                        node.path,
                        display_path(&output)
                    ))
                }
            }
            CodeFormat::Nuget | CodeFormat::Snupkg => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                if args.skip_signed && package_has_signature(&input_bytes, &node.format)? {
                    std::fs::write(&output, input_bytes).with_context(|| {
                        format!("write skipped NuGet package {}", output.display())
                    })?;
                    Ok(format!(
                        "skipped {} -> {} (already signed)",
                        node.path,
                        display_path(&output)
                    ))
                } else {
                    let signed = sign_nuget_bytes(
                        &input_bytes,
                        &node.path,
                        digest,
                        signing_digest,
                        &signer,
                        args.chain_certs.clone(),
                        &nested_excludes,
                        args.skip_signed,
                        args.overwrite,
                        None,
                        args.timestamp_url.as_deref(),
                        args.timestamp_digest,
                    )
                    .with_context(|| {
                        format!("create NuGet package signature for {}", input.display())
                    })?;
                    std::fs::write(&output, signed).with_context(|| {
                        format!("write signed NuGet package {}", output.display())
                    })?;
                    Ok(format!(
                        "signed {} -> {} ({})",
                        node.path,
                        display_path(&output),
                        nuget::PACKAGE_SIGNATURE_FILE_NAME
                    ))
                }
            }
            CodeFormat::AppInstaller => {
                let output = appinstaller_companion_output_path(node)?;
                ensure_parent_dir(&output)?;
                let mut bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                validate_appinstaller_descriptor(&bytes).with_context(|| {
                    format!("validate App Installer descriptor {}", input.display())
                })?;
                let descriptor_output = if let Some(publisher) = args.publisher_name.as_deref() {
                    bytes = update_appinstaller_publisher_bytes(&bytes, publisher).with_context(
                        || format!("update App Installer publisher for {}", input.display()),
                    )?;
                    let descriptor_output = appinstaller_descriptor_output_path(node)?;
                    ensure_parent_dir(&descriptor_output)?;
                    std::fs::write(&descriptor_output, &bytes).with_context(|| {
                        format!(
                            "write updated App Installer descriptor {}",
                            descriptor_output.display()
                        )
                    })?;
                    Some(descriptor_output)
                } else {
                    None
                };
                let pkcs7 = sign_pkcs7_id_data(
                    &bytes,
                    SignPkcs7IdDataOptions {
                        signer: &signer,
                        chain_certs: args.chain_certs.clone(),
                        digest: signing_digest,
                        timestamp_url: args.timestamp_url.as_deref(),
                        timestamp_digest: args.timestamp_digest,
                        content_mode: pkcs7::Pkcs7ContentMode::Detached,
                        timestamp_attribute: Rfc3161TimestampAttribute::MicrosoftAuthenticode,
                        signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile::Basic,
                    },
                )
                .with_context(|| {
                    format!(
                        "create App Installer companion signature for {}",
                        input.display()
                    )
                })?;
                std::fs::write(&output, pkcs7)
                    .with_context(|| format!("write {}", output.display()))?;
                if let Some(descriptor_output) = descriptor_output {
                    Ok(format!(
                        "signed {} -> {} (updated descriptor {}; detached PKCS#7 companion)",
                        node.path,
                        display_path(&output),
                        display_path(&descriptor_output)
                    ))
                } else {
                    Ok(format!(
                        "signed {} -> {} (detached PKCS#7 companion)",
                        node.path,
                        display_path(&output)
                    ))
                }
            }
            CodeFormat::Vsix => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                if args.skip_signed && package_has_signature(&input_bytes, &node.format)? {
                    std::fs::write(&output, input_bytes).with_context(|| {
                        format!("write skipped VSIX package {}", output.display())
                    })?;
                    Ok(format!(
                        "skipped {} -> {} (already signed)",
                        node.path,
                        display_path(&output)
                    ))
                } else {
                    let signed = sign_vsix_bytes(
                        &input_bytes,
                        &node.path,
                        digest,
                        signing_digest,
                        vsix_digest,
                        &signer,
                        args.chain_certs.clone(),
                        &nested_excludes,
                        args.skip_signed,
                        args.overwrite,
                        None,
                        args.timestamp_url.as_deref(),
                        args.timestamp_digest,
                    )
                    .with_context(|| format!("create VSIX signature for {}", input.display()))?;
                    std::fs::write(&output, signed).with_context(|| {
                        format!("write signed VSIX package {}", output.display())
                    })?;
                    Ok(format!(
                        "signed {} -> {} ({})",
                        node.path,
                        display_path(&output),
                        vsix::DEFAULT_VSIX_SIGNATURE_PART
                    ))
                }
            }
            CodeFormat::Zip => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                let signed = sign_zip_container_bytes(
                    &input_bytes,
                    &node.path,
                    digest,
                    signing_digest,
                    vsix_digest,
                    &signer,
                    args.chain_certs.clone(),
                    &nested_excludes,
                    args.skip_signed,
                    args.overwrite,
                    args.publisher_name.as_deref(),
                    args.timestamp_url.as_deref(),
                    args.timestamp_digest,
                )
                .with_context(|| format!("sign nested package entries in {}", input.display()))?;
                std::fs::write(&output, signed)
                    .with_context(|| format!("write signed ZIP container {}", output.display()))?;
                Ok(format!(
                    "signed {} -> {} (nested package entries)",
                    node.path,
                    display_path(&output)
                ))
            }
            CodeFormat::Msix
            | CodeFormat::Appx
            | CodeFormat::MsixBundle
            | CodeFormat::AppxBundle
            | CodeFormat::AppxUpload
            | CodeFormat::MsixUpload => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                let prepared = prepare_msix_family_bytes(
                    &input_bytes,
                    &node.path,
                    digest,
                    signing_digest,
                    vsix_digest,
                    &signer,
                    args.chain_certs.clone(),
                    &nested_excludes,
                    args.skip_signed,
                    args.overwrite,
                    node.format.clone(),
                    args.publisher_name.as_deref(),
                    args.timestamp_url.as_deref(),
                    args.timestamp_digest,
                )
                .with_context(|| format!("prepare MSIX/AppX package {}", input.display()))?;
                std::fs::write(&output, prepared).with_context(|| {
                    format!("write prepared MSIX/AppX package {}", output.display())
                })?;
                Ok(format!(
                    "prepared {} -> {} (unsigned MSIX/AppX; final AppX SIP signing pending)",
                    node.path,
                    display_path(&output)
                ))
            }
            CodeFormat::EncryptedMsix => Err(anyhow!(
                "`psign-tool code` recognized {} as an encrypted MSIX/AppX package; encrypted .eappx/.emsix packages require Windows AppxSip OS delegation and are not supported by the portable package prepare path",
                node.path
            )),
            CodeFormat::ClickOnceApplication | CodeFormat::Vsto | CodeFormat::Manifest => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                if args.skip_signed && clickonce_manifest_has_signature(&input_bytes) {
                    std::fs::write(&output, input_bytes).with_context(|| {
                        format!("write skipped ClickOnce manifest {}", output.display())
                    })?;
                    Ok(format!(
                        "skipped {} -> {} (already signed)",
                        node.path,
                        display_path(&output)
                    ))
                } else {
                    let signed = sign_clickonce_manifest_bytes(
                        &input_bytes,
                        &node.path,
                        &signer,
                        vsix_digest,
                        args.timestamp_url.as_deref(),
                        args.timestamp_digest,
                    )
                    .with_context(|| format!("sign ClickOnce manifest {}", input.display()))?;
                    std::fs::write(&output, signed).with_context(|| {
                        format!("write signed ClickOnce manifest {}", output.display())
                    })?;
                    Ok(format!(
                        "signed {} -> {} (ClickOnce manifest XMLDSig)",
                        node.path,
                        display_path(&output)
                    ))
                }
            }
            CodeFormat::Deploy => {
                let output = output_path_for_node(node)?;
                ensure_parent_dir(&output)?;
                let input_bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                let signed = sign_clickonce_deploy_bytes(
                    &input_bytes,
                    &node.path,
                    &signer,
                    signing_digest,
                    args.timestamp_url.as_deref(),
                    args.timestamp_digest,
                )
                .with_context(|| format!("sign ClickOnce deploy payload {}", input.display()))?;
                std::fs::write(&output, signed).with_context(|| {
                    format!("write signed ClickOnce deploy payload {}", output.display())
                })?;
                Ok(format!(
                    "signed {} -> {} (ClickOnce .deploy payload)",
                    node.path,
                    display_path(&output)
                ))
            }
            CodeFormat::BusinessCentralApp => Err(anyhow!(
                "`psign-tool code` recognized {} as a Business Central NAVX .app package, but Business Central package signing is not implemented yet",
                node.path
            )),
            _ => Err(anyhow!(
                "`psign-tool code` signing execution currently supports top-level PE/WinMD, NuGet/SNuGet, VSIX, ZIP, MSIX/AppX prepare, ClickOnce manifests, ClickOnce .deploy PE payloads, and App Installer descriptors only ({} is {:?})",
                node.path,
                node.format
            )),
        }
    };

    let mut lines = Vec::new();
    let mut exit_code = 0;
    let top_nodes: Vec<&CodePlanNode> = plan.nodes.iter().filter(|node| node.depth == 0).collect();
    let max_concurrency = args.max_concurrency.unwrap_or(1).max(1);
    if max_concurrency == 1 {
        for node in top_nodes {
            let result = execute_node(node);
            match result {
                Ok(line) => lines.push(line),
                Err(err) if args.continue_on_error => {
                    exit_code = 1;
                    lines.push(format!("failed {}: {err:#}", node.path));
                }
                Err(err) => return Err(err),
            };
        }
    } else {
        for chunk in top_nodes.chunks(max_concurrency) {
            let batch: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|node| {
                        let node = *node;
                        let execute_node = &execute_node;
                        scope.spawn(move || {
                            let result = execute_node(node);
                            (node.id, node.path.clone(), result)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("code signing worker panicked"))
                    .collect()
            });
            for (_id, path, result) in batch {
                match result {
                    Ok(line) => lines.push(line),
                    Err(err) if args.continue_on_error => {
                        exit_code = 1;
                        lines.push(format!("failed {path}: {err:#}"));
                    }
                    Err(err) => return Err(err),
                };
            }
        }
    }
    Ok(CommandOutput::with_exit(
        format!("{}\n", lines.join("\n")),
        exit_code,
    ))
}

#[allow(clippy::too_many_arguments)]
fn sign_nuget_bytes(
    input_bytes: &[u8],
    label: &str,
    digest: nuget::NuGetHashAlgorithm,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    signer: &CodeSigner,
    chain_certs: Vec<PathBuf>,
    nested_excludes: &[String],
    skip_signed: bool,
    overwrite: bool,
    publisher: Option<&str>,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    if skip_signed && package_has_signature(input_bytes, &CodeFormat::Nuget)? {
        return Ok(input_bytes.to_vec());
    }
    let updated = sign_nested_package_entries(
        input_bytes,
        label,
        digest,
        signing_digest,
        vsix::VsixHashAlgorithm::Sha256,
        signer,
        chain_certs.clone(),
        nested_excludes,
        skip_signed,
        overwrite,
        publisher,
        timestamp_url,
        timestamp_digest,
    )?;
    if !overwrite {
        ensure_nuget_unsigned(&updated, label)?;
    }
    let unsigned = nuget::canonical_unsigned_package_bytes(Cursor::new(updated))
        .with_context(|| format!("canonicalize NuGet package before signing {label}"))?;
    let content = nuget::signature_content_bytes(digest, &digest.hash(&unsigned));
    let pkcs7 = sign_pkcs7_id_data(
        &content,
        SignPkcs7IdDataOptions {
            signer,
            chain_certs,
            digest: signing_digest,
            timestamp_url,
            timestamp_digest,
            content_mode: pkcs7::Pkcs7ContentMode::Attached,
            timestamp_attribute: Rfc3161TimestampAttribute::CmsTimeStampToken,
            signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile::NuGetAuthor,
        },
    )?;
    let mut out = Cursor::new(Vec::new());
    nuget::embed_signature(Cursor::new(unsigned), &mut out, &pkcs7, false)
        .with_context(|| format!("embed NuGet signature into {label}"))?;
    Ok(out.into_inner())
}

#[allow(clippy::too_many_arguments)]
fn sign_vsix_bytes(
    input_bytes: &[u8],
    label: &str,
    digest: nuget::NuGetHashAlgorithm,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    vsix_digest: vsix::VsixHashAlgorithm,
    signer: &CodeSigner,
    chain_certs: Vec<PathBuf>,
    nested_excludes: &[String],
    skip_signed: bool,
    overwrite: bool,
    publisher: Option<&str>,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    if timestamp_url.is_some() || timestamp_digest.is_some() {
        return Err(anyhow!(
            "VSIX XMLDSig timestamping is not implemented in `psign-tool code` yet"
        ));
    }
    if skip_signed && package_has_signature(input_bytes, &CodeFormat::Vsix)? {
        return Ok(input_bytes.to_vec());
    }
    let updated = sign_nested_package_entries(
        input_bytes,
        label,
        digest,
        signing_digest,
        vsix_digest,
        signer,
        chain_certs,
        nested_excludes,
        skip_signed,
        overwrite,
        publisher,
        timestamp_url,
        timestamp_digest,
    )?;
    let signed_info = vsix::signed_info_xml(Cursor::new(updated.clone()), vsix_digest)
        .with_context(|| format!("create VSIX SignedInfo for {label}"))?;
    let (signature, cert_bytes) = signer.sign_xml_signed_info(vsix_digest, &signed_info)?;
    let xml = vsix::signature_xml_from_signed_info(&signed_info, &signature, Some(&cert_bytes))
        .into_bytes();
    let mut out = Cursor::new(Vec::new());
    vsix::embed_signature_xml(Cursor::new(updated), &mut out, &xml, overwrite)
        .with_context(|| format!("embed VSIX signature XML into {label}"))?;
    Ok(out.into_inner())
}

fn sign_clickonce_manifest_bytes(
    input_bytes: &[u8],
    label: &str,
    signer: &CodeSigner,
    digest: vsix::VsixHashAlgorithm,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    if timestamp_url.is_some() || timestamp_digest.is_some() {
        return Err(anyhow!(
            "ClickOnce manifest XMLDSig timestamping is not implemented in `psign-tool code` yet"
        ));
    }
    let text = std::str::from_utf8(input_bytes)
        .with_context(|| format!("read ClickOnce manifest {label} as UTF-8 XML"))?;
    let unsigned = unsigned_clickonce_manifest_text(text)?;
    let signed_info = clickonce_manifest_signed_info_xml(&unsigned, digest);
    let (signature, cert_bytes) = signer.sign_xml_signed_info(digest, &signed_info)?;
    let signature_xml = clickonce_manifest_signature_xml(&signed_info, &signature, &cert_bytes);
    Ok(insert_clickonce_signature_xml(&unsigned, &signature_xml)?.into_bytes())
}

fn clickonce_manifest_has_signature(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        find_xml_element_span_by_local_name(text, "Signature", 0).is_ok_and(|span| span.is_some())
    })
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
    digest: vsix::VsixHashAlgorithm,
) -> Vec<u8> {
    let manifest_digest =
        clickonce_signature_digest_bytes(digest, unsigned_manifest_text.as_bytes());
    let digest_b64 = BASE64_STANDARD.encode(manifest_digest);
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
        BASE64_STANDARD.encode(signature),
        BASE64_STANDARD.encode(cert_der)
    )
}

fn insert_clickonce_signature_xml(
    unsigned_manifest_text: &str,
    signature_xml: &str,
) -> Result<String> {
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

fn clickonce_signature_algorithm_uri(digest: vsix::VsixHashAlgorithm) -> &'static str {
    match digest {
        vsix::VsixHashAlgorithm::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        vsix::VsixHashAlgorithm::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        vsix::VsixHashAlgorithm::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    }
}

fn clickonce_signature_digest_uri(digest: vsix::VsixHashAlgorithm) -> &'static str {
    match digest {
        vsix::VsixHashAlgorithm::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        vsix::VsixHashAlgorithm::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        vsix::VsixHashAlgorithm::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    }
}

fn clickonce_signature_digest_bytes(digest: vsix::VsixHashAlgorithm, bytes: &[u8]) -> Vec<u8> {
    match digest {
        vsix::VsixHashAlgorithm::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
        vsix::VsixHashAlgorithm::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
        vsix::VsixHashAlgorithm::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_zip_container_bytes(
    input_bytes: &[u8],
    label: &str,
    digest: nuget::NuGetHashAlgorithm,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    vsix_digest: vsix::VsixHashAlgorithm,
    signer: &CodeSigner,
    chain_certs: Vec<PathBuf>,
    nested_excludes: &[String],
    skip_signed: bool,
    overwrite: bool,
    publisher: Option<&str>,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    sign_nested_package_entries(
        input_bytes,
        label,
        digest,
        signing_digest,
        vsix_digest,
        signer,
        chain_certs,
        nested_excludes,
        skip_signed,
        overwrite,
        publisher,
        timestamp_url,
        timestamp_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_nested_package_entries(
    input_bytes: &[u8],
    label: &str,
    digest: nuget::NuGetHashAlgorithm,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    vsix_digest: vsix::VsixHashAlgorithm,
    signer: &CodeSigner,
    chain_certs: Vec<PathBuf>,
    nested_excludes: &[String],
    skip_signed: bool,
    overwrite: bool,
    publisher: Option<&str>,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(input_bytes))
        .with_context(|| format!("open {label} as ZIP while signing nested package entries"))?;
    let mut updates = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read ZIP entry in {label}"))?;
        if file.is_dir() {
            continue;
        }
        let name = normalize_zip_name(file.name())?;
        let compression = file.compression();
        let format = detect_format(Path::new(&name), None);
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)?;
        let nested_label = format!("{label}!{name}");
        if nested_excludes.iter().any(|pattern| {
            glob_match(pattern, &name) || glob_match(pattern, &nested_label.replace('!', "/"))
        }) {
            continue;
        }
        let mut entry_updates = Vec::new();
        match &format {
            CodeFormat::Nuget | CodeFormat::Snupkg => entry_updates.push(ZipEntryUpdate {
                name,
                bytes: sign_nuget_bytes(
                    &bytes,
                    &nested_label,
                    digest,
                    signing_digest,
                    signer,
                    chain_certs.clone(),
                    nested_excludes,
                    skip_signed,
                    overwrite,
                    None,
                    timestamp_url,
                    timestamp_digest,
                )?,
                compression,
            }),
            CodeFormat::Vsix => entry_updates.push(ZipEntryUpdate {
                name,
                bytes: sign_vsix_bytes(
                    &bytes,
                    &nested_label,
                    digest,
                    signing_digest,
                    vsix_digest,
                    signer,
                    chain_certs.clone(),
                    nested_excludes,
                    skip_signed,
                    overwrite,
                    None,
                    timestamp_url,
                    timestamp_digest,
                )?,
                compression,
            }),
            CodeFormat::AppInstaller => {
                validate_appinstaller_descriptor(&bytes)
                    .with_context(|| format!("validate nested App Installer {nested_label}"))?;
                let mut descriptor = bytes;
                if let Some(publisher) = publisher {
                    descriptor = update_appinstaller_publisher_bytes(&descriptor, publisher)
                        .with_context(|| {
                            format!("update nested App Installer publisher for {nested_label}")
                        })?;
                    entry_updates.push(ZipEntryUpdate {
                        name: name.clone(),
                        bytes: descriptor.clone(),
                        compression,
                    });
                }
                let companion_name = format!("{name}.p7");
                if !overwrite && zip_contains_entry(input_bytes, &companion_name)? {
                    return Err(anyhow!(
                        "{nested_label} already has companion signature {companion_name}; use --overwrite to replace it"
                    ));
                }
                let pkcs7 = sign_pkcs7_id_data(
                    &descriptor,
                    SignPkcs7IdDataOptions {
                        signer,
                        chain_certs: chain_certs.clone(),
                        digest: signing_digest,
                        timestamp_url,
                        timestamp_digest,
                        content_mode: pkcs7::Pkcs7ContentMode::Detached,
                        timestamp_attribute: Rfc3161TimestampAttribute::MicrosoftAuthenticode,
                        signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile::Basic,
                    },
                )
                .with_context(|| {
                    format!("create nested App Installer companion signature for {nested_label}")
                })?;
                entry_updates.push(ZipEntryUpdate {
                    name: companion_name,
                    bytes: pkcs7,
                    compression: zip::CompressionMethod::Stored,
                });
            }
            CodeFormat::ClickOnceApplication | CodeFormat::Vsto | CodeFormat::Manifest
                if !(skip_signed && clickonce_manifest_has_signature(&bytes)) =>
            {
                entry_updates.push(ZipEntryUpdate {
                    name,
                    bytes: sign_clickonce_manifest_bytes(
                        &bytes,
                        &nested_label,
                        signer,
                        vsix_digest,
                        timestamp_url,
                        timestamp_digest,
                    )?,
                    compression,
                });
            }
            CodeFormat::Deploy => entry_updates.push(ZipEntryUpdate {
                name,
                bytes: sign_clickonce_deploy_bytes(
                    &bytes,
                    &nested_label,
                    signer,
                    signing_digest,
                    timestamp_url,
                    timestamp_digest,
                )?,
                compression,
            }),
            CodeFormat::Pe | CodeFormat::Winmd => entry_updates.push(ZipEntryUpdate {
                name,
                bytes: sign_pe_bytes(
                    &bytes,
                    &nested_label,
                    signer,
                    signing_digest,
                    skip_signed,
                    timestamp_url,
                    timestamp_digest,
                )?,
                compression,
            }),
            CodeFormat::Msix
            | CodeFormat::Appx
            | CodeFormat::MsixBundle
            | CodeFormat::AppxBundle
            | CodeFormat::AppxUpload
            | CodeFormat::MsixUpload => entry_updates.push(ZipEntryUpdate {
                name,
                bytes: prepare_msix_family_bytes(
                    &bytes,
                    &nested_label,
                    digest,
                    signing_digest,
                    vsix_digest,
                    signer,
                    chain_certs.clone(),
                    nested_excludes,
                    skip_signed,
                    overwrite,
                    format.clone(),
                    publisher,
                    timestamp_url,
                    timestamp_digest,
                )?,
                compression,
            }),
            _ if is_unsupported_nested_signable(&format) => {
                return Err(anyhow!(
                    "`psign-tool code` nested execution cannot sign {nested_label} yet ({format:?})"
                ));
            }
            _ => {}
        }
        updates.extend(entry_updates);
    }
    drop(archive);

    if updates.is_empty() {
        return Ok(input_bytes.to_vec());
    }
    let mut out = Cursor::new(Vec::new());
    repack_zip_with_updates(Cursor::new(input_bytes), &mut out, updates)
        .with_context(|| format!("repack {label} with signed nested package entries"))?;
    Ok(out.into_inner())
}

fn ensure_nuget_unsigned(bytes: &[u8], label: &str) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .with_context(|| format!("open NuGet package {label}"))?;
    if archive.by_name(nuget::PACKAGE_SIGNATURE_FILE_NAME).is_ok() {
        return Err(anyhow!(
            "{label} already contains {}; nested re-sign overwrite is not wired yet",
            nuget::PACKAGE_SIGNATURE_FILE_NAME
        ));
    }
    Ok(())
}

fn sign_clickonce_deploy_bytes(
    input_bytes: &[u8],
    label: &str,
    signer: &CodeSigner,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    if signing_digest != pkcs7::AuthenticodeSigningDigest::Sha256 {
        return Err(anyhow!(
            "ClickOnce .deploy payload signing currently supports only SHA-256"
        ));
    }
    let content_name = clickonce_deploy_content_name(label)
        .ok_or_else(|| anyhow!("{label} is not a ClickOnce .deploy payload path"))?;
    let ext = Path::new(&content_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !is_pe_like_extension(&ext) {
        return Err(anyhow!(
            "ClickOnce .deploy payload {label} maps to unsupported content name {content_name}"
        ));
    }
    sign_pe_bytes(
        input_bytes,
        label,
        signer,
        signing_digest,
        false,
        timestamp_url,
        timestamp_digest,
    )
    .with_context(|| format!("sign ClickOnce .deploy PE payload {label}"))
}

fn clickonce_deploy_content_name(label: &str) -> Option<String> {
    label
        .rsplit_once('!')
        .map(|(_, name)| name)
        .unwrap_or(label)
        .strip_suffix(".deploy")
        .map(str::to_owned)
}

fn is_pe_like_extension(ext: &str) -> bool {
    matches!(
        ext,
        "exe" | "dll" | "sys" | "ocx" | "efi" | "scr" | "cpl" | "mui" | "winmd"
    )
}

fn sign_pe_bytes(
    input_bytes: &[u8],
    label: &str,
    signer: &CodeSigner,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    skip_signed: bool,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    if skip_signed && pe_has_signature(input_bytes) {
        return Ok(input_bytes.to_vec());
    }
    if signing_digest != pkcs7::AuthenticodeSigningDigest::Sha256 {
        return Err(anyhow!("PE/WinMD signing currently supports only SHA-256"));
    }
    let (input_bytes, _) = pe_embed::pe_remove_authenticode_certificates(input_bytes.to_vec())
        .with_context(|| {
            format!("remove existing PE/WinMD Authenticode signatures from {label}")
        })?;
    let signed = signer
        .sign_pe_bytes(&input_bytes, signing_digest)
        .with_context(|| format!("sign PE/WinMD payload {label}"))?;
    timestamp_pe_if_requested(&signed, timestamp_url, timestamp_digest)
        .with_context(|| format!("timestamp PE/WinMD payload {label}"))
}

fn timestamp_pe_if_requested(
    pe_image: &[u8],
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    match (timestamp_url, timestamp_digest) {
        (Some(url), Some(digest)) => timestamp_pe_rfc3161(pe_image, url, digest),
        (Some(_), None) => Err(anyhow!(
            "`psign-tool code` requires --timestamp-digest with --timestamp-url"
        )),
        (None, Some(_)) => Err(anyhow!(
            "`psign-tool code` requires --timestamp-url with --timestamp-digest"
        )),
        (None, None) => Ok(pe_image.to_vec()),
    }
}

#[cfg(feature = "timestamp-http")]
fn timestamp_pe_rfc3161(
    pe_image: &[u8],
    timestamp_url: &str,
    timestamp_digest: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let pkcs7_count = verify_pe::pe_pkcs7_signed_data_entry_count(pe_image)
        .context("inspect PE/WinMD Authenticode PKCS#7 rows")?;
    let pkcs7_index = pkcs7_count
        .checked_sub(1)
        .ok_or_else(|| anyhow!("PE/WinMD has no PKCS#7 Authenticode row to timestamp"))?;
    let pkcs7_der = verify_pe::pe_nth_pkcs7_signed_data_der(pe_image, pkcs7_index)
        .with_context(|| format!("extract PE/WinMD PKCS#7 row {pkcs7_index}"))?;
    let stamped_pkcs7 = timestamp_pkcs7_der_rfc3161(
        &pkcs7_der,
        timestamp_url,
        timestamp_digest,
        Rfc3161TimestampAttribute::MicrosoftAuthenticode,
    )
    .with_context(|| format!("timestamp PE/WinMD PKCS#7 row {pkcs7_index}"))?;
    pe_embed::pe_replace_authenticode_pkcs7_certificate_at(
        pe_image.to_vec(),
        pkcs7_index,
        &stamped_pkcs7,
    )
    .with_context(|| format!("replace PE/WinMD PKCS#7 row {pkcs7_index}"))
}

#[cfg(not(feature = "timestamp-http"))]
fn timestamp_pe_rfc3161(
    _pe_image: &[u8],
    _timestamp_url: &str,
    _timestamp_digest: DigestAlgorithm,
) -> Result<Vec<u8>> {
    Err(anyhow!(
        "`psign-tool code` RFC3161 timestamping requires the timestamp-http feature"
    ))
}

#[allow(clippy::too_many_arguments)]
fn prepare_msix_family_bytes(
    input_bytes: &[u8],
    label: &str,
    digest: nuget::NuGetHashAlgorithm,
    signing_digest: pkcs7::AuthenticodeSigningDigest,
    vsix_digest: vsix::VsixHashAlgorithm,
    signer: &CodeSigner,
    chain_certs: Vec<PathBuf>,
    nested_excludes: &[String],
    skip_signed: bool,
    overwrite: bool,
    format: CodeFormat,
    publisher: Option<&str>,
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
) -> Result<Vec<u8>> {
    ensure_unsigned_msix_family(input_bytes, label)?;
    // True bundles (.msixbundle/.appxbundle) always carry AppxMetadata/AppxBundleManifest.xml;
    // upload containers (.appxupload/.msixupload) are dotnet packaging wrappers whose
    // nested flat packages carry their own AppxManifest.xml.
    let is_true_bundle = matches!(format, CodeFormat::MsixBundle | CodeFormat::AppxBundle);
    let mut updated = sign_nested_package_entries(
        input_bytes,
        label,
        digest,
        signing_digest,
        vsix_digest,
        signer,
        chain_certs,
        nested_excludes,
        skip_signed,
        overwrite,
        publisher,
        timestamp_url,
        timestamp_digest,
    )?;
    if let Some(publisher) = publisher {
        if zip_contains_entry(&updated, "AppxManifest.xml")? {
            updated = update_msix_manifest_publisher_bytes(&updated, label, publisher)?;
        } else if zip_contains_entry(&updated, "AppxMetadata/AppxBundleManifest.xml")? {
            updated = update_msix_bundle_manifest_publisher_bytes(&updated, label, publisher)?;
        } else if matches!(format, CodeFormat::Msix | CodeFormat::Appx) {
            return Err(anyhow!("{label} is missing AppxManifest.xml"));
        } else if is_true_bundle {
            return Err(anyhow!(
                "{label} is missing AppxMetadata/AppxBundleManifest.xml"
            ));
        }
    }
    // Bundle block maps cover only the bundle manifest; flat/upload layouts hash all payloads.
    let is_bundle_layout = zip_contains_entry(&updated, "AppxMetadata/AppxBundleManifest.xml")?;
    if zip_contains_entry(&updated, "AppxBlockMap.xml")? {
        let block_map = if is_bundle_layout {
            build_msix_bundle_block_map_xml(&updated)?
        } else {
            build_msix_block_map_xml(&updated)?
        };
        updated = repack_with_block_map(&updated, label, block_map)?;
    }
    Ok(updated)
}

fn ensure_unsigned_msix_family(bytes: &[u8], label: &str) -> Result<()> {
    if zip_contains_entry(bytes, "AppxSignature.p7x")? {
        return Err(anyhow!(
            "{label} already contains AppxSignature.p7x; update the unsigned package before final AppX signing"
        ));
    }
    Ok(())
}

fn update_msix_manifest_publisher_bytes(
    input_bytes: &[u8],
    label: &str,
    publisher: &str,
) -> Result<Vec<u8>> {
    if publisher.is_empty() {
        return Err(anyhow!("MSIX/AppX publisher cannot be empty"));
    }
    let escaped = xml_escape_attr(publisher);
    let mut archive = zip::ZipArchive::new(Cursor::new(input_bytes))
        .with_context(|| format!("open MSIX/AppX package {label}"))?;
    let mut updates = Vec::new();
    let mut updated_manifest = false;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("read MSIX/AppX entry in {label}"))?;
        if file.is_dir() {
            continue;
        }
        let name = normalize_zip_name(file.name())?;
        if name == "AppxManifest.xml" {
            let compression = file.compression();
            let mut text = String::new();
            file.read_to_string(&mut text)
                .context("read AppxManifest.xml as UTF-8")?;
            let updated = update_attr_for_tags(&text, "Identity", "Publisher", &escaped)?;
            updates.push(ZipEntryUpdate {
                name,
                bytes: updated.into_bytes(),
                compression,
            });
            updated_manifest = true;
        }
    }
    drop(archive);
    if !updated_manifest {
        return Err(anyhow!("{label} is missing AppxManifest.xml"));
    }
    let mut out = Cursor::new(Vec::new());
    repack_zip_with_updates(Cursor::new(input_bytes), &mut out, updates)
        .with_context(|| format!("repack {label} with updated AppxManifest.xml"))?;
    Ok(out.into_inner())
}

fn update_appinstaller_publisher_bytes(bytes: &[u8], publisher: &str) -> Result<Vec<u8>> {
    if publisher.is_empty() {
        return Err(anyhow!("App Installer publisher cannot be empty"));
    }
    let text = std::str::from_utf8(bytes).context("App Installer descriptor is not UTF-8")?;
    validate_appinstaller_descriptor(bytes)?;
    let escaped = xml_escape_attr(publisher);
    let mut updated = text.to_owned();
    for tag in ["MainPackage", "MainBundle"] {
        updated = update_attr_for_local_tags(&updated, tag, "Publisher", &escaped)?;
    }
    Ok(updated.into_bytes())
}

fn repack_with_block_map(input_bytes: &[u8], label: &str, block_map: Vec<u8>) -> Result<Vec<u8>> {
    let mut out = Cursor::new(Vec::new());
    repack_zip_with_updates(
        Cursor::new(input_bytes),
        &mut out,
        vec![ZipEntryUpdate {
            name: "AppxBlockMap.xml".to_owned(),
            bytes: block_map,
            compression: zip::CompressionMethod::Stored,
        }],
    )
    .with_context(|| format!("repack {label} with regenerated AppxBlockMap.xml"))?;
    Ok(out.into_inner())
}

/// Bundle block maps list exactly one `File` — the bundle manifest — using backslash
/// separators and per-block `Size`, matching native `MakeAppx bundle` output.
fn build_msix_bundle_block_map_xml(input_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(input_bytes)).context("open MSIX/AppX bundle ZIP")?;
    let mut manifest = archive
        .by_name("AppxMetadata/AppxBundleManifest.xml")
        .context("read AppxMetadata/AppxBundleManifest.xml")?;
    let mut bytes = Vec::with_capacity(manifest.size() as usize);
    manifest.read_to_end(&mut bytes)?;
    drop(manifest);

    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push_str(r#"<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">"#);
    xml.push_str(&format!(
        r#"<File Name="AppxMetadata\AppxBundleManifest.xml" Size="{}">"#,
        bytes.len()
    ));
    for chunk in bytes.chunks(64 * 1024) {
        let hash = sha2::Sha256::digest(chunk);
        xml.push_str(&format!(
            r#"<Block Hash="{}" Size="{}"/>"#,
            BASE64_STANDARD.encode(hash),
            chunk.len()
        ));
    }
    xml.push_str("</File></BlockMap>");
    Ok(xml.into_bytes())
}

fn update_msix_bundle_manifest_publisher_bytes(
    input_bytes: &[u8],
    label: &str,
    publisher: &str,
) -> Result<Vec<u8>> {
    if publisher.is_empty() {
        return Err(anyhow!("MSIX/AppX publisher cannot be empty"));
    }
    let escaped = xml_escape_attr(publisher);
    let mut archive = zip::ZipArchive::new(Cursor::new(input_bytes))
        .with_context(|| format!("open MSIX/AppX bundle {label}"))?;
    let mut manifest = archive
        .by_name("AppxMetadata/AppxBundleManifest.xml")
        .with_context(|| format!("read AppxMetadata/AppxBundleManifest.xml in {label}"))?;
    let mut text = String::new();
    manifest
        .read_to_string(&mut text)
        .context("read AppxMetadata/AppxBundleManifest.xml as UTF-8")?;
    drop(manifest);

    // Identity@Publisher describes the bundle; Package@Publisher mirrors the child packages
    // so both stay in sync with the requested signing subject.
    let mut updated = update_attr_for_local_tags(&text, "Identity", "Publisher", &escaped)?;
    updated = update_attr_for_local_tags(&updated, "Package", "Publisher", &escaped)?;

    let mut out = Cursor::new(Vec::new());
    repack_zip_with_updates(
        Cursor::new(input_bytes),
        &mut out,
        vec![ZipEntryUpdate {
            name: "AppxMetadata/AppxBundleManifest.xml".to_owned(),
            bytes: updated.into_bytes(),
            compression: zip::CompressionMethod::Deflated,
        }],
    )
    .with_context(|| format!("repack {label} with updated AppxBundleManifest.xml"))?;
    Ok(out.into_inner())
}

fn build_msix_block_map_xml(input_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(input_bytes)).context("open MSIX/AppX ZIP")?;
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .context("read MSIX/AppX entry for block map")?;
        if file.is_dir() {
            continue;
        }
        let name = normalize_zip_name(file.name())?;
        if matches!(
            name.as_str(),
            "[Content_Types].xml" | "AppxBlockMap.xml" | "AppxSignature.p7x"
        ) {
            continue;
        }
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)?;
        files.push((name, bytes));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push_str(r#"<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">"#);
    for (name, bytes) in files {
        xml.push_str(&format!(
            r#"<File Name="{}" Size="{}">"#,
            xml_escape_attr(&name),
            bytes.len()
        ));
        for chunk in bytes.chunks(64 * 1024) {
            let hash = sha2::Sha256::digest(chunk);
            xml.push_str(&format!(
                r#"<Block Hash="{}"/>"#,
                BASE64_STANDARD.encode(hash)
            ));
        }
        xml.push_str("</File>");
    }
    xml.push_str("</BlockMap>");
    Ok(xml.into_bytes())
}

fn zip_contains_entry(bytes: &[u8], entry_name: &str) -> Result<bool> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("open ZIP")?;
    Ok(archive.by_name(entry_name).is_ok())
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
            .ok_or_else(|| anyhow!("XML <{tag}> tag is not closed"))?;
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
            .ok_or_else(|| anyhow!("XML {attr} attribute is not closed"))?;
        let mut out = String::with_capacity(tag.len() + escaped_value.len());
        out.push_str(&tag[..value_start]);
        out.push_str(escaped_value);
        out.push_str(&tag[value_end..]);
        return Ok(out);
    }

    let insert_at = tag
        .rfind("/>")
        .or_else(|| tag.rfind('>'))
        .ok_or_else(|| anyhow!("XML tag is not closed"))?;
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

#[derive(Debug)]
struct XmlStartTagSpan {
    start: usize,
    end: usize,
    name: String,
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
        let name_local = name
            .rsplit_once(':')
            .map(|(_, local)| local)
            .unwrap_or(name);
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
            return Err(anyhow!(
                "ClickOnce XML starts with an unexpected closing tag"
            ));
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
    Err(anyhow!(
        "ClickOnce manifest does not contain a root XML element"
    ))
}

fn pe_has_signature(bytes: &[u8]) -> bool {
    psign_sip_digest::verify_pe::pe_pkcs7_signed_data_entry_count(bytes)
        .is_ok_and(|count| count > 0)
}

fn package_has_signature(bytes: &[u8], format: &CodeFormat) -> Result<bool> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("open package to inspect signature")?;
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }
        let name = normalize_zip_name(file.name())?;
        let signed = match format {
            CodeFormat::Nuget | CodeFormat::Snupkg => name == nuget::PACKAGE_SIGNATURE_FILE_NAME,
            CodeFormat::Vsix => {
                name == opc::OPC_SIGNATURE_ORIGIN_PART
                    || name == vsix::DEFAULT_VSIX_SIGNATURE_PART
                    || name.starts_with(opc::OPC_SIGNATURES_PREFIX)
            }
            _ => false,
        };
        if signed {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_unsupported_nested_signable(format: &CodeFormat) -> bool {
    matches!(
        format,
        CodeFormat::Cab
            | CodeFormat::Msi
            | CodeFormat::Msp
            | CodeFormat::Mst
            | CodeFormat::Catalog
            | CodeFormat::Script
            | CodeFormat::Msix
            | CodeFormat::Appx
            | CodeFormat::MsixBundle
            | CodeFormat::AppxBundle
            | CodeFormat::AppxUpload
            | CodeFormat::MsixUpload
            | CodeFormat::EncryptedMsix
            | CodeFormat::ClickOnceApplication
            | CodeFormat::Vsto
            | CodeFormat::Manifest
            | CodeFormat::AppInstaller
            | CodeFormat::BusinessCentralApp
    )
}

struct SignPkcs7IdDataOptions<'a> {
    signer: &'a CodeSigner,
    chain_certs: Vec<PathBuf>,
    digest: pkcs7::AuthenticodeSigningDigest,
    timestamp_url: Option<&'a str>,
    timestamp_digest: Option<DigestAlgorithm>,
    content_mode: pkcs7::Pkcs7ContentMode,
    timestamp_attribute: Rfc3161TimestampAttribute,
    signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile,
}

fn sign_pkcs7_id_data(content: &[u8], options: SignPkcs7IdDataOptions<'_>) -> Result<Vec<u8>> {
    let SignPkcs7IdDataOptions {
        signer,
        chain_certs,
        digest,
        timestamp_url,
        timestamp_digest,
        content_mode,
        timestamp_attribute,
        signed_attribute_profile,
    } = options;
    let chain = load_chain_certs(chain_certs)?;
    let econtent_der = OctetString::new(content.to_vec())
        .map_err(|e| anyhow!("encode CMS id-data OCTET STRING: {e}"))?
        .to_der()
        .map_err(|e| anyhow!("encode CMS id-data DER: {e}"))?;
    let id_data = ObjectIdentifier::new(pkcs7::PKCS7_ID_DATA_OID)
        .map_err(|e| anyhow!("parse CMS id-data OID: {e}"))?;
    let pkcs7 = signer.sign_pkcs7(
        id_data,
        &econtent_der,
        digest,
        chain,
        content_mode,
        signed_attribute_profile,
    )?;
    timestamp_pkcs7_if_requested(&pkcs7, timestamp_url, timestamp_digest, timestamp_attribute)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rfc3161TimestampAttribute {
    MicrosoftAuthenticode,
    CmsTimeStampToken,
}

fn timestamp_pkcs7_if_requested(
    pkcs7_der: &[u8],
    timestamp_url: Option<&str>,
    timestamp_digest: Option<DigestAlgorithm>,
    timestamp_attribute: Rfc3161TimestampAttribute,
) -> Result<Vec<u8>> {
    match (timestamp_url, timestamp_digest) {
        (Some(url), Some(digest)) => {
            timestamp_pkcs7_der_rfc3161(pkcs7_der, url, digest, timestamp_attribute)
        }
        (Some(_), None) => Err(anyhow!(
            "`psign-tool code` requires --timestamp-digest with --timestamp-url"
        )),
        (None, Some(_)) => Err(anyhow!(
            "`psign-tool code` requires --timestamp-url with --timestamp-digest"
        )),
        (None, None) => Ok(pkcs7_der.to_vec()),
    }
}

#[cfg(feature = "timestamp-http")]
fn timestamp_pkcs7_der_rfc3161(
    pkcs7_der: &[u8],
    timestamp_url: &str,
    timestamp_digest: DigestAlgorithm,
    timestamp_attribute: Rfc3161TimestampAttribute,
) -> Result<Vec<u8>> {
    let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7_der).context("parse PKCS#7 SignedData")?;
    let signer = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("PKCS#7 SignedData has no SignerInfo to timestamp"))?;
    let imprint = timestamp_digest_bytes(timestamp_digest, signer.signature.as_bytes())?;
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

#[cfg(not(feature = "timestamp-http"))]
fn timestamp_pkcs7_der_rfc3161(
    _pkcs7_der: &[u8],
    _timestamp_url: &str,
    _timestamp_digest: DigestAlgorithm,
    _timestamp_attribute: Rfc3161TimestampAttribute,
) -> Result<Vec<u8>> {
    Err(anyhow!(
        "`psign-tool code` RFC3161 timestamping requires the timestamp-http feature"
    ))
}

#[cfg(feature = "timestamp-http")]
fn post_rfc3161_timestamp_request(
    url: &str,
    algorithm: DigestAlgorithm,
    message_imprint: &[u8],
) -> Result<Vec<u8>> {
    let plan = psign_sip_digest::timestamp::Rfc3161TimestampRequestPlan {
        digest_alg_oid: timestamp_digest_oid(algorithm)?,
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
        .context("build HTTP client")?;
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
            "TSA HTTP {} - first {} body bytes (hex): {}",
            status,
            body.len().min(256),
            hex_lower(&body[..body.len().min(256)])
        ));
    }
    Ok(body.to_vec())
}

#[cfg(feature = "timestamp-http")]
fn timestamp_digest_oid(digest: DigestAlgorithm) -> Result<&'static str> {
    match digest {
        DigestAlgorithm::Sha1 => Ok("1.3.14.3.2.26"),
        DigestAlgorithm::Sha256 => Ok("2.16.840.1.101.3.4.2.1"),
        DigestAlgorithm::Sha384 => Ok("2.16.840.1.101.3.4.2.2"),
        DigestAlgorithm::Sha512 => Ok("2.16.840.1.101.3.4.2.3"),
        DigestAlgorithm::CertHash => Err(anyhow!(
            "`psign-tool code` timestamping supports SHA-1, SHA-256, SHA-384, or SHA-512"
        )),
    }
}

#[cfg(feature = "timestamp-http")]
fn timestamp_digest_bytes(digest: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
    match digest {
        DigestAlgorithm::Sha1 => Ok(sha1::Sha1::digest(bytes).to_vec()),
        DigestAlgorithm::Sha256 => Ok(sha2::Sha256::digest(bytes).to_vec()),
        DigestAlgorithm::Sha384 => Ok(sha2::Sha384::digest(bytes).to_vec()),
        DigestAlgorithm::Sha512 => Ok(sha2::Sha512::digest(bytes).to_vec()),
        DigestAlgorithm::CertHash => Err(anyhow!(
            "`psign-tool code` timestamping supports SHA-1, SHA-256, SHA-384, or SHA-512"
        )),
    }
}

struct CodeSigner {
    backend: CodeSignerBackend,
}

enum CodeSignerBackend {
    Local(CodeSignerPaths),
    #[cfg(feature = "azure-kv-sign")]
    AzureKeyVault(Box<CodeAzureKeyVaultSigner>),
    #[cfg(feature = "artifact-signing-rest")]
    ArtifactSigning(Box<CodeArtifactSigningSigner>),
}

struct CodeSignerPaths {
    cert: PathBuf,
    key: PathBuf,
    temp_dir: Option<PathBuf>,
}

#[cfg(feature = "azure-kv-sign")]
struct CodeAzureKeyVaultSigner {
    http: reqwest::blocking::Client,
    token: String,
    certificate: KeyVaultCertificate,
    cert_der: Vec<u8>,
}

#[cfg(feature = "artifact-signing-rest")]
struct CodeArtifactSigningSigner {
    metadata: Option<PathBuf>,
    region: Option<String>,
    endpoint: Option<String>,
    account_name: Option<String>,
    profile_name: Option<String>,
    signature_algorithm: Option<String>,
    api_version: Option<String>,
    correlation_id: Option<String>,
    access_token: Option<String>,
    managed_identity: bool,
    managed_identity_resource_id: Option<String>,
    credential_type: Option<AzureCredentialType>,
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    federated_token_file: Option<String>,
    authority: Option<String>,
    endpoint_base_url: Option<String>,
}

struct RemoteCodeSignature {
    signature: Vec<u8>,
    signer_cert_der: Vec<u8>,
    signer_cert: x509_cert::Certificate,
    chain: Vec<x509_cert::Certificate>,
}

#[derive(Clone, Copy)]
enum CodeRemoteDigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Drop for CodeSignerPaths {
    fn drop(&mut self) {
        if let Some(dir) = &self.temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl CodeSigner {
    fn local_paths(&self) -> Option<(&Path, &Path)> {
        match &self.backend {
            CodeSignerBackend::Local(paths) => Some((&paths.cert, &paths.key)),
            #[cfg(feature = "azure-kv-sign")]
            CodeSignerBackend::AzureKeyVault(_) => None,
            #[cfg(feature = "artifact-signing-rest")]
            CodeSignerBackend::ArtifactSigning(_) => None,
        }
    }

    fn sign_pkcs7(
        &self,
        econtent_type: ObjectIdentifier,
        econtent_der: &[u8],
        digest: pkcs7::AuthenticodeSigningDigest,
        chain: Vec<x509_cert::Certificate>,
        content_mode: pkcs7::Pkcs7ContentMode,
        signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile,
    ) -> Result<Vec<u8>> {
        if let Some((cert, key)) = self.local_paths() {
            let cert_bytes =
                std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
            let signer_cert = rdp::parse_certificate(&cert_bytes)
                .with_context(|| format!("parse signer certificate {}", cert.display()))?;
            let key_bytes =
                std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            let signed_attrs = pkcs7::pkcs7_signed_attrs(
                econtent_type,
                econtent_der,
                digest,
                signed_attribute_profile,
                Some(&signer_cert),
            )?;
            let prehash = pkcs7::pkcs7_signed_attrs_digest(&signed_attrs, digest)?;
            let signature = sign_pkcs7_signed_attrs_digest(digest, private_key, &prehash)?;
            return pkcs7::create_pkcs7_signed_data_der_with_signed_attrs_and_rsa_signature(
                pkcs7::Pkcs7SignedDataDerInput {
                    econtent_type,
                    econtent_der,
                    digest_algorithm: digest,
                    signer_cert,
                    chain_certs: chain,
                    encrypted_digest: &signature,
                    content_mode,
                    signed_attrs,
                },
            );
        }

        self.sign_pkcs7_remote(
            econtent_type,
            econtent_der,
            digest,
            chain,
            content_mode,
            signed_attribute_profile,
        )
    }

    fn sign_pkcs7_remote(
        &self,
        econtent_type: ObjectIdentifier,
        econtent_der: &[u8],
        digest: pkcs7::AuthenticodeSigningDigest,
        chain: Vec<x509_cert::Certificate>,
        content_mode: pkcs7::Pkcs7ContentMode,
        signed_attribute_profile: pkcs7::Pkcs7SignedAttributeProfile,
    ) -> Result<Vec<u8>> {
        let mut signer_cert_hint = if signed_attribute_profile.requires_signer_certificate() {
            Some(match self.remote_signer_certificate_hint()? {
                Some(signer_cert) => signer_cert,
                None => self.probe_remote_signer_certificate(digest)?,
            })
        } else {
            None
        };

        for attempt in 0..2 {
            let signed_attrs = pkcs7::pkcs7_signed_attrs(
                econtent_type,
                econtent_der,
                digest,
                signed_attribute_profile,
                signer_cert_hint.as_ref(),
            )?;
            let prehash = pkcs7::pkcs7_signed_attrs_digest(&signed_attrs, digest)?;
            let mut remote =
                self.sign_remote_digest(code_remote_digest_from_pkcs7(digest), &prehash)?;
            if let Some(expected_cert) = signer_cert_hint.as_ref()
                && !certificates_der_equal(expected_cert, &remote.signer_cert)?
            {
                if attempt == 0 {
                    signer_cert_hint = Some(remote.signer_cert);
                    continue;
                }
                return Err(anyhow!(
                    "remote signer certificate changed while building NuGet signing-certificate-v2"
                ));
            }
            remote.chain.extend(chain.clone());
            return pkcs7::create_pkcs7_signed_data_der_with_signed_attrs_and_rsa_signature(
                pkcs7::Pkcs7SignedDataDerInput {
                    econtent_type,
                    econtent_der,
                    digest_algorithm: digest,
                    signer_cert: remote.signer_cert,
                    chain_certs: remote.chain,
                    encrypted_digest: &remote.signature,
                    content_mode,
                    signed_attrs,
                },
            );
        }

        unreachable!("remote PKCS#7 signing loop returns or errors")
    }

    fn probe_remote_signer_certificate(
        &self,
        digest: pkcs7::AuthenticodeSigningDigest,
    ) -> Result<x509_cert::Certificate> {
        let probe_digest = vec![0u8; digest.pe_hash_kind().digest_output_len()];
        let remote =
            self.sign_remote_digest(code_remote_digest_from_pkcs7(digest), &probe_digest)?;
        Ok(remote.signer_cert)
    }

    fn remote_signer_certificate_hint(&self) -> Result<Option<x509_cert::Certificate>> {
        match &self.backend {
            CodeSignerBackend::Local(_) => Ok(None),
            #[cfg(feature = "azure-kv-sign")]
            CodeSignerBackend::AzureKeyVault(signer) => rdp::parse_certificate(&signer.cert_der)
                .context("parse Azure Key Vault signer certificate")
                .map(Some),
            #[cfg(feature = "artifact-signing-rest")]
            CodeSignerBackend::ArtifactSigning(_) => Ok(None),
        }
    }

    fn sign_xml_signed_info(
        &self,
        algorithm: vsix::VsixHashAlgorithm,
        signed_info: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if let Some((cert, key)) = self.local_paths() {
            let cert_bytes =
                std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
            let key_bytes =
                std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
            let private_key = rdp::parse_rsa_private_key(&key_bytes)
                .with_context(|| format!("parse RSA private key {}", key.display()))?;
            return Ok((
                sign_xml_signed_info(algorithm, private_key, signed_info),
                cert_bytes,
            ));
        }

        let prehash = clickonce_signature_digest_bytes(algorithm, signed_info);
        let remote = self.sign_remote_digest(code_remote_digest_from_vsix(algorithm), &prehash)?;
        Ok((remote.signature, remote.signer_cert_der))
    }

    fn sign_pe_bytes(
        &self,
        input_bytes: &[u8],
        signing_digest: pkcs7::AuthenticodeSigningDigest,
    ) -> Result<Vec<u8>> {
        if let Some((cert, key)) = self.local_paths() {
            let cert_bytes =
                std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
            let key_bytes =
                std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
            return psign_sip_digest::pe_sign::sign_pe_image_rsa_sha256(
                input_bytes,
                &cert_bytes,
                &key_bytes,
            );
        }

        let pe_digest =
            pe_digest::pe_authenticode_digest(input_bytes, signing_digest.pe_hash_kind())
                .context("compute PE/WinMD Authenticode digest")?;
        let indirect = pkcs7::pe_spc_indirect_data(signing_digest, &pe_digest)?;
        let prehash =
            pkcs7::authenticode_remote_rsa_signed_attrs_digest(&indirect, signing_digest)?;
        let remote =
            self.sign_remote_digest(code_remote_digest_from_pkcs7(signing_digest), &prehash)?;
        let pkcs7 = pkcs7::create_authenticode_pkcs7_der_with_rsa_signature(
            indirect,
            signing_digest,
            remote.signer_cert,
            remote.chain,
            &remote.signature,
        )?;
        pe_embed::pe_append_authenticode_pkcs7_certificate(input_bytes.to_vec(), &pkcs7)
            .context("embed Authenticode PKCS#7")
    }

    fn sign_remote_digest(
        &self,
        algorithm: CodeRemoteDigestAlgorithm,
        digest: &[u8],
    ) -> Result<RemoteCodeSignature> {
        match &self.backend {
            CodeSignerBackend::Local(_) => Err(anyhow!("local signer cannot remote-sign a digest")),
            #[cfg(feature = "azure-kv-sign")]
            CodeSignerBackend::AzureKeyVault(signer) => signer.sign_digest(algorithm, digest),
            #[cfg(feature = "artifact-signing-rest")]
            CodeSignerBackend::ArtifactSigning(signer) => signer.sign_digest(algorithm, digest),
        }
    }
}

#[cfg(feature = "azure-kv-sign")]
impl CodeAzureKeyVaultSigner {
    fn sign_digest(
        &self,
        algorithm: CodeRemoteDigestAlgorithm,
        digest: &[u8],
    ) -> Result<RemoteCodeSignature> {
        let signature = kv_sign_digest_from_certificate(
            &self.http,
            &self.token,
            &self.certificate,
            kv_hash_algorithm(algorithm),
            digest,
        )?;
        let signer_cert = rdp::parse_certificate(&self.cert_der)
            .context("parse Azure Key Vault signer certificate")?;
        Ok(RemoteCodeSignature {
            signature,
            signer_cert_der: self.cert_der.clone(),
            signer_cert,
            chain: Vec::new(),
        })
    }
}

#[cfg(feature = "artifact-signing-rest")]
impl CodeArtifactSigningSigner {
    fn sign_digest(
        &self,
        algorithm: CodeRemoteDigestAlgorithm,
        digest: &[u8],
    ) -> Result<RemoteCodeSignature> {
        let params =
            self.params_for_digest(digest.to_vec(), artifact_signature_algorithm(algorithm))?;
        let signed = submit_codesign_hash_signature_blocking(&params, |_| {})?;
        let (signer_cert, chain) =
            pkcs7::parse_artifact_signing_certificates(&signed.signing_certificate)?;
        let signer_cert_der = signer_cert
            .to_der()
            .map_err(|e| anyhow!("encode Artifact Signing signer certificate: {e}"))?;
        Ok(RemoteCodeSignature {
            signature: signed.signature,
            signer_cert_der,
            signer_cert,
            chain,
        })
    }

    fn params_for_digest(
        &self,
        digest: Vec<u8>,
        default_signature_algorithm: &str,
    ) -> Result<CodesigningSubmitParams> {
        let metadata = if let Some(path) = self.metadata.as_deref() {
            let raw = std::fs::read(path)
                .with_context(|| format!("read Artifact Signing metadata {}", path.display()))?;
            Some(
                serde_json::from_slice::<ArtifactSigningMetadataDoc>(&raw)
                    .context("parse Artifact Signing metadata JSON")?,
            )
        } else {
            None
        };
        let endpoint = text_opt(self.endpoint_base_url.as_deref())
            .or_else(|| text_opt(self.endpoint.as_deref()))
            .or_else(|| metadata.as_ref().and_then(|m| text_opt(Some(&m.Endpoint))));
        let account_name = text_opt(self.account_name.as_deref())
            .or_else(|| {
                metadata
                    .as_ref()
                    .and_then(|m| text_opt(Some(&m.CodeSigningAccountName)))
            })
            .ok_or_else(|| anyhow!("Artifact Signing requires --artifact-signing-account-name or metadata CodeSigningAccountName"))?;
        let profile_name = text_opt(self.profile_name.as_deref())
            .or_else(|| {
                metadata
                    .as_ref()
                    .and_then(|m| text_opt(Some(&m.CertificateProfileName)))
            })
            .ok_or_else(|| anyhow!("Artifact Signing requires --artifact-signing-profile-name or metadata CertificateProfileName"))?;
        Ok(CodesigningSubmitParams {
            region: text_opt(self.region.as_deref()).unwrap_or_else(|| "unused".to_string()),
            account_name,
            profile_name,
            digest,
            signature_algorithm: text_opt(self.signature_algorithm.as_deref())
                .unwrap_or_else(|| default_signature_algorithm.to_string()),
            api_version: text_opt(self.api_version.as_deref())
                .unwrap_or_else(|| DEFAULT_API_VERSION.to_string()),
            correlation_id: text_opt(self.correlation_id.as_deref()).or_else(|| {
                metadata
                    .as_ref()
                    .and_then(|m| text_opt(m.CorrelationId.as_deref()))
            }),
            authority: text_opt(self.authority.as_deref()),
            auth: self.auth(
                metadata
                    .as_ref()
                    .and_then(|m| m.ExcludeCredentials.clone())
                    .unwrap_or_default(),
            )?,
            endpoint_base_url: endpoint,
        })
    }

    fn auth(&self, exclude_credentials: Vec<String>) -> Result<CodesigningAuth> {
        resolve_codesigning_auth(&CodesigningAuthInput {
            access_token: self.access_token.clone(),
            managed_identity: self.managed_identity,
            managed_identity_resource_id: self.managed_identity_resource_id.clone(),
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            federated_token_file: self.federated_token_file.clone(),
            credential_type: codesigning_credential_type(self.credential_type),
            exclude_credentials,
        })
    }
}

#[cfg(feature = "artifact-signing-rest")]
fn codesigning_credential_type(
    value: Option<AzureCredentialType>,
) -> Option<CodesigningCredentialType> {
    value.map(|value| match value {
        AzureCredentialType::Default => CodesigningCredentialType::Default,
        AzureCredentialType::ManagedIdentity => CodesigningCredentialType::ManagedIdentity,
        AzureCredentialType::AccessToken => CodesigningCredentialType::AccessToken,
        AzureCredentialType::ClientSecret => CodesigningCredentialType::ClientSecret,
        AzureCredentialType::WorkloadIdentity => CodesigningCredentialType::WorkloadIdentity,
    })
}

fn resolve_code_signer(args: &CodeArgs) -> Result<CodeSigner> {
    let local_files = args.cert.is_some() || args.key.is_some();
    let pfx = args.pfx.is_some();
    let portable_store = args
        .cert_sha1
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let azure_key_vault = azure_key_vault_requested(args);
    let artifact_signing = artifact_signing_requested(args);
    let provider_count = local_files as u8
        + pfx as u8
        + portable_store as u8
        + azure_key_vault as u8
        + artifact_signing as u8;
    if provider_count != 1 {
        return Err(anyhow!(
            "`psign-tool code` signing execution requires exactly one signer: --cert/--key, --pfx, --sha1, Azure Key Vault, or Artifact Signing"
        ));
    }

    if local_files {
        let cert = args.cert.clone().ok_or_else(|| {
            anyhow!("`psign-tool code` signing execution requires --cert with --key")
        })?;
        let key = args.key.clone().ok_or_else(|| {
            anyhow!("`psign-tool code` signing execution requires --key with --cert")
        })?;
        return Ok(CodeSigner {
            backend: CodeSignerBackend::Local(CodeSignerPaths {
                cert,
                key,
                temp_dir: None,
            }),
        });
    }

    if let Some(pfx) = args.pfx.as_deref() {
        let bytes = std::fs::read(pfx).with_context(|| format!("read PFX '{}'", pfx.display()))?;
        let password = args.password.as_deref().unwrap_or("");
        let (cert_der, key_pem) = crate::cert_store::load_pfx_cert_and_key(&bytes, password)
            .with_context(|| format!("extract signer identity from PFX '{}'", pfx.display()))?;
        return Ok(CodeSigner {
            backend: CodeSignerBackend::Local(write_temp_signer_material(
                cert_der,
                key_pem.into_bytes(),
            )?),
        });
    }

    if let Some(sha1) = args.cert_sha1.as_deref() {
        let identity = crate::cert_store::resolve_signing_identity(
            args.cert_store_dir.as_deref(),
            args.machine_store,
            &args.store_name,
            sha1,
        )?;
        return Ok(CodeSigner {
            backend: CodeSignerBackend::Local(write_temp_signer_material(
                identity.cert_der,
                identity.key_pem,
            )?),
        });
    }

    if azure_key_vault {
        return resolve_code_signer_azure_key_vault(args);
    }

    if artifact_signing {
        return resolve_code_signer_artifact_signing(args);
    }

    unreachable!("provider_count checked above");
}

fn write_temp_signer_material(cert_der: Vec<u8>, key_pem: Vec<u8>) -> Result<CodeSignerPaths> {
    let dir = unique_code_signer_temp_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create signer material temp directory {}", dir.display()))?;
    let cert = dir.join("signer.der");
    let key = dir.join("signer.key");
    std::fs::write(&cert, cert_der)
        .with_context(|| format!("write temporary signer certificate {}", cert.display()))?;
    std::fs::write(&key, key_pem)
        .with_context(|| format!("write temporary signer key {}", key.display()))?;
    Ok(CodeSignerPaths {
        cert,
        key,
        temp_dir: Some(dir),
    })
}

fn unique_code_signer_temp_dir() -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("system clock before Unix epoch: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("psign-code-signer-{}-{nanos}", std::process::id())))
}

#[cfg(feature = "azure-kv-sign")]
fn resolve_code_signer_azure_key_vault(args: &CodeArgs) -> Result<CodeSigner> {
    if matches!(
        args.azure_key_vault_credential_type,
        Some(AzureCredentialType::WorkloadIdentity)
    ) {
        return Err(anyhow!(
            "`psign-tool code` Azure Key Vault execution does not support workload identity yet"
        ));
    }
    let vault_url = required_text("--azure-key-vault-url", args.azure_key_vault_url.as_deref())?;
    let certificate_name = required_text(
        "--azure-key-vault-certificate",
        args.azure_key_vault_certificate.as_deref(),
    )?;
    let managed_identity = args.azure_key_vault_managed_identity
        || matches!(
            args.azure_key_vault_credential_type,
            Some(AzureCredentialType::ManagedIdentity)
        );
    let auth = KvAuthParams {
        access_token: args.azure_key_vault_access_token.as_deref(),
        managed_identity,
        tenant_id: args.azure_key_vault_tenant_id.as_deref(),
        client_id: args.azure_key_vault_client_id.as_deref(),
        client_secret: args.azure_key_vault_client_secret.as_deref(),
        authority: args.azure_authority.as_deref(),
    };
    let token = acquire_kv_access_token(&auth)?;
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let certificate = fetch_kv_certificate(
        &http,
        &vault_url,
        &certificate_name,
        args.azure_key_vault_certificate_version.as_deref(),
        &token,
    )?;
    let cert_der = kv_decode_cer_b64(&certificate.cer)?;
    if kv_public_key_kind_from_cer_der(&cert_der)? != KvPublicKeyKind::Rsa {
        return Err(anyhow!(
            "`psign-tool code` Azure Key Vault package orchestration requires an RSA signing certificate"
        ));
    }
    Ok(CodeSigner {
        backend: CodeSignerBackend::AzureKeyVault(Box::new(CodeAzureKeyVaultSigner {
            http,
            token,
            certificate,
            cert_der,
        })),
    })
}

#[cfg(not(feature = "azure-kv-sign"))]
fn resolve_code_signer_azure_key_vault(_args: &CodeArgs) -> Result<CodeSigner> {
    Err(anyhow!(
        "`psign-tool code` Azure Key Vault execution requires the azure-kv-sign feature"
    ))
}

#[cfg(feature = "artifact-signing-rest")]
fn resolve_code_signer_artifact_signing(args: &CodeArgs) -> Result<CodeSigner> {
    Ok(CodeSigner {
        backend: CodeSignerBackend::ArtifactSigning(Box::new(CodeArtifactSigningSigner {
            metadata: args.artifact_signing_metadata.clone(),
            region: args.artifact_signing_region.clone(),
            endpoint: args.artifact_signing_endpoint.clone(),
            account_name: args.artifact_signing_account_name.clone(),
            profile_name: args.artifact_signing_profile_name.clone(),
            signature_algorithm: args.artifact_signing_signature_algorithm.clone(),
            api_version: args.artifact_signing_api_version.clone(),
            correlation_id: args.artifact_signing_correlation_id.clone(),
            access_token: args.artifact_signing_access_token.clone(),
            managed_identity: args.artifact_signing_managed_identity
                || matches!(
                    args.artifact_signing_credential_type,
                    Some(AzureCredentialType::ManagedIdentity)
                ),
            managed_identity_resource_id: args
                .artifact_signing_managed_identity_resource_id
                .clone(),
            credential_type: args.artifact_signing_credential_type,
            tenant_id: args.artifact_signing_tenant_id.clone(),
            client_id: args.artifact_signing_client_id.clone(),
            client_secret: args.artifact_signing_client_secret.clone(),
            federated_token_file: args.artifact_signing_federated_token_file.clone(),
            authority: args.artifact_signing_authority.clone(),
            endpoint_base_url: args.artifact_signing_endpoint_base_url.clone(),
        })),
    })
}

#[cfg(not(feature = "artifact-signing-rest"))]
fn resolve_code_signer_artifact_signing(_args: &CodeArgs) -> Result<CodeSigner> {
    Err(anyhow!(
        "`psign-tool code` Artifact Signing execution requires the artifact-signing-rest feature"
    ))
}

fn azure_key_vault_requested(args: &CodeArgs) -> bool {
    text_opt(args.azure_key_vault_url.as_deref()).is_some()
        || text_opt(args.azure_key_vault_certificate.as_deref()).is_some()
        || text_opt(args.azure_key_vault_certificate_version.as_deref()).is_some()
        || text_opt(args.azure_key_vault_client_id.as_deref()).is_some()
        || text_opt(args.azure_key_vault_client_secret.as_deref()).is_some()
        || text_opt(args.azure_key_vault_tenant_id.as_deref()).is_some()
        || text_opt(args.azure_key_vault_access_token.as_deref()).is_some()
        || args.azure_key_vault_managed_identity
        || args.azure_key_vault_credential_type.is_some()
        || text_opt(args.azure_authority.as_deref()).is_some()
}

fn artifact_signing_requested(args: &CodeArgs) -> bool {
    args.artifact_signing_metadata.is_some()
        || text_opt(args.artifact_signing_region.as_deref()).is_some()
        || text_opt(args.artifact_signing_endpoint.as_deref()).is_some()
        || text_opt(args.artifact_signing_account_name.as_deref()).is_some()
        || text_opt(args.artifact_signing_profile_name.as_deref()).is_some()
        || text_opt(args.artifact_signing_signature_algorithm.as_deref()).is_some()
        || text_opt(args.artifact_signing_api_version.as_deref()).is_some()
        || text_opt(args.artifact_signing_correlation_id.as_deref()).is_some()
        || text_opt(args.artifact_signing_access_token.as_deref()).is_some()
        || args.artifact_signing_managed_identity
        || text_opt(
            args.artifact_signing_managed_identity_resource_id
                .as_deref(),
        )
        .is_some()
        || args.artifact_signing_credential_type.is_some()
        || text_opt(args.artifact_signing_tenant_id.as_deref()).is_some()
        || text_opt(args.artifact_signing_client_id.as_deref()).is_some()
        || text_opt(args.artifact_signing_client_secret.as_deref()).is_some()
        || text_opt(args.artifact_signing_federated_token_file.as_deref()).is_some()
        || text_opt(args.artifact_signing_authority.as_deref()).is_some()
        || text_opt(args.artifact_signing_endpoint_base_url.as_deref()).is_some()
}

fn required_text(name: &str, value: Option<&str>) -> Result<String> {
    text_opt(value).ok_or_else(|| anyhow!("{name} is required for the selected signing provider"))
}

fn text_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn code_remote_digest_from_pkcs7(
    digest: pkcs7::AuthenticodeSigningDigest,
) -> CodeRemoteDigestAlgorithm {
    match digest {
        pkcs7::AuthenticodeSigningDigest::Sha256 => CodeRemoteDigestAlgorithm::Sha256,
        pkcs7::AuthenticodeSigningDigest::Sha384 => CodeRemoteDigestAlgorithm::Sha384,
        pkcs7::AuthenticodeSigningDigest::Sha512 => CodeRemoteDigestAlgorithm::Sha512,
    }
}

fn code_remote_digest_from_vsix(digest: vsix::VsixHashAlgorithm) -> CodeRemoteDigestAlgorithm {
    match digest {
        vsix::VsixHashAlgorithm::Sha256 => CodeRemoteDigestAlgorithm::Sha256,
        vsix::VsixHashAlgorithm::Sha384 => CodeRemoteDigestAlgorithm::Sha384,
        vsix::VsixHashAlgorithm::Sha512 => CodeRemoteDigestAlgorithm::Sha512,
    }
}

#[cfg(feature = "azure-kv-sign")]
fn kv_hash_algorithm(algorithm: CodeRemoteDigestAlgorithm) -> KvHashAlg {
    match algorithm {
        CodeRemoteDigestAlgorithm::Sha256 => KvHashAlg::Sha256,
        CodeRemoteDigestAlgorithm::Sha384 => KvHashAlg::Sha384,
        CodeRemoteDigestAlgorithm::Sha512 => KvHashAlg::Sha512,
    }
}

#[cfg(feature = "artifact-signing-rest")]
fn artifact_signature_algorithm(algorithm: CodeRemoteDigestAlgorithm) -> &'static str {
    match algorithm {
        CodeRemoteDigestAlgorithm::Sha256 => "RS256",
        CodeRemoteDigestAlgorithm::Sha384 => "RS384",
        CodeRemoteDigestAlgorithm::Sha512 => "RS512",
    }
}

fn load_chain_certs(paths: Vec<PathBuf>) -> Result<Vec<x509_cert::Certificate>> {
    let mut chain = Vec::with_capacity(paths.len());
    for chain_cert in paths {
        let bytes =
            std::fs::read(&chain_cert).with_context(|| format!("read {}", chain_cert.display()))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse chain certificate {}", chain_cert.display()))?,
        );
    }
    Ok(chain)
}

#[cfg(feature = "artifact-signing-rest")]
#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
struct ArtifactSigningMetadataDoc {
    Endpoint: String,
    CodeSigningAccountName: String,
    CertificateProfileName: String,
    #[serde(default)]
    CorrelationId: Option<String>,
    #[serde(default)]
    ExcludeCredentials: Option<Vec<String>>,
}

fn nuget_hash_algorithm(digest: DigestAlgorithm) -> Result<nuget::NuGetHashAlgorithm> {
    match digest {
        DigestAlgorithm::Sha256 => Ok(nuget::NuGetHashAlgorithm::Sha256),
        DigestAlgorithm::Sha384 => Ok(nuget::NuGetHashAlgorithm::Sha384),
        DigestAlgorithm::Sha512 => Ok(nuget::NuGetHashAlgorithm::Sha512),
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => Err(anyhow!(
            "`psign-tool code` package signing supports SHA-256, SHA-384, or SHA-512 file digests"
        )),
    }
}

fn signing_digest_algorithm(digest: DigestAlgorithm) -> Result<pkcs7::AuthenticodeSigningDigest> {
    match digest {
        DigestAlgorithm::Sha256 => Ok(pkcs7::AuthenticodeSigningDigest::Sha256),
        DigestAlgorithm::Sha384 => Ok(pkcs7::AuthenticodeSigningDigest::Sha384),
        DigestAlgorithm::Sha512 => Ok(pkcs7::AuthenticodeSigningDigest::Sha512),
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => Err(anyhow!(
            "`psign-tool code` package signing supports SHA-256, SHA-384, or SHA-512 file digests"
        )),
    }
}

fn vsix_hash_algorithm(digest: DigestAlgorithm) -> Result<vsix::VsixHashAlgorithm> {
    match digest {
        DigestAlgorithm::Sha256 => Ok(vsix::VsixHashAlgorithm::Sha256),
        DigestAlgorithm::Sha384 => Ok(vsix::VsixHashAlgorithm::Sha384),
        DigestAlgorithm::Sha512 => Ok(vsix::VsixHashAlgorithm::Sha512),
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => Err(anyhow!(
            "`psign-tool code` package signing supports SHA-256, SHA-384, or SHA-512 file digests"
        )),
    }
}

fn sign_pkcs7_signed_attrs_digest(
    digest: pkcs7::AuthenticodeSigningDigest,
    private_key: rsa::RsaPrivateKey,
    signed_attrs_digest: &[u8],
) -> Result<Vec<u8>> {
    let signature = match digest {
        pkcs7::AuthenticodeSigningDigest::Sha256 => {
            let key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
            key.sign_prehash(signed_attrs_digest)
                .map_err(|e| anyhow!("RSA/SHA-256 signed attributes prehash sign: {e}"))?
                .to_bytes()
                .to_vec()
        }
        pkcs7::AuthenticodeSigningDigest::Sha384 => {
            let key = rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(private_key);
            key.sign_prehash(signed_attrs_digest)
                .map_err(|e| anyhow!("RSA/SHA-384 signed attributes prehash sign: {e}"))?
                .to_bytes()
                .to_vec()
        }
        pkcs7::AuthenticodeSigningDigest::Sha512 => {
            let key = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private_key);
            key.sign_prehash(signed_attrs_digest)
                .map_err(|e| anyhow!("RSA/SHA-512 signed attributes prehash sign: {e}"))?
                .to_bytes()
                .to_vec()
        }
    };
    Ok(signature)
}

fn certificates_der_equal(a: &x509_cert::Certificate, b: &x509_cert::Certificate) -> Result<bool> {
    let a_der = a
        .to_der()
        .map_err(|e| anyhow!("encode expected signer certificate DER: {e}"))?;
    let b_der = b
        .to_der()
        .map_err(|e| anyhow!("encode actual signer certificate DER: {e}"))?;
    Ok(a_der == b_der)
}

fn sign_xml_signed_info(
    algorithm: vsix::VsixHashAlgorithm,
    private_key: rsa::RsaPrivateKey,
    signed_info: &[u8],
) -> Vec<u8> {
    match algorithm {
        vsix::VsixHashAlgorithm::Sha256 => {
            rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key)
                .sign(signed_info)
                .to_vec()
        }
        vsix::VsixHashAlgorithm::Sha384 => {
            rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(private_key)
                .sign(signed_info)
                .to_vec()
        }
        vsix::VsixHashAlgorithm::Sha512 => {
            rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private_key)
                .sign(signed_info)
                .to_vec()
        }
    }
}

fn output_path_for_node(node: &CodePlanNode) -> Result<PathBuf> {
    if node.output_path.contains('!') {
        return Err(anyhow!(
            "`psign-tool code` signing execution cannot write nested output path {} yet",
            node.output_path
        ));
    }
    Ok(display_to_path(&node.output_path))
}

fn appinstaller_companion_output_path(node: &CodePlanNode) -> Result<PathBuf> {
    let mut output = output_path_for_node(node)?;
    if output
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("p7"))
    {
        return Ok(output);
    }
    let Some(name) = output.file_name().and_then(|name| name.to_str()) else {
        return Err(anyhow!(
            "invalid App Installer output path {}",
            output.display()
        ));
    };
    output.set_file_name(format!("{name}.p7"));
    Ok(output)
}

fn appinstaller_descriptor_output_path(node: &CodePlanNode) -> Result<PathBuf> {
    let output = output_path_for_node(node)?;
    if output
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("p7"))
    {
        let stem = output
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| anyhow!("invalid App Installer output path {}", output.display()))?;
        let mut descriptor = output.clone();
        descriptor.set_file_name(stem);
        return Ok(descriptor);
    }
    Ok(output)
}

fn display_to_path(display: &str) -> PathBuf {
    PathBuf::from(display.replace('/', std::path::MAIN_SEPARATOR_STR))
}

#[cfg(feature = "timestamp-http")]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    Ok(())
}

fn validate_appinstaller_descriptor(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("App Installer descriptor is not UTF-8")?;
    if !text.contains("<AppInstaller") {
        return Err(anyhow!(
            "App Installer descriptor root <AppInstaller> not found"
        ));
    }
    if find_xml_start_tag_by_local_name(text, "MainPackage", 0)?.is_none()
        && find_xml_start_tag_by_local_name(text, "MainBundle", 0)?.is_none()
    {
        return Err(anyhow!(
            "App Installer descriptor does not contain MainPackage or MainBundle"
        ));
    }
    Ok(())
}

fn selection_rules(base: &Path, args: &CodeArgs) -> Result<Vec<PatternRule>> {
    let mut rules = Vec::new();
    for input in &args.inputs {
        rules.extend(pattern_rules(input)?);
    }
    if let Some(file_list) = &args.file_list {
        let path = if file_list.is_absolute() {
            file_list.clone()
        } else {
            base.join(file_list)
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read file list {}", path.display()))?;
        for (line_no, raw) in text.lines().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            rules.extend(
                pattern_rules(trimmed)
                    .with_context(|| format!("parse {} line {}", path.display(), line_no + 1))?,
            );
        }
    }
    if rules.is_empty() {
        return Err(anyhow!(
            "code dry-run requires at least one input or --file-list entry"
        ));
    }
    Ok(rules)
}

fn nested_exclude_patterns(base: &Path, args: &CodeArgs) -> Result<Vec<String>> {
    Ok(selection_rules(base, args)?
        .into_iter()
        .filter(|rule| !rule.include)
        .map(|rule| rule.pattern)
        .collect())
}

fn select_inputs(base: &Path, rules: &[PatternRule]) -> Result<Vec<PathBuf>> {
    let mut selected = BTreeSet::new();
    for rule in rules {
        let matches = resolve_rule(base, rule)?;
        if rule.include {
            selected.extend(matches);
        } else {
            for path in matches {
                selected.remove(&path);
            }
        }
    }
    Ok(selected.into_iter().collect())
}

fn pattern_rules(input: &str) -> Result<Vec<PatternRule>> {
    let mut include = true;
    let pattern = if let Some(rest) = input.strip_prefix("\\!") {
        format!("!{}", unescape_pattern(rest)?)
    } else if let Some(rest) = input.strip_prefix('!') {
        include = false;
        unescape_pattern(rest)?
    } else {
        unescape_pattern(input)?
    };
    if pattern.is_empty() {
        return Err(anyhow!("empty pattern"));
    }
    validate_relative_pattern(&pattern)?;
    Ok(expand_braces(&pattern)?
        .into_iter()
        .map(|pattern| PatternRule { include, pattern })
        .collect())
}

fn resolve_rule(base: &Path, rule: &PatternRule) -> Result<Vec<PathBuf>> {
    if has_glob_meta(&rule.pattern) {
        let mut out = Vec::new();
        for candidate in walk_files(base)? {
            let rel = candidate
                .strip_prefix(base)
                .with_context(|| format!("strip base from {}", candidate.display()))?;
            let normalized = normalize_match_path(rel);
            if glob_match(&rule.pattern, &normalized) {
                out.push(candidate);
            }
        }
        Ok(out)
    } else {
        let path = base.join(pattern_to_native_path(&rule.pattern));
        Ok(if path.is_file() {
            vec![path]
        } else {
            Vec::new()
        })
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

impl PlanBuilder {
    fn add_path(
        &mut self,
        path: &Path,
        base: &Path,
        depth: usize,
        recurse_containers: bool,
    ) -> Result<usize> {
        let display = path
            .strip_prefix(base)
            .map(normalize_match_path)
            .unwrap_or_else(|_| display_path(path));
        let output_display = self.top_level_output_path(&display);
        self.add_node_from_reader(
            path,
            display,
            output_display,
            depth,
            recurse_containers,
            None,
        )
    }

    fn add_nested_zip_entry(
        &mut self,
        display: String,
        output_display: String,
        depth: usize,
        recurse_containers: bool,
        bytes: Vec<u8>,
    ) -> Result<usize> {
        let path = PathBuf::from(&display);
        self.add_node_from_reader(
            &path,
            display,
            output_display,
            depth,
            recurse_containers,
            Some(bytes),
        )
    }

    fn add_node_from_reader(
        &mut self,
        path: &Path,
        display: String,
        output_display: String,
        depth: usize,
        recurse_containers: bool,
        bytes: Option<Vec<u8>>,
    ) -> Result<usize> {
        if let Some(id) = self.node_ids.get(&display) {
            return Ok(*id);
        }
        let owned_prefix = if bytes.is_none() && is_extension(path, "app") && path.is_file() {
            Some(read_prefix(path, 4)?)
        } else {
            None
        };
        let format = detect_format(path, bytes.as_deref().or(owned_prefix.as_deref()));
        let id = self.nodes.len();
        self.node_ids.insert(display.clone(), id);
        self.nodes.push(CodePlanNode {
            id,
            path: display.clone(),
            output_path: output_display.clone(),
            signer: signer_for_format(&format),
            container: format.is_container(),
            format: format.clone(),
            depth,
        });

        if recurse_containers && format.is_container() {
            let nested = if let Some(bytes) = bytes {
                self.inspect_zip_entries(Cursor::new(bytes), &display, &output_display, depth + 1)?
            } else {
                self.inspect_zip_entries(
                    File::open(path).with_context(|| format!("open {}", path.display()))?,
                    &display,
                    &output_display,
                    depth + 1,
                )?
            };
            for entry in nested {
                let child = self.add_nested_zip_entry(
                    entry.display,
                    entry.output_display,
                    entry.depth,
                    recurse_containers,
                    entry.bytes,
                )?;
                self.edges.push(CodePlanEdge {
                    before: child,
                    after: id,
                });
            }
        }
        Ok(id)
    }

    fn top_level_output_path(&self, display: &str) -> String {
        let Some(output) = &self.output else {
            return display.to_owned();
        };
        let output_display = normalize_output_display(output);
        if self.top_level_count == 1 && !is_output_directory_target(output) {
            output_display
        } else {
            join_display_path(&output_display, display)
        }
    }

    fn inspect_zip_entries<R>(
        &self,
        reader: R,
        container: &str,
        container_output: &str,
        depth: usize,
    ) -> Result<Vec<NestedEntry>>
    where
        R: Read + Seek,
    {
        let mut archive = zip::ZipArchive::new(reader)
            .with_context(|| format!("open ZIP container {container}"))?;
        let mut entries = Vec::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.is_dir() {
                continue;
            }
            let name = normalize_zip_name(file.name())?;
            let display = format!("{container}!{name}");
            let output_display = format!("{container_output}!{name}");
            if self.nested_excludes.iter().any(|pattern| {
                glob_match(pattern, &name) || glob_match(pattern, &display.replace('!', "/"))
            }) {
                continue;
            }
            let format = detect_format(Path::new(&name), None);
            if format == CodeFormat::Unknown {
                continue;
            }
            let mut bytes = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut bytes)?;
            entries.push(NestedEntry {
                display,
                output_display,
                depth,
                bytes,
            });
        }
        entries.sort_by(|a, b| a.display.cmp(&b.display));
        Ok(entries)
    }
}

struct NestedEntry {
    display: String,
    output_display: String,
    depth: usize,
    bytes: Vec<u8>,
}

#[allow(dead_code)]
pub(crate) struct ZipEntryUpdate {
    pub name: String,
    pub bytes: Vec<u8>,
    pub compression: zip::CompressionMethod,
}

fn zip_file_options(
    compression: zip::CompressionMethod,
    modified: zip::DateTime,
) -> zip::write::FileOptions {
    zip::write::FileOptions::default()
        .compression_method(compression)
        .last_modified_time(modified)
}

#[allow(dead_code)]
pub(crate) fn repack_zip_with_updates<R, W>(
    reader: R,
    writer: W,
    updates: Vec<ZipEntryUpdate>,
) -> Result<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let mut pending = BTreeMap::new();
    let updated_timestamp = opc::current_zip_datetime()
        .context("determine local ZIP timestamp for rewritten entries")?;
    for update in updates {
        let name = normalize_zip_name(&update.name)?;
        if pending.insert(name.clone(), update).is_some() {
            return Err(anyhow!("duplicate ZIP update entry: {name}"));
        }
    }

    let mut input = zip::ZipArchive::new(reader).context("open ZIP for repack")?;
    let mut output = zip::ZipWriter::new(writer);
    for i in 0..input.len() {
        let mut file = input.by_index(i).context("read ZIP entry for repack")?;
        let name = normalize_zip_name(file.name())?;
        if let Some(update) = pending.remove(&name) {
            output.start_file(
                name,
                zip_file_options(update.compression, updated_timestamp),
            )?;
            output.write_all(&update.bytes)?;
        } else {
            let options = zip_file_options(file.compression(), file.last_modified());
            if file.is_dir() {
                output.add_directory(name, options)?;
            } else {
                output.start_file(name, options)?;
                std::io::copy(&mut file, &mut output)?;
            }
        }
    }

    for (name, update) in pending {
        output.start_file(
            name,
            zip_file_options(update.compression, updated_timestamp),
        )?;
        output.write_all(&update.bytes)?;
    }
    output.finish()?;
    Ok(())
}

fn detect_format(path: &Path, bytes: Option<&[u8]>) -> CodeFormat {
    if is_extension(path, "app") {
        return if bytes.is_some_and(|b| b.starts_with(b"NAVX")) {
            CodeFormat::BusinessCentralApp
        } else {
            CodeFormat::Unknown
        };
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("exe" | "dll" | "sys" | "ocx" | "efi" | "scr" | "cpl" | "mui") => CodeFormat::Pe,
        Some("winmd") => CodeFormat::Winmd,
        Some("cab") => CodeFormat::Cab,
        Some("msi") => CodeFormat::Msi,
        Some("msp") => CodeFormat::Msp,
        Some("mst") => CodeFormat::Mst,
        Some("cat") => CodeFormat::Catalog,
        Some(
            "ps1" | "psd1" | "psm1" | "ps1xml" | "psc1" | "cdxml" | "mof" | "js" | "vbs" | "wsf"
            | "jse" | "vbe" | "wsc",
        ) => CodeFormat::Script,
        Some("msix") => CodeFormat::Msix,
        Some("appx") => CodeFormat::Appx,
        Some("msixbundle") => CodeFormat::MsixBundle,
        Some("appxbundle") => CodeFormat::AppxBundle,
        Some("appxupload") => CodeFormat::AppxUpload,
        Some("msixupload") => CodeFormat::MsixUpload,
        Some("eappx" | "emsix" | "eappxbundle" | "emsixbundle") => CodeFormat::EncryptedMsix,
        Some("nupkg") => CodeFormat::Nuget,
        Some("snupkg") => CodeFormat::Snupkg,
        Some("vsix") => CodeFormat::Vsix,
        Some("application") => CodeFormat::ClickOnceApplication,
        Some("vsto") => CodeFormat::Vsto,
        Some("manifest") => CodeFormat::Manifest,
        Some("deploy") => CodeFormat::Deploy,
        Some("appinstaller") => CodeFormat::AppInstaller,
        Some("zip") => CodeFormat::Zip,
        _ => CodeFormat::Unknown,
    }
}

fn is_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}

fn read_prefix(path: &Path, len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    file.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; len];
    let read = file.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

fn signer_for_format(format: &CodeFormat) -> &'static str {
    match format {
        CodeFormat::Nuget | CodeFormat::Snupkg => "nuget-package-native",
        CodeFormat::Vsix => "vsix-opc-xmldsig",
        CodeFormat::ClickOnceApplication
        | CodeFormat::Vsto
        | CodeFormat::Manifest
        | CodeFormat::Deploy => "clickonce-manifest",
        CodeFormat::EncryptedMsix => "msix-encrypted-os-only",
        CodeFormat::AppInstaller => "appinstaller-detached-pkcs7",
        CodeFormat::BusinessCentralApp => "business-central-app",
        CodeFormat::Zip => "container-only",
        CodeFormat::Unknown => "unsupported",
        _ => "authenticode",
    }
}

fn digest_name(digest: DigestAlgorithm) -> &'static str {
    match digest {
        DigestAlgorithm::Sha1 => "sha1",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha384 => "sha384",
        DigestAlgorithm::Sha512 => "sha512",
        DigestAlgorithm::CertHash => "cert-hash",
    }
}

fn render_text_plan(plan: &CodePlan) -> String {
    let mut out = String::new();
    out.push_str("psign code dry-run plan\n");
    out.push_str(&format!("base_directory={}\n", plan.base_directory));
    out.push_str(&format!("nodes={}\n", plan.nodes.len()));
    for node in &plan.nodes {
        out.push_str(&format!(
            "#{:03} depth={} format={:?} signer={} path={} output={}\n",
            node.id, node.depth, node.format, node.signer, node.path, node.output_path
        ));
    }
    out
}

fn validate_relative_pattern(pattern: &str) -> Result<()> {
    let path = pattern_to_native_path(pattern);
    if Path::new(&path).is_absolute() {
        return Err(anyhow!("absolute patterns are not supported: {pattern}"));
    }
    for component in Path::new(&path).components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(anyhow!(
                "pattern may not traverse outside the base directory: {pattern}"
            ));
        }
    }
    Ok(())
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn pattern_to_native_path(pattern: &str) -> PathBuf {
    pattern.split('/').collect()
}

fn is_output_directory_target(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    path.is_dir() || text.ends_with('/') || text.ends_with('\\')
}

fn normalize_output_display(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn join_display_path(base: &str, rel: &str) -> String {
    if base.is_empty() {
        rel.to_owned()
    } else if base.ends_with('/') {
        format!("{base}{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

fn normalize_match_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(s) => Some(s.to_string_lossy().replace('\\', "/")),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn normalize_zip_name(name: &str) -> Result<String> {
    if name.is_empty() || name.starts_with('/') || name.contains('\\') {
        return Err(anyhow!("unsafe ZIP entry path: {name}"));
    }
    if name.split('/').any(|part| part == "." || part == "..") {
        return Err(anyhow!("unsafe ZIP entry path: {name}"));
    }
    Ok(name.to_owned())
}

fn unescape_pattern(input: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(next @ ('!' | '{' | '}' | '\\')) => out.push(next),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => return Err(anyhow!("trailing escape")),
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn expand_braces(pattern: &str) -> Result<Vec<String>> {
    let Some((start, end)) = first_brace(pattern)? else {
        return Ok(vec![pattern.to_owned()]);
    };
    let before = &pattern[..start];
    let body = &pattern[start + 1..end];
    let after = &pattern[end + 1..];
    let choices = brace_choices(body)?;
    let mut out = Vec::new();
    for choice in choices {
        for expanded in expand_braces(&format!("{before}{choice}{after}"))? {
            out.push(expanded);
        }
    }
    Ok(out)
}

fn first_brace(pattern: &str) -> Result<Option<(usize, usize)>> {
    let mut start = None;
    let mut depth = 0usize;
    let mut escaped = false;
    for (idx, ch) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '{' => {
                if depth == 0 {
                    start = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    return Err(anyhow!("unmatched closing brace in pattern: {pattern}"));
                }
                depth -= 1;
                if depth == 0 {
                    return Ok(Some((start.expect("brace start"), idx)));
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(anyhow!("unmatched opening brace in pattern: {pattern}"));
    }
    Ok(None)
}

fn brace_choices(body: &str) -> Result<Vec<String>> {
    if let Some((start, end)) = body.split_once("..") {
        let first = start.parse::<i64>();
        let last = end.parse::<i64>();
        if let (Ok(first), Ok(last)) = (first, last) {
            let width = start.len().max(end.len());
            let range: Box<dyn Iterator<Item = i64>> = if first <= last {
                Box::new(first..=last)
            } else {
                Box::new((last..=first).rev())
            };
            return Ok(range
                .map(|n| {
                    if width > 1 {
                        format!("{n:0width$}")
                    } else {
                        n.to_string()
                    }
                })
                .collect());
        }
    }

    let mut choices = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in body.chars() {
        match ch {
            '{' => {
                depth += 1;
                current.push(ch);
            }
            '}' => {
                if depth == 0 {
                    return Err(anyhow!("unmatched closing brace in {body}"));
                }
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                choices.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }
    choices.push(current);
    Ok(choices)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut memo = BTreeMap::new();
    glob_match_inner(p, t, 0, 0, &mut memo)
}

fn glob_match_inner(
    pattern: &[u8],
    text: &[u8],
    pi: usize,
    ti: usize,
    memo: &mut BTreeMap<(usize, usize), bool>,
) -> bool {
    if let Some(value) = memo.get(&(pi, ti)) {
        return *value;
    }
    let result = if pi == pattern.len() {
        ti == text.len()
    } else if pattern[pi] == b'*' {
        if pi + 1 < pattern.len() && pattern[pi + 1] == b'*' {
            ((pi + 2 < pattern.len()
                && pattern[pi + 2] == b'/'
                && glob_match_inner(pattern, text, pi + 3, ti, memo))
                || glob_match_inner(pattern, text, pi + 2, ti, memo))
                || (ti < text.len() && glob_match_inner(pattern, text, pi, ti + 1, memo))
        } else {
            glob_match_inner(pattern, text, pi + 1, ti, memo)
                || (ti < text.len()
                    && text[ti] != b'/'
                    && glob_match_inner(pattern, text, pi, ti + 1, memo))
        }
    } else if pattern[pi] == b'?' {
        ti < text.len() && text[ti] != b'/' && glob_match_inner(pattern, text, pi + 1, ti + 1, memo)
    } else {
        ti < text.len()
            && pattern[pi].eq_ignore_ascii_case(&text[ti])
            && glob_match_inner(pattern, text, pi + 1, ti + 1, memo)
    };
    memo.insert((pi, ti), result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::FileOptions;

    fn test_datetime(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> zip::DateTime {
        zip::DateTime::from_date_and_time(year, month, day, hour, minute, second)
            .expect("valid test timestamp")
    }

    fn zip_datetime_parts(dt: zip::DateTime) -> (u16, u8, u8, u8, u8, u8) {
        (
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        )
    }

    #[test]
    fn brace_expansion_supports_nested_lists_and_ranges() {
        assert_eq!(
            expand_braces("lib/{net{6,8}.0,tools}/file{01..02}.dll").unwrap(),
            [
                "lib/net6.0/file01.dll",
                "lib/net6.0/file02.dll",
                "lib/net8.0/file01.dll",
                "lib/net8.0/file02.dll",
                "lib/tools/file01.dll",
                "lib/tools/file02.dll",
            ]
        );
    }

    #[test]
    fn globstar_crosses_directories_but_star_does_not() {
        assert!(glob_match("**/*.dll", "lib/net8.0/a.dll"));
        assert!(glob_match("**/*.dll", "a.dll"));
        assert!(!glob_match("*.dll", "lib/net8.0/a.dll"));
        assert!(glob_match("lib/net?.0/*.dll", "lib/net8.0/a.dll"));
    }

    #[test]
    fn rejects_traversal_patterns() {
        assert!(pattern_rules("../secret.dll").is_err());
        assert!(pattern_rules("safe/../../secret.dll").is_err());
    }

    #[test]
    fn repack_zip_replaces_and_appends_entries() {
        let input = test_zip(&[
            ("lib/net8.0/a.dll", b"old".as_slice()),
            ("content/readme.txt", b"text".as_slice()),
        ]);
        let mut output = Cursor::new(Vec::new());

        repack_zip_with_updates(
            Cursor::new(input),
            &mut output,
            vec![
                ZipEntryUpdate {
                    name: "lib/net8.0/a.dll".to_owned(),
                    bytes: b"new".to_vec(),
                    compression: zip::CompressionMethod::Deflated,
                },
                ZipEntryUpdate {
                    name: ".signature.p7s".to_owned(),
                    bytes: b"cms".to_vec(),
                    compression: zip::CompressionMethod::Stored,
                },
            ],
        )
        .unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(output.into_inner())).unwrap();
        assert_eq!(read_zip_entry(&mut archive, "lib/net8.0/a.dll"), b"new");
        assert_eq!(read_zip_entry(&mut archive, ".signature.p7s"), b"cms");
        assert_eq!(
            archive.by_name(".signature.p7s").unwrap().compression(),
            zip::CompressionMethod::Stored
        );
    }

    #[test]
    fn repack_zip_preserves_unchanged_entry_timestamps_and_stamps_updates() {
        let original_a = test_datetime(2001, 2, 3, 4, 5, 6);
        let original_readme = test_datetime(2002, 3, 4, 5, 6, 8);
        let input = test_zip_with_timestamps(&[
            ("lib/net8.0/a.dll", b"old".as_slice(), original_a),
            ("content/readme.txt", b"text".as_slice(), original_readme),
        ]);
        let mut output = Cursor::new(Vec::new());

        repack_zip_with_updates(
            Cursor::new(input),
            &mut output,
            vec![
                ZipEntryUpdate {
                    name: "lib/net8.0/a.dll".to_owned(),
                    bytes: b"new".to_vec(),
                    compression: zip::CompressionMethod::Deflated,
                },
                ZipEntryUpdate {
                    name: ".signature.p7s".to_owned(),
                    bytes: b"cms".to_vec(),
                    compression: zip::CompressionMethod::Stored,
                },
            ],
        )
        .unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(output.into_inner())).unwrap();
        assert_eq!(
            zip_datetime_parts(
                archive
                    .by_name("content/readme.txt")
                    .unwrap()
                    .last_modified()
            ),
            zip_datetime_parts(original_readme)
        );

        let updated = archive.by_name("lib/net8.0/a.dll").unwrap().last_modified();
        assert_ne!(zip_datetime_parts(updated), zip_datetime_parts(original_a));
        assert_ne!(
            zip_datetime_parts(updated),
            zip_datetime_parts(zip::DateTime::default())
        );

        let signature = archive.by_name(".signature.p7s").unwrap().last_modified();
        assert_ne!(
            zip_datetime_parts(signature),
            zip_datetime_parts(zip::DateTime::default())
        );
    }

    #[test]
    fn repack_zip_rejects_unsafe_update_path() {
        let input = test_zip(&[("file.txt", b"text".as_slice())]);
        let err = repack_zip_with_updates(
            Cursor::new(input),
            Cursor::new(Vec::new()),
            vec![ZipEntryUpdate {
                name: "../evil.txt".to_owned(),
                bytes: b"evil".to_vec(),
                compression: zip::CompressionMethod::Deflated,
            }],
        )
        .unwrap_err();

        assert!(err.to_string().contains("unsafe ZIP entry path"));
    }

    fn test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        test_zip_with_timestamps(
            &entries
                .iter()
                .map(|(name, bytes)| (*name, *bytes, zip::DateTime::default()))
                .collect::<Vec<_>>(),
        )
    }

    fn test_zip_with_timestamps(entries: &[(&str, &[u8], zip::DateTime)]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            for (name, bytes, modified) in entries {
                writer
                    .start_file(*name, FileOptions::default().last_modified_time(*modified))
                    .expect("start zip entry");
                writer.write_all(bytes).expect("write zip entry");
            }
            writer.finish().expect("finish zip");
        }
        out.into_inner()
    }

    fn read_zip_entry(archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
        let mut file = archive.by_name(name).expect("zip entry");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read zip entry");
        bytes
    }
}
