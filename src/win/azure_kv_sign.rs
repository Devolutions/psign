//! Azure Key Vault REST signing for Authenticode (`SignerSignEx3` + `AuthenticodeDigestSign` callback).

use crate::cli::{DigestAlgorithm, GlobalOpts, SignArgs};
use crate::win::sealing::validate_sign_constraints_paths;
use crate::win::sign_core::{
    adopt_cert, authenticode_sign_embedded, encoding, infer_digest_for_cert,
    merge_additional_cert_file, open_memory_cert_store, validate_cert_constraints,
};
use anyhow::{Result, anyhow};
use psign_azure_kv_rest::{
    KvAuthParams, KvHashAlg, KvPublicKeyKind, acquire_kv_access_token, fetch_kv_certificate,
    kv_decode_cer_b64, kv_jws_alg, kv_public_key_kind_from_cer_der, kv_sign_digest,
    kv_sign_url_from_kid,
};
use std::cell::RefCell;
use std::mem::size_of;
use windows::Win32::Foundation::{E_FAIL, S_OK};
use windows::Win32::Security::Cryptography::ALG_ID;
use windows::Win32::Security::Cryptography::{
    CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, CERT_CONTEXT, CERT_STORE_ADD_REPLACE_EXISTING,
    CRYPT_INTEGER_BLOB, CertAddCertificateContextToStore, CertCreateCertificateContext,
    CertFreeCertificateContext, SIGNER_DIGEST_SIGN_INFO, SIGNER_DIGEST_SIGN_INFO_0,
};
use windows::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};
use windows::core::HRESULT;

thread_local! {
    static KV_HTTP: RefCell<Option<KvCallbackState>> = const { RefCell::new(None) };
}

struct KvCallbackState {
    client: reqwest::blocking::Client,
    token: String,
    sign_url: String,
    key_kind: KvPublicKeyKind,
}

fn auth_params_from_sign_args(args: &SignArgs) -> KvAuthParams<'_> {
    KvAuthParams {
        access_token: args.azure_key_vault_access_token.as_deref(),
        managed_identity: args.azure_key_vault_managed_identity,
        tenant_id: args.azure_key_vault_tenant_id.as_deref(),
        client_id: args.azure_key_vault_client_id.as_deref(),
        client_secret: args.azure_key_vault_client_secret.as_deref(),
        authority: args.azure_authority.as_deref(),
    }
}

fn algid_to_kv_hash(algid: ALG_ID) -> Result<KvHashAlg> {
    if algid == CALG_SHA_256 {
        Ok(KvHashAlg::Sha256)
    } else if algid == CALG_SHA_384 {
        Ok(KvHashAlg::Sha384)
    } else if algid == CALG_SHA_512 {
        Ok(KvHashAlg::Sha512)
    } else {
        Err(anyhow!(
            "unsupported digest algorithm for Azure Key Vault signing (try SHA256/384/512)"
        ))
    }
}

unsafe extern "system" fn azure_kv_digest_callback(
    _p_cert: *const CERT_CONTEXT,
    _p_metadata: *const CRYPT_INTEGER_BLOB,
    algid_hash: ALG_ID,
    pb_digest: *const u8,
    cb_digest: u32,
    p_signature_blob: *mut CRYPT_INTEGER_BLOB,
) -> HRESULT {
    if pb_digest.is_null() || p_signature_blob.is_null() {
        return E_FAIL;
    }
    let digest = unsafe { std::slice::from_raw_parts(pb_digest, cb_digest as usize) };

    let outcome = KV_HTTP.with(|slot| {
        let borrowed = slot.borrow();
        let Some(state) = borrowed.as_ref() else {
            return Err(anyhow!(
                "Azure KV signing thread-local state was not installed"
            ));
        };
        let hash = match algid_to_kv_hash(algid_hash) {
            Ok(h) => h,
            Err(_) => return Err(anyhow!("unsupported digest / key kind for KV")),
        };
        let alg = match kv_jws_alg(state.key_kind, hash) {
            Ok(a) => a,
            Err(_) => return Err(anyhow!("unsupported digest / key kind for KV")),
        };
        kv_sign_digest(
            &state.client,
            &state.token,
            &state.sign_url,
            alg.as_str(),
            digest,
        )
    });

    let sig = match outcome {
        Ok(b) => b,
        Err(_) => return E_FAIL,
    };

    // SAFETY: `LocalAlloc` matches native Authenticode expectations for out-of-band digest callbacks.
    let raw = match unsafe { LocalAlloc(LMEM_FIXED, sig.len()) } {
        Ok(h) => h,
        Err(_) => return E_FAIL,
    };
    if raw.is_invalid() {
        return E_FAIL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sig.as_ptr(), raw.0 as *mut u8, sig.len());
        (*p_signature_blob).cbData = sig.len() as u32;
        (*p_signature_blob).pbData = raw.0 as *mut u8;
    }
    S_OK
}

pub(crate) fn validate_azure_kv_mutex(args: &SignArgs) -> Result<()> {
    let has_url = args
        .azure_key_vault_url
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !has_url {
        let mut any = false;
        macro_rules! flag {
            ($($f:ident),*) => {
                $( any |= args.$f.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false); )*
            };
        }
        flag!(
            azure_key_vault_certificate,
            azure_key_vault_certificate_version,
            azure_key_vault_client_id,
            azure_key_vault_client_secret,
            azure_key_vault_tenant_id,
            azure_key_vault_access_token
        );
        any |= args.azure_key_vault_managed_identity;
        if any {
            return Err(anyhow!(
                "Azure Key Vault options require --azure-key-vault-url (-kvu)"
            ));
        }
        return Ok(());
    }

    if args.pfx.is_some() {
        return Err(anyhow!(
            "Azure Key Vault signing cannot be combined with --pfx (-f)"
        ));
    }
    if args.csp.is_some() || args.key_container.is_some() {
        return Err(anyhow!(
            "Azure Key Vault signing cannot be combined with --csp / --key-container"
        ));
    }
    if args.dlib.is_some() || args.dmdf.is_some() || args.trusted_signing_dlib_root.is_some() {
        return Err(anyhow!(
            "Azure Key Vault signing cannot be combined with --dlib / --dmdf / --trusted-signing-dlib-root"
        ));
    }
    if args.subject_name.is_some()
        || args.issuer_name.is_some()
        || args.cert_sha1.is_some()
        || args.auto_select
    {
        return Err(anyhow!(
            "Azure Key Vault signing does not use store certificate selection; omit --n/--i/--sha1/--a"
        ));
    }

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
            "choose Azure Key Vault authentication: --azure-key-vault-accesstoken, --azure-key-vault-managed-identity, or client id/secret/tenant"
        ));
    }

    Ok(())
}

pub(crate) fn sign_with_azure_key_vault(
    args: &SignArgs,
    target: &std::path::Path,
    global: &GlobalOpts,
) -> Result<String> {
    validate_azure_kv_mutex(args)?;
    validate_sign_constraints_paths(args, std::iter::once(target))?;
    if args.page_hashes {
        return Err(anyhow!(
            "--page-hashes with Azure Key Vault is not supported in this implementation"
        ));
    }

    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let token = acquire_kv_access_token(&auth_params_from_sign_args(args))?;
    let vault_base = args
        .azure_key_vault_url
        .as_deref()
        .ok_or_else(|| anyhow!("internal: missing vault URL"))?;
    let cert_name = args
        .azure_key_vault_certificate
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("--azure-key-vault-certificate (-kvc) is required"))?;
    let cert = fetch_kv_certificate(
        &http,
        vault_base,
        cert_name,
        args.azure_key_vault_certificate_version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        &token,
    )?;

    let sign_url = kv_sign_url_from_kid(cert.kid.trim())?;

    let cer_der = kv_decode_cer_b64(cert.cer.trim())?;
    let key_kind = kv_public_key_kind_from_cer_der(&cer_der)?;

    let store = open_memory_cert_store()?;
    // SAFETY: `cer_der` is valid DER for the duration of import.
    let leaf = unsafe { CertCreateCertificateContext(encoding(), &cer_der) };
    if leaf.is_null() {
        return Err(anyhow!(
            "CertCreateCertificateContext failed for Key Vault certificate"
        ));
    }
    unsafe {
        CertAddCertificateContextToStore(
            Some(store.0),
            leaf.cast_const(),
            CERT_STORE_ADD_REPLACE_EXISTING,
            None,
        )
        .map_err(|e| {
            let _ = CertFreeCertificateContext(Some(leaf.cast_const()));
            anyhow!("CertAddCertificateContextToStore: {e}")
        })?;
    }
    let signing = adopt_cert(leaf)?;
    unsafe {
        let _ = CertFreeCertificateContext(Some(leaf.cast_const()));
    }

    validate_cert_constraints(signing.0 as *const CERT_CONTEXT, args)?;

    for ac in &args.additional_certs {
        merge_additional_cert_file(store.0, ac)?;
    }

    let resolved_digest = match args.digest {
        DigestAlgorithm::CertHash => infer_digest_for_cert(signing.0 as *const CERT_CONTEXT)?,
        other => other,
    };

    let mut empty_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let mut anon = SIGNER_DIGEST_SIGN_INFO_0::default();
    anon.pfnAuthenticodeDigestSign = Some(azure_kv_digest_callback);
    let digest_info = SIGNER_DIGEST_SIGN_INFO {
        cbSize: size_of::<SIGNER_DIGEST_SIGN_INFO>() as u32,
        dwDigestSignChoice: 1,
        Anonymous: anon,
        pMetadataBlob: std::ptr::addr_of_mut!(empty_blob),
        dwReserved: 0,
        dwReserved2: 0,
        dwReserved3: 0,
    };
    let digest_ptr = std::ptr::addr_of!(digest_info);

    KV_HTTP.with(|slot| {
        *slot.borrow_mut() = Some(KvCallbackState {
            client: http,
            token,
            sign_url,
            key_kind,
        });
    });

    let report = authenticode_sign_embedded(
        args,
        target,
        global,
        store.0,
        &signing,
        resolved_digest,
        None,
        Some(digest_ptr),
        "azure-key-vault",
        "MEMORY",
        None,
        None,
    );

    KV_HTTP.with(|slot| {
        slot.borrow_mut().take();
    });

    report
}
