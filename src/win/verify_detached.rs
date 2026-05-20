use crate::cli::{VerifyArgs, VerifyPolicy};
use anyhow::{Result, anyhow};
use std::borrow::Cow;
use std::mem::size_of;
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG,
    CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_ENCODING_TYPE, CRYPT_VERIFY_MESSAGE_PARA, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertGetNameStringW,
    CertVerifyCertificateChainPolicy, CryptVerifyDetachedMessageSignature, HCRYPTPROV_LEGACY,
};

pub struct DetachedVerifySummary {
    pub signer_subject: String,
}

/// PKCS #7 `ContentInfo` wrapping `signedData` — OID `1.2.840.113549.1.7.2`.
const PKCS7_SIGNED_DATA_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];

fn der_encode_definite_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut n = len;
    let mut stack = Vec::new();
    while n > 0 {
        stack.push((n & 0xff) as u8);
        n >>= 8;
    }
    stack.reverse();
    let mut out = vec![0x80 | (stack.len() as u8)];
    out.extend(stack);
    out
}

/// If `signtool /p7` wrote a bare CMS `SignedData` sequence (first element is `version` INTEGER),
/// wrap it as a PKCS #7 `ContentInfo` so `CryptVerifyDetachedMessageSignature` accepts it.
fn pkcs7_content_info_signed_data(signed_data_der: &[u8]) -> Vec<u8> {
    let explicit_wrapped_len = signed_data_der.len();
    let mut explicit = Vec::with_capacity(2 + explicit_wrapped_len + 8);
    explicit.push(0xA0);
    explicit.extend(der_encode_definite_length(explicit_wrapped_len));
    explicit.extend_from_slice(signed_data_der);

    let inner_len = PKCS7_SIGNED_DATA_OID_DER.len() + explicit.len();
    let mut out = Vec::with_capacity(2 + inner_len + 8);
    out.push(0x30);
    out.extend(der_encode_definite_length(inner_len));
    out.extend_from_slice(PKCS7_SIGNED_DATA_OID_DER);
    out.extend(explicit);
    out
}

/// First TLV is `SEQUENCE`; return payload bytes inside it (excluding tag and length).
fn tlv_outer_sequence_payload(data: &[u8]) -> Option<&[u8]> {
    if data.first().copied()? != 0x30 {
        return None;
    }
    let (len, hdr) = parse_der_definite_length(&data[1..])?;
    let total = 1 + hdr + len;
    if data.len() < total {
        return None;
    }
    Some(&data[1 + hdr..total])
}

fn parse_der_definite_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n_octets = (first & 0x7f) as usize;
    if n_octets == 0 || n_octets > 4 || bytes.len() < 1 + n_octets {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n_octets {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Some((len, 1 + n_octets))
}

fn detached_pkcs7_blob_for_verify(sig_blob: &[u8]) -> Cow<'_, [u8]> {
    let Some(inner) = tlv_outer_sequence_payload(sig_blob) else {
        return Cow::Borrowed(sig_blob);
    };
    match inner.first().copied() {
        Some(0x06) => Cow::Borrowed(sig_blob),
        Some(0x02) => Cow::Owned(pkcs7_content_info_signed_data(sig_blob)),
        _ => Cow::Borrowed(sig_blob),
    }
}

fn cert_simple_name(cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT) -> String {
    if cert.is_null() {
        return "unknown".to_string();
    }
    // SAFETY: first call requests required size only.
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if len == 0 {
        return "unknown".to_string();
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: buffer is valid for reported size.
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(buf.as_mut_slice()),
        )
    };
    if written == 0 {
        return "unknown".to_string();
    }
    String::from_utf16_lossy(&buf[..written.saturating_sub(1) as usize])
}

pub fn verify_detached_pkcs7(
    content: &std::path::Path,
    signature: &std::path::Path,
    args: &VerifyArgs,
) -> Result<(DetachedVerifySummary, Vec<String>)> {
    let content_bytes = std::fs::read(content)?;
    let sig_raw = std::fs::read(signature)?;
    let sig_normalized = detached_pkcs7_blob_for_verify(&sig_raw);
    let sig_slice: &[u8] = sig_normalized.as_ref();
    let ptr = content_bytes.as_ptr();
    let len = content_bytes.len() as u32;
    let ptrs = [ptr];
    let lens = [len];

    let verify = CRYPT_VERIFY_MESSAGE_PARA {
        cbSize: size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32,
        dwMsgAndCertEncodingType: CERT_QUERY_ENCODING_TYPE(0x0001_0001).0,
        hCryptProv: HCRYPTPROV_LEGACY(0),
        pfnGetSignerCertificate: None,
        pvGetArg: std::ptr::null_mut(),
    };

    let mut signer = std::ptr::null_mut();
    // SAFETY: all pointers are valid and in-scope; detached signature buffer is immutable.
    unsafe {
        CryptVerifyDetachedMessageSignature(
            &verify,
            0,
            sig_slice,
            1,
            ptrs.as_ptr(),
            lens.as_ptr(),
            Some(&mut signer),
        )
    }
    .map_err(|e| anyhow!("CryptVerifyDetachedMessageSignature failed: {e}"))?;

    let signer_subject = cert_simple_name(signer);
    let detached_warnings = if !signer.is_null() {
        let constraints = (|| -> Result<Vec<String>> {
            crate::win::verify_chain::verify_signer_thumbprints_allowed(
                signer.cast_const(),
                &args.signer_thumbprint_sha1,
            )?;
            if !crate::win::verify_chain::intermediate_ca_thumbprints_match(
                signer.cast_const(),
                &args.intermediate_ca_sha1,
            )? {
                return Err(anyhow!(
                    "Verification failed: no intermediate CA certificate matched /ca thumbprints"
                ));
            }
            let mut w = crate::win::verify_chain::warn_missing_eku_messages(
                signer.cast_const(),
                &args.warn_if_missing_eku,
            )?;
            w.extend(crate::win::verify_chain::pca_2010_warning_message_lines(
                signer.cast_const(),
                matches!(args.policy, VerifyPolicy::Default),
                args.kernel_policy,
                args.warn_pca_2010,
                args.no_warn_pca_2010,
            )?);
            Ok(w)
        })();
        match constraints {
            Ok(w) => w,
            Err(e) => {
                unsafe {
                    let _ = CertFreeCertificateContext(Some(signer.cast_const()));
                }
                return Err(e);
            }
        }
    } else {
        vec![]
    };

    if !signer.is_null() {
        let chain_para = CERT_CHAIN_PARA {
            cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };
        let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        // SAFETY: signer context is valid and chain output pointer is valid.
        let chain_acq = unsafe {
            CertGetCertificateChain(
                None,
                signer.cast_const(),
                None,
                None,
                &chain_para,
                if args.revocation_check {
                    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                } else {
                    0
                },
                None,
                &mut chain,
            )
        };
        if let Err(e) = chain_acq {
            unsafe {
                let _ = CertFreeCertificateContext(Some(signer.cast_const()));
            }
            return Err(anyhow!("CertGetCertificateChain failed: {e}"));
        }
        if !chain.is_null() {
            let chain_policy_para = CERT_CHAIN_POLICY_PARA {
                cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
                dwFlags: if args.allow_test_root {
                    CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG
                } else {
                    Default::default()
                },
                ..Default::default()
            };
            let mut chain_policy_status = CERT_CHAIN_POLICY_STATUS {
                cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
                ..Default::default()
            };
            // SAFETY: pointers are valid and owned in this scope.
            let ok = unsafe {
                CertVerifyCertificateChainPolicy(
                    if args.kernel_policy {
                        windows::Win32::Security::Cryptography::CERT_CHAIN_POLICY_MICROSOFT_ROOT
                    } else if args.policy == VerifyPolicy::Pa {
                        windows::Win32::Security::Cryptography::CERT_CHAIN_POLICY_AUTHENTICODE
                    } else {
                        CERT_CHAIN_POLICY_BASE
                    },
                    chain.cast_const(),
                    &chain_policy_para,
                    &mut chain_policy_status,
                )
            };
            if !ok.as_bool() || chain_policy_status.dwError != 0 {
                unsafe {
                    CertFreeCertificateChain(chain.cast_const());
                    let _ = CertFreeCertificateContext(Some(signer.cast_const()));
                }
                return Err(anyhow!(
                    "detached signature signer chain policy failed: 0x{:08X}",
                    chain_policy_status.dwError
                ));
            }
            // SAFETY: chain context acquired by CertGetCertificateChain.
            unsafe {
                CertFreeCertificateChain(chain.cast_const());
            }
        }
    }
    if !signer.is_null() {
        // SAFETY: signer cert context returned by CryptVerifyDetachedMessageSignature.
        unsafe {
            let _ = CertFreeCertificateContext(Some(signer.cast_const()));
        }
    }

    Ok((DetachedVerifySummary { signer_subject }, detached_warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_bare_signed_data_sequence_for_verify() {
        let bare_signed_data = [0x30u8, 0x03, 0x02, 0x01, 0x01];
        let normalized = detached_pkcs7_blob_for_verify(&bare_signed_data);
        let Cow::Owned(wrapped) = normalized else {
            panic!("expected wrap");
        };
        let payload = tlv_outer_sequence_payload(&wrapped).expect("outer seq");
        assert_eq!(payload.first(), Some(&0x06));
    }

    #[test]
    fn leaves_content_info_unchanged() {
        let mut blob = vec![0x30u8];
        blob.extend(der_encode_definite_length(
            PKCS7_SIGNED_DATA_OID_DER.len() + 2,
        ));
        blob.extend_from_slice(PKCS7_SIGNED_DATA_OID_DER);
        blob.push(0x05);
        blob.push(0x00);
        assert!(matches!(
            detached_pkcs7_blob_for_verify(&blob),
            Cow::Borrowed(_)
        ));
    }
}
