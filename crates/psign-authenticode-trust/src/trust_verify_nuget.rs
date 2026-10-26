//! NuGet package author-signature trust (`.nupkg` / `.snupkg`).
//!
//! The `.signature.p7s` CMS encapsulates the signature content
//! (`Version:1` + `<hash OID>-Hash:<base64>`). The package hash is recomputed over the exact
//! unsigned package bytes (see [`psign_opc_sign::nuget::signed_package_unsigned_bytes`]), then the
//! CMS is trust-verified with its PKCS#9 `messageDigest` bound to that content.

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::{Context, Result, anyhow};
use der::asn1::OctetString;
use psign_opc_sign::nuget;
use psign_sip_digest::pkcs7::{
    parse_pkcs7_signed_data_der, signer_info_pkcs9_message_digest_octets,
};
use sha2::Digest;

fn digest_for_length(len: usize, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match len {
        32 => sha2::Sha256::digest(data).to_vec(),
        48 => sha2::Sha384::digest(data).to_vec(),
        64 => sha2::Sha512::digest(data).to_vec(),
        n => return Err(anyhow!("unsupported NuGet signature digest length {n}")),
    })
}

/// The verified NuGet signature content of `package` and its PKCS#9 `messageDigest`.
///
/// Embedded content (as `dotnet nuget sign` writes it) must record the package hash of the exact
/// unsigned bytes. A detached CMS (written by earlier psign releases) is accepted when the
/// signature content rebuilt from that package hash matches the signed `messageDigest`.
pub fn nuget_verified_signature_content(
    package: &[u8],
    signature: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let sd = parse_pkcs7_signed_data_der(signature).context("NuGet .signature.p7s CMS")?;
    let signer = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("NuGet signature has no SignerInfo"))?;
    let message_digest = signer_info_pkcs9_message_digest_octets(signer)
        .map_err(|e| anyhow!("NuGet signature messageDigest: {e}"))?;
    let unsigned = nuget::signed_package_unsigned_bytes(package)?;

    let content = match sd.encap_content_info.econtent.as_ref() {
        Some(econtent) => {
            let content = econtent
                .decode_as::<OctetString>()
                .map_err(|e| anyhow!("NuGet signature content is not an OCTET STRING: {e}"))?
                .as_bytes()
                .to_vec();
            let parsed = nuget::parse_signature_content(&content)?;
            if parsed.hash_algorithm.hash(&unsigned) != parsed.package_hash {
                return Err(anyhow!(
                    "NuGet package hash mismatch: the package content changed after signing"
                ));
            }
            content
        }
        None => [
            nuget::NuGetHashAlgorithm::Sha256,
            nuget::NuGetHashAlgorithm::Sha384,
            nuget::NuGetHashAlgorithm::Sha512,
        ]
        .into_iter()
        .map(|alg| nuget::signature_content_bytes(alg, &alg.hash(&unsigned)))
        .find(|content| {
            digest_for_length(message_digest.len(), content)
                .ok()
                .as_ref()
                == Some(&message_digest)
        })
        .ok_or_else(|| {
            anyhow!("NuGet package hash mismatch: the package content changed after signing")
        })?,
    };
    if digest_for_length(message_digest.len(), &content)? != message_digest {
        return Err(anyhow!(
            "NuGet signature messageDigest mismatch: the signed content differs from the embedded content"
        ));
    }
    Ok((content, message_digest))
}

pub fn trust_verify_nuget_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let signature = nuget::extract_signature(std::io::Cursor::new(data))?;
    let (_, content_digest) = nuget_verified_signature_content(data, &signature)?;

    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        &signature,
        0,
        &content_digest,
        Pkcs7DigestBinding::Pkcs9MessageDigest,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}
