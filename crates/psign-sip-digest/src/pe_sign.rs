use crate::pe_digest::{PeAuthenticodeHashKind, pe_authenticode_digest};
use crate::pe_embed::pe_append_authenticode_pkcs7_certificate;
use crate::pkcs7::{encode_pkcs7_content_info_signed_data_der, parse_pkcs7_signed_data_der};
use crate::rdp::{parse_certificate, parse_rsa_private_key};
use anyhow::{Context, Result, anyhow};
use authenticode::{DigestInfo, SPC_INDIRECT_DATA_OBJID, SpcAttributeTypeAndOptionalValue};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::CmsVersion;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;
use x509_cert::spki::AlgorithmIdentifierOwned;

const OID_SPC_PE_IMAGE_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const DER_NULL: &[u8] = &[0x05, 0x00];

// SpcPeImageData with the conventional empty "<<<Obsolete>>>" link used by Authenticode PE signatures.
const SPC_PE_IMAGE_DATA_DER: &[u8] = &[
    0x30, 0x25, 0x03, 0x01, 0x00, 0xA0, 0x20, 0xA2, 0x1E, 0x80, 0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00,
    0x3C, 0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x74, 0x00,
    0x65, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3E,
];

pub fn sign_pe_image_rsa_sha256(
    pe_image: &[u8],
    signer_cert_der: &[u8],
    private_key_bytes: &[u8],
) -> Result<Vec<u8>> {
    let digest = pe_authenticode_digest(pe_image, PeAuthenticodeHashKind::Sha256)
        .context("compute PE Authenticode SHA-256 digest")?;
    let pkcs7 =
        build_pe_authenticode_pkcs7_rsa_sha256(&digest, signer_cert_der, private_key_bytes)?;
    pe_append_authenticode_pkcs7_certificate(pe_image.to_vec(), &pkcs7)
        .context("embed Authenticode PKCS#7")
}

pub fn build_pe_authenticode_pkcs7_rsa_sha256(
    pe_digest_sha256: &[u8],
    signer_cert_der: &[u8],
    private_key_bytes: &[u8],
) -> Result<Vec<u8>> {
    if pe_digest_sha256.len() != 32 {
        return Err(anyhow!(
            "PE SHA-256 digest must be 32 bytes, got {}",
            pe_digest_sha256.len()
        ));
    }
    let signer_cert = parse_certificate(signer_cert_der).context("parse signer certificate")?;
    let private_key = parse_rsa_private_key(private_key_bytes).context("parse RSA private key")?;
    let signer = SigningKey::<Sha256>::new(private_key);
    let digest_algorithm = sha256_algorithm_identifier()?;

    let indirect = authenticode::SpcIndirectDataContent {
        data: SpcAttributeTypeAndOptionalValue {
            value_type: OID_SPC_PE_IMAGE_DATA,
            value: Any::from_der(SPC_PE_IMAGE_DATA_DER).context("SpcPeImageData DER")?,
        },
        message_digest: DigestInfo {
            digest_algorithm: digest_algorithm.clone(),
            digest: OctetString::new(pe_digest_sha256.to_vec())
                .map_err(|e| anyhow!("PE digest OCTET STRING: {e}"))?,
        },
    };
    let indirect_der = indirect
        .to_der()
        .map_err(|e| anyhow!("encode SpcIndirectDataContent: {e}"))?;
    let content = EncapsulatedContentInfo {
        econtent_type: SPC_INDIRECT_DATA_OBJID,
        econtent: Some(
            Any::from_der(&indirect_der).context("SpcIndirectDataContent encapsulated content")?,
        ),
    };
    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });
    let signer_info =
        SignerInfoBuilder::new(&signer, signer_id, digest_algorithm.clone(), &content, None)
            .map_err(|e| anyhow!("build Authenticode SignerInfo: {e}"))?;
    let pkcs7 = SignedDataBuilder::new(&content)
        .add_digest_algorithm(digest_algorithm)
        .map_err(|e| anyhow!("add Authenticode digest algorithm: {e}"))?
        .add_certificate(CertificateChoices::Certificate(signer_cert))
        .map_err(|e| anyhow!("add signer certificate: {e}"))?
        .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info)
        .map_err(|e| anyhow!("sign Authenticode authenticated attributes: {e}"))?
        .build()
        .map_err(|e| anyhow!("build Authenticode SignedData: {e}"))?;
    let pkcs7_der = pkcs7
        .to_der()
        .map_err(|e| anyhow!("encode Authenticode PKCS#7 ContentInfo: {e}"))?;
    let mut signed_data =
        parse_pkcs7_signed_data_der(&pkcs7_der).context("parse generated Authenticode PKCS#7")?;
    signed_data.version = CmsVersion::V1;
    encode_pkcs7_content_info_signed_data_der(&signed_data)
}

fn sha256_algorithm_identifier() -> Result<AlgorithmIdentifierOwned> {
    Ok(AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: Some(Any::from_der(DER_NULL).context("NULL algorithm parameters")?),
    })
}
