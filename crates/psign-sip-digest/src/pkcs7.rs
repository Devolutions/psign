//! PKCS#7 `SignedData` production for a standalone Rust signer (Tier 1a completion).
//!
//! Today, signing remains OS-delegated (`SignerSignEx3` / `mssign32` in `psign`). A future path may use
//! Windows `CryptMsgOpenToEncode` or the `cms` crate to assemble `SPC_INDIRECT_DATA` and embed `WIN_CERTIFICATE` entries.
//!
//! Format-specific **subject digests** feeding `SpcIndirectData` live elsewhere: [`crate::pe_digest`] (PE image hash),
//! [`crate::cab_digest`] (MSCF CAB layout), [`crate::msi_digest`] (OLE compound), [`crate::msix_digest`] (APPX AX\* blob under OID **`1.3.6.1.4.1.311.2.1.30`**), etc. Encoding those payloads into PKCS#7 is the missing producer piece; [`crate::pe_embed`] can append **`WIN_CERTIFICATE`** rows once PKCS#7 DER exists.
//!
//! **Milestone:** The **`authenticode`** crate publishes ASN.1 structs (`SpcIndirectDataContent`, `DigestInfo`, …) with `der` **Decode**/**Encode**.
//! [`parse_pe_pkcs7_spc_indirect_data_at`] / [`parse_pe_pkcs7_spc_indirect_data`] and [`spc_indirect_data_replace_message_digest`] support **Linux-side digest substitution** before a future **`SignedData`** signer assembles countersignatures / PKCS#9 attributes. [`cms_digest_encapsulated_econtent_bytes`] and [`signer_info_pkcs9_message_digest_octets`] pin **RFC 5652 §5.4** **`eContent`** hashing to PKCS#9 **`messageDigest`** on fixtures (RustCrypto **`cms` SignerInfoBuilder** semantics). [`signer_info_signed_attributes_sequence_der`] yields the **`SET OF Attribute`** octets for §5.4 authenticated-attribute signing; [`signed_attributes_replace_pkcs9_message_digest`] refreshes PKCS#9 **`messageDigest`** after **`encapContentInfo`** changes (**`encryptedDigest`** still requires re-sign). [`signer_info_sha256_digest_over_signed_attrs`] and [`signed_data_rsa_sha256_signer_prehash_digest`] **SHA-256**-hash **of** that **`SET`** (staging digest before PKCS#1 **DigestInfo** / **KV `RS256`** validation). [`signer_info_clone_with_signed_attrs`] / [`signer_info_clone_with_signature_octets`] patch **`SignerInfo`** after remote signing; [`signed_data_replace_signer_info_at`] / [`signed_data_replace_first_signer_info`] splice it back into **`SignedData.signerInfos`**. **`WIN_CERTIFICATE`** embedding remains [`crate::pe_embed`].

use anyhow::{Context as _, Result, anyhow};
use authenticode::{DigestInfo, SpcAttributeTypeAndOptionalValue, SpcIndirectDataContent};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignatureValue, SignedAttributes, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, AnyRef, ObjectIdentifier, OctetString, OctetStringRef, SetOfVec};
use der::{Decode, Encode, Reader, SliceReader, Tag};
use digest::Digest as _;
use rsa::RsaPrivateKey;
use sha2::{Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::spki::AlgorithmIdentifierOwned;

/// CMS **`signedData`** content type OID (`id-signedData`).
const ID_SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// Authenticode PE image-data OID (`SPC_PE_IMAGE_DATA_OBJID`).
const SPC_PE_IMAGE_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");
/// CAB Authenticode data OID observed in Windows CAB signatures (`SPC_LINK_OBJID`).
const SPC_CAB_LINK_OBJID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.28");
/// Windows Installer Authenticode data OID observed in MSI signatures (`SPC_SIGINFO_OBJID`).
const SPC_MSI_SIGINFO_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.30");
/// Stable minimal `SpcPeImageData` body used by Windows SignTool for PE Authenticode.
///
/// This is the DER **value** of the `SEQUENCE`:
/// `BIT STRING ''`, followed by an obsolete `SpcLink` placeholder (`<<<Obsolete>>>`).
const SPC_PE_IMAGE_DATA_VALUE: &[u8] = &[
    0x03, 0x01, 0x00, 0xa0, 0x20, 0xa2, 0x1e, 0x80, 0x1c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00,
    0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00,
    0x3e, 0x00, 0x3e, 0x00, 0x3e,
];
/// Stable CAB `SpcLink` value DER observed in Windows CAB Authenticode signatures.
const SPC_CAB_LINK_VALUE_DER: &[u8] = &[
    0xa1, 0x48, 0x04, 0x10, 0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17,
    0xda, 0x8e, 0x60, 0xd6, 0x04, 0x34, 0x31, 0x32, 0x30, 0x30, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x82, 0x37, 0x02, 0x05, 0x01, 0x31, 0x22, 0x04, 0x20, 0x1f, 0xa1, 0x2d, 0xdc, 0xd1, 0x11,
    0x50, 0x32, 0xe8, 0x90, 0x3f, 0x91, 0x52, 0x54, 0xb2, 0x19, 0x3a, 0x87, 0x34, 0xb1, 0x7e, 0x92,
    0x10, 0xd5, 0x52, 0x10, 0x8b, 0x77, 0x16, 0xee, 0x52, 0x9b,
];
/// Stable MSI `SpcSigInfo` value DER observed in Windows MSI/MSP Authenticode signatures.
const SPC_MSI_SIGINFO_VALUE_DER: &[u8] = &[
    0x30, 0x24, 0x02, 0x01, 0x02, 0x04, 0x10, 0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
];

/// **`SignerInfo.digestAlgorithm`** / **`DigestInfo.digestAlgorithm`** SHA-1 OID.
const DIGEST_OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
/// SHA-256 OID (**`id-sha256`**).
const DIGEST_OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// SHA-384 OID (**`id-sha384`**).
const DIGEST_OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// SHA-512 OID (**`id-sha512`**).
const DIGEST_OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// PKCS#9 **`messageDigest`** authenticated-attribute type OID.
pub const PKCS9_MESSAGE_DIGEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// PKCS#9 **`contentType`** authenticated-attribute type OID.
pub const PKCS9_CONTENT_TYPE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// Microsoft Authenticode RFC3161 timestamp-token unsigned attribute.
pub const MS_RFC3161_TIMESTAMP_TOKEN_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

/// CMS **`data`** content type OID (`id-data`).
pub const PKCS7_ID_DATA_OID: &str = "1.2.840.113549.1.7.1";

/// CMS **`signedData`** content type OID (string form).
pub const PKCS7_ID_SIGNED_DATA_OID: &str = "1.2.840.113549.1.7.2";

/// Digest algorithms supported by the portable Authenticode CMS producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticodeSigningDigest {
    /// SHA-256 (`id-sha256`) with RSA PKCS#1 v1.5 `sha256WithRSAEncryption`.
    Sha256,
    /// SHA-384 (`id-sha384`) with RSA PKCS#1 v1.5 `sha384WithRSAEncryption`.
    Sha384,
    /// SHA-512 (`id-sha512`) with RSA PKCS#1 v1.5 `sha512WithRSAEncryption`.
    Sha512,
}

impl AuthenticodeSigningDigest {
    /// Matching PE image digest kind.
    pub fn pe_hash_kind(self) -> crate::pe_digest::PeAuthenticodeHashKind {
        match self {
            Self::Sha256 => crate::pe_digest::PeAuthenticodeHashKind::Sha256,
            Self::Sha384 => crate::pe_digest::PeAuthenticodeHashKind::Sha384,
            Self::Sha512 => crate::pe_digest::PeAuthenticodeHashKind::Sha512,
        }
    }

    fn digest_algorithm(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: match self {
                Self::Sha256 => DIGEST_OID_SHA256,
                Self::Sha384 => DIGEST_OID_SHA384,
                Self::Sha512 => DIGEST_OID_SHA512,
            },
            parameters: None,
        }
    }

    fn rsa_signature_algorithm(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: match self {
                Self::Sha256 => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
                Self::Sha384 => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
                Self::Sha512 => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
            },
            parameters: Some(Any::from(AnyRef::NULL)),
        }
    }

    fn digest_bytes(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

/// Build the Authenticode `SpcIndirectDataContent` for a PE image digest.
pub fn pe_spc_indirect_data(
    digest_algorithm: AuthenticodeSigningDigest,
    pe_digest: &[u8],
) -> Result<SpcIndirectDataContent> {
    spc_indirect_data(
        digest_algorithm,
        pe_digest,
        SPC_PE_IMAGE_DATA_OBJID,
        Any::new(Tag::Sequence, SPC_PE_IMAGE_DATA_VALUE)
            .map_err(|e| anyhow!("SPC_PE_IMAGE_DATA Any: {e}"))?,
        "PE",
    )
}

/// Build the Authenticode `SpcIndirectDataContent` for a CAB file digest.
pub fn cab_spc_indirect_data(
    digest_algorithm: AuthenticodeSigningDigest,
    cab_digest: &[u8],
) -> Result<SpcIndirectDataContent> {
    spc_indirect_data(
        digest_algorithm,
        cab_digest,
        SPC_CAB_LINK_OBJID,
        Any::from_der(SPC_CAB_LINK_VALUE_DER).map_err(|e| anyhow!("SPC_CAB_LINK Any: {e}"))?,
        "CAB",
    )
}

/// Build the Authenticode `SpcIndirectDataContent` for an MSI/MSP OLE package digest.
pub fn msi_spc_indirect_data(
    digest_algorithm: AuthenticodeSigningDigest,
    msi_digest: &[u8],
) -> Result<SpcIndirectDataContent> {
    spc_indirect_data(
        digest_algorithm,
        msi_digest,
        SPC_MSI_SIGINFO_OBJID,
        Any::from_der(SPC_MSI_SIGINFO_VALUE_DER)
            .map_err(|e| anyhow!("SPC_MSI_SIGINFO Any: {e}"))?,
        "MSI",
    )
}

fn spc_indirect_data(
    digest_algorithm: AuthenticodeSigningDigest,
    subject_digest: &[u8],
    value_type: ObjectIdentifier,
    value: Any,
    label: &str,
) -> Result<SpcIndirectDataContent> {
    let expected = digest_algorithm.pe_hash_kind().digest_output_len();
    if subject_digest.len() != expected {
        return Err(anyhow!(
            "{label} digest length {} does not match {:?} ({expected} octets)",
            subject_digest.len(),
            digest_algorithm
        ));
    }
    let digest = OctetString::new(subject_digest.to_vec())
        .map_err(|e| anyhow!("SpcIndirectData digest OCTET STRING: {e}"))?;
    Ok(SpcIndirectDataContent {
        data: SpcAttributeTypeAndOptionalValue { value_type, value },
        message_digest: DigestInfo {
            digest_algorithm: digest_algorithm.digest_algorithm(),
            digest,
        },
    })
}

/// Create PKCS#7 `ContentInfo(SignedData)` DER for a CAB Authenticode signature using an RSA private key.
pub fn create_cab_authenticode_pkcs7_der_rsa(
    cab_image: &[u8],
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>> {
    let cab_digest = crate::cab_digest::cab_authenticode_digest_for_signing(
        cab_image,
        digest_algorithm.pe_hash_kind(),
    )?;
    let indirect = cab_spc_indirect_data(digest_algorithm, &cab_digest)?;
    create_authenticode_pkcs7_der_rsa(
        indirect,
        digest_algorithm,
        signer_cert,
        chain_certs,
        private_key,
    )
}

/// Create PKCS#7 `ContentInfo(SignedData)` DER for an MSI/MSP Authenticode signature using an RSA private key.
pub fn create_msi_authenticode_pkcs7_der_rsa(
    msi_image: &[u8],
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>> {
    let msi_digest = crate::msi_digest::compute_msi_authenticode_digest(
        msi_image,
        digest_algorithm.pe_hash_kind(),
    )?;
    let indirect = msi_spc_indirect_data(digest_algorithm, &msi_digest)?;
    create_authenticode_pkcs7_der_rsa(
        indirect,
        digest_algorithm,
        signer_cert,
        chain_certs,
        private_key,
    )
}

/// Create PKCS#7 `ContentInfo(SignedData)` DER for a PE Authenticode signature using an RSA private key.
///
/// This is the portable CMS producer used before format-specific embedding (for PE, `pe_embed` wraps the
/// returned DER in a `WIN_CERTIFICATE`). It intentionally supports the modern RSA/SHA-2 subset first.
pub fn create_pe_authenticode_pkcs7_der_rsa(
    pe_image: &[u8],
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>> {
    let pe_digest =
        crate::pe_digest::pe_authenticode_digest(pe_image, digest_algorithm.pe_hash_kind())?;
    let indirect = pe_spc_indirect_data(digest_algorithm, &pe_digest)?;
    create_authenticode_pkcs7_der_rsa(
        indirect,
        digest_algorithm,
        signer_cert,
        chain_certs,
        private_key,
    )
}

/// Create PKCS#7 `ContentInfo(SignedData)` DER for an Authenticode `SpcIndirectDataContent`.
pub fn create_authenticode_pkcs7_der_rsa(
    indirect: SpcIndirectDataContent,
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>> {
    match digest_algorithm {
        AuthenticodeSigningDigest::Sha256 => {
            create_authenticode_pkcs7_der_rsa_for_digest::<Sha256, rsa::pkcs1v15::Signature>(
                indirect,
                digest_algorithm,
                signer_cert,
                chain_certs,
                private_key,
            )
        }
        AuthenticodeSigningDigest::Sha384 => {
            create_authenticode_pkcs7_der_rsa_for_digest::<Sha384, rsa::pkcs1v15::Signature>(
                indirect,
                digest_algorithm,
                signer_cert,
                chain_certs,
                private_key,
            )
        }
        AuthenticodeSigningDigest::Sha512 => {
            create_authenticode_pkcs7_der_rsa_for_digest::<Sha512, rsa::pkcs1v15::Signature>(
                indirect,
                digest_algorithm,
                signer_cert,
                chain_certs,
                private_key,
            )
        }
    }
}

/// Return the digest that a remote RSA PKCS#1 v1.5 signer must sign for this Authenticode payload.
///
/// The returned bytes are the SHA-2 digest of DER `SignedAttributes` (`SET OF Attribute`) per RFC 5652 §5.4.
/// Pass the corresponding raw signature to [`create_authenticode_pkcs7_der_with_rsa_signature`].
pub fn authenticode_remote_rsa_signed_attrs_digest(
    indirect: &SpcIndirectDataContent,
    digest_algorithm: AuthenticodeSigningDigest,
) -> Result<Vec<u8>> {
    let attrs = authenticode_signed_attrs(indirect, digest_algorithm)?;
    let der = signed_attributes_der(&attrs)?;
    Ok(digest_algorithm.digest_bytes(&der))
}

/// Create PKCS#7 `ContentInfo(SignedData)` DER from externally produced RSA PKCS#1 v1.5 signature bytes.
///
/// This supports remote signers such as Key Vault or Trusted Signing once the caller has signed
/// [`authenticode_remote_rsa_signed_attrs_digest`] with the matching RSA/SHA-2 algorithm.
pub fn create_authenticode_pkcs7_der_with_rsa_signature(
    indirect: SpcIndirectDataContent,
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    encrypted_digest: &[u8],
) -> Result<Vec<u8>> {
    let attrs = authenticode_signed_attrs(&indirect, digest_algorithm)?;
    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: signer_id,
        digest_alg: digest_algorithm.digest_algorithm(),
        signed_attrs: Some(attrs),
        signature_algorithm: digest_algorithm.rsa_signature_algorithm(),
        signature: SignatureValue::new(encrypted_digest.to_vec())
            .map_err(|e| anyhow!("SignerInfo.signature OCTET STRING: {e}"))?,
        unsigned_attrs: None,
    };
    let indirect_der = encode_spc_indirect_data_der(&indirect)?;
    let mut rd = SliceReader::new(indirect_der.as_slice())
        .map_err(|e| anyhow!("indirect DER reader: {e}"))?;
    let econtent = Any::decode(&mut rd).map_err(|e| anyhow!("SpcIndirectData as CMS Any: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after SpcIndirectDataContent DER: {e}"))?;
    let digest_algorithms = SetOfVec::try_from(vec![digest_algorithm.digest_algorithm()])
        .map_err(|e| anyhow!("DigestAlgorithmIdentifiers SET: {e}"))?;
    let mut certs = Vec::with_capacity(chain_certs.len() + 1);
    certs.push(CertificateChoices::Certificate(signer_cert));
    certs.extend(chain_certs.into_iter().map(CertificateChoices::Certificate));
    let certificates = Some(CertificateSet(
        SetOfVec::try_from(certs).map_err(|e| anyhow!("CertificateSet SET: {e}"))?,
    ));
    let signer_infos = SignerInfos(
        SetOfVec::try_from(vec![signer_info]).map_err(|e| anyhow!("SignerInfos SET: {e}"))?,
    );
    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: authenticode::SPC_INDIRECT_DATA_OBJID,
            econtent: Some(econtent),
        },
        certificates,
        crls: None,
        signer_infos,
    };
    encode_pkcs7_content_info_signed_data_der(&sd)
}

/// Attach a raw RFC3161 `timeStampToken` `ContentInfo` as a Microsoft Authenticode unsigned attribute.
pub fn signed_data_add_rfc3161_timestamp_token(
    sd: &SignedData,
    signer_index: usize,
    timestamp_token_der: &[u8],
) -> Result<SignedData> {
    let signers = sd.signer_infos.0.as_slice();
    let si = signers.get(signer_index).ok_or_else(|| {
        anyhow!(
            "SignerInfo index {} out of range (len {})",
            signer_index,
            signers.len()
        )
    })?;
    let token_der = crate::pkcs7_wire::pkcs7_outer_sequence_prefix(timestamp_token_der)
        .unwrap_or(timestamp_token_der);
    let mut rd =
        SliceReader::new(token_der).map_err(|e| anyhow!("timestamp token DER reader: {e}"))?;
    let token_any =
        Any::decode(&mut rd).map_err(|e| anyhow!("timestamp token ContentInfo: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after timestamp token ContentInfo: {e}"))?;
    let mut values = SetOfVec::new();
    values
        .insert(token_any)
        .map_err(|e| anyhow!("timestamp AttributeValue SET: {e}"))?;
    let timestamp_attr = Attribute {
        oid: MS_RFC3161_TIMESTAMP_TOKEN_OID,
        values,
    };
    let mut attrs: Vec<Attribute> = si
        .unsigned_attrs
        .as_ref()
        .map(|attrs| attrs.iter().cloned().collect())
        .unwrap_or_default();
    attrs.retain(|attr| attr.oid != MS_RFC3161_TIMESTAMP_TOKEN_OID);
    attrs.push(timestamp_attr);
    let mut stamped = si.clone();
    stamped.unsigned_attrs = Some(
        SetOfVec::try_from(attrs)
            .map_err(|e| anyhow!("UnsignedAttributes SET canonicalization: {e}"))?,
    );
    signed_data_replace_signer_info_at(sd, signer_index, stamped)
}

fn create_authenticode_pkcs7_der_rsa_for_digest<D, Sig>(
    indirect: SpcIndirectDataContent,
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>>
where
    D: digest::Digest + rsa::pkcs8::AssociatedOid + rsa::pkcs1v15::RsaSignatureAssociatedOid,
    rsa::pkcs1v15::SigningKey<D>: rsa::signature::Keypair
        + rsa::signature::Signer<Sig>
        + x509_cert::spki::DynSignatureAlgorithmIdentifier,
    Sig: x509_cert::spki::SignatureBitStringEncoding,
{
    let indirect_der = encode_spc_indirect_data_der(&indirect)?;
    create_pkcs7_signed_data_der_rsa_for_digest::<D, Sig>(
        authenticode::SPC_INDIRECT_DATA_OBJID,
        &indirect_der,
        digest_algorithm,
        signer_cert,
        chain_certs,
        private_key,
    )
}

/// Create PKCS#7 `ContentInfo(SignedData)` DER for an arbitrary encapsulated content type using an RSA private key.
///
/// This is shared by Authenticode `SpcIndirectDataContent` producers and Microsoft CTL/catalog
/// authoring. `econtent_der` must be one complete DER TLV for the value placed inside
/// `EncapsulatedContentInfo.eContent`.
pub fn create_pkcs7_signed_data_der_rsa(
    econtent_type: ObjectIdentifier,
    econtent_der: &[u8],
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>> {
    match digest_algorithm {
        AuthenticodeSigningDigest::Sha256 => {
            create_pkcs7_signed_data_der_rsa_for_digest::<Sha256, rsa::pkcs1v15::Signature>(
                econtent_type,
                econtent_der,
                digest_algorithm,
                signer_cert,
                chain_certs,
                private_key,
            )
        }
        AuthenticodeSigningDigest::Sha384 => {
            create_pkcs7_signed_data_der_rsa_for_digest::<Sha384, rsa::pkcs1v15::Signature>(
                econtent_type,
                econtent_der,
                digest_algorithm,
                signer_cert,
                chain_certs,
                private_key,
            )
        }
        AuthenticodeSigningDigest::Sha512 => {
            create_pkcs7_signed_data_der_rsa_for_digest::<Sha512, rsa::pkcs1v15::Signature>(
                econtent_type,
                econtent_der,
                digest_algorithm,
                signer_cert,
                chain_certs,
                private_key,
            )
        }
    }
}

fn create_pkcs7_signed_data_der_rsa_for_digest<D, Sig>(
    econtent_type: ObjectIdentifier,
    econtent_der: &[u8],
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>>
where
    D: digest::Digest + rsa::pkcs8::AssociatedOid + rsa::pkcs1v15::RsaSignatureAssociatedOid,
    rsa::pkcs1v15::SigningKey<D>: rsa::signature::Keypair
        + rsa::signature::Signer<Sig>
        + x509_cert::spki::DynSignatureAlgorithmIdentifier,
    Sig: x509_cert::spki::SignatureBitStringEncoding,
{
    let signer = rsa::pkcs1v15::SigningKey::<D>::new(private_key);
    let digest_alg = digest_algorithm.digest_algorithm();
    let mut rd = SliceReader::new(econtent_der)
        .map_err(|e| anyhow!("encapsulated content DER reader: {e}"))?;
    let econtent =
        Any::decode(&mut rd).map_err(|e| anyhow!("encapsulated content as CMS Any: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after encapsulated content DER: {e}"))?;
    let content = EncapsulatedContentInfo {
        econtent_type,
        econtent: Some(econtent),
    };
    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });
    let signer_info =
        SignerInfoBuilder::new(&signer, signer_id, digest_alg.clone(), &content, None)
            .map_err(|e| anyhow!("build CMS SignerInfo: {e}"))?;
    let mut builder = SignedDataBuilder::new(&content);
    builder
        .add_digest_algorithm(digest_alg)
        .map_err(|e| anyhow!("add CMS digest algorithm: {e}"))?
        .add_certificate(CertificateChoices::Certificate(signer_cert))
        .map_err(|e| anyhow!("add CMS signer certificate: {e}"))?;
    for cert in chain_certs {
        builder
            .add_certificate(CertificateChoices::Certificate(cert))
            .map_err(|e| anyhow!("add CMS chain certificate: {e}"))?;
    }
    let pkcs7 = builder
        .add_signer_info::<rsa::pkcs1v15::SigningKey<D>, Sig>(signer_info)
        .map_err(|e| anyhow!("sign CMS signed attributes: {e}"))?
        .build()
        .map_err(|e| anyhow!("build CMS SignedData: {e}"))?
        .to_der()
        .map_err(|e| anyhow!("encode CMS PKCS#7 ContentInfo: {e}"))?;
    let mut sd = parse_pkcs7_signed_data_der(&pkcs7)?;
    // Microsoft Authenticode/catalog PKCS#7 profiles use SignedData.version v1 even though
    // RFC 5652 would normally select v3 for non-id-data encapsulated content. The existing
    // parser and Windows fixtures expect this value; it is outside the signed attribute digest.
    sd.version = CmsVersion::V1;
    encode_pkcs7_content_info_signed_data_der(&sd)
}

/// Encode **`SignedData`** as a PKCS#7 **`ContentInfo`** (**`contentType`** = **`id-signedData`**, RFC 5652).
///
/// This is a **building block** for portable Authenticode: mutating **`SignedData`** (e.g. new **`SignerInfo`**
/// with remote signature octets) then calling this function yields DER for **`pe_embed`**. Re-encoding an
/// unmodified structure is tested for **decode → encode → decode** stability on fixtures; **byte-for-byte**
/// equality with a given **`signtool.exe`** / **`CryptMsgOpenToEncode`** output is **not** guaranteed.
pub fn encode_pkcs7_content_info_signed_data_der(sd: &SignedData) -> Result<Vec<u8>> {
    let sd_der = sd.to_der().map_err(|e| anyhow!("encode SignedData: {e}"))?;
    let mut rd =
        SliceReader::new(sd_der.as_slice()).map_err(|e| anyhow!("SignedData DER reader: {e}"))?;
    let content = Any::decode(&mut rd).map_err(|e| anyhow!("SignedData as CMS Any: {e}"))?;
    let ci = ContentInfo {
        content_type: ID_SIGNED_DATA_OID,
        content,
    };
    ci.to_der().map_err(|e| anyhow!("encode ContentInfo: {e}"))
}

/// Decode **`SignedData`** from PKCS#7 DER (**outer `ContentInfo`** with **`contentType`** **`id-signedData`**).
///
/// Accepts the same blob layout as embedded PE **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** rows (after optional
/// [`crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode`] trimming).
pub fn parse_pkcs7_signed_data_der(pkcs7_der: &[u8]) -> Result<SignedData> {
    let normalized = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let bytes = normalized.as_ref();
    let mut r = SliceReader::new(bytes).map_err(|_| anyhow!("empty PKCS#7"))?;
    let ci = ContentInfo::decode(&mut r).map_err(|e| anyhow!("PKCS#7 ContentInfo decode: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA_OID {
        return Err(anyhow!(
            "PKCS#7 root content type is not SignedData (got {})",
            ci.content_type
        ));
    }
    ci.content
        .decode_as::<SignedData>()
        .map_err(|e| anyhow!("SignedData: {e}"))
}

/// **id-ce-subjectKeyIdentifier** (RFC 5280).
const SUBJECT_KEY_IDENTIFIER_EXT_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// Locate the embedded **`Certificate`** matching **`SignerInfo.sid`** (**`IssuerAndSerialNumber`** or **`SubjectKeyIdentifier`**).
pub fn signed_data_certificate_for_signer_identifier<'a>(
    sd: &'a SignedData,
    sid: &SignerIdentifier,
) -> Result<&'a Certificate> {
    let set = sd
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow!("SignedData has no certificates"))?;
    for choice in set.0.iter() {
        let CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        match sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                if cert.tbs_certificate.issuer == ias.issuer
                    && cert.tbs_certificate.serial_number == ias.serial_number
                {
                    return Ok(cert);
                }
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                let want = ski.0.as_bytes();
                let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
                    continue;
                };
                for ext in exts
                    .iter()
                    .filter(|e| e.extn_id == SUBJECT_KEY_IDENTIFIER_EXT_OID)
                {
                    let got = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
                        .map_err(|e| anyhow!("SKI extension parse: {e}"))?;
                    if got.0.as_bytes() == want {
                        return Ok(cert);
                    }
                }
            }
        }
    }
    Err(anyhow!("no embedded certificate matches SignerIdentifier"))
}

/// PKCS#9 **`messageDigest`** match + **RSA PKCS#1 v1.5** verify over authenticated **`signedAttrs`**
/// (**SHA-256** digest algorithm only), using the embedded signer certificate’s public key.
///
/// Used when **`picky`** rejects **`SpcIndirectData`** variants it does not model (e.g. CAB **`SpcCabinetData`**)
/// while the portable stack has already validated the Authenticode subject digest against the same PKCS#7.
/// Raw **`messageDigest.digest`** octets from **`SignedData.encapContentInfo.eContent`** decoded as **`SpcIndirectDataContent`**.
pub fn signed_data_spc_indirect_message_digest_octets(sd: &SignedData) -> Result<Vec<u8>> {
    let encap_any = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("SignedData missing encapsulated content"))?;
    let indirect = encap_any
        .decode_as::<SpcIndirectDataContent>()
        .map_err(|e| anyhow!("SpcIndirectDataContent: {e}"))?;
    Ok(indirect.message_digest.digest.as_bytes().to_vec())
}

/// Match **`expected_subject_digest`** against **`SpcIndirectData.messageDigest`**, then verify **RSA PKCS#1 v1.5**
/// over authenticated **`signedAttrs`** (**SHA-256** **`SignerInfo.digestAlgorithm`** only).
///
/// **Note:** PKCS#9 **`messageDigest`** signed attributes are not always identical to the encapsulated
/// **`SpcIndirectData`** digest on every Authenticode variant (observed on CAB fixtures); picky’s
/// **`require_basic_authenticode_validation`** is tied to the indirect object, so this helper does the same.
pub fn verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
    sd: &SignedData,
    signer_index: usize,
    expected_subject_digest: &[u8],
) -> Result<()> {
    let indirect = signed_data_spc_indirect_message_digest_octets(sd)?;
    if indirect.as_slice() != expected_subject_digest {
        return Err(anyhow!(
            "SpcIndirectData messageDigest does not match expected subject digest"
        ));
    }
    verify_signed_data_rsa_sha256_pkcs1v15_signature(sd, signer_index)
}

/// Match PKCS#9 **`messageDigest`** against `expected_content_digest`, then verify **RSA PKCS#1 v1.5**
/// over authenticated **`signedAttrs`** (**SHA-256** **`SignerInfo.digestAlgorithm`** only).
pub fn verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature(
    sd: &SignedData,
    signer_index: usize,
    expected_content_digest: &[u8],
) -> Result<()> {
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .get(signer_index)
        .ok_or_else(|| {
            anyhow!(
                "SignerInfo index {signer_index} out of range (len {})",
                sd.signer_infos.0.len()
            )
        })?;
    let md = signer_info_pkcs9_message_digest_octets(si)?;
    if md.as_slice() != expected_content_digest {
        return Err(anyhow!(
            "PKCS#9 messageDigest does not match expected content digest"
        ));
    }
    verify_signed_data_rsa_sha256_pkcs1v15_signature(sd, signer_index)
}

fn verify_signed_data_rsa_sha256_pkcs1v15_signature(
    sd: &SignedData,
    signer_index: usize,
) -> Result<()> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::hazmat::PrehashVerifier;
    use sha2::Sha256;

    const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

    let si = sd
        .signer_infos
        .0
        .as_slice()
        .get(signer_index)
        .ok_or_else(|| {
            anyhow!(
                "SignerInfo index {signer_index} out of range (len {})",
                sd.signer_infos.0.len()
            )
        })?;
    if si.digest_alg.oid != DIGEST_OID_SHA256 {
        return Err(anyhow!(
            "CMS fallback trust requires SignerInfo digestAlgorithm SHA-256 (got {})",
            si.digest_alg.oid
        ));
    }
    let cert = signed_data_certificate_for_signer_identifier(sd, &si.sid)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid.to_string() != RSA_ENCRYPTION_OID {
        return Err(anyhow!(
            "CMS fallback trust requires RSA public key (got algorithm OID {})",
            spki.algorithm.oid
        ));
    }
    let spki_der = spki
        .to_der()
        .map_err(|e| anyhow!("encode SubjectPublicKeyInfo: {e}"))?;
    let pk = rsa::RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| anyhow!("RSA public key from certificate: {e}"))?;
    let prehash = signer_info_sha256_digest_over_signed_attrs(si)?;
    let vk = VerifyingKey::<Sha256>::new(pk);
    let sig = Signature::try_from(si.signature.as_bytes())
        .map_err(|e| anyhow!("SignerInfo.signature PKCS#1 v1.5 octets: {e}"))?;
    vk.verify_prehash(&prehash, &sig)
        .map_err(|e| anyhow!("RSA PKCS#1 v1.5 verify over signedAttrs (SHA-256): {e}"))?;
    Ok(())
}

/// Decode **`SpcIndirectDataContent`** from the **`pkcs7_index`**-th embedded **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** PKCS#7 (**`0`** = first), certificate-table order.
///
/// Fails if there is no certificate table, no PKCS#7 row at **`pkcs7_index`**, or CMS parsing does not yield encapsulated Authenticode content.
pub fn parse_pe_pkcs7_spc_indirect_data_at(
    pe_image: &[u8],
    pkcs7_index: usize,
) -> Result<SpcIndirectDataContent> {
    let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_image, pkcs7_index)?;
    let sd = parse_pkcs7_signed_data_der(&pkcs7)?;
    let encap_any = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("SignedData missing encapsulated content"))?;
    encap_any
        .decode_as::<SpcIndirectDataContent>()
        .map_err(|e| anyhow!("SpcIndirectDataContent: {e}"))
}

/// Decode **`SpcIndirectDataContent`** from the **first** embedded PKCS#7 (same as **`pkcs7_index`** **`0`**).
///
/// See [`parse_pe_pkcs7_spc_indirect_data_at`] for multi-signed PEs.
pub fn parse_pe_pkcs7_spc_indirect_data(pe_image: &[u8]) -> Result<SpcIndirectDataContent> {
    parse_pe_pkcs7_spc_indirect_data_at(pe_image, 0)
}

/// Clone **`template.data`** (including **`SpcPeImageData`** bits) and replace **`messageDigest.digest`** with **`new_digest`**.
///
/// **`digest_algorithm`** is copied from the template; **`new_digest`** must match the template digest **octet length**
/// (Authenticode PE uses 20 / 32 / 48 / 64 bytes for SHA-1 / SHA-256 / SHA-384 / SHA-512).
pub fn spc_indirect_data_replace_message_digest(
    template: &SpcIndirectDataContent,
    new_digest: &[u8],
) -> Result<SpcIndirectDataContent> {
    let old_len = template.message_digest.digest.as_bytes().len();
    if new_digest.len() != old_len {
        return Err(anyhow!(
            "digest length {} does not match template Authenticode digest field ({old_len} octets)",
            new_digest.len(),
        ));
    }
    let digest =
        OctetString::new(new_digest.to_vec()).map_err(|e| anyhow!("digest OCTET STRING: {e}"))?;
    Ok(SpcIndirectDataContent {
        data: template.data.clone(),
        message_digest: DigestInfo {
            digest_algorithm: template.message_digest.digest_algorithm.clone(),
            digest,
        },
    })
}

/// DER-encode **`SpcIndirectDataContent`** (what CMS **`eContent`** carries for **`SPC_INDIRECT_DATA_OBJID`**).
pub fn encode_spc_indirect_data_der(indirect: &SpcIndirectDataContent) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    indirect
        .encode_to_vec(&mut out)
        .map_err(|e| anyhow!("encode SpcIndirectDataContent: {e}"))?;
    Ok(out)
}

/// Digest **`SignedData.encapContentInfo.eContent`** octets using **`digest_alg_oid`** (**`SignerInfo.digestAlgorithm.oid`**).
///
/// Matches RustCrypto **`cms`** **`SignerInfoBuilder`** (**RFC 5652** §5.4): hash only **`eContent` [`Any::value`]**
/// (no outer tag/length).
pub fn cms_digest_encapsulated_econtent_bytes(
    digest_alg_oid: &ObjectIdentifier,
    econtent: &Any,
) -> Result<Vec<u8>> {
    let payload = econtent.value();
    if digest_alg_oid == &DIGEST_OID_SHA256 {
        return Ok(sha2::Sha256::digest(payload).to_vec());
    }
    if digest_alg_oid == &DIGEST_OID_SHA1 {
        return Ok(sha1::Sha1::digest(payload).to_vec());
    }
    if digest_alg_oid == &DIGEST_OID_SHA384 {
        return Ok(sha2::Sha384::digest(payload).to_vec());
    }
    if digest_alg_oid == &DIGEST_OID_SHA512 {
        return Ok(sha2::Sha512::digest(payload).to_vec());
    }
    Err(anyhow!(
        "unsupported digest OID for CMS encap hash: {}",
        digest_alg_oid
    ))
}

/// Same as [`cms_digest_encapsulated_econtent_bytes`] using the **first** **`SignerInfo`** digest algorithm.
///
/// Fails when there is no **`SignerInfo`** or **`encapContentInfo.eContent`**.
pub fn cms_digest_encapsulated_econtent_bytes_from_signed_data(sd: &SignedData) -> Result<Vec<u8>> {
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("SignedData has no SignerInfo"))?;
    let encap = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("SignedData missing encapContentInfo eContent"))?;
    cms_digest_encapsulated_econtent_bytes(&si.digest_alg.oid, encap)
}

/// PKCS#9 **`messageDigest`** value (**raw digest octets**) from **`SignerInfo`** authenticated attributes.
pub fn signer_info_pkcs9_message_digest_octets(si: &SignerInfo) -> Result<Vec<u8>> {
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("SignerInfo has no authenticated attributes"))?;
    for attr in attrs.iter() {
        if attr.oid == PKCS9_MESSAGE_DIGEST_OID {
            let any = attr
                .values
                .get(0)
                .ok_or_else(|| anyhow!("messageDigest attribute has empty SET"))?;
            let oct = any
                .decode_as::<OctetString>()
                .map_err(|e| anyhow!("messageDigest attribute OCTET STRING: {e}"))?;
            return Ok(oct.as_bytes().to_vec());
        }
    }
    Err(anyhow!("PKCS#9 messageDigest attribute not found"))
}

/// DER **`SET OF Attribute`** for **`SignerInfo.signedAttrs`** (**inner value only** — **no** **`[0]` IMPLICIT** wrapper).
///
/// **RFC 5652** §5.4: when authenticated attributes are present, signature generation digests this **`SET`**
/// (with PKCS#1 / ECDSA rules layered on top), not the outer **`SignerInfo`** tagging. Exporting these octets
/// supports portable pipelines that must match **`CryptMsgOpenToEncode`** / **`cms::SignerInfoBuilder`** behavior
/// before submitting a digest to **KV `keys/sign`** or Artifact **`:sign`**.
pub fn signer_info_signed_attributes_sequence_der(si: &SignerInfo) -> Result<Vec<u8>> {
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow!("SignerInfo has no authenticated attributes"))?;
    let mut out = Vec::new();
    attrs
        .encode_to_vec(&mut out)
        .map_err(|e| anyhow!("encode authenticated attributes SET OF Attribute: {e}"))?;
    Ok(out)
}

/// SHA-256 (**32 octets**) over **[`signer_info_signed_attributes_sequence_der`**].
///
/// This is the **raw prehash** Azure Key Vault **`keys/sign`** expects in the JSON **`value`** field for **`RS256`**
/// (base64 of these **32** octets; the service applies PKCS#1 v1.5 **DigestInfo** and returns **`encryptedDigest`**-sized
/// signature octets for [`signer_info_clone_with_signature_octets`]). The same prehash verifies with
/// **`rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::verify_prehash`** against an embedded end-entity **RSA** certificate
/// on the **tiny32** / **tiny64** fixtures (**`rsa_pkcs1v15_signed_attrs_verify`** tests). **`SignerSignEx3`** / **`CryptMsg`**
/// use the same §5.4 **SET** digest for RSA PKCS#1 v1.5 **SHA-256** Authenticode; **ECDSA** paths use different rules.
pub fn signer_info_sha256_digest_over_signed_attrs(si: &SignerInfo) -> Result<Vec<u8>> {
    let der = signer_info_signed_attributes_sequence_der(si)?;
    Ok(sha2::Sha256::digest(&der).to_vec())
}

/// Raw **SHA-256** (**32** octets) for **`SignerInfo`** at **`signer_index`** in **`sd.signer_infos`** — same contract as [`signer_info_sha256_digest_over_signed_attrs`].
///
/// Requires **`SignerInfo.digestAlgorithm`** **SHA-256** (**`id-sha256`**) and authenticated **`signedAttrs`**. Use **`signer_index`** **`0`** for the primary Authenticode signer when **`SignedData`** carries multiple **`SignerInfo`** rows.
pub fn signed_data_rsa_sha256_signer_prehash_digest(
    sd: &SignedData,
    signer_index: usize,
) -> Result<Vec<u8>> {
    const SHA256_DIGEST_OID_STR: &str = "2.16.840.1.101.3.4.2.1";
    let signers = sd.signer_infos.0.as_slice();
    let si = signers.get(signer_index).ok_or_else(|| {
        anyhow!(
            "SignerInfo index {} out of range (len {})",
            signer_index,
            signers.len()
        )
    })?;
    if si.digest_alg.oid.to_string() != SHA256_DIGEST_OID_STR {
        anyhow::bail!(
            "SignerInfo.digestAlgorithm must be SHA-256 ({SHA256_DIGEST_OID_STR}) for RS256 prehash; got {}",
            si.digest_alg.oid
        );
    }
    signer_info_sha256_digest_over_signed_attrs(si).with_context(|| {
        format!(
            "authenticated-attribute SET hash (SignerInfo index {signer_index}) — need signedAttrs"
        )
    })
}

/// Clone **`si`** and set **`signedAttrs`** (**replace** authenticated-attribute **`SET`** wholesale).
pub fn signer_info_clone_with_signed_attrs(
    si: &SignerInfo,
    signed_attrs: SignedAttributes,
) -> SignerInfo {
    let mut out = si.clone();
    out.signed_attrs = Some(signed_attrs);
    out
}

/// Clone **`si`** and replace **`encryptedDigest`** (**`signature`** **`OCTET STRING`**) with **`encrypted_digest`** octets from **`KV keys/sign`**, Artifact **`:sign`**, or local PKCS#1 / ECDSA output.
pub fn signer_info_clone_with_signature_octets(
    si: &SignerInfo,
    encrypted_digest: &[u8],
) -> Result<SignerInfo> {
    let mut out = si.clone();
    out.signature = SignatureValue::new(encrypted_digest.to_vec())
        .map_err(|e| anyhow!("SignerInfo.signature OCTET STRING: {e}"))?;
    Ok(out)
}

fn pkcs9_message_digest_attribute(new_digest: &[u8]) -> Result<Attribute> {
    let md_der = OctetStringRef::new(new_digest)
        .map_err(|e| anyhow!("messageDigest OCTET STRING ref: {e}"))?;
    let val = Any::new(Tag::OctetString, md_der.as_bytes())
        .map_err(|e| anyhow!("PKCS#9 messageDigest AttributeValue ANY: {e}"))?;
    let mut values = SetOfVec::new();
    values
        .insert(val)
        .map_err(|e| anyhow!("SET OF AttributeValue insert: {e}"))?;
    Ok(Attribute {
        oid: PKCS9_MESSAGE_DIGEST_OID,
        values,
    })
}

fn pkcs9_content_type_attribute(content_type: ObjectIdentifier) -> Result<Attribute> {
    let oid_der = content_type
        .to_der()
        .map_err(|e| anyhow!("contentType OID DER: {e}"))?;
    let mut rd = SliceReader::new(oid_der.as_slice())
        .map_err(|e| anyhow!("contentType OID DER reader: {e}"))?;
    let val = Any::decode(&mut rd).map_err(|e| anyhow!("contentType AttributeValue ANY: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after contentType OID DER: {e}"))?;
    let mut values = SetOfVec::new();
    values
        .insert(val)
        .map_err(|e| anyhow!("SET OF AttributeValue insert: {e}"))?;
    Ok(Attribute {
        oid: PKCS9_CONTENT_TYPE_OID,
        values,
    })
}

fn signed_attributes_der(attrs: &SignedAttributes) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    attrs
        .encode_to_vec(&mut out)
        .map_err(|e| anyhow!("encode authenticated attributes SET OF Attribute: {e}"))?;
    Ok(out)
}

fn authenticode_signed_attrs(
    indirect: &SpcIndirectDataContent,
    digest_algorithm: AuthenticodeSigningDigest,
) -> Result<SignedAttributes> {
    let indirect_der = encode_spc_indirect_data_der(indirect)?;
    let mut rd = SliceReader::new(indirect_der.as_slice())
        .map_err(|e| anyhow!("indirect DER reader: {e}"))?;
    let econtent = Any::decode(&mut rd).map_err(|e| anyhow!("SpcIndirectData as CMS Any: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after SpcIndirectDataContent DER: {e}"))?;
    let econtent_digest = cms_digest_encapsulated_econtent_bytes(
        &digest_algorithm.digest_algorithm().oid,
        &econtent,
    )?;
    SetOfVec::try_from(vec![
        pkcs9_content_type_attribute(authenticode::SPC_INDIRECT_DATA_OBJID)?,
        pkcs9_message_digest_attribute(&econtent_digest)?,
    ])
    .map_err(|e| anyhow!("SignedAttributes SET OF Attribute canonicalization: {e}"))
}

/// Clone authenticated **`SET OF Attribute`** and replace PKCS#9 **`messageDigest`** (**[`PKCS9_MESSAGE_DIGEST_OID`]**) with **`new_message_digest`**.
///
/// **`SET`** element ordering is re-canonicalized via **`SetOfVec::try_from`** (DER ordering). Encoding matches RustCrypto **`cms`** **`create_message_digest_attribute`** (**`builder`** feature; **RFC 5652** §11.2).
///
/// **`SignerInfo.encryptedDigest`** remains invalid until the key signs the updated authenticated-attribute **`SET`** (**RFC 5652** §5.4).
pub fn signed_attributes_replace_pkcs9_message_digest(
    attrs: &SignedAttributes,
    new_message_digest: &[u8],
) -> Result<SignedAttributes> {
    let mut found = false;
    let mut out = Vec::with_capacity(attrs.len());
    for attr in attrs.iter() {
        if attr.oid == PKCS9_MESSAGE_DIGEST_OID {
            found = true;
            out.push(pkcs9_message_digest_attribute(new_message_digest)?);
        } else {
            out.push(attr.clone());
        }
    }
    if !found {
        return Err(anyhow!(
            "authenticated attributes contain no PKCS#9 messageDigest ({})",
            PKCS9_MESSAGE_DIGEST_OID
        ));
    }
    SetOfVec::try_from(out)
        .map_err(|e| anyhow!("SignedAttributes SET OF Attribute canonicalization: {e}"))
}

/// Replace **`SignedData.encapContentInfo.eContent`** with **`indirect`** while keeping **`digestAlgorithms`**, **`certificates`**, **`crls`**, and **`signerInfos`** unchanged.
///
/// **`template`** must already use **`eContentType`** **`authenticode::SPC_INDIRECT_DATA_OBJID`** (Authenticode **`SpcIndirectDataContent`**).
///
/// **Cryptographic note:** Swapping the indirect payload **invalidates** the existing **`SignerInfo`** signature (PKCS#9 **`messageDigest`** / **`contentType`** attrs no longer match **`encryptedDigest`**). **`cms_digest_encapsulated_econtent_bytes_from_signed_data`** then disagrees with **`signer_info_pkcs9_message_digest_octets`** until authenticated attributes are rebuilt (**[`signed_attributes_replace_pkcs9_message_digest`]**) — regression **`replace_encap_only_leaves_pkcs9_message_digest_stale_vs_fresh_econtent_hash`**. Use for **tests**, **`verify-pe`** negative cases, or pipelines that also rebuild **`SignerInfo`** and signature octets (remote signing).
pub fn signed_data_replace_encapsulated_spc_indirect(
    template: &SignedData,
    indirect: &SpcIndirectDataContent,
) -> Result<SignedData> {
    if template.encap_content_info.econtent_type != authenticode::SPC_INDIRECT_DATA_OBJID {
        return Err(anyhow!(
            "SignedData encap content type is not SPC_INDIRECT_DATA (got {})",
            template.encap_content_info.econtent_type
        ));
    }
    let der = encode_spc_indirect_data_der(indirect)?;
    let mut rd =
        SliceReader::new(der.as_slice()).map_err(|e| anyhow!("indirect DER reader: {e}"))?;
    let econtent = Any::decode(&mut rd).map_err(|e| anyhow!("SpcIndirectData as CMS Any: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after SpcIndirectDataContent DER: {e}"))?;
    let mut out = template.clone();
    out.encap_content_info.econtent = Some(econtent);
    Ok(out)
}

/// Replace the **`SignerInfo`** at **`index`** in **`SignedData.signer_infos`** (**RFC 5652** **`SignerInfos`** **`SET`**).
///
/// The signer list is re-canonicalized via **`SetOfVec::try_from`** (DER **`SET OF`** ordering). Typical callers build **`signer_info`** with
/// [`signer_info_clone_with_signed_attrs`] / [`signer_info_clone_with_signature_octets`] after refreshing PKCS#9 attributes and obtaining **`encryptedDigest`** from a remote signer.
pub fn signed_data_replace_signer_info_at(
    sd: &SignedData,
    index: usize,
    signer_info: SignerInfo,
) -> Result<SignedData> {
    let signers = sd.signer_infos.0.as_slice();
    if index >= signers.len() {
        return Err(anyhow!(
            "SignerInfo index {} out of range (len {})",
            index,
            signers.len()
        ));
    }
    let mut vec: Vec<SignerInfo> = signers.to_vec();
    vec[index] = signer_info;
    let signer_infos = SignerInfos(
        SetOfVec::try_from(vec).map_err(|e| anyhow!("SignerInfos SET canonicalization: {e}"))?,
    );
    let mut out = sd.clone();
    out.signer_infos = signer_infos;
    Ok(out)
}

/// Replace the first **`SignerInfo`** (Authenticode primary signature slot).
pub fn signed_data_replace_first_signer_info(
    sd: &SignedData,
    signer_info: SignerInfo,
) -> Result<SignedData> {
    signed_data_replace_signer_info_at(sd, 0, signer_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticode::SpcIndirectDataContent;
    use cms::signed_data::SignedAttributes;
    use der::Decode;

    #[test]
    fn signed_data_oid_matches_rfc_display_form() {
        assert!(PKCS7_ID_SIGNED_DATA_OID.ends_with(".7.2"));
        assert!(PKCS7_ID_DATA_OID.ends_with(".7.1"));
    }

    fn assert_cms_encap_digest_matches_pkcs9(pe_bytes: &[u8]) {
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
        let computed =
            cms_digest_encapsulated_econtent_bytes_from_signed_data(&sd).expect("encap digest");
        let embedded = signer_info_pkcs9_message_digest_octets(si).expect("pkcs9 md");
        assert_eq!(
            computed, embedded,
            "CMS eContent hash must match PKCS#9 messageDigest attribute"
        );
    }

    #[test]
    fn cms_encap_digest_matches_pkcs9_message_digest_on_tiny32_fixture() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert_cms_encap_digest_matches_pkcs9(pe_bytes);
    }

    #[test]
    fn cms_encap_digest_matches_pkcs9_message_digest_on_tiny64_fixture() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        assert_cms_encap_digest_matches_pkcs9(pe_bytes);
    }

    #[test]
    fn signer_info_signed_attrs_sequence_der_round_trips_on_tiny_fixtures() {
        for pe_bytes in [
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice(),
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi")
                .as_slice(),
        ] {
            let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
            let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
            let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
            let der = signer_info_signed_attributes_sequence_der(si).expect("attrs DER");
            assert_eq!(
                der.first().copied(),
                Some(der::Tag::Set.into()),
                "authenticated attributes encode as ASN.1 SET"
            );
            let mut rd = SliceReader::new(der.as_slice()).expect("reader");
            let back = SignedAttributes::decode(&mut rd).expect("decode SignedAttributes");
            rd.finish(())
                .expect("no trailing bytes after SET OF Attribute");
            assert_eq!(
                si.signed_attrs.as_ref().expect("signed_attrs"),
                &back,
                "SET OF Attribute DER round-trip"
            );
        }
    }

    #[test]
    fn replace_pkcs9_message_digest_realigns_with_encap_hash_after_indirect_swap() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let mut flipped_digest = indirect.message_digest.digest.as_bytes().to_vec();
        flipped_digest[0] ^= 0xff;
        let flipped =
            spc_indirect_data_replace_message_digest(&indirect, &flipped_digest).expect("flip");
        let sd_new =
            signed_data_replace_encapsulated_spc_indirect(&sd, &flipped).expect("replace encap");
        let fresh =
            cms_digest_encapsulated_econtent_bytes_from_signed_data(&sd_new).expect("encap digest");

        let si = sd_new
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo");
        let h_before =
            signer_info_sha256_digest_over_signed_attrs(si).expect("sha256 over signedAttrs");
        let attrs = si.signed_attrs.as_ref().expect("signed_attrs");
        let fixed_attrs = signed_attributes_replace_pkcs9_message_digest(attrs, &fresh)
            .expect("replace pkcs9 md");

        let mut si_fixed = si.clone();
        si_fixed.signed_attrs = Some(fixed_attrs);
        assert_eq!(
            signer_info_pkcs9_message_digest_octets(&si_fixed).expect("pkcs9"),
            fresh,
            "PKCS#9 messageDigest must match fresh CMS eContent hash after attr rewrite"
        );
        let h_after =
            signer_info_sha256_digest_over_signed_attrs(&si_fixed).expect("sha256 after pkcs9 fix");
        assert_ne!(
            h_before, h_after,
            "authenticated-attribute SET hash must change when PKCS#9 messageDigest is refreshed"
        );
    }

    #[test]
    fn signer_info_sha256_over_signed_attrs_stable_when_pkcs9_replaced_with_same_octets() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
        let md = signer_info_pkcs9_message_digest_octets(si).expect("pkcs9 md");
        let h0 = signer_info_sha256_digest_over_signed_attrs(si).expect("h0");
        let rebuilt = signed_attributes_replace_pkcs9_message_digest(
            si.signed_attrs.as_ref().expect("signed_attrs"),
            &md,
        )
        .expect("noop pkcs9 rebuild");
        let mut si2 = si.clone();
        si2.signed_attrs = Some(rebuilt);
        let h1 = signer_info_sha256_digest_over_signed_attrs(&si2).expect("h1");
        assert_eq!(
            h0, h1,
            "replacing PKCS#9 digest with identical octets must preserve SET hash"
        );
    }

    #[test]
    fn signer_info_clone_with_signed_attrs_and_signature_are_identity_on_fixture() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
        let attrs = si.signed_attrs.clone().expect("signed_attrs");
        let si_attrs = signer_info_clone_with_signed_attrs(si, attrs);
        assert_eq!(*si, si_attrs);
        let sig = si.signature.as_bytes();
        let si_sig = signer_info_clone_with_signature_octets(si, sig).expect("signature clone");
        assert_eq!(*si, si_sig);
    }

    #[test]
    fn signed_data_replace_first_signer_info_identity_round_trips_pkcs7() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si0 = sd
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo")
            .clone();
        let sd2 = signed_data_replace_first_signer_info(&sd, si0).expect("splice");
        assert_eq!(sd, sd2);
        let out = encode_pkcs7_content_info_signed_data_der(&sd2).expect("encode");
        let sd3 = parse_pkcs7_signed_data_der(&out).expect("re-parse");
        assert_eq!(sd, sd3);
    }

    #[test]
    fn signed_data_replace_signer_info_at_errors_when_index_out_of_range() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si0 = sd
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo")
            .clone();
        assert!(signed_data_replace_signer_info_at(&sd, 1, si0.clone()).is_err());
    }

    #[test]
    fn signed_data_rsa_sha256_signer_prehash_digest_matches_direct_signer_call_on_tiny32() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
        let direct = signer_info_sha256_digest_over_signed_attrs(si).expect("direct");
        let via_sd = signed_data_rsa_sha256_signer_prehash_digest(&sd, 0).expect("helper");
        assert_eq!(direct, via_sd);
    }

    #[test]
    fn signed_data_rsa_sha256_signer_prehash_digest_errors_when_signer_index_out_of_range() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        assert!(signed_data_rsa_sha256_signer_prehash_digest(&sd, 1).is_err());
    }

    // Encap-only swap: PKCS#9 messageDigest in SignerInfo stays stale until attrs + signature rebuild.
    #[test]
    fn replace_encap_only_leaves_pkcs9_message_digest_stale_vs_fresh_econtent_hash() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let mut flipped_digest = indirect.message_digest.digest.as_bytes().to_vec();
        flipped_digest[0] ^= 0xff;
        let flipped =
            spc_indirect_data_replace_message_digest(&indirect, &flipped_digest).expect("flip");
        let sd_new =
            signed_data_replace_encapsulated_spc_indirect(&sd, &flipped).expect("replace encap");

        let si = sd_new
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo");
        let fresh_encap_digest =
            cms_digest_encapsulated_econtent_bytes_from_signed_data(&sd_new).expect("encap hash");
        let stale_pkcs9 = signer_info_pkcs9_message_digest_octets(si).expect("pkcs9");
        assert_ne!(
            fresh_encap_digest, stale_pkcs9,
            "SignerInfo still carries old PKCS#9 messageDigest after encap-only swap"
        );
    }

    fn assert_spc_round_trip_and_digest_matches_sip(pe_bytes: &[u8]) {
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("parse indirect");

        let re_encoded = encode_spc_indirect_data_der(&indirect).expect("encode");
        let again = SpcIndirectDataContent::from_der(re_encoded.as_slice()).expect("re-decode");
        assert_eq!(indirect, again);

        let digest = crate::pe_digest::pe_authenticode_digest(
            pe_bytes,
            crate::pe_digest::PeAuthenticodeHashKind::Sha256,
        )
        .expect("PE digest");
        assert_eq!(
            indirect.message_digest.digest.as_bytes(),
            digest.as_slice(),
            "embedded DigestInfo must match Rust SIP PE digest"
        );
    }

    #[test]
    fn spc_indirect_data_der_round_trips_from_upstream_tiny32_signed_efi() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert_spc_round_trip_and_digest_matches_sip(pe_bytes);
    }

    #[test]
    fn spc_indirect_data_der_round_trips_from_upstream_tiny64_signed_efi() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        assert_spc_round_trip_and_digest_matches_sip(pe_bytes);
    }

    #[test]
    fn parse_pe_pkcs7_spc_indirect_at_index_zero_matches_helper() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let a = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("parse");
        let b = parse_pe_pkcs7_spc_indirect_data_at(pe_bytes, 0).expect("parse at 0");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_pe_pkcs7_spc_indirect_at_index_one_errors_on_single_signed_fixture() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert!(parse_pe_pkcs7_spc_indirect_data_at(pe_bytes, 1).is_err());
    }

    #[test]
    fn signed_data_to_der_round_trips() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let der = sd.to_der().expect("to_der");
        let again = SignedData::from_der(der.as_slice()).expect("from_der");
        assert_eq!(sd, again);
    }

    #[test]
    fn content_info_encode_decode_round_trip_on_tiny32_pkcs7() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let normalized = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(&pkcs7);
        let bytes = normalized.as_ref();
        let mut r = SliceReader::new(bytes).expect("reader");
        let ci = ContentInfo::decode(&mut r).expect("ContentInfo");
        let sd = ci
            .content
            .decode_as::<SignedData>()
            .expect("inner SignedData");
        let out = encode_pkcs7_content_info_signed_data_der(&sd).expect("encode");
        let mut r2 = SliceReader::new(out.as_slice()).expect("reader2");
        let ci2 = ContentInfo::decode(&mut r2).expect("ContentInfo2");
        let sd2 = ci2.content.decode_as::<SignedData>().expect("SignedData2");
        assert_eq!(sd, sd2);
    }

    #[test]
    fn signed_data_replace_encap_round_trips_identical_indirect_through_pkcs7() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let sd2 =
            signed_data_replace_encapsulated_spc_indirect(&sd, &indirect).expect("replace encap");
        assert_eq!(sd, sd2);
        let out = encode_pkcs7_content_info_signed_data_der(&sd2).expect("encode outer");
        let sd3 = parse_pkcs7_signed_data_der(&out).expect("re-parse");
        assert_eq!(sd, sd3);
    }

    #[test]
    fn signed_data_replace_encap_preserves_flipped_digest_through_pkcs7_reencode() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let mut flipped_digest = indirect.message_digest.digest.as_bytes().to_vec();
        flipped_digest[0] ^= 0xff;
        let flipped =
            spc_indirect_data_replace_message_digest(&indirect, &flipped_digest).expect("flip");
        let sd_m = signed_data_replace_encapsulated_spc_indirect(&sd, &flipped).expect("mut encap");
        let pkcs7_out = encode_pkcs7_content_info_signed_data_der(&sd_m).expect("encode");
        let sd_r = parse_pkcs7_signed_data_der(&pkcs7_out).expect("parse mutated");
        let encap = sd_r.encap_content_info.econtent.as_ref().expect("econtent");
        let got = encap
            .decode_as::<SpcIndirectDataContent>()
            .expect("indirect decode");
        assert_eq!(got, flipped);
    }

    #[test]
    fn replace_message_digest_preserves_pe_image_blob_and_round_trips() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("parse");
        let digest = crate::pe_digest::pe_authenticode_digest(
            pe_bytes,
            crate::pe_digest::PeAuthenticodeHashKind::Sha256,
        )
        .expect("sip digest");

        let replaced = spc_indirect_data_replace_message_digest(&indirect, digest.as_slice())
            .expect("replace");
        assert_eq!(replaced, indirect);

        let wrong_len = vec![0u8; 31];
        assert!(spc_indirect_data_replace_message_digest(&indirect, &wrong_len).is_err());

        let mut flipped = digest.clone();
        flipped[0] ^= 0xff;
        let patched = spc_indirect_data_replace_message_digest(&indirect, &flipped).expect("patch");
        assert_ne!(patched, indirect);
        assert_eq!(patched.message_digest.digest.as_bytes(), flipped.as_slice());
        assert_eq!(patched.data, indirect.data);
        encode_spc_indirect_data_der(&patched).expect("encode patched");
    }

    /// PKCS#1 v1.5 **RS256** prehash parity: [`super::signer_info_sha256_digest_over_signed_attrs`] matches
    /// **`SignerInfo.signature`** when verified with the embedded **RSA** signer certificate (same contract as Azure KV **`keys/sign`** digest input).
    mod rsa_pkcs1v15_signed_attrs_verify {
        use super::parse_pkcs7_signed_data_der;
        use super::signed_data_spc_indirect_message_digest_octets;
        use super::verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature;
        use crate::verify_pe::pe_nth_pkcs7_signed_data_der;
        use der::asn1::ObjectIdentifier;

        const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

        fn assert_rs256_prehash_verifies_on_fixture(pe_bytes: &[u8]) {
            let pkcs7 = pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
            let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
            let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
            assert_eq!(
                si.digest_alg.oid, SHA256_OID,
                "fixture must use SHA-256 SignerInfo digest for RS256 prehash test"
            );
            let indirect = signed_data_spc_indirect_message_digest_octets(&sd).expect("indirect");
            verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
                &sd,
                0,
                indirect.as_slice(),
            )
            .expect("RS256-style prehash verifies against embedded CMS signature");
        }

        #[test]
        fn tiny32_embedded_signer_rs256_prehash_verifies() {
            assert_rs256_prehash_verifies_on_fixture(include_bytes!(
                "../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi"
            ));
        }

        #[test]
        fn tiny64_embedded_signer_rs256_prehash_verifies() {
            assert_rs256_prehash_verifies_on_fixture(include_bytes!(
                "../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi"
            ));
        }
    }
}
