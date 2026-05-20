//! Portable Authenticode **trust** verification (CMS signature + certificate chain + anchors).
//!
//! ## Crate split (see [`docs/authenticode-trust-stack.md`](../../docs/authenticode-trust-stack.md))
//!
//! - **`cms` / `der`**: PKCS#7 `ContentInfo`, `SignedData`, `SignerInfo`, authenticated attributes.
//! - **`authenticode` / [`psign_sip_digest`]**: PE certificate table iteration; PE image digest recomputation.
//! - **`picky` / `picky-asn1-x509`**: X.509 parsing, TBSCertificate signature verification, extension interpretation.

pub mod anchor;
pub mod authroot_cab;
pub mod authroot_ctl;
pub mod chain;
pub mod inspect;
pub mod online;
pub mod policy;
pub mod rfc3161_extract;
pub mod trust_pkcs7;
pub mod trust_verify_cab;
pub mod trust_verify_catalog;
pub mod trust_verify_detached;
pub mod trust_verify_esd;
pub mod trust_verify_msi;
pub mod trust_verify_pe;
pub mod verification_instant;

pub use inspect::{
    InspectAuthenticodeDigest, InspectPeEntry, InspectPeFileReport, InspectPkcs7Report,
    InspectSigner, TimestampHint, inspect_authenticode_pkcs7_der, inspect_pe_authenticode,
};
pub use policy::AuthenticodeTrustPolicy;
pub use trust_verify_cab::trust_verify_cab_bytes;
pub use trust_verify_catalog::trust_verify_catalog_bytes;
pub use trust_verify_detached::trust_verify_detached_bytes;
pub use trust_verify_esd::trust_verify_wim_esd_path;
pub use trust_verify_msi::trust_verify_msi_bytes;
pub use trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material, pe_first_pkcs7_terminal_root,
    pkcs7_signed_data_der_terminal_root, trust_verify_pe_bytes,
};
pub use verification_instant::parse_verification_date_ymd;
