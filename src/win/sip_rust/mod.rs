//! Experimental **Rust SIP** helpers: PE Authenticode image digest and PKCS#7 indirect-digest consistency.
//!
//! This does **not** replace registered OS CryptSIP DLLs. Signing still uses OS **`SignerSignEx3`** /
//! **`mssign32`** via [`crate::win::sign_core::sign_with_mssign32`]; [`sign_pe`] optionally verifies that the
//! embedded PKCS#7 indirect digest matches a Rust recomputation after signing.
//!
//! Digest algorithms and file-format parsers live in the portable **`psign-sip-digest`** crate (Linux-friendly).
//!
//! ## `mso.dll` (VBA macros) — no Rust digest parity
//!
//! Registry SIP **`{9FA65764-C36F-4319-9737-658A34585BB7}`** maps macro-enabled Office subjects to **`mso.dll`**
//! (**`MsoVBADigSigGetSignedDataMsg`**, **`MsoVBADigSigCreateIndirectData`**, **`MsoVBADigSigVerifyIndirectData`**).
//! Indirect-data layouts distinguish legacy vs agile OID families; the actual project digest is produced via **VBE7.DLL**
//! (**`DllVbeGetHashOfCodeProjectEx`**, **`DllVbeGetHashOfCodeStorageEx`**) over the VBA storage graph. Porting that in pure
//! Rust would duplicate the Office runtime — out of scope. This crate does not load **VBE7**; verification stays on
//! **`WinVerifyTrust`**. See **`docs/windows-signing-components.md`**.

pub use psign_sip_digest::{
    cab_digest, catalog_digest, esd_digest, msi_digest, msix_digest, page_hashes, pe_digest,
    pe_embed, pkcs7, ps_script, timestamp, verify_pe, verify_script_digest_consistency, wsh_script,
};

pub mod sign_cab;
pub mod sign_catalog;
pub mod sign_esd;
pub mod sign_msi;
pub mod sign_msix;
pub mod sign_pe;
pub mod sign_script;
