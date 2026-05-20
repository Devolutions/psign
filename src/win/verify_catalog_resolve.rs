//! Resolve a `.cat` file path for a member file using catalog administrator APIs.

use crate::cli::{CatalogHashAlgorithm, CatalogSearchMode};
use anyhow::{Result, anyhow};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::Catalog::CATALOG_INFO;
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::core::GUID;

fn wide_os_str(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn hash_alg_w(h: CatalogHashAlgorithm) -> Vec<u16> {
    match h {
        CatalogHashAlgorithm::Sha1 => wide_os_str(OsStr::new("SHA1")),
        CatalogHashAlgorithm::Sha256 => wide_os_str(OsStr::new("SHA256")),
    }
}

fn wide_to_path(buf: &[u16; 260]) -> std::path::PathBuf {
    let v: Vec<u16> = buf.iter().copied().take_while(|c| *c != 0).collect();
    std::path::PathBuf::from(String::from_utf16_lossy(&v))
}

/// Default catalog database subsystem (`signtool catdb /d`).
pub const SUBSYSTEM_DEFAULT_CATALOG: GUID = GUID::from_u128(0x58957AF9840F42EEA944D801CE599461u128);

/// System component / driver catalog database subsystem (`signtool` implicit default without `/d`).
pub const SUBSYSTEM_SYSTEM_COMPONENT: GUID =
    GUID::from_u128(0xDE351D438E084749A36E7CCCEFC83041u128);

fn subsystem_attempts(
    catalog_search: Option<CatalogSearchMode>,
    catalog_database_guid: Option<&str>,
) -> Result<Vec<Option<GUID>>> {
    if let Some(raw) = catalog_database_guid {
        let u =
            uuid::Uuid::parse_str(raw).map_err(|e| anyhow!("invalid catalog GUID '{raw}': {e}"))?;
        return Ok(vec![Some(GUID::from_u128(u.as_u128()))]);
    }
    Ok(match catalog_search {
        None => vec![],
        Some(CatalogSearchMode::All) => vec![
            None,
            Some(SUBSYSTEM_DEFAULT_CATALOG),
            Some(SUBSYSTEM_SYSTEM_COMPONENT),
        ],
        Some(CatalogSearchMode::DefaultDb) => vec![Some(SUBSYSTEM_DEFAULT_CATALOG)],
        Some(CatalogSearchMode::System) => vec![Some(SUBSYSTEM_SYSTEM_COMPONENT)],
    })
}

pub fn resolve_catalog_for_verify(
    member_path: &std::path::Path,
    catalog_search: Option<CatalogSearchMode>,
    catalog_database_guid: Option<&str>,
    hash_algorithm: CatalogHashAlgorithm,
) -> Result<Option<std::path::PathBuf>> {
    let attempts = subsystem_attempts(catalog_search, catalog_database_guid)?;
    if attempts.is_empty() {
        return Ok(None);
    }

    let file = std::fs::File::open(member_path)?;
    let hfile = HANDLE(file.as_raw_handle() as *mut _);

    for sub in attempts {
        if let Some(path) = resolve_with_subsystem(hfile, sub, hash_algorithm)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn resolve_with_subsystem(
    hfile: HANDLE,
    subsystem: Option<GUID>,
    hash_algorithm: CatalogHashAlgorithm,
) -> Result<Option<std::path::PathBuf>> {
    let mut hcatadmin: isize = 0;
    let alg = hash_alg_w(hash_algorithm);
    let sub_ptr = subsystem.as_ref().map(|g: &GUID| g as *const GUID);
    unsafe {
        CryptCATAdminAcquireContext2(
            &mut hcatadmin,
            sub_ptr,
            windows::core::PCWSTR(alg.as_ptr()),
            None,
            None,
        )
    }
    .map_err(|e| anyhow!("CryptCATAdminAcquireContext2 failed: {e}"))?;

    let mut hash_len = 0u32;
    unsafe { CryptCATAdminCalcHashFromFileHandle2(hcatadmin, hfile, &mut hash_len, None, None) }
        .map_err(|e| anyhow!("CryptCATAdminCalcHashFromFileHandle2(size) failed: {e}"))?;
    let mut hash = vec![0u8; hash_len as usize];
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            hcatadmin,
            hfile,
            &mut hash_len,
            Some(hash.as_mut_ptr()),
            None,
        )
    }
    .map_err(|e| anyhow!("CryptCATAdminCalcHashFromFileHandle2(data) failed: {e}"))?;
    hash.truncate(hash_len as usize);

    let mut prev: isize = 0;
    loop {
        let hcatinfo =
            unsafe { CryptCATAdminEnumCatalogFromHash(hcatadmin, &hash, Some(0), Some(&mut prev)) };
        if hcatinfo == 0 {
            break;
        }
        let mut catinfo = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        let info_ok = unsafe { CryptCATCatalogInfoFromContext(hcatinfo, &mut catinfo, 0).is_ok() };
        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(hcatadmin, hcatinfo, 0);
        }
        if info_ok {
            let path = wide_to_path(&catinfo.wszCatalogFile);
            unsafe {
                let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
            }
            return Ok(Some(path));
        }
    }

    unsafe {
        let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
    }
    Ok(None)
}
