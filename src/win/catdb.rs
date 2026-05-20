use crate::CommandOutput;
use crate::cli::{CatdbArgs, GlobalOpts};
use crate::win::verify_catalog_resolve::{SUBSYSTEM_DEFAULT_CATALOG, SUBSYSTEM_SYSTEM_COMPONENT};
use anyhow::{Result, anyhow};
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use uuid::Uuid;
use windows::Win32::Security::Cryptography::Catalog::{
    CRYPTCAT_ADDCATALOG_HARDLINK, CRYPTCAT_ADDCATALOG_NONE, CryptCATAdminAcquireContext2,
    CryptCATAdminAddCatalog, CryptCATAdminReleaseContext, CryptCATAdminRemoveCatalog,
};
use windows::core::GUID;

fn to_wide_path(path: &std::path::Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(once(0)).collect()
}

fn basename_wide(path: &std::path::Path) -> Vec<u16> {
    path.file_name()
        .unwrap_or_default()
        .encode_wide()
        .chain(once(0))
        .collect()
}

fn utf16_literal(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

pub fn catdb_command(args: &CatdbArgs, _global: &GlobalOpts) -> Result<CommandOutput> {
    if args.catalogs.is_empty() {
        return Err(anyhow!("catdb requires at least one catalog file"));
    }
    if args.default_database && args.database_guid.is_some() {
        return Err(anyhow!(
            "choose either --default-database (/d) or --database-guid (/g)"
        ));
    }

    let subsystem: Option<GUID> = if let Some(raw) = &args.database_guid {
        let u = Uuid::parse_str(raw).map_err(|e| anyhow!("invalid database GUID '{raw}': {e}"))?;
        Some(GUID::from_u128(u.as_u128()))
    } else if args.default_database {
        Some(SUBSYSTEM_DEFAULT_CATALOG)
    } else {
        Some(SUBSYSTEM_SYSTEM_COMPONENT)
    };

    let mut hcatadmin: isize = 0;
    let alg = utf16_literal("SHA256");
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

    let mut report = String::new();
    for cat in &args.catalogs {
        let wide_path = to_wide_path(cat);
        let wide_base = basename_wide(cat);
        if args.remove {
            unsafe {
                CryptCATAdminRemoveCatalog(hcatadmin, windows::core::PCWSTR(wide_path.as_ptr()), 0)
            }
            .map_err(|e| {
                anyhow!(
                    "CryptCATAdminRemoveCatalog failed for {}: {e}",
                    cat.display()
                )
            })?;
            report.push_str(&format!(
                "Removed {} from catalog database\n",
                cat.display()
            ));
        } else {
            let flags = if args.unique_name {
                CRYPTCAT_ADDCATALOG_HARDLINK
            } else {
                CRYPTCAT_ADDCATALOG_NONE
            };
            let _ctx = unsafe {
                CryptCATAdminAddCatalog(
                    hcatadmin,
                    windows::core::PCWSTR(wide_path.as_ptr()),
                    windows::core::PCWSTR(wide_base.as_ptr()),
                    flags,
                )
            };
            if _ctx == 0 {
                unsafe {
                    let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
                }
                return Err(anyhow!(
                    "CryptCATAdminAddCatalog failed for {}",
                    cat.display()
                ));
            }
            report.push_str(&format!("Added {} to catalog database\n", cat.display()));
        }
    }

    unsafe {
        let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
    }

    Ok(CommandOutput::ok(report))
}
