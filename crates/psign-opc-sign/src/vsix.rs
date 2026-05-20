use crate::opc::{PackageSummary, inspect_package_path};
use anyhow::Result;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VsixPackageInfo {
    pub package: PackageSummary,
    pub has_opc_signature: bool,
}

pub fn inspect_vsix_path(path: &Path) -> Result<VsixPackageInfo> {
    let package = inspect_package_path(path)?;
    let has_opc_signature =
        package.has_opc_signature_origin || !package.opc_signature_parts.is_empty();
    Ok(VsixPackageInfo {
        package,
        has_opc_signature,
    })
}
