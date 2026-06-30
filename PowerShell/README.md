# Devolutions.Psign PowerShell Module

Cross-platform Authenticode signing and verification for PowerShell 7.4+, backed by [psign](https://github.com/Devolutions/psign).

## Installation

```powershell
# From the repository (development)
Import-Module ./PowerShell/Devolutions.Psign/Devolutions.Psign.psd1

# Build from source
./PowerShell/build.ps1
```

## Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `Get-PsignSignature` | Inspect Authenticode signatures (PE, scripts, packages) |
| `Set-PsignSignature` | Sign files using local keys, PFX, cert store, Azure KV, or Trusted Signing |
| `Test-PsignModule` | Validate a module against AllSigned/RemoteSigned execution policy |
| `Protect-PsignModule` | Batch-sign all policy-checked files in a module |
| `Unprotect-PsignSignature` | Strip script signature blocks and clear PE signatures |

`Set-PsignSignature -AppendSignature` appends PE Authenticode signatures; without it, PE signing replaces existing signatures. Use `-SkipSigned` to leave PE/WinMD files with an intact embedded Authenticode signature unchanged. Signature inspection exposes decoded CMS details through the `SignedCms` property when PKCS#7 bytes are available.

## Quick Start

### Verify a file

```powershell
Get-PsignSignature ./signed-script.ps1

# Detailed output
Get-PsignSignature ./app.exe | Format-List
```

### Sign a script

```powershell
# With a PFX file
Set-PsignSignature ./script.ps1 -PfxPath ./cert.pfx -Password (Read-Host -AsSecureString)

# With cert + key files
Set-PsignSignature ./script.ps1 -CertificatePath ./cert.pem -PrivateKeyPath ./key.pem

# With the portable cert store
Set-PsignSignature ./script.ps1 -Thumbprint ABC123DEF456...
```

### Module compliance

```powershell
# Check if a module would pass AllSigned policy
Test-PsignModule ./MyModule -Policy AllSigned

# Sign all module files
Protect-PsignModule ./MyModule -PfxPath ./cert.pfx

# Verify after signing
Test-PsignModule ./MyModule -Policy AllSigned

# Pipeline: test → sign if needed
$result = Test-PsignModule ./MyModule
if (-not $result.Valid) {
    $result | Protect-PsignModule -PfxPath ./cert.pfx
}
```

### Strip signatures

```powershell
Unprotect-PsignSignature ./script.ps1
Get-ChildItem ./src -Recurse -Include *.ps1,*.psm1 | Unprotect-PsignSignature
```

## Certificate Store (`pcert:\`)

The module provides a `pcert:\` PowerShell drive mapped to `~/.psign/cert-store/`:

```powershell
# List certificates
Get-ChildItem pcert:\CurrentUser\MY

# Import a certificate
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("./cert.pfx", "password")
New-Item pcert:\CurrentUser\MY -Value $cert

# Use for signing
Set-PsignSignature ./script.ps1 -Thumbprint (Get-ChildItem pcert:\CurrentUser\MY)[0].Thumbprint

# Create a custom drive
New-PSDrive -Name certs -PSProvider PortableCertStore -Root ./project-certs
```

## Trust Model

By default, `Get-PsignSignature`, `Test-PsignFileCatalog`, and `Test-PsignModule` automatically download and cache the Microsoft AuthRoot CAB for trust evaluation when no explicit trust anchors are supplied. The cache lives at `~/.psign/authroot/` and is refreshed when it is older than 7 days. Set `PSIGN_AUTHROOT_MAX_AGE_DAYS`, `PSIGN_AUTHROOT_CACHE_DIR`, or `PSIGN_AUTHROOT_URL` to override the stale window, cache directory, or source URL.

```powershell
# Disable auto-trust
$env:PSIGN_NO_AUTO_TRUST = '1'

# Explicit trust anchors
Get-PsignSignature ./app.exe -TrustedCertificatePath ./ca.cer
Get-PsignSignature ./app.exe -AnchorDirectory ./trusted-roots/
Get-PsignSignature ./app.exe -AuthRootCab ./authroot.cab
```

## Signing Sources

| Source | Parameters |
|--------|-----------|
| In-memory certificate | `-Certificate <X509Certificate2>` |
| File-backed key pair | `-CertificatePath` + `-PrivateKeyPath` |
| PFX/PKCS#12 | `-PfxPath` [`-Password`] |
| Portable cert store | `-Thumbprint` [`-StoreName`] [`-MachineStore`] |
| Azure Key Vault | `-AzureKeyVaultUrl` `-AzureKeyVaultCertificate` + auth params |
| Azure Trusted Signing | `-ArtifactSigningEndpoint` `-ArtifactSigningAccountName` + auth params |

## Help

```powershell
Get-Help about_Devolutions.Psign
Get-Help Get-PsignSignature -Full
Get-Help Set-PsignSignature -Full
```

## Requirements

- PowerShell 7.4 or later
- Works on Windows, Linux, and macOS
- No dependency on Windows trust stack or `signtool.exe`
