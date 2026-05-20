# CryptSIPDllGetSignedDataMsg — snapshot from a typical Windows install

Values below come from:

`HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg`

Regenerate locally with:

```powershell
$p = 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg'
Get-ChildItem $p | ForEach-Object {
  $pr = Get-ItemProperty $_.PSPath
  [PSCustomObject]@{ Guid = $_.PSChildName; Dll = $pr.Dll; FuncName = $pr.FuncName }
} | Sort-Object Dll, Guid | Format-Table -AutoSize
```

## Rows (example machine)

| Guid | Dll | FuncName |
|------|-----|----------|
| `0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1` | AppxSip.dll | AppxSipGetSignedDataMsg |
| `0F5F58B3-AADE-4B9A-A434-95742D92ECEB` | AppxSip.dll | AppxBundleSipGetSignedDataMsg |
| `1AD2DCB4-1FC8-42EF-8D9B-1EDFB2F7C75D` | AppxSip.dll | ExtensionsSipGetSignedDataMsg |
| `5598CFF1-68DB-4340-B57F-1CACF88C9A51` | AppxSip.dll | P7xSipGetSignedDataMsg |
| `CF78C6DE-64A2-4799-B506-89ADFF5D16D6` | AppxSip.dll | EappxSipGetSignedDataMsg |
| `D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C` | AppxSip.dll | EappxBundleSipGetSignedDataMsg |
| `9F3053C5-439D-4BF7-8A77-04F0450A1D9F` | EsdSip.dll | EsdSipGetSignature |
| `000C10F1-0000-0000-C000-000000000046` | MSISIP.DLL | MsiSIPGetSignedDataMsg |
| `603BCC1F-4B59-4E08-B724-D2C6297EF351` | pwrshsip.dll | PsGetSignature |
| `06C9E010-38CE-11D4-A2A3-00104BD35090` | wshext.dll | GetSignedDataMsg |
| `1629F04E-2799-4DB5-8FE5-ACE10F17EBAB` | wshext.dll | GetSignedDataMsg |
| `1A610570-38CE-11D4-A2A3-00104BD35090` | wshext.dll | GetSignedDataMsg |
| `9FA65764-C36F-4319-9737-658A34585BB7` | mso.dll | MsoVBADigSigGetSignedDataMsg |
| `18B3C141-AE0D-40F9-9465-E542AFC1ABC7` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |
| `9BA61D3F-E73A-11D0-8CD2-00C04FC295EE` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |
| `C689AAB8-8E78-11D0-8C47-00C04FC295EE` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |
| `C689AAB9-8E78-11D0-8C47-00C04FC295EE` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |
| `C689AABA-8E78-11D0-8C47-00C04FC295EE` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |
| `DE351A42-8E59-11D0-8C47-00C04FC295EE` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |
| `DE351A43-8E59-11D0-8C47-00C04FC295EE` | WINTRUST.DLL | CryptSIPGetSignedDataMsg |

Rust SIP digest parity in-tree: **PE / WinMD** (`--rust-sip pe`), **PowerShell + WSH** (`--rust-sip script`), **MSI** (`--rust-sip msi`), **WIM/ESD** (`--rust-sip esd`), **flat/bundle MSIX and APPX ZIP** (`sip_rust::msix_digest`; `--rust-sip msix`, `verify --rust-sip-msix-digest-check`; matches osslsigncode `appx.c` / `AppxSipVerifyIndirectData` for cleartext OPC). **Encrypted** AppX rows (**`EappxSip*`**, **`EappxBundleSip*`**), **`P7xSip*`** (standalone PKCX container extraction), and **`ExtensionsSip*`** (delegates to optional extension DLLs) are not reimplemented. **VBA** (`mso.dll` → **`VBE7`**) is not reimplemented. **CAB** / **`.cat`** use **`WINTRUST`** routing — see [`windows-signing-components.md`](windows-signing-components.md).

Consolidated gap list: [`rust-sip-gaps.md`](rust-sip-gaps.md).
