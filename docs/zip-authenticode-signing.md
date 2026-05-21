# ZIP Authenticode signing

`psign` supports the custom ZIP Authenticode convention used by
[`Devolutions/devolutions-authenticode`](https://github.com/Devolutions/devolutions-authenticode).
This is not a Windows SIP and native `signtool verify` does not verify the ZIP
file directly. Instead, the ZIP comment stores an Authenticode-signed
PowerShell-script representation of the ZIP digest.

## Format

Signing computes SHA-256 over the ZIP bytes from the beginning of the file
through the end-of-central-directory (EOCD) record. Before hashing, the two-byte
EOCD comment length field is treated as zero and the existing ZIP comment bytes
are excluded. The digest string is:

```text
sha256:<64 lowercase hex chars>
```

That string is written to a temporary UTF-8 `.sig.ps1` file with no byte-order
mark and no trailing newline. The temporary script is Authenticode-signed, then
the PKCS#7 payload from the script signature block is embedded as the ZIP
comment:

```text
ZipAuthenticode=sha256:<64 lowercase hex chars>,<base64 PKCS#7>
```

The ZIP comment is limited by the ZIP format to 65,535 bytes. Signing replaces
the entire pre-existing ZIP comment with the `ZipAuthenticode=` payload, matching
the upstream convention.

## Signing and verifying

On Windows, `.zip` files are first-class inputs to top-level `sign` and `verify`:

```powershell
psign-tool sign --pfx cert.pfx --password "pfx-password" --digest sha256 archive.zip
psign-tool verify --allow-test-root archive.zip
```

For direct PFX input, `psign` builds the same Authenticode CMS signature that
Windows script signing would embed in the temporary `.sig.ps1` bridge file, then
stores that PKCS#7 in the ZIP comment. Other signing sources are routed through
the existing Windows script-signing bridge when the local signing stack supports
PowerShell script subjects. Options that depend on native SIP features or
multi-signature storage are rejected for ZIP input, including append-signature,
page-hash, sealing, detached PKCS#7 output, and split-digest flows.

Verification extracts the ZIP comment, validates the digest binding against the
current ZIP bytes, reconstructs the `.sig.ps1` file, and verifies that script's
Authenticode signature. A successful result means the ZIP bytes match the
embedded digest and the reconstructed script signature chains according to the
selected verification policy.

Portable verification is available without Win32:

```powershell
psign-tool portable verify-zip archive.zip
psign-tool portable trust-verify-zip archive.zip --anchor-dir anchors
psign-tool --mode portable verify archive.zip --anchor-dir anchors
```

`verify-zip` checks the ZIP digest binding and PowerShell-script PKCS#7 indirect
digest consistency. `trust-verify-zip` also validates the PKCS#7 signer chain
against explicit anchors; portable mode never uses the OS trust store.

## Security and interoperability notes

- This custom format is recognized by `psign` and Devolutions tooling, not by the
  Windows SIP registry.
- The signature covers ZIP bytes through EOCD with the comment length zeroed, so
  changes to ZIP entries, central directory records, or EOCD fields invalidate
  the digest. Replacing or appending ZIP comments also invalidates the format
  unless the new comment contains a matching `ZipAuthenticode=` payload.
- `psign` validates the EOCD candidate strictly by requiring the EOCD comment to
  end exactly at EOF. This avoids treating `PK\x05\x06` bytes inside a comment
  as the actual EOCD record.
- ZIP64 archives are supported when they still include the standard EOCD comment
  field, as required by the ZIP format.

## Test fixtures

The committed fixtures live under `tests\fixtures\zip-authenticode`:

- `unsigned\sample.zip`
- `signed\sample.signed.zip`
- `zip-authenticode-fixtures.json`

Regenerate them from a Windows checkout with:

```powershell
scripts\ci\build-zip-authenticode-fixtures.ps1 -Force
```

The script uses the public Devolutions test PFX by default:
`tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx` with
password `CodeSign123!`.
