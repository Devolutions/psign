# Portable core FFI

`psign-portable-ffi` exposes the reusable portable Authenticode core as a native shared library for managed callers such as a PowerShell 7.4 / .NET 8 binary module.

The ABI is intentionally small and JSON-based:

- `psign_portable_version()`
- `psign_portable_get_signature(request_json_ptr, request_json_len)`
- `psign_portable_sign(request_json_ptr, request_json_len)`
- `psign_portable_free(buffer)`

All request and response JSON uses UTF-8. Callers pass borrowed input buffers; Rust returns an owned `PsignFfiBuffer { ptr, len, cap }`. Managed callers must copy the bytes immediately and call `psign_portable_free` exactly once with the returned buffer.

The first schema version supports portable digest/signature inspection and local RSA signing for PE, CAB, MSI, ZIP Authenticode, MSIX/AppX packages, and PowerShell script inputs. `Set-PortableSignature` accepts certificate/key paths, exportable `X509Certificate2` values, exportable PFX files, chain certificates, RFC3161 timestamp settings, and portable cert-store material resolved by managed callers. `Set-PortableSignature` and `Get-PortableSignature` also accept PowerShell module directories and expand them to signable `.ps1`, `.psm1`, and `.psd1` files.

`psign_portable_get_signature` also accepts explicit trust material in the JSON request: trusted certificate paths, DER-encoded trusted certificates, anchor directory, AuthRoot CAB, `as_of`, timestamp-time policy booleans, online AIA/OCSP toggles, and revocation mode. The portable core never falls back to OS trust; when trust is requested, the response includes `trust_status` in addition to the digest/signature `status`.
