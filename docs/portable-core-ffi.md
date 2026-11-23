# Portable core FFI

`psign-portable-ffi` exposes the reusable portable Authenticode core as a native shared library for native or P/Invoke callers (for example patched PowerShell hosts). The `Devolutions.Psign` PowerShell module no longer loads it: it calls the managed equivalent, `Devolutions.Psign.Signing.Portable.PortableCoreJson`, which accepts the same operations and JSON. It is no longer built or signed by the release workflow; build it from source when needed (`cargo build --release -p psign-portable-ffi --features "azure-kv-sign artifact-signing-rest"`). Cargo names the library `psign_core` (`psign_core.dll`, `libpsign_core.so`, `libpsign_core.dylib`) because Rust library target names cannot contain hyphens; the former module packaging renamed it to `psign-core`. In this repository it remains the reference implementation for the C# differential tests (`PSIGN_RUST_FFI`).

The ABI is intentionally small and JSON-based:

- `psign_core_version()`
- `psign_core_get_signature(request_json_ptr, request_json_len)`
- `psign_core_get_artifact_signing_identity(request_json_ptr, request_json_len)`
- `psign_core_validate_powershell_script(request_json_ptr, request_json_len)`
- `psign_core_sign(request_json_ptr, request_json_len)`
- `psign_core_free(buffer)`

All request and response JSON uses UTF-8. Callers pass borrowed input buffers; Rust returns an owned `PsignFfiBuffer { ptr, len, cap }`. Managed callers must copy the bytes immediately and call `psign_core_free` exactly once with the returned buffer.

The first schema version supports portable digest/signature inspection and local RSA signing for PE, CAB, MSI, ZIP Authenticode, MSIX/AppX packages, and PowerShell script inputs. `Set-PsignSignature` accepts certificate/key paths, exportable `X509Certificate2` values, exportable PFX files, chain certificates, RFC3161 timestamp settings, `-SkipSigned` for intact PE/WinMD signatures, and portable cert-store material resolved by managed callers. `Set-PsignSignature` and `Get-PsignSignature` also accept PowerShell module directories and expand them to signable `.ps1`, `.psm1`, and `.psd1` files.

`psign_core_get_signature` also accepts explicit trust material in the JSON request: trusted certificate paths, DER-encoded trusted certificates, anchor directory, AuthRoot CAB, `as_of`, timestamp-time policy booleans, online AIA/OCSP toggles, and revocation mode. The portable core never falls back to OS trust; when trust is requested, the response includes `trust_status` in addition to the digest/signature `status`.

Azure Artifact Signing validation is requested with an `artifact_signing` object (`publisher_ids`, `private_trust_root_paths`, `allow_missing_timestamp`) instead of trust anchors. Combining it with trusted certificates, an anchor directory, or an AuthRoot CAB is an error. Every response carries `artifact_signing` (the signer's decoded identity: `kind`, `publisher_id`, `identity_eku`, `has_public_trust_marker`, `has_code_signing_eku`) when present. A successful validation adds `artifact_signing_verification` (`root_sha1`, `root_subject`, `verification_time`, `timestamped`). `psign_core_get_artifact_signing_identity` takes `{ "certificate_der_base64": "…" }` and returns `{ "schema_version", "identity" }` (`identity` is `null` for certificates without an Artifact Signing EKU). See [artifact-signing-validation.md](artifact-signing-validation.md).

`psign_core_validate_powershell_script` is the embedding-oriented variant for patched PowerShell hosts. Its request contains `source_path_or_extension`, `content_base64`, and the same explicit trust fields as `psign_core_get_signature`. The function validates `.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.psc1`, `.cdxml`, and `.mof` content from memory so policy enforcement can avoid temporary files and shelling out.
