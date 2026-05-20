# Linux signing pipelines (what works today)

**`psign-tool portable`** on Linux/macOS can now sign PE, unsigned single-volume CAB, MSI/MSP, generic catalogs, and RDP files with local RSA/SHA-2 keys. It still does not provide a broad native-compatible `sign` verb, MSIX signing/embed, OS catalog database policy, or WinTrust policy emulation (see [`rust-sip-gaps.md`](rust-sip-gaps.md)). This page describes **practical portable**, **hybrid**, and **verify-only** flows.

For tool-by-tool gaps vs **`signtool.exe`**, AzureSignTool, and Artifact Signing, see [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md). On Windows, for writable copies of native signing binaries outside protected install paths, see [`writable-signing-binaries.md`](writable-signing-binaries.md).

## 1. Verify-only on Linux (recommended CI gate)

After any Windows signing job:

| Format | Commands |
|--------|----------|
| PE | `verify-pe`, `trust-verify-pe` (+ anchors), `inspect-authenticode` |
| CAB | `verify-cab`, `trust-verify-cab` |
| MSI / ESD / MSIX / catalog / scripts | matching **`verify-*`** |

Automation: **`scripts/linux-portable-validation.sh`**, GitHub **`ci-unix`**, and the portable crate/test commands documented in [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md). Windows differential parity: **`scripts/run-parity-diff.ps1`** (see [`ci-parity.md`](ci-parity.md)).

## 1.1 Local portable signing

Local RSA/SHA-2 signing is intentionally exposed through scoped portable commands before routing the native-shaped `sign` verb:

```bash
psign-tool portable sign-pe --cert cert.der --key key.pk8 --output signed.exe unsigned.exe
psign-tool portable sign-cab --cert cert.der --key key.pk8 --output signed.cab unsigned.cab
psign-tool portable sign-msi --cert cert.der --key key.pk8 --output signed.msi unsigned.msi
psign-tool portable sign-catalog --cert cert.der --key key.pk8 --output files.cat file1.exe file2.txt
```

`sign-catalog` authors generic CTL member entries and signs the catalog PKCS#7. Pair it with `verify-catalog` and `verify-catalog-member --catalog files.cat file1.exe`; driver/INF policy and OS catalog database lookup remain Windows-only.

## 1.5 RFC 3161 TSA query/reply (DER only; no embed)

**`psign-tool portable rfc3161-timestamp-req`** builds **`TimeStampReq`** DER from **`--digest-hex`** / **`--digest-file`** (message-imprint preimage; optional **`--nonce`**, **`--cert-req`**). **`rfc3161-timestamp-resp-inspect`** prints **`pki_status`** / **`pki_status_int`** (raw **`PKIStatus`** INTEGER) / **`granted`** / token length, **`time_stamp_token_prefix_hex`** (first **16** octets of the **`timeStampToken`** TLV), **`status_strings_json`**, **`fail_info_tlv_hex`**, and **`fail_info_flags_json`** from **`TimeStampResp`** DER. When the token is a parseable CMS **`id-ct-TSTInfo`** timestamp token, it also prints structural **`tst_info_*`** fields for policy OID, message-imprint digest OID/hash, serial, **`genTime`**, and nonce; **`--expect-digest-hex`** and **`--expect-nonce`** add request-binding diagnostics (`tst_info_message_imprint_match`, `tst_info_nonce_match`). These fields are diagnostic only and do not imply TSA trust or CMS signature validation. Build with **`--features timestamp-http`** for **`rfc3161-timestamp-http-post --url …`** (Rustls POST **`application/timestamp-query`**, response DER to stdout / **`--output`**); otherwise use **`curl`** or OpenSSL **`ts`**. **`timestamp-pe-rfc3161`** can attach the granted token to an existing PE Authenticode `SignerInfo`; non-PE timestamp mutation still goes through **`psign-tool`** / **`SignerTimeStampEx3`** today.

For deterministic local tests, build **`psign-server`** with **`--features timestamp-server`** and run:

```bash
cargo run --features timestamp-server --bin psign-server -- \
  timestamp-server --listen 127.0.0.1:48161 --gen-time 20240102030405Z
```

It serves RFC 3161 **`POST`** requests as **`application/timestamp-reply`** with a generated test TSA certificate and signed **`TimeStampToken`**. Use **`--max-requests 1`** for one-shot integration tests, **`--status rejection`** / **`--status waiting`** for non-granted **`PKIStatus`**, or **`--response-mode bad-alg|malformed-der|http-error|mismatched-imprint|invalid-signature`** for deterministic negative paths. This server is development/test infrastructure, not a production TSA.

For Windows parser/trust experiments, **`--cert-output PATH`** writes the generated root CA certificate and **`--tsa-cert-output PATH`** writes the generated TSA leaf certificate. The token includes the leaf and root certificates; local trust-store setup is still test-only.

## 2. Azure Artifact Signing — digest + REST on Linux, embed on Windows

Build **`psign-tool portable`** with **`--features artifact-signing-rest`**.

1. **Subject digest** (raw bytes for REST body):

   ```bash
   psign-tool portable pe-digest --algorithm sha256 --encoding raw --output digest.bin ./MyApp.exe
   # CAB:
   psign-tool portable cab-digest --algorithm sha256 --encoding raw --output digest.bin ./My.cab
   # CMS RS256 prehash on signed CAB (KV keys/sign), not cab-digest:
   # psign-tool portable cab-signer-rs256-prehash --encoding raw --output signer-prehash.bin ./My.cab
   # Same for MSI (DigitalSignature stream), not installer fingerprint digest:
   # psign-tool portable msi-signer-rs256-prehash --encoding raw --output signer-prehash.bin ./My.msi
   # Whole-file PKCS#7 .cat (same 32-byte digest as pkcs7-signer-rs256-prehash on that DER):
   # psign-tool portable catalog-signer-rs256-prehash --encoding raw --output signer-prehash.bin ./My.cat
   ```

2. **`:sign` LRO** (same as **`psign-tool artifact-signing-submit`**):

   ```bash
   psign-tool portable artifact-signing-submit \
     --region REGION --account-name ACCOUNT --profile-name PROFILE \
     --digest-file digest.bin --signature-algorithm RS256 \
     --managed-identity   # or --access-token / tenant + client-id + client-secret
   ```

3. **Embed** PKCS#7 / complete Authenticode: still **`psign-tool`** + **`SignerSignEx3`** (and typically **`--dlib`** / **`--dmdf`** for Trusted Signing) until a portable embedder exists.

Optional debug: **`SIGNTOOL_PORTABLE_DEBUG=1`**.

Details: [`migration-artifact-signing.md`](migration-artifact-signing.md).

## 3. AzureSignTool — Key Vault digest sign on Linux

**Partial.** Use **`pe-digest` / `cab-digest`** (**`--encoding raw`**) for **subject layout** digests when that matches your tool mode, or the **CMS authenticated-attribute** prehash family when you mirror **`CryptMsg`** / **`SignerSignEx3`** signing over **`signedAttrs`**:

| Subject | Prehash for KV **`RS256`** (`--encoding raw`, 32 bytes) | Same bytes via extract + generic PKCS#7 |
|---------|------------------------------------------------------------|-------------------------------------------|
| PE | **`pe-signer-rs256-prehash`** (`--index` = cert-table row, **`--signer-index`** = **`SignerInfo`**) | **`extract-pe-pkcs7`** → **`pkcs7-signer-rs256-prehash`** |
| CAB | **`cab-signer-rs256-prehash`** | **`extract-cab-pkcs7`** → **`pkcs7-signer-rs256-prehash`** |
| MSI | **`msi-signer-rs256-prehash`** | **`extract-msi-pkcs7`** → **`pkcs7-signer-rs256-prehash`** |
| Raw PKCS#7 (e.g. **`.cat`**) | **`catalog-signer-rs256-prehash`** | **`pkcs7-signer-rs256-prehash`** on the same file |

Then **`azure-key-vault-sign-digest`** with **`--features azure-kv-sign-portable`** performs **`keys/sign`** (see [`migration-azuresigntool.md`](migration-azuresigntool.md)). **`verify-catalog`** checks CTL-style **`messageDigest` ↔ eContent`** and can disagree with Authenticode-only PKCS#7 bodies—use the right command for catalog *membership* vs *CMS signer* prehash.

**Embed** PKCS#7 on Windows with **`psign-tool`** (`--features azure-kv-sign`) or native **`signtool.exe`**.

Details: [`migration-azuresigntool.md`](migration-azuresigntool.md).

## 4. Roadmap — portable embed + more formats

Ordered backlog (engineering): [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) (Phase 2 stretch: PKCS#7 + PE **`WIN_CERTIFICATE`**, then CAB/MSI/MSIX). SIP coverage limits: [`rust-sip-gaps.md`](rust-sip-gaps.md).

**PE checksum:** **`psign-tool portable pe-checksum ./file.exe`** compares optional-header **`CheckSum`** to **`pe_compute_image_checksum`** (same algorithm used after **`append-pe-pkcs7`**). **`--strict`** fails when they differ.

**Library + CLI:** [`psign-sip-digest::pkcs7`](../crates/psign-sip-digest/src/pkcs7.rs) exposes **`parse_pe_pkcs7_spc_indirect_data`** (read **`SpcIndirectDataContent`** from an embedded PE PKCS#7), **`spc_indirect_data_replace_message_digest`** (swap the **`messageDigest`** octets while keeping **`SpcPeImageData`**), **`cms_digest_encapsulated_econtent_bytes`** / **`signer_info_pkcs9_message_digest_octets`** (RFC 5652 **`eContent`** hash vs PKCS#9 **`messageDigest`** — matches RustCrypto **`cms` SignerInfoBuilder** semantics), **`signer_info_signed_attributes_sequence_der`** (**`SET OF Attribute`** DER for §5.4 authenticated-attribute signing — compare **`CryptMsg`** / **`SignerInfoBuilder`** inputs when wiring KV **`:sign`**), **`signed_attributes_replace_pkcs9_message_digest`** (rewrite PKCS#9 **`messageDigest`** in the authenticated-attribute **`SET`** after **`encapContentInfo`** changes — still need new **`encryptedDigest`**), **`signer_info_sha256_digest_over_signed_attrs`** (**SHA-256** over that **`SET`** — validate vs **`CryptMsg`** / **KV `RS256`** before production), **`signer_info_clone_with_signed_attrs`** / **`signer_info_clone_with_signature_octets`** (apply rebuilt attrs / remote **`encryptedDigest`** octets), **`signed_data_replace_signer_info_at`** / **`signed_data_replace_first_signer_info`** (splice **`SignerInfo`** back into **`SignedData.signerInfos`**), and **`signed_data_replace_encapsulated_spc_indirect`** (rewrite **`SignedData.encapContentInfo.eContent`** — **`SignerInfo`** signature becomes invalid until rebuilt; see doc comment). On Linux, **`psign-tool portable pe-signer-rs256-prehash ./file.exe`** (**`--encoding raw`**, optional **`--signer-index`** for the *N*th **`SignerInfo`** in the PKCS#7 row selected by **`--index`**) emits the **32-byte** **`RS256`** digest for Azure Key Vault **`keys/sign`** (CMS authenticated-attribute **`SET`** §5.4 — distinct from **`pe-digest`** image hash). **`psign-tool portable pkcs7-signer-rs256-prehash ./blob.p7`** (**`--signer-index 0`**, **`--encoding raw`**) computes the same digest from PKCS#7 DER alone (for example **`extract-pe-pkcs7 --output`** first). **`psign-tool portable inspect-pe-spc-indirect ./file.exe`** prints JSON (OIDs, digest hex, SIP match flag) for the same structure—use **`--index N`** to match the *N*th PKCS#7 row (**`list-pe-pkcs7`** / **`extract-pe-pkcs7`** order)—useful before a portable **`SignedData`** / **`WIN_CERTIFICATE`** rebuild exists. **`psign-tool portable extract-pe-pkcs7 ./file.exe`** writes embedded PKCS#7 DER to stdout (or **`--output`**); use **`--index N`** for the *N*th **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row (multi-signed binaries). **`psign-tool portable list-pe-pkcs7 ./file.exe`** prints **`pkcs7_entries`** and each row’s **`byte_len`** (same index order as **`extract-pe-pkcs7`**). **`psign-tool portable append-pe-pkcs7 --pe in.exe --pkcs7 blob.der --output out.exe`** appends a PKCS#7 row via **`pe_embed`** and refreshes the PE **image checksum** (experimental — not a full CMS signer).
