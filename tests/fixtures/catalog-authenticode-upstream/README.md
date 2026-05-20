# Catalog / CMS PKCS#7 fixtures

- **`tiny32-content.cat`**: raw PKCS#7 **`ContentInfo`/`SignedData`** extracted from **`tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi`** (Authenticode **SPC_INDIRECT_DATA**), not a Microsoft CTL **`.cat`**. It exercises **`catalog-signer-rs256-prehash`** / **`pkcs7-signer-rs256-prehash`** (same bytes) and **RS256** prehash parity.

**`verify-catalog`** is **expected to fail** on this file: the portable catalog checker validates PKCS#9 **`messageDigest`** vs **`eContent`** using the **catalog** scan rules; Authenticode PE **`SignedData`** encodes **`messageDigest`** differently than CTL-style catalogs.

Regenerate:

```powershell
cargo run -p psign --bin psign-tool -- `
  portable extract-pe-pkcs7 tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi `
  --output tests/fixtures/catalog-authenticode-upstream/tiny32-content.cat
```

Or **`scripts/ci/build-catalog-pe-pkcs7-fixture.ps1`**.
