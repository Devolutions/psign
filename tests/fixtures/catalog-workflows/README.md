# Catalog workflow fixtures

MakeCat + signtool reference fixtures for portable catalog membership tests.

- Subjects live under `subjects/`: `tiny32.efi`, `hello.txt`, and `blob.bin`.
- CDF inputs live under `cdf/` and request SHA-256 catalog signing metadata.
- `.cat` files are signed with the public Devolutions Authenticode test PFX used by the rest of the generated signing fixtures. They are intentionally not timestamped.

Regenerate on Windows with the Windows SDK installed:

```powershell
scripts/ci/build-catalog-workflow-fixtures.ps1
```

Current MakeCat output records SHA-1 member digests inside the CTL entries even though the catalog `SignedData` itself is signed with SHA-256. The portable verifier honors the digest algorithm recorded per member.
