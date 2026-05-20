# Devolutions Authenticode test PKI

These files are public **test-only** signing materials from
[`Devolutions/devolutions-authenticode`](https://github.com/Devolutions/devolutions-authenticode),
pinned to commit `df20875f2935645a007a4fdc12bf8900f8316362`.

They are vendored so local and CI parity runs can sign test vectors without
downloading the same public fixtures on every run.

| File | SHA-256 |
| --- | --- |
| `authenticode-test-ca.crt` | `a4f2a4df35d8db33f704e32276a5874b6b44906536637e22df579e300aa3bc0e` |
| `authenticode-test-cert.pfx` | `d5b5fc1bb184c5689d2abe2a9c988b72496f79aa19ccb2683271c4c7db31eb8d` |

The PFX password is public and test-only: `CodeSign123!`.

Do not use this PKI for production signing.
