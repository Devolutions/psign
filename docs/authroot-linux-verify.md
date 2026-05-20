# AuthRoot-style anchors on Linux

Windows resolves Authenticode chains against machine/user certificate stores plus **Microsoft Authenticode roots**. On Linux, **`psign-tool portable trust-verify-pe`** requires you to supply **explicit roots** (and optionally intermediates embedded in the PE PKCS#7).

## Phase A — anchor directory (recommended first ship)

1. On a Windows machine with updates, sync roots you trust, for example:
   - **`certutil -generateSSTFromWU roots.sst`** then export, or  
   - Copy known **`.crt`** / **`.cer`** files into a folder (repo-local or CI cache).
2. Pass **`--anchor-dir /path/to/certs`** to **`trust-verify-pe`**, or pass individual files with repeatable **`--trusted-ca /path/to/root.cer`**.  
   Non-recursive: only **`*.crt`**, **`*.cer`**, **`*.pem`** in that directory are loaded.
3. Thumbprints are **SHA-1 over full certificate DER** (same convention as many Windows tools), not TBSCertificate-only.

Keep separate what you **trust as an anchor** vs what happens to be embedded in the PE (intermediates are usually present in the signature).

## Phase B — `authrootstl.cab` extraction

`psign-authenticode-trust` reads a Microsoft **`authrootstl.cab`**, walks **`*.stl`** entries, and:

1. Harvests **X.509 certificates** from PKCS#7 blobs (`Pkcs7::from_der` on each member).
2. Parses PKCS#7 **`ContentInfo` → `SignedData`** when present and extracts CTL **`eContent`** **TrustedSubject** SHA-1 **`SubjectIdentifier`** octets into the anchor thumbprint set (alongside cert-derived thumbs).

Pass **`--authroot-cab /path/to/authrootstl.cab`** on any **`trust-verify-*`** subcommand.

### Bootstrap integrity

- **CI / reproducibility:** pin a **SHA-256** of the CAB; pass **`--expect-authroot-cab-sha256 <64-hex>`** so ingest aborts on mismatch.
- **Future hardening:** verify the **outer** Authenticode signature / CTL semantics on the STL (see technical plan).

## Example

```bash
psign-tool portable trust-verify-pe \
  --anchor-dir ./my-trusted-roots \
  ./signed.exe
```

Single-file non-admin trust anchor:

```bash
psign-tool portable trust-verify-pe \
  --trusted-ca ./test-root.cer \
  ./signed.exe
```

The unified CLI can use the same trust path without writing to the Windows or Linux OS trust store. With **`--mode portable verify`**, trust inputs such as **`--trusted-ca`**, **`--anchor-dir`**, **`--authroot-cab`**, AIA/OCSP/CRL flags, and timestamp policy flags route to the corresponding portable **`trust-verify-*`** command inferred from the subject file:

```bash
psign-tool --mode portable verify \
  --trusted-ca ./test-root.cer \
  ./signed.exe
```

With Microsoft root harvest from CAB:

```bash
psign-tool --mode portable verify \
  --authroot-cab ./authrootstl.cab \
  --anchor-dir ./extra-enterprise-roots \
  --verbose-chain \
  ./signed.exe
```

Strict **code signing** EKU is default; for diagnostics only:

```bash
psign-tool portable trust-verify-pe --allow-loose-signing-cert ...
```

Expired corpora / reproducible CI: pin verification instant:

```bash
psign-tool portable trust-verify-pe --anchor-dir ./roots --as-of 2023-07-01 ./fixture.exe
```

For local online issuer tests, enable bounded in-memory AIA fetching. Only **HTTP** AIA URLs are currently supported, intended for loopback `psign-server` tests:

```bash
psign-tool portable trust-verify-pe \
  --trusted-ca ./test-root.cer \
  --online-aia \
  ./signed-with-missing-intermediate.exe
```

For local CRL revocation tests, use strict revocation with an explicit loopback CRL URL. The CRL is fetched into memory, checked against the issuing CA signature, and evaluated for revoked signer/intermediate serials without touching OS stores:

```bash
psign-tool portable trust-verify-detached \
  ./content.bin ./signature.p7 \
  --trusted-ca ./test-root.cer \
  --revocation-mode require \
  --crl-url-override http://127.0.0.1:5000/crl.der
```

OCSP loopback tests use the same revocation policy. The portable verifier sends a bounded OCSP request, verifies the BasicOCSPResponse signature with the issuing CA, and applies good/revoked/unknown status:

```bash
psign-tool portable trust-verify-detached \
  ./content.bin ./signature.p7 \
  --trusted-ca ./test-root.cer \
  --revocation-mode require \
  --online-ocsp \
  --ocsp-url-override http://127.0.0.1:5000/ocsp
```

## Related docs

- **[authenticode-trust-stack.md](authenticode-trust-stack.md)** — crate split and verification order.
- **[plan-linux-authenticode-trust-verify.md](plan-linux-authenticode-trust-verify.md)** — full design / risks / test matrix.
