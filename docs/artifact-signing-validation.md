# Azure Artifact Signing validation

This document explains how psign checks that an Authenticode signature was produced by **Azure Artifact Signing** (formerly *Trusted Signing* / *Azure Code Signing*). It can optionally pin a specific Artifact Signing certificate profile, using its **publisher ID**. It covers the identity mechanism, how the publisher ID is encoded, which Microsoft root CAs are pinned and why, and the exact validation steps.

Implementation: [`crates/psign-authenticode-trust/src/artifact_signing.rs`](../crates/psign-authenticode-trust/src/artifact_signing.rs). Surfaces: `psign-tool verify --artifact-signing…` (Windows and portable modes), `psign-tool portable trust-verify-* --artifact-signing…`, `psign-tool portable artifact-signing-publisher-id`, and the PowerShell cmdlets `Test-PsignArtifactSigning`, `Get-PsignArtifactSigningPublisherId`, and `Get-PsignSignature -ArtifactSigning…`.

## Why generic Authenticode trust is not enough

A generic trust check (`trust-verify-pe`, or `WinVerifyTrust`) answers *"does this chain end at **any** trusted root?"*. For Artifact Signing that is the wrong question, for three reasons:

1. **Certificates are short-lived.** Artifact Signing issues a new signer certificate every day, valid for **72 hours**. Thumbprints, serial numbers, and public keys change daily, so none of them can be pinned.
2. **The subject DN is not an identity.** It holds the validated legal name (`CN=Devolutions Inc, O=Devolutions Inc, …`). That name is not unique across CAs and can change over the life of an organization.
3. **An EKU is only an OID.** Microsoft encodes the durable profile identity as an extended key usage (EKU) OID (below). *Any* CA trusted by AuthRoot could technically issue a certificate that carries the same OID. The identity only means something if the chain is **pinned to the Microsoft root that operates Artifact Signing**.

Microsoft has also announced that the Artifact Signing code-signing CAs are being removed from the Common CA Database (CCADB). They stay on the Windows platform trust list, so Windows keeps trusting them. Trust stores that follow CCADB (Mozilla-derived bundles on Linux) will not include them. Pinning the root explicitly makes validation independent of any platform trust store.

## The durable identity: certificate profile EKU

Each Artifact Signing **certificate profile** gets a custom EKU that every certificate issued from that profile carries, for the whole life of the profile. All Artifact Signing EKUs live under:

```text
1.3.6.1.4.1.311.97      iso.org.dod.internet.private.enterprise.microsoft(311).97
```

The arcs that follow identify the **profile type**, then the **profile-specific identity**:

| Profile type | Identity EKU | Other EKUs present | Root |
|---|---|---|---|
| Public Trust | `1.3.6.1.4.1.311.97.<id>` | `1.3.6.1.4.1.311.97.1.0` (Public Trust marker), `1.3.6.1.5.5.7.3.3` (code signing) | Microsoft Identity Verification Root CA 2020 |
| Public Trust Test | `1.3.6.1.4.1.311.97.1.2.<id>` | code signing, `1.3.6.1.4.1.311.10.3.13` (lifetime signing) | Test root (not a production Microsoft root) |
| Private Trust | `1.3.6.1.4.1.311.97.1.3.1.<id>` | code signing | Subscriber-specific root (`Get-AzCodeSigningRootCert` / `artifact-signing-root`) |
| Private Trust CI Policy | `1.3.6.1.4.1.311.97.1.4.1.<id>` | **no** code signing EKU | Subscriber-specific root |

The Public Trust Test prefix `…97.1.2.` is observed in real test-profile certificates (see the unit tests in [`trust_pkcs7.rs`](../crates/psign-authenticode-trust/src/trust_pkcs7.rs)). The other prefixes come from Microsoft's documentation.

Rules psign applies when classifying an EKU under `1.3.6.1.4.1.311.97`:

- `…97.1.0` exactly is the Public Trust **marker**, not an identity.
- `…97.1.2.*`, `…97.1.3.1.*`, `…97.1.4.1.*` map to the types above.
- Any other `…97.1.*` is an unknown sub-type and is ignored.
- Anything else under `…97.` (first arc ≠ `1`) is a **Public Trust identity**.
- A certificate with **two different** identity EKUs is rejected as ambiguous.

Lifecycle notes from Microsoft:

- The EKU belongs to the **certificate profile**, not to the subscriber or the identity validation. Two profiles of the same organization have **different** publisher IDs.
- **Deleting and recreating** a profile produces a **new** EKU. Anything pinned to the old value (a psign `--artifact-signing-publisher-id`, a WDAC policy, an ELAM resource) must be updated.
- For Private Trust, the CI Policy EKU uses the same suffix as the Private Trust code-signing EKU, under the `…97.1.4.1.` prefix.

## The publisher ID

psign calls the arcs **after the profile-type prefix** the **publisher ID**, rendered as a dotted decimal string:

| Identity EKU | Kind | Publisher ID |
|---|---|---|
| `1.3.6.1.4.1.311.97.285218949.549339218.252840042.443064405` | `public_trust` | `285218949.549339218.252840042.443064405` |
| `1.3.6.1.4.1.311.97.1.3.1.29433.35007.34545.16815.37291.11644.53265.56135` | `private_trust` | `29433.35007.34545.16815.37291.11644.53265.56135` |

Treat the publisher ID as an **opaque string** and compare it exactly. Microsoft documents only the prefix and that the suffix is unique per profile. Observed values have a regular shape: four arcs below 2³⁰ for Public Trust, eight arcs below 2¹⁶ in the Private Trust example. That suggests a 128-bit value split into groups, but the mapping to any Azure resource GUID is **not documented**, so psign does not try to convert it.

### DER encoding walkthrough

The EKU extension (`2.5.29.37`) of the Devolutions signer certificate in [`tests/fixtures/artifact-signing/`](../tests/fixtures/artifact-signing/) is:

```text
30 33                                       SEQUENCE (51 bytes)
   06 0A 2B 06 01 04 01 82 37 61 01 00         OID 1.3.6.1.4.1.311.97.1.0          (Public Trust marker)
   06 08 2B 06 01 05 05 07 03 03               OID 1.3.6.1.5.5.7.3.3               (code signing)
   06 1B 2B 06 01 04 01 82 37 61               OID 1.3.6.1.4.1.311.97 …            (identity, 27 bytes)
         81 88 80 B1 05                            285218949
         82 85 F9 80 52                            549339218
         F8 C8 90 6A                               252840042
         81 D3 A2 C0 55                            443064405
```

Each arc is base-128, big-endian, with the high bit set on every byte except the last. Worked example for `81 88 80 B1 05`:

```text
0x01·2²⁸ + 0x08·2²¹ + 0x00·2¹⁴ + 0x31·2⁷ + 0x05
= 268435456 + 16777216 + 0 + 6272 + 5 = 285218949
```

Arcs ≥ 2²⁸ need **five** base-128 bytes. `const-oid` 0.9, which the `x509-cert` / `cms` stack uses, refuses arcs longer than four bytes, so `ExtendedKeyUsage` cannot be decoded with the usual types. psign therefore walks the EKU `SEQUENCE OF OBJECT IDENTIFIER` by hand. It rejects non-minimal encodings (a leading `0x80` byte), truncated OIDs, arcs wider than 64 bits, non-OID entries, and trailing data.

### Extracting the publisher ID

```bash
# Every embedded PE signature (no trust decision):
psign-tool portable artifact-signing-publisher-id ./MyApp.exe

# A raw PKCS#7 / CMS blob, or a single certificate (PEM or DER):
psign-tool portable artifact-signing-publisher-id ./sig.p7s --input pkcs7
psign-tool portable artifact-signing-publisher-id ./signer.cer --input cert
```

```json
[
  {
    "pkcs7_index": 0,
    "signer_subject": "C=CA,ST=Québec,L=Lavaltrie,O=Devolutions Inc,CN=Devolutions Inc",
    "identity": {
      "kind": "public_trust",
      "publisher_id": "285218949.549339218.252840042.443064405",
      "identity_eku": "1.3.6.1.4.1.311.97.285218949.549339218.252840042.443064405",
      "has_public_trust_marker": true,
      "has_code_signing_eku": true
    }
  }
]
```

`identity` is `null` when the signer has no Artifact Signing identity EKU. This command does **not** validate the signature: any certificate can carry these OIDs. Use it to *discover* the ID you want to pin, then pin it with `--artifact-signing-publisher-id` (or `-PublisherId` in PowerShell).

To get only the publisher ID for pinning, without JSON parsing:

```bash
psign-tool portable artifact-signing-publisher-id --format publisher-id ./MyApp.exe
# 285218949.549339218.252840042.443064405
```

```powershell
(Get-PsignArtifactSigningPublisherId .\MyApp.exe).PublisherId
```

`--format publisher-id` prints one line per signature that carries an identity, and exits non-zero when none does.

On Windows the same value appears in the certificate's *Enhanced Key Usage* field as `Unknown Key Usage (1.3.6.1.4.1.311.97.…)`.

## Root CAs and chain layout

### Public Trust signer chain

Observed on the Devolutions sample (October 2026):

| Level | Subject | SHA-1 thumbprint | Validity |
|---|---|---|---|
| Leaf | `CN=Devolutions Inc, O=Devolutions Inc, …` | changes daily | 72 hours |
| Issuing CA | `CN=Microsoft ID Verified CS AOC CA 04` | `4c07413e5da89a259a127e1d76f792af239cd9d9` | 2026-03-26 → 2031-03-26 |
| Policy CA | `CN=Microsoft ID Verified Code Signing PCA 2021` | `8e750f459daf9a79d6370db747ad2226866ad818` | 2021-04-01 → 2036-04-01 |
| **Root (pinned)** | `CN=Microsoft Identity Verification Root Certificate Authority 2020` | **`f40042e2e5f7e8ef8189fed15519aece42c3bfa2`** | 2020-04-16 → 2045-04-16 |

### Timestamp (TSA) chain

Artifact Signing's TSA is `http://timestamp.acs.microsoft.com`:

| Level | Subject | SHA-1 thumbprint |
|---|---|---|
| TSA | `CN=Microsoft Public RSA Time Stamping Authority, …` | rotates |
| Issuing CA | `CN=Microsoft Public RSA Timestamping CA 2020` | `27f0abac2877ba255f62b389b43ff539a0fb598e` |
| **Root (pinned)** | `CN=Microsoft Identity Verification Root Certificate Authority 2020` | **`f40042e2e5f7e8ef8189fed15519aece42c3bfa2`** |

### What is pinned and why

psign pins exactly **one** root for Public Trust: **Microsoft Identity Verification Root Certificate Authority 2020**.

- SHA-1 `f40042e2e5f7e8ef8189fed15519aece42c3bfa2` (matches Microsoft's [PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm))
- SHA-256 `5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270`
- Embedded as PEM in [`crates/psign-authenticode-trust/certs/microsoft-identity-verification-root-ca-2020.pem`](../crates/psign-authenticode-trust/certs/microsoft-identity-verification-root-ca-2020.pem). It is re-hashed against **both** thumbprints every time it is loaded, so an edited PEM fails closed.

Design choices:

- **Pin the root, not the intermediates.** Issuing CAs rotate (the sample used *AOC CA 04*, issued March 2026). Pinning them would break validation on every rotation. The policy CA is long-lived, but the root is the stable anchor Microsoft publishes.
- **Use the same root for the TSA.** The timestamp decides *when* the signer certificate is checked for validity, and that is what keeps a 72-hour certificate's signature valid for years. A TSA from an arbitrary AuthRoot CA could back-date a signature into a revoked or expired certificate's validity window, so the TSA chain must end at the pinned root too.
- **Exclude everything else.** AuthRoot, `--anchor-dir`, the OS store, and other Microsoft roots (for example *Microsoft Root Certificate Authority 2010/2011*) are **not** consulted. The anchor set is fixed by the binary.
- **Private Trust / Public Trust Test** profiles chain to roots that are not production Microsoft roots. These signatures validate only when the caller supplies the root with `--artifact-signing-private-trust-root` (`-PrivateTrustRoot` in PowerShell). The pinned Microsoft root is **filtered out** of that list, so a Public Trust root can never anchor a non-Public-Trust identity.

If Microsoft adds another Artifact Signing root, add a `PinnedRoot` entry to `PUBLIC_TRUST_ROOTS` with its PEM and both thumbprints.

## Where the policy runs

The policy lives in one place: `TrustVerifyPeOptions::artifact_signing` ([`trust_verify_pe.rs`](../crates/psign-authenticode-trust/src/trust_verify_pe.rs)). When it is set, every `trust_verify_*` entry point swaps its generic anchor handling for the Artifact Signing check. That covers PE/WinMD, CAB, MSI/MSP, WIM/ESD, catalogs, ZIP Authenticode, PowerShell and WSH scripts, cleartext MSIX/AppX packages and bundles, NuGet packages, VSIX packages, and detached PKCS#7 (see [Format notes](#format-notes)). All callers reach it through the same functions:

| Surface | How it reaches the policy |
|---|---|
| `psign-tool verify --artifact-signing…`, **Windows mode** | `WinVerifyTrust` first (forced to the Authenticode `/pa` policy unless `--policy` is given, because Artifact Signing certificates never satisfy the default driver policy), then [`artifact_signing_verify::verify_targets`](../src/artifact_signing_verify.rs) → `trust_verify_path`. NuGet and VSIX have no Windows SIP, so they skip `WinVerifyTrust`. |
| `psign-tool verify --artifact-signing…`, **portable mode** | The same `verify_targets` call, in place of the generic AuthRoot trust. `--policy pa` is accepted, so one command line works in both modes. |
| `psign-tool portable trust-verify-{pe,cab,msi,esd,catalog,zip,detached,script,msix,nupkg,vsix} --artifact-signing…` | The shared portable trust flags build the same `TrustVerifyPeOptions`. |
| PowerShell `Test-PsignArtifactSigning`, `Get-PsignSignature -ArtifactSigning…` | The `artifact_signing` object in the `psign_core_get_signature` request ([portable-core-ffi.md](portable-core-ffi.md)). |

Windows mode can only be *stricter* than portable mode: a file must pass both WinVerifyTrust and the Artifact Signing check. For a genuine Artifact Signing signature both pass. The CLI tests in [`tests/artifact_signing_cli.rs`](../tests/artifact_signing_cli.rs) assert the same accept/reject outcome in both modes, using a real sample when `PSIGN_ARTIFACT_SIGNING_SAMPLE` is set.

## Validation algorithm

For **every** signature the format exposes (each PE certificate-table entry, or the single signature of the other formats), all of these must pass. Step 1 and the chain/timestamp sources differ per format; see [Format notes](#format-notes).

1. **Digest binding.** Recompute the subject digest with the format's SIP logic and require it to equal the PKCS#7 binding. That is the indirect `SpcIndirectDataContent` digest for Authenticode formats, and the PKCS#9 `messageDigest` for catalogs and CMS-detached signatures.
2. **Identity.** Take the certificate of the first `SignerInfo` and decode its Artifact Signing identity (see above). Fail if:
   - it has no identity EKU;
   - it is `public_trust` but lacks the `…97.1.0` marker;
   - it is `private_trust_ci_policy` (WDAC policy signing, not code);
   - it lacks the code signing EKU `1.3.6.1.5.5.7.3.3`.
3. **Publisher pin.** If one or more expected publisher IDs are given, the publisher ID must equal one of them (exact string match).
4. **Trusted timestamp.** Find the RFC 3161 countersignature (`1.3.6.1.4.1.311.3.3.1` or `1.2.840.113549.1.9.16.2.14`) on the primary signer and verify:
   - its `MessageImprint` covers the primary `SignerInfo.signature`;
   - its CMS signature verifies;
   - the TSA signer certificate has the `timeStamping` EKU;
   - the TSA chain ends at the **pinned Microsoft root** and is valid at `genTime`.

   `genTime` becomes the verification instant. With no timestamp, validation fails unless missing timestamps are explicitly allowed, in which case the current time is used. `--as-of YYYY-MM-DD` replaces the instant and skips this step.
5. **Anchor selection.**
   - `public_trust`: the pinned Microsoft root(s) only.
   - `public_trust_test` / `private_trust`: the supplied private trust roots, with any pinned Microsoft root removed. Fail if none remain.

   Generic anchor inputs (`--anchor-dir`, `--trusted-ca`, `--additional-trusted-ca`, `--authroot-cab`, and `-TrustedCertificate`/`-AnchorDirectory`/`-AuthRootCab` in PowerShell) are **rejected** with the Artifact Signing options, rather than silently ignored. AuthRoot is never downloaded.
6. **Signer chain and CMS.** Run the shared portable verifier ([`trust_pkcs7.rs`](../crates/psign-authenticode-trust/src/trust_pkcs7.rs)) with **strict** code-signing EKU policy:
   - validate the authenticated attributes and the signature;
   - build the issuer chain from the PKCS#7 certificate bag plus the anchors;
   - require the terminal root's SHA-1 thumbprint to be in the selected anchor set;
   - check every certificate signature and validity period at the instant from step 4.
7. **Revocation (opt-in).** With `--revocation-mode best-effort|require` (and optionally `--online-ocsp`), fetch the CRL from each certificate's distribution point and verify it with the issuing CA's key. This covers every non-root certificate in both the signer chain and the TSA chain. Any listed serial fails validation. `require` also fails when a CRL cannot be fetched, parsed, or verified, or is stale. On the sample, that is the CRLs of *ID Verified CS AOC CA 04* (≈22 KB), *Code Signing PCA 2021*, *Public RSA Timestamping CA 2020*, and the root (≈1 KB each), all well under the default 1 MiB download limit.

The result reports, per signature: `publisher_id`, `kind`, `identity_eku`, the terminal root subject and SHA-1 (`root_sha1`), the verification instant, and whether it came from a trusted timestamp.

## Usage

### psign-tool

```bash
# Accept any Artifact Signing Public Trust signer (Windows or portable mode, any supported format):
psign-tool verify --artifact-signing ./MyApp.exe

# Accept only one certificate profile (repeat the flag to allow a set, e.g. across a profile rotation):
psign-tool verify --artifact-signing-publisher-id 285218949.549339218.252840042.443064405 ./MyApp.exe

# Same check without WinVerifyTrust (Linux/macOS, or to skip the OS policy on Windows):
psign-tool --mode portable verify --artifact-signing-publisher-id 285218949.549339218.252840042.443064405 ./MyApp.exe

# Private Trust: supply the subscriber root (see `artifact-signing-root` in migration-artifact-signing.md):
psign-tool verify --artifact-signing-private-trust-root ./profile-root.cer ./MyApp.exe

# Fail closed on revoked or unverifiable revocation status (network required):
psign-tool verify --artifact-signing --revocation-mode require ./MyApp.msi

# Low-level portable commands take the same flags:
psign-tool portable trust-verify-cab --artifact-signing-publisher-id 285218949.549339218.252840042.443064405 ./payload.cab

# Discover the publisher ID to pin (no trust decision):
psign-tool portable artifact-signing-publisher-id ./MyApp.exe
```

| Flag (`verify` and `portable trust-verify-*`) | Effect |
|---|---|
| `--artifact-signing` | Enable the policy with defaults. |
| `--artifact-signing-publisher-id ID` | Repeatable; the signer's publisher ID must equal one of the values. Implies `--artifact-signing`. |
| `--artifact-signing-private-trust-root PATH` | Repeatable PEM/DER root for Private Trust / Public Trust Test; ignored for Public Trust. Implies `--artifact-signing`. |
| `--artifact-signing-allow-missing-timestamp` | Accept signatures without a timestamp and validate at the current time. They fail once the 72-hour certificate expires. Implies `--artifact-signing`. |
| `--as-of YYYY-MM-DD` | Fixed verification instant; skips timestamp verification. |
| `--revocation-mode off\|best-effort\|require`, `--online-ocsp`, `--online-timeout-secs N` | Online revocation, off by default. |
| `--verbose-chain` | Print the signer and TSA chains to stderr. |

Sample output in Windows mode (portable mode prints only the Artifact Signing block):

```text
Successfully verified: ./MyApp.exe
Artifact Signing verified: ./MyApp.exe
  signature[0] C=CA,ST=Québec,L=Lavaltrie,O=Devolutions Inc,CN=Devolutions Inc publisher_id=285218949.549339218.252840042.443064405 kind=public_trust root=f40042e2e5f7e8ef8189fed15519aece42c3bfa2 time=2026-10-23T18:43:55Z (timestamp)
```

### PowerShell (`Devolutions.Psign`)

```powershell
# Discover the publisher ID (no trust decision) from a file or a certificate:
Get-PsignArtifactSigningPublisherId .\MyApp.exe
Get-PsignArtifactSigningPublisherId -Certificate $cert

# Boolean check with publisher pinning; -Detailed returns the signature object:
Test-PsignArtifactSigning .\MyApp.exe -PublisherId 285218949.549339218.252840042.443064405
Test-PsignArtifactSigning .\MyApp.exe -PublisherId 285218949.549339218.252840042.443064405 -Detailed

# Full signature object with the policy applied:
Get-PsignSignature .\MyApp.exe -ArtifactSigningPublisherId 285218949.549339218.252840042.443064405
```

Every `Get-PsignSignature` result exposes `ArtifactSigning` (the decoded identity) and `ArtifactSigningPublisherId`, even without validation. With the policy applied, `ArtifactSigningVerification` holds the verified root, timestamp time, and signer. A failed policy check sets `Status`/`TrustStatus` to `NotTrusted`, and `StatusMessage` gives the reason. `Test-PsignArtifactSigning` also takes `-PrivateTrustRoot`, `-AllowMissingTimestamp`, `-AsOf`, `-RevocationMode`, and `-OnlineOcsp`.

### Library API

```rust
use psign_authenticode_trust::{ArtifactSigningPolicy, TrustVerifyPeOptions, trust_verify_path};

let report = trust_verify_path(path, &TrustVerifyPeOptions {
    artifact_signing: Some(ArtifactSigningPolicy {
        expected_publisher_ids: vec!["285218949.549339218.252840042.443064405".into()],
        ..Default::default() // require_timestamp: true
    }),
    ..Default::default()
})?;
for sig in &report.artifact_signing {
    println!("{sig}");
}
```

Other entry points:

- `trust_verify_{pe,cab,msi,catalog,zip,script,detached}_bytes` / `trust_verify_wim_esd_path` with the same options.
- `verify_artifact_signing_pkcs7(pkcs7_der, index, subject_digest, binding, &policy, &opts)` for a PKCS#7 whose subject digest you computed yourself.
- `artifact_signing_identity_from_certificate` / `_from_cert_bytes` / `_from_pkcs7_der` / `artifact_signing_identities_from_pe` for identity extraction only.

## Format notes

| Format | Signature binding checked before the policy | Signer chain / timestamp source |
|---|---|---|
| PE/WinMD, CAB, MSI/MSP, WIM/ESD, ZIP | Format SIP digest vs `SpcIndirectDataContent` | PKCS#7 bag; RFC 3161 unsigned attribute |
| PowerShell scripts, WSH scripts (`.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`) | `pwrshsip` / `wshext` digest of the stripped script | PKCS#7 bag; RFC 3161 unsigned attribute |
| MSIX/AppX and bundles | APPX blob: AXPC/AXCD/AXCT/AXBM (+ AXCI when `CodeIntegrity.cat` exists, on both sides), block map file hashes, bundle children | `AppxSignature.p7x` bag; RFC 3161 unsigned attribute |
| Catalogs, detached PKCS#7 | PKCS#9 `messageDigest` over the content | PKCS#7 bag; RFC 3161 unsigned attribute |
| NuGet (`.nupkg`, `.snupkg`) | Package hash over the **exact** unsigned bytes: the `.signature.p7s` entry must be the last ZIP entry, and is cut out byte for byte, as NuGet does. The signature content (`Version:1`, `<oid>-Hash:`) must be embedded in the CMS and match, with PKCS#9 `messageDigest` over it | `.signature.p7s` bag; RFC 3161 unsigned attribute |
| VSIX | OPC XMLDSig: C14N 1.0 / exclusive C14N `SignedInfo` and `SignatureValue` (RSA SHA-256/384/512); `#idPackageObject` digest; every `Manifest` part digest (raw, C14N, or OPC RelationshipTransform). Every package part except `[Content_Types].xml` and the signature part must be signed, and each reference's `ContentType` must match `[Content_Types].xml` | `KeyInfo` certificates; RFC 3161 token in `<Object><TimeStamp><EncodedTime>` (dotnet/sign), imprint over the raw `SignatureValue` octets |

VSIX signatures from dotnet/sign carry only the leaf certificate in `KeyInfo`, so building the Public Trust chain needs the issuing CAs from their AIA URLs. Pass `--online-aia` (fetched certificates are still validated against the pinned root). NuGet, MSIX and the PKCS#7 formats embed the chain.

Windows mode runs `WinVerifyTrust` for every format that has a Windows SIP, including MSIX/AppX and WSH. NuGet and VSIX have no SIP, so Windows mode applies only the shared check to them.

## Other places the identity is used

- **WDAC / App Control policies** can pin the identity EKU directly. That is the Windows-native equivalent of `--artifact-signing-publisher-id`.
- **ELAM anti-malware services**: Microsoft asks vendors to put the TBS hash of *Microsoft ID Verified Code Signing PCA 2021* in the ELAM resource `CertHash` and their identity EKU in its `EKU` field.
- **Signing-certificate selection**: `psign-tool sign --signing-cert-eku-prefix 1.3.6.1.4.1.311.97.` selects an Artifact Signing certificate from a store, the same way PowerShell OpenAuthenticode does.

## Limitations

- **Revocation is opt-in.** It is off by default because it needs network access. Use `--revocation-mode require` to fail closed. Microsoft revokes individual daily certificates on confirmed misuse, so require mode is recommended where network access is available. The Artifact Signing signer certificates publish a CRL distribution point but no OCSP URL, so CRLs do the work. Microsoft PKI CRLs are signed with `sha384WithRSAEncryption`, which the portable verifier supports along with SHA-256 and SHA-512. RSA-PSS and ECDSA-signed CRLs and OCSP responses are not supported. Revocation status is checked against the **current** CRL, not as of the timestamp time.
- **Formats.** Everything in [Format notes](#format-notes) is covered. ClickOnce manifests, App Installer descriptors, encrypted MSIX, and MSIX/AppX upload containers are rejected with the Artifact Signing options. In the PowerShell module, WIM/ESD and detached PKCS#7 have no portable trust path.
- **Legacy psign signatures.** psign now writes standard VSIX signatures (verified by .NET `PackageDigitalSignatureManager`) and embedded NuGet signature content. Packages signed by earlier psign releases are handled for compatibility only. Old VSIX signatures referenced parts directly, without the OPC `Object`/`Manifest`. Inspection still reports them, but trust and Artifact Signing verification reject them; re-sign such packages. Old `Set-PsignSignature` NuGet signatures used a detached CMS. They are still accepted when the rebuilt signature content matches the signed digest.
- **Catalog database lookup.** `verify --catalog-search` / `--catalog-database-guid` cannot be combined with the policy. Pass the catalog explicitly with `--catalog`; its signature is then checked, and member hashes are verified as usual.
- **Nested signatures.** Only certificate-table entries are checked. Nested signatures (`1.3.6.1.4.1.311.2.4.1`) inside an entry are not evaluated as separate Artifact Signing signatures.
- **Root subtree.** The pinned root also issues non-Artifact-Signing CAs (for example the timestamping CA). Requiring the identity EKU, the Public Trust marker, and the code signing EKU on the signer is what limits acceptance to Artifact Signing. Intermediates are deliberately not pinned (see above).

## References

- Microsoft Learn: [Artifact Signing certificate management](https://learn.microsoft.com/azure/artifact-signing/concept-certificate-management), covering short-lived certificates, the certificate profile EKU, and the TSA endpoint.
- Microsoft Learn: [Artifact Signing FAQ](https://learn.microsoft.com/azure/artifact-signing/faq), covering ELAM `CertHash` / EKU guidance and Windows support.
- Microsoft: [PKI Services repository](https://www.microsoft.com/pkiops/docs/repository.htm), covering the root certificate download and thumbprint.
- Related psign docs: [migration-artifact-signing.md](migration-artifact-signing.md) (signing), [authenticode-trust-stack.md](authenticode-trust-stack.md) (portable trust internals), [psa-interoperability.md](psa-interoperability.md).
