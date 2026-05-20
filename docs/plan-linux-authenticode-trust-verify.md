# Plan (expanded): Portable Authenticode trust verification on Linux

This document deepens the Linux Authenticode **cryptographic verification** plan: AuthRoot-equivalent anchors, **picky-rs**, CMS/`authenticode` alignment with existing crates, and parity notes vs Windows **`WinVerifyTrust`** / **`CertVerifyCertificateChainPolicy`**.

Related reading: [Michael Waterman — Microsoft Root Certificate Program](https://michaelwaterman.nl/2022/11/17/the-microsoft-root-certificate-program/) (how **`authrootstl.cab`** / CTL sync relates to Windows Update and offline mirrors). Crypto/X.509 stack: [Devolutions/picky-rs](https://github.com/Devolutions/picky-rs).

---

## 1. Current codebase baseline

| Layer | Location | Linux today |
|-------|----------|-------------|
| PE digest vs PKCS#7 indirect digest | [`crates/psign-sip-digest/src/verify_pe.rs`](crates/psign-sip-digest/src/verify_pe.rs) | Yes — **integrity only** |
| CMS `SignedData` parsing (catalogs) | [`crates/psign-sip-digest/src/catalog_digest.rs`](crates/psign-sip-digest/src/catalog_digest.rs) | Yes — **`messageDigest` vs `eContent`** |
| Detached PKCS#7 + chain + policy | [`src/win/verify_detached.rs`](src/win/verify_detached.rs) | No — **`CryptVerifyDetachedMessageSignature`**, **`CertGetCertificateChain`**, **`CertVerifyCertificateChainPolicy`** |
| Signer / CA thumbprint filters, optional EKU warnings | [`src/win/verify_chain.rs`](src/win/verify_chain.rs) | No |

Portable trust work **extends** digest checks with: **CMS signature verification**, **X.509 path validation** to AuthRoot anchors, and **EKU/KU policy**.

---

## 2. Windows verification pipeline (behavioral spec)

Understanding this avoids guessing; trace **`psign`** Win32 paths and public docs instead of relying on opaque summaries of closed-source tools.

### 2.1 Embedded PE / SIP subjects

- **`WinVerifyTrust`** drives SIP providers (**`WINTRUST`**, **`AppxSip`**, …), PKCS#7 extraction, and trust policy.
- Internally, certificate evaluation uses **certificate chaining** against stores (**`ROOT`**, **`AuthRoot`**, **`CA`**, **`Disallowed`**, …) and **policy modules** (Authenticode, driver policy, etc.).

### 2.2 Detached PKCS#7 (already clearest in-tree)

[`verify_detached.rs`](src/win/verify_detached.rs) order:

1. **`CryptVerifyDetachedMessageSignature`** — validates CMS structure and populates signer cert context (cryptographic verification against content bytes).
2. Optional filters: signer SHA1 (`/sha1`), intermediate CA thumbprints (`/ca`), optional **EKU warning** queries (`warn_missing_eku_messages`).
3. **`CertGetCertificateChain`** — builds chain to a trusted root (uses AuthRoot / enterprise roots / cached CTL). Flags include optional **`CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`** when `args.revocation_check`.
4. **`CertVerifyCertificateChainPolicy`** with policy GUID:
   - **`CERT_CHAIN_POLICY_AUTHENTICODE`** when **`/pa`**-style generic verification,
   - **`CERT_CHAIN_POLICY_MICROSOFT_ROOT`** for kernel policy mode,
   - **`CERT_CHAIN_POLICY_BASE`** otherwise,
   - plus **`CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG`** when allowing test roots.

**Linux MVP target:** approximate **(1) + (3) subset + (4) Authenticode-flavored rules** without full CryptoAPI store semantics — **explicit anchor set** from AuthRoot STL instead of **`CertDllOpenCertificateStore`** glue.

### 2.3 Policy gaps to document up front

Windows applies **CTL updates**, **disallowed cert STL**, **pinning rules** (`PinRulesSTL`), **AutoFlushNextDelta**, enterprise **TrustedPublisher** stores, and **Appx-specific** publisher checks. The Linux tool should:

- Ship with a **declared subset** (AuthRoot + optional Disallowed + optional strict EKU).
- Record non-goals in [`rust-sip-gaps.md`](rust-sip-gaps.md) with stable identifiers (e.g. `linux_trust_no_pinrules`, `linux_trust_no_flush_policy`).

---

## 3. AuthRoot / `authrootstl.cab` (technical depth)

### 3.1 Operational sources (from Waterman + Microsoft practice)

- Public CTL distribution URL pattern (example):  
  `http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab`
- **`certutil -syncWithWU \\server\share`** pulls **`authrootstl.cab`**, **`disallowedcertstl.cab`**, **`*.crt`**, pin rules, etc. — enterprises host mirrors; Linux CLI should document **file-based** inputs mirroring that layout.
- **Fallback roots in `crypt32.dll`** when update endpoints are unreachable — **not portable**; do not rely on this for Linux.

### 3.2 CAB contents

Expect at least:

- **`authrootstl.stl`** (or similarly named) — PKCS#7-wrapped **CTL** listing trusted roots (often **SHA-1 thumbprint** / subject key identifiers + metadata, not always full DER certs inline).
- Often companion **`.crt`** extracts for roots — easiest **MVP anchor ingestion**: load **DER/PEM certs from a directory** produced by Windows **`certutil`** or extracted from CAB.

### 3.3 CTL inner structure (Microsoft)

CTL uses content type OID **`1.3.6.1.4.1.311.10.1`** (Microsoft CTL). Conceptually:

- **Subject algorithm** (often SHA-1 thumbprint of root cert),
- **Sequence of `TrustedSubject`** entries: identifier + attributes (friendly name, EKUs, disable entries, etc.).

**Implementation strategy:**

1. **Phase A (fastest):** CLI **`--anchor-dir`** pointing at **`.crt` files** (same as admin-synced bundle). Parse each cert with **picky-rs**, insert into **`HashMap<Thumbprint, Certificate>`** or SKI-based map.
2. **Phase B:** Parse **`authrootstl.stl`** CTL directly from CAB — reuse **`cms`** patterns from [`catalog_digest.rs`](crates/psign-sip-digest/src/catalog_digest.rs) (also Microsoft CTL content type) to decode **`SignedData`**, extract **`eContent`**, then ASN.1-parse CTL body with **picky / picky-asn1** generated or hand-written models (may need a thin CTL schema crate or internal module).

### 3.4 Bootstrap integrity of the STL/CAB

| Approach | Pros | Cons |
|---------|------|------|
| User-supplied path + docs | Simple | No crypto proof of cab origin |
| HTTPS fetch + **pinned SHA-256** in docs/CI | Detects CDN corruption | Pin rot requires doc updates |
| Verify STL **`SignedData`** with **Microsoft STL signer** chain pinned in binary | Strongest | Maintenance burden; signer rotates |
| TOFU store in `~/.cache/psign/authroot/` | UX | Still needs first-fetch integrity |

**Recommendation:** MVP = **pinned hash for CI artifact** + **`--anchor-dir`** for air-gapped; Phase 2 = optional STL signature verification using embedded Microsoft roots updated per release.

---

## 4. picky-rs integration map

[picky-rs](https://github.com/Devolutions/picky-rs) is a multi-crate workspace. Likely roles:

| Concern | Crate(s) | Notes |
|---------|-----------|------|
| X.509 certificate DER | `picky-asn1-x509`, `picky` | Parse **`Certificate`**, extensions (**EKU**, **BasicConstraints**, **SKI/AKI**) |
| Public key ops / signature verify | `picky` (and underlying crypto deps — confirm RSA-PKCS#1-v1.5 vs PSS, ECDSA P-256/P-384) | Use for **TBSCertificate** signature verification |
| Time / validity | application code | Apply **notBefore/notAfter** with optional timestamp grace later |

**Keep existing:**

| Concern | Crate | Notes |
|---------|-------|------|
| Authenticode **`SpcIndirectData`** / PE security dir | `authenticode` | Continue extracting PKCS#7 + indirect digest |
| CMS **`SignedData`**, **`SignerInfo`**, digest alg | `cms`, `der` | Matches [`catalog_digest.rs`](crates/psign-sip-digest/src/catalog_digest.rs) patterns |

**Spike checklist (before large implementation):**

- Verify **picky** can verify **RSA PKCS#1 v1.5** signatures on **SHA-256** digests (typical Authenticode).
- Verify **ECDSA** P-256 / P-384 support if commercial chains require it.
- Decide whether **picky** exposes CMS **`SignerInfo`** verification or you implement **digest + RSA/ECDSA** on the **authenticated attributes** DER blob per RFC 5652 / Authenticode rules.

---

## 5. CMS `SignedData` verification order (normative for implementation)

For each **`SignerInfo`** in Authenticode PKCS#7:

1. **Gather certs:** embedded **`certificates`** bag + optional external anchors (not typical for PE).
2. **Resolve signer cert:** **`SignerInfo.sid`** matches **`IssuerAndSerialNumber`** or **`SubjectKeyIdentifier`**.
3. **Digest algorithm:** from **`SignerInfo.digestAlgorithm`**.
4. **Authenticated attributes:** Authenticode requires **`contentType`**, **`messageDigest`**, and typically **`signingTime`** or countersignature conventions — parse with **`cms`**.
5. **Compute digest:**
   - **If authenticated attributes present:** digest is over the **DER-encoded `SignedAttributes`** (SET OF), **not** over raw file bytes directly for the CMS signature step.
   - **Concurrently:** **`messageDigest`** attribute must equal **hash** defined by Authenticode for the **subject** (PE image digest from **`pe_authenticode_digest`** — already implemented).
6. **Verify `SignerInfo.signature`** using signer cert’s public key over the digest from step 5.
7. **Chain:** walk **issuer** pointers using **`AuthorityKeyIdentifier`** / **subject/issuer DN + serial** matching until an anchor matches AuthRoot entry (thumbprint/SKI).
8. **Policy:** EKU/KU, BC, validity.

**Countersignatures (RFC3161):** nested **`SignerInfo`** — **Phase 2**. MVP may treat **expired leaf** as **fail** unless **`--timestamp-policy=ignore-expiry`** once timestamp crypto exists.

---

## 6. EKU / KU policy (explicit rules)

### 6.1 Leaf (signing) certificate

- **Require** Extended Key Usage contains **`1.3.6.1.5.5.7.3.3` (codeSigning)** when **`--strict-eku`** (default **on**).
- If EKU extension is **absent**: Windows behavior can vary by policy and age of cert — document as **fail** under strict mode; optional **`--legacy-missing-eku=warn|allow`** for parity investigations.

### 6.2 CA certificates

- **BasicConstraints:** `CA:TRUE` with appropriate **`pathLenConstraint`**.
- **Key usage:** **`keyCertSign`** typically required for intermediates (relax only if needed for broken real-world chains — log warnings).

### 6.3 Alignment with `psign` Windows path

Mirror concepts from [`warn_missing_eku_messages`](src/win/verify_chain.rs) / native **`/u`** where feasible — Linux CLI flags **`--require-eku-oid`** could accept repeated OIDs for parity testing.

---

## 7. Crate / module layout (refined)

Options:

- **`crates/psign-authenticode-trust`** — **recommended**: isolates **picky** + trust logic; **`psign-sip-digest`** stays digest-focused; **`psign-digest-cli`** gains subcommands.
- Feature flag **`psign-sip-digest/trust`** — avoids new crate but couples digest + PKI dependency weight.

Add **read-only CAB extraction** dependency (e.g. **`cab`** crate) **only** in the trust crate or CLI — **not** inside **`cab_digest`** (different concern).

---

## 8. CLI design (expanded)

### 8.1 Subcommands

| Command | Purpose |
|---------|---------|
| **`trust-verify-pe`** | PE path + anchor source |
| (later) **`trust-verify-detached`** | content path + PKCS#7 path (mirror [`verify_detached.rs`](src/win/verify_detached.rs)) |
| (later) **`trust-verify-catalog`** | `.cat` as trust blob (CTL membership still separate) |

### 8.2 Flags (illustrative)

- **`--authroot-cab PATH`** — extract STL/certs (Phase B) or document “extract first” for MVP.
- **`--anchor-dir PATH`** — directory of **`.crt`/`.cer`** (Phase A).
- **`--disallowed PATH`** — STL/CAB for untrusted roots/certs (Phase 1.5).
- **`--strict-eku`** / **`--no-strict-eku`**
- **`--require-timestamp`** — future
- **`--verbose-chain`** — print chain PEM summaries / subjects for debugging

Preserve existing **`verify-pe`** as **digest-only** — no breaking change.

---

## 9. Testing matrix (expanded)

### 9.1 Unit / property tests (no network)

| Test | Goal |
|------|------|
| **EKU missing** | Leaf without `codeSigning` → **fail** under strict |
| **Wrong anchor** | Chain to unknown root → **fail** |
| **Tampered `messageDigest`** | Integrity failure before crypto chain |
| **Tampered CMS signature** | Signature verify fails |
| **BC violation** | Synthetic EE marked `CA:true` → **fail** |
| **RSA vs ECDSA** | Two minimal chains via **`rcgen`** or precomputed fixtures |

### 9.2 Integration tests (network optional)

- Download **`authrootstl.cab`** in CI (cache action); extract or use **`--anchor-dir`** from unpacked **`crt`** set.
- **Signed artifact:** choose **redistributable** Windows PE:
  - **PuTTY `putty.exe`** — [licence](https://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html) allows redistribution; pin **SHA-256** of downloaded binary in test.
  - Alternatives: other OSS with explicit redistribution terms; avoid proprietary installers without license files.

### 9.3 Negative integration

- Flip one byte in PE → expect failure.
- Wrong **`--anchor-dir`** (empty or wrong roots) → failure.

### 9.4 License hygiene

Add **`tests/fixtures/README.md`** listing third-party binaries, URLs, pinned hashes, and license blurbs.

---

## 10. Phased delivery

| Phase | Scope |
|-------|--------|
| **P0 — Spike** | picky verifies cert signatures; **`cms`** extracts **`SignerInfo`** + attrs; chain builder skeleton |
| **P1 — MVP** | **`--anchor-dir`** + **`trust-verify-pe`** + strict EKU + unit tests |
| **P2** | **`authrootstl.cab`** ingest + pinned fetch in CI |
| **P3** | Disallowed STL + timestamp verification path |
| **P4** | Detached PKCS#7 parity with [`verify_detached.rs`](src/win/verify_detached.rs) subset |

---

## 11. Risk register

| Risk | Mitigation |
|------|------------|
| **STL parsing complexity** | Ship **CRT directory** path first |
| **RSA-PSS vs PKCS#1 confusion** | Spike real chains early |
| **Revocation drift vs Windows** | Document **no CRL/OCSP** in MVP |
| **Supply chain of cab download** | Pin hashes; HTTPS; corporate mirror docs |
| **License on test binaries** | Central **`fixtures/README`** |

---

## 12. Documentation deliverables

- New **`docs/authroot-linux-verify.md`** — operational guide (fetch, mirror, pin, **`certutil`** equivalence).
- Update [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) Phase 2 with trust verification.
- Update [`rust-sip-gaps.md`](rust-sip-gaps.md) with Windows-vs-Linux trust parity matrix.

---

## 13. Task checklist (from expanded plan)

1. **Spike:** picky-rs signature verify + `cms` **`SignerInfo`** attribute parsing for one known PKCS#7 blob (use in-repo signed PE fixture or minimal PKCS#7).
2. **Anchor store:** `--anchor-dir` loader + thumbprint/SKI index.
3. **Chain builder:** RFC 5280-ish linking using embedded PKCS#7 certs.
4. **Verifier:** integrate **`verify_pe`** digest check + CMS signature verify + chain + EKU.
5. **CLI:** `trust-verify-pe` + flags.
6. **Tests:** rcgen/synthetic + optional CI with **`authrootstl.cab`** + PuTTY pin.
7. **Docs:** authroot guide + gaps matrix.
