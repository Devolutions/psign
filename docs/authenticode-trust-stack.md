# Authenticode trust stack (portable)

This describes how **`crates/psign-authenticode-trust`** composes crates for **Linux/macOS-style** Authenticode trust checks without **`CertGetCertificateChain`** / **`WinVerifyTrust`**.

## Responsibility split

| Layer | Crate | Role |
|-------|--------|------|
| PKCS#7 shell, **`SignerInfo`**, authenticated attributes | **`cms`**, **`der`** (via **`authenticode`** / **`picky`**) | Parse **`SignedData`**, locate **`messageDigest`**, carry DER blobs. |
| PE layout, indirect **`SpcIndirectData`**, image digest | **`authenticode`**, **`psign-sip-digest`** | Enumerate embedded PKCS#7 from the PE certificate table; recompute **`pe_authenticode_digest`** for the embedded hash algorithm. |
| CMS Authenticode rules + X.509 chain verification | **`picky`** (`AuthenticodeSignature`, `authenticode_verifier`, `Cert::verifier`) | Validate **`messageDigest`** vs provided digest, signature over authenticated attributes, TBSCertificate signatures along **`issuer_chain`**, Basic Constraints / dates / EKU policy hooks. |
| Trust anchors | This crate (**`anchor`**, **`authroot_cab`**, **`authroot_ctl`**) | Phase A: load **`*.crt`/`*.cer`/`*.pem`** from **`--anchor-dir`** or repeatable **`--trusted-ca`** files. Phase B: CAB **`*.stl`** → PKCS#7 **`SignedData`** **`eContent`** CTL parse for **SHA-1 subject identifiers** plus PKCS#7-embedded certs. |
| Policy knobs | **`policy::AuthenticodeTrustPolicy`** | Default **strict** code-signing EKU; CLI **`allow-loose-signing-cert`**, **`--prefer-timestamp-signing-time`** / **`--require-valid-timestamp`** (see [**Verification instant / timestamps**](#verification-instant--timestamps)), **`--as-of YYYY-MM-DD`** for **`exact_date`**. |
| Portable CLI | **`psign-tool portable`** | **`trust-verify-pe`**, **`trust-verify-cab`**, **`trust-verify-catalog`**, **`trust-verify-detached`** share anchor, AuthRoot CAB, AIA, OCSP, CRL revocation, timestamp-policy, and chain-diagnostic flags; detached uses [`pkcs7_wire::normalize_pkcs7_der_for_authenticode`](../crates/psign-sip-digest/src/pkcs7_wire.rs). **`inspect-authenticode`** emits JSON for PKCS#7 signers, timestamp-related OIDs, and nested signatures (**`1.3.6.1.4.1.311.2.4.1`**). Unified **`psign-tool --mode portable verify`** switches from digest-only verification to these trust commands when trust inputs such as **`--trusted-ca`**, **`--anchor-dir`**, **`--authroot-cab`**, **`--online-aia`**, **`--online-ocsp`**, **`--revocation-mode`**, or **`--require-valid-timestamp`** are present. |
| CMS inspection (no trust decision) | This crate **`inspect`** | Uses **`cms`** **`SignedData`** + **`authenticode`** digest probe; complements picky **`trust_*`** paths. See [**psa-interoperability.md**](psa-interoperability.md). |

## Verification order (per PKCS#7 blob)

1. Parse PKCS#7 with **`authenticode-rs`** to read the embedded **`messageDigest`** and infer **`PeAuthenticodeHashKind`**.
2. Recompute the PE Authenticode digest with **`pe_authenticode_digest`**; fail fast if it does not match.
3. Parse the same DER with picky **`AuthenticodeSignature::from_der`** and run **`authenticode_verifier()`** with **`require_basic_authenticode_validation(pe_digest)`**, **`ignore_chain_check()`** (chain is validated explicitly below), and **`exact_date`** (see [Verification instant / timestamps](#verification-instant--timestamps)).
   - **CAB / non-PE `SpcIndirectData`:** when picky rejects the PKCS#7 shell, a **CMS fallback** validates **`SpcIndirectData.messageDigest`** against the caller’s subject digest (not raw PKCS#9 **`messageDigest`** signed attributes, which can differ on CAB fixtures), verifies **RSA PKCS#1 v1.5 / SHA-256** over authenticated **`signedAttrs`**, then builds the issuer chain using **X.509 `Name` DER equality** so **`--anchor-dir`** CA certificates match **`cms`**-parsed signers even when picky’s **`Name`** equality would not. **`--anchor-dir`** must still contain the **terminal self-signed root** thumbprint (and any missing intermediates not present in the PKCS#7 bag).
4. Merge picky-decoded embedded certs with anchor / CAB-extracted certs; resolve the signing cert; walk **`issuer_chain_excluding_leaf`** to the terminal root (or the CMS fallback equivalent above).
5. If **`--online-aia`** is enabled and an issuer is missing, fetch **HTTP** AIA **`caIssuers`** certificates into memory only (or use **`--aia-url-override`** for deterministic local tests); no OS intermediate/root store is modified.
6. Require the terminal root’s **SHA-1 thumbprint** (full cert DER, Windows-style) to appear in the configured **`AnchorStore`**.
7. If **`--online-ocsp`** or **`--ocsp-url-override`** is set with revocation enabled, POST a bounded OCSP request, require a successful BasicOCSPResponse, verify its RSA/SHA-256 signature with the issuing CA, match the requested serial, and apply good/revoked/unknown status.
8. If OCSP is not configured or does not return a definitive good status, fetch the CRL over bounded HTTP from **`--crl-url-override`** or the first HTTP CRL Distribution Point URL, verify its RSA/SHA-256 signature with the issuing CA, and reject revoked leaf/intermediate serials.
9. **`leaf.verifier().chain(...).exact_date(...).verify()`** to validate signatures along the path.

Normative background and CTL/bootstrap notes live in **[plan-linux-authenticode-trust-verify.md](plan-linux-authenticode-trust-verify.md)**.

## Verification instant / timestamps

**`exact_date`** passed to picky controls not-before / not-after checks on the chain. Resolution order:

1. **`--as-of YYYY-MM-DD`** (CLI) / **`verification_instant_override`** — fixed UTC midnight for reproducible CI or expired-leaf fixtures (**timestamp presence is not checked** on this path).
2. Otherwise, if **`prefer_timestamp_signing_time`** is **false** (default): wall clock **`UtcDate::now()`**.
3. If **`prefer_timestamp_signing_time`** is **true** and **`require_valid_timestamp`** is unset: **[`rfc3161_extract::utc_date_from_authenticode_timestamp_token`](../crates/psign-authenticode-trust/src/rfc3161_extract.rs)** scans CMS **`SignedData`** **`SignerInfo`** rows — **first** nested PKCS#7 with **`id-ct-TSTInfo`** encapsulated content and a parsable **`TSTInfo.genTime`** wins; if none, the **first** PKCS#9 **`signing-time`** in signed attributes wins; if none, falls back to wall clock.
4. If **`prefer_timestamp_signing_time`** and **`require_valid_timestamp`** are both set: **`trusted_utc_date_from_authenticode_timestamp_token`** requires a nested RFC3161 token whose **`MessageImprint`** matches the primary **`SignerInfo.signature`** digest, whose timestamp CMS **`messageDigest`** and RSA/SHA-256 signature verify, whose TSA signer has **`timeStamping`** EKU, and whose TSA chain terminates in an explicit **`--trusted-ca`** / **`--anchor-dir`** trust anchor. The TSA chain also goes through the configured revocation policy.

PKCS#9 **`signing-time`** remains a convenience for non-required timestamp instant selection. It does not satisfy **`--require-valid-timestamp`**.

## Remaining gaps

- OS **AuthRoot** / **Intermediate** stores, **PinRules**, enterprise **TrustedPublisher**, or public-store policy. AIA and CRL retrieval are explicit and in-memory only.
- Indirect CRLs, delta CRLs, OCSP nonce policy, delegated OCSP responder authorization, and richer OCSP response variants are still future work; the implemented revocation path handles issuing-CA-signed OCSP and CRL responses over HTTP for `psign-server` tests and rejects stale `nextUpdate` windows.
- RFC3161 support is intentionally narrow: RSA/SHA-256 timestamp CMS signatures, primary-signature **`MessageImprint`**, explicit-anchor TSA chains, and `timeStamping` EKU are covered; delegated responders, non-RSA/non-SHA-256 TSA signatures, richer timestamp policies, and timestamp token embedding during portable signing remain future work.
