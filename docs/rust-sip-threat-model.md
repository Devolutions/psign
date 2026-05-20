# Rust SIP — threat model (initial)

## Trust boundaries

- **Inputs:** Arbitrary file paths from the CLI user; PE bytes are treated as **untrusted**.
- **Outputs:** Diagnostics only; `--rust-sip` does not change Windows trust stores.

## Parsing risks (`sip_rust`, `authenticode`, `object`)

- **Memory safety:** Prefer bounded slices (`get` ranges) over unchecked indexing; rely on `object` / `authenticode` for PE traversal — report upstream issues if found.
- **Denial of service:** Extremely large `SizeOfImage`, bogus section table, or certificate table sizes could force large allocations — `object` bounds checks expected; monitor fuzzing results if `cargo fuzz` is added later.

## Signing

- Until PKCS#7 is produced in-tree, private keys stay inside **Windows CAPI/CNG** via existing `SignerSignEx3` paths.
- Experimental `--rust-sip pe` adds **only** a digest consistency check; it is not a second signature format.

## Operational

- Do not promote `--rust-sip` for compliance regimes (e.g. FIPS) without independent review.
