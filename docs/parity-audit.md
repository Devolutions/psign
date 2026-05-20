# Parity Audit Snapshot

Audit scope:
- `src/cli.rs`
- `src/win/sealing.rs`
- `src/win/sign_core.rs`
- `src/win/timestamp_core.rs`
- `tests/parity_signtool.rs`
- `scripts/run-parity-diff.ps1`

Observed MSIX-focused baseline before this parity wave:
- MSIX signing constraints were stricter than native parity in some paths.
- Decoupled digest (`/dlib` + `/dmdf`) now executes in-process via `SignerSignEx3`.
- Sign-time digest parity lacked explicit `/td`-equivalent control.
- CI parity gate did not exercise MSIX-specific semantic scenarios.

Current audit status:
- MSIX sign/timestamp constraints are explicitly validated in `src/win/sealing.rs`.
- Decoupled digest requests execute through a deterministic native bridge in `src/win/sign_core.rs`.
- Sign path now supports independent timestamp digest selection (`--timestamp-digest`).
- Parity script + CI include MSIX semantic scenarios with required fixture env gates.

Audit outputs now tracked in:
- `docs/parity-matrix.md`
- `tests/fixtures/corpus.json`
- `parity-output/parity-report.json` (generated)
