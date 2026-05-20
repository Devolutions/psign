# CLI parity backlog (non-SIP)

These items are **native `signtool.exe` switches and workflows** that are intentionally partial or stubbed in `psign`. They are independent of **file-format / SIP** coverage: signing PE, WinMD, MSIX, scripts, etc. still goes through the OS Cryptography SIP stack (`SignerSignEx3`, `WinVerifyTrust`) where implemented.

Source of truth for tiers and per-flag notes: [`psign-cli-matrix.json`](psign-cli-matrix.json).

## P1 — Often deferred

| Area | Native switches | Rust status |
|------|-------------------|-------------|
| Strict digest option requirements | Missing sign `/fd`; missing RFC3161 `/td` with sign `/tr` or timestamp `/tr` | Native `signtool.exe` throws explicit `No /fd flag specified` / `No /td flag specified`; `psign` currently defaults to SHA-256 for compatibility |
| Split digest pipeline | `/dg`, `/di`, `/ds`, `/dxml` | Parsed; execution returns explicit error — use atomic sign or native `signtool` |
| Verify shim | `/ms` (`--multiple-semantics`) | Accepted; documented compatibility note |
| Timestamp | `/p7` (timestamp PKCS#7 files), `/force`, `/nosealwarn` | Explicit not-implemented errors |
| Sign sealing / warnings | `/seal`, `/itos`, `/force` (sign), `/nosealwarn`, `/noenclavewarn` | Explicit not-implemented errors (`sealing.rs`) |
| Sign auth / templates | `/sa` OID+value, `/c` template | Explicit not-implemented errors |
| Digest vs cert warn | `/fdchw`, `/tdchw`, `/rmc` | Explicit not-implemented errors |

## P2 — Lower volume

| Area | Native switches | Rust status |
|------|-------------------|-------------|
| PKCS#7 product signing | `/p7`, `/p7ce`, `/p7co` | Partial / explicit errors — differs from SIP-backed PE signing |
| catdb | subsystem GUIDs | Best-effort vs SDK |

## Verify partials

| Native | Notes |
|--------|--------|
| `/bp`, `/enclave` | CLI accepted; WinTrust action GUID wiring blocked on published policy IDs (see JSON) |

Prioritize implementation based on product need; SIP-backed format signing does **not** require completing this backlog.

## Experimental Rust SIP (PE)

| Area | Notes |
|------|--------|
| `sign --rust-sip pe`, `PSIGN_RUST_SIP` | Post-sign Authenticode digest consistency vs PKCS#7 after `SignerSignEx3`; see `docs/rust-sip-architecture.md` |
| `verify --rust-sip-pe-digest-check` | Additive check after WinTrust on PE/WinMD — does not replace `WinVerifyTrust` |
| `verify --rust-sip-all-digest-checks` | Enables every `--rust-sip-*-digest-check` for embedded verify; encrypted MSIX extensions fail explicitly in the MSIX checker |
| `/dg` staging overlap | When Rust PKCS#7 encode exists, split-digest backlog intersects Tier 1a completion |

Full SIP-shaped gap list: [`rust-sip-gaps.md`](rust-sip-gaps.md).
