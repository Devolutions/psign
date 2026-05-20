# MSIX / AppX Rust SIP — spike (Tier 4)

## Scope

MSIX signing is **not** implemented in the Rust SIP path. This document captures inputs for a future effort.

## SIP digest inputs (high level)

- **ZIP package** layout (`[Content_Types].xml`, block map, manifest).
- **APPX-specific digest** computation over payload + manifest structures (distinct from flat PE SIP).
- Interaction with **decoupled digest** (`/dlib`, `/dmdf`) already modeled for MSIX in [`sign_core.rs`](../src/win/sign_core.rs).

## Dependencies on earlier tiers

- **Tier 1c** page-hash discipline and PKCS#7 attribute conventions inform how nested OIDs align with packaged modes.
- Parity harness should mirror [`scripts/msix-parity-sign.ps1`](../scripts/msix-parity-sign.ps1) outcomes.

## Effort estimate (order of magnitude)

Several engineer-weeks minimum for digest + parity CI, excluding catalog/store publishing workflows.
