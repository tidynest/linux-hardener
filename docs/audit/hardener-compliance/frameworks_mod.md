# hardener-compliance::frameworks::mod
**File:** `crates/hardener-compliance/src/frameworks/mod.rs` | **Lines:** 26

## Purpose
Framework module root — dispatches `get_controls()` to the correct framework module.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls(framework)` | fn | Match on `ComplianceFramework` → delegate to submodule |

## Submodules
`cis`, `gdpr`, `hipaa`, `nist`, `pci`, `stig`

## Design Note
`ISO27001` variant returns `vec![]` — placeholder for future implementation.

## Flags
None.
