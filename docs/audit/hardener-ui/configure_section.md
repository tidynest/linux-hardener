# hardener-ui::components::configure_section
**File:** `crates/hardener-ui/src/components/configure_section.rs` | **Lines:** 315

## Purpose
Profile selection (baseline/secure/high), per-plugin toggles, dry-run preview, and apply flow.
Uses `StoredValue` for plugin state across closures, `Arc<dyn Fn>` for profile update callbacks.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ConfigureSection` | component | Full hardening configuration panel with profile selector, plugin toggles, preview, and apply button |

## Internal Details
| Item | Lines | Description |
|------|-------|-------------|
| Profile selector | — | Baseline/Secure/High radio buttons update plugin toggle defaults |
| Plugin toggles | — | Per-plugin enable/disable via `StoredValue` signals |
| Dry-run preview | — | Calls `invoke_apply_dry_run()`, displays validation results before commit |
| Apply flow | — | Confirms via dry-run, then calls `invoke_apply()` with selected plugins |

## Flags
None.
