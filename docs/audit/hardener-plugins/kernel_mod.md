# hardener-plugins::kernel
**File:** `crates/hardener-plugins/src/kernel/mod.rs` | **Lines:** 480

## Purpose
Hardens kernel security parameters via sysctl. Table-driven via `KERNEL_PARAMS` const (12 parameters). Dual-write: applies to `/proc/sys/` (runtime) and `/etc/sysctl.d/99-hardener.conf` (persistent). Only plugin that calls `checkpoint_manager().rollback()` directly instead of the common `rollback_files_from_checkpoint()` helper.

## Dependencies
- Imports from: `hardener_common::error`, `hardener_common::types`, `hardener_core::plugin`, `hardener_core::Context`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `KernelHardeningPlugin` | struct | Unit struct implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Reads each sysctl param from `/proc/sys/`, compares to expected value |
| `HardeningPlugin::apply` | async fn | Checkpoint → write `/proc/sys/` (runtime) + `/etc/sysctl.d/` (persistent) |
| `HardeningPlugin::rollback` | async fn | `checkpoint_manager().rollback()` → `sysctl --system` |
| `HardeningPlugin::validate` | async fn | Checks param existence and writability via file metadata |

## Data Flow
`apply()` → checkpoint → for each `KERNEL_PARAMS`: write `/proc/sys/<path>` + append to config string → write `/etc/sysctl.d/99-hardener.conf`

`rollback()` → `manager.rollback(checkpoint_id)` → `sysctl --system` to reload from restored config

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `read_sysctl` | 49-53 | Reads `/proc/sys/<param>` via executor |
| `get_compliance_mappings` | 126-190 | CIS mappings per parameter name |

## Flags
- **WRONG MAPPING** (line 159-164): Fixed — `fs.protected_hardlinks`/`fs.protected_symlinks` were mapped to CIS 1.5.3 "Ensure core dumps are restricted". Changed to CIS 1.6.1 "Ensure filesystem hardening is configured".
- **SHADOWED IMPORT** (line 274): Fixed — `use std::path::Path` was already imported at file top.
- **DESIGN** (line 233): `finding_impact` says "Low impact - requires reboot or sysctl reload" — this describes remediation effort, not security impact of the insecure value. Deferred.
- **DESIGN** (line 240): All kernel findings use `Severity::Medium` uniformly. ASLR disabled is more critical than symlink protection. `KERNEL_PARAMS` uses bare tuples without a severity field — should be a struct like the other plugins. Deferred.
