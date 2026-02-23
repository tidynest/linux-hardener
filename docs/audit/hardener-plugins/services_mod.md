# hardener-plugins::services
**File:** `crates/hardener-plugins/src/services/mod.rs` | **Lines:** 453

## Purpose
Identifies and disables unnecessary systemd services to reduce attack surface. Table-driven via `UNNECESSARY_SERVICES` (4 services). Most aggressive plugin: stop → disable → mask. Masking symlinks the unit to `/dev/null`, preventing even manual starts.

## Dependencies
- Imports from: `hardener_common::error`, `hardener_common::types`, `hardener_core::plugin`, `hardener_core::Context`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ServicesHardeningPlugin` | struct | Zero-field plugin implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Checks each service: exists → enabled/active → finding |
| `HardeningPlugin::apply` | async fn | Checkpoint → stop → disable → mask for each active/enabled service |
| `HardeningPlugin::rollback` | async fn | Restores checkpoint files, `systemctl daemon-reload` |
| `HardeningPlugin::validate` | async fn | Checks systemctl availability, lists services that would be disabled |

## Data Flow
`apply()` → checkpoint → for each `UNNECESSARY_SERVICES`: `is_service_exists` → `is_service_enabled`/`is_service_active` → `stop_service` → `disable_service` → `mask_service`

`rollback()` → `rollback_files_from_checkpoint()` → `systemctl daemon-reload`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `get_service_compliance_mappings` | 42-64 | CIS 2.x mappings per service name |
| `is_service_exists` | 101-108 | `systemctl list-unit-files <name>` |
| `is_service_enabled` | 111-117 | `systemctl is-enabled <name>` |
| `is_service_active` | 120-126 | `systemctl is-active <name>` |
| `stop_service` | 129-134 | `systemctl stop <name>` |
| `disable_service` | 137-142 | `systemctl disable <name>` |
| `mask_service` | 145-150 | `systemctl mask <name>` |

## Flags
- **STYLE** (line 207): Fixed — `replace("-", "_")` → `replace('-', "_")`.
- **DEAD CODE** (line 239): Fixed — removed unused `_start` variable in `apply()`.
- **DESIGN** (lines 129-150): `stop_service`/`disable_service`/`mask_service` discard `CommandOutput` and return `Ok(())` even on non-zero exit. Only execution failure (e.g., command not found) propagates as error. Deferred.
