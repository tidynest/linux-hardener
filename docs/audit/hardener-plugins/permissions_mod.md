# hardener-plugins::permissions
**File:** `crates/hardener-plugins/src/permissions/mod.rs` | **Lines:** 423

## Purpose
Audits and secures critical file/directory permissions. Table-driven via `CRITICAL_PERMISSIONS` (5 paths). Uses metadata-only checkpoints (no content snapshots) since only mode bits matter. Post-chmod verify catches vfat/FAT32 silent no-ops.

## Dependencies
- Imports from: `hardener_common::error`, `hardener_common::types`, `hardener_core::plugin`, `hardener_core::Context`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PermissionsHardeningPlugin` | struct | Zero-field plugin implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Reads mode bits from each path, compares to expected |
| `HardeningPlugin::apply` | async fn | Metadata-only checkpoint → `chmod` each path → post-verify |
| `HardeningPlugin::rollback` | async fn | Restores checkpoint (permissions only, no content) |
| `HardeningPlugin::validate` | async fn | Checks path readability, estimates permission changes |

## Data Flow
`scan()` → for each `CRITICAL_PERMISSIONS`: `file_metadata()` → `mode & 0o777` → compare to `permission_mode` → `Finding`

`apply()` → `create_checkpoint_metadata_only_for_apply()` → for each: `chmod` → re-read metadata to verify

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `check_path_permissions` | 113-155 | Checks one path, returns `Option<Finding>` |
| `get_permissions_compliance_mappings` | 158-194 | CIS 6.1.x mappings per path |
| `apply_path_permissions` | 199-275 | chmod + post-verify, returns `Option<Change>` |

## Flags
- **TYPO** (line 7): Fixed — period instead of comma in module doc (`/etc/ssh. /etc/sudoers`).
- **FORMAT** (lines 163, 171, 179, 187): Fixed — compliance titles had embedded newlines producing garbled output.
- **DESIGN** (lines 53-54): `_permission_owner`/`_permission_group` are dead fields — apply only runs `chmod`, never `chown`. Either wire up ownership enforcement or remove. Deferred.
- **DESIGN** (line 141): `finding_impact` is uniformly "Low" regardless of severity — wrong for `/etc/sudoers` (Critical). Should vary per path. Deferred.
