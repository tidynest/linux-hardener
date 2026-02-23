# hardener-plugins::pam
**File:** `crates/hardener-plugins/src/pam/mod.rs` | **Lines:** 661

## Purpose
Hardens PAM authentication: password quality (`pwquality.conf`), account lockout, and password ageing (`login.defs`). Table-driven via `PAM_DIRECTIVES` const array. PAM module config (`/etc/pam.d/`) is intentionally stubbed — too distribution-specific.

## Dependencies
- Imports from: `hardener_common::file_utils::parse_config_value` (config parsing), `hardener_core::plugin` (trait + DTOs), `hardener_core::Context`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PamHardeningPlugin` | struct | Zero-field plugin implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Reads pwquality.conf + login.defs, checks each directive against secure values |
| `HardeningPlugin::apply` | async fn | Checkpoint → backup → read configs → apply directives in-memory → write files |
| `HardeningPlugin::rollback` | async fn | Restores checkpoint files (no service restart needed — PAM is stateless) |
| `HardeningPlugin::validate` | async fn | Checks config file existence, estimates directive change count |

## Data Flow
`scan()` → read pwquality.conf + login.defs → `parse_config_value()` per directive → compare to `pam_secure_value` → `Vec<Finding>`

`apply()` → checkpoint → backup → read files → `apply_directive_to_content()` per directive (in-memory edit) → `write_file()` both configs

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `get_pam_compliance_mappings` | 42-72 | CIS 5.3.x mappings by check name |
| `read_pwquality_config` | 584-589 | Reads `/etc/security/pwquality.conf` |
| `read_login_defs` | 592-597 | Reads `/etc/login.defs` |
| `create_config_backup` | 600-616 | Timestamped `cp` backup (legacy, alongside checkpoint) |
| `apply_directive_to_content` | 622-661 | In-memory find-and-replace or append for key=value directives |

## Flags
- **BUG** (line 386-389): Fixed — log format args were `(changes.len(), duration_ms, duration_ms)` instead of `(changes.len(), all_success, duration_ms)`.
- **TYPO** (line 5): Fixed — "lookout" → "lockout".
- **TYPO** (line 67): Fixed — double space in compliance title.
- **STUB** (line 124-131, 312-319): `PamAuth` variant skipped with debug log — intentional, PAM module editing is a phase 2 item.
