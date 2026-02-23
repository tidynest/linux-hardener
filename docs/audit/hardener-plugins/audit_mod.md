# hardener-plugins::audit
**File:** `crates/hardener-plugins/src/audit/mod.rs` | **Lines:** 808

## Purpose
Configures Linux auditd rules for system monitoring and compliance. Table-driven: a `const AUDIT_RULES` array is the single source of truth for scan, apply, and validate.

## Dependencies
- Imports from: `hardener_common::error`, `hardener_common::types`, `hardener_core::plugin` (trait + DTOs), `hardener_core::context::Context`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `AuditHardeningPlugin` | struct | Zero-field plugin implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Checks auditd installed/enabled/running, then matches each rule by category |
| `HardeningPlugin::apply` | async fn | Creates checkpoint, enables/starts auditd, writes rules file, reloads via augenrules |
| `HardeningPlugin::rollback` | async fn | Restores checkpoint files, reloads rules |
| `HardeningPlugin::validate` | async fn | Dry-run: counts missing rules, checks auditd prerequisites |

## Data Flow
`scan()` → `is_auditd_installed/enabled/running` → `read_current_audit_rules(auditctl -l)` → match each `AUDIT_RULES` entry by category → `Vec<Finding>`

`apply()` → checkpoint → enable/start auditd → build rules string from `AUDIT_RULES` → `write_audit_rules_file()` (backup + write) → `reload_audit_rules()` (augenrules --load, fallback systemctl restart)

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `is_auditd_installed` | 242-247 | `command_exists("auditd")` |
| `is_auditd_enabled` | 250-256 | `systemctl is-enabled auditd` |
| `is_auditd_running` | 259-265 | `systemctl is-active auditd` |
| `read_current_audit_rules` | 278-301 | `auditctl -l`, returns `Rules(Vec)` or `PermissionDenied` |
| `write_audit_rules_file` | 304-337 | Backup existing, mkdir -p, write content |
| `reload_audit_rules` | 346-378 | `augenrules --load`, fallback `systemctl restart` |
| `get_audit_compliance_mappings` | 381-403 | CIS control IDs per finding type |

## Flags
- **DESIGN** (line 504-507): Rule matching uses category name (`contains(category)`), not exact content. One existing `time-change` rule masks all 4 expected rules — latent false-negative in scan.
- **TYPO** (line 398): Fixed — double space in compliance title.
- **TYPO** (line 449): Fixed — "pint" → "point".
- **TYPO** (line 464): Fixed — "enable" → "enabled".
- **STYLE** (line 520): Fixed — `replace("-", "_")` → `replace('-', "_")` (char pattern).
