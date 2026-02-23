# hardener-plugins::ssh
**File:** `crates/hardener-plugins/src/ssh/mod.rs` | **Lines:** 620

## Purpose
Hardens OpenSSH server configuration (`sshd_config`). Table-driven via `SSH_DIRECTIVES`. The "pilot plugin" for the config system — the only plugin that consumes `PluginConfig.directives` (value overrides) and `PluginConfig.has_valid_exception()` (skip rules with documented reason).

## Dependencies
- Imports from: `hardener_common::file_utils::{parse_config_value, set_config_directive}`, `hardener_core::plugin`, `hardener_core::Context`, `chrono::Utc`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SshHardeningPlugin` | struct | Unit struct implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Reads sshd_config, compares each directive to secure value |
| `HardeningPlugin::apply` | async fn | Checkpoint → backup → read → apply directives (with exception/override support) → write → restart sshd |
| `HardeningPlugin::rollback` | async fn | Restores checkpoint files, restarts sshd |
| `HardeningPlugin::validate` | async fn | Checks config file accessibility, estimates directive changes |

## Data Flow
`apply()` → checkpoint → `cp -p` backup → read sshd_config → for each directive: check exception → resolve target value (config override or baseline) → `set_config_directive()` → `write_file()` → `restart_ssh_service()` (systemctl, fallback service)

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `restart_ssh_service` | 117-157 | `systemctl restart sshd`, fallback `service ssh restart` |
| `get_ssh_compliance_mappings` | 161-207 | CIS 5.2.x mappings per directive name |

## Flags
- **BUG** (line 172): Fixed — PasswordAuthentication compliance title incorrectly said "PermitEmptyPasswords" (copy-paste).
- **STYLE** (line 5): Fixed — inconsistent indentation in module doc.
- **COSMETIC** (line 380): Fixed — duplicate "Step 3" comment numbering, renumbered 4/5/6.
