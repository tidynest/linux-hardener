# hardener-plugins::mac
**File:** `crates/hardener-plugins/src/mac/mod.rs` | **Lines:** 523

## Purpose
Manages Mandatory Access Control (SELinux / AppArmor). Detection-first pattern: probes `/sys/fs/selinux` and `/sys/kernel/security/apparmor` to discover which MAC system is present, then branches into system-specific logic.

## Dependencies
- Imports from: `hardener_common::error`, `hardener_common::types`, `hardener_core::plugin`, `hardener_core::Context`
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `MacSystem` | enum | `SELinux` / `AppArmor` |
| `MacHardeningPlugin` | struct | Zero-field plugin implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Detects MAC system → checks mode (SELinux) or profile counts (AppArmor) |
| `HardeningPlugin::apply` | async fn | Checkpoint → `setenforce 1` (SELinux) or advisory change (AppArmor) |
| `HardeningPlugin::rollback` | async fn | Restores checkpoint files, attempts to reload MAC policy |
| `HardeningPlugin::validate` | async fn | Checks MAC tool availability (`getenforce` / `aa-status`) |

## Data Flow
`scan()` → `detect_mac_system()` → branch:
- SELinux: `getenforce` → compare to "Enforcing"
- AppArmor: `aa-status --verbose` → parse enforce/complain counts
- None: finding "no MAC system"

`apply()` → checkpoint → branch:
- SELinux: `setenforce 1`
- AppArmor: advisory only (no automatic profile enforcement)

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `detect_mac_system` | 57-82 | Checks `/sys/fs/selinux` then `/sys/kernel/security/apparmor` |
| `get_selinux_mode` | 87-103 | `getenforce` → "Enforcing"/"Permissive"/"Disabled" |
| `set_selinux_enforcing` | 106-140 | `setenforce 1`, returns Change |
| `get_apparmor_status` | 145-160 | `aa-status --verbose` → raw output |
| `count_apparmor_profiles` | 165-187 | Parses aa-status for enforce/complain/total counts |
| `get_mac_compliance_mappings` | 191-215 | CIS 1.6.1.x mappings |

## Flags
- **SEMANTIC** (line 399-407): Fixed — `change_error` was set to an instruction string on a `change_success: true` entry. Moved instruction to `change_description`, set `change_error: None`.
- **DESIGN** (line 446-448): Rollback blindly runs `setenforce 1` regardless of the checkpoint's original SELinux mode. Should read checkpoint config to determine correct mode. Deferred.
