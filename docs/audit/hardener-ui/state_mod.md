# hardener-ui::state::mod
**File:** `crates/hardener-ui/src/state/mod.rs` | **Lines:** 98

## Purpose
Global application state. All reactive signals for scan results, apply results,
checkpoints, selected finding, error state, compliance data, remote scanning,
scheduler configuration, and config file management.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `AppState` | struct | 21 `RwSignal` fields — central reactive store for the entire UI |

## Fields
| Field | Type | Description |
|-------|------|-------------|
| `scan_results` | `RwSignal<Vec<ScanResult>>` | Current scan findings |
| `selected_finding` | `RwSignal<Option<Finding>>` | Currently selected finding for detail view |
| `severity_filter` | `RwSignal<Option<Severity>>` | Active severity filter |
| `apply_results` | `RwSignal<Vec<ApplyResult>>` | Last apply operation results |
| `rollback_result` | `RwSignal<Option<RollbackResult>>` | Last rollback operation result |
| `is_scanning` | `RwSignal<bool>` | Scan in progress |
| `is_applying` | `RwSignal<bool>` | Apply in progress |
| `is_previewing` | `RwSignal<bool>` | Dry-run preview in progress |
| `compliance_reports` | `RwSignal<Vec<ComplianceReport>>` | Generated compliance reports |
| `is_generating_report` | `RwSignal<bool>` | Report generation in progress |
| `preview_results` | `RwSignal<Vec<ValidationReport>>` | Dry-run preview results |
| `show_preview` | `RwSignal<bool>` | Whether preview panel is visible |
| `error_message` | `RwSignal<String>` | Error message text |
| `remote_hosts` | `RwSignal<Vec<RemoteHostProfile>>` | Configured remote hosts |
| `remote_connection` | `RwSignal<Option<RemoteConnectionInfo>>` | Active remote connection |
| `remote_scan_results` | `RwSignal<Vec<ScanResult>>` | Remote scan findings |
| `is_connecting` | `RwSignal<bool>` | SSH connection in progress |
| `is_remote_scanning` | `RwSignal<bool>` | Remote scan in progress |
| `scheduler_config` | `RwSignal<Option<SchedulerUiConfig>>` | Scheduler configuration |
| `is_saving_scheduler` | `RwSignal<bool>` | Scheduler save in progress |
| `is_testing_notification` | `RwSignal<bool>` | Notification test in progress |
| `config_path` | `RwSignal<Option<String>>` | Selected config file path |
| `config_summary` | `RwSignal<Option<ConfigSummary>>` | Config file validation summary |

## Internal Details
| Item | Description |
|------|-------------|
| `Default` impl | Empty collections, `false` booleans, `None` options, empty strings |
| Derives | `Clone + Copy` — all fields are `RwSignal` (cheap copy) |

## Flags
None.
