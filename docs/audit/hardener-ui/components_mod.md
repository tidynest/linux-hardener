# hardener-ui::components::mod
**File:** `crates/hardener-ui/src/components/mod.rs` | **Lines:** 46

## Purpose
Component module root. Declares and re-exports all 22 UI components for use
by page modules and the root `App` component.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| (re-exports) | `pub use` | All 22 component structs/functions re-exported |

## Re-exported Components
`Card`, `CardVariant`, `HeadingLevel`, `ComplianceTab`, `ConfigFileCard`,
`ConfigureSection`, `FindingDetail`, `FindingsGrid`, `FindingsTab`,
`HistorySection`, `HostForm`, `HostList`, `MiniSecurityScore`,
`NotificationSection`, `QuickActions`, `RecentActivity`, `RemoteStatus`,
`ScanHistoryTab`, `ScheduleSection`, `SecurityScore`, `SeverityBadge`,
`TabBar`, `TabDef`, `TabPanel`, `ThemeToggle`

## Internal Details
| Item | Description |
|------|-------------|
| `#[allow(unused_imports)]` | On `CardVariant` re-export — exported for API completeness |
| `form_helpers` | Shared JsCast event extraction (not re-exported — used internally by components) |

## Flags
None.
