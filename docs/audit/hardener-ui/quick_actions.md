# hardener-ui::components::quick_actions
**File:** `crates/hardener-ui/src/components/quick_actions.rs` | **Lines:** 99

## Purpose
Dashboard quick action buttons. Provides one-click scan, navigation to analysis,
and navigation to hardening configuration.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `QuickActions` | component | Three action buttons: Run Scan, View Analysis, Configure Hardening |

## Internal Details
| Item | Description |
|------|-------------|
| Run Scan | Triggers `invoke_scan()`, then auto-generates compliance reports for all 6 frameworks |
| View Analysis | Navigates to `/analysis` route |
| Configure Hardening | Navigates to `/hardening` route |
| Post-scan compliance | Iterates CIS, STIG, NIST, PCI-DSS, HIPAA, GDPR and calls `invoke_generate_report()` for each |

## Flags
None.
