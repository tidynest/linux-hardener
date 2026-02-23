# hardener-ui::components::compliance_tab
**File:** `crates/hardener-ui/src/components/compliance_tab.rs` | **Lines:** 183

## Purpose
Framework selection checkboxes and compliance report generation. Supports CIS, STIG, NIST,
PCI-DSS, HIPAA, and GDPR frameworks. Displays score cards for generated reports.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ComplianceTab` | component | Framework selection, report generation trigger, and score card results |

## Internal Details
| Item | Description |
|------|-------------|
| Framework checkboxes | Six toggles for CIS, STIG, NIST, PCI-DSS, HIPAA, GDPR |
| Generate button | Calls `invoke_generate_report()` for each selected framework |
| Score cards | Renders `FrameworkScore` results with colour-coded pass/fail indicators |

## Flags
None.
