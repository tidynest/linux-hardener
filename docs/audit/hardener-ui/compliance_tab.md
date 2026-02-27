# hardener-ui::components::compliance_tab
**File:** `crates/hardener-ui/src/components/compliance_tab.rs` | **Lines:** 239

## Purpose
Framework selection checkboxes and compliance report generation. Supports CIS, STIG, NIST,
PCI-DSS, HIPAA, and GDPR frameworks. Displays detailed score cards with control-level
pass/fail breakdowns and export options for generated reports.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ComplianceTab` | component | Framework selection, report generation trigger, score cards, and export |

## Internal Details
| Item | Description |
|------|-------------|
| Framework checkboxes | Six toggles for CIS, STIG, NIST, PCI-DSS, HIPAA, GDPR |
| Generate button | Calls `invoke_generate_report()` for each selected framework |
| Score cards | Renders `ComplianceReport` results with pass/fail/manual-review breakdown |
| Export | Calls `invoke_export_report()` with selected format (JSON, CSV, HTML) |

## Flags
None.
