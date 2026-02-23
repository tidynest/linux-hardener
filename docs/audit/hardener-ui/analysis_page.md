# hardener-ui::pages::analysis_page
**File:** `crates/hardener-ui/src/pages/analysis_page.rs` | **Lines:** 108

## Purpose
Tabbed analysis interface with Findings and Compliance tabs. Includes scan trigger button
and finding count badge in the tab header.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `AnalysisPage` | component | Two-tab layout (Findings/Compliance) with scan button and finding count |

## Internal Details
| Item | Description |
|------|-------------|
| Tab bar | Uses `TabBar`/`TabPanel` components from `tabs` module |
| Scan button | Calls `invoke_scan()`, updates `AppState.scan_results` on completion |
| Finding badge | Reactive count derived from `AppState.scan_results` signal length |

## Flags
None.
