# hardener-ui::pages::hardening_page
**File:** `crates/hardener-ui/src/pages/hardening_page.rs` | **Lines:** 71

## Purpose
Section toggle between Configure and History views. Shows an indicator dot on the
History tab when apply results exist.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HardeningPage` | component | Two-section layout: Configure and History with toggle navigation |

## Internal Details
| Item | Description |
|------|-------------|
| Section toggle | Signal-driven switch between `ConfigureSection` and `HistorySection` |
| Indicator dot | Reactive — visible when `AppState.apply_results` is non-empty |

## Flags
None.
