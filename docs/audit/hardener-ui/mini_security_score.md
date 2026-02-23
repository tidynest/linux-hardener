# hardener-ui::components::mini_security_score
**File:** `crates/hardener-ui/src/components/mini_security_score.rs` | **Lines:** 52

## Purpose
Compact score badge for page headers. Reuses `calculate_all_scores()` from the
`security_score` module and applies colour coding based on score thresholds.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `MiniSecurityScore` | component | Compact colour-coded score badge |

## Internal Details
| Item | Description |
|------|-------------|
| Score source | Calls `calculate_all_scores()` with current `AppState.scan_results` |
| Colour coding | green (good, >=80), amber (warning, >=50), red (critical, <50), grey (pending, no data) |

## Flags
None.
