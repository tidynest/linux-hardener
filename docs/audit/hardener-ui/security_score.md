# hardener-ui::components::security_score
**File:** `crates/hardener-ui/src/components/security_score.rs` | **Lines:** 218

## Purpose
Weighted scoring algorithm and display component. Converts scan findings into per-framework
and overall security scores using severity-based weighting.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SecurityScore` | component | Dashboard score display with circular progress indicators |
| `FrameworkScore` | struct | Score result: framework name, score (0–100), finding count |
| `calculate_all_scores` | fn | Computes scores across all frameworks from findings |
| `calculate_framework_score` | fn | Single framework score from its findings |
| `severity_to_weight` | fn | Maps `Severity` variant to numeric weight |

## Fixes Applied
| # | Description |
|---|-------------|
| 1 | Added `//!` module doc |
| 2 | `partial_cmp().unwrap()` → `.unwrap_or(Ordering::Equal)` for NaN safety in score sorting |
| 3 | Added `use std::cmp::Ordering` import |

## Flags
None — all issues resolved.
