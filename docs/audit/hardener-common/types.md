# hardener-common::types
**File:** `crates/hardener-common/src/types.rs` | **Lines:** 10

## Purpose
Re-export shim — forwards types from `hardener-types` for backwards compatibility.

## Dependencies
- Imports from: `hardener-types` — all shared DTOs
- Used by: crates that import `hardener_common::types::*` instead of `hardener_types` directly

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ComplianceFramework` | re-export | Compliance framework identifier |
| `ComplianceMapping` | re-export | Maps findings to framework controls |
| `ControlStatus` | re-export | Pass/Fail/NotApplicable |
| `FindingCategory` | re-export | Category of security finding |
| `FindingPolicyException` | re-export | Policy exception for a finding |
| `PluginId` | re-export | Unique plugin identifier |
| `Severity` | re-export | Finding severity level |

## Flags
None — pure re-exports, no logic.
