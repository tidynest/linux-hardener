# hardener-plugins::firewall::firewalld
**File:** `crates/hardener-plugins/src/firewall/firewalld.rs` | **Lines:** 281

## Purpose
Firewalld backend for RHEL/Fedora/CentOS. Zone-based rule management using `firewall-cmd`. All rule changes are `--permanent` with a final `--reload`.

## Dependencies
- Imports from: `crate::firewall::{FirewallBackend, Rule, get_baseline_rules}`, `hardener_common::error`, `hardener_core`
- Used by: `firewall/mod.rs` (detected first in priority order)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `FirewalldBackend` | struct | Unit struct implementing `FirewallBackend` |
| `::new()` | fn | Constructor |

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `execute_firewall_cmd` | 25-42 | Runs `firewall-cmd`, checks exit status |
| `get_default_zone` | 47-52 | `firewall-cmd --get-default-zone` |

## Data Flow
`apply_rules()` → skip loopback/established (firewalld handles implicitly) → `--set-target=DROP` for deny-all → `--add-port` for accept rules → `--reload`

## Flags
- **SEMANTIC** (line 241): Fixed — failure `change_description` said "Added port" instead of "Failed to add port".
