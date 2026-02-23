# hardener-plugins::firewall::ufw
**File:** `crates/hardener-plugins/src/firewall/ufw.rs` | **Lines:** 259

## Purpose
UFW (Uncomplicated Firewall) backend for Ubuntu/Debian. Uses `ufw` CLI with English-like syntax. Detection via `command_exists("ufw")`, status check via `systemctl is-active ufw` (non-root friendly) with fallback to `ufw status`.

## Dependencies
- Imports from: `crate::firewall::{FirewallBackend, Rule, get_baseline_rules}`, `hardener_common::error`, `hardener_core`
- Used by: `firewall/mod.rs` (detected second in priority order)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `UfwBackend` | struct | Unit struct implementing `FirewallBackend` |
| `::new()` | fn | Constructor |

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `execute_ufw` | 28-42 | Runs `ufw` command, checks exit status |
| `parse_ufw_rule_line` | 47-85 | Parses `"22/tcp  Allow  Anywhere"` → `Rule` |
| `build_ufw_rule_args` | 91-123 | Converts `Rule` → ufw args (`allow from ... to any port ... proto ...`) |

## Flags
- **SILENT FAILURE** (lines 246-248): Fixed — failed rule application only logged a warning without pushing a `Change`. Failures are now tracked in the changes list.
