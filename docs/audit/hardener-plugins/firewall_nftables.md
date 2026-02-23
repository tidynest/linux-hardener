# hardener-plugins::firewall::nftables
**File:** `crates/hardener-plugins/src/firewall/nftables.rs` | **Lines:** 314

## Purpose
Nftables firewall backend. Creates `inet filter` table with input/forward/output chains, parses `nft list ruleset` output, and applies rules via `nft add rule`.

## Dependencies
- Imports from: `crate::firewall::{FirewallBackend, Rule, get_baseline_rules}`, `hardener_common::error`, `hardener_core`
- Used by: `firewall/mod.rs` (detected as backend on Arch, Debian 10+, Ubuntu 20.04+)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `NftablesBackend` | struct | Unit struct implementing `FirewallBackend` |
| `::new()` | fn | Constructor |

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `execute_nft` | 35-50 | Runs `nft` command, checks exit status |
| `parse_nft_rule_line` | 58-102 | Parses one rule line → `Option<Rule>` |
| `build_nft_rule_args` | 108-156 | Converts `Rule` → nft args (special-cases loopback, established) |

## Flags
- **BUG** (line 130): Fixed — `ct state established` was missing `,related`. Without it, related connections (e.g., FTP data channels, ICMP replies) would be dropped.
- **TYPO** (line 204): Fixed — missing closing parenthesis in comment.
