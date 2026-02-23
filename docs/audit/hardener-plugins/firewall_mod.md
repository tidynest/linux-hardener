# hardener-plugins::firewall
**File:** `crates/hardener-plugins/src/firewall/mod.rs` | **Lines:** 419

## Purpose
Coordinator plugin for firewall hardening using the strategy pattern. Detects which backend is available (firewalld → ufw → nftables) and delegates all operations. Defines `FirewallBackend` trait and backend-agnostic `Rule` struct.

## Dependencies
- Imports from: `hardener_common::error`, `hardener_common::types`, `hardener_core::plugin`, `hardener_core::Context`
- Submodules: `firewalld`, `nftables`, `ufw` (each implements `FirewallBackend`)
- Used by: `lib.rs` (re-exported), CLI scan/apply/rollback commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Rule` | struct | Backend-agnostic firewall rule (protocol, port, source, action) |
| `FirewallBackend` | trait | `detect`, `is_enabled`, `enable`, `list_rules`, `apply_rules`, `get_default_rules` |
| `get_baseline_rules()` | fn | Returns 4 default rules: loopback, established, SSH, drop-all |
| `FirewallHardeningPlugin` | struct | Coordinator implementing `HardeningPlugin` |
| `::new()` | fn | Constructor |
| `HardeningPlugin::scan` | async fn | Detect backend → check if enabled → finding if disabled |
| `HardeningPlugin::apply` | async fn | Checkpoint → detect → enable → apply default rules |
| `HardeningPlugin::rollback` | async fn | Restore checkpoint → re-enable backend |
| `HardeningPlugin::validate` | async fn | Detect backend → check enabled → estimate rule count |

## Data Flow
`detect_backend()` → try firewalld → ufw → nftables → `Box<dyn FirewallBackend>`

`apply()` → checkpoint → `detect_backend()` → `is_enabled()` → `enable()` → `get_default_rules()` → `apply_rules()`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `detect_backend` | 164-190 | Tries firewalld/ufw/nftables in order |
| `get_firewall_compliance_mappings` | 86-93 | CIS 3.4.1.2 |
| `get_baseline_rules` | 102-133 | 4 default rules (loopback, established, SSH, drop-all) |

## Flags
- **BUG** (line 188): Fixed — error message omitted "firewalld" from list of checked backends.
- **TYPO** (line 29): Fixed — stale `finding_description` in doc comment from a field rename.
