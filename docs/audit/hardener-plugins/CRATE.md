# hardener-plugins Audit Summary
**Crate:** `crates/hardener-plugins` | **Files:** 13 | **Lines:** ~5,947

## Architecture
Largest crate — directly mutates system configuration via 8 hardening plugins implementing `HardeningPlugin` trait. Each plugin follows a table-driven pattern with const arrays defining rules/directives. Firewall uses a strategy pattern with 3 backends (nftables, firewalld, ufw).

## Per-File Documentation
| File | Lines | Doc |
|------|-------|-----|
| `audit/mod.rs` | 808 | [audit_mod.md](audit_mod.md) |
| `pam/mod.rs` | 661 | [pam_mod.md](pam_mod.md) |
| `ssh/mod.rs` | 620 | [ssh_mod.md](ssh_mod.md) |
| `mac/mod.rs` | 523 | [mac_mod.md](mac_mod.md) |
| `kernel/mod.rs` | 480 | [kernel_mod.md](kernel_mod.md) |
| `services/mod.rs` | 453 | [services_mod.md](services_mod.md) |
| `permissions/mod.rs` | 423 | [permissions_mod.md](permissions_mod.md) |
| `firewall/mod.rs` | 419 | [firewall_mod.md](firewall_mod.md) |
| `firewall/nftables.rs` | 314 | [firewall_nftables.md](firewall_nftables.md) |
| `firewall/firewalld.rs` | 281 | [firewall_firewalld.md](firewall_firewalld.md) |
| `firewall/ufw.rs` | 259 | [firewall_ufw.md](firewall_ufw.md) |
| `lib.rs` | 170 | [lib.md](lib.md) |
| `macros.rs` | 81 | [macros.md](macros.md) |

## Fixes Applied (27)
| # | File | Line | Severity | Fix |
|---|------|------|----------|-----|
| 1 | audit/mod.rs | 398 | Typo | Double space in compliance title |
| 2 | audit/mod.rs | 449 | Typo | "pint" → "point" |
| 3 | audit/mod.rs | 464 | Typo | "enable" → "enabled" |
| 4 | audit/mod.rs | 520 | Style | `replace("-", "_")` → `replace('-', "_")` |
| 5 | pam/mod.rs | 5 | Typo | "lookout" → "lockout" |
| 6 | pam/mod.rs | 67 | Typo | Double space in compliance title |
| 7 | pam/mod.rs | 386-389 | Bug | Wrong format args in log (duration printed twice, success missing) |
| 8 | ssh/mod.rs | 5 | Typo | Extra leading space in module doc |
| 9 | ssh/mod.rs | 172 | Semantic | Wrong compliance title "PermitEmptyPasswords" → "PasswordAuthentication" |
| 10 | ssh/mod.rs | 380 | Semantic | Duplicate step numbering (3,3,4,5 → 3,4,5,6) |
| 11 | mac/mod.rs | 399-407 | Semantic | `change_success: true` with `change_error` set — moved instruction to description |
| 12 | kernel/mod.rs | 159-164 | Semantic | Wrong CIS mapping: "core dumps" → "filesystem hardening" for hardlinks/symlinks |
| 13 | kernel/mod.rs | 274 | Dead code | Removed shadowed `use std::path::Path` import |
| 14 | services/mod.rs | 207 | Style | `replace("-", "_")` → `replace('-', "_")` |
| 15 | services/mod.rs | 239 | Dead code | Removed unused `let _start = Instant::now()` |
| 16 | permissions/mod.rs | 7 | Typo | Period → comma in module doc |
| 17-20 | permissions/mod.rs | 163,171,179,187 | Bug | Embedded newlines in 4 compliance title strings |
| 21 | firewall/mod.rs | 188 | Semantic | Error message missing "firewalld" from checked backends list |
| 22 | firewall/mod.rs | 29 | Typo | Stale "finding_description" in doc comment |
| 23 | firewall/nftables.rs | 130 | Bug | `ct state established` missing `,related` — drops ICMP replies, FTP data |
| 24 | firewall/nftables.rs | 204 | Typo | Missing closing parenthesis in comment |
| 25 | firewall/firewalld.rs | 241 | Semantic | Failure description said "Added port" instead of "Failed to add port" |
| 26 | firewall/ufw.rs | 246-248 | Bug | Failed rule application only logged warning — no `Change` pushed |
| 27 | lib.rs | 103-108 | Style | `#[doc(hidden)]` scope covered plugin re-exports instead of macro-support crates |
| 28 | macros.rs | 46 | Bug | Unqualified `PluginId` — would break any non-empty `dependencies` list |

## Design Flags (deferred)
| # | File | Issue |
|---|------|-------|
| D1 | audit/mod.rs | Scan matches rules by category name, not exact content — one existing rule masks all others |
| D2 | mac/mod.rs | Rollback blindly runs `setenforce 1` regardless of checkpoint's original SELinux mode |
| D3 | kernel/mod.rs | Uniform `finding_impact` wording describes effort ("minor change") not impact |
| D4 | kernel/mod.rs | All 6 params use `Severity::Medium` — should vary (e.g., ASLR = High) |
| D5 | services/mod.rs | `stop_service`/`disable_service`/`mask_service` don't check `output.success()` |
| D6 | permissions/mod.rs | `_permission_owner`/`_permission_group` fields in `PERMISSION_CHECKS` are never used |
| D7 | permissions/mod.rs | Uniform "Low" impact text for all 4 checks |
| D8 | lib.rs | `let _ = registry.register(...)` silently discards registration errors |
| D9 | macros.rs | `todo!()` stubs panic at runtime — scaffolding only |
