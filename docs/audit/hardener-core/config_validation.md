# hardener-core::config_validation
**File:** `crates/hardener-core/src/config_validation.rs` | **Lines:** 397 (250 prod, 147 test)

## Purpose
Defence-in-depth validation layer for `HardenerConfig` — rejects shell metacharacters, control characters, and format-invalid values before they reach plugin executors. Prevents command injection (CWE-78) and path traversal (CWE-22) at the configuration boundary.

## Dependencies
- Imports from: `crate::config::HardenerConfig`
- Used by: `hardener-cli::commands::apply` (pre-apply validation), `src-tauri::commands` (IPC validation)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `validate_config(config)` | fn | Validates all directive values across all plugins; collects all errors before returning |
| `validate_directive_key(plugin_id, key)` | fn | Validates key for safe characters; rejects path traversal attempts |

## Constants
| Name | Description |
|------|-------------|
| `SHELL_METACHARACTERS` | Forbidden chars: `;`, `` ` ``, `$`, `(`, `)`, `{`, `}`, `\|`, `&`, `\n`, `\r`, `\0` |

## Per-Plugin Validators
| Function | Lines | Rules |
|----------|-------|-------|
| `check_universal(value)` | 104-115 | Rejects shell metacharacters, control chars |
| `validate_kernel_value(key, value)` | 140-152 | Numeric sysctl values only |
| `validate_ssh_value(key, value)` | 155-163 | Single-line, non-empty, max 256 chars |
| `validate_firewall_value(key, value)` | 166-204 | Port ranges, protocols (tcp/udp/any), actions (accept/drop/reject), IP/CIDR |
| `validate_pam_value(key, value)` | 207-225 | Integers or alphanumeric tokens |
| `validate_permissions_value(key, value)` | 229-250 | Octal modes 3-4 digits; rejects SUID/SGID/world-writable/zero |

## Data Flow
```
validate_config(config) → for each plugin:
  → for each directive (key, value):
    → validate_directive_key(plugin_id, key) → reject path traversal
    → check_universal(value) → reject shell metacharacters
    → per-plugin validator (kernel/ssh/firewall/pam/permissions) → format-specific rules
  → collect all errors → return Ok(()) or Err(all errors joined)
```

## Tests
14 test functions covering universal validation, per-plugin validators, directive key validation, and full config validation with good/bad inputs.

## Flags
None — clean, security-critical module.
