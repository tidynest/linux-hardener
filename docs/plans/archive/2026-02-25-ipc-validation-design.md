# IPC Input Validation Layer Design

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Date:** 2026-02-25
**Resolves:** SAM-015, SAM-016, SAM-040, SAM-043, SAM-071, SAM-072, SAM-077, SAM-078

---

## Summary

Create a centralised input validation module (`src-tauri/src/validation.rs`) that validates all IPC parameters before they reach `pkexec`, filesystem operations, or SSH connections. Standalone validator functions return `Result<T, String>`, matching the existing error pattern in Tauri commands.

## Design Decisions

1. **Module location:** `src-tauri/src/validation.rs` -- separate file, imported into `commands.rs`
2. **Error type:** `Result<T, String>` -- consistent with existing Tauri command signatures
3. **Path strictness:** Strict allowlist for privileged paths (pkexec), deny-dangerous for user-level paths
4. **Approach:** Standalone validator functions + shared internal helpers (no newtypes, no custom Deserialize)

## Module Structure

### Constants

```rust
const MAX_IPC_STRING_LEN: usize = 4096;
const MAX_CHECKPOINT_NAME_LEN: usize = 255;

const KNOWN_PLUGIN_IDS: &[&str] = &[
    "audit-hardening", "firewall-hardening", "kernel-hardening",
    "mac-hardening", "pam-hardening", "permissions-hardening",
    "services-hardening", "ssh-hardening",
];
```

### Public Validators

| Function | Purpose | Returns |
|----------|---------|---------|
| `validate_ipc_string(s, field_name)` | Reject control chars, enforce max length | `Result<(), String>` |
| `validate_plugin_ids(ids)` | Check against static plugin allowlist | `Result<(), String>` |
| `validate_checkpoint_id(id)` | Match `cp_<digits>_<8hex>` format | `Result<(), String>` |
| `validate_checkpoint_name(name)` | 1-255 chars, alphanumeric + space/hyphen/underscore | `Result<(), String>` |
| `validate_privileged_config_path(path)` | Strict allowlist: `/etc/linux-hardener/`, `~/.config/linux-hardener/` | `Result<PathBuf, String>` |
| `validate_user_config_path(path)` | Deny-dangerous + require `.toml` extension | `Result<PathBuf, String>` |
| `validate_output_path(path)` | Allow `~/Documents/`, `~/Downloads/`, `/tmp/`, XDG dirs | `Result<PathBuf, String>` |
| `validate_ssh_key_path(path)` | Restrict to `~/.ssh/` | `Result<PathBuf, String>` |

### Internal Helpers

```rust
fn reject_path_traversal(path: &Path) -> Result<(), String>
fn is_dangerous_path(path: &Path) -> bool
```

## Command Integration

Each `#[tauri::command]` calls validators at the top before any logic.

| Command | Validators Applied |
|---------|-------------------|
| `run_scan` | `validate_plugin_ids`, `validate_user_config_path` |
| `run_apply` | `validate_plugin_ids`, `validate_privileged_config_path` |
| `run_apply_dry_run` | `validate_plugin_ids`, `validate_user_config_path` |
| `run_rollback` | `validate_checkpoint_id`, `validate_privileged_config_path` |
| `create_checkpoint` | `validate_checkpoint_name` |
| `delete_checkpoint` | `validate_checkpoint_id` |
| `get_checkpoint_detail` | `validate_checkpoint_id` |
| `get_scan_session` | `validate_ipc_string` |
| `export_compliance_report` | `validate_output_path`, `validate_ipc_string` |
| `validate_config` | `validate_user_config_path` |
| `save_scheduler_config` | `validate_ipc_string` on string fields |
| `save_remote_host` | `validate_ssh_key_path`, `validate_ipc_string` |
| `connect_remote` | `validate_ipc_string` |

## Argument Separator

Insert `"--"` before positional arguments in commands passed to `run_privileged_command`:

- `run_rollback`: `["rollback", "--format", "json", "--", &checkpoint_id]`
- `create_checkpoint`: `["checkpoint", "create", "--format", "json", "--", &name]`

Not applied globally in `run_privileged_command` because `run_apply` uses only flags (no positional args).

## Path Validation Strategy

**Privileged paths** (flow to pkexec as root):
- Canonicalise, reject `..` segments, reject symlinks outside allowed dirs
- Allowlist: `/etc/linux-hardener/`, `~/.config/linux-hardener/`

**User paths** (run as current user):
- Deny-dangerous: reject `/proc/`, `/sys/`, `/dev/`, dotfiles (`.ssh/`, `.bashrc`, `.gnupg/`)
- Require `.toml` extension for config paths

**Output paths** (file write as current user):
- Allow: `~/Documents/`, `~/Downloads/`, `/tmp/`, XDG user dirs
- Canonicalise parent directory (file may not exist yet)
- Reject: dotfiles, system directories, hidden directories

**SSH key paths:**
- Canonicalise, verify inside `~/.ssh/`, reject symlinks escaping

## Testing

Each validator gets unit tests covering happy paths and attack cases:
- Control characters, oversized strings, empty strings
- Path traversal (`../../../etc/shadow`)
- Argument injection (`--config`, `--format`)
- Shell metacharacters (`$(rm -rf)`, backticks, pipes)
- Boundary lengths (0, 1, 255, 256)

## Findings Closed

| SAM-ID | Resolution |
|--------|-----------|
| SAM-015 | Plugin IDs, checkpoint IDs/names validated; `--` separator |
| SAM-016 | Config path restricted for privileged commands |
| SAM-040 | Output path restricted to safe directories |
| SAM-043 | SSH key_file restricted to `~/.ssh/` |
| SAM-071 | validate_config uses user-level path validation |
| SAM-072 | save_scheduler_config fields validated |
| SAM-077 | Dry-run validates plugin_ids and config_path |
| SAM-078 | Checkpoint name validated for length/content |

## Out of Scope

- SAM-017: Binary path TOCTOU (separate fix)
- SAM-044: Rate limiting on pkexec (separate fix)
- SAM-041: Mutex deadlock risk (separate fix)
