# Remote Scanning UI — Design Document

**Date:** 2026-02-24
**Version:** v0.4.0 (P3 feature)
**Scope:** GUI for scanning remote hosts via SSH

---

## Summary

Add a dedicated "Remote" page to the Tauri/Leptos GUI that lets users manage saved SSH host profiles, connect to remote machines, and run security scans over SSH. Results display using the same findings components as local scans.

**Scope boundaries:**
- Scan only (no remote apply/rollback)
- Key file + SSH agent authentication (no password auth)
- One active connection at a time (no concurrent multi-host)
- Results live in reactive signals (no DB persistence for remote scans)
- No remote compliance report generation

All of the above are deliberate YAGNI cuts. The architecture supports adding them later without refactoring.

---

## Architecture

### Approach: Tauri-side connection

The Tauri backend holds an `SshExecutor` in managed state. The GUI sends connection details via IPC, Tauri connects and holds the session, then runs scans through it.

```
WASM/Leptos  →  Tauri IPC  →  SshExecutor (in-process)
                               ↕
                            Remote Host
```

Why this over CLI subprocess spawning:
- SSH session persists across operations (connect once, scan many times)
- Full access to `SystemExecutor` trait — reuses existing scan pipeline directly
- No pkexec needed (SSH auth handles privilege on the remote side)
- Connection status visible in real-time

---

## Host Profile Storage

Profiles stored as TOML in `~/.config/linux-hardener/hosts.toml`. This is configuration data, not transactional — TOML is human-editable and requires no DB migration.

```toml
[[hosts]]
name = "web-01"
hostname = "192.168.1.10"
user = "root"
port = 22
key_file = "/home/user/.ssh/id_ed25519"
host_key_checking = true

[[hosts]]
name = "db-01"
hostname = "db.internal.lan"
user = "admin"
port = 2222
# key_file omitted → uses SSH agent
host_key_checking = true
```

### Rust type (in `hardener-types`)

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RemoteHostProfile {
    pub name: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: u16,
    pub key_file: Option<String>,
    pub host_key_checking: bool,
}
```

### TOML wrapper

```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostsConfig {
    #[serde(default)]
    pub hosts: Vec<RemoteHostProfile>,
}
```

---

## Tauri State & IPC Commands

### Managed state

```rust
pub struct RemoteState {
    active_connection: Mutex<Option<ActiveConnection>>,
    profiles: Mutex<Vec<RemoteHostProfile>>,
}

struct ActiveConnection {
    executor: Arc<SshExecutor>,
    profile_name: String,
}
```

### IPC commands (6 total)

| Command | Signature | Purpose |
|---------|-----------|---------|
| `list_remote_hosts` | `() → Vec<RemoteHostProfile>` | Load saved profiles from TOML |
| `save_remote_host` | `(profile: RemoteHostProfile) → ()` | Add or update a host profile (upsert by name) |
| `delete_remote_host` | `(name: String) → ()` | Remove a host profile |
| `connect_remote` | `(name: String) → RemoteConnectionStatus` | SSH connect to a saved host |
| `disconnect_remote` | `() → ()` | Close active SSH session |
| `run_remote_scan` | `(pluginIds: Option<Vec<String>>) → Vec<ScanResult>` | Scan via active SSH connection |

### Connection status type (in `hardener-types`)

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoteConnectionStatus {
    Connected { host: String, user: String },
    Failed { error: String },
}
```

### Key implementation detail

`run_remote_scan` reuses the identical `PluginManager::scan()` pipeline as local scans. The only difference is the executor passed into `Context`:

```rust
// Local scan (existing)
let ctx = Context::with_executor(Arc::new(LocalExecutor::new()));

// Remote scan (new)
let ctx = Context::with_executor(active_connection.executor.clone());
```

Scan results are `Vec<ScanResult>` — identical format. Existing findings rendering works unchanged.

---

## GUI Page Layout

New route: `/remote` — fourth top-level navigation item.

```
┌─────────────────────────────────────────────────────┐
│  Remote Scanning                                     │
├──────────────────┬──────────────────────────────────┤
│  Saved Hosts     │  Right panel (state-dependent)   │
│                  │                                   │
│  ┌────────────┐  │  A: No connection                 │
│  │ web-01     │  │     "Select a host or add a       │
│  │ root@192.. │  │      new one to get started."     │
│  │ [Connect]  │  │                                   │
│  ├────────────┤  │  B: Connected                     │
│  │ db-01      │  │     "Connected: root@192.168..."  │
│  │ admin@db.. │  │     [Run Scan] [Disconnect]       │
│  │ [Connect]  │  │     (scan results table)          │
│  ├────────────┤  │                                   │
│  │ [+ Add     │  │  C: Scanning                      │
│  │   Host]    │  │     "Scanning root@192.168..."    │
│  └────────────┘  │     (loading spinner)             │
│                  │                                   │
│  Edit / Delete   │  D: Connection failed             │
│  on selected     │     "Connection failed: ..."      │
│  host            │     [Retry]                       │
└──────────────────┴──────────────────────────────────┘
```

### Components

| Component | File | Responsibility |
|-----------|------|----------------|
| `RemotePage` | `pages/remote_page.rs` | Two-panel layout, state routing |
| `HostList` | `components/host_list.rs` | Saved hosts sidebar, connect/edit/delete |
| `HostForm` | `components/host_form.rs` | Add/edit host profile modal or inline form |
| `RemoteStatus` | `components/remote_status.rs` | Connection banner, scan trigger, results display |

### Host form fields

| Field | Input type | Required | Default |
|-------|-----------|----------|---------|
| Display name | text | Yes | — |
| Hostname / IP | text | Yes | — |
| Username | text | No | (current user) |
| Port | number | No | 22 |
| Key file path | text | No | (SSH agent) |
| Verify host key | checkbox | No | checked |

### AppState signals (new)

```rust
pub remote_hosts: RwSignal<Vec<RemoteHostProfile>>,
pub remote_connection: RwSignal<Option<RemoteConnectionInfo>>,
pub remote_scan_results: RwSignal<Vec<ScanResult>>,
pub is_connecting: RwSignal<bool>,
pub is_remote_scanning: RwSignal<bool>,
```

Remote scan results are separate from local (`remote_scan_results` vs `scan_results`). Switching pages never clobbers either set.

### RemoteConnectionInfo (UI-side, in hardener-types)

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteConnectionInfo {
    pub profile_name: String,
    pub host: String,
    pub user: String,
}
```

---

## Data Flow

### 1. App startup

```
App loads → invoke list_remote_hosts()
  → Reads ~/.config/linux-hardener/hosts.toml
  → Populates remote_hosts signal
```

### 2. Connect

```
User clicks [Connect] on "web-01"
  → is_connecting = true
  → invoke connect_remote("web-01")
  → Tauri: load profile → build SshConfig → SshExecutor::connect()
  → Return RemoteConnectionStatus::Connected or ::Failed
  → Update remote_connection signal
  → is_connecting = false
```

### 3. Scan

```
User clicks [Run Scan]
  → is_remote_scanning = true
  → invoke run_remote_scan(None)
  → Tauri: read active_connection from RemoteState
  → Create Context::with_executor(ssh_executor.clone())
  → PluginManager runs all 8 plugins via SSH
  → Return Vec<ScanResult>
  → Update remote_scan_results signal
  → is_remote_scanning = false
```

### 4. Disconnect

```
User clicks [Disconnect]
  → invoke disconnect_remote()
  → Tauri: drop SshExecutor (closes SSH session)
  → Clear remote_connection signal
  → Clear remote_scan_results signal
```

### Error handling

- Connection failure → right panel shows error with retry option
- Scan failure → error banner (same pattern as local scans)
- Connection drop mid-scan → SshExecutor methods return errors → propagated as scan error
- TOML parse failure → empty host list + error logged

---

## Authentication

Supported methods:
- **SSH agent** — default when no key_file specified. Uses `SSH_AUTH_SOCK`.
- **Key file** — user provides path to private key. The `openssh` crate handles passphrase prompts via the system SSH agent.

Not supported (intentionally):
- Password authentication — security risk in GUI context, would require careful memory handling.

---

## Files Modified / Created

### New files

| File | Purpose |
|------|---------|
| `crates/hardener-types/src/remote.rs` | `RemoteHostProfile`, `RemoteConnectionStatus`, `RemoteConnectionInfo` |
| `crates/hardener-ui/src/pages/remote_page.rs` | Remote page layout |
| `crates/hardener-ui/src/components/host_list.rs` | Host sidebar component |
| `crates/hardener-ui/src/components/host_form.rs` | Add/edit host form |
| `crates/hardener-ui/src/components/remote_status.rs` | Connection + scan results panel |

### Modified files

| File | Change |
|------|--------|
| `crates/hardener-types/src/lib.rs` | Add `mod remote` + re-exports |
| `crates/hardener-ui/src/lib.rs` | Add `/remote` route + nav link |
| `crates/hardener-ui/src/state/mod.rs` | Add 5 remote signals to `AppState` |
| `crates/hardener-ui/src/tauri_bindings.rs` | Add 6 `invoke_*` functions |
| `src-tauri/src/main.rs` | Register 6 new commands + `RemoteState` |
| `src-tauri/src/commands.rs` | Implement 6 new Tauri commands |
| `src-tauri/Cargo.toml` | Add `toml` dependency (if not present) |

---

## Future Extensibility

The architecture cleanly supports these additions without refactoring:

| Feature | Confidence | Notes |
|---------|-----------|-------|
| Remote apply/rollback | **High** | `SystemExecutor` trait already abstracts this. Apply works through the same trait methods as scan. Gate behind explicit confirmation dialogs and a per-host "allow apply" toggle. |
| Host groups | **High** | Pure data modelling — `group: Option<String>` on profiles, filter/sort in UI. No architectural impact. |
| Password auth | **Medium-High** | `openssh` crate supports it. GUI password input needs care: never persist, never log, clear from memory after use. Tricky part is UX — password prompts during connection need a modal dialog flow. |
| Concurrent multi-host | **Medium** | Architecturally sound (`tokio::JoinSet` with multiple `SshExecutor`s). Complexity is in the UI — showing N concurrent progress states, handling partial failures, aggregating results. Best done over multiple sessions. |
| Remote scan persistence | **High** | Add `remote_host` column to existing `scan_sessions` table. `ScanHistoryManager` already handles persistence — just tag sessions with origin host. |
| Remote compliance reports | **High** | Reports generate from `Vec<ScanResult>` — they don't care whether results came from local or SSH. Once remote scan results exist, compliance is essentially free. |
