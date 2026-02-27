# hardener-types::remote
**File:** `crates/hardener-types/src/remote.rs` | **Lines:** 54 (all production)

## Purpose
Types for remote SSH scanning and host profile management. Used by the Leptos UI to display, create, and manage remote host connections.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `RemoteHostProfile` | struct | SSH host definition: name, hostname, user, port (default 22), key_file, host_key_checking (default true) |
| `HostsConfig` | struct | TOML file wrapper: `hosts: Vec<RemoteHostProfile>` |
| `RemoteConnectionStatus` | enum | `Connected { host, user }` or `Failed { error }` |
| `RemoteConnectionInfo` | struct | Active connection UI info: profile_name, host, user |

## Helper Functions
| Function | Description |
|----------|-------------|
| `default_port()` | Returns `22` — serde default for SSH port |
| `default_true()` | Returns `true` — serde default for host_key_checking |

## Design Notes
- Mirrors backend `RemoteHostProfile` but omits SMTP/connection internals for UI safety
- WASM-compatible (no native-only types)

## Flags
None.
