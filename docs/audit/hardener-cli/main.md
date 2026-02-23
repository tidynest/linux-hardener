# hardener-cli::main
**File:** `crates/hardener-cli/src/main.rs` | **Lines:** 160

## Purpose
CLI entry point — parses args, creates executor (local or SSH), dispatches to subcommand handlers.

## Dependencies
- Imports from: all local modules (`cli`, `commands`, `output`, `ssh_config`), `hardener_core::{LocalExecutor, SshExecutor}`
- Used by: binary entry point

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `main()` | async fn | Tokio entry point |

## Data Flow
`Cli::parse()` → create executor (Local or SSH) → `match cli.command` → dispatch → error → exit(1)

## Flags
- **MISSING:** No `//!` module doc.
