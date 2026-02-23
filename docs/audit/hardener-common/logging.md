# hardener-common::logging
**File:** `crates/hardener-common/src/logging.rs` | **Lines:** 47 (34 prod, 13 test)

## Purpose
Initialises the `tracing`-based structured logging system for the application.

## Dependencies
- Imports from: `tracing_subscriber` — `EnvFilter` + `fmt` subscriber builder
- Used by: `hardener-cli/src/main.rs` — called once at startup

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `init_logger` | fn | Set up tracing subscriber with RUST_LOG or default `info` |

## Data Flow
`RUST_LOG` env → `EnvFilter` → `fmt` subscriber → global default

## Configuration
- Default level: `info`
- Shows: target, line numbers
- Hides: thread IDs
- Override: set `RUST_LOG=debug` (or any valid filter)

## Flags
- **TYPO (line 14):** Doc comment says `ìnfo` (grave accent) instead of `info`.
