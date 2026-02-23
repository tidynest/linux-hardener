# hardener-state::hash_chain
**File:** `crates/hardener-state/src/hash_chain.rs` | **Lines:** 129 (85 prod, 44 test)

## Purpose
SHA-256 hash chain for tamper-proof audit logging. Each hash = SHA-256(previous_hash || data).

## Dependencies
- Imports from: `ring::digest` (SHA-256), `serde` (Serialize/Deserialize)
- Used by: `audit::AuditLogger` (computes entry hashes, verifies chain integrity)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HashChain` | struct | Holds `previous_hash: Vec<u8>` |
| `::new()` | fn | Genesis chain with 32 zero bytes |
| `::next_hash(data)` | fn | SHA-256(previous_hash \|\| data), returns new hash |
| `::update(new_hash)` | fn | Advances chain to new previous_hash |
| `::verify_entry(prev, data, claimed)` | fn | Static: recomputes hash, compares with claimed |
| `::current_hash()` | fn | Returns current previous_hash ref |

## Data Flow
`next_hash(data)` → clone previous_hash → extend with data → SHA-256 → return hash bytes

`verify_entry()` → same computation → compare with `claimed_hash` → bool

## Flags
- **MISSING** (line 1): No `//!` module doc comment. File starts with `use`.
- **TYPO** (line 11): "32-bit array" should be "32-byte array".
