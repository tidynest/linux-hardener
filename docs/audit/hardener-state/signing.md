# hardener-state::signing
**File:** `crates/hardener-state/src/signing.rs` | **Lines:** 277 (135 prod, 142 test)

## Purpose
Ed25519 key management for checkpoint signing. Generates, loads, saves, signs, and verifies.

## Dependencies
- Imports from: `ed25519_dalek` (Ed25519 crypto), `rand` (key generation), `hardener_common::error`
- Used by: `manager::CheckpointManager` (signs checkpoints)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CheckpointSigner` | struct | Wraps `ed25519_dalek::SigningKey` |
| `::new()` | fn | Loads or generates key at `/var/lib/linux-hardener/signing.key` |
| `::new_with_path(path)` | fn | Custom key path (used by tests) |
| `::sign(data)` | fn | Returns 64-byte Ed25519 signature |
| `::verify(data, sig)` | fn | Verifies signature, returns `Result<()>` |

## Data Flow
`new_with_path()` → if key exists: `load_key()` (read 32 bytes) → `SigningKey::from_bytes()`; else: `generate_key()` (CSPRNG) → `save_key()` (write + chmod 0600)

`sign(data)` → `SigningKey::sign()` → 64-byte Vec

`verify(data, sig)` → validate length (64) → `VerifyingKey::verify()` → Ok/Err

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `generate_key()` | 45-53 | 32 random bytes → `SigningKey` |
| `load_key()` | 57-71 | Read file, validate 32 bytes, construct key |
| `save_key()` | 77-93 | Create parent dirs, write bytes, chmod 0600 |

## Flags
- **TYPO** (line 1): Module doc ends with comma, not period.
- **TYPO** (line 3): "Use Ed25519" should be "Uses Ed25519".
- No production unwraps. Clean error handling throughout.
