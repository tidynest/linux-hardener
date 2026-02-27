# hardener-state::signing
**File:** `crates/hardener-state/src/signing.rs` | **Lines:** 367 (250 prod, 117 test)

## Purpose
Ed25519 key management for checkpoint signing. Generates, loads, saves, signs, and verifies.

## Dependencies
- Imports from: `ed25519_dalek` (Ed25519 crypto), `rand` (key generation), `aes_gcm` (AES-256-GCM), `hkdf`/`sha2` (HKDF key derivation), `hardener_common::error`
- Used by: `manager::CheckpointManager` (signs checkpoints)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CheckpointSigner` | struct | Wraps `ed25519_dalek::SigningKey` + optional `VerifyingKey` |
| `::new()` | fn | Loads or generates key at `/etc/linux-hardener/signing.key` |
| `::new_with_path(path)` | fn | Custom key path (used by tests) |
| `::load_verifier_only(path)` | fn | Loads public key only — verification without signing capability (SAM-014) |
| `::sign(data)` | fn | Returns 64-byte Ed25519 signature |
| `::verify(data, sig)` | fn | Verifies signature, returns `Result<()>` |
| `::rotate_key()` | fn | Generates new key, archives old key with timestamp |
| `::public_key_bytes()` | fn | Returns 32-byte public key |
| `::can_sign()` | fn | Returns `bool` — whether signing key is loaded |

## Data Flow
`new_with_path()` → if key exists: `load_key()` (read + auto-migrate unencrypted→AES-256-GCM) → `SigningKey::from_bytes()`; else: `generate_key()` (CSPRNG) → `save_key()` (encrypt + write + chmod 0400) → `save_public_key()` (write + chmod 0444)

`sign(data)` → `SigningKey::sign()` → 64-byte Vec

`verify(data, sig)` → validate length (64) → `VerifyingKey::verify()` → Ok/Err

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `generate_key()` | 94-105 | 32 random bytes → `SigningKey` |
| `load_key()` | 107-149 | Read file, detect encrypted (magic `LSH1`), auto-migrate unencrypted keys |
| `save_key()` | 151-181 | AES-256-GCM encrypt → write + chmod 0400 |
| `save_public_key()` | 183-200 | Write public key + chmod 0444 |
| `derive_encryption_key()` | 202-224 | HKDF-SHA256 from `/etc/machine-id` |
| `encrypt_key()` | 226-257 | AES-256-GCM: magic + nonce + ciphertext + tag |
| `decrypt_key()` | 259-291 | Reverse encryption, detect tampering |

## Flags
- No production unwraps. Clean error handling throughout.
- Keys encrypted at rest with AES-256-GCM, derived from machine-id via HKDF.
- Auto-migration: unencrypted legacy keys re-encrypted on first load.
