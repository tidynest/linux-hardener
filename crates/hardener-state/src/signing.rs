//! Cryptographic signing for checkpoint integrity.
//!
//! Uses Ed25519 signatures to ensure checkpoints cannot be tampered with.
//! Private keys are encrypted at rest using AES-256-GCM with a key derived
//! from the machine identity via HKDF-SHA256.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hardener_common::error::{HardeningError, Result};
use std::{fs, path::Path};
use zeroize::Zeroize;

/// File header magic bytes identifying an encrypted key file (v1).
const ENCRYPTED_KEY_MAGIC: &[u8; 4] = b"LSH1";

/// HKDF salt for the key that encrypts the signing key at rest. **Frozen.**
///
/// This is a key-derivation input, not a label. The AES-256-GCM key protecting
/// `signing.key` is derived from the host's machine identity and this value, so
/// changing it returns a different key: the existing signing key stops
/// decrypting, nothing can be signed, and every signature already written
/// becomes unverifiable. It is data loss on a host that has run `apply`, and it
/// compiles and passes any test that does not read a key an earlier binary
/// wrote.
///
/// It reads like a path and a project-wide rename would take it (#51), which is
/// why it is named here rather than left inline, and why
/// `the_key_derivation_has_a_known_answer` pins the derived bytes rather than
/// this string: the expansion's `signing-key-encryption` info is frozen for the
/// same reason and has no name of its own.
///
/// The `-v1` suffix is where a versioned derivation would start, trying v2 and
/// falling back to v1 with a re-encrypt on success. Nothing reads a v2 today.
const KEY_DERIVATION_SALT: &[u8] = b"linux-hardener-signing-key-v1";

/// Manages Ed25519 signing keys for checkpoint signatures.
///
/// Supports both signing and verification-only modes.
/// When only a public key is available, sign operations will fail
/// but verification still works, providing trust separation (SAM-014).
#[derive(Clone)]
pub struct CheckpointSigner {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl CheckpointSigner {
    /// Default path for the signing key.
    const DEFAULT_KEY_PATH: &'static str = "/etc/linux-hardener/signing.key";
    /// Default path for the public verification key.
    #[allow(dead_code)]
    const DEFAULT_PUBKEY_PATH: &'static str = "/etc/linux-hardener/signing.pub";
}

impl CheckpointSigner {
    /// Creates a new signer, loading or generating a signing key.
    ///
    /// If a key exists at the default path, it will be loaded.
    /// Otherwise, a new key will be generated and saved.
    pub fn new() -> Result<CheckpointSigner> {
        Self::new_with_path(Path::new(Self::DEFAULT_KEY_PATH))
    }

    /// Creates a new signer with a custom key path.
    pub fn new_with_path(key_path: &Path) -> Result<CheckpointSigner> {
        let pubkey_path = key_path.with_extension("pub");

        // Verification-only mode is for a reader that has the public key and
        // not the private one, and "has not got it" covers being unable to read
        // it as well as its being absent. Keying on absence alone left out the
        // shipped layout, where a root-owned `signing.key` at 0400 sits beside a
        // readable `signing.pub`: for every unprivileged reader the private key
        // is present and unreadable, so the load below failed and the public key
        // sitting next to it was never tried.
        //
        // `try_exists` rather than `exists`, so a key under a directory this
        // process may not search is not mistaken for one that is not there. That
        // distinction decides whether a key is generated, and generating one
        // where a key already exists would void the signature of every
        // checkpoint already written.
        // Opening it answers both questions at once, and answers them the way
        // the load would: absent and unreadable both fail here.
        let private_key_readable = fs::File::open(key_path).is_ok();
        if !private_key_readable && matches!(pubkey_path.try_exists(), Ok(true)) {
            return Self::load_verifier_only(&pubkey_path);
        }

        let signing_key = if private_key_readable {
            Self::load_key(key_path)?
        } else if matches!(key_path.try_exists(), Ok(false)) {
            let key = Self::generate_key()?;
            Self::save_key(key_path, &key)?;
            // Also save the public key alongside for verification-only setups
            Self::save_public_key(&pubkey_path, &key.verifying_key())?;
            key
        } else {
            // The key is there and cannot be read, and there is no public key to
            // fall back on. Say that, rather than reporting whatever a write
            // into a directory we cannot even search happens to fail with.
            return Err(HardeningError::Config(format!(
                "Signing key at {} could not be read, and no public key was \
                 available beside it. Run this command with the privileges that \
                 own the key, or install its public half for verification.",
                key_path.display()
            )));
        };

        let verifying_key = signing_key.verifying_key();
        Ok(CheckpointSigner {
            signing_key: Some(signing_key),
            verifying_key,
        })
    }

    /// Creates a verification-only signer from a public key file.
    ///
    /// This mode allows signature verification without access to the
    /// private key, providing trust separation (SAM-014).
    fn load_verifier_only(pubkey_path: &Path) -> Result<CheckpointSigner> {
        let key_bytes = fs::read(pubkey_path).map_err(HardeningError::System)?;

        if key_bytes.len() != 32 {
            return Err(HardeningError::Config(
                "Invalid public key: must be 32 bytes".to_string(),
            ));
        }

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| HardeningError::Config("Invalid public key format".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| HardeningError::Config(format!("Invalid public key: {e}")))?;

        Ok(CheckpointSigner {
            signing_key: None,
            verifying_key,
        })
    }

    /// Generates a new Ed25519 signing key.
    fn generate_key() -> Result<SigningKey> {
        use rand::RngCore;

        let mut secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();

        Ok(signing_key)
    }

    /// Loads a signing key from disk, supporting both encrypted and legacy formats.
    fn load_key(key_path: &Path) -> Result<SigningKey> {
        let file_bytes = fs::read(key_path).map_err(HardeningError::System)?;

        // Whether this file still needs migrating, decided from the bytes
        // already in hand. Reading the file a second time to answer the same
        // question meant a transient read failure was indistinguishable from
        // "not yet encrypted", and the migration below then deleted the key.
        let is_legacy_format = !file_bytes.starts_with(ENCRYPTED_KEY_MAGIC);

        // Detect format: encrypted keys have the magic header
        let raw_key = if file_bytes.starts_with(ENCRYPTED_KEY_MAGIC) {
            Self::decrypt_key(&file_bytes)?
        } else if file_bytes.len() == 32 {
            // Legacy unencrypted format: migrate to encrypted on next save
            file_bytes
        } else {
            return Err(HardeningError::Config(
                "Invalid signing key file format".to_string(),
            ));
        };

        if raw_key.len() != 32 {
            return Err(HardeningError::Config(
                "Invalid signing key: must be 32 bytes".to_string(),
            ));
        }

        let mut key_array: [u8; 32] = raw_key
            .try_into()
            .map_err(|_| HardeningError::Config("Invalid key format".to_string()))?;

        let signing_key = SigningKey::from_bytes(&key_array);
        key_array.zeroize();

        // Migrate a legacy plaintext key to the encrypted format, without ever
        // leaving the host without one. The previous sequence removed the file
        // and then created a new one, so a failure at the second step
        // destroyed the key and only logged a warning, taking the
        // tamper-evidence of every existing checkpoint with it. Writing a
        // temporary file and renaming it over the original replaces the key in
        // one atomic step, so a failure leaves the original untouched and the
        // migration simply happens next time.
        if is_legacy_format && let Err(e) = Self::replace_key_atomically(key_path, &signing_key) {
            tracing::warn!(
                "Could not migrate the signing key to the encrypted format, \
                 leaving the existing key in place: {e}"
            );
        }

        Ok(signing_key)
    }

    /// Saves a signing key to disk, encrypted with AES-256-GCM.
    ///
    /// Key derivation: HKDF-SHA256 over `/etc/machine-id` content,
    /// providing encryption at rest without interactive passphrases.
    fn save_key(key_path: &Path, signing_key: &SigningKey) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        // Ensure parent directory exists (idempotent)
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).map_err(HardeningError::System)?;
            let perms = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(parent, perms);
        }

        let encrypted = Self::encrypt_key(&signing_key.to_bytes())?;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(key_path)
            .map_err(HardeningError::System)?;

        file.write_all(&encrypted).map_err(HardeningError::System)?;

        Ok(())
    }

    /// Replaces an existing key file with its encrypted form in one step.
    ///
    /// `save_key` opens with `create_new`, which is right for creating a key
    /// that must never clobber an existing one, but means a replacement has to
    /// delete first. Deleting first is what made a failed migration destroy the
    /// key, so this writes a temporary file alongside and renames it over the
    /// target: the original stays readable until the moment it is replaced, and
    /// a failure anywhere leaves it exactly as it was.
    fn replace_key_atomically(key_path: &Path, signing_key: &SigningKey) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // Deliberately neither creates nor re-permissions the parent: the key
        // being replaced is already in it, so the directory exists, and
        // silently widening an existing directory's permissions is not this
        // function's business.
        let encrypted = Self::encrypt_key(&signing_key.to_bytes())?;

        // Same directory, so the rename below is a rename and not a copy.
        let temp_path = key_path.with_extension("migrating");
        // Not create_new: a temporary left behind by an interrupted earlier
        // attempt must not block every future migration.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .open(&temp_path)
            .map_err(HardeningError::System)?;
        file.write_all(&encrypted).map_err(HardeningError::System)?;
        file.sync_all().map_err(HardeningError::System)?;
        drop(file);

        std::fs::rename(&temp_path, key_path).inspect_err(|_| {
            // Leaving the temporary behind would keep a second copy of the key
            // on disk at a path nothing manages.
            let _ = std::fs::remove_file(&temp_path);
        })?;
        Ok(())
    }

    /// Saves the public key to disk for verification-only setups.
    fn save_public_key(pubkey_path: &Path, verifying_key: &VerifyingKey) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444) // Public key is world-readable
            .open(pubkey_path)
            .map_err(HardeningError::System)?;

        file.write_all(verifying_key.as_bytes())
            .map_err(HardeningError::System)?;

        Ok(())
    }

    /// Derives an AES-256 key from the machine identity using HKDF-SHA256.
    fn derive_encryption_key() -> Result<[u8; 32]> {
        let machine_id = fs::read_to_string("/etc/machine-id")
            .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
            .map_err(|e| {
                HardeningError::Config(format!("Cannot read machine-id for key encryption: {e}"))
            })?;

        Self::derive_encryption_key_from(machine_id.trim())
    }

    /// [`derive_encryption_key`](Self::derive_encryption_key) with the machine
    /// identity supplied rather than read, so the derivation has a known answer
    /// a test can pin. Reading `/etc/machine-id` is the only thing it leaves
    /// behind, and a host's own identity is not something a test can choose.
    fn derive_encryption_key_from(machine_id: &str) -> Result<[u8; 32]> {
        use ring::hkdf;

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, KEY_DERIVATION_SALT);
        let prk = salt.extract(machine_id.as_bytes());

        let okm = prk
            .expand(&[b"signing-key-encryption"], &ring::aead::AES_256_GCM)
            .map_err(|_| HardeningError::Config("HKDF expand failed".to_string()))?;

        let mut key_bytes = [0u8; 32];
        okm.fill(&mut key_bytes)
            .map_err(|_| HardeningError::Config("HKDF output length mismatch".to_string()))?;

        Ok(key_bytes)
    }

    /// Encrypts signing key bytes with AES-256-GCM.
    ///
    /// Format: `MAGIC(4) || NONCE(12) || CIPHERTEXT(32) || TAG(16)` = 64 bytes.
    fn encrypt_key(key_bytes: &[u8; 32]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        use ring::rand::{SecureRandom, SystemRandom};

        let enc_key = Self::derive_encryption_key()?;
        let unbound = UnboundKey::new(&AES_256_GCM, &enc_key)
            .map_err(|_| HardeningError::Config("Failed to create encryption key".to_string()))?;
        let aead_key = LessSafeKey::new(unbound);

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| HardeningError::Config("Failed to generate nonce".to_string()))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = key_bytes.to_vec();

        aead_key
            .seal_in_place_append_tag(nonce, Aad::from(ENCRYPTED_KEY_MAGIC), &mut in_out)
            .map_err(|_| HardeningError::Config("Encryption failed".to_string()))?;

        // Build output: MAGIC || NONCE || CIPHERTEXT+TAG
        let mut output = Vec::with_capacity(4 + 12 + in_out.len());
        output.extend_from_slice(ENCRYPTED_KEY_MAGIC);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&in_out);

        Ok(output)
    }

    /// Decrypts signing key bytes from the encrypted file format.
    fn decrypt_key(file_bytes: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

        // MAGIC(4) + NONCE(12) + CIPHERTEXT(32) + TAG(16) = 64
        if file_bytes.len() < 4 + 12 + 32 + 16 {
            return Err(HardeningError::Config(
                "Encrypted key file too short".to_string(),
            ));
        }

        let nonce_bytes: [u8; 12] = file_bytes[4..16]
            .try_into()
            .map_err(|_| HardeningError::Config("Invalid nonce in key file".to_string()))?;

        let enc_key = Self::derive_encryption_key()?;
        let unbound = UnboundKey::new(&AES_256_GCM, &enc_key)
            .map_err(|_| HardeningError::Config("Failed to create decryption key".to_string()))?;
        let aead_key = LessSafeKey::new(unbound);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = file_bytes[16..].to_vec();

        let plaintext = aead_key
            .open_in_place(nonce, Aad::from(ENCRYPTED_KEY_MAGIC), &mut ciphertext)
            .map_err(|_| {
                HardeningError::Config(
                    "Key decryption failed (wrong machine or corrupted file)".to_string(),
                )
            })?;

        Ok(plaintext.to_vec())
    }

    /// Signs checkpoint data, producing a 64-byte Ed25519 signature.
    ///
    /// Requires the private key to be available. Returns an error in
    /// verification-only mode.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            HardeningError::Config(
                "Cannot sign: private key not available (verification-only mode)".to_string(),
            )
        })?;
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies a signature against data.
    ///
    /// Works in both full and verification-only modes.
    pub fn verify(&self, data: &[u8], signature_bytes: &[u8]) -> Result<()> {
        if signature_bytes.len() != 64 {
            return Err(HardeningError::Config(
                "Invalid signature: must be 64 bytes".to_string(),
            ));
        }

        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| HardeningError::Config("Invalid signature format".to_string()))?;

        let signature = Signature::from_bytes(&signature_array);

        self.verifying_key
            .verify(data, &signature)
            .map_err(|_| HardeningError::Config("Signature verification failed".to_string()))?;

        Ok(())
    }

    /// Returns the public key bytes for embedding or export.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Returns true if this signer has the private key and can sign.
    pub fn can_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Rotates the signing key: generates a new key, saves it encrypted,
    /// and returns the new signer.
    ///
    /// The caller is responsible for re-signing existing checkpoints if needed.
    /// The old public key should be retained for verifying old signatures.
    pub fn rotate_key(key_path: &Path) -> Result<CheckpointSigner> {
        let new_key = Self::generate_key()?;

        // Archive old key file before overwriting
        let archive_path = key_path.with_extension("key.old");
        if key_path.exists() {
            fs::rename(key_path, &archive_path).map_err(HardeningError::System)?;
        }

        Self::save_key(key_path, &new_key)?;

        // Update public key
        let pubkey_path = key_path.with_extension("pub");
        let _ = fs::remove_file(&pubkey_path);
        Self::save_public_key(&pubkey_path, &new_key.verifying_key())?;

        let verifying_key = new_key.verifying_key();
        Ok(CheckpointSigner {
            signing_key: Some(new_key),
            verifying_key,
        })
    }
}

#[cfg(test)]
mod tests;
