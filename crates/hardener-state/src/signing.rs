//! Cryptographic signing for checkpoint integrity,
//!
//! Use Ed25519 signatures to ensure checkpoints cannot be tampered with.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hardener_common::error::{HardeningError, Result};
use std::{fs, path::Path};

/// Manages Ed25519 signing keys for checkpoint signatures.
pub struct CheckpointSigner {
    signing_key: SigningKey,
}

impl CheckpointSigner {
    /// Default path for the signing key.
    const DEFAULT_KEY_PATH: &'static str = "/var/lib/linux-hardener/signing.key";
}

impl CheckpointSigner {
    /// Creates a new signer, loading or generating a signing key.
    ///
    /// If a key exists at the default path, it will be loaded.
    /// Otherwise, a new key will be generated and saved.
    ///
    /// # Security Implications
    /// The private key must be protected with restrictive file permissions.
    pub fn new() -> Result<CheckpointSigner> {
        Self::new_with_path(Path::new(Self::DEFAULT_KEY_PATH))
    }

    /// Creates a new signer with a custom key path.
    pub fn new_with_path(key_path: &Path) -> Result<CheckpointSigner> {
        let signing_key = if key_path.exists() {
            Self::load_key(key_path)?
        } else {
            let key = Self::generate_key()?;
            Self::save_key(key_path, &key)?;
            key
        };

        Ok(CheckpointSigner { signing_key })
    }

    /// Generates a new Ed25519 signing key.
    fn generate_key() -> Result<SigningKey> {
        use rand::RngCore;

        let mut secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut secret_bytes);

        let signing_key = SigningKey::from_bytes(&secret_bytes);

        Ok(signing_key)
    }

    /// Loads a signing key from disk.
    fn load_key(key_path: &Path) -> Result<SigningKey> {
        let key_bytes = fs::read(key_path).map_err(HardeningError::System)?;

        if key_bytes.len() != 32 {
            return Err(HardeningError::Config(
                "Invalid signing key: must be 32 bytes".to_string(),
            ));
        }

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| HardeningError::Config("Invalid key format".to_string()))?;

        Ok(SigningKey::from_bytes(&key_array))
    }

    /// Saves a signing key to disk with restrictive permissions.
    ///
    /// # Security Implications
    /// Sets file permissions to 0600 (owner read/write only).
    fn save_key(key_path: &Path, signing_key: &SigningKey) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        // Ensure parent directory exists
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(HardeningError::System)?;
        }

        // Write key bytes to file
        let key_bytes = signing_key.to_bytes();
        fs::write(key_path, key_bytes).map_err(HardeningError::System)?;

        // Set restrictive permissions (0600 - owner read/write only)
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(key_path, permissions).map_err(HardeningError::System)?;

        Ok(())
    }

    /// Signs checkpoint data, producing a 64-byte Ed25519 signature.
    ///
    /// The signature covers the checkpoint metadata and file content hashes.
    ///
    /// # Arguments
    /// * `data` - The data to sign (typically serialised checkpoint metadata)
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Verifies a signature against data.
    ///
    /// # Arguments
    /// * `data` - The original data that was signed
    /// * `signature_bytes` - The signature to verify
    ///
    /// # Returns
    /// `Ok(())` if signature is valid, `Err` otherwise.
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
        let verifying_key = self.signing_key.verifying_key();

        verifying_key
            .verify(data, &signature)
            .map_err(|_| HardeningError::Config("Signature verification failed".to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_signer_creates_new_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let signer = CheckpointSigner::new_with_path(&key_path).unwrap();

        assert!(key_path.exists());
        // Key should be 32 bytes
        let key_bytes = fs::read(&key_path).unwrap();
        assert_eq!(key_bytes.len(), 32);

        // Should be able to sign with the new key
        let signature = signer.sign(b"test data");
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_signer_loads_existing_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        // Create first signer (generates key)
        let signer1 = CheckpointSigner::new_with_path(&key_path).unwrap();
        let sig1 = signer1.sign(b"test data");

        // Create second signer (loads same key)
        let signer2 = CheckpointSigner::new_with_path(&key_path).unwrap();
        let sig2 = signer2.sign(b"test data");

        // Both signers should produce the same signature
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_sign_and_verify_success() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let signer = CheckpointSigner::new_with_path(&key_path).unwrap();
        let data = b"important checkpoint data";

        let signature = signer.sign(data);
        let result = signer.verify(data, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_fails_with_wrong_data() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let signer = CheckpointSigner::new_with_path(&key_path).unwrap();
        let data = b"original data";

        let signature = signer.sign(data);
        let result = signer.verify(b"tampered data", &signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_with_wrong_signature() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let signer = CheckpointSigner::new_with_path(&key_path).unwrap();
        let data = b"original data";

        let mut signature = signer.sign(data);
        // Tamper with signature
        signature[0] ^= 0xFF;

        let result = signer.verify(data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_fails_with_invalid_signature_length() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let signer = CheckpointSigner::new_with_path(&key_path).unwrap();

        // Too short
        let result = signer.verify(b"data", &[0u8; 32]);
        assert!(result.is_err());

        // Too long
        let result = signer.verify(b"data", &[0u8; 128]);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_invalid_length() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bad.key");

        // Write invalid key (wrong length)
        fs::write(&key_path, vec![0u8; 16]).unwrap();

        let result = CheckpointSigner::new_with_path(&key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        let dir = tempdir().unwrap();
        let key_path1 = dir.path().join("key1.key");
        let key_path2 = dir.path().join("key2.key");

        let signer1 = CheckpointSigner::new_with_path(&key_path1).unwrap();
        let signer2 = CheckpointSigner::new_with_path(&key_path2).unwrap();

        let data = b"same data";
        let sig1 = signer1.sign(data);
        let sig2 = signer2.sign(data);

        // Different keys should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_key_file_permissions() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let _signer = CheckpointSigner::new_with_path(&key_path).unwrap();

        // Check permissions (0600)
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&key_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
