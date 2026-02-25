use hardener_state::CheckpointSigner;
use std::fs;
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
