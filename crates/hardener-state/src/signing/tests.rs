#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`signing`].
//!
//! Split out of `signing.rs`. This file sits in the `signing/` directory
//! beside it, so `super` still resolves to `crate::signing` and every
//! import carried across unchanged, private items included.

use super::*;

/// A legacy key file: 32 raw bytes, no magic header.
fn write_legacy_key(path: &Path) -> Vec<u8> {
    let bytes: Vec<u8> = (0u8..32).collect();
    fs::write(path, &bytes).expect("write legacy key");
    bytes
}

#[test]
fn a_legacy_key_is_migrated_to_the_encrypted_format() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("signing.key");
    let original = write_legacy_key(&key_path);

    let signer = CheckpointSigner::new_with_path(&key_path).expect("load legacy key");

    let stored = fs::read(&key_path).expect("key still readable");
    assert!(
        stored.starts_with(ENCRYPTED_KEY_MAGIC),
        "the migrated file must carry the encrypted magic"
    );
    assert_ne!(
        stored, original,
        "the plaintext key must not remain on disk"
    );
    // The key itself must survive the format change.
    let reloaded = CheckpointSigner::new_with_path(&key_path).expect("reload migrated key");
    assert_eq!(
        signer.public_key_bytes(),
        reloaded.public_key_bytes(),
        "migration must preserve the key, not mint a new one"
    );
}

#[test]
fn a_failed_migration_leaves_the_original_key_in_place() {
    // The old sequence removed the key and then created a new one, so a
    // failure at the second step destroyed it and only logged a warning,
    // taking the tamper-evidence of every existing checkpoint with it.
    // Migration must be all-or-nothing.
    //
    // The failure is induced by occupying the path the replacement is
    // written to with a directory, which cannot be opened as a file. A
    // read-only parent directory does NOT work here: it also blocks the
    // deletion, so the old destructive code preserved the key too and the
    // test passed against the very bug it was written for.
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("signing.key");
    let original = write_legacy_key(&key_path);
    fs::create_dir(key_path.with_extension("migrating")).expect("occupy the temporary path");

    let result = CheckpointSigner::new_with_path(&key_path);

    assert!(
        result.is_ok(),
        "a key that loaded fine must still be usable when only its migration failed"
    );
    assert_eq!(
        fs::read(&key_path).expect("the key must still exist"),
        original,
        "a failed migration must leave the original key exactly as it was"
    );
}

/// Verification-only mode exists for trust separation (SAM-014): a reader that
/// has the public key can check signatures without the private one. It engaged
/// only when the private key was **absent**, which is not the situation it was
/// built for. The shipped layout is a root-owned `signing.key` at 0400 beside a
/// world-readable `signing.pub`, so for every unprivileged reader the private
/// key is present and unreadable, and that took the load path and failed.
///
/// The desktop is the reader this stranded: it could not construct a manager
/// for the system checkpoint database at all, so it could neither list nor
/// verify any privileged checkpoint.
#[test]
fn a_private_key_that_cannot_be_read_falls_back_to_the_public_one() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("a scratch directory");
    let key_path = dir.path().join("signing.key");

    // Generate a real pair through the normal path, then close the private key
    // exactly as the packaging does.
    let signed_by_owner = CheckpointSigner::new_with_path(&key_path).expect("a generated key");
    let payload = b"checkpoint bytes";
    let signature = signed_by_owner.sign(payload).expect("the owner can sign");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o000))
        .expect("the private key is closed");

    let unreadable = std::fs::read(&key_path).is_err();
    let reader = CheckpointSigner::new_with_path(&key_path);

    let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));

    assert!(
        unreadable,
        "the private key must actually be unreadable, or this test proves \
         nothing; running as root would read it anyway and this assertion says so"
    );
    let reader = reader.expect(
        "a reader holding only the public key must still get a signer, because \
         verifying is what it is there to do",
    );
    assert!(
        reader.verify(payload, &signature).is_ok(),
        "and that signer verifies what the private key signed"
    );
    assert!(
        reader.sign(payload).is_err(),
        "while still being unable to sign, which is the separation this mode is for"
    );
}
