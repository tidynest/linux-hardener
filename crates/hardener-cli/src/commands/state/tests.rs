#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`state`](super).
//!
//! Split out of `commands/state.rs`. This file sits in the `state/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::state` and every import carried
//! across unchanged, private items included.

use super::*;

// The two audit-log tests that lived here moved to
// `hardener-core/src/config_write/tests.rs` with the function they exercise.
// `audit_logger_in` is not in this crate any more: the desktop backend needed
// the same answer to where this host's audit trail lives, and a binary cannot
// be depended on.

// ---------------------------------------------------------------------------
// The two root directories `prepare_root_dirs` settles.
//
// The key directory is `/etc/linux-hardener`, which is also where `config.toml`
// lives. This used to force it to 0700, so after one root run an unprivileged
// `scan` could not read the configuration a privileged `apply` read, and said
// nothing: `Path::exists` answers `false` for a file under a directory it may
// not search. The data directory has no second role and is still set outright.
// ---------------------------------------------------------------------------

/// Runs [`prepare_root_dirs`] over a scratch pair with the key directory pinned
/// at exactly `key_mode`, and answers with both directories' modes afterwards.
///
/// Both modes are set rather than requested, because the process umask clears
/// bits from a `create_dir` and the exact value is the whole subject here.
///
/// The data directory is deliberately pre-created at 0700, not left to
/// `prepare_root_dirs` to create. Under the umask on this machine a fresh
/// directory already arrives at 0755, so a data directory created here would
/// read as 0755 whether or not the function set it, and the assertion on it
/// could not fail. Starting it somewhere else is what makes the set observable.
fn modes_after_preparing_a_key_dir_at(key_mode: u32) -> (u32, u32) {
    let dir = tempfile::tempdir().unwrap();
    let key_dir = dir.path().join("etc");
    let data_dir = dir.path().join("var");
    for (path, mode) in [(&key_dir, key_mode), (&data_dir, 0o700)] {
        fs::create_dir(path).expect("create the directory");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("pin its mode");
    }

    prepare_root_dirs(&key_dir, &data_dir).expect("writable scratch directories must prepare");

    let mode_of = |p: &Path| {
        fs::metadata(p)
            .expect("directory must exist")
            .permissions()
            .mode()
            & 0o777
    };
    (mode_of(&key_dir), mode_of(&data_dir))
}

/// The installed case, and the defect. `/etc/linux-hardener` arrives at 0755
/// from the package, and a root run must leave it readable.
#[test]
fn the_shared_configuration_directory_keeps_its_installed_mode() {
    let (key_mode, data_mode) = modes_after_preparing_a_key_dir_at(0o755);

    assert_eq!(
        key_mode, 0o755,
        "narrowing the configuration directory makes an unprivileged scan and \
         a privileged apply resolve different configuration, silently"
    );
    assert_eq!(
        data_mode, 0o755,
        "the data directory is unrelated and must still be set to 0755"
    );
}

/// The repair, for a host an earlier version already narrowed.
#[test]
fn a_configuration_directory_narrowed_by_an_earlier_run_is_widened() {
    let (key_mode, _) = modes_after_preparing_a_key_dir_at(0o700);

    assert_eq!(
        key_mode, 0o755,
        "0700 is exactly what this function used to write, so it is repaired"
    );
}

/// The arm that proves the repair is targeted. Without it both tests above pass
/// against an unconditional chmod to 0755, which is the blanket behaviour this
/// change exists to remove.
#[test]
fn another_restrictive_configuration_directory_mode_is_left_alone() {
    let (key_mode, _) = modes_after_preparing_a_key_dir_at(0o750);

    assert_eq!(
        key_mode, 0o750,
        "a mode this code never wrote belongs to whoever chose it"
    );
}

/// The upgrade this function exists for. A host hardened before the key and
/// the database were separated has its key at the legacy path and nothing at
/// the new one, and the key must arrive there: `CheckpointSigner` mints a
/// fresh key for a path holding none, so a key left behind means every
/// checkpoint taken before the upgrade fails its signature check and cannot be
/// rolled back.
#[test]
fn a_legacy_key_moves_to_a_new_path_that_holds_none() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("legacy.key");
    let current = dir.path().join("current.key");
    fs::write(&legacy, b"legacy key bytes").unwrap();

    migrate_key_from(&legacy, &current).expect("a legacy key must migrate");

    assert_eq!(fs::read(&current).unwrap(), b"legacy key bytes");
    assert!(!legacy.exists(), "the legacy key must not be left behind");
    let mode = fs::metadata(&current).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o400, "the migrated key must be root read-only");
}

/// The other half, and the destructive one. A key already at the new path
/// signed every checkpoint taken since the separation, so copying the legacy
/// key over it destroys exactly what it was meant to preserve. Both files are
/// given distinct contents, so a copy in either direction is visible rather
/// than being hidden by two identical files.
#[test]
fn a_key_already_at_the_new_path_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("legacy.key");
    let current = dir.path().join("current.key");
    fs::write(&legacy, b"legacy key bytes").unwrap();
    fs::write(&current, b"current key bytes").unwrap();

    migrate_key_from(&legacy, &current).expect("a no-op must not fail");

    assert_eq!(
        fs::read(&current).unwrap(),
        b"current key bytes",
        "the key in use must survive"
    );
    assert_eq!(
        fs::read(&legacy).unwrap(),
        b"legacy key bytes",
        "the legacy key must be left alone rather than deleted"
    );
}

/// The common case on every host installed after the separation.
#[test]
fn no_legacy_key_leaves_the_new_path_alone() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("legacy.key");
    let current = dir.path().join("current.key");

    migrate_key_from(&legacy, &current).expect("nothing to migrate must not fail");

    assert!(!current.exists(), "no key must be invented from nothing");
}
