#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! The mode string the desktop puts in front of an operator inspecting a
//! checkpoint.
//!
//! `file_permissions` holds the whole `st_mode`, type field included, which is
//! what lets a captured directory be told from a captured file without a second
//! column. Rollback masks that down to the permission bits before it chmods.
//! The desktop's expander did not, so a file captured at 0644 was listed under
//! a column headed "permissions" as `100644`, and the number the operator read
//! was not the number a rollback would apply.

use super::*;

fn checkpoint() -> Checkpoint {
    Checkpoint {
        checkpoint_id: CheckpointId::new("cp-1"),
        checkpoint_name: "before ssh hardening".to_string(),
        checkpoint_timestamp: 1_700_000_000,
        checkpoint_username: "bakri".to_string(),
        checkpoint_signature: vec![1, 2, 3],
        host_key: "local".to_string(),
    }
}

fn captured(path: &str, mode: u32, content: Option<Vec<u8>>) -> FileState {
    FileState {
        file_path: path.to_string(),
        file_content: content,
        file_permissions: mode,
        file_owner_uid: 0,
        file_owner_gid: 0,
        file_link_target: None,
        file_content_absence: None,
    }
}

fn modes_of(files: Vec<FileState>) -> Vec<String> {
    checkpoint_to_detail(checkpoint(), files)
        .files
        .into_iter()
        .map(|f| f.permissions)
        .collect()
}

/// The ordinary case, and the one an operator sees on nearly every row.
///
/// `0o100644` is a regular file at 0644: `0o100000` is the type field. Reading
/// the type field as part of the mode turns a familiar three-digit number into
/// a six-digit one that means nothing to a reader and matches no `chmod`.
#[test]
fn a_captured_file_lists_its_permission_bits_and_not_its_type_field() {
    assert_eq!(
        modes_of(vec![captured(
            "/etc/ssh/sshd_config",
            0o100_644,
            Some(b"x".to_vec())
        )]),
        vec!["644".to_string()],
    );
}

/// Directories and symlinks carry the widest type fields, so they drift most.
///
/// A directory is `0o040000 | mode` and a captured symlink is stored as the
/// fixed `0o120777`, neither of which the operator asked about.
#[test]
fn a_directory_and_a_symlink_list_permission_bits_too() {
    assert_eq!(
        modes_of(vec![
            captured("/etc/sudoers.d", 0o040_755, None),
            captured(
                "/etc/systemd/system/x.target.wants/y.service",
                0o120_777,
                None
            ),
        ]),
        vec!["755".to_string(), "777".to_string()],
    );
}

/// Setuid, setgid and sticky are permission bits and must survive the mask.
///
/// This is the guard on masking too narrowly. `& 0o777` would render
/// `/usr/bin/passwd` as `755` and hide the setuid bit that is the entire reason
/// an operator looks at that row.
#[test]
fn the_setuid_setgid_and_sticky_bits_are_kept() {
    assert_eq!(
        modes_of(vec![
            captured("/usr/bin/passwd", 0o104_755, None),
            captured("/tmp", 0o041_777, None),
        ]),
        vec!["4755".to_string(), "1777".to_string()],
    );
}

/// A path that did not exist is stored with a zero mode, and stays visible.
///
/// Rollback reads a zero mode as "remove this path", so the row is not noise:
/// it is the record of something the checkpoint will delete. It renders as `0`
/// both before and after the mask, which is asserted so a later change to the
/// absent-row display cannot happen by accident.
#[test]
fn an_absent_path_is_still_listed() {
    let detail = checkpoint_to_detail(checkpoint(), vec![captured("/etc/nftables.conf", 0, None)]);

    assert_eq!(detail.files[0].permissions, "0");
    assert!(!detail.files[0].has_content);
}

/// The rest of the mapping, so a field silently dropped is not invisible.
#[test]
fn the_detail_carries_the_checkpoint_and_counts_its_files() {
    let files = vec![
        captured("/etc/login.defs", 0o100_644, Some(b"a".to_vec())),
        captured("/etc/security/limits.conf", 0o100_600, None),
    ];
    let detail = checkpoint_to_detail(checkpoint(), files);

    assert_eq!(detail.checkpoint_id, "cp-1");
    assert_eq!(detail.checkpoint_name, "before ssh hardening");
    assert_eq!(detail.checkpoint_user, "bakri");
    assert_eq!(detail.checkpoint_created, "2023-11-14 22:13:20 UTC");
    assert_eq!(detail.file_count, 2);
    assert_eq!(detail.files.len(), 2);
    assert!(detail.files[0].has_content);
    assert!(!detail.files[1].has_content);
}

/// The desktop and the rollback must read the same mode off the same row.
///
/// This is the assertion the two-copies problem needs: the number shown and the
/// number chmodded come from one function, so they cannot drift apart without
/// this going red. Comparing against a literal here would prove only that the
/// desktop matches a literal.
#[test]
fn the_listed_mode_is_the_mode_rollback_would_chmod() {
    for mode in [0o100_644, 0o040_755, 0o104_755, 0o041_777, 0o120_777, 0] {
        let file = captured("/etc/x", mode, None);
        assert_eq!(
            modes_of(vec![file.clone()]),
            vec![file.restore_mode_string()],
            "mode {mode:o}",
        );
    }
}
