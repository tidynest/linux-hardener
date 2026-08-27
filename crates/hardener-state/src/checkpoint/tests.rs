#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`checkpoint`](super).
//!
//! `restore_mode_string` had none, in the crate that owns it. Narrowing
//! `MODE_PERMISSION_BITS` from `0o7777` to `0o777` left all 146 of this crate's
//! tests green while every rollback would `chmod` setuid, setgid and sticky off
//! the paths it restored. The only test in the workspace that failed was
//! `the_setuid_setgid_and_sticky_bits_are_kept`, in `src-tauri`, which reaches
//! this function through the desktop's checkpoint expander.
//!
//! That is the wrong place for the proof to live. The expander only displays
//! the string; the rollback **executes** it, as the mode argument to `chmod`.
//! A crate whose own suite cannot see its most dangerous mutation is relying on
//! a caller two crates away to notice, and that caller could be deleted for
//! reasons having nothing to do with file modes.

use super::*;

/// A file row at `permissions`, with the fields this decision does not read
/// left at their empty values.
fn row(permissions: u32) -> FileState {
    FileState {
        file_path: "/usr/bin/sudo".to_string(),
        file_content: None,
        file_permissions: permissions,
        file_owner_uid: 0,
        file_owner_gid: 0,
        file_link_target: None,
        file_content_absence: None,
    }
}

/// The type field is dropped and the permission bits are not.
///
/// `0o100644` is what `stat` reports for an ordinary file at `644`: the
/// `0o100000` above it says "regular file". Showing that to an operator under a
/// column headed permissions read as `100644`, and handing it to `chmod` would
/// set bits nobody captured.
#[test]
fn the_file_type_field_is_dropped_and_the_permissions_are_not() {
    assert_eq!(row(0o100644).restore_mode_string(), "644");
    assert_eq!(row(0o040755).restore_mode_string(), "755");
}

/// **The mutation this file exists for.** Narrow the mask to `0o777` and this
/// is what goes red.
///
/// Each of the three is a real bit on a real path a rollback restores: setuid on
/// `/usr/bin/sudo`, setgid on a shared group directory, sticky on `/tmp`. A
/// rollback that dropped them would silently undo the very thing the checkpoint
/// was taken to protect, and would report success, because `chmod 755` succeeds
/// perfectly well.
///
/// Asserted one bit at a time as well as all three together. All three at once
/// alone would pass a mask that kept any one of them.
#[test]
fn setuid_setgid_and_sticky_survive_the_mask() {
    assert_eq!(row(0o104755).restore_mode_string(), "4755", "setuid");
    assert_eq!(row(0o102755).restore_mode_string(), "2755", "setgid");
    assert_eq!(row(0o041777).restore_mode_string(), "1777", "sticky");
    assert_eq!(row(0o107777).restore_mode_string(), "7777", "all three");
}

/// The string is what `chmod` is handed, so its shape is part of the contract.
///
/// Octal, unpadded, no `0o` and no leading zero. `format!("{:o}")` gives that
/// today; a later switch to `{:#o}` or `{:04o}` would produce `0o644` or `0644`.
/// The second of those `chmod` accepts and the first it does not, which is
/// exactly the kind of difference a test asserting only the number would miss.
#[test]
fn the_mode_is_rendered_as_chmod_takes_it() {
    let rendered = row(0o100644).restore_mode_string();

    assert!(!rendered.starts_with('0'), "no leading zero: {rendered}");
    assert!(!rendered.contains('o'), "no radix prefix: {rendered}");
    assert!(
        rendered.chars().all(|c| ('0'..='7').contains(&c)),
        "octal digits only: {rendered}"
    );
}

/// A row with no permission bits renders `0`, and that is a record of a
/// deletion rather than a file nobody may read.
///
/// Rollback reads the zero as "remove this path". Worth its own case because
/// `0` is the one output that means something other than a mode, and a mask
/// change that turned it into `""` or `"0000"` would be read by neither the
/// rollback nor the operator as the same thing.
#[test]
fn a_row_with_no_permission_bits_renders_a_bare_zero() {
    assert_eq!(row(0).restore_mode_string(), "0");
    assert_eq!(
        row(0o100000).restore_mode_string(),
        "0",
        "a type field with no permission bits is still a deletion record"
    );
}
