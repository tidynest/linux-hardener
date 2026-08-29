//! Fuzzes the PAM parsing halves: `stack_loads_module`, `inline_arg_in_content`
//! and `apply_exact_directive`.
//!
//! The first two consume `/etc/pam.d` stack files and the third rewrites the
//! `/etc/security` conffiles and `login.defs`; all of that content arrives
//! from remote hosts over the SSH executor, which is input the operator does
//! not control. A stack line is also a place where one wrong character
//! changes the answer (`even_deny_root` must never match `deny`, a commented
//! line must never count as loading anything), which is the shape of bug a
//! corpus of PAM-shaped text finds and a fixture hand-written from the same
//! reading as the code does not.
//!
//! Invariants asserted, beyond not panicking:
//!
//! - `stack_loads_module` answers true exactly when the content holds a live
//!   (uncommented) line naming the module. The content is built from the
//!   input, so the expectation is derived from construction.
//! - `inline_arg_in_content` returns the `arg=value` token's value exactly
//!   when a live module line carries one, ignoring a commented decoy line
//!   that names the module and carries the token, and is deterministic.
//! - `apply_exact_directive` converges: after a first application, parsing
//!   the file in the syntax it was written in finds the target value, and a
//!   second application takes the Skipped branch, changing neither the
//!   content nor the changed flag. A file this loop cannot settle is a file
//!   every run rewrites, which is the non-convergence an earlier release
//!   shipped.

#![no_main]

use hardener_common::file_utils::{ConfigFormat, parse_config_value};
use hardener_core::ChangeType;
use hardener_plugins::fuzz_seams::pam_parsing::{
    apply_exact_directive, inline_arg_in_content, stack_loads_module,
};
use libfuzzer_sys::fuzz_target;

const MODULE: &str = "pam_pwquality.so";
const ARG: &str = "deny";

fn simple(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn simple_prefix(raw: &str) -> Option<String> {
    let taken: String = raw
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    simple(&taken).then_some(taken)
}

fuzz_target!(|data: &[u8]| {
    let (head, tail) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    // tail: a flags byte, a format byte, then the directive key.
    let flags = tail.first().copied().unwrap_or(0);
    let format = match tail.get(1) {
        Some(b'k') => ConfigFormat::KeyValue,
        Some(b'a') => ConfigFormat::Auto,
        _ => ConfigFormat::SpaceSeparated,
    };
    let key = simple_prefix(&String::from_utf8_lossy(&tail[2.min(tail.len())..]))
        .unwrap_or_else(|| "minlen".to_string());
    let value = simple_prefix(&String::from_utf8_lossy(head)).unwrap_or_else(|| "9".to_string());

    // The stack content, built so the expectation is known: a commented decoy
    // that names the module and carries the token (flag 0x1), a live module
    // line without the token (0x2), and a live module line with it (0x4).
    let decoy = format!("# auth required {MODULE} {ARG}=decoy");
    let bare = format!("auth required {MODULE}");
    let armed = format!("auth required {MODULE} {ARG}={value}");
    let mut lines: Vec<&str> = Vec::new();
    if flags & 0x1 != 0 {
        lines.push(&decoy);
    }
    if flags & 0x2 != 0 {
        lines.push(&bare);
    }
    if flags & 0x4 != 0 {
        lines.push(&armed);
    }
    let content = lines.join("\n");

    let loads = flags & 0x6 != 0;
    assert_eq!(
        stack_loads_module(&content, MODULE),
        loads,
        "loads exactly when a live line names the module; a comment never loads"
    );

    let inline = if flags & 0x4 != 0 {
        Some(value.clone())
    } else {
        None
    };
    assert_eq!(
        inline_arg_in_content(&content, MODULE, ARG).map(str::to_string),
        inline,
        "the token counts only on a live module line"
    );
    assert_eq!(
        inline_arg_in_content(&content, MODULE, ARG).map(str::to_string),
        inline,
        "and answers the same way twice"
    );

    // Convergence of the conffile writer, starting from arbitrary content.
    let mut file = String::from_utf8_lossy(head).into_owned();
    let mut changed = false;
    let mut changes = Vec::new();
    apply_exact_directive(
        &mut file,
        &mut changed,
        &mut changes,
        &key,
        &value,
        format,
        "fuzz.conf",
    );
    assert_eq!(
        parse_config_value(&file, &key, format, true).as_deref(),
        Some(value.as_str()),
        "after an application, the file parses to the target in its own syntax"
    );

    let settled = file.clone();
    let changed_before = changed;
    apply_exact_directive(
        &mut file,
        &mut changed,
        &mut changes,
        &key,
        &value,
        format,
        "fuzz.conf",
    );
    assert_eq!(
        file, settled,
        "a second application leaves the file byte-identical"
    );
    assert_eq!(
        changed, changed_before,
        "a second application does not report the file changed"
    );
    assert_eq!(
        changes.last().map(|c| c.change_type),
        Some(ChangeType::Skipped),
        "a second application records the no-op"
    );
});
