use super::*;

fn exception(value: &str, reason: &str) -> PolicyException {
    PolicyException {
        value: value.to_string(),
        allowed: true,
        reason: reason.to_string(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: None,
    }
}

/// The operator's file is theirs. An edit that reformats it, drops a comment or
/// reorders a section is a change nobody asked for, and it lands in a file that
/// is read by root.
#[test]
fn an_edit_leaves_every_unrelated_byte_alone() {
    let original = "\
# my notes
[global]
disabled_plugins = []

[ssh]
# keep this comment
enabled = true
";
    let written = upsert_exception(
        original,
        "ssh",
        "PermitRootLogin",
        &exception("yes", "bastion"),
    )
    .expect("write must succeed");

    assert!(
        written.contains("# my notes"),
        "leading comment survives: {written}"
    );
    assert!(
        written.contains("# keep this comment"),
        "inner comment survives: {written}"
    );
    assert!(
        written.contains("disabled_plugins = []"),
        "unrelated section survives: {written}"
    );
    assert!(
        written.contains("[ssh.exceptions.PermitRootLogin]"),
        "the exception table is written: {written}"
    );
    assert!(
        written.contains(r#"value = "yes""#),
        "the pinned value is written: {written}"
    );
    assert!(
        written.contains("allowed = true"),
        "allowed is written: {written}"
    );
    assert!(
        written.contains(r#"reason = "bastion""#),
        "the reason is written: {written}"
    );
}

/// A dotted key is not a bare TOML key. Written unquoted, `net.ipv4.ip_forward`
/// becomes three nested tables, the file still parses, and nothing tells the
/// operator their exception names something else.
#[test]
fn a_dotted_key_is_written_quoted() {
    let written = upsert_exception(
        "",
        "kernel",
        "net.ipv4.ip_forward",
        &exception("1", "router"),
    )
    .expect("write must succeed");

    assert!(
        written.contains(r#"[kernel.exceptions."net.ipv4.ip_forward"]"#),
        "a dotted key is one quoted key, not three tables: {written}"
    );
}

/// The optional fields are optional in the file too. Writing them as empty
/// strings would make an unapproved exception look approved by nobody, which is
/// not the same as unapproved.
#[test]
fn absent_optional_fields_are_not_written() {
    let written = upsert_exception("", "services", "bluetooth", &exception("enabled", "laptop"))
        .expect("write must succeed");

    assert!(
        !written.contains("approved_by"),
        "no empty approver: {written}"
    );
    assert!(!written.contains("ticket"), "no empty ticket: {written}");
    assert!(!written.contains("expires"), "no empty expiry: {written}");
}

/// Present optional fields are written.
#[test]
fn supplied_optional_fields_are_written() {
    let mut e = exception("enabled", "laptop");
    e.approved_by = Some("eric".to_string());
    e.ticket = Some("OPS-12".to_string());
    e.expires = Some("2027-01-01".to_string());

    let written = upsert_exception("", "services", "bluetooth", &e).expect("write must succeed");

    assert!(written.contains(r#"approved_by = "eric""#), "{written}");
    assert!(written.contains(r#"ticket = "OPS-12""#), "{written}");
    assert!(written.contains(r#"expires = "2027-01-01""#), "{written}");
}

/// A second write to the same key replaces it rather than appending a duplicate
/// table, which TOML would reject on the next load.
#[test]
fn a_second_write_to_one_key_replaces_it() {
    let first = upsert_exception("", "services", "bluetooth", &exception("enabled", "first"))
        .expect("first write");
    let second = upsert_exception(
        &first,
        "services",
        "bluetooth",
        &exception("enabled", "second"),
    )
    .expect("second write");

    assert_eq!(
        second.matches("[services.exceptions.bluetooth]").count(),
        1,
        "one table, not two: {second}"
    );
    assert!(second.contains(r#"reason = "second""#), "{second}");
    assert!(!second.contains(r#"reason = "first""#), "{second}");
    second
        .parse::<toml_edit::DocumentMut>()
        .expect("the result must still parse");
}

/// Add then remove returns the file to what it was. Anything else means the
/// edit left a scar: an emptied table, a stray blank line, a lost comment.
#[test]
fn add_then_remove_restores_the_file() {
    let original = "\
# notes
[ssh]
enabled = true
";
    let written = upsert_exception(
        original,
        "ssh",
        "PermitRootLogin",
        &exception("yes", "bastion"),
    )
    .expect("write");
    let restored = remove_exception(&written, "ssh", "PermitRootLogin").expect("remove");

    assert_eq!(restored, original, "add then remove must be a round trip");
}

/// Refusing beats guessing. A file this cannot parse is a file whose keys this
/// cannot preserve, and a partial write loses settings the operator never saw
/// this touch.
#[test]
fn a_parse_error_refuses_the_write() {
    let err = upsert_exception("this is not = = toml", "ssh", "k", &exception("v", "r"))
        .expect_err("invalid TOML must refuse");

    assert!(
        err.to_string().contains("not valid TOML"),
        "the refusal must name the cause: {err}"
    );
}

/// Removing something that is not there is not success. A typo against a
/// hand-edited file would otherwise report done and change nothing.
#[test]
fn removing_an_absent_key_is_an_error() {
    let err = remove_exception("[ssh]\nenabled = true\n", "ssh", "PermitRootLogin")
        .expect_err("an absent key must error");

    assert!(
        err.to_string().contains("PermitRootLogin"),
        "the error names the key: {err}"
    );
}

/// A freshly created `exceptions` table holds only the keyed table beneath
/// it, so it should contribute no header line of its own: the file should
/// read as one table naming the exception, not two.
#[test]
fn a_new_exceptions_table_has_no_empty_header_of_its_own() {
    let written = upsert_exception("", "services", "bluetooth", &exception("enabled", "laptop"))
        .expect("write must succeed");

    assert!(
        !written.contains("[services.exceptions]\n"),
        "the intermediate table must not print its own header: {written}"
    );
    assert!(
        written.contains("[services.exceptions.bluetooth]"),
        "the keyed table is still written: {written}"
    );
}
