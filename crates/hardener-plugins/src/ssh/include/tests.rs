#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`include`].
//!
//! Split out of `include.rs`. This file sits in the `include/` directory
//! beside it, so `super` still resolves to `crate::include` and every
//! import carried across unchanged, private items included.

use super::*;

#[test]
fn a_live_include_yields_its_patterns() {
    assert_eq!(
        include_patterns("Include /etc/ssh/sshd_config.d/*.conf"),
        Some(vec!["/etc/ssh/sshd_config.d/*.conf".to_string()])
    );
}

#[test]
fn include_is_matched_case_insensitively_and_may_carry_several_patterns() {
    assert_eq!(
        include_patterns("  include  a.conf   b.conf "),
        Some(vec!["a.conf".to_string(), "b.conf".to_string()])
    );
}

/// Gentoo writes `Include "/etc/ssh/sshd_config.d/*.conf"`, and sshd drops
/// the quotes (`argv_split`, misc.c), so the pattern is the bare path.
#[test]
fn include_patterns_are_split_the_way_sshd_splits_them() {
    assert_eq!(
        include_patterns("Include \"/etc/ssh/sshd_config.d/*.conf\""),
        Some(vec!["/etc/ssh/sshd_config.d/*.conf".to_string()])
    );
    assert_eq!(
        include_patterns("Include '/etc/ssh/a dir/*.conf' b.conf # trailing"),
        Some(vec![
            "/etc/ssh/a dir/*.conf".to_string(),
            "b.conf".to_string()
        ])
    );
    assert_eq!(
        include_patterns("Include /etc/ssh/a\\ b.conf\tc\\\"d.conf"),
        Some(vec![
            "/etc/ssh/a b.conf".to_string(),
            "c\"d.conf".to_string()
        ])
    );
    assert_eq!(include_patterns("Include # nothing"), None);
}

/// On a real file system, where a directory that does not exist cannot be
/// listed: the quoted pattern used to be read as the relative path
/// `"/.../d/*.conf"`, and resolving failed, which on a stock Gentoo host
/// left every SSH check unchecked and the apply refusing to run.
#[tokio::test]
async fn a_quoted_include_resolves_on_a_real_file_system() {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let dropins = dir.path().join("d");
    std::fs::create_dir(&dropins).expect("the drop-in directory");
    std::fs::write(
        dropins.join("9999999gentoo-pam.conf"),
        "UsePAM yes\nPasswordAuthentication no\n",
    )
    .expect("a drop-in");
    let main = format!(
        "KbdInteractiveAuthentication no\nInclude \"{}/*.conf\"\n",
        dropins.display()
    );
    let main_path = dir.path().join("sshd_config").display().to_string();

    let resolved = resolve(&Context::new(), &main_path, &main)
        .await
        .expect("the quoted Include resolves");

    assert_eq!(
        resolved
            .effective("PasswordAuthentication")
            .map(|effective| effective.value),
        Some("no".to_string())
    );
    assert_eq!(
        resolved
            .effective("KbdInteractiveAuthentication")
            .map(|effective| effective.source),
        Some(main_path.clone()),
        "the line above the Include is read first"
    );
    assert_eq!(
        main_line_ahead_of_dropins(
            &main,
            &main_path,
            "KbdInteractiveAuthentication",
            &dropins.join("00-hardener.conf")
        )
        .map(|line| line.value),
        Some("no".to_string())
    );
    assert_eq!(
        main_line_ahead_of_dropins(
            &main,
            &main_path,
            "UsePAM",
            &dropins.join("00-hardener.conf")
        ),
        None,
        "the walk stops at the quoted Include"
    );
}

#[test]
fn a_commented_include_includes_nothing() {
    assert_eq!(
        include_patterns("# Include /etc/ssh/sshd_config.d/*.conf"),
        None
    );
    assert_eq!(include_patterns("#Include foo.conf"), None);
}

#[test]
fn other_directives_are_not_includes() {
    assert_eq!(include_patterns("PermitRootLogin no"), None);
    assert_eq!(include_patterns(""), None);
    // A bare keyword names no file.
    assert_eq!(include_patterns("Include"), None);
}

#[test]
fn glob_star_matches_the_conf_suffix() {
    assert!(glob_matches("*.conf", "99-archlinux.conf"));
    assert!(glob_matches("*.conf", ".conf"));
    assert!(!glob_matches("*.conf", "readme.txt"));
    assert!(!glob_matches("*.conf", "conf"));
}

#[test]
fn glob_question_mark_matches_exactly_one_character() {
    assert!(glob_matches("0?-base.conf", "01-base.conf"));
    assert!(!glob_matches("0?-base.conf", "0-base.conf"));
    assert!(!glob_matches("0?-base.conf", "012-base.conf"));
}

#[test]
fn glob_handles_a_star_that_must_backtrack() {
    // The naive matcher fails this: the first `*` must give back the `a`
    // it consumed so the literal `ab` can match at the end.
    assert!(glob_matches("*ab", "aab"));
    assert!(glob_matches("*a*b", "xaybzb"));
    assert!(!glob_matches("*ab", "aba"));
}

#[test]
fn a_pattern_with_a_character_class_is_refused_not_guessed() {
    // Treating it as "matches nothing" would hide a drop-in, which is the
    // false pass this module exists to remove.
    assert!(!pattern_is_supported("[0-9]*.conf"));
    assert!(pattern_is_supported("*.conf"));
}

#[test]
fn a_relative_include_resolves_under_etc_ssh() {
    assert_eq!(
        absolute_pattern("sshd_config.d/*.conf", "/etc/ssh/sshd_config"),
        Some(PathBuf::from("/etc/ssh/sshd_config.d/*.conf"))
    );
    assert_eq!(
        absolute_pattern("/somewhere/else.conf", "/etc/ssh/sshd_config"),
        Some(PathBuf::from("/somewhere/else.conf"))
    );
}

#[test]
fn a_relative_include_from_the_vendor_layer_is_refused_rather_than_guessed() {
    // sshd resolves a relative include against its compiled sysconfdir,
    // which this tool cannot read. Guessing /etc/ssh for a file under
    // /usr/etc would silently mis-locate the fragment and report a value
    // that is not in force.
    assert_eq!(
        absolute_pattern("sshd_config.d/*.conf", "/usr/etc/ssh/sshd_config"),
        None
    );
    // An absolute pattern needs no base, so it still resolves.
    assert_eq!(
        absolute_pattern(
            "/usr/etc/ssh/sshd_config.d/40-suse.conf",
            "/usr/etc/ssh/sshd_config"
        ),
        Some(PathBuf::from("/usr/etc/ssh/sshd_config.d/40-suse.conf"))
    );
}

/// A resolved configuration from `(path, content)` pairs in sshd's reading
/// order, with no executor behind it.
fn resolved(segments: &[(&str, &str)]) -> ResolvedConfig {
    ResolvedConfig {
        segments: segments
            .iter()
            .map(|(path, content)| (path.to_string(), content.to_string()))
            .collect(),
    }
}

#[test]
fn a_legacy_spelling_answers_for_the_current_keyword() {
    // Rocky 10's 50-redhat.conf, which ships the old name and no other.
    let config = resolved(&[(
        "/etc/ssh/sshd_config.d/50-redhat.conf",
        "ChallengeResponseAuthentication no\n",
    )]);
    let effective = config
        .effective("KbdInteractiveAuthentication")
        .expect("the old name sets the same option");
    assert_eq!(effective.value, "no");
    assert_eq!(effective.keyword, "ChallengeResponseAuthentication");
}

#[test]
fn the_first_line_wins_whichever_spelling_it_uses() {
    // Both orders checked with `sshd -G` on OpenSSH 10.6p1: The earlier line
    // is the one in force, and its name makes no difference.
    for (content, expected) in [
        (
            "ChallengeResponseAuthentication no\nKbdInteractiveAuthentication yes\n",
            "no",
        ),
        (
            "KbdInteractiveAuthentication yes\nSkeyAuthentication no\n",
            "yes",
        ),
    ] {
        let config = resolved(&[("/etc/ssh/sshd_config", content)]);
        assert_eq!(
            config
                .effective("KbdInteractiveAuthentication")
                .map(|effective| effective.value)
                .as_deref(),
            Some(expected),
            "{content}"
        );
    }
}

#[test]
fn a_keyword_is_not_answered_by_a_different_option() {
    let config = resolved(&[("/etc/ssh/sshd_config", "KbdInteractiveAuthentication no\n")]);
    assert_eq!(config.effective("PasswordAuthentication"), None);
}

/// The resolver used to read each file through `parse_config_value`. These
/// are the guarantees that reader gave, held here now that the lines are
/// walked directly: A comment sets nothing, neither does a keyword with no
/// value, and `Key=value`, indentation and case are all accepted.
#[test]
fn a_comment_or_a_bare_keyword_sets_nothing() {
    let config = resolved(&[(
        "/etc/ssh/sshd_config",
        "#PermitRootLogin yes\nPermitRootLogin\n  permitrootlogin=no\n",
    )]);
    assert_eq!(
        config
            .effective("PermitRootLogin")
            .map(|effective| effective.value)
            .as_deref(),
        Some("no")
    );
}

#[test]
fn a_list_valued_directive_yields_every_argument() {
    // sshd accepts the quotes and the trailing comment, and `sshd -G` prints
    // the two lists bare.
    let config = resolved(&[(
        "/etc/ssh/sshd_config",
        "AuthenticationMethods \"publickey,keyboard-interactive\" publickey # either\n",
    )]);
    assert_eq!(
        config.effective_arguments("AuthenticationMethods"),
        Some(vec!["publickey,keyboard-interactive", "publickey"])
    );
}

/// Gentoo includes the drop-ins at the foot of the main file, so a line above
/// that Include is read before every drop-in; every other layout puts the
/// Include first, where nothing is above it (#185 round 2).
#[test]
fn only_a_main_file_line_above_the_drop_in_include_comes_first() {
    let fragment = Path::new("/etc/ssh/sshd_config.d/00-hardener.conf");
    let gentoo = "#PasswordAuthentication yes\n\
                  ChallengeResponseAuthentication no\n\
                  #UsePAM no\n\
                  Include \"/etc/ssh/sshd_config.d/*.conf\"\n\
                  KbdInteractiveAuthentication yes\n";
    let line = main_line_ahead_of_dropins(
        gentoo,
        "/etc/ssh/sshd_config",
        "KbdInteractiveAuthentication",
        fragment,
    )
    .expect("the old spelling above the Include answers");
    assert_eq!(
        (line.keyword.as_str(), line.value.as_str()),
        ("ChallengeResponseAuthentication", "no")
    );

    // Debian: the Include first, the `no` below it, which loses to a drop-in.
    let debian = "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\n";
    assert_eq!(
        main_line_ahead_of_dropins(
            debian,
            "/etc/ssh/sshd_config",
            "KbdInteractiveAuthentication",
            fragment
        ),
        None
    );

    // An Include of some other directory does not stop the walk, and a
    // commented default sets nothing.
    let other = "Include /etc/ssh/other/*.conf\n#KbdInteractiveAuthentication yes\n\
                 KbdInteractiveAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\n";
    assert_eq!(
        main_line_ahead_of_dropins(
            other,
            "/etc/ssh/sshd_config",
            "KbdInteractiveAuthentication",
            fragment
        )
        .map(|line| line.value),
        Some("no".to_string())
    );

    // A line inside a Match block is not a global one.
    let scoped = "Match User eric\n    KbdInteractiveAuthentication no\n\
                  Include /etc/ssh/sshd_config.d/*.conf\n";
    assert_eq!(
        main_line_ahead_of_dropins(
            scoped,
            "/etc/ssh/sshd_config",
            "KbdInteractiveAuthentication",
            fragment
        ),
        None
    );
}

#[test]
fn match_blocks_end_at_the_next_match_or_the_end_of_their_file() {
    let config = resolved(&[
        (
            "/etc/ssh/sshd_config",
            "PasswordAuthentication no\nMatch User eric\n    \
             AuthenticationMethods publickey keyboard-interactive\n    \
             ChallengeResponseAuthentication no\nMatch Address 10.0.0.0/8\n    \
             # a comment\n    AuthenticationMethods \"publickey\"\n",
        ),
        (
            "/etc/ssh/sshd_config.d/50-ci.conf",
            "Match User ci\n    AuthenticationMethods publickey\n",
        ),
        ("/etc/ssh/sshd_config.d/99-global.conf", "PrintMotd no\n"),
    ]);
    let blocks = config.match_blocks();
    assert_eq!(
        blocks
            .iter()
            .map(|block| (block.source, block.criteria))
            .collect::<Vec<_>>(),
        vec![
            ("/etc/ssh/sshd_config", "User eric"),
            ("/etc/ssh/sshd_config", "Address 10.0.0.0/8"),
            ("/etc/ssh/sshd_config.d/50-ci.conf", "User ci"),
        ]
    );
    assert_eq!(
        blocks[0].arguments("AuthenticationMethods"),
        Some(vec!["publickey", "keyboard-interactive"])
    );
    // The old spelling answers for the current name inside a block as well.
    assert_eq!(
        blocks[0].arguments("KbdInteractiveAuthentication"),
        Some(vec!["no"])
    );
    assert_eq!(
        blocks[1].arguments("AuthenticationMethods"),
        Some(vec!["publickey"])
    );
    assert_eq!(blocks[2].arguments("KbdInteractiveAuthentication"), None);
}

/// The `sshd -t` candidate, held against a real sshd rather than against the
/// text a mock test expects (#185). On disk the fragment still says
/// `KbdInteractiveAuthentication no`, from an apply before the operator's own
/// `10-2fa.conf`, and the new fragment body drops it. The old candidate
/// pasted the new body ahead of the main file, whose Include then read the
/// stale copy as well, and sshd refused it; the staged one reads the new body
/// where the fragment sorts. CI's root-gated job runs this after installing
/// openssh-server.
#[tokio::test]
#[ignore = "Requires root and an sshd binary"]
async fn real_sshd_accepts_the_staged_candidate_where_the_old_shape_failed() {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let root = dir.path();
    let keygen = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(root.join("hostkey"))
        .status()
        .expect("ssh-keygen runs");
    assert!(keygen.success(), "ssh-keygen made a host key");
    let dropins = root.join("d");
    std::fs::create_dir(&dropins).expect("the drop-in directory");
    let fragment = dropins.join("00-hardener.conf");
    std::fs::write(&fragment, "KbdInteractiveAuthentication no\n").expect("the stale fragment");
    std::fs::write(
        dropins.join("10-2fa.conf"),
        "AuthenticationMethods publickey,keyboard-interactive\n\
         KbdInteractiveAuthentication yes\nUsePAM yes\n",
    )
    .expect("the operator's drop-in");
    let main_path = root.join("main.conf");
    let main = format!(
        "Include {}/*.conf\nHostKey {}/hostkey\nPasswordAuthentication no\n",
        dropins.display(),
        root.display()
    );
    std::fs::write(&main_path, &main).expect("the main file");
    let new_body = "MaxAuthTries 3\n";
    let staged = root.join("staged-fragment.conf");
    std::fs::write(&staged, new_body).expect("the staged fragment");

    let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .expect("this test needs an sshd binary: install openssh-server");
    let sshd_t = |candidate: &str, name: &str| {
        let path = root.join(name);
        std::fs::write(&path, candidate).expect("the candidate");
        std::process::Command::new(&sshd)
            .arg("-t")
            .arg("-f")
            .arg(&path)
            .output()
            .expect("sshd -t runs")
    };

    let old = sshd_t(&format!("{new_body}\n{main}"), "old-candidate.conf");
    assert!(
        !old.status.success(),
        "the old shape reads the stale fragment and sshd refuses it"
    );
    assert!(
        String::from_utf8_lossy(&old.stderr).contains("keyboard-interactive"),
        "{}",
        String::from_utf8_lossy(&old.stderr)
    );

    let ctx = Context::new();
    let candidate = stage_fragment_includes(
        &ctx,
        &main_path.display().to_string(),
        &main,
        &fragment,
        Some(&staged),
    )
    .await
    .expect("the candidate stages");
    let new = sshd_t(&candidate, "new-candidate.conf");
    assert!(
        new.status.success(),
        "sshd -t refused the staged candidate:\n{candidate}\n{}",
        String::from_utf8_lossy(&new.stderr)
    );
}
