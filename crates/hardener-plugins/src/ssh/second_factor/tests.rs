#![cfg(test)]
//
// Gated here as well as at the declaration, for the reason given at the top
// of `ssh/tests.rs`: The validators decide test context from the file itself.

//! Unit tests for [`second_factor`](super).

use super::*;
use hardener_core::{CommandOutput, MockExecutor};

const POLICY: &str = "publickey,keyboard-interactive";

fn resolved(segments: &[(&str, &str)]) -> ResolvedConfig {
    ResolvedConfig::from_segments(
        segments
            .iter()
            .map(|(path, content)| (path.to_string(), content.to_string()))
            .collect(),
    )
}

fn config_asking_for(value: &str) -> PluginConfig {
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("AuthenticationMethods".to_string(), value.to_string());
    config
}

#[test]
fn only_a_supported_policy_is_requested() {
    assert_eq!(requested(&PluginConfig::default()), None);
    assert_eq!(requested(&config_asking_for(POLICY)), Some(POLICY));
    assert_eq!(
        requested(&config_asking_for("publickey,keyboard-interactive:pam")),
        Some("publickey,keyboard-interactive:pam")
    );
    // Refused at load time; ignored if it arrives some other way.
    assert_eq!(requested(&config_asking_for("publickey,password")), None);
}

/// Each way a host can fall short, in the words the finding reports.
#[test]
fn the_shortfall_names_the_first_thing_missing() {
    let cases: &[(&str, Option<&str>)] = &[
        ("", Some("not set")),
        ("AuthenticationMethods publickey\n", Some("publickey")),
        (
            "AuthenticationMethods publickey,keyboard-interactive\n\
             KbdInteractiveAuthentication no\nUsePAM yes\n",
            Some("publickey,keyboard-interactive with KbdInteractiveAuthentication no"),
        ),
        (
            "AuthenticationMethods publickey,keyboard-interactive\n",
            Some("publickey,keyboard-interactive with UsePAM not set"),
        ),
        (
            "AuthenticationMethods publickey,keyboard-interactive\nUsePAM no\n",
            Some("publickey,keyboard-interactive with UsePAM no"),
        ),
        (
            "AuthenticationMethods publickey,keyboard-interactive\nUsePAM yes\n",
            None,
        ),
        (
            "AuthenticationMethods publickey,keyboard-interactive\n\
             ChallengeResponseAuthentication yes\nUsePAM yes\n",
            None,
        ),
    ];
    for (content, expected) in cases {
        let host = resolved(&[("/etc/ssh/sshd_config", content)]);
        assert_eq!(shortfall(&host).as_deref(), *expected, "for:\n{content}");
    }
}

/// A stricter list beneath the fragment is kept, and the fragment then
/// carries only the two settings the list depends on.
#[test]
fn a_stricter_list_beneath_the_fragment_is_not_written_over() {
    let host = resolved(&[(
        "/etc/ssh/sshd_config.d/10-2fa.conf",
        "AuthenticationMethods publickey,publickey,keyboard-interactive\n",
    )]);
    let plan = plan(POLICY, &host);
    assert!(!plan.writes_methods);
    assert_eq!(
        directives(&plan)
            .iter()
            .map(|directive| directive.keyword)
            .collect::<Vec<_>>(),
        vec![KBD_INTERACTIVE, USE_PAM]
    );
    assert_eq!(
        planned_lists(Some(&plan), &host),
        Some(vec!["publickey,publickey,keyboard-interactive"])
    );
}

/// The fragment's own list does not count as already being there: it is the
/// file the apply is about to rewrite.
#[test]
fn the_fragments_own_list_is_written_again_and_dropped_without_the_policy() {
    let host = resolved(&[
        (
            dropin::DROPIN_PATH,
            "AuthenticationMethods publickey,keyboard-interactive\n\
             KbdInteractiveAuthentication yes\nUsePAM yes\n",
        ),
        (
            "/etc/ssh/sshd_config.d/99-archlinux.conf",
            "KbdInteractiveAuthentication no\n",
        ),
    ]);
    let plan = plan(POLICY, &host);
    assert!(plan.writes_methods, "the fragment is rewritten whole");
    assert_eq!(plan.shortfall, None, "the host enforces it today");
    assert!(
        pending(&plan, &host).is_empty(),
        "nothing changes, so nothing is reported"
    );
    // Taken out of the config: the rewrite drops the list, so
    // keyboard-interactive is judged against what is left.
    assert_eq!(planned_lists(None, &host), None);
}

#[test]
fn the_pending_settings_are_those_that_differ() {
    let host = resolved(&[(
        "/etc/ssh/sshd_config",
        "KbdInteractiveAuthentication no\nUsePAM yes\n",
    )]);
    let plan = plan(POLICY, &host);
    let pending: Vec<(&str, Option<String>)> = pending(&plan, &host)
        .into_iter()
        .map(|(directive, now)| (directive.keyword, now))
        .collect();
    assert_eq!(
        pending,
        vec![
            ("AuthenticationMethods", None),
            (KBD_INTERACTIVE, Some("no".to_string())),
        ]
    );
}

#[test]
fn the_compliance_mappings_are_the_multi_factor_controls_and_are_not_covered() {
    let ids: Vec<String> = compliance()
        .into_iter()
        .map(|mapping| mapping.compliance_control_id)
        .collect();
    assert_eq!(ids, vec!["IA-2(1)", "IA-2(2)"]);
    // A host that never opted in must not pass these by default.
    let covered = super::super::coverage();
    assert!(
        !covered
            .iter()
            .any(|mapping| ids.contains(&mapping.compliance_control_id)),
        "multi-factor controls must stay out of coverage()"
    );
}

// -----------------------------------------------------------------------------
// PAM
// -----------------------------------------------------------------------------

#[test]
fn auth_steps_follow_every_shipped_spelling() {
    // Debian and Ubuntu: @include, and a bracketed control over two words.
    assert_eq!(
        auth_steps(
            "# PAM configuration for the Secure Shell service\n\
             @include common-auth\n\
             account    required     pam_nologin.so\n"
        ),
        vec![AuthStep::Include("common-auth".to_string())]
    );
    assert_eq!(
        auth_steps("auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"),
        vec![AuthStep::Module("pam_unix.so".to_string())]
    );
    // Fedora, RHEL and openSUSE: substack; Arch and Gentoo: include.
    assert_eq!(
        auth_steps(
            "auth       substack     password-auth\n\
             auth       include      postlogin\n\
             -auth      optional     /usr/lib64/security/pam_systemd_home.so\n"
        ),
        vec![
            AuthStep::Include("password-auth".to_string()),
            AuthStep::Include("postlogin".to_string()),
            AuthStep::Module("pam_systemd_home.so".to_string()),
        ]
    );
    // Other types are not the prompt's business.
    assert!(auth_steps("password required pam_unix.so\nsession include system-login\n").is_empty());
}

fn pam_host(files: &[(&str, &str)]) -> MockExecutor {
    files
        .iter()
        .fold(MockExecutor::new(), |executor, (path, content)| {
            executor.with_file(path, content)
        })
}

#[tokio::test]
async fn the_pam_stack_is_followed_to_pam_unix() {
    // Arch and Gentoo nest three deep.
    let executor = pam_host(&[
        ("/etc/pam.d/sshd", "auth include system-remote-login\n"),
        (
            "/etc/pam.d/system-remote-login",
            "auth include system-login\n",
        ),
        ("/etc/pam.d/system-login", "auth include system-auth\n"),
        (
            "/etc/pam.d/system-auth",
            "auth required pam_faillock.so preauth\nauth [success=1 default=bad] pam_unix.so try_first_pass nullok\n",
        ),
    ]);
    assert_eq!(
        pam_answers_with_password(&executor).await,
        PamAnswer::Password {
            module: "pam_unix.so".to_string(),
            file: "/etc/pam.d/system-auth".to_string(),
        }
    );
}

#[tokio::test]
async fn opensuses_vendor_pam_file_is_found_under_usr_lib() {
    let executor = pam_host(&[
        (
            "/usr/lib/pam.d/sshd",
            "auth requisite pam_nologin.so\nauth substack common-auth\n",
        ),
        (
            "/etc/pam.d/common-auth",
            "auth required pam_unix.so try_first_pass\n",
        ),
    ]);
    assert!(matches!(
        pam_answers_with_password(&executor).await,
        PamAnswer::Password { .. }
    ));
}

#[tokio::test]
async fn a_stack_with_no_password_module_is_refused_by_name() {
    let executor = pam_host(&[(
        "/etc/pam.d/sshd",
        "auth required pam_google_authenticator.so\n",
    )]);
    let answer = pam_answers_with_password(&executor).await;
    assert_eq!(
        answer,
        PamAnswer::NoPassword {
            files: vec!["/etc/pam.d/sshd".to_string()]
        }
    );
    assert!(
        answer
            .refusal()
            .is_some_and(|reason| reason.contains("/etc/pam.d/sshd")),
        "the refusal names the file it read"
    );
}

#[tokio::test]
async fn a_missing_pam_file_is_unknown_and_a_loop_ends() {
    assert!(matches!(
        pam_answers_with_password(&MockExecutor::new()).await,
        PamAnswer::Unknown(_)
    ));
    let looping = pam_host(&[
        ("/etc/pam.d/sshd", "auth include common\n"),
        ("/etc/pam.d/common", "auth include sshd\n"),
    ]);
    assert!(matches!(
        pam_answers_with_password(&looping).await,
        PamAnswer::NoPassword { .. }
    ));
}

// -----------------------------------------------------------------------------
// sshd -T and accounts
// -----------------------------------------------------------------------------

#[test]
fn the_sshd_dump_is_read_for_the_three_settings_the_guards_use() {
    let effective = parse_sshd_dump(
        "port 22\n\
         permitrootlogin without-password\n\
         authenticationmethods publickey,keyboard-interactive publickey\n\
         authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n",
    )
    .expect("a dump with authenticationmethods parses");
    assert_eq!(
        effective,
        Effective {
            methods: vec![
                "publickey,keyboard-interactive".to_string(),
                "publickey".to_string()
            ],
            permit_root_login: "without-password".to_string(),
            authorized_keys_files: vec![
                ".ssh/authorized_keys".to_string(),
                ".ssh/authorized_keys2".to_string()
            ],
        }
    );
    assert_eq!(parse_sshd_dump("port 22\n"), None);
}

#[test]
fn root_gets_in_on_its_key_only_where_sshd_lets_root_use_one() {
    let dump = |root: &str| Effective {
        methods: vec!["publickey".to_string()],
        permit_root_login: root.to_string(),
        authorized_keys_files: Vec::new(),
    };
    assert!(key_gets_in(&dump("prohibit-password"), 0));
    assert!(key_gets_in(&dump("without-password"), 0));
    assert!(!key_gets_in(&dump("no"), 0));
    assert!(!key_gets_in(&dump("forced-commands-only"), 0));
    assert!(key_gets_in(&dump("no"), 1000), "the rule is root's alone");
    let behind_password = Effective {
        methods: vec![POLICY.to_string()],
        ..dump("prohibit-password")
    };
    assert!(!key_gets_in(&behind_password, 1000));
}

#[test]
fn accounts_are_marked_by_whether_shadow_holds_a_usable_hash() {
    let accounts = parse_accounts(
        "root:x:0:0:root:/root:/bin/bash\n\
         eric:x:1000:1000::/home/eric:/bin/bash\n\
         deploy:x:1001:1001::/home/deploy:/bin/sh\n\
         git:x:998:998::/srv/git:/usr/bin/git-shell\n\
         nobody:x:65534:65534::/:/usr/sbin/nologin\n\
         broken line\n",
        "root:!:20000::::::\n\
         eric:$y$j9T$salt$hash:20000:0:99999:7:::\n\
         deploy:!!:20000::::::\n\
         git:*:20000::::::\n",
    );
    let marked: Vec<(&str, u32, bool)> = accounts
        .iter()
        .map(|account| (account.name.as_str(), account.uid, account.usable_password))
        .collect();
    assert_eq!(
        marked,
        vec![
            ("root", 0, false),
            ("eric", 1000, true),
            ("deploy", 1001, false),
            ("git", 998, false),
            ("nobody", 65534, false),
        ]
    );
    assert!(shell_logs_in("/usr/bin/git-shell"));
    assert!(shell_logs_in(""), "an empty shell field means /bin/sh");
    assert!(!shell_logs_in("/usr/sbin/nologin"));
    assert!(!shell_logs_in("/bin/false"));
}

#[test]
fn key_file_templates_expand_the_way_sshd_expands_them() {
    let account = Account {
        name: "eric".to_string(),
        uid: 1000,
        home: "/home/eric".to_string(),
        shell: "/bin/bash".to_string(),
        usable_password: true,
    };
    let templates: Vec<String> = [
        ".ssh/authorized_keys",
        "/etc/ssh/keys/%u",
        "%h/.ssh/extra_%%",
        "none",
    ]
    .iter()
    .map(|template| template.to_string())
    .collect();
    assert_eq!(
        key_files(&templates, &account),
        vec![
            PathBuf::from("/home/eric/.ssh/authorized_keys"),
            PathBuf::from("/etc/ssh/keys/eric"),
            PathBuf::from("/home/eric/.ssh/extra_%"),
        ]
    );
}

// -----------------------------------------------------------------------------
// The guards, end to end against a mock
// -----------------------------------------------------------------------------

const STAGED: &str = "/tmp/staged.conf";
const LIVE: &str = "/etc/ssh/sshd_config";

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: 0,
    }
}

fn dump(methods: &str, root: &str) -> CommandOutput {
    ok(&format!(
        "permitrootlogin {root}\nauthenticationmethods {methods}\n\
         authorizedkeysfile .ssh/authorized_keys\n"
    ))
}

/// A host whose PAM stack reaches pam_unix, with `eric` (a password) and
/// `deploy` (no password), both holding a key.
fn guarded_host() -> MockExecutor {
    pam_host(&[
        ("/etc/pam.d/sshd", "@include common-auth\n"),
        (
            "/etc/pam.d/common-auth",
            "auth [success=1 default=ignore] pam_unix.so\n",
        ),
        (
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             eric:x:1000:1000::/home/eric:/bin/bash\n\
             deploy:x:1001:1001::/home/deploy:/bin/sh\n",
        ),
        (
            "/etc/shadow",
            "root:*:20000::::::\neric:$y$hash:20000::::::\ndeploy:!:20000::::::\n",
        ),
        ("/home/eric/.ssh/authorized_keys", "ssh-ed25519 AAAA eric\n"),
        ("/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAA ci\n"),
    ])
    .with_command("sshd", &["-T", "-f", STAGED], dump(POLICY, "no"))
}

fn probe_args(user: &str, address: &str) -> [String; 5] {
    [
        "-T".to_string(),
        "-f".to_string(),
        STAGED.to_string(),
        "-C".to_string(),
        format!("user={user},host={address},addr={address}"),
    ]
}

fn with_probe(
    executor: MockExecutor,
    user: &str,
    address: &str,
    output: CommandOutput,
) -> MockExecutor {
    let args = probe_args(user, address);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    executor.with_command("sshd", &args, output)
}

#[tokio::test]
async fn an_account_with_a_key_and_no_password_is_refused_by_name() {
    let executor = with_probe(guarded_host(), "deploy", "127.0.0.1", dump(POLICY, "no"));

    let verdict = check(&executor, &PluginConfig::default(), STAGED, LIVE).await;

    let Verdict::Refuse(reason) = verdict else {
        panic!("deploy would be locked out: {verdict:?}");
    };
    assert!(reason.contains(": deploy "), "{reason}");
    assert!(
        reason.contains("second-factor-lockout"),
        "the refusal names the way to accept it: {reason}"
    );
    assert!(
        !reason.contains("eric"),
        "eric has a password and gets past the prompt: {reason}"
    );
}

#[tokio::test]
async fn a_match_block_keeping_the_account_on_its_key_lets_it_through() {
    let executor = with_probe(
        guarded_host(),
        "deploy",
        "127.0.0.1",
        dump("publickey", "no"),
    );

    let verdict = check(&executor, &PluginConfig::default(), STAGED, LIVE).await;

    assert_eq!(verdict, Verdict::Proceed(Vec::new()));
}

#[tokio::test]
async fn an_exception_naming_exactly_the_stranded_accounts_accepts_them() {
    let executor = with_probe(guarded_host(), "deploy", "127.0.0.1", dump(POLICY, "no"));
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        LOCKOUT_EXCEPTION_KEY.to_string(),
        hardener_core::PolicyException {
            value: "deploy".to_string(),
            allowed: true,
            reason: "CI deploys through the console host now".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let Verdict::Proceed(notes) = check(&executor, &config, STAGED, LIVE).await else {
        panic!("the exception names exactly the account found");
    };
    assert!(
        notes
            .iter()
            .any(|note| note.contains("deploy") && note.contains("CI deploys")),
        "{notes:?}"
    );

    // The same exception no longer matches once another account would go too.
    config
        .exceptions
        .get_mut(LOCKOUT_EXCEPTION_KEY)
        .expect("inserted above")
        .value = "build".to_string();
    assert!(matches!(
        check(&executor, &config, STAGED, LIVE).await,
        Verdict::Refuse(_)
    ));
}

#[tokio::test]
async fn shadow_that_cannot_be_read_refuses_rather_than_guesses() {
    let executor = guarded_host().with_read_permission_denied("/etc/shadow");

    let Verdict::Refuse(reason) = check(&executor, &PluginConfig::default(), STAGED, LIVE).await
    else {
        panic!("a guard that could not look has not found the host safe");
    };
    assert!(reason.contains("/etc/shadow"), "{reason}");
}

/// The remote root session: today root gets in on its key, and under the
/// policy sshd refuses root every keyboard-interactive login.
#[tokio::test]
async fn a_remote_root_session_that_would_lose_its_key_login_is_refused() {
    let address = "192.0.2.10";
    let executor = guarded_host()
        .remote()
        .with_command("id", &["-un"], ok("root\n"))
        .with_command(
            "printenv",
            &["SSH_CONNECTION"],
            ok("192.0.2.10 50000 192.0.2.1 22\n"),
        );
    let executor = with_probe(executor, "root", address, dump(POLICY, "prohibit-password"));
    let live_args = [
        "-T",
        "-f",
        LIVE,
        "-C",
        "user=root,host=192.0.2.10,addr=192.0.2.10",
    ];
    let executor = executor.with_command("sshd", &live_args, dump("any", "prohibit-password"));

    let Verdict::Refuse(reason) = check(&executor, &PluginConfig::default(), STAGED, LIVE).await
    else {
        panic!("the session doing the apply would be cut off");
    };
    assert!(reason.contains("root from 192.0.2.10"), "{reason}");
    assert!(reason.contains("Match block"), "{reason}");

    // With a Match block exempting root from that address, it goes ahead as
    // far as this guard is concerned.
    let exempted = with_probe(
        guarded_host()
            .remote()
            .with_command("id", &["-un"], ok("root\n"))
            .with_command(
                "printenv",
                &["SSH_CONNECTION"],
                ok("192.0.2.10 50000 192.0.2.1 22\n"),
            )
            .with_command("sshd", &live_args, dump("any", "prohibit-password")),
        "root",
        address,
        dump("publickey", "prohibit-password"),
    );
    let exempted = with_probe(
        exempted,
        "deploy",
        address,
        dump("publickey", "prohibit-password"),
    );
    assert_eq!(
        check(&exempted, &PluginConfig::default(), STAGED, LIVE).await,
        Verdict::Proceed(Vec::new())
    );
}

#[tokio::test]
async fn a_pam_stack_without_the_password_refuses_before_anything_else() {
    let executor = MockExecutor::new().with_file("/etc/pam.d/sshd", "auth required pam_deny.so\n");

    let Verdict::Refuse(reason) = check(&executor, &PluginConfig::default(), STAGED, LIVE).await
    else {
        panic!("no prompt would ask for the password");
    };
    assert!(reason.contains("pam_unix"), "{reason}");
    assert!(
        executor.log().commands_executed.is_empty(),
        "nothing else is probed once PAM has refused: {:?}",
        executor.log().commands_executed
    );
}
