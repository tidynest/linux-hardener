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
        pam_answers_with_password(&executor, "sshd").await,
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
        pam_answers_with_password(&executor, "sshd").await,
        PamAnswer::Password { .. }
    ));
}

#[tokio::test]
async fn a_stack_with_no_password_module_is_refused_by_name() {
    let executor = pam_host(&[(
        "/etc/pam.d/sshd",
        "auth required pam_google_authenticator.so\n",
    )]);
    let answer = pam_answers_with_password(&executor, "sshd").await;
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
        pam_answers_with_password(&MockExecutor::new(), "sshd").await,
        PamAnswer::Unknown(_)
    ));
    let looping = pam_host(&[
        ("/etc/pam.d/sshd", "auth include common\n"),
        ("/etc/pam.d/common", "auth include sshd\n"),
    ]);
    assert!(matches!(
        pam_answers_with_password(&looping, "sshd").await,
        PamAnswer::NoPassword { .. }
    ));
}

// -----------------------------------------------------------------------------
// sshd -T and accounts
// -----------------------------------------------------------------------------

/// What `sshd -T` prints for the settings the guards read, on a host where
/// the candidate does what the fragment asks.
fn dump_text(methods: &str, root: &str) -> String {
    format!(
        "usepam yes\n\
         permitrootlogin {root}\n\
         pubkeyauthentication yes\n\
         passwordauthentication no\n\
         kbdinteractiveauthentication yes\n\
         trustedusercakeys none\n\
         authorizedkeyscommand none\n\
         authorizedkeysfile .ssh/authorized_keys\n\
         authenticationmethods {methods}\n"
    )
}

fn effective(methods: &str, root: &str) -> Effective {
    parse_sshd_dump(&dump_text(methods, root)).expect("the test dump parses")
}

fn account(name: &str, uid: u32, usable_password: bool) -> Account {
    Account {
        name: name.to_string(),
        uid,
        home: format!("/home/{name}"),
        usable_password,
    }
}

#[test]
fn the_sshd_dump_is_read_for_every_setting_the_guards_use() {
    // OpenSSH 10.6 prints PAMServiceName; a certificate authority is set.
    let parsed = parse_sshd_dump(
        "port 22\n\
         usepam yes\n\
         pamservicename sshd-2fa\n\
         permitrootlogin without-password\n\
         pubkeyauthentication yes\n\
         passwordauthentication no\n\
         kbdinteractiveauthentication yes\n\
         hostbasedauthentication no\n\
         trustedusercakeys /etc/ssh/user_ca.pub\n\
         authorizedkeyscommand none\n\
         authenticationmethods publickey,keyboard-interactive publickey\n\
         authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n",
    )
    .expect("a dump with authenticationmethods parses");
    assert_eq!(
        parsed,
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
            enabled: ["publickey", "keyboard-interactive"].into_iter().collect(),
            use_pam: Some(true),
            pam_service: Some("sshd-2fa".to_string()),
            unlisted_key_sources: vec!["TrustedUserCAKeys"],
        }
    );
    assert_eq!(parse_sshd_dump("port 22\n"), None);
    // sshd before 8.7 printed keyboard-interactive's switch under the old
    // name, and a build without PAM prints no usepam line at all.
    let old = parse_sshd_dump("challengeresponseauthentication yes\nauthenticationmethods any\n")
        .expect("parses");
    assert!(old.enabled.contains("keyboard-interactive"));
    assert_eq!(old.use_pam, None);
}

/// sshd drops each list naming a method switched off for the connection, and
/// keyboard-interactive without PAM has no device to ask with.
#[test]
fn a_list_naming_a_switched_off_method_is_dropped_as_sshd_drops_it() {
    let both = effective(&format!("{POLICY} publickey"), "no");
    assert_eq!(usable_lists(&both), vec![POLICY, "publickey"]);

    let mut kbd_off = effective(&format!("{POLICY} publickey"), "no");
    kbd_off.enabled.remove("keyboard-interactive");
    assert_eq!(usable_lists(&kbd_off), vec!["publickey"]);

    let mut no_pam = effective(POLICY, "no");
    no_pam.use_pam = Some(false);
    assert!(
        usable_lists(&no_pam).is_empty(),
        "sshd would disconnect: no authentication methods enabled"
    );

    assert_eq!(usable_lists(&effective("any", "no")), vec!["any"]);
}

#[test]
fn root_gets_in_on_its_key_only_where_sshd_lets_root_use_one() {
    assert!(key_gets_in(&effective("publickey", "prohibit-password"), 0));
    assert!(key_gets_in(&effective("publickey", "without-password"), 0));
    assert!(!key_gets_in(&effective("publickey", "no"), 0));
    assert!(!key_gets_in(
        &effective("publickey", "forced-commands-only"),
        0
    ));
    assert!(
        key_gets_in(&effective("publickey", "no"), 1000),
        "the rule is root's alone"
    );
    assert!(!key_gets_in(&effective(POLICY, "prohibit-password"), 1000));
    assert!(key_gets_in(&effective("any", "prohibit-password"), 1000));
    let mut keys_off = effective("any", "prohibit-password");
    keys_off.enabled.remove("publickey");
    assert!(!key_gets_in(&keys_off, 1000));
}

#[test]
fn a_password_gets_in_only_where_a_list_takes_a_key_and_a_password() {
    let policy = effective(POLICY, "prohibit-password");
    assert!(password_gets_in(&policy, &account("eric", 1000, true)));
    assert!(!password_gets_in(&policy, &account("deploy", 1001, false)));
    assert!(
        !password_gets_in(&policy, &account("root", 0, true)),
        "sshd refuses root every keyboard-interactive step under prohibit-password"
    );
    assert!(password_gets_in(
        &effective(POLICY, "yes"),
        &account("root", 0, true)
    ));
    // A Match block switching keyboard-interactive off for this account.
    let mut kbd_off = effective(POLICY, "no");
    kbd_off.enabled.remove("keyboard-interactive");
    assert!(!password_gets_in(&kbd_off, &account("eric", 1000, true)));
    // A list that also needs a host key is not one a key and a password pass.
    assert!(!password_gets_in(
        &effective("publickey,hostbased,keyboard-interactive", "no"),
        &account("eric", 1000, true)
    ));
}

#[test]
fn candidate_refusal_names_what_keeps_the_fragment_out() {
    assert_eq!(candidate_refusal(&effective(POLICY, "no")), None);

    let mut no_pam = effective(POLICY, "no");
    no_pam.use_pam = Some(false);
    let reason = candidate_refusal(&no_pam).expect("UsePAM no is refused");
    assert!(
        reason.contains("UsePAM no") && reason.contains("00-hardener.conf"),
        "{reason}"
    );

    let mut built_without = effective(POLICY, "no");
    built_without.use_pam = None;
    assert!(candidate_refusal(&built_without).is_some_and(|reason| reason.contains("without PAM")));

    let mut kbd_off = effective(POLICY, "no");
    kbd_off.enabled.remove("keyboard-interactive");
    assert!(
        candidate_refusal(&kbd_off)
            .is_some_and(|reason| reason.contains("KbdInteractiveAuthentication no"))
    );

    // A list above the main file's Include wins over the fragment's.
    assert!(
        candidate_refusal(&effective("publickey", "no"))
            .is_some_and(|reason| reason.contains("AuthenticationMethods publickey"))
    );
}

#[test]
fn accounts_are_marked_by_whether_shadow_holds_a_usable_hash() {
    let accounts = parse_accounts(
        "root:x:0:0:root:/root:/bin/bash\n\
         eric:x:1000:1000::/home/eric:/bin/bash\n\
         deploy:x:1001:1001::/home/deploy:/bin/sh\n\
         git:x:998:998::/srv/git:/usr/bin/git-shell\n\
         sftp:x:1002:1002::/home/sftp:/usr/sbin/nologin\n\
         broken line\n",
        "root:!:20000::::::\n\
         eric:$y$j9T$salt$hash:20000:0:99999:7:::\n\
         deploy:!!:20000::::::\n\
         git:*:20000::::::\n\
         sftp:$y$j9T$salt$hash:20000::::::\n",
    );
    let marked: Vec<(&str, u32, bool)> = accounts
        .iter()
        .map(|account| (account.name.as_str(), account.uid, account.usable_password))
        .collect();
    // A nologin shell is kept: sshd lets such an account authenticate.
    assert_eq!(
        marked,
        vec![
            ("root", 0, false),
            ("eric", 1000, true),
            ("deploy", 1001, false),
            ("git", 998, false),
            ("sftp", 1002, true),
        ]
    );
}

#[test]
fn key_file_templates_expand_the_way_sshd_expands_them() {
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
        key_files(&templates, &account("eric", 1000, true)),
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
    ok(&dump_text(methods, root))
}

/// A host whose PAM stack reaches pam_unix, with `eric` (a password) and
/// `deploy` (no password), both holding a key, and the global read of the
/// staged candidate registered.
fn guarded_host_without_probes() -> MockExecutor {
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

/// [`guarded_host_without_probes`] with `eric`'s local probe registered.
/// Every account with a key is probed, eric included, and under the policy he
/// is asked for his password after the key.
fn guarded_host() -> MockExecutor {
    with_probe(
        guarded_host_without_probes(),
        "eric",
        "127.0.0.1",
        dump(POLICY, "no"),
    )
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

fn notes(verdict: Verdict) -> Vec<String> {
    match verdict {
        Verdict::Proceed(notes) => notes,
        Verdict::Refuse(reason) => panic!("expected to go ahead, refused: {reason}"),
    }
}

fn refusal(verdict: Verdict) -> String {
    match verdict {
        Verdict::Refuse(reason) => reason,
        Verdict::Proceed(notes) => panic!("expected a refusal, went ahead: {notes:?}"),
    }
}

#[tokio::test]
async fn an_account_with_a_key_and_no_password_is_refused_by_name() {
    let executor = with_probe(guarded_host(), "deploy", "127.0.0.1", dump(POLICY, "no"));

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);

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

/// Every account with a key is probed, and the ones that will meet the
/// prompt are named, because a script logging in as one of them with a key
/// alone stops working.
#[tokio::test]
async fn a_match_block_keeping_the_account_on_its_key_lets_it_through() {
    let executor = with_probe(
        guarded_host(),
        "deploy",
        "127.0.0.1",
        dump("publickey", "no"),
    );

    let notes = notes(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);

    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("eric will be asked for the account password after the key")
            && notes[0].contains("Match block")
            && !notes[0].contains("deploy"),
        "{notes:?}"
    );
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

    let notes = notes(check(&executor, &config, STAGED, LIVE).await);
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

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains("/etc/shadow"), "{reason}");
}

/// The remote root session: today root gets in on its key, and under the
/// policy sshd refuses root every keyboard-interactive login.
#[tokio::test]
async fn a_remote_root_session_that_would_lose_its_key_login_is_refused() {
    let address = "192.0.2.10";
    let remote = |executor: MockExecutor| {
        executor
            .remote()
            .with_command("id", &["-un"], ok("root\n"))
            .with_command(
                "printenv",
                &["SSH_CONNECTION"],
                ok("192.0.2.10 50000 192.0.2.1 22\n"),
            )
    };
    let live_args = [
        "-T",
        "-f",
        LIVE,
        "-C",
        "user=root,host=192.0.2.10,addr=192.0.2.10",
    ];
    let executor = with_probe(
        remote(guarded_host_without_probes()),
        "root",
        address,
        dump(POLICY, "prohibit-password"),
    )
    .with_command("sshd", &live_args, dump("any", "prohibit-password"));

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains("root from 192.0.2.10"), "{reason}");
    assert!(reason.contains("Match block"), "{reason}");

    // With a Match block exempting root from that address, it goes ahead as
    // far as this guard is concerned.
    let exempted = remote(guarded_host_without_probes()).with_command(
        "sshd",
        &live_args,
        dump("any", "prohibit-password"),
    );
    let exempted = with_probe(
        exempted,
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
    let exempted = with_probe(exempted, "eric", address, dump(POLICY, "prohibit-password"));
    let notes = notes(check(&exempted, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(notes.iter().any(|note| note.contains("eric")), "{notes:?}");
}

#[tokio::test]
async fn a_pam_stack_without_the_password_refuses_before_any_account_is_read() {
    let executor = MockExecutor::new()
        .with_file("/etc/pam.d/sshd", "auth required pam_deny.so\n")
        .with_command("sshd", &["-T", "-f", STAGED], dump(POLICY, "no"));

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains("pam_unix"), "{reason}");
    assert_eq!(
        executor.log().commands_executed,
        vec![(
            "sshd".to_string(),
            vec!["-T".to_string(), "-f".to_string(), STAGED.to_string()]
        )],
        "only the global read runs before PAM refuses"
    );
}

/// sshd lets an account whose shell is `nologin` authenticate, which is how
/// SFTP-only and tunnel-only accounts work, so such an account with a key and
/// no password is locked out like any other. Measured with OpenSSH 9.6p1: an
/// `ssh -N` login in BatchMode went from "Accepted publickey" to "Permission
/// denied (keyboard-interactive)" once the fragment was in place.
#[tokio::test]
async fn a_nologin_account_with_a_key_is_checked_like_any_other() {
    let executor = with_probe(
        guarded_host()
            .with_file(
                "/etc/passwd",
                "eric:x:1000:1000::/home/eric:/bin/bash\n\
                 tunnel:x:1002:1002::/home/tunnel:/usr/sbin/nologin\n",
            )
            .with_file(
                "/etc/shadow",
                "eric:$y$hash:20000::::::\ntunnel:*:20000::::::\n",
            )
            .with_file("/home/tunnel/.ssh/authorized_keys", "ssh-ed25519 AAAA t\n"),
        "tunnel",
        "127.0.0.1",
        dump(POLICY, "no"),
    );

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains(": tunnel "), "{reason}");
}

/// A `UsePAM no` sshd reads before the fragment, above the main file's
/// Include, passes `sshd -t` and turns every login away after the key.
/// Measured with OpenSSH 9.6p1: `sshd -t` exits 0 and `sshd -T` prints
/// `usepam no` beside the fragment's list.
#[tokio::test]
async fn usepam_no_ahead_of_the_fragment_refuses_before_any_account_is_read() {
    let without_pam = dump_text(POLICY, "no").replace("usepam yes", "usepam no");
    let executor = guarded_host().with_command("sshd", &["-T", "-f", STAGED], ok(&without_pam));

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains("UsePAM no"), "{reason}");
    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(_, args)| args.iter().any(|arg| arg == "-C")),
        "no account is probed once the candidate is known to fail"
    );
}

/// A `Match` block switching keyboard-interactive off for an account leaves
/// it no list sshd will keep, password or not. `sshd -t` checks the global
/// lists only and passes it.
#[tokio::test]
async fn a_match_block_switching_keyboard_interactive_off_strands_its_accounts() {
    let kbd_off = dump_text(POLICY, "no").replace(
        "kbdinteractiveauthentication yes",
        "kbdinteractiveauthentication no",
    );
    let executor = with_probe(
        with_probe(
            guarded_host_without_probes(),
            "eric",
            "127.0.0.1",
            ok(&kbd_off),
        ),
        "deploy",
        "127.0.0.1",
        dump("publickey", "no"),
    );

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains(": eric "), "{reason}");
}

/// OpenSSH 10.0 and later hand the prompt to the PAM service
/// `PAMServiceName` names, not to `sshd`.
#[tokio::test]
async fn the_pam_service_sshd_names_is_the_one_followed() {
    let named = || {
        ok(&format!(
            "pamservicename sshd-2fa\n{}",
            dump_text(POLICY, "no")
        ))
    };
    let host = |sshd: &str, named_service: &str| {
        let executor = pam_host(&[
            ("/etc/pam.d/sshd", sshd),
            ("/etc/pam.d/sshd-2fa", named_service),
            ("/etc/passwd", "eric:x:1000:1000::/home/eric:/bin/bash\n"),
            ("/etc/shadow", "eric:$y$hash:20000::::::\n"),
            ("/home/eric/.ssh/authorized_keys", "ssh-ed25519 AAAA eric\n"),
        ])
        .with_command("sshd", &["-T", "-f", STAGED], named());
        with_probe(executor, "eric", "127.0.0.1", named())
    };
    let deny = "auth required pam_deny.so\n";
    let unix = "auth required pam_unix.so\n";

    notes(check(&host(deny, unix), &PluginConfig::default(), STAGED, LIVE).await);
    let reason = refusal(check(&host(unix, deny), &PluginConfig::default(), STAGED, LIVE).await);
    assert!(reason.contains("/etc/pam.d/sshd-2fa"), "{reason}");
}

/// A `Match` block may give one account a PAM service of its own.
#[tokio::test]
async fn a_pam_service_one_account_is_given_is_checked_for_it() {
    let own = ok(&format!(
        "pamservicename sshd-eric\n{}",
        dump_text(POLICY, "no")
    ));
    let executor = with_probe(
        with_probe(guarded_host_without_probes(), "eric", "127.0.0.1", own)
            .with_file("/etc/pam.d/sshd-eric", "auth required pam_permit.so\n"),
        "deploy",
        "127.0.0.1",
        dump("publickey", "no"),
    );

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(
        reason.contains("sshd-eric") && reason.contains("for eric"),
        "{reason}"
    );
}

/// Keys handed over by `AuthorizedKeysCommand`, and user certificates under
/// `TrustedUserCAKeys`, belong to accounts no key file shows, so the check
/// refuses until an exception names the settings.
#[tokio::test]
async fn keys_no_file_lists_refuse_until_an_exception_names_them() {
    let with_ca = dump_text(POLICY, "no").replace(
        "trustedusercakeys none",
        "trustedusercakeys /etc/ssh/user_ca.pub",
    );
    let executor = with_probe(
        guarded_host().with_command("sshd", &["-T", "-f", STAGED], ok(&with_ca)),
        "deploy",
        "127.0.0.1",
        dump("publickey", "no"),
    );

    let reason = refusal(check(&executor, &PluginConfig::default(), STAGED, LIVE).await);
    assert!(
        reason.contains("TrustedUserCAKeys") && reason.contains(UNLISTED_KEYS_EXCEPTION_KEY),
        "{reason}"
    );

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        UNLISTED_KEYS_EXCEPTION_KEY.to_string(),
        hardener_core::PolicyException {
            value: "TrustedUserCAKeys".to_string(),
            allowed: true,
            reason: "Certificates are issued for console logins only".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    let notes = notes(check(&executor, &config, STAGED, LIVE).await);
    assert!(
        notes
            .iter()
            .any(|note| note.contains("TrustedUserCAKeys") && note.contains("console logins")),
        "{notes:?}"
    );
}

// -----------------------------------------------------------------------------
// Against a real sshd (root-gated)
// -----------------------------------------------------------------------------

/// The sshd binary on this host, where the distribution puts it.
fn real_sshd() -> PathBuf {
    ["/usr/sbin/sshd", "/usr/bin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .expect("these tests need an sshd binary: install openssh-server")
}

/// A scratch directory holding a host key, a main file reading `d/*.conf`
/// after `main_head` and before `main_tail`, and the drop-ins given.
fn real_sshd_host(main_head: &str, main_tail: &str, dropins: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let root = dir.path();
    let keygen = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(root.join("hostkey"))
        .status()
        .expect("ssh-keygen runs");
    assert!(keygen.success(), "ssh-keygen made a host key");
    std::fs::create_dir(root.join("d")).expect("the drop-in directory");
    for (name, content) in dropins {
        std::fs::write(root.join("d").join(name), content).expect("a drop-in");
    }
    std::fs::write(
        root.join("main.conf"),
        format!(
            "{main_head}Include {}/d/*.conf\nHostKey {}/hostkey\n{main_tail}",
            root.display(),
            root.display()
        ),
    )
    .expect("the main file");
    dir
}

/// What the real sshd prints for `main.conf` in `dir`, for one connection
/// where `connection` names one.
fn real_dump(dir: &tempfile::TempDir, connection: Option<&str>) -> Effective {
    let main = dir.path().join("main.conf");
    let mut command = std::process::Command::new(real_sshd());
    command.arg("-T").arg("-f").arg(&main);
    if let Some(spec) = connection {
        command.args(["-C", spec]);
    }
    let output = command.output().expect("sshd -T runs");
    assert!(
        output.status.success(),
        "sshd -T: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_sshd_dump(&String::from_utf8_lossy(&output.stdout)).expect("real sshd -T output parses")
}

const REAL_FRAGMENT: &str = "AuthenticationMethods publickey,keyboard-interactive\n\
                             KbdInteractiveAuthentication yes\nUsePAM yes\n";

const REAL_TAIL: &str = "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\n";

/// The guards' reading of `sshd -T`, held against the real thing rather than
/// against this file's idea of its output. CI's root-gated job runs it after
/// installing openssh-server.
#[test]
#[ignore = "Requires root and an sshd binary"]
fn real_sshd_output_is_read_the_way_the_guards_expect() {
    // The fragment as the apply writes it, ahead of a main file switching
    // keyboard-interactive off below the Include.
    let good = real_sshd_host("", REAL_TAIL, &[("00-hardener.conf", REAL_FRAGMENT)]);
    let global = real_dump(&good, None);
    assert_eq!(candidate_refusal(&global), None, "{global:?}");
    assert_eq!(global.methods, vec![POLICY.to_string()]);
    assert!(global.enabled.contains("publickey"), "{global:?}");
    assert!(global.unlisted_key_sources.is_empty(), "{global:?}");
    assert!(
        global
            .pam_service
            .as_deref()
            .is_none_or(|service| service == DEFAULT_PAM_SERVICE),
        "{global:?}"
    );
    let eric = real_dump(&good, Some("user=eric,host=127.0.0.1,addr=127.0.0.1"));
    assert!(!key_gets_in(&eric, 1000));
    assert!(password_gets_in(&eric, &account("eric", 1000, true)));

    // UsePAM no above the Include: sshd -t passes, and the guard refuses.
    let no_pam = real_sshd_host(
        "UsePAM no\n",
        REAL_TAIL,
        &[("00-hardener.conf", REAL_FRAGMENT)],
    );
    assert!(
        candidate_refusal(&real_dump(&no_pam, None))
            .is_some_and(|reason| reason.contains("UsePAM no"))
    );

    // A Match block switching keyboard-interactive off for one account.
    let ghost = real_sshd_host(
        "",
        REAL_TAIL,
        &[
            ("00-hardener.conf", REAL_FRAGMENT),
            (
                "50-ghost.conf",
                "Match User ghost\n    KbdInteractiveAuthentication no\n",
            ),
        ],
    );
    let ghost_dump = real_dump(&ghost, Some("user=ghost,host=127.0.0.1,addr=127.0.0.1"));
    assert!(usable_lists(&ghost_dump).is_empty(), "{ghost_dump:?}");
    assert!(!password_gets_in(
        &ghost_dump,
        &account("ghost", 1001, true)
    ));

    // The Match exemption the reference documents, root from one address,
    // with PermitRootLogin no everywhere else.
    let exempt = real_sshd_host(
        "",
        REAL_TAIL,
        &[
            ("00-hardener.conf", REAL_FRAGMENT),
            ("01-root.conf", "PermitRootLogin no\n"),
            (
                "60-automation.conf",
                "Match User root Address 192.0.2.10\n    AuthenticationMethods publickey\n    \
                 PermitRootLogin prohibit-password\n",
            ),
        ],
    );
    assert!(key_gets_in(
        &real_dump(&exempt, Some("user=root,host=192.0.2.10,addr=192.0.2.10")),
        0
    ));
    assert!(!key_gets_in(
        &real_dump(
            &exempt,
            Some("user=root,host=198.51.100.7,addr=198.51.100.7")
        ),
        0
    ));

    // A certificate authority is a key source no file lists.
    let ca_path = format!("{}/hostkey.pub", good.path().display());
    let ca_line = format!("TrustedUserCAKeys {ca_path}\n");
    let ca = real_sshd_host(
        "",
        REAL_TAIL,
        &[
            ("00-hardener.conf", REAL_FRAGMENT),
            ("30-ca.conf", &ca_line),
        ],
    );
    assert_eq!(
        real_dump(&ca, None).unlisted_key_sources,
        vec!["TrustedUserCAKeys"]
    );
}
