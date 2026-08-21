#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`config_loader`](super).
//!
//! Split out of `config_loader.rs`. This file sits in the `config_loader/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::config_loader` and
//! every import carried across unchanged, private items included.

use super::*;
use crate::config::PolicyException;
use crate::config::scope::ScopeExclusion;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_default_config() {
    let loader = ConfigLoader::new().skip_defaults();
    let config = loader.load().unwrap();
    assert!(config.global.enabled_plugins.is_empty());
    assert!(config.ssh.is_enabled());
}

/// `custom_directives` was accepted and validated for several releases
/// while no plugin ever read it, and it has now been removed rather than
/// implemented. An operator's file still carries the table, so the loader
/// has to keep ignoring it: nothing here sets `deny_unknown_fields`, and
/// this is what says so out loud, because adding that attribute would turn
/// every such file into a hard load failure.
#[test]
fn a_config_still_naming_the_removed_custom_directives_loads() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
  [ssh]
  enabled = true

  [ssh.directives]
  PermitRootLogin = "no"

  [ssh.custom_directives]
  SomeSettingNoPluginEverRead = "yes"
  "#
    )
    .unwrap();

    let config = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file.path().to_path_buf())
        .load()
        .expect("a file naming the removed table must still load");

    assert!(config.ssh.is_enabled());
    assert_eq!(
        config
            .ssh
            .directives
            .get("PermitRootLogin")
            .map(String::as_str),
        Some("no"),
        "the surviving directives must be read, not discarded with the removed table"
    );
}

#[test]
fn test_load_from_file() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
  [global]
  disabled_plugins = ["mac-hardening"]

  [ssh]
  enabled = true
  "#
    )
    .unwrap();

    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file.path().to_path_buf());

    let config = loader.load().unwrap();
    assert_eq!(
        config.global.disabled_plugins,
        vec!["mac-hardening".to_string()]
    );
    assert!(config.ssh.is_enabled());
}

#[test]
fn test_missing_cli_config_error() {
    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(PathBuf::from("/nonexistent/config.toml"));

    let result = loader.load();
    assert!(result.is_err());
}

#[test]
fn test_merge_configs() {
    let base = HardenerConfig::default();
    let mut overlay = HardenerConfig::default();
    overlay.global.disabled_plugins = vec!["ssh-hardening".to_string()];
    overlay.ssh.enabled = Some(false);

    let merged = ConfigLoader::merge_configs(base, overlay).unwrap();
    assert_eq!(
        merged.global.disabled_plugins,
        vec!["ssh-hardening".to_string()]
    );
    assert!(!merged.ssh.is_enabled());
}

#[test]
fn test_merge_directives() {
    let mut base = HardenerConfig::default();
    base.ssh
        .directives
        .insert("MaxAuthTries".to_string(), "3".to_string());

    let mut overlay = HardenerConfig::default();
    overlay
        .ssh
        .directives
        .insert("PermitRootLogin".to_string(), "no".to_string());

    let merged = ConfigLoader::merge_configs(base, overlay).unwrap();
    assert_eq!(merged.ssh.directives.get("MaxAuthTries").unwrap(), "3");
    assert_eq!(merged.ssh.directives.get("PermitRootLogin").unwrap(), "no");
}

#[test]
fn test_user_config_path() {
    let path = ConfigLoader::user_config_path();
    assert!(path.is_some());
    let path = path.unwrap();
    assert!(path.to_string_lossy().contains("linux-hardener"));
}

#[test]
fn test_system_config_path() {
    let path = ConfigLoader::system_config_path();
    assert!(path.is_some());
    assert_eq!(
        path.unwrap(),
        PathBuf::from("/etc/linux-hardener/config.toml")
    );
}

#[test]
fn test_config_routing_end_to_end() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[services.exceptions.cups]
value = "running"
allowed = true
reason = "Print server required"
"#
    )
    .unwrap();

    let config = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file.path().to_path_buf())
        .load()
        .unwrap();

    let plugin = config.get_plugin_config("service-minimisation");
    assert!(
        plugin.has_valid_exception("cups").is_some(),
        "Exception added under [services] must be reachable via service-minimisation ID"
    );
}

/// A later source that merely mentions a section must not re-enable a plugin an
/// earlier source disabled.
///
/// `enabled` defaulted to `true`, so a file that named `[mac]` for any reason,
/// a single directive included, supplied `enabled = true` for it. That was
/// indistinguishable from a file that asked for it. Site policy disabling
/// `mac-hardening` was therefore undone by any partial `--config`, and since
/// `apply` began honouring that flag the verb that writes was exposed to it: a
/// plugin the site had turned off would be applied.
#[test]
fn a_section_mentioned_without_enabled_does_not_revive_a_disabled_plugin() {
    let mut base = HardenerConfig::default();
    base.mac.enabled = Some(false);

    let mut overlay = HardenerConfig::default();
    overlay
        .mac
        .directives
        .insert("selinux_mode".to_string(), "enforcing".to_string());

    let merged = ConfigLoader::merge_configs(base, overlay).expect("the sources merge");

    assert!(
        !merged.is_plugin_enabled("mac-hardening"),
        "a section mentioned for its directives says nothing about whether the \
         plugin runs, so the earlier decision stands"
    );
    assert_eq!(
        merged
            .mac
            .directives
            .get("selinux_mode")
            .map(String::as_str),
        Some("enforcing"),
        "while the directive it did carry is still merged, or the fix would have \
         cost the file its actual purpose"
    );
}

/// A user config that excludes one control of a framework must not discard the
/// other exclusions the system config declared for that same framework.
///
/// `merge_compliance` merges per control rather than per framework for exactly
/// this reason, and nothing asserted it. A plain `extend` of the outer map
/// would replace the whole `iso27001` entry, silently returning every other
/// control the site had excluded to the score's denominator: a change that
/// *lowers* a score and so is not noticed as a security defect, but which
/// makes the two sources disagree about what was decided.
#[test]
fn a_user_exclusion_does_not_discard_the_sites_other_exclusions() {
    let excluded = |reason: &str| ScopeExclusion {
        reason: reason.to_string(),
        approved_date: Some("2026-08-18".to_string()),
        ..Default::default()
    };
    let framework = |controls: [(&str, ScopeExclusion); 1]| {
        let mut config = ComplianceConfig::default();
        config
            .not_applicable
            .entry("iso27001".to_string())
            .or_default()
            .extend(controls.map(|(id, e)| (id.to_string(), e)));
        config
    };

    let base = HardenerConfig {
        compliance: framework([("7.1", excluded("no premises"))]),
        ..Default::default()
    };
    let overlay = HardenerConfig {
        compliance: framework([("7.2", excluded("no on-site staff"))]),
        ..Default::default()
    };

    let merged = ConfigLoader::merge_configs(base, overlay).expect("the sources merge");
    let iso = merged
        .compliance
        .not_applicable
        .get("iso27001")
        .expect("the framework survives the merge");

    assert_eq!(
        iso.get("7.1").map(|e| e.reason.as_str()),
        Some("no premises"),
        "the system config's exclusion must survive a user config that names \
         only a different control of the same framework"
    );
    assert_eq!(
        iso.get("7.2").map(|e| e.reason.as_str()),
        Some("no on-site staff"),
        "while the user config's own exclusion is of course added"
    );
}

/// The other half of the same rule: a later source naming the same control
/// does replace it, or a site exclusion could never be corrected.
#[test]
fn a_user_exclusion_replaces_the_same_control() {
    let mut base = HardenerConfig::default();
    base.compliance
        .not_applicable
        .entry("iso27001".to_string())
        .or_default()
        .insert(
            "7.1".to_string(),
            ScopeExclusion {
                reason: "no premises".to_string(),
                ..Default::default()
            },
        );
    let mut overlay = HardenerConfig::default();
    overlay
        .compliance
        .not_applicable
        .entry("iso27001".to_string())
        .or_default()
        .insert(
            "7.1".to_string(),
            ScopeExclusion {
                reason: "premises are leased and out of scope".to_string(),
                ..Default::default()
            },
        );

    let merged = ConfigLoader::merge_configs(base, overlay).expect("the sources merge");
    assert_eq!(
        merged
            .compliance
            .not_applicable
            .get("iso27001")
            .and_then(|f| f.get("7.1"))
            .map(|e| e.reason.as_str()),
        Some("premises are leased and out of scope")
    );
}

/// The control, in both directions: a later source that *says* so still decides.
#[test]
fn a_section_that_states_enabled_still_decides_it() {
    let mut base = HardenerConfig::default();
    base.mac.enabled = Some(false);
    let mut overlay = HardenerConfig::default();
    overlay.mac.enabled = Some(true);

    let revived = ConfigLoader::merge_configs(base, overlay).expect("the sources merge");
    assert!(
        revived.is_plugin_enabled("mac-hardening"),
        "an explicit `enabled = true` is a decision and must be honoured"
    );

    let mut base = HardenerConfig::default();
    let mut overlay = HardenerConfig::default();
    overlay.mac.enabled = Some(false);
    let disabled = ConfigLoader::merge_configs(base.clone(), overlay).expect("the sources merge");
    assert!(
        !disabled.is_plugin_enabled("mac-hardening"),
        "and an explicit `enabled = false` still turns a plugin off"
    );
    base.mac.enabled = None;
    assert!(
        HardenerConfig::default().is_plugin_enabled("mac-hardening"),
        "with nothing said anywhere, a plugin runs, which is the shipped default"
    );
}

/// `skip_defaults` has to set its own field and keep everything already
/// decided, not hand back a fresh loader.
///
/// Every other test in this file calls it first and `with_cli_config` second,
/// an order under which a `skip_defaults` that returned `Self::default()`
/// behaves identically: the CLI path is set afterwards, and the two default
/// locations it wrongly stopped skipping are absent on the machine running
/// the suite. Reversing the order is what makes the difference reachable.
#[test]
fn skip_defaults_keeps_the_cli_path_a_prior_call_set() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[ssh.directives]
PermitRootLogin = "no"
"#
    )
    .unwrap();

    let config = ConfigLoader::new()
        .with_cli_config(file.path().to_path_buf())
        .skip_defaults()
        .load()
        .expect("the CLI file exists, so a loader that kept it loads");

    assert_eq!(
        config
            .ssh
            .directives
            .get("PermitRootLogin")
            .map(String::as_str),
        Some("no"),
        "the builder call made before `skip_defaults` must survive it"
    );
}

/// The directive limit is a ceiling, not a target: exactly the maximum is
/// allowed and one more is refused.
///
/// Asking only about a wildly oversized config cannot fail under `>=` or `==`
/// in place of `>`, so both sides of the boundary are here.
#[test]
fn the_directive_limit_admits_the_maximum_and_refuses_one_more() {
    let plugin_with = |n: usize| PluginConfig {
        enabled: None,
        directives: (0..n).map(|i| (format!("d{i}"), "v".to_string())).collect(),
        exceptions: HashMap::new(),
    };

    let at_limit = ConfigLoader::merge_plugin(
        plugin_with(ConfigLoader::MAX_DIRECTIVES_PER_PLUGIN),
        PluginConfig::default(),
    )
    .expect("exactly the maximum is within the limit");
    assert_eq!(
        at_limit.directives.len(),
        ConfigLoader::MAX_DIRECTIVES_PER_PLUGIN
    );

    let err = ConfigLoader::merge_plugin(
        plugin_with(ConfigLoader::MAX_DIRECTIVES_PER_PLUGIN + 1),
        PluginConfig::default(),
    )
    .expect_err("one directive past the maximum is refused");
    assert!(
        err.to_string().contains("directive limit"),
        "and refused for the reason it was, not some other failure: {err}"
    );
}

/// The same ceiling reading for exceptions, which is a separate limit with a
/// separate comparison and so a separate pair of survivors.
#[test]
fn the_exception_limit_admits_the_maximum_and_refuses_one_more() {
    let plugin_with = |n: usize| PluginConfig {
        enabled: None,
        directives: HashMap::new(),
        exceptions: (0..n)
            .map(|i| {
                (
                    format!("e{i}"),
                    PolicyException {
                        value: "running".to_string(),
                        allowed: true,
                        reason: "fixture".to_string(),
                        approved_by: None,
                        approved_date: None,
                        ticket: None,
                        expires: None,
                    },
                )
            })
            .collect(),
    };

    let at_limit = ConfigLoader::merge_plugin(
        plugin_with(ConfigLoader::MAX_EXCEPTIONS_PER_PLUGIN),
        PluginConfig::default(),
    )
    .expect("exactly the maximum is within the limit");
    assert_eq!(
        at_limit.exceptions.len(),
        ConfigLoader::MAX_EXCEPTIONS_PER_PLUGIN
    );

    let err = ConfigLoader::merge_plugin(
        plugin_with(ConfigLoader::MAX_EXCEPTIONS_PER_PLUGIN + 1),
        PluginConfig::default(),
    )
    .expect_err("one exception past the maximum is refused");
    assert!(
        err.to_string().contains("exception limit"),
        "and refused for the reason it was, not some other failure: {err}"
    );
}

/// The same ceiling reading for compliance exclusions, which `merge_compliance`
/// had no cap on at all while `merge_plugin` capped both of its maps.
///
/// Split across the two sources rather than piled into one, because the cap is
/// checked after the merge: two files each comfortably inside the limit can add
/// up to one map past it, and a per-source check would let them.
#[test]
fn the_exclusion_limit_admits_the_maximum_and_refuses_one_more() {
    let split_at = |n: usize| {
        let exclusions = |range: std::ops::Range<usize>| {
            let mut config = ComplianceConfig::default();
            config.not_applicable.insert(
                "iso27001".to_string(),
                range
                    .map(|i| {
                        (
                            format!("7.{i}"),
                            ScopeExclusion {
                                reason: "fixture".to_string(),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
            );
            config
        };
        let half = n / 2;
        ConfigLoader::merge_compliance(exclusions(0..half), exclusions(half..n))
    };

    let at_limit = split_at(ConfigLoader::MAX_EXCLUSIONS_PER_FRAMEWORK)
        .expect("exactly the maximum is within the limit");
    assert_eq!(
        at_limit.not_applicable["iso27001"].len(),
        ConfigLoader::MAX_EXCLUSIONS_PER_FRAMEWORK
    );

    let err = split_at(ConfigLoader::MAX_EXCLUSIONS_PER_FRAMEWORK + 1)
        .expect_err("one exclusion past the maximum is refused");
    assert!(
        err.to_string().contains("exclusion limit for 'iso27001'"),
        "and refused for the reason it was, naming the framework that \
         overflowed: {err}"
    );
}

/// The 1 MiB file cap, both sides. The padding is a TOML comment, so a file
/// sized to the byte is still a file the parser accepts and the only thing
/// under test is the size comparison.
#[test]
fn the_config_size_cap_admits_a_file_of_exactly_one_mib_and_refuses_one_byte_more() {
    let sized_file = |bytes: usize| {
        let head = "[ssh]\nenabled = true\n#";
        let mut content = String::with_capacity(bytes);
        content.push_str(head);
        content.push_str(&"x".repeat(bytes - head.len() - 1));
        content.push('\n');
        assert_eq!(
            content.len(),
            bytes,
            "the fixture must hit the byte exactly"
        );
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    };

    let max = usize::try_from(ConfigLoader::MAX_CONFIG_SIZE).unwrap();

    let at_limit = sized_file(max);
    let config = ConfigLoader::load_from_file(at_limit.path())
        .expect("a file of exactly the maximum is within the cap");
    assert_eq!(config.ssh.enabled, Some(true));

    let over = sized_file(max + 1);
    let err = ConfigLoader::load_from_file(over.path())
        .expect_err("one byte past the maximum is refused");
    assert!(
        err.to_string().contains("exceeds 1 MiB size limit"),
        "and refused for its size, not for failing to parse or stat: {err}"
    );
}

/// The environment plugin lists are split, trimmed, emptied of blanks, and
/// every surviving id checked against the known set.
///
/// Asking only "did it come back Ok" cannot fail under a body replaced by a
/// constant `Ok`, and asking only "did it come back Err" cannot fail under an
/// inverted membership test that errors on the ids it should accept. Both
/// directions are asked, and the refusal is read for what it names.
#[test]
fn the_env_plugin_list_is_parsed_and_every_id_checked() {
    let ids = ConfigLoader::parse_and_validate_env_list(
        " ssh-hardening , ,kernel-hardening ",
        ConfigLoader::ENV_DISABLED_PLUGINS,
    )
    .expect("known ids, whitespace and an empty field the parser is meant to absorb");
    assert_eq!(
        ids,
        vec!["ssh-hardening".to_string(), "kernel-hardening".to_string()],
        "the ids are trimmed, kept in order, and the blank field dropped"
    );

    let err = ConfigLoader::parse_and_validate_env_list(
        "ssh-hardening,not-a-plugin",
        ConfigLoader::ENV_ENABLED_PLUGINS,
    )
    .expect_err("an id outside the known set is refused");
    let message = err.to_string();
    assert!(
        message.contains("not-a-plugin"),
        "the refusal names the offending id: {message}"
    );
    assert!(
        message.contains(ConfigLoader::ENV_ENABLED_PLUGINS),
        "and the variable it came from, so an operator knows which to fix: {message}"
    );
}

/// Writes a user config under `dir` and returns the loader that will read it.
fn loader_reading_user_config(dir: &std::path::Path, body: &str) -> ConfigLoader {
    let config_dir = dir.join("linux-hardener");
    std::fs::create_dir_all(&config_dir).expect("create the config directory");
    std::fs::write(config_dir.join("config.toml"), body).expect("write the user config");
    ConfigLoader::new().with_config_dir(dir.to_path_buf())
}

/// A user config is read when defaults are not skipped, and not when they are.
///
/// Both branches were unobservable before the seam existed: neither default
/// location is present on a test runner, so taking the `skip_defaults` branch
/// and skipping it produced an identical configuration and deleting the `!`
/// changed nothing any assertion could see. With the lookup pointed at a
/// directory the test owns, the two answers differ.
#[test]
fn skip_defaults_decides_whether_the_user_config_is_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = "[ssh.directives]\nPermitRootLogin = \"no\"\n";

    let read = loader_reading_user_config(dir.path(), body)
        .load()
        .expect("a loader that reads defaults loads the user config");
    assert_eq!(
        read.ssh
            .directives
            .get("PermitRootLogin")
            .map(String::as_str),
        Some("no"),
        "the user config is one of the sources `load` is documented to merge"
    );

    let skipped = loader_reading_user_config(dir.path(), body)
        .skip_defaults()
        .load()
        .expect("a loader that skips defaults still loads");
    assert!(
        !skipped.ssh.directives.contains_key("PermitRootLogin"),
        "and `skip_defaults` must actually skip it, or the flag names nothing"
    );
}

/// Running as root skips the user config, and not running as root reads it.
///
/// The rule exists because `pkexec` runs this tool as root from an
/// unprivileged session: an ordinary user's `~/.config` must not be able to
/// steer root-level hardening. The suite runs unprivileged, so the real
/// `is_running_as_root` answers `false` and the *reading* half is what a test
/// can ask directly; the refusing half is asked by pointing the loader at a
/// directory whose config would be visible if the guard were inverted.
///
/// `is_running_as_root` replaced by `false` stays alive on purpose and is
/// recorded as **provably equivalent**: under a non-root runner the real
/// function already returns `false`, so no assertion can separate them. The
/// `true` replacement is the dangerous half and is what this kills, along with
/// the `!` deletion, which inverts the rule into reading user config **only**
/// when root.
#[test]
fn an_unprivileged_session_reads_the_user_config_the_root_rule_would_skip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = loader_reading_user_config(
        dir.path(),
        "[global]\ndisabled_plugins = [\"mac-hardening\"]\n",
    )
    .load()
    .expect("the suite runs unprivileged, so the user config is read");

    assert_eq!(
        config.global.disabled_plugins,
        vec!["mac-hardening".to_string()],
        "an unprivileged session must honour the operator's own config; a rule \
         answering `root` for everyone, or inverted to read it only as root, \
         silently drops it"
    );
}

/// A root session refuses the user config that an unprivileged one reads.
///
/// This is the half with security consequences and it had never been asked.
/// `pkexec` runs this tool as root from an unprivileged session, so an ordinary
/// user's `~/.config` must not steer root-level hardening. Every test runs
/// unprivileged, which meant the rule could only ever be shown doing the safe,
/// permissive thing; that it *refuses* was inferred from the neighbouring test
/// rather than observed.
///
/// The same config body and directory as the unprivileged case, so the only
/// difference between the two tests is the answer to the root question. If the
/// guard were dropped, inverted, or wired to the wrong value, this goes red and
/// its neighbour stays green, which is what says the rule is a rule rather than
/// a constant.
///
/// Not a mutation kill, and not intended as one: replacing `is_running_as_root`
/// with `false` remains provably equivalent under a non-root runner. What is
/// pinned here is the behaviour that function feeds.
/// Both answers are asserted in one test, and that is the point rather than
/// tidiness. Asserting only the root case checks for an *empty* result, which
/// is also what a loader that read nothing at all would produce: the seam
/// returning `Default::default()` and discarding the directory passes such a
/// test for entirely the wrong reason. Requiring the same builder to read the
/// file when the answer is `false` is what makes emptiness mean refusal.
#[test]
fn a_root_session_skips_the_user_config_an_unprivileged_one_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = "[global]\ndisabled_plugins = [\"mac-hardening\"]\n";

    let as_root = loader_reading_user_config(dir.path(), body)
        .with_running_as_root(true)
        .load()
        .expect("a root load still succeeds, it just ignores the user config");
    let as_user = loader_reading_user_config(dir.path(), body)
        .with_running_as_root(false)
        .load()
        .expect("an unprivileged load reads the same file");

    assert_eq!(
        as_user.global.disabled_plugins,
        vec!["mac-hardening".to_string()],
        "the unprivileged answer must still read the file, or the root case \
         below is empty because nothing was read rather than because it was \
         refused"
    );
    assert!(
        as_root.global.disabled_plugins.is_empty(),
        "root must not take plugin selection from an unprivileged ~/.config: \
         pkexec runs this as root from the user's own session, so honouring it \
         lets an ordinary user disable the hardening being applied to them"
    );
}

/// The system config is read, and the seam that lets a test say where it is
/// actually redirects the read.
///
/// Nothing exercised this layer before 2026-08-20. `SYSTEM_CONFIG_PATH` is a
/// hardcoded absolute path, so on a test runner it does not exist and the
/// branch reading it was never taken. A layer no test can reach is a layer
/// whose removal no test would notice.
#[test]
fn the_system_config_is_read_from_the_path_the_seam_names() {
    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("system.toml");
    std::fs::write(
        &system,
        "[global]\ndisabled_plugins = [\"mac-hardening\"]\n",
    )
    .expect("write system config");

    let config = ConfigLoader::new()
        .with_system_config(system)
        .with_config_dir(dir.path().join("no-user-config"))
        .with_running_as_root(false)
        .load()
        .expect("load");

    assert!(
        !config.is_plugin_enabled("mac-hardening"),
        "the system config named mac-hardening in disabled_plugins and must be read"
    );
    assert!(
        config.is_plugin_enabled("ssh-hardening"),
        "the control: a plugin the system config did not name stays enabled"
    );
}

/// The user config outranks the system config, which is the order
/// `configuration.md` promises and which nothing asserted before 2026-08-20.
///
/// Red-first control: swapping the two blocks in `load()` compiles cleanly and
/// silently inverts this, so this test is what stands between that
/// transposition and a release.
#[test]
fn the_user_config_outranks_the_system_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("system.toml");
    let user_dir = dir.path().join("user");
    std::fs::create_dir_all(user_dir.join("linux-hardener")).expect("user dir");

    std::fs::write(
        &system,
        "[ssh.directives]\nMaxAuthTries = \"6\"\nPermitRootLogin = \"no\"\n",
    )
    .expect("write system");
    std::fs::write(
        user_dir.join("linux-hardener/config.toml"),
        "[ssh.directives]\nMaxAuthTries = \"3\"\n",
    )
    .expect("write user");

    let config = ConfigLoader::new()
        .with_system_config(system)
        .with_config_dir(user_dir)
        .with_running_as_root(false)
        .load()
        .expect("load");

    let ssh = config.get_plugin_config("ssh-hardening");
    assert_eq!(
        ssh.directives.get("MaxAuthTries").map(String::as_str),
        Some("3"),
        "the user config states this key later and must win"
    );
    assert_eq!(
        ssh.directives.get("PermitRootLogin").map(String::as_str),
        Some("no"),
        "a key only the system config states must survive: the sources merge \
         per key rather than the later file replacing the earlier wholesale"
    );
}

/// `--config` is an addition to the earlier sources, not a replacement for
/// them, which is what `configuration.md` promises and what no test drove
/// through `load()` before 2026-08-20.
#[test]
fn a_named_config_adds_to_the_sources_below_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("system.toml");
    let user_dir = dir.path().join("user");
    let named = dir.path().join("named.toml");
    std::fs::create_dir_all(user_dir.join("linux-hardener")).expect("user dir");

    std::fs::write(&system, "[kernel.directives]\nfrom_system = \"1\"\n").expect("write system");
    std::fs::write(
        user_dir.join("linux-hardener/config.toml"),
        "[kernel.directives]\nfrom_user = \"1\"\n",
    )
    .expect("write user");
    std::fs::write(
        &named,
        "[kernel.directives]\nfrom_named = \"1\"\nfrom_user = \"2\"\n",
    )
    .expect("write named");

    let config = ConfigLoader::new()
        .with_system_config(system)
        .with_config_dir(user_dir)
        .with_running_as_root(false)
        .with_cli_config(named)
        .load()
        .expect("load");

    let kernel = config.get_plugin_config("kernel-hardening");
    for key in ["from_system", "from_user", "from_named"] {
        assert!(
            kernel.directives.contains_key(key),
            "`{key}` came from a source the named file does not replace"
        );
    }
    assert_eq!(
        kernel.directives.get("from_user").map(String::as_str),
        Some("2"),
        "the named file states this key last and must win on the collision"
    );
}

// The test proving environment overrides outrank a named `--config` file
// lives in `tests/config_env_precedence.rs`, its own integration binary,
// rather than here: `HARDENER_DISABLED_PLUGINS` is process-wide, and this
// file's tests run as threads sharing one process with it. See that file's
// header for why that matters and what it once broke.

/// The last source that STATES `enabled` decides it, and a source that
/// mentions the section without the key decides nothing. Both halves were
/// asserted against `merge_configs` directly; neither was driven through
/// `load()` with real files until 2026-08-20.
///
/// Red-first control: `base.enabled.or(overlay.enabled)` at the merge site
/// compiles cleanly and makes the FIRST source to state it win forever.
#[test]
fn the_last_source_to_state_enabled_decides_it_through_load() {
    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("system.toml");
    let user_dir = dir.path().join("user");
    std::fs::create_dir_all(user_dir.join("linux-hardener")).expect("user dir");

    // The system config disables ssh and enables nothing else explicitly.
    std::fs::write(&system, "[ssh]\nenabled = false\n[pam]\nenabled = false\n")
        .expect("write system");
    // The user config revives ssh by STATING it, and mentions pam without the
    // key, which must decide nothing.
    std::fs::write(
        user_dir.join("linux-hardener/config.toml"),
        "[ssh]\nenabled = true\n[pam.directives]\nminlen = \"14\"\n",
    )
    .expect("write user");

    let config = ConfigLoader::new()
        .with_system_config(system)
        .with_config_dir(user_dir)
        .with_running_as_root(false)
        .load()
        .expect("load");

    assert!(
        config.is_plugin_enabled("ssh-hardening"),
        "the user config states enabled = true later and must revive it"
    );
    assert!(
        !config.is_plugin_enabled("pam-hardening"),
        "the user config mentions [pam.directives] without the enabled key, \
         which says nothing, so the system config's false stands"
    );
    assert_eq!(
        config
            .get_plugin_config("pam-hardening")
            .directives
            .get("minlen")
            .map(String::as_str),
        Some("14"),
        "the control: the section really was read, so the assertion above is \
         about the enabled key and not about the file being ignored"
    );
}

/// The directive cap is enforced against the merged result, so two files each
/// within it that together exceed it are refused. Proven of `merge_plugin`
/// directly before 2026-08-20; this drives it through `load()` with two real
/// files, which is the shape an operator actually reaches.
#[test]
fn two_files_each_under_the_directive_cap_are_refused_together() {
    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("system.toml");
    let user_dir = dir.path().join("user");
    std::fs::create_dir_all(user_dir.join("linux-hardener")).expect("user dir");

    let half = ConfigLoader::MAX_DIRECTIVES_PER_PLUGIN / 2 + 1;
    let body = |prefix: &str, count: usize| {
        let mut text = String::from("[kernel.directives]\n");
        for index in 0..count {
            text.push_str(&format!("{prefix}_{index} = \"1\"\n"));
        }
        text
    };
    std::fs::write(&system, body("sys", half)).expect("write system");
    std::fs::write(
        user_dir.join("linux-hardener/config.toml"),
        body("usr", half),
    )
    .expect("write user");

    let refusal = ConfigLoader::new()
        .with_system_config(system)
        .with_config_dir(user_dir)
        .with_running_as_root(false)
        .load()
        .expect_err("two halves that together exceed the cap must be refused");
    assert!(
        refusal.to_string().contains("directive"),
        "the refusal must name what was exceeded: {refusal}"
    );
}

/// The seam falls back to the real system path when unset, and returns the
/// seam when one is set.
///
/// Every other test in this file that reaches the system layer sets the
/// seam, so nothing asked what an unset one falls back to. The mutant
/// `self.system_config_path.clone().or_else(Self::system_config_path)`
/// replaced by `self.system_config_path.clone()` stops the shipping product
/// reading `/etc/linux-hardener/config.toml` at all, because every caller
/// that ships leaves the seam unset, and the whole workspace suite stayed
/// green under it.
#[test]
fn system_config_path_for_falls_back_to_the_real_path_when_unset() {
    let unseamed = ConfigLoader::new();
    assert_eq!(
        unseamed.system_config_path_for(),
        ConfigLoader::system_config_path(),
        "with no seam set, the loader must fall back to the real system path"
    );

    let seam = PathBuf::from("/tmp/config-loader-tests/system-config-seam.toml");
    let seamed = ConfigLoader::new().with_system_config(seam.clone());
    assert_eq!(
        seamed.system_config_path_for(),
        Some(seam),
        "and with a seam set, that seam must be what is returned"
    );
}

/// True when this process would read a closed file regardless of its mode, so
/// a permission test below can prove nothing and must say so by returning.
///
/// `chmod 0o000` does not stop a process with effective UID 0. Under a root
/// runner both permission tests in this file would go green without exercising
/// anything, which is the vacuous pass this project keeps meeting. An early
/// return is deliberately preferred to `#[ignore]`: this suite already carries
/// ignored tests, and an ignored test is one nobody runs, whereas a guarded one
/// runs on every unprivileged machine and only steps aside where it is blind.
///
/// It asks `ConfigLoader::is_running_as_root`, which under the default
/// `system` feature is `nix::unistd::geteuid().is_root()`, rather than calling
/// `nix` here, so the guard compiles on the same feature set as the crate.
fn root_would_read_it_anyway() -> bool {
    ConfigLoader::is_running_as_root()
}

/// Restores a directory's mode when it leaves scope, panic or not.
///
/// A `TempDir` deletes its tree on drop and cannot descend into a `0o000`
/// directory, so a test that closes one has to reopen it or the cleanup fails.
/// A plain statement at the end of the test would be skipped by a failing
/// assertion, which is precisely the run where the tree still needs removing.
struct ReopensOnDrop<'a>(&'a Path);

impl Drop for ReopensOnDrop<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;

        let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// The classifier tells a file that is not there from one that is, which is the
/// distinction the whole skip rests on.
///
/// Without this pair, a classifier answering `Unreachable` for everything, or
/// `Absent` for everything, would satisfy the unreachable test below: that one
/// asks only that a closed directory is not read. The two ordinary answers are
/// what say the classifier is classifying rather than returning a constant, and
/// they need no permission games, so they are asked outside the root guard and
/// run on every machine.
#[test]
fn classify_source_tells_an_absent_file_from_a_present_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let present = dir.path().join("config.toml");
    std::fs::write(&present, "[ssh]\nenabled = true\n").expect("write the config");

    assert_eq!(
        ConfigLoader::classify_source(&present),
        ConfigSourceState::Present,
        "a file that is there and can be stat'd is present"
    );
    assert_eq!(
        ConfigLoader::classify_source(&dir.path().join("nothing-here.toml")),
        ConfigSourceState::Absent,
        "and a path nobody installed anything at is absent, which is the \
         ordinary case and the one that stays silent"
    );
}

/// A source under a directory this process cannot traverse classifies as
/// unreachable, carrying the reason, rather than as absent.
///
/// This is the arm `Path::exists()` cannot express. The premise is asserted
/// first: `exists()` really does answer `false` here, identically to the absent
/// case above, so the two situations were genuinely indistinguishable to
/// `merge_source` and the operator got no signal for either.
///
/// Guarded, because `chmod 0o000` does not stop a process with effective UID 0:
/// under a root runner the directory stays traversable and the assertion would
/// pass without exercising anything.
///
/// The reopened control at the end is what stops the answer being a constant:
/// the same path, the same classifier, and a different answer once the
/// traversal is allowed.
#[test]
fn classify_source_reports_an_unreachable_file_rather_than_calling_it_absent() {
    use std::os::unix::fs::PermissionsExt;

    if root_would_read_it_anyway() {
        return;
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let closed = dir.path().join("closed");
    std::fs::create_dir(&closed).expect("create the directory that will be closed");
    let system = closed.join("system.toml");
    std::fs::write(&system, "[ssh]\nenabled = true\n").expect("write the config");

    // The file itself stays readable. Only the directory above it is closed,
    // so the failure under test is the traversal and not the read.
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
        .expect("close the directory");
    let _reopen = ReopensOnDrop(&closed);

    assert!(
        !system.exists(),
        "the premise: `exists()` is `metadata(..).is_ok()` and answers `false` \
         here exactly as it does for a file nobody installed, which is why the \
         classifier exists at all"
    );
    assert_eq!(
        ConfigLoader::classify_source(&system),
        ConfigSourceState::Unreachable(std::io::ErrorKind::PermissionDenied),
        "the classifier must say the question went unanswered, and say why, \
         rather than reporting the file as absent"
    );

    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
        .expect("reopen the directory");
    assert_eq!(
        ConfigLoader::classify_source(&system),
        ConfigSourceState::Present,
        "the control: the same path classifies as present once the directory is \
         traversable, so the answer above is about the permissions and not about \
         the path being wrong"
    );
}

/// A system config that exists and cannot be read is a hard error naming the
/// path, not a layer quietly dropped.
///
/// Nothing reached the read arm of `load_from_file` before. An unbounded grep
/// for `Failed to read config file` across the workspace finds two format
/// strings, this one and an unrelated one in the CLI's daemon command, and no
/// test site at all, so every mutant in that arm survived. The behaviour is
/// worth pinning for more than the mutant: the
/// package ships `/etc/linux-hardener/config.toml`, so a mode an operator or a
/// packaging step tightens turns every hardener command into an immediate
/// failure, and that failure must at minimum name the file that caused it.
///
/// Read together with its neighbour below. An unreadable FILE stops the tool;
/// an unreachable DIRECTORY is a skip that warns. The two are opposites and
/// neither is safe to let drift into the other unnoticed.
#[test]
fn an_unreadable_system_config_is_a_hard_error_naming_the_path() {
    use std::os::unix::fs::PermissionsExt;

    if root_would_read_it_anyway() {
        return;
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let system = dir.path().join("system.toml");
    std::fs::write(
        &system,
        "[global]\ndisabled_plugins = [\"mac-hardening\"]\n",
    )
    .expect("write system config");
    std::fs::set_permissions(&system, std::fs::Permissions::from_mode(0o000))
        .expect("close the system config to its owner");

    let refusal = ConfigLoader::new()
        .with_system_config(system.clone())
        .with_config_dir(dir.path().join("no-user-config"))
        .with_running_as_root(false)
        .load()
        .expect_err("a system config that exists and cannot be read must not be skipped");

    let message = refusal.to_string();
    assert!(
        message.contains("Failed to read config file"),
        "the refusal must come from the read arm rather than from the stat, the \
         size cap or the parser, or a different failure is being pinned: {message}"
    );
    assert!(
        message.contains(&system.display().to_string()),
        "and it must name the file, because an operator has no other way to tell \
         which of the layered sources refused: {message}"
    );
}

/// A system config the process cannot reach is skipped with a warning, and the
/// skip is the shipped behaviour rather than an accident of this test.
///
/// The skip is deliberate. Refusing to run would break every unprivileged
/// `scan` on a host in this state, usually over a benign default config, so
/// `merge_source` keeps returning the base configuration. What the operator
/// lacked was any signal, and the warning is what makes the skip observable;
/// the log line itself is not asserted here, because the decision that produces
/// it is asserted directly of `classify_source` above.
///
/// The situation is not hypothetical. `/etc/linux-hardener` is `0700
/// root:root` on a host that has run the tool as root once, because saving the
/// signing key chmods the key's parent, which is that shared config directory.
/// On such a host an unprivileged `scan` and a root `apply` resolve different
/// configuration, and until the warning existed neither said so.
///
/// Read together with its neighbour above. What this test buys is that the
/// difference between the two cannot change unnoticed, in either direction: if
/// the skip ever becomes a refusal, or the refusal ever becomes a skip, one of
/// the two goes red.
///
/// The reachable control at the end is what stops the assertion being vacuous.
/// Absence alone is also what a loader that read nothing whatsoever would
/// produce, so the same builder is made to read the same file once the
/// directory is reopened.
#[test]
fn a_system_config_inside_an_unreachable_directory_is_skipped_with_a_warning() {
    use std::os::unix::fs::PermissionsExt;

    if root_would_read_it_anyway() {
        return;
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let closed = dir.path().join("closed");
    std::fs::create_dir(&closed).expect("create the directory that will be closed");
    let system = closed.join("system.toml");
    std::fs::write(&system, "[ssh.directives]\nPermitRootLogin = \"no\"\n")
        .expect("write system config");

    // The file itself stays readable. Only the directory above it is closed,
    // so the failure under test is the traversal and not the read.
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
        .expect("close the directory");
    let _reopen = ReopensOnDrop(&closed);

    let unreachable = ConfigLoader::new()
        .with_system_config(system.clone())
        .with_config_dir(dir.path().join("no-user-config"))
        .with_running_as_root(false)
        .load()
        .expect("an unreachable system config is not an error today, it is a skip");

    assert!(
        !unreachable.ssh.directives.contains_key("PermitRootLogin"),
        "the file sets this directive and the load must not have seen it: the \
         source classifies as unreachable, so `merge_source` returns the base \
         config and the entire system layer is skipped, warning as it goes"
    );

    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
        .expect("reopen the directory");
    let reachable = ConfigLoader::new()
        .with_system_config(system)
        .with_config_dir(dir.path().join("no-user-config"))
        .with_running_as_root(false)
        .load()
        .expect("the same load with the directory reopened");

    assert_eq!(
        reachable
            .ssh
            .directives
            .get("PermitRootLogin")
            .map(String::as_str),
        Some("no"),
        "the control: the same builder reading the same file must pick the \
         directive up once the directory is traversable, or the absence above \
         says nothing about permissions and everything about the seam being ignored"
    );
}
