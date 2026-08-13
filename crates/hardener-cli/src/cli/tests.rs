#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`cli`](super).
//!
//! Split out of `cli.rs`. This file sits in the `cli/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::cli` and every import carried
//! across unchanged, private items included.
//!
//! 451 test lines of argument parsing, the second largest block in the crate.

use super::*;
use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Csv,
    Html,
}

#[test]
fn test_cli_parse_scan() {
    let cli = Cli::parse_from(["hardener", "scan"]);
    assert!(matches!(cli.command, Command::Scan { .. }));
}

#[test]
fn test_cli_parse_scan_with_plugin() {
    let cli = Cli::parse_from(["hardener", "scan", "--plugin", "kernel"]);
    if let Command::Scan { plugin, .. } = cli.command {
        assert_eq!(plugin, vec!["kernel"]);
    } else {
        panic!("Expected Scan command");
    }
}

#[test]
fn test_cli_parse_scan_with_severity() {
    let cli = Cli::parse_from(["hardener", "scan", "--severity", "high"]);
    if let Command::Scan { severity, .. } = cli.command {
        assert!(matches!(severity, SeverityFilter::High));
    } else {
        panic!("Expected Scan command");
    }
}

#[test]
fn test_cli_parse_apply() {
    let cli = Cli::parse_from(["hardener", "apply", "--all"]);
    if let Command::Apply { all, .. } = cli.command {
        assert!(all);
    } else {
        panic!("Expected Apply command");
    }
}

#[test]
fn test_cli_parse_apply_dry_run() {
    let cli = Cli::parse_from(["hardener", "apply", "--all", "--dry-run"]);
    if let Command::Apply { dry_run, .. } = cli.command {
        assert!(dry_run);
    } else {
        panic!("Expected Apply command");
    }
}

#[test]
fn test_cli_parse_plugins() {
    let cli = Cli::parse_from(["hardener", "plugins"]);
    assert!(matches!(cli.command, Command::Plugins));
}

#[test]
fn test_cli_parse_report_framework() {
    let cli = Cli::parse_from(["hardener", "report", "--framework", "cis"]);
    if let Command::Report { framework, .. } = cli.command {
        assert_eq!(framework, Some("cis".to_string()));
    } else {
        panic!("Expected Report command");
    }
}

#[test]
fn test_cli_parse_report_profile() {
    let cli = Cli::parse_from(["hardener", "report", "--profile", "rhel10"]);
    if let Command::Report { profile, .. } = cli.command {
        assert_eq!(profile, Some("rhel10".to_string()));
    } else {
        panic!("Expected Report command");
    }

    // Omitted -> None, so the command auto-detects.
    let cli = Cli::parse_from(["hardener", "report"]);
    if let Command::Report { profile, .. } = cli.command {
        assert!(profile.is_none());
    } else {
        panic!("Expected Report command");
    }
}

#[test]
fn test_cli_parse_checkpoint_list() {
    let cli = Cli::parse_from(["hardener", "checkpoint", "list"]);
    if let Command::Checkpoint { action } = cli.command {
        assert!(
            matches!(
                action,
                CheckpointAction::List {
                    limit: 20,
                    all: false
                }
            ),
            "list defaults to a 20-row limit and not --all"
        );
    } else {
        panic!("Expected Checkpoint command");
    }
}

#[test]
fn test_cli_parse_checkpoint_list_limit_and_all() {
    let cli = Cli::parse_from(["hardener", "checkpoint", "list", "--limit", "5", "--all"]);
    if let Command::Checkpoint {
        action: CheckpointAction::List { limit, all },
    } = cli.command
    {
        assert_eq!(limit, 5);
        assert!(all);
    } else {
        panic!("Expected Checkpoint list with limit and all");
    }
}

#[test]
fn test_cli_parse_checkpoint_create() {
    let cli = Cli::parse_from(["hardener", "checkpoint", "create", "my-checkpoint"]);
    if let Command::Checkpoint { action } = cli.command {
        if let CheckpointAction::Create { name } = action {
            assert_eq!(name, "my-checkpoint");
        } else {
            panic!("Expected Create action");
        }
    } else {
        panic!("Expected Checkpoint command");
    }
}

#[test]
fn test_cli_global_format_json() {
    let cli = Cli::parse_from(["hardener", "--format", "json", "scan"]);
    assert!(matches!(cli.format, GlobalFormat::Json));
}

#[test]
fn test_cli_global_quiet() {
    let cli = Cli::parse_from(["hardener", "--quiet", "scan"]);
    assert!(cli.quiet);
}

/// `--compliance` was accepted and did nothing: it built a `ScanMode`
/// variant no code read, so it produced the default scan while its help
/// text and the manual promised a filtered one. Accepting it is the
/// defect, so rejecting it is the fix. `report --framework X` is the real
/// compliance output.
#[test]
fn scan_rejects_the_removed_compliance_flag() {
    let parsed = Cli::try_parse_from(["hardener", "scan", "--compliance"]);
    assert!(
        parsed.is_err(),
        "--compliance must no longer be accepted, but clap parsed it"
    );
}

#[test]
fn test_scan_mode_default() {
    let mode = ScanMode::default();
    assert_eq!(mode, ScanMode::Default);
}

#[test]
fn test_severity_filter_default() {
    let filter = SeverityFilter::default();
    assert!(matches!(filter, SeverityFilter::Info));
}

#[test]
fn test_report_format_values() {
    assert!(matches!(
        ReportFormat::from_str("text", true).unwrap(),
        ReportFormat::Text
    ));
    assert!(matches!(
        ReportFormat::from_str("json", true).unwrap(),
        ReportFormat::Json
    ));
    assert!(matches!(
        ReportFormat::from_str("csv", true).unwrap(),
        ReportFormat::Csv
    ));
    assert!(matches!(
        ReportFormat::from_str("html", true).unwrap(),
        ReportFormat::Html
    ));
}

#[test]
fn test_cli_parse_systemd_generate() {
    let cli = Cli::parse_from(["hardener", "systemd", "generate"]);
    if let Command::Systemd { action } = cli.command {
        assert!(matches!(action, SystemdAction::Generate { .. }));
    } else {
        panic!("Expected Systemd command");
    }
}

#[test]
fn test_cli_parse_systemd_install_user() {
    let cli = Cli::parse_from(["hardener", "systemd", "install", "--user"]);
    if let Command::Systemd { action } = cli.command {
        if let SystemdAction::Install { user, .. } = action {
            assert!(user);
        } else {
            panic!("Expected Install action");
        }
    } else {
        panic!("Expected Systemd command");
    }
}

#[test]
fn test_cli_parse_history_list() {
    let cli = Cli::parse_from(["hardener", "history", "list"]);
    if let Command::History { action } = cli.command {
        assert!(matches!(action, HistoryAction::List { .. }));
    } else {
        panic!("Expected History command");
    }
}

#[test]
fn test_cli_parse_history_list_with_limit() {
    let cli = Cli::parse_from(["hardener", "history", "list", "--limit", "50"]);
    if let Command::History { action } = cli.command {
        if let HistoryAction::List { limit, .. } = action {
            assert_eq!(limit, 50);
        } else {
            panic!("Expected List action");
        }
    } else {
        panic!("Expected History command");
    }
}

#[test]
fn test_cli_parse_history_list_with_filters() {
    let cli = Cli::parse_from([
        "hardener",
        "history",
        "list",
        "--host",
        "server1",
        "--status",
        "completed",
    ]);
    if let Command::History { action } = cli.command {
        if let HistoryAction::List { host, status, .. } = action {
            assert_eq!(host, Some("server1".to_string()));
            assert_eq!(status, Some("completed".to_string()));
        } else {
            panic!("Expected List action");
        }
    } else {
        panic!("Expected History command");
    }
}

#[test]
fn test_cli_parse_history_show() {
    let cli = Cli::parse_from(["hardener", "history", "show", "abc-123"]);
    if let Command::History { action } = cli.command {
        if let HistoryAction::Show { session_id } = action {
            assert_eq!(session_id, "abc-123");
        } else {
            panic!("Expected Show action");
        }
    } else {
        panic!("Expected History command");
    }
}

#[test]
fn test_cli_parse_history_export() {
    let cli = Cli::parse_from(["hardener", "history", "export", "abc-123"]);
    if let Command::History { action } = cli.command {
        if let HistoryAction::Export { session_id, output } = action {
            assert_eq!(session_id, "abc-123");
            assert!(output.is_none());
        } else {
            panic!("Expected Export action");
        }
    } else {
        panic!("Expected History command");
    }
}

#[test]
fn test_cli_parse_batch_scan_all() {
    let cli = Cli::parse_from(["hardener", "batch", "scan", "--all"]);
    assert!(matches!(cli.command, Command::Batch { .. }));
    if let Command::Batch {
        action: BatchAction::Scan { all, .. },
    } = cli.command
    {
        assert!(all);
    } else {
        panic!("Expected Batch Scan command");
    }
}

#[test]
fn test_cli_parse_batch_host_comma() {
    let cli = Cli::parse_from(["hardener", "batch", "scan", "--host", "web-01,db-02"]);
    if let Command::Batch {
        action: BatchAction::Scan { host, .. },
    } = cli.command
    {
        assert_eq!(host, vec!["web-01", "db-02"]);
    } else {
        panic!("Expected Batch Scan command");
    }
}

#[test]
fn test_cli_parse_batch_all_conflicts_host() {
    assert!(Cli::try_parse_from(["hardener", "batch", "scan", "--all", "--host", "x"]).is_err());
}

#[test]
fn test_cli_parse_batch_defaults_and_output() {
    let cli = Cli::parse_from(["hardener", "batch", "scan", "--ssh", "u@h"]);
    if let Command::Batch {
        action:
            BatchAction::Scan {
                concurrency,
                output,
                ..
            },
    } = cli.command
    {
        assert_eq!(concurrency, 8);
        assert!(output.is_none());
    } else {
        panic!("Expected Batch Scan command");
    }

    let cli = Cli::parse_from([
        "hardener",
        "batch",
        "scan",
        "--all",
        "--output",
        "/tmp/x",
        "--concurrency",
        "4",
    ]);
    if let Command::Batch {
        action:
            BatchAction::Scan {
                concurrency,
                output,
                ..
            },
    } = cli.command
    {
        assert_eq!(output, Some("/tmp/x".to_string()));
        assert_eq!(concurrency, 4);
    } else {
        panic!("Expected Batch Scan command");
    }
}

#[test]
fn test_cli_parse_batch_report_framework() {
    let cli = Cli::parse_from(["hardener", "batch", "report", "--all", "--framework", "cis"]);
    if let Command::Batch {
        action: BatchAction::Report { all, framework, .. },
    } = cli.command
    {
        assert!(all);
        assert_eq!(framework.as_deref(), Some("cis"));
    } else {
        panic!("Expected Batch Report command");
    }
}

#[test]
fn test_cli_parse_batch_report_profile() {
    let cli = Cli::parse_from([
        "hardener",
        "batch",
        "report",
        "--all",
        "--profile",
        "rhel10",
    ]);
    if let Command::Batch {
        action: BatchAction::Report { all, profile, .. },
    } = cli.command
    {
        assert!(all);
        assert_eq!(profile.as_deref(), Some("rhel10"));
    } else {
        panic!("Expected Batch Report command");
    }
}

#[test]
fn test_cli_parse_batch_report_framework_conflicts_scenario() {
    assert!(
        Cli::try_parse_from([
            "hardener",
            "batch",
            "report",
            "--all",
            "--framework",
            "cis",
            "--scenario",
            "server",
        ])
        .is_err(),
        "--framework and --scenario are mutually exclusive",
    );
}

#[test]
fn test_cli_parse_history_export_with_output() {
    let cli = Cli::parse_from([
        "hardener",
        "history",
        "export",
        "abc-123",
        "--output",
        "/tmp/export.json",
    ]);
    if let Command::History { action } = cli.command {
        if let HistoryAction::Export { session_id, output } = action {
            assert_eq!(session_id, "abc-123");
            assert_eq!(output, Some(std::path::PathBuf::from("/tmp/export.json")));
        } else {
            panic!("Expected Export action");
        }
    } else {
        panic!("Expected History command");
    }
}

/// Every invocation that must keep working, so the refusals below cannot be
/// read as "the flag is refused wherever it was not obviously needed".
///
/// The last two are the ones that would cost the most: `batch` carries its own
/// `--ssh` on each subcommand, and a refusal matching the flag as a token
/// rather than as the parsed global would refuse every ad-hoc fleet run,
/// including the desktop's, which composes exactly this vector.
#[test]
fn the_commands_that_reach_a_host_still_take_ssh() {
    let honoured: Vec<Vec<&str>> = vec![
        vec!["hardener", "--ssh", "web-01", "scan"],
        vec!["hardener", "--ssh", "web-01", "apply", "--all"],
        vec!["hardener", "--ssh", "web-01", "rollback", "cp_1"],
        vec![
            "hardener",
            "--ssh",
            "web-01",
            "report",
            "--framework",
            "cis",
        ],
        vec!["hardener", "--ssh", "web-01", "report", "--interactive"],
        vec!["hardener", "--ssh", "web-01", "checkpoint", "list"],
        vec!["hardener", "--ssh", "web-01", "checkpoint", "create", "pre"],
    ];

    for argv in honoured {
        let cli = Cli::parse_from(&argv);
        assert!(
            cli.command.ssh_refusal().is_none(),
            "{} must keep honouring --ssh",
            argv.join(" ")
        );
        assert_eq!(cli.ssh.as_deref(), Some("web-01"));
    }
}

/// `--ssh` and batch's own `--ssh` are one argument, in either position.
///
/// This is the assertion the whole refusal rests on, and it was written after
/// the opposite was assumed: clap resolves the global argument and the one
/// each batch subcommand declares to a single argument, because the
/// identifiers match. So both forms below fill the global field AND batch's
/// ad-hoc target list, and refusing `batch` on the strength of the global
/// field being set would refuse every ad-hoc fleet run, the desktop's
/// included. If a clap upgrade ever separates them, this fails here rather
/// than in somebody's fleet.
#[test]
fn a_batch_ad_hoc_target_is_the_same_argument_as_the_global_flag() {
    for argv in [
        vec!["hardener", "batch", "scan", "--ssh", "root@10.0.0.5:22"],
        vec!["hardener", "--ssh", "root@10.0.0.5:22", "batch", "scan"],
    ] {
        let cli = Cli::parse_from(&argv);

        assert_eq!(
            cli.ssh.as_deref(),
            Some("root@10.0.0.5:22"),
            "{}: the global field carries it whichever side of the subcommand it was typed",
            argv.join(" ")
        );
        assert!(
            cli.command.ssh_refusal().is_none(),
            "{}: batch consumes this flag rather than ignoring it",
            argv.join(" ")
        );
        if let Command::Batch { action } = &cli.command
            && let BatchAction::Scan { ssh, .. } = action
        {
            assert_eq!(
                ssh,
                &vec!["root@10.0.0.5:22".to_string()],
                "{}: and it reaches batch's ad-hoc target list",
                argv.join(" ")
            );
        } else {
            panic!("Expected Batch Scan");
        }
    }
}

/// The commands that never receive the executor. Each is named in the refusal,
/// because "--ssh is not supported" on a five-word command line leaves the
/// operator to work out which of the five words was the problem.
#[test]
fn the_commands_that_never_reach_a_host_refuse_ssh() {
    let refused: Vec<(Vec<&str>, &str)> = vec![
        (vec!["hardener", "--ssh", "web-01", "plugins"], "plugins"),
        (
            vec!["hardener", "--ssh", "web-01", "daemon", "start"],
            "daemon start",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "daemon", "run-once"],
            "daemon run-once",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "daemon", "status"],
            "daemon status",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "systemd", "generate"],
            "systemd generate",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "systemd", "install"],
            "systemd install",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "systemd", "uninstall"],
            "systemd uninstall",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "systemd", "status"],
            "systemd status",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "history", "list"],
            "history list",
        ),
        (
            vec![
                "hardener", "--ssh", "web-01", "history", "trends", "--host", "web-01",
            ],
            "history trends",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "history", "regressions"],
            "history regressions",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "history", "show", "s1"],
            "history show",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "history", "export", "s1"],
            "history export",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "checkpoint", "show", "cp_1"],
            "checkpoint show",
        ),
        (
            vec![
                "hardener",
                "--ssh",
                "web-01",
                "checkpoint",
                "delete",
                "cp_1",
            ],
            "checkpoint delete",
        ),
        (
            vec!["hardener", "--ssh", "web-01", "checkpoint", "repair"],
            "checkpoint repair",
        ),
        (
            vec![
                "hardener",
                "--ssh",
                "web-01",
                "exception",
                "add",
                "kernel-hardening",
                "KEG1",
                "--reason",
                "acceptable deviation",
            ],
            "exception",
        ),
        (
            vec![
                "hardener",
                "--ssh",
                "web-01",
                "exception",
                "remove",
                "kernel-hardening",
                "KEG1",
            ],
            "exception",
        ),
    ];

    for (argv, name) in refused {
        let cli = Cli::parse_from(&argv);
        let refusal = cli
            .command
            .ssh_refusal()
            .unwrap_or_else(|| panic!("{} must refuse --ssh", argv.join(" ")));
        assert_eq!(refusal.command, name);
        assert!(
            refusal.because.starts_with("it ") || refusal.because.starts_with("the "),
            "{name}'s reason must complete the sentence it is printed in rather than restate the command"
        );
    }
}

/// The two halves of one checkpoint group answer differently, which is the
/// case a per-command classification would get wrong.
///
/// `list` and `create` reach the host; `show` and `delete` address one row of
/// this host's own database by an id that is unique across every host in it. A
/// classification written per command rather than per action would have to
/// pick one answer for all four, and either choice is wrong for two of them.
#[test]
fn one_command_group_can_answer_both_ways() {
    let reaching = Cli::parse_from(["hardener", "--ssh", "web-01", "checkpoint", "list"]);
    let local = Cli::parse_from([
        "hardener",
        "--ssh",
        "web-01",
        "checkpoint",
        "delete",
        "cp_1",
    ]);

    assert!(reaching.command.ssh_refusal().is_none());
    assert_eq!(
        local.command.ssh_refusal().map(|r| r.command),
        Some("checkpoint delete")
    );
}

/// The global flag renders two formats and now says so at the parse.
///
/// It was typed as the compliance crate's five-valued enum, so clap accepted
/// `csv`, `html` and `pdf` on every command in the binary while not one of them
/// rendered any of the three: they were byte-identical aliases of `text`, in
/// `scan`, `history export`, every `checkpoint` verb and all four `batch`
/// verbs. Refusing them at the parse is what stops a fleet report from being
/// asked for as csv and handed over as text.
#[test]
fn the_global_format_flag_takes_only_what_it_renders() {
    for accepted in ["text", "json"] {
        assert!(
            Cli::try_parse_from(["hardener", "--format", accepted, "scan"]).is_ok(),
            "--format {accepted} is rendered and must parse"
        );
    }

    for refused in ["csv", "html", "pdf"] {
        let parsed = Cli::try_parse_from(["hardener", "--format", refused, "scan"]);
        let rendered = match parsed {
            Ok(_) => panic!("--format {refused} renders nothing and must be refused at the parse"),
            Err(error) => error.to_string(),
        };

        assert!(
            rendered.contains("text") && rendered.contains("json"),
            "--format {refused} is refused naming what it could have been: {rendered}"
        );
    }
}

/// The conversion every command now flows through, in both directions.
///
/// Two same-shaped two-variant enums and a hand-written match is exactly the
/// place a swapped arm compiles and says nothing: `Text => Json` would make the
/// default invocation of every command in the binary emit JSON, and no other
/// test in the crate would notice, because they all assert on the flag rather
/// than on what it becomes.
#[test]
fn the_narrowed_flag_widens_to_the_format_it_names() {
    assert_eq!(OutputFormat::from(GlobalFormat::Text), OutputFormat::Text);
    assert_eq!(OutputFormat::from(GlobalFormat::Json), OutputFormat::Json);
}

/// The rich formats keep their own route, which is the reason the flag above
/// can be narrowed without taking a capability away.
///
/// This asserts the parse alone: `--report-format` is an `Option<String>` that
/// `commands::report` matches at runtime, so what this pins is that the flag
/// still exists, still takes those three values, and still carries them
/// through to the command. The runtime match is proved by the suite's own
/// section 7, which renders all five for every framework in a container.
#[test]
fn report_still_takes_the_formats_the_global_flag_does_not() {
    for format in ["csv", "html", "pdf"] {
        let cli = Cli::parse_from(["hardener", "report", "--report-format", format]);
        if let Command::Report { report_format, .. } = cli.command {
            assert_eq!(report_format.as_deref(), Some(format));
        } else {
            panic!("Expected Report command");
        }
    }
}

/// An unstated `--report-format` must arrive as `None`, not as a defaulted
/// string.
///
/// This is the parse half of #160. The flag carried a clap `default_value` of
/// "text", so `commands::report` received the same value whether the user had
/// asked for text or asked for nothing, and could not let the global
/// `-f/--format` decide in the second case without overriding the first. The
/// resolution half is pinned in `commands::report`'s own tests; without this
/// one, re-adding `default_value` would leave that test green and silently
/// restore the defect, because the resolver would simply never see `None`.
#[test]
fn an_unstated_report_format_is_absent_rather_than_defaulted() {
    let cli = Cli::parse_from(["hardener", "report"]);
    if let Command::Report { report_format, .. } = cli.command {
        assert_eq!(
            report_format, None,
            "a defaulted value here makes the command unable to tell an \
             explicit --report-format text from an unstated one"
        );
    } else {
        panic!("Expected Report command");
    }
}
