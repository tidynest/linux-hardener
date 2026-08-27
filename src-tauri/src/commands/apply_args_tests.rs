#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms, following `fleet_tests.rs`.

//! Tests for [`apply_args`](super::apply_args), the argv behind both
//! `run_apply` and `run_apply_dry_run`.
//!
//! The builder is shared, so `--dry-run` is now the only thing standing
//! between a preview and a real modification of the host. That flag is what
//! these tests are for. `build_batch_args` has the same shape and the same
//! reason for existing.

use super::*;

fn ids(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

/// The flag the whole split turns on. A mutation dropping it would make the
/// desktop's preview harden the host for real, and the operator would see a
/// dialogue promising the opposite.
#[test]
fn dry_run_adds_the_flag_and_a_real_apply_does_not() {
    let preview = apply_args(true, &ids(&["kernel-hardening"]), None);
    let real = apply_args(false, &ids(&["kernel-hardening"]), None);

    assert!(
        preview.contains(&"--dry-run".to_string()),
        "a preview must ask the CLI for one: {preview:?}"
    );
    assert!(
        !real.contains(&"--dry-run".to_string()),
        "a real apply must not be turned into a preview: {real:?}"
    );
}

/// Both spellings name the same verb and the same output format. A preview
/// parsed by a different rule than the apply that follows it is a preview of
/// something else.
#[test]
fn both_forms_ask_for_apply_in_json() {
    for dry_run in [true, false] {
        let args = apply_args(dry_run, &[], None);
        assert_eq!(args.first().map(String::as_str), Some("apply"));
        assert!(
            args.windows(2)
                .any(|w| w == ["--format".to_string(), "json".to_string()]),
            "dry_run={dry_run} lost --format json: {args:?}"
        );
    }
}

/// One repeated `--plugin` per id, in the order given. A joined list would
/// reach clap as a single unmatched value, and the CLI's `apply` drops an
/// unmatched plugin name silently.
#[test]
fn each_plugin_id_gets_its_own_flag_in_order() {
    let args = apply_args(false, &ids(&["kernel-hardening", "ssh-hardening"]), None);

    let plugins: Vec<&str> = args
        .windows(2)
        .filter(|w| w[0] == "--plugin")
        .map(|w| w[1].as_str())
        .collect();

    assert_eq!(plugins, vec!["kernel-hardening", "ssh-hardening"]);
}

/// No plugins means no `--plugin`, which is how the CLI is asked for its
/// default set rather than for an empty one.
#[test]
fn no_plugins_emits_no_plugin_flag() {
    let args = apply_args(false, &[], None);
    assert!(
        !args.contains(&"--plugin".to_string()),
        "an empty selection must not become an empty flag: {args:?}"
    );
}

/// `--config` appears only when there is one, and carries the path given.
/// `rollback_args` records what the absent case costs on the neighbouring
/// verb: a flag pushed where the CLI does not expect one made clap refuse the
/// whole command.
#[test]
fn config_path_is_passed_only_when_set() {
    let without = apply_args(true, &ids(&["ssh-hardening"]), None);
    assert!(
        !without.contains(&"--config".to_string()),
        "no config path must mean no flag: {without:?}"
    );

    let with = apply_args(true, &ids(&["ssh-hardening"]), Some("/etc/hardener.toml"));
    let pair = with
        .windows(2)
        .find(|w| w[0] == "--config")
        .expect("a config path must reach the CLI");
    assert_eq!(pair[1], "/etc/hardener.toml");
}
