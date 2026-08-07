#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`config`](super).
//!
//! Split out of `config.rs`. This file sits in the `config/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`, so
//! `super` still resolves to `crate::config` and every import carried across
//! unchanged, private items included.

use super::*;

#[test]
fn policy_exception_maps_to_finding_exception() {
    let ex = PolicyException {
        value: "yes".into(),
        allowed: true,
        reason: "legacy jump host".into(),
        approved_by: Some("Security Team".into()),
        approved_date: Some("2026-01-15".into()),
        ticket: Some("SEC-1234".into()),
        expires: None,
    };
    let fe = ex.to_finding_exception();
    assert_eq!(fe.exception_allowed_value, "yes");
    assert_eq!(fe.exception_reason, "legacy jump host");
    assert_eq!(fe.exception_ticket.as_deref(), Some("SEC-1234"));
    assert!(!fe.exception_is_expired); // no expiry -> not expired
}

/// Builds a valid exception allowing `value` for testing.
fn exception(value: &str, expires: Option<&str>) -> PolicyException {
    PolicyException {
        value: value.into(),
        allowed: true,
        reason: "documented deviation".into(),
        approved_by: None,
        approved_date: None,
        ticket: None,
        expires: expires.map(str::to_string),
    }
}

fn plugin_with(key: &str, exception: PolicyException) -> PluginConfig {
    let mut plugin = PluginConfig::default();
    plugin.exceptions.insert(key.to_string(), exception);
    plugin
}

#[test]
fn matching_exception_honours_only_the_documented_value() {
    let plugin = plugin_with("PermitRootLogin", exception("yes", None));

    // The exception describes the real deviation: honoured.
    assert!(
        plugin
            .matching_exception("PermitRootLogin", "yes")
            .is_some()
    );
    // The system deviates differently from what was approved: ignored.
    assert!(
        plugin
            .matching_exception("PermitRootLogin", "prohibit-password")
            .is_none()
    );
    // Unknown key: nothing to honour.
    assert!(plugin.matching_exception("X11Forwarding", "yes").is_none());
}

#[test]
fn matching_exception_rejects_an_expired_exception() {
    let plugin = plugin_with("PermitRootLogin", exception("yes", Some("2020-01-01")));

    assert!(
        plugin
            .matching_exception("PermitRootLogin", "yes")
            .is_none()
    );
}

#[test]
fn matching_mode_exception_normalises_octal_spelling() {
    let plugin = plugin_with("/etc/passwd", exception("644", None));

    // Written without the leading zero, but the same mode.
    assert!(
        plugin
            .matching_mode_exception("/etc/passwd", 0o644)
            .is_some()
    );
    // A different mode is not the approved deviation.
    assert!(
        plugin
            .matching_mode_exception("/etc/passwd", 0o600)
            .is_none()
    );

    // The four-digit spelling of the same mode also matches.
    let padded = plugin_with("/etc/passwd", exception("0644", None));
    assert!(
        padded
            .matching_mode_exception("/etc/passwd", 0o644)
            .is_some()
    );
    // A non-octal value can never describe a mode.
    let bogus = plugin_with("/etc/passwd", exception("rw-r--r--", None));
    assert!(
        bogus
            .matching_mode_exception("/etc/passwd", 0o644)
            .is_none()
    );
}

/// The section a plugin's exceptions live under and the field
/// [`HardenerConfig::get_plugin_config`] returns are two separate eight-arm
/// matches that could drift apart in silence. Writing an exception under the
/// named section and reading it back through the other match is the only
/// thing that proves they did not.
#[test]
fn every_plugin_reads_exceptions_from_the_section_it_names() {
    const PLUGIN_IDS: &[&str] = &[
        "ssh-hardening",
        "kernel-hardening",
        "firewall-hardening",
        "pam-hardening",
        "audit-hardening",
        "mac-hardening",
        "permissions-hardening",
        "service-minimisation",
    ];

    for plugin_id in PLUGIN_IDS {
        let section = HardenerConfig::config_section(plugin_id)
            .unwrap_or_else(|| panic!("{plugin_id} names no config section"));
        let document = format!(
            "[{section}.exceptions.\"a.key\"]\n\
             value = \"live\"\n\
             allowed = true\n\
             reason = \"test\"\n"
        );
        let config: HardenerConfig = toml::from_str(&document).unwrap_or_else(|e| {
            panic!("{plugin_id} names section {section}, which did not parse: {e}")
        });

        assert!(
            config
                .get_plugin_config(plugin_id)
                .has_valid_exception("a.key")
                .is_some(),
            "{plugin_id} names section {section}, but get_plugin_config does not read that section",
        );
    }
}

/// The control for the test above. Without it a `config_section` returning one
/// wrong section for every plugin would still pass, because the exception
/// would be written and read back in the same wrong place.
#[test]
fn an_exception_in_another_plugins_section_is_not_read() {
    let config: HardenerConfig = toml::from_str(
        "[ssh.exceptions.\"a.key\"]\nvalue = \"live\"\nallowed = true\nreason = \"test\"\n",
    )
    .expect("the fixture parses");

    assert!(
        config
            .get_plugin_config("ssh-hardening")
            .has_valid_exception("a.key")
            .is_some(),
        "the fixture must be a real exception, or this control measures nothing",
    );
    assert!(
        config
            .get_plugin_config("kernel-hardening")
            .has_valid_exception("a.key")
            .is_none(),
        "an exception written under [ssh] must not be visible to the kernel plugin",
    );
}

#[test]
fn exception_outcome_declines_a_value_the_host_does_not_have() {
    let config = plugin_with("PermitRootLogin", exception("yes", None));

    let outcome = config.exception_outcome("PermitRootLogin", "prohibit-password");

    match outcome {
        ExceptionOutcome::Declined(declined) => match declined.exception_declined_reason {
            DeclineReason::ValueMismatch {
                documented,
                observed,
            } => {
                assert_eq!(
                    documented, "yes",
                    "the documented value is reported as written"
                );
                assert_eq!(
                    observed, "prohibit-password",
                    "the observed value is reported as read"
                );
            }
            other => panic!("expected a value mismatch, got {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }
}

#[test]
fn exception_outcome_declines_an_expired_exception() {
    let config = plugin_with(
        "PermitRootLogin",
        exception("prohibit-password", Some("2000-01-01")),
    );

    let outcome = config.exception_outcome("PermitRootLogin", "prohibit-password");

    match outcome {
        ExceptionOutcome::Declined(declined) => match declined.exception_declined_reason {
            DeclineReason::Expired { expired_on } => {
                assert_eq!(
                    expired_on, "2000-01-01",
                    "the expiry the operator wrote is the one reported"
                );
            }
            other => panic!("expected an expiry, got {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }
}

#[test]
fn exception_outcome_declines_expiry_over_a_simultaneous_value_mismatch() {
    // Both conditions hold at once: the exception documents "yes" but the
    // host now reads "prohibit-password", AND the exception expired in 2000.
    // Expiry must win, because expiry is the reason the exception stopped
    // applying, and correcting the value would not bring it back.
    let config = plugin_with("PermitRootLogin", exception("yes", Some("2000-01-01")));

    let outcome = config.exception_outcome("PermitRootLogin", "prohibit-password");

    match outcome {
        ExceptionOutcome::Declined(declined) => match declined.exception_declined_reason {
            DeclineReason::Expired { expired_on } => {
                assert_eq!(
                    expired_on, "2000-01-01",
                    "the expiry the operator wrote is the one reported"
                );
            }
            other => panic!("expected an expiry, got {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }
}

#[test]
fn exception_outcome_stays_silent_when_the_operator_wrote_allowed_false() {
    let mut refused = exception("yes", None);
    refused.allowed = false;
    let config = plugin_with("PermitRootLogin", refused);

    let outcome = config.exception_outcome("PermitRootLogin", "prohibit-password");

    assert!(
        matches!(outcome, ExceptionOutcome::NotConfigured),
        "allowed = false is the operator declining to except this, and honouring \
         that by doing nothing is correct rather than silent"
    );
}

#[test]
fn exception_outcome_applies_a_valid_matching_exception() {
    let config = plugin_with("PermitRootLogin", exception("yes", None));

    let outcome = config.exception_outcome("PermitRootLogin", "yes");

    match outcome {
        ExceptionOutcome::Applied(applied) => {
            assert_eq!(applied.exception_allowed_value, "yes");
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

#[test]
fn exception_outcome_for_presence_never_reports_a_value_mismatch() {
    let config = plugin_with("bluetooth", exception("running", None));

    let outcome = config.exception_outcome_for_presence("bluetooth");

    assert!(
        matches!(outcome, ExceptionOutcome::Applied(_)),
        "a presence check has no host value to compare, so the exception's own \
         value field is advisory and must never decline the exception"
    );
}

#[test]
fn exception_outcome_for_presence_still_declines_an_expiry() {
    let config = plugin_with("bluetooth", exception("running", Some("2000-01-01")));

    let outcome = config.exception_outcome_for_presence("bluetooth");

    assert!(
        matches!(
            outcome,
            ExceptionOutcome::Declined(FindingExceptionDeclined {
                exception_declined_reason: DeclineReason::Expired { .. },
                ..
            })
        ),
        "expiry applies to every check, valued or not"
    );
}

#[test]
fn exception_outcome_is_not_configured_when_no_exception_names_the_key() {
    let config = PluginConfig::default();

    let outcome = config.exception_outcome("PermitRootLogin", "prohibit-password");

    assert!(matches!(outcome, ExceptionOutcome::NotConfigured));
}

/// The regression this exists for: the permissions plugin formats an
/// observed mode zero-padded (`"0640"`), but an operator may document their
/// exception without the leading zero (`"640"`), and `docs/reference/
/// configuration.md` promises both spellings match the same mode. Comparing
/// them as text via `exception_outcome` reports a working exception as a
/// declined value mismatch; `exception_outcome_for_mode` must compare
/// numerically instead and apply it.
#[test]
fn exception_outcome_for_mode_applies_an_exception_spelled_without_the_leading_zero() {
    let config = plugin_with("/etc/shadow", exception("640", None));

    let outcome = config.exception_outcome_for_mode("/etc/shadow", 0o640);

    match outcome {
        ExceptionOutcome::Applied(applied) => {
            assert_eq!(
                applied.exception_allowed_value, "640",
                "the operator's own spelling is carried onto the finding unchanged"
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

/// The control for the test above: a genuinely different mode must still
/// decline, so the numeric comparison is not accidentally matching
/// everything.
#[test]
fn exception_outcome_for_mode_declines_a_genuinely_different_mode() {
    let config = plugin_with("/etc/shadow", exception("640", None));

    let outcome = config.exception_outcome_for_mode("/etc/shadow", 0o600);

    match outcome {
        ExceptionOutcome::Declined(declined) => match declined.exception_declined_reason {
            DeclineReason::ValueMismatch {
                documented,
                observed,
            } => {
                assert_eq!(
                    documented, "640",
                    "the documented value is reported as the operator wrote it"
                );
                assert_eq!(
                    observed, "0600",
                    "the observed mode is reported zero-padded, matching finding_current_value"
                );
            }
            other => panic!("expected a value mismatch, got {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }
}

/// A value that is not valid octal can never describe a mode, so it must
/// never match, regardless of what the observed mode happens to be.
#[test]
fn exception_outcome_for_mode_declines_a_non_octal_value() {
    let config = plugin_with("/etc/shadow", exception("rw-r-----", None));

    let outcome = config.exception_outcome_for_mode("/etc/shadow", 0o640);

    assert!(
        matches!(
            outcome,
            ExceptionOutcome::Declined(FindingExceptionDeclined {
                exception_declined_reason: DeclineReason::ValueMismatch { .. },
                ..
            })
        ),
        "a non-octal value must decline as a value mismatch, got {outcome:?}"
    );
}
