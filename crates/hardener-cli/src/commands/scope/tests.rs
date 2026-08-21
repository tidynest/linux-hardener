//! Tests for `hardener scope`.
//!
//! Every case injects an audit-log path through `run_exclude_to` and
//! `run_include_to`, so no test writes to `/var/log` or to the operator's own
//! data directory, and every case writes its configuration into a temporary
//! directory of its own.

use super::{run_exclude_to, run_include_to};
use hardener_state::audit::{ActionResult, ActionType, AuditLogger, QueryFilter};
use std::path::PathBuf;

/// A scratch configuration file and audit log for one test.
struct Scratch {
    _dir: tempfile::TempDir,
    config: PathBuf,
    log: PathBuf,
}

impl Scratch {
    fn seeded(config_text: &str) -> Scratch {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        let log = dir.path().join("audit.log");
        std::fs::write(&config, config_text).expect("seed config");
        Scratch {
            _dir: dir,
            config,
            log,
        }
    }

    fn log_path(&self) -> &str {
        self.log.to_str().expect("utf-8 path")
    }

    fn written(&self) -> String {
        std::fs::read_to_string(&self.config).expect("read back")
    }

    async fn entries(&self) -> Vec<hardener_state::AuditEntry> {
        AuditLogger::query(self.log_path(), QueryFilter::new())
            .await
            .expect("query")
    }
}

#[tokio::test]
async fn exclude_writes_the_table_and_preserves_the_rest_of_the_file() {
    let scratch =
        Scratch::seeded("# operator's own note\n[global]\ndisabled_plugins = [\"mac\"]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "No physical premises",
        Some("eric"),
        Some("SEC-412"),
        Some("2027-08-18"),
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("exclude succeeds");

    let written = scratch.written();
    assert!(
        written.contains("# operator's own note"),
        "comments survive"
    );
    assert!(
        written.contains("disabled_plugins"),
        "unrelated sections survive"
    );
    assert!(written.contains(r#"[compliance.not_applicable.iso27001."7.1"]"#));
    assert!(written.contains("SEC-412"));
}

#[tokio::test]
async fn an_empty_reason_is_refused() {
    let scratch = Scratch::seeded("[global]\n");

    let result = run_exclude_to(
        "iso27001",
        "7.1",
        "   ",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    assert!(
        result.is_err(),
        "an unexplained exclusion raises a score for no stated cause"
    );
    assert!(
        !scratch.written().contains("not_applicable"),
        "nothing was written"
    );
}

#[tokio::test]
async fn an_unknown_framework_is_refused() {
    let scratch = Scratch::seeded("[global]\n");

    let result = run_exclude_to(
        "not-a-framework",
        "7.1",
        "reason",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    assert!(result.is_err());
    assert!(
        !scratch.written().contains("not_applicable"),
        "nothing was written"
    );
}

/// A control id belonging to no catalogue is a typo, and a typo written to the
/// file is worse than a refusal: the exclusion is inert, the report never
/// moves, and the audit log carries a declaration that a control was excluded
/// when none was. `A.7.1` is the ISO 27001:2022 Annex A notation; this
/// catalogue uses the bare clause numbers, so the real id is `7.1`.
#[tokio::test]
async fn an_unknown_control_id_is_refused_under_a_curated_framework() {
    let scratch = Scratch::seeded("[global]\n");

    let result = run_exclude_to(
        "iso27001",
        "A.7.1",
        "No physical premises",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    assert!(
        result.is_err(),
        "'A.7.1' is in no ISO/IEC 27001 catalogue, so excluding it could only \
         ever be a silent no-op"
    );
    assert!(
        !scratch.written().contains("not_applicable"),
        "and nothing was written"
    );

    let message = format!("{:#}", result.expect_err("refused"));
    assert!(
        message.contains("A.7.1"),
        "the refusal names the id given: {message}"
    );
    assert!(
        message.contains("ISO"),
        "and the framework it was refused for, because the notation differs \
         between catalogues: {message}"
    );
    assert!(
        message.contains("report --framework iso27001"),
        "and says how to list the real ids, which is the question a refusal \
         otherwise leaves the operator with: {message}"
    );
}

/// The control that proves the case above is not vacuous. The same call with
/// the catalogue's own spelling of that very control has to succeed and write,
/// or the refusal above would pass equally well against a verb that refused
/// every id.
#[tokio::test]
async fn the_catalogues_own_spelling_of_that_control_still_succeeds() {
    let scratch = Scratch::seeded("[global]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "No physical premises",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("'7.1' is a real ISO/IEC 27001:2022 Annex A clause number");

    assert!(
        scratch
            .written()
            .contains(r#"[compliance.not_applicable.iso27001."7.1"]"#),
        "the real id is written"
    );
}

/// An attempt to exclude a control that does not exist is exactly the attempt
/// an auditor wants on the record, and it goes through `log_failure` like every
/// other refusal, so its cause sits in the one detail the verifier hashes.
#[tokio::test]
async fn a_refused_unknown_control_is_logged_as_a_failure() {
    let scratch = Scratch::seeded("[global]\n");

    let _ = run_exclude_to(
        "cis",
        "1.1.1",
        "Not applicable to this host",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_result, ActionResult::Failure);
    assert_eq!(entries[0].entry_action_type, ActionType::ScopeExclusion);
    assert_eq!(
        entries[0].entry_target, "cis:1.1.1",
        "the target names the framework and the id that was refused"
    );
    let error = entries[0]
        .entry_details
        .get("error")
        .expect("the cause is in the one hashed detail");
    assert!(
        error.contains("1.1.1"),
        "the logged cause names the id: {error}"
    );
    assert_eq!(
        entries[0].entry_details.len(),
        1,
        "no second detail, because only 'error' is hashed on a failure entry"
    );

    assert!(
        AuditLogger::verify_integrity(scratch.log_path())
            .await
            .expect("verify"),
        "and the chain still verifies with the refusal in it"
    );
}

/// Eight of the ten frameworks have no curated catalogue: theirs is derived at
/// report time from the live plugin coverage set, so every control it lists is
/// one the engine assesses and the generator settles as `Pass` or `Fail` before
/// it ever reaches the exclusion arm. An exclusion for such a framework is
/// therefore inert. It is still written and still audited, because a framework
/// may gain a curated catalogue later and the entry is harmless meanwhile, but
/// the operator is told it changes no report today rather than left believing a
/// score moved.
#[tokio::test]
async fn a_derived_framework_is_warned_about_yet_still_written_and_audited() {
    let scratch = Scratch::seeded("[global]\n");

    let advisory = run_exclude_to(
        "soc2",
        "CC6.1",
        "Handled by the hosting provider",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("a derived framework is warned about, not refused");

    let advisory = advisory.expect("an inert exclusion is flagged to the operator");
    assert!(
        advisory.contains("CC6.1"),
        "the advisory names the control it concerns: {advisory}"
    );
    assert!(
        advisory.contains("SOC 2"),
        "and the framework it cannot take effect for: {advisory}"
    );

    assert!(
        scratch
            .written()
            .contains(r#"[compliance.not_applicable.soc2."CC6.1"]"#),
        "the declaration is written all the same"
    );
    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1, "and audited all the same");
    assert_eq!(entries[0].entry_result, ActionResult::Success);
    assert_eq!(entries[0].entry_target, "soc2:CC6.1");
    assert_eq!(
        entries[0]
            .entry_details
            .get("takes_effect")
            .map(String::as_str),
        Some("false"),
        "and the entry says so, because the advisory goes to stderr and an \
         auditor reading the log months later has no stderr to read"
    );
    assert!(
        AuditLogger::verify_integrity(scratch.log_path())
            .await
            .expect("verify"),
        "the flag is inside the hash chain, as every detail on a success entry \
         is, so it cannot be edited out without detection"
    );
}

/// The other direction, without which the case above would pass just as well
/// against a verb that warned on every framework, or that stamped every entry
/// `takes_effect = false` whatever the catalogue. CIS and ISO/IEC 27001 carry
/// hand-curated catalogues, so their catalogues list controls the engine does
/// not assess and an exclusion of one does reach the generator's exclusion arm.
#[tokio::test]
async fn a_curated_framework_is_not_warned_about() {
    for (framework, control) in [("cis", "1.5.1"), ("iso27001", "7.1")] {
        let scratch = Scratch::seeded("[global]\n");

        let advisory = run_exclude_to(
            framework,
            control,
            "Not applicable to this host",
            None,
            None,
            None,
            &[],
            Some(&scratch.config),
            scratch.log_path(),
        )
        .await
        .expect("exclude succeeds");

        assert!(
            advisory.is_none(),
            "{framework} has a curated catalogue, so the exclusion takes effect \
             and there is nothing to warn about: {advisory:?}"
        );

        let entries = scratch.entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_result, ActionResult::Success);
        assert_eq!(
            entries[0].entry_details.get("takes_effect"),
            None,
            "and nothing on the entry says it cannot take effect, for {framework}: \
             {:?}",
            entries[0].entry_details
        );
    }
}

#[tokio::test]
async fn include_removes_only_the_named_control() {
    let scratch = Scratch::seeded("[global]\n");

    for control in ["7.1", "7.2"] {
        run_exclude_to(
            "iso27001",
            control,
            "reason",
            None,
            None,
            None,
            &[],
            Some(&scratch.config),
            scratch.log_path(),
        )
        .await
        .expect("exclude");
    }

    run_include_to("iso27001", "7.1", Some(&scratch.config), scratch.log_path())
        .await
        .expect("include");

    let written = scratch.written();
    assert!(!written.contains(r#""7.1""#), "the named control is gone");
    assert!(written.contains(r#""7.2""#), "its neighbour is untouched");
}

/// A log of successes only cannot show an operator trying to exclude something
/// they should not have.
#[tokio::test]
async fn a_refused_exclusion_is_still_logged() {
    let scratch = Scratch::seeded("[global]\n");

    let _ = run_exclude_to(
        "not-a-framework",
        "7.1",
        "reason",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_result, ActionResult::Failure);
    assert_eq!(entries[0].entry_action_type, ActionType::ScopeExclusion);
    assert_eq!(entries[0].entry_target, "not-a-framework:7.1");
}

/// The refusal is written through `log_failure`, whose single `error` detail is
/// the only detail `verify_integrity` hashes on a failure entry: anything else
/// recorded there would sit outside the chain and could be edited without
/// detection. So the reason for the refusal has to be inside that message, and
/// the chain has to still verify with the refusal in it.
#[tokio::test]
async fn a_refusal_carries_its_reason_inside_the_hash_chain() {
    let scratch = Scratch::seeded("[global]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "sound reason",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("exclude succeeds");
    let _ = run_exclude_to(
        "iso27001",
        "7.2",
        "  ",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    let entries = scratch.entries().await;
    assert_eq!(
        entries.len(),
        2,
        "the success and the refusal are both there"
    );

    let refusal = &entries[1];
    assert_eq!(refusal.entry_result, ActionResult::Failure);
    let error = refusal
        .entry_details
        .get("error")
        .expect("the refusal states its cause in the one hashed detail");
    assert!(
        error.contains("reason"),
        "the message says what was wrong, not merely that something was: {error}"
    );
    assert_eq!(
        refusal.entry_details.len(),
        1,
        "no second detail, because only 'error' is hashed on a failure entry"
    );

    assert!(
        AuditLogger::verify_integrity(scratch.log_path())
            .await
            .expect("verify"),
        "a log holding a success with details and a refusal still verifies"
    );
}

/// The details an auditor reads back off a granted exclusion. They are inside
/// the hash on a success entry, which is why the success path uses
/// `log_action_with_details` and the refusal path cannot.
#[tokio::test]
async fn a_granted_exclusion_records_who_approved_it_and_why() {
    let scratch = Scratch::seeded("[global]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "No physical premises",
        Some("eric"),
        Some("SEC-412"),
        Some("2027-08-18"),
        &["web-01".to_string(), "web-02".to_string()],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("exclude succeeds");

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.entry_result, ActionResult::Success);
    assert_eq!(entry.entry_action_type, ActionType::ScopeExclusion);
    assert_eq!(entry.entry_target, "iso27001:7.1");

    let detail = |key: &str| entry.entry_details.get(key).map(String::as_str);
    assert_eq!(detail("operation"), Some("exclude"));
    assert_eq!(detail("reason"), Some("No physical premises"));
    assert_eq!(detail("approved_by"), Some("eric"));
    assert_eq!(detail("ticket"), Some("SEC-412"));
    assert_eq!(detail("review_by"), Some("2027-08-18"));
    assert_eq!(detail("hosts"), Some("web-01,web-02"));

    assert!(
        AuditLogger::verify_integrity(scratch.log_path())
            .await
            .expect("verify"),
        "the details are inside the chain"
    );
}

/// A `--review-by` the report path cannot parse is refused before anything is
/// written.
///
/// `ScopeExclusion::review_deadline` fails closed on an unparseable
/// `review_by`: it returns `None`, `is_valid_on` is false on every day, and the
/// control stays `ManualReview`. Written unvalidated, the operator would get a
/// success message, a table in their configuration and an audit entry recording
/// a granted declaration, for a report that never moves. That is the same shape
/// as the unknown-control defect, so it earns the same refusal.
#[tokio::test]
async fn an_unparseable_review_by_is_refused() {
    for spelling in [
        "next August",
        "2027/08/18",
        "18-08-2027",
        "2027-13-01",
        "2027-08-18T00:00:00Z",
        "",
    ] {
        let scratch = Scratch::seeded("[global]\n");

        let result = run_exclude_to(
            "iso27001",
            "7.1",
            "No physical premises",
            None,
            None,
            Some(spelling),
            &[],
            Some(&scratch.config),
            scratch.log_path(),
        )
        .await;

        let Err(error) = result else {
            panic!("'{spelling}' is no date the report can read, so it must be refused");
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("YYYY-MM-DD"),
            "the refusal states the spelling wanted: {message}"
        );
        assert!(
            !scratch.written().contains("not_applicable"),
            "and nothing was written for '{spelling}'"
        );

        let entries = scratch.entries().await;
        assert_eq!(entries.len(), 1, "the attempt is on the record");
        assert_eq!(entries[0].entry_result, ActionResult::Failure);
        assert_eq!(entries[0].entry_target, "iso27001:7.1");
        assert!(
            AuditLogger::verify_integrity(scratch.log_path())
                .await
                .expect("verify"),
            "and the chain still verifies with the refusal in it"
        );
    }
}

/// The control that keeps the case above from passing against a verb that
/// refused every `--review-by`. An ISO 8601 date is written through and lands in
/// the file under its own key.
#[tokio::test]
async fn an_iso_8601_review_by_is_written_through() {
    let scratch = Scratch::seeded("[global]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "No physical premises",
        None,
        None,
        Some("2027-08-18"),
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("a parseable date is not a refusal");

    assert!(
        scratch.written().contains(r#"review_by = "2027-08-18""#),
        "the date reaches the file: {}",
        scratch.written()
    );
}

/// A refusal is filed under the canonical framework id, not the spelling the
/// operator typed.
///
/// `from_id` accepts `ISO-27001` and `iso27001` alike. An auditor filtering
/// their log for `iso27001:7.1` would otherwise see the granted exclusions and
/// miss a refusal filed as `ISO-27001:7.1`, which is precisely the entry they
/// were looking for.
#[tokio::test]
async fn a_refusal_is_filed_under_the_canonical_framework_id() {
    let scratch = Scratch::seeded("[global]\n");

    let _ = run_exclude_to(
        "ISO-27001",
        "7.1",
        "   ",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].entry_target, "iso27001:7.1",
        "the canonical id, not the operator's spelling of it"
    );
}

/// A write that fails is an attempt that left no trace of itself, which is the
/// one outcome this module argues at length must be on the record.
///
/// The realistic cause is an unprivileged operator against
/// `/etc/linux-hardener/config.toml`. Here the temporary file the atomic write
/// needs is a directory instead, which fails the same way for every user and so
/// does not turn on whether the suite happens to run as root.
#[tokio::test]
async fn a_failed_write_is_audited() {
    let scratch = Scratch::seeded("[global]\n");
    std::fs::create_dir(scratch.config.with_extension("toml.new")).expect("block the write");

    let result = run_exclude_to(
        "iso27001",
        "7.1",
        "No physical premises",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await;

    assert!(result.is_err(), "the write failed, so the command failed");
    assert!(
        !scratch.written().contains("not_applicable"),
        "and the configuration is as it was"
    );

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1, "the failed attempt is on the record");
    assert_eq!(entries[0].entry_result, ActionResult::Failure);
    assert_eq!(entries[0].entry_target, "iso27001:7.1");
    assert!(
        AuditLogger::verify_integrity(scratch.log_path())
            .await
            .expect("verify"),
        "and the chain still verifies with it in"
    );
}

/// A withdrawal that fails to write is as much an untraced attempt as a grant
/// that does, and is refused and logged the same way.
#[tokio::test]
async fn a_failed_withdrawal_write_is_audited() {
    let scratch = Scratch::seeded("[global]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "No physical premises",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("exclude");
    std::fs::create_dir(scratch.config.with_extension("toml.new")).expect("block the write");

    let result = run_include_to("iso27001", "7.1", Some(&scratch.config), scratch.log_path()).await;

    assert!(result.is_err(), "the write failed, so the command failed");
    assert!(
        scratch.written().contains("not_applicable"),
        "and the exclusion is still there"
    );

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 2, "the grant, then the failed withdrawal");
    assert_eq!(entries[1].entry_result, ActionResult::Failure);
    assert_eq!(entries[1].entry_target, "iso27001:7.1");
}

/// Withdrawing an exclusion lowers the score again, so it is as much an
/// auditable act as granting one.
#[tokio::test]
async fn withdrawing_an_exclusion_is_logged_too() {
    let scratch = Scratch::seeded("[global]\n");

    run_exclude_to(
        "iso27001",
        "7.1",
        "reason",
        None,
        None,
        None,
        &[],
        Some(&scratch.config),
        scratch.log_path(),
    )
    .await
    .expect("exclude");
    run_include_to("iso27001", "7.1", Some(&scratch.config), scratch.log_path())
        .await
        .expect("include");

    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].entry_result, ActionResult::Success);
    assert_eq!(entries[1].entry_target, "iso27001:7.1");
    assert_eq!(
        entries[1]
            .entry_details
            .get("operation")
            .map(String::as_str),
        Some("include")
    );
    assert_eq!(
        entries[0]
            .entry_details
            .get("operation")
            .map(String::as_str),
        Some("exclude"),
        "the withdrawal is a second entry, not the deletion of the first"
    );
    assert!(
        AuditLogger::verify_integrity(scratch.log_path())
            .await
            .expect("verify"),
        "and the chain still verifies across both, which is what would catch a \
         new writer breaking it"
    );
}

/// Removing an exclusion that was never written is an error rather than a
/// quiet success, for the reason `remove_exception` gives: a typo against a
/// hand-edited file would otherwise read as done.
#[tokio::test]
async fn withdrawing_an_exclusion_that_is_not_there_is_refused() {
    let scratch = Scratch::seeded("[global]\n");

    let result = run_include_to("iso27001", "7.1", Some(&scratch.config), scratch.log_path()).await;

    assert!(result.is_err(), "there was nothing to withdraw");
    let entries = scratch.entries().await;
    assert_eq!(entries.len(), 1, "and the attempt is on the record");
    assert_eq!(entries[0].entry_result, ActionResult::Failure);
}
