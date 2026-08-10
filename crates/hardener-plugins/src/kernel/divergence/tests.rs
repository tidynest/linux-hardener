#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`divergence`].

use super::*;
use hardener_common::executor::MockExecutor;
use std::sync::Arc;

/// The probe reads `/proc/sys` for the parameter and `/etc/sysctl.d` for what
/// still names it. A mock carrying neither is the "nothing to say" baseline.
fn ctx_with(mock: MockExecutor) -> Context {
    Context::with_executor(Arc::new(mock))
}

/// #138 exactly: the value the apply set is still in the running kernel and
/// no surviving file names it, so the reload had nothing to read.
#[tokio::test]
async fn a_runtime_value_no_file_names_is_reported() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must be reported");
    assert_eq!(row.divergence_state, DivergenceState::Diverged);
    assert!(
        row.divergence_detail
            .contains("no configuration file names it"),
        "the sentence must state the measured fact: {}",
        row.divergence_detail
    );
}

/// A surviving file naming the pre-apply value is the case
/// `verify-rollback.sh` seeds today, and it must produce no row at all.
#[tokio::test]
async fn a_value_a_surviving_file_names_is_not_reported() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/00-baseline.conf",
                "net.ipv4.conf.all.log_martians = 0\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    assert!(
        !rows
            .iter()
            .any(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians"),
        "the configuration and the running kernel agree, so there is nothing to say"
    );
}

/// A file naming a different value from the one running is a divergence in
/// its own right, and the sentence carries both numbers so the operator does
/// not have to go and look.
#[tokio::test]
async fn a_file_disagreeing_with_the_running_kernel_is_reported_with_both_values() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/00-baseline.conf",
                "net.ipv4.conf.all.log_martians = 0\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a disagreement must be reported");
    assert_eq!(row.divergence_state, DivergenceState::Diverged);
    assert!(row.divergence_detail.contains('0') && row.divergence_detail.contains('1'));
}

/// An unreadable `/proc/sys` says nothing about the host, and must not be
/// recorded as agreement. This is the container case: nspawn mounts
/// `/proc/sys` read-only and the host's own values show through.
#[tokio::test]
async fn an_unreadable_runtime_value_is_unverifiable_rather_than_silent() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_read_permission_denied("/proc/sys/net/ipv4/conf/all/log_martians"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("an unreadable probe must still produce a row");
    assert_eq!(row.divergence_state, DivergenceState::Unverifiable);
}

/// A glob-assigning file may or may not name a parameter. Reporting it as
/// "no file names this" would turn an unanswered question into a claim.
///
/// The row that matters is the parameter's own: a generic "something is
/// unresolved" row would pass even if the per-parameter loop went on to emit
/// a confident `Diverged` claim for the very parameter the glob might name,
/// which is exactly how #138's false claim slipped through review once.
#[tokio::test]
async fn a_glob_assigning_file_makes_the_answer_unverifiable() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/99-glob.conf",
                "net.ipv4.conf.*.log_martians = 1\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter a glob might name must carry its own row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "an unresolved glob might name this parameter, so a Diverged claim is unearned: {}",
        row.divergence_detail
    );
    assert!(
        !rows
            .iter()
            .any(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians"
                && r.divergence_state == DivergenceState::Diverged),
        "no Diverged row may exist for a parameter an unresolved source might name"
    );
}

/// Classification row five: nothing names the parameter, and the running
/// value is looser than the baseline. An operator who deliberately loosened
/// below the baseline has left little for a rollback to have undone, so this
/// case produces no row at all, even with an empty `/etc/sysctl.d`. A
/// regression that dropped the `!` from the strictness guard, or that pushed
/// a row regardless of strictness, would still pass every other test here.
#[tokio::test]
async fn nothing_names_it_and_runtime_is_looser_produces_no_row() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    assert!(
        !rows
            .iter()
            .any(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians"),
        "a value looser than the baseline that nothing names is not this rollback's doing"
    );
}

/// Fix round 2, finding 1: an unresolved source must produce a row of its
/// own, not only a row reached through the per-parameter loop. Here every
/// managed parameter's `/proc/sys` read fails (nothing is mocked under
/// `/proc/sys`), so none of them ever reaches the arm that used to be the
/// only place `source_unresolved` was consulted. Before the fix this left the
/// glob-assigning file with no row anywhere in the output.
#[tokio::test]
async fn an_unresolved_source_is_reported_even_when_no_parameter_reaches_the_unnamed_arm() {
    let ctx = ctx_with(MockExecutor::new().with_file(
        "/etc/sysctl.d/99-glob.conf",
        "net.ipv4.conf.*.log_martians = 1\n",
    ));

    let rows = sysctl_divergences(&ctx).await;

    assert!(
        rows.iter()
            .any(|r| r.divergence_state == DivergenceState::Unverifiable
                && r.divergence_detail.contains("/etc/sysctl.d/99-glob.conf")),
        "an unresolved source must produce its own row naming the file, regardless of how \
         every managed parameter happens to classify: {rows:?}"
    );
}

/// Fix round 2, finding 2: the row an unresolved source produces must name
/// the file. Round 1's collapse to a boolean left the per-parameter sentence
/// generic; the row the unresolved source itself produces is where the path
/// has to survive.
#[tokio::test]
async fn an_unresolved_sources_row_names_the_file() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/99-glob.conf",
                "net.ipv4.conf.*.log_martians = 1\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let unresolved_row = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel parameters")
        .expect("the unresolved source must carry a row of its own");
    assert_eq!(
        unresolved_row.divergence_state,
        DivergenceState::Unverifiable
    );
    assert!(
        unresolved_row
            .divergence_detail
            .contains("/etc/sysctl.d/99-glob.conf"),
        "the row must name the file an operator has to go and look at: {}",
        unresolved_row.divergence_detail
    );
}

/// Fix round 2, finding 3: the other flavour of unresolved source, a drop-in
/// this scan could list but not read, exercised by name rather than only
/// through the glob-file flavour above.
///
/// Finding 3 (final review): the sentence must be true of the caller that
/// asked. The scan's own wording for this same failure names
/// `SYSCTL_HARDENER_CONF` and says the file "sorts after" it, both of which
/// describe a file a rollback has typically just deleted; asserting only that
/// the path appears would have let that false scan sentence keep flowing
/// through this path unnoticed.
#[tokio::test]
async fn an_unreadable_dropin_file_is_an_unresolved_source() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file("/etc/sysctl.d/50-locked.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.d/50-locked.conf"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let unresolved_row = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel parameters")
        .expect("a drop-in this scan could not read must be reported as an unresolved source");
    assert_eq!(
        unresolved_row.divergence_state,
        DivergenceState::Unverifiable
    );
    assert!(
        unresolved_row
            .divergence_detail
            .contains("/etc/sysctl.d/50-locked.conf"),
        "the row must name the file that could not be read: {}",
        unresolved_row.divergence_detail
    );
    assert!(
        !unresolved_row.divergence_detail.contains("sorts after")
            && !unresolved_row.divergence_detail.contains("overriding"),
        "the sentence must be true of a rollback, which has no drop-in of its own left to be \
         sorted after or overridden by the time this runs: {}",
        unresolved_row.divergence_detail
    );
}

/// Finding 1: `net.ipv4.conf.*.rp_filter` is exactly the pattern systemd's own
/// `50-default.conf` ships on every systemd host. A boolean `source_unresolved`
/// downgraded every parameter reaching the unnamed arm, including one this
/// pattern plainly cannot name. This is the regression that shipped: on a real
/// host issue #138's own case reported "could not check" rather than
/// `Diverged`.
#[tokio::test]
async fn a_glob_pattern_that_cannot_match_the_key_does_not_block_diverged() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/usr/lib/sysctl.d/50-default.conf",
                "net.ipv4.conf.*.rp_filter = 2\n",
            )
            .with_file("/proc/sys/kernel/kptr_restrict", "2\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel.kptr_restrict")
        .expect("a parameter no glob pattern could name must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "net.ipv4.conf.* cannot name kernel.kptr_restrict, so attribution must not be blocked: {row:?}"
    );
}

/// The other half of the same host: the parameter the pattern genuinely could
/// name must stay `Unverifiable`, so the fix narrows the block rather than
/// removing it.
#[tokio::test]
async fn a_glob_pattern_that_could_match_the_key_stays_unverifiable() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/usr/lib/sysctl.d/50-default.conf",
                "net.ipv4.conf.*.rp_filter = 2\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.rp_filter")
        .expect("a parameter the glob pattern could name must still carry its own row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "net.ipv4.conf.*.rp_filter could name net.ipv4.conf.all.rp_filter, so a Diverged claim \
         is unearned: {row:?}"
    );
}

/// An unreadable drop-in (not a glob) still blocks every parameter, including
/// one no glob pattern in play could ever have named. The narrowing is only
/// for the glob case; a file nobody could open could still say anything.
#[tokio::test]
async fn an_unreadable_dropin_blocks_a_parameter_no_glob_could_name() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file("/etc/sysctl.d/50-locked.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.d/50-locked.conf")
            .with_file("/proc/sys/kernel/kptr_restrict", "2\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel.kptr_restrict")
        .expect("an unreadable source must still produce a row for a parameter no glob names");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "an unreadable file could name anything, so attribution stays blocked even for a \
         parameter no glob pattern could ever have named: {row:?}"
    );
}

/// #140 exactly. `/etc/sysctl.conf` names the parameter, so the sentence that
/// no configuration file names it is false, and so is the claim that the value
/// did not come from the restored configuration: the rollback's own
/// `sysctl --system` reads this file.
#[tokio::test]
async fn a_parameter_named_only_in_sysctl_conf_is_not_reported_as_named_by_nothing() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still be reported");
    assert!(
        !row.divergence_detail
            .contains("no configuration file names it"),
        "a file names it, so this clause is false: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail.contains("/etc/sysctl.conf"),
        "the sentence must name the file an operator has to go and look at: {}",
        row.divergence_detail
    );
}

/// The clause that survives. systemd-sysctl does not read the file, so the
/// value really is lost at the next boot and the row stays Diverged.
///
/// The state alone is not evidence: the pre-fix code produced `Diverged` for
/// this fixture too, through the false "no configuration file names it"
/// sentence. The assertion on the detail is what pins the clause that survived
/// to the row that is meant to carry it.
#[tokio::test]
async fn a_parameter_named_only_in_sysctl_conf_stays_diverged_because_the_reboot_drops_it() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "the next boot drops the value, which is a real divergence: {row:?}"
    );
    assert!(
        row.divergence_detail.contains("lost at the next reboot"),
        "the surviving clause is the reboot one, and the row has to be the thing that says it: {}",
        row.divergence_detail
    );
}

/// No applier this probe recognises. The file names the parameter and whether
/// the host applies that file at boot was not established, so neither claim
/// is earned.
#[tokio::test]
async fn an_unknown_boot_applier_downgrades_the_sysctl_conf_case_to_unverifiable() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", false)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "which applier runs at boot was not established, so neither claim is earned: {row:?}"
    );
    // The state alone is no evidence: it would still hold if the sentence were
    // replaced by any other unverifiable one, including one that claimed the
    // reboot drops the value after all.
    assert!(
        row.divergence_detail.contains("/etc/sysctl.conf")
            && row.divergence_detail.contains("was not established")
            && row
                .divergence_detail
                .contains("survives a reboot is unknown"),
        "the row has to name the file and say which question went unanswered: {}",
        row.divergence_detail
    );
}

/// A host with no `/etc/sysctl.conf` at all, which is four of the five
/// distributions measured. Nothing about the existing #138 case may move.
#[tokio::test]
async fn an_absent_sysctl_conf_leaves_the_original_sentence_untouched() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must be reported");
    assert_eq!(row.divergence_state, DivergenceState::Diverged);
    assert!(
        row.divergence_detail
            .contains("no configuration file names it"),
        "with no such file, the original measurement is still the true one: {}",
        row.divergence_detail
    );
}

/// An unreadable `/etc/sysctl.conf` could name anything, so it blocks
/// attribution the way an unreadable drop-in does, and it earns a row of its
/// own naming the file.
#[tokio::test]
async fn an_unreadable_sysctl_conf_blocks_attribution_and_earns_its_own_row() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.conf")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let parameter_row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        parameter_row.divergence_state,
        DivergenceState::Unverifiable,
        "a file nobody could open could name this parameter: {parameter_row:?}"
    );
    assert!(
        rows.iter()
            .any(|r| r.divergence_subject == "kernel parameters"
                && r.divergence_state == DivergenceState::Unverifiable
                && r.divergence_detail.contains("/etc/sysctl.conf")),
        "the file that could not be read must earn a row naming it: {rows:?}"
    );
}

/// A glob in `/etc/sysctl.conf` blocks only the keys it could name, matching
/// how a glob in a drop-in is already treated. Without this the narrowing that
/// landed in `7cc4f9a1` would be undone for this one file.
#[tokio::test]
async fn a_glob_in_sysctl_conf_blocks_only_the_keys_it_could_name() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.*.log_martians = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n")
            .with_file("/proc/sys/kernel/kptr_restrict", "2\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let blocked = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the key the pattern could name must carry a row");
    assert_eq!(blocked.divergence_state, DivergenceState::Unverifiable);

    let unblocked = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel.kptr_restrict")
        .expect("a key the pattern cannot name must still be reported");
    assert_eq!(
        unblocked.divergence_state,
        DivergenceState::Diverged,
        "net.ipv4.conf.* cannot name kernel.kptr_restrict: {unblocked:?}"
    );
}

/// Review finding 1: the blocked sentence may not claim more than the drop-in
/// directories were asked. Here a drop-in nobody could read blocks attribution
/// while `/etc/sysctl.conf` carries an explicit assignment for the very
/// parameter, so "no explicit assignment names it" is a false clause on a row
/// that is otherwise correct.
#[tokio::test]
async fn a_blocked_row_does_not_deny_the_explicit_assignment_sysctl_conf_carries() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file("/etc/sysctl.d/50-locked.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.d/50-locked.conf")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "a drop-in nobody could open could name this parameter: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("no explicit assignment names it"),
        "/etc/sysctl.conf carries an explicit assignment for this key, so the wider clause is \
         false: {}",
        row.divergence_detail
    );
    // Asserting only the absence of one wording lets any equally over-wide
    // rewording through. The assignment is in hand and is the most actionable
    // fact on the row, so the row has to carry it.
    assert!(
        row.divergence_detail.contains("/etc/sysctl.conf assigns")
            && row
                .divergence_detail
                .contains("net.ipv4.conf.all.log_martians 1"),
        "the explicit assignment that was read must appear, with its value: {}",
        row.divergence_detail
    );
}

/// Review finding 2: an unreadable `/etc/sysctl.conf` is the one open question
/// on this host, and its name is in hand, so the row must name it rather than
/// fall back to the wording reserved for several unresolved sources at once.
#[tokio::test]
async fn a_lone_unreadable_sysctl_conf_is_named_in_the_parameter_sentence() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.conf")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert!(
        row.divergence_detail.contains("/etc/sysctl.conf"),
        "exactly one source is open and its name is known, so the sentence must carry it: {}",
        row.divergence_detail
    );
    assert!(
        !row.divergence_detail
            .contains("could not resolve every configuration source"),
        "the generic wording is for several open sources, and here there is one: {}",
        row.divergence_detail
    );
}

/// Review finding 3: the precedence host this slice exists for. `man sysctl`
/// reads `/etc/sysctl.conf` last, so the rollback's own `sysctl --system` runs
/// the kernel to that file's value and the host IS running what its own files
/// describe. The divergence is the next boot, where the drop-in wins instead.
#[tokio::test]
async fn a_running_value_sysctl_conf_explains_is_not_called_a_host_ignoring_its_files() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a parameter the next boot will change must be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "the next boot switches the parameter, which is a real divergence: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("not running what its own files describe"),
        "/etc/sysctl.conf is read last, so the running value is exactly what this host's files \
         describe: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail.contains("/etc/sysctl.conf")
            && row.divergence_detail.contains("sysctl.d"),
        "an operator has two files to reconcile and the sentence must name both: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail.contains('0') && row.divergence_detail.contains('1'),
        "both the running value and the one the next boot brings must appear: {}",
        row.divergence_detail
    );
}

/// The same host with no applier this probe recognises. The reboot half of the
/// sentence is not established there, so the row degrades the way the
/// named-only-in-sysctl.conf case already does rather than claiming it.
#[tokio::test]
async fn the_precedence_case_is_unverifiable_when_no_boot_applier_is_recognised() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", false)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "which applier runs at boot was not established, so the reboot claim is unearned: {row:?}"
    );
    // Without these the sentence the test exists for could be replaced by any
    // other unverifiable one and the state assertion would not notice.
    assert!(
        !row.divergence_detail
            .contains("not running what its own files describe"),
        "/etc/sysctl.conf is read last, so the running value is what this host's files describe \
         whichever applier boots it: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail
            .contains("/etc/sysctl.conf assigns it and a reload reads that file last")
            && row.divergence_detail.contains("was not established")
            && row
                .divergence_detail
                .contains("whether the next boot switches"),
        "the row must keep the precedence half it measured and mark only the boot half unknown: {}",
        row.divergence_detail
    );
}

/// Review finding C1: the file read last decides the reload, so a disagreement
/// judged without it is judged on every file but the deciding one. An
/// unreadable `/etc/sysctl.conf` could name this parameter with the running
/// value, which is precisely the case the row would otherwise accuse the host
/// over.
#[tokio::test]
async fn an_unreadable_sysctl_conf_blocks_the_disagreement_row_too() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.conf")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "the file that decides the reload was never read, so no accusation is earned: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("not running what its own files describe"),
        "one of this host's files went unread, so this clause is not measured: {}",
        row.divergence_detail
    );
    // An absence assertion alone passes against any other unverifiable
    // sentence, including one claiming the file was read and named nothing.
    // These pin the wording this test exists for: what was measured, which
    // read failed, and which question that leaves open.
    assert!(
        row.divergence_detail
            .contains("/etc/sysctl.d/50-x.conf says 1")
            && row
                .divergence_detail
                .contains("/etc/sysctl.conf could not be read")
            && row
                .divergence_detail
                .contains("a reload reads it after every drop-in")
            && row
                .divergence_detail
                .contains("the running value is unknown"),
        "the row must carry the measurement, the read that failed, and the question it leaves \
         open: {}",
        row.divergence_detail
    );
}

/// Review finding C1, the glob half. A pattern in `/etc/sysctl.conf` that
/// could name the key leaves the deciding assignment unresolved for that key,
/// and the silent case already treats exactly this as unknown.
#[tokio::test]
async fn a_legacy_glob_blocks_the_disagreement_row_for_the_keys_it_could_name() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.*.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "a pattern in the file read last could be the whole explanation: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("not running what its own files describe"),
        "the pattern was never resolved, so this clause is not measured: {}",
        row.divergence_detail
    );
    // Same reason as the test above: the absence of one clause is not evidence
    // that the clause which replaced it says anything true, so the pattern, the
    // file it is in, and the key it could reach are all pinned here.
    assert!(
        row.divergence_detail
            .contains("/etc/sysctl.d/50-x.conf says 1")
            && row.divergence_detail.contains(
                "a glob pattern in /etc/sysctl.conf could name net.ipv4.conf.all.log_martians"
            )
            && row
                .divergence_detail
                .contains("the running value is unknown"),
        "the row must name the pattern's file, the key it could reach, and what that leaves \
         open: {}",
        row.divergence_detail
    );
}

/// Review finding C2: three values, one per place. The accusation stands, but
/// the value a reload restores is `/etc/sysctl.conf`'s, so a sentence naming
/// the drop-in's value as what the restored configuration says would send an
/// operator to edit a file whose value the reload then discards.
#[tokio::test]
async fn a_third_value_in_sysctl_conf_is_what_the_row_reports_as_deciding() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 2\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a host running a value no file names must be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "the running value matches neither file, so the accusation is earned: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("the restored configuration says 1"),
        "a reload reads /etc/sysctl.conf last, so 1 is not what the restored configuration \
         leaves running: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail.contains("a reload restores 2")
            && row.divergence_detail.contains("/etc/sysctl.conf assigns"),
        "the value that decides the reload, and the file it came from, are what an operator \
         needs: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail.contains("/etc/sysctl.d/50-x.conf"),
        "the drop-in is the other file to reconcile and its path is in hand: {}",
        row.divergence_detail
    );
}

/// Review finding C3: a glob in `/etc/sysctl.conf` that can name nothing this
/// plugin manages still leaves the file unresolved, and a file this scan could
/// not resolve must never be silent. Without its own row, `vm.*` here would
/// produce no mention of the file anywhere in the output.
#[tokio::test]
async fn a_legacy_glob_naming_nothing_managed_still_earns_the_file_a_row() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "vm.* = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    assert!(
        rows.iter()
            .any(|r| r.divergence_subject == "kernel parameters"
                && r.divergence_state == DivergenceState::Unverifiable
                && r.divergence_detail.contains("/etc/sysctl.conf")
                && r.divergence_detail.contains("glob")),
        "the file this scan did not resolve must be named somewhere: {rows:?}"
    );
    let parameter = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a key the pattern cannot name must still be reported");
    assert_eq!(
        parameter.divergence_state,
        DivergenceState::Diverged,
        "vm.* cannot name net.ipv4.conf.all.log_martians: {parameter:?}"
    );
}

/// Review finding B1: the value the precedence sentence predicts for the next
/// boot is the winner among the drop-ins this scan could READ, which is not the
/// winner among all of them. Here `/etc/sysctl.d/60-y.conf` is unreadable and
/// sorts after the drop-in that was read, so the next boot could just as well
/// switch the parameter to 2, and the file the sentence names as deciding could
/// be the wrong one. Neither claim is earned, so the row makes neither.
#[tokio::test]
async fn an_unread_dropin_blocks_the_precedence_rows_boot_prediction() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file(
                "/etc/sysctl.d/60-y.conf",
                "net.ipv4.conf.all.log_martians = 2\n",
            )
            .with_read_permission_denied("/etc/sysctl.d/60-y.conf")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "a drop-in nobody could read could outrank the one that was, so the boot value is not \
         measured: {row:?}"
    );
    assert!(
        !row.divergence_detail.contains("the next boot switches"),
        "the value the next boot brings was not measured, so the row may not name one: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail
            .contains("could not resolve every configuration source")
            && row
                .divergence_detail
                .contains("what the next boot leaves it at, are unknown"),
        "the row must say which question went unanswered: {}",
        row.divergence_detail
    );
}

/// Review finding B1, the drop-in glob half. A pattern in a drop-in this scan
/// chose not to resolve could assign the running value, or outrank the drop-in
/// that was resolved, so the same two claims go unearned. The silent case has
/// treated exactly this as unknown since `7cc4f9a1`.
#[tokio::test]
async fn a_dropin_glob_blocks_the_disagreement_row_for_the_keys_it_could_name() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file(
                "/etc/sysctl.d/60-glob.conf",
                "net.ipv4.conf.*.log_martians = 2\n",
            )
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "an unresolved pattern could be the whole explanation for the running value: {row:?}"
    );
    assert!(
        row.divergence_detail.contains(
            "a glob pattern in the surviving configuration could name \
                      net.ipv4.conf.all.log_martians"
        ),
        "the row must say which unresolved thing blocked it: {}",
        row.divergence_detail
    );
}

/// Review finding B2: the accusation is false under an unread drop-in for the
/// same reason it is false under an unread `/etc/sysctl.conf`. The unread file
/// may assign exactly the running value, in which case the host IS running what
/// its own files describe. There is no `/etc/sysctl.conf` on this host at all,
/// so nothing but the drop-in side can be what blocks the row.
#[tokio::test]
async fn an_unreadable_dropin_blocks_the_disagreement_row_too() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.d/60-y.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.d/60-y.conf")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "a drop-in nobody could read could name the running value: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("not running what its own files describe"),
        "an unread file could describe exactly what is running, so this clause is not \
         measured: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail
            .contains("could not resolve every configuration source"),
        "the row must say what left the question open: {}",
        row.divergence_detail
    );
}

/// The narrowing, for the legacy glob guard on the disagreement arm. A pattern
/// that cannot name the key must not block it, or the guard becomes a blanket
/// "any glob anywhere blocks everything" and `7cc4f9a1` is undone here. Without
/// this test, swapping `glob_could_match` for a non-empty check passes.
#[tokio::test]
async fn a_legacy_glob_that_cannot_name_the_key_leaves_the_disagreement_row_alone() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file("/etc/sysctl.d/50-x.conf", "kernel.kptr_restrict = 2\n")
            .with_file("/etc/sysctl.conf", "vm.* = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/kernel/kptr_restrict", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel.kptr_restrict")
        .expect("a key no pattern could name must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "vm.* cannot name kernel.kptr_restrict, so the disagreement stands: {row:?}"
    );
    assert!(
        row.divergence_detail
            .contains("not running what its own files describe"),
        "nothing blocks this row, so it must carry the finding it exists for: {}",
        row.divergence_detail
    );
}

/// Final review, finding 1. The silence arm named the file at ANY value and
/// then asserted the running value came from it. Here `/etc/sysctl.conf` is the
/// only file naming the parameter and says 0 while the kernel reads 1, so the
/// reload plainly did not put 1 there, and the row must say so rather than
/// crediting the file with a value it does not carry.
///
/// This is a routine state, not an exotic one: `reload_after_rollback`
/// tolerates a non-zero exit from its own `sysctl --system`, so any key that
/// reload failed to write reaches this arm holding whatever the apply left.
#[tokio::test]
async fn a_legacy_value_the_kernel_is_not_running_is_not_credited_with_the_running_value() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a host running a value its only naming file does not carry must be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "the running value came from no surviving file, which is a divergence now: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("The rollback's own `sysctl --system` reads that file, but"),
        "the file says 0 and the kernel reads 1, so the reload did not leave this value: {}",
        row.divergence_detail
    );
    assert!(
        !row.divergence_detail.contains("lost at the next reboot"),
        "a value the reload never applied is not a value a reboot takes away: {}",
        row.divergence_detail
    );
    // The absence of the false clause proves nothing about what replaced it, so
    // the measurement, both values and the conclusion are pinned here.
    assert!(
        row.divergence_detail
            .contains("net.ipv4.conf.all.log_martians reads 1 in the running kernel")
            && row
                .divergence_detail
                .contains("the only file naming it, /etc/sysctl.conf, says 0")
            && row.divergence_detail.contains("the reload did not take"),
        "the row must carry both values and say that the reload did not take: {}",
        row.divergence_detail
    );
}

/// The same host with no applier this probe recognises. The sentence above
/// makes no claim about a later boot, so nothing on it depends on `Reach` and
/// the row must not degrade: what the kernel reads now came from no surviving
/// file whichever applier boots it next.
#[tokio::test]
async fn the_reload_did_not_take_row_is_the_same_when_no_boot_applier_is_recognised() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", false)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "the measurement is present tense and needs no applier to be true: {row:?}"
    );
    assert!(
        row.divergence_detail.contains("the reload did not take")
            && !row.divergence_detail.contains("reboot")
            && !row.divergence_detail.contains("was not established"),
        "the sentence states what is running against what the file says, and claims nothing \
         about a boot: {}",
        row.divergence_detail
    );
}

/// Final review, finding 2. `/etc/sysctl.conf` can be a symlink into
/// `sysctl.d`, and there the boot applier DOES apply its content, under the
/// drop-in's name. This probe does not detect the link, so no row may assert
/// what the boot applier does with that file. What it may assert is measured
/// either way: no `sysctl --system` runs at boot, and among the files the boot
/// sequence applies, the deciding one is named.
#[tokio::test]
async fn the_precedence_row_makes_no_claim_about_the_boot_applier_reading_the_legacy_file() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/50-x.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 0\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must be reported");
    assert_eq!(row.divergence_state, DivergenceState::Diverged);
    assert!(
        !row.divergence_detail.contains("does not read"),
        "a symlinked /etc/sysctl.conf is applied at boot under the drop-in's name, so no row \
         may say the boot applier does not read it: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail
            .contains("No such reload runs at boot")
            && row.divergence_detail.contains(
                "/etc/sysctl.d/50-x.conf is what decides net.ipv4.conf.all.log_martians among \
                 the files the boot sequence does apply"
            )
            && row
                .divergence_detail
                .contains("the next boot switches net.ipv4.conf.all.log_martians to 1"),
        "the row must predict the boot from the file that decides among the ones applied there: \
         {}",
        row.divergence_detail
    );
}

/// Final review, finding 3. `effective_boot_values` chains
/// `/etc/ufw/sysctl.conf` last, so the file that decides is not always a
/// drop-in, and ufw applies it from a unit ordered AFTER systemd-sysctl while
/// `sysctl --system` never reads it. On this host the reload leaves 2, from
/// `/etc/sysctl.conf`, and the next boot leaves 0, from ufw's file, so an
/// unqualified "the value that decides is the one in /etc/sysctl.conf" is false.
#[tokio::test]
async fn the_deciding_value_claim_is_qualified_to_the_reload_where_ufw_decides_the_boot() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/ufw/ufw.conf", "ENABLED=yes\n")
            .with_file("/etc/default/ufw", "IPT_SYSCTL=/etc/ufw/sysctl.conf\n")
            .with_file("/etc/ufw/sysctl.conf", "net/ipv4/conf/all/log_martians=0\n")
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 2\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a running value no file names must be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "the running value matches neither file, so the accusation is earned: {row:?}"
    );
    assert!(
        !row.divergence_detail
            .contains("the value that decides is the one in /etc/sysctl.conf"),
        "ufw applies its file after systemd-sysctl and sysctl --system never reads it, so at \
         the next boot ufw's value decides and this clause is false: {}",
        row.divergence_detail
    );
    assert!(
        row.divergence_detail
            .contains("the value a reload leaves behind is the one in /etc/sysctl.conf")
            && row.divergence_detail.contains("/etc/ufw/sysctl.conf"),
        "the row must qualify the claim to the reload and name the file it is measured against: \
         {}",
        row.divergence_detail
    );
}

/// Final review, finding 5. The glob branch dropped an explicit
/// `/etc/sysctl.conf` assignment that had been read, which is both the most
/// actionable fact on the row and the one `sysctl` would prefer over the
/// pattern that blocked it. The blocked-source branch beside it has carried the
/// clause since the first review round; this is the missing half.
#[tokio::test]
async fn a_glob_blocked_row_still_carries_the_assignment_sysctl_conf_was_read_to_have() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/60-glob.conf",
                "net.ipv4.conf.*.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.conf", "net.ipv4.conf.all.log_martians = 1\n")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a key the pattern could name must carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "an unresolved pattern could name this key, so no confident claim is earned: {row:?}"
    );
    assert!(
        row.divergence_detail
            .contains("/etc/sysctl.conf assigns net.ipv4.conf.all.log_martians 1")
            && row
                .divergence_detail
                .contains("a reload reads that file after every drop-in"),
        "the assignment that was read is the row's most actionable fact and must appear: {}",
        row.divergence_detail
    );
}

/// The same narrowing for the drop-in glob guard added alongside it. `vm.*` in
/// `/etc/sysctl.conf` is the legacy file's half above; this is the drop-in's.
#[tokio::test]
async fn a_dropin_glob_that_cannot_name_the_key_leaves_the_disagreement_row_alone() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file("/etc/sysctl.d/50-x.conf", "kernel.kptr_restrict = 2\n")
            .with_file(
                "/etc/sysctl.d/60-glob.conf",
                "net.ipv4.conf.*.rp_filter = 2\n",
            )
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/kernel/kptr_restrict", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "kernel.kptr_restrict")
        .expect("a key no pattern could name must still be reported");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "net.ipv4.conf.* cannot name kernel.kptr_restrict, so the disagreement stands: {row:?}"
    );
    assert!(
        row.divergence_detail
            .contains("not running what its own files describe"),
        "nothing blocks this row, so it must carry the finding it exists for: {}",
        row.divergence_detail
    );
}

/// #145, the narrowing itself. An unreadable drop-in whose name sorts BEFORE
/// the file that decided the key cannot have decided it: both appliers let the
/// lexicographically last filename win, measured from `sysctl.d(5)` and
/// `sysctl(8)` on 2026-08-09. The row it earns of its own is unaffected; what
/// it no longer does is take this parameter's verdict down with it.
#[tokio::test]
async fn an_unreadable_dropin_sorting_before_the_deciding_file_does_not_block_it() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/etc/sysctl.d/10-locked.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.d/10-locked.conf")
            .with_file(
                "/etc/sysctl.d/60-decides.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Diverged,
        "10-locked.conf sorts before 60-decides.conf, so it cannot be what assigned the running \
         value and must not downgrade this verdict: {row:?}"
    );
    // The unread file is still reported, which is what makes the narrowing a
    // narrowing rather than a silencing.
    assert!(
        rows.iter()
            .any(|r| r.divergence_detail.contains("10-locked.conf")),
        "the unread file must still earn a row of its own naming it: {rows:?}"
    );
}

/// The other side of the same rule, and the one that must not be lost: an
/// unreadable drop-in sorting AFTER the deciding file could have overridden it,
/// so the verdict stays blocked.
#[tokio::test]
async fn an_unreadable_dropin_sorting_after_the_deciding_file_still_blocks_it() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file(
                "/etc/sysctl.d/60-decides.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/etc/sysctl.d/70-locked.conf", "irrelevant\n")
            .with_read_permission_denied("/etc/sysctl.d/70-locked.conf")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "70-locked.conf sorts after 60-decides.conf and could have assigned the running value, \
         so accusing the host would be a claim on the strength of every file but that one: \
         {row:?}"
    );
}

/// A directory nobody could list is not narrowable by any name, because the
/// names it holds are exactly what was not read. It blocks whatever the
/// deciding file is called.
#[tokio::test]
async fn a_directory_that_could_not_be_listed_still_blocks_a_decided_parameter() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/60-decides.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_read_dir_permission_denied("/run/sysctl.d")
            .with_path_exists("/usr/lib/systemd/systemd-sysctl", true)
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must carry a row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "an unlisted directory hides the very names a comparison would need: {row:?}"
    );
}

/// #138 exactly: the running kernel holds a value the apply set, the rollback
/// removed the file that named it, and `sysctl --system` does not reset a
/// parameter no surviving file names. The value stays until the next reboot.
/// This is the designed consequence and appears on every rollback that removed
/// a drop-in.
#[tokio::test]
async fn a_runtime_value_no_file_names_is_expected() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let named = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("one diverged row");
    assert_eq!(named.divergence_state, DivergenceState::Diverged);
    let reason = named
        .divergence_expected
        .as_ref()
        .expect("a rollback does not write /proc/sys");
    assert!(
        reason.contains("/proc/sys"),
        "the reason has to name the mechanism: {reason}"
    );
}

/// A file names the parameter and the running kernel still disagrees with it.
/// `sysctl --system` ran over that file during the rollback and should have
/// applied it, so this is not designed and must stay unexpected.
#[tokio::test]
async fn a_runtime_value_contradicting_a_naming_file_is_not_expected() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/00-baseline.conf",
                "net.ipv4.conf.all.log_martians = 1\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let named = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("one diverged row");
    assert_eq!(named.divergence_state, DivergenceState::Diverged);
    assert!(
        named.divergence_expected.is_none(),
        "a reload that should have applied the file and did not is never routine: {:?}",
        named.divergence_expected
    );
}
