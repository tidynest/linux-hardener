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
