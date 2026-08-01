//! The drop-in this tool writes when it cannot win by editing sshd_config.
//!
//! sshd uses the **first** value it obtains for a keyword and reads
//! `/etc/ssh/sshd_config.d/*.conf` in lexical order, so `00-hardener.conf`
//! outranks the fragments distributions ship (`50-redhat.conf` on Red Hat,
//! `40-suse-crypto-policies.conf` on openSUSE) and the main file's own body.
//! openSUSE's vendor sshd_config includes the `/etc` directory six lines above
//! its own, and its comments direct administrators here rather than to the file
//! itself.
//!
//! Note the direction is per format: `sysctl.d` takes the **last** value, which
//! is why the kernel plugin's `99-hardener.conf` is numbered the other way.
//! Nothing here may be reused for that without flipping the ordering.

use hardener_common::error::{HardeningError, Result};
use hardener_core::context::Context;
use std::path::Path;

/// The fragment this tool owns. Always the admin layer, never `/usr/etc`:
/// writing under the vendor directory would edit distribution-owned files, and
/// writing `/etc/ssh/sshd_config` would mask the vendor config wholesale.
pub(super) const DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/00-hardener.conf";

/// The directory the fragment lives in, created when the host lacks it.
const DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

/// Mode of the fragment. Matches what SUSE ships for its own drop-in, and is
/// set explicitly rather than inherited: a file being created has no original
/// permissions to restore, so it would otherwise wear whatever mode the
/// temporary file happened to have.
const DROPIN_MODE: &str = "0600";

const HEADER: &str = "\
# Managed by linux-system-hardener. Edits here are overwritten on the next
# apply, and this file is removed when it is no longer needed. sshd reads this
# directory before the main configuration, which is why the directives below
# live here rather than in sshd_config.
";

/// A directive bound for the fragment.
pub(super) struct Directive {
    pub keyword: &'static str,
    pub value: String,
    /// Explanation appended to the reported change, empty when there is none.
    /// Carries the remote-root downgrade note, which must reach the operator
    /// whichever file the directive ends up in.
    pub note: &'static str,
}

/// The fragment's content for a set of directives.
///
/// Sorted by keyword so the output is stable across runs and a diff means a
/// real change rather than a reordering.
pub(super) fn render(directives: &[Directive]) -> String {
    let mut sorted: Vec<&Directive> = directives.iter().collect();
    sorted.sort_by_key(|directive| directive.keyword);
    let mut rendered = String::from(HEADER);
    for directive in sorted {
        rendered.push_str(directive.keyword);
        rendered.push(' ');
        rendered.push_str(&directive.value);
        rendered.push('\n');
    }
    rendered
}

/// Writes the fragment, or removes it when no directive needs it.
///
/// Each apply rewrites it to exactly the directives that currently need it, so
/// an operator who removes the fragment that made it necessary gets the
/// now-pointless override cleaned up on the next run rather than left to shadow
/// sshd_config indefinitely.
pub(super) async fn write_dropin(ctx: &Context, directives: &[Directive]) -> Result<()> {
    if directives.is_empty() {
        return remove_dropin(ctx).await;
    }

    // `write_file` cannot create a missing parent, so the directory the
    // fragment goes in is ensured first. Every distribution seen so far ships
    // it, and the shared helper owns the rule that decides when to try: a probe
    // which cannot answer counts as may-be-missing, because `mkdir -p` on an
    // existing directory does nothing.
    //
    // No ordering against this apply's checkpoint is needed, unlike the kernel
    // and audit plugins. That checkpoint captures the main config and the
    // fragment itself, never the bare directory, so no row is ever written for
    // it and the creation is invisible to a rollback of this apply.
    if let Some(reason) = crate::ensure_directory(ctx, DROPIN_DIR).await {
        return Err(HardeningError::Plugin(reason));
    }

    ctx.executor()
        .write_file(Path::new(DROPIN_PATH), &render(directives))
        .await
        .map_err(|e| HardeningError::Plugin(format!("Failed to write {DROPIN_PATH}: {e}")))?;

    // Failing to set the mode is not fatal: the directives are in force either
    // way, and refusing the whole apply over a permission bit would leave the
    // host unhardened for a lesser problem.
    let chmod = ctx
        .executor()
        .execute_command("chmod", &[DROPIN_MODE, DROPIN_PATH])
        .await;
    match chmod {
        Ok(output) if output.success() => {}
        Ok(output) => tracing::warn!(
            "Could not set {} on {}: {}",
            DROPIN_MODE,
            DROPIN_PATH,
            output.stderr.trim()
        ),
        Err(e) => tracing::warn!("Could not set {} on {}: {}", DROPIN_MODE, DROPIN_PATH, e),
    }
    Ok(())
}

/// Removes the fragment when nothing needs it any more.
///
/// The directory is deliberately left alone: an empty one is harmless, and
/// removing one this tool may not have created is not.
async fn remove_dropin(ctx: &Context) -> Result<()> {
    match ctx.executor().path_exists(Path::new(DROPIN_PATH)).await {
        // Absence positively confirmed, so there is nothing to prune.
        Ok(false) => return Ok(()),
        Ok(true) => {}
        // Existence could not be determined. Attempting the removal anyway is
        // the fail-safe direction: `rm -f` on an absent path succeeds, so the
        // only cost is a command that does nothing.
        Err(e) => tracing::warn!("Could not check whether {} exists: {}", DROPIN_PATH, e),
    }

    let removed = ctx
        .executor()
        .execute_command("rm", &["-f", DROPIN_PATH])
        .await
        .map_err(|e| HardeningError::Plugin(format!("Failed to remove {DROPIN_PATH}: {e}")))?;
    if !removed.success() {
        return Err(HardeningError::Plugin(format!(
            "Failed to remove {DROPIN_PATH}: {}",
            removed.stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
