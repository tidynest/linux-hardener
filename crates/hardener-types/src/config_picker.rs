//! Types for the config file picker UI.

use serde::{Deserialize, Serialize};

/// Summary of a validated configuration file.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigSummary {
    /// Path to the config file that was validated.
    pub config_path: String,
    /// Whether the file parsed successfully.
    pub config_is_valid: bool,
    /// Parse error message (None if valid).
    pub config_error: Option<String>,
    /// Names of plugins that are enabled in this config.
    pub config_enabled_plugins: Vec<String>,
    /// Total directive count across all plugin sections.
    pub config_directive_count: u32,
    /// Total exception count across all plugin sections.
    pub config_exception_count: u32,
    /// Whether the commands that escalate would accept this path.
    ///
    /// The desktop validates a config path by two rules, not one. `run_scan`,
    /// `run_apply_dry_run` and the validation behind this summary take any
    /// `.toml` outside a deny-list. `run_apply` and `run_deep_scan` hand the
    /// file to root through `pkexec`, so they take it only from
    /// `/etc/linux-hardener/` or `~/.config/linux-hardener/`: a config the
    /// operator can rewrite between the preview and the apply is not one root
    /// should read.
    ///
    /// Both readings are right and the narrower one is not going to widen. What
    /// was missing is that a single picked path feeds both, so a file in, say,
    /// `~/Documents` used to validate, summarise, scan and preview its changes
    /// before apply refused it. `false` here is what lets the picker card say so
    /// while the file is still being chosen.
    ///
    /// Not a claim that an apply will succeed. It is one refusal out of the way,
    /// the one decided by the path alone.
    pub config_apply_accepts: bool,
}
