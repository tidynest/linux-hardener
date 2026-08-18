//! CLI subcommand implementations.

pub mod apply;
pub mod batch;
pub mod checkpoint;
pub mod daemon;
pub mod exception;
pub mod history;
pub(crate) mod plugin_filter;
pub mod plugins;
pub(crate) mod privilege;
pub mod report;
pub mod report_wizard;
pub mod scan;
pub mod scope;
pub mod state;
pub mod systemd;

/// Builds the configuration loader for a command, honouring a `--config` path
/// when the operator gave one.
///
/// One definition, because every command that reads policy has to agree on what
/// `--config` means: the flag is global, so any of them can be handed a path.
/// What each does with a load *failure* stays its own, since a command that
/// only reads a host may reasonably fall back to defaults where one that writes
/// to it may not.
pub(crate) fn config_loader(
    config_path: Option<&std::path::PathBuf>,
) -> hardener_core::ConfigLoader {
    match config_path {
        Some(path) => hardener_core::ConfigLoader::new().with_cli_config(path.clone()),
        None => hardener_core::ConfigLoader::new(),
    }
}
