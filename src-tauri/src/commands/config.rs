//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// The config file's own eight plugin sections, each under the plugin id that
/// owns it.
///
/// These are fields of `HardenerConfig` rather than a second copy of the
/// registry, so naming them here is the only way to walk them. The ids must
/// still match `get_plugin_config`'s arms, which is what
/// `every_section_id_resolves_to_its_own_section` pins: an id that drifts
/// falls through to that function's empty default, which reports enabled
/// whatever the file says.
pub(crate) fn plugin_sections(config: &HardenerConfig) -> [(&'static str, &PluginConfig); 8] {
    [
        ("kernel-hardening", &config.kernel),
        ("ssh-hardening", &config.ssh),
        ("firewall-hardening", &config.firewall),
        ("pam-hardening", &config.pam),
        ("service-minimisation", &config.services),
        ("audit-hardening", &config.audit),
        ("permissions-hardening", &config.permissions),
        ("mac-hardening", &config.mac),
    ]
}

/// Describes a loaded config the way the picker card reports it.
///
/// Split from the command so the decision can be driven: the command itself
/// only resolves a path and reads a file.
///
/// **The enabled set is the one that will actually run.** It used to be each
/// section's own `enabled` flag, which is one of the three things the real
/// gate reads: `is_plugin_enabled` also honours `global.disabled_plugins` and
/// the `global.enabled_plugins` allow list. So a config narrowing the set
/// globally still reported all eight, and the card an operator reads to
/// confirm they picked the right file said "8 plugins" for a file that runs
/// one. It could only ever over-report, never claim a plugin was off while it
/// ran, because a section disabled by its own flag fails the wider gate too.
///
/// `apply_accepts` is passed in rather than asked here, for the reason
/// `write_scheduler_config` takes its logger as an argument. The question is
/// answered by `validate_privileged_config_path`, which canonicalises and reads
/// `dirs::config_dir()`, so asking it inside this function would tie every test
/// of the summary to the filesystem and to `$HOME`. **A ceiling worth naming:
/// the refusing direction is drivable and the accepting one is not.** Any path
/// a test can create lies outside both allowed directories, so proving the
/// `true` arm end to end would mean moving `HOME` while the rest of this
/// binary's tests run in threads beside it. The join is one line in
/// `validate_config`.
pub(crate) fn summarise_config(
    path: String,
    config: &HardenerConfig,
    apply_accepts: bool,
) -> ConfigSummary {
    let sections = plugin_sections(config);

    ConfigSummary {
        config_path: path,
        config_is_valid: true,
        config_error: None,
        config_apply_accepts: apply_accepts,
        config_enabled_plugins: sections
            .iter()
            .filter(|(id, _)| config.is_plugin_enabled(id))
            .map(|(id, _)| (*id).to_string())
            .collect(),
        // Counts describe what the file declares, enabled or not: this is the
        // "3 directives" on the card, not a prediction of what will apply.
        config_directive_count: sections
            .iter()
            .map(|(_, section)| section.directives.len() as u32)
            .sum(),
        config_exception_count: sections
            .iter()
            .map(|(_, section)| section.exceptions.len() as u32)
            .sum(),
    }
}

/// Validates a config file and returns a summary of its contents.
///
/// Parses the TOML file using `ConfigLoader` and counts plugins, directives
/// and exceptions. Returns error details if invalid. The summary itself is
/// built by [`summarise_config`], which is where the decisions live.
///
/// Validates by the user rule and reports the privileged one. The card an
/// operator reads before pressing anything is the only place both answers are
/// available at once, and asking the escalating commands' own validator is what
/// stops this becoming a third statement of where a config may live.
#[tauri::command]
pub async fn validate_config(path: String) -> Result<ConfigSummary, String> {
    validate_user_config_path(&path)?;
    let apply_accepts = validate_privileged_config_path(&path).is_ok();

    use hardener_core::ConfigLoader;

    let file_path = std::path::PathBuf::from(&path);

    // Carried into both failure arms as well, so the field never says "apply
    // would refuse this path" on the strength of a `Default` when the reason
    // the summary failed is the file's contents. A broken config inside
    // `~/.config/linux-hardener/` is one the escalating commands accept by path
    // and reject by parse, and those are different sentences.
    if !file_path.exists() {
        return Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some("File not found".to_string()),
            config_apply_accepts: apply_accepts,
            ..Default::default()
        });
    }

    let loader = ConfigLoader::new()
        .skip_defaults()
        .with_cli_config(file_path);

    match loader.load() {
        Ok(config) => Ok(summarise_config(path, &config, apply_accepts)),
        Err(e) => Ok(ConfigSummary {
            config_path: path,
            config_is_valid: false,
            config_error: Some(e.to_string()),
            config_apply_accepts: apply_accepts,
            ..Default::default()
        }),
    }
}

/// Opens a native file dialog for selecting a TOML config file.
///
/// Returns the selected file path, or None if the dialog was cancelled.
#[tauri::command]
pub async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file_path = app
        .dialog()
        .file()
        .add_filter("TOML Config", &["toml"])
        .set_title("Select Configuration File")
        .blocking_pick_file();

    Ok(file_path.map(|p| p.to_string()))
}

// ---------------------------------------------------------------------------
// Per-host history (scheduler database)
// ---------------------------------------------------------------------------
