//! `hardener exception`: author a policy exception from the finding that needs
//! one.
//!
//! The exception itself is not new. Every plugin has honoured
//! [`PolicyException`] at apply for as long as one could be written, and a
//! declined one has reported itself since the exception-not-applied work. What
//! was missing is a way to write one without hand-editing a root-owned file
//! whose check ids nothing in the interface names.

pub mod document;

use anyhow::{Result, anyhow};
use hardener_compliance::OutputFormat;
use hardener_core::executor::SystemExecutor;
use hardener_core::{Context, Finding, HardenerConfig, PolicyException};
use hardener_types::PluginId;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where an exception is written when `--config` names nothing.
///
/// Not a choice. `ConfigLoader::load` skips the user config when running as
/// root (`crates/hardener-core/src/config_loader.rs:61`), and apply runs as
/// root, so an exception written under `~/.config` would be shown by the
/// desktop and ignored by the apply it was created to change.
const SYSTEM_CONFIG_PATH: &str = "/etc/linux-hardener/config.toml";

pub struct AddOptions<'a> {
    pub plugin_id: &'a str,
    pub key: &'a str,
    pub reason: &'a str,
    pub approved_by: Option<&'a str>,
    pub ticket: Option<&'a str>,
    pub expires: Option<&'a str>,
    pub config_path: Option<&'a PathBuf>,
    pub format: OutputFormat,
    pub quiet: bool,
    pub executor: Arc<dyn SystemExecutor>,
}

pub struct RemoveOptions<'a> {
    pub plugin_id: &'a str,
    pub key: &'a str,
    pub config_path: Option<&'a PathBuf>,
    pub format: OutputFormat,
    pub quiet: bool,
}

/// The finding this key names, or a refusal naming the key.
///
/// Separated from `add` so the match rule is testable without a host: it is the
/// step that decides both what value is pinned and whether a key reaching this
/// binary over IPC is one the host itself produced.
pub fn pin_from_findings<'a>(findings: &'a [Finding], key: &str) -> Result<&'a Finding> {
    findings
        .iter()
        .find(|f| f.finding_exception_key.as_deref() == Some(key))
        .ok_or_else(|| {
            anyhow!(
                "No live finding is keyed '{key}'. Run `hardener scan` and use the \
                 key it prints beside the finding you want to accept."
            )
        })
}

pub async fn add(opts: AddOptions<'_>) -> Result<()> {
    let section = section_for(opts.plugin_id)?;
    let config = super::config_loader(opts.config_path)
        .load()
        .map_err(|e| anyhow!("Config error: {e}"))?;

    let registry = hardener_plugins::create_plugin_registry();
    let plugin = registry
        .get(&PluginId::new(opts.plugin_id))?
        .ok_or_else(|| anyhow!("Unknown plugin '{}'.", opts.plugin_id))?;
    let ctx = Context::with_executor(opts.executor.clone());
    let scan = plugin
        .scan(&ctx, config.get_plugin_config(opts.plugin_id))
        .await?;

    let finding = pin_from_findings(&scan.scan_findings, opts.key)?;

    let exception = PolicyException {
        value: finding.finding_current_value.clone(),
        allowed: true,
        reason: opts.reason.to_string(),
        approved_by: opts.approved_by.map(str::to_string),
        approved_date: None,
        ticket: opts.ticket.map(str::to_string),
        expires: opts.expires.map(str::to_string),
    };

    let path = write_path(opts.config_path);
    let existing = read_or_empty(&path)?;
    let written = document::upsert_exception(&existing, section, opts.key, &exception)?;
    write_atomically(&path, &written)?;

    report_add(&opts, section, &exception, &path);
    Ok(())
}

pub async fn remove(opts: RemoveOptions<'_>) -> Result<()> {
    let section = section_for(opts.plugin_id)?;
    let path = write_path(opts.config_path);
    let existing = read_or_empty(&path)?;
    let written = document::remove_exception(&existing, section, opts.key)?;
    write_atomically(&path, &written)?;

    report_remove(&opts, section, &path);
    Ok(())
}

/// The `config.toml` section a plugin's exceptions live under, which is not its
/// plugin id: the services plugin declares `service-minimisation` and is
/// configured under `[services]`.
fn section_for(plugin_id: &str) -> Result<&'static str> {
    HardenerConfig::config_section(plugin_id).ok_or_else(|| {
        anyhow!(
            "Unknown plugin id '{plugin_id}'. Run `hardener plugins` for the ids \
             this binary carries."
        )
    })
}

fn write_path(config_path: Option<&PathBuf>) -> PathBuf {
    config_path
        .cloned()
        .unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG_PATH))
}

/// A config file that does not exist yet is an empty document, not an error:
/// the first exception on a host may be the first line of its config.
fn read_or_empty(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(anyhow!("Cannot read {}: {e}", path.display())),
    }
}

/// Write to a sibling temporary file and rename over the target, so an
/// interrupted write cannot leave a half-written config that root then fails to
/// parse on the next scan.
fn write_atomically(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("Cannot create {}: {e}", parent.display()))?;
    }
    let temporary = path.with_extension("toml.new");
    std::fs::write(&temporary, contents)
        .map_err(|e| anyhow!("Cannot write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| anyhow!("Cannot replace {}: {e}", path.display()))
}

fn report_add(opts: &AddOptions<'_>, section: &str, exception: &PolicyException, path: &Path) {
    if matches!(opts.format, OutputFormat::Json) {
        let payload = serde_json::json!({
            "section": section,
            "key": opts.key,
            "value": exception.value,
            "reason": exception.reason,
            "approved_by": exception.approved_by,
            "ticket": exception.ticket,
            "expires": exception.expires,
            "path": path.display().to_string(),
        });
        println!("{payload}");
        return;
    }
    if !opts.quiet {
        println!(
            "Accepted '{}' in [{section}.exceptions] at value '{}'. Written to {}.",
            opts.key,
            exception.value,
            path.display()
        );
    }
}

fn report_remove(opts: &RemoveOptions<'_>, section: &str, path: &Path) {
    if matches!(opts.format, OutputFormat::Json) {
        let payload = serde_json::json!({
            "section": section,
            "key": opts.key,
            "removed": true,
            "path": path.display().to_string(),
        });
        println!("{payload}");
        return;
    }
    if !opts.quiet {
        println!(
            "Removed '{}' from [{section}.exceptions] in {}.",
            opts.key,
            path.display()
        );
    }
}

#[cfg(test)]
mod tests;
