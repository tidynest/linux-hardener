//! One rule for resolving `--plugin` filter entries to plugins.
//!
//! The rule used to live in two places. `scan` refused an entry that named no
//! plugin; `apply` and `batch` dropped it and carried on, so
//! `hardener apply --plugin services` hardened nothing, said nothing, and
//! exited 0. Both halves now route through here, so a filter can only ever
//! shrink because the operator asked it to.

use anyhow::{Result, bail};
use hardener_common::types::PluginId;
use hardener_core::PluginMetadata;

/// Whether a filter entry names this plugin: the full id
/// (`"service-minimisation"`) or the short prefix before the first hyphen
/// (`"service"`).
///
/// The trailing hyphen is what makes the prefix a whole segment rather than
/// any leading substring. Without it `"serv"` would match
/// `"service-minimisation"`, and `""` would match every plugin there is, so a
/// filter naming nothing would quietly select something. With it, both match
/// nothing and are refused.
///
/// The plural `"services"` matches nothing either way, which is why it is not
/// the example: it is a real mistake an operator makes and it is refused, but
/// it says nothing about what the hyphen does.
pub(crate) fn matches(entry: &str, plugin_id: &str) -> bool {
    plugin_id == entry || plugin_id.starts_with(&format!("{entry}-"))
}

/// Rejects any filter entry that names no plugin, listing the valid ids.
///
/// An empty filter is accepted: callers decide whether that means all plugins
/// or none.
pub(crate) fn validate(filter: &[String], all: &[PluginMetadata]) -> Result<()> {
    let unknown: Vec<&str> = filter
        .iter()
        .filter(|entry| !all.iter().any(|p| matches(entry, p.plugin_id.as_str())))
        .map(String::as_str)
        .collect();

    if unknown.is_empty() {
        return Ok(());
    }

    let valid: Vec<&str> = all.iter().map(|p| p.plugin_id.as_str()).collect();
    bail!(
        "Unknown plugin(s): {}. Valid plugins: {}",
        unknown.join(", "),
        valid.join(", ")
    )
}

/// Expands a filter to plugin ids, in the order the operator wrote them.
///
/// Order is the caller's: plugins are applied in the sequence given, and
/// resolving to registry order instead would silently reorder an apply.
pub(crate) fn expand(all: &[PluginMetadata], filter: &[String]) -> Result<Vec<PluginId>> {
    validate(filter, all)?;

    // Every entry matched during validation, so this maps one id per entry.
    Ok(filter
        .iter()
        .filter_map(|entry| {
            all.iter()
                .find(|p| matches(entry, p.plugin_id.as_str()))
                .map(|p| p.plugin_id.clone())
        })
        .collect())
}

#[cfg(test)]
mod tests;
