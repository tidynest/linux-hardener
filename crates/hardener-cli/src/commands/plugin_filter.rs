//! What a `--plugin` filter entry is allowed to do once it names a plugin.
//!
//! Which entries name which plugin is [`plugin_id_named_by`], one rule for the
//! whole product. What lives here is the consequence: `scan` refused an entry
//! that named no plugin; `apply` and `batch` dropped it and carried on, so
//! `hardener apply --plugin services` hardened nothing, said nothing, and
//! exited 0. Both halves now route through here, so a filter can only ever
//! shrink because the operator asked it to.

use anyhow::{Result, bail};
use hardener_common::types::PluginId;
use hardener_core::PluginMetadata;
use hardener_types::plugin_id_named_by;

/// Rejects any filter entry that names no plugin, listing the valid ids.
///
/// An empty filter is accepted: callers decide whether that means all plugins
/// or none.
pub(crate) fn validate(filter: &[String], all: &[PluginMetadata]) -> Result<()> {
    let unknown: Vec<&str> = filter
        .iter()
        .filter(|entry| {
            !all.iter()
                .any(|p| plugin_id_named_by(p.plugin_id.as_str(), entry))
        })
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
                .find(|p| plugin_id_named_by(p.plugin_id.as_str(), entry))
                .map(|p| p.plugin_id.clone())
        })
        .collect())
}

#[cfg(test)]
mod tests;
