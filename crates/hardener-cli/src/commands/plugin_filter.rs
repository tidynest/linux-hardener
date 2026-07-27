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
/// any leading substring. Without it `"services"` would match
/// `"service-minimisation"`; with it, that entry correctly matches nothing.
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
mod tests {
    use super::*;
    use hardener_common::types::{FindingCategory, PluginId};

    fn meta(id: &str) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Kernel,
            plugin_description: String::new(),
            plugin_id: PluginId::new(id),
            plugin_name: id.to_string(),
            plugin_version: "0".to_string(),
        }
    }

    fn registry() -> Vec<PluginMetadata> {
        vec![
            meta("ssh-hardening"),
            meta("kernel-hardening"),
            meta("service-minimisation"),
        ]
    }

    #[test]
    fn short_name_matches_the_segment_before_the_first_hyphen() {
        assert!(matches("service", "service-minimisation"));
        assert!(matches("ssh", "ssh-hardening"));
    }

    #[test]
    fn full_id_matches_itself() {
        assert!(matches("service-minimisation", "service-minimisation"));
    }

    #[test]
    fn a_longer_prefix_is_not_a_segment_and_must_not_match() {
        // The plural reads naturally and is the mistake an operator makes;
        // it names no plugin and must be refused rather than silently dropped.
        assert!(!matches("services", "service-minimisation"));
    }

    #[test]
    fn expand_rejects_an_entry_that_names_no_plugin() {
        let err = expand(&registry(), &["services".to_string()])
            .expect_err("an unmatched entry must be an error, not an empty selection");
        let message = err.to_string();
        assert!(
            message.contains("services"),
            "names the bad entry: {message}"
        );
        assert!(
            message.contains("service-minimisation"),
            "lists the valid ids: {message}"
        );
    }

    #[test]
    fn expand_rejects_a_bad_entry_even_when_another_entry_is_good() {
        // The dangerous shape: a filter that shrinks instead of failing, so
        // the operator believes both plugins ran.
        expand(&registry(), &["ssh".to_string(), "services".to_string()])
            .expect_err("one bad entry must fail the whole selection");
    }

    #[test]
    fn expand_preserves_the_order_the_operator_wrote() {
        let ids = expand(&registry(), &["service".to_string(), "ssh".to_string()])
            .expect("both entries are valid");
        assert_eq!(
            ids.iter().map(|i| i.as_str()).collect::<Vec<_>>(),
            vec!["service-minimisation", "ssh-hardening"]
        );
    }

    #[test]
    fn an_empty_filter_expands_to_nothing_without_error() {
        assert!(expand(&registry(), &[]).expect("empty is valid").is_empty());
    }
}
