//! Editing one `exceptions` table inside a config document.
//!
//! `toml_edit` rather than `toml`, for the reason `save_scheduler_config`
//! already records at `src-tauri/src/commands.rs:1978`: a serialise-and-write
//! round trip through a typed struct silently discards every key the struct
//! does not model, along with the operator's comments and section order. This
//! writes one table and leaves the rest of the bytes alone.
//!
//! `upsert_exception` and `remove_exception` have no caller yet: the CLI verb
//! that wires them in is a later task in this plan. Dead code is allowed only
//! outside test builds, where `document/tests.rs` already exercises both, so
//! the lint still guards against a genuinely unused item once the verb lands.
#![cfg_attr(not(test), allow(dead_code))]

use anyhow::{Context as _, Result, anyhow};
use hardener_core::PolicyException;
use toml_edit::{DocumentMut, Item, Table, value};

/// Writes `exception` at `[<section>.exceptions."<key>"]`, replacing any table
/// already there, and returns the whole document as text.
///
/// An absent `[section]` or `[section.exceptions]` is created. The optional
/// fields are written only when set: an empty `approved_by` in the file would
/// say the exception was approved by nobody, which is not what an unapproved
/// exception means.
pub fn upsert_exception(
    document_text: &str,
    section: &str,
    key: &str,
    exception: &PolicyException,
) -> Result<String> {
    let mut document = parse(document_text)?;

    let mut entry = Table::new();
    entry["value"] = value(exception.value.as_str());
    entry["allowed"] = value(exception.allowed);
    entry["reason"] = value(exception.reason.as_str());
    for (name, field) in [
        ("approved_by", &exception.approved_by),
        ("approved_date", &exception.approved_date),
        ("ticket", &exception.ticket),
        ("expires", &exception.expires),
    ] {
        if let Some(text) = field {
            entry[name] = value(text.as_str());
        }
    }

    exceptions_table(&mut document, section)?[key] = Item::Table(entry);

    Ok(document.to_string())
}

/// Removes `[<section>.exceptions."<key>"]`, and the tables above it when they
/// are left empty, so that add followed by remove is a round trip rather than a
/// file gaining an empty table each time.
///
/// An absent key is an error. Reporting success would let a typo against a
/// hand-edited file read as done.
pub fn remove_exception(document_text: &str, section: &str, key: &str) -> Result<String> {
    let mut document = parse(document_text)?;

    let exceptions = exceptions_table(&mut document, section)?;
    if exceptions.remove(key).is_none() {
        return Err(anyhow!(
            "No exception '{key}' in [{section}.exceptions] to remove."
        ));
    }
    let exceptions_now_empty = exceptions.is_empty();
    if !exceptions_now_empty {
        return Ok(document.to_string());
    }

    let table = section_table(&mut document, section)?;
    table.remove("exceptions");
    if table.is_empty() {
        document.remove(section);
    }

    Ok(document.to_string())
}

fn parse(document_text: &str) -> Result<DocumentMut> {
    document_text
        .parse::<DocumentMut>()
        .context("The configuration file is not valid TOML, so it was not written")
}

fn section_table<'a>(document: &'a mut DocumentMut, section: &str) -> Result<&'a mut Table> {
    document
        .entry(section)
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("[{section}] is not a table in this configuration file"))
}

fn exceptions_table<'a>(document: &'a mut DocumentMut, section: &str) -> Result<&'a mut Table> {
    section_table(document, section)?
        .entry("exceptions")
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("[{section}.exceptions] is not a table in this configuration file"))
}

#[cfg(test)]
mod tests;
