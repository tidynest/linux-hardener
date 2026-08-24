//! `hardener scope`: declare a compliance control not applicable, or withdraw
//! that declaration.
//!
//! Writes one `[compliance.not_applicable.<framework>."<control>"]` table and
//! one audit entry. Every other line of the file is left as it was, through
//! `toml_edit`, for the reason `exception/document.rs` records: a round trip
//! through a typed struct discards the operator's comments, their section order
//! and every key the struct does not model.
//!
//! **Validation happens before the write.** An exclusion raises a compliance
//! score by leaving its denominator, so the framework id, the reason, the
//! review date and, where there is a catalogue to check it against, the control
//! id are all insisted on first. Unlike a finding exception there is no live
//! finding to reconcile against, so for the eight frameworks whose catalogue is
//! derived at report time the id cannot be checked at all. See
//! `unknown_control_refusal`.
//!
//! **Every failed attempt is audited, not only every refused one.** A write
//! that fails, most plausibly because an unprivileged operator reached for
//! `/etc/linux-hardener/config.toml`, otherwise left no trace at all: the
//! validation refusals were on the record and the one attempt that touched the
//! filesystem was not. See `refuse`.
//!
//! **An exclusion is inert for eight of the ten frameworks.** Only CIS and
//! ISO/IEC 27001 have a hand-curated catalogue; the rest derive theirs from the
//! live plugin coverage set, so every control listed is one the engine assesses
//! and the generator settles it before reaching the arm that honours an
//! exclusion. Such a declaration is still written and still audited, because a
//! framework may gain a curated catalogue later, but it is written with a
//! warning on stderr rather than in silence, and its audit entry carries
//! `takes_effect = false` so that an auditor with only the log in front of them
//! can tell the two apart. See `inert_exclusion_advisory`.
//!
//! **Why this verb exists at all.** The same declaration could be typed into
//! the configuration file by hand, and the generator would honour it. What a
//! hand edit cannot produce is the audit entry: a file edited by an editor runs
//! no code, so nothing records who raised the score, when, or on what grounds.

#[cfg(test)]
use super::exception::logger_at;
use super::exception::{WriteAudit, read_or_empty, write_atomically, write_path};
use super::state::effective_user;
use anyhow::{Context as _, Result, anyhow};
use hardener_compliance::frameworks::curated_controls;
use hardener_core::config::scope::ScopeExclusion;
use hardener_state::audit::{ActionType, AuditLogger};
use hardener_types::ComplianceFramework;
use std::collections::HashMap;
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item, Table, value};

/// The nesting the exclusion tables live under, above the framework id.
const SCOPE_PATH: [&str; 2] = ["compliance", "not_applicable"];

/// One `exclude` request, as the two entry points below hand it on.
///
/// A struct rather than eight further parameters on the shared implementation:
/// the two wrappers differ only in where the audit entry is written, and every
/// other value passes through untouched.
struct ExcludeRequest<'a> {
    framework: &'a str,
    control: &'a str,
    reason: &'a str,
    approved_by: Option<&'a str>,
    ticket: Option<&'a str>,
    review_by: Option<&'a str>,
    hosts: &'a [String],
    config_path: Option<&'a Path>,
}

/// Declares `control` not applicable, recording the act in the log it is given.
///
/// **The logger is a parameter and there is no form without one.** It used to
/// resolve `super::state::get_audit_logger` here, which answers with this
/// host's own trail chosen by uid. `exception::add` had the same shape until
/// 2026-08-24, with a `_to` sibling for tests exactly as [`run_exclude_to`] is
/// here, and five tests reached for the short name and filed 126 real entries
/// into the developer's audit log before anyone noticed. Nothing had gone wrong
/// in this module, and nothing distinguished it from the one that failed.
///
/// [`run_exclude_to`] survives as sugar over the same call. What is gone is the
/// spelling that silently picked a log.
#[allow(clippy::too_many_arguments)]
pub async fn run_exclude(
    framework: &str,
    control: &str,
    reason: &str,
    approved_by: Option<&str>,
    ticket: Option<&str>,
    review_by: Option<&str>,
    hosts: &[String],
    config_path: Option<&Path>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    let request = ExcludeRequest {
        framework,
        control,
        reason,
        approved_by,
        ticket,
        review_by,
        hosts,
        config_path,
    };
    exclude(request, logger).await.map(|_advisory| ())
}

/// [`run_exclude`] with the audit log named, so a test writes neither
/// `/var/log` nor the operator's own data directory.
///
/// Compiled for tests alone. The production entry point resolves its log
/// through [`super::state::get_audit_logger`], which also creates the directory
/// and restricts its mode, and a second public way in would be a second answer
/// to where this host's audit trail lives.
///
/// Returns whatever advisory [`exclude`] printed, which the production entry
/// point discards: stderr cannot be read back inside the process that wrote it,
/// so this is how a test observes which frameworks are warned about.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn run_exclude_to(
    framework: &str,
    control: &str,
    reason: &str,
    approved_by: Option<&str>,
    ticket: Option<&str>,
    review_by: Option<&str>,
    hosts: &[String],
    config_path: Option<&Path>,
    audit_log_path: &str,
) -> Result<Option<String>> {
    let request = ExcludeRequest {
        framework,
        control,
        reason,
        approved_by,
        ticket,
        review_by,
        hosts,
        config_path,
    };
    exclude(request, logger_at(audit_log_path).await).await
}

/// Withdraws a not-applicable declaration, returning the control to the score.
///
/// Takes its logger for the reason [`run_exclude`] does.
pub async fn run_include(
    framework: &str,
    control: &str,
    config_path: Option<&Path>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    include(framework, control, config_path, logger).await
}

/// [`run_include`] with the audit log named. Tests only, as
/// [`run_exclude_to`] is.
#[cfg(test)]
pub async fn run_include_to(
    framework: &str,
    control: &str,
    config_path: Option<&Path>,
    audit_log_path: &str,
) -> Result<()> {
    include(
        framework,
        control,
        config_path,
        logger_at(audit_log_path).await,
    )
    .await
}

async fn exclude(
    request: ExcludeRequest<'_>,
    logger: Option<AuditLogger>,
) -> Result<Option<String>> {
    let reason = request.reason.trim();

    // Resolved ahead of the first refusal so that every entry this call can
    // file names the framework the same way. The canonical id, not the spelling
    // given: `from_id` accepts `ISO-27001` and `iso27001` alike, two spellings
    // of one framework would otherwise write two tables of which the generator
    // reads one, and an auditor filtering their log for `iso27001:7.1` would
    // miss a refusal filed as `ISO-27001:7.1`.
    let resolved = ComplianceFramework::from_id(request.framework);

    // A name that resolves to nothing falls back to the operator's own
    // spelling, on purpose: there is no canonical form for a framework this
    // tool does not know, and what the audit trail owes for one is what was
    // actually attempted.
    let target = format!(
        "{}:{}",
        resolved.as_ref().map_or(request.framework, |f| f.id()),
        request.control
    );

    if reason.is_empty() {
        return refuse(
            logger.as_ref(),
            target,
            format!(
                "--reason is empty, so control '{}' was not excluded. An exclusion \
                 raises the compliance score by leaving its denominator, and an \
                 unexplained one raises it for no stated cause.",
                request.control
            ),
        )
        .await;
    }

    let Some(framework) = resolved else {
        return refuse(
            logger.as_ref(),
            target,
            format!(
                "Unknown compliance framework '{}', so control '{}' was not \
                 excluded. Run `hardener report --help` for the ids this binary \
                 carries.",
                request.framework, request.control
            ),
        )
        .await;
    };

    let framework_id = framework.id();

    if let Some(message) = unknown_control_refusal(&framework, request.control) {
        return refuse(logger.as_ref(), target, message).await;
    }

    if let Some(review_by) = request.review_by
        && !is_iso_date(review_by)
    {
        return refuse(
            logger.as_ref(),
            target,
            format!(
                "--review-by '{review_by}' is not an ISO 8601 date (YYYY-MM-DD), so \
                 control '{}' was not excluded. `ScopeExclusion::review_deadline` \
                 fails closed on a date it cannot read: the exclusion would have no \
                 deadline, would apply on no day, and the control would stay under \
                 manual review while the configuration and the audit log both said \
                 it had been excluded.",
                request.control
            ),
        )
        .await;
    }

    let exclusion = ScopeExclusion {
        reason: reason.to_string(),
        approved_by: request.approved_by.map(str::to_string),
        // Written now rather than left absent, because `review_deadline` has
        // no fallback base date: with neither `approved_date` nor a parseable
        // `review_by` it returns `None`, `is_valid_on` is then false on every
        // day, and the exclusion applies never rather than forever. Deleting
        // this line makes every exclusion this verb writes inert. It once did
        // fall back to the day of evaluation, which made a dateless exclusion
        // valid forever; `91ebe8e6` removed that, inverting the consequence
        // without changing what has to be written here.
        approved_date: Some(chrono::Utc::now().date_naive().to_string()),
        ticket: request.ticket.map(str::to_string),
        review_by: request.review_by.map(str::to_string),
        hosts: request.hosts.to_vec(),
    };

    let path = write_path(request.config_path);

    // Reading and editing the document are still a synchronous chain; only the
    // write is not, because the write is what files the entry. A failure here
    // never reached the file, so it is refused rather than left to the write to
    // report.
    let written = match read_or_empty(&path)
        .and_then(|existing| upsert_exclusion(&existing, framework_id, request.control, &exclusion))
    {
        Ok(written) => written,
        Err(e) => {
            return refuse(
                logger.as_ref(),
                target,
                format!("Control '{}' was not excluded: {e:#}", request.control),
            )
            .await;
        }
    };

    // Settled before the write rather than after it, because the write files
    // its own entry now and this is one of that entry's details. Nothing here
    // reads the file: `inert_exclusion_advisory` asks the framework and the
    // control whether any catalogue could carry it, which no write changes.
    //
    // It is filed at all because an auditor reading `audit.log` has no stderr
    // to read alongside it: an inert SOC 2 exclusion and an effective CIS one
    // would otherwise be the same entry. `unknown_control_refusal` refuses a
    // mistyped id on exactly that reasoning, that the log must not record a
    // control as excluded that no catalogue carries, and a declaration no
    // catalogue can honour is that same claim one step weaker.
    let advisory = inert_exclusion_advisory(&framework, request.control);

    let mut details = HashMap::from([
        ("operation".to_string(), "exclude".to_string()),
        ("reason".to_string(), exclusion.reason.clone()),
    ]);
    for (key, field) in [
        ("approved_by", &exclusion.approved_by),
        ("approved_date", &exclusion.approved_date),
        ("ticket", &exclusion.ticket),
        ("review_by", &exclusion.review_by),
    ] {
        if let Some(text) = field {
            details.insert(key.to_string(), text.clone());
        }
    }
    if !exclusion.hosts.is_empty() {
        details.insert("hosts".to_string(), exclusion.hosts.join(","));
    }
    // Written only when the declaration cannot take effect, as every optional
    // detail above is written only when there is something to say. The key
    // borrows the advisory's own words, so the entry and the warning on stderr
    // name the same fact. It is inside the hash, because a success entry goes
    // through `log_action_with_details`; only the failure path is held to a
    // single `error` detail. See `WriteAudit::record`.
    if advisory.is_some() {
        details.insert("takes_effect".to_string(), "false".to_string());
    }

    // The failure entry is filed by the write itself, so a write that cannot be
    // made returns its cause here rather than going through `refuse`, which
    // would file a second entry for one attempt.
    write_atomically(
        &path,
        &written,
        WriteAudit {
            logger: logger.as_ref(),
            action: ActionType::ScopeExclusion,
            target,
            details,
        },
    )
    .await
    .map_err(|e| anyhow!("Control '{}' was not excluded: {e:#}", request.control))?;

    println!(
        "Excluded '{}' from {} as not applicable. Written to {}.",
        request.control,
        framework,
        path.display()
    );

    if let Some(text) = &advisory {
        eprintln!("⚠  {text}");
    }
    Ok(advisory)
}

/// The refusal an unknown control id warrants, or `None` when the id can be
/// excluded.
///
/// **Why refuse rather than warn.** An exclusion naming a control no catalogue
/// carries is inert: the report never changes, and yet the configuration gains
/// an entry and the audit log gains a signed declaration that a control was
/// excluded when none was. A typo is the common case, so the quiet outcome is
/// the likely one. `exception add` refuses a key the scan did not produce for
/// the same reason, and with the same second benefit: this is the input
/// validation for a caller reaching the verb over IPC rather than through a
/// terminal.
///
/// **Only a curated framework can be checked.** [`curated_controls`] answers
/// `None` for the eight frameworks whose catalogue is derived from live plugin
/// coverage at report time, and this process holds no such catalogue at the
/// moment of the write. An exclusion for one of those cannot take effect at all,
/// whatever it names, and [`inert_exclusion_advisory`] already says so, so
/// nothing is gained by inventing a second check there.
///
/// **Why the message names the framework and the listing command.** The
/// notation differs between catalogues, and this one refuses ISO 27001's own
/// Annex A prefix (`A.7.1`) because the catalogue holds the bare clause number
/// (`7.1`). A refusal that only said "unknown control" would leave the operator
/// guessing at exactly that.
fn unknown_control_refusal(framework: &ComplianceFramework, control: &str) -> Option<String> {
    let catalogue = curated_controls(framework)?;
    if catalogue
        .iter()
        .any(|mapping| mapping.compliance_control_id == control)
    {
        return None;
    }
    Some(format!(
        "'{control}' is not a control in the {framework} catalogue, so nothing was \
         excluded. Written as it stands it would change no report, while the \
         configuration and the audit log would both record a control as excluded \
         that no catalogue carries. Catalogues differ in notation, so run \
         `hardener report --framework {}` for every control this one holds, each \
         printed with the id to give here.",
        framework.id()
    ))
}

/// Whether `value` is a date the report path will read back.
///
/// Whether `value` is a date the config layer will actually parse.
///
/// Calls the same function the stored `review_by` is read back through, rather
/// than restating its format string. A verb that accepted a spelling the config
/// layer then rejected would write an exclusion audited as granted that never
/// applies, which is the defect this check exists to prevent, so the two must
/// not be able to drift apart.
fn is_iso_date(value: &str) -> bool {
    hardener_core::config::scope::parse_iso_date(value).is_some()
}

/// The warning an exclusion for `framework` warrants, or `None` when the
/// framework carries a hand-curated catalogue and the declaration can take
/// effect.
///
/// Only CIS and ISO/IEC 27001 are curated. Every other framework's catalogue is
/// derived at report time from the live plugin coverage set, so each control it
/// lists is one the engine assesses, and the generator settles an assessed
/// control one arm above the arm that honours an exclusion. Such an exclusion
/// can therefore never fire, whatever it names.
///
/// The question is asked of [`curated_controls`], not of a list of two
/// framework names kept here: the compliance crate already owns that fact, and
/// a copy of it would say the wrong thing on the day a ninth catalogue is
/// curated.
fn inert_exclusion_advisory(framework: &ComplianceFramework, control: &str) -> Option<String> {
    if curated_controls(framework).is_some() {
        return None;
    }
    Some(format!(
        "'{control}' was written and audited, but it cannot take effect for {framework}. \
         That framework's control catalogue is derived from what this engine can already \
         assess, so it lists no control an exclusion could apply to, and the report will \
         not change. The declaration is kept in case {framework} gains a curated \
         catalogue later."
    ))
}

async fn include(
    framework: &str,
    control: &str,
    config_path: Option<&Path>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    let raw_target = format!("{framework}:{control}");
    let Some(known) = ComplianceFramework::from_id(framework) else {
        return refuse(
            logger.as_ref(),
            raw_target,
            format!(
                "Unknown compliance framework '{framework}', so nothing was \
                 withdrawn. Run `hardener report --help` for the ids this binary \
                 carries."
            ),
        )
        .await;
    };

    let framework_id = known.id();
    let path = write_path(config_path);

    // One entry for every way the withdrawal can fail to land: an unreadable
    // file, an exclusion that was never there, and a write that cannot be made.
    // The last of those is the one an unprivileged operator meets, and leaving
    // it to `?` filed nothing for an attempt on this host's policy. The first
    // two never reach the file and are refused here; the third the write files
    // itself.
    let written = match read_or_empty(&path)
        .and_then(|existing| remove_exclusion(&existing, framework_id, control))
    {
        Ok(written) => written,
        Err(e) => {
            return refuse(
                logger.as_ref(),
                format!("{framework_id}:{control}"),
                format!("{e:#}"),
            )
            .await;
        }
    };

    write_atomically(
        &path,
        &written,
        WriteAudit {
            logger: logger.as_ref(),
            action: ActionType::ScopeExclusion,
            target: format!("{framework_id}:{control}"),
            details: HashMap::from([("operation".to_string(), "include".to_string())]),
        },
    )
    .await?;

    println!(
        "Withdrew the exclusion of '{control}' from {known}; it counts towards \
         the score again. Written to {}.",
        path.display()
    );
    Ok(())
}

/// Records an attempt that did not take effect and returns the error the
/// operator sees.
///
/// Used for the validation refusals and for a write that fails, which is an
/// attempt on this host's compliance policy just as much as a refused one and
/// was previously the only one leaving no trace.
///
/// **A failure to audit never masks the failure being audited.** The log may
/// well be unwritable in the same circumstances that made the configuration
/// unwritable, so a logging error is warned about and dropped, and the error
/// returned to the caller is always the original cause.
///
/// **`log_failure`, not `log_action_with_details`.**
/// [`AuditLogger::verify_integrity`] verifies a failure entry through a branch
/// of its own that hashes the single `error` detail and nothing else
/// (`crates/hardener-state/src/audit.rs:507`), so any further detail written on
/// a failure entry would sit outside the hash chain and could be altered
/// without detection. The cause therefore goes into the error message, which is
/// hashed, and the control it was refused for goes into the target, which is
/// also hashed.
async fn refuse<T>(logger: Option<&AuditLogger>, target: String, message: String) -> Result<T> {
    if let Some(logger) = logger
        && let Err(e) = logger
            .log_failure(
                ActionType::ScopeExclusion,
                effective_user(),
                target,
                message.clone(),
            )
            .await
    {
        tracing::warn!("a refused scope change was not audited: {e}");
    }
    Err(anyhow!(message))
}

/// Writes `exclusion` at `[compliance.not_applicable.<framework>."<control>"]`,
/// replacing any table already there, and returns the whole document as text.
///
/// The optional fields are written only when set: an empty `approved_by` in the
/// file would say the exclusion was approved by nobody, which is not what an
/// unapproved exclusion means. An empty `hosts` is likewise left out, because
/// there it means every host rather than none.
fn upsert_exclusion(
    document_text: &str,
    framework_id: &str,
    control: &str,
    exclusion: &ScopeExclusion,
) -> Result<String> {
    let mut document = parse(document_text)?;

    let mut entry = Table::new();
    entry["reason"] = value(exclusion.reason.as_str());
    for (name, field) in [
        ("approved_by", &exclusion.approved_by),
        ("approved_date", &exclusion.approved_date),
        ("ticket", &exclusion.ticket),
        ("review_by", &exclusion.review_by),
    ] {
        if let Some(text) = field {
            entry[name] = value(text.as_str());
        }
    }
    if !exclusion.hosts.is_empty() {
        entry["hosts"] = value(Array::from_iter(exclusion.hosts.iter().map(String::as_str)));
    }

    table_at(&mut document, &framework_path(framework_id))?[control] = Item::Table(entry);

    Ok(document.to_string())
}

/// Removes one control's table, and the tables above it when they are left
/// empty, so that exclude followed by include is a round trip rather than a
/// file gaining an empty header each time.
///
/// An absent control is an error, for the reason `remove_exception` gives: a
/// typo against a hand-edited file would otherwise read as done.
fn remove_exclusion(document_text: &str, framework_id: &str, control: &str) -> Result<String> {
    let mut document = parse(document_text)?;

    let controls = table_at(&mut document, &framework_path(framework_id))?;
    if controls.remove(control).is_none() {
        return Err(anyhow!(
            "No exclusion of '{control}' under '{framework_id}' to withdraw."
        ));
    }
    if !controls.is_empty() {
        return Ok(document.to_string());
    }

    // The framework's own table is now empty, and so may be each table above
    // it. Pruned from the innermost outwards, stopping at the first that still
    // holds something.
    let mut path: Vec<&str> = framework_path(framework_id);
    while let Some(leaf) = path.pop() {
        let parent = table_at(&mut document, &path)?;
        parent.remove(leaf);
        if !parent.is_empty() {
            break;
        }
    }

    Ok(document.to_string())
}

fn framework_path(framework_id: &str) -> Vec<&str> {
    let mut path = SCOPE_PATH.to_vec();
    path.push(framework_id);
    path
}

fn parse(document_text: &str) -> Result<DocumentMut> {
    document_text
        .parse::<DocumentMut>()
        .context("The configuration file is not valid TOML, so it was not written")
}

/// The table at `path`, creating any missing level on the way.
///
/// Every level created here is marked implicit, because none of them ever
/// carries a value directly: only the control table at the end does. An
/// implicit table contributes no header line of its own, so a first exclusion
/// on an empty file adds exactly one header, the one that holds the data.
fn table_at<'a>(document: &'a mut DocumentMut, path: &[&str]) -> Result<&'a mut Table> {
    let mut current = document.as_table_mut();
    for (depth, name) in path.iter().enumerate() {
        current = current
            .entry(name)
            .or_insert_with(|| {
                let mut table = Table::new();
                table.set_implicit(true);
                Item::Table(table)
            })
            .as_table_mut()
            .ok_or_else(|| {
                anyhow!(
                    "[{}] is not a table in this configuration file",
                    path[..=depth].join(".")
                )
            })?;
    }
    Ok(current)
}

#[cfg(test)]
mod tests;
