//! Declaring a compliance control not applicable to this system.
//!
//! A control the engine cannot assess is reported as `ManualReview` and counts
//! against the score. Some of those controls do not merely go unmeasured, they
//! do not apply: ISO 27001 Annex A physical controls on a cloud instance with
//! no premises. This is how an operator says so.
//!
//! # The review interval comes from the framework owner
//!
//! Researched 2026-08-18. Four frameworks publish an interval bearing on a
//! scope or applicability determination; six publish none and state a change
//! trigger instead, in near-identical language (GDPR Art 35(11), HIPAA 45 CFR
//! 164.316(b)(2)(iii)). So the date here is a backstop and the change triggers
//! in the generator are the primary mechanism.
//!
//! | Framework | Months | Basis |
//! |---|---|---|
//! | PCI DSS | 12 | Req 12.5.2, explicit. Service providers must set 6 by hand under 12.5.2.1; the tool cannot know which an operator is, so it does not guess. |
//! | FedRAMP | 12 | CA-2 annual independent assessment. |
//! | SOC 2 | 12 | Type II observation period, scoping re-decided per engagement. |
//! | NIST 800-171 | 36 | CMMC certification validity, 32 CFR 170. Longer than this project would choose; honoured because it is the official figure. |
//! | ISO 27001, NIST 800-53, HIPAA, GDPR, CIS, STIG | 12 | No published interval. Project default, chosen as the shortest with an official basis anywhere in this table. |

use chrono::{Months, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default months before an exclusion must be reviewed again.
///
/// See the module header for the source of each figure. Every framework except
/// NIST 800-171 is twelve months.
pub fn default_review_months(framework_id: &str) -> u32 {
    match framework_id {
        "800-171" => 36,
        _ => 12,
    }
}

/// One declared-not-applicable control.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ScopeExclusion {
    /// Why the control does not apply. Mandatory in practice: an exclusion
    /// with an empty reason is rejected by the verb and reported by the
    /// generator, because an unexplained exclusion raises a score for no
    /// stated cause.
    pub reason: String,
    /// Who approved it.
    pub approved_by: Option<String>,
    /// When it was approved (ISO 8601 date).
    pub approved_date: Option<String>,
    /// Reference to an approval ticket or issue.
    pub ticket: Option<String>,
    /// When it must be reviewed again (ISO 8601 date). Absent means the
    /// framework's default interval from [`default_review_months`].
    pub review_by: Option<String>,
    /// Hosts this exclusion covers. **Empty means every host**, which is the
    /// common case. Entries are matched against `RemoteHostProfile::target()`
    /// or against the bare hostname.
    pub hosts: Vec<String>,
}

impl ScopeExclusion {
    /// The day after which this exclusion stops applying.
    ///
    /// An explicit `review_by` wins. Otherwise the framework's default
    /// interval is added to `approved_date`, or to `fallback` when the
    /// approval date is absent or unparseable.
    pub fn review_deadline(&self, framework_id: &str, fallback: NaiveDate) -> NaiveDate {
        if let Some(explicit) = self.review_by.as_deref()
            && let Ok(date) = NaiveDate::parse_from_str(explicit, "%Y-%m-%d")
        {
            return date;
        }
        let base = self
            .approved_date
            .as_deref()
            .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            .unwrap_or(fallback);
        base.checked_add_months(Months::new(default_review_months(framework_id)))
            .unwrap_or(base)
    }

    /// Whether this exclusion still applies on `today`.
    ///
    /// **Fails closed.** A `review_by` that does not parse makes the exclusion
    /// invalid rather than defaulted, so a typo returns the control to counting
    /// against the score instead of silently extending the exclusion.
    pub fn is_valid_on(&self, framework_id: &str, today: NaiveDate) -> bool {
        if let Some(explicit) = self.review_by.as_deref()
            && NaiveDate::parse_from_str(explicit, "%Y-%m-%d").is_err()
        {
            return false;
        }
        today <= self.review_deadline(framework_id, today)
    }

    /// Whether this exclusion covers `host_target`, the canonical
    /// `RemoteHostProfile::target()` string, or `hostname`.
    ///
    /// An empty `hosts` list covers everything. A populated one is matched
    /// against both forms so an operator is not forced to write `:22` on every
    /// entry, and `hostname` is a field rather than a guess.
    pub fn covers_host(&self, host_target: &str, hostname: &str) -> bool {
        self.hosts.is_empty() || self.hosts.iter().any(|h| h == host_target || h == hostname)
    }
}

/// The `[compliance]` config section.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ComplianceConfig {
    /// Framework id to control id to exclusion. Keyed by `String` and not by
    /// `ComplianceFramework` because the config is deserialised before any id
    /// is validated, and an unknown framework must be ignorable rather than
    /// fatal.
    pub not_applicable: HashMap<String, HashMap<String, ScopeExclusion>>,
}

#[path = "scope/tests.rs"]
mod tests;
