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
//! Every framework is twelve months. The table records why, per framework,
//! rather than collapsing to a single sentence, because the figures come from
//! four different kinds of source and only one of them is a plain interval.
//!
//! | Framework | Months | Basis |
//! |---|---|---|
//! | PCI DSS | 12 | Req 12.5.2, explicit. Service providers must set 6 by hand under 12.5.2.1; the tool cannot know which an operator is, so it does not guess. |
//! | FedRAMP | 12 | CA-2 annual independent assessment. |
//! | SOC 2 | 12 | Type II observation period, scoping re-decided per engagement. |
//! | NIST 800-171 | 12 | 32 CFR 170.22: the Affirming Official affirms continuing compliance at completion of an assessment "and annually thereafter", at every CMMC level. This was 36, taken from the certification assessment cycle in the same part, which is how often an *assessment* is repeated and not how often a determination that a control does not apply must be re-examined. Where two published requirements bear on the same question, the annual one binds, and taking the more permissive reading for a mechanism that raises a score was the wrong instinct. |
//! | ISO 27001, NIST 800-53, HIPAA, GDPR, CIS, STIG | 12 | No published interval. Project default, chosen as the shortest with an official basis anywhere in this table. |

use chrono::{Months, NaiveDate};
use hardener_types::ComplianceFramework;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default months before an exclusion must be reviewed again.
///
/// See the module header for the source of each figure. Taking the enum rather
/// than an id string is the point: every variant is named here with no
/// wildcard arm, so an eleventh framework is a compile error and has to be
/// given an interval deliberately. A `_ =>` arm silently handed its default to
/// anything, typos included.
pub fn default_review_months(framework: ComplianceFramework) -> u32 {
    match framework {
        ComplianceFramework::CIS => 12,
        ComplianceFramework::STIG => 12,
        ComplianceFramework::NIST => 12,
        ComplianceFramework::PCIDSS => 12,
        ComplianceFramework::HIPAA => 12,
        ComplianceFramework::GDPR => 12,
        ComplianceFramework::ISO27001 => 12,
        ComplianceFramework::SOC2 => 12,
        ComplianceFramework::NIST800171 => 12,
        ComplianceFramework::FedRAMP => 12,
    }
}

/// Parses an ISO 8601 date, `None` when it does not parse.
///
/// One helper for both dates so the two call sites cannot drift into
/// disagreeing about what a date is.
/// The one definition of the date format this section accepts.
///
/// `pub` because `hardener scope` must refuse a `--review-by` this cannot
/// parse, and it briefly held its own copy of the format string to do so. Two
/// copies would diverge in the one direction that matters: a verb accepting a
/// spelling the config layer then rejects writes an exclusion that is silently
/// inert, which is the defect the control-id refusal exists to prevent.
pub fn parse_iso_date(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

/// `user@host:22` or `host:22` without its port, so an operator may write
/// `root@web-01`.
///
/// Returns the input unchanged unless the text after the last colon is all
/// digits and the host part itself holds no colon. That second condition
/// leaves an unbracketed IPv6 literal alone, which `RemoteHostProfile` already
/// treats as portless for the same reason: there is no unambiguous
/// `host:port` reading of one.
fn strip_port(target: &str) -> &str {
    let Some((head, port)) = target.rsplit_once(':') else {
        return target;
    };
    let host = head.rsplit_once('@').map_or(head, |(_, h)| h);
    let numeric = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
    if numeric && !host.contains(':') {
        head
    } else {
        target
    }
}

/// One declared-not-applicable control.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ScopeExclusion {
    /// Why the control does not apply. `hardener scope exclude` refuses an
    /// empty one and logs the refusal, because an unexplained exclusion raises
    /// a score for no stated cause.
    ///
    /// **The verb is the only enforcement.** The generator never reads this
    /// field: it decides on the framework key, the control id, the review
    /// deadline and the host list alone. So an exclusion hand-edited into the
    /// config file with `reason = ""` applies in full, leaves the control out
    /// of the score's denominator, and nothing anywhere reports that it came
    /// with no justification.
    pub reason: String,
    /// Who approved it.
    pub approved_by: Option<String>,
    /// When it was approved (ISO 8601 date). With no `review_by` this is what
    /// the framework's interval is measured from, so an exclusion carrying
    /// neither date never applies.
    pub approved_date: Option<String>,
    /// Reference to an approval ticket or issue.
    pub ticket: Option<String>,
    /// When it must be reviewed again (ISO 8601 date). Absent means the
    /// framework's default interval from [`default_review_months`] measured
    /// from `approved_date`.
    pub review_by: Option<String>,
    /// Hosts this exclusion covers. **Empty means every host**, which is the
    /// common case. See [`Self::covers_host`] for the spellings an entry may
    /// take.
    pub hosts: Vec<String>,
}

impl ScopeExclusion {
    /// The day after which this exclusion stops applying, or `None` when it
    /// carries no usable date and so never applies.
    ///
    /// **Fails closed at every step**, because every failure mode here removes
    /// a control from the score's denominator and so raises the score:
    ///
    /// - an unknown `framework_id` is a typo, not a framework, so there is no
    ///   interval to apply and no deadline;
    /// - an explicit `review_by` decides the deadline, and if it does not
    ///   parse there is no deadline rather than a defaulted one;
    /// - otherwise the framework's interval is added to `approved_date`, which
    ///   must be present and parseable.
    ///
    /// There is deliberately no fallback date. Defaulting the base to the day
    /// of the scan made an exclusion with no dates valid on every day forever,
    /// since the comparison reduced to `today <= today + interval`.
    pub fn review_deadline(&self, framework_id: &str) -> Option<NaiveDate> {
        let framework = ComplianceFramework::from_id(framework_id)?;
        if let Some(explicit) = self.review_by.as_deref() {
            return parse_iso_date(explicit);
        }
        let approved = parse_iso_date(self.approved_date.as_deref()?)?;
        approved.checked_add_months(Months::new(default_review_months(framework)))
    }

    /// Whether this exclusion still applies on `today`.
    ///
    /// Takes the framework id as a string because the config is deserialised
    /// before any id is validated; resolving it happens in
    /// [`Self::review_deadline`], and an id that does not resolve makes the
    /// exclusion invalid.
    pub fn is_valid_on(&self, framework_id: &str, today: NaiveDate) -> bool {
        self.review_deadline(framework_id)
            .is_some_and(|deadline| today <= deadline)
    }

    /// Whether this exclusion covers a host, given its canonical
    /// `RemoteHostProfile::target()` string, its `hostname` and its display
    /// `name`.
    ///
    /// An empty `hosts` list covers everything, which is the common case.
    ///
    /// A populated one is matched, case insensitively, against four spellings:
    /// the target, the target with its port removed, the hostname and the
    /// name. All four are spellings an operator has reason to write. `name` is
    /// a separate field from `hostname` and is what the inventory file and the
    /// fleet view display, so it is often the only one they have seen; the
    /// port-less target is `user@host`, which nothing else here produces
    /// because `target()` always appends a port; and DNS is case insensitive,
    /// so `WEB-01` is the same host as `web-01`.
    ///
    /// Every one of those failed safely, in that the exclusion simply did not
    /// apply, which is why they are worth widening rather than tolerating: a
    /// silent non-match surfaces as a control the operator is certain they
    /// excluded, with nothing in the report pointing at the spelling.
    pub fn covers_host(&self, host_target: &str, hostname: &str, name: &str) -> bool {
        if self.hosts.is_empty() {
            return true;
        }
        let spellings = [host_target, strip_port(host_target), hostname, name];
        self.hosts
            .iter()
            .any(|h| spellings.iter().any(|s| h.eq_ignore_ascii_case(s)))
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

#[cfg(test)]
mod tests;
