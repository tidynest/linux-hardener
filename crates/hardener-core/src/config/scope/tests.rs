#![cfg(test)]
//! Unit tests for [`scope`](super).

use super::*;
use chrono::NaiveDate;
use hardener_types::remote::RemoteHostProfile;

fn day(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("test date parses")
}

fn exclusion(review_by: Option<&str>) -> ScopeExclusion {
    ScopeExclusion {
        reason: "No physical premises".to_string(),
        approved_by: Some("eric".to_string()),
        approved_date: Some("2026-08-18".to_string()),
        ticket: None,
        review_by: review_by.map(str::to_string),
        hosts: Vec::new(),
    }
}

/// Every framework is twelve months, including NIST 800-171: see the module
/// header for why the three-year CMMC assessment cycle is not the figure that
/// governs a scope determination.
///
/// Iterating `ComplianceFramework::ALL` rather than a list of id strings is
/// what makes this assertion mean anything. Over strings it passed for any
/// input at all, typos included, because the table had a catch-all arm; over
/// the enum it is an assertion about the real framework set, and an eleventh
/// framework cannot join without being counted here.
#[test]
fn review_intervals_follow_the_framework_owners() {
    for framework in ComplianceFramework::ALL {
        assert_eq!(
            default_review_months(framework),
            12,
            "{} defaults to 12 months",
            framework.id()
        );
    }
}

#[test]
fn an_absent_review_by_is_defaulted_from_the_approval_date() {
    let e = exclusion(None);
    assert_eq!(
        e.review_deadline("iso27001"),
        Some(day("2027-08-18")),
        "twelve months after the approval date"
    );
}

#[test]
fn an_explicit_review_by_wins_over_the_default() {
    let e = exclusion(Some("2026-12-01"));
    assert_eq!(e.review_deadline("iso27001"), Some(day("2026-12-01")));
}

#[test]
fn an_exclusion_is_valid_up_to_and_including_its_deadline() {
    let e = exclusion(Some("2026-12-01"));
    assert!(e.is_valid_on("iso27001", day("2026-11-30")));
    assert!(
        e.is_valid_on("iso27001", day("2026-12-01")),
        "the deadline day itself is still valid"
    );
    assert!(!e.is_valid_on("iso27001", day("2026-12-02")));
}

/// A malformed date must not silently extend an exclusion. Failing closed means
/// the control returns to counting against the score.
#[test]
fn an_unparseable_review_by_is_invalid_rather_than_ignored() {
    let e = exclusion(Some("not-a-date"));
    assert!(!e.is_valid_on("iso27001", day("2026-08-18")));
}

/// An exclusion carrying no usable date at all must not apply.
///
/// `today` was passed as its own fallback, so the comparison became
/// `today <= today + 12 months`, true on every day forever. A hand-written
/// entry with a reason and nothing else therefore excluded a control
/// permanently, and the CLI verb that always writes `approved_date` could not
/// be relied on to prevent it because the file is editable by hand.
#[test]
fn an_exclusion_with_no_dates_at_all_is_invalid() {
    let mut e = exclusion(None);
    e.approved_date = None;
    assert!(!e.is_valid_on("iso27001", day("2026-08-18")));
    assert!(
        !e.is_valid_on("iso27001", day("2099-01-01")),
        "and is still invalid decades later, which the fallback made impossible"
    );
}

/// The fail-closed rule `review_by` already had, applied to the other date. A
/// date that does not parse is never defaulted.
#[test]
fn an_unparseable_approved_date_with_no_review_by_is_invalid() {
    let mut e = exclusion(None);
    e.approved_date = Some("18/08/2026".to_string());
    assert!(!e.is_valid_on("iso27001", day("2026-08-18")));
}

/// The control for the two above: the shape the CLI verb writes, an approval
/// date and no `review_by`, must still be valid for twelve months and expire
/// the day after. Failing closed must not fail closed on everything.
#[test]
fn a_parseable_approved_date_with_no_review_by_lasts_twelve_months() {
    let e = exclusion(None);
    assert!(
        e.is_valid_on("iso27001", day("2027-08-18")),
        "twelve months after the approval date, the last valid day"
    );
    assert!(!e.is_valid_on("iso27001", day("2027-08-19")));
}

/// An unknown framework id is a typo, and a typo must not buy a permanent
/// exclusion. The id is resolved through `ComplianceFramework::from_id`, which
/// accepts the canonical ids and their documented aliases and nothing else.
#[test]
fn an_unknown_framework_id_makes_an_exclusion_invalid() {
    let e = exclusion(None);
    assert!(!e.is_valid_on("iso-270001", day("2026-08-18")));
    assert!(
        !exclusion(Some("2099-01-01")).is_valid_on("iso-270001", day("2026-08-18")),
        "even with an explicit review_by far in the future"
    );
}

/// The profile every host test below is matched against: display name and
/// hostname deliberately different, which is the case `hosts.toml` and the GUI
/// make ordinary, since both show the name and neither shows the target.
fn profile() -> RemoteHostProfile {
    RemoteHostProfile {
        name: "web-01".to_string(),
        hostname: "web-01.example.net".to_string(),
        user: Some("root".to_string()),
        port: 22,
        key_file: None,
        host_key_checking: true,
    }
}

fn covers(host_entry: &str) -> bool {
    let p = profile();
    let e = ScopeExclusion {
        hosts: vec![host_entry.to_string()],
        ..exclusion(None)
    };
    e.covers_host(&p.target(), &p.hostname, &p.name)
}

/// The rule that must not change: an exclusion naming no hosts covers all of
/// them, which is the common case and the one the verb writes by default.
#[test]
fn an_empty_host_list_covers_every_host() {
    let p = profile();
    assert!(exclusion(None).covers_host(&p.target(), &p.hostname, &p.name));
}

/// The two forms that already worked, kept as the control: whatever the wider
/// matching does, it must not stop matching these.
#[test]
fn the_canonical_target_and_the_bare_hostname_both_match() {
    assert!(covers("root@web-01.example.net:22"), "the target() form");
    assert!(covers("web-01.example.net"), "the bare hostname");
}

/// A user with no port is the spelling an operator reaches for first, and it
/// matched neither form: not `target()`, which always carries `:22`, and not
/// the bare hostname, which carries no user.
#[test]
fn a_user_and_host_without_a_port_matches() {
    assert!(covers("root@web-01.example.net"));
}

/// `name` is a separate field from `hostname` and is the one an operator reads
/// off the inventory or the fleet view, so it is the one they will write.
#[test]
fn the_profile_display_name_matches() {
    assert!(covers("web-01"));
}

/// DNS is case insensitive; a case-sensitive comparison made `WEB-01` a
/// different host from `web-01`.
#[test]
fn host_matching_ignores_case() {
    assert!(covers("WEB-01.EXAMPLE.NET"), "the hostname");
    assert!(covers("Root@Web-01.Example.Net:22"), "the target form");
    assert!(covers("Web-01"), "the display name");
}

/// The negative control. Widening the match must not widen it to everything:
/// a host the exclusion does not name is still not covered.
#[test]
fn a_host_the_exclusion_does_not_name_is_not_covered() {
    assert!(!covers("db-02"));
    assert!(!covers("web-01.example.org"));
}

#[test]
fn the_config_section_parses_from_toml() {
    let toml = r#"
[compliance.not_applicable.iso27001."A.7.1"]
reason = "No physical premises; all infrastructure is cloud-hosted"
approved_by = "eric"
approved_date = "2026-08-18"
ticket = "SEC-412"
review_by = "2027-08-18"
hosts = ["web-01.example.net"]
"#;
    let config: crate::config::HardenerConfig = toml::from_str(toml).expect("parses");
    let entry = config
        .compliance
        .not_applicable
        .get("iso27001")
        .and_then(|f| f.get("A.7.1"))
        .expect("the exclusion is present");
    assert_eq!(entry.ticket.as_deref(), Some("SEC-412"));
    assert_eq!(entry.hosts, vec!["web-01.example.net".to_string()]);
}

/// The section is optional. A config that never mentions compliance must still
/// load, or every existing deployment breaks on upgrade.
#[test]
fn a_config_without_the_section_still_loads() {
    let config: crate::config::HardenerConfig = toml::from_str("[global]\n").expect("parses");
    assert!(config.compliance.not_applicable.is_empty());
}
