//! `hardener batch scan` — scan many remote hosts concurrently.

use anyhow::{Result, anyhow, bail};
use hardener_common::types::Severity;
use hardener_core::plugin::Finding;
use hardener_types::remote::{HostsConfig, RemoteHostProfile};
use serde::Serialize;

/// Per-severity tally of one host's findings.
// Consumed by the batch-scan command wired up in a later task.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[allow(dead_code)]
impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut c = SeverityCounts::default();
        for f in findings {
            match f.finding_severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                _ => {} // Info and below are not counted in the rollup
            }
        }
        c
    }
}

/// Outcome of scanning one host.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum HostStatus {
    Scanned {
        counts: SeverityCounts,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        findings: Vec<Finding>,
    },
    Failed {
        error: String,
    },
}

/// One host's batch result. `name` is the inventory name (or target for ad-hoc
/// hosts); `target` is `user@host:port` for display.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize)]
pub struct HostOutcome {
    pub name: String,
    pub target: String,
    #[serde(flatten)]
    pub status: HostStatus,
}

/// Tiered exit code: 0 = all clean, 1 = findings present, 2 = any host errored.
#[allow(dead_code)]
pub fn exit_code(outcomes: &[HostOutcome]) -> i32 {
    let mut code = 0;
    for o in outcomes {
        match &o.status {
            HostStatus::Failed { .. } => return 2,
            HostStatus::Scanned { counts, .. } if counts.total() > 0 => code = 1,
            HostStatus::Scanned { .. } => {}
        }
    }
    code
}

/// Parses an ad-hoc `--ssh user@host` target into a profile. Port and key come
/// from the global SSH flags (defaults applied by the caller).
#[allow(dead_code)]
pub fn parse_inline(
    target: &str,
    port: u16,
    key_file: Option<String>,
    verify: bool,
) -> RemoteHostProfile {
    let (user, hostname) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target.to_string()),
    };
    RemoteHostProfile {
        name: hostname.clone(),
        hostname,
        user,
        port,
        key_file,
        host_key_checking: verify,
    }
}

/// Resolves the host set to scan from inventory selection plus inline hosts.
/// De-duplicates by `name`, inventory taking precedence. Unknown `--host` names
/// are an error so a typo never silently scans nothing.
#[allow(dead_code)]
pub fn resolve_hosts(
    inventory: &HostsConfig,
    all: bool,
    names: &[String],
    inline: Vec<RemoteHostProfile>,
) -> Result<Vec<RemoteHostProfile>> {
    let mut selected: Vec<RemoteHostProfile> = if all {
        inventory.hosts.clone()
    } else {
        names
            .iter()
            .map(|n| {
                inventory
                    .hosts
                    .iter()
                    .find(|h| &h.name == n)
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown host '{n}' (not in inventory)"))
            })
            .collect::<Result<Vec<_>>>()?
    };

    for profile in inline {
        if !selected.iter().any(|h| h.name == profile.name) {
            selected.push(profile);
        }
    }

    if selected.is_empty() {
        bail!("no hosts selected: use --all, --host <names>, or --ssh <user@host>");
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_common::types::{FindingCategory, Severity};

    fn finding(sev: Severity) -> Finding {
        Finding {
            finding_category: FindingCategory::Kernel,
            finding_current_value: String::new(),
            finding_description: String::new(),
            finding_explanation: String::new(),
            finding_id: "x".into(),
            finding_impact: String::new(),
            finding_recommended_value: String::new(),
            finding_remediation_steps: vec![],
            finding_severity: sev,
            finding_title: "t".into(),
            finding_compliance: vec![],
            finding_policy_exception: None,
        }
    }

    fn scanned(total_high: usize) -> HostOutcome {
        HostOutcome {
            name: "h".into(),
            target: "u@h:22".into(),
            status: HostStatus::Scanned {
                counts: SeverityCounts {
                    high: total_high,
                    ..Default::default()
                },
                findings: vec![],
            },
        }
    }

    fn failed() -> HostOutcome {
        HostOutcome {
            name: "h".into(),
            target: "u@h:22".into(),
            status: HostStatus::Failed {
                error: "boom".into(),
            },
        }
    }

    #[test]
    fn exit_code_tiers() {
        assert_eq!(exit_code(&[scanned(0)]), 0);
        assert_eq!(exit_code(&[scanned(0), scanned(3)]), 1);
        assert_eq!(exit_code(&[scanned(3), failed()]), 2);
        assert_eq!(exit_code(&[]), 0);
    }

    fn inv() -> HostsConfig {
        HostsConfig {
            hosts: vec![profile("web-01"), profile("db-02")],
        }
    }
    fn profile(name: &str) -> RemoteHostProfile {
        RemoteHostProfile {
            name: name.into(),
            hostname: format!("{name}.local"),
            user: Some("admin".into()),
            port: 22,
            key_file: None,
            host_key_checking: true,
        }
    }

    #[test]
    fn resolve_all_returns_inventory() {
        let r = resolve_hosts(&inv(), true, &[], vec![]).unwrap();
        assert_eq!(r.len(), 2);
    }
    #[test]
    fn resolve_named_subset() {
        let r = resolve_hosts(&inv(), false, &["db-02".into()], vec![]).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "db-02");
    }
    #[test]
    fn resolve_unknown_name_errors() {
        assert!(resolve_hosts(&inv(), false, &["nope".into()], vec![]).is_err());
    }
    #[test]
    fn resolve_dedups_inline_against_inventory() {
        let inline = vec![parse_inline("admin@web-01", 22, None, true)];
        let r = resolve_hosts(&inv(), true, &[], inline).unwrap();
        assert_eq!(r.len(), 2, "inline duplicate of inventory host is dropped");
    }
    #[test]
    fn resolve_empty_errors() {
        assert!(resolve_hosts(&HostsConfig::default(), false, &[], vec![]).is_err());
    }
    #[test]
    fn parse_inline_splits_user() {
        let p = parse_inline("root@10.0.0.5", 2222, None, false);
        assert_eq!(p.user.as_deref(), Some("root"));
        assert_eq!(p.hostname, "10.0.0.5");
        assert_eq!(p.port, 2222);
        assert!(!p.host_key_checking);
    }

    #[test]
    fn counts_tally_by_severity() {
        let f = vec![
            finding(Severity::Critical),
            finding(Severity::High),
            finding(Severity::High),
            finding(Severity::Low),
        ];
        let c = SeverityCounts::from_findings(&f);
        assert_eq!(
            c,
            SeverityCounts {
                critical: 1,
                high: 2,
                medium: 0,
                low: 1
            }
        );
        assert_eq!(c.total(), 4);
    }
}
