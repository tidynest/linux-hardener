//! The Dashboard's hardening area map: one tile per plugin area, in the
//! order the Hardening page lists them, each carrying what the last scan
//! said about that area.
//!
//! The pure half (`area_tiles` and friends) is tested on the host; the
//! component only renders what it returns. An area nobody measured has no
//! band, for the reason the compliance list leaves an unscored framework
//! uncoloured: painting it would say it passed or failed.

use super::configure_section::hardening_areas;
use crate::state::AppState;
use crate::types::{ScanResult, Severity};
use crate::utils::ScoreBand;
use leptos::prelude::*;
use leptos_router::components::A;

/// Live finding counts by severity, with documented deviations kept aside.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Findings a policy exception applies to. Not violations, so they are
    /// outside the five counts and outside the band, the same split the
    /// Findings tab makes with `split_policy_excepted`.
    pub excepted: usize,
}

impl LiveCounts {
    fn live_total(self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Counts live findings across results. Shared by the tiles, which pass one
/// result, and the posture strip, which passes them all.
pub fn live_counts(results: &[ScanResult]) -> LiveCounts {
    let mut counts = LiveCounts::default();
    for finding in results.iter().flat_map(|r| &r.scan_findings) {
        if finding.is_policy_excepted() {
            counts.excepted += 1;
            continue;
        }
        match finding.finding_severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    counts
}

/// What the scan said about one area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AreaStatus {
    /// No entry in the results. Before any scan, every area is this.
    NotScanned,
    /// A skip marker rode in: the configuration disabled the plugin.
    DisabledByConfig,
    /// The plugin ran and did not complete.
    Failed,
    /// The plugin ran; the counts are its findings.
    Scanned,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AreaTile {
    /// Short id from the Hardening page table, e.g. `"kernel"`.
    pub id: &'static str,
    /// Display name from the same table, e.g. `"Kernel Hardening"`.
    pub name: &'static str,
    pub status: AreaStatus,
    pub counts: LiveCounts,
    /// `None` unless `status` is `Scanned`.
    pub band: Option<ScoreBand>,
}

/// One tile per area in Hardening page order, whatever the results hold.
pub fn area_tiles(results: &[ScanResult]) -> Vec<AreaTile> {
    hardening_areas()
        .map(|(id, name)| {
            let entry = results
                .iter()
                .find(|r| hardener_types::plugin_id_named_by(r.scan_plugin_id.as_str(), id));
            let status = match entry {
                None => AreaStatus::NotScanned,
                Some(r) if r.scan_skipped.is_some() => AreaStatus::DisabledByConfig,
                Some(r) if !r.scan_success => AreaStatus::Failed,
                Some(_) => AreaStatus::Scanned,
            };
            let counts = entry.map_or_else(LiveCounts::default, |r| {
                live_counts(std::slice::from_ref(r))
            });
            let band = (status == AreaStatus::Scanned).then(|| band_for(counts));
            AreaTile {
                id,
                name,
                status,
                counts,
                band,
            }
        })
        .collect()
}

/// Worst live severity present decides the band. Info and Low are Good:
/// they are the findings a hardened host is allowed to carry.
fn band_for(counts: LiveCounts) -> ScoreBand {
    if counts.critical > 0 {
        ScoreBand::Critical
    } else if counts.high > 0 || counts.medium > 0 {
        ScoreBand::Warning
    } else {
        ScoreBand::Good
    }
}

/// Modifier class for a tile. Six states, not three: the three unmeasured
/// states must not share a colour with any measured one.
pub fn area_tile_class(tile: &AreaTile) -> &'static str {
    match (tile.status, tile.band) {
        (AreaStatus::Scanned, Some(ScoreBand::Critical)) => "area-critical",
        (AreaStatus::Scanned, Some(ScoreBand::Warning)) => "area-warning",
        (AreaStatus::Scanned, _) => "area-good",
        (AreaStatus::NotScanned, _) => "area-unscanned",
        (AreaStatus::DisabledByConfig, _) => "area-disabled",
        (AreaStatus::Failed, _) => "area-failed",
    }
}

/// The tile's one-line status, and part of the link's accessible name.
pub fn area_status_text(tile: &AreaTile) -> String {
    match tile.status {
        AreaStatus::NotScanned => "Not scanned".to_string(),
        AreaStatus::DisabledByConfig => "Disabled by config".to_string(),
        AreaStatus::Failed => "Scan failed".to_string(),
        AreaStatus::Scanned => {
            let c = tile.counts;
            let parts: Vec<String> = [
                (c.critical, "critical"),
                (c.high, "high"),
                (c.medium, "medium"),
                (c.low, "low"),
                (c.info, "info"),
            ]
            .into_iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, label)| format!("{n} {label}"))
            .collect();
            if parts.is_empty() {
                "No findings".to_string()
            } else {
                parts.join(", ")
            }
        }
    }
}

/// Class for one digit of the tile's count row. A zero is still rendered,
/// so the four columns line up across tiles, but it is painted muted so a
/// row of zeros reads as quiet rather than as four alarms that happen to
/// say nothing.
fn count_class(kind: &str, n: usize) -> String {
    let zero = if n == 0 { " area-count-zero" } else { "" };
    format!("area-count area-count-{kind}{zero}")
}

/// Findings go to Analysis, where they are listed; everything else goes to
/// Hardening, where an unscanned or clean area is acted on.
pub fn area_href(tile: &AreaTile) -> &'static str {
    if tile.status == AreaStatus::Scanned && tile.counts.live_total() > 0 {
        "/analysis"
    } else {
        "/hardening"
    }
}

/// Eight tiles, one per hardening area, each a link to where the area is
/// acted on. Rebuilt from `area_tiles` whenever `scan_results` changes.
#[component]
pub fn AreaMap() -> impl IntoView {
    let app_state = expect_context::<AppState>();
    let tiles = move || area_tiles(&app_state.scan_results.get());

    view! {
        <section class="area-map" aria-labelledby="area-map-title">
            <h2 id="area-map-title" class="area-map-title">"Hardening areas"</h2>
            <ul class="area-grid">
                {move || tiles().into_iter().map(|tile| {
                    let cls = format!("area-tile {}", area_tile_class(&tile));
                    let href = area_href(&tile);
                    let status = area_status_text(&tile);
                    let c = tile.counts;
                    // Option<View> renders nothing for None: cheaper than a
                    // Show, and nothing here needs to be Copy.
                    let counts = (tile.status == AreaStatus::Scanned).then(|| view! {
                        <span class="area-counts" aria-hidden="true">
                            <span class=count_class("critical", c.critical)>{c.critical.to_string()}</span>
                            <span class=count_class("high", c.high)>{c.high.to_string()}</span>
                            <span class=count_class("medium", c.medium)>{c.medium.to_string()}</span>
                            <span class=count_class("low", c.low)>{c.low.to_string()}</span>
                        </span>
                    });
                    let excepted = (c.excepted > 0).then(|| view! {
                        <span class="area-excepted">{format!("{} excepted", c.excepted)}</span>
                    });
                    view! {
                        <li class=cls data-area=tile.id>
                            <A href=href attr:class="area-tile-link">
                                <span class="area-name">{tile.name}</span>
                                <span class="area-status">{status}</span>
                                {counts}
                                {excepted}
                            </A>
                        </li>
                    }
                }).collect::<Vec<_>>()}
            </ul>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ExceptionOutcome, Finding, FindingCategory, FindingPolicyException, PluginId,
    };
    use hardener_types::SkipReason;

    fn finding(sev: Severity, exception: ExceptionOutcome) -> Finding {
        Finding {
            finding_category: FindingCategory::Kernel,
            finding_current_value: "a".to_string(),
            finding_description: "d".to_string(),
            finding_explanation: "e".to_string(),
            finding_id: "f".to_string(),
            finding_impact: "i".to_string(),
            finding_recommended_value: "b".to_string(),
            finding_remediation_steps: vec![],
            finding_severity: sev,
            finding_title: "t".to_string(),
            finding_compliance: vec![],
            finding_exception: exception,
            finding_exception_key: None,
        }
    }

    fn live(sev: Severity) -> Finding {
        finding(sev, ExceptionOutcome::NotConfigured)
    }

    fn result(
        id: &str,
        success: bool,
        skipped: Option<SkipReason>,
        findings: Vec<Finding>,
    ) -> ScanResult {
        ScanResult {
            scan_plugin_id: PluginId::new(id),
            scan_success: success,
            scan_findings: findings,
            scan_unchecked: vec![],
            scan_duration_us: 0,
            scan_error: None,
            scan_skipped: skipped,
        }
    }

    fn tile<'a>(tiles: &'a [AreaTile], id: &str) -> &'a AreaTile {
        tiles.iter().find(|t| t.id == id).expect("area exists")
    }

    /// Absence is never rendered as clean: with no results every area is
    /// NotScanned, unbanded, and in the order the Hardening page uses.
    #[test]
    fn every_area_has_a_tile_in_hardening_page_order_with_no_results() {
        let tiles = area_tiles(&[]);
        let ids: Vec<&str> = tiles.iter().map(|t| t.id).collect();
        assert_eq!(
            ids,
            [
                "kernel",
                "ssh",
                "firewall",
                "pam",
                "service",
                "audit",
                "permissions",
                "mac"
            ]
        );
        assert!(tiles.iter().all(|t| t.status == AreaStatus::NotScanned));
        assert!(tiles.iter().all(|t| t.band.is_none()));
        assert!(tiles.iter().all(|t| t.counts == LiveCounts::default()));
    }

    /// The backend speaks full registry ids and the table holds short ones,
    /// joined by `plugin_id_named_by`, the drift `plugin_display_name`
    /// documents.
    #[test]
    fn a_tile_is_matched_by_registry_id_segment_and_counts_by_severity() {
        let tiles = area_tiles(&[
            result(
                "kernel-hardening",
                true,
                None,
                vec![live(Severity::Critical), live(Severity::High)],
            ),
            result(
                "service-minimisation",
                true,
                None,
                vec![live(Severity::Medium), live(Severity::Low)],
            ),
        ]);
        let kernel = tile(&tiles, "kernel");
        assert_eq!(kernel.status, AreaStatus::Scanned);
        assert_eq!((kernel.counts.critical, kernel.counts.high), (1, 1));
        let service = tile(&tiles, "service");
        assert_eq!((service.counts.medium, service.counts.low), (1, 1));
        assert_eq!(tile(&tiles, "audit").status, AreaStatus::NotScanned);
    }

    #[test]
    fn band_follows_the_worst_live_severity() {
        let band = |findings: Vec<Finding>| {
            tile(
                &area_tiles(&[result("kernel", true, None, findings)]),
                "kernel",
            )
            .band
        };
        assert_eq!(
            band(vec![live(Severity::Critical), live(Severity::Low)]),
            Some(ScoreBand::Critical)
        );
        assert_eq!(band(vec![live(Severity::High)]), Some(ScoreBand::Warning));
        assert_eq!(band(vec![live(Severity::Medium)]), Some(ScoreBand::Warning));
        assert_eq!(band(vec![live(Severity::Low)]), Some(ScoreBand::Good));
        assert_eq!(band(vec![]), Some(ScoreBand::Good));
    }

    /// An unassessed area shows no findings and must not look like a clean
    /// one: the T-FIND-13 concern, moved onto the tiles.
    #[test]
    fn a_skip_marker_or_a_failed_scan_is_never_read_as_clean() {
        let tiles = area_tiles(&[
            result("pam", true, Some(SkipReason::DisabledByConfig), vec![]),
            result("ssh", false, None, vec![]),
        ]);
        let pam = tile(&tiles, "pam");
        assert_eq!(pam.status, AreaStatus::DisabledByConfig);
        assert_eq!(pam.band, None);
        assert_eq!(area_href(pam), "/hardening");
        let ssh = tile(&tiles, "ssh");
        assert_eq!(ssh.status, AreaStatus::Failed);
        assert_eq!(ssh.band, None);
        assert_eq!(area_tile_class(ssh), "area-failed");
    }

    /// Matches the Findings tab's split, so the Dashboard and Analysis cannot
    /// disagree on whether an area has a problem.
    #[test]
    fn an_applied_exception_leaves_both_the_counts_and_the_band() {
        let excepted = finding(
            Severity::Medium,
            ExceptionOutcome::Applied(FindingPolicyException::default()),
        );
        let tiles = area_tiles(&[result(
            "service",
            true,
            None,
            vec![excepted, live(Severity::Low)],
        )]);
        let service = tile(&tiles, "service");
        assert_eq!(service.counts.medium, 0);
        assert_eq!(service.counts.excepted, 1);
        assert_eq!(service.band, Some(ScoreBand::Good));
        assert_eq!(area_href(service), "/analysis");
        assert_eq!(area_status_text(service), "1 low");
    }
}
