# hardener-ui — Crate Audit

**Files:** 33 | **Lines:** 4,574 | **Fixes:** 3 | **Design Flags:** 2

## Purpose

Leptos/WASM frontend for the Linux System Hardener Tauri desktop application. Provides a reactive single-page UI with routing, theme switching, and Tauri IPC bindings for scan, apply, compliance, and rollback operations.

## Architecture

```
lib.rs (App + Router, 5 routes)
    │
    ├── pages/
    │   ├── DashboardPage   → SecurityScore + QuickActions + RecentActivity
    │   ├── AnalysisPage    → Tabs(Findings / Compliance / ScanHistory)
    │   ├── HardeningPage   → Sections(Configure / History)
    │   ├── RemotePage      → HostList + HostForm + RemoteStatus
    │   └── SchedulerPage   → ScheduleSection + NotificationSection
    │
    ├── components/         → 22 reusable UI components
    ├── state/              → AppState (21 RwSignals)
    ├── tauri_bindings      → 24 Tauri IPC async functions
    ├── types               → Re-exports from hardener-types + CheckpointInfo
    └── utils/mock_data     → 3 mock ScanResults for dev
```

## Module Map

| Module | Lines | Role |
|--------|-------|------|
| `tauri_bindings.rs` | 404 | Tauri IPC WASM bindings (24 async functions) |
| `components/history_section.rs` | 398 | Checkpoint table + rollback |
| `components/configure_section.rs` | 315 | Profile selection, plugin toggles, preview/apply |
| `components/schedule_section.rs` | 266 | Cron schedule config + plugin selection |
| `components/notification_section.rs` | 255 | Email + webhook notification settings |
| `components/compliance_tab.rs` | 239 | Framework selection + report generation |
| `components/security_score.rs` | 217 | Weighted scoring algorithm + display |
| `components/host_form.rs` | 193 | Remote host SSH profile form |
| `components/host_list.rs` | 188 | Remote host list with connect/delete |
| `components/config_file_card.rs` | 163 | Config file picker + validation summary |
| `components/findings_tab.rs` | 160 | FindingsGrid + FindingDetail + severity filter |
| `components/remote_status.rs` | 149 | Remote connection status + scan trigger |
| `components/scan_history_tab.rs` | 133 | Scan history list + session detail |
| `lib.rs` | 123 | Crate root, App, Router (5 routes), DOM bootstrap |
| `pages/analysis_page.rs` | 119 | Tabbed findings/compliance/history |
| `utils/mock_data.rs` | 106 | Mock scan results for testing |
| `components/tabs.rs` | 102 | WAI-ARIA tabs pattern |
| `components/quick_actions.rs` | 99 | Dashboard action buttons |
| `state/mod.rs` | 98 | AppState (21 RwSignals) |
| `components/recent_activity.rs` | 97 | Last scan/apply summary |
| `components/theme_toggle.rs` | 91 | 6 themes + localStorage |
| `components/finding_detail.rs` | 85 | Finding detail panel |
| `components/card.rs` | 79 | Reusable card container |
| `pages/hardening_page.rs` | 71 | Configure/History toggle |
| `components/findings_grid.rs` | 66 | Findings table with row click |
| `types.rs` | 53 | Re-exports + CheckpointInfo |
| `components/mini_security_score.rs` | 52 | Compact score badge |
| `pages/remote_page.rs` | 51 | Remote scanning layout |
| `components/mod.rs` | 46 | 22-component re-export root |
| `components/severity_badge.rs` | 39 | Colour-coded severity display |
| `pages/scheduler_page.rs` | 38 | Scheduler layout |
| `pages/dashboard_page.rs` | 35 | Dashboard layout |
| `pages/mod.rs` | 11 | Page re-exports (5 pages) |
| `components/form_helpers.rs` | 30 | Shared JsCast event extraction |
| `utils/mod.rs` | 3 | Utils module root |

## Fixes Applied

| # | File | Fix | Severity |
|---|------|-----|----------|
| 1 | security_score.rs:1-3 | Added missing `//!` module doc | DOC |
| 2 | security_score.rs:59 | `partial_cmp().unwrap()` → `.unwrap_or(Ordering::Equal)` (NaN safety) | SAFETY |
| 3 | history_section.rs:84 | `.unwrap()` → `.expect("guarded by Show when=")` | CLIPPY |

## Design Flags (Deferred)

| # | File | Flag |
|---|------|------|
| D1 | severity_badge.rs:1 | Missing `//!` module doc (cosmetic) |
| D2 | components/mod.rs:16 | `#[allow(unused_imports)]` on CardVariant (API completeness) |

## Accessibility

- Skip-link in App root (`<a href="#main-content">`)
- WAI-ARIA tabs: `role="tablist"`, `aria-selected`, `aria-controls`, `tabindex`
- Error banner: `role="alert"`
- Theme select: `<label class="sr-only">`
- Semantic HTML: `<article>`, `<header>`, `<nav>`, `<aside>`, `<main>`
