# hardener-ui — Crate Audit

**Files:** 25 | **Lines:** 2,374 | **Fixes:** 3 | **Design Flags:** 2

## Purpose

Leptos/WASM frontend for the Linux System Hardener Tauri desktop application. Provides a reactive single-page UI with routing, theme switching, and Tauri IPC bindings for scan, apply, compliance, and rollback operations.

## Architecture

```
lib.rs (App + Router)
    │
    ├── pages/
    │   ├── DashboardPage   → SecurityScore + QuickActions + RecentActivity
    │   ├── AnalysisPage    → Tabs(Findings / Compliance)
    │   └── HardeningPage   → Sections(Configure / History)
    │
    ├── components/         → 14 reusable UI components
    ├── state/              → AppState (11 RwSignals)
    ├── tauri_bindings      → 8 Tauri IPC async functions
    ├── types               → Re-exports from hardener-types + CheckpointInfo
    └── utils/mock_data     → 3 mock ScanResults for dev
```

## Module Map

| Module | Lines | Role |
|--------|-------|------|
| `components/configure_section.rs` | 315 | Profile selection, plugin toggles, preview/apply |
| `components/security_score.rs` | 218 | Weighted scoring algorithm + display |
| `components/history_section.rs` | 193 | Checkpoint table + rollback |
| `components/compliance_tab.rs` | 183 | Framework selection + report generation |
| `tauri_bindings.rs` | 141 | Tauri IPC WASM bindings |
| `lib.rs` | 119 | Crate root, App, Router, DOM bootstrap |
| `pages/analysis_page.rs` | 108 | Tabbed findings/compliance |
| `utils/mock_data.rs` | 106 | Mock scan results for testing |
| `components/tabs.rs` | 102 | WAI-ARIA tabs pattern |
| `components/quick_actions.rs` | 99 | Dashboard action buttons |
| `components/recent_activity.rs` | 97 | Last scan/apply summary |
| `components/theme_toggle.rs` | 89 | 6 themes + localStorage |
| `components/finding_detail.rs` | 85 | Finding detail panel |
| `components/card.rs` | 79 | Reusable card container |
| `components/findings_grid.rs` | 76 | Findings table with row click |
| `pages/hardening_page.rs` | 71 | Configure/History toggle |
| `state/mod.rs` | 57 | AppState (11 RwSignals) |
| `components/findings_tab.rs` | 55 | FindingsGrid + FindingDetail wrapper |
| `components/mini_security_score.rs` | 52 | Compact score badge |
| `components/severity_badge.rs` | 39 | Colour-coded severity display |
| `pages/dashboard_page.rs` | 35 | Dashboard layout |
| `components/mod.rs` | 31 | 14-component re-export root |
| `types.rs` | 20 | Re-exports + CheckpointInfo |
| `pages/mod.rs` | 7 | Page re-exports |
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
