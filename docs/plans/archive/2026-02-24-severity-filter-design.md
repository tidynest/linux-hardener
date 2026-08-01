# Severity Filter: GUI Design

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Date**: 2026-02-24
**Status**: Implemented
**Priority**: P0 (v0.4.0 GUI/CLI Parity)

## Summary

Add a client-side severity filter dropdown to the findings tab header. Users select a minimum severity level; only findings at or above that level are shown. The count updates to reflect filtered vs total findings.

## UI Layout

```
┌─────────────────────────────────────────────┐
│ 12 of 47 findings detected   [Min: ▼ High] │
├─────────────────────────────────────────────┤
│ Sev  │ Category │ Title  │ Current │ Rec'd │
│ CRIT │ Kernel   │ ...    │ ...     │ ...   │
│ HIGH │ SSH      │ ...    │ ...     │ ...   │
└─────────────────────────────────────────────┘
```

## Changes

| File | Change |
|------|--------|
| `state/mod.rs` | Add `severity_filter: RwSignal<Option<Severity>>` |
| `findings_tab.rs` | Dropdown in header, filter logic, "X of Y" count |
| `findings_grid.rs` | Accept `Vec<Finding>` prop instead of reading state directly |

## Data Flow

```
Dropdown change → severity_filter signal (Option<Severity>)
  → findings_tab filters: finding.finding_severity >= threshold
  → filtered vec passed as prop to FindingsGrid
  → count shows "X of Y findings detected"
```

## Design Decisions

- **Client-side filtering**: All findings stay in memory; no re-scan needed. Instant toggle.
- **`Option<Severity>`**: `None` = show all (default), `Some(level)` = minimum threshold.
- **Existing `PartialOrd`**: `Severity` already derives `Ord`, so `>=` comparison works.
- **Existing CSS**: `.severity-filter` styles already in `styles.css`.
