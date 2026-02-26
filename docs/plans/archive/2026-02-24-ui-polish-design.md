# UI Polish Pass — Design

## Goal

Eliminate wasted space across all four pages (Dashboard, Remote, Hardening, Scheduler) in a single pass. Fix empty-state sizing, introduce side-by-side layouts where content is compact, and add directional guidance in empty states.

## Decisions

| Decision | Choice |
|----------|--------|
| Scope | All four pages |
| Empty states | Hybrid — fill with guidance where useful, collapse where unnecessary |
| Side-by-side pattern | Match Scheduler's `flex-row` + fix height-matching via `align-self: start` |
| Remote idle state | Keep two-panel, fill right side with quick-start guide, drop `min-height` |

## Shared CSS

One reusable class for all side-by-side layouts:

```css
.two-col-row {
    display: flex;
    gap: var(--space-lg);
}
.two-col-row > * {
    flex: 1;
    min-width: 0;
    align-self: start;
}
@media (max-width: 768px) {
    .two-col-row { flex-direction: column; }
}
```

## Per-Page Changes

### 1. Dashboard

- Remove `flex: 1 1 auto` from `.recent-activity` — let it size to content
- Improve empty state: "Run a scan from Quick Actions to see activity here"

### 2. Remote Page

- Drop `min-height: 400px` on `.remote-layout`
- Replace single-line placeholder with numbered quick-start guide:
  1. Add a host using the sidebar
  2. Click Connect to establish SSH
  3. Run a remote scan
- Guide hidden when connection is active (existing `Show` conditional)

### 3. Hardening — Configure Tab

- Profile + Plugin Control: side-by-side using `.two-col-row`
- ConfigFileCard: stays full-width above (spans both columns)
- Apply Controls: remove wrapper card, standalone button below the row

### 4. Hardening — History Tab

- Latest Apply + Latest Rollback: side-by-side using `.two-col-row`
- Empty states get directional text pointing users to the right action
- System Checkpoints table: stays full-width below

### 5. Scheduler

- Replace `flex: 1` height-matching with `align-self: start` on both cards
- Each card sizes to its own content instead of stretching to match sibling
