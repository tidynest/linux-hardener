# Theme Design Guide

This document explains the theming system for Linux Hardener's GUI and provides guidelines for creating new themes.

---

## Theme Architecture Overview

### How Themes Work

The theming system uses CSS custom properties (variables) with a `[data-theme]` attribute selector pattern:

1. **Base styles** are defined in `:root, [data-theme="default"]` (the default
   "Midnight Teal" theme)
2. **Theme overrides** use `[data-theme="theme-name"]` selectors
3. **A single Effect** in `App` sets the `data-theme` attribute on the `<html>` element
4. **Persistence** uses localStorage to remember the user's choice

There are seven themes in total: the default plus six overrides.
`THEMES` in `crates/hardener-ui/src/utils/theme.rs` is the single list, and
`apply_theme` there is the only writer of the attribute.

The base block is deliberately written as the pair `:root, [data-theme="default"]`
rather than `:root` alone. `apply_theme` **removes** the attribute for the
default theme instead of setting it, so `:root` is what actually styles the page.
The extra `[data-theme="default"]` selector exists so the default theme's preview
card in the Settings swatch grid can render its own colours while a different
theme is active: without it, that one card would inherit whichever theme is
currently applied and show the wrong palette.

There are three theme controls, and all three simply write the shared
`AppState.theme` signal rather than touching the DOM or storage themselves:

- The **Settings > Appearance swatch grid** (`ThemePicker`, a keyboard-navigable
  WAI-ARIA radiogroup of live-coloured preview cards) is the primary selector.
- The **sidebar quick-switch dropdown** (`ThemeToggle`) offers the same choice
  without leaving the current page. It is hidden while the sidebar is in rail
  mode.
- **Alt+T** cycles to the next theme in `THEMES` order, wrapping at the end
  (`cycle_theme` in `crates/hardener-ui/src/keyboard.rs`).

Adding a fourth control means writing that signal, never calling `apply_theme`
or `store_theme` directly. Those two are the Effect's business alone.

```
User selects theme
 (ThemePicker grid, ThemeToggle dropdown, or Alt+T)
        │
        ▼
┌───────────────────────┐
│ AppState.theme signal │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────────────────────┐
│ Effect in App (lib.rs)                │
│ utils::theme::apply_theme()           │
│ utils::theme::store_theme()           │
└───────────┬───────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│ <html data-theme="fortress">          │
└───────────┬───────────────────────────┘
            │
            ▼
┌───────────────────────────────────────┐
│ CSS: [data-theme="fortress"] {        │
│   --bg-primary: #0c1222;              │
│   --color-accent: #fbbf24;            │
│   /* ... other overrides */           │
│ }                                     │
└───────────────────────────────────────┘
```

### File Locations

| File | Purpose |
|------|---------|
| `crates/hardener-ui/styles.css` | All theme CSS variables |
| `crates/hardener-ui/src/utils/theme.rs` | `THEMES` list plus the `apply_theme`/`get_stored_theme`/`store_theme` helpers; the only writer of `<html data-theme>` and the `theme` localStorage key |
| `crates/hardener-ui/src/components/theme_picker.rs` | Settings page swatch grid (`ThemePicker`), the primary theme selector |
| `crates/hardener-ui/src/components/theme_toggle.rs` | Sidebar quick-switch dropdown (`ThemeToggle`); writes `AppState.theme` |
| `crates/hardener-ui/src/keyboard.rs` | `cycle_theme`, the Alt+T shortcut; writes `AppState.theme` |
| `crates/hardener-ui/src/state/mod.rs` | `AppState.theme`, the `RwSignal<String>` every control writes, initialised to `"default"` |
| `crates/hardener-ui/src/lib.rs` | The `App` component's single `Effect` that applies and persists the theme whenever `AppState.theme` changes |

---

## Colour Variable Categories

The theme system defines six categories of themed variable. Every one of the six
override themes sets the same 24 variables, so a new theme that sets fewer will
inherit the default's value for the rest and look subtly wrong rather than
obviously broken.

### 1. Background Colours

Used for layered surfaces (darker = lower level):

| Variable | Purpose | Example Usage |
|----------|---------|---------------|
| `--bg-primary` | Base/deepest background | Page body |
| `--bg-secondary` | Elevated surfaces | Cards, panels |
| `--bg-tertiary` | Interactive surfaces | Table headers, hover states |
| `--bg-elevated` | Highest layer | Dropdowns, modals |

### 2. Text Colours

For readability hierarchy:

| Variable | Purpose | Contrast Requirement |
|----------|---------|---------------------|
| `--text-primary` | Main content | WCAG AA (4.5:1) |
| `--text-secondary` | Supporting text | WCAG AA (4.5:1) |
| `--text-muted` | Tertiary/disabled | WCAG AA (4.5:1) |

### 3. Semantic Colours

For status and severity indication:

| Variable | Purpose | Bright Variant |
|----------|---------|---------------|
| `--color-good` | Success, safe | `--color-good-bright` |
| `--color-warning` | Caution, medium severity | `--color-warning-bright` |
| `--color-critical` | Error, high severity | `--color-critical-bright` |
| `--color-info` | Information, low severity | - |
| `--color-pending` | Unknown, awaiting | - |

### 4. Interactive Colours

For user interaction feedback:

| Variable | Purpose |
|----------|---------|
| `--color-accent` | Primary brand/action colour |
| `--color-accent-hover` | Hover state for accent |
| `--color-focus` | Focus ring colour (transparent) |

### 5. Status Tints

Low-alpha fills for badges and calm boxes, layered over the background tiers:

| Variable | Purpose |
|----------|---------|
| `--color-good-bg` | Pass and success fills |
| `--color-warning-bg` | Caution and medium-severity fills |
| `--color-critical-bg` | Error and high-severity fills |
| `--color-accent-bg` | Selected and accented surfaces |

These are `rgba()` values rather than hex, because they sit on top of a
background tier and must not hide it.

### 6. Borders

| Variable | Purpose |
|----------|---------|
| `--border` | Hairline separators, themed per file |
| `--border-strong` | Emphasis and hover borders |

Every theme overrides both. A light theme is not a special case here: `daywatch`
sets `--border: #d6d3d1` through the same variable the dark themes use.

### Button Styles

`.btn-primary` is the one hard-coded button colour, at `#065f46` with `#047857`
on hover. It was chosen over the default green to meet the WCAG AA contrast
requirement (4.5:1) for white text on a coloured background, and it does not
change with the theme.

---

## Current Themes

### Default (Midnight Teal), id `default`

The base theme. Cool, professional aesthetic with teal accents. It also carries
everything that is not themed: typography, the spacing and radius scales, layout
sizes, z-index tiers, shadows and transitions all live in this one block and are
never overridden per theme.

```css
:root,
[data-theme="default"] {
  --bg-primary: #0f1419;
  --color-accent: #22d3ee;
  /* ... */
}
```

### Theme Overrides

Each theme overrides the same 24 base variables:

| Theme | id | Identity | Accent Colour | Background Family |
|-------|----|----------|---------------|-------------------|
| **Fortress** | `fortress` | Strategic, vault-like | Gold #fbbf24 | Deep slate-blue #0c1222 |
| **Sentinel** | `sentinel` | Vigilant, warm | Amber #f59e0b | Warm charcoal #1a1614 |
| **Command** | `command` | Military precision | Ice-blue #38bdf8 | Deep navy #0a0e1a |
| **Guardian** | `guardian` | Protective, natural | Emerald #10b981 | Forest black #0c120e |
| **Daywatch** | `daywatch` | Light, productive | Teal #0d9488 | Warm off-white #f8f6f2 |
| **High Contrast** | `high-contrast` | Maximum contrast, WCAG AAA | Cyan #67e8f9 | Pure black #000000 |

Daywatch is the only light theme, and High Contrast is the only theme targeting
WCAG AAA rather than AA.

---

## Creating a New Theme

### Step 1: Define Your Colour Palette

Start with these questions:
- What emotion should the theme evoke? (Security, trust, warmth, precision)
- What's the primary accent colour?
- Is it light mode or dark mode?

Design a palette with:
- 4 background shades (progressive lightening/darkening)
- 3 text shades (high to low contrast)
- 1 primary accent + hover variant, plus a focus ring in the same hue
- 8 semantic colours (base and bright for good, warning and critical, plus info
  and pending)
- 2 border shades
- 4 low-alpha status tints derived from the semantics and the accent

### Step 2: Add CSS Variables Block

Add your theme to `styles.css` after the existing themes, at the end of section
1b. Set all 24 variables. Leaving one out silently inherits the default theme's
value, which is the failure mode that is hardest to spot.

```css
/* Your Theme Name - Brief description */
[data-theme="your-theme"] {
    /* Backgrounds */
    --bg-primary: #??????;
    --bg-secondary: #??????;
    --bg-tertiary: #??????;
    --bg-elevated: #??????;

    /* Text */
    --text-primary: #??????;
    --text-secondary: #??????;
    --text-muted: #??????;

    /* Semantic */
    --color-good: #??????;
    --color-good-bright: #??????;
    --color-warning: #??????;
    --color-warning-bright: #??????;
    --color-critical: #??????;
    --color-critical-bright: #??????;
    --color-info: #??????;
    --color-pending: #??????;

    /* Interactive */
    --color-accent: #??????;
    --color-accent-hover: #??????;
    --color-focus: rgba(?, ?, ?, 0.4);

    /* Borders */
    --border: #??????;
    --border-strong: #??????;

    /* Status tints - keep the alpha low so the surface still reads through */
    --color-good-bg: rgba(?, ?, ?, .15);
    --color-warning-bg: rgba(?, ?, ?, .15);
    --color-critical-bg: rgba(?, ?, ?, .15);
    --color-accent-bg: rgba(?, ?, ?, .12);
}
```

### Step 3: Register the Theme

Add your theme to the `THEMES` array in `crates/hardener-ui/src/utils/theme.rs`.
All three controls read this single array: the sidebar dropdown (`ThemeToggle`)
and the Settings swatch grid (`ThemePicker`) render their options from it, and
Alt+T cycles through it in order. One edit updates all three, and it also
extends what `get_stored_theme` will accept back out of localStorage:

```rust
pub const THEMES: &[(&str, &str)] = &[
    ("default", "Midnight Teal"),
    ("fortress", "Fortress"),
    ("sentinel", "Sentinel"),
    ("command", "Command"),
    ("guardian", "Guardian"),
    ("daywatch", "Daywatch"),
    ("high-contrast", "High Contrast"),
    ("your-theme", "Your Theme Name"),  // Add here
];
```

### Step 4: Test for Accessibility

Verify WCAG AA compliance (4.5:1 contrast ratio):

1. **Text on backgrounds**: Test `--text-primary`, `--text-secondary`, `--text-muted` against all background levels
2. **Interactive elements**: Ensure buttons, links are visible
3. **Semantic colours**: Check severity badges are distinguishable
4. **Focus states**: Verify focus rings are visible

Tools:
- [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)
- [Colour Contrast Analyser](https://www.tpgi.com/color-contrast-checker/)
- Browser DevTools accessibility panel

High Contrast targets WCAG AAA (7:1), so if you are extending that theme rather
than adding a new one, hold it to the stricter ratio.

### Step 5: Visual Testing

1. Run the app: `cd crates/hardener-ui && trunk serve --port 1420`
2. Select your theme from the Settings page swatch grid, the sidebar
   quick-switch dropdown, or Alt+T
3. Navigate all seven routes: `/` (Dashboard), `/analysis`, `/hardening`,
   `/fleet` (Hosts), `/fleet-apply`, `/scheduler`, `/settings`
4. Check:
   - Title colour reflects accent
   - Cards and panels have clear hierarchy
   - Buttons are visible and interactive
   - Tables and badges are readable
   - Empty states and error messages are visible
   - The Settings swatch grid still shows every theme's own colours, including
     the default card, while your theme is the active one

---

## Colour Psychology for Security Tools

When designing security-focused themes, consider these associations:

### Dark Themes (Recommended for Security)

| Colour Family | Psychology | Example Theme |
|---------------|------------|---------------|
| **Deep blues/navy** | Trust, professionalism, stability | Command |
| **Slate/charcoal** | Strength, protection, vault-like | Fortress |
| **Forest/dark green** | Growth, health, natural protection | Guardian |
| **Warm charcoal** | Vigilance, warmth, alertness | Sentinel |

### Accent Colours

| Colour | Psychology | Usage |
|--------|------------|-------|
| **Gold/Amber** | Valuable, protected, premium | High-value actions |
| **Teal/Cyan** | Modern, clean, technological | Tech-forward brand |
| **Emerald** | Healthy, secure, growing | Positive outcomes |
| **Ice blue** | Precision, clarity, command | Technical precision |

### Light Themes

Light themes work well for:
- Daytime use (reduced eye strain)
- Print/screenshot contexts
- Accessibility (some users prefer light)

Use warm off-whites rather than pure white to reduce harshness. Daywatch is the
worked example: `--bg-primary: #f8f6f2` with `--bg-elevated: #ffffff`, so pure
white is reserved for the topmost layer rather than the page.

### High Contrast

High Contrast is the exception to everything above. It is not an aesthetic
choice, it is an accessibility target: pure black `#000000` against pure white
`#ffffff`, semantic colours lifted to their pale variants so they clear 7:1 on
black, and the three semantic tints at `.25` alpha rather than `.15` so a badge
fill is actually visible. Do not "improve" its palette for looks.

---

## Accessibility Requirements

### Minimum Contrast Ratios (WCAG 2.1)

| Level | Ratio | Requirement |
|-------|-------|-------------|
| **AA** | 4.5:1 | Normal text |
| **AA** | 3:1 | Large text (18pt+), UI components |
| **AAA** | 7:1 | Enhanced (optional) |

### Focus States

All interactive elements must have visible focus indicators:

```css
*:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}
```

### Testing Checklist

- [ ] All text meets 4.5:1 contrast against its background
- [ ] Severity badges are distinguishable (not just by colour)
- [ ] Focus rings are visible on all interactive elements
- [ ] Theme works with browser zoom (100%, 150%, 200%)
- [ ] No information is conveyed by colour alone

---

## Theme Variable Reference

The 24 variables every theme sets:

```css
/* Background tiers */
--bg-primary        /* Deepest background */
--bg-secondary      /* Cards, panels */
--bg-tertiary       /* Interactive surfaces */
--bg-elevated       /* Highest layer */

/* Text hierarchy */
--text-primary      /* Main content */
--text-secondary    /* Supporting text */
--text-muted        /* Tertiary text */

/* Semantic status */
--color-good        /* Success base */
--color-good-bright /* Success emphasis */
--color-warning     /* Warning base */
--color-warning-bright /* Warning emphasis */
--color-critical    /* Error base */
--color-critical-bright /* Error emphasis */
--color-info        /* Information */
--color-pending     /* Unknown/waiting */

/* Interactive */
--color-accent      /* Primary action colour */
--color-accent-hover /* Hover state */
--color-focus       /* Focus ring (with alpha) */

/* Borders */
--border            /* Hairline separators */
--border-strong     /* Emphasis and hover */

/* Status tints (rgba, low alpha) */
--color-good-bg     /* Pass fills */
--color-warning-bg  /* Caution fills */
--color-critical-bg /* Error fills */
--color-accent-bg   /* Selected surfaces */
```

Set once in the base block and **not** themed, so a theme block should leave
them alone:

```css
--font-sans, --font-mono
--font-size-caption .. --font-size-title, --leading-ui, --leading-prose
--header-height, --content-padding, --sidebar-width, --sidebar-rail-width
--space-xs .. --space-2xl
--control-height, --control-pad-x, --row-gap, --section-gap
--radius-sm, --radius-md, --radius-lg, --radius-full, --border-radius
--z-skip-link, --z-modal, --z-sticky, --z-dropdown
--shadow-sm, --shadow-md
--transition-fast, --transition-normal, --transition-slow
```

---

**Last Updated**: 2026-08-07
