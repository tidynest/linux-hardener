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
| `crates/hardener-ui/styles.css` | All theme CSS variables, and the two `@font-face` rules at the top |
| `crates/hardener-ui/fonts/` | The bundled faces, latin subset, OFL licences beside them: Martian Mono (variable weight and width; the display face at full width, the data mono at `--stretch-data`) and IBM Plex Sans (variable weight; the body face). Copied into `dist/` by the `copy-dir` link in `index.html` and served from the app's own origin, which the Tauri CSP allows |
| `crates/hardener-ui/src/utils/theme.rs` | `THEMES` list plus the `apply_theme`/`get_stored_theme`/`store_theme` helpers; the only writer of `<html data-theme>` and the `theme` localStorage key |
| `crates/hardener-ui/src/components/theme_picker.rs` | Settings page swatch grid (`ThemePicker`), the primary theme selector |
| `crates/hardener-ui/src/components/theme_toggle.rs` | Sidebar quick-switch dropdown (`ThemeToggle`); writes `AppState.theme` |
| `crates/hardener-ui/src/keyboard.rs` | `cycle_theme`, the Alt+T shortcut; writes `AppState.theme` |
| `crates/hardener-ui/src/state/mod.rs` | `AppState.theme`, the `RwSignal<String>` every control writes, initialised to `"default"` |
| `crates/hardener-ui/src/lib.rs` | The `App` component's single `Effect` that applies and persists the theme whenever `AppState.theme` changes |

---

## Colour Variable Categories

The theme system defines seven categories of themed variable. Every override
theme sets the same 32: the 24 palette variables and the eight ink-frame ones
(category 7 below), so a new theme that sets fewer will inherit the default's
value for the rest and look subtly wrong rather than obviously broken.

**Daywatch sets 33 and High Contrast 34**, and the extras are the point of those
two themes rather than an inconsistency. `--danger-fill` and `--danger-on-fill`
are defined in the default block and overridden by High Contrast alone, because
a destructive button carrying the shared token sat at 1.9:1 there.
`--color-medium-bright` has the same shape: defined in the default block,
overridden by Daywatch alone, because `.severity_medium` was the only severity
badge whose text colour was a hardcoded literal rather than a token, and a
literal is precisely what a light theme has no way to retune. They are the
seventh category in all but name, and a theme that goes light, or aims at AAA,
has to consider them. Re-read the counts with the block-scoped variable list
rather than by eye; `grep` over the whole file gives one number for every theme.

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
| `--color-warning` | Caution; the bright variant is `.severity_high` | `--color-warning-bright` |
| `--color-medium-bright` | `.severity_medium`, one rung below high | n/a, it is the bright variant |
| `--color-critical` | Error; the bright variant is `.severity_critical` | `--color-critical-bright` |
| `--color-info` | Information, low severity | - |
| `--color-pending` | Unknown, awaiting | - |

`--color-medium-bright` has no base counterpart because it is only ever read as
text: it is the `.severity_medium` colour and nothing else. Like `--danger-fill`,
it is declared in the default block and overridden by exactly one theme,
Daywatch, where the literal it replaced rendered at 1.77:1 against that theme's
own amber tint. Its four siblings resolved tokens and so were retuned with the
rest of the palette; it could not be, which is the whole reason it exists.

Daywatch's value `#7a5c00` clears WCAG AA on all four of that theme's surfaces,
worst 4.60:1 on `--bg-tertiary` and best 5.70:1 on `--bg-elevated`. It carries a
known and accepted ceiling: on Daywatch, medium and high badges read alike,
because every amber readable on a light tint sits within 1.29:1 of that theme's
`--color-warning-bright` (`#794203`). The severity rank is carried by the badge's
text label instead, since `severity_class(sev)` is always emitted beside
`severity_label(sev)`.

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
| `--border` | Separators between things on one surface: rows, cells, inputs |
| `--border-strong` | Emphasis and hover borders |
| `--edge` | The outline of a surface itself: cards, panels, the plugin list |

Every theme overrides the first two. A light theme is not a special case
here: `daywatch` sets `--border: #d6d3d1` through the same variable the dark
themes use.

`--edge` is different. On the six dark themes it is one faint value,
`rgba(255, 255, 255, 0.06)`, inherited from the base block: a card is a change
of tone, and the edge only crisps it where two tones meet. Two themes set it
to a real line because tone alone does not separate there: `daywatch` to
`rgba(28, 25, 23, 0.1)` and `high-contrast` to its own `--border`. A rule
that outlines a region uses `--edge`; a rule that divides one region into
rows uses `--border`.

### 7. The ink frame

The posture strip across the top and the sidebar down the left are one dark
surface in every theme, the light one included, and the routed page sits
inside it. Nothing on that surface reads a `--text-*` or `--bg-*` token; it
has its own set, so a light theme can keep a dark frame without its page
palette having to serve two grounds at once.

| Variable | Purpose |
|----------|---------|
| `--bg-ink` | The frame's surface; darker than `--bg-primary` on the dark themes, `#1c1917` on Daywatch |
| `--ink-fg` | Primary text on ink: values in the strip, the wordmark |
| `--ink-muted` | Secondary text on ink: strip keys, nav links at rest, the version line |
| `--ink-hover` | Translucent white wash for hovered and active nav links, and the frame's own dividers |
| `--ink-accent` | The accent as painted on ink: the active nav link, the scanning segment |
| `--ink-good`, `--ink-warning`, `--ink-critical` | Status text on ink: the strip's band and counts |

All eight are literal values in every theme block, never `var()` chains, so
`validate_contrast.py` can resolve each pair on paper. The dark themes reuse
their bright status set and their accent; Daywatch cannot, because its status
set and accent are tuned dark for cream and vanish on ink, so it sets light
ones (`#34d399`, `#fbbf24`, `#f87171`, and `#2dd4bf` for the accent).

### Button Styles

`.btn-primary` is ink on paper: the theme's `--text-primary` as the fill and
its `--bg-primary` as the label, so the one pair every theme already
guarantees at 13:1 or better is the one the primary action wears, and no
theme needs a correction for it. It used to be a fixed dark green (`#065f46`),
which two things argued against. A status colour on a button claims a state
an unpressed button has not earned, and in Guardian `--color-accent` and
`--color-good` were at the time the same green, so the primary button was
indistinguishable from a pass. That collision is gone (see the accent rule
under Theme Overrides), and the button stays ink because ink cannot collide
with any status in any future theme either. Hover mixes 15% of the page colour back into
the fill with `color-mix()`, a step down rather than a colour change.
`.btn-danger` keeps its own pair, `--danger-fill` and `--danger-on-fill`.

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
  --bg-primary: #0b1016;
  --color-accent: #22d3ee;
  --bg-ink: #06090d;
  /* ... */
}
```

### Theme Overrides

Each theme overrides the same 32 base variables. Daywatch overrides one more
(`--color-medium-bright`) and High Contrast two more (`--danger-fill`,
`--danger-on-fill`):

| Theme | id | Identity | Accent Colour | Background Family | Ink |
|-------|----|----------|---------------|-------------------|-----|
| **Fortress** | `fortress` | Neutral, vault-like | Steel blue #7cb8ff | Slate #111315 | #0a0b0d |
| **Sentinel** | `sentinel` | Vigilant, warm | Rose #f472b6 | Umber #171210 | #0f0c0a |
| **Command** | `command` | Precise, cool | Violet #a78bfa | Indigo #0a0c1c | #06071a |
| **Guardian** | `guardian` | Protective, natural | Ivory #f2e9d8 | Forest black #0b120e | #060b08 |
| **Daywatch** | `daywatch` | Light, productive | Teal #096961 | Warm off-white #f8f6f2 | #1c1917 |
| **High Contrast** | `high-contrast` | Maximum contrast, WCAG AAA | Cyan #67e8f9 | Pure black #000000 | #000000 |

Daywatch is the only light theme, and High Contrast is the only theme targeting
WCAG AAA rather than AA.

**The accent rule.** Every accent is a hue no status colour uses, and no two
themes share one: teal, steel blue, rose, violet, ivory, dark teal, cyan.
Selection and the active nav link therefore never read as pass, warn or fail.
Two themes broke this before the 2026-09 re-palette: Guardian's accent was the
same emerald as `--color-good`, so a selected row and a passing check were one
green, and Sentinel's was the same amber as `--color-warning`. Fortress,
Command and Midnight Teal were also three near-identical blue-blacks told
apart by accent alone; Fortress is now a neutral slate and Command a real
indigo, so the surfaces carry the identity and the accent only confirms it.

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
value, which is the failure mode that is hardest to spot. Three further tokens
live in the default block rather than in the 24, and each has to be checked
separately. If the theme targets AAA, or simply darkens the palette far from the
default, check `.btn-danger` against `--danger-fill`/`--danger-on-fill` and
override those two as well; High Contrast is the only theme that currently needs
its own. If the theme goes light, check `.severity_medium` against
`--color-medium-bright` the same way; Daywatch is the only theme that currently
needs its own.

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

- [ ] `python3 scripts/validate/validate_contrast.py` passes
- [ ] All text meets 4.5:1 contrast against its background
- [ ] Severity badges are distinguishable (not just by colour)
- [ ] Focus rings are visible on all interactive elements
- [ ] Theme works with browser zoom (100%, 150%, 200%)
- [ ] No information is conveyed by colour alone

**The first item is a gate, not advice.** `validate_contrast.py` runs inside
`validate_all.py`, so a new theme that fails it fails the documentation gate.
**Know what it does and does not read**: it checks every foreground and
background pair `styles.css` declares *together in one rule*, across all seven
themes. Where that declared background is translucent, it composites the fill
over every opaque `--bg-*` surface the theme declares and keeps the best
resulting ratio, so an alpha background is now checked rather than skipped; that
lifted the pairs checked from 182 to 322. It deliberately does not test every
token against every surface, because that pairing was tried, reported five
themes failing on combinations that may never render, and contradicted the
screenshots. So a pair the stylesheet never states in one rule is unchecked,
which is how a High Contrast `.btn-danger` sat at 1.9:1 through eight reviewers
and is why `--danger-fill` exists. **The remaining items on this list are the
half that check cannot make**, and the screenshot is still the evidence for
them.

---

## Theme Variable Reference

The 32 variables every override theme sets, followed by the three the default
block defines and a single theme each overrides:

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
--color-warning-bright /* Warning emphasis, high severity */
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

/* The ink frame: posture strip and sidebar */
--bg-ink            /* The frame's surface */
--ink-fg            /* Primary text on ink */
--ink-muted         /* Secondary text on ink */
--ink-hover         /* Hover and active wash, frame dividers (rgba) */
--ink-accent        /* Accent as painted on ink */
--ink-good          /* Status text on ink */
--ink-warning
--ink-critical

/* Default block defines these; one theme each overrides them */
--color-medium-bright /* Medium severity text; Daywatch only */
--danger-fill         /* Destructive button fill; High Contrast only */
--danger-on-fill      /* Text on that fill; High Contrast only */
--edge                /* Surface outline; Daywatch and High Contrast */
```

Set once in the base block and **not** themed, so a theme block should leave
them alone:

```css
--font-sans, --font-display, --font-mono, --stretch-data
--font-size-caption .. --font-size-display, --font-size-strip
--tracking-title, --tracking-display
--leading-ui, --leading-prose
--header-height, --content-padding, --sidebar-width, --sidebar-rail-width
--width-form, --width-page
--space-xs .. --space-2xl
--control-height, --control-pad-x, --row-gap, --section-gap
--radius-sm, --radius-md, --radius-lg, --radius-full
--z-skip-link, --z-modal, --z-sticky, --z-dropdown
--shadow-sm, --shadow-md
--transition-fast, --transition-normal, --transition-slow
```

---

**Last Updated**: 2026-09-03
