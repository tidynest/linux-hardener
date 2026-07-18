# Theme Design Guide

This document explains the theming system for Linux System Hardener's GUI and provides guidelines for creating new themes.

---

## Theme Architecture Overview

### How Themes Work

The theming system uses CSS custom properties (variables) with a `[data-theme]` attribute selector pattern:

1. **Base styles** are defined in `:root` (the default "Midnight Teal" theme)
2. **Theme overrides** use `[data-theme="theme-name"]` selectors
3. **JavaScript** sets the `data-theme` attribute on the `<html>` element
4. **Persistence** uses localStorage to remember the user's choice

```
User selects theme
        │
        ▼
┌───────────────────────┐
│ theme_toggle.rs       │
│ apply_theme()         │
└───────────┬───────────┘
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
| `crates/hardener-ui/src/components/theme_toggle.rs` | Theme switching component |

---

## Colour Variable Categories

The theme system defines four categories of colour variables:

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

### 5. Button Styles

Dedicated button classes for consistent, WCAG-compliant interactive elements:

| Class | Background | Purpose | Contrast |
|-------|-----------|---------|----------|
| `.btn-primary` | `#065f46` (darker green) | Primary actions (Save, Apply) | WCAG AA compliant against white text |
| `.btn-accent` | `#155e75` (teal) | Secondary prominent actions (Test Notification) | WCAG AA compliant against white text |

The `.btn-primary` colour was chosen over the default green to meet WCAG AA contrast
requirements (4.5:1) for white text on coloured backgrounds. The `.btn-accent` provides
a visually distinct alternative for secondary actions that still need prominence.

---

## Current Themes

### Default (Midnight Teal)

The base theme defined in `:root`. Cool, professional aesthetic with teal accents.

```css
:root {
  --bg-primary: #0f1419;
  --color-accent: #22d3ee;
  /* ... */
}
```

### Theme Overrides

Each theme overrides the base variables:

| Theme | Identity | Accent Colour | Background Family |
|-------|----------|---------------|-------------------|
| **Fortress** | Strategic, vault-like | Gold #fbbf24 | Deep slate-blue |
| **Sentinel** | Vigilant, warm | Amber #f59e0b | Warm charcoal |
| **Command** | Military precision | Ice-blue #38bdf8 | Deep navy |
| **Guardian** | Protective, natural | Emerald #10b981 | Forest black |
| **Daywatch** | Light, productive | Teal #0d9488 | Warm off-white |

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
- 1 primary accent + hover variant
- Semantic colours (can reuse defaults if appropriate)

### Step 2: Add CSS Variables Block

Add your theme to `styles.css` after the existing themes:

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

    /* Semantic (override if needed) */
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

    /* Light themes need border override */
    /* --border-color: #??????; */
}
```

### Step 3: Register the Theme

Add your theme to the THEMES array in `theme_toggle.rs`:

```rust
const THEMES: &[(&str, &str)] = &[
    ("default", "Midnight Teal"),
    ("fortress", "Fortress"),
    ("sentinel", "Sentinel"),
    ("command", "Command"),
    ("guardian", "Guardian"),
    ("daywatch", "Daywatch"),
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

### Step 5: Visual Testing

1. Run the app: `trunk serve --port 1420`
2. Select your theme from the dropdown
3. Navigate all pages (Dashboard, Analysis, Hardening)
4. Check:
   - Title colour reflects accent
   - Cards and panels have clear hierarchy
   - Buttons are visible and interactive
   - Tables and badges are readable
   - Empty states and error messages are visible

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

Use warm off-whites rather than pure white to reduce harshness.

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

Complete list of CSS variables used in themes:

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

/* Borders (light themes) */
--border-color      /* Override for light themes */
```

---

**Last Updated**: 2026-07-18
