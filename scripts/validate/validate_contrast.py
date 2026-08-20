#!/usr/bin/env python3
"""Check the contrast of every colour pair the stylesheet declares together.

Exit codes:
    0: every declared pair clears its threshold
    1: at least one pair is below it

Why this exists
---------------
Three real contrast defects shipped and none was caught by review. The theme
named High Contrast rendered its Roll back and Delete buttons at 1.9:1, because
`--color-critical` is a light AAA-on-black TEXT colour and `.btn-danger` used it
as a button fill under hardcoded white. The five dark themes had the same shape
at 3.76:1. Daywatch's disabled buttons collapsed to 2.35:1 because `opacity`
alpha-blends toward whatever is behind it, which is background-dependent.

Two of the three were invisible to eight reviewers looking at 222 screenshots,
because a red button with white text is the most conventional control there is.
It looks right. It is the arithmetic that says otherwise, and arithmetic is
cheap, so it should run every time rather than when somebody thinks to check.

What it checks, and what it deliberately does not
-------------------------------------------------
Only rules that declare BOTH a text colour and a background in the same block.
Those two provably render on each other, so a failure is a fact rather than a
guess.

It does NOT pair every colour token against every surface token. That was tried
and it reported five themes failing at 3.2 to 3.6:1, pairings that may never
occur together on screen. A check that manufactures defects gets muted, and a
muted check is worse than none. The cost of the narrow scope is real: a text
colour whose background comes from an ancestor rule is not checked here, and
the daywatch `--color-critical` defect would not have been caught by this file.
Widening it needs the computed cascade, which means a browser, which means the
container GUI suite rather than a static parse.

Alpha backgrounds ARE checked, and were not until 322 pairs replaced 182. An
`rgba()` fill has no one colour until it composites over its ancestor, and a
static parse cannot know which ancestor, so both instruments used to skip the
whole class: this file returned None for it and the browser half skipped any
rule declaring a background at all. 18 rules were invisible to both, every
severity badge among them, and one of them read 1.77:1.

What makes them checkable without guessing is compositing over EVERY `--bg-*`
surface the theme declares and taking the BEST result. A failure then holds
whatever the ancestor turns out to be, so it is still a fact. The worst-case
rule was measured and reports 61 failures on pairings that may never co-occur,
which is the manufactured-defect mode described above; best-case reports 8, and
all 8 were real. The cost is the mirror of that: a pair that fails on the darker
surfaces but clears on one is not reported here.

That browser half now exists, as `gui-tests/tests/contrast.spec.js` (#158). It
covers the colour-only rules named above, and since it learned to read
translucent fills it also weighs the alpha class described here, on the
ancestor that actually painted rather than on the best one available. That is
the ceiling above being closed, not a duplicate: the two files answer
different questions and both answers are facts. An OPAQUE declared fill is
still weighed here and nowhere else, because that one IS fully determined on
paper, and two numbers for one question is how a team learns to read neither.
The boundary is one function, `browserOwnsPairing` in
`gui-tests/tests/contrast-math.js`, provable with plain node.

This file still runs on every commit and needs no container, which is why the
narrow scope is worth keeping rather than retiring: the browser half runs only
inside nspawn, so on a development host this is the only contrast check there
is.
"""

import re
import sys
from pathlib import Path

GREEN, RED, YELLOW, BLUE, NC = (
    "\033[0;32m",
    "\033[0;31m",
    "\033[1;33m",
    "\033[0;34m",
    "\033[0m",
)

# WCAG 2.1 1.4.3. Normal-size text needs 4.5; large text and UI boundaries need
# 3.0. A static parse cannot know the rendered font size, so everything is held
# to 4.5 unless its selector is listed below with a reason.
THRESHOLD = 4.5

# Selectors held to 3.0 rather than 4.5, each with the reason it qualifies.
# Keep this short. Every entry is a claim that something is large text or a
# non-text boundary, and a wrong entry silently lowers the bar.
LARGE_TEXT: dict[str, str] = {}

# Pairs excluded entirely, with the reason. Disabled controls are exempt from
# 1.4.3 by the specification itself.
EXEMPT = (
    ":disabled",
    '[aria-disabled="true"]',
)

# Known failures held open on purpose, each with the reason and who decides.
#
# These are REPORTED on every run and merely do not fail the build. That
# distinction is the whole point: a silent narrowing turns an unexamined area
# into a green tick, which is the failure mode this file exists to answer. An
# entry here is a decision someone made, not a check quietly switched off, and
# it is meant to be removed rather than accumulated.
# A stale entry is invisible: the lookup happens only once a pair already
# failed, so an entry whose defect was fixed goes on sitting here reported by
# nothing. Three did, deferring daywatch's #0d9488 accent at 3.47:1 and 3.74:1
# after 4284612d darkened it to #096961 on 2026-08-15; they now measure 6.07:1
# and 6.55:1 and were removed. Re-read the ratio before trusting an entry.
DEFERRED: dict[str, str] = {
    ".severity_low": (
        "daywatch, --color-info #0891b2 on its own cyan tint at 3.32:1. No "
        "--color-info-bright token exists in any theme, so clearing it means "
        "retuning --color-info theme-wide rather than picking a brighter "
        "sibling as .severity_medium did. Maintainer's design decision."
    ),
}

HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
VAR = re.compile(r"var\(\s*(--[a-z0-9-]+)\s*(?:,[^)]*)?\)")
TOKEN_DECL = re.compile(
    r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6}|rgba?\([^)]*\))\s*;"
)
THEME_BLOCK = re.compile(
    r"(?::root\s*,\s*)?\[data-theme=\"([a-z-]+)\"\]\s*\{(.*?)\n\}", re.S
)
RULE = re.compile(r"([^{}]+)\{([^{}]*)\}", re.S)
COLOUR_PROP = re.compile(r"(?<![-\w])color\s*:\s*([^;]+);")
BG_PROP = re.compile(r"(?<![-\w])background(?:-color)?\s*:\s*([^;]+);")
RGBA = re.compile(
    r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)"
)


def relative_luminance(hex_colour: str) -> float:
    """WCAG relative luminance of a #rrggbb colour."""
    h = hex_colour.lstrip("#")
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [
        c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(a: str, b: str) -> float:
    la, lb = relative_luminance(a), relative_luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def parse_themes(css: str) -> dict[str, dict[str, str]]:
    """Every theme's token map. The `:root,` block is the default theme."""
    themes: dict[str, dict[str, str]] = {}
    for name, body in THEME_BLOCK.findall(css):
        tokens = dict(TOKEN_DECL.findall(body))
        if tokens:
            themes[name] = tokens
    # Themes other than the default declare only what they override, so each
    # one inherits the default's tokens underneath its own.
    base = themes.get("default", {})
    for name, tokens in themes.items():
        if name != "default":
            themes[name] = {**base, **tokens}
    return themes


def resolve(value: str, tokens: dict[str, str]) -> str | None:
    """A declaration's literal OPAQUE colour, or None if it is not one.

    Returns None rather than guessing for gradients, transparent, currentColor,
    keywords and anything else a static parse cannot pin to one hex value.
    Silence beats a fabricated reading. An alpha colour also returns None here
    and is handled by `alpha_colour` instead, because it has no one hex value
    until it is composited over something.
    """
    value = value.strip()
    if "gradient" in value or "!important" in value.replace(" ", ""):
        value = value.replace("!important", "").strip()
        if "gradient" in value:
            return None
    match = VAR.search(value)
    if match:
        resolved = tokens.get(match.group(1)[2:])
        # TOKEN_DECL captures alpha tokens too, so a token can resolve to an
        # rgba literal. Without this guard relative_luminance is handed
        # "rgba(..." and dies on int("rg", 16).
        return resolved if resolved and resolved.startswith("#") else None
    found = HEX.search(value)
    if found:
        return found.group(0)
    return None


def alpha_colour(
    value: str, tokens: dict[str, str]
) -> tuple[int, int, int, float] | None:
    """The rgb(a) a declaration names, as (r, g, b, alpha), or None."""
    match = VAR.search(value)
    if match:
        value = tokens.get(match.group(1)[2:], "")
    found = RGBA.search(value)
    if not found:
        return None
    r, g, b, a = found.groups()
    return int(r), int(g), int(b), float(a) if a is not None else 1.0


def over(colour: tuple[int, int, int, float], backdrop: str) -> str:
    """`colour` alpha-composited over an opaque #rrggbb backdrop.

    Source-over in sRGB, which is what the browser does for background-color,
    so the result is the rendered pixel rather than an approximation of it.
    """
    base = [int(backdrop[i : i + 2], 16) for i in (1, 3, 5)]
    r, g, b, a = colour
    return "#%02x%02x%02x" % tuple(
        round(c * a + s * (1 - a)) for c, s in zip((r, g, b), base)
    )


def check(css_path: Path) -> int:
    css = css_path.read_text()
    themes = parse_themes(css)
    if not themes:
        print(f"{RED}No theme blocks found in {css_path}{NC}")
        return 1

    failures: list[tuple[str, str, str, str, float]] = []
    deferred: list[tuple[str, str, str, str, float]] = []
    checked = 0

    for selector, body in RULE.findall(css):
        selector = " ".join(selector.split())
        if selector.startswith("@") or selector.startswith(":root"):
            continue
        if any(marker in selector for marker in EXEMPT):
            continue
        fg_decl = COLOUR_PROP.search(body)
        bg_decl = BG_PROP.search(body)
        if not (fg_decl and bg_decl):
            continue

        # A rule scoped to one theme is checked only against that theme.
        scoped = re.search(r'\[data-theme="([a-z-]+)"\]', selector)
        applicable = [scoped.group(1)] if scoped else list(themes)
        need = 3.0 if selector in LARGE_TEXT else THRESHOLD

        for theme in applicable:
            tokens = themes.get(theme, {})
            fg = resolve(fg_decl.group(1), tokens)
            bg = resolve(bg_decl.group(1), tokens)
            if not fg:
                continue
            if bg:
                ratio = contrast_ratio(fg, bg)
            else:
                # An alpha background composites over an ancestor a static
                # parse cannot know, so take the BEST of every surface the
                # theme declares: a failure then holds whatever the ancestor
                # turns out to be, which keeps a report a fact rather than a
                # guess. The worst-case rule was measured too and reports 61
                # failures on pairings that may never co-occur, which is the
                # manufactured-defect mode recorded in this file's docstring.
                tint = alpha_colour(bg_decl.group(1), tokens)
                surfaces = [
                    v
                    for k, v in tokens.items()
                    if k.startswith("bg-") and v.startswith("#")
                ]
                if not (tint and surfaces):
                    continue
                ratio = max(contrast_ratio(fg, over(tint, s)) for s in surfaces)
                bg = f"{bg_decl.group(1).strip()} over --bg-*"
            checked += 1
            if ratio < need:
                if selector in DEFERRED:
                    deferred.append((theme, selector, fg, bg, ratio))
                else:
                    failures.append((theme, selector, fg, bg, ratio))

    print(f"{BLUE}Validating declared colour pairs in {css_path.name}...{NC}\n")
    if deferred:
        print(f"{YELLOW}Held open by decision ({len(deferred)}):{NC}\n")
        for theme, selector, fg, bg, ratio in sorted(deferred, key=lambda d: d[4]):
            print(f"  {YELLOW}!{NC} [{theme}] {selector}")
            print(f"      {fg} on {bg} is {ratio:.2f}:1")
            print(f"      {DEFERRED[selector]}\n")
    if failures:
        print(f"{RED}Contrast failures ({len(failures)}):{NC}\n")
        for theme, selector, fg, bg, ratio in sorted(failures, key=lambda f: f[4]):
            print(f"  {RED}✗{NC} [{theme}] {selector}")
            print(f"      {fg} on {bg} is {ratio:.2f}:1, needs {THRESHOLD}\n")
        print(
            f"{YELLOW}A pair here is declared in one rule, so both colours do "
            f"render together.{NC}"
        )
        return 1

    print(f"{GREEN}All {checked} declared colour pairs pass{NC}")
    print(f"  Themes: {len(themes)} ({', '.join(sorted(themes))})")
    print(f"  Threshold: {THRESHOLD}:1")
    print(
        f"  {YELLOW}Scope: pairs declared in one rule only. Text whose "
        f"background comes from an ancestor is not reached by a static parse.{NC}"
    )
    return 0


def main() -> int:
    root = Path(__file__).resolve().parent.parent.parent
    css = root / "crates" / "hardener-ui" / "styles.css"
    if not css.exists():
        print(f"{RED}Stylesheet not found: {css}{NC}")
        return 1
    return check(css)


if __name__ == "__main__":
    sys.exit(main())
