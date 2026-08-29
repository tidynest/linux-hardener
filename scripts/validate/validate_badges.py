#!/usr/bin/env python3
"""
Validates that the committed badge SVGs say what their generator declares.

`scripts/badges/generate.js` is the declared source for the SVGs under
`docs/assets/badges/`, and `docs/contributing/releasing.md` documents
regenerating them as a manual release step. Nothing held the two together, so
they drifted: the generator declared version 1.5.0 and tests 1100+ while the
committed SVGs read 1.5.1 and 1191+. The artefacts had been edited without the
source, which made the documented procedure destructive. Running it would have
rewritten two correct badges back to stale values, and the only warning would
have been a reader noticing the README had got worse.

That is the same failure this project refuses everywhere else. A generator whose
output nobody compares against it is a control that cannot fail, and the badges
are the first thing anyone sees on the front page.

It compares the rendered text rather than the SVG bytes, so it does not need node
or an npm install to run in the gate. That is a deliberate ceiling: a change to
badge-maker's colours or geometry is invisible here, and only the values a human
edits are pinned. Those are the ones that have drifted.

Reading the displayed text alone was not enough. badge-maker writes the same
label and message into `aria-label` and `<title>`, which is what a screen reader
announces in place of the graphic, and the committed aur badge carried
"AUR: 1.5.1" in both while rendering "1.6.0". It survived two releases because
only the half a hand-edit touches was ever compared. All three are generated
from one `message` field, so a generated badge cannot disagree with itself and
any disagreement means the artefact was edited by hand.

The checker's own cases run quietly before every verdict, `--self-test` to see
them named. A check that missed one shape for two releases has to demonstrate it
can still see that shape, and the case table carries the real 1.6.0 badge's.

Agreeing with the generator is not the same as being true, and the AUR badge is
why that distinction is worth a second check rather than a comment: it read
1.5.0 while `packaging/PKGBUILD` read 1.5.1, so the generator and the artefact
were in perfect agreement about a published release they were both behind. Where
a badge has a single source of truth in the repo it is compared against that
source as well.

The tests badge has none, deliberately. Its `+` makes it a floor rather than a
count, and pinning it to a measured figure would make this gate depend on a full
workspace test run. It has to be true, which is a judgement, not reachable here.

Usage:
    ./scripts/validate/validate_badges.py

Exit codes:
    0: every declared badge exists and renders the declared label and message
    1: at least one badge is missing, unparseable, or disagrees with its source
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
NC = "\033[0m"

GENERATOR = Path("scripts") / "badges" / "generate.js"
BADGE_DIR = Path("docs") / "assets" / "badges"
PKGBUILD = Path("packaging") / "PKGBUILD"
WORKSPACE_MANIFEST = Path("Cargo.toml")

# A badge whose value exists somewhere else in the repo, and where that other
# place is the authority rather than a second copy. `aur` tracks the package
# actually published, which is what `packaging/PKGBUILD` is copied to the AUR
# clone to produce; `version` tracks the workspace version release.sh bumps.
CROSS_CHECKS = {
    "aur": (PKGBUILD, re.compile(r"^pkgver=(.+)$", re.M)),
    "version": (WORKSPACE_MANIFEST, re.compile(r'^version\s*=\s*"([^"]+)"', re.M)),
    # `rust-version` only became an authority when it was declared; before that
    # the 1.85 in this badge, in README.md and in building.md rested on nothing
    # a machine could read. The `^` anchors matter: `version` must not match the
    # `rust-version` line sitting two lines below it in the same file.
    "rust": (WORKSPACE_MANIFEST, re.compile(r'^rust-version\s*=\s*"([^"]+)"', re.M)),
}

# The entries of the BADGES table, which is a flat literal by design so that the
# value a maintainer bumps on release is one obvious string.
DECLARATION = re.compile(
    r"\{\s*file:\s*'([^']+)'\s*,\s*label:\s*'([^']+)'\s*,\s*message:\s*'([^']+)'"
)

# badge-maker's flat-square style emits exactly two of these, the label and the
# message. An embedded logo travels as a base64 data URI, whose alphabet has no
# angle bracket, so it cannot be caught here.
SVG_TEXT = re.compile(r"<text[^>]*>([^<]*)</text>")

# The same value badge-maker writes into the two places nobody looks at. Both
# read "<label>: <message>", and both are what a screen reader announces in
# place of the graphic. The committed aur badge said "AUR: 1.5.1" here while
# rendering "1.6.0", so a blind reader was told a version two releases old for
# as long as that badge stood. Only the rendered text was compared, which is
# exactly the half a hand-edit touches.
#
# The logo's own <title> is inside a base64 data URI for the same reason the
# text pattern is safe, so these see the outer document only.
ACCESSIBLE_NAME = {
    "aria-label": re.compile(r'aria-label="([^"]*)"'),
    "<title>": re.compile(r"<title>([^<]*)</title>"),
}


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def check_badges(root: Path) -> tuple[list[str], int]:
    """Compare every declared badge against the SVG committed for it."""
    generator = root / GENERATOR
    if not generator.exists():
        return [f"{GENERATOR} does not exist, so nothing declares the badges"], 0

    declared = DECLARATION.findall(generator.read_text(encoding="utf-8"))

    # Positive control. A regex that matches nothing would otherwise report
    # every badge as consistent, which is this project's most repeated defect
    # and would be especially quiet here: zero comparisons reads exactly like
    # zero disagreements.
    if not declared:
        return [
            f"no badge declarations found in {GENERATOR}. Either the BADGES "
            f"table moved or its shape changed, and this check compared "
            f"nothing while reporting success"
        ], 0

    failures = []
    for name, label, message in declared:
        svg = root / BADGE_DIR / f"{name}.svg"
        if not svg.exists():
            failures.append(f"{GENERATOR} declares {name}, but {BADGE_DIR / f'{name}.svg'} does not exist")
            continue

        failures.extend(check_svg(name, label, message, svg.read_text(encoding="utf-8")))
        failures.extend(check_against_source(root, name, message))

    return failures, len(declared)


def check_svg(name: str, label: str, message: str, content: str) -> list[str]:
    """Compare one committed SVG against the label and message declared for it.

    Split out from the walk so the self-test can drive it with shapes the tree
    does not contain. Everything a human can edit by hand is compared here.
    """
    rendered = SVG_TEXT.findall(content)
    if len(rendered) != 2:
        return [
            f"{BADGE_DIR / f'{name}.svg'} holds {len(rendered)} text elements, "
            f"not the label and message pair this check knows how to read"
        ]

    failures = []
    if rendered[0] != label:
        failures.append(
            f"{name}: the generator declares label '{label}', the committed "
            f"SVG renders '{rendered[0]}'"
        )
    if rendered[1] != message:
        failures.append(
            f"{name}: the generator declares '{message}', the committed SVG "
            f"renders '{rendered[1]}'. Regenerating would replace the second "
            f"with the first"
        )

    # The accessible name is generated from the same one `message` field as the
    # text above, so a generated badge cannot disagree with itself. Disagreement
    # here means the SVG was edited by hand, which is the defect being caught.
    wanted = f"{label}: {message}"
    for where, pattern in ACCESSIBLE_NAME.items():
        found = pattern.findall(content)
        if len(found) != 1:
            failures.append(
                f"{name}: {len(found)} {where} in the SVG, not the one a screen "
                f"reader announces in place of the graphic"
            )
            continue
        if found[0] != wanted:
            failures.append(
                f"{name}: {where} announces '{found[0]}' while the badge renders "
                f"'{wanted}'. A screen reader reads the first and nobody sees it"
            )
    return failures


def check_against_source(root: Path, name: str, message: str) -> list[str]:
    """Compare a badge that has an authority in the repo against that authority.

    Silence here is a pass only when the badge has no such authority. Where it
    has one and the file or the pattern cannot be reached, that is reported: a
    cross-check that cannot run must not read as a cross-check that agreed.
    """
    if name not in CROSS_CHECKS:
        return []

    source, pattern = CROSS_CHECKS[name]
    path = root / source
    if not path.exists():
        return [f"{name}: {source} is the authority for this badge and does not exist"]

    found = pattern.search(path.read_text(encoding="utf-8"))
    if not found:
        return [f"{name}: nothing in {source} matches {pattern.pattern}, so this badge is unchecked"]

    # A trailing plus marks a floor rather than an exact value, which is how the
    # rust badge reads its minimum. The number in front of it still has to be
    # the declared one.
    if message.rstrip("+") != found.group(1):
        return [
            f"{name}: the badge says '{message}' while {source} says "
            f"'{found.group(1)}', which is the authority for it"
        ]
    return []


def badge_svg(accessible: str, label: str, message: str, titles: int = 1) -> str:
    """The shape badge-maker emits, reduced to the parts this check reads."""
    title = f"<title>{accessible}</title>" * titles
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="89" height="20" '
        f'role="img" aria-label="{accessible}">{title}'
        f'<text x="345" y="140">{label}</text>'
        f'<text x="685" y="140">{message}</text></svg>'
    )


# Each case is the SVG, whether it must be flagged, and why. The label and
# message declared for every case are 'AUR' and '1.7.0'.
SELF_TEST_CASES: list[tuple[str, bool, str]] = [
    (
        badge_svg("AUR: 1.7.0", "AUR", "1.7.0"),
        False,
        "a badge whose text, aria-label and title all agree is accepted",
    ),
    (
        badge_svg("AUR: 1.5.1", "AUR", "1.7.0"),
        True,
        "a stale aria-label and title against correct display text is flagged, "
        "which is what shipped in the 1.6.0 badge",
    ),
    (
        badge_svg("AUR: 1.7.0", "AUR", "1.5.1"),
        True,
        "stale display text against a correct accessible name is flagged",
    ),
    (
        badge_svg("AUR: 1.5.1", "AUR", "1.5.1"),
        True,
        "a self-consistent badge is still flagged when it disagrees with the generator",
    ),
    (
        badge_svg("AUR: 1.7.0", "AUR", "1.7.0").replace(' aria-label="AUR: 1.7.0"', ""),
        True,
        "a badge with no aria-label is flagged rather than passing on absence",
    ),
    (
        badge_svg("AUR: 1.7.0", "AUR", "1.7.0", titles=0),
        True,
        "a badge with no title is flagged rather than passing on absence",
    ),
    (
        badge_svg("AUR: 1.7.0", "AUR", "1.7.0", titles=2),
        True,
        "two titles are flagged, since this check cannot tell which one a reader gets",
    ),
    (
        badge_svg("Arch: 1.7.0", "AUR", "1.7.0"),
        True,
        "an accessible name carrying the wrong label is flagged, not just the wrong version",
    ),
]


def self_test(quiet: bool = False) -> int:
    """Runs the checker against shapes the committed badges do not contain."""
    if not quiet:
        print(f"{BLUE}Self-test: badge shapes this check must reject, and one it must not...{NC}\n")

    # Doing nothing must never exit 0. An emptied table would otherwise report a
    # clean self-test, which is the failure this whole check exists to answer.
    if len(SELF_TEST_CASES) < 8:
        print(f"{RED}The self-test table holds {len(SELF_TEST_CASES)} cases, fewer than the 8 written.{NC}")
        return 1

    failures = 0
    for index, (content, should_flag, why) in enumerate(SELF_TEST_CASES):
        flagged = bool(check_svg("aur", "AUR", "1.7.0", content))
        if flagged != should_flag:
            verdict = "flagged" if flagged else "accepted"
            wanted = "flagged" if should_flag else "accepted"
            print(f"  {RED}x{NC} case {index}: {verdict}, expected {wanted}: {why}")
            failures += 1
            continue
        if not quiet:
            print(f"  {GREEN}v{NC} {why}")

    if failures:
        print(f"\n{RED}{failures} of {len(SELF_TEST_CASES)} self-test case(s) failed{NC}")
        return 1
    if not quiet:
        print(f"\n{GREEN}All {len(SELF_TEST_CASES)} self-test cases behave as written{NC}")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    print(f"{BLUE}Validating badges against their generator...{NC}\n")
    root = find_project_root()

    # The self-test runs quietly before any verdict about the committed badges.
    # A stale aria-label survived two releases here, so a green line from this
    # check has to mean the check can still see that shape.
    if self_test(quiet=True) != 0:
        print(f"{RED}The checker's own self-test failed, so its verdict on the badges is worthless.{NC}")
        print(f"{RED}Run: python3 scripts/validate/validate_badges.py --self-test{NC}")
        return 1

    failures, declared = check_badges(root)

    if failures:
        print(f"  {RED}Badges that disagree with {GENERATOR}:{NC}")
        for failure in failures:
            print(f"    {RED}x{NC} {failure}")
        print(
            f"\n{RED}{len(failures)} problem(s) across {declared} declared "
            f"badge(s). The README shows the SVGs; the release procedure "
            f"regenerates them from the source.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {declared} badges render what {GENERATOR} declares")
    print(f"\n{GREEN}Badge validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
