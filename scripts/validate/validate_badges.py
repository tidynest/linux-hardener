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

It compares the rendered label and message text rather than the SVG bytes, so it
does not need node or an npm install to run in the gate. That is a deliberate
ceiling: a change to badge-maker's colours or geometry is invisible here, and
only the values a human edits are pinned. Those are the ones that have drifted.

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

        rendered = SVG_TEXT.findall(svg.read_text(encoding="utf-8"))
        if len(rendered) != 2:
            failures.append(
                f"{BADGE_DIR / f'{name}.svg'} holds {len(rendered)} text elements, "
                f"not the label and message pair this check knows how to read"
            )
            continue

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

        failures.extend(check_against_source(root, name, message))

    return failures, len(declared)


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


def main() -> int:
    print(f"{BLUE}Validating badges against their generator...{NC}\n")
    root = find_project_root()

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
