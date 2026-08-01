#!/usr/bin/env python3
"""
Validates that no release entry in CHANGELOG.md repeats a change-type heading.

Keep a Changelog gives each release one section per change type. A second
`### Fixed` under the same `## [version]` is not a formatting quibble: the
entries under it are invisible to anyone reading the first one, a reader who
finds "the Fixed section" has no way to know there is another eighty lines
further down, and a release whose notes are cut from the file publishes the same
heading twice with its entries split between them on no principle at all.

It had happened four times and nobody noticed, because nothing looked. The
`[Unreleased]` block carried two `### Changed`, which is the one that would have
shipped; `[1.3.0]` carried Added, Changed and Fixed twice each; `[1.1.0]`
carried Fixed and Changed twice.

The comparison is on the exact heading text, which is deliberately narrow.
`[1.0.3]` writes `### Added (Testing Infrastructure)` beside `### Fixed (GUI
Tests)`, and those are two different sections rather than a duplicate pair, so
matching on a normalised prefix would fail a file that is doing nothing wrong.
The failure this exists to catch is the identical heading, twice.

Everything below the last release entry is ignored: the link-reference
definitions and the version-history summary carry no `###` headings, and a
future appendix that did should not be read as part of the release above it.
"""

import re
import sys
from pathlib import Path

GREEN = "\033[0;32m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
NC = "\033[0m"

CHANGELOG = Path("CHANGELOG.md")
RELEASE = re.compile(r"^## (\[[^\]]+\].*)$", re.M)
SECTION = re.compile(r"^### .+$")


def find_project_root() -> Path:
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    return Path.cwd()


def duplicate_headings(text: str) -> list[str]:
    """Every heading that appears more than once inside one release entry."""
    problems = []
    release = None
    seen: dict[str, int] = {}

    for number, line in enumerate(text.splitlines(), 1):
        if match := RELEASE.match(line):
            release = match.group(1)
            seen = {}
            continue
        if release is None or not SECTION.match(line):
            continue
        heading = line.strip()
        if heading in seen:
            problems.append(
                f"CHANGELOG.md:{number}: {release} repeats '{heading}', "
                f"first seen at line {seen[heading]}"
            )
        else:
            seen[heading] = number
    return problems


def main() -> int:
    print(f"{BLUE}Validating CHANGELOG release headings...{NC}\n")
    root = find_project_root()
    path = root / CHANGELOG
    if not path.exists():
        print(f"  {RED}x{NC} {CHANGELOG} does not exist")
        return 1

    text = path.read_text()
    releases = len(RELEASE.findall(text))
    if releases == 0:
        print(f"  {RED}x{NC} {CHANGELOG} carries no '## [version]' entry to check")
        return 1

    problems = duplicate_headings(text)
    if problems:
        print(f"  {RED}Release entries with a repeated change-type heading:{NC}")
        for problem in problems:
            print(f"    {RED}x{NC} {problem}")
        print(
            f"\n{RED}{len(problems)} duplicate heading(s). Move the later "
            f"section's entries under the first heading and delete the "
            f"duplicate; nothing is dropped, so the file's lines should compare "
            f"equal as a multiset before and after.{NC}"
        )
        return 1

    print(f"  {GREEN}v{NC} All {releases} release entries carry each heading once")
    print(f"\n{GREEN}CHANGELOG heading validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
