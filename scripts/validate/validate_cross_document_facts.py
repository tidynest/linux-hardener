#!/usr/bin/env python3
"""Hold a fact stated in more than one document to the site that owns it.

Every other validator here reads structure: a path, a key, a colour pair, a
version marker. A claim in a sentence, in a second file, is invisible to all
of them, and a fact stated correctly in one document and wrongly in another
has been found five times by hand.

`validate_test_counts.py` already holds five such sites, but every one is
anchored to a row of the evidence ledger, so a fact with no ledger row cannot
be registered there at all. This names the canonical source PER FACT: the
tree where the tree decides the fact, and one named document where it does
not.

**A dated reading is never a registered site.** `docs/ROADMAP.md:204` says
"All 6 compliance frameworks" and is correct, written on 2026-02-22 when there
were six. Only present-tense claims are registered, and the note on each site
says why it is one.

Usage:
    ./scripts/validate/validate_cross_document_facts.py

Exit codes:
    0: every registered site agrees with its canonical source
    1: a site has drifted, or a pattern stopped matching
"""

import re
import sys
from pathlib import Path

# The sibling validator already parses this enum, and a second copy of the
# parse would be a second thing to keep true. `validate_all.py` runs each
# validator as `python3 scripts/validate/<name>.py`, so sys.path[0] is this
# directory and the import resolves. Importing it runs nothing: that module
# calls `main()` only under `__name__ == "__main__"`.
from validate_compliance_docs import parse_enum_frameworks

GREEN, RED, BLUE, NC = "\033[0;32m", "\033[0;31m", "\033[0;34m", "\033[0m"


def framework_count(root: Path) -> int:
    """How many frameworks the tree defines, counted where the tree says it."""
    variants = parse_enum_frameworks(root)
    if not variants:
        raise LookupError("ComplianceFramework parsed to zero variants")
    return len(variants)


# (fact, canonical source callable, [(path, pattern, note)])
#
# The pattern must capture exactly one group and must be present-tense. A
# pattern that stops matching is an ERROR and never a skip: a pattern matching
# nothing is what makes a validator report green while checking nothing.
REGISTRY = [
    (
        "compliance frameworks",
        framework_count,
        [
            (
                "scripts/README.md",
                r"all (\d+) compliance frameworks",
                "the full-test-suite entry's Purpose line. Said 7 of the 10 "
                "until 2026-08-19, made false the same day by 74d0b700 and "
                "caught by nothing",
            ),
            (
                "scripts/README.md",
                r"PDF reports for all (\d+) compliance frameworks",
                "the Output list of the same entry, which drifted with it",
            ),
        ],
    ),
]


def find_project_root() -> Path:
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: could not find project root{NC}")
    sys.exit(1)


def main() -> int:
    root = find_project_root()
    print(f"{BLUE}Validating facts stated in more than one document...{NC}\n")
    errors: list[str] = []

    if not REGISTRY:
        print(f"{RED}The registry is empty, so this run checked nothing{NC}")
        return 1

    checked = 0
    for fact, canonical, sites in REGISTRY:
        if not sites:
            errors.append(f"{fact}: registered with no dependent site")
            continue
        try:
            expected = canonical(root)
        except LookupError as problem:
            errors.append(f"{fact}: canonical source unreadable: {problem}")
            continue
        print(f"  {BLUE}{fact}{NC}: the tree says {expected}")
        for path, pattern, note in sites:
            match = re.search(pattern, (root / path).read_text())
            if match is None:
                errors.append(
                    f"{path}: the pattern for '{fact}' matched nothing, so "
                    f"the site was not checked rather than found clean "
                    f"({note})"
                )
                continue
            checked += 1
            if int(match.group(1)) == expected:
                print(f"    {GREEN}OK{NC} {path} agrees at {expected}")
                continue
            errors.append(
                f"{path}: says {match.group(1)} for '{fact}', the tree says "
                f"{expected} ({note})"
            )

    print()
    if errors:
        print(f"{RED}Cross-document fact problems ({len(errors)}):{NC}\n")
        for problem in errors:
            print(f"  {RED}x{NC} {problem}")
        return 1

    print(f"{GREEN}All {checked} registered sites agree with their source{NC}")
    print("  Dated readings are deliberately not registered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
