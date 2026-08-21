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

**A dated reading is never a registered site.** `docs/ROADMAP.md:208` says
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


def gui_playwright_test_count(root: Path) -> int:
    """The GUI Playwright suite's current size, read from the Reading table.

    This fact has no tree definition: the count is generated at Playwright's
    own collection time from parameterised specs, so the document is the
    source, not the code. The Reading table in distribution-validation.md
    keeps every superseded count alongside the current one, so the row
    marked **current** is the one this reads, not the last row or the
    largest number.
    """
    path = root / "docs" / "reference" / "distribution-validation.md"
    try:
        text = path.read_text()
    except OSError as problem:
        raise LookupError(f"cannot read {path}: {problem}") from problem
    match = re.search(
        r"\|\s*\*\*[\d-]+\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*\d+\*\*\s*\|\s*"
        r"\*\*current\*\*",
        text,
    )
    if not match:
        raise LookupError(
            f"{path}: no row marked '**current**' found in the Reading table"
        )
    return int(match.group(1))


def gui_playwright_call_sites(root: Path) -> int:
    """How many `test()` call sites the specs carry, counted in the tree.

    The fact above has no tree definition and is therefore read out of the
    document it validates, which means it can only ever check that the
    consumer sites agree with the row: it cannot ask whether the row is true.
    On 2026-08-20 three documents called 156 current while the suite read 157,
    and this validator was green throughout.

    This is the tree quantity that moves when a test is added, and it is
    registered so that the tree, rather than a person's memory, is what turns
    the paragraph stating both numbers red. It counts CALL SITES and not
    cases: `npx playwright test --list` reported 116 distinct sites producing
    157 cases on 2026-08-20, and this count agreed with it exactly.

    **It does not verify the case count, and one shape defeats it**: a
    parameterised site gaining cases moves the total without moving any call
    site, so an eighth theme would take 157 past 160 with this still reading
    116. What it does catch is the ordinary way the suite grows, which is how
    the 2026-08-20 drift happened.

    A `test.skip`/`only`/`fixme`/`fail` variant would break the agreement with
    `--list`, which still counts a skipped test as a case. Rather than
    miscount in silence the scan refuses, naming the file.
    """
    specs = sorted((root / "gui-tests" / "tests").glob("*.spec.js"))
    if not specs:
        raise LookupError("no gui-tests/tests/*.spec.js found")
    call_site = re.compile(r"^\s*test\s*\(", re.MULTILINE)
    variant = re.compile(r"^\s*test\.(skip|only|fixme|fail)\s*\(", re.MULTILINE)
    total = 0
    for spec in specs:
        text = spec.read_text()
        if found := variant.search(text):
            raise LookupError(
                f"{spec.relative_to(root)}: {found.group(0).strip()} makes this "
                "count disagree with `npx playwright test --list`, which counts "
                "a skipped test as a case. Teach this function the variant "
                "rather than letting the number drift"
            )
        total += len(call_site.findall(text))
    if not total:
        raise LookupError("gui-tests/tests/*.spec.js parsed to zero call sites")
    return total


def _count_array_entries(path: Path, name: str) -> int:
    """Entries in a top-level `const <name> = [...]` array of objects.

    Counts object OPENERS at the array's own indent, `^  {`, which is the one
    structural marker the two arrays share: `STATES` spreads each entry over
    many lines and `THEMES` writes each on one. Counting a key instead was the
    first attempt and read `THEMES` as zero, because its `name:` sits inline
    rather than at four spaces. Zero is refused below rather than returned, so
    that mistake failed loudly instead of reporting a product of zero that
    every document would then have disagreed with.

    Anything nested inside an entry is indented further and cannot be counted
    twice. The array is bounded by a `];` at column 0, so a nested array cannot
    end the scan early.
    """
    try:
        text = path.read_text()
    except OSError as problem:
        raise LookupError(f"cannot read {path}: {problem}") from problem
    match = re.search(
        rf"^const {re.escape(name)} = \[$(.*?)^\];$", text, re.MULTILINE | re.DOTALL
    )
    if not match:
        raise LookupError(f"{path}: no top-level `const {name} = [` array found")
    entries = len(re.findall(r"^ {2}\{", match.group(1), re.MULTILINE))
    if not entries:
        raise LookupError(f"{path}: `{name}` parsed to zero entries")
    return entries


def theme_sweep_states(root: Path) -> int:
    """How many states the theme screenshot sweep captures, per theme.

    Registered because of a drift this validator watched happen and could not
    see. On 2026-08-21 the sweep gained a sixth state, the rollback modal, and
    the suite went from 158 cases to 165 WITHOUT a new `test()` call site,
    which is the one shape `gui_playwright_call_sites` documents itself as
    unable to catch. Four documents went on saying 158 and 35 screenshots with
    every check green.

    This is the quantity that actually moved, and it is three lines of parsing
    away from the tree. `gui_playwright_test_count` still has no tree
    definition and still reads the document it validates; this does not fix
    that, and is not a substitute for it. What it does is turn the ORDINARY way
    a parameterised site grows into something the tree reports.
    """
    return _count_array_entries(root / "gui-tests" / "tests" / "themes.spec.js", "STATES")


def theme_sweep_screenshots(root: Path) -> int:
    """Screenshots the theme sweep writes per distribution: states x themes.

    Derived rather than declared, so it moves when EITHER factor moves. A theme
    added to `THEMES` is otherwise guarded only by `T-THEME-09`, which holds the
    selector's option list against that same array and therefore says nothing
    about any count stated in prose.

    `THEMES` lives in `helpers.js` and `STATES` in `themes.spec.js`, so this is
    the one fact here whose canonical source spans two files. That is the
    argument for deriving it: a reader updating one array has no reason to look
    at the other, and the product of the two is what every document states.
    """
    themes = _count_array_entries(root / "gui-tests" / "tests" / "helpers.js", "THEMES")
    return theme_sweep_states(root) * themes


def registered_site_count(_root: Path) -> int:
    """How many sites this validator holds, counted off its own registry.

    The only fact here whose canonical source is this file rather than the tree
    or a named document, and it exists because the Example Output block in
    `scripts/README.md` had gone stale TWICE: it said 156 across 4 sites until
    2026-08-20 and 157 across 6 until 2026-08-21. A sample of a validator's
    output, in the entry describing that validator, drifting exactly as the
    validator exists to prevent.

    It is deliberately self-referential. Registering it added a site, so the
    number it reports moved 17 to 18 in the same edit, and any fact added later
    moves it again whether or not that fact's own sites are in this file. That
    is the property worth having: this is the one number in the block that
    changes on EVERY registry change rather than only on a change to what it
    describes.

    `main` counts a site as checked only after it has agreed, and prints this
    line only when nothing failed, so on a green run its `checked` equals this
    sum by construction. On a failing run the line is never printed and the
    comparison never arises.

    `_root` is unused and named so. The registry passes a project root to every
    canonical callable, and a signature that quietly ignored it would read as
    an oversight rather than as the point.
    """
    return sum(len(sites) for _fact, _source, sites in REGISTRY)


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
                r"\*\*all (\d+) compliance frameworks\*\*",
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
    (
        "GUI Playwright tests",
        gui_playwright_test_count,
        [
            (
                "docs/reference/distribution-validation.md",
                r"\*\*(\d+) of \d+ on all six distributions\*\*",
                "the supersession pointer above the Reading table, which "
                "restates the current count rather than only pointing at it",
            ),
            (
                "scripts/README.md",
                r"is \*\*(\d+) tests in \d+ files\*\*",
                "the run-gui-tests.sh entry's Purpose line",
            ),
        ],
    ),
    (
        "GUI Playwright test call sites",
        gui_playwright_call_sites,
        [
            (
                "docs/reference/distribution-validation.md",
                r"\*\*(\d+) `test\(\)` call sites produce \d+\s+cases\*\*",
                "the Spec Inventory preamble, which states this number beside "
                "the case count. Registered so the TREE turns that paragraph "
                "red: the case count beside it has no tree definition and went "
                "stale for two days in three documents",
            ),
            (
                "docs/reference/distribution-validation.md",
                r"a count of\s+`test\(` calls is (\d+) and understates the suite",
                "the same paragraph's closing sentence, which restates it as "
                "the reason for reading the runner instead",
            ),
        ],
    ),
    (
        "theme sweep states",
        theme_sweep_states,
        [
            (
                "gui-tests/tests/themes.spec.js",
                r"SCREENSHOT CAPTURES - (\d+) states x \d+ themes",
                "the banner directly above the array it counts. Registered "
                "even though it sits in the same file, because it went stale "
                "there too: a reader adding a state edits the array and not "
                "the comment, which is exactly what a banner stating a count "
                "is for",
            ),
            (
                "docs/reference/distribution-validation.md",
                r"screenshots \((\d+) states x \d+ themes\)",
                "the Spec Inventory preamble, which names the two factors "
                "beside the product",
            ),
            (
                "docs/reference/distribution-validation.md",
                r"screenshot tests are generated as (\d+) states x \d+ themes",
                "the `themes.spec.js` row of the same table, which restates it",
            ),
            (
                "docs/reference/file-map.md",
                r"generated at collection time from (\d+) states x \d+ themes",
                "the `themes.spec.js` row. This file said FIVE routes for "
                "`contrast.spec.js` through three route additions, so a count "
                "here is exactly the kind that rots unwatched",
            ),
            (
                "scripts/README.md",
                r"`themes\.spec\.js` produces \d+ from \d+ themes x (\d+) states",
                "the run-gui-tests.sh entry, which states the factors in the "
                "opposite order. The order is why this is a separate pattern "
                "rather than a fifth use of the one above",
            ),
        ],
    ),
    (
        "theme sweep screenshots",
        theme_sweep_screenshots,
        [
            (
                "gui-tests/tests/themes.spec.js",
                r"T-THEME-01\.\.09\) \+ (\d+) Screenshot Captures",
                "the file's own header banner",
            ),
            (
                "gui-tests/tests/themes.spec.js",
                r"states x \d+ themes = (\d+) screenshots",
                "the product stated beside its factors",
            ),
            (
                "docs/reference/distribution-validation.md",
                r"\| 9 \+ (\d+) \|",
                "the Tests cell of the `themes.spec.js` row, which carries the "
                "sweep as an addend rather than as prose",
            ),
            (
                "docs/reference/distribution-validation.md",
                r"The (\d+) screenshot tests are generated",
                "the same row's description",
            ),
            (
                "docs/reference/file-map.md",
                r"T-THEME-01\.\.09 \(\d+ tests \+ (\d+) screenshots\)",
                "the `themes.spec.js` row",
            ),
            (
                "scripts/README.md",
                r"`themes\.spec\.js` produces (\d+) from \d+ themes",
                "the run-gui-tests.sh entry's explanation of why the count is "
                "read off the runner",
            ),
        ],
    ),
    (
        "registered sites",
        registered_site_count,
        [
            (
                "scripts/README.md",
                r"All (\d+) registered sites agree with their source",
                "the Example Output block of this validator's own entry, which "
                "went stale at 4 sites and again at 6. The other numbers in "
                "that block are illustrative and remain unheld: each duplicates "
                "a fact registered against a different site, and a pattern "
                "unique enough to pin one of them inside a fenced sample would "
                "be pinned to the sample's line ORDER. This line needs no such "
                "anchor and is the only one that moves on every registry change",
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
        except (LookupError, SystemExit) as problem:
            # parse_enum_frameworks (in the sibling validator) exits the
            # process directly when the enum block itself is missing, rather
            # than raising. Catching SystemExit here as well as LookupError
            # means that failure is reported through this registry too,
            # instead of killing the run with the sibling's own message.
            detail = (
                problem
                if isinstance(problem, LookupError)
                else f"exited with status {problem.code}"
            )
            errors.append(f"{fact}: canonical source unreadable: {detail}")
            continue
        print(f"  {BLUE}{fact}{NC}: the tree says {expected}")
        for path, pattern, note in sites:
            matches = list(re.finditer(pattern, (root / path).read_text()))
            if not matches:
                errors.append(
                    f"{path}: the pattern for '{fact}' matched nothing, so "
                    f"the site was not checked rather than found clean "
                    f"({note})"
                )
                continue
            if len(matches) > 1:
                errors.append(
                    f"{path}: the pattern for '{fact}' matched "
                    f"{len(matches)} places, so which one is checked would "
                    f"depend on file order ({note})"
                )
                continue
            match = matches[0]
            try:
                found = int(match.group(1))
            except ValueError:
                errors.append(
                    f"{path}: the pattern for '{fact}' captured "
                    f"'{match.group(1)}', which is not an integer ({note})"
                )
                continue
            checked += 1
            if found == expected:
                print(f"    {GREEN}OK{NC} {path} agrees at {expected}")
                continue
            errors.append(
                f"{path}: says {found} for '{fact}', the tree says "
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
