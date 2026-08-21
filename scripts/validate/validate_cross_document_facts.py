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


def _blank_js(text: str) -> str:
    """`text` with every comment and string body replaced by spaces.

    Length and line numbers are preserved, so an offset into the result is an
    offset into the source. Brace and paren counting is only sound on this:
    `gui-tests/tests/` is a corpus of heavily commented specs, and a `{` inside
    a sentence about an object literal would otherwise open a scope that never
    closes. Quotes are kept and their contents blanked, so a comma inside a
    string cannot be counted as an array separator either.

    Refuses on an unterminated comment or string rather than running off the
    end and reporting whatever the truncated parse happened to produce.
    """
    out: list[str] = []
    i, end = 0, len(text)
    while i < end:
        char, pair = text[i], text[i : i + 2]
        if pair == "//":
            stop = text.find("\n", i)
            stop = end if stop < 0 else stop
            out.append(" " * (stop - i))
            i = stop
        elif pair == "/*":
            stop = text.find("*/", i + 2)
            if stop < 0:
                raise LookupError("unterminated block comment")
            stop += 2
            out.append("".join(c if c == "\n" else " " for c in text[i:stop]))
            i = stop
        elif char in "'\"`":
            stop = i + 1
            while stop < end and text[stop] != char:
                stop += 2 if text[stop] == "\\" else 1
            if stop >= end:
                raise LookupError(f"unterminated string at offset {i}")
            body = text[i + 1 : stop]
            out.append(char + "".join(c if c == "\n" else " " for c in body) + char)
            i = stop + 1
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _literal_length(expr: str) -> int | None:
    """Entries in an inline array literal, or None if `expr` is not one.

    Counts separators at the literal's own nesting depth, so
    `[['wide', 1280], ['narrow', 420]]` is two and not four.
    """
    if not (expr.startswith("[") and expr.endswith("]")):
        return None
    inner = expr[1:-1]
    if not inner.strip():
        return 0
    depth = separators = 0
    for char in inner:
        if char in "[({":
            depth += 1
        elif char in "])}":
            depth -= 1
        elif char == "," and depth == 0:
            separators += 1
    return separators + 1


def _array_length(src: str, name: str) -> int | None:
    """Entries in a top-level `const <name> = [...]`, or None if there is none.

    Counts object OPENERS at the array's own indent, `^  {`, which is the one
    structural marker these arrays share: `STATES` spreads each entry over many
    lines and `THEMES` writes each on one. Counting a key instead was the first
    attempt and read `THEMES` as zero, because its `name:` sits inline rather
    than at four spaces.

    None means the array is absent and 0 means it is empty; both are refused by
    the callers, which is why they are distinguished here rather than collapsed.
    Anything nested inside an entry is indented further and cannot be counted
    twice, and the array is bounded by a `];` at column 0, so a nested array
    cannot end the scan early.
    """
    match = re.search(
        rf"^const {re.escape(name)} = \[$(.*?)^\];$", src, re.MULTILINE | re.DOTALL
    )
    if not match:
        return None
    return len(re.findall(r"^ {2}\{", match.group(1), re.MULTILINE))


_FOR_HEAD = re.compile(r"\bfor\s*\(")
_TEST_SITE = re.compile(r"^[ \t]*test\s*\(", re.MULTILINE)


def _spec_cases(path: Path, helpers: str) -> tuple[int, int, dict[int, int]]:
    """Cases, call sites, and `{line: multiplier}` for every parameterised site.

    Walks the blanked source once, keeping a stack of the enclosing `for...of`
    loops. A `test(` contributes the product of the stack, which is one for an
    ordinary site and the loop lengths for a parameterised one; nested loops
    multiply, which is what `themes.spec.js` needs.

    An iterable is resolved LAZILY, at the `test(` site rather than at the loop
    that opens. Most loops in these files iterate a runtime value inside a test
    body - `for (const rule of rules)` in the contrast sweep - and resolving
    eagerly refused on the first of them while counting nothing wrong. A loop
    that contains no `test(` cannot change a count, so it does not have to be
    understood; one that does is refused by name.
    """
    src = _blank_js(path.read_text())

    bodies: dict[int, str] = {}
    for head in _FOR_HEAD.finditer(src):
        open_paren = src.index("(", head.start())
        depth, cursor = 0, open_paren
        while cursor < len(src):
            if src[cursor] == "(":
                depth += 1
            elif src[cursor] == ")":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        else:
            raise LookupError(f"{path.name}: unclosed `for (` at offset {open_paren}")
        header = src[open_paren + 1 : cursor]
        # A C-style `for (let i = 0; ...)` has no ` of ` and cannot repeat a
        # `test()` call site, so it is left as a plain block.
        marker = header.find(" of ")
        if marker < 0:
            continue
        rest = src[cursor + 1 :]
        gap = len(rest) - len(rest.lstrip())
        if not rest[gap:].startswith("{"):
            raise LookupError(
                f"{path.name}: a brace-less `for...of` body cannot be bounded by "
                "this scan; give the loop a block"
            )
        bodies[cursor + 1 + gap] = header[marker + 4 :].strip()

    def resolve(expr: str) -> int:
        if (length := _literal_length(expr)) is not None:
            return length
        if re.fullmatch(r"[A-Za-z_$][\w$]*", expr):
            length = _array_length(src, expr) or _array_length(helpers, expr)
            if length:
                return length
        raise LookupError(
            f"{path.name}: a `test()` is parameterised over `{expr}`, which is "
            "neither an inline array nor a `const NAME = [` array in this file "
            "or in helpers.js. Teach this function the shape rather than "
            "letting the count drift"
        )

    sites = {match.start() for match in _TEST_SITE.finditer(src)}
    depth, stack = 0, []  # stack: (depth the loop body opened at, iterable text)
    cases = found = 0
    parameterised: dict[int, int] = {}
    for offset, char in enumerate(src):
        if offset in sites:
            multiplier = 1
            for _opened_at, iterable in stack:
                multiplier *= resolve(iterable)
            cases += multiplier
            found += 1
            if multiplier > 1:
                parameterised[src.count("\n", 0, offset) + 1] = multiplier
        if char == "{":
            if offset in bodies:
                stack.append((depth, bodies[offset]))
            depth += 1
        elif char == "}":
            depth -= 1
            while stack and stack[-1][0] == depth:
                stack.pop()
    return cases, found, parameterised


def _suite_shape(root: Path) -> tuple[int, dict[str, int]]:
    """The whole suite's case count, and the line of each parameterised site."""
    specs = sorted((root / "gui-tests" / "tests").glob("*.spec.js"))
    if not specs:
        raise LookupError("no gui-tests/tests/*.spec.js found")
    helpers = _blank_js((root / "gui-tests" / "tests" / "helpers.js").read_text())
    cases = sites = 0
    lines: dict[str, int] = {}
    for spec in specs:
        spec_cases, spec_sites, parameterised = _spec_cases(spec, helpers)
        cases += spec_cases
        sites += spec_sites
        if len(parameterised) > 1:
            raise LookupError(
                f"{spec.relative_to(root)}: {len(parameterised)} parameterised "
                "sites, and the documents name one per file"
            )
        for line in parameterised:
            lines[spec.name] = line
    # A total check on the walk itself. `gui_playwright_call_sites` counts the
    # same `test(` sites with a plain regex over the raw text and no brace
    # tracking at all, so the two agree only if the blanking preserved every
    # site and invented none. A silent disagreement is the one failure this
    # walk could have that still produces a plausible number.
    independent = gui_playwright_call_sites(root)
    if sites != independent:
        raise LookupError(
            f"the case walk found {sites} `test()` sites and the independent "
            f"count found {independent}; the walk is misreading the source, so "
            "its case total cannot be trusted either"
        )
    if not cases:
        raise LookupError("gui-tests/tests/*.spec.js parsed to zero cases")
    return cases, lines


def gui_playwright_test_count(root: Path) -> int:
    """The GUI Playwright suite's size, DERIVED from the specs.

    This read the Reading table in distribution-validation.md until 2026-08-21,
    because the count is produced at Playwright's collection time and the
    document was the only place it existed. That made this fact the one entry in
    the registry that could not ask whether its source was true: on 2026-08-20
    three documents called 156 current while the suite read 157, and every site
    agreed with the row, so this validator was green.

    `_spec_cases` resolves the parameterisation instead, and reproduces
    `npx playwright test --list` exactly: 165 cases over 117 call sites on
    2026-08-21, the same pair the runner reported that day. Deriving rather than
    running keeps `validate_all.py` free of `gui-tests/node_modules`, which is
    gitignored and absent from a fresh clone.

    **The ceiling is the shapes it understands**: `for...of` over an inline
    array or over a `const NAME = [` array in the spec or in helpers.js. Any
    other parameterisation is REFUSED by name at the `test()` it reaches, never
    counted as one. The runner remains the ground truth; this is a second
    instrument that agrees with it, and the Reading table's rows stay as the
    record of what a container actually executed.
    """
    return _suite_shape(root)[0]


def _parameterised_site_line(spec: str):
    """A callable reporting the line of `spec`'s single parameterised site.

    Registered per spec because the documents name the three individually, and
    all three were stale on 2026-08-21 with nothing able to say so: two had been
    displaced by edits elsewhere in their own files, `contrast.spec.js` by 114
    lines. A line number is the one cross-reference that rots without anyone
    touching what it names, so it is worth the three entries.
    """

    def line(root: Path) -> int:
        lines = _suite_shape(root)[1]
        if spec not in lines:
            raise LookupError(
                f"{spec} no longer has a parameterised `test()` site, so the "
                "documents naming one are describing a file that changed"
            )
        return lines[spec]

    return line


def gui_playwright_call_sites(root: Path) -> int:
    """How many `test()` call sites the specs carry, counted in the tree.

    The fact above had no tree definition until 2026-08-21 and was read out of
    the document it validates, which meant it could only check that the consumer
    sites agreed with the row: it could not ask whether the row was true. On
    2026-08-20 three documents called 156 current while the suite read 157, and
    this validator was green throughout.

    `_spec_cases` now derives that count, and this scan is what proves the
    derivation read the source correctly: `_suite_shape` compares its walk
    against this plain regex and refuses if they disagree. Two counts of the
    same thing by different means, kept because the walk is the one with
    somewhere to go wrong.

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
    """`_array_length` against a file, refusing rather than returning nothing.

    Zero is refused rather than returned, so a parse that stops reading its
    source fails loudly instead of reporting a product of zero that every
    document would then have "disagreed" with.
    """
    try:
        text = path.read_text()
    except OSError as problem:
        raise LookupError(f"cannot read {path}: {problem}") from problem
    entries = _array_length(text, name)
    if entries is None:
        raise LookupError(f"{path}: no top-level `const {name} = [` array found")
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
    away from the tree. It was registered while `gui_playwright_test_count`
    still read the document it validates, as the cheap half of closing that
    gap; the expensive half followed on the same day, and the case count is now
    derived too. Both are kept: this one names the factor a reader changes,
    where the derived total only says the product moved.
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


def contrast_routes(root: Path) -> int:
    """Routes the computed-cascade contrast sweep drives, per theme.

    Registered because this is the count with the worst record in the tree: the
    `contrast.spec.js` cell of `file-map.md` said FIVE from the day five was
    right until 2026-08-21, through three separate route additions, and the
    matching cell in `distribution-validation.md` drifted with it. Adding a
    route changes no test count - the routes are swept inside one case per
    theme - so nothing else here moves when one lands, which is precisely why
    the prose rotted unnoticed.
    """
    return _count_array_entries(
        root / "gui-tests" / "tests" / "contrast.spec.js", "ROUTES"
    )


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
            (
                "docs/reference/distribution-validation.md",
                r"### Spec Inventory \(\d+ Specs, (\d+) Tests\)",
                "the Spec Inventory heading, a present-tense claim about the "
                "suite's size that no check could reach while this fact's "
                "canonical source was the same document",
            ),
            (
                "docs/reference/distribution-validation.md",
                r"\|\s*\*\*[\d-]+\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*\d+\*\*"
                r"\s*\|\s*\*\*current\*\*",
                "the row marked **current** in the Reading table, which WAS "
                "this fact's canonical source until the derivation replaced it. "
                "The rows are dated readings and stay that way; what is held "
                "here is the one marked current, whose whole job is to state "
                "today's size. It turns red when a test is added and no run has "
                "recorded the new count, which is the correct reading of that "
                "state rather than an inconvenience",
            ),
        ],
    ),
    (
        "themes.spec.js parameterised site line",
        _parameterised_site_line("themes.spec.js"),
        [
            (
                "docs/reference/distribution-validation.md",
                r"`themes\.spec\.js:(\d+)` produces",
                "the Spec Inventory preamble, which names the three "
                "parameterised sites by line. This one moved 152 to 200 and was "
                "corrected by hand on 2026-08-21",
            ),
        ],
    ),
    (
        "contrast.spec.js parameterised site line",
        _parameterised_site_line("contrast.spec.js"),
        [
            (
                "docs/reference/distribution-validation.md",
                r"`contrast\.spec\.js:(\d+)` produces",
                "the same preamble. It was corrected to 551 on 2026-08-21 and "
                "was ALREADY wrong: the site sat at 665, displaced 114 lines by "
                "edits elsewhere in its own file, and the correction that "
                "flagged two stale numbers introduced a third",
            ),
        ],
    ),
    (
        "hardening.spec.js parameterised site line",
        _parameterised_site_line("hardening.spec.js"),
        [
            (
                "docs/reference/distribution-validation.md",
                r"`hardening\.spec\.js:(\d+)` produces",
                "the same preamble, where it was named at 470 while sitting at "
                "464",
            ),
        ],
    ),
    (
        "contrast sweep routes",
        contrast_routes,
        [
            (
                "docs/reference/distribution-validation.md",
                r"\*\*(\d+) routes\*\*, \d+ of which need a state",
                "the `contrast.spec.js` row of the Spec Inventory. Both this "
                "site and the one below said the count in WORDS until this fact "
                "was registered; they are digits now because every pattern here "
                "must capture something `int()` accepts, and a word-to-number "
                "table in `main` would be a second thing to keep true for one "
                "site's prose style",
            ),
            (
                "docs/reference/file-map.md",
                r"Drives (\d+) routes, \d+ of them into a state",
                "the `contrast.spec.js` row, the cell that said FIVE for three "
                "route additions running",
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
