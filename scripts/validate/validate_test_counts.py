#!/usr/bin/env python3
"""Check the test-count figures the evidence ledger states against the tree.

Exit codes:
    0: every statically derivable count matches, and the stated arithmetic holds
    1: a count has drifted, or the figures contradict each other

Why this exists
---------------
The most-repeated defect shape in this repository is prose that counts
something in a file that keeps growing. `verify-rollback.sh` went from 9 tests
to 14 on 2026-08-10 and two documents still said 9 while contradicting each
other about whether a dated run existed. One test-count figure had drifted into
four values across six documents. Adding two validators on 2026-08-12 made the
ledger's own validator row false the moment it landed.

Nothing checked any of it. Every other validator in this directory reads
structure: a path, a key, a colour pair, a version marker. A number in a
sentence was invisible to all of them.

Not running cargo, and why that is not a compromise
---------------------------------------------------
Three of the ledger's baseline rows can only be produced by building and
running the suite, which is minutes of machine time this check cannot spend on
every commit. It never runs cargo. It gets at those rows a different way.

Two kinds of check, neither needing a build:

**Derived.** The ledger states the command beside the reading, and for some
rows that command is a `grep` over the tree. Those are reproduced exactly as
written and compared. Test annotations and the `#[ignore]` count are read this
way, as is the validator count, from the registry in `validate_all.py`.

**Arithmetic.** The remaining rows are pinned to each other by identities the
document already asserts in prose: the gap between annotations and executions
IS the ignored count, and the `cargo test` totals ARE the nextest totals plus
the doctests. An edit that moves one figure without moving the others fails
here, even though no number in the identity was measured. That is the whole
trick, and it is why the arithmetic sentence at the foot of the baseline table
is load-bearing rather than decorative.

A figure that is neither derivable nor pinned is not checked, and is listed in
the summary as such rather than passed over in silence. A check that reports a
subset as the whole is the defect this file exists to catch.

What is deliberately not checked
--------------------------------
Dated measurements in other documents. `docs/contributing/testing.md` says
"Measured 2026-08-12 at commit `dddb7651`", and a reading that names its own
commit is supposed to keep saying what it says. Demanding edits to an honest
historical record is how a check earns itself a permanent `|| true`.

Which other documents state a count as CURRENT rather than as dated, and must
therefore agree with the ledger, is a policy decision recorded in
`CROSS_DOCUMENT_SITES` below.
"""

import re
import subprocess
import sys
from pathlib import Path

GREEN, RED, YELLOW, BLUE, NC = (
    "\033[0;32m",
    "\033[0;31m",
    "\033[1;33m",
    "\033[0;34m",
    "\033[0m",
)

LEDGER = "docs/reference/evidence-ledger.md"

# Rows of the ledger's baseline table that a static read of the tree can
# reproduce. `measure` returns the tree's answer; `pattern` pulls the ledger's
# claim out of the row. The ledger states the command for each; where it does,
# the measurement here is that command and not a paraphrase of it.
#
# (label, ledger regex with one capture group, measure, the ledger's command)
DERIVED: list[tuple[str, str, str, str]] = [
    (
        "test annotations",
        r"\| Test annotations in the tree \|[^|]*\| (\d+) \|",
        "annotations",
        r"grep -rEc '^\s*#\[(tokio::)?test\]' crates src-tauri, summed",
    ),
    (
        "ignored tests",
        r"\| Tests the default suite runs \|[^|]*\| [\d,]+ passed, (\d+) skipped \|",
        "ignored",
        r"grep -rEc '^\s*#\[ignore' crates src-tauri, summed",
    ),
    (
        "validators",
        r"\| Documentation and naming validators \|[^|]*\| All (\d+) validations passed \|",
        "validators",
        "the registry in scripts/validate/validate_all.py",
    ),
]

# Documents other than the ledger that state one of these counts as CURRENT,
# and must therefore agree with it. A dated reading is not a site: it is
# supposed to keep saying what it says.
#
# Sample output counts. `scripts/README.md` shows what `validate_all.py`
# prints, and a reader takes the total in it as the number of validators there
# are, not as a transcript of one run in August. It said 21 while the registry
# said 24. Illustrative output that carries a real figure is a claim.
#
# (path, regex with one capture group, the claim it must match, note)
CROSS_DOCUMENT_SITES: list[tuple[str, str, str, str]] = [
    (
        "scripts/README.md",
        r"All (\d+) validations passed!",
        "validators",
        "sample output of validate_all.py",
    ),
    (
        "scripts/README.md",
        r"Runs all (\d+) checks in the table above",
        "validators",
        "the Modes section. The Python figure beside it is this total minus "
        "the one shell check, and is not separately captured",
    ),
]

# Figures no static read can produce. Each is pinned by an identity below
# instead, so an edit that moves one without the others still fails.
UNMEASURABLE = {
    "nextest passes": r"\| Tests the default suite runs \|[^|]*\| ([\d]+) passed",
    "cargo test passes": r"\| Tests `cargo test` runs[^|]*\|[^|]*\| ([\d]+) passed",
    "cargo test ignores": r"\| Tests `cargo test` runs[^|]*\|[^|]*\| [\d]+ passed, 0 failed, (\d+) ignored \|",
    "doctest passes": r"\| Doctests, which nextest does not run at all \|[^|]*\| (\d+) passed",
    "doctest ignores": r"\| Doctests, which nextest does not run at all \|[^|]*\| \d+ passed, (\d+) ignored \|",
}


def _summed_grep(root: Path, pattern: str) -> int:
    """Sum a per-file `grep -c` over the crate sources, as the ledger does."""
    out = subprocess.run(
        ["grep", "-rEc", pattern, "crates", "src-tauri"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    # grep exits 1 when nothing matched anywhere; that is a real answer of 0,
    # not a failure, and exit 2 is the only genuine error.
    if out.returncode > 1:
        raise RuntimeError(f"grep failed: {out.stderr.strip()}")
    return sum(int(line.rsplit(":", 1)[1]) for line in out.stdout.splitlines())


def annotations(root: Path) -> int:
    return _summed_grep(root, r"^\s*#\[(tokio::)?test\]")


def ignored(root: Path) -> int:
    return _summed_grep(root, r"^\s*#\[ignore")


def validators(root: Path) -> int:
    """Count the registry entries in validate_all.py.

    Reads the registered tuples rather than the summary line, so the count is
    what the runner would run and not what it last printed.
    """
    text = (root / "scripts/validate/validate_all.py").read_text()
    return len(
        re.findall(
            r'^\s+\("[^"]+", "(?:validate_[a-z_]+\.py|\.\./release/release\.sh)"',
            text,
            re.M,
        )
    )


MEASURES = {"annotations": annotations, "ignored": ignored, "validators": validators}


def stated(text: str, pattern: str, label: str, errors: list[str]) -> int | None:
    match = re.search(pattern, text)
    if not match:
        errors.append(
            f"{LEDGER}: no row found for {label}. The pattern in this validator "
            f"no longer matches the table, which hides the figure rather than "
            f"checking it"
        )
        return None
    return int(match.group(1))


def check(root: Path) -> int:
    text = (root / LEDGER).read_text()
    errors: list[str] = []
    claims: dict[str, int] = {}

    print(f"{BLUE}Validating test counts against the tree...{NC}\n")

    for label, pattern, measure, command in DERIVED:
        claim = stated(text, pattern, label, errors)
        if claim is None:
            continue
        claims[label] = claim
        actual = MEASURES[measure](root)
        if claim == actual:
            print(f"  {GREEN}✓{NC} {label}: {actual}")
            continue
        errors.append(
            f"{LEDGER}: says {claim} {label}, the tree has {actual} ({command})"
        )

    for path, pattern, label, note in CROSS_DOCUMENT_SITES:
        if label not in claims:
            continue
        elsewhere = stated((root / path).read_text(), pattern, f"{label} in {path}", errors)
        if elsewhere is None:
            continue
        if elsewhere == claims[label]:
            where = note.split(".")[0]
            print(f"  {GREEN}✓{NC} {path} agrees at {elsewhere} {label} ({where})")
            continue
        errors.append(
            f"{path}: says {elsewhere} {label}, {LEDGER} says {claims[label]} ({note})"
        )

    for label, pattern in UNMEASURABLE.items():
        claim = stated(text, pattern, label, errors)
        if claim is not None:
            claims[label] = claim

    # The identities the document asserts in prose. These pin the figures no
    # static read can produce, so moving one without the others fails here.
    identities = [
        (
            "the gap between annotations and executions is the ignored count",
            ("test annotations", "-", "nextest passes"),
            "ignored tests",
        ),
        (
            "cargo test passes are the nextest passes plus the doctests",
            ("nextest passes", "+", "doctest passes"),
            "cargo test passes",
        ),
        (
            "cargo test ignores are the nextest skips plus the doctest ignores",
            ("ignored tests", "+", "doctest ignores"),
            "cargo test ignores",
        ),
    ]

    for sentence, (left, op, right), expected in identities:
        if not {left, right, expected} <= claims.keys():
            continue
        got = claims[left] - claims[right] if op == "-" else claims[left] + claims[right]
        if got == claims[expected]:
            print(
                f"  {GREEN}✓{NC} {claims[left]} {op} {claims[right]} "
                f"= {claims[expected]}, {sentence}"
            )
            continue
        errors.append(
            f"{LEDGER}: {sentence}, but {claims[left]} {op} {claims[right]} "
            f"is {got} and the table says {claims[expected]}"
        )

    print()
    if errors:
        print(f"{RED}Test count problems ({len(errors)}):{NC}\n")
        for e in errors:
            print(f"  {RED}✗{NC} {e}")
        print(
            f"\n{YELLOW}Re-measure before amending a figure. Do not copy one "
            f"from an older document.{NC}"
        )
        return 1

    print(f"{GREEN}All {len(DERIVED)} derived counts match the tree{NC}")
    print(f"  Pinned by arithmetic rather than measured: {len(UNMEASURABLE)}")
    print(f"  Other documents held to the ledger:        {len(CROSS_DOCUMENT_SITES)}")
    print(
        f"  {YELLOW}Dated readings in other documents are deliberately not "
        f"checked; a reading that names its own commit is supposed to keep "
        f"saying what it says.{NC}"
    )
    return 0


def main() -> int:
    root = Path(__file__).resolve().parent.parent.parent
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
