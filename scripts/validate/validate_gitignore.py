#!/usr/bin/env python3
"""Check that the ignore rules and the documents describing them agree.

Exit codes:
    0: every documented claim holds, and no unregistered file is both tracked
       and ignored
    1: a claim is false, or a file is in both states without a reason

Why this exists
---------------
Documents tell a contributor that a path is ignored, and some of those claims
are instructions rather than description: `docs/superpowers/` and
`.rust-sec-ci.toml` being ignored is the stated reason `git add -A` is safe to
run in this repository. A reader following that advice after the rule changed
would put specifications and a CI configuration into a release commit. The
claim is load bearing, and nothing checked it.

Three of the claims below sit in tracked documents and are cited as such. The
rest are asserted only in working-tree instruction files, which a fresh clone
does not carry, so no tracked file can be cited for them. They are checked
anyway: a claim nobody can read from the repository is more likely to go stale,
not less.

The reverse state is quieter and was already present. A file can be tracked and
ignored at once: git honours the index, so the rule has no effect on it, while
every tool and reader that consults `.gitignore` is told the opposite. Nobody
notices until a contributor deletes the file, or regenerates it and finds the
change does not appear where they expected.

What is checked
---------------
**Documented claims.** Each path a tracked document says is ignored is put to
`git check-ignore`. The document and line are named in the failure, because a
false claim is fixed in the document about as often as in `.gitignore` and the
reader needs to know which one to open.

**Tracked and ignored at once.** `git ls-files --cached --ignored` lists them.
Any file not registered in `BOTH_STATES_OK` fails, so a new one cannot arrive
unnoticed. Registered entries are printed rather than passed over in silence: a
check that hides its own exceptions reports a subset as the whole.

Not checked: whether every ignore rule is still needed. A stale rule matching
nothing is harmless, and a check that nags about one would be turned off.
"""

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

# Paths a tracked document states are ignored, and where it says so. A claim a
# reader acts on is the reason this list exists, so each entry names the
# document rather than only the path.
#
# (path, the document making the claim, what the reader is told to do with it)
DOCUMENTED_CLAIMS: list[tuple[str, str, str]] = [
    (
        "scripts/badges/node_modules",
        "docs/contributing/releasing.md",
        "the badge generator's dependencies are not committed",
    ),
    (
        "mutants.out",
        "docs/reference/evidence-ledger.md",
        "a mutation run leaves its output at the repository root",
    ),
    (
        "test-results",
        "scripts/README.md",
        "suite output is not committed",
    ),
    (
        "docs/superpowers",
        "working-tree instructions, no tracked document",
        "the stated reason `git add -A` is safe here",
    ),
    (
        ".rust-sec-ci.toml",
        "working-tree instructions, no tracked document",
        "the other half of that reason",
    ),
    (
        "crates/hardener-ui/dist",
        "working-tree instructions, no tracked document",
        "a fresh clone has no built frontend, so trunk must run before a build",
    ),
]

# Files deliberately or historically in both states. Each entry is ground this
# check no longer covers, so each carries its reason.
BOTH_STATES_OK: dict[str, str] = {
    "gui-tests/package-lock.json": (
        "committed before the rule that ignores it, and left tracked so the "
        "GUI suite installs the versions it was tested against. Undecided "
        "rather than designed: either untrack it or narrow the rule"
    ),
}


def git(*args: str, root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=root
    )


def check(root: Path) -> int:
    errors: list[str] = []
    print(f"{BLUE}Validating ignore rules against the documents...{NC}\n")

    for path, document, purpose in DOCUMENTED_CLAIMS:
        # check-ignore exits 0 when the path is ignored and 1 when it is not.
        if git("check-ignore", "-q", path, root=root).returncode == 0:
            print(f"  {GREEN}✓{NC} {path} is ignored ({purpose})")
            continue
        errors.append(
            f"{path}: {document} says this is ignored and it is not. "
            f"Fix whichever is wrong, the rule or the document: {purpose}"
        )

    print()
    both = git(
        "ls-files", "--cached", "--ignored", "--exclude-standard", root=root
    ).stdout.split()

    for path in both:
        reason = BOTH_STATES_OK.get(path)
        if reason is None:
            errors.append(
                f"{path}: tracked and ignored at once. Git honours the index, "
                f"so the rule does nothing while every reader of .gitignore is "
                f"told otherwise. Untrack it, narrow the rule, or register it "
                f"in BOTH_STATES_OK with a reason"
            )
            continue
        print(f"  {YELLOW}!{NC} {path} is tracked and ignored: {reason}")

    if errors:
        print(f"\n{RED}Ignore rule problems ({len(errors)}):{NC}\n")
        for e in errors:
            print(f"  {RED}✗{NC} {e}")
        return 1

    print(
        f"\n{GREEN}All {len(DOCUMENTED_CLAIMS)} documented ignore claims hold{NC}"
    )
    print(f"  Tracked and ignored at once, by registration: {len(BOTH_STATES_OK)}")
    return 0


def main() -> int:
    root = Path(__file__).resolve().parent.parent.parent
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
