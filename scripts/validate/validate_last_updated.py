#!/usr/bin/env python3
"""
Validates that "Last Updated" dates in markdown files match git history.

Usage:
    ./scripts/validate/validate_last_updated.py
    ./scripts/validate/validate_last_updated.py --fix  # Update stale dates

Exit codes:
    0: All dates are accurate (within tolerance)
    1: Stale dates found
"""

import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from update_all_docs import git_content_date  # noqa: E402

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No colour

# No tolerance. A stamp is either the date its content last changed or it is
# wrong, which is the question `update_all_docs.py` has always asked and can
# always answer. Seven days of slack was here so a run a few days after an edit
# would not nag; what it actually bought was five stamps reported current while
# the updater was ready to correct every one of them.


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def get_git_last_modified(filepath: Path) -> datetime | None:
    """The date this file's *content* last changed, per `update_all_docs.py`.

    Imported rather than reimplemented, because two implementations of one
    field is what went wrong. This asked `git log -1` and allowed seven days of
    slack; the updater asks for the last commit that changed something other
    than the stamp and allows none. So the two disagreed by construction, and
    on 2026-08-16 five stamps were a day behind their own content while this
    validator reported every one of them current. A tolerance cannot be
    reconciled with an exact answer; it can only hide it.
    """
    date_str = git_content_date(find_project_root(), filepath)
    if date_str:
        return datetime.strptime(date_str, "%Y-%m-%d")
    return None


# Match patterns like:
# **Last Updated**: 2025-12-06
# *Last Updated*: 2025-12-06
# Last Updated: 2025-12-06
LAST_UPDATED_PATTERNS = [
    r'\*\*Last Updated\*\*:\s*(\d{4}-\d{2}-\d{2})',
    r'\*Last Updated\*:\s*(\d{4}-\d{2}-\d{2})',
    r'Last Updated:\s*(\d{4}-\d{2}-\d{2})',
]
LAST_UPDATED_COMBINED = re.compile(
    "|".join(f"(?:{p})" for p in LAST_UPDATED_PATTERNS), re.IGNORECASE
)

# A fenced code block delimiter. Toggles an in/out-of-fence flag as the file
# is read line by line; a fence need not be closed for the file to end, so an
# unbalanced fence is treated as "still in a fence" for every line after it,
# which is the conservative direction (missing a real marker rather than
# validating an example as if it were one).
FENCE_LINE = re.compile(r'^\s*(```|~~~)')


def find_last_updated_markers(content: str) -> list[tuple[int, str, datetime]]:
    """Find every real 'Last Updated: DATE' marker in markdown content.

    Returns (line_number, date_str, date) for each marker, 1-indexed by line.

    This used to be parse_last_updated(), which called re.search once per
    pattern and returned only the FIRST match in the whole file. A document
    with both a header and a footer marker -- distribution-validation.md and
    file-map.md both carry one of each -- had the footer never inspected, so
    the two could silently disagree (or both go stale) with the validator
    still reporting the file current. Every marker is now found and returned
    for the caller to check individually.

    Not every line that looks like a marker is one, though. scripts/README.md
    documents this validator's own three supported formats under "Supported
    Date Formats", each shown with an example date, inside a fenced
    ```markdown block -- an illustration of the pattern, not a claim about
    when scripts/README.md itself was last edited. The rule applied here is:
    a marker counts only if it is NOT inside a fenced code block (``` or
    ~~~). This is a heuristic rather than a proof -- a real marker placed
    inside a fence on purpose would be silently skipped -- but the tree was
    checked by hand and carries no such case today, and a missed real marker
    (a false-negative warning, at worst) is a far smaller failure than
    validating an example line as though it were a genuine date, which is
    what produced this file's original bug in the other direction.
    """
    markers = []
    in_fence = False
    for lineno, line in enumerate(content.split("\n"), start=1):
        if FENCE_LINE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = LAST_UPDATED_COMBINED.search(line)
        if not match:
            continue
        date_str = next(g for g in match.groups() if g is not None)
        try:
            date = datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            continue
        markers.append((lineno, date_str, date))
    return markers


def is_archived(rel_path: Path) -> bool:
    """Whether a document lives in an archive directory.

    Matches any `archive` path component rather than a fixed prefix, because
    the archives are not all in one place: `docs/archive/`,
    `docs/plans/archive/` and `docs/security/archive/` all exist today, and a
    prefix list would silently stop covering the next one.
    """
    return "archive" in rel_path.parts


def find_markdown_files(root: Path) -> list[Path]:
    """Find all markdown files that should have Last Updated dates."""
    files = []

    # Root markdown files
    for md in root.glob("*.md"):
        files.append(md)

    # docs/ directory (recursive; skip gitignored local notes)
    docs_dir = root / "docs"
    if docs_dir.exists():
        for md in docs_dir.rglob("*.md"):
            files.append(md)

    # scripts/README.md
    scripts_readme = root / "scripts" / "README.md"
    if scripts_readme.exists():
        files.append(scripts_readme)

    return sorted(f for f in files if f not in git_ignored(root, files))


def git_ignored(root: Path, paths: list[Path]) -> set[Path]:
    """The subset of `paths` git is ignoring.

    Asked of git in one batch rather than by matching names, because the set is
    not fixed: `docs/superpowers/` was hardcoded here while `docs/HANDOFF.md`,
    `docs/NEXT-SESSION-PROMPT.md` and `docs/QUESTIONS-FOR-MAINTAINER.md` were
    not, so three working-tree notes were reported as missing a date on every
    run. A gitignored file is absent from a fresh clone, so a date on it is a
    claim about a document no reader outside this machine has.

    An empty set on any git failure, which keeps the validator working in a
    tarball checkout: the cost is the old behaviour rather than a crash.
    """
    if not paths:
        return set()
    try:
        result = subprocess.run(
            ["git", "check-ignore", "--stdin"],
            input="\n".join(str(p) for p in paths),
            capture_output=True,
            text=True,
            cwd=root,
        )
    except OSError:
        return set()
    # Exit 0 means some paths matched, 1 means none did; anything else is an
    # error and is treated as "nothing is ignored".
    if result.returncode not in (0, 1):
        return set()
    return {Path(line) for line in result.stdout.split("\n") if line}


def update_last_updated(filepath: Path, line_no: int, new_date: str) -> bool:
    """Update the Last Updated date on one specific line of a file.

    Takes a line number (from find_last_updated_markers) instead of
    substituting every occurrence of a date pattern across the whole file.
    A file can carry two real markers (header and footer) that go stale on
    different dates, and can also carry a same-looking pattern inside a
    fenced code example that must never be rewritten -- a whole-file
    substitution could not tell those apart.
    """
    lines = filepath.read_text().split("\n")
    if not 1 <= line_no <= len(lines):
        return False
    new_line, count = re.subn(r'\d{4}-\d{2}-\d{2}', new_date, lines[line_no - 1], count=1)
    if count == 0:
        return False
    lines[line_no - 1] = new_line
    filepath.write_text("\n".join(lines))
    return True


def main():
    fix_mode = "--fix" in sys.argv

    print(f"{BLUE}Validating 'Last Updated' dates in markdown files...{NC}\n")

    root = find_project_root()
    markdown_files = find_markdown_files(root)

    print(f"Found {GREEN}{len(markdown_files)}{NC} markdown files to check\n")

    stale_files = []
    missing_dates = []
    current_files = []

    for filepath in markdown_files:
        rel_path = filepath.relative_to(root)
        content = filepath.read_text()

        markers = find_last_updated_markers(content)
        git_date = get_git_last_modified(filepath)

        if not markers:
            # An archived document is frozen by definition, so a "Last Updated"
            # date on it would be a claim nobody maintains. Requiring one
            # produced 37 permanent warnings, every run, and a warning that is
            # always present is a warning nobody reads. An archived file that
            # *does* carry a date is still checked below, so an accidental edit
            # leaving a stale one is still caught.
            if not is_archived(rel_path):
                missing_dates.append(rel_path)
            continue

        if git_date is None:
            # File not in git yet, can't validate
            for line_no, date_str, _ in markers:
                current_files.append((rel_path, line_no, date_str, "untracked"))
            continue

        # Every marker is checked, not only the first: a file can carry more
        # than one (header + footer), and each is an independent claim about
        # when the file was last updated.
        for line_no, date_str, doc_date in markers:
            # Archived documents are frozen, and `update_all_docs.py` refuses to
            # rewrite their stamps. Holding them to a git date the sanctioned
            # tool will not correct produces a red with no green path, which is
            # the state this validator was in the moment the tolerance came off:
            # three archived plans, all moved on 2026-08-01 by a reorganisation
            # that changed no word in them. The two tools now agree on scope as
            # well as on the question.
            if is_archived(rel_path):
                current_files.append((rel_path, line_no, date_str, "archived"))
                continue
            if git_date > doc_date:
                stale_files.append({
                    "path": rel_path,
                    "line": line_no,
                    "documented": date_str,
                    "git_date": git_date.strftime("%Y-%m-%d"),
                    "days_stale": (git_date - doc_date).days,
                })
            else:
                current_files.append((rel_path, line_no, date_str, "current"))

    # Report results
    if current_files:
        print(f"{GREEN}Current files ({len(current_files)}):{NC}")
        for path, line_no, date, status in current_files:
            print(f"  ✓ {path}:{line_no}: {date}")
        print()

    if missing_dates:
        print(f"{YELLOW}Files without 'Last Updated' date ({len(missing_dates)}):{NC}")
        for path in missing_dates:
            print(f"  - {path}")
        print()

    if stale_files:
        print(f"{RED}Stale dates found ({len(stale_files)}):{NC}")
        for info in stale_files:
            print(f"  ✗ {info['path']}:{info['line']}")
            print(f"      Documented: {info['documented']}")
            print(f"      Git shows:  {info['git_date']} ({info['days_stale']} days newer)")

        if fix_mode:
            print(f"\n{BLUE}Updating stale dates...{NC}")
            for info in stale_files:
                filepath = root / info['path']
                if update_last_updated(filepath, info['line'], info['git_date']):
                    print(f"  ✓ Updated {info['path']}:{info['line']} to {info['git_date']}")
                else:
                    print(f"  ✗ Failed to update {info['path']}:{info['line']}")
            print()
        else:
            print(f"\n{YELLOW}Run with --fix to update stale dates automatically{NC}\n")

    # Summary
    total_checked = len(markdown_files)
    issues = len(stale_files) + len(missing_dates)

    if stale_files and not fix_mode:
        print(f"{RED}Last Updated validation failed: {len(stale_files)} stale date(s){NC}")
        sys.exit(1)
    elif missing_dates:
        print(f"{YELLOW}Warning: {len(missing_dates)} file(s) missing 'Last Updated' date{NC}")
        sys.exit(0)
    else:
        print(f"{GREEN}All {total_checked} markdown files have current dates{NC}")
        sys.exit(0)


if __name__ == "__main__":
    main()
