#!/usr/bin/env python3
"""
Detects doc comments that have come loose from the function they describe.

Usage:
    ./scripts/validate/validate_doc_attachment.py

Exit codes:
    0: No loose doc comments found
    1: One or more found

Rust attaches a `///` block to the item that immediately follows it, so
inserting a new item between a comment and its function silently hands the
comment to the newcomer. Nothing warns: it compiles, rustdoc renders, and the
only symptom is one function documented as two things while the function the
prose actually describes has nothing at all. It has happened eight times in
this repository, once in rollback code, where the fail-closed deletion contract
ended up attached to a neighbouring helper.

The shape it leaves behind is what this checks: a free function with no doc of
its own, sitting immediately after an item carrying a substantial one. The
length matters, and is the whole rule. A long block is one that could plausibly
have swallowed a second summary; a one-line comment could not have, and treating
every undocumented helper as a suspect would report sixty of them and gate on
nothing.

Three limits, said out loud rather than discovered later:

  - Only the orphan sitting directly above its thief is visible. That is five of
    the eight, and it is the shape that recurs, because the accident is caused by
    inserting an item. Where the stolen summary's real owner sits further down
    the file (`permissions`, `services`, `ssh`) nothing here connects the two.
  - A short orphan is invisible. One of the eight was a single line ("Returns
    compliance mappings for a given SSH directive."), below any threshold that
    is not also reporting every brief helper in the workspace.
  - Only free functions are examined. Methods inside `impl` blocks are indented
    and skipped, which is where none of the eight happened.

The obvious sharper rule was measured and rejected, so nobody re-derives it: a
merged block leaves a sentence ending at a line boundary followed by a new
capitalised sentence, and detecting that finds all seven plugin instances
exactly. It also finds eighty-one innocent ones, because ordinary prose wraps
that way whenever a paragraph's last line happens to end a sentence. Perfect
recall, eight per cent precision, unusable as a gate. The rule below trades
recall for a number that can be held at zero.

MIN_NEIGHBOUR_DOC_LINES is a ratchet, not a constant of nature. Lower it as the
workspace's undocumented helpers acquire a line each; at 4 there are seven more
to write, and at 0 there are sixty.

Fixing a report means one of two things. Either the neighbour's doc really did
swallow this function's summary, in which case move the stolen half down here;
or the function is simply undocumented, in which case write it a line. Both
answers leave the tree cleaner than the report found it.
"""

import re
import sys
from pathlib import Path

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No colour

# A neighbouring doc block at least this long is one that could have absorbed
# another function's summary without looking odd.
MIN_NEIGHBOUR_DOC_LINES = 8

# Items that can own a doc block and precede a function at file scope.
ITEM = re.compile(
    r"^(pub(\([a-z]+\))? )?(async )?(fn|struct|enum|const|static|trait|impl|type|mod) "
)
# A function declared at file scope, which is the only place the accident has
# happened: a method inside an `impl` is indented and never matches.
FREE_FN = re.compile(r"^(pub(\([a-z]+\))? )?(async )?fn ([a-z_0-9]+)")

DOC_OR_ATTR = ("///", "#[")


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def preceding_item_doc_length(lines: list[str], before: int) -> tuple[int, str]:
    """Length of the doc block on the item that precedes line `before`.

    Walks backwards over the preceding item's body by brace depth rather than
    by indentation, so a function whose body contains braces at column zero
    cannot be mistaken for the start of the item.
    """
    depth = 0
    index = before
    while index >= 0:
        depth += lines[index].count("}") - lines[index].count("{")
        if depth == 0 and ITEM.match(lines[index]):
            break
        index -= 1
    if index < 0:
        return 0, ""

    owner = lines[index].strip()
    length = 0
    index -= 1
    while index >= 0 and lines[index].startswith(DOC_OR_ATTR):
        if lines[index].startswith("///"):
            length += 1
        index -= 1
    return length, owner


def loose_docs_in(path: Path) -> list[tuple[int, str, str, int]]:
    """Every undocumented free function in `path` that follows a long doc block."""
    lines = path.read_text().splitlines()
    found = []
    for i, line in enumerate(lines):
        # Everything from the unit-test module on is out of scope: test helpers
        # are undocumented by convention and would drown the real reports.
        stripped = line.strip()
        if stripped == "#[cfg(test)]" or stripped.startswith("mod tests"):
            break

        match = FREE_FN.match(line)
        if not match:
            continue

        previous = i - 1
        while previous >= 0 and not lines[previous].strip():
            previous -= 1
        if previous < 0 or lines[previous].strip().startswith(("///", "#[", "//")):
            continue

        length, owner = preceding_item_doc_length(lines, previous)
        if length >= MIN_NEIGHBOUR_DOC_LINES:
            found.append((i + 1, match.group(4), owner, length))
    return found


def main():
    print(f"{BLUE}Checking that doc comments describe the item they precede...{NC}\n")

    root = find_project_root()
    sources = [
        p
        for p in sorted((root / "crates").rglob("*.rs"))
        if "/tests/" not in str(p)
    ]

    reports = []
    for path in sources:
        for line_no, name, owner, length in loose_docs_in(path):
            reports.append((path.relative_to(root), line_no, name, owner, length))

    print(f"Scanned {GREEN}{len(sources)}{NC} source files\n")

    if not reports:
        print(f"{GREEN}Every doc comment describes the item it precedes{NC}")
        sys.exit(0)

    print(f"{RED}Found {len(reports)} function(s) with no doc beside a long one:{NC}\n")
    for path, line_no, name, owner, length in reports:
        print(f"  {RED}{path}:{line_no}{NC}")
        print(f"    {name} has no doc comment")
        print(f"    the item above it, {owner}, carries {length} doc lines")
        print("    move the half that describes this function down, or write it a line\n")

    print(f"{RED}Doc attachment validation failed{NC}")
    sys.exit(1)


if __name__ == "__main__":
    main()
