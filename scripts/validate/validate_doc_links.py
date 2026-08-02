#!/usr/bin/env python3
"""
Validates that every markdown link in a tracked document resolves for a reader
who has only the repository.

A link to a missing file is the obvious failure and nothing looked for it. The
failure this exists for is the other one, and it is invisible to the maintainer
by construction: a link whose target is on their disk but is **gitignored**. It
opens for them, in their editor, on every check they might think to run, and it
is a 404 for everyone who clones. No amount of careful reading finds that,
because the reading happens on the machine where the file exists.

It had happened. `docs/ROADMAP.md` linked the frontend layout plan and
`docs/architecture/architecture.md` linked the browser-automation notes, both
under `docs/archive/`, which `.gitignore` lists file by file under the heading
"Internal development documents (not for public repositories)". So two public
documents advertised internal ones that no reader could open.

Relative targets are resolved against the linking file's own directory rather
than matched as text. That is the whole point of the check and it is where the
last hand audit went wrong: it grepped for `docs/archive/` and missed
`../archive/browser-automation.md`, which is the same directory written from one
level down.

Only tracked `.md` files are read, since an untracked document has no readers to
mislead. Image links are skipped, as are `http`, `https`, `mailto` and
same-document anchors. The fragment on a file link is stripped before the file
is looked up: anchor resolution is a separate question and a hand audit of all
63 anchors in the corpus found none broken, so there is nothing here to catch.
"""

import re
import subprocess
import sys
from pathlib import Path

GREEN = "\033[0;32m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
NC = "\033[0m"

# A markdown inline link, minus images: `[text](target "optional title")`.
LINK = re.compile(r'(?<!!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
EXTERNAL = ("http://", "https://", "mailto:", "#")


def find_project_root() -> Path:
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    return Path.cwd()


def git(root: Path, *args: str, stdin: str = "") -> str:
    """Run git in the project root and return its stdout, empty on failure."""
    done = subprocess.run(
        ["git", "-C", str(root), *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.stdout


def local_links(root: Path, document: Path) -> list[tuple[int, str, Path]]:
    """Every (line, target, resolved path) link to a file in the repository."""
    found = []
    for number, line in enumerate(
        document.read_text(encoding="utf-8").splitlines(), 1
    ):
        for match in LINK.finditer(line):
            target = match.group(1)
            if target.startswith(EXTERNAL):
                continue
            path = target.split("#", 1)[0]
            if not path:
                continue
            resolved = (document.parent / path).resolve()
            found.append((number, target, resolved))
    return found


def main() -> int:
    print(f"{BLUE}Validating markdown links against the tracked tree...{NC}\n")
    root = find_project_root().resolve()

    documents = [
        root / name for name in git(root, "ls-files", "*.md").split() if name
    ]
    if not documents:
        print(f"  {RED}x{NC} No tracked .md files found to check")
        return 1

    links = [
        (document, number, target, resolved)
        for document in documents
        for number, target, resolved in local_links(root, document)
    ]

    # One git call for the whole corpus: check-ignore reads paths on stdin and
    # echoes back only the ones it would ignore.
    candidates = sorted({str(resolved) for _, _, _, resolved in links})
    ignored = set(
        git(root, "check-ignore", "--stdin", stdin="\n".join(candidates)).split("\n")
    )

    problems = []
    for document, number, target, resolved in links:
        where = f"{document.relative_to(root)}:{number}"
        if str(resolved) in ignored:
            problems.append(
                f"{where}: '{target}' resolves to {resolved.relative_to(root)}, "
                f"which is gitignored, so the link 404s for every reader who "
                f"is not you"
            )
        elif not resolved.exists():
            problems.append(f"{where}: '{target}' points at a file that does not exist")

    if problems:
        print(f"  {RED}Markdown links that do not resolve in a clone:{NC}")
        for problem in problems:
            print(f"    {RED}x{NC} {problem}")
        print(
            f"\n{RED}{len(problems)} unresolvable link(s). Either track the "
            f"target or reword the reference so it stops presenting an internal "
            f"document as something a reader can open.{NC}"
        )
        return 1

    print(
        f"  {GREEN}v{NC} All {len(links)} local links across "
        f"{len(documents)} tracked documents resolve"
    )
    print(f"\n{GREEN}Markdown link validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
