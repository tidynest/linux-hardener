#!/usr/bin/env python3
"""
Holds every file-creating call site in the plugins tree to a written reason why
its parent directory exists.

Usage:
    ./scripts/validate/validate_write_sites.py

Exit codes:
    0: Every file-creating call site is classified
    1: A site is unclassified, an entry is stale, or the pinned count moved

One defect was fixed three times. `460f037` (kernel), `202bb6a` (pam) and
`6ce1799` (audit) each say the same thing: a file is written into a directory
that nothing ensures exists, and `write_file` cannot create a missing parent
because it lands its content through a temporary file in the target directory.
`9b400b9` then collapsed four copies of the fix into `crate::ensure_directory`.
Two plugins had solved it independently before any of that.

All three were findable the moment the first was understood. They were found one
at a time, across a day, because nothing swept for the question "which write
sites target a directory nothing ensures". That is the measured pattern across
the 49 plugin commits since v1.5.1: no site has ever been fixed twice and no
commit reverts another, yet twelve describe themselves as the second or third
copy of a defect already fixed.

WHAT THIS PROVES, AND IT IS NARROW

That no file-creating call site under `crates/hardener-plugins/src` is
unclassified. A new one cannot be added without someone deciding, in writing,
why its parent directory is there. That is the property whose absence let one
defect become three commits.

It is a registry check, not a static analysis. Said plainly, because a check
that overstates itself is worse than no check:

  - It does not prove any ensure is correct, covers the right parent, or runs
    before the write on every path that reaches it. For an `ensured` entry it
    confirms only that an `ensure_directory` for the named directory exists in
    the same file. The ordering argument is the reviewer's, and for the audit
    plugin it is subtle: the ensure has to sit above the checkpoint capture,
    because a checkpoint stores an absent path with a zero mode and a rollback
    reads that as "remove this".
  - It does not see a file created by `execute_command` through any means other
    than the argv[0] names in FILE_CREATING_COMMANDS. A shell redirection, a
    `sh -c` script, or a program named by a variable rather than a literal all
    pass unseen.
  - It does not see a direct `std::fs` write. There are none in the tree today
    (measured: the only `OpenOptions` is permissions/mod.rs, opened read-only
    with `O_NOFOLLOW` for a TOCTOU-safe `fchmod`, which creates nothing), so the
    absence is currently free, but nothing here would notice one arriving.
  - `mkdir` is deliberately absent from FILE_CREATING_COMMANDS. It creates
    directories rather than files, and `mkdir -p` makes its own parents, so it
    is the one call that cannot suffer this defect. `crate::ensure_directory`
    itself would otherwise be reported as a site.

EXPECTED_SITE_COUNT is pinned as a literal for the reason
`require_check_tables` in scripts/test/differential-suite.sh pins every table
length: a registry that discovers its own expected size cannot fail when a site
is added, which is the one thing this check exists to do.
"""

import re
import sys
from pathlib import Path

# ANSI colour codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No colour

PLUGIN_SRC = Path("crates/hardener-plugins/src")

# The number of file-creating call sites in the tree, pinned rather than
# counted. Counted off the registry it would follow the registry down, and a
# site added with no entry would be the exact thing this check cannot see.
EXPECTED_SITE_COUNT = 10

# `execute_command` is the escape hatch: it can materialise a path without ever
# touching `write_file`. Only a literal argv[0] is recognised, and only these.
# `cp` is the one used today, three times, always for a backup; the others are
# listed so that reaching for one is a decision rather than an omission.
FILE_CREATING_COMMANDS = ("cp", "mv", "ln", "tee", "touch", "install", "dd")

# `SystemExecutor` (crates/hardener-common/src/executor/mod.rs) has exactly one
# file-creating method, `write_file`; the rest of its surface reads
# (`read_file`, `read_file_optional`, `path_exists`, `read_link`,
# `file_metadata`, `read_dir`) or runs a command (`execute_command`,
# `command_exists`). Matched as a method call, because the leading dot is what
# separates one from `async fn write_file(&self, ...)` in an impl block. A free
# function wrapping the executor would be missed, but the wrapper's own call to
# the executor would not, which is the layer that matters.
CALL = re.compile(r"\.(write_file|execute_command)\s*\(")

# Backups are written as the source path plus a suffix, so the destination's
# parent is the source's own. A source that cannot be read fails the copy, and
# every one of these sites checks the exit code and aborts, so no content can
# land in a directory that is not there.
BACKUP_BESIDE_SOURCE = (
    "backup written as {} plus a suffix, so its parent is that file's own; "
    "the copy cannot succeed unless the source is readable, and the checked "
    "exit code aborts the caller before any write"
)

# Every file-creating call site, keyed by the file it is in and the call's own
# first argument, which is stable under the line drift a line number is not.
#
# "ensured": the run reaches a `crate::ensure_directory` for this path's parent
# before the write, and the entry names the directory it passes.
# "exempt": the parent is guaranteed by something other than this tool, and the
# entry says by what. The reasons genuinely differ, so they are written out per
# site rather than shared: a kernel-provided pseudo-filesystem, a path under
# /tmp, and a file that must already exist to have been read are three different
# guarantees that happen to land in one bucket.
REGISTRY = {
    ("kernel/mod.rs", "write_file(Path::new(&path)"): (
        "exempt",
        "/proc/sys/<param>: the kernel creates the whole tree when procfs is "
        "mounted, no package owns it, and mkdir cannot add to it",
    ),
    ("kernel/mod.rs", "write_file(hardener_sysctl_path"): (
        "ensured",
        "SYSCTL_DROPIN_DIR",
    ),
    ("ssh/dropin.rs", "write_file(Path::new(DROPIN_PATH)"): (
        "ensured",
        "DROPIN_DIR",
    ),
    ("audit/mod.rs", "write_file(Path::new(AUDIT_RULES_PATH)"): (
        "ensured",
        "AUDIT_RULES_DIR",
    ),
    ("audit/mod.rs", 'execute_command("cp"'): (
        "exempt",
        BACKUP_BESIDE_SOURCE.format("AUDIT_RULES_PATH")
        + "; it also sits under the AUDIT_RULES_DIR ensure that guards the "
        "write below it",
    ),
    ("pam/mod.rs", "write_file(Path::new(path)"): (
        "ensured",
        "dir",
    ),
    ("pam/mod.rs", 'execute_command("cp"'): (
        "exempt",
        BACKUP_BESIDE_SOURCE.format("the file being backed up"),
    ),
    ("ssh/mod.rs", "write_file(&temp_path"): (
        "exempt",
        "/tmp/linux-hardener-sshd-validate-<pid>.conf: scratch copy for "
        "`sshd -t`, and /tmp is mounted by the system on every host this runs "
        "on",
    ),
    ("ssh/mod.rs", "write_file(Path::new(config_path)"): (
        "exempt",
        "sshd_config itself, whose content was read into `main` above; the "
        "absent and unreadable arms both return early, so reaching the write "
        "proves the file and therefore its directory exist",
    ),
    ("ssh/mod.rs", 'execute_command("cp"'): (
        "exempt",
        BACKUP_BESIDE_SOURCE.format("config_path"),
    ),
}


def find_project_root() -> Path:
    """Find the project root by looking for Cargo.toml."""
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def first_argument(text: str, open_paren: int) -> str:
    """The first argument of the call whose '(' sits at `open_paren`.

    Scans by bracket depth over the whole file rather than by line, so a call
    split across lines yields the same key as one written on a single line.
    A string literal containing a bracket or comma would fool it; none of the
    ten sites contains one.
    """
    depth = 0
    for i in range(open_paren, len(text)):
        char = text[i]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i].strip()
        elif char == "," and depth == 1:
            return text[open_paren + 1 : i].strip()
    return ""


def sites_in(path: Path, relative: str) -> list[tuple[str, str, int]]:
    """Every file-creating call site in `path` as (relative, key, line)."""
    text = path.read_text()
    found = []
    for match in CALL.finditer(text):
        method = match.group(1)
        argument = first_argument(text, match.end() - 1)
        # Only a literal argv[0] naming a command that materialises a path.
        # `systemctl`, `chmod` and the rest create nothing. A program named by a
        # variable leaves `literal` as None and is skipped, which is a blind
        # spot the docstring names rather than one this hides.
        literal = argument.strip('"') if argument.startswith('"') else None
        if method == "execute_command" and literal not in FILE_CREATING_COMMANDS:
            continue
        line = text.count("\n", 0, match.start()) + 1
        found.append((relative, f"{method}({argument}", line))
    return found


def main():
    print(f"{BLUE}Checking that every file-creating call site is classified...{NC}\n")

    root = find_project_root()
    source_dir = root / PLUGIN_SRC
    if not source_dir.is_dir():
        print(f"{RED}Error: {PLUGIN_SRC} not found{NC}")
        sys.exit(1)

    sources = sorted(source_dir.rglob("*.rs"))
    sites = []
    for path in sources:
        sites.extend(sites_in(path, str(path.relative_to(source_dir))))

    contents = {
        str(p.relative_to(source_dir)): p.read_text() for p in sources
    }

    unregistered = [s for s in sites if (s[0], s[1]) not in REGISTRY]
    seen = {(s[0], s[1]) for s in sites}
    stale = [key for key in REGISTRY if key not in seen]

    # An `ensured` entry names the directory its ensure passes rather than a
    # line number, so the citation cannot rot as the file grows. This confirms
    # the call is still there; it cannot confirm it runs before the write.
    missing_ensure = [
        (relative, key, reason)
        for (relative, key), (kind, reason) in REGISTRY.items()
        if kind == "ensured"
        and f"ensure_directory(ctx, {reason})" not in contents.get(relative, "")
    ]

    print(f"Scanned {GREEN}{len(sources)}{NC} plugin source files")
    print(f"Found {GREEN}{len(sites)}{NC} file-creating call site(s)\n")

    problems = False

    if unregistered:
        problems = True
        print(f"{RED}{len(unregistered)} call site(s) with no registry entry:{NC}\n")
        for relative, key, line in unregistered:
            print(f"  {RED}{PLUGIN_SRC}/{relative}:{line}{NC}")
            print(f"    {key}...) creates a file and nothing says why its")
            print("    parent directory exists")
            print("    decide which it is, then add the entry to REGISTRY in")
            print(f"    {Path(__file__).name}:")
            print('      "ensured": name the directory passed to')
            print("        crate::ensure_directory above this write")
            print('      "exempt": say what guarantees the parent instead\n')

    if stale:
        problems = True
        print(f"{RED}{len(stale)} registry entry(ies) with no call site:{NC}\n")
        for relative, key in stale:
            print(f"  {RED}{PLUGIN_SRC}/{relative}{NC}")
            print(f"    the registry classifies {key}...) but no such call")
            print("    site is there any more")
            print("    remove the entry: a registry describing code that has")
            print("    gone is how one drifts into fiction\n")

    if missing_ensure:
        problems = True
        print(f"{RED}{len(missing_ensure)} ensured site(s) whose ensure is gone:{NC}\n")
        for relative, key, reason in missing_ensure:
            print(f"  {RED}{PLUGIN_SRC}/{relative}{NC}")
            print(f"    {key}...) is registered as ensured by {reason}, but")
            print(f"    the file contains no ensure_directory(ctx, {reason})")
            print("    restore the ensure, or reclassify the site\n")

    if len(sites) != EXPECTED_SITE_COUNT:
        problems = True
        print(f"{RED}Site count is {len(sites)}, expected {EXPECTED_SITE_COUNT}{NC}")
        print("  The count is pinned rather than counted off the registry, so")
        print("  that a site added with no entry cannot pass by moving the")
        print("  total with it. Change EXPECTED_SITE_COUNT beside the registry")
        print("  once the new site has an entry, or once a removed one has had")
        print("  its entry taken out.\n")

    if len(REGISTRY) != EXPECTED_SITE_COUNT:
        problems = True
        print(
            f"{RED}Registry holds {len(REGISTRY)} entries, "
            f"expected {EXPECTED_SITE_COUNT}{NC}"
        )
        print("  A registry shorter than the pin classifies fewer sites than")
        print("  the tree has; one longer than it carries an entry for")
        print("  something that is not there.\n")

    if problems:
        print(f"{RED}File-creating call site validation failed{NC}")
        sys.exit(1)

    ensured = sum(1 for kind, _ in REGISTRY.values() if kind == "ensured")
    print(
        f"{GREEN}All {len(sites)} file-creating call sites are classified{NC} "
        f"({ensured} ensured, {len(REGISTRY) - ensured} exempt)"
    )
    print(
        f"{YELLOW}This proves no site is unclassified. It does not prove any"
        f" ensure is correct.{NC}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
