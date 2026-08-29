#!/usr/bin/env python3
"""Check every file that states the CURRENT version against Cargo.toml.

Exit codes:
    0: every registered site matches, and no unregistered site exists
    1: a mismatch, a missing site, or a site nobody registered

Why this exists
---------------
`release.sh --verify` reads four files. Thirteen are registered here, and
fifty-three tracked files contain the version string. The gap is not
theoretical:
`docs/contributing/releasing.md` documents which sites are automatic and which
are manual, and an audit found that table wrong in both directions, marking
SECURITY.md manual when `update_all_docs.py` writes it and describing "three
markers" where the list holds four. Nothing checked the table, and nothing
checked the sites it did not mention.

The failure mode is specific and it has already happened elsewhere in this
repository: a fix lands in one location, the reason is written down, and the
other locations are never swept. `--text-muted` was brightened for WCAG in the
default theme and five themes kept the old value for months.

What counts as a site
---------------------
A marker that asserts what the version IS RIGHT NOW. A changelog heading, a
`%changelog` entry, a debian stanza below the first, and prose like "v1.3.0 to
v1.5.1: released" are history and are correctly silent here: they are supposed
to keep saying what they say after a bump.

That distinction is the whole design. A naive sweep for the version string hits
fifty-three files and would demand edits to the historical record, which is how
a check earns itself a permanent `|| true`.

Adding a new current-version marker to any tracked file fails this check until
the marker is registered below, which is the point: a site nobody registered is
a site nobody will remember to bump.

Known gap: `docs/assets/badges/version.svg` carries the version as rendered
text and is skipped, along with every other binary-ish asset, because a static
parse of generated SVG is a poor way to learn what a badge says. Its generator,
`scripts/badges/generate.js`, IS checked, so a drift between the generator and
the committed SVG would pass here. `validate_badges.py` covers that pair.
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

# Every file that states the current version, the pattern that finds it, and
# whether release.sh writes it. `automated` is asserted against
# update_all_docs.py and release.sh, not taken on trust.
#
# (path, regex with one capture group, automated, note)
SITES: list[tuple[str, str, bool, str]] = [
    ("Cargo.toml", r'(?m)^version = "([\d.]+)"', True, "workspace, the source of truth"),
    ("src-tauri/tauri.conf.json", r'"version":\s*"([\d.]+)"', True, "release.sh step 3b"),
    ("docs/architecture/architecture.md", r"\*\*Version:\*\*\s*([\d.]+)", True, "update_all_docs.py"),
    ("docs/reference/data-flow.md", r"\*\*Version:\*\*\s*([\d.]+)", True, "update_all_docs.py"),
    ("README.md", r"\*\*Version\*\*:\s*([\d.]+)", True, "update_all_docs.py"),
    ("SECURITY.md", r"current release is \*\*([\d.]+)\*\*", True, "update_all_docs.py"),
    ("packaging/assets/hardener.1", r'(?m)^\.TH\s+\S+\s+\d+\s+"[^"]*"\s+"([\d.]+)"', True, "release.sh step 3b"),
    ("scripts/badges/generate.js", r"file: 'version',\s*label: 'version',\s*message: '([\d.]+)'", True, "release.sh step 3c"),
    ("packaging/PKGBUILD", r"(?m)^pkgver=([\d.]+)", False, "AUR"),
    ("packaging/.SRCINFO", r"(?m)^\s*pkgver = ([\d.]+)", False, "regenerated from PKGBUILD"),
    ("packaging/linux-hardener.spec", r"(?m)^Version:\s+([\d.]+)", False, "rpm"),
    ("packaging/debian/changelog", r"^linux-hardener \(([\d.]+)-\d+\)", False, "top stanza only"),
    ("docs/NEXT.md", r"\*\*Current Version\*\*:\s*([\d.]+)", False, "prose"),
]

# Marker shapes that assert a current version. Any tracked file matching one of
# these and absent from SITES is an unregistered site.
CURRENT_MARKERS = [
    r"(?m)^version = \"[\d.]+\"",
    r"\*\*Version\*\*:\s*[\d.]+",
    r"\*\*Version:\*\*\s*[\d.]+",
    r"\*\*Current Version\*\*:\s*[\d.]+",
    r"(?m)^pkgver=[\d.]+",
    r"(?m)^Version:\s+[\d.]+",
    r'"version":\s*"[\d.]+"',
]

# Archived material states the version it was written against and is supposed
# to keep saying so. Excluded by directory rather than by file, so a document
# added to an archive later does not fail this check for being honest about
# its own date. Verified: these carry 0.3.3, 1.0 and 1.0.2, all long past.
ARCHIVE_PREFIXES = (
    "docs/plans/archive/",
    "docs/security/archive/",
)

# Files allowed to carry a marker shape without being a registered site, with
# the reason. Kept short; each entry is ground the check no longer covers.
UNREGISTERED_OK = {
    "Cargo.lock": "generated from Cargo.toml by cargo, never edited by hand",
    "gui-tests/package-lock.json": "npm lockfile, versions are dependencies",
    "gui-tests/package.json": "npm manifest, unrelated to the release version",
    "scripts/badges/package.json": "npm manifest for the badge generator",
    "scripts/badges/package-lock.json": "npm lockfile",
    # The fuzz crate is deliberately version 0.0.0 and never published; the
    # 1.7.0 shapes in both files are the hardener-common dependency it
    # path-references, carried from the workspace, not version sites anyone
    # bumps on release.
    "fuzz/Cargo.toml": "fuzz crate, version 0.0.0 by design, markers are dependency paths",
    "fuzz/Cargo.lock": "fuzz crate lockfile, generated",
}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    )
    return out.stdout.splitlines()


def workspace_version(root: Path) -> str | None:
    match = re.search(r'(?m)^version = "([\d.]+)"', (root / "Cargo.toml").read_text())
    return match.group(1) if match else None


def check(root: Path) -> int:
    expected = workspace_version(root)
    if not expected:
        print(f"{RED}Could not read the workspace version from Cargo.toml{NC}")
        return 1

    print(f"{BLUE}Validating version locations against Cargo.toml {expected}...{NC}\n")
    errors: list[str] = []
    registered = {path for path, _, _, _ in SITES}

    for path, pattern, automated, note in SITES:
        f = root / path
        if not f.exists():
            errors.append(f"{path}: registered site does not exist")
            continue
        match = re.search(pattern, f.read_text())
        if not match:
            errors.append(
                f"{path}: no version marker found. The pattern in this "
                f"validator no longer matches the file, which hides the site "
                f"rather than checking it"
            )
            continue
        found = match.group(1)
        if found != expected:
            kind = "automated" if automated else "manual"
            errors.append(f"{path}: says {found}, workspace says {expected} ({kind}, {note})")

    # A site nobody registered is a site nobody will remember to bump.
    for path in tracked_files():
        if path in registered or path in UNREGISTERED_OK:
            continue
        if path.startswith(ARCHIVE_PREFIXES):
            continue
        f = root / path
        if not f.is_file() or f.suffix in {".svg", ".png", ".wasm"}:
            continue
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for marker in CURRENT_MARKERS:
            if re.search(marker, text):
                errors.append(
                    f"{path}: carries a current-version marker but is not "
                    f"registered in this validator. Add it to SITES, or to "
                    f"UNREGISTERED_OK with a reason"
                )
                break

    if errors:
        print(f"{RED}Version location problems ({len(errors)}):{NC}\n")
        for e in errors:
            print(f"  {RED}✗{NC} {e}")
        print(
            f"\n{YELLOW}release.sh --verify reads four of these. This reads "
            f"all {len(SITES)}.{NC}"
        )
        return 1

    automated = sum(1 for _, _, a, _ in SITES if a)
    print(f"{GREEN}All {len(SITES)} version locations agree at {expected}{NC}")
    print(f"  Automated by release.sh: {automated}")
    print(f"  Manual at release time:  {len(SITES) - automated}")
    print(
        f"  {YELLOW}Historical mentions (changelogs, %changelog, older debian "
        f"stanzas, prose about past releases) are deliberately not checked.{NC}"
    )
    return 0


def main() -> int:
    root = Path(__file__).resolve().parent.parent.parent
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
