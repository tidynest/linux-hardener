#!/usr/bin/env python3
"""Check every file that states a mode for the three packaged directories.

Exit codes:
    0: every registered site agrees with the authority, and no site is unregistered
    1: a mismatch, a site that states nothing, or a site nobody registered

Why this exists
---------------
`94a1a98e` moved `/var/lib/linux-hardener` from 0755 to 0700 in `PKGBUILD`, the
rpm spec and `debian/rules`, because `init_db` chmods it to 0700 the moment the
database is created and pacman warned about the mismatch on every upgrade. The
sweep missed `scripts/test/test-package-install.sh`, which installs the
directory and then asserts its mode, both from the same file. It kept passing.
The suite whose whole job is catching packaging defects would have certified a
mode the project had abandoned, in the release that abandoned it.

It also missed `docs/guide/installation.md`, which tells a reader building from
source to run `install -dm755 /var/lib/linux-hardener` by hand, and
`docs/architecture/architecture.md`, which calls it a 0755 directory in prose.
Both were still wrong when this check was written, four commits after the fix.

That is the third instance of one shape in a single day, after the packaging
mirror and the badge whose `aria-label` nobody compared. **A check that reads
one of the several places a value is written passes whenever someone updates
the place the check reads.** The fix is never a sharper assertion on that one
site. It is asserting that the sites agree.

What counts as a site
---------------------
Anything that states what one of these directories' modes IS: an `install -d`,
an rpm `%attr`, a test assertion, a documented command a reader will run, or
prose naming the mode. A tracked file that states one and is not registered
below fails this check, which is the point: a site nobody registered is a site
nobody will sweep.

The authority is `packaging/PKGBUILD`. Not because it is more true than the
others, but because it is the artefact copied to the AUR clone, it is already
the authority for the `aur` badge in `validate_badges.py`, and it carries the
comment explaining why each mode is what it is. Change it and every other site
here fails until it follows.

Known gap: nothing here reads the Rust that enforces these modes at runtime.
`config_write.rs` passes `Some(0o700)` for the log directory, and `init_db`
chmods the state directory, but both are reached through helpers that take the
mode as an argument, so a static parse would be pinning the call site rather
than the behaviour. The packaging is checked against itself, and against what a
human is told to type. Whether that matches what the code does is asserted by
the package suite at runtime, not here.
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

AUTHORITY = "packaging/PKGBUILD"

# The three directories the packages create, and why each mode is what it is.
# The reasons are here so a future change has to argue with them rather than
# discover them; they are not parsed.
DIRECTORIES = {
    "etc/linux-hardener": "0755: the config is read unprivileged, and the "
    "signing key inside it is 0400. Narrowing the directory to 0700 was a "
    "defect once already and broke the desktop",
    "var/lib/linux-hardener": "0700: holds checkpoints.db, which stores "
    "captured contents of files including /etc/shadow",
    "var/log/linux-hardener": "0700: holds the tamper-evident audit log",
}

ALL = frozenset(DIRECTORIES)
STATE = frozenset({"var/lib/linux-hardener", "var/log/linux-hardener"})
LOG = frozenset({"var/log/linux-hardener"})

# Each site, the pattern that finds every mode statement in it, the directories
# it is REQUIRED to state a mode for, and a note. The pattern must name two
# groups, `mode` and `dir`. Several files hold more than one kind of statement
# and appear more than once.
#
# `covers` is declared rather than inferred, so a site that stops mentioning a
# directory fails instead of quietly shrinking. That is the difference between
# a waiver and a claim: the rpm %files block genuinely governs only two of the
# three, and saying so is checkable, where "this site may be partial" is not.
#
# (path, kind, pattern, covers, note)
SITES: list[tuple[str, str, str, frozenset[str], str]] = [
    (
        "packaging/PKGBUILD",
        "install",
        r'install -dm(?P<mode>\d{3})\s+"(?P<dir>[^"]*linux-hardener)"',
        ALL,
        "the authority, and what the AUR ships",
    ),
    (
        "packaging/linux-hardener.spec",
        "install",
        r"install -d -m (?P<mode>\d{3}) (?P<dir>\S*linux-hardener)",
        ALL,
        "rpm buildroot",
    ),
    (
        "packaging/linux-hardener.spec",
        "%files attr",
        r"%dir %attr\((?P<mode>\d{3}),[^)]*\)\s*(?P<dir>\S*linux-hardener)",
        STATE,
        "rpm %files. /etc carries no %attr and inherits the install above, "
        "which is checked, so it is not required here",
    ),
    (
        "packaging/debian/rules",
        "install",
        r"install -dm(?P<mode>\d{3})\s+(?P<dir>\S*linux-hardener)",
        ALL,
        "debian binary package",
    ),
    (
        "packaging/debian/postinst",
        "install",
        r"install -dm(?P<mode>\d{3})\s+(?P<dir>\S*linux-hardener)",
        STATE,
        "debian recreates the two state directories on configure. /etc is "
        "shipped by the package and not remade here",
    ),
    (
        "scripts/test/test-package-install.sh",
        "install",
        r"install -dm(?P<mode>\d{3})\s+(?P<dir>\S*linux-hardener)",
        ALL,
        "the suite's hand-kept mirror of the packaging, the copy that drifted",
    ),
    (
        "scripts/test/test-package-install.sh",
        "assertion",
        r"check_dir\s+(?P<dir>\S*linux-hardener)\s+(?P<mode>\d{3})",
        ALL,
        "what the suite actually asserts, as opposed to what it installs",
    ),
    (
        "docs/guide/installation.md",
        "documented command",
        r"install -dm(?P<mode>\d{3})\s+(?P<dir>\S*linux-hardener)",
        ALL,
        "what a reader building from source is told to type",
    ),
    (
        "docs/architecture/architecture.md",
        "prose",
        r"`(?P<dir>/(?:etc|var/lib|var/log)/linux-hardener)[^`]*`\s*\((?P<mode>0?\d{3}) dir",
        ALL,
        "the runtime paths table",
    ),
    (
        "crates/hardener-core/src/config_write.rs",
        "doc comment",
        r"`(?P<dir>/var/log/linux-hardener)[^`]*`\s*\((?P<mode>0?\d{3}) dir",
        LOG,
        "the module that writes the audit log names the mode of the directory "
        "it writes into",
    ),
]

# Shapes that state a mode for one of these directories. A tracked file holding
# one of these and absent from SITES is an unregistered site.
MODE_MARKERS = [
    r"install -dm\d{3}\s+\S*linux-hardener",
    r"install -d -m \d{3} \S*linux-hardener",
    r"%dir %attr\(\d{3},[^)]*\)\s*\S*linux-hardener",
    r"check_dir\s+\S*linux-hardener\s+\d{3}",
    r"`/(?:etc|var/lib|var/log)/linux-hardener[^`]*`\s*\(0\d{3} dir",
]

# Archived material records what was true when it was written and is supposed to
# keep saying so. Excluded by directory, the same rule
# `validate_version_locations.py` uses, so a document archived later does not
# fail this check for being honest about its own date.
ARCHIVE_PREFIXES = (
    "docs/plans/archive/",
    "docs/security/archive/",
)

# Files allowed to carry a marker shape without being a registered site, with
# the reason. Kept to the minimum; each entry is ground this check no longer
# covers. The list is deliberately not a directory prefix.
UNREGISTERED_OK = {
    # Found by the sweep the moment this file became tracked, which is the
    # sweep working. A file that defines what a mode statement looks like has
    # to quote one, and the docstring quotes the exact command that was wrong
    # in installation.md. Nothing installs anything from here.
    "scripts/validate/validate_directory_modes.py": "defines the markers, so it "
    "necessarily contains examples of them",
    # Documents the check itself, including the row describing these modes.
    "scripts/README.md": "the validator reference, which quotes what each check reads",
}


def find_project_root() -> Path:
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root (no Cargo.toml found){NC}")
    sys.exit(1)


def canonical(raw: str) -> str | None:
    """Reduce a path as written in any packaging dialect to one of DIRECTORIES.

    The same directory is spelled five ways: `$pkgdir/etc/...` in the PKGBUILD,
    `%{buildroot}%{_sysconfdir}/...` in the spec, `debian/linux-hardener/...`
    in the debian rules, and bare `/etc/...` in the suite and the docs.
    """
    path = raw.replace("%{buildroot}", "").replace("$pkgdir", "")
    path = path.replace("%{_sysconfdir}", "/etc").replace("%{_localstatedir}", "/var")
    path = path.replace("debian/linux-hardener/", "/")
    path = path.lstrip("/")
    return path if path in DIRECTORIES else None


def normalised_mode(raw: str) -> str:
    """`0755` in prose and `755` in a shell command are the same mode.

    Comparing the digits as written would have reported the architecture table
    as disagreeing with the PKGBUILD about /etc, which it does not. A check that
    cries wolf about a correct site teaches people to skip it.
    """
    return f"{int(raw, 8):03o}"


def read_site(root: Path, path: str, pattern: str) -> tuple[dict[str, set[str]], list[str]]:
    """Every mode a site states, keyed by directory. A set, so a file that
    contradicts itself is visible rather than resolved by whichever match the
    regex reached last."""
    text = (root / path).read_text(encoding="utf-8")
    found: dict[str, set[str]] = {}
    unknown = []
    for match in re.finditer(pattern, text):
        directory = canonical(match.group("dir"))
        if directory is None:
            unknown.append(match.group("dir"))
            continue
        found.setdefault(directory, set()).add(normalised_mode(match.group("mode")))
    return found, unknown


def check(root: Path) -> tuple[list[str], int]:
    missing = [path for path, _, _, _, _ in SITES if not (root / path).exists()]
    if missing:
        return [f"{path} is a registered site and does not exist" for path in sorted(set(missing))], 0

    authority, _ = read_site(root, AUTHORITY, SITES[0][2])
    if set(authority) != set(DIRECTORIES):
        absent = ", ".join(sorted(set(DIRECTORIES) - set(authority))) or "none"
        return [
            f"{AUTHORITY} is the authority and states a mode for "
            f"{len(authority)} of {len(DIRECTORIES)} directories, missing "
            f"{absent}. Nothing can be checked against it"
        ], 0
    for directory, modes in authority.items():
        if len(modes) != 1:
            return [
                f"{AUTHORITY} states {sorted(modes)} for {directory}, so the "
                f"authority contradicts itself and nothing can be checked"
            ], 0

    expected = {directory: modes.pop() for directory, modes in authority.items()}

    failures = []
    compared = 0
    for path, kind, pattern, covers, _note in SITES:
        found, unknown = read_site(root, path, pattern)
        for raw in unknown:
            failures.append(f"{path} ({kind}): '{raw}' matched but is not one of the three directories")

        absent = covers - set(found)
        if absent:
            failures.append(
                f"{path} ({kind}): states no mode for "
                f"{', '.join(sorted(absent))}, which it is registered to cover. "
                f"A directory this site never mentions is one it cannot keep honest"
            )

        for directory, modes in sorted(found.items()):
            compared += 1
            wrong = sorted(mode for mode in modes if mode != expected[directory])
            if wrong:
                failures.append(
                    f"{path} ({kind}): {directory} is {' and '.join(wrong)}, "
                    f"{AUTHORITY} says {expected[directory]}"
                )

    failures.extend(unregistered_sites(root))
    return failures, compared


def unregistered_sites(root: Path) -> list[str]:
    """Any tracked file stating one of these modes without being registered."""
    registered = {path for path, _, _, _, _ in SITES}
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    markers = [re.compile(marker) for marker in MODE_MARKERS]

    failures = []
    for name in out.stdout.splitlines():
        if name in registered or name in UNREGISTERED_OK or name.startswith(ARCHIVE_PREFIXES):
            continue
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for marker in markers:
            if marker.search(text):
                failures.append(
                    f"{name} states a mode for one of these directories and is "
                    f"not registered in {Path(__file__).name}. Register it or "
                    f"stop stating the mode there"
                )
                break
    return failures


def main() -> int:
    print(f"{BLUE}Validating packaged directory modes against {AUTHORITY}...{NC}\n")
    root = find_project_root()

    failures, compared = check(root)

    # Doing nothing must not exit 0, and the cheap way to silence this check is
    # to delete a registration rather than fix the file it names. `covers`
    # already makes a site that stops stating a mode fail, so a count of
    # comparisons cannot be the guard here: no failures implies every covered
    # directory was found, which implies the count is exactly what the
    # registrations promise. A floor on that number would be unreachable, and
    # an unreachable guard is worse than none because it reads like protection.
    #
    # What is reachable is the registry shrinking. Ten sites were found by
    # sweeping the tree; if that becomes nine, someone removed one.
    if len(SITES) < 10:
        print(f"{RED}{len(SITES)} sites registered, fewer than the 10 this check was written against.{NC}")
        print(f"{RED}Deleting a registration is not a way to make this check pass.{NC}")
        return 1

    if failures:
        print(f"  {RED}Directory modes that disagree with {AUTHORITY}:{NC}")
        for failure in failures:
            print(f"    {RED}x{NC} {failure}")
        print(f"\n{RED}{len(failures)} problem(s) across {len(SITES)} registered site(s).{NC}")
        print(f"{YELLOW}Every one of these states what a mode IS. They have to agree.{NC}")
        return 1

    print(f"  {GREEN}v{NC} {compared} statements across {len(SITES)} sites agree with {AUTHORITY}")
    for directory, why in sorted(DIRECTORIES.items()):
        print(f"      /{directory}: {why.split(':')[0]}")
    print(f"\n{GREEN}Directory mode validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
