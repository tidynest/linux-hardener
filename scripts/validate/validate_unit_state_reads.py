#!/usr/bin/env python3
"""
Holds every `systemctl is-enabled` call site to a written answer: does it judge
systemd's word, or systemd's exit status, and why is that right here.

Usage:
    ./scripts/validate/validate_unit_state_reads.py

Exit codes:
    0: Every call site carries an entry whose answer matches its code
    1: A site has no entry, an entry names a site that is gone, an entry's
       answer contradicts the code beneath it, or the pinned count moved

WHY THIS QUESTION AND NOT ANOTHER

`systemctl is-enabled` exits 0 for more states than `enabled`. Measured on a
live host rather than taken from the manual: `static` and `indirect` each print
their own word and exit 0, while `disabled` and `masked` print theirs and exit
1. `enabled-runtime` exits 0 as well, and it is the one that costs the most,
because a runtime enablement lives in /run/systemd/system and the next boot
discards it. So "the command succeeded" and "this unit starts at the next boot"
are different claims, and the exit status only answers the first.

Three plugins ask systemd that question and they do not all want the same
answer, which is exactly why a check that simply banned the exit status would be
wrong:

  - firewall reads the word and keeps a three-way answer, because it tells the
    operator WHICH way the unit fails to start: a masked unit has to be unmasked
    before enabling it can work at all. `NOT_AT_BOOT_STATES` there is the list.
  - audit reads the word and reduces it to a boolean, because it only decides
    whether to run `systemctl enable`. It judged the exit status until an
    `enabled-runtime` host was reported compliant while nothing would start
    auditd after a reboot.
  - services judges the exit status DELIBERATELY. It wants the unit not to run
    at all; its caller skips a directive that is neither enabled nor active, and
    the mask that follows is what stops the unit. A `static` unit is inactive
    and cannot be enabled, yet another unit may pull it in, and it reaches that
    mask only because the exit status reads as enabled. Reading the word there
    would step over it and leave a startable unit unmasked, which is the
    loosening direction.

One shape, three sites, two correct answers and one that was a defect. A check
cannot decide which a new site wants, and that is the argument for a registry of
written answers rather than a rule.

WHAT MAKES THIS MORE THAN A FORM

An entry is not only prose. The answer it gives is cross-checked against the
code beneath it: a site answering `word` must not read `output.success()` in the
function that holds it, and a site answering `exit-status` must. So flipping an
implementation without touching its entry fails here, which is the failure this
exists to catch. The prose is for the reader; the keyword is for the check.

That cross-check is deliberately crude, and crude is what makes it honest. It
asks whether the enclosing function mentions `output.success()`, not what the
function does with it. A site that reads both, or that passes the output to a
helper which judges it elsewhere, would satisfy the keyword while doing
something this cannot see. None exists today, and a new one would be a reason to
sharpen this rather than a hole to leave quiet.

WHAT IT CANNOT SEE

  - A call whose arguments are not the literal string "is-enabled": built
    through `format!`, assembled in a variable, or run through a shell. The
    three sites today all pass the literal.
  - `systemctl is-active`, `is-failed` and the rest. `is-active` exits 0 only
    for a running unit, so its status and its word answer the same question;
    that is why only `is-enabled` is held here. If that ever stops being true of
    another subcommand, it belongs in this registry too.
  - Anything under a `#[cfg(test)]` module, and any line that is a comment. Test
    fixtures name the states on purpose and a doc comment showing the call is
    not a call. That exclusion is a cut at the first `#[cfg(test)]` rather than
    a parse, so a production function written BELOW the test module is invisible
    too. Measured, not assumed: a site placed after the test module was not
    counted. Every source in this workspace puts its test module last, so
    nothing is missed today, and a file that stops doing that would hide a site
    here rather than fail.
  - Whether the ANSWER is right. That a site reads the word does not mean it
    reads the right word, and `enabled` being the only permanent state is a
    claim this file makes rather than checks.

EXPECTED_SITE_COUNT is pinned as a literal for the reason every table length in
scripts/test/differential-suite.sh is pinned: a check that counts its own
expected size cannot fail when a site is added, and a site added without an
answer is the one thing this exists to catch. It is also the guard against this
file quietly matching nothing at all, which is how a check comes to pass by
finding no work to do.
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

CRATES = Path("crates")

# The number of production `systemctl is-enabled` call sites, pinned rather than
# counted off the registry, which would follow the registry down.
EXPECTED_SITE_COUNT = 3

# The literal every site passes today. A call that builds this string any other
# way is invisible here, which the docstring says rather than hides.
PROBE = '"is-enabled"'

# Everything from the first `#[cfg(test)]` onwards is a test module, whose
# fixtures name states deliberately and must not be held to the registry.
TEST_MODULE = "#[cfg(test)]"

# A whole file gated as tests, rather than a module at the end of one.
FILE_IS_TEST = "#![cfg(test)]"

# The enclosing function is found by walking back to the nearest `fn`, which is
# the unit the cross-check reads: a site's judgement lives in the function that
# holds it in all three cases today.
FUNCTION = re.compile(r"(?:async\s+)?fn\s+(\w+)")

# The read that separates the two answers. `output.success()` is how a caller
# asks for the exit status; a site judging the word compares the stdout instead.
STATUS_READ = "output.success()"

# Every production call site, keyed by file and enclosing function, answering
# `word` or `exit-status` with the reason that answer is right there.
REGISTRY = {
    ("hardener-plugins/src/firewall/mod.rs", "unit_boot_persistence"): (
        "word",
        "tells the operator which of the several ways of not starting at boot "
        "this host is in, so it needs the word itself and not a boolean; "
        "NOT_AT_BOOT_STATES beside it is the list, and a state it does not "
        "recognise is Undeterminable rather than a pass",
    ),
    ("hardener-plugins/src/audit/mod.rs", "is_auditd_enabled"): (
        "word",
        "decides whether to run `systemctl enable`, and only the exact word "
        "`enabled` is a permanent enablement; it judged the exit status until "
        "an enabled-runtime host read as compliant while nothing would start "
        "auditd after a reboot",
    ),
    ("hardener-plugins/src/services/mod.rs", "is_service_enabled"): (
        "exit-status",
        "deliberate: this plugin wants the unit not to run at all, and a "
        "static unit reaches the unconditional mask only because the status "
        "reads as enabled; reading the word would leave a unit another unit "
        "can pull in unmasked, which is the loosening direction. ENABLED_STATES "
        "in the same file spells the seven exit-zero states out for the batched "
        "scan path, so both of its paths agree",
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


def production_text(path: Path) -> str:
    """`path` with its test module removed.

    Cut at the first `#[cfg(test)]` rather than parsed, because a source that
    keeps its test module inline puts it last, and a partial cut would be worse
    than none: it would drop production code and could only ever hide a site.

    A file that opens with `#![cfg(test)]` is a test module in its own right,
    split out of the source it exercises, so all of it is test text and none of
    it is a site. Without this the split would resurrect every site a test
    fixture makes, which is how four mock firewall fixtures came to be asked a
    question only the product can answer.
    """
    text = path.read_text()
    if FILE_IS_TEST in text[:text.find("\n\n") + 2 or len(text)]:
        return ""
    cut = text.find(TEST_MODULE)
    return text if cut == -1 else text[:cut]


def enclosing_function(text: str, index: int) -> tuple[str, str]:
    """The name and body of the function containing `index`.

    Returns ("", "") when no `fn` precedes the index, which cannot happen for a
    call site and is reported as an unregistered site rather than guessed at.
    The body is taken by brace depth from the signature's opening brace, so a
    nested block or a closure inside it is included, which is what the
    cross-check wants: a judgement made in a closure is still made here.
    """
    matches = list(FUNCTION.finditer(text, 0, index))
    if not matches:
        return "", ""
    match = matches[-1]
    open_brace = text.find("{", match.end())
    if open_brace == -1:
        return match.group(1), ""
    depth = 0
    for position in range(open_brace, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return match.group(1), text[open_brace : position + 1]
    return match.group(1), text[open_brace:]


def sites_in(path: Path, relative: str) -> list[tuple[str, str, int, str]]:
    """Every production probe in `path` as (relative, function, line, body)."""
    text = production_text(path)
    found = []
    for match in re.finditer(re.escape(PROBE), text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        # A doc comment showing the call is not a call, and neither is a line
        # of prose naming the probe.
        if text[line_start : match.start()].lstrip().startswith("//"):
            continue
        line = text.count("\n", 0, match.start()) + 1
        name, body = enclosing_function(text, match.start())
        found.append((relative, name, line, body))
    return found


def main():
    print(f"{BLUE}Checking how every `systemctl is-enabled` site is judged...{NC}\n")

    root = find_project_root()
    crates_dir = root / CRATES
    if not crates_dir.is_dir():
        print(f"{RED}Error: {CRATES} not found{NC}")
        sys.exit(1)

    sources = sorted(crates_dir.rglob("src/**/*.rs"))
    sites = []
    for path in sources:
        sites.extend(sites_in(path, str(path.relative_to(crates_dir))))

    problems = False

    unregistered = [site for site in sites if (site[0], site[1]) not in REGISTRY]
    if unregistered:
        problems = True
        print(f"{RED}{len(unregistered)} call site(s) with no registry entry:{NC}\n")
        for relative, name, line, _ in unregistered:
            print(f"  {RED}{CRATES}/{relative}:{line}{NC}")
            print(f"    `systemctl is-enabled` inside {name or '<no function>'}()")
            print("    and nothing says whether it judges systemd's word or")
            print("    systemd's exit status, which are different answers")
            print("    add an entry saying which, and why that is right here\n")

    found_keys = {(relative, name) for relative, name, _, _ in sites}
    stale = [key for key in REGISTRY if key not in found_keys]
    if stale:
        problems = True
        print(f"{RED}{len(stale)} registry entry(ies) naming a site that is gone:{NC}\n")
        for relative, name in stale:
            print(f"  {RED}{relative}{NC}: {name}()")
            print("    no `systemctl is-enabled` here any more; remove the")
            print("    entry, or fix the name if the function was renamed\n")

    # The cross-check: an answer that the code beneath it contradicts. This is
    # the failure the registry exists to catch, since prose alone goes stale
    # silently while an implementation is flipped in one line.
    contradicted = []
    for relative, name, line, body in sites:
        answer = REGISTRY.get((relative, name))
        if answer is None:
            continue
        reads_status = STATUS_READ in body
        if answer[0] == "word" and reads_status:
            contradicted.append((relative, name, line, "word", "reads"))
        elif answer[0] == "exit-status" and not reads_status:
            contradicted.append((relative, name, line, "exit-status", "does not read"))

    if contradicted:
        problems = True
        print(f"{RED}{len(contradicted)} entry(ies) contradicted by the code:{NC}\n")
        for relative, name, line, answer, reads in contradicted:
            print(f"  {RED}{CRATES}/{relative}:{line}{NC}")
            print(f"    the entry answers `{answer}` and {name}() {reads}")
            print(f"    {STATUS_READ}")
            print("    either the code changed its mind or the entry did;")
            print("    whichever it was, they no longer agree\n")

    if len(sites) != EXPECTED_SITE_COUNT:
        problems = True
        print(f"{RED}Site count is {len(sites)}, expected {EXPECTED_SITE_COUNT}{NC}")
        print("  A site was added or removed. Answer the question for the new")
        print("  one, or drop its entry, then move the pin.\n")

    print(f"Scanned {GREEN}{len(sources)}{NC} source files")
    print(f"Found {GREEN}{len(sites)}{NC} `systemctl is-enabled` call site(s)\n")

    if problems:
        print(f"{RED}Unit state read validation failed{NC}")
        sys.exit(1)

    by_word = sum(1 for answer, _ in REGISTRY.values() if answer == "word")
    print(f"{GREEN}All {len(sites)} call sites carry an answer the code agrees with{NC}")
    print(f"  judged on the word:        {by_word}")
    print(f"  judged on the exit status: {len(REGISTRY) - by_word}")
    print(
        f"{YELLOW}This proves each site says which it does and that the two"
        f" agree. It does not prove the answer is the right one for that"
        f" plugin, nor that the word it accepts is the right word.{NC}"
    )
    print(
        f"{YELLOW}It reads only the literal \"is-enabled\": a probe built"
        f" through format!, a variable, or a shell is not a site here.{NC}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
