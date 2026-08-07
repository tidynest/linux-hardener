#!/usr/bin/env python3
"""
Validates that no test can pass having asserted nothing.

A test whose every assertion sits inside an `if`, a `for` or a `match` arm does
not assert when the condition does not hold. It still exits 0, it still counts
towards the suite total, and the total is what everyone reads. That is the
project's oldest failure mode wearing a green tick: a control that cannot reach
the answer reports the reassuring one.

Issue #46 is the family. Seven plugin tests ran against whatever machine the
suite happened to be on and then wrapped their real assertions in a conditional,
so:

    match result {
        Ok(report) => {
            assert_eq!(report.plugin_id, PluginId::new("ssh-hardening"));
            if report.is_valid {
                assert!(report.issues.is_empty());
            }
        }
        Err(_) => {
            // Validation may fail if sshd_config doesn't exist.
        }
    }

On a host with no `sshd_config` that test asserts one string equality. On a host
with any validation issue it asserts one string equality. It was not `#[ignore]`d
and it ran in every suite, green, for as long as it existed.

## The rule

Every test function must carry at least one assertion at the top level of its
own body, outside every conditional and every loop. A test may branch all it
likes underneath that, but something must be true no matter which way the
branches go, and if nothing is, there is no test.

## What this deliberately does NOT check

It does not judge whether the top-level assertion is a good one. A test that
asserts only its own plugin id satisfies this and is still weak. That judgement
is a reading, not a grep, and pretending otherwise would put a number on
something this script cannot see.

It does not follow calls. An assertion inside a helper the test calls is
invisible here, so a test whose only top-level statement is `check_it(&result)`
is reported. Declare such a test with the marker below rather than weakening the
rule for everyone.

## The escape hatch, and why it is a comment rather than a name

A test whose top-level assertions genuinely live in a helper, or which is
deliberately an exploratory harness, carries

    // assertions-in-helper: <reason>

on the line above the `#[test]` or `#[tokio::test]` attribute. It is a comment
rather than a naming convention because the reason is the point: a reader meets
the reason at the site, and a grep for the marker lists every exemption in the
tree with its justification attached.

Usage:
    ./scripts/validate/validate_test_assertions.py [--all]

    `--all` is the whole tree, and it is what the gate runs. It adds every
    `.rs` file under `crates/*/src/` and `src-tauri/src/` to the integration
    suites under `crates/*/tests/` and `src-tauri/tests/`. Not the file names
    unit tests are conventionally split out under, every file: a test module is
    wherever someone put it, and scoping by convention meant the run twice
    reported a whole tree it had not read. See `test_files` for both misses.

    Without it the scope is those integration suites alone. That was the
    default the gate used until issue #130, and it meant the check read 646
    tests, reported "all 646 assert unconditionally", and never opened the
    inline `#[cfg(test)]` modules under `src/` where most of this workspace's
    tests live. Run that way it found 0 offenders; run over the tree it found
    46, and a test that asserted nothing whatsoever had already been sitting in
    the unread half. That 46 is the check as it stood before the widening, run
    with `--all` against `3e22d29`, the commit the widening landed on; the same
    reading against this branch's base is 47, and a bare number with neither
    tree nor check version beside it is what went stale here once already. A check that reports a clean tree it cannot see is the
    failure this file was written about, so the narrow scope is kept only as a
    faster local pass and never as the gate.

Exit codes:
    0: every test function asserts something unconditionally
    1: at least one test can run to completion having asserted nothing
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

# Any attribute ending in `test`, so `#[tokio::test]` and `#[wasm_bindgen_test]`
# count. An earlier tool in this repo matched the bare `#[test]` alone and
# reported that two files full of async tests held none.
TEST_ATTR = re.compile(r"^\s*#\[(\w+::)*test\]\s*$")
FN_START = re.compile(r"^\s*(pub )?(async )?fn\s+(\w+)")

# `assert!`, `assert_eq!`, `debug_assert!`, `panic!`, `unreachable!` and the
# `expect`/`unwrap` family all fail the test when the thing they guard is not
# so. `expect` is included deliberately: a test whose only unconditional
# statement is `plugin.scan(..).await.expect("scan")` does assert something,
# namely that the call succeeded, and calling that "no assertion" would push
# people to write a weaker test to satisfy this script.
#
# `expect_err` and `unwrap_err` are the same family pointed the other way: they
# fail the test when the call *succeeded*. Leaving them out said that a test
# proving a refusal asserts nothing, which is backwards. The whole point of
# `probe_rejects_an_unrecognised_marker` is that the parse must not succeed, and
# the tree's refusal tests are exactly the ones guarding the sentinel-conflation
# bugs this project has been paying for.
ASSERTION = re.compile(
    r"\b(assert|assert_eq|assert_ne|debug_assert|panic|unreachable)!"
    r"|\.(expect|unwrap)(_err)?\("
)

EXEMPTION = re.compile(r"//\s*assertions-in-helper:\s*(\S.*)")

# A block opener at the start of a statement. `if let`, `while let` and `match`
# are included; a bare `{` block is not, because it does not condition anything.
BLOCK_OPENER = re.compile(r"^\s*(\}\s*)?(if|for|while|match|else)\b")

# A `for` whose subject is written out at the site runs a known number of times,
# and a table-driven test is the good form of the shape this script hunts, not
# the bad one. `for value in ["without-password", "forced-commands-only"]` is a
# test that says exactly what it covers. Only a loop over something computed can
# quietly run zero times.
LITERAL_LOOP = re.compile(r"^\s*for\b.*\bin\s*&?(\[|vec!\[)")

# The same table one line further away. A case list long enough to be worth
# writing is too long to sit in the `for` header, so it is bound first and
# looped over by name, and the count is just as countable by the reader for
# being on the line above. `for (family, name, version, expected) in cases`
# reads zero times only if `cases` does, and `cases` is right there.
#
# The binding must not be `mut`: a `let mut` can be drained or filtered between
# its literal and the loop, and then the count at the site is not the count that
# runs. A subject that is a path rather than a bare name (`ComplianceFramework::
# ALL`, `CRITICAL_PERMISSIONS`) does not match either, deliberately. Those tables
# live in another file, this script cannot see whether they are empty, and an
# emptied table is precisely the silent vacuity it exists to catch.
NAMED_LOOP = re.compile(r"^\s*for\b.*\bin\s+&?([A-Za-z_]\w*)\s*\{")
EMPTY_LITERAL = re.compile(r"=\s*&?(\[\s*\]|vec!\[\s*\])")

# The openers `blank_literals` needs. A character literal is matched whole, so
# that the `'` of a lifetime is never read as an opening quote.
RAW_OPEN = re.compile(r'r(#*)"')
CHAR_LITERAL = re.compile(r"'(\\.|[^'\\])'")


def loop_runs_a_countable_number_of_times(body: list[str], index: int, stripped: str) -> bool:
    """Whether this `for`'s subject is written out where the reader can count it."""
    if LITERAL_LOOP.match(stripped):
        return True

    named = NAMED_LOOP.match(stripped)
    if not named:
        return False

    binding = re.compile(rf"^\s*(let|const)\s+{re.escape(named.group(1))}\b[^=]*=\s*&?(\[|vec!\[)")
    return any(
        binding.match(line) and not EMPTY_LITERAL.search(line) for line in body[:index]
    )


def find_project_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "Cargo.toml").exists() and (parent / "crates").is_dir():
            return parent
    return Path.cwd()


def test_files(root: Path, everything: bool) -> list[Path]:
    """The files in scope, sorted so the report is stable between runs.

    `--all` globs every `.rs` under `src/` rather than the file names unit tests
    are usually split out under, and that is a correction rather than a
    flourish. The globs were `crates/*/src/**/tests.rs` and
    `src-tauri/src/**/*_tests.rs`, one convention each, and each one missed
    exactly what the other caught: `crates/*/src/**/*_tests.rs` and
    `src-tauri/src/**/tests.rs` were both unread. 62 tests in 4 files sat
    outside them while the docstring said the run was the whole tree, and 48 of
    those were `src-tauri/src/validation/tests.rs`, the check that decides
    whether a path the desktop was handed may be written to. 9 of its tests
    asserted nothing on a host with no home directory.

    Naming one more convention would have closed today's gap and reopened on the
    next file named a third way, so scope is no longer a guess about file names.
    A source file with no test functions in it contributes nothing to the walk
    and costs a regex pass, and the whole tree reads in well under a second.
    """
    found = sorted(root.glob("crates/*/tests/**/*.rs")) + sorted(
        root.glob("src-tauri/tests/**/*.rs")
    )
    if everything:
        found += sorted(root.glob("crates/*/src/**/*.rs"))
        found += sorted(root.glob("src-tauri/src/**/*.rs"))
    return found


def strip_strings(line: str) -> str:
    """Blanks string literals so their braces do not move the depth count."""
    return re.sub(r'"(\\.|[^"\\])*"', '""', line)


def blank_literals(lines: list[str]) -> list[str]:
    """The file with every brace that is not code neutralised, line count intact.

    A line at a time is not enough, and the shortfall was not cosmetic. Blanking
    each line on its own left 37 test functions in this tree unread, because a
    brace that is not code still moved the walk's idea of where a test body
    ends, and a body that ends in the wrong place takes every test after it out
    of scope. A validator that silently stops reading is the failure it exists
    to catch, so the three sources are handled here rather than worked around at
    the call sites:

    - A string literal that spans lines. `firewall_mock_tests.rs` holds whole
      nftables rulesets in one, `table inet linux_hardener {` and all, and a
      per-line regex can never pair those quotes. 34 tests in that one file.
    - A character literal. `json_from(&out.stdout, '{')` opened a block that
      nothing closed and swallowed the three tests that followed it.
    - A brace inside a comment. Only the braces are blanked there, not the text,
      because the `assertions-in-helper` marker is read off these same lines.

    Lifetimes are the trap in the character case: `&'a str` and `<'a>` must not
    read as an opening quote, so a character literal is recognised only in full,
    as a quote-delimited single character or escape.
    """
    blanked: list[str] = []
    normal = False
    raw_hashes: int | None = None

    for line in lines:
        rendered: list[str] = []
        index = 0
        while index < len(line):
            if raw_hashes is not None:
                closer = '"' + "#" * raw_hashes
                if line.startswith(closer, index):
                    raw_hashes = None
                    rendered.append('""')
                    index += len(closer)
                else:
                    index += 1
                continue

            if normal:
                if line[index] == "\\":
                    index += 2
                    continue
                if line[index] == '"':
                    normal = False
                    rendered.append('""')
                index += 1
                continue

            if line.startswith("//", index):
                rendered.append(line[index:].replace("{", " ").replace("}", " "))
                break

            raw = RAW_OPEN.match(line, index)
            if raw and (index == 0 or not (line[index - 1].isalnum() or line[index - 1] == "_")):
                raw_hashes = raw.group(1).count("#")
                index = raw.end()
                continue

            if line[index] == '"':
                normal = True
                index += 1
                continue

            character = CHAR_LITERAL.match(line, index)
            if character:
                rendered.append("''")
                index = character.end()
                continue

            rendered.append(line[index])
            index += 1

        blanked.append("".join(rendered))

    return blanked


def block_extent(body: list[str], start: int) -> int:
    """Index of the line holding the brace that closes the block opened at `start`.

    Two things make this more than a running brace count, and both were found
    by this script reporting `if cond { assert } else { panic }` as a test that
    asserts nothing.

    The first is that `} else {` nets to zero. Counted a line at a time, the
    closing brace of one branch and the opening brace of the next cancel, the
    depth never falls back, and the scan runs on to the end of the whole chain.
    The caller then sees no `else` where one is written and reads a total
    if/else as an `if` with no `else`, which is the one shape it is supposed to
    accept. So the close is recognised by a line that *begins* with `}` while
    exactly one block is open, which is the closing brace whatever follows it on
    that line.

    The second is that an opener carries braces of its own. `if let
    Command::Scan { plugin, .. } = cli.command {` closes a struct pattern before
    it opens a block, so the depth returns to zero mid-header and a scan that
    stopped there would call the pattern the block. The header is therefore
    measured whole, and the search for the close starts on the line after it. A
    leading `}` is dropped from that measurement for the same reason, so a
    `} else {` passed in as its own opener measures its own branch rather than
    starting one short.
    """
    header = strip_strings(body[start]).strip()
    if header.startswith("}"):
        header = header[1:]
    depth = header.count("{") - header.count("}")

    # A block that opens and closes inside its own header holds nothing worth
    # walking into, and has no separate closing line to find.
    if depth <= 0 and "{" in header:
        return start

    for index in range(start + 1, len(body)):
        text = strip_strings(body[index])
        if depth == 1 and text.strip().startswith("}"):
            return index
        depth += text.count("{") - text.count("}")
    return len(body) - 1


def split_arms(block: list[str]) -> list[list[str]]:
    """The arms of a `match` block, by the depth-zero `=>` that opens each."""
    arms: list[list[str]] = []
    current: list[str] | None = None
    depth = 0
    for raw in block:
        text = strip_strings(raw)
        if depth == 0 and "=>" in text:
            if current is not None:
                arms.append(current)
            current = []
        if current is not None:
            current.append(raw)
        depth += text.count("{") - text.count("}")
        depth = max(0, depth)
    if current is not None:
        arms.append(current)
    return arms


def asserts_on_every_path(body: list[str]) -> bool:
    """Whether every path through `body` reaches an assertion.

    A plain assertion at the top level settles it. So does a construct that
    covers all its own paths: a `match`, which Rust makes exhaustive, and an
    `if` chain that ends in `else`, provided every arm or branch asserts in
    turn. That distinction is the whole reason this is recursive rather than a
    depth counter. `test_ssh_apply_requires_root` matches on a result and
    panics in the `Err` arm, so it cannot pass having asserted nothing, and a
    check that flagged it would be teaching people to write the weaker form.

    A `for` or `while` never counts, however much it asserts inside. A loop
    over an empty collection runs its body zero times, and "the collection was
    not empty" is exactly the thing such a test is failing to say.
    """
    index = 0
    while index < len(body):
        raw = body[index]
        line = strip_strings(raw)
        stripped = line.strip()

        if stripped.startswith("//") or not stripped:
            index += 1
            continue

        opener = BLOCK_OPENER.match(stripped)
        if not opener:
            if ASSERTION.search(line):
                return True
            index += 1
            continue

        keyword = opener.group(2)
        end = block_extent(body, index)
        inner = body[index + 1:end]

        if keyword == "match" and split_arms(inner) and all(
            asserts_on_every_path(arm) for arm in split_arms(inner)
        ):
            return True

        if (
            keyword == "for"
            and loop_runs_a_countable_number_of_times(body, index, stripped)
            and asserts_on_every_path(inner)
        ):
            return True

        if keyword in ("if", "else"):
            # Walk the whole chain, requiring a final bare `else` and an
            # assertion in every branch. An `if` with no `else` is a skip.
            branches = [inner]
            closed = False
            cursor = end
            while cursor < len(body):
                tail = strip_strings(body[cursor]).strip()
                if not tail.startswith("}") or "else" not in tail:
                    break
                nxt = block_extent(body, cursor)
                branches.append(body[cursor + 1:nxt])
                closed = not re.search(r"else\s+if\b", tail)
                cursor = nxt
                if closed:
                    break
            if closed and all(asserts_on_every_path(branch) for branch in branches):
                return True
            index = cursor if cursor > index else end + 1
            continue

        index = end + 1
    return False


def check_file(path: Path) -> tuple[list[tuple[int, str]], int]:
    """Returns the offending (line, name) pairs and how many tests were read."""
    lines = blank_literals(path.read_text(encoding="utf-8").split("\n"))
    offenders: list[tuple[int, str]] = []
    total = 0

    index = 0
    while index < len(lines):
        if not TEST_ATTR.match(lines[index]):
            index += 1
            continue

        # Walk back over the attributes and comments above the `#[test]` to
        # find an exemption marker written for this test.
        exempt = False
        look = index - 1
        while look >= 0 and (lines[look].strip().startswith(("#[", "//", "///"))):
            if EXEMPTION.search(lines[look]):
                exempt = True
            look -= 1

        # Find the signature, skipping any further attributes such as `#[ignore]`.
        start = index + 1
        while start < len(lines) and not FN_START.match(lines[start]):
            start += 1
        if start >= len(lines):
            break

        name = FN_START.match(lines[start]).group(3)
        total += 1

        # The body runs from the signature to the brace that closes it. The
        # walk has to know it has been inside the body before it can recognise
        # the end: testing `depth <= 0` alone is true on the signature line
        # before its own `{` is counted, and testing it together with "this
        # line has a brace" never fires on the closing `}`, which has no `{`.
        # Written the second way, this loop ran to end of file and the scan
        # read one test per file. It reported a clean tree, which is the exact
        # failure it exists to catch.
        depth = 0
        entered = False
        end = start
        for end in range(start, len(lines)):
            text = re.sub(r'"(\\.|[^"\\])*"', '""', lines[end])
            depth += text.count("{") - text.count("}")
            entered = entered or depth > 0
            if entered and depth <= 0:
                break

        if not exempt and not asserts_on_every_path(lines[start + 1:end]):
            offenders.append((start + 1, name))
        index = end + 1

    return offenders, total


def main() -> int:
    everything = "--all" in sys.argv
    print(f"{BLUE}Validating that every test asserts something unconditionally...{NC}\n")
    root = find_project_root()

    files = test_files(root, everything)
    if not files:
        print(f"{RED}No test files found. The glob reached nothing, so this run proves nothing.{NC}")
        return 1

    all_offenders: list[tuple[Path, int, str]] = []
    read = 0
    for path in files:
        offenders, total = check_file(path)
        read += total
        all_offenders += [(path.relative_to(root), line, name) for line, name in offenders]

    # Doing nothing must never exit 0. If the walk found no test functions at
    # all, the filters are wrong and a pass here would mean nothing.
    if read == 0:
        print(f"{RED}Read {len(files)} file(s) and found no test functions at all.{NC}")
        print(f"{RED}That is a broken matcher rather than a clean tree.{NC}")
        return 1

    if all_offenders:
        print(f"  {YELLOW}Tests that can run to completion having asserted nothing:{NC}")
        for path, line, name in all_offenders:
            print(f"    {RED}x{NC} {path}:{line}  {name}")
        print(
            f"\n{RED}{len(all_offenders)} of {read} test(s) hold every assertion "
            f"inside a conditional.{NC}"
        )
        print(
            f"{YELLOW}Move one assertion out to the top level of the test, or, if the "
            f"assertions genuinely live in a helper, write{NC}"
        )
        print(f"{YELLOW}    // assertions-in-helper: <reason>{NC}")
        print(f"{YELLOW}above the test attribute.{NC}")
        return 1

    print(f"  {GREEN}v{NC} All {read} test(s) across {len(files)} file(s) assert unconditionally")
    print(f"\n{GREEN}Test assertion validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
