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

    Default scope is the integration suites under `crates/*/tests/` and
    `src-tauri/tests/`. `--all` adds the unit-test files split out under
    `src/`, which is slower and noisier.

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
ASSERTION = re.compile(r"\b(assert|assert_eq|assert_ne|debug_assert|panic|unreachable)!|\.expect\(|\.unwrap\(")

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


def find_project_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "Cargo.toml").exists() and (parent / "crates").is_dir():
            return parent
    return Path.cwd()


def test_files(root: Path, everything: bool) -> list[Path]:
    """The files in scope, sorted so the report is stable between runs."""
    found = sorted(root.glob("crates/*/tests/**/*.rs")) + sorted(
        root.glob("src-tauri/tests/**/*.rs")
    )
    if everything:
        found += sorted(root.glob("crates/*/src/**/tests.rs"))
        found += sorted(root.glob("src-tauri/src/**/*_tests.rs"))
    return found


def strip_strings(line: str) -> str:
    """Blanks string literals so their braces do not move the depth count."""
    return re.sub(r'"(\\.|[^"\\])*"', '""', line)


def block_extent(body: list[str], start: int) -> int:
    """Index of the line closing the block opened at or after `start`."""
    depth = 0
    entered = False
    for index in range(start, len(body)):
        text = strip_strings(body[index])
        depth += text.count("{") - text.count("}")
        entered = entered or depth > 0
        if entered and depth <= 0:
            return index
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

        if keyword == "for" and LITERAL_LOOP.match(stripped) and asserts_on_every_path(inner):
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
    lines = path.read_text(encoding="utf-8").split("\n")
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
