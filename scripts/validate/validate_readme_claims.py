#!/usr/bin/env python3
"""
Holds each limitation README.md's "Known limitations" section states against
the code that would make it false.

Every other validator in this directory reads structure: a table row, a
heading, a registry entry, a count. A limitation is different because it is
a claim of *absence*, and absence leaves no structure to read. The sentence
"`scan --format json` reports a plugin whose scan failed identically to one
that passed, because the per-plugin success flag is not serialised" sat in
README.md for a month while every entry of that output carried
`scan_success` and `scan_error`, and nothing went red: the renderer gaining
a field changes no heading, no count and no link.

The dates are worth recording because they are not a story of neglect. The
sentence was added by `a6b8de69` at 10:02 on 2026-07-27, when it was true.
`685cf305` taught the renderer the fields at 14:31 the same day, and the
document it had just corrected was not swept again. A fix and its sibling
claim can be four and a half hours apart and still miss each other; this
check exists so the second half of that pair cannot land silently again.

Each machine-checked predicate reads the code that *produces* the behaviour
the bullet describes, never the type that carries it. That distinction is
the lesson of the fixing commit's own message, which dated the field
"2025-11-25": that is the struct field's birthday, found by searching for
the name and taking the oldest hit, and the renderer emitted nothing until
`685cf305`. A field existing on a type is not that field reaching a
consumer, and only the second is what a limitation promises. Predicates
here name the file they read and fail, with a reason, when that file no
longer carries the shape they were written against.

Coverage is reported rather than maximised. Of the five bullets currently
registered, three are machine-checked and two are judgements no parser
reaches ("some changes need a reboot", "some hardening breaks specific
applications"); those are registered as judgements so the summary says
three of five rather than silently skipping what it cannot see. A bullet
that is reworded beyond its locator fails as "not found", which is the
registry asking to move with the text, not noise: a limitation that no
longer says what it did needs its predicate re-read by a human regardless.

The checker's own cases run quietly before every verdict, `--self-test` to
see them named. A predicate that can no longer recognise the shape it was
written against is an internal failure and exits non-zero rather than
passing vacuously.

Usage:
    ./scripts/validate/validate_readme_claims.py
    ./scripts/validate/validate_readme_claims.py --self-test

Exit codes:
    0: every registered bullet is present, and every predicate holds
    1: a bullet moved or vanished, a predicate failed, or a self-test did
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

README = Path("README.md")
OUTPUT_RS = Path("crates/hardener-cli/src/output.rs")
MAC_MOD = Path("crates/hardener-plugins/src/mac/mod.rs")
PERMISSIONS_MOD = Path("crates/hardener-plugins/src/permissions/mod.rs")

# The JSON renderer's function. Its return type is the payload's shape: a
# Vec serialised straight to stdout is a bare array, and a wrapper object
# with a schema field would change this signature or the call that
# serialises it. Both are asserted, so either half of a future "version the
# output" change fails here until README's bullet moves with it.
#
# The parameter list is matched greedily to the line's last closing paren:
# it is a tuple type containing parens of its own
# (`&[(PluginMetadata, ScanResult)]`), and a `[^)]*` body stops at the
# first of those, which never reaches the return type. That shape of mistake
# passes every case expected to fail, for the wrong reason each time, and
# only the case expected to pass exposes it - which is why the self-test
# table below asserts each failure's own detail rather than its bare
# verdict.
SCAN_JSON_SIGNATURE = re.compile(r"fn scan_json\(.*\)\s*->\s*Vec<serde_json::Value>")
SCAN_JSON_CALLER = 'serde_json::to_string_pretty(&scan_json('


def scan_json_body(text: str) -> str | None:
    """The body of `fn scan_json`, or None if the function is gone."""
    start = text.find("fn scan_json")
    if start == -1:
        return None
    end = text.find("\n}", start)
    return text[start:end] if end != -1 else text[start:]


def check_json_output(text: str) -> tuple[bool, str]:
    """README: "emits a bare array with no schema version ... every entry
    carries `scan_success` and `scan_error`"."""
    if not SCAN_JSON_SIGNATURE.search(text):
        return False, (
            "scan_json no longer returns Vec<serde_json::Value>, so the payload "
            "is no longer a bare array - or the function moved, and the "
            "predicate needs re-registering against its new home"
        )
    if SCAN_JSON_CALLER not in text:
        return False, (
            "the serialisation call no longer passes scan_json's Vec straight "
            "to the serialiser; a wrapper object may have been added around it"
        )
    body = scan_json_body(text)
    if body is None:
        return False, "scan_json has no extractable body to read keys from"
    for key in ("scan_success", "scan_error"):
        if f'"{key}"' not in body:
            return False, f'scan_json no longer emits "{key}" on its entries'
    if re.search(r'"(schema_version|schema|version)"\s*:', body):
        return False, (
            "a version key appeared inside scan_json; the bullet that says "
            "there is none is now false"
        )
    return True, (
        "scan_json's Vec is serialised unwrapped, so the payload is a bare "
        "array, with scan_success and scan_error on every entry and no "
        "version key"
    )


def check_mac(text: str) -> tuple[bool, str]:
    """README: "SELinux and AppArmor policies are detected, not managed" and,
    per the plugin table, "SELinux changes are runtime-only". The positive
    half (a setenforce execution exists) and the negative half (no
    write_file call site exists in the module) each name one direction of
    that sentence."""
    writes = text.count(".write_file(")
    if writes:
        return False, (
            f"the MAC plugin has {writes} write_file call site(s); it manages "
            "persistent state now, so 'detected, not managed' is no longer "
            "the whole truth"
        )
    if "setenforce" not in text:
        return False, (
            "no setenforce execution remains in the MAC plugin; it no longer "
            "makes even runtime changes, and the bullet understates it"
        )
    return True, "no write_file call sites; setenforce present (runtime-only)"


def check_permissions(text: str) -> tuple[bool, str]:
    """README: a permissions finding "can name a package-owned file under
    /usr/etc that the tool deliberately never writes ... apply stays silent
    about it by design". The VendorOnly variant is the marker of that
    decision, its explanation string is what a reader of the finding sees,
    and the `install` remediation is the copy command the bullet says scan
    prints instead of acting."""
    anchors = [
        ("VendorOnly", "the VendorOnly variant is gone from PermissionCheck"),
        (
            "install -o root -g root -m",
            "the copy-into-/etc remediation command has changed shape",
        ),
        (
            "does not write the vendor layer",
            "the finding explanation no longer states that the vendor layer "
            "is never written",
        ),
    ]
    for needle, failure in anchors:
        if needle not in text:
            return False, failure
    return True, (
        "VendorOnly present, with the copy remediation and the "
        "never-writes-the-vendor-layer explanation"
    )


# One row per bullet under "### Known limitations", in README order. The
# locator must find the bullet; the predicate, when present, must hold
# against the file named in `reads`. A `judgement` row has no predicate and
# is counted in the summary as registered but not machine-checked.
REGISTRY = [
    {
        "id": "reboot-required",
        "locator": re.compile(r"- Some changes need a reboot to take full effect\."),
        "reads": None,
        "predicate": None,
        "judgement": "whether a change needs a reboot is a property of the kernel "
        "and daemons the tool configures, not of anything in this tree",
    },
    {
        "id": "staging",
        "locator": re.compile(r"- Some hardening breaks specific applications\. Test in staging\."),
        "reads": None,
        "predicate": None,
        "judgement": "which applications break under which hardening is a fact "
        "about software outside the repository",
    },
    {
        "id": "mac-detected-not-managed",
        "locator": re.compile(r"- SELinux and AppArmor policies are detected, not managed\."),
        "reads": MAC_MOD,
        "predicate": check_mac,
        "judgement": None,
    },
    {
        "id": "vendor-layer-never-written",
        "locator": re.compile(r"- Not every finding is one `apply` can act on\."),
        "reads": PERMISSIONS_MOD,
        "predicate": check_permissions,
        "judgement": None,
    },
    {
        "id": "json-bare-array",
        "locator": re.compile(r"- `scan --format json` emits a bare array with no schema version"),
        "reads": OUTPUT_RS,
        "predicate": check_json_output,
        "judgement": None,
    },
]

SECTION_HEADING = "### Known limitations"


def known_limitations_section(readme_text: str) -> str | None:
    """The Known limitations section, or None when README stops carrying it."""
    start = readme_text.find(SECTION_HEADING)
    if start == -1:
        return None
    tail = readme_text[start + len(SECTION_HEADING):]
    ends = [e for e in (tail.find("\n### "), tail.find("\n## "), tail.find("\nOpen defects")) if e != -1]
    return tail[: min(ends)] if ends else tail


def find_project_root() -> Path:
    current = Path.cwd()
    while current != current.parent:
        if (current / "Cargo.toml").exists():
            return current
        current = current.parent
    print(f"{RED}Error: Could not find project root{NC}")
    sys.exit(1)


# (name, predicate, sample text, expected verdict, detail substring the
# failure or pass must carry). The detail half is what stops a case passing
# vacuously: a predicate that fails every input for one broken reason still
# satisfies three expected-False cases, and only the detail each case names
# distinguishes failing for its own reason from failing at all. The shape
# arrived on the first draft of this very file, whose signature regex never
# matched anything and whose three negative cases were green within a
# minute of being written.
SELF_TEST_CASES = [
    (
        "mac: a write_file site fails the claim",
        check_mac,
        'async fn f() { e.write_file(p, s).await }\n"setenforce"',
        False,
        "write_file call site",
    ),
    (
        "mac: losing setenforce fails the claim",
        check_mac,
        "async fn f() { e.execute_command(\"AppArmor\", &[]).await }",
        False,
        "setenforce",
    ),
    (
        "mac: runtime-only shape passes",
        check_mac,
        'ctx.executor().execute_command("setenforce", &[mode]).await',
        True,
        "runtime-only",
    ),
    (
        "permissions: a missing anchor fails",
        check_permissions,
        "enum PermissionCheck { Clear, Insecure }",
        False,
        "VendorOnly",
    ),
    (
        "permissions: the three anchors pass",
        check_permissions,
        "VendorOnly(Box::new(Finding {\n"
        "    finding_explanation: format!(\"This tool does not write the vendor layer\"),\n"
        '    finding_remediation_steps: vec![format!("install -o root -g root -m {:04o}")]',
        True,
        "copy remediation",
    ),
    (
        "output: a version key inside the renderer fails",
        check_json_output,
        "fn scan_json(results: &[(PluginMetadata, ScanResult)]) -> Vec<serde_json::Value> {\n"
        '    serde_json::json!({ "schema_version": 2, "plugins": [{ "scan_success": r.scan_success, "scan_error": r.scan_error }] })\n'
        "}\n"
        "let _ = serde_json::to_string_pretty(&scan_json(results));",
        False,
        "version key",
    ),
    (
        "output: dropping scan_success fails",
        check_json_output,
        "fn scan_json(results: &[(PluginMetadata, ScanResult)]) -> Vec<serde_json::Value> {\n"
        '    serde_json::json!({ "plugin_id": m.plugin_id, "scan_error": r.scan_error })\n'
        "}\n"
        "let _ = serde_json::to_string_pretty(&scan_json(results));",
        False,
        "scan_success",
    ),
    (
        "output: wrapping the serialisation fails",
        check_json_output,
        "fn scan_json(results: &[(PluginMetadata, ScanResult)]) -> Vec<serde_json::Value> {\n"
        '    serde_json::json!({ "scan_success": r.scan_success, "scan_error": r.scan_error })\n'
        "}\n"
        'let _ = serde_json::to_string_pretty(&serde_json::json!({ "version": 1, "results": scan_json(results) }));',
        False,
        "serialisation call",
    ),
    (
        "output: the real shape passes",
        check_json_output,
        "fn scan_json(results: &[(PluginMetadata, ScanResult)]) -> Vec<serde_json::Value> {\n"
        '    serde_json::json!({ "scan_success": r.scan_success, "scan_error": r.scan_error })\n'
        "}\n"
        "let _ = serde_json::to_string_pretty(&scan_json(results));",
        True,
        "bare array",
    ),
]


def run_self_tests(verbose: bool) -> bool:
    """Every predicate meets the shape it was written against, both ways."""
    ok = True
    for name, predicate, sample, expected, detail in SELF_TEST_CASES:
        verdict, message = predicate(sample)
        passed = verdict == expected and (detail in message)
        ok = ok and passed
        if verbose:
            state = f"{GREEN}pass{NC}" if passed else f"{RED}FAIL{NC}"
            print(f"  {state} {name}")
    return ok


def main() -> None:
    self_test_only = "--self-test" in sys.argv

    if not run_self_tests(verbose=self_test_only):
        print(
            f"{RED}internal: a predicate can no longer recognise the shape it "
            f"was written against; the registry is stale{NC}"
        )
        sys.exit(1)
    if self_test_only:
        print(f"{GREEN}all {len(SELF_TEST_CASES)} self-test cases hold{NC}")
        return

    root = find_project_root()
    readme_text = (root / README).read_text(encoding="utf-8")
    section = known_limitations_section(readme_text)
    if section is None:
        print(
            f"{RED}README.md no longer carries a '{SECTION_HEADING}' section; "
            f"the registry here is written against it{NC}"
        )
        sys.exit(1)

    failed = 0
    checked = 0
    judgements = 0
    found = 0

    for entry in REGISTRY:
        bullet = entry["locator"].search(section)
        if bullet is None:
            print(
                f"{RED}✗ {entry['id']}: bullet not found under Known limitations "
                f"- reworded or removed; re-register it in the same change{NC}"
            )
            failed += 1
            continue
        found += 1

        if entry["predicate"] is None:
            judgements += 1
            print(f"{YELLOW}⊘ {entry['id']}: judgement, not machine-checked{NC}")
            continue

        checked += 1
        text = (root / entry["reads"]).read_text(encoding="utf-8")
        verdict, detail = entry["predicate"](text)
        if verdict:
            print(f"{GREEN}✓ {entry['id']}: {detail}{NC}")
        else:
            print(f"{RED}✗ {entry['id']}: {detail}{NC}")
            failed += 1

    total = len(REGISTRY)
    print()
    if failed == 0:
        print(
            f"{GREEN}All {total} registered limitations hold: {checked} "
            f"machine-checked, {judgements} registered judgements, "
            f"{found}/{total} bullets found{NC}"
        )
        sys.exit(0)
    print(
        f"{RED}{failed}/{total} registered limitations failed or moved{NC}"
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
