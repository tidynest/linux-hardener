#!/usr/bin/env python3
"""Check the Playwright Tauri mock's payloads against the Rust types.

`gui-tests/tauri-mock.js` is a hand-written mirror of the types the frontend
deserialises, and until now nothing read it. Eight separate drifts accumulated
in it unnoticed, because every one fails in a way that looks like something
else: the frontend reports "missing field `x`" into an alert box the tests do
not assert on, the affected view renders empty, and the suite reports what
looks like stale selectors. Six of the eight are field-level and are exactly
what this catches.

The mock's payloads are obtained by running it, not by parsing it: the file is
loaded against a stubbed `window` and each command is invoked, so what is
compared is what serde would actually receive. Field names come from the Rust
via a deliberately simple parse of `pub struct` blocks.

Exit status is 0 when every probe matches, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
TYPES = PROJECT / "crates" / "hardener-types" / "src"
MOCK = PROJECT / "gui-tests" / "tauri-mock.js"

# (command, args, path into the reply, Rust struct the objects there must match)
#
# A path step of "[]" walks into every element of a list. Commands are chosen to
# reach the payloads the GUI suite depends on, which is where the drift was.
PROBES = [
    ("run_scan", {}, "[]", "ScanResult"),
    ("run_scan", {}, "[].scan_findings[]", "Finding"),
    ("run_apply", {}, "[]", "ApplyResult"),
    # Reached through the default all-success fixture, but the mixed-outcome
    # one added for #136 is the same two structs, so a field rename in either
    # is caught here for both.
    ("run_apply", {}, "[].apply_changes[]", "Change"),
    ("list_plugins", {}, "[]", "PluginMetadata"),
    # The five checkpoint and scan-session structs. Until #157 they were
    # hand-written in `hardener-ui/src/types.rs`, outside the tree TYPES
    # resolves, so no probe could name them however badly the mock drifted:
    # `system_unreadable` (#156) and `checkpoint_verified` (#157) both fell
    # through that copy. They now live in `hardener-types`, so these entries
    # are possible for the first time.
    ("get_checkpoints", {}, "", "CheckpointList"),
    ("get_checkpoints", {}, "checkpoints[]", "CheckpointInfo"),
    ("get_scan_history", {}, "[]", "ScanSessionInfo"),
    (
        "get_checkpoint_detail",
        {"checkpointId": "chk-20260223-001"},
        "",
        "CheckpointDetail",
    ),
    (
        "get_checkpoint_detail",
        {"checkpointId": "chk-20260223-001"},
        "files[]",
        "CheckpointFileInfo",
    ),
    # The rollback modal's payload, which no probe reached. Its divergence
    # section shipped unrendered (#143) and its rows were absent from this mock
    # entirely, so the one check that could have said the fixture was short was
    # not looking at this command at all.
    ("run_rollback", {"checkpointId": "cp_mock_1234"}, "", "RollbackResult"),
    (
        "run_rollback",
        {"checkpointId": "cp_mock_1234"},
        "rollback_files[]",
        "FileRestoreResult",
    ),
    # Added with the reload section's coverage (2026-09-01): the mock omitted
    # `rollback_reloads` until then, and `#[serde(default)]` read the absence
    # as an empty vec - legal for serde, invisible to every check, and the
    # reason the Result stage's reload section had never rendered with data.
    # This probe is what turns that particular silence into a failure.
    (
        "run_rollback",
        {"checkpointId": "cp_mock_1234"},
        "rollback_reloads[]",
        "ReloadResult",
    ),
    # The enum-valued field is the reason this one matters: `divergence_state`
    # is a bare Rust enum, so the mock has to spell a real variant and nothing
    # else would have said so.
    (
        "run_rollback",
        {"checkpointId": "cp_mock_1234"},
        "rollback_divergences[]",
        "RollbackDivergence",
    ),
    # The host expander's history rail. `HostPanel` fires this on every row
    # expand and swallows the failure with `.unwrap_or_default()`, so a mock
    # that has never answered it renders the same empty state as a host with no
    # persisted scans, and three GUI tests expand a row without noticing.
    ("get_host_history", {"host": "web-01", "limit": 10}, "[]", "HostSessionInfo"),
    ("run_fleet_scan", {"hostNames": ["web-01"], "adhoc": []}, "[]", "FleetHostScan"),
    (
        "run_fleet_scan",
        {"hostNames": ["web-01"], "adhoc": []},
        "[].compliance[]",
        "FleetFrameworkPosture",
    ),
    (
        "run_fleet_scan",
        {"hostNames": ["web-01"], "adhoc": []},
        "[].compliance[].controls[]",
        "ControlOutcome",
    ),
    (
        "generate_compliance_report",
        {"frameworks": ["cis"]},
        "[]",
        "ComplianceReport",
    ),
    # `WrittenException` is the CLI's own observed value coming back, echoed
    # by the desktop command untouched, so a field the CLI adds or renames
    # there has to show up here too.
    (
        "add_policy_exception",
        {
            "pluginId": "service-minimisation",
            "exceptionKey": "bluetooth-service",
            "reason": "probe",
            "approvedBy": None,
            "ticket": None,
            "expires": None,
        },
        "",
        "WrittenException",
    ),
]

# Invoked purely so a missing or renamed mock case throws where a stale one
# currently would not. `remove_policy_exception` returns Rust `()`, which
# serialises to `null` and carries no fields for a PROBES entry to diff, so
# this is the only check it can meaningfully get.
SMOKE_COMMANDS = [
    (
        "remove_policy_exception",
        {"pluginId": "service-minimisation", "exceptionKey": "bluetooth-service"},
    ),
]

# (path, field, enum) for fields whose value has to name a real variant. serde
# rejects anything else, and `Logging` and `AccessControl` both sat here.
ENUM_FIELDS = [
    ("list_plugins", {}, "[]", "plugin_category", "FindingCategory"),
    ("run_scan", {}, "[].scan_findings[]", "finding_category", "FindingCategory"),
    ("run_scan", {}, "[].scan_findings[]", "finding_severity", "Severity"),
    # A probe over the struct alone does NOT reach this: the struct check reads
    # field names, and `divergence_state: 'Divergent'` passed it. Measured
    # 2026-08-09 by writing exactly that and watching the run stay green.
    (
        "run_rollback",
        {"checkpointId": "cp_mock_1234"},
        "rollback_divergences[]",
        "divergence_state",
        "DivergenceState",
    ),
]

DUMP_JS = """
global.window = {{ location: {{ search: '' }} }};
global.URLSearchParams = URLSearchParams;
const log = console.log;
console.log = () => {{}};
require({mock});
const invoke = global.window.__TAURI__.core.invoke;
const probes = {probes};
(async () => {{
  const out = [];
  for (const [command, args] of probes) {{
    out.push(await invoke(command, args));
  }}
  log(JSON.stringify(out));
}})().catch((e) => {{ log(JSON.stringify({{ error: String(e) }})); process.exit(3); }});
"""


def rust_fields(struct: str) -> tuple[set[str], set[str]]:
    """A struct's `pub` fields, split into (required, all).

    A field is not required when serde can supply it: `Option<T>` deserialises
    to None when absent, and `#[serde(default)]` says so outright, on the field
    or on the struct. Treating those as required is wrong in the direction that
    matters, since it would report a mock that works.
    """
    for source in sorted(TYPES.rglob("*.rs")):
        text = source.read_text()
        match = re.search(rf"(?:(#\[serde\([^)]*\)\])\s*)?pub struct {struct} \{{(.*?)\n\}}", text, re.S)
        if not match:
            continue
        struct_default = "default" in (match.group(1) or "")
        required: set[str] = set()
        every: set[str] = set()
        attributes = ""
        for line in match.group(2).splitlines():
            stripped = line.strip()
            if stripped.startswith("#["):
                attributes += stripped
                continue
            field = re.match(r"pub (\w+):\s*(.+?),?$", stripped)
            if not field:
                if stripped and not stripped.startswith("///"):
                    attributes = ""
                continue
            name, kind = field.group(1), field.group(2)
            every.add(name)
            optional = (
                struct_default
                or "default" in attributes
                or "skip" in attributes
                or kind.startswith("Option<")
            )
            if not optional:
                required.add(name)
            attributes = ""
        return required, every
    raise SystemExit(f"no `pub struct {struct}` found under {TYPES}")


def rust_variants(enum: str) -> list[str]:
    """The variant names of a fieldless enum."""
    for source in sorted(TYPES.rglob("*.rs")):
        text = source.read_text()
        match = re.search(rf"pub enum {enum} \{{(.*?)\n\}}", text, re.S)
        if match:
            return re.findall(r"^\s*(\w+)\s*(?:,|\{|\()", match.group(1), re.M)
    raise SystemExit(f"no `pub enum {enum}` found under {TYPES}")


def walk(payload, path: str):
    """Every object reached by `path`, which uses `[]` to mean each element."""
    nodes = [payload]
    for step in [s for s in path.split(".") if s]:
        name, _, brackets = step.partition("[")
        if name:
            nodes = [n[name] for n in nodes if isinstance(n, dict) and name in n]
        if brackets:
            nodes = [item for n in nodes if isinstance(n, list) for item in n]
    return [n for n in nodes if isinstance(n, dict)]


def mock_payloads(commands) -> list:
    script = DUMP_JS.format(mock=json.dumps(str(MOCK)), probes=json.dumps(commands))
    result = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, cwd=PROJECT
    )
    if result.returncode != 0:
        # The harness catches a rejected invoke and writes `{"error": ...}` to
        # stdout before exiting 3, so reporting stderr alone printed the header
        # and nothing else: a mock missing a probed command said only "could
        # not run the mock". Both streams go out, whichever carried the reason.
        detail = "\n".join(s for s in (result.stdout.strip(), result.stderr.strip()) if s)
        raise SystemExit(f"could not run the mock:\n{detail}")
    return json.loads(result.stdout)


def main() -> int:
    commands = (
        [[c, a] for c, a, _, _ in PROBES]
        + [[c, a] for c, a, _, _, _ in ENUM_FIELDS]
        + [[c, a] for c, a in SMOKE_COMMANDS]
    )
    payloads = mock_payloads(commands)
    problems: list[str] = []

    for index, (command, _, path, struct) in enumerate(PROBES):
        required, every = rust_fields(struct)
        objects = walk(payloads[index], path)
        if not objects:
            problems.append(f"{command} {path}: reached no object to check against {struct}")
            continue
        for obj in objects:
            actual = set(obj)
            for field in sorted(required - actual):
                problems.append(f"{command} {path}: {struct} requires `{field}`, which is absent")
            # An extra field is not a serde error on its own, but a renamed one
            # arrives as an extra beside a missing, and the missing half is what
            # breaks. Reporting both names the rename rather than half of it.
            for field in sorted(actual - every):
                problems.append(f"{command} {path}: `{field}` is not a field of {struct}")
            break  # every element of a list shares its shape; one is enough

    for offset, (command, _, path, field, enum) in enumerate(ENUM_FIELDS):
        variants = set(rust_variants(enum))
        for obj in walk(payloads[len(PROBES) + offset], path):
            value = obj.get(field)
            if isinstance(value, str) and value not in variants:
                problems.append(
                    f"{command} {path}: {field} `{value}` is not a {enum} variant"
                )

    if problems:
        print("\033[0;31mThe GUI mock disagrees with the Rust types:\033[0m")
        for problem in dict.fromkeys(problems):
            print(f"  - {problem}")
        print("\n  gui-tests/tauri-mock.js is what the Playwright suite deserialises.")
        print("  A mismatch empties the affected view and reads as a stale selector.")
        return 1

    checked = len(PROBES) + len(ENUM_FIELDS)
    smoked = len(SMOKE_COMMANDS)
    print(
        f"\033[0;32mGUI mock fixtures match the Rust types "
        f"({checked} probes, {smoked} smoke-invoked)\033[0m"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
