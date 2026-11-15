#!/usr/bin/env python3
"""Hold the baseline reference page to the baseline tables in the plugins.

`docs/reference/baseline-sources.md` lists every value the plugins check, how
each is compared, its severity, and where the value came from. It exists
because issue #189 asked which guide the defaults follow, and the honest answer
needed a table per setting: no single guide, and most values with no recorded
source at all.

A hand-written table of values is the shape this repository has watched go
stale more than any other. The PAM table is under discussion in #190 and #191,
so the first row to move is already known. When a value changes without its row,
the page tells a reader the old number, and the source column describes a
decision nobody made. When a row is missing, a new check ships with no record
of where its value came from. That second case is the defect #189 reported, and
this check is what stops it coming back.

What is checked
---------------
Each table on the page opens with a marker comment, `<!-- baseline-table: KEY
-->`, and is compared with the code it names:

- `kernel`, `ssh` and `pam`: the setting, its default, its comparison and its
  severity, against `KERNEL_PARAMS`, `SSH_DIRECTIVES` and `PAM_DIRECTIVES`. A
  `Ranked` comparison must list its order, weakest first, as the code does.
- `ssh-crypto`: each allow-list, in preference order, and its severity.
- `services`: the service names and severities in `UNNECESSARY_SERVICES`.
- `permissions`: path, mode, exact or mask comparison, and severity.
- `firewall`: action, protocol, port and source of each baseline rule.
- `audit`: every rule line, its category and severity, and the backlog
  prelude's two numbers.
- `weaker-pass`: every control the page says a host can pass on a weaker
  value must still be an identifier the code emits, and the baseline value
  the row quotes must still be the code's.

Both directions fail: a setting in code with no row, and a row naming a setting
the code no longer has. Every row must also say where its value came from. A row
may say that no source is recorded, and most do, but it may not be empty.

Not checked: what the guides say. Their values are quoted with a version and a
date, and only a person reading the new release can tell whether they moved.
The MAC plugin's single target, SELinux `Enforcing`, sits in prose and is not
parsed. A parser that no longer recognises a table in the code fails rather
than comparing the page with nothing.

The checker's own cases run quietly before every verdict, `--self-test` to see
them named.

Usage:
    ./scripts/validate/validate_baseline_sources.py
    ./scripts/validate/validate_baseline_sources.py --self-test

Exit codes:
    0: every table on the page agrees with the code
    1: a value, comparison, severity or row disagrees, a table is missing, or
       a self-test case failed
"""

import re
import sys
from pathlib import Path

RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
NC = "\033[0m"

PAGE = Path("docs/reference/baseline-sources.md")
PLUGINS = Path("crates/hardener-plugins/src")
PROFILES = Path("crates/hardener-compliance/src/profiles.rs")

# How the page spells each direction. `Ranked` is spelled "ranked" followed by
# its order, which is compared separately.
COMPARISON_WORDS = {
    "AtLeast": "at least",
    "AtMost": "at most",
    "NonZeroAtMost": "at most, not 0",
}

# Directive tables that share one shape: (page key, file, const, struct, name
# field, value field, severity field, comparison field).
SCALAR_TABLES = [
    (
        "kernel",
        "kernel/mod.rs",
        "KERNEL_PARAMS",
        "KernelParameter",
        "kernel_parameter_name",
        "kernel_secure_value",
        "kernel_severity",
        "kernel_compare",
    ),
    (
        "ssh",
        "ssh/mod.rs",
        "SSH_DIRECTIVES",
        "SshConfigDirective",
        "ssh_directive_name",
        "ssh_secure_value",
        "ssh_severity",
        "ssh_compare",
    ),
    (
        "pam",
        "pam/mod.rs",
        "PAM_DIRECTIVES",
        "PamDirective",
        "pam_directive_name",
        "pam_secure_value",
        "pam_severity",
        "pam_compare",
    ),
]


class ParseError(Exception):
    """The code no longer has the shape this parser was written against."""


# ---------------------------------------------------------------------------
# Reading the code
# ---------------------------------------------------------------------------


def const_body(text: str, name: str) -> str:
    """The text of `const NAME ... = &[ ... ];`, between the brackets."""
    match = re.search(rf"\bconst {name}\b[^=]*=\s*&\[", text)
    if match is None:
        raise ParseError(f"const {name} not found")
    end = text.find("\n];", match.end())
    if end == -1:
        raise ParseError(f"const {name} has no closing `];` at the start of a line")
    return text[match.end() : end]


def struct_bodies(block: str, struct: str) -> list[str]:
    """Each `Struct { ... },` literal inside a const's body."""
    return re.findall(rf"\b{struct}\s*\{{(.*?)\n\s*\}},", block, re.S)


def string_field(body: str, name: str) -> str:
    """A field written as a string literal, which may itself hold commas."""
    match = re.search(rf'\b{name}:\s*"((?:[^"\\]|\\.)*)"', body)
    if match is None:
        raise ParseError(f"field {name} is not a string literal here")
    return match.group(1)


def raw_field(body: str, name: str) -> str:
    """A field written as an expression with no comma in it."""
    match = re.search(rf"\b{name}:\s*([^,\n]+?)\s*,", body)
    if match is None:
        raise ParseError(f"field {name} not found")
    return match.group(1)


def severity_of(body: str, name: str) -> str:
    """`Severity::High` read as `High`."""
    raw = raw_field(body, name)
    match = re.fullmatch(r"Severity::(\w+)", raw)
    if match is None:
        raise ParseError(f"{name} is `{raw}`, not a Severity variant")
    return match.group(1)


def str_const(text: str, name: str) -> str:
    """The value of `const NAME: &str = "...";` in the same file."""
    match = re.search(rf'\bconst {name}:\s*&str\s*=\s*"([^"]*)"\s*;', text)
    if match is None:
        raise ParseError(f"const {name}: &str not found")
    return match.group(1)


def ranked_order(text: str, name: str) -> list[str]:
    """A `Ranked` order flattened weakest first, constants resolved.

    Synonyms in one group keep their written order, so `prohibit-password`
    and `without-password` appear in the order the code lists them.
    """
    match = re.search(rf"\bconst {name}\b[^=]*=(.*?);", text, re.S)
    if match is None:
        raise ParseError(f"ranked order {name} not found")
    flattened = []
    for group in re.findall(r"&\[([^\[\]]*)\]", match.group(1)):
        for item in (part.strip() for part in group.split(",")):
            if not item:
                continue
            if item.startswith('"'):
                flattened.append(item.strip('"'))
            else:
                flattened.append(str_const(text, item))
    if not flattened:
        raise ParseError(f"ranked order {name} is empty")
    return flattened


def comparison_of(text: str, raw: str) -> tuple[str, list[str]]:
    """A `Strictness` expression as (word, order); order is empty unless ranked."""
    match = re.fullmatch(r"Strictness::(\w+)(?:\((\w+)\))?", raw)
    if match is None:
        raise ParseError(f"`{raw}` is not a Strictness variant")
    variant, order = match.groups()
    if variant == "Ranked":
        if order is None:
            raise ParseError("Strictness::Ranked without an order constant")
        return "ranked", ranked_order(text, order)
    if variant not in COMPARISON_WORDS:
        raise ParseError(f"Strictness::{variant} has no spelling on the page")
    return COMPARISON_WORDS[variant], []


def string_list(text: str, name: str) -> list[str]:
    """A `const NAME: &[&str] = &[ ... ];` list, in order."""
    return re.findall(r'"([^"]*)"', const_body(text, name))


def code_scalar(text: str, spec: tuple) -> dict[str, dict]:
    """One directive table as {setting: expected cells}."""
    _, _, const, struct, name_f, value_f, severity_f, compare_f = spec
    entries = {}
    bodies = struct_bodies(const_body(text, const), struct)
    if not bodies:
        raise ParseError(f"{const} holds no {struct} literals")
    for body in bodies:
        word, order = comparison_of(text, raw_field(body, compare_f))
        entries[string_field(body, name_f)] = {
            "default": string_field(body, value_f),
            "comparison": word,
            "order": order,
            "severity": severity_of(body, severity_f),
        }
    return entries


def code_crypto(text: str) -> dict[str, dict]:
    """The SSH algorithm allow-lists as {directive: expected cells}."""
    entries = {}
    for body in struct_bodies(const_body(text, "SSH_CRYPTO_DIRECTIVES"), "SshCryptoDirective"):
        entries[string_field(body, "crypto_directive_name")] = {
            "list": string_list(text, raw_field(body, "crypto_desired")),
            "severity": severity_of(body, "crypto_severity"),
        }
    if not entries:
        raise ParseError("SSH_CRYPTO_DIRECTIVES holds no SshCryptoDirective literals")
    return entries


def code_services(text: str) -> dict[str, dict]:
    entries = {}
    for body in struct_bodies(const_body(text, "UNNECESSARY_SERVICES"), "ServiceDirective"):
        entries[string_field(body, "service_name")] = {
            "severity": severity_of(body, "service_severity"),
        }
    if not entries:
        raise ParseError("UNNECESSARY_SERVICES holds no ServiceDirective literals")
    return entries


def code_permissions(text: str) -> dict[str, dict]:
    entries = {}
    for body in struct_bodies(const_body(text, "CRITICAL_PERMISSIONS"), "PermissionDirective"):
        mode = raw_field(body, "permission_mode")
        if not re.fullmatch(r"0o[0-7]{3,4}", mode):
            raise ParseError(f"permission_mode `{mode}` is not an octal literal")
        mask = raw_field(body, "permission_max_mask")
        entries[string_field(body, "permission_path")] = {
            "mode": "0" + mode[2:] if len(mode) == 5 else mode[2:],
            "comparison": "no bits beyond" if mask == "true" else "exact",
            "severity": severity_of(body, "permission_severity"),
        }
    if not entries:
        raise ParseError("CRITICAL_PERMISSIONS holds no PermissionDirective literals")
    return entries


def code_firewall(text: str) -> dict[str, dict]:
    """The baseline rules, keyed by the id `rule_id` gives each."""
    ids = {}
    id_fn = re.search(r"\bfn rule_id\b.*?\n\}\n", text, re.S)
    if id_fn is None:
        raise ParseError("fn rule_id not found")
    for description, rule_id in re.findall(
        r'"([^"]+)"\s*=>\s*"([^"]+)"\.to_string\(\)', id_fn.group(0)
    ):
        ids[description] = rule_id

    function = re.search(r"\bpub fn get_baseline_rules\b.*?\n\}\n", text, re.S)
    if function is None:
        raise ParseError("fn get_baseline_rules not found")
    entries = {}
    for body in struct_bodies(function.group(0), "Rule"):
        description = string_field(body, "rule_description")
        if description not in ids:
            raise ParseError(f"baseline rule {description!r} has no id in rule_id")
        entries[ids[description]] = {
            "action": string_field(body, "rule_action"),
            "protocol": string_field(body, "rule_protocol"),
            "port": string_field(body, "rule_port"),
            "source": string_field(body, "rule_source"),
        }
    if not entries:
        raise ParseError("get_baseline_rules builds no Rule literals")
    return entries


def code_audit(text: str) -> tuple[dict[str, dict], list[str]]:
    """The audit rules keyed by their line, and the prelude's two settings."""
    entries = {}
    for body in struct_bodies(const_body(text, "AUDIT_RULES"), "AuditRuleDirective"):
        entries[string_field(body, "audit_rule_content")] = {
            "category": string_field(body, "audit_rule_category"),
            "severity": severity_of(body, "audit_rule_severity"),
        }
    if not entries:
        raise ParseError("AUDIT_RULES holds no AuditRuleDirective literals")
    prelude = re.search(r'\bconst AUDIT_BACKLOG_PRELUDE: &str = "(.*?)";', text, re.S)
    if prelude is None:
        raise ParseError("AUDIT_BACKLOG_PRELUDE not found")
    settings = re.findall(r"^(-b \d+|--backlog_wait_time \d+)$", prelude.group(1), re.M)
    if len(settings) != 2:
        raise ParseError("AUDIT_BACKLOG_PRELUDE no longer sets -b and --backlog_wait_time")
    return entries, settings


def read_code(root: Path) -> dict:
    """Every baseline the page describes, read from the plugin sources."""
    src = root / PLUGINS
    code = {}
    for spec in SCALAR_TABLES:
        code[spec[0]] = code_scalar((src / spec[1]).read_text(encoding="utf-8"), spec)
    ssh = (src / "ssh/mod.rs").read_text(encoding="utf-8")
    code["ssh-crypto"] = code_crypto(ssh)
    code["services"] = code_services((src / "services/mod.rs").read_text(encoding="utf-8"))
    code["permissions"] = code_permissions(
        (src / "permissions/mod.rs").read_text(encoding="utf-8")
    )
    code["firewall"] = code_firewall((src / "firewall/mod.rs").read_text(encoding="utf-8"))
    code["audit"], code["audit-prelude"] = code_audit(
        (src / "audit/mod.rs").read_text(encoding="utf-8")
    )
    return code


def emitted_identifiers(root: Path) -> str:
    """Every source a control identifier the page names may come from."""
    texts = [p.read_text(encoding="utf-8") for p in sorted((root / PLUGINS).rglob("*.rs"))]
    texts.append((root / PROFILES).read_text(encoding="utf-8"))
    return "\n".join(texts)


# ---------------------------------------------------------------------------
# Reading the page
# ---------------------------------------------------------------------------


def ticks(cell: str) -> list[str]:
    """The backticked tokens in a cell, in order."""
    return re.findall(r"`([^`]+)`", cell)


def page_table(page: str, key: str) -> list[list[str]] | None:
    """The body rows of the table after `<!-- baseline-table: KEY -->`."""
    marker = f"<!-- baseline-table: {key} -->"
    start = page.find(marker)
    if start == -1:
        return None
    lines = page[start + len(marker) :].split("\n")
    table = []
    for line in lines:
        if not table and not line.strip():
            continue
        if not line.lstrip().startswith("|"):
            break
        table.append(line)
    if len(table) < 2:
        return []
    return [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in table[2:]]


def keyed(rows: list[list[str]], key_column: int, problems: list[str], table: str) -> dict:
    """Rows keyed by the first backticked token of one column."""
    found = {}
    for row in rows:
        names = ticks(row[key_column]) if len(row) > key_column else []
        if not names:
            problems.append(f"{table}: a row names no setting in backticks: {' | '.join(row)}")
            continue
        if names[0] in found:
            problems.append(f"{table}: `{names[0]}` has more than one row")
            continue
        found[names[0]] = row
    return found


def both_directions(table: str, expected: dict, rows: dict, problems: list[str]) -> list[str]:
    """Report missing and stale rows; return the names present on both sides."""
    for name in expected:
        if name not in rows:
            problems.append(f"{table}: `{name}` is in the code and has no row on the page")
    for name in rows:
        if name not in expected:
            problems.append(f"{table}: `{name}` has a row but is not in the code")
    return [name for name in expected if name in rows]


def need_cells(table: str, name: str, row: list[str], count: int, problems: list[str]) -> bool:
    if len(row) < count:
        problems.append(f"{table}: `{name}` has {len(row)} cells, expected {count}")
        return False
    return True


def first_tick(cell: str) -> str | None:
    found = ticks(cell)
    return found[0] if found else None


def check_source_cell(table: str, name: str, cell: str, problems: list[str]) -> None:
    if not cell.strip():
        problems.append(f"{table}: `{name}` does not say where its value comes from")


def check_scalar(table: str, expected: dict, rows: list[list[str]]) -> list[str]:
    """Setting | Default | Comparison | Severity | Source | Guides."""
    problems: list[str] = []
    by_name = keyed(rows, 0, problems, table)
    for name in both_directions(table, expected, by_name, problems):
        row, want = by_name[name], expected[name]
        if not need_cells(table, name, row, 6, problems):
            continue
        if first_tick(row[1]) != want["default"]:
            problems.append(
                f"{table}: `{name}` default reads {row[1]!r}, the code says `{want['default']}`"
            )
        comparison = row[2].strip().lower()
        if want["comparison"] == "ranked":
            if not comparison.startswith("ranked") or ticks(row[2]) != want["order"]:
                order = ", ".join(want["order"])
                problems.append(
                    f"{table}: `{name}` comparison reads {row[2]!r}, the code ranks it "
                    f"weakest first as {order}"
                )
        elif comparison != want["comparison"]:
            problems.append(
                f"{table}: `{name}` comparison reads {row[2]!r}, the code says "
                f"{want['comparison']!r}"
            )
        if row[3].strip() != want["severity"]:
            problems.append(
                f"{table}: `{name}` severity reads {row[3]!r}, the code says {want['severity']}"
            )
        check_source_cell(table, name, row[4], problems)
    return problems


def check_crypto(expected: dict, rows: list[list[str]]) -> list[str]:
    """Directive | Allow-list | Severity | Source | Guides."""
    table = "ssh-crypto"
    problems: list[str] = []
    by_name = keyed(rows, 0, problems, table)
    for name in both_directions(table, expected, by_name, problems):
        row, want = by_name[name], expected[name]
        if not need_cells(table, name, row, 5, problems):
            continue
        if ticks(row[1]) != want["list"]:
            problems.append(
                f"{table}: `{name}` lists {ticks(row[1])}, the code allows "
                f"{want['list']} in that order"
            )
        if row[2].strip() != want["severity"]:
            problems.append(
                f"{table}: `{name}` severity reads {row[2]!r}, the code says {want['severity']}"
            )
        check_source_cell(table, name, row[3], problems)
    return problems


def check_services(expected: dict, rows: list[list[str]]) -> list[str]:
    """Service | Severity | Source | Guides."""
    table = "services"
    problems: list[str] = []
    by_name = keyed(rows, 0, problems, table)
    for name in both_directions(table, expected, by_name, problems):
        row = by_name[name]
        if not need_cells(table, name, row, 4, problems):
            continue
        if row[1].strip() != expected[name]["severity"]:
            problems.append(
                f"{table}: `{name}` severity reads {row[1]!r}, the code says "
                f"{expected[name]['severity']}"
            )
        check_source_cell(table, name, row[2], problems)
    return problems


def check_permissions(expected: dict, rows: list[list[str]]) -> list[str]:
    """Path | Mode | Comparison | Severity | Source | Notes."""
    table = "permissions"
    problems: list[str] = []
    by_name = keyed(rows, 0, problems, table)
    for name in both_directions(table, expected, by_name, problems):
        row, want = by_name[name], expected[name]
        if not need_cells(table, name, row, 6, problems):
            continue
        if first_tick(row[1]) != want["mode"]:
            problems.append(f"{table}: `{name}` mode reads {row[1]!r}, the code says {want['mode']}")
        if row[2].strip().lower() != want["comparison"]:
            problems.append(
                f"{table}: `{name}` comparison reads {row[2]!r}, the code says "
                f"{want['comparison']!r}"
            )
        if row[3].strip() != want["severity"]:
            problems.append(
                f"{table}: `{name}` severity reads {row[3]!r}, the code says {want['severity']}"
            )
        check_source_cell(table, name, row[4], problems)
    return problems


def check_firewall(expected: dict, rows: list[list[str]]) -> list[str]:
    """Rule | Action | Protocol | Port | Source address | Notes."""
    table = "firewall"
    problems: list[str] = []
    by_name = keyed(rows, 0, problems, table)
    for name in both_directions(table, expected, by_name, problems):
        row, want = by_name[name], expected[name]
        if not need_cells(table, name, row, 6, problems):
            continue
        for column, field in enumerate(("action", "protocol", "port", "source"), start=1):
            if first_tick(row[column]) != want[field]:
                problems.append(
                    f"{table}: `{name}` {field} reads {row[column]!r}, the code says "
                    f"`{want[field]}`"
                )
    return problems


def check_audit(expected: dict, prelude: list[str], page: str, rows: list[list[str]]) -> list[str]:
    """Category | Rule | Severity, plus the prelude's two settings in the page."""
    table = "audit"
    problems: list[str] = []
    by_rule = keyed(rows, 1, problems, table)
    for rule in both_directions(table, expected, by_rule, problems):
        row, want = by_rule[rule], expected[rule]
        if not need_cells(table, rule, row, 3, problems):
            continue
        if first_tick(row[0]) != want["category"]:
            problems.append(
                f"{table}: `{rule}` category reads {row[0]!r}, the code says {want['category']}"
            )
        if row[2].strip() != want["severity"]:
            problems.append(
                f"{table}: `{rule}` severity reads {row[2]!r}, the code says {want['severity']}"
            )
    for setting in prelude:
        if f"`{setting}`" not in page:
            problems.append(f"{table}: the backlog prelude sets `{setting}` and the page never says so")
    return problems


def check_weaker_pass(code: dict, identifiers: str, rows: list[list[str]]) -> list[str]:
    """Control | What the control asks | Setting | Baseline."""
    table = "weaker-pass"
    problems: list[str] = []
    if not rows:
        problems.append(f"{table}: the table is empty")
    for row in rows:
        if len(row) < 4:
            problems.append(f"{table}: a row has {len(row)} cells, expected 4")
            continue
        controls = ticks(row[0])
        if not controls:
            problems.append(f"{table}: a row names no control in backticks: {row[0]!r}")
        for control in controls:
            if f'"{control}"' not in identifiers:
                problems.append(
                    f"{table}: `{control}` is not an identifier the plugins or the "
                    f"profiles emit any more"
                )
        setting = first_tick(row[2])
        quoted = first_tick(row[3])
        scalar = {**code["kernel"], **code["ssh"], **code["pam"]}
        if setting in scalar:
            if quoted != scalar[setting]["default"]:
                problems.append(
                    f"{table}: `{setting}` is quoted as {row[3]!r}, the code's default "
                    f"is `{scalar[setting]['default']}`"
                )
        elif setting in code["ssh-crypto"]:
            if quoted not in code["ssh-crypto"][setting]["list"]:
                problems.append(
                    f"{table}: `{setting}` is said to allow {row[3]!r}, which the "
                    f"code's allow-list does not hold"
                )
        else:
            problems.append(f"{table}: {row[2]!r} names no setting any baseline table holds")
    return problems


def check_page(page: str, code: dict, identifiers: str) -> list[str]:
    """Every problem with the page, against code already read."""
    problems: list[str] = []
    tables = {}
    keys = [spec[0] for spec in SCALAR_TABLES] + [
        "ssh-crypto",
        "services",
        "permissions",
        "firewall",
        "audit",
        "weaker-pass",
    ]
    for key in keys:
        rows = page_table(page, key)
        if rows is None:
            problems.append(f"no `<!-- baseline-table: {key} -->` marker on the page")
            continue
        tables[key] = rows
    for spec in SCALAR_TABLES:
        if spec[0] in tables:
            problems += check_scalar(spec[0], code[spec[0]], tables[spec[0]])
    if "ssh-crypto" in tables:
        problems += check_crypto(code["ssh-crypto"], tables["ssh-crypto"])
    if "services" in tables:
        problems += check_services(code["services"], tables["services"])
    if "permissions" in tables:
        problems += check_permissions(code["permissions"], tables["permissions"])
    if "firewall" in tables:
        problems += check_firewall(code["firewall"], tables["firewall"])
    if "audit" in tables:
        problems += check_audit(code["audit"], code["audit-prelude"], page, tables["audit"])
    if "weaker-pass" in tables:
        problems += check_weaker_pass(code, identifiers, tables["weaker-pass"])
    return problems


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

SAMPLE_KERNEL_RS = """
const ORDER: &[&[&str]] = &[&["0"], &[SPELLING, "2b"], &["1"]];
const SPELLING: &str = "2";
const KERNEL_PARAMS: &[KernelParameter] = &[
    KernelParameter {
        kernel_parameter_name: "a.b",
        kernel_secure_value: "2",
        kernel_severity: Severity::High,
        // a comment with a comma, and braces { }
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "c.d",
        kernel_secure_value: "1",
        kernel_severity: Severity::Low,
        kernel_compare: Strictness::Ranked(ORDER),
    },
];
"""

SAMPLE_SPEC = SCALAR_TABLES[0]


def sample_page(rows: list[str]) -> str:
    header = (
        "<!-- baseline-table: kernel -->\n\n"
        "| Setting | Default | Comparison | Severity | Source | Guides |\n"
        "|---|---|---|---|---|---|\n"
    )
    return header + "\n".join(rows) + "\n\nAfter the table.\n"


GOOD_A = "| `a.b` | `2` | at least | High | Project choice | none |"
GOOD_C = "| `c.d` | `1` | ranked, weakest first: `0`, `2`, `2b`, `1` | Low | Project choice | none |"

# (rows on the page, whether the check must flag them, why)
SELF_TEST_CASES = [
    ([GOOD_A, GOOD_C], False, "a page that matches the code passes"),
    (
        [GOOD_A.replace("`2`", "`3`"), GOOD_C],
        True,
        "a default that moved in the code is flagged",
    ),
    (
        [GOOD_A.replace("at least", "at most"), GOOD_C],
        True,
        "a comparison in the wrong direction is flagged",
    ),
    (
        [GOOD_A.replace("High", "Medium"), GOOD_C],
        True,
        "a severity that changed is flagged",
    ),
    ([GOOD_A], True, "a setting with no row is flagged"),
    (
        [GOOD_A, GOOD_C, "| `e.f` | `0` | at most | Low | Project choice | none |"],
        True,
        "a row for a setting the code dropped is flagged",
    ),
    (
        [GOOD_A, GOOD_C, GOOD_A],
        True,
        "a setting with two rows is flagged",
    ),
    (
        [GOOD_A.replace("Project choice", ""), GOOD_C],
        True,
        "a row that does not say where its value comes from is flagged",
    ),
    (
        [GOOD_A, GOOD_C.replace("`2`, `2b`", "`2b`, `2`")],
        True,
        "a ranked order written in the wrong order is flagged",
    ),
]


def self_test(quiet: bool = False) -> int:
    """Runs the checker against page shapes the real page does not contain."""
    if not quiet:
        print(f"{BLUE}Self-test: page shapes this check must reject, and one it must not...{NC}\n")
    if len(SELF_TEST_CASES) < 9:
        print(f"{RED}The self-test table holds {len(SELF_TEST_CASES)} cases, fewer than the 9 written.{NC}")
        return 1

    failures = 0
    try:
        expected = code_scalar(SAMPLE_KERNEL_RS, SAMPLE_SPEC)
    except ParseError as error:
        print(f"  {RED}x{NC} the parser cannot read its own sample: {error}")
        return 1
    if expected["c.d"]["order"] != ["0", "2", "2b", "1"]:
        print(f"  {RED}x{NC} a ranked order with a constant in it was read as {expected['c.d']['order']}")
        failures += 1

    for index, (rows, should_flag, why) in enumerate(SELF_TEST_CASES):
        table = page_table(sample_page(rows), "kernel") or []
        flagged = bool(check_scalar("kernel", expected, table))
        if flagged != should_flag:
            verdict = "flagged" if flagged else "accepted"
            wanted = "flagged" if should_flag else "accepted"
            print(f"  {RED}x{NC} case {index}: {verdict}, expected {wanted}: {why}")
            failures += 1
            continue
        if not quiet:
            print(f"  {GREEN}v{NC} {why}")

    if page_table("no marker here", "kernel") is not None:
        print(f"  {RED}x{NC} a page without the marker was read as having the table")
        failures += 1
    elif not quiet:
        print(f"  {GREEN}v{NC} a page without the table's marker is reported, not read as empty")

    if failures:
        print(f"\n{RED}{failures} self-test case(s) failed{NC}")
        return 1
    if not quiet:
        print(f"\n{GREEN}All {len(SELF_TEST_CASES) + 2} self-test cases behave as written{NC}")
    return 0


# ---------------------------------------------------------------------------


def find_project_root() -> Path:
    """The repository root, found by walking up from this file."""
    return Path(__file__).resolve().parent.parent.parent


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    print(f"{BLUE}Validating {PAGE} against the plugin baselines...{NC}\n")
    if self_test(quiet=True) != 0:
        print(f"{RED}The checker's own self-test failed, so its verdict on the page is worthless.{NC}")
        print(f"{RED}Run: python3 scripts/validate/validate_baseline_sources.py --self-test{NC}")
        return 1

    root = find_project_root()
    page_path = root / PAGE
    if not page_path.exists():
        print(f"{RED}{PAGE} does not exist{NC}")
        return 1

    try:
        code = read_code(root)
    except (ParseError, OSError) as error:
        print(f"{RED}The code no longer has the shape this parser reads: {error}{NC}")
        print("  Update the parser in this script rather than leaving the page unchecked.")
        return 1

    problems = check_page(page_path.read_text(encoding="utf-8"), code, emitted_identifiers(root))
    if problems:
        print(f"{RED}{PAGE} disagrees with the code ({len(problems)}):{NC}")
        for problem in problems:
            print(f"  {RED}x{NC} {problem}")
        print()
        print("  A changed default needs its row changed in the same commit, and a new")
        print("  check needs a row that says where its value came from.")
        return 1

    counts = ", ".join(
        f"{len(code[key])} {key}"
        for key in ("kernel", "ssh", "ssh-crypto", "pam", "services", "permissions", "firewall", "audit")
    )
    print(f"  {GREEN}v{NC} Every baseline row agrees with the code: {counts}")
    print(f"\n{GREEN}Baseline sources validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
