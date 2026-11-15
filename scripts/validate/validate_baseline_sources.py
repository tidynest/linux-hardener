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
- `weaker-pass`, `unmeasured-pass`, `switched-off-pass` and
  `exact-value-pass`: the controls a host can pass while not doing what the
  control's text asks. Each row names the check, the control the plugin maps
  it to and the control's RHEL 10 identifier. The mapped control must sit in
  that check's own arm of the plugin's mapping function, helper calls in the
  arm included, so a plugin that stops mapping it fails the row even while
  `profiles.rs` still holds the identifier as a translation key. Each RHEL 10
  identifier must be one `profiles.rs` translates a mapped control to. In
  `weaker-pass` and `exact-value-pass`, the baseline value the row quotes must
  still be the code's. In `switched-off-pass`, the check must still be
  compared "at most", the comparison that ranks the switched-off value as the
  strictest, so a fix to the comparison fails the row until it is removed.

Both directions fail: a setting in code with no row, and a row naming a setting
the code no longer has. Every setting row, audit and firewall included, must
also say where its value came from. A row may say that no source is recorded,
and most do, but it may not be empty. Every comparison the code uses must be
defined under the page's "How to read the tables".

A new table fails too. Any `const` or `static` in the plugin sources that holds
a slice or array of a struct the plugins define is a table of values until this
script reads it or `NOT_BASELINE` says, with a reason, that it holds none. A
check added in a new file, as a new table, therefore fails here until it has a
parser and rows, rather than passing unseen. Values built inside a function, as
the firewall's are, or held in tuples, are not found this way; the firewall's
function is read by name.

README.md is held on three points. The baseline values its "Where the default
values come from" section and its Pass limitation quote must be the code's,
and each registered quote must still be found, so rewording one means moving
its pattern here. The "Compliance frameworks" paragraph must still say that a
Pass is not always everything a control asks, and the report generator must
still decide Pass on findings alone, which is what makes that sentence true.

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

# The README limitation and the compliance paragraph rest on the same fact
# about the report generator, and its sibling already reads it. One parse of
# that status chain is one thing to keep true, so it is imported rather than
# copied. Importing runs nothing: that module calls `main()` only under
# `__name__ == "__main__"`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_readme_claims import check_pass_against_baseline  # noqa: E402

RED = "\033[0;31m"
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
NC = "\033[0m"

PAGE = Path("docs/reference/baseline-sources.md")
PLUGINS = Path("crates/hardener-plugins/src")
PROFILES = Path("crates/hardener-compliance/src/profiles.rs")
README = Path("README.md")
GENERATOR = Path("crates/hardener-compliance/src/generator.rs")

# The page's tables of controls a host can pass while not doing what the
# control asks: (marker key, what the last column holds). "value" is a quoted
# baseline value that must be the code's, "switch-off" a value that switches
# the check off and that the code's comparison must still rank as strictest,
# and None is prose.
CONTROL_TABLES = [
    ("weaker-pass", "value"),
    ("unmeasured-pass", None),
    ("switched-off-pass", "switch-off"),
    ("exact-value-pass", "value"),
]

# Baseline values README quotes: (section heading, pattern with one group,
# table, setting). A space in a pattern matches any run of whitespace, so
# rewrapping a paragraph does not break it. Rewording does, on purpose: the
# quote has moved, and this registry has to move with it.
README_QUOTES = [
    ("### Where the default values come from", r"a (\d+)-character minimum and", "pam", "minlen"),
    ("### Where the default values come from", r"minimum and (\d+) remembered passwords", "pam", "remember"),
    ("### Where the default values come from", r"Its (\d+)-day password expiry", "pam", "PASS_MAX_DAYS"),
    ("### Where the default values come from", r"while its (\d+)-character minimum", "pam", "minlen"),
    ("### Known limitations", r"where the baseline asks for (\d+)", "pam", "minlen"),
]

# The sentence that replaced README's old claim that a report "cannot claim
# compliance the tool did not measure", which this page's two control tables
# disprove. It is true only while the generator passes a covered control on the
# absence of a finding, so it is held to that status chain as well.
README_PASS_SENTENCE = (
    "### Compliance frameworks",
    "A covered control passes when its plugin finds nothing weaker than the "
    "baseline, which is not always everything the control asks for",
)

# How the page spells each direction. `Ranked` is spelled "ranked" followed by
# its order, which is compared separately. The last three are not in this tree:
# the branch for #190 adds them. They are spelled here so that a merge with it
# names the rows whose comparison changed, instead of stopping at the parser. A
# spelling the code uses must also be defined in the page's legend, which
# `check_legend` holds, so an unused one here costs nothing.
COMPARISON_WORDS = {
    "AtLeast": "at least",
    "AtMost": "at most",
    "NonZeroAtMost": "at most, not 0",
    "PositiveAtMost": "at most, above 0",
    "ClosestToZero": "closest to 0",
    "AtLeastOrUnlimited": "at least, or -1 for no limit",
}

# Tables of values this script reads, beyond the SCALAR_TABLES below, as
# (file under PLUGINS, const). The firewall's rules are built in a function,
# `get_baseline_rules`, which `code_firewall` reads by name.
READ_TABLES = {
    ("ssh/mod.rs", "SSH_CRYPTO_DIRECTIVES"),
    ("services/mod.rs", "UNNECESSARY_SERVICES"),
    ("permissions/mod.rs", "CRITICAL_PERMISSIONS"),
    ("audit/mod.rs", "AUDIT_RULES"),
}

# Tables of a plugin struct that hold no baseline value, each with the reason.
# Adding one here is a claim a reviewer can check; leaving a new table out of
# both this and the readers is what `unread_tables` refuses.
NOT_BASELINE = {
    ("pam/layer_drift.rs", "LAYERED_CONFS"): (
        "the /etc and /usr/etc file pairs the drift probe compares, not values"
    ),
}

# `const NAME: &[Struct]`, `static NAME: &'static [Struct]` or `const NAME:
# [Struct; N]`, at any visibility. Element types that are references or tuples
# do not match, and `unread_tables` keeps only structs the plugins define, so a
# list of names or an array of a framework enum is not taken for a table.
TABLE_CONST = re.compile(
    r"\b(?:const|static)\s+([A-Z][A-Z0-9_]*)\s*:\s*&?(?:'static\s+)?\[\s*([A-Z]\w*)\s*(?:;[^\]]*)?\]"
)

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


def plugin_sources(root: Path) -> dict[str, str]:
    """Every non-test `.rs` file under PLUGINS, keyed by its path below it."""
    sources = {}
    for path in sorted((root / PLUGINS).rglob("*.rs")):
        rel = path.relative_to(root / PLUGINS)
        if path.name == "tests.rs" or "tests" in rel.parts[:-1]:
            continue
        sources[rel.as_posix()] = path.read_text(encoding="utf-8")
    return sources


def unread_tables(sources: dict[str, str]) -> list[str]:
    """Deny by default: a table of a plugin struct is a table of values until
    this script reads it or NOT_BASELINE says why it holds none.

    The registry used to be the only list of tables, so a check added in a new
    file passed with no row at all, which is the gap issue #189 reported. The
    first two branches written after this page each added such a table.
    """
    structs = set()
    for text in sources.values():
        structs |= set(re.findall(r"\bstruct ([A-Z]\w*)", text))
    read = {(spec[1], spec[2]) for spec in SCALAR_TABLES} | READ_TABLES
    problems = []
    for rel, text in sources.items():
        for name, struct in TABLE_CONST.findall(text):
            if struct not in structs or (rel, name) in read or (rel, name) in NOT_BASELINE:
                continue
            problems.append(
                f"{PLUGINS / rel}: `{name}` is a table of `{struct}` this check does not read. "
                f"Give it a table on {PAGE} and a parser here, or name it in NOT_BASELINE "
                "with the reason it holds no baseline value"
            )
    for rel, name in sorted(read | set(NOT_BASELINE)):
        text = sources.get(rel)
        if text is None or not re.search(rf"\b(?:const|static)\s+{name}\b", text):
            problems.append(
                f"{PLUGINS / rel}: `{name}` is registered here but no longer defined there; "
                "move the registration with it"
            )
    return problems


CLOSERS = {"(": ")", "[": "]", "{": "}"}


def skip_string(text: str, start: int) -> int:
    """The index just past the string literal that opens at `start`."""
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index + 1
        index += 1
    raise ParseError("a string literal is never closed")


def balanced(text: str, start: int) -> tuple[str, int]:
    """The text inside the bracket at `start`, and the index of its partner.

    String literals and line comments are skipped, so a bracket inside a
    control's title or a comment does not count.
    """
    stack = [CLOSERS[text[start]]]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == '"':
            index = skip_string(text, index)
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = len(text) if newline == -1 else newline
            continue
        if char in CLOSERS:
            stack.append(CLOSERS[char])
        elif char in ")]}":
            if char != stack.pop():
                raise ParseError(f"an unbalanced {char!r}")
            if not stack:
                return text[start + 1 : index], index
        index += 1
    raise ParseError("a bracket is never closed")


def function_body(text: str, name: str) -> str | None:
    """The body of `fn name(...) ... { ... }` in this file, or None."""
    found = re.search(rf"\bfn {re.escape(name)}\s*\(", text)
    if found is None:
        return None
    _, params_end = balanced(text, found.end() - 1)
    brace = text.find("{", params_end)
    if brace == -1:
        raise ParseError(f"fn {name} has no body")
    return balanced(text, brace)[0]


def mapping_arms(text: str) -> list[tuple[str, str]]:
    """(pattern, body) for every `PATTERN => vec![...]` arm of the file's
    `*compliance_mappings` functions.

    A helper the arm calls, defined in the same file, is appended to its body,
    because some identifiers are built there: the PAM ageing arms reach the
    FedRAMP control through `pam_fedramp_password_ageing()`.
    """
    arms = []
    for found in re.finditer(r"\bfn (\w*compliance_mappings)\s*\(", text):
        body = function_body(text, found.group(1))
        if body is None:
            continue
        for arm in re.finditer(r"^[ \t]*([^\n]*?)\s*=>\s*vec!\[", body, re.M):
            inner, _ = balanced(body, arm.end() - 1)
            helpers = []
            for call in sorted(set(re.findall(r"\b(\w+)\(", inner))):
                if call == found.group(1):
                    continue
                helper = function_body(text, call)
                if helper is not None:
                    helpers.append(helper)
            arms.append((arm.group(1), "\n".join([inner, *helpers])))
    return arms


def arm_matches(pattern: str, key: str) -> bool:
    """Whether a check named `key` takes this arm: a string literal in the
    pattern equal to it, or a `contains("...")` guard it satisfies."""
    for literal in re.findall(r'"([^"]*)"', pattern):
        if literal == key:
            return True
        if literal and f'contains("{literal}")' in pattern and literal in key:
            return True
    return False


def plugin_arms(root: Path) -> list[tuple[str, str]]:
    """The mapping arms of every plugin, in one list."""
    arms = []
    for module in sorted((root / PLUGINS).glob("*/mod.rs")):
        arms += mapping_arms(module.read_text(encoding="utf-8"))
    if not arms:
        raise ParseError("no plugin has a `*compliance_mappings` function with arms")
    return arms


def profile_translations(text: str) -> dict[str, set[str]]:
    """{canonical identifier: the identifiers a profile translates it to}."""
    names = re.findall(r"\bconst (\w+): &\[Row\]", text)
    if not names:
        raise ParseError("profiles.rs declares no `&[Row]` tables")
    found: dict[str, set[str]] = {}
    for name in names:
        for canonical, target in re.findall(r'\(\s*"([^"]+)",\s*"([^"]+)",', const_body(text, name)):
            found.setdefault(canonical, set()).add(target)
    if not found:
        raise ParseError("the `&[Row]` tables in profiles.rs hold no rows")
    return found


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
    """Rule | Action | Protocol | Port | Source address | Source | Notes."""
    table = "firewall"
    problems: list[str] = []
    by_name = keyed(rows, 0, problems, table)
    for name in both_directions(table, expected, by_name, problems):
        row, want = by_name[name], expected[name]
        if not need_cells(table, name, row, 7, problems):
            continue
        for column, field in enumerate(("action", "protocol", "port", "source"), start=1):
            if first_tick(row[column]) != want[field]:
                problems.append(
                    f"{table}: `{name}` {field} reads {row[column]!r}, the code says "
                    f"`{want[field]}`"
                )
        check_source_cell(table, name, row[5], problems)
    return problems


def check_audit(expected: dict, prelude: list[str], page: str, rows: list[list[str]]) -> list[str]:
    """Category | Rule | Severity | Source, plus the prelude's two settings."""
    table = "audit"
    problems: list[str] = []
    by_rule = keyed(rows, 1, problems, table)
    for rule in both_directions(table, expected, by_rule, problems):
        row, want = by_rule[rule], expected[rule]
        if not need_cells(table, rule, row, 4, problems):
            continue
        if first_tick(row[0]) != want["category"]:
            problems.append(
                f"{table}: `{rule}` category reads {row[0]!r}, the code says {want['category']}"
            )
        if row[2].strip() != want["severity"]:
            problems.append(
                f"{table}: `{rule}` severity reads {row[2]!r}, the code says {want['severity']}"
            )
        check_source_cell(table, rule, row[3], problems)
    for setting in prelude:
        if f"`{setting}`" not in page:
            problems.append(f"{table}: the backlog prelude sets `{setting}` and the page never says so")
    return problems


LEGEND_HEADING = "## How to read the tables"


def check_legend(page: str, code: dict) -> list[str]:
    """Every comparison the code uses is defined in the page's legend.

    A row is held to the code's comparison word, but a word nobody defines
    tells a reader nothing; this is what makes a new direction, such as the
    ones #190 adds, arrive with its meaning written down.
    """
    heading = re.search(rf"^{re.escape(LEGEND_HEADING)}$", page, re.M)
    if heading is None:
        return [f"no `{LEGEND_HEADING}` section on the page"]
    end = page.find("\n## ", heading.end())
    legend = page[heading.end() : end if end != -1 else len(page)]
    used = sorted({entry["comparison"] for spec in SCALAR_TABLES for entry in code[spec[0]].values()})
    return [
        f"legend: the code compares some setting *{word}*, and `{LEGEND_HEADING}` does not "
        f"define it as `*{word}*`"
        for word in used
        if f"*{word}*" not in legend
    ]


def check_switch_off(table: str, code: dict, check: str, cell: str, problems: list[str]) -> None:
    """A switched-off row: the check is still compared plainly "at most", which
    ranks 0 and every negative number as the strictest values there are, and
    the value the row quotes is one of those."""
    scalar = {**code["kernel"], **code["ssh"], **code["pam"]}
    if check not in scalar:
        problems.append(f"{table}: `{check}` is in no kernel, SSH or PAM table")
        return
    word = scalar[check]["comparison"]
    if word != COMPARISON_WORDS["AtMost"]:
        problems.append(
            f"{table}: `{check}` is now compared {word!r}, not 'at most', so a value that switches "
            "it off may no longer pass; re-read the row and remove it if the gap is closed"
        )
    quoted = first_tick(cell)
    if quoted is None or not re.fullmatch(r"-?\d+", quoted) or int(quoted) > 0:
        problems.append(
            f"{table}: `{check}` should quote the switched-off value, 0 or below, first in "
            f"backticks, and reads {cell!r}"
        )


def check_quoted_value(table: str, code: dict, check: str, cell: str, problems: list[str]) -> None:
    """A stricter-value row's last cell quotes the baseline; it must be the code's."""
    quoted = first_tick(cell)
    scalar = {**code["kernel"], **code["ssh"], **code["pam"]}
    if quoted is None:
        problems.append(f"{table}: `{check}` quotes no baseline value in backticks")
    elif check in scalar:
        if quoted != scalar[check]["default"]:
            problems.append(
                f"{table}: `{check}` is quoted as {cell!r}, the code's default is "
                f"`{scalar[check]['default']}`"
            )
    elif check in code["ssh-crypto"]:
        if quoted not in code["ssh-crypto"][check]["list"]:
            problems.append(
                f"{table}: `{check}` is said to allow {cell!r}, which the code's allow-list "
                f"does not hold"
            )
    elif check in code["permissions"]:
        if quoted != code["permissions"][check]["mode"]:
            problems.append(
                f"{table}: `{check}` is quoted as {cell!r}, the code's mode is "
                f"`{code['permissions'][check]['mode']}`"
            )
    else:
        problems.append(
            f"{table}: `{check}` is in no baseline table, so the value it quotes cannot be held"
        )


def check_control_rows(
    table: str,
    code: dict,
    arms: list[tuple[str, str]],
    translations: dict[str, set[str]],
    rows: list[list[str]],
    last_column: str | None,
) -> list[str]:
    """Check | Control the plugin maps | Under the RHEL 10 profile | Asks | Accepts."""
    problems: list[str] = []
    if not rows:
        problems.append(f"{table}: the table is empty")
    for row in rows:
        if len(row) < 5:
            problems.append(f"{table}: a row has {len(row)} cells, expected 5")
            continue
        checks, mapped = ticks(row[0]), ticks(row[1])
        if not checks:
            problems.append(f"{table}: a row names no check in backticks: {row[0]!r}")
            continue
        label = ", ".join(checks)
        if not mapped:
            problems.append(f"{table}: `{label}` names no mapped control in backticks")
        bodies = []
        for check in checks:
            matched = [body for pattern, body in arms if arm_matches(pattern, check)]
            if not matched:
                problems.append(
                    f"{table}: `{check}` takes no arm of any plugin's mapping function"
                )
            bodies += matched
        mapped_text = "\n".join(bodies)
        for control in mapped:
            if bodies and f'"{control}"' not in mapped_text:
                problems.append(
                    f"{table}: `{label}` is no longer mapped to `{control}` in the plugin"
                )
        targets: set[str] = set()
        for control in mapped:
            targets |= translations.get(control, set())
        for control in ticks(row[2]):
            if control not in targets:
                problems.append(
                    f"{table}: `{control}` is not what profiles.rs translates "
                    f"{', '.join(mapped) or 'the mapped control'} to"
                )
        if last_column == "value":
            check_quoted_value(table, code, checks[0], row[4], problems)
        elif last_column == "switch-off":
            for check in checks:
                check_switch_off(table, code, check, row[4], problems)
    return problems


def readme_section(readme: str, heading: str) -> str | None:
    """README text from `heading` to the next heading of level two or three."""
    start = readme.find(heading + "\n")
    if start == -1:
        return None
    tail = readme[start + len(heading) :]
    ends = [end for end in (tail.find("\n### "), tail.find("\n## ")) if end != -1]
    return tail[: min(ends)] if ends else tail


def flexible(pattern: str) -> re.Pattern:
    """`pattern` with each space matching any run of whitespace."""
    return re.compile(pattern.replace(" ", r"\s+"))


def check_readme(readme: str, code: dict, generator: str) -> list[str]:
    """The baseline values README quotes, and its sentence on what a Pass means."""
    problems: list[str] = []
    for heading, pattern, table, setting in README_QUOTES:
        section = readme_section(readme, heading)
        if section is None:
            problems.append(f"README.md: no `{heading}` section any more")
            continue
        found = flexible(pattern).findall(section)
        want = code[table][setting]["default"]
        if not found:
            problems.append(
                f"README.md: `{heading}` no longer reads {pattern!r}; re-read the "
                f"quote of `{setting}` and move the pattern with it"
            )
        for value in found:
            if value != want:
                problems.append(
                    f"README.md: `{heading}` quotes `{setting}` as {value}, the code says {want}"
                )
    heading, sentence = README_PASS_SENTENCE
    section = readme_section(readme, heading)
    if section is None or not flexible(re.escape(sentence).replace(r"\ ", " ")).search(section):
        problems.append(
            f"README.md: `{heading}` no longer says a Pass is not always everything a "
            f"control asks for; the cases on {PAGE} still say so"
        )
    holds, detail = check_pass_against_baseline(generator)
    if not holds:
        problems.append(f"README.md: `{heading}` describes a Pass the generator no longer gives: {detail}")
    return problems


def check_page(
    page: str,
    code: dict,
    arms: list[tuple[str, str]],
    translations: dict[str, set[str]],
) -> list[str]:
    """Every problem with the page, against code already read."""
    problems: list[str] = []
    tables = {}
    keys = [spec[0] for spec in SCALAR_TABLES] + [
        "ssh-crypto",
        "services",
        "permissions",
        "firewall",
        "audit",
    ] + [key for key, _ in CONTROL_TABLES]
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
    for key, last_column in CONTROL_TABLES:
        if key in tables:
            problems += check_control_rows(key, code, arms, translations, tables[key], last_column)
    problems += check_legend(page, code)
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

# A plugin's mapping function in the shapes the real ones use: a literal arm
# whose identifier also arrives through a helper, a `contains` guard, a title
# with brackets in it, and a default arm.
SAMPLE_PLUGIN_RS = """
fn get_sample_compliance_mappings(name: &str) -> Vec<ComplianceMapping> {
    match name {
        "alpha" => vec![
            mapping("STIG-A", "A title [with] brackets"),
            helper_ids(),
        ],
        n if n.contains("beta") => vec![mapping("CIS-B", "x")],
        _ => vec![],
    }
}

fn helper_ids() -> ComplianceMapping {
    mapping("FED-H", "y")
}
"""

SAMPLE_PROFILES_RS = """
const SAMPLE_ROWS: &[Row] = &[
    ("STIG-A", "R10-A", "t", None),
    (
        "CIS-B",
        "R10-B",
        "t",
        None,
    ),
];
"""

SAMPLE_CODE = {
    "kernel": {"alpha": {"default": "5", "comparison": "at most"}},
    "ssh": {},
    "pam": {"minlen": {"default": "14"}, "remember": {"default": "5"}, "PASS_MAX_DAYS": {"default": "90"}},
    "ssh-crypto": {"Ciphers": {"list": ["a", "b"], "severity": "High"}},
    "permissions": {"/etc/x": {"mode": "0640", "comparison": "no bits beyond", "severity": "Critical"}},
    "services": {"cups": {"severity": "Medium"}},
    "firewall": {"ssh": {"action": "accept", "protocol": "tcp", "port": "22", "source": "any"}},
    "audit": {"-w /x -p wa -k k": {"category": "k", "severity": "High"}},
    "audit-prelude": ["-b 1"],
}

SAMPLE_GENERATOR_RS = (
    "let status = if has_live_finding(&related) {\n"
    "    ControlStatus::Fail\n"
    "} else if unchecked_ids.contains(control.compliance_control_id.as_str()) {\n"
    "    ControlStatus::ManualReview\n"
    "} else if assessed.contains(control.compliance_control_id.as_str()) {\n"
    "    ControlStatus::Pass\n"
)

SAMPLE_README = """### Compliance frameworks

A covered control passes when its plugin finds nothing weaker than the
baseline, which is not always everything the control asks for; see below.

### Where the default values come from

The password rules, a 14-character minimum and 5 remembered
passwords, are an older edition's. Its 90-day password expiry is stricter,
while its 14-character minimum is one short.

### Known limitations

- A Pass, such as a 15-character minimum where the
  baseline asks for 14, still passes.
"""


def rows_of(header: str, rows: list[str]) -> list[list[str]]:
    """Rows as the page reader returns them, from a table under a marker."""
    page = "<!-- baseline-table: t -->\n\n" + header + "\n".join(rows) + "\n\nAfter the table.\n"
    return page_table(page, "t") or []


SCALAR_HEADER = "| Setting | Default | Comparison | Severity | Source | Guides |\n|---|---|---|---|---|---|\n"
GOOD_A = "| `a.b` | `2` | at least | High | Project choice | none |"
GOOD_C = "| `c.d` | `1` | ranked, weakest first: `0`, `2`, `2b`, `1` | Low | Project choice | none |"


def scalar(rows: list[str]):
    def run() -> list[str]:
        expected = code_scalar(SAMPLE_KERNEL_RS, SAMPLE_SPEC)
        return check_scalar("kernel", expected, rows_of(SCALAR_HEADER, rows))

    return run


CRYPTO_HEADER = "| Directive | List | Severity | Source | Guides |\n|---|---|---|---|---|\n"
GOOD_CRYPTO = "| `Ciphers` | `a`, `b` | High | Commit | none |"
SERVICES_HEADER = "| Service | Severity | Source | Guides |\n|---|---|---|---|\n"
GOOD_SERVICE = "| `cups` | Medium | No source recorded | none |"
PERMISSIONS_HEADER = "| Path | Mode | Comparison | Severity | Source | Notes |\n|---|---|---|---|---|---|\n"
GOOD_PERMISSION = "| `/etc/x` | `0640` | no bits beyond | Critical | Commit | |"
FIREWALL_HEADER = (
    "| Rule | Action | Protocol | Port | Address | Source | Notes |\n|---|---|---|---|---|---|---|\n"
)
GOOD_FIREWALL = "| `ssh` | `accept` | `tcp` | `22` | `any` | No source recorded | n |"
AUDIT_HEADER = "| Category | Rule | Severity | Source |\n|---|---|---|---|\n"
GOOD_AUDIT = "| `k` | `-w /x -p wa -k k` | High | Code comment |"
AUDIT_PAGE = "The file opens with `-b 1`."
CONTROL_HEADER = "| Check | Mapped | RHEL 10 | Asks | Accepts |\n|---|---|---|---|---|\n"
GOOD_CONTROL = "| `alpha` | STIG `STIG-A`, FedRAMP `FED-H` | STIG `R10-A` | 15 | `5` or more |"
GUARD_CONTROL = "| `xbetax` | CIS `CIS-B` | CIS `R10-B` | more | prose only |"
SWITCH_CONTROL = "| `alpha` | STIG `STIG-A` | STIG `R10-A` | a limit | `0`, ranked stricter than `5` |"


def crypto(rows: list[str]):
    return lambda: check_crypto(SAMPLE_CODE["ssh-crypto"], rows_of(CRYPTO_HEADER, rows))


def services(rows: list[str]):
    return lambda: check_services(SAMPLE_CODE["services"], rows_of(SERVICES_HEADER, rows))


def permissions(rows: list[str]):
    return lambda: check_permissions(SAMPLE_CODE["permissions"], rows_of(PERMISSIONS_HEADER, rows))


def firewall(rows: list[str]):
    return lambda: check_firewall(SAMPLE_CODE["firewall"], rows_of(FIREWALL_HEADER, rows))


def audit(rows: list[str], page: str = AUDIT_PAGE):
    def run() -> list[str]:
        table = rows_of(AUDIT_HEADER, rows)
        return check_audit(SAMPLE_CODE["audit"], SAMPLE_CODE["audit-prelude"], page, table)

    return run


def controls(
    rows: list[str],
    plugin: str = SAMPLE_PLUGIN_RS,
    last_column: str | None = "value",
    code: dict = SAMPLE_CODE,
):
    def run() -> list[str]:
        arms = mapping_arms(plugin)
        translations = profile_translations(SAMPLE_PROFILES_RS)
        table = rows_of(CONTROL_HEADER, rows)
        return check_control_rows("t", code, arms, translations, table, last_column)

    return run


def registered_sources() -> dict[str, str]:
    """A plugin tree in which every registered table is defined, each of a
    struct of its own, as the real tree has them."""
    sources: dict[str, str] = {}
    registered = sorted({(spec[1], spec[2]) for spec in SCALAR_TABLES} | READ_TABLES | set(NOT_BASELINE))
    for number, (rel, name) in enumerate(registered):
        sources[rel] = sources.get(rel, "") + (
            f"pub(super) struct Row{number} {{ x: u8 }}\nconst {name}: &[Row{number}] = &[\n];\n"
        )
    return sources


def tables(extra: dict[str, str] | None = None, drop: str | None = None):
    def run() -> list[str]:
        sources = registered_sources()
        if drop is not None:
            for rel, text in sources.items():
                sources[rel] = text.replace(f"const {drop}:", f"const RENAMED_{drop}:")
        for rel, text in (extra or {}).items():
            sources[rel] = sources.get(rel, "") + text
        return unread_tables(sources)

    return run


SAMPLE_LEGEND_PAGE = (
    "## How to read the tables\n\n- *at least*: larger is stricter.\n"
    "- *at most*: smaller is stricter.\n\n## Kernel parameters\n\n*closest to 0* is not here.\n"
)


def legend(comparisons: list[str]):
    code = {
        "kernel": {f"k{i}": {"comparison": word} for i, word in enumerate(comparisons)},
        "ssh": {},
        "pam": {},
    }
    return lambda: check_legend(SAMPLE_LEGEND_PAGE, code)


def readme(text: str = SAMPLE_README, code: dict = SAMPLE_CODE, generator: str = SAMPLE_GENERATOR_RS):
    return lambda: check_readme(text, code, generator)


def ranked_order_read() -> list[str]:
    order = code_scalar(SAMPLE_KERNEL_RS, SAMPLE_SPEC)["c.d"]["order"]
    return [] if order == ["0", "2", "2b", "1"] else [f"read as {order}"]


def missing_marker() -> list[str]:
    return [] if page_table("no marker here", "kernel") is None else ["read as a table"]


# (why, the detail a rejection must carry or None for a page the check must
# accept, the check to run). Every checker has a case it must accept and at
# least one it must reject, so a checker broken into accepting everything, or
# rejecting everything, fails here before its verdict on the real page is
# printed. A rejection must also name its own reason: a checker that rejects
# every input for one broken reason would otherwise pass every negative case.
SELF_TEST_CASES = [
    ("a page that matches the code passes", None, scalar([GOOD_A, GOOD_C])),
    ("a default that moved in the code is flagged", 'default reads', scalar([GOOD_A.replace("`2`", "`3`"), GOOD_C])),
    ("a comparison in the wrong direction is flagged", 'comparison reads', scalar([GOOD_A.replace("at least", "at most"), GOOD_C])),
    ("a severity that changed is flagged", 'severity reads', scalar([GOOD_A.replace("High", "Medium"), GOOD_C])),
    ("a setting with no row is flagged", 'has no row on the page', scalar([GOOD_A])),
    (
        "a row for a setting the code dropped is flagged",
        'is not in the code',
        scalar([GOOD_A, GOOD_C, "| `e.f` | `0` | at most | Low | Project choice | none |"]),
    ),
    ("a setting with two rows is flagged", 'more than one row', scalar([GOOD_A, GOOD_C, GOOD_A])),
    (
        "a row that does not say where its value comes from is flagged",
        'does not say where its value comes from',
        scalar([GOOD_A.replace("Project choice", ""), GOOD_C]),
    ),
    (
        "a ranked order written in the wrong order is flagged",
        'ranks it weakest first',
        scalar([GOOD_A, GOOD_C.replace("`2`, `2b`", "`2b`, `2`")]),
    ),
    ("a ranked order with a constant in it is read weakest first", None, ranked_order_read),
    ("a page without a table's marker is reported, not read as empty", None, missing_marker),
    ("crypto: a list that matches the code passes", None, crypto([GOOD_CRYPTO])),
    ("crypto: a list in another order is flagged", 'in that order', crypto([GOOD_CRYPTO.replace("`a`, `b`", "`b`, `a`")])),
    ("crypto: a list with no source is flagged", 'does not say where its value comes from', crypto([GOOD_CRYPTO.replace("Commit", "")])),
    ("services: a row that matches the code passes", None, services([GOOD_SERVICE])),
    ("services: a severity that changed is flagged", 'severity reads', services([GOOD_SERVICE.replace("Medium", "Low")])),
    ("permissions: a row that matches the code passes", None, permissions([GOOD_PERMISSION])),
    ("permissions: a wrong mode is flagged", 'mode reads', permissions([GOOD_PERMISSION.replace("`0640`", "`0600`")])),
    (
        "permissions: exact where the code masks is flagged",
        'comparison reads',
        permissions([GOOD_PERMISSION.replace("no bits beyond", "exact")]),
    ),
    ("firewall: a rule that matches the code passes", None, firewall([GOOD_FIREWALL])),
    ("firewall: a port that moved is flagged", 'port reads', firewall([GOOD_FIREWALL.replace("`22`", "`2222`")])),
    (
        "firewall: a rule with no source is flagged",
        'does not say where its value comes from',
        firewall([GOOD_FIREWALL.replace("No source recorded", "")]),
    ),
    ("audit: a rule that matches the code passes", None, audit([GOOD_AUDIT])),
    ("audit: a rule the code has and the page lacks is flagged", 'has no row on the page', audit([])),
    ("audit: a rule with no source is flagged", 'does not say where its value comes from', audit([GOOD_AUDIT.replace("Code comment", "")])),
    ("audit: a page silent on the backlog prelude is flagged", 'backlog prelude', audit([GOOD_AUDIT], page="")),
    (
        "controls: rows held to the mapping arms, a helper and a contains guard pass",
        None,
        controls([GOOD_CONTROL, GUARD_CONTROL], last_column=None),
    ),
    ("controls: a quoted value that is the code's passes", None, controls([GOOD_CONTROL])),
    (
        "controls: a control the plugin stopped mapping is flagged although profiles.rs keeps it",
        'no longer mapped to `STIG-A`',
        controls([GOOD_CONTROL], plugin=SAMPLE_PLUGIN_RS.replace('"STIG-A"', '"STIG-Z"')),
    ),
    (
        "controls: a RHEL 10 identifier the mapped control does not translate to is flagged",
        'is not what profiles.rs translates',
        controls([GOOD_CONTROL.replace("`R10-A`", "`R10-B`")]),
    ),
    ("controls: a check that takes no mapping arm is flagged", 'takes no arm', controls([GOOD_CONTROL.replace("`alpha`", "`gamma`")])),
    ("controls: a quoted value that moved is flagged", "the code's default is", controls([GOOD_CONTROL.replace("`5`", "`6`")])),
    ("readme: quotes and the Pass sentence that match the code pass", None, readme()),
    (
        "readme: a quoted value the code changed is flagged",
        'quotes `minlen` as 14, the code says 15',
        readme(code={**SAMPLE_CODE, "pam": {**SAMPLE_CODE["pam"], "minlen": {"default": "15"}}}),
    ),
    (
        "readme: a reworded quote is flagged rather than skipped",
        'no longer reads',
        readme(text=SAMPLE_README.replace("Its 90-day password expiry", "Expiry after 90 days")),
    ),
    (
        "readme: the old claim restored in place of the Pass sentence is flagged",
        'no longer says a Pass',
        readme(
            text=SAMPLE_README.replace(
                "A covered control passes when its plugin finds nothing weaker than the\n"
                "baseline, which is not always everything the control asks for; see below.",
                "A report cannot claim compliance the tool did not measure.",
            )
        ),
    ),
    ("controls: a switched-off value the code still ranks strictest passes", None, controls([SWITCH_CONTROL], last_column="switch-off")),
    (
        "controls: a switched-off row whose comparison was fixed is flagged",
        "is now compared 'at most, above 0'",
        controls(
            [SWITCH_CONTROL],
            last_column="switch-off",
            code={**SAMPLE_CODE, "kernel": {"alpha": {"default": "5", "comparison": "at most, above 0"}}},
        ),
    ),
    (
        "controls: a switched-off row quoting a working limit is flagged",
        "should quote the switched-off value",
        controls([SWITCH_CONTROL.replace("`0`", "`3`")], last_column="switch-off"),
    ),
    ("tables: a tree whose tables are all read passes", None, tables()),
    (
        "tables: a new table of a plugin struct in a new file is flagged",
        "`HASHING_DIRECTIVES` is a table of `Row",
        tables(extra={"pam/hashing.rs": "pub(super) const HASHING_DIRECTIVES: &[Row0] = &[\n];\n"}),
    ),
    (
        "tables: an array of a plugin struct is flagged as well as a slice",
        "`NIST_RULES` is a table of `NistRule`",
        tables(extra={"pam/policy.rs": "struct NistRule { a: u8 }\nconst NIST_RULES: [NistRule; 2] = [\n];\n"}),
    ),
    (
        "tables: a list of names and an array of an outside enum are not tables",
        None,
        tables(extra={"pam/policy.rs": "const NAMES: &[&str] = &[];\nconst F: [ComplianceFramework; 4] = [];\n"}),
    ),
    (
        "tables: a registered table that no longer exists is flagged",
        "registered here but no longer defined",
        tables(drop="AUDIT_RULES"),
    ),
    ("legend: comparisons the legend defines pass", None, legend(["at least", "at most"])),
    (
        "legend: a comparison the code uses and the legend does not define is flagged",
        "does not define it as `*closest to 0*`",
        legend(["at least", "closest to 0"]),
    ),
    (
        "readme: a Pass arm that gains a condition is flagged",
        'Pass arm',
        readme(generator=SAMPLE_GENERATOR_RS.replace(
            "} else if assessed.contains(control.compliance_control_id.as_str()) {",
            "} else if assessed.contains(control.compliance_control_id.as_str())\n"
            "    && !partial.contains(control.compliance_control_id.as_str()) {",
        )),
    ),
]

# Fewer cases than this means one was dropped, and with it a checker may have
# lost the only case that rejects anything.
MINIMUM_SELF_TEST_CASES = 47


def self_test(quiet: bool = False) -> int:
    """Runs every checker against page shapes the real page does not contain."""
    if not quiet:
        print(f"{BLUE}Self-test: page shapes each check must reject, and ones it must not...{NC}\n")
    if len(SELF_TEST_CASES) < MINIMUM_SELF_TEST_CASES:
        print(
            f"{RED}The self-test table holds {len(SELF_TEST_CASES)} cases, fewer than the "
            f"{MINIMUM_SELF_TEST_CASES} written.{NC}"
        )
        return 1

    failures = 0
    for why, expected_detail, run in SELF_TEST_CASES:
        try:
            problems = run()
        except ParseError as error:
            print(f"  {RED}x{NC} {why}: the parser cannot read its own sample: {error}")
            failures += 1
            continue
        if expected_detail is None and problems:
            print(f"  {RED}x{NC} {why}: flagged, expected accepted ({problems[0]})")
            failures += 1
            continue
        if expected_detail is not None and not any(expected_detail in p for p in problems):
            got = problems[0] if problems else "accepted"
            print(f"  {RED}x{NC} {why}: expected a problem naming {expected_detail!r}, got {got!r}")
            failures += 1
            continue
        if not quiet:
            print(f"  {GREEN}v{NC} {why}")

    if failures:
        print(f"\n{RED}{failures} self-test case(s) failed{NC}")
        return 1
    if not quiet:
        print(f"\n{GREEN}All {len(SELF_TEST_CASES)} self-test cases behave as written{NC}")
    return 0


# ---------------------------------------------------------------------------


def find_project_root() -> Path:
    """The repository root, found by walking up from this file."""
    return Path(__file__).resolve().parent.parent.parent


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    print(f"{BLUE}Validating {PAGE} and README.md against the plugin baselines...{NC}\n")
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
        sources = plugin_sources(root)
        code = read_code(root)
        arms = plugin_arms(root)
        translations = profile_translations((root / PROFILES).read_text(encoding="utf-8"))
        readme_text = (root / README).read_text(encoding="utf-8")
        generator = (root / GENERATOR).read_text(encoding="utf-8")
    except (ParseError, OSError) as error:
        print(f"{RED}The code no longer has the shape this parser reads: {error}{NC}")
        print("  Update the parser in this script rather than leaving the page unchecked.")
        return 1

    problems = unread_tables(sources)
    problems += check_page(page_path.read_text(encoding="utf-8"), code, arms, translations)
    problems += check_readme(readme_text, code, generator)
    if problems:
        print(f"{RED}{PAGE} or README.md disagrees with the code ({len(problems)}):{NC}")
        for problem in problems:
            print(f"  {RED}x{NC} {problem}")
        print()
        print("  A changed default needs its row, and any README quote of it, changed in")
        print("  the same commit, and a new check needs a row that says where its value")
        print("  came from. A new table of values needs a parser here as well as rows.")
        return 1

    counts = ", ".join(
        f"{len(code[key])} {key}"
        for key in ("kernel", "ssh", "ssh-crypto", "pam", "services", "permissions", "firewall", "audit")
    )
    control_rows = sum(len(page_table(page_path.read_text(encoding="utf-8"), key) or []) for key, _ in CONTROL_TABLES)
    read = len({(spec[1], spec[2]) for spec in SCALAR_TABLES} | READ_TABLES) + 1
    print(f"  {GREEN}v{NC} Every baseline row agrees with the code: {counts}")
    print(
        f"  {GREEN}v{NC} No plugin table goes unread: {read} read, counting the firewall's "
        f"function, and {len(NOT_BASELINE)} named as holding no values"
    )
    print(f"  {GREEN}v{NC} {control_rows} rows of Passes that fall short hold to the plugins' mapping arms and profiles.rs")
    print(f"  {GREEN}v{NC} README quotes {len(README_QUOTES)} baseline values correctly, and its Pass sentence holds")
    print(f"\n{GREEN}Baseline sources validation passed{NC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
