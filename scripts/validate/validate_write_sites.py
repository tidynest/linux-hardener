#!/usr/bin/env python3
"""
Holds every file-creating call site in the plugins tree to two written answers:
why its parent directory exists, and whether the path it creates is declared to
its own plugin's pre-apply checkpoint. Then asserts, of the `cp` sites alone,
the one thing that needs no answer because it has only one: that a backup copy
preserves its source's mode and does not follow a symlink.

Usage:
    ./scripts/validate/validate_write_sites.py

Exit codes:
    0: Every file-creating call site is classified on both questions, and
       every `cp` passes both backup flags
    1: A site is unclassified on either question, an entry is stale or
       malformed, a cited ensure or checkpoint declaration is gone, a `cp` is
       missing a backup flag, or either pinned count moved

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

THE SECOND QUESTION, AND WHY IT IS ASKED HERE

A file can have a parent directory that certainly exists and still outlive the
apply that created it. `CheckpointManager::create_checkpoint` captures a
declared directory recursively, which records the children that are there when
it runs, and `CheckpointManager::rollback` walks only the rows the checkpoint
holds. A file the apply is about to create has no row, so nothing removes it,
and the hardening survives the rollback meant to undo it.

The convention that closes it is to declare the path itself alongside its
directory. A declared path that is absent at capture is stored with a zero mode,
which `restore_file_state_tracked` reads as "remove this", so the rollback
deletes exactly what the apply created and leaves an untouched host alone.
kernel/mod.rs declares SYSCTL_HARDENER_CONF beside SYSCTL_DROPIN_DIR and ssh
declares dropin::DROPIN_PATH beside the main config for this reason.

This has now been found twice, which is the same shape as the story above and
the reason a second column exists rather than a second one-off fix:

  - services/mod.rs: the `systemctl mask` link went undeclared, so `systemctl
    mask` was not undoable. `386d122` and `ed60feb`, proved in containers on
    five distributions.
  - audit/mod.rs: AUDIT_RULES_PATH was written while only auditd.conf and
    AUDIT_RULES_DIR were declared, so the rules file a first apply created
    survived that apply's own rollback. `60e9b12`.

THE THIRD QUESTION, WHICH IS AN ASSERTION RATHER THAN A COLUMN

Three plugins copy a configuration file before rewriting it, and all three asked
`cp` the same question with three different answers: pam passed no flags, ssh
passed `-p`, audit passed `--no-dereference`. Each was therefore losing what the
other two kept. A copy made without `-p` records none of the source's mode,
ownership or timestamps, so an operator who restores it gets the file at
whatever the umask hands them, which on the audit rules file is the map of every
path and syscall the host watches. A copy made without `--no-dereference`
follows a symlink and copies its target, so a config that is a link elsewhere is
backed up as some other file and the object about to be overwritten has no
backup at all.

That is the same shape as the two stories above, one defect standing in three
places, but it is asked differently here. The other two questions have answers
that legitimately differ per site, which is why they are registry columns: a
kernel pseudo-file and a scratch copy in /tmp are exempt for genuinely
unrelated reasons, and a check cannot tell a deliberate asymmetry from an
overlooked path. This one has a single correct answer everywhere. There is
nothing for an entry to decide, so a fourth column would only offer a place to
write "exempt" in prose, which is how a check becomes a form. It is asserted
instead: every call whose argv[0] literal is `cp` passes both flags, or the
run fails.

What it cannot see is the same blind spot the whole file has, and it is worth
saying twice because this assertion looks stricter than it is. It reads the
argument text of calls whose argv[0] is the literal string "cp". A `cp` invoked
through a variable, through `sh -c`, or by any wrapper is not a site here and is
not checked. A copy made by other means, `install`, `dd`, a `tee` from a read,
or a `write_file` of content read a moment earlier, is a backup in every sense
that matters and this says nothing about it. And it reads text: a site passing
a `&[flag, path, dest]` built above the call is invisible to it, though none
exists today. It also asks presence and not position: a site passing the flags
after the source and destination satisfies it, and `cp` accepts that, but an
argument added after the source is one `cp` would read as another file to copy.
The three plugins' own tests are what pin the order, by asserting the source and
destination are still the last two arguments; this was measured by moving the
flags to the end, which the tests caught and this did not. What it does
guarantee is that the three literal `cp` backups in the tree cannot drift apart
again without failing.

IT CANNOT SEE THE MASK LINK, WHICH IS THE DEFECT THAT PROMPTED IT

Said first because it is the limit most likely to be misread. The tuple below
holds argv[0] names, and `systemctl mask` creates its link through
`execute_command("systemctl", ...)`. Adding "systemctl" to that tuple would drag
in every `start`, `stop`, `is-enabled`, `is-active`, `daemon-reload` and
`list-unit-files` call in the tree, twenty-two `systemctl` calls in all, of
which the mask is one. So the services defect that prompted this column sits
outside the column's reach, and so does every sibling of it: `systemctl enable`
writes a `.wants` symlink under /etc/systemd/system for the firewall and audit
plugins, neither of whose checkpoints declares anything there; `augenrules
--load` merges /etc/audit/rules.d into /etc/audit/audit.rules and saves the
previous compiled copy as /etc/audit/audit.rules.prev, both of which the audit
checkpoint now declares, having been measured on five distributions surviving
the rollback that was supposed to undo them; and `firewall-cmd --permanent` and
`ufw` write their persistence through their own tooling, into /etc/firewalld and
/etc/ufw, which the firewall checkpoint does declare. The last two are the
reminder that unseen and undeclared are different failures: this check finds
neither, and only one of them is a defect. The augenrules pair is also the
reminder that unseen is not harmless, because that one was both, and nothing
here reported it: it was found by reading the files on a host after a rollback.

Those are the reviewer's questions, and this file answers none of them. Nor
would answering them be mechanical if it could see them. The same sweep that
found the two defects above reached firewall's `ensure_unit_wanted_at_boot`,
which creates such a symlink that no checkpoint declares, and the answer there
is that leaving it is deliberate: removing it would disable the firewall at boot
on a host whose operator asked only to undo a hardening run. `925263a` wrote
that reasoning onto the function. audit's `systemctl enable auditd` is the same
shape and now carries its own note, reached by the same rule and deliberately
not a copy: firewall's argument rests partly on its own rollback re-enabling the
firewall unconditionally, and audit's rollback says nothing about enablement, so
only the shared rule carries the audit case. A check cannot tell a deliberate
asymmetry from an overlooked path, which is the argument for a registry of
written answers and against a cleverer analysis.

WHAT THIS PROVES, AND IT IS NARROW

That no file-creating call site under `crates/hardener-plugins/src` is
unclassified on either question, and that no literal `cp` among them copies
without both backup flags. A new one cannot be added without someone deciding,
in writing, why its parent directory is there and whether a rollback reaches
what it creates. That is the property whose absence let one defect become three
commits and a second one two.

It is a registry check, not a static analysis. Said plainly, because a check
that overstates itself is worse than no check:

  - It does not prove any ensure is correct, covers the right parent, or runs
    before the write on every path that reaches it. For an `ensured` entry it
    confirms only that an `ensure_directory` for the named directory exists in
    the same file. The ordering argument is the reviewer's, and for the audit
    plugin it is subtle: the ensure has to sit above the checkpoint capture,
    because a checkpoint stores an absent path with a zero mode and a rollback
    reads that as "remove this".
  - It does not prove a declaration is correct either. For a `declared` entry it
    confirms only that the named token appears inside a checkpoint declaration
    somewhere in the same plugin directory: the arguments of a
    `create_checkpoint*_for_apply` call, the initialiser of a `Vec<&Path>`
    binding, or the body of a `checkpoint_paths` returning the paths one
    backend writes. It does not follow the token to a path, does not check
    that the declaration is the one that runs on the branch reaching the
    write, and does not know whether the checkpoint is captured before the
    write. A path appended to a list after its initialiser, as
    services/mod.rs does with `service_paths.extend(...)`, is not read at
    all.
  - The directory search is per plugin directory rather than per file because
    ssh/dropin.rs writes a path that ssh/mod.rs declares. That is deliberate,
    and it is also the loosest part of the check: two plugins are never
    conflated, but two apply paths within one plugin are.
  - It does not see a file created by `execute_command` through any means other
    than the argv[0] names in FILE_CREATING_COMMANDS. A shell redirection, a
    `sh -c` script, or a program named by a variable rather than a literal all
    pass unseen, as does every case in the section above.
  - It does not see a direct `std::fs` write. There are none in the tree today
    (measured: the only `OpenOptions` is permissions/mod.rs, opened read-only
    with `O_NOFOLLOW` for a TOCTOU-safe `fchmod`, which creates nothing), so the
    absence is currently free, but nothing here would notice one arriving.
  - `mkdir` is deliberately absent from FILE_CREATING_COMMANDS. It creates
    directories rather than files, and `mkdir -p` makes its own parents, so it
    is the one call that cannot suffer the parent-directory defect.
    `crate::ensure_directory` itself would otherwise be reported as a site.

EXPECTED_SITE_COUNT is pinned as a literal for the reason
`require_check_tables` in scripts/test/differential-suite.sh pins every table
length: a registry that discovers its own expected size cannot fail when a site
is added, which is the one thing this check exists to do. The second column
needs no pin of its own. Every entry carries both answers or is rejected as
malformed, and the registry's length is already held to the pin, so a site
arriving unanswered on the new question fails on the count exactly as it does on
the old one. A pinned count of `declared` sites would add nothing to that and
would have to be edited every time a site legitimately changed bucket, which is
how a pin turns into a number people update without reading.

TWO COUNTS ARE PINNED, NOT ONE, AND THEY CATCH DIFFERENT FAILURES

EXPECTED_SITE_COUNT holds the number of DISTINCT (file, key) patterns,
`len(seen)` in `main`, which the unregistered/stale/malformed checks above it
already keep equal to `len(REGISTRY)`. What it catches is a genuinely new
pattern arriving classified: a call site can only reach an unfamiliar key by
being `unregistered`, or by arriving alongside a new entry that answers for
it, and in the second case nothing else in this file would ever ask a human
to notice the total grew. This pin is what does.

EXPECTED_RAW_SITE_COUNT holds `len(sites)`, the count of `.write_file(` and
recognised `.execute_command(` matches before any of them are folded into a
pattern. It exists because the fold can hide a genuinely new site behind an
old key rather than behind a new one. A write site whose first argument
happens to read the same as an already-registered site's, `write_file(path`
answering for a second, unrelated path because the new call also binds its
argument to a local named `path`, is not `unregistered`: its key is already
in REGISTRY, so it is classified, silently, by an entry written to justify a
different write. `len(seen)` cannot see this, because a repeated key does not
grow the set of distinct patterns; only the raw count does. This was proven
directly: a `write_file(path, ...)` call appended to `firewall/nftables.rs`
under that reused key passed every check here with EXPECTED_SITE_COUNT alone
and was refused only once EXPECTED_RAW_SITE_COUNT stood beside it.

The two numbers coincide only while every key in the tree answers for exactly
one call site, which held until the nftables boot-persistence work gave
`write_file(Path::new(NFTABLES_CHECK_PATH)` a second call site on purpose:
`execute_nft_from_string` and `refuse_a_ruleset_nft_will_not_parse` both park
a candidate ruleset at that same scratch path for the same documented reason,
so one registry entry now answers for two real writes and `len(sites)` sits
one above `len(seen)`. That gap is itself information, the number of call
sites currently sharing a key for a stated reason, and the two constants are
edited together for a genuinely new pattern and independently whenever a
sharing like that one is added or removed. Keeping both, rather than folding
one into the other, is two integers; refusing the one write this file cannot
see any other way is what the second buys.
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

# The number of distinct (file, key) call-site patterns in the tree, pinned
# rather than counted. Counted off the registry it would follow the registry
# down, and a site added with no entry would be the exact thing this check
# cannot see. Not the same as the raw number of matched calls: two call sites
# sharing one pattern, as the two writes to NFTABLES_CHECK_PATH now do, are
# one pattern and answer to one registry entry.
EXPECTED_SITE_COUNT = 13

# The raw number of `.write_file(`/`.execute_command(` matches, before any of
# them are folded into a (file, key) pattern. Pinned separately from
# EXPECTED_SITE_COUNT because the fold is exactly what a new site can hide
# behind: one whose first argument's text happens to match an already
# registered key raises `len(sites)` without raising `len(seen)` or
# registering as `unregistered`, since its key is already in REGISTRY. Proven
# directly against this file: a `write_file(path, ...)` appended under the
# reused key `write_file(path` passed with this pin absent and failed once it
# was restored. Edited together with EXPECTED_SITE_COUNT when a genuinely new
# pattern arrives; edited alone when an existing pattern gains or loses a
# call site that deliberately shares its key, as NFTABLES_CHECK_PATH's two
# sites do.
EXPECTED_RAW_SITE_COUNT = 14

# `execute_command` is the escape hatch: it can materialise a path without ever
# touching `write_file`. Only a literal argv[0] is recognised, and only these.
# `cp` is the one used today, three times, always for a backup; the others are
# listed so that reaching for one is a decision rather than an omission.
FILE_CREATING_COMMANDS = ("cp", "mv", "ln", "tee", "touch", "install", "dd")

# Both flags a backup copy has to carry, asserted rather than registered because
# the answer is the same at every site. `-p` preserves the source's mode,
# ownership and timestamps, so a restored copy is the file rather than one
# wearing the umask's mode; `--no-dereference` copies a symlink as a symlink, so
# what is backed up is the object about to be overwritten rather than whatever
# it points at. Matched as quoted literals, so `-pr` does not satisfy `-p` and a
# flag reaching the call through a variable is reported as missing rather than
# guessed at. Only the copy is held to this: `mv`, `ln` and the rest are listed
# above so that using one is a decision, and none of them takes these flags.
BACKUP_CP_FLAGS = ("-p", "--no-dereference")

# Where a plugin declares the paths its pre-apply checkpoint captures. Two
# shapes carry them today and both are matched: the arguments of a
# `create_checkpoint_for_apply` or `create_checkpoint_metadata_only_for_apply`
# call, and the initialiser of the `Vec<&Path>` binding such a call is usually
# handed. The second is needed because the binding is built several lines above
# the call it feeds, and the first because ssh passes its paths inline.
CHECKPOINT_CALL = re.compile(r"create_checkpoint(?:_metadata_only)?_for_apply\s*\(")
CHECKPOINT_PATH_LIST = re.compile(r":\s*Vec<&Path>\s*=")

# A third shape, and the reason it exists is worth keeping. The firewall plugin
# used to declare all three backends' paths in one literal list at its apply
# site, so a ufw host recorded a checkpoint row for `/etc/nftables.conf`, a file
# its apply could never create. A row recorded absent is an instruction to
# delete, so a rollback on such a host would have removed whatever had arrived
# at that path in the meantime. The declaration now lives on the backend that
# does the writing, as `FirewallBackend::checkpoint_paths`, and `apply` hands
# that return value straight to `create_checkpoint_for_apply`. Matching the
# body keeps a per-backend declaration as visible to this check as a literal
# list.
#
# The signature changed once more since: it was `fn config_paths(&self) ->
# &'static [&'static str]`, a synchronous method returning literal paths,
# until the nftables backend needed to probe the boot unit through the
# executor to know which file it was declaring. All three backends carry the
# new shape, `async fn checkpoint_paths(&self, ctx: &Context) ->
# Result<Vec<String>>`, whether or not a given backend's own body reads `ctx`,
# and the parameter is named `ctx` on the one implementation that does and
# `_ctx` on the two that do not, so both are matched.
CHECKPOINT_PATHS_FN = re.compile(
    r"fn checkpoint_paths\(&self,\s*_?ctx:\s*&Context\)\s*->\s*Result<Vec<String>>\s*\{"
)

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

# The same three copies, answering the other question, and the one answer that
# nobody appears to have written down before. `ce9185c` added the checkpoint
# alongside the copy the ssh plugin already took and called it a "legacy backup
# in addition to checkpoint", which settles that the two coexist and says
# nothing about what a rollback should do with the copy; no other commit,
# comment, test or document in the tree addresses it. What follows is therefore
# this registry's reasoning rather than a citation of anyone's decision, and it
# is written out in one place so a reader can disagree with it once rather than
# three times.
BACKUP_SURVIVES_ROLLBACK = (
    "the copy's name carries a timestamp minted during the apply, after the "
    "checkpoint that would have to name it was captured, so no checkpoint can "
    "hold a row for it and every rollback leaves it where it is. That is a "
    "deliberate consequence rather than a fixed one: declaring it would mean "
    "choosing the name above the capture and passing it down. It costs nothing "
    "this column exists to protect, because the copy imposes no state of ours "
    "on the host, only a second reading of state the host already had, and {}"
)

# Every file-creating call site, keyed by the file it is in and the call's own
# first argument, which is stable under the line drift a line number is not.
#
# Each entry answers two questions in two pairs, in the order a defect of each
# kind was found: first the parent directory, then the rollback.
#
# Parent directory, "why can this write land at all":
# "ensured": the run reaches a `crate::ensure_directory` for this path's parent
# before the write, and the entry names the directory it passes.
# "exempt": the parent is guaranteed by something other than this tool, and the
# entry says by what. The reasons genuinely differ, so they are written out per
# site rather than shared: a kernel-provided pseudo-filesystem, a path under
# /tmp, and a file that must already exist to have been read are three different
# guarantees that happen to land in one bucket.
#
# Rollback, "does a rollback reach what this write created":
# "declared": the path is named to this plugin's pre-apply checkpoint, so a
# capture taken before the write records it (absent, with a zero mode, when the
# apply is the thing creating it) and the restore removes or rewrites it. The
# entry names the tokens that have to appear in the declaration, and every one
# of them is checked. Several tokens where one write site can land on several
# paths: the answer is only true if it is true of all of them.
# "exempt": nothing declares it and the entry says why that is right rather than
# missed. As above the reasons differ, and here the difference matters more,
# because "no checkpoint holds this" is the exact shape of the defect the column
# exists to catch. Each one has to argue that no state of ours outlives the
# rollback, not merely that no row exists.
REGISTRY = {
    ("kernel/mod.rs", "write_file(Path::new(&path)"): (
        (
            "exempt",
            "/proc/sys/<param>: the kernel creates the whole tree when procfs "
            "is mounted, no package owns it, and mkdir cannot add to it",
        ),
        (
            "exempt",
            "the write creates nothing to declare: the procfs node is there "
            "whenever procfs is mounted, both before this write and after any "
            "rollback, so there is no path for a capture to record or a "
            "restore to remove. Whether the value it carries reverts is a "
            "different question from the one asked here, and the honest answer "
            "is that a rollback alone does not revert it: restoring "
            "SYSCTL_HARDENER_CONF's row deletes the file, and the `sysctl "
            "--system` the plugin's rollback runs then reloads the files that "
            "remain, none of which mentions the parameter, so the value stands "
            "until the host reboots",
        ),
    ),
    ("kernel/mod.rs", "write_file(hardener_sysctl_path"): (
        ("ensured", "SYSCTL_DROPIN_DIR"),
        # The binding rather than SYSCTL_HARDENER_CONF, because the binding is
        # what the path list holds. It is the weakest of the five tokens for
        # that reason: it is the same name on both sides of the question, so it
        # would survive being pointed at another path. What it does catch, which
        # is the failure this column exists for, is the declaration going away.
        ("declared", ("hardener_sysctl_path",)),
    ),
    ("ssh/dropin.rs", "write_file(Path::new(DROPIN_PATH)"): (
        ("ensured", "DROPIN_DIR"),
        # Declared by ssh/mod.rs rather than by the file holding the write,
        # which is why the search is per plugin directory.
        ("declared", ("dropin::DROPIN_PATH",)),
    ),
    ("firewall/nftables.rs", "write_file(Path::new(NFTABLES_CHECK_PATH)"): (
        (
            "exempt",
            "/run is created by the kernel before any unit starts and is "
            "present on every host this runs on, so there is no parent for "
            "the plugin to ensure",
        ),
        # Deliberately NOT checkpointed, and deliberately not in /etc. This is
        # a scratch copy of the candidate ruleset, written only so that
        # `nft --check` can judge it before the boot path is touched, and
        # removed again in the same function whichever way the check went. It
        # is on tmpfs, so anything an interrupted apply leaves behind is gone at
        # the next boot, and it is root-owned, so nobody unprivileged can swap
        # the file between the write and the check. No state of ours outlives a
        # rollback here: the file the rollback restores is the probed boot
        # path, and this scratch path is never loaded, never read back, and
        # never referenced by the unit.
        (
            "exempt",
            "a scratch file removed by the same function that writes it, so no "
            "state of ours outlives a rollback that never removes this file",
        ),
    ),
    ("firewall/nftables.rs", "write_file(path"): (
        # The write inside `ensure_include_line`, appending the include line
        # to whatever file `boot_ruleset` named. Its parent is almost always
        # there already, being the distribution's own /etc or /etc/sysconfig;
        # the one host where it is not, openSUSE's /etc/nftables/rules, is
        # created immediately above this call, in `apply_rules`'s own
        # `mkdir -p` loop over `[HARDENER_RULESET_DIR,
        # parent_of(&boot_path)]`. That loop runs through `execute_command`
        # rather than `crate::ensure_directory` because one call site has to
        # cover both directories it is responsible for.
        (
            "exempt",
            "the parent is created immediately above this call by "
            "apply_rules's own `mkdir -p` loop over "
            "[HARDENER_RULESET_DIR, parent_of(&boot_path)], run through "
            "execute_command rather than crate::ensure_directory because "
            "one loop covers both directories the apply has to create",
        ),
        # `boot_path` is the same binding name `checkpoint_paths` returns in
        # its own `Ok` arm, both read from the same `boot_ruleset` probe, so a
        # capture taken before this write records whatever stood at that path
        # beforehand and a rollback restores it, which removes the appended
        # include line along with anything else this write touched. A host
        # whose boot path could not be probed never reaches this call at all:
        # `apply_rules` returns before writing anything once `boot_ruleset`
        # answers `Err`.
        ("declared", ("boot_path",)),
    ),
    ("firewall/nftables.rs", "write_file(Path::new(HARDENER_RULESET_PATH)"): (
        # The write in `apply_rules` that lands the whole rendered ruleset in
        # this plugin's own fragment. Same loop, same reasoning as the site
        # above: HARDENER_RULESET_DIR is the other directory `mkdir -p`
        # covers in that one call site.
        (
            "exempt",
            "HARDENER_RULESET_DIR is created immediately above this call by "
            "the same mkdir -p loop that also covers the boot path's parent, "
            "run through execute_command rather than crate::ensure_directory "
            "because one loop covers both directories",
        ),
        # Declared by this backend's own `checkpoint_paths`, which the
        # firewall apply hands straight to `create_checkpoint_for_apply` once
        # it knows which backend it selected. Nothing but this plugin ever
        # writes HARDENER_RULESET_PATH, so a checkpoint recording it absent on
        # a first apply and a rollback removing it afterwards is always the
        # right answer, unlike the probed boot path beside it, which a
        # distribution's own package can also own.
        ("declared", ("HARDENER_RULESET_PATH",)),
    ),
    ("audit/mod.rs", "write_file(Path::new(AUDIT_RULES_PATH)"): (
        ("ensured", "AUDIT_RULES_DIR"),
        # AUDIT_RULES_DIR is declared too and is captured recursively, which
        # holds this file only on the runs where it already exists. The first
        # apply on a host is the one that creates it, and that is the run whose
        # rollback has to remove it, so the directory is not the answer and the
        # path has to be named in its own right.
        ("declared", ("AUDIT_RULES_PATH",)),
    ),
    ("audit/mod.rs", 'execute_command("cp"'): (
        (
            "exempt",
            BACKUP_BESIDE_SOURCE.format("AUDIT_RULES_PATH")
            + "; it also sits under the AUDIT_RULES_DIR ensure that guards the "
            "write below it",
        ),
        (
            "exempt",
            BACKUP_SURVIVES_ROLLBACK.format(
                "nothing reads it: augenrules(8) merges only the files in "
                "/etc/audit/rules.d ending in .rules and says outright that it "
                "ignores all the others, and this one ends in "
                ".backup.<timestamp>.<nonce>"
            ),
        ),
    ),
    ("pam/mod.rs", "write_file(Path::new(path)"): (
        ("ensured", "dir"),
        # One site, four possible destinations: pwquality.conf and login.defs,
        # which this plugin rewrites, and the two `SecurityConf` paths,
        # faillock.conf and pwhistory.conf, which it will create on a host that
        # has neither. All four are named to the checkpoint and all four are
        # checked, because a site declaring three of its four paths is
        # undeclared on the fourth, and the fourth is the one a rollback would
        # leave behind. /etc/pam.d is declared beside them and is not part of
        # this answer: the plugin refuses to write the PAM stack at all.
        (
            "declared",
            (
                '"/etc/security/pwquality.conf"',
                '"/etc/login.defs"',
                '"/etc/security/faillock.conf"',
                '"/etc/security/pwhistory.conf"',
            ),
        ),
    ),
    ("pam/mod.rs", 'execute_command("cp"'): (
        (
            "exempt",
            BACKUP_BESIDE_SOURCE.format("the file being backed up"),
        ),
        (
            "exempt",
            BACKUP_SURVIVES_ROLLBACK.format(
                "nothing reads it: the PAM modules open /etc/security/*.conf "
                "and /etc/login.defs by exact name, so a suffixed copy lying "
                "beside one is read by no module and shadows nothing"
            ),
        ),
    ),
    ("ssh/mod.rs", "write_file(&temp_path"): (
        (
            "exempt",
            "/tmp/linux-hardener-sshd-validate-<pid>.conf: scratch copy for "
            "`sshd -t`, and /tmp is mounted by the system on every host this "
            "runs on",
        ),
        (
            "exempt",
            "nothing of it survives the apply to declare: "
            "`validate_sshd_config` removes the scratch file on every path out "
            "of itself, the rejecting ones included, so a rollback would find "
            "nothing there to remove. The removal is best-effort, so a `rm` "
            "that fails leaves a copy of a candidate config in /tmp, which is "
            "warned about and which a declared path would not have helped "
            "with either: the checkpoint is captured before the file exists "
            "and /tmp is outside the rollback allowlist in any case",
        ),
    ),
    ("ssh/mod.rs", "write_file(Path::new(config_path)"): (
        (
            "exempt",
            "sshd_config itself, whose content was read into `main` above; the "
            "absent and unreadable arms both return early, so reaching the "
            "write proves the file and therefore its directory exist",
        ),
        # The same binding is declared and written, so whichever layer's config
        # this run resolved to is the one the capture holds.
        ("declared", ("config_path",)),
    ),
    ("ssh/mod.rs", 'execute_command("cp"'): (
        (
            "exempt",
            BACKUP_BESIDE_SOURCE.format("config_path"),
        ),
        (
            "exempt",
            BACKUP_SURVIVES_ROLLBACK.format(
                "nothing reads it: sshd reads sshd_config and "
                "sshd_config.d/*.conf, and the copy is neither, because it "
                "lands beside the main file rather than in the drop-in "
                "directory"
            ),
        ),
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


def span(text: str, start: int, terminators: str) -> str:
    """`text` from `start` up to the first terminator outside any bracket.

    Scans by bracket depth over the whole file rather than by line, so a
    construct split across lines yields the same result as one written on a
    single line. A string literal containing a bracket or a terminator would
    fool it; none of the constructs read here contains one. Returns "" when no
    terminator is reached, which is the honest answer for text that does not
    close: better an empty read that fails a lookup than a plausible one taken
    from a file that ends mid-statement.
    """
    depth = 0
    for i in range(start, len(text)):
        char = text[i]
        if depth == 0 and char in terminators:
            return text[start:i].strip()
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
    return ""


def first_argument(text: str, open_paren: int) -> str:
    """The first argument of the call whose '(' sits at `open_paren`."""
    return span(text, open_paren + 1, ",)")


def checkpoint_declarations(text: str) -> str:
    """Every checkpoint path declaration in `text`, run together.

    The result is searched for the tokens a `declared` entry names, so it is
    kept to the two constructs that actually declare paths rather than taken
    from the file at large. That distinction is the whole value of the check:
    AUDIT_RULES_PATH is written thirteen times in audit/mod.rs and was written
    there throughout the window in which it was undeclared, so a check that
    searched the file would have passed over the live defect it exists to
    catch. Measured, not assumed: the same file with its declaration taken back
    out is what this was run against, and it reported the site.
    """
    regions = [
        span(text, match.end(), ")") for match in CHECKPOINT_CALL.finditer(text)
    ]
    regions += [
        span(text, match.end(), ";") for match in CHECKPOINT_PATH_LIST.finditer(text)
    ]
    regions += [
        span(text, match.end(), "}") for match in CHECKPOINT_PATHS_FN.finditer(text)
    ]
    return "\n".join(regions)


def well_formed(answers) -> bool:
    """Whether a registry value answers both questions in the shape read below.

    Cheap and structural on purpose. It cannot tell a considered reason from a
    plausible sentence, and nothing here can; what it can do is stop an entry
    that answers only the older question from reaching an unpacking that would
    raise, which is how the missing answer would otherwise be reported.
    """
    if not isinstance(answers, tuple) or len(answers) != 2:
        return False
    # Checked rather than assumed, because the entry this exists to catch is the
    # one written in the older single-answer shape, whose two elements are a
    # kind and a sentence and whose unpacking would raise here.
    if not all(isinstance(answer, tuple) and len(answer) == 2 for answer in answers):
        return False
    (parent_kind, parent_reason), (rollback_kind, rollback_detail) = answers
    if parent_kind not in ("ensured", "exempt") or not isinstance(parent_reason, str):
        return False
    if rollback_kind == "declared":
        return bool(rollback_detail) and all(
            isinstance(token, str) and token for token in rollback_detail
        )
    return rollback_kind == "exempt" and isinstance(rollback_detail, str)


def sites_in(path: Path, relative: str) -> list[tuple[str, str, int, str, str]]:
    """Every file-creating call site as (relative, key, line, program, args).

    `program` is the literal argv[0] for an `execute_command` site and "" for a
    `write_file` one; `args` is the call's whole argument text, read by the same
    bracket-depth scan that reads the first argument, so a call split across
    lines yields what one written on a single line would. Both are carried
    because the flag assertion needs to see the arguments of a `cp` and the two
    registry columns need only the key.
    """
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
        arguments = span(text, match.end(), ")")
        found.append((relative, f"{method}({argument}", line, literal or "", arguments))
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

    # One declaration text per plugin directory, because a checkpoint belongs to
    # a plugin rather than to a file: ssh/dropin.rs writes the fragment that
    # ssh/mod.rs declares. Keyed on the first path component, which is the
    # plugin directory for every source that holds a site.
    declared_in_plugin = {}
    for relative, text in contents.items():
        plugin = relative.split("/")[0] if "/" in relative else ""
        declared_in_plugin.setdefault(plugin, []).append(checkpoint_declarations(text))
    declarations = {
        plugin: "\n".join(regions) for plugin, regions in declared_in_plugin.items()
    }

    unregistered = [s for s in sites if (s[0], s[1]) not in REGISTRY]
    seen = {(s[0], s[1]) for s in sites}
    stale = [key for key in REGISTRY if key not in seen]

    # An entry that does not answer both questions in the shape the checks below
    # read. Found before either is read, and the readable entries are the ones
    # the checks then run on, because unpacking a half-written entry raises
    # rather than reports and a validator whose own failure mode is a stack
    # trace teaches people to rerun it rather than to read it.
    malformed = [key for key, answers in REGISTRY.items() if not well_formed(answers)]
    readable = {
        key: answers for key, answers in REGISTRY.items() if well_formed(answers)
    }

    # An `ensured` entry names the directory its ensure passes rather than a
    # line number, so the citation cannot rot as the file grows. This confirms
    # the call is still there; it cannot confirm it runs before the write.
    missing_ensure = [
        (relative, key, reason)
        for (relative, key), ((kind, reason), _) in readable.items()
        if kind == "ensured"
        and f"ensure_directory(ctx, {reason})" not in contents.get(relative, "")
    ]

    # A `declared` entry names the tokens that have to appear in one of its
    # plugin's checkpoint declarations. Every token is looked for, and one
    # missing is enough: a site landing on four paths of which three are
    # declared is undeclared on the fourth, and it is the fourth whose file
    # outlives the rollback.
    undeclared = [
        (relative, key, token)
        for (relative, key), (_, (kind, tokens)) in readable.items()
        if kind == "declared"
        for token in tokens
        if token not in declarations.get(relative.split("/")[0], "")
    ]

    # The third question, and the only one asked of the code rather than of the
    # registry. A site is reported once per flag it is missing, because the two
    # flags fail differently and telling someone only about the first would send
    # them back for the second.
    flagless = [
        (relative, key, line, flag)
        for relative, key, line, program, arguments in sites
        if program == "cp"
        for flag in BACKUP_CP_FLAGS
        if f'"{flag}"' not in arguments
    ]

    print(f"Scanned {GREEN}{len(sources)}{NC} plugin source files")
    print(f"Found {GREEN}{len(sites)}{NC} file-creating call site(s)\n")

    problems = False

    if unregistered:
        problems = True
        print(f"{RED}{len(unregistered)} call site(s) with no registry entry:{NC}\n")
        for relative, key, line, _, _ in unregistered:
            print(f"  {RED}{PLUGIN_SRC}/{relative}:{line}{NC}")
            print(f"    {key}...) creates a file and nothing says why its")
            print("    parent directory exists, nor whether a rollback reaches")
            print("    what it creates")
            print("    decide both, then add the entry to REGISTRY in")
            print(f"    {Path(__file__).name}, as a pair of pairs:")
            print('      parent:   "ensured", naming the directory passed to')
            print("        crate::ensure_directory above this write, or")
            print('        "exempt", saying what guarantees the parent instead')
            print('      rollback: "declared", naming the token(s) this')
            print("        plugin's checkpoint path list has to contain, or")
            print('        "exempt", saying why no state of ours outlives a')
            print("        rollback that never removes this file\n")

    if stale:
        problems = True
        print(f"{RED}{len(stale)} registry entry(ies) with no call site:{NC}\n")
        for relative, key in stale:
            print(f"  {RED}{PLUGIN_SRC}/{relative}{NC}")
            print(f"    the registry classifies {key}...) but no such call")
            print("    site is there any more")
            print("    remove the entry: a registry describing code that has")
            print("    gone is how one drifts into fiction\n")

    if malformed:
        problems = True
        print(f"{RED}{len(malformed)} registry entry(ies) missing an answer:{NC}\n")
        for relative, key in malformed:
            print(f"  {RED}{PLUGIN_SRC}/{relative}{NC}")
            print(f"    the entry for {key}...) is not a pair of pairs")
            print("    every site answers two questions now: why its parent")
            print("    directory exists, and whether the path it creates is")
            print("    declared to this plugin's pre-apply checkpoint. Write")
            print('    the second answer as ("declared", ("TOKEN",)) or as')
            print('    ("exempt", "why nothing has to declare it")\n')

    if missing_ensure:
        problems = True
        print(f"{RED}{len(missing_ensure)} ensured site(s) whose ensure is gone:{NC}\n")
        for relative, key, reason in missing_ensure:
            print(f"  {RED}{PLUGIN_SRC}/{relative}{NC}")
            print(f"    {key}...) is registered as ensured by {reason}, but")
            print(f"    the file contains no ensure_directory(ctx, {reason})")
            print("    restore the ensure, or reclassify the site\n")

    if undeclared:
        problems = True
        print(f"{RED}{len(undeclared)} declared path(s) no checkpoint names:{NC}\n")
        for relative, key, token in undeclared:
            plugin = relative.split("/")[0]
            print(f"  {RED}{PLUGIN_SRC}/{relative}{NC}")
            print(f"    {key}...) is registered as declared")
            print(f"    by {token}, but no checkpoint path list under")
            print(f"    {PLUGIN_SRC}/{plugin} names it, so a capture taken")
            print("    before this write holds no row for the path, and a")
            print("    rollback of this apply leaves the file behind")
            print("    declare it in the paths this plugin's")
            print("    create_checkpoint_for_apply is given, above the write,")
            print("    or reclassify the site and say why nothing of ours")
            print("    outlives the rollback\n")

    if flagless:
        problems = True
        print(f"{RED}{len(flagless)} backup copy(ies) missing a cp flag:{NC}\n")
        for relative, key, line, flag in flagless:
            print(f"  {RED}{PLUGIN_SRC}/{relative}:{line}{NC}")
            print(f"    {key}...) copies a file without {flag}")
            if flag == "-p":
                print("    without it the copy carries none of the source's")
                print("    mode, ownership or timestamps, so restoring it hands")
                print("    the operator the file at whatever the umask gives")
            else:
                print("    without it the copy follows a symlink and records")
                print("    the target, so a config that is a link is backed up")
                print("    as some other file and the one about to be")
                print("    overwritten has no backup at all")
            print("    pass both flags, in the order -p --no-dereference,")
            print("    before the source and destination\n")

    # `sites`, not `seen`: a new call site that reuses an already-registered
    # key raises this count without raising the distinct-pattern one below,
    # since its (file, key) pair is already in REGISTRY and it is therefore
    # neither `unregistered` nor able to move `len(seen)`. This is the only
    # check in the file that would refuse such a site.
    if len(sites) != EXPECTED_RAW_SITE_COUNT:
        problems = True
        print(f"{RED}Raw site count is {len(sites)}, expected {EXPECTED_RAW_SITE_COUNT}{NC}")
        print("  This count is every matched call before folding into (file,")
        print("  key) patterns, pinned separately from the distinct-pattern")
        print("  count below because a new site landing under an already")
        print("  registered key would move this total and not that one.")
        print("  Change EXPECTED_RAW_SITE_COUNT once the new or removed site")
        print("  is accounted for, and say in the commit whether it is a")
        print("  genuinely new pattern or a deliberately shared key.\n")

    # `seen`, not `sites`: two real call sites sharing one (file, key)
    # pattern, as the two writes to NFTABLES_CHECK_PATH now do, are one
    # pattern and register once, so the pin counts distinct patterns rather
    # than raw matches.
    if len(seen) != EXPECTED_SITE_COUNT:
        problems = True
        print(f"{RED}Site count is {len(seen)}, expected {EXPECTED_SITE_COUNT}{NC}")
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

    ensured = sum(1 for (kind, _), _ in REGISTRY.values() if kind == "ensured")
    declared = sum(1 for _, (kind, _) in REGISTRY.values() if kind == "declared")
    copies = sum(1 for _, _, _, program, _ in sites if program == "cp")
    print(
        f"{GREEN}All {len(sites)} file-creating call sites are classified{NC} "
        f"on both questions"
    )
    print(
        f"  parent directory: {ensured} ensured, {len(REGISTRY) - ensured} exempt"
    )
    print(
        f"  rollback:         {declared} declared, "
        f"{len(REGISTRY) - declared} exempt"
    )
    print(
        f"  backup flags:     {copies} cp site(s), all passing "
        f"{' and '.join(BACKUP_CP_FLAGS)}"
    )
    print(
        f"{YELLOW}This proves no site is unclassified. It does not prove any"
        f" ensure is correct, nor that any declaration reaches the right path"
        f" or runs before the write.{NC}"
    )
    print(
        f"{YELLOW}The flag assertion reads only calls whose argv[0] is the"
        f" literal \"cp\": a copy made through a variable, a shell, or any"
        f" other program is not held to it.{NC}"
    )
    print(
        f"{YELLOW}It does not see the `systemctl mask` link at all: that file"
        f" is created through execute_command(\"systemctl\", ...), which this"
        f" cannot admit without admitting every start, stop and daemon-reload"
        f" beside it.{NC}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
