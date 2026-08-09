# What This Release Does Not Prove

**Last Updated**: 2026-08-08

This release does not claim to be proven bug-free, and no release of anything
ever has been. It claims something narrower and checkable: every capability it
advertises carries named evidence, and every claim it cannot make is written
down and shipped. [The evidence ledger](evidence-ledger.md) is the first half of
that sentence. This document is the second.

It is written for an operator deciding whether to run this on a host that
matters, and it is organised as the questions such a person actually asks rather
than as a list of internal test-harness limitations. Nothing here is a bug
report: defects already known to affect a shipped release are in
[SECURITY.md](../../SECURITY.md) and [CHANGELOG.md](../../CHANGELOG.md), and open
ones are GitHub issues. What follows is the less commonly published thing, namely
**the places where this tool may well be correct and nothing has ever checked.**

Every figure below was measured rather than remembered, and the two documents it
draws on say how. [The evidence ledger](evidence-ledger.md) records what each
capability's tests actually ask, and grades them: a mock, a real filesystem, or a
live oracle that puts the question to the setting's own consumer.
[The coverage baseline](coverage-baseline.md) records what no test reaches at
all, and warns in its own words that its list is a lower bound, because coverage
cannot see dead code that its own tests cover.

---

## Contents

- [If it breaks my host, can I get it back?](#if-it-breaks-my-host-can-i-get-it-back)
- [When it says it changed something, did it?](#when-it-says-it-changed-something-did-it)
- [Will it behave the same on my distribution, my hardware and my kernel?](#will-it-behave-the-same-on-my-distribution-my-hardware-and-my-kernel)
- [Can I point it at a fleet over SSH and believe what comes back?](#can-i-point-it-at-a-fleet-over-ssh-and-believe-what-comes-back)
- [Can I hand the compliance report to an auditor?](#can-i-hand-the-compliance-report-to-an-auditor)
- [Does any of this cover the desktop application?](#does-any-of-this-cover-the-desktop-application)
- [What runs automatically, and what needed a person?](#what-runs-automatically-and-what-needed-a-person)
- [What happens when I upgrade from the version I am on?](#what-happens-when-i-upgrade-from-the-version-i-am-on)
- [Keeping this document true](#keeping-this-document-true)

---

## If it breaks my host, can I get it back?

Usually, and here is the boundary of that word.

**A checkpoint stores text.** Restore writes captured content back through
`String::from_utf8_lossy`, so a configuration file holding non-UTF-8 bytes
cannot round-trip, and no test asserts that it can. If a path this tool touches
on your host is not text, its restore is unproven.

**Seven of the eight plugins have a rollback reading written against a real
system, and the kernel's is the one to read the small print on.**
`scripts/test/verify-rollback.sh` re-reads kernel sysctl values, `sshd_config`
content and directory modes after a rollback. Section 12A of
`scripts/test/full-test-suite.sh` requires that the audit rules file the apply
wrote is gone, that the whole `/etc/audit` tree diffs identical to its pre-apply
state, and that the compiled rule count came back. Section 12B does the same for
the `systemctl mask` symlink the services plugin leaves. The differential suite
puts an ssh rollback and reload cycle back through `sshd -T`. The same script's
TEST 6 seeds `PASS_MAX_DAYS` in `/etc/login.defs` to shadow's own default of
99999, which the pam plugin's `AtMost 90` makes a genuine violation, and asserts
that the apply lowers it, that the rollback returns it, and that the file comes
back byte for byte. TEST 7 does the same for the firewall, against whichever
backend the plugin selects rather than an assumed one, and asks both the
backend's own configuration and **what the host is actually enforcing**.

**The mac plugin now has one reading, and it is the inverse of every other one
here.** Measured on the development host 2026-08-09, `/sys/kernel/security/lsm`
reads `capability,landlock,lockdown,yama,bpf`: this kernel carries neither
SELinux nor AppArmor, and a container shares the host's kernel. So the
differential suite asks the only question that exists on this machine, which is
whether the apply leaves `/etc/selinux`, `/etc/apparmor` and `/etc/apparmor.d`
exactly as it found them on a host with no MAC system to configure. The oracle
is the kernel's own LSM registry read beside a content, mode and size digest of
that tree, and the registry is a different source from the two securityfs paths
the plugin probes, which is what keeps it from being an echo of the tool.

What that catches is a plugin writing an SELinux configuration onto a host that
has no SELinux. It catches nothing else, and in particular it says nothing
whatever about enforcement.

**Reading mac enforcement back still needs a virtual machine, which is issue
#18.** Loading an LSM policy is host-global, so a container cannot be given the
question: this is not a missing nspawn flag, the way the kernel arm's private
network namespace turned out to be. Where the LSM registry does name a MAC
system, the suite declares these rows unaskable rather than passing them,
because a no-op oracle asserted against a host the plugin is supposed to act on
would be asserting the opposite of the requirement. It does the same where the registry cannot be read
at all.

**No container mounts securityfs, measured on all six booted fixtures
2026-08-09**, which is the same thing the arch container showed under `--pipe`
on 2026-08-08: no AppArmor or SELinux tooling, no `/sys/kernel/security/lsm`, no
securityfs. The first container run of this oracle therefore asked nothing and
declared every row unaskable, correctly and uselessly. So the runner reads the
host's registry and declares it into the container the way it already declares
`HARDENER_DIFF_BOOTED` and `HARDENER_DIFF_NETNS`. The container shares that
kernel, so it is the same fact rather than a second one, and the log names which
source answered. The cost is real and is stated here rather than hidden: this
row now depends on the runner declaring the truth, where before it depended only
on the kernel.

**The kernel reading in that script can now fail, and its runtime half is asked
only where a container permits the question.** Both halves used to be
unfalsifiable. The file half recorded an apply that wrote no
`/etc/sysctl.d/99-hardener.conf` as information rather than as a failure, so the
removal assertion could pass over a file that was never written; it now fails
that run at the apply, and separately requires the written file to name the
parameter under test. The runtime half read `kernel.kptr_restrict` and
`kernel.dmesg_restrict` before the apply and again after the rollback and
asserted them equal, which no apply inside a container can move, so it compared
a constant with itself. The probe is now `net.ipv4.conf.all.log_martians`,
seeded below the plugin's target before the apply and read back after the
rollback, with the seed itself asserted so that a seed which did not take fails
rather than quietly restoring the old vacuity.

**That stronger reading has now been taken, on 2026-08-08.** A rolled-back
kernel runtime value has been read off a real system:
`net.ipv4.conf.all.log_martians` seeded to 0, raised to 1 by the apply and read
back at 0 after the rollback, all three asserted. 18 checks, none skipped, none
failing.

It took a one-flag change to get there, and the flag was withheld by a wrong
belief rather than by a limitation. `/proc/sys` inside an nspawn container is
the host's and read-only outside `/proc/sys/net`, and even `/proc/sys/net` is
writable only for a container holding its own network namespace. The one runner
that calls this script did not give it one, so the arm recorded a named skip on
every run and the capability existed without ever being exercised: issue #131.
The runner now passes `--private-network`, **measured** to be sufficient under
`--pipe`, `--boot` not being required despite a code comment and three
documents saying it was. Where the namespace is absent the arm still skips
rather than passing, and the script now exits 2 rather than 0 so that a skip
cannot be reported as a reading.

The seven `kernel.` and `fs.` parameters
`scripts/test/differential-suite.sh` declares permanently unaskable stay
unaskable here: `/proc/sys` outside `/proc/sys/net` is the host's and read-only
whatever the namespace. **So the confirmed reading covers one `net.ipv4`
parameter, and is one parameter rather than a class.**

**None of those readings runs unless a person starts a container.**
`scripts/test/verify-rollback.sh` is invoked by no CI job, and by exactly one
runner, `scripts/test/release-readiness-root.sh`, a root-only batch that was
first run on 2026-08-07. Its rollback suite passed that day, 11 checks with none
failing, reading the kernel config file, ssh and permissions back after a
rollback, with the runtime kernel arm skipped. It was run again on 2026-08-08
with `--private-network`, and passed 18 checks with none skipped: three new ones
for the runtime arm that issue #131 was filed about, and four more for the pam
readback added the same day. A third run the same day added the firewall arm and
passed 21. A fourth added TEST 8 and passed 23, and a fifth added TEST 9 and
passed 26; both are described below. **Five dated runs rather than a habit**,
at 11, 18, 21, 23 and 26 checks: nothing runs this without a person.

**A rollback can now say what it left diverged, and that capability is itself
unproven by a container run.** Two of the eight plugins, kernel and firewall,
ask their own subsystem after the reload whether the running host still
disagrees with what was restored: a managed sysctl that no surviving file
names, and a `ufw` still enforcing over a restored `/etc/ufw/ufw.conf` that says
`ENABLED=no`, or the reverse. `RollbackResult.rollback_divergences` carries one
row per subject a probe examined, and distinguishes a measured disagreement
(`Diverged`) from a probe that could not answer at all (`Unverifiable`), so an
empty vector means everything checkable came back rather than that nobody
looked. The CLI, the GUI rollback modal and the fleet summary all render it,
the fleet summary as two separate counts. **This is reporting, not
reconciliation.** No rollback behaviour, exit code or `rollback_success` value
changed to add it: nothing is restarted, stopped or re-enabled because of what
the probe found. **The other six plugins are asked nothing**, because no probe
has been written for them, not because nothing there could diverge.
`scripts/test/verify-rollback.sh` gained an eighth arm, TEST 8, which removes
TEST 1's own baseline-drop-in workaround so that a surviving file does not name
the seeded parameter, then requires the rollback's own JSON to carry it as
`Diverged`. **It was read green on 2026-08-08, 23 of 23 with none skipped**, on
the arch container, against a musl binary the pre-flight verified against the
working tree. That run is the first time a rollback's own report of what it
left behind has been read off a real system.

A ninth arm, TEST 9, followed on the same day for #140: it names a managed
parameter in `/etc/sysctl.conf` with no drop-in surviving, and requires the row
to come back `Diverged` saying that the rollback's own `sysctl --system` reads
that file while the boot applier does not. It asks three questions rather than
one, so **the suite is now nine tests and 26 checks, read green on the arch
container on 2026-08-08 at 26 of 26 with none failed and none skipped.** The row
it read was `net.ipv4.conf.all.log_martians`, reported `Diverged`.

The 26-of-26 run measured what the kernel probe actually says, which no reasoning
had settled: **15 rows, 12 of them `Diverged` and 3 `Unverifiable`.** The
23-of-23 run had read the same three figures before the `/etc/sysctl.conf` work,
so that work moved no row in this breakdown; the reading quoted here is the one
taken against the post-change binary. The 12 are
not noise. An apply writes one drop-in naming every parameter it moves and the
rollback deletes it, so those 12 parameters really are still hardened in the
running kernel with no surviving file naming them, and every one of them is an
instance of the defect this reporting exists to surface. The 3 are the glob
source row for `/usr/lib/sysctl.d/50-default.conf` and the two managed keys its
patterns could name, `net.ipv4.conf.all.rp_filter` and
`net.ipv4.conf.all.accept_source_route`. That is the narrowing working: the
same file's patterns block those two parameters and leave the other seventeen
attributable, where an earlier draft let one glob anywhere make every parameter
on every systemd host unverifiable.

That container must be a fresh one, and the runner rebuilds it for exactly that
reason. Run by hand against a container an earlier run has finished with, the
suite reports three failures that are all one artefact: the pre-apply state it
records is the previous run's post-apply state, so the config file it "restores"
is already the hardened one, sshd is already compliant and leaves no checkpoint,
and the checkpoint count is then short. Measured 2026-08-08, and none of the
three was a defect.
Sections 12A and 12B need `scripts/test/full-test-suite.sh` started as root
inside a container with its `--apply` flag; 12B additionally needs that
container booted under systemd, and 12A needs a container no earlier `--apply`
run has touched, or it reports its own reading void rather than passing it.

**On a remote host without root, a restore degrades to content only.** The
content write goes through `sudo tee`, but the `chmod`, `chown` and `rm` that
follow it do not, so modes and ownership can fail to come back while the bytes
succeed. Account databases are captured metadata-only by design, which is a
deliberate choice rather than an oversight, and the distinct `ContentAbsence`
discriminant keeps that apart from a read that failed.

What is proven, and is worth stating beside the above: a rollback takes its own
checkpoint before it writes anything, so the undo is itself reversible, and a
rollback aimed at a checkpoint belonging to another host is refused outright by
comparing the stored host key.

---

## When it says it changed something, did it?

For seven plugins of eight there is an answer that does not come from this tool.
For the eighth, mac, the only answer available on this machine is that it
changed nothing, which is what that host requires of it.

A **live oracle** is the only grade of evidence that can catch a reader and a
writer which agree with each other and disagree with Linux, because it asks the
setting's real consumer: `sshd -T`, `sysctl`, `chage`, `nft list ruleset`,
`systemctl is-enabled`, `stat`. It lives in `scripts/test/differential-suite.sh`
and `scripts/test/full-test-suite.sh`, and both run only inside an nspawn
container, as root, by hand.

| Plugin | Is there an oracle that reads the system back? |
|---|---|
| `ssh-hardening` | Yes. `sshd -T` answers for it, which this project's parser cannot satisfy by agreeing with this project's writer. The best-evidenced plugin in the tree, with one thing about it that no test pins: the crypto allow-lists are intersected with `ssh -Q` at runtime, so which ciphers, key exchanges and MACs your host ends up offering follows its own OpenSSH build and is fixed by nothing here. |
| `permissions-hardening` | Yes, for modes. `stat` is asked about nine paths. Ownership and ACLs are read back by nothing. |
| `firewall-hardening` | Yes, for nftables only. Three rows against `nft list ruleset` in the fixture container from `scripts/containers/nftables-fixture.sh`. The firewalld and ufw backends have mock evidence only. |
| `pam-hardening` | Partly. `chage` and `passwd -S` answer for password ageing, and libpwquality's own `pwscore` answers for password strength. **No probe password ever reaches the live PAM stack**, so the path from a real authentication attempt through PAM to a refusal is tested nowhere. The apply is also narrower than the name suggests: it writes `/etc/security/*.conf` and `/etc/login.defs`, and it refuses by design to edit `/etc/pam.d/*`, because a malformed edit to the authentication stack can lock every user out. Where a directive is set inline in that stack it overrides the file the apply may write, so the plugin reports the manual edit you must make and marks the run unsuccessful rather than making it for you. |
| `kernel-hardening` | Only in a container holding its own network namespace, and only for 11 of the 18 parameters the plugin manages. A boot is not part of the requirement: this cell said "a booted container" until 2026-08-09, and `--private-network` under `--pipe` was measured sufficient (#137). |
| `service-minimisation` | Only in a booted container, because `systemctl` needs systemd as PID 1. |
| `audit-hardening` | **No.** See below. |
| `mac-hardening` | **Only for what it must not do.** The kernel's LSM registry says this host has no MAC system, and the suite reads the configuration tree back to prove the apply left it alone. Nothing here reads enforcement. See below. |

**The kernel plugin's ceiling is a property of containers, not of the tests.**
Under `systemd-nspawn`, `/proc/sys` is the host's and mounted read-only, so a
container cannot show the plugin writing a value: a write is refused with
`sysctl: permission denied on key "kernel.kptr_restrict"`. Only `/proc/sys/net`
is remounted read-write, and only for a container holding its own network
namespace, which is why the 11 askable parameters are all `net.ipv4`. The other
seven, covering ASLR, kernel pointer restriction, dmesg restriction, ptrace
scope and the three `fs.` protections, are declared permanently unaskable in the
suite itself and are proven by no live reading anywhere.

**`audit-hardening`'s scan is mock-only and its apply is judged on the
filesystem.** The plugin does ask `auditctl`, at `-l` for the loaded rules and
`-s` for the subsystem's status
(`crates/hardener-plugins/src/audit/mod.rs`), but nothing in this tree ever asks
a real one: every test that reaches those calls hands them a programmed answer
through `MockExecutor`, and no shell script in `scripts/` runs `auditctl` or
`augenrules` at all. So every claim about what this plugin *reports* is the
plugin agreeing with a fixture it was handed. Its apply is better placed, and the common
shorthand that it has no differential evidence is too strong: section 12A of
`scripts/test/full-test-suite.sh` runs the apply on a real host and then reads
`/etc/audit` back, as described in the previous section. What is absent is an
oracle that asks the audit subsystem's own state, so nothing anywhere compares
what the plugin reported against what auditd actually holds. In a container the
apply also fails by design, because there is no auditd for `augenrules --load`
and `systemctl restart auditd` to reach, which is why that section judges the
filesystem and not the exit status.

**`mac-hardening` has an oracle for its no-op case only, and the safety point
below is unchanged by it.** The differential suite proves the apply writes
nothing where the kernel carries no MAC system. Nothing proves what it does
where one exists, which is the whole of its enforcing behaviour. Live
runs of this plugin do exist, and `getenforce` and `aa-status` are reached
through the real executor on any host carrying them, but every one of those runs
judges an exit status, a plugin id or a non-zero duration. None holds what those
tools answer against what the plugin reported, and outside
`crates/hardener-plugins/tests/mac_mock_tests.rs` nothing decides which of the
two systems is present except the host itself. The safety point is this. Section
14 of `scripts/test/full-test-suite.sh` deliberately skips the audit and mac
per-plugin applies inside a container, on the stated grounds that there is no
SELinux or AppArmor there. Section 15 then runs `apply --all`, which carries no
container guard, and `crates/hardener-cli/src/commands/apply.rs` selects **every
registered plugin** under `--all`, all eight of which are registered
unconditionally in `crates/hardener-plugins/src/lib.rs`. So the two applies
section 14 calls unsafe run anyway, one section later, and section 15 now says
so rather than leaving it to be inferred: its check reads the apply's own JSON
result document and fails a run in which any of the eight plugins left no
result, which is what would catch `--all` quietly ceasing to select one. Reading
the tool's account of itself is the whole of what it can do, and no check
anywhere reads the host back after that apply. **If you run
`hardener apply --all`, MAC hardening is included**, on a plugin whose live
behaviour no reading has ever confirmed. `disabled_plugins = ["mac-hardening"]`
in the configuration is how you decline it.

**Extending the oracle to the remaining plugins is tracked as
[issue #47](https://github.com/tidynest/linux-hardener/issues/47).** Read it for
its reasoning about what each plugin's oracle would need, which is still
accurate. Do not read its counts: its body predates the current suite and says
two plugins are covered, where the compared set is now seven under `--pipe` and
eight in a booted run.

---

## Will it behave the same on my distribution, my hardware and my kernel?

**Six distributions have been run end to end, across four families.** They are
Arch rolling, Debian 13 "Trixie", Ubuntu 24.04 LTS "Noble", Fedora 44, Rocky
Linux 10 and openSUSE Leap 16.0, all built by
`scripts/containers/create-container.sh`, and the last full cross-distribution
run was 2026-08-07 with the containers recreated first. Every
result and every per-distribution difference is in
[distribution-validation.md](distribution-validation.md). Four families, not
five: `DistroFamily` in `crates/hardener-distro/src/lib.rs` has exactly the
variants Debian, RedHat, Arch and Suse, and Fedora and Rocky are both RedHat.

**Nineteen distribution identifiers are accepted, and six distributions have
been run.** `Distribution::map_to_family` in
`crates/hardener-distro/src/lib.rs` matches an allowlist of nineteen
`/etc/os-release` `ID` values and returns `UnsupportedDistro` for anything else,
so a distribution outside that list fails cleanly rather than guessing. Inside
it, family routing means an identifier no container has ever presented takes a
measured family's code path unchanged. **Ubuntu used to be the case worth
naming** and is no longer: it was the release a newcomer is most likely to reach
for with no run behind it, and on 2026-08-07 it got one. Its container was built
by `scripts/containers/create-container.sh ubuntu` and ran the full cross-distro
suite under `--apply --booted` and the differential suite, both passing, with a
dated result in [distribution-validation.md](distribution-validation.md). Linux
Mint, Pop!\_OS, elementary, RHEL proper, CentOS, AlmaLinux, Oracle Linux,
Manjaro, EndeavourOS, Garuda, openSUSE Tumbleweed and SLES are still accepted on
family routing alone, and so is whichever of `opensuse` and `opensuse-leap` the
Leap container does not present, both being in the allowlist. That is thirteen
identifiers no container has ever run, against the six that one has.

**No hardware variation is covered and no kernel variation is covered.** Every
container is `systemd-nspawn`, which shares the host's kernel, so five
distributions on one machine are five userlands on one kernel. Nothing has been
run on a different CPU, a different kernel version, a different kernel
configuration, a hardened or vendor kernel, a virtual machine of a different
hypervisor, or bare metal other than the development machine. The packages
declare `x86_64` and `amd64` only, so no other architecture is claimed.

**Continuous integration adds no variety.** Every job in
`.github/workflows/ci.yml` runs on `ubuntu-latest`, a single distribution on a
single runner image.

---

## Can I point it at a fleet over SSH and believe what comes back?

This is the section to read hardest, because almost nothing in it runs unless a
person boots a container first.

**One happy path per fleet verb, and not one of them runs by default.**
`crates/hardener-cli/tests/batch_ssh_integration.rs` holds a single test each
for `batch scan`, `report`, `apply` and `rollback`, all four `#[ignore]`d behind
a live `SSH_TEST_HOST`. That is the only live evidence any of the four fleet
verbs has. A green reading from that file used to be indistinguishable from not
running it, because each test opened with an early return when the variable was
unset and the run then printed `test result: ok. 4 passed; 0 failed` having
reached no host at all. It now aborts with `SSH_TEST_HOST not set` instead,
matching the two SSH suites in `crates/hardener-core` and
`crates/hardener-plugins`, so the output can be believed. What that fixed is
whether you can read the result, not how much of the fleet path was exercised:
four happy paths, against one container, started by hand.

**Nothing that touches a wire runs by default or in CI.** Of the 40 tests the
workspace suite skips, 25 need `SSH_TEST_HOST` and a booted fixture from
`scripts/containers/boot-ssh-test-container.sh`. A regression in the SSH
transport is therefore invisible to `cargo test`.

**The 69 in-crate `batch` tests never open a connection.** They are target
parsing, output shaping and refusal policy over fixtures. Multi-host behaviour
against real hosts, partial failure part-way across a fleet, and a privilege
refusal from a host that genuinely refuses are unproven against anything live.

**The remote executor's own default coverage is three tests of fifteen**, and
those three assert configuration shape and description formatting.

Two things bound the risk rather than adding to it. Authentication is key and
agent based with no password path anywhere in the code, so there is no password
handling to get wrong. And `batch apply` and `batch rollback` are dry-run by
default and privilege-probe every host under `--execute`, so an unprivileged
host fails in isolation rather than half-way through.

---

## Can I hand the compliance report to an auditor?

The honesty guarantee is real and its foundation is a declaration rather than a
measurement.

**A control no plugin covers is reported as Manual Review and never as a Pass.**
That is asserted directly, and it is the property that stops a report claiming
compliance the engine never measured.

**Coverage is declared by each plugin's own `coverage()` function.** The
guarantee is therefore exactly as good as those declarations: a plugin that
over-declares turns a Manual Review into a Pass, and nothing in the compliance
crate would notice. The curated catalogues are CIS and ISO 27001:2022; the other
eight frameworks are derived from coverage, so a mapping error in a derived
framework is a data defect no test can see.

**No rendered report is ever parsed back by the consumer that will read it.**
The JSON is handed to no deserialiser, the CSV to no CSV reader, the HTML to no
parser, and the PDF row checks only that the output starts with `%PDF-` and
exceeds 1000 bytes, so a structurally invalid document no viewer could open
would pass. Of the fifteen output tests, ten assert on substrings of the
rendered string, one asserts a prefix and a byte length on it, and four assert
on a helper rather than on any rendered output.

**The entry point every real consumer calls is entered by no test.**
`ReportFormatter::format_all` is the multi-report path used by `hardener report`,
the report wizard and the desktop, and the coverage baseline records it and
`compare_control_ids`, the comparator that orders controls in every rendered
report, as reached by nothing.

---

## Does any of this cover the desktop application?

No. This is the largest single hole in the release's evidence and it is stated
here rather than left to be inferred.

**The evidence ledger has no row for the desktop.** Its Tauri IPC surface and
its Leptos frontend are covered by nothing in that table, so no claim in it
should be read as a claim about the graphical application.

**Continuous integration excludes both crates.** `.github/workflows/ci.yml` runs
`cargo test --workspace` with `--exclude linux-hardener-desktop --exclude
hardener-ui`, so a green CI badge is silent about every line either of them
holds.

**`src-tauri/src/commands.rs` is the single largest uncovered file in the
workspace**, at 26.60 per cent line coverage with 1115 lines missed across
thirty command bodies. Its neighbour `src-tauri/src/validation.rs` reaches 91.39
per cent, so the split is clean and deliberate: the pure validation layer is
tested and the command bodies that need a Tauri runtime and `pkexec` are not.

**The frontend's coverage figure cannot be read as a coverage figure.**
`hardener-ui` was measured on the host target, and what ships is a
`wasm32-unknown-unknown` build. On the host there is no DOM, so a Leptos
component body is compiled and never instantiated. Its 10.02 per cent says
nothing about whether the interface works.

**The browser-level end-to-end suite is stale against the redesigned interface
and is being rewritten**
([issue #48](https://github.com/tidynest/linux-hardener/issues/48)). Until it
lands, **nothing automated exercises the graphical application at all**, and the
only evidence behind it is a person looking at it.

The practical reading for an operator: the command-line tool is the surface this
release has evidence for, and the desktop is a front end to it whose own
behaviour is checked by eye.

---

## What runs automatically, and what needed a person?

**Nothing automated rises above a real-filesystem test.** `.github/workflows/ci.yml`
executes no `#[ignore]`d test and no shell suite. Every live-oracle result cited
anywhere in this project was produced by a person starting a container by hand,
and the date of the last such run is in
[distribution-validation.md](distribution-validation.md).

**A green CI run is a weaker reading than the workspace suite**, because the two
crate exclusions above make CI's set strictly smaller than the 1815 tests
`cargo nextest run --workspace` passed on 2026-08-08. That is the same figure
[evidence-ledger.md](evidence-ledger.md) records for the CI ceiling; the 1693
this paragraph used to quote was the 2026-08-07 reading of the same suite.

**The 40 tests the workspace suite skips, and what each needs:**

| What it needs | Count | Where |
|---|---:|---|
| A live SSH host (`SSH_TEST_HOST`) | 25 | `crates/hardener-core/tests/ssh_executor_tests.rs` (12), `crates/hardener-plugins/tests/ssh_integration_tests.rs` (9), `crates/hardener-cli/tests/batch_ssh_integration.rs` (4) |
| Root, and permission to change the host it runs on | 8 | one per plugin, in each plugin's integration test file |
| The nftables fixture container | 3 | `crates/hardener-plugins/tests/ssh_integration_tests.rs` |
| A named firewall backend already installed | 3 | `crates/hardener-plugins/tests/firewall_tests.rs` |
| A person to look at the output | 1 | `crates/hardener-cli/src/commands/batch/tests.rs` |

None of the 40 runs in CI. A `cargo test --workspace` run reports a larger
ignored figure than 40, because it also builds a documentation-test binary for
each of the workspace's nine library crates and seven documentation examples are
`#[ignore]`d as well.

**Coverage: 60.09 per cent is what the release ships, 79.11 per cent is what the
release tests.** The gap between the two figures is the desktop application. The
full per-crate and per-file picture, and the six limitations of how it was
measured, are in [the coverage baseline](coverage-baseline.md).

**Mutation testing has been smoked, not run.** Coverage says which lines a test
reaches and cannot say whether the test checks anything; mutation testing is the
question that separates the two, and so far it has been put only to
`hardener-distro`, chosen because it is the smallest crate in the workspace. The
integrity-critical crates, the plugins, the state layer and the compliance
renderers, have not been mutation-tested. Until they have, no figure anywhere in
this project distinguishes a line a test pins from a line a test merely visits.

---

## What happens when I upgrade from the version I am on?

**No automated test upgrades an installed older release to this one.** The
notices in [upgrading](../guide/upgrading.md) cover three starting points, "1.4.0
and earlier", "1.5.0 and earlier" and "1.5.1 and earlier", and each was written
from the defect it describes and verified by hand. Nothing in this repository
installs an old package, upgrades it and reads the result:
`scripts/test/test-package-install.sh` mirrors the `PKGBUILD` package function to
check the installed file layout, which is a fresh install rather than an
upgrade, and the `replaces`, `Replaces`/`Breaks` and `Obsoletes` metadata that
performs the rename swap is declared in the packaging and exercised by no test.

Two narrower upgrade paths are tested, and they are the ones inside the data
rather than around the package. `every_migration_restores_its_column` in
`crates/hardener-state/src/db/tests.rs` enumerates the checkpoint database's
in-place column migrations and requires each to restore what it promises, and
`a_legacy_key_is_migrated_to_the_encrypted_format` in
`crates/hardener-state/src/signing/tests.rs` covers the move from a raw signing
key to the encrypted format.

The practical reading: an upgrade to a stored database or a stored key has
evidence, and an upgrade as your package manager performs it does not. Read
[upgrading](../guide/upgrading.md) before installing over an existing
installation, because several of the fixes it describes repair the tool and not
the host the tool already changed.

---

## Keeping this document true

This file is only worth anything while it is accurate, so three rules govern it.

1. **Every entry names what was measured, not how it felt.** A ceiling that
   cannot be traced to a file, a section number or a command does not belong
   here.
2. **Closing a gap means deleting its entry, in the same change.** An entry that
   outlives the limitation it describes is worse than no entry, because it
   understates a release that has improved.
3. **A new limitation is recorded when it is found, not when it is fixed.** The
   point of this document is that an operator learns a limit from the project
   rather than from their own host.

Re-measure before amending a figure here. Do not copy one forward from an older
document, and record the commit any new run was taken on, exactly as
[the coverage baseline](coverage-baseline.md) and
[the evidence ledger](evidence-ledger.md) do.
