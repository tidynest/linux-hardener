# What This Release Does Not Prove

**Last Updated**: 2026-08-24

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
- [Does configuration load in the order the docs promise?](#does-configuration-load-in-the-order-the-docs-promise)
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

**Read green on five of six fixtures 2026-08-09**, the rows asked rather than
declared unaskable, each reporting `/etc/selinux` unchanged across the apply.
Arch was the sixth and went unasked for a different reason, which turned out to
be a fault in the oracle rather than in the fixture: it required a
configuration tree to already exist, on the reasoning that an untouched absence
compares one absence with another. It does not. A plugin that CREATES
`/etc/selinux/config` on a host with no `/etc/selinux` moves the digest from
empty to non-empty and fails the row, and that is the likeliest way this plugin
could misbehave. The condition is gone, so a host with no MAC configuration at
all is now asked whether one appeared.

**Re-read on all six 2026-08-09, and every fixture now asks the row.** Arch
moved from 94 declared and 12 unaskable to 96 and 10, and the other five did not
move at all, which is what says the change reached the one fixture it was for
and nothing else. Arch's row reports that none of the three paths existed before
the apply and none was created; the other five report `/etc/selinux` unchanged.

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
unproven by a container run.** Kernel and firewall were the first two of the
eight plugins to ask their own subsystem after the reload whether the running
host still disagrees with what was restored: a managed sysctl that no surviving
file names, and a `ufw` still enforcing over a restored `/etc/ufw/ufw.conf` that
says `ENABLED=no`, or the reverse. **All eight answer now (#142)**, which the
paragraphs below take up one plugin at a time; the reading in this paragraph was
taken while only those two did. `RollbackResult.rollback_divergences` carries one
row per subject a probe examined, and distinguishes a measured disagreement
(`Diverged`) from a probe that could not answer at all (`Unverifiable`), so an
empty vector means everything checkable came back rather than that nobody
looked. The CLI, the GUI rollback modal and the fleet summary all render it,
the fleet summary as two separate counts. **This is reporting, not
reconciliation.** No rollback behaviour, exit code or `rollback_success` value
changed to add it: nothing is restarted, stopped or re-enabled because of what
the probe found. **The other six were asked nothing when this was written**,
because no probe had been written for them, not because nothing there could
diverge. That is no longer the ceiling: the trait method carries no default body,
so all eight plugins implement it and a ninth could not inherit silence. What
each of the six actually earned, and which of their answers are ceilings rather
than readings, is set out below.
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

**Those 12 rows are exactly the case #152 later marked `divergence_expected`.**
A rollback restores files and reloads them; it never writes `/proc/sys`, so a
parameter no surviving file names keeps whatever the apply gave it until the
next reboot, which is stronger than the restored configuration asks for rather
than weaker. The reverse case, a running value contradicting a file that DOES
name it, stays unmarked: the reload did not take, and that is not a design
outcome. The same split applies to the ufw case above: enforcing over a
restored `ENABLED=no` is marked, because a rollback never stops a running
firewall; a restored `ENABLED=yes` left not enforcing is not, because nothing
in the design explains that either.

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

**All eight plugins now answer what a rollback left diverged (#142), not two,
and three of the answers are a ceiling rather than a reading.** The trait's
default was an empty vector, which this codebase treats as "everything
checkable came back": six plugins were inheriting that claim without a probe
ever having looked, and the default is now deleted so a ninth plugin cannot
inherit the same silence.

**A row can now also say whether it was expected (#152), and expected does not
mean lesser.** `RollbackDivergence.divergence_expected: Option<String>` carries
`Some(reason)` when the row is the designed consequence of a plugin's own
apply plus a rollback that never starts, stops or writes anything live, and
`None` otherwise. The field has no default, so every construction site,
including a ninth plugin's, has to answer rather than inherit a claim nobody
made. The test is direction, not frequency: expected means the rollback left
the host STRONGER than the configuration it just restored asks for; unexpected
means WEAKER, or means the rollback did not reach what it should have. Two
kernel rows fire on every rollback of a host with a legacy
`/etc/sysctl.conf` and stay unmarked anyway, because they leave the host
weaker at the next reboot, and marking them expected would teach an operator
to skip a row saying their host silently loses a hardening setting. An
expected row can still be `Diverged`; the field says the row was predictable,
not that it is unimportant, and none of the three reporting surfaces hides or
drops it. The CLI and the desktop rollback modal print the rows nothing in the
design produces first, then the rest under an "Expected, by design:" heading
carrying the reason; the fleet `batch rollback` summary changes only the
order, keeping its existing counts.

**`audit-hardening` reports a single `Unverifiable` row naming #18, and that is
a statement about this project's containers, not about the plugin.**
`auditctl` cannot run in any container this project builds at all, measured
twice on 2026-08-10, booted and unbooted. **`mac-hardening` reports nothing at
all in the same containers**, not an `Unverifiable` row: none of them expose
SELinux or AppArmor, so `MacDetection::Absent` is what this probe reads there,
and a host with no MAC system installed has no restored configuration and no
enforced policy for either to disagree with. That is a correct empty answer,
the same one `firewall/divergence.rs` gives for a host with no firewall
backend, not the "everything checkable came back" claim an empty vector
means everywhere else in this file: nothing here was checkable to begin with.
A container that could be handed a detected-but-unreadable MAC system would
still get `mac-hardening`'s `Unverifiable` row naming #18; none of this
project's containers can produce that state either, measured the same way as
`audit-hardening`. Neither row, where either appears, is ever `Diverged`,
because nothing here has been compared against anything. Both plugins mark
their #18 row `divergence_expected`: it is a stated ceiling rather than a
probe that failed, and #18 is what turns it into a measurement. **Read neither
the `Unverifiable` row nor the silence as "this plugin cannot diverge after a
rollback."** That claim was never earned; the only claim earned is that no
container this machine can build lets it be asked, and #18, a real virtual
machine, is what changes that.

**`service-minimisation`'s probe is readable on any booted host and has never
fired against a real divergence.** Unlike mac and audit, its state genuinely
can be read in a container: `systemctl is-enabled`/`is-active` work wherever
systemd is PID 1. What no container this project builds can do is force the
divergence the probe exists to catch. `bluetooth.service`, the one candidate
judged safe to force, was measured 2026-08-10 to go `failed` rather than
`active` when a start was attempted against it, so the probe's `Diverged`
branch is written but has never been exercised against a real one. That is a
narrower gap than mac or audit's, and a real one rather than a formality: the
probe could be silently wrong about a case nothing has ever put in front of
it. Only one of its two `Diverged` arms is marked expected: enabled-but-stopped
is, because `reload_after_rollback` runs `daemon-reload` only and never starts
anything, so a unit `apply` had stopped stays stopped and that is the design
working. Not-enabled-but-running is the reverse case, the host running a unit
its own restored files say should be disabled, and it is not marked: nothing
here explains why the unit would still be running, so it stays in the
unexpected group that sorts first.

**`permissions-hardening` and `pam-hardening` earned their empty vectors
rather than inheriting them, on the strength of a forcing exercise repeated
three times against one distribution in one container.** `/etc/shadow` was
forced to `666` and read back at `600` after the rollback; a line appended to
`/etc/security/faillock.conf` was forced in and read back gone. Both reverted
cleanly on every reproduction. That is strong evidence for the host it was
measured on, and not a proof that covers every distribution or every path
either plugin manages.

**`ssh-hardening`'s probe closes a gap for sshd specifically: a reload that
silently fails to take.** It is not a gap the other seven plugins all shared:
kernel's sysctl probe and firewall's ufw probe already exist for the same
reason, catching a reload that did not take on the running system. sshd had
none of its own, because `reload_after_rollback` restarts it unconditionally
and reports a failed restart only through its own `Err`, never through the
divergence row, so the two paths could disagree with each other with nothing
to say so. Measured 2026-08-10 in a booted arch container: masking
`sshd.service` before a rollback left it reporting `active` both before the
mask and after the rollback's restart attempt, which the probe now reports as
`Diverged`, and a second run confirmed it fires. **This probe has no expected
rows at all**, pinned by a test rather than left as an absence: every row it
can emit is a reload that did not take, which is never the designed outcome of
a rollback, so every row it prints is worth an operator's attention.

**`scripts/test/verify-rollback.sh` now runs as two passes, and only TEST 10
and TEST 11 are work the booted one adds.** The default invocation (unbooted,
under `--pipe`) runs TESTs 1-14, not the nine the 26-of-26 reading above
measured: that reading predates TESTs 10-14 existing at all, back when TESTs
1-9 were the whole suite. TEST 10 and TEST 11 gate on `host_is_booted` and
SKIP in the unbooted pass, because `ssh-hardening`'s and
`service-minimisation`'s probes need systemd as PID 1 to be askable at all,
but TESTs 12, 13 and 14 carry no such gate and run to completion there the
same as TESTs 1-9. A second invocation, with
`VERIFY_ROLLBACK_DIVERGENCE_ONLY` set, runs under `--boot` and covers TEST 10
onward: TEST 10 and TEST 11 are what it makes askable for the first time,
while TESTs 12, 13 and 14 run a second time and their assertions are counted
twice rather than added once. Both were read green on 2026-08-10 and again on
2026-08-11 against `d04de4c4`, with the same figures: **30 passed and 2 skipped
on the unbooted pass (TEST 10 and TEST 11, exactly the two `host_is_booted`
gates above), exiting 2 rather than 0 because a skip must never be recorded as
a clean pass, and 5 of 5 on the booted invocation.** The second reading is the
one that counts, because it is the first since #152 changed what every
divergence row reports; the 2026-08-10 figures were taken before that.

**On a remote host without root, a restore degrades to content only.** The
content write goes through `sudo tee`, but the `chmod`, `chown` and `rm` that
follow it do not, so modes and ownership can fail to come back while the bytes
succeed. Account databases are captured metadata-only by design, which is a
deliberate choice rather than an oversight, and the distinct `ContentAbsence`
discriminant keeps that apart from a read that failed.

**On RHEL, a rollback of the audit apply ends with a file the host never had,
and why is not yet known.** The release-readiness run of 2026-08-19 failed one
check on one distribution: `/etc/audit/audit.rules.prev` was absent before the
apply and present after the rollback. The content is correct, and the assertion
immediately after it passed, reading `audit.rules` back at its original six
lines; what survives is the backup copy, not wrong hardening.

A second run at `16f08948` passed on all six. **It was recorded here as proving
nothing on the grounds that no distribution had produced a `.prev` that time.
That was wrong, and the reasoning is worth keeping because it is a trap this
document exists to catch: `.prev` is named in a run's log only when the tree
comparison fails and prints its diff.** A run in which every host passed had no
reason to mention the file whether or not it existed, so reading the silence as
absence inferred a fact from a log that was never asked the question. What that
run actually established is weaker and real: the audit tree came back identical
on all six.

The third run, at `99723784`, settled it. Section 12A now says which case it is
in, and **`augenrules` created the backup during the apply on all five
distributions that completed, RHEL included** - the fallback that would have
created one never fired. So the conditions of the 2026-08-18 failure were
reproduced on the host that failed, and the rollback removed the file. The named
assertion `Audit rollback: the compiled-rules backup is gone` passed on arch,
debian, ubuntu, fedora and RHEL.

**That leaves the original failure unexplained rather than absent.** It has now
been observed once and not reproduced across two later runs under conditions
that look the same from the log. The check is no longer a lottery ticket: it
forces the file into existence when an apply leaves none, and it names the file
when it survives rather than reporting only that two directory listings differ.
But a pass still cannot prove the intermittent case is gone, only that it did
not occur.

**openSUSE needed a second attempt, and the first version of this check got it
wrong.** Its audit package arrives with `.prev` already present, on a container
the runner recreates moments before. The check refused that as a host state an
earlier run must have left, failed the section and returned, costing that
distribution the other eight checks including the tree comparison. It now
removes the file before taking its baseline instead.

**That fix ran at `c269ef84` and openSUSE passed: 151 declared, 149 passed, 0
failed.** Its log carries the removal line on that host and on no other, then
records `augenrules` leaving a fresh `.prev` during the apply and the rollback
removing it. So all six distributions now exercise the removal path through the
real mechanism, and all six pass it.

**What remains open is narrow and should not be read as closed.** The
2026-08-18 RHEL failure has been observed once and not reproduced since, under
conditions the logs cannot distinguish from the runs that pass. The apply's
row-recording for this path and the audit plugin's post-reload removal are still
the two unexamined candidates. What has changed is that a recurrence would now
be named rather than reported as two directory listings differing.

Three mechanisms could produce it: the apply recording no checkpoint row for
the path, the restore declining to act on that row, or the audit plugin's own
post-reload cleanup missing the copy `augenrules` writes again on the way out.
**The middle one has since been ruled out.**
`rollback_deletes_the_compiled_rules_backup_augenrules_saved` gives the restore
exactly that row and reads what it does: it issues `rm -f` and reports
`Removed`. Both of its assertions were watched failing against mutated code
before being believed, one with the path added to
`UNDELETABLE_ROLLBACK_PATHS` and one with `recorded_absent` forced false. So
the remaining candidates are the apply's row-recording and the plugin's
post-reload removal, and neither has been read on a host that reproduces it.
The checkpoint database that would answer it lived in the RHEL container, which
is destroyed at the end of every run.

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
run was 2026-08-14 with the containers recreated first, all six VALIDATED at
149 declared, 147 passed, 0 failed and 8 skipped. Every
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
container is `systemd-nspawn`, which shares the host's kernel, so six
distributions on one machine are six userlands on one kernel. Nothing has been
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

**Nothing that touches a wire runs by default or in CI.** Of the 42 tests the
workspace suite skips, 27 need `SSH_TEST_HOST` and a booted fixture from
`scripts/containers/boot-ssh-test-container.sh`. A regression in the SSH
transport is therefore invisible to `cargo test`.

**The 86 in-crate `batch` tests never open a connection.** They are target
parsing, output shaping and refusal policy over fixtures. Multi-host behaviour
against real hosts, partial failure part-way across a fleet, and a privilege
refusal from a host that genuinely refuses are unproven against anything live.

**`run_fleet_scan`, the desktop's own fleet path, is still entered by no test,
but most of what it decides no longer lives inside it.** It is a
`#[tauri::command]` opening one SSH connection per host, so nothing reaches the
command itself without live SSH, and unlike the CLI's four fleet verbs it has no
`#[ignore]`d live test standing ready for a booted fixture. Of its 126 lines,
five need a socket. On 2026-08-22 the rest moved into `fleet_targets`,
`ssh_config_for` and `attach_compliance`, and all three are covered by
`src-tauri/src/commands/fleet_tests.rs` over `MockExecutor` and plain fixtures:
the profile map keyed by inventory name and by full ad-hoc target, the
precedence of a saved host over an ad-hoc target spelling its name, the
`host_key_checking` to `KnownHosts` mapping, the identity each host's generator
is handed, which is what makes a host-targeted exclusion apply to the right row,
and the gate that leaves a failed host with no posture at all. What is still
proven by nothing is the wiring: that the command hands those three the right
arguments, and that `SshExecutor::connect` and `detect_host_profile` behave over
a real connection. `local_exclusions()`, the read that loads the operator's
declared-not-applicable set, is called only from the command body and is entered
by no test.

**That paragraph used to end by saying a mutation in any of those decisions
would leave the whole workspace suite green. One already had.** The flatten
written by hand in that body counted 38 passing CIS controls for a fleet row
scanned with a single plugin, the same 38 a row scanned with all eight counted,
because a plugin that reports nothing leaves nothing for the generator to mark
unassessed and its controls pass on the silence. The fleet path now flattens
through `flatten_scan_results`, the same call the local compliance tab makes, so
a plugin missing from a row contributes an unassessed entry: the one-plugin row
counts 10. The defect is fixed and asserted. The general point is the one worth
keeping, that a function body no test enters is where this happens, and that a
copy of logic that already exists elsewhere is where it happens first.

**Whether a plugin can error at all on a remote host is unproven, and the arm
that handles it is asserted only in isolation.** `scan_with_executor` now
records a plugin whose `scan` returns `Err` as a failed result rather than
dropping it, which is what both local scan paths already did. No fixture reaches
that arm: measured over a `MockExecutor` stubbing nothing, all eight plugins
return `Ok`, three of them carrying `scan_success: false` because the host is
too bare to assess rather than because anything failed. The `Err` arm is a
transport failure part-way through a host, and nothing short of a live
connection that drops mid-scan produces one. What is asserted is the rule in
isolation, that `recorded_scan` turns an error into a failed result carrying its
message, and separately that a bare host still yields eight accounted rows and
not five.

**The remote executor's own default coverage is three tests of seventeen**, and
those three assert configuration shape and description formatting. The other
fourteen are `#[ignore]`d behind `SSH_TEST_HOST`.

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

**A control no plugin *reached on this host* is a separate rule, and it is the
one that broke.** Coverage is declared statically, so a plugin that declares a
control but never ran leaves that control with no finding against it, and a
control with no finding and no unchecked entry passes. What stops that is the
flatten, which contributes an unassessed entry for a plugin missing from the
results.

Until 2026-08-23 that flatten sat in `hardener_plugins::scan_outcome`, in front
of the generator, so the rule held only where a caller remembered to go through
it. On 2026-08-22 the desktop's fleet path did not. All six sites building a
`ReportGenerator` were traced by hand that day and each fixed, and **nothing
enforced it for a seventh.** A validator was considered and not written, because
deciding whether a call's arguments came from an approved flatten needs to
follow bindings through pass-through functions, and a regex that guesses would
either miss the case or need enough exemptions to stop meaning anything.

**It is now structural.** `ReportGenerator::generate` takes raw per-plugin scan
results and flattens them itself; the scoring pass beside it is private. There
is no flattened pair a caller can hand to scoring, so a seventh site cannot get
this wrong the way the sixth did. The rule's own tests live with it in
`hardener-compliance/src/scan_evidence/tests.rs`, and both front ends keep the
behavioural tests they had:
`flattening_no_results_leaves_every_plugin_unassessed` for the desktop's local
path and `a_fleet_row_cannot_pass_a_control_the_scan_never_assessed` for the
fleet column. Deleting the absent-plugin loop fails eight tests across three
crates, including both of those.

**What that does not cover.** `scan_evidence::flatten` is still public, because
`batch scan` publishes the flattened pair as JSON and never builds a report. A
caller can therefore still flatten by hand for output purposes and get it wrong;
what it cannot do is score the result, which is where a wrong answer became a
false `Pass`. The seal is on the scoring path, not on the flatten.

**Coverage is declared by each plugin's own `coverage()` function.** The
guarantee is therefore exactly as good as those declarations: a plugin that
over-declares turns a Manual Review into a Pass, and nothing in the compliance
crate would notice. The curated catalogues are CIS and ISO 27001:2022; the other
eight frameworks are derived from coverage, so a mapping error in a derived
framework is a data defect no test can see.

**ISO 27001 cannot score above 11.8 per cent, on any host, at root.** Measured
2026-08-18 on the arch capture host with a privileged scan: 93 controls, 11
assessable, 82 `ManualReview`. The ceiling is `11 / 93`, so that row can never
leave the critical colour band however well a machine is hardened. This is a
*measured* ceiling and not an inference from the catalogue's size: an
unprivileged run of the same scan left 86 unassessed, and root moved only four
of them, which is what separates the two causes. The 82 are Annex A controls
about policy, personnel, supplier relationships and physical security, and no
configuration scanner can assess them; adding plugins raises the ceiling only
as far as the technological subset of Annex A reaches.

**The comparison the dashboard invites is therefore not one the numbers
support.** A curated framework's denominator is the whole published standard
and a derived framework's is only what the engine assesses, so ISO 27001's 8.6
per cent and SOC 2's 60 per cent from the same privileged scan are answering
different questions. The per-framework row states its unassessed count beside
the score, which makes each row honest read alone; nothing stops a reader
ranking one row against another, and on this evidence a ranking would be wrong.
Whether curated and derived frameworks should share one list, one colour scale
or one screen is an open design question, recorded here rather than decided.

**SOC 2's unassessed controls were entirely a privilege artefact**, by
contrast, and the same run proves it: 3 of 5 `ManualReview` unprivileged, 0 of
5 at root, with both failures unchanged. So an unassessed count is not one
thing. On a derived framework it usually means a check could not run; on a
curated one it usually means no check exists. The report's coverage note
distinguishes them only in the first case.

**No rendered report is ever parsed back by the consumer that will read it.**
The JSON is handed to no deserialiser, the CSV to no CSV reader, the HTML to no
parser, and the PDF row checks only that the output starts with `%PDF-` and
exceeds 1000 bytes, so a structurally invalid document no viewer could open
would pass. Of the fifteen output tests, ten assert on substrings of the
rendered string, one asserts a prefix and a byte length on it, and four assert
on a helper rather than on any rendered output.

**All ten frameworks are now rendered on all six distributions.** This entry is
kept rather than deleted because what it recorded was true for months and the
shape of it is worth keeping: a gap nothing could see, in a table no instrument
read. `FRAMEWORKS` at `scripts/test/full-test-suite.sh:58` named seven until
2026-08-19, `cis stig nist pcidss hipaa gdpr iso27001`, so the cross-distro
matrix rendered a report for those seven and no others: **SOC 2, NIST 800-171 r3
and FedRAMP were in `ComplianceFramework::ALL` and in every framework picker,
and no run on any of the six distributions had ever rendered one.** The array
names all ten as of that date, and `validate_compliance_docs.py` holds it to
`ComplianceFramework::id()` by set equality so a framework added later cannot be
left out of it in silence. **The six checks that adds, three in section 5 and
three in section 7, passed on all six distributions at `5652bb45`**, containers
recreated first, each log recording `Version: hardener 1.5.1 (5652bb45
2026-08-19)`, and each container finishing with ten framework PDFs on disk
between 27 and 35 KB. That closes it as a matter of measurement rather than of
argument. The gap was always narrower than it sounds and should not be widened
in the retelling: the coverage mappings of all three were already asserted by
plugin unit tests, which is where a mapping error would show, and the three
share the rendering path with the seven long exercised.

**What the run does not say.** It says the report and the PDF render without
error, which is what the checks assert. No rendered report is parsed back, here
or anywhere, per the entry above this one, so a structurally invalid document
no viewer could open would still pass. This document did not mention any of the
three by name until 2026-08-16.

**The entry point every real consumer calls is entered by no test.**
`ReportFormatter::format_all` is the multi-report path used by `hardener report`,
the report wizard and the desktop, and the coverage baseline records it and
`compare_control_ids`, the comparator that orders controls in every rendered
report, as reached by nothing.

**A scope exclusion typed into `config.toml` by hand produces no audit entry.**
`hardener scope exclude` writes the `[compliance.not_applicable]` table and
files a signed entry beside it saying who raised the score, when and on what
grounds. The same table typed into the file by an editor is honoured by the
generator identically, and nothing logs it, because no code ran. This is a
property of the mechanism rather than a defect in it: any configuration key an
operator can write by hand has the same shape, and a config file is not a
tamper-evident record. The rendered report does list the controls an exclusion
removed from the denominator, so the effect is visible in the artefact; that is
a mitigation and it is not the log. An estate that needs the log has to reach
the declarations through the verb, and nothing in this tool enforces that.

**The report names the controls an exclusion removed from the score and never
says why any of them was removed.** Every format marks such a control `N/A` in
its per-control table, the text report gives them a "Not applicable" listing of
their own, and the score line states that exclusions are in force, so the effect
is visible. The reason the operator gave is in none of it. It lives in the
`[compliance.not_applicable]` table and in the audit entry `hardener scope
exclude` files beside it, and `ControlResult`, which is what a rendered report
carries, has no field to put it in; adding one is a change to a type the
backend, the compliance renderers and the desktop all share, and it was judged
out of scope for the branch that added exclusions rather than attempted. The
practical shape of the gap is this: an operator can reduce the denominator of a
compliance score, and the artefact an auditor is handed lists the controls that
left it and offers no justification for a single one of them. **The information
is not lost, it is in the wrong document.** The audit log holds each reason with
the person who declared it and the date, so an estate that reached its
declarations through the verb can produce them; the report does not, and does
not say where to look.

**An inert exclusion is flagged in the log, but only as a boolean.** Only CIS
and ISO 27001:2022 have a curated catalogue; for the other eight frameworks the
catalogue is derived from live plugin coverage at report time, so every control
in it is one the engine assesses and the generator settles it before reaching
the arm that would honour an exclusion. `hardener scope exclude` still writes
such a declaration and still audits it, with `W  ...` on stderr saying it will
not take effect. The entry carries `takes_effect = false` beside it, inside the
hash chain, so the log alone distinguishes an inert declaration from an
effective one; both directions are asserted, including that a curated framework
gets no such key. What the entry does not carry is the advisory's own text,
which names the reason the catalogue cannot honour the control. An operator who
redirects stderr, or who reaches the verb over IPC, gets the flag and not the
explanation.

**A desktop config change lands in a chain the host's auditor does not read.**
Every configuration write in this project now goes through one writer that files
its own entry, the CLI's four and the desktop's three alike, and a write that
records nothing does not compile. Where the entry lands is still chosen by uid:
root writes `/var/log/linux-hardener/audit.log`, everyone else writes
`$XDG_DATA_HOME/linux-hardener/audit.log`. The desktop's own writes, the
scheduler section and the two host-inventory commands, run as the desktop user
and do not escalate, so their entries are in that user's chain and not the
host's. An auditor reading `/var/log` sees the exception and scope entries,
which reach it through `pkexec`, and none of the three above. **Nothing is lost
and nothing is unrecorded; it is in a second file, per user, and no tool in this
project collects the two together.** Making the desktop escalate to record its
own settings would be a worse trade than the gap.

**`hardener systemd generate --output-dir` writes files and records nothing,
deliberately.** `install` and `uninstall` both go through the shared writer now
and file an entry each way. `generate` does not, because it writes to a
directory the operator named on the command line rather than to a systemd unit
path: it produces units for inspection, and nothing it writes runs. If a future
change lets `generate` target a live unit directory, that reasoning stops
holding.

**`install` and `uninstall` are observed end to end apart from three lines
each.** Both now talk to systemd through a `SystemExecutor`, the same
abstraction the plugins scan through, so `install_with` and `uninstall_with`
take the executor, the unit directory and the audit logger as arguments and a
`MockExecutor` answers for systemd. Six tests in
`crates/hardener-cli/src/commands/systemd/tests.rs` drive them against a
temporary directory: the units written and each entry filed, the reload
arriving before the enable, a system install never carrying `--user`, a timer
that would not start reported as such, and an uninstall proceeding past a
`disable` that failed.

**What each verb still resolves for itself is untested:** `unit_dir_for`, which
reads `HOME` and picks `/etc/systemd/system` over `~/.config/systemd/user`; the
root check, which is about this process; and the `LocalExecutor` the production
path passes. A change to any of those would send a correct install to the wrong
instance and every test here would still pass.

**The suite wrote real audit entries into the operator's own log until
2026-08-24, and four modules keep the shape that allowed it.**
`exception::add` and `remove` each had a no-argument form beside an `add_at`
form compiled for tests. Five call sites in `exception/tests.rs` reached for the
short name, so every `cargo test --workspace` filed four genuine exception
entries, an add and a remove for `ssh:PasswordAuthentication` and
`audit:auditd-present`, into `$XDG_DATA_HOME/linux-hardener/audit.log`. 126 had
accumulated by the time it was found. The short forms are gone and the logger is
now a parameter, so the leak cannot be reached by forgetting a suffix.

**No command in `hardener-cli` resolves its own audit logger any more.** All
eleven that file entries take an `Option<AuditLogger>`, and `main.rs` supplies
it: `exception` add and remove, `scope` exclude and include, `checkpoint`
create, delete, repair and rollback, `apply` run, `batch` apply and rollback
through their options structs, and `systemd` install and uninstall. The rule is
checkable rather than remembered, which is the point:

```
git grep -c 'get_audit_logger[(]' -- crates/hardener-cli/src
```

answers `main.rs:13` and names no other file. A command that grew its own
resolution would show up as a second file in that output.

**Both oddities in that pattern are load-bearing, and two earlier spellings had
to fail to find them.** Without the paren, it matches every doc comment
discussing the rule as readily as every call: 21 lines across 5 files, 8 of them
prose, which reads at a glance as the rule being broken in `exception.rs`,
`scope.rs` and `systemd.rs`, where it holds. With a plain `()`, it matches the
line in `commands/state.rs` that writes the command down, so the check reports
its own documentation as a second call site. The character class matches a
literal `(` without being one.

**It is checkable, not enforced.** Nothing runs that grep. No validator asserts
it and no test fails if a twelfth command resolves its own, because what a test
would have to observe is a write to a path outside the temporary directory it
controls, and it has no way to see one. The measurement that stands in for it is
crude and was run: `cargo test --workspace` leaves
`$XDG_DATA_HOME/linux-hardener/audit.log` byte-identical, checked by line count
before and after.

**Nor is any of this defended against being undone.** Reverting means restoring
a no-argument form, and no assertion anywhere would notice. The seal is the
signature, and the only thing holding it is that there is no second spelling.

**`hardener systemd status` still spawns `systemctl` itself.** It was left
alone deliberately: it already captures rather than inheriting, its decision
about which stream holds the answer is asserted by `status_report`, and moving
it to the executor would change `exit_code` in the JSON envelope from a
nullable field to an always-present number for no coverage gained.

**All three of the desktop's writes are observed reaching the file and the
log.** Each command reads both its target path and the audit log path from the
process environment, and moving environment variables under `cargo test`'s
threads is the race that put
`crates/hardener-core/tests/inventory_shared_path.rs` in its own binary, so in
each case the part that edits and writes takes both as arguments:
`write_scheduler_config`, `upsert_host` and `remove_host`. Six tests in
`src-tauri/src/commands/config_write_detail_tests.rs` drive them against a
temporary config, inventory and log, and read back both the file and the entry.

**What remains uncovered is which path each command picks.**
`writable_config_path` and `inventory_path` resolve from the environment, and a
test that moved it would be the race above. So a change that sent a write to
the wrong file would still pass: every test here would watch it arrive at the
path it was handed. The two resolvers are one line each and are read by nothing
else, which is the whole of the argument that this is a small gap rather than
no gap.

**`inventory::save_audited_to` exists so those tests can name a file.** It is
public and takes an arbitrary path, which the module otherwise refuses: the
`save_to` that used to sit beside it was removed for taking a path *and*
writing it unaudited with a bare `std::fs::write`. This keeps the mandatory
audit descriptor and the atomic write and gives up only the location, and every
production caller still goes through `save_audited`, which resolves
`default_path`. **A second production answer to where the inventory lives would
not fail any test**; it would show up as a call to this function outside a test
module.

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
thirty-two command bodies. The percentage and the missed-line count are the
2026-08-14 coverage reading; the body count is measured from the file, which
carries 32 `#[tauri::command]` functions. Its neighbour `src-tauri/src/validation.rs` reaches 91.39
per cent, so the split is clean and deliberate: the pure validation layer is
tested and the command bodies that need a Tauri runtime and `pkexec` are not.

**The frontend's coverage figure cannot be read as a coverage figure.**
`hardener-ui` was measured on the host target, and what ships is a
`wasm32-unknown-unknown` build. On the host there is no DOM, so a Leptos
component body is compiled and never instantiated. Its 10.02 per cent says
nothing about whether the interface works.

**The browser-level end-to-end suite was rewritten against the redesigned
interface** ([issue #48](https://github.com/tidynest/linux-hardener/issues/48),
closed 2026-08-08), and this section said the opposite of the truth for three
days afterwards: that nothing automated exercised the graphical application at
all. It read **134 of 134 on all six distributions on 2026-08-11** against
`7c81c491`, none skipped and none flaky, covering findings and compliance,
configure, history and apply, fleet, scheduler, errors, the `/remote` redirect
and all seven themes. **That reading is now stale and has not been repeated.**
`gui-tests/tests/settings.spec.js` (8 tests, covering the Appearance and About
panes) was added on 2026-08-12 at `dddb7651`, growing the suite to 142 tests per
distribution.

**The grown suite has since been run, twice, and this paragraph's own caveat is
discharged.** 152 of 152 on all six distributions on 2026-08-15 at `4284612d`,
then **154 of 154 on all six on 2026-08-16 at `5b715039`**, none failed, none
skipped, none flaky, with all six containers destroyed and recreated first.
`npx playwright test --list` reported 154 in 11 files that day, and that count
was a result rather than a count. Recorded in
[distribution-validation.md](distribution-validation.md).

**It reports 156 as of 2026-08-18, and for one day that figure was a count
rather than a result**, which is the distinction this document is for.
`T-FLEET-10` and `T-SCHED-07` were written that morning and could not be run
where they were written, the suite executing only inside the nspawn containers.
The run came the same day: **156 of 156 on all six at `653b4ff1`**, none failed,
none skipped, none flaky, both new cases green on every distribution. The
distinction is recorded rather than deleted because it recurs every time a case
is added between runs, and a declared case that has never run proves nothing.

**It reports 157 as of 2026-08-18, and the one hundred and fifty-seventh has
never been run.** `npx playwright test --list` reports 157 in 11 files. The new
case is `T-DASH-11` in `gui-tests/tests/dashboard.spec.js`, asserting that the
compliance row carries the "excluded by policy" annotation for GDPR, the one
framework the mock fixture gives exclusions to, and does not carry it for CIS.
It was written on the `scope-exclusion` branch and could not be run where it was
written: the Playwright suite executes only inside the nspawn containers, which
need root. So the paragraph above repeats itself one paragraph later, exactly as
it predicted it would. **A declared case that has never executed proves
nothing**, and until a container run comes back the branch has no evidence that
the annotation renders, that it renders only where there are exclusions, or that
the assertion would fail if it did not.

The first of those runs is worth keeping in view here, because it is the case
this document exists for: `contrast.spec.js` had shipped on 2026-08-13 and its
rule flattener dropped every rule it was given, so it measured **0** colour
pairings and passed its own vacuity guard's failure. A suite can be green about
nothing, and for two days this one was.

**The `.compliance-excluded` pill is now weighed, and it passes on all seven
themes.** This subsection claimed the opposite until 2026-08-19: that an alpha
background fell between the two contrast instruments, and that nothing could be
said about whether the pill passed or failed.
`scripts/validate/validate_contrast.py` no longer returns `None` for an
`rgba()` fill. `alpha_colour` reads the tint out of the declaration, or out of
the token the declaration names; `over` composites that tint onto an opaque
backdrop in sRGB source-over, which is what the browser does for
`background-color`; and the check runs that compositing against every `--bg-*`
surface the theme declares, keeping the best of the resulting ratios. The pill
reads 5.18:1 on default, 5.26 on daywatch, 5.38 on guardian, 5.38 on sentinel,
5.51 on command, 5.54 on fortress and 12.12 on high-contrast.
`.severity_exception` shares `--pill-muted-bg` and measures identically, which
is what the shared token buys. The rule declares `color: var(--text-muted)` and
`background-color: var(--pill-muted-bg)`, a token rather than the bare literal
this subsection used to quote; `--pill-muted-bg` is `rgba(148, 163, 184, 0.14)`
in the default block. No theme colour changed to produce that reading: the fix
was not the obvious one of giving the pill an opaque fill, it was widening the
instrument.

**Best of every surface is a deliberate ceiling, and it is the reason these
figures are facts rather than guesses.** A static parse cannot know which
ancestor an `rgba()` fill composites over, so taking the best result means a
failure holds whatever the ancestor turns out to be. The worst-case rule was
measured too: it reports 61 failures on pairings that may never co-occur, which
is the manufactured-defect mode that gets a check muted and is worse than no
check. Best-case reports 8, and all 8 were real. Pairs checked went from 182 to
322, the 140 that became measurable coming from 18 rules that declared an alpha
background. Two of those failures were cleared by giving `.severity_medium` a
new `--color-medium-bright` token, daywatch having read 1.77:1, and six by
moving `.partial-row-badge-failed` and `.status-error` from `--color-critical`
to `--color-critical-bright`, 4.07:1 to 4.49:1. `.severity_low` on daywatch was
held open at 3.32:1 and was **fixed on 2026-08-20** when the reopening found
its reasoning had surveyed one call site of two: daywatch's `--color-info`
moved `#0891b2` to `#155e75`, which reads 6.55:1 at the best surface and
5.31:1 at `--bg-tertiary`. `DEFERRED` is now empty, which is its intended
resting state.

**What the widening does not do is close the gap it was cut from.** The
best-case rule means a pair that fails on the darker surfaces but clears on one
is still not reported here, so a green line in this file is a claim about the
most favourable ancestor rather than about every ancestor.

**The browser half was widened to answer exactly that, on 2026-08-20, and it
has not run once.** `gui-tests/tests/contrast.spec.js` no longer skips every
rule declaring a background: the boundary between the two files moved from
"declares a background" to "the static parse already has the true number",
which stopped being the same thing the moment this file learned to composite.
An opaque declared fill is still weighed by the static check alone. A
translucent one is now weighed by both, and that is not two numbers for one
question: this file reports the best surface available, the browser reports the
one that painted. The rule is `browserOwnsPairing` in
`gui-tests/tests/contrast-math.js`, and it is proved on the host by that file's
own self-check, each of its three arms observed failing under the transposition
that would disable it.

**The first container run confirmed the ceiling was real, and cost the
widening a defect it could not have found any other way.** Arch, 2026-08-20,
`--grep T-CONTRAST`: 7 of 7 themes passed, 37 pairings measured per theme (39
on daywatch), 0 unmeasurable. **`.compliance-excluded` reads 4.91:1 on daywatch
against the ancestor that actually painted, `rgb(234,234,234)`, where the
best-of-surfaces figure above is 5.26:1.** Both are correct answers to
different questions, and the 0.35 between them is the size of the ceiling this
subsection had been describing in the abstract since 2026-08-19.

**The defect was in the scope rule, and only the run's own output showed it.**
The suite was green, so nothing failed; reading the per-theme listing rather
than the summary is what found it. Ownership was keyed on the element's
COMPUTED background alpha, and `.tab-button.tab-active` declares an opaque
`--bg-secondary` while the same element is also `:hover`, which paints a
translucent `--bg-elevated` over it. The selector was therefore admitted in all
seven themes and carried a number here AND in `validate_contrast.py`, measured
against two different backdrops: exactly the two-answers-one-label confusion
the split exists to prevent. It appears 0 times in the 2026-08-19 logs and 7
times in the 2026-08-20 one, which is how it was pinned. Ownership is a
question about a rule, so it now reads the alpha of the fill the rule declares,
resolved through the theme's custom properties but not through the cascade.

**A second hole went with it.** The widening's vacuity guard counted any rule
declaring a background, which includes `background: transparent` - reachable
before the widening and behaviourally identical to a colour-only rule. Two are
on these routes, so the guard could have been satisfied entirely by pairings
the widening did not win. It now counts only fills strictly between 0 and 1.

**The second run confirmed the fix and refuted the prediction that came with
it.** `.tab-button.tab-active` went from 7 occurrences to 0, and
`.tab-button:hover` with it, which is exactly what reading the rule rather than
the element was meant to do. The predicted per-theme fall of about two did not
happen: the count went 37 to 38, daywatch 39 to 39. Diffing the two daywatch
listings selector by selector shows why, and it is not a wash. Two entries
left, the two opaque-declared tab rules; **two different ones arrived**, both
`.tab-button` on `/analysis` ("Findings" at 14.99:1, "Scan History" at
17.49:1), neither present in the first run.

**Nothing in the scope fix can add a rule.** The predicate only ever removes
them, and `.tab-button` declares `transparent` in both runs, so it was eligible
throughout. Two mechanisms could produce this and neither has been pinned: the
`/analysis` route may render a different number of tab buttons run to run, or
the scratch element the resolver appends to `document.body` may be forcing a
style and layout flush that the sweep previously ran ahead of, since collection
is gated on `getClientRects().length`. **Either way the first run was
under-collecting two real pairings, and neither `MINIMUM_PAIRS` nor
`MUST_REACH` could have said so.** A sweep whose collected set varies between
runs can lose coverage silently; that is now a known property of this check and
not a settled one.

**The widening's real reach is one pairing per theme.** Every theme reports
exactly 1 fill strictly between 0 and 1, and it is `.compliance-excluded`. The
guard therefore sits precisely on its floor: one rule fewer and it fails. That
is an honest tripwire rather than a comfortable margin, and it is the strongest
argument for the gap in the next paragraph.

**The severity classes are not badges, and no scan will ever reach them.**
This subsection said on 2026-08-20 that they went unmeasured because
`/analysis` loads without a scan. That was half right and the wrong half was
the conclusion. `severity_class()` is passed to `finding_group`
(`findings_tab.rs:176`) and `host_finding_subgroup` (`host_panel.rs:283`), and
both put it on an **empty** span: `finding-dot`, `host-finding-dot`. It never
wraps text anywhere in the application. A text-contrast check that requires an
element to render its own text is therefore not missing them by fixture or by
route; they are outside what it measures, by construction.

**The one screenshot anybody took answered a question six container runs could
not.** Nothing had eyeballed this work; on 2026-08-20 the daywatch findings
view from the container corpus was read and its dots sampled directly. Row
background `rgb(248,246,242)`:

| group | rendered | vs background |
|---|---|---|
| Critical | `#991b1b` | 7.70:1 |
| High | `#794203` | 7.50:1 |
| Medium | `#7a5c00` | 5.79:1 |
| Low | `#0891b2` | 3.41:1 |
| Policy Exceptions | `#6a635f` | 5.46:1 |

The Low row is a reading of the screen on 2026-08-20 and keeps saying what it
says, but it is **not current**: daywatch's `--color-info` moved to `#155e75`
later that day, so the dot now draws darker than this records. Re-read it from
a fresh capture before quoting the 3.41.

Two things it confirms. Medium renders as `#7a5c00`, the `--color-medium-bright`
token added on 2026-08-19, so that fix reached the screen. And High against
Medium measures **1.29:1 dot to dot**, matching the ceiling recorded for it in
prose to two decimals: those were token arithmetic, and this is pixels.

**It also put the `.severity_low` deferral in doubt, on evidence rather than
on a hunch** - and the reopening on 2026-08-20 then refuted the doubt itself.
The argument was that the class only ever lands on an 8px dot, so
`.finding-dot`'s `background: currentColor` (line 4039, winning the cascade
over `.severity_low` at line 1085) overrides the `rgba()` tint being
composited and the pair weighed is not drawn at all; the bar for a non-text
graphical object being WCAG 1.4.11 at 3.0 rather than 1.4.3 at 4.5, and the
dot as rendered reading 3.41:1, which clears it.

**That argument surveyed one consumer of `severity_class()` and there are
two.** `findings_tab.rs:221` is the dot and the reasoning holds there.
`host_panel.rs:42` is not: it renders
`<span class="host-severity-label {class}">` carrying the text `"Low (3)"`,
and `.host-severity-label` is `font-size: 0.78rem; font-weight: 500`, about
12.5px at normal weight, which is ordinary text and takes the 4.5. The
screenshot that prompted the doubt was the daywatch **findings** view, which
contains only the dot; nothing had looked at the host panel. So the 4.5 bar
was the right bar, the deferral was real, and it was fixed rather than
dismissed: daywatch `--color-info` `#0891b2` to `#155e75`.

**The consumer that justified the fix had no browser coverage, and the gap was
closed the same day.** The first `--grep T-CONTRAST` run after the fix passed
while proving nothing about it: its log carried **zero** occurrences of
`severity_low`, of any other `severity_*`, of `finding-dot` or of
`host-severity-label`. Two separate reasons. `.finding-dot` is an empty span,
so there is no text to weigh and the sweep is right to skip it.
`.host-severity-label` never rendered, because the five routes in
`contrast.spec.js` were the dashboard post-scan, `/hardening` History,
`/hardening` under `apply_mode=mixed` and `/analysis` twice; none reached
`/fleet` with a host expanded. `MUST_REACH` did not report the absence because
`.severity_low` was not in it.

A sixth route was added, `fleet, host expanded`, driving a scan of `web-01` and
expanding its row, with `.severity_low` added to `MUST_REACH` so the route
cannot quietly stop contributing. **Daywatch now reads 5.29:1 rendered**,
`#155e75` on `rgb(202,225,222)`, confirming the fix against the ancestor that
actually paints. That is 0.02 below the static parse's 5.31 floor, and the
reason is instructive: the panel's row paints a composited surface the theme
never declares as a `--bg-*` token, so the static check cannot reason about it
at all. Below the spread is a disagreement, and this is one, at the smallest
scale the two instruments can disagree by.

**Adding that one route turned up thirteen rendered failures in four rules,
none of them a regression.** `.severity_exception` is short in six themes of
seven (4.21 to 4.34), `.tally-crit` in five (3.82 to 4.20), and one theme each
for `.severity_critical` (sentinel 4.18) and `.severity_low` (fortress 4.29).
Every one has been failing since the panel was written; what changed is that
something finally looked. All thirteen were verified live against the run's own
listing, so none was a dead entry excluding nothing.

**`.tally-crit` was taken first and is fixed**, being the worst of them and a
reading of a critical count. It moved to `--color-critical-bright`, the same
move `.partial-row-badge-failed` and `.status-error` made on 2026-08-19, and
the token already existed in all seven themes. Worst case goes 3.82:1 to
**5.20:1** in Sentinel, and the two themes that already passed improve as well,
daywatch 5.07 to 6.51 and high contrast 9.17 to 12.03. Its five deferrals were
deleted rather than left true-when-written, because the lookup runs only after
a pair has already failed and a fixed entry is consulted by nothing.

**The seven predicted ratios matched the rendered readings exactly**, to two
decimals in all seven themes. The static arithmetic and the browser agree
without remainder here because the host row paints an opaque surface; where
they differed by 0.02 on `.severity_low` in daywatch, the backdrop was a
composited tint no theme declares.

**`.severity_exception` was the next six and is also fixed.** The single cause
the cluster suggested was real, and un-compositing the backdrop found it: each
theme's `--text-muted` is tuned to clear 4.5 against the bare surface, reading
4.61 to 5.53 there, and the pill's own 14% lighter fill lifts the backdrop just
far enough to put it under. That also ruled out the obvious remedy: lowering
the fill's alpha cannot rescue daywatch, whose `#6a635f` reaches only 4.61 on
the bare background and so stays short at any alpha. Moving to
`--text-secondary` clears every theme. Predicted before the run and measured
after, within 0.03 in all seven: Command 4.83, Sentinel 4.89, Guardian 5.64,
Fortress 5.67, Midnight Teal 5.97, Daywatch 7.36, High Contrast 10.94.

`.compliance-excluded` moved with it. It shares `--pill-muted-bg` **and**
`--text-muted`, so it is the identical pairing, and no contrast route renders a
compliance table, so it had never been measured; computed over declared
surfaces it read 3.55:1 to 4.22:1 at worst across the six dark themes. Fixing
one and not the other would have split a pair the stylesheet keeps together on
purpose.

**The residual is the `--bg-elevated` question already open**, not a new one:
on that surface alone Command reads 4.13 and Sentinel 4.18, while every other
surface clears. It now has four instances rather than two.

**The last two were fixed rather than carried, and `DEFERRED` is empty again**,
which is its intended resting state. `.severity_critical` in sentinel at 4.18
and `.severity_low` in fortress at 4.29 both already carried the brightest text
token their family offers, so neither was a token swap. What neither had
touched was its OWN translucent fill, which is exactly what lifts the backdrop
under its text: `#ef4444` became `#b91c1c` and `#22d3ee` became `#0ea5e9`, each
at its existing alpha.

Two alternatives were computed and both were ruled out by measurement rather
than by taste. Brightening sentinel's `--color-critical-bright` clears sentinel
alone at 6.10 while moving all fifteen consumers of that token and leaving four
themes at 4.49 to 4.65. Thinning the critical fill to 0.15 does not reach the
bar at all, sentinel stopping at 4.44.

Measured, all seven themes, against predictions made before the run and
matching **within 0.02 in all fourteen readings**. `.severity_critical`:
sentinel 4.75, daywatch 4.72, fortress 5.10, Midnight Teal 5.15, guardian 5.23,
command 5.27, high contrast 10.79. `.severity_low`: fortress 4.66, daywatch
5.01, sentinel 5.11, command 5.82, guardian 6.44, Midnight Teal 6.77, high
contrast 7.75. Daywatch pays for both, 5.15 to 4.72 and 5.31 to 5.01, because
its text is dark and a darker fill costs it; 4.72 is the smallest margin in the
set and still clears.

**All thirteen of the failures the fleet route exposed are fixed.** None was
carried, and the route that found them is now guarded by `.severity_low` in
`MUST_REACH`.

> **Second time a widening has paid like this.** The 2026-08-19 alpha-fill
> widening found eight; this route found thirteen. A documented gap is a
> choice, not a law, and the cost of looking has twice been about thirty lines.

**A fourteenth surfaced with the seventh route and is also fixed.**
`.host-row-error`, the SSH failure line, sits outside the expanded panel, so it
paints the same two surfaces `.host-row-failed` does and gave the same five
readings against `--bg-tertiary`: 3.82 Sentinel, 4.00 Fortress, 4.11 Midnight
Teal, 4.16 Guardian, 4.20 Command. It moved to `--color-critical-bright` with
its siblings and now renders 5.20 to 12.03 expanded and 6.50 to 14.52
collapsed, all fourteen readings matching predictions exactly.

**But the rule has two callers, and only one of them is on a page any contrast
route visits.** `fleet_outcome_row.rs:37` draws the same class inside
`.fleet-outcome`, on `--bg-secondary`, and **no route reaches the fleet apply
page at all**. That third surface was failing too - 4.35 in Sentinel - and
neither instrument could say so: the browser half never renders the page, and
the static half skips the rule because it declares no background of its own.
The fix clears it at 5.91, but that figure is **computed, not rendered**, and
so is the 4.35 it replaces.

**That left open a page rather than a rule, and it was closed the same day.**
Two routes now load the fleet apply page, one per state, and every rule on it
is measured: `.fleet-stat` plain and its three bands, `.fleet-outcome-name`,
`.fleet-outcome-target`, `.fleet-glyph-pending`, `.fleet-glyph-failed` and the
error line on `--bg-secondary`. All seven themes clear, worst case 5.05 in
daywatch, and every reading matched a prediction made before the run.

**The fixture was what had been hiding it, not the route list.** Every host
succeeded identically in the mock's `run_fleet_apply`, so the outcome row could
draw exactly one shape: three bands, the error line and two glyphs were
unreachable by any test that could have been written against it. db-01 now
fails there, which is not an invention but the fleet scan fixture's own
failing host under a different verb, and executed outcomes gained a non-zero
`failed`. That is the third instance of a fixture deciding what a check is
able to detect.

**One rule on the page stays unmeasured and is recorded rather than left to
look measured.** `.fleet-glyph-ok` needs a host that applied with nothing
failing, and the fixture has two hosts, one of which must keep failing to hold
the error line. It is `--color-good-bright` on `.fleet-outcome`, the same token
on the same surface as `.fleet-stat.score-good` at 6.58 to 14.10, so it is the
same pairing and the same reading - reasoning, not a measurement.

**Recorded against a repeat: a deferral whose reasoning surveys one call site
has not been checked.** The class is applied through a helper, so the question
is never "where does this selector appear in the CSS" but "what does every
caller of the function that emits it render". Cyan-700 `#0e7490` was rejected
in passing for a related reason: it reaches 4.83 at the best surface and would
have satisfied this file's best-case rule while sitting at 3.91 on
`--bg-tertiary`.

What had changed before that, and still stands, is that the
deferral's stated reason - a theme-wide retune of `--color-info` - may buy
nothing, and nobody re-deriving it from the tokens alone would ever find that
out.

**And the dot does not render what `validate_contrast.py` weighs.**
`.finding-dot` declares `background: currentColor` at `styles.css:4035`, later
in source than `.severity_critical` at `1082` and of equal specificity, so the
`rgba()` fill the static check composites is overridden: the element is a solid
8px disc of the text colour. At the `host-finding-dot` site no background is
set, so the tint does render, as a 6px disc with no text. Either way the pair
"this colour as text on this tint" is a pair the static parse declares and the
product never draws. That is the documented cost of a static parse rather than
a defect in it, but it bears on how the 2026-08-19 fixes should be read: of
the eight sites cleared, `.partial-row-badge-failed` x5 and `.status-error`
carry real text, and the `.severity_medium` one is a dot. The fix was still
worth making, because a coloured disc is subject to WCAG 1.4.11 non-text
contrast at 3.0 rather than 1.4.3 at 4.5, and 1.77:1 fails both.

**The two rules that do put real text over a translucent fill now have routes,
and have never been run.** `.partial-row-badge-failed` renders the word
"Failed" (`configure_section.rs:1407`) after an apply that partly failed, which
the default fixture does not produce: its apply succeeds outright and reaches
the done panel, so the route uses `apply_mode=mixed`, under which
firewall-hardening fails alongside a success. `.status-error` renders the
rejection message from a failed export (`compliance_tab.rs:174`), which needed
a new mock lever: `error_mode=export`, narrower than the existing `all` because
`all` also fails `get_compliance_reports`, leaving nothing to select and the
Export button disabled. Both are among the eight cleared on 2026-08-19 and
until now neither had been measured against a real ancestor by anything.

**Both are in `MUST_REACH`, and that is the load-bearing part.** Coverage
bought with a query flag is coverage a query flag can silently remove: a
renamed mode, a changed default fixture or a reordered confirmation flow would
return these routes to a state that renders neither badge, and every other
assertion in the file would stay green. That is the same failure `/analysis`
sat in for two runs.

**The first run of these routes failed on a drive step, as predicted, and the
apply route passed.** All seven themes failed at the export drive on
2026-08-20, before any ratio was computed, so no listing exists yet. The
hardening route under `apply_mode=mixed` is verified by that same run: it runs
before the export route, so `runApply` completed and `.partial-panel` became
visible inside its wait.

**The defective step assumed a state instead of asserting one.** It clicked the
first framework toggle to enable Export, but `compliance_tab.rs:28` starts with
`vec!["cis"]`, so that toggle is already pressed and the click DESELECTED it,
emptying the selection and leaving Export disabled. The step now ensures the
toggle is pressed and asserts it, which is what the analysis suite already does
for these `aria-pressed` controls. **A drive step that toggles depends on the
state it finds; one that asserts does not**, and the difference is invisible
until the default changes or a route arrives at the screen differently.

Worth separating from the colour work: that was a failure to reach the subject,
not a finding about it.

**Both badges now have a measured ratio against the ancestor that painted, for
the first time.** The run after the fix passed all seven themes, at 64 pairings
each and 5 over a partly translucent fill, so the widening's own guard is off
its floor of 1. Every reading clears 4.5.

| theme | `.partial-row-badge-failed` | `.status-error` |
|---|---|---|
| sentinel | 5.02:1 | 5.89:1 |
| fortress | 5.35:1 | 6.22:1 |
| midnight teal | 5.40:1 | 6.14:1 |
| guardian | 5.45:1 | 6.31:1 |
| command | 5.66:1 | 6.44:1 |
| daywatch | 5.70:1 | 6.79:1 |
| high contrast | 8.33:1 | 13.55:1 |

**The full GUI suite is green on all six distributions at `2bc8bd76`**: 157
passed, 0 failed on each of arch, debian, ubuntu, fedora, rhel and opensuse,
2.9 to 4.5 minutes apiece. That covers the two changes this arc made outside
`contrast.spec.js` and never exercised by a `--grep T-CONTRAST` run: `runApply`
moving into `helpers.js`, whose only four callers are `hardening.spec.js`
T-APPLY-01..04, all green; and the `error_mode=export` branch in
`tauri-mock.js`, which no other spec sets.

**Two of those six results cost more than they should have, for reasons that
were not the code.** Running the six with `--parallel` starved them: five
concurrent containers each booting a 2.5 MB WASM bundle exceeded
`waitForApp`'s 30-second timeout, and arch failed a test it had just passed
serially. Killing that run left the debian and ubuntu images with an
interrupted `dpkg` and unmet dependencies, so neither executed a single test
across the next two attempts, each time reporting a container error that reads
nothing like a test result. **On this machine the GUI suite is serial**, and
its aggregate cost is about twenty minutes rather than four. The repair is
`dpkg --configure -a` plus `apt-get -f install` inside the affected container,
which is far cheaper than the debootstrap rebuild it looks like it needs.

**The question that reading raised is now answered from the tool rather than
from prose.** `validate_contrast.py --explain <selector>` prints every theme's
figure for a pair, and for an alpha background it prints the SPREAD: the best
surface the theme declares, the worst, and which each is. The two instruments
can therefore be compared without anyone remembering a number.

**Every rendered reading falls inside its own theme's static spread, in both
selectors and all seven themes.** The 5.02 on sentinel that prompted this sits
inside 3.86 to 5.54. It was below the documented 5.54-to-6.11 range because
that range was the best case across themes, which is not the quantity a
rendered reading should be compared against at all. **The two checks agree
everywhere, in exactly the sense the design intends: the browser lands between
the worst and best surfaces, because it resolves the one real ancestor.** The
only readings outside are `.status-error` on sentinel and command, over by
0.01, which is two pipelines rounding the same value to two decimals rather
than a disagreement.

**The spread exposes something the headline figure hides, and it is a question
for the maintainer rather than a defect.** For both selectors the worst surface
is `--bg-elevated` in six of seven themes, and it falls below 4.5 in five of
them: `.partial-row-badge-failed` reads 3.86 on sentinel, 4.05 on fortress,
4.10 on default, 4.22 on guardian and 4.29 on command, with `.status-error`
within a few hundredths of the same. So both pairs would fail WCAG if they ever
rendered on an elevated surface. On the routes measured they do not, which is
why the browser half reads 5.02 and above.

**For these two selectors that surface is unreachable, and the question is
closed by ancestry rather than by a route.** It was recorded here as a product
question about modals and cards; it is not one, because each selector has
exactly one render site and each site's ancestry is fixed.
`.partial-row-badge-failed`
(`configure_section.rs:1407`) sits inside a `<Card class="partial-panel">`, and
`.card` paints an opaque `--bg-secondary`, so nothing above the Card can lift
its backdrop, a modal included. `.status-error` (`compliance_tab.rs:174`)
resolves through `.compliance-actions`, `.compliance-tab`, `.tab-panel` and
`.app-main`, none of which declares a background, to `body` at `--bg-primary`,
the best surface in its own spread. Of the thirteen rules that paint
`--bg-elevated`, eleven are hover or focus states on controls, a scrollbar
thumb, a swatch or an action bar; the only one that could hold arbitrary
content is `.modal`, and neither site is reachable from it. **A route measures
what one route draws; an opaque ancestor decides what any route can draw**, and
that is why walking the chain answered in minutes what no sweep had settled.
Both rules carry the finding as a comment naming the dependency it rests on, so
a future wrapper that breaks it is visible at the rule.

The tradeoff this file's docstring accepted in the abstract, when it chose
best-case over worst-case and recorded 61 as the worst-case count, is therefore
still live in general and no longer has these two as its concrete form.

**Asking the same question of the other selectors found nine failures that were
shipping.** The `--bg-elevated` residual was recorded for four selectors, the
two above plus `.severity_exception` and `.compliance-excluded`, on one shared
justification: no route renders them there. For `.severity_exception` that was
false when it was written. `host_panel.rs:42` renders it, and every other
`.severity_*` class, inside a `<summary>`, and `summary:hover` painted
`--bg-elevated`. So the hover state of every host-panel finding subgroup put
four of the six severity pills under 4.5: `.severity_low` 3.94 in fortress and
4.42 in sentinel, `.severity_exception` 4.13 in command and 4.18 in sentinel,
`.severity_critical` 4.19 in sentinel with 4.43 in default and fortress, and
`.severity_info` 4.28 in command and 4.40 in sentinel.

**The resting half of that model was checked against a real browser before any
of it was believed.** The arch run records `.severity_exception` at 5.97 on
`rgb(47,55,65)` in default on the fleet host panel. Compositing
`--pill-muted-bg`, `rgba(148,163,184,0.14)`, over `--bg-tertiary` `#1e252e`
gives `rgb(47,55,65)`. The summary paints the tier the bare rule says it does,
so the hover tier is the one the bare hover rule said too.

**Neither check could see it, and the reason is specific rather than general.**
The static half enumerates all four `--bg-*` tiers for a translucent fill and
reports the best, so the one tier a parent actually paints is filed as a worst
case no route reaches. The browser half resolves the real ancestor but has no
hover step. Note what this is NOT: the static half handles a hover fill
correctly whenever one rule declares both the fill and the text over it, which
is why `.tab-button:hover`, `.segment-btn:hover`, `.plugin-row-help:hover` and
`.config-clear-btn:hover` are sound, the lowest being 5.23 in guardian. **The
shape it misses is a parent's hover fill under a child's own fill**, where the
two live in different rules and only the cascade joins them.

**The fix is at `summary:hover`, which now moves the text instead of the
backdrop**, the idiom `.advanced-disclosure-summary:hover` already used. That
removes the app's only parent-hover backdrop lift, so the shape has no second
instance to find today.

**Asking it once more of the modals found two failures that were not on hover
at all.** No contrast route has ever opened a modal, and `.modal` painted
`--bg-elevated` permanently. Of the thirty classes rendered inside the three
modal components, only three appear in the static corpus, because a rule that
declares a colour and no background is left to the browser half by design, and
for these the browser half never arrives. The two that carry critical red both
failed, permanently, in the same five themes:

- `.exception-modal .modal-error`, its text over its own translucent fill over
  the modal: 3.86 sentinel, 4.05 fortress, 4.10 default, 4.22 guardian, 4.29
  command. Identical colour and fill to `.partial-row-badge-failed`, which is
  why the spread matches it exactly, and the third user of that combination
  was the one sitting permanently on the surface the other two can never
  reach.
- `.restore-error`, colour-only, on `--color-critical` rather than
  `--color-critical-bright`: 3.25 sentinel to 3.57 command. It was missed by
  the sweep that moved five other rules to the bright token precisely because
  it renders only inside the rollback modal.

**`--bg-elevated` cannot carry critical red at 4.5 in this token system, and
both narrower fixes were computed before that was concluded.** Darkening
`--color-critical-bg` to rgba(185,28,28,.15), the value `.severity_critical`
already uses, leaves fortress at 4.46 and sentinel at 4.27. Using
`--color-critical-bright` bare leaves sentinel at 4.42. Only moving the modal
to `--bg-secondary` clears every theme, and it still needs the bright token
alongside it, because the base token reads 4.35 in sentinel even there. After
both: `.modal-error` 5.00 to 8.32, `.restore-error` 5.91 to 13.68,
`.restore-warn .restore-error` 5.55 to 15.02, title and body text 13.81 to
19.80, `.field-input` 15.14 to 21.00.

**The raised read survives the tier drop for free.** `--border-strong` is the
same value as `--bg-elevated` in all six dark themes, so a 1px edge carries the
elevated tone as an outline instead of as the surface the text sits on.
`.exception-modal .field-input` moved down a tier with its panel, to keep the
one-tier gap that makes a field read as a well rather than as part of the
dialog.

**Neither check can confirm any of this, which is the same boundary that hid
it.** The static half still prints the identical four-tier spread for
`.modal-error`, because it enumerates surfaces as hypotheses and does not know
which one a parent paints; its `--bg-secondary` point, 5.00 in sentinel, is now
the real reading rather than the `--bg-elevated` one, and nothing in the output
says so. The browser half would settle it in one assertion by opening a modal
on a contrast route.

**That route now exists, and it is two routes rather than one.** Added
2026-08-21: `hardening, rollback modal` reaches `.restore-error` on the default
fixture, whose rollback reports divergences on the success path, and `analysis,
exception write failed` reaches `.exception-modal .modal-error` under a new
`error_mode=exception`, which fails `add_policy_exception` alone. `all` cannot
serve it, because `all` also fails `run_scan` and there is then no finding to
accept and no modal to fail a write in. Both selectors are in `MUST_REACH`,
separately: they fail independently, and a route reaching a modal is not the
same claim as a route reaching the rule the modal was opened for.

**Both routes carry a `scope`, and the reason is a false PASS rather than
noise.** `backdropStack` walks ancestors, and `.modal-backdrop` is an overlay
rather than an ancestor of the page it covers, so with a dialog open every
element behind it would be weighed as though undimmed. Compositing
rgba(0, 0, 0, .5) over text and fill alike drives both luminances toward zero
while the +0.05 in the ratio stays where it is, so the rendered contrast behind
a backdrop is WORSE than the number the sweep would report. Everything behind
the dialog is already measured, undimmed and correctly, by the route it belongs
to. The scope is resolved once and a scope that matches nothing throws, because
the alternative is a silent whole-document sweep that reports MORE pairings
than before while measuring the wrong thing.

The containment test is applied to matched elements rather than by querying
under the root, which looks like the longer way round and is not:
`.exception-modal .modal-error` is written from an ancestor the root itself
carries, so `root.querySelectorAll` would match nothing for exactly the rule
these routes exist for while every other rule went on matching. That failure is
silent and reads as a clean sweep.

**THE FIRST RUN OF THESE ROUTES PASSED WHILE MEASURING THE WRONG THING, and
that is the finding worth keeping.** It collected fourteen `.restore-error`
pairings, two per theme, and `--color-critical-bright` `rgb(248,113,113)` was in
none of them. Both instances the default fixture draws are overridden by a more
specific rule: `.restore-warn .restore-error` in amber, and
`.rollback-divergence-unchecked .restore-error.divergence-detail` in muted grey.
`rollback_modal.rs:271` and `:293` render the rule in its own colour and both
sit behind `err.map(...)`, so nothing draws it until a file or a reload actually
fails, and the fixture restored everything successfully. The `.restore-error`
half of `04930f71`, the 3.25 sentinel reading and the worse of the two failures,
was the half the route could not see.

**`MUST_REACH` cannot catch this and should not be expected to.** It asks
whether a SELECTOR was measured, `s.includes(selector)` over the rule text, and
not which rule won the cascade for the element. `.restore-error` satisfied it
from an instance whose colour came from somewhere else entirely. That is the
same defect as `.tab-button.tab-active` in decision 2 of `contrast.spec.js`,
arriving from the opposite direction: there a rule was measured against a
backdrop another rule had overridden, here a rule was credited for a colour
another rule had overridden.

The fix is `rollback_mode=partial`, following the `apply_mode=mixed` precedent
rather than flipping the default fixture, which would have bought the failure
path by giving up the success path. The route now asserts
`.restore-fail .restore-error`, the instance whose colour can only come from the
rule itself. **The third instance of an all-success fixture hiding the branch a
check existed to weigh**, after the identical-counts case and the fleet-apply
outcome row.

**The eyeball half of it IS now closed, and it was closed by a different
instrument.** On 2026-08-21 the theme sweep gained a sixth state, the rollback
modal, so `.modal` is rendered in all seven themes on all six distributions,
44 screenshots per distribution instead of 37. Before that the entire modal
surface had been captured in exactly one theme, as a by-product of
`T-DIVG-03`'s geometry check, which parameterises over viewport width and not
over theme: sentinel, the worst of the five failures, had no modal shot at any
width. The shots say the dialog still reads as raised a tier lower, most
clearly in High Contrast, where `--border-strong` carries the separation as a
bright outline and the surface itself is near-black.

**That is a rendering, not a measurement.** A screenshot answers whether the
dialog reads as raised and answers nothing about the ratio. Two questions were
being carried as one, and the screenshots settled only the cheaper.

**The ratios were settled the same day, by the two contrast routes below, and
every prediction `04930f71` made held.** Measured on all six distributions,
`.restore-error` 5.91 to 13.68 against a predicted 5.91 to 13.68,
`.restore-warn .restore-error` 5.55 to 15.02 against a predicted 5.55 to 15.02,
and `.exception-modal .modal-error` 5.02 to 8.33 against a predicted 5.00 to
8.32. Five endpoints of six matched to the digit and the sixth by 0.01. Arch
and openSUSE agree exactly on all five dark-theme `.restore-error` readings,
5.91, 6.16, 6.26, 6.30 and 6.52, so this is a property of the stylesheet and
not of one container.

**The sweep's own ordering is a constraint worth recording**, because it is
invisible until something breaks on it. Each state now applies its own theme
instead of the loop applying one after `setup`. `.modal-backdrop` is
`position: fixed; inset: 0` at `z-index: 50`, so once a modal is open the theme
selector is underneath it and `selectOption`'s actionability check cannot reach
the control; the modal state must therefore theme BEFORE it opens the dialog,
while the other five must theme AFTER their `loadApp`, `page.goto` taking any
earlier selection with it. No single position in the loop satisfies both. A
seventh state that opens anything over the sidebar inherits this.

**And the visual read of the new hover affordance is unverified.** The
measurement is settled and the failure is gone by construction, but no
container run has looked at a summary hovering since the change, so whether a
colour move alone still reads as hoverable on a row whose chevron does not
move is an eyeball question that no number here answers.

**`/analysis` is now scanned rather than bare**, which was worth doing on its
own: the first two container runs loaded it into its empty state, so it
contributed its chrome and none of its content. `.finding-group-count` is in
`MUST_REACH` as the tripwire, because a `runScan` that silently failed would
return the route to that state with every other assertion still green.

**The third run confirms it took and shows the gain is small.** All seven
themes reach `.finding-group-count`, and the route trades `.empty-state-hint`
and `.empty-state-title` for `.finding-group-count`, `.findings-count` and
`.finding-tag`. Three rules, not the notable rise predicted alongside the
change: a findings table of eight rows collapses to a handful of distinct
rules, because pairings are deduplicated by selector, colour and backdrop
rather than counted per element. Per-theme totals are 38 everywhere, daywatch
having come down from 39.

**The drift is now measured across three runs and is not explained by any
change made to this file.** Run 1 to run 2 gained two `.tab-button` entries on
`/analysis`; run 2 to run 3 lost one of those and lost `.btn-secondary` on the
hardening route, which nothing in that commit touched. The leading hypothesis
is the pointer: Playwright leaves the mouse wherever the last click put it, so
`:hover` matches a different element between runs and changes both which rules
match and what colour they compute. Run 1 collected `.tab-button:hover` and no
later run has.

**The pointer is now parked at the viewport corner after each route's setup and
before each sweep.** The corner is arbitrary and fixed, which is the point: it
buys reproducibility rather than the absence of hover.

**The fourth run came back verbatim identical to the third.** All 273
measurement lines across all seven themes match exactly, ratios and computed
colours included, not merely the selector sets. That is the first consecutive
pair of runs with no drift, following two consecutive pairs that both drifted.

**It is evidence for the hypothesis and not proof of it.** One stable pair
where the two before it were unstable is consistent with the pointer having
been the cause; it does not exclude a cause that happened to be quiet. The
claim that has actually been earned is the narrower one, and it is the useful
one: **this check is now reproducible run to run, so a future listing that
differs means something changed rather than meaning nothing.** That property is
what makes a retained baseline worth keeping at all. If drift ever returns, the
remaining candidate is layout timing, collection being gated on
`getClientRects()`.

**What neither vacuity guard can do is see this at all**, which is why three
runs of it passed unremarked. `MINIMUM_PAIRS` answers "did the sweep collect
nothing" and `MUST_REACH` answers "did it miss these named selectors". Drift is
a relative property and both are absolute checks, so a different 38 reads
exactly like the same 38. It became visible only because two listings were kept
side by side. A within-run check comparing the selector set across the seven
theme cases would detect it for free, and is not written, because theme blocks
can legitimately introduce rules that match in one theme and not another, so
plain set equality would fail for a correct reason.

**What that suite drives is not the desktop application.** It serves the same
wasm bundle the desktop embeds, with `gui-tests/tauri-mock.js` injected ahead of
it to stand in for `window.__TAURI__.core.invoke`. So the markup, the
behaviour, the routing and the theming are exercised, and **the Tauri command
bodies, `pkexec` and the CLI beneath them are not reached by it**: the frontend
is asked what it renders for a given reply, never whether the backend would
send that reply. The mock's field names are a hand-written copy of the Rust
structs, so it can drift from them, and a drift empties a view rather than
failing loudly.

**The mock and the real command set are not the same set.**
`src-tauri/src/commands.rs` carries 32 `#[tauri::command]` functions;
`gui-tests/tauri-mock.js` carries 34 distinct commands over 38 `case` labels,
four of them appearing in both of the mock's two switch blocks
(`get_checkpoints`, `run_apply`, `run_apply_dry_run`, `run_scan`). The two lists
differ in both directions. `get_host_history` and `run_deep_scan` are real
commands the frontend calls (`crates/hardener-ui/src/tauri_bindings.rs`, from
`components/host_panel.rs` and the deep-scan action), and until 2026-08-18
neither had a mock case: a Playwright run that reaches either path falls
through to the mock's `default:` arm, which throws an "Unknown command" error
naming the command it could not answer. `get_host_history` now has one, so
`run_deep_scan` is the only real command the mock cannot answer.

**The two are not in the same position, and this paragraph said they were until
2026-08-16.** It claimed no spec file mentions either command name, "so no test
reaches that path to trigger the throw either; both are simply untouched by the
browser suite". The premise is true and **the inference does not hold**: a spec
never names an IPC command that a component fires for it.

- `run_deep_scan` is genuinely untouched. It sits behind a button no spec
  clicks, and both call sites `match` on the result, so a run that did reach it
  would surface an error rather than silence.
- **`get_host_history` is reached on every fleet row expand**, which
  `T-FLEET-05`, `T-FLEET-08` and `T-FLEET-09` all perform. `HostPanel` fires it
  from a `spawn_local` on mount and takes the result through
  `.unwrap_or_default()` at `host_panel.rs:85`, so the mock's throw became an
  empty `Vec` and the panel rendered its no-history state whatever the backend
  would have returned. The mock now answers it, with rows for `web-01` and
  none for `db-01` so both branches are reachable from a real answer. **What
  has not changed is the reason it went unnoticed: the per-host history panel
  is entered by three tests and asserted on by none.** Adding the handler adds
  no case, so the suite total does not move; the assertion that would make the
  rail visible to a run is still owed, and until it exists a mock that stopped
  answering would be swallowed exactly as the throw was.

The correction matters beyond the one command: "no spec mentions it" was being
used as a proxy for "no test reaches it", and for anything a component invokes
on mount the two are unrelated questions.
`export_report`, `run_scan_filtered` and `run_scan_with_options` run the other
way: all three have a mock case and none exists in `commands.rs`, so they
answer a command the frontend never sends. `scripts/validate/validate_gui_mock_fixtures.py`,
the one validator that reads the mock's payload shapes at all, invokes 12 of the
32 real commands (`run_scan`, `run_apply`, `list_plugins`, `run_rollback`,
`run_fleet_scan`, `generate_compliance_report`, `add_policy_exception`,
`remove_policy_exception`, `get_checkpoints`, `get_checkpoint_detail`,
`get_scan_history`, `get_host_history`) to do it, so it does not catch the one
uncovered real command or the three dead mock ones. It is what caught this one:
the probe was added before the handler and reported `Unknown command:
get_host_history`, which is the only reading in this document produced by a
check written to fail first.

The practical reading for an operator: the command-line tool is the surface this
release has the deepest evidence for; the desktop's interface is now exercised
automatically against a stubbed backend, and the path from a button to a
privileged command is still checked by eye.

**That eye-check was carried out on 2026-08-16**, driving the real desktop app
against the real backend in a headless compositor, and it is worth recording
what it changes and what it does not. It found five interface defects the
then 154-test suite could not: three of them on the Scheduler and Fleet Apply
screens, which no screenshot in the corpus covers, and one of those was a
plugin naming inconsistency that a green suite had rendered past for months. It
also produced one **retracted** finding, where the instrument rather than the
application was at fault.

None of that moves the paragraphs above. A person driving the application once
is not coverage, the evidence ledger still has no desktop row, and CI still
excludes both crates. What it does establish is that the eye-check named here is
a thing that has actually happened rather than an intention.

**The screenshots were the oldest evidence in this project and nothing checks
their age. They were replaced on 2026-08-18.** The previous set dated from
2026-07-27 (`3cb7d762`), with 54 commits to `crates/hardener-ui/src` and 20 to
`styles.css` in between, and two of them were substantively wrong rather than
merely old: Fleet Apply and Scheduler both listed plugins by raw identifier,
which is the naming inconsistency the 2026-08-16 eye-check found and this
release fixed, so the front page advertised a defect that was gone.

All seven subjects were re-captured at `653b4ff1` by driving the desktop app in
the headless sandbox, and **sixteen further images record states no single view
reaches**: the finding detail expander, the per-control compliance view, the
scan-history timeline, the hardening advanced override, the dry-run preview,
the checkpoint timeline and its detail and rollback confirmation, the expanded
host panel, the armed delete, the add-host and ad-hoc forms, the Fleet Apply
rollback tab, and the Scheduler with its custom-cron field, its notification
channels, and the toggle both on and off.

**Three things this does not establish, and one it does.**

- **The rollback result stage is not photographed.** Its divergence rows render
  only after a restore actually executes, which on the capture host means
  overwriting `/etc/ssh/sshd_config` for a screenshot. The confirm stage is
  captured; the stage the `T-DIVG-*` tests assert on is not.
- **The dry-run preview reads "Nothing to apply"** on both the Secure and the
  High profile, because the capture host is already hardened and PAM findings
  are manual-only by design. That is an honest reading of that host and not a
  demonstration of the feature.
- **Nothing checks any of this next time.** `validate_markdown_links.py` asks
  that the path resolves, and an image that resolves is not an image that is
  current. The same drift starts accumulating from today.

**And it began the same week, and was closed the same day.** The
compliance-score reconciliation landed after the 2026-08-18 capture and changed
what that screen renders: the per-framework row used to print a graded score
beside a binary fraction and now prints one number twice, with an unassessed
count that did not exist when the image was taken. `dashboard.png` was
**recaptured at `b263ae10`** in the same headless sandbox and against the same
scratch `XDG_CONFIG_HOME`, so it is current rather than known-stale. The other
twenty-two are untouched by that change, and `analysis-compliance.png` in
particular, because the compliance tab already read the report's score.

**The recapture is also the only end-to-end evidence the fix has.** No
Playwright case asserts the dashboard's per-framework row, so the new markup is
covered by nothing that executes; what the image shows is ten rows whose
percentage equals the fraction beside it, driven by the real backend rather
than the mock. The starkest pair is worth keeping in words, because the image
is the only place it is recorded: SOC 2 read **63 per cent beside 0/5** before
and reads **0 per cent** after, so the old dashboard published a passing-looking
figure for a framework where nothing passed. ISO 27001 read 80 against 4/93 and
now reads 4 with **86 unassessed** stated beside it.
- What it does establish is the Scheduler notes from `a5ca6d03` and `3fcc75a8`,
  seen present with scheduled scanning off and absent with it on, in the real
  application against the real backend rather than through the Playwright mock.

**The capture procedure changed, and the reason is a defect in the old one.**
The app reads `~/.config/linux-hardener/config.toml`, so the Scheduler's
Notifications section renders whatever addresses that file holds. `3cb7d762`
tried to handle this by editing the recipient in the running app, and reached
Recipients while leaving a real personal address in From address, where it has
sat in the published image ever since. The new captures were taken against a
scratch `XDG_CONFIG_HOME`, so the file holding personal data is never read and
every address on screen is the field's own placeholder.

**Replacing the image does not remove the old one from git history, and the
decision on 2026-08-18 was to leave it.** One blob carries it, the one
`3cb7d762` was written to replace, reachable from 33 commits and from both the
`v1.5.0` and `v1.5.1` tags. Stripping it rewrites 871 commits, and this corpus
cites SHAs in nearly every document, so the cure changes more facts than the
disease. A force-push would not finish the job either: unreachable objects stay
fetchable by hash on both forges until support purges them. The exposure is
pixels in an image rather than text, so no code search reaches it. **This is
recorded as a decision taken rather than an oversight**, so a later session does
not rediscover the blob and rewrite history for it.

---

## Does configuration load in the order the docs promise?

The sequence tests added on 2026-08-20 drive `ConfigLoader::load()` through
real files and a real seam for the first time, in
`crates/hardener-core/src/config_loader/tests.rs` and
`crates/hardener-core/tests/config_env_precedence.rs`. What follows is what
they reach and what they still leave open, each measured the same day.

**The real root check is never exercised.** `an_unprivileged_session_reads_the_user_config_the_root_rule_would_skip`
and `a_root_session_skips_the_user_config_an_unprivileged_one_reads` prove the
rule through the `with_running_as_root` seam, both directions, against a
directory the test owns. `is_running_as_root`'s real body,
`nix::unistd::geteuid().is_root()`, is called by no test, because the suite
runs unprivileged and the seam exists precisely so the rule can be asked
without it. `pkexec` running this tool as root from an unprivileged session is
the entire reason the rule exists, and nothing here has run as the root that
matters.

**The `#[cfg(not(feature = "system"))]` branch of `is_running_as_root` returns
`false` and is dead in every build this workspace performs.** Nothing runs
`cargo test --no-default-features`. `hardener-compliance` is the one crate
that builds `hardener-core` with `default-features = false`, and it never
calls `ConfigLoader::load()`, so the branch is unreachable from a running
program as well as from a test.

**The system config's real path is still observed by no test.** The seam in
`with_system_config` proves the layer merges, and
`system_config_path_for_falls_back_to_the_real_path_when_unset` now guards the
fallback from that seam to `Self::system_config_path()`, so an unset seam is
provably still the real path rather than `None`. What neither test does is
read `/etc/linux-hardener/config.toml` itself: nothing in this suite writes to
that path or runs against a host where it exists, so the resolved default is
pinned and the file it names is not.

**`[compliance.not_applicable]` has no documented cross-source merge rule, so
there is nothing to test against.** `merge_compliance` merges the table per
control id, the same shape `merge_plugin` gives directives and exceptions:
a later source naming one control of a framework does not discard an earlier
source's exclusions for other controls of that framework.
[File locations and precedence](configuration.md#file-locations-and-precedence)
states the merge rule for directives, exceptions and `enabled`, and states
nothing for `[compliance.not_applicable]`, so a reader has no promise to check
the code against and no test enforces one.

**The 1 MiB size cap is per file, not per merged config.** Two files each
comfortably under `MAX_CONFIG_SIZE` that together exceed it are not caught:
`load_from_file` stats and rejects one file at a time, before any merge runs.
That is the opposite of the directive and exclusion caps, both of which are
checked cumulatively after the merge for exactly this reason, and both of
which have a test that splits its fixture across two sources to prove it
(`two_files_each_under_the_directive_cap_are_refused_together`, driven through
two real files and `load()`, and
`the_exclusion_limit_admits_the_maximum_and_refuses_one_more`, split across
`merge_compliance`'s two arguments). The exception cap is enforced the same
cumulative way in `merge_plugin`, beside the directive cap, but its own test
does not split across two sources the way those two do. No test splits a
fixture across two sources for the size cap either, and none of the four
caps' tests establishes what an operator with two large but individually
compliant files should expect.

---

## What runs automatically, and what needed a person?

**Nothing automated rises above a real-filesystem test.** `.github/workflows/ci.yml`
executes no `#[ignore]`d test and no shell suite. Every live-oracle result cited
anywhere in this project was produced by a person starting a container by hand,
and the date of the last such run is in
[distribution-validation.md](distribution-validation.md).

**A green CI run is a weaker reading than the workspace suite**, because the two
crate exclusions above make CI's set strictly smaller than the workspace total.
CI runs `cargo test`, whose comparable figure is **2052 passed, measured
2026-08-18**, which is what [evidence-ledger.md](evidence-ledger.md)'s baseline
records; `cargo nextest run --workspace` read 2046 the same day, the difference
being the six doctests nextest does not run. Earlier readings of the same growing
suite were 1693 on 2026-08-07, 1815 on 2026-08-08 and 1991 on 2026-08-12. **The
1991 stood here, and in the ledger, after the baseline had moved on**;
re-measure this figure rather than copying it forward again.

**The 42 tests the workspace suite skips, and what each needs:**

| What it needs | Count | Where |
|---|---:|---|
| A live SSH host (`SSH_TEST_HOST`) | 27 | `crates/hardener-core/tests/ssh_executor_tests.rs` (14), `crates/hardener-plugins/tests/ssh_integration_tests.rs` (9), `crates/hardener-cli/tests/batch_ssh_integration.rs` (4) |
| Root, and permission to change the host it runs on | 8 | one per plugin, in each plugin's integration test file |
| The nftables fixture container | 3 | `crates/hardener-plugins/tests/ssh_integration_tests.rs` |
| A named firewall backend already installed | 3 | `crates/hardener-plugins/tests/firewall_tests.rs` |
| A person to look at the output | 1 | `crates/hardener-cli/src/commands/batch/tests.rs` |

The `ssh_executor_tests.rs` cell grew from 12 to 14 on 2026-08-11, when the
mutation-testing pass added two more `#[ignore]`d tests, `read_dir` and
`legacy_description`, while killing survivors in `executor/ssh.rs` (see
[evidence-ledger.md](evidence-ledger.md)); that is the whole of the 40-to-42
change.

None of the 42 runs in CI. A `cargo test --workspace` run reports a larger
ignored figure than 42, because it also builds a documentation-test binary for
each of the workspace's nine library crates and seven documentation examples are
`#[ignore]`d as well.

**Coverage: 60.09 per cent is what the release ships, 79.11 per cent is what the
release tests.** The gap between the two figures is the desktop application. The
full per-crate and per-file picture, and the six limitations of how it was
measured, are in [the coverage baseline](coverage-baseline.md).

**Mutation testing has run on three of the workspace's eleven crates.** Coverage
says which lines a test reaches and cannot say whether the test checks
anything; mutation testing is the question that separates the two. A full pass
against the three integrity-critical crates, `hardener-common`,
`hardener-state` and `hardener-core`, completed on 2026-08-11 at `56245cc7`:
700 mutants, 430 caught and 161 missed on the first reading. A day of kill
commits against that survivor list, `269dadc2` through `dd85255f`, brought it
to 580 caught and 10 missed, 2 per cent of viable mutants, and found two
production bugs along the way rather than only test gaps: `SshExecutor`
classified a device as a regular file
(`crates/hardener-core/src/executor/ssh.rs`, fixed in `fb98c044`), and the same
file misread `stat` output entirely under a non-English locale
([issue #155](https://github.com/tidynest/linux-hardener/issues/155), fixed in
`dabbb1fe`). Full detail, cluster by cluster, is in
[evidence-ledger.md](evidence-ledger.md).

**Seven survivors remain, identified but not resolved.**
`hardener-common/file_utils.rs` keeps one, recorded acceptable because a
comment can never match a directive name. `hardener-common/logging.rs` keeps
one, recorded acceptable because the process-global logger it installs panics
if called twice, so a test exercising it would poison every other test in the
binary. `hardener-core/executor/ssh.rs` keeps three: two are unreachable over a
real connection, because a signal-killed remote command exits through the
local ssh client, which never reports the sentinel the mutant touches; and one
needs a change to the test fixture rather than to the code.
`hardener-core/config_loader.rs` keeps one, provably equivalent under a non-root
test runner. `hardener-core/testing.rs` keeps one, a test double's own method,
provably equivalent.

**This paragraph read "ten" until 2026-08-16, and the three it lost are worth
naming, because each was recorded here with a reason that turned out to be
wrong rather than merely old.** `hardener-core/inventory.rs`'s `load` and `save`
were said to need "a signature change reaching the CLI and two Tauri commands,
judged a larger change than two mutants justify"; no signature changed, and
`crates/hardener-core/tests/inventory_shared_path.rs` pins both by controlling
the ambient config root instead. The fourth in `executor/ssh.rs` was recorded as
provably equivalent, which held only for well-formed `stat` output, and this
parser reads whatever a remote host sends. Full detail in
[evidence-ledger.md](evidence-ledger.md).

**The seven is an enumeration of the survivors described above and in the
ledger, not a fresh reading.** The last measured pass is 2026-08-12; only a
`cargo mutants` re-run confirms it.

**Seven of the eleven workspace crates have never been mutation-tested at
all:** `hardener-plugins` (all eight plugins), `hardener-compliance` (the
compliance renderers), `hardener-cli`, `hardener-scheduler`,
`hardener-types`, `hardener-ui` and `src-tauri` (`linux-hardener-desktop`, the
desktop). `hardener-distro` was
mutation-tested once, before the Phase 3 deletion that removed the dead module
holding every one of its survivors; that reading no longer corresponds to the
crate as it stands and is kept in the ledger only for the `-j 1` finding it
paid for, not as a current figure. Until the plugins and the compliance
renderers have been mutation-tested, no figure anywhere in this project
distinguishes, for that code, a line a test pins from a line a test merely
visits.

**Cross-document fact checking holds what is registered, and quantities only.**
`validate_cross_document_facts.py` compares a fact stated in more than one
document against the site that owns it, and `crosscheck.py`, which lives
outside this repository in `~/Documents/DEVELOPMENT/prose-sweep/`, is what
finds candidates for it. Six limits, four of them deliberate and two of them
discovered blind spots, the second found on 2026-08-20 by the defect it let
through:

- **It reads quantities, not claims.** "Five distributions" is in scope. "The
  suite has never been run against a booted host" carries no number and is
  invisible to both tiers.
- **The gate holds only what is registered.** Only one of its three facts grew
  from a confirmed survivor of a sweep: the GUI Playwright test count. The
  compliance framework count predates `crosscheck.py` entirely, added from an
  earlier throwaway probe, so the registry is evidence-driven only by the one
  fact that happens to be, not by design. A fact nobody has swept for, or
  swept for and not registered, is not held.
- **A registered fact can be sourced from the document it validates, and one
  is.** `gui_playwright_test_count` reads the row marked **current** in
  `distribution-validation.md`, because Playwright generates the count at
  collection time and no tree definition of it exists. So the gate confirms
  that the consumer sites agree with the row and **cannot ask whether the row
  is true**. On 2026-08-20 three documents called 156 current while the suite
  read 157, for two days, with this validator green throughout and
  `crosscheck.py` unable to see it either, 157 standing in exactly one tracked
  file where the sweep needs a key to disagree across more than one.
  Mitigated, not closed, by registering the **call-site count** as a third
  fact on 2026-08-20: `test()` call sites in `gui-tests/tests/*.spec.js` are a
  tree quantity that moves whenever a test is added, and they sit in the same
  paragraph as the case count, so the tree now turns that paragraph red.
  **One shape still defeats it**: a parameterised site gaining cases moves the
  total without moving any call site, so an eighth theme would take the total
  past 160 with the call-site count unchanged. Three controls were observed
  firing, including a `test.skip` variant, which would disagree with `--list`
  and is refused by name rather than miscounted.
- **The sweep is not scheduled.** Nothing runs it. It was last run on
  2026-08-20, returning seven clusters and no defect: the one real staleness
  that day was found by asking whether the largest number was the current one,
  which is a question the sweep has no way to put.
- **A stale pointer is found only when it carries a number.** The defect it
  found on 2026-08-19 was caught because the sentence contained "154". The
  same sentence phrased "superseded by the August reading" would be invisible.
- **A bullet list can collapse into the paragraph before it.** Markdown bullet
  lines carry no blank line between them, so `crosscheck.py` joins the wrapped
  lines of an entire list into one paragraph, and the pattern's "a number plus
  up to four following words" match lets a number ending one bullet absorb the
  leading dash of the next. Measured on 2026-08-19 with `crosscheck.py`'s own
  `paragraphs`/`LABELLED`/`key_of`, counting a match whose span crosses a
  physical line, and of those, the ones crossing into a line opening a new
  bullet: 214 matches cross a physical line and 24 of those cross into a new
  bullet. **How many contaminated keys those 24 produce is deliberately not
  stated here.** Three independent measurements of it, taken on 2026-08-19 and
  2026-08-20 from the same written definition, returned 16, 21 and 23: the
  figure turns on definitional choices the sentence describing it never pinned
  down, chiefly whether a key counts when the absorbed dash is truncated away
  by `key_of`'s three-word cap. All three agreed on the part that carries the
  conclusion, and it is the part worth stating: none of the contaminated keys
  reaches the threshold of disagreeing across more than one file, so the effect
  on the report today is zero. It is a latent false-positive risk rather than a
  live defect. A number three careful readings cannot reproduce is not a
  measurement, and printing one anyway would be the defect this file exists to
  refuse. This entry's own text sits
  inside the corpus it sweeps, so the self-referential matches it forms about
  its own figures are excluded from the 214: a literal re-run of the same
  pipeline against the corpus as it now reads will not reproduce 214 exactly,
  and will read higher, because the size of that exclusion is the count of
  self-referential matches this entry currently contains, which changes
  whenever this entry is reworded, including by this sentence.

The measured noise floor when the sweep was written was roughly 60 per cent:
ARTEFACT plus SUBJECT verdicts covered 4 of the triage's 7 clusters and 16 of
its 26 hits, against 6 of 7 clusters triaged not a defect, which is why
discovery reports rather than fails. A blame date is printed beside every hit
because a stale count and a correct historical measurement are
indistinguishable without one: `docs/ROADMAP.md:208` says "All 6 compliance
frameworks" and is right, having been written when there were six.

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
