# Testing Commands

Commands for running unit tests, integration tests, container-based root tests, cross-distro validation, and GUI tests.

---

## Unit and Integration Tests (Cargo)

### Run all tests

```bash
cargo test --workspace
```

Runs every test across all 11 crates. Currently 1300+ tests.

### CI subset (excludes GUI crates)

```bash
cargo test --workspace --exclude linux-hardener-desktop --exclude hardener-ui
```

Excludes the Tauri backend and WASM frontend crates; used in CI where GUI dependencies may not be available.

### Single crate

```bash
cargo test -p hardener-core                  # Core engine tests
cargo test -p hardener-plugins               # Plugin tests
cargo test -p hardener-cli                   # CLI argument parsing and command tests
cargo test -p hardener-state                 # Checkpoint, signing, audit log tests
cargo test -p hardener-common                # Utility and error type tests
cargo test -p hardener-compliance            # Compliance framework tests
cargo test -p hardener-scheduler             # Daemon and scheduling tests
cargo test -p hardener-distro                # Distribution detection tests
cargo test -p hardener-types                 # Shared type tests
```

### Show test output

```bash
cargo test -- --nocapture                    # Print stdout/stderr from passing tests
```

### Run ignored tests (require root)

```bash
sudo cargo test -- --ignored
```

Some tests require root privileges and are marked `#[ignore]`. These test operations like file permission changes that need elevated access.

---

## Test Container Creation

All root-level and destructive tests run inside `systemd-nspawn` containers, never on the host. Each script creates a minimal container under `/var/lib/machines/`.

All five containers are created by one script, `create-container.sh`, which takes the distro as its first argument:

```bash
sudo ./scripts/containers/create-container.sh arch              # Create container
sudo ./scripts/containers/create-container.sh arch enter         # Enter existing container interactively
sudo ./scripts/containers/create-container.sh arch clean         # Remove container completely
```

| Distro argument | Container name |
|-----------------|----------------|
| `arch` (primary) | `hardener-test` |
| `debian` | `hardener-test-debian` |
| `fedora` | `hardener-test-fedora` |
| `rhel` (Rocky Linux, RHEL-compatible) | `hardener-test-rhel` |
| `opensuse` | `hardener-test-opensuse` |

Enabling `sshd` and `auditd` is a required step, not a best-effort one: if it
fails the script reports what the service manager said and refuses to finish,
because a container missing the services under test produces suite results that
look like passes. Every bootstrap installs both packages, so a failure there
means the bootstrap did not do what it reported doing.

### SSH integration fixture (booted container)

The suites above run containers via `nspawn --pipe` (no network, no sshd). The
`#[ignore]` SSH integration tests need a *booted* container with networking and
an authorised key instead; the SSH executor is key/agent-auth only, so the
containers' root password is not usable:

```bash
sudo ./scripts/containers/boot-ssh-test-container.sh            # boot hardener-test with --network-veth, inject test key
# then, using the env exports the script prints:
export SSH_TEST_HOST=<addr> SSH_TEST_USER=root SSH_TEST_PORT=22 SSH_TEST_KEY=~/.ssh/hardener_test_ed25519
ssh-add "$SSH_TEST_KEY"
cargo test -p hardener-core --test ssh_executor_tests -- --ignored      # executor primitives
cargo test -p hardener-cli --test batch_ssh_integration -- --ignored    # batch scan/report/apply/rollback end-to-end
sudo machinectl stop hardener-test                   # tear down
```

The batch tests are read-only against the fixture (scan/report scan; apply and
rollback run as dry-runs). Without `SSH_TEST_HOST` they skip.

### Booted suite containers (`--booted`)

Under `--pipe` systemd never starts, so anything that asks the service manager a
question is untestable. `--booted` runs the same suite as a child of the
container's own systemd:

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --distro arch --apply --booted
```

Measured on arch 2026-07-30 against the identical run under `--pipe`: of 138
verdicts exactly one changes, `Apply ssh-hardening` from
`(partial apply: expected in container)` to a clean pass, because the service
restart now works. Inside the firewall apply, ten
`iptables-restore: Permission denied` and fifteen
`sysctl: permission denied on key "net.ipv4.*"` disappear.

The container gets `--private-network`, not `--network-veth`, and the choice is
load-bearing in both directions:

- **It must own a network namespace.** nspawn grants `CAP_NET_ADMIN` only to a
  container that does, which is exactly why `iptables-restore` fails under
  `--pipe`. Never add `--capability=CAP_NET_ADMIN` to a container sharing the
  host's namespace: these suites run
  `hardener apply --plugin firewall-hardening`, and those rules would land in
  the host's own netfilter.
- **It does not need a veth pair.** `--private-network` and `--network-veth`
  give an identical capability set (`CapEff 00000000fdecbfff`), the same
  read-write `/proc/sys/net`, and the same working `iptables`. The veth variant
  only adds a `ve-*` interface on the host and addressing at both ends, which
  no suite uses.

`/proc/sys` stays read-only either way, so the seven `fs.*` and `kernel.*`
parameters remain unreachable and the in-container
`apply --plugin kernel-hardening` cannot touch the host. **Do not mount it
writable to enable a kernel oracle.** The eleven `net.ipv4.*` parameters do
become writable, inside the container's namespace only.

Take a container reading through `systemd-run --machine`, never `nsenter`.
nsenter enters the namespaces but keeps the caller's capabilities, so it reports
the host's `CapEff 000001ffffffffff` and makes a forbidden operation look
permitted.

**Host prerequisite: ufw's netfilter extensions must already be loaded.** A
container cannot autoload a kernel module, because `CAP_SYS_MODULE` is cleared
and must stay cleared, so the extensions ufw's baseline rules need have to be
present on the host before the run. Without them the firewall apply fails with
`Extension limit revision 0 not supported, missing kernel module?` followed by
`RULE_APPEND failed (No such file or directory)`, which reads like a tool defect
and is not one:

```bash
sudo modprobe -a xt_limit xt_LOG ipt_REJECT ip6t_REJECT ip6t_rt xt_hl xt_multiport xt_recent
```

Note `-a`. Without it `modprobe` loads the first module and treats the rest as
*parameters* to it, which fails silently in the sense that it reports success
having loaded one of eight.

**With those loaded, `--booted` reaches 126/126 on arch** (2026-07-30, arch,
`--apply`, container recreated first), against 125/126 under `--pipe` in the
same run. Exactly two verdicts differ and nothing else moves:

```
- [FAIL] Apply firewall-hardening (the plugin reported no result at all)
+ [PASS] Apply firewall-hardening
- [PASS] Apply ssh-hardening (partial apply: expected in container)
+ [PASS] Apply ssh-hardening
```

That was the last failing test in the container suites.

---

## Root Test Suites (Inside Containers)

These scripts must be run inside a container (`create-container.sh arch enter`), not on the host.

### Root test suite (focused)

```bash
sudo ./scripts/test/root-test-suite.sh                    # Read-only tests only
sudo ./scripts/test/root-test-suite.sh --apply             # Include destructive apply + rollback tests
```

Tests hardener operations that require root: scanning as root, checkpoint creation, plugin apply/rollback.

Without `--apply`: only tests scanning and checkpoint operations (non-destructive).
With `--apply`: also tests applying hardening changes and rolling them back (modifies system config files, then restores them).

### Full test suite (comprehensive, 26 sections)

```bash
sudo ./scripts/test/full-test-suite.sh                     # Sections 1-12, 17-22, 24-26 (no apply)
sudo ./scripts/test/full-test-suite.sh --apply              # All 26 sections including apply and rollback
```

More thorough than `root-test-suite.sh`. Covers CLI argument parsing, every plugin's scan output, checkpoint lifecycle, compliance reports, daemon commands, systemd integration, history commands, and per-plugin apply/rollback cycles.

Without `--apply`: skips sections 13-16 (per-plugin apply and rollback) and section 23 (per-plugin lifecycle).
With `--apply`: runs all 26 sections including destructive per-plugin lifecycle testing.

```bash
bash scripts/test/full-test-suite.sh --self-test            # classification and diagnostics, safe anywhere
```

Needs no root and no container. It drives the decisions the suite makes rather
than the system it makes them about, currently the one that separates an apply
that partially succeeded, which a container is expected to produce, from an
apply that never ran, which it is not. Inside a container both exit 1, so the
suite tells them apart by whether the tool left a result document behind.

### Rollback verification

```bash
sudo ./scripts/test/verify-rollback.sh
```

Runs 5 targeted tests that verify checkpoint creation, apply, and rollback produce the expected system state. Must be run inside a container.

### Manual verification

```bash
sudo ./scripts/test/manual-verification-test.sh
```

Interactive step-by-step test with pauses between operations. Designed for manually inspecting system state at each stage. Must be run inside a container.

---

## Differential Suite (Ask The System, Not The Tool)

Every other suite compares the tool against itself: it applies a setting, reads
the file back with the same parser that wrote it, and reports agreement. That is
how a maximum password age of 99999 shipped as "compliant" from v1.0.0 onwards.
The differential suite applies hardening and then asks each setting's real
consumer what is in force:

| Setting | Oracle | Why not read the file |
|---------|--------|-----------------------|
| The `sshd_config` directives in `SSH_CHECKS` | `sshd -T` | Resolves `Include` precedence and `Match` scoping, which our parser does not |
| `PASS_MIN_DAYS`, `PASS_MAX_DAYS`, `PASS_WARN_AGE` | `useradd` then `chage -l` | `login.defs` supplies defaults for NEW accounts, so only a fresh account shows what the file means today |
| `ENCRYPT_METHOD`, `HOME_MODE`, `UMASK` | a probe account: the scheme prefix `crypt` wrote into its shadow field, `stat -c %a` on its home, `su - probe -c umask` | These are settings the tool does **not** manage, and the file they come from is the one a masked `/etc` copy silences. Reading that file back would ask the masked copy what it says |
| The nine paths in `PERMISSION_CHECKS` | `stat -c %a` | A mode has no parser to disagree with: the value the kernel reports **is** the value in force. What the oracle adds is the comparison, because two of the nine are allowed-bits masks where a stricter mode is compliant |
| The three properties in `FIREWALL_CHECKS` | `nft list ruleset` and `systemctl is-enabled`, each diffed against a pre-apply capture | `ufw status` and `firewall-cmd --list-all` are the tools' own frontends. Netfilter is what a packet meets, and systemd is what decides whether it still will after a reboot. **The two ruleset rows require `--booted`; `boot-persistence` does not** |
| The 11 `net.ipv4.*` parameters in `KERNEL_CHECKS` | `sysctl -n` | The file under `/etc/sysctl.d` is what the tool wrote, not what the kernel runs, and a reader sharing one mistake with the writer agrees with it and disagrees with Linux. **Requires `--booted`** |

Two assertions per directive, because both have failed in production: the system
satisfies what this run requires of it, and `scan`'s verdict agrees with the
system.

**The firewall rows are one assertion each, not two**, because there is no
per-rule tool verdict to compare against: the plugin's only scan finding is
`{backend}-disabled`, which says nothing about an individual rule. Four things
about that oracle were measured on real containers rather than reasoned about,
and each would otherwise have produced a check that passes on broken code:

- **`iptables -S` cannot see firewalld.** After a successful apply on Fedora it
  prints three policy lines and nothing else, because every rule firewalld wrote
  lives in `table inet firewalld`. An `iptables -S` oracle matches nothing on
  three of five distributions, and matching nothing is this suite's pass
  condition. Its policy lines are still read, because ufw expresses its default
  disposition there and nowhere else.
- **Presence is not evidence, because the baseline is not empty.** Fedora's
  container starts with 344 lines of firewalld ruleset already loaded, including
  `ct state {established, related} accept` and `iifname "lo" accept`. Arch starts
  at 4. The same presence assertion would be honest on Arch and vacuous three
  distributions over, so everything is compared against a pre-apply capture.
- **A firewalld DROP zone target renders as a bare `drop`** replacing the zone
  chain's trailing `reject with icmpx admin-prohibited`. A pattern written for
  `policy drop` matches firewalld never. The self-test pins this: relaxing the
  check to accept `reject` makes an unhardened Fedora container pass the oracle,
  and four assertions fail when it is mutated that way.
- **A ruleset carries nothing about the next boot.** A firewall started by hand
  renders identically to one that comes back after a reboot, so both rules-based
  rows stayed green against the Arch container whose `ufw` unit had no
  `multi-user.target.wants` symlink at all. Measured, by comparing the run
  before the repair existed against the run after it: all 68 assertion lines
  are byte-identical on all five distributions, so nothing in the suite would
  have caught the repair regressing. `boot-persistence` asks `systemctl
  is-enabled` instead, either side of the apply, and judges on systemd's word
  rather than its exit status: `enabled-runtime` and `static` both exit zero and
  neither survives a reboot.

**`ssh-still-accepted` is a safety property, not proof the tool acted**, and the
code says so. On firewalld that rule exists before the apply as well, because the
default `public` zone allows the ssh service, so it would pass against a tool
that did nothing. It earns its place because a firewall that drops inbound *and*
drops ssh has locked the operator out, and no other check would notice.

**`boot-persistence` says in its own message whether its row is
discriminating.** Only Arch is load-bearing there: Fedora, RHEL and openSUSE
ship firewalld already enabled, and Debian's `ufw` package enables the unit at
install, so four of the five would read `enabled` without the repair. The
pass message therefore compares against the pre-apply reading and names which
case it is, because a wording that read the same on all five would make one row
of evidence look like five.

**That pre-apply reading asks every candidate unit, and not the one the
pre-apply ruleset names.** Deriving it from the ruleset was a defect of exactly
the kind this row exists to prevent. On Arch and Debian `ufw` is installed but
not enabled before the apply, so its chains do not exist, the pre-apply backend
reads as none, and systemd was never asked at all. The row then filled that gap
by crediting the apply, which is true on Arch and almost certainly false on
Debian, whose firewall survived a reboot before the repair existed and whose
`ufw` package enables the unit at install. `FIREWALL_UNIT_CANDIDATES` therefore
holds both units, both are asked before the apply and recorded as
`<unit>|<word>` pairs, and the row looks up the unit its own post-apply reading
names. A before state that could not be read, or that systemd worded in a way
the suite cannot name, leaves the row passing on its after reading while saying
it cannot tell whether the apply is what did it: filling that gap with a claim
is the whole defect, and making it in a different branch would be worth nothing.
The candidate list and `firewall_backend_kind` have to name the same backends
and nothing in the run path makes them, so the self-test reads the kinds back
out of that function's own body, and the row says so in its own message if the
two come apart during a run.

The row is deliberately **not** gated on `--booted`,
unlike the kernel rows: whether `systemctl is-enabled` answers inside an
unbooted `--pipe` container is unmeasured, so a run that cannot ask goes red
rather than quiet. An answer that is neither `enabled` nor one of the six states
the tool repairs is a failure, never a skip, and the failure carries the word
systemd used, because a masked unit must be unmasked before enabling it can
work.

**The firewall plugin's pre-apply control is not the finding-count one** the
other three get. Its only finding is `{backend}-disabled`, and firewalld is
already active in three of the five containers, so a finding-count control would
fail there against a tool behaving correctly. It asks the stronger question
instead: was inbound traffic already dropped before the apply? If it was, the
post-apply check proves nothing whatever it reports.

**A reading satisfying a requirement is not always string equality**, which is
why `requirement_satisfied` carries a direction. `/etc/shadow` and `/etc/gshadow`
are compared against an allowed-bits mask of `0640`: a stricter mode sets no bit
the mask disallows and is compliant, so Arch's `0600` and RHEL's `0000` are both
correct and the tool deliberately leaves them alone. An equality oracle would
have reported a defect on three of the five distributions against a tool behaving
exactly as designed. The comparison lives in one place for the same reason the
product side keeps its own in `strictness.rs`: a second copy behind the verdict
question would answer differently for precisely the readings the mask exists for.

**A path absent from both layers still contributes two assertions.** The tool
treats an absence confirmed at `/etc` and at `/usr/etc` as nothing to report, so
the requirement there is that it reports nothing, and a tool inventing a finding
for a path that is not there fails. What is given up is the mode comparison, and
the run prints how many paths gave it up rather than leaving a reader to notice a
shorter proof.

**Absent from `/etc` is not absent from the host**, and the first container run of
this oracle proved why. openSUSE keeps `sudoers` at `/usr/etc/sudoers` with
nothing at `/etc/sudoers`, at mode 0444 against a 0440 target, so both the tool
and the first version of this oracle said nothing and agreed with each other: two
silences comparing equal, which is the shape the suite exists to refuse. The
capture now asks the vendor layer whenever `/etc` holds nothing, mirroring
`vendor_path_for`, and a vendor reading is compared against the same target by the
same rule.

For a vendor row the **first** assertion records the reading rather than demanding
compliance, and that is deliberate: this tool never writes `/usr/etc`, so a
violating vendor file is a state it reports and cannot correct, and requiring
compliance would leave the suite permanently red against a tool behaving exactly
as designed. The message states the mode and the requirement so the violation is
visible, and the verdict assertion is the one that can fail: the tool must report
a finding when the vendor mode violates and stay silent when it does not, pinned
in all four directions by the self-test.

One assertion per unmanaged setting, because there is no tool-reported
counterpart: the value after apply must be the value before it. The tool claims
nothing about these, so any change at all is damage whatever the new value is,
and the check is written as that invariant rather than as an expected value.
Hardcoding one would make it distribution-specific for no gain: the same run
reads `$y$` on four distributions and `$6$` on openSUSE, `0022` on four and
`0002` on debian.

**The run applies twice**, and one assertion per reading in
`IDEMPOTENCE_CHECKS` says the second apply changed nothing: every managed
permission mode as one reading, `sshd -T` in full, `/etc/ssh/sshd_config.d` as
filenames and contents, and what `login.defs` means to a fresh account. The
permission reading is taken **first**, because reading `login.defs` creates and
removes a probe account and `useradd` and `userdel` rewrite `/etc/passwd` and
`/etc/shadow`: taking it ahead of that keeps one probe cycle out from between the
two readings being compared. It cannot keep all of them out, since one cycle
still runs between that baseline and the post-apply capture, and that is why the
shared failure message names no cause: it reports that the reading moved between
the two applies rather than that the second apply moved it, because for this
reading the probe account could have. It also makes permissions the second
plugin in the repo whose apply is checked for idempotency at all, ssh having
been the only one,
and ssh failed that check twice. Idempotency is an invariant rather than a nicety, because
the scheduler applies on a cadence: an apply that undoes the previous one is a
fleet host returning to an unhardened state on a timer while reporting success
every time. A single-apply oracle structurally cannot see that, which is how a
defect that deleted the tool's own `sshd_config.d` fragment on the second run
survived a green 125/125.

The readings are whole rather than per directive, because the defect this
catches need not touch a directive anyone thought to list. A consequence worth
knowing: every other check now runs against the state after **two** applies, so
a directive a second apply un-hardens fails its own check as well as the
idempotency one.

This family is the reason a green run was never proof on its own. Every other
check asks whether a setting the tool targets reached its target; none asked
whether the rest of the file survived, which is exactly how a masked
`/etc/login.defs` stayed invisible.

Each of the three has been watched failing on a real container, which is the
only evidence that a check can fail at all: replacing the vendor file with the
one-directive `/etc/login.defs` that releases up to 1.5.0 wrote moves
`ENCRYPT_METHOD` from sha512 to DES and `HOME_MODE` from 0700 to 755 on
openSUSE Leap, and `UMASK` from 0002 to 0022 on debian. Which distribution
demonstrates which depends on what that distribution's `login.defs` actually
drives, so a check looking inert on one host is not evidence it is inert.

The second assertion is the harder one to state honestly, because after a
successful apply it expects `scan` to report no finding, and no finding is also
what the tool emits when it did not check. `scan --format json` carries a second
array, `unchecked`, whose ids are identical to the finding ids, and a directive
listed there is scored as a failure rather than as agreement: the ssh plugin
moves all of its directives into it at once when `sshd_config` cannot be read,
and still reports the scan as successful. The JSON also omits `scan_success`
altogether, so a plugin whose scan failed emits exactly what a compliant host
emits. Against that, the suite takes a second `scan` capture before `apply`, and
requires each plugin to have reported at least one finding while the container
was still unhardened. Without it, every finding filter would pass by matching
nothing on every green run.


### Password quality actually being enforced

`PWQUALITY_ENFORCEMENT_CHECKS` asks whether the file the tool writes is read by
anything. `/etc/security/pwquality.conf` is consumed by `pam_pwquality.so` and
by nothing else, so a host whose PAM stack never loads that module enforces no
password policy however the file is written. Every check that reads the file
agrees with itself, and with the tool, while the system enforces nothing: the
purest form of this project's second root-cause family, the tool tested against
itself.

Two readings, one check each. The first compares the stack
(`/etc/pam.d/system-auth`, `password-auth`, `common-password`) against the
tool's `pam-minlen` verdict, and requires them to say the same thing: a stack
that loads the module must leave the tool with nothing to report after apply,
and a stack that does not must leave it reporting the directive unenforced. The
second asks libpwquality itself, through `pwscore`, and is the positive control
the first cannot supply: a policy that refuses every password and one that
refuses none both make a one-sided filter look correct, so the weak password
must be refused **and** the probe password accepted in the same breath.

A stack with no readable file is refused rather than read as "no module", for
the same reason a filter that matches nothing is not a pass: absence concluded
from nothing scores a host this run never looked at. `pwscore` being absent is a
real answer rather than a skip, since no libpwquality means no
`pam_pwquality.so` either.

### Declared unaskable, which is not a skip

`record_unaskable` sits beside `record_pass` and `record_fail`. It keeps its own
counter, `CHECKS_UNASKABLE`, prints every row it records by name, and stays
outside `CHECKS_TOTAL`, so the `Total`, `Passed` and `Failed` numbers the
host-side runner parses mean exactly what they meant before it existed.

**It does not weaken the rule that an oracle which cannot answer is a failure.**
The distinction is *when* unaskability is decided. A property of the fixture,
known before the run and written into a table with its reason, is unaskable: a
container has no writable `/proc/sys`, and that is true before a single check
runs. A property of the run, discovered at the moment a read comes back empty,
stays a failure: "I asked and got nothing" is the silence this suite exists to
refuse, and reaching for `record_unaskable` where a read fails would turn the
mechanism into the escape hatch it was built to avoid.

That is also why the count is named on its own line rather than folded into any
of the four labels:

```
  Skipped:      0
  Unaskable:    7 (declared above, not asked on this fixture)
```

`Skipped` stays 0 and always will. A green run carrying an `Unaskable` line is
not full coverage, and the line exists so that it cannot be read as though it
were.

### The kernel oracle, and the parameters it cannot ask about

`KERNEL_CHECKS` holds 11 `net.ipv4.*` parameters, one assertion each: `sysctl -n`
is asked what the kernel enforces, and the reading is compared against the
target in that parameter's own direction. One assertion rather than two, as with
the firewall rows, because the plugin publishes no per-parameter verdict to
compare a reading against.

**It covers 11 of the 18 parameters the kernel plugin manages, and the other 7
are named rather than quietly left out.** `nspawn` mounts `/proc/sys` read-only,
and it is the **host's**: a write is refused, and a read reports the host's value
rather than the container's. Only `/proc/sys/net` is remounted read-write, and
only for a container holding its own network namespace, which is why every
askable row is a `net.ipv4.` parameter and why these 7 are not:

- `kernel.randomize_va_space`, `kernel.kptr_restrict`, `kernel.dmesg_restrict`
  and `kernel.yama.ptrace_scope`
- `fs.suid_dumpable`, `fs.protected_hardlinks` and `fs.protected_symlinks`

Each sits in `KERNEL_UNASKABLE` with its reason beside it and prints a `----`
row in every run, so the gap is on the log rather than in the reader's head.

**The comparison carries a direction**, for the reason `requirement_satisfied`
does: a host already stricter than the target is compliant, and an equality
oracle would report a defect against a tool behaving exactly as designed.
`rp_filter` is the sharp row, and it is sharp against the arithmetic. 0 is off,
2 is loose mode, which accepts a packet whose source is reachable through any
interface, and 1 is strict mode, which requires the interface it arrived on. The
larger number is the weaker setting, so no numeric direction can express that
row at all and it carries the value space itself as `ranked:0,2,1`, weakest
first.

**One row is seeded stricter than the tool's own target before the first
apply**, because a container arrives with nothing above the baseline, and an
oracle that only ever watches a host being raised to its target can never watch
one being lowered from above it. The seed is `net.ipv4.tcp_syncookies` written
to `2` against a tool target of `1`: 2 sends SYN cookies unconditionally rather
than only under pressure, so a host at 2 is ahead of the target rather than
broken, and a reading of 2 after the apply is the evidence that the tool
declined to un-harden it. `rp_filter` is deliberately **not** that row, though it
looks like the obvious candidate: 2 there ranks below strict mode 1, so seeding
it would seed a looser value, a correct tool would tighten it, and the check
would report a defect against every distribution.

**A run that is not booted asks the kernel nothing.** The signal is
`HARDENER_DIFF_BOOTED`, exported by `run-cross-distro-tests.sh` on the
`systemd-run --machine` invocation inside `nspawn_suite_booted` and nowhere
else, and anything other than the literal `1` means not booted. It is never
inferred from what the fixture happens to permit, because a mode concluded from
a failed read is one value standing for several outcomes, which is the family of
defect this project keeps closing. The header prints
`Booted (kernel oracle): 0` or `Booted (kernel oracle): 1` beside the binary
version, so a reader meeting an old log can see which arithmetic applied to it.

**The totals move with the mode, and both kernel tables are pinned.** A run
records **56 checks when it is not booted and 69 when it is**, and
`expected_check_total` carries an arm for each: the 11 kernel rows and the
seeded row are checks the tables ask for only where they can be asked at all.
The unaskable count runs the other way, **7 when booted and 19 when not**, the
19 being the 11 rows the mode puts out of reach, the 7 the mount does, and the
seeded row whose seed could not be written. `KERNEL_CHECKS_EXPECTED` and
`KERNEL_UNASKABLE_EXPECTED` are both pinned in `require_check_tables`, for one
reason beyond the usual: the failure mode here is a red row being quietly
"fixed" by moving it out of `KERNEL_CHECKS` and into `KERNEL_UNASKABLE`, and
with both sizes pinned that move fails the guard twice rather than passing.

### Full run (container + root)

```bash
sudo ./scripts/test/differential-suite.sh              # inside the container
sudo ./scripts/test/run-cross-distro-tests.sh --differential --distro arch   # from the host
```

It refuses to start outside a container, and it refuses to start as a non-root
user. It applies hardening and creates a probe account, so it is destructive by
design and never safe on a real system. From the host it replaces the full suite
for that run: `--differential` always applies, whether or not `--apply` is given,
and results land in `test-results/<distro>.log` like any other run.

Each run opens by printing the binary's path and its `--version` string, so a
log can be attributed to a commit long afterwards rather than by reconstructing
which build happened to be current. A binary whose `--version` fails or prints
nothing is recorded as `UNAVAILABLE` with the reason, never as a blank beside
the path.

`jq` is required, along with `grep`, `sshd`, `ssh-keygen`, `useradd`,
`userdel`, `chage`, `id`, `chpasswd`, `stat` and `su`. A missing one aborts the
run by name before any check runs. The account rows the probe reads are parsed
by the shell rather than by `awk`, which is in neither the dnf-family nor the
openSUSE package set the container script installs. An oracle that cannot answer
is a failure here, never a skip: a skipped check that reads as a pass is the
disease being treated.

The binary under test must be built from this tree. Its `scan --format json`
output has to carry both a `findings` and an `unchecked` array per plugin, and
each `unchecked` entry has to carry an `unchecked_check_id`; a build old enough
to predate `unchecked` is refused rather than counted as reporting nothing.
Setting `BINARY` names the binary exactly: an explicit path that is not
executable aborts the run instead of falling back to a build from the tree, which
would report a run of one binary as a run of another.

### Self-test (safe anywhere)

```bash
bash scripts/test/differential-suite.sh --self-test
```

Needs neither root nor a container. It drives the text extractors, the freshness
guard that refuses a capture taken before `apply`, the probe's create-and-remove
safety, and all three plugins' finding-id conventions against fixtures,
including the doubled dash in `perm--etc-shadow` that a filter written without it
would silently miss. `jq` is the only external command it needs.

The idempotency family is proven here too, because its readings want root and a
container: the fragment listing against a temporary directory that is missing,
empty and then populated, the refusal of an unknown reading key, and each of the
four ways a baseline can fail to describe what one apply produced. The
comparison itself is driven through a stubbed reading and watched in both
directions, since a reading compared against itself passes whatever the tool
did.

The vendor survival family is proven here in both directions, because its whole
job is to notice a value changing: an unchanged value agrees, a changed one does
not, a reading that could not be taken on either side fails the check rather
than skipping it, and a shadow field carrying no usable hash (`!`, `*`, or a
`!`-prefixed hash) is refused rather than reported, since those are stable
across an apply and would otherwise pass as a setting that survived while
proving nothing.

It also pins the shapes of `scan` output that would otherwise read as a clean
bill of health: a plugin object missing its `findings` or `unchecked` array, an
`unchecked` entry whose `unchecked_check_id` has been renamed, more than one JSON
document on stdout, a directive the tool listed as unchecked, and a pre-apply
capture in which a plugin reported nothing.

The lengths of the check tables are pinned there as literals as well. A total
counted off the tables cannot notice one of them being edited down: with the ssh
table emptied, a run over the `login.defs` directives alone would agree with
itself, exit 0, and be reported as a PASS. So the size the run is measured
against is counted off `SSH_CHECKS_EXPECTED`, `SEEDED_SSH_CHECKS_EXPECTED`,
`LOGIN_DEFS_CHECKS_EXPECTED`, `VENDOR_SURVIVAL_CHECKS_EXPECTED`,
`IDEMPOTENCE_CHECKS_EXPECTED`, `PWQUALITY_ENFORCEMENT_CHECKS_EXPECTED`,
`PERMISSION_CHECKS_EXPECTED`, `FIREWALL_CHECKS_EXPECTED`,
`KERNEL_CHECKS_EXPECTED`, `SEEDED_KERNEL_CHECKS_EXPECTED` and
`DIFF_PLUGINS_EXPECTED`, which the tables are then checked against, rather than
off the tables themselves. `KERNEL_UNASKABLE_EXPECTED` is pinned alongside them
in `require_check_tables` but contributes to no total, because a row that was
never asked is not a check that ran.

Adding a directive therefore means changing four literals in
`scripts/test/differential-suite.sh`, not one: the `*_EXPECTED` constant beside
its table, that same length re-pinned in the self-test (`the ssh table holds
seven directives`), the total the run is sized at, which `expected_check_total`
computes at **56** unbooted and **69** booted, and the number of directives the
pre-apply control covers (`19`). `VENDOR_SURVIVAL_CHECKS`, `IDEMPOTENCE_CHECKS` and
`PWQUALITY_ENFORCEMENT_CHECKS` are sized the same way, and contribute one check
each rather than two. Every one of them fails loudly, over two `--self-test` runs,
because the total is counted off the constant and only moves once the constant
has been raised. Adding the idempotency table did exactly that: the self-test
refused the run at `got '28', want '25'` until the literal was raised on
purpose, and the pwquality enforcement pair did it again at
`got '30', want '28'`. The permissions table did it a third time: adding nine
paths and a third plugin moved the total from 30 to 51, and the self-test refused
the run until both literals were raised on purpose. The `permission-modes`
idempotency reading did it a fourth time, refusing the run at
`got '51', want '52'`. The firewall oracle and then the kernel oracle did it
again. `boot-persistence` did it a seventh time, and failed twice over as the
firewall tables are meant to: with `FIREWALL_CHECKS_EXPECTED` left at 2 the
self-test reads `got '55', want '56'` and `require_check_tables` refuses the
three-entry table beside it. The per-distribution total now stands at **56** for
a run that is not booted and **69** for one that is.

### What a failure means

A failure means the operating system disagrees with what the tool reported, or
that an oracle could not be read. Neither is a flaky test: a disagreement is a
product defect and is exactly what this suite exists to find, and an oracle that
cannot answer leaves a directive unproven, which is recorded as a failure rather
than skipped. Each `FAIL` line names the directive, and where the two disagree,
the value the system holds and what this run requires of it:

- `the system holds 'X' but this run requires 'Y'`: `apply` did not take effect.
  For the two mask rows the requirement reads `no bit outside 'Y'` instead,
  because a stricter mode is compliant there and a message claiming the run
  requires `640` would be false of a directive that also accepts `600`.
- `the tool claims a compliance the system does not have`: `scan` reported
  nothing while the system holds something other than the target. This is the
  shape of the `login.defs` defect, and of the openSUSE vendor-file defect where
  the mode in force sat at `/usr/etc` and the tool had looked only at `/etc`.
- `the tool reports N finding(s) ... while the system holds 'X' and this run
  requires 'Y'`: `scan` is flagging a host that is in fact compliant.
- `the tool did not check '<id>'`: the id came back in the `unchecked` array.
  The tool verified nothing for that directive, which is neither agreement with
  the system nor a contradiction of it, and the usual cause is a config file the
  scan could not read.
- `idempotency <key>: this reading moved between the two applies`: the second
  apply did not leave the reading where the first one did, so applying on a
  cadence does not hold the host where one apply put it. The message names no
  cause on purpose: for `permission-modes` the probe account that reading
  `login.defs` creates and removes rewrites `/etc/passwd` and `/etc/shadow`, so
  the apply is not the only candidate. The `diff|` lines beneath it name the
  lines that moved, in both directions.
- `before apply the tool reported no finding for any of the N compared
  directives`: the pre-apply control failed for that plugin. Either its scan
  produced nothing, which this JSON cannot distinguish from a compliant host, or
  the harness's filter for it matches nothing.
- `Recorded N check(s) where the tables ask for M`: the run was shorter than the
  tables it was built from, so some directives went unproven.

Investigate the plugin, not the harness. If the harness itself is wrong, the
self-test is where the fix is proven.

---

## Cross-Distro Testing

Runs the full test suite across multiple distribution containers from the host.

### Cargo target directory resolution

The host-side test runners no longer assume binaries live under `./target`. Each
resolves the real cargo target directory in this order:

1. `$CARGO_TARGET_DIR`, if set.
2. `cargo metadata --format-version 1 --no-deps` → `target_directory` (honours a
   `[build] target-dir` in `~/.cargo/config.toml`), when cargo is on `PATH`.
3. `./target` (the default for a fresh clone); if the wanted binary is absent
   there but present under the invoking user's `~/.cache/cargo-target` (checked
   via `$SUDO_USER` when running under sudo), that directory is used instead.

When the resolved directory is not `./target`, the container runners additionally
bind-mount it read-only at `/project/target`, so the in-container scripts
(`full-test-suite.sh`, `test-package-install.sh`, `tauri-gui-test-inner.sh`,
`verify-rollback.sh`) keep finding binaries at their documented paths unchanged.

### All distributions

```bash
sudo ./scripts/test/run-cross-distro-tests.sh              # Read-only, all distros
sudo ./scripts/test/run-cross-distro-tests.sh --apply       # Destructive, all distros
```

Iterates through all 5 container types (Arch, Debian, Fedora, Rocky, openSUSE), copies the musl binary into each, and runs the full test suite.

### Single distribution

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --distro arch
sudo ./scripts/test/run-cross-distro-tests.sh --distro debian
sudo ./scripts/test/run-cross-distro-tests.sh --distro fedora
sudo ./scripts/test/run-cross-distro-tests.sh --distro rhel
sudo ./scripts/test/run-cross-distro-tests.sh --distro opensuse
```

### Differential suite instead of the full suite

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --differential
```

Runs `differential-suite.sh` in each container in place of `full-test-suite.sh`,
through the same nspawn invocation and the same per-distro logs and summary
table. See the differential suite section above; it is always destructive.

### With GUI tests

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --apply --gui
```

Runs CLI tests plus Playwright GUI tests inside each container.

### Rebuild binary first

```bash
sudo ./scripts/test/run-cross-distro-tests.sh --rebuild
```

Recompiles the musl binary (`x86_64-unknown-linux-musl/release/hardener` under the resolved cargo target directory) before copying it into containers. Use this after code changes.

Test results are written to `test-results/<distro>.log`.

---

## GUI Tests

### Web UI tests (Playwright, all distros)

```bash
sudo ./scripts/test/gui/run-gui-tests.sh                       # All distro containers
sudo ./scripts/test/gui/run-gui-tests.sh --distro arch          # Arch container only
sudo ./scripts/test/gui/run-gui-tests.sh --distro debian        # Debian container only
```

Orchestrates Playwright tests inside nspawn containers with Xvfb (virtual display). Tests the Leptos web frontend served by Trunk.

Uses `scripts/test/gui/gui-test-inner.sh` internally (the script that runs inside the container).

### Tauri desktop GUI tests (Arch only)

```bash
sudo ./scripts/test/gui/run-tauri-gui-tests.sh
```

Tests the native Tauri desktop application using xdotool for window interaction. Runs inside the Arch container (`hardener-test`).

Uses `scripts/test/gui/tauri-gui-test-inner.sh` internally.

### Direct Playwright commands

From the `gui-tests/` directory (inside a container, not the host):

```bash
cd gui-tests
npm install                                            # Install @playwright/test
npx playwright test                                    # Run all tests
npx playwright test --reporter=list                    # Verbose output
```

Test results are written to `test-results/gui/`.

---

## CI Pipeline Commands

These run automatically via GitHub Actions; listed here for reference and local reproduction.

### ci.yml (every push/PR to main)

```bash
cargo check --workspace --exclude linux-hardener-desktop --exclude hardener-ui
cargo test --workspace --exclude linux-hardener-desktop --exclude hardener-ui
cargo clippy --workspace --exclude linux-hardener-desktop --exclude hardener-ui -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo check -p hardener-ui --target wasm32-unknown-unknown
cargo build --release --target x86_64-unknown-linux-gnu -p hardener-cli
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
```

### release.yml (on tags matching `v[0-9]+.[0-9]+.[0-9]+`)

```bash
cargo test --workspace --exclude linux-hardener-desktop --exclude hardener-ui
cargo build --release --target x86_64-unknown-linux-gnu -p hardener-cli
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cargo build --release --target aarch64-unknown-linux-gnu -p hardener-cli
```

Produces three release tarballs and creates a GitHub release.

**Last Updated**: 2026-07-30
