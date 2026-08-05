# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **A remote `apply` on the nftables backend locked the operator out of the
  host it was hardening.** `enable` created the input chain with `policy drop`
  and no rules, and ran before `apply_rules` installed the baseline rule named
  "Allow SSH to prevent lockout". Over SSH the drop policy severed the very
  connection carrying the rest of the apply, so the anti-lockout rule was never
  installed and the host was left filtering all inbound traffic with no SSH. On
  a real remote host that is unrecoverable without console access. Reversing the
  two calls would not have helped: `ensure_managed_chain` created the same
  dropping chain at the top of `apply_rules` itself. The whole ruleset is now
  rendered and loaded in **one `nft -f` transaction**, so the policy is never
  live without the accepts beside it; nftables applies a file or none of it.
  `policy drop` is kept rather than traded for `accept` plus the baseline's
  final drop rule, so a host whose load fails outright stays closed rather than
  open. The replacement is **scoped to a table this plugin owns**, `inet
  linux_hardener`, with the bare `table` declaration then `delete table` then
  the new definition, all in the same transaction. Two wider drafts were written
  and rejected before it. A whole-ruleset `flush ruleset` came first and would
  tear down the tables Docker, libvirt and `iptables-nft` create, on a host this
  tool was only asked to harden. Scoping those same statements to `inet filter`
  came second and was narrower without being correct: that is the conventional
  default name rather than an owned one, most distributions ship a packaged
  ruleset using it, and measured in a network namespace against an
  administrator's chain holding two accepts, the old incremental path left both
  standing while a rendered `delete table inet filter` removed both. **Stated
  consequence of owning a separate table:** the plugin no longer merges into the
  administrator's chain, so an accept of theirs no longer keeps a port open,
  because a `drop` verdict in any chain ends a packet's journey and this chain's
  `policy drop` governs whatever its own rules do not accept. A port that must
  stay open is expressed as a directive to this tool.
  **A second ceiling runs the other way and is stated rather than fixed:** the
  ruleset is written to `/etc/nftables.conf` and that write replaces the whole
  file, which on Arch and Debian is where the administrator's own `inet filter`
  table is defined. Their table survives the apply in the running kernel and is
  gone at the next boot. Scoping the `nft` load stopped the runtime destruction;
  it did not stop this one, which is a question about which file the ruleset is
  written to and is tracked separately.
  Per-rule reporting is unchanged, the diff being taken before the load,
  so `applied_change_count()` and `is_skipped()` keep meaning what they meant.
  `ensure_managed_chain` is deleted and `enable` now only enables the unit at
  boot. Because an apply now creates `/etc/nftables.conf` on any host that
  never had one, that path is **deliberately deletable on rollback** and was
  removed from `UNDELETABLE_ROLLBACK_PATHS`: protecting it would leave the
  rendered ruleset on disk with the unit enabled, so the posture the operator
  rolled back would return at the next boot and the plugin's own reload would
  load it straight back in. Same precedent as the ssh and kernel drop-ins.
  The checkpoint itself is now scoped to the backend that was selected, through
  a new `FirewallBackend::config_paths`, rather than listing all three
  backends' paths on every host. The combined list recorded a row for
  `/etc/nftables.conf` on ufw and firewalld hosts too, where no apply can
  create it, and a row recorded absent is an instruction to delete: a rollback
  would have removed an `/etc/nftables.conf` that arrived between the
  checkpoint and the undo, from the `nftables` package or from the
  administrator, with nothing to show it had ever been ours. A backend now
  declares what it writes beside the writing, so the two cannot drift apart.
  **Stated ceiling:** the ruleset is written to `/etc/nftables.conf`,
  which persists it on hosts whose `nftables.service` reads that path, but
  Fedora and RHEL ship `/etc/sysconfig/nftables.conf`, so boot persistence there
  is still unresolved and #52 stays open. Closes #92.

- **A firewall `source`, `protocol` or `port` directive could weaken the
  ruleset and the tool applied it as written.** `apply_rule_directives` clamped
  the `action` field alone; the other three were assigned onto the rule exactly
  as the operator gave them. All four are now clamped, and the direction is the
  rule's rather than the field's: an **accepting** rule admits what it matches
  and so weakens as it matches more, a **blocking** rule refuses what it matches
  and so weakens as it matches less. The sharpest case was the second kind and
  went unnamed in #64: `drop_default.source = "10.0.0.0/8"` narrows the catch-all
  drop so that everything outside that subnet stops being dropped at all, and on
  firewalld it also silently stopped the zone's default target being set to DROP,
  because `sets_default_target` is gated on that rule still holding `any`.
  `port` is clamped too, contrary to the belief that it merely moves: the
  configuration layer accepts `1-65535` as a range, so `ssh.port = "1-65535"`
  was accept-all-TCP through a validated config. Breadth is measured rather than
  matched textually, so every spelling of the whole address space is caught,
  `any` and `0.0.0.0/0` and `8.8.8.8/0` alike. The `action` clamp now runs
  **first**, so the other three are judged against the action the rule ends up
  carrying: tightening a rule into a `drop` and widening its port in the same
  config is a stricter ruleset and is admitted. Refusals are logged and the
  baseline value stands. **Stated ceiling:** two values of the same width
  compare equal, so a source of the same prefix length covering a different
  range, `127.0.0.1/8` becoming `10.0.0.0/8`, is still honoured. Refusing that
  needs CIDR containment across both address families, and this plugin
  deliberately does not own an address comparator. Anything the clamp cannot
  measure, including a source in the other family and a prefix longer than its
  family allows, is refused rather than guessed at. The issue's own worked
  example, `ssh.source = "0.0.0.0/0"`, turned out to widen nothing: that rule's
  baseline source is already `any`. Closes #64.

- **A rollback probed as the login user and wrote as root, so a path the probe
  could not reach was admitted and written through.** `SshExecutor::write_file`
  goes through `sudo tee` while its command probes ran bare, and GNU `readlink`
  exits 1 both for "not a symlink" and for a path it may not traverse. The
  rollback guard read that status as the positive answer, so on a remote host
  where the login user could not reach an allow-listed path, the guard admitted
  the row and root wrote through whatever actually stood there. `/root` is in
  `DEFAULT_ROLLBACK_PREFIXES` and is 0700 on an ordinary host. The guard now
  asks through `link_target_as_writer`, which elevates exactly as the write
  does; anything undeterminable refuses. The whole probe body runs inside one
  elevated invocation, so an elevation that refuses to run anything, a `sudo`
  rule scoped to a command list among them, yields no answer rather than the
  admitting one, and the probe pins its own `PATH` to the same trusted list
  `resolve_binary` uses. What makes the negative trustworthy is that matched
  privilege, not the parent gate the probe also applies: resolving a parent
  needs search permission on that parent's ancestors while the `lstat` behind
  `test -h` needs it on the parent itself, so the gate is kept for the two
  cases it does settle, a dangling link and a missing parent component, and is
  claimed for nothing more. Rollback already required root or passwordless
  sudo on the target session, so this demands nothing new. Checkpoint capture
  is deliberately unchanged, because it reads content as the login user and
  its degrading to content-only is an accepted ceiling. **Stated ceiling:**
  the guard still judges the final component alone, so a regular file under a
  symlinked parent directory is admitted without resolution, as it always was;
  and a checkpoint row whose parent directory has since been removed is now
  refused at the guard rather than admitted, where the restore used to run
  `ensure_directory` and recreate the tree with `mkdir -p`. That is the
  fail-closed direction, and it is a behaviour change rather than a defect
  fixed: the probe cannot say what a path under an absent parent would become.

  The probe elevates exactly when the executor's own `write_file` does.
  `SshExecutor::write_file` goes through `sudo tee`, so a remote probe
  elevates; `LocalExecutor::write_file` writes as the process user, so a local
  probe does not. Elevating unconditionally would have made a local probe
  answer for root while a local write happened as somebody else, which is the
  same mismatch pointed the other way.

  A path spelled with a trailing slash, or with a trailing `/.` or `/..`, made
  the kernel resolve the final named component before the check, so a symlink
  answered "not a symlink", the admitting answer. Trailing slashes are now
  normalised away, and a path whose final component is `.` or `..` is refused
  rather than guessed at, because resolving a dot segment by name disagrees
  with the kernel whenever the component before it is a link.

  `SystemExecutor::canonical_path` was removed. It had no callers once the
  guard moved, and the reasoning it carried now lives on `LINK_PROBE_SCRIPT`.
  Closes #83.

- **The rollback symlink guard asked the machine running the tool, not the
  machine being rolled back.** `rollback_target_refusal` decided whether a
  restore may write a path by calling `Path::is_symlink` and
  `Path::canonicalize`, both `std::fs` syscalls against the controller's own
  filesystem, while the path named belongs to the target host. Both remote
  rollback paths reach it with an `SshExecutor` active, single-host
  `hardener rollback --ssh` and per-host `hardener batch rollback`, and it was
  wrong in both directions. Fail-open: a remote path the checkpoint recorded as
  a regular file, standing now as a symlink into a directory the allowlist
  excludes, does not exist on the controller, so `is_symlink` answered false,
  the prefix allowlist became the whole check, and the restore wrote a captured
  copy through the link. The identical local case has always been refused.
  False refusal: a link the controller happened to hold at an allow-listed path,
  resolving outside it, refused a remote rollback of that path with a message
  naming a path the operator reads as the remote's, and if every restorable row
  was such a path the whole rollback aborted. The check now resolves through
  `SystemExecutor::read_link`, the same primitive capture has used since
  `link_target_of`, for the question of whether the path is a link at all, and
  through a new `SystemExecutor::canonical_path` for the question of where it
  leads. Two questions, two primitives, and the split is the load-bearing part:
  `canonical_path` is `realpath` semantics, every component resolved by the
  filesystem that owns them, which is exactly what `Path::canonicalize` gave and
  must not be given up to reach the target host. Resolving the chain here
  instead, one hop at a time with `..` flattened by name, is wrong wherever the
  component before a `..` is itself a link: with `<allowed>/dlink` pointing at a
  directory outside the allowlist, `<allowed>/f -> dlink/../victim` collapses by
  name to `<allowed>/victim` and is admitted, while the write lands on
  `<outside>/victim`. That was measured on a real filesystem, not reasoned
  about, and it is why the resolution is asked rather than computed. A path that
  does not resolve to something that exists, whether from a dangling target, a
  missing component, a traversal that is refused or a symlink loop, is refused:
  what the write would reach is unknown, and that is the same answer
  `canonicalize` returning `Err` produced. Unchanged: the prefix allowlist, the
  exemption for a row carrying a link target, and the exemption for a row
  recorded absent, both of which restore onto the path itself and follow
  nothing; and the scope of the check, which is still a path whose own final
  component is a link, since a regular file under a symlinked parent was
  admitted by `Path::is_symlink` too.

- **The shared IPC string guard let U+007F through the check that exists to
  reject control characters.** `validate_ipc_string` tested `b < 0x20`, and DEL
  is `0x7F`, so the one ASCII control character above space passed a guard whose
  name, doc comment and error message all say it rejects control characters. It
  is the check on 31 call sites, among them `webhook_url`, `from_address`,
  `email_recipient`, `schedule`, `checkpoint_name`, `config_path`,
  `output_path`, `key_file` and `hostname`. Reached live rather than reasoned
  about: a `Delete` keypress that inserts a literal DEL left one in the
  desktop's webhook URL field, and the save wrote it into the config as an
  endpoint URL. No caller mishandles it today, and the TOML serialiser escapes
  the byte so nothing breaks out of its string; the defect is that a guard did
  not do what every description of it says. Tab stays permitted, deliberately.
  The C1 range is still accepted, because it is multi-byte in UTF-8 and no
  single-byte comparison reaches it; that is recorded at the function rather
  than left to be discovered.

- **A partial `--config` re-enabled a plugin the system configuration had
  disabled, on the verb that writes.** A plugin section's `enabled` key was a
  `bool` defaulting to `true`, so a later source that mentioned a section for
  any reason at all, a single directive included, supplied `enabled = true` for
  it. A file that asked for the plugin and a file that merely named it were
  indistinguishable. Site policy disabling `mac-hardening` was therefore undone
  by `sudo hardener apply --all --config /tmp/tighten-ssh.toml`, and the plugin
  was applied; the desktop makes this the ordinary case, since it persists a
  user-picked config file and passes it to the privileged apply, and such files
  are typically partial. The key is now an `Option`, so a section that does not
  state it decides nothing and the earlier decision stands. An explicit
  `enabled = true` still revives a plugin, and an explicit `enabled = false`
  still disables one. Read it through `PluginConfig::is_enabled`, which answers
  `true` when no source stated it, so a configuration that mentions the key
  nowhere behaves exactly as it always has.

- **Two ad-hoc targets for one machine could file their checkpoints under a
  single key, so a fleet rollback could restore already-hardened state and
  report success.** The checkpoint host key comes from
  `SshExecutor::description`, which substitutes a literal `root` when a target
  named no user, so `--ssh web-01` and `--ssh root@web-01` are two targets
  everywhere else and one host key there. Checkpoints are scoped by
  `(host key, name)` and the newest per key wins, so under `batch apply
  --execute` both captured a pre-apply checkpoint under the same pair and the
  survivor could be the one taken after the other target had already hardened
  the machine. The cross-host guard could not refuse the later rollback, because
  by its measure the two keys are equal. This was not a race introduced by
  concurrency: `--concurrency 1` serialises the two captures and still writes
  both under one key. A fleet run that writes now refuses such a selection,
  exit `2`, before it opens a connection, naming both targets and the single key
  they would have shared. The refusal covers `batch rollback --execute` as well
  as `batch apply --execute`: rollback takes its own reversible-rollback
  snapshot through the same path, and it also *reads* by host key, so a
  colliding pair could restore one target from the other's checkpoint. The key
  itself is unchanged, so no stored checkpoint is affected; correcting it means
  resolving the effective remote user at connect time, which orphans every
  checkpoint already filed under the old key and is a separate decision.

  **This closes the collision within one invocation and not the underlying
  defect.** The newest checkpoint per key wins across the whole database rather
  than within a run, so reaching one machine as `--ssh web-01` in one run and as
  `--ssh root@web-01` in another still files both under one key, with no
  selection to refuse, and the single-host `apply` and `rollback` verbs never
  reach this check at all. Until the key is corrected, reach a given machine by
  one and only one form of target. Both the limitation and the key format are
  now documented in the CLI reference, which had never recorded either despite
  two commit messages claiming it did.
- **`batch apply --execute` hardened an entire fleet from the compiled-in
  defaults when the `--config` path it was given could not be loaded.** The
  fleet loader warned on stderr and fell back for any configuration failure: a
  mistyped or moved path, a parse error in any source, or a directive the
  validator rejected. That file decides which plugins write, the values they
  write and the violations deliberately excepted, so the fallback did not change
  what was reported about the hosts, it changed what was written to them, over
  SSH, on every host in the run. Nothing recorded that policy had been
  defaulted, so the run still exited `0` on success, and the `nothing_ran()`
  guard could not fire either: it refuses a run that hardened nothing, and the
  defaults enable every plugin. A named `--config` that will not load is now
  fatal for that run, before the first connection is opened, and it exits `2` to
  match the tier `batch` already uses for its own usage refusals. This is the
  fleet half of the single-host `apply` fix, which was deliberately left out of
  that change because refusing mid-fleet alters fleet behaviour and wanted
  deciding on its own. `batch rollback` is unaffected: it reads no config at all.

  Two limits of this fix are worth stating rather than leaving to be discovered.
  **The verbs that do not write to a host keep the fallback**, so `batch scan`,
  `batch report` and `batch apply` without `--execute` still warn and continue.
  That is not free: a fleet scan persists a session per host into the scheduler
  database, and the findings it stores come from the config, so a defaulted run
  writes a different plugin set at different thresholds into rows that outlive
  the warning and are later read by `history trends`, `history regressions` and
  the daemon's regression notifications. It can therefore manufacture or mask a
  regression on a later run where no warning is in sight. Refusing there too was
  considered and not taken, because those verbs change no host. **And the guard
  keys on the flag, not on the outcome**: a run that names no `--config` still
  degrades to defaults when the controller's own `/etc/linux-hardener/config.toml`
  is present but broken, which is the behaviour single-host `apply` also keeps.
  The desktop's Fleet Apply passes no `--config` at all, so it cannot reach this
  refusal and is exposed to exactly that case.
- **Debian hosts hardened by any release up to and including 1.5.1 may have no
  firewall at all, while the tool reported one was applied.** `apply --plugin
  firewall-hardening` decided ufw was already enabled when `systemctl is-active
  ufw` printed `active`, and skipped enabling it. Debian ships `ENABLED=no` in
  `/etc/ufw/ufw.conf` and its `ufw` unit is a oneshot that reports active having
  loaded no rules, so that check passed on a host with no firewall. The
  subsequent `ufw allow` commands succeeded, because they write ufw's own rule
  files rather than the kernel's tables, and the tool reported three applied
  changes against a kernel holding an empty filter table and a default-ACCEPT
  policy. Measured on the Debian test container: identical binary, identical
  run, Arch ended with a 392-line ruleset and `-P INPUT DROP` while Debian ended
  with nothing. **Check an affected host with `ufw status` (not `systemctl
  is-active ufw`) and run `ufw --force enable` if it reports inactive.** The
  activity probe now asks ufw rather than systemd; the unit hint is still used,
  but only where it belongs, to mark a root-blocked probe as unverified rather
  than as confirmed.
- **Arch hosts hardened by any release up to and including 1.5.1 lose their ufw
  firewall at the next reboot, while the tool reported it enabled.** `apply
  --plugin firewall-hardening` turned ufw on with `ufw --force enable` and did
  nothing else. That command writes `ENABLED=yes` into `/etc/ufw/ufw.conf` and
  loads the rules into the running kernel, but it never asks systemd to want
  the `ufw` unit at boot: ufw's own code contains no call to `systemctl` at
  all. Whether the unit starts at boot is decided by the distribution's
  packaging, and Debian's package enables it where Arch's does not. Measured by
  booting the hardened Arch test container: `systemctl is-active ufw` read
  `inactive`, `/etc/ufw/ufw.conf` read `ENABLED=yes`, and
  `/etc/systemd/system/multi-user.target.wants/ufw.service` did not exist. The
  same check on Debian showed the symlink present and the unit active, so
  Debian is unaffected. **Check an affected host with `systemctl is-enabled
  ufw` and run `systemctl enable ufw` if it reports disabled.** The ufw backend
  now runs `systemctl enable ufw` after turning the firewall on, and a unit
  that cannot be enabled fails the apply with systemd's own message, matching
  what the firewalld backend has always done.
- **A firewall that is running but will not come back after a reboot is now
  reported, and repaired.** The fix above only reaches a host whose firewall is
  off when `apply` runs, because `enable` is called only when the firewall is
  not already running. A host already running an unwanted unit, which is every
  Arch host hardened by an earlier release, was skipped and no re-run could
  repair it. Scan now asks systemd separately whether the backend's unit starts
  at boot and reports a High finding when it does not, with its own id rather
  than the existing `{backend}-disabled` one, because a running firewall is not
  a disabled one. Apply enables the unit, and records a skipped no-op when it
  was already wanted. Two answers that look like success are treated as the
  faults they are: `enabled-runtime` is an enablement held in `/run` and
  discarded at the next boot, and a unit with no `[Install]` section cannot be
  enabled at all; both exit zero, so the state is judged on systemd's word and
  never on its exit code. A question systemd cannot answer becomes an unchecked
  entry rather than a silent pass. **On nftables this makes the unit start
  without making this tool's rules come back**, because that backend writes into
  the running kernel and never into `/etc/nftables.conf`; that gap is separate
  and still open.
- **A host running ufw may be reverting kernel parameters at every boot, and no
  release up to and including 1.5.1 said so.** The kernel plugin writes
  `/etc/sysctl.d/99-hardener.conf` and treated that as its boot-persistence
  guarantee. `ufw.service` is ordered after `systemd-sysctl` and applies its own
  sysctl file when it starts, so whatever that file sets lands after everything
  in `sysctl.d`. Measured on the booted Debian test container:
  `99-hardener.conf` holds `log_martians = 1` and the running kernel reads 0,
  because the ufw package ships a file setting both `log_martians` scopes to 0.
  A host reported compliant therefore stopped being compliant at its next
  restart. `scan` now reports a `kernel_boot_override_*` finding for a managed
  parameter that a unit applies after `systemd-sysctl` has run, at that
  parameter's own severity, because what is at stake is the setting's
  consequence arriving at the next boot rather than now. A `sysctl.d` drop-in is
  deliberately not reported: those are applied in filename order and
  `99-hardener.conf` sorts after what distributions ship, so reporting mere
  presence would raise findings on hosts that have no defect. ufw applies its
  file only where its own `ENABLED` flag in `/etc/default/ufw` says yes, and
  that gate is honoured, so an installed but disabled ufw raises nothing.
  **The check is report-only.** Editing another package's configuration is not
  this tool's to do, so `apply` gains no change and writes no file it did not
  write before; the repair is to remove the managed parameters from the other
  package's file by hand.
- **Fedora, RHEL and openSUSE hosts were reported as having SSH crypto
  hardening they did not have, in every release up to and including 1.5.1.**
  Those distributions ship a layout where `Include
  /etc/ssh/sshd_config.d/*.conf` sits above everything this tool writes and
  crypto-policies supplies `Ciphers`, `MACs` and `KexAlgorithms` from a drop-in,
  and sshd uses the **first** value it obtains. `scan` resolved `Include`
  directives for every other directive and kept reading those three from the
  main file alone, so the tool wrote a strong list into `sshd_config`, read it
  back, and reported the host compliant while sshd went on negotiating whatever
  the drop-in said. Those three directives are declared in the plugin's
  `coverage()`, so the missing finding was not merely silence: the report
  generator passes an assessed control that produced no finding, and the
  compliance report claimed those controls too. The mirror was wrong in the
  other direction, and cost an operator differently: a drop-in already holding a
  strong list read as "not set", so the tool raised a finding against a
  compliant host and sent them to edit a file that decides nothing. `scan` now
  reads the crypto directives from the resolved configuration and names the file
  in force when it is not the main one, and `apply` routes an overridden crypto
  directive to `/etc/ssh/sshd_config.d/00-hardener.conf`, whose precedence is
  verified afterwards by re-resolving the configuration rather than assumed from
  the filename. **This tool overrides a distribution's crypto-policies fragment
  rather than deferring to it**, because a hardening run that reports a change
  must make one; a file underneath offering only algorithms from the allow-list
  is left alone and recorded as a skipped no-op instead. **Check an affected
  host by asking sshd rather than the file: `sudo sshd -T | grep -iE
  '^(ciphers|macs|kexalgorithms)'`.**
- **openSUSE hosts hardened by 1.5.0 or earlier may be storing DES password
  hashes, and should have those passwords set again.** Those releases wrote a
  short `/etc/login.defs` on a distribution that keeps its copy under
  `/usr/etc`, and that override is whole-file rather than per directive, so
  every key the vendor file set stopped applying. Measured on openSUSE Leap:
  `ENCRYPT_METHOD SHA512` stopped applying and shadow fell back to **DES**,
  which truncates a password at eight characters however long it was typed, and
  `HOME_MODE 0700` stopped applying, so new home directories were created
  world readable at 755. This release stops the masking happening, and reports
  it where it has already happened, but it cannot undo it: a password already
  hashed with DES stays DES until it is set again, and an `/etc/login.defs`
  that already exists is edited rather than replaced, so the keys an older
  release dropped stay dropped until they are restored by hand. `hardener scan`
  now names them in a Medium finding, `pam-login-defs-masked-keys`. Checking and
  repairing an affected host is written out in
  [docs/guide/upgrading.md](docs/guide/upgrading.md#150-and-earlier-opensuse-hosts-may-have-a-short-file-masking-the-vendor-copy).

### Added

- **A fleet host's compliance count can be drilled into.** The Hosts panel
  showed a score and per-framework pass/fail/manual counts with no way to find
  out what they were counts of. `FleetFrameworkPosture` now carries one
  `ControlOutcome` per control the summary counted, and the host panel renders
  a collapsed list per framework, reusing the compliance tab's own
  `control-row` markup and `.status-*` classes so one verdict cannot read two
  ways across two screens. Manual review stays amber and never red: a control
  the engine does not assess is a gap in coverage, not a gap in the host, and
  `control_status_class` moved into `utils` so both screens share one mapping.
  The rows were already being computed and thrown away: `posture_for_findings`
  generated a full `ComplianceReport` per framework and kept two of its fields.
  `ControlOutcome` is `ControlResult` without `control_findings`, deliberately:
  a control's findings are selected by a pure filter on each finding's own
  `finding_compliance` mappings, so a consumer holding the host's
  `scan_results` reproduces them exactly and duplicates no backend judgement,
  while the `ControlStatus` needs the coverage and exception logic the
  generator owns and so is what travels. Measured on one host across the nine
  fleet frameworks, 145 controls: these rows are 23 KB against 222 KB for the
  full `ControlResult`s, on a per-host response already carrying 122 KB of
  `scan_results`. No IPC command, no capability entry, no database and no
  migration are involved, contrary to the issue's own description of the work.
  Closes #50.

- **`hardener checkpoint repair` reports file rows that no checkpoint owns, and
  removes them with `--execute`.** A checkpoint is stored as one metadata row
  plus one file row per captured file. A file row whose checkpoint row is gone
  can never be listed, restored or deleted: `checkpoint delete` refuses an id
  matching no metadata row, and it is the only other statement in the tree that
  removes from that table, so such a row was unreachable. A clean answer is the
  expected one, because the schema declares the foreign key and the database is
  opened with enforcement on, so nothing acting through this tool can strand a
  row. What this repairs is a database edited by something else: `sqlite3`
  defaults that enforcement off, so deleting a checkpoint row by hand leaves its
  file rows behind. Reporting is the default and `--execute` is required to
  delete, matching `batch`, where a destructive run is asked for explicitly.
  Counting and removal share one SQL predicate, so a repair cannot reach a row
  its own report did not offer. Under `--format json` a report and a removal are
  told apart by `executed` rather than by a count that happens to be zero. It
  refuses `--ssh`, like `checkpoint show` and `delete`, and a removal is written
  to the audit log.

- **`validate_file_map.py` derives the test counts `file-map.md` claims.** Five
  rows describe a test module by how many tests it holds, and the number was
  kept by hand; it drifted twice in two sessions. Each claim is now checked
  against the `#[test]` and `#[tokio::test]` declarations in the file the row
  names, both spellings, so a module that gained an async test cannot start
  undercounting without saying so.

- **The same validator now enforces `file-map.md`'s per-crate annotation
  counts.** That column names a crate rather than a file and carries no "N
  tests" phrase, so the per-file rule above could never see it, and it drifted
  three times in two days: every time because a commit added tests elsewhere in
  the branch and the number was already written. Each row's last column is
  checked against the annotations declared across the whole crate, tests
  directory included, which is exactly what the table says it holds. The count
  has to be taken after the last test in a branch rather than before it, and
  the failure message says so.

- **`/etc/sudoers` and `/etc/sudoers.d` are reported on by a compliance
  framework.** Both fell through the catch-all arm of the permissions plugin's
  mapping table, so neither contributed a control identifier and a framework
  report rendered them as neither Pass nor Fail nor ManualReview. They were
  absent, which is quieter than a wrong answer and harder to notice: a reader
  looking for sudoers found nothing and could not tell whether the tool had
  checked and was content or had never looked at all. Both paths are Critical
  and both now carry the seven control identifiers already sourced in that file
  whose titles name no file, on the same reasoning that puts least privilege
  and access restriction on `/etc/shadow`. CIS and PCI-DSS are deliberately
  left out and the reason is recorded at the site: a CIS control names its own
  file in its title, so `/etc/shadow`'s cannot be transferred and no sudoers
  control identifier exists anywhere in this tree to put in its place, and
  PCI-DSS is decided per file by the upstream SSG rule, which is why
  `/etc/gshadow` already drops it. Both absences are asserted by a test, with
  the account files as its positive control, so the set cannot be completed by
  inventing the two.

### Changed

- **Ten of the eleven kernel rows in the differential suite now arrive loosened,
  so they can no longer pass on a host that was already compliant.** The suite
  seeded one parameter below the tool's target before the first apply,
  `net.ipv4.conf.all.accept_source_route`, and the other ten read their target
  before the apply and read it again after: no mutation of the kernel plugin
  could have moved either reading, so ten of the eleven assertions were vacuous
  on an already-compliant container. `SEEDED_LOOSER_KERNEL_CHECKS` now carries
  every askable row except `net.ipv4.tcp_syncookies`, each seeded in the
  direction that scores it, 1 for an `at-most 0` row, 0 for an `at-least 1` row,
  and 0 for `rp_filter`, whose space is ranked `0,2,1` weakest first and whose
  looser value is therefore not the larger number. If the plugin does nothing
  the seeds are still standing when the checks read them, and all ten fail.
  `tcp_syncookies` is excluded because `SEEDED_KERNEL_CHECKS` seeds it *stricter*
  to ask whether an apply un-hardens a host already ahead of its target: one
  parameter cannot carry both seeds, since whichever write landed second would
  decide the reading and the check that lost would be scoring the other one's
  seed. That row stays vacuous in `KERNEL_CHECKS` and is answered by
  `run_seeded_kernel_check` instead. The pre-apply control gained the assertion
  the seeds' own read-backs cannot make: a seeded parameter the capture finds
  back at its target fails the control by name, because a read-back proves what
  the kernel reported at seed time while the control scores a capture taken
  afterwards, and without it nine loosened rows would carry a tenth that was as
  vacuous as before. The self-test pins the arithmetic rather than the literal,
  so a twelfth askable parameter cannot be added without a seed in one table or
  the other. No total moves: the loosened rows are already counted among the
  eleven. Part of #47; the remaining plugins there are unaffected.

- **`--format csv`, `--format html` and `--format pdf` are refused rather than
  rendered as text.** The global `-f`/`--format` flag was typed as the
  compliance crate's five-valued enum because that enum already existed, so clap
  accepted all five on every command in the binary while **not one command
  rendered any of the three**: every renderer matches JSON and sends the rest to
  a text arm, making csv, html and pdf byte-identical aliases of text. Measured
  by hashing the output of eight verbs across all five values, rather than
  inferred. The sharpest edges were `batch report`, the fleet compliance surface,
  which has no `--report-format` of its own and so had the global flag as its
  only lever; and `hardener --format pdf history export <id> -o report.pdf`,
  which wrote a JSON document into a file named `report.pdf` and exited 0. The
  flag now has its own two-valued type, so clap refuses the other three when the
  arguments are parsed, exit 2, listing what it does render. **No capability is
  lost**: the CSV, HTML and PDF formatters were never reachable through this
  flag, and `report --report-format` and the interactive wizard still reach them.
  The manual page was wrong in both directions and is corrected: it promised the
  three on the global flag and denied them on `--report-format`, which is the
  one flag that has always had them.

- **`--port` reaches a `batch` ad-hoc target instead of being dropped.** The one
  site that parses `--ssh user@host` targets for the fleet verbs passed the
  literal `22`, while `--ssh-key`, `--ssh-timeout` and `--ssh-no-verify` all
  reached them, so `hardener --ssh web-01 --port 2222 batch scan` dialled 22.
  On a host answering on both ports that scanned the wrong daemon, with a
  different `Port`, `ListenAddress` and `Match` set from the one the operator
  named, and the report called the host `web-01:22`. It is the same
  accepted-and-discarded defect as the refusal below, on the one command that
  shares `--ssh` with the global flag. A port written into the target still
  outranks the flag, and inventory hosts still carry their own.

- **`--ssh` is refused by the commands that never acted on the target, instead
  of being accepted and discarded.** One executor is built for the whole
  process and handed to some commands and not to others, and from the outside
  the difference was invisible: `daemon`, `systemd`, `history`, `plugins` and
  the two checkpoint verbs that address a row by id opened the connection,
  announced it unless `--quiet` had silenced that line, and then read and wrote
  the controller. `hardener --ssh web-01 daemon run-once` scanned the machine it
  was typed on and filed the result under that machine's name; `hardener --ssh
  web-01 history list` printed the controller's own history, which an operator
  could easily read as the remote's. The flag's only live effect on those
  commands was that an unreachable target stopped them, so it could refuse work
  and never redirect it, and under `--quiet` it did both without a word. **They
  now exit 2 with a message naming themselves and what they act on instead,
  before any connection is opened**, so a refused command costs no round trip,
  no key prompt and no host-key decision. `history` says in the same breath that
  a host inside the history is selected with `--host`, which is the question its
  operators were really asking, and `daemon run-once` names `hardener --ssh HOST
  scan`. **This is a behaviour change**: a command line that used to run, having
  quietly done the wrong thing, now fails. Nothing that reaches a host changes:
  `scan`, `apply`, `rollback`, `report`, `checkpoint list`, `checkpoint create`
  and `batch` all keep the flag, and `batch`'s own `--ssh` is the same argument
  as the global one, so `--ssh host batch scan` and `batch scan --ssh host`
  remain one invocation naming one ad-hoc target. `checkpoint show` and
  `checkpoint delete` are refused rather than scoped deliberately: their id is
  unique across every host in the database, and scoping them to a host would
  have made the rows of a decommissioned host unreachable, since its key cannot
  be produced without connecting to it.

- **`UncheckedCheck` records what blocked a check rather than a single
  boolean.** `unchecked_needs_privilege: bool` is replaced by
  `unchecked_blocker`, one of `Privilege`, `Environment` or `Unknown`. The
  boolean had to stand for two situations that need opposite advice: the
  session is not privileged and a re-run with sudo would reach the check, or it
  is already privileged and something else blocks it, so sudo changes nothing.
  There was nowhere to record the second, and four producers asserted the first
  without checking anything, which is how a container running as uid 0 came to
  be told to try again as root.

  **Two consequences worth knowing before you upgrade.** A scan already in your
  history was persisted with the old field, which no longer exists, so it reads
  back as `Unknown` and the desktop stops offering "Run with sudo" for it until
  you rescan. Nothing errors and no history is lost. Separately, `batch
  --format json` now emits `unchecked_blocker` with a string value in place of
  `unchecked_needs_privilege` with a boolean, so anything outside this project
  keying on that field needs updating.

  **Four plugins now ask before they answer.** `firewall`, `audit`, `mac` and
  `ssh` asserted that a privileged re-run would reach a check they could not
  perform, without ever asking whether the session was already privileged. On a
  host running as root that is a remedy the operator has already applied, and
  whatever stopped the probe stops it again. Each now records `Environment` when
  the session is already uid 0 and `Privilege` otherwise, so an unprivileged
  scan reports exactly what it always did and a privileged one stops sending
  the operator in a circle. The uid probe behind it is one definition shared
  with the CLI's privilege gate and the ssh plugin's remote-root guard, which
  had each grown their own copy.

  Two entries also stopped claiming things they had not established: a plugin
  whose own scan failed is no longer reported as beyond privilege's reach, since
  the reason is that plugin's prose and nothing reads it, and the ssh entry
  raised when Include resolution fails no longer says "reading
  /etc/ssh/sshd_config requires root" about a file it read successfully three
  lines earlier.
- **The differential test suite asks whether settings the tool does not manage
  survived the run.** `ENCRYPT_METHOD`, `HOME_MODE` and `UMASK` are captured
  before apply and again afterwards and must be unchanged, each read from the
  setting's own consumer rather than from a configuration file. The assertion
  is the invariant, never a particular value, because the correct value differs
  between distributions while "unchanged" does not. Nothing in the suite
  previously asked this, so a masking regression could have reappeared with
  every existing check green. The per-distribution total moves from 22 checks
  to 25, and the five-distribution total from 110 to 125.
- **The full test suite asks whether a rollback undid anything.** Its per-plugin
  lifecycle section applied a plugin and rolled it back, and its only rollback
  assertion was that the command exited 0, so it reported a pass for a rollback
  that restored nothing. That is the defect family this project keeps finding in
  its own product, and two instances of it were fixed in the audit plugin alone
  while the suite read the same 126 of 126 on five distributions before and
  after. New section 12A applies audit hardening, rolls it back and then reads
  the filesystem: the rules file must be gone, `/etc/audit` must list exactly
  the paths it listed beforehand, and the compiled rule set must be back at its
  pre-apply line count. It runs first inside the apply block by necessity, since
  a rollback can only be seen to *remove* a created file on a host that does not
  have it yet, and it refuses to report at all on a container an earlier
  `--apply` run has already hardened, because a reading taken there would answer
  a different question. The per-distribution total moves from 126 tests to 133.
  A services arm is owed and deliberately absent: reading the equivalent mask
  defect needs a unit the plugin manages, and no container image installs one.
- **The services arm that entry says is owed now exists, as section 12B**, and
  it takes the per-distribution total from 133 to 140. It asks the same
  questions of `systemctl mask`: that the apply created the mask link, that the
  rollback removed it, that the unit is enabled again afterwards and that
  `/etc/systemd/system` lists exactly the paths it listed before. It needs a
  host running systemd, says so before doing anything, and under `--pipe` skips
  while naming the flag that would let it run.
- **The suite refuses a run whose size it did not expect.** That total has moved
  twice without anyone deciding it should, 126 to 133 and 133 to 140, and
  nothing held it, so a section that quietly stopped recording checks would have
  read as a shorter run rather than as a fault. Each section now declares how
  many checks it records, the declarations are counted off the pinned lengths of
  the plugin, framework, scenario, format and severity tables rather than off
  the tables themselves, and a run that recorded a different number is reported
  as a failure rather than only as a non-zero exit, because the cross-distro
  runner writes PASS into its summary for any distribution whose failure count
  is zero. The five per-distribution logs of the last full run were counted
  section by section to establish the declarations, and all five agreed on every
  section.
- **The per-plugin lifecycle section asks what its apply and its rollback did.**
  Section 23 applies, re-scans and rolls back kernel, ssh and permissions on a
  host sections 13 to 15 have already hardened, and it could see none of that.
  Its rollback was judged on the exit status alone. Its finding count was
  compared with `-le`, which is satisfied by nothing having happened, so the
  false branch was unreachable on every host the suite runs on and fifteen
  readings across five distributions all read N to N. Its checkpoint was chosen
  with `head -1` over an unfiltered listing, so a plugin whose apply failed
  before taking one would have rolled back another plugin's snapshot and
  reported a pass for undoing somebody else's work. The count is now compared
  for equality, with each direction named, and the checkpoint comes from the
  apply's own result document, which is the only place the pairing between an
  apply and the checkpoint it took exists. A plugin whose apply had nothing to
  do takes none, ssh says so at its own apply site, and the rollback rows are
  then skipped with that reason rather than rolling back some other apply's
  checkpoint. The host is re-scanned after the rollback as well, and the count
  must be where the apply found it, which is what a rollback removing a drop-in
  it should have restored would break. A scan that produced no document is told apart from a host with
  no findings, because a failed scan prints no finding id and its count of zero
  compared equal to a clean host's. Whether a rollback removes what an apply
  created cannot be asked at this position, since the apply here changes
  nothing, and that question stays with sections 12A and 12B. The
  per-distribution total moves from 140 to 149.
- **Three more validators.** `validate_doc_attachment.py` catches a `///`
  block that came loose from the item it describes, which is what happens when
  a new item is inserted between a comment and its function: it compiles,
  rustdoc renders, and the only symptom is one function documented as two
  things while the function the prose describes has nothing. Eight instances
  had accumulated.
  `validate_write_sites.py` is a registry holding every file-creating call site
  in the plugins tree to two written answers, why its parent directory exists
  and whether the path it creates is declared to that plugin's own pre-apply
  checkpoint. Both questions were answered by hand, three times and twice
  respectively, before anything swept for them, which is the point at which this
  project stops fixing instances one at a time. That script also asserts that
  every `cp` site passes both `-p` and `--no-dereference`, as an assertion
  rather than a registry column, because unlike the other two that question has
  a single correct answer everywhere and a column would only offer somewhere to
  write "exempt". `validate_unit_state_reads.py` holds every `systemctl
  is-enabled` site to a declared answer about whether it judges the printed word
  or the exit status, because the three sites differ deliberately and a rule
  banning either reading would be wrong at one of them.
- **The cross-distro runner can boot the container it tests in.** Under `--pipe`
  the suite itself is PID 1, so systemd never runs and every question that goes
  through the service manager is unanswerable, which is why services, audit and
  firewall had no differential oracle. `--booted` runs the same suite as a child
  of the container's own systemd instead, leaving `--pipe` untouched as the
  default so every measurement taken under it stays valid. The container is
  given `--private-network` rather than `--network-veth`, measured rather than
  reasoned about: both give an identical capability set with `CAP_NET_ADMIN`,
  the same read-write `/proc/sys/net` and the same working iptables.
- **The release notices that used to open `README.md` now live in
  [docs/guide/upgrading.md](docs/guide/upgrading.md)**, organised by the version
  a host is being upgraded **from** rather than by the release that fixed the
  defect, so an operator reads the one section that applies to the host in front
  of them. `README.md` describes the tool before it apologises for it.

- **Six more validators, so `scripts/validate/validate_all.py` runs sixteen
  checks.** `validate_doc_targets.py` holds `update_all_docs.py`'s declared
  target lists and the tree to each other in both directions, because the
  updater silently skips a target whose file is missing and then reports "no
  changes needed" for work it never attempted: five compliance files it names
  had been deleted six weeks earlier and every run said there was nothing to
  do. `validate_badges.py` compares the committed badge SVGs against the
  generator that declares them, which had drifted to a different version and a
  different test count, making the documented regeneration step destructive.
  `validate_test_assertions.py` refuses a test whose every assertion sits
  inside an `if`, a `for` or a `match` arm, since such a test asserts nothing
  when the condition does not hold and still counts towards the total everyone
  reads. `validate_policy_exception_sites.py` fails on a finding that hardcodes
  its policy exception to `None` with no comment beside it, because counting
  those sites cannot tell an oversight from a decision and neither can a test
  asserting the field is `None`. `validate_srcinfo.py` holds
  `packaging/.SRCINFO` to `packaging/PKGBUILD`, field by field always and byte
  for byte against a fresh `makepkg --printsrcinfo` where `makepkg` exists.
  `validate_changelog_headings.py` refuses a release entry that repeats a
  change-type heading, which had happened in four releases unnoticed.
- **The full test suite's dry-run and apply rows read the document they are
  given.** Both passed on the command exiting 0 or on a result document merely
  existing, so a row read the same whether the plugin's preview was correct,
  wrong or reverted to an earlier version. Each now compares the exit code
  against the document's own verdict, which the CLI derives one from the other:
  a dry run fails on a Critical or High validation issue, and for a single
  plugin an apply's exit code is exactly `apply_success`. A run that exits
  non-zero with nothing in its report to explain it is now a failure, and the
  blocking issues are printed into the log, so a run can say which blocker
  fired rather than only that one did.

### Fixed

- **An IPv6 firewall `source` rendered an IPv4 match, and under one transaction
  that cost the entire ruleset.** `build_nft_rule_args` emitted `ip saddr` for
  every source whatever family it was in, so `ssh.source = "::1"` rendered
  `ip saddr ::1`, which `nft` refuses with "Address family for hostname not
  supported". Nothing upstream refused the value: the configuration layer admits
  a `:` in a source, and the #64 breadth clamp reads `::1` as a narrowing of the
  baseline `any` and permits it. Under the old per-rule path one bad value cost
  one rule and the other baseline rules still applied; under the single
  transaction the load is refused outright, so **no** baseline rule lands, the
  default drop included. The family now comes from parsing the address with
  `std::net`, so `ip` and `ip6` are chosen by what the value actually is rather
  than guessed.
  A source that parses as neither, which the clamp deliberately does not check
  because it measures prefix width alone, now **refuses the whole ruleset before
  anything is written**. That ordering is the second half of the fix: the write
  precedes the load, so a ruleset that rendered and then failed at `nft` left
  the host holding a file `nftables.service` cannot parse, at the path it loads
  from at boot, on a unit the same apply had already enabled. Closes #94.

- **The four tests guarding the rendered nftables ruleset could not fail.**
  Each asserted with `contains` or `find` over the whole rendered blob, which
  anchors a needle to nothing, and two mutations proved the cost while the whole
  suite stayed green. Rendering every statement behind a `# ` marker ships the
  input chain with `policy drop;` and no effective rules, which is the lockout
  of #92 delivered in one transaction instead of two, and every needle still
  matched inside the commented line in the same byte order. Slicing the argv
  from index 4 rather than 5 prefixes every statement with the chain name, which
  `nft` refuses outright, and a needle built from `args[5..]` is then a suffix
  of the rendered line and invisible to `contains`. The assertions now compare
  whole lines for equality, against the input chain's rules alone, so a
  commented-out statement is not its statement and a prefixed one is not
  either; the chain is additionally required to hold one line per baseline rule
  and nothing else, which refuses an addition as well as a removal. Both
  mutations are now killed by a named assertion. Closes #96.

- **The SSH test-container boot script could not cold-boot a container, which
  is the only thing it exists to do.** Its registration wait read
  `machinectl status` into a bare assignment through a pipeline. Until the
  machine registers that command exits non-zero, `pipefail` promotes it to the
  pipeline's status, and a bare `x="$(cmd)"` under `set -e` aborts on it, unlike
  the `local x="$(cmd)"` form. The first loop iteration therefore killed the
  script silently, before its own timeout branch or `diagnose` could print
  anything, so the documented 60 second registration window was unreachable. The
  script only ever succeeded against a machine that was **already** registered.
  A cold boot left the machine running with its veth down and no address, and
  the next thing an operator saw was an unrelated SSH timeout against
  `10.242.117.2`. Because the `#[ignore]` SSH integration tests need this script
  to bring their fixture up, they have been unrunnable from a cold start.
  Proved in isolation: `set -euo pipefail; x="$(false | awk '{print}')"` exits 1
  without reaching the next line, and reaches it with `|| true` appended inside
  the substitution. Verified live by a real cold boot afterwards.

- **A firewall port range reached ufw in a syntax ufw refuses.** `rule_port` was
  passed to each backend as written, and the three backends do not agree on how
  a range is spelled. nftables (`dport 80-443`) and firewalld (`80-443/tcp`)
  both take the dash, which is also the one form `validate_firewall_value`
  accepts, so the dash is the canonical separator. ufw wants a colon and rejects
  the dash outright, measured rather than inferred: `ufw --dry-run allow to any
  port 80-443 proto tcp` answers `ERROR: Bad port '80-443'` and exits at the
  parser, while `80:443` gets past it to the root check. The translation now
  happens in the ufw backend, at the one place the difference lives, and the
  other two are untouched. Reachable through `loopback.port = "80-443"`, which
  narrows an accepting rule whose baseline port is `any` and so passes the
  directive clamp; on a ufw host the rule then failed at apply time while the
  same config worked on the other two backends. `Rule::rule_port`'s own doc
  comment was the other half of the disagreement: it gave `"80:443"` as its
  example, a value its own validator refuses, and now gives `"80-443"`. A value
  that is not a dash-separated pair of port numbers is handed to ufw unchanged
  rather than rewritten, so it fails with ufw's own message instead of being
  quietly turned into a different malformed value. Closes #85.

- **The merged checkpoint list's de-duplication had no test, and the case it
  guards cannot be built through the public API.** `collect_checkpoints` merges
  the user and system databases and drops an id it has already seen, first-wins.
  That guard is what stands between the operator and the same checkpoint offered
  twice, and which copy survives is load-bearing rather than cosmetic: the
  manager kept beside the row decides the verification flag and where a later
  operation acts. Every write generates a fresh id, so one id in two databases
  is unconstructible by creating checkpoints; the fixture copies the database
  instead and lets the second directory keep a signing key of its own, which is
  what a real host has and what makes the surviving pairing observable. Covered
  now, and proved by two mutations: removing the guard lists the row twice, and
  making it last-wins keeps the count at one while pairing the row with the key
  that did not sign it.

- **`report --interactive` put its own chatter on stdout, so a redirected JSON
  report was not JSON.** The wizard decorated its prompts with `println!`: the
  banner, the three step headings, the review block, the progress lines and the
  completion summary all went to stdout, and the summary is printed *after* the
  report body is written there. `hardener report --interactive > report.json`,
  choosing JSON with stdout as the destination, therefore produced a file with a
  banner above the document and a summary below it. The non-interactive path had
  been disciplined about this all along, which is what made the difference easy
  to miss. All fifty of those calls now write to stderr, where `dialoguer`
  already puts the prompts they decorate, and the single `writeln!` that emits
  the report body is the only thing left addressing stdout.

- **`systemd uninstall` said "Systemd units removed" whatever happened, and
  discarded the one outcome that could contradict it.** The `disable --now` exit
  status went to `let _`, so an uninstall that removed the unit files but failed
  to stop the timer reported plain success, and a host with nothing installed
  reported a removal it had not performed. The JSON envelope now carries
  `timer_disabled` beside `removed`, matching the `timer_enabled` that `install`
  reports forty-eight lines above, and the text line says which of the three
  things happened. Expect `timer_disabled: false` where the timer was never
  enabled, because `systemctl` fails for a unit that does not exist; it is worth
  reading beside a non-empty `removed`, where it means the files are gone and
  the timer may still be running. The same function decided whether to remove a
  file with `Path::exists`, which is `metadata(..).is_ok()` and answers `false`
  for a unit this process may not stat, so it could report a clean uninstall
  having touched nothing; that check is now `try_exists` and its error is
  surfaced.

- **A webhook configured in the desktop never reached the daemon, and both
  sides reported success.** `WebhookUiConfig` serialised its own flat shape, so
  the desktop wrote `url` and `format` into
  `[scheduler.notifications.webhooks]`, whose backend struct has neither field
  and expects an `endpoints` list. Nothing rejects an unknown key, so the file
  saved without complaint, `endpoints` stayed empty, and the dispatcher built no
  notifier. `get_scheduler_config` read the file back through the same UI type
  that wrote it, so the round trip was self-consistent: the operator saved a
  URL, reopened the page and saw their URL, and only the daemon disagreed, by
  doing nothing. The desktop's single webhook is now converted to and from the
  one-entry endpoint list the scheduler reads, under the name `desktop`. A
  config written by an earlier build is still read, so an existing setting
  reaches the form instead of coming back blank and being discarded on the next
  save. Driven on a real desktop before release: the GUI now writes an
  `[[scheduler.notifications.webhooks.endpoints]]` block, the daemon parses that
  file, and navigating away and back reads the URL out of the list again.

  Two things found while fixing it, both of which would have defeated the fix on
  their own. The section writer moved each serialised table header under
  `[scheduler]` by replacing the first `[`, which turns an array-of-tables
  header into `[scheduler.[notifications.webhooks.endpoints]]` and leaves the
  file unparseable; nothing had met that because the desktop rendered no list.
  And `WebhookUiConfig::default()` leaves `format` empty while the scheduler
  page sets the form straight from it, so a fresh form saved unchanged carried
  an empty format through. As a flat key that was inert, since the backend never
  read it; inside an endpoint it is fatal, because `""` is not one of the three
  variants the enum accepts and the whole file then fails to parse. Measured
  both ways. The guard is therefore part of making the endpoint list safe rather
  than a defect that had been biting, and an unset format is written as the
  documented `generic`.

- **Saving the desktop's scheduler page destroyed every `[scheduler]` key the
  form does not model.** The save rewrote the whole section from a UI type that
  carries a strict subset of the scheduler's, so pressing Save without changing
  anything deleted `smtp_host`, `smtp_port`, `smtp_tls` and `smtp_username`,
  the whole of `[scheduler.storage]`, and `notify_mode`. `enabled` *is*
  modelled, so it survived: the result was a config asserting email
  notifications were on while `EmailNotifier::new` returned `None` for an empty
  SMTP host, and a host pointed at a custom `database_path` silently reverting
  to the default while its history appeared to stop. The form shows none of
  these fields, so the loss was neither visible nor repairable from the desktop.
  The save now merges the form over the section already in the file: a key the
  form does not emit is a key it does not own. Deliberately generic rather than
  a list of fields to carry across, because a list has to be remembered every
  time the backend gains a key, which is the same defect one step later. What
  the form does model it still owns outright, including the endpoint list, so
  clearing the webhook URL removes the endpoint. Ownership reaches inside that
  list: an endpoint the desktop writes carries `name`, `url` and `format` only,
  so a hand-written `headers` table is replaced by the first save from the GUI,
  which the reference now states for a single endpoint and not only for a
  multi-endpoint list. Reading the existing section fails the save rather than
  falling back to an empty one, since a silent fallback would be this defect
  again with no bad input required.

  The merge needed two things retired with it. The flat `url`/`format` pair
  earlier builds wrote is now deleted rather than merely not written: under a
  merge, a key the form does not emit is a key it keeps, and the read path
  prefers that pair whenever the endpoint list is empty, so a webhook deleted in
  the GUI reappeared on the next load and went live again on the save after
  that, with the daemon posting to an endpoint the operator had removed. And the
  rendered section is now serialised nested under its own key instead of having
  each table header re-prefixed textually afterwards. That pass could not tell a
  header from a line of a multi-line string starting with `[`, and once the
  merge began carrying every existing string through, each save nested such a
  value one level deeper than the last.

- **A `[scheduler]` section that named some of its keys and not others failed
  the whole configuration file, stopping `daemon` and `history` outright.**
  `SchedulerConfig` was the only struct in that tree without a struct-level
  `#[serde(default)]`, so its four scalar keys were mandatory as a group even
  though each one is documented with a default: `[scheduler]` followed by
  `enabled = true` was refused with ``missing field `schedule` ``. It is also the
  one table in that tree an operator writes by hand. The section is read from
  whichever file in the search order carries it and a parse failure there is
  returned rather than skipped, so a partial section anywhere in that search was
  fatal to `daemon` and to every `history` verb. The other two callers that open
  the same database, `scan` and `batch`, swallow the error instead, so for them
  the same file silently dropped scan-history persistence and still exited 0,
  which is the quieter half of the same defect and was reported nowhere. Each
  key now falls back to the default the reference already listed for it. The
  same omission one level down, on `WebhookEndpoint`'s `format`, is fixed with
  it, and `name` and `url` stay required because neither has an answer worth
  guessing. The section still does not merge across files, so a partial section
  in the user config hides a complete one in the system config and takes these
  defaults for what it omits rather than that file's values; `configuration.md`
  said the opposite of the new behaviour and has been corrected. One thing is
  given up: the mandatory group was an accidental typo detector, so a misspelled
  key is now accepted in silence. Nothing in this workspace sets
  `deny_unknown_fields`, and setting it here alone would refuse a file written
  for a newer version, so the trade is recorded rather than taken back.

- **A configuration path containing a space or a `%` produced a systemd unit
  that could never run.** `systemd generate` and `install` interpolate `-C` and
  the binary path straight into `ExecStart=`, which is neither a shell line nor
  a value passed through untouched: systemd expands `%` specifiers over it and
  then splits it on whitespace. Measured on a live unit, `--config
  /etc/my conf.toml` reached the process as the two arguments `/etc/my` and
  `conf.toml`, so clap refused the command with `unrecognized subcommand
  'conf.toml'` and exited 2 at every scheduled run, reported nowhere because
  nothing watches a timer's exit status by default; `%h` in a path was replaced
  by the home directory before the process saw it. Both paths are now emitted as
  quoted words with `%` escaped, so what the operator typed is what the
  scheduled run receives.

- **A refused desktop operation blocked the next real one for five seconds.**
  The rate limit that paces privileged operations was started by the RAII
  guard's `Drop`, and every command takes that guard *before* it validates its
  arguments. So a mistyped plugin name, a checkpoint id in neither database, or
  any other refusal that raised no authentication prompt still armed the
  cooldown, and the operator's next genuine apply, rollback or checkpoint met
  "Rate limit: please wait N seconds". Deleting a checkpoint from a stale list
  made that the ordinary case. The cooldown now starts where `pkexec` actually
  ran, so it paces prompts rather than attempts. A prompt that was refused or
  cancelled still counts, because pacing retries is the point; a failure to
  launch `pkexec` at all does not. The guard keeps the mutual exclusion it also
  provides, which was never the part at fault.

- **Verification-only signing never engaged for the readers it was built for, so
  the desktop could not open the system checkpoint database at all.** The mode
  exists so a reader holding the public key can check signatures without the
  private one, and it was selected only when the private key was **absent**.
  That is not the shipped layout: a root-owned `signing.key` at 0400 sits beside
  a readable `signing.pub`, so for every unprivileged reader the private key is
  present and unreadable. Construction took the load path, failed on permission,
  and the public key next to it was never tried. The desktop therefore could
  neither list nor verify any privileged checkpoint, whatever else it did. Being
  unable to read the private key now selects the same mode as not having one.
  The absence test also moves from `Path::exists` to `try_exists`, so a key
  under a directory this process cannot search is no longer mistaken for a key
  that is not there: that distinction is what decides whether a fresh key is
  generated, and generating one where a key already exists would void the
  signature of every checkpoint already written. When neither half can be read,
  the error now says so rather than reporting whatever a write into an
  unreachable directory happened to fail with.

- **The desktop's checkpoint list could omit every privileged checkpoint and
  look like a host that had none.** It decided whether to consult the system
  database with `Path::exists`, which is `metadata(..).is_ok()` and therefore
  answers `false` for a file this process merely may not stat. That database is
  root-owned, and its directory is `drwx------` on at least one real host, so an
  unprivileged desktop read "cannot see it" as "not there" and silently dropped
  its rows. The two are now told apart, and a system database that cannot be
  reached is logged as such, so a checkpoint an operator watched being created
  and then cannot find is diagnosable rather than a mystery. The same conflation
  was fixed in the delete path in this release; this was the other half of it.
  The two near-identical collection blocks also become one, which removes a
  redundant manager construction per checkpoint.

- **The desktop's Rollback failed outright for any operator who had set a
  configuration file.** It appended `--config <path>` to the CLI argv *after*
  the `--` that shields the checkpoint id, so clap read `--config` as a second
  positional, refused the command with "unexpected argument" and exited 2 before
  anything was restored; the desktop then surfaced that as a parse failure
  rather than as the reason. The flag had nothing to do there in the first
  place: `rollback` restores the files a checkpoint captured and consults no
  directive, exception or plugin list, exactly as `batch rollback` reads no
  `config.toml` at all. The path is gone from the Tauri command, the frontend
  binding and the modal that called it, rather than merely moved earlier in the
  argv. The argv is now built by one function whose test asserts the id is last
  and behind the separator, because anything appended after it is a positional
  the command does not take.

- **A timer installed against a policy file ran its scheduled scan on the
  compiled-in scheduler defaults.** `systemd generate` and `systemd install`
  embed the `--config` path in the unit they write, and making `-C` reach the
  `[scheduler]` section had it replace the search rather than join it, so a
  named file with no `[scheduler]` section meant "use the defaults" rather than
  "this file does not configure the scheduler". Measured: with a real config
  enabling a 04:00 scan into a chosen database, the same host under
  `--config policy.toml` reported the scheduler **disabled**, on another
  schedule, writing to the default database, and said nothing about it. Since
  the unit embeds that path, the misconfiguration was permanent and silent, and
  every scheduled scan it produced would have been skipped.
  The named path is now searched **first** rather than instead, and a file
  without the section is not treated as configuring it, so the operator's own
  settings still decide. The section still does not merge: the first file that
  actually configures it wins whole. This also corrects the same shadowing
  between the default locations, where a user config mentioning only `[global]`
  silenced a system config that had the settings.

- **A fleet run whose `--output` named the wrong document scanned the whole
  fleet before saying so.** The check sat at the point of writing, so `batch
  report --output fleet.json` under the default text format contacted every
  host, produced the report, and only then refused its destination. It also
  exited 1 from there, while every other pre-connection refusal in `batch` exits
  2, the tier the reference documents for a batch usage error. Two arguments
  contradicting each other is knowable before a single host is reached, so all
  four fleet verbs now judge `--output` first: refused runs cost no fleet work
  and exit 2 with the rest. `report` still exits 1 for its own, which is not a
  tier but the ordinary error path of a command with no per-host tiering, and
  both references now say which is which. The fleet message is worded
  separately from `report`'s, which offers the named format as an alternative:
  that advice is wrong here, because a fleet report is text or JSON only and the
  CSV, HTML and PDF formatters are reachable per host alone.

- **The desktop raised an authentication prompt to delete a checkpoint that
  does not exist.** Delete tries the user database and falls back to a
  privileged `hardener checkpoint delete` for root-owned rows. The fallback is
  right, and it became reachable once the delete stopped reporting success for a
  row it had not removed, but it fired for an id in neither database too, which
  is what a stale list, a double click, or a row already removed from the CLI
  produces: a polkit dialog appeared and the operation then failed. It now
  escalates only when the row could plausibly be there. The system database is
  root-owned and an unprivileged desktop may be unable to read it, so the only
  case treated as decisive is the one that is: a reachable system database that
  positively lacks the row, or no system database at all, which is every desktop
  that has never run a privileged apply. A database that cannot be read is not
  an answer and still escalates, so a root-owned checkpoint is never left
  undeletable.

- **`-C`, `--config` was ignored by `daemon` and by all five `history` verbs**,
  which read the `[scheduler]` section through a loader that took no path and
  searched the default locations itself. A single file carrying both a
  `[global]` and a `[scheduler]` section was half honoured: `scan` read its
  policy from the named file and then wrote its history to whichever database
  the default search happened to find, so the two halves of one configuration
  could disagree about where the run's results went. The scheduler section now
  comes from the named file when one was named, and a named path that is missing
  or will not parse is an error rather than a fall-through to the defaults. That
  is not universal and the reference now says so: `batch scan`, `batch report`
  and `batch apply --dry-run` deliberately keep their fallback, warning on
  stderr, because they change no host. The default search is unchanged when no
  path is named. One consequence is worth knowing before passing `-C` to these
  verbs: the `[scheduler]` section does not merge, so a named file that has no
  `[scheduler]` section yields the compiled-in defaults rather than the settings
  in your system or user config, and a partial `[scheduler]` table will not parse
  at all. `docs/reference/cli.md` enumerated the
  surfaces that accept `-C` without acting on it and presented that list as
  complete while naming neither of these; the list is now correct.

- **`--format json` was ignored by every `systemd` verb, so a caller parsing
  stdout as JSON received a unit file beginning with `#` or a systemctl status
  table.** `main` passed the four verbs no format at all and the module imported
  no `OutputFormat`. All four now honour the flag and print one envelope each:
  `generate` carries the units it produced, or the paths it wrote; `install`
  carries the paths and whether the timer was enabled; `uninstall` carries what
  it removed, which is empty rather than absent when there was nothing to
  remove; and `status` carries `user_mode`, `exit_code`, `stdout` and `stderr`.
  `status` reports the exit code rather than discarding it, because an inactive
  timer and a unit that does not exist both make `systemctl` return non-zero and
  nothing else tells them apart without reading prose. `install` reports
  `timer_enabled` from what `systemctl enable --now` actually returned, rather
  than asserting an outcome nothing had checked. The text rendering is
  unchanged. `--quiet` continues to suppress progress and never a result, so
  `generate` writing units to stdout still prints them.

  The other half of the same report was **`report` ignoring the global
  `--format`, and that is by design**: `--report-format` selects the report
  body, and the global flag governs only the command's own progress. The
  reference already said so where `--report-format` is described; it now says so
  in the global flag's own row as well, which is where a reader looking for the
  promise would start.

- **`report --output` wrote the wrong document into a path that named a
  format.** The extension was added when the path had none and never checked
  when it had one, and `--report-format` defaults to `text`, so
  `hardener report --output report.json` wrote a human text report into a file
  called `report.json`, exited 0 and said it had saved a report. A path whose
  extension contradicts the selected format is now refused, naming both
  documents and the flag that would reconcile them. Refusing rather than letting
  the extension choose the format is deliberate: `report` renders five formats,
  and an extension that silently overrode `--report-format` would be the same
  defect pointing the other way, with no way to tell an explicit
  `--report-format text` from the default. The comparison uses a closed list of
  the formats this tool actually renders, because `Path::extension` answers
  "what follows the last dot" rather than "what document is this", so
  `report.2026.08.03` asks for nothing and is still written as given. That list
  now lives with the formats themselves as `OutputFormat::from_extension`, a
  left inverse of `extension()` (`htm` maps to HTML, which writes `html`), and
  `history export` and `batch`'s `--output` writer were moved onto it, so the
  commands that judge a path can no longer disagree about what an extension
  names. `history export` accepts and refuses exactly what it did before: the
  two predicates are the same set. The wizard behind `report --interactive`
  carried the same defect on its own code path and is refused there too.

- **The container test suite no longer fails a rollback that did its job.** A
  rollback restores the files and then asks each plugin to reload the service
  that reads them, reporting a reload that did not happen rather than calling
  the rollback clean. Inside an nspawn container auditd cannot load rules, so
  `augenrules --load` and `systemctl restart` both fail and the rollback exits 1
  with every file correctly restored. The suite's two rollback rows asserted
  exit 0 flatly, so four of five distributions failed a run in which
  `/etc/audit` came back byte-identical to its pre-apply state and every other
  assertion in the section passed. Arch was unaffected only because its reload
  succeeds. The rows now accept a non-zero exit whose cause is the reload alone,
  which is the allowance the apply row two sections up already carries and
  states. The allowance is deliberately narrow: a rollback that failed to
  restore files reports that with a different sentence and still fails the row,
  and the classification is a function of its own with three self-test
  assertions covering both halves and neither. No check was added to a section
  and no declared size moved.

- **`checkpoint delete` says which row it removed, and refuses an id that
  matched none.** Under `--format json` a successful delete wrote nothing at
  all, so a machine consumer had to read success out of a zero-byte stream; the
  only line it ever produced was an intent announcement on stderr, printed
  before the work and suppressed under `--quiet`. Making that report honest
  required fixing what sat underneath it: `DELETE ... WHERE` matching no rows
  is a successful statement, and the row count was never inspected, so deleting
  an id that never existed committed a transaction, returned `Ok`, exited 0 and
  wrote a success into the audit log. The manager's own documentation already
  said it "returns an error if checkpoint doesn't exist", so the contract was
  right and the implementation was not. A delete that removed nothing is now an
  error, and a successful one prints `{"deleted": true, "checkpoint_id": ...}`
  under `--format json` and a `✓` line otherwise, matching `checkpoint create`.
  Both outcomes are now written to the audit log, before anything is printed:
  a delete that found no such row is an operator action on the checkpoint store
  just as much as one that succeeded, and it is the shape a probe takes, so
  returning early would have removed it from the trail entirely. `rollback` and
  `apply` already recorded both. This also restores the desktop's fallback to
  the system checkpoint database: it treated any non-error as proof of
  deletion, so on a machine that had ever run the GUI it stopped there and a
  root-owned checkpoint was silently never deleted while the interface reported
  success. One consequence to know about: the desktop now reaches its `pkexec`
  fallback for an id in neither database, so clicking Delete on a stale row
  raises an authentication prompt for an operation that then fails, where it
  previously reported success without prompting. A second: `file_states` rows
  orphaned from their checkpoint, which nothing in the current code can create,
  were previously swept by deleting their absent parent and now cannot be. The
  container suite's existing delete row matches the reported outcome rather
  than the exit status, without adding a check.
- **`history export -o report.pdf` is refused instead of writing JSON into
  that name.** Narrowing the global `--format` closed the half of this defect
  that needed a refused format value; `--output` reached the same wrong
  artefact with no format flag involved at all, because the extension was
  produced when building the default filename and never read when the operator
  supplied one. The command exited 0 and reported success, leaving a file whose
  name promised a document nobody could open. This exporter serialises one
  struct and has no second formatter behind it, which the help text, the
  reference and the default filename all already said, so the honest answer is
  to refuse the path rather than invent renderers. What is refused is a closed
  list of the formats this tool genuinely renders elsewhere, reachable through
  `report --report-format`: `.csv`, `.htm`, `.html`, `.pdf` and `.txt`, in any
  casing. The inverse rule, refusing anything that is not `.json`, was rejected
  because a path's last dotted segment is not a document type: a dated backup
  name like `backups.2026.08.03` would have been refused for an "extension" of
  `03`, breaking an invocation that asks for nothing this command cannot give.
  The refusal happens before the database is opened, so a rejected run reads
  nothing, writes nothing, and leaves no file under the misleading name. No
  caller in this repository passes a refused path.
- **A `batch` run no longer silently drops a host you named, and no longer
  scans one machine twice.** Ad-hoc `--ssh` targets were de-duplicated on
  `name`, which is not an identity: for an ad-hoc target it is the bare
  hostname, with the user and port already split off, and for an inventory host
  it is a free-form nickname unrelated to the hostname. Both directions were
  wrong. `--ssh admin@web-01:22 --ssh admin@web-01:2222` collapsed to one host
  and reported `Scanning 1 host(s)`, as did `--ssh root@web-01 --ssh
  admin@web-01`, though the account decides which checks can run at all. This
  reaches all four batch verbs, so `batch apply --execute` could report success
  having never hardened a host that was named on the command line. In the other
  direction, an ad-hoc target genuinely duplicating an inventory host was
  compared against that host's nickname, never matched, and the same machine
  was scanned twice under two different history keys. The desktop already
  de-duplicated its own ad-hoc targets on the canonical form before shelling
  out, and the CLI then undid that; it has never compared an ad-hoc target
  against a selected inventory host, and still does not. Targets are now
  compared on the canonical `user@host:port`, the identity `host_key_of` already
  reached for the history key of an ad-hoc host. No existing history key is
  renamed; runs that used to collapse simply write the row for each host they
  were always asked to scan. Hostnames are still compared as written and never
  resolved, matching every other host identity in the tree, and only `--ssh`
  targets are compared at all: `--all` and `--host` are taken as given, so two
  inventory entries for one machine still produce two hosts. The one existing
  test asserted the wrong outcome, calling a distinct endpoint a duplicate, and
  has been corrected. **One collision is left open and is not this change's to
  close:** `SshExecutor::description` substitutes a literal `root` when `--ssh`
  named no user, so `--ssh web-01` and `--ssh root@web-01` are now two hosts
  sharing one checkpoint host key, and under `batch apply --execute` they run
  concurrently and their pre-apply checkpoints collide. Telling those targets
  apart is correct; the fabricated `root` is the defect and has to be fixed
  where it is invented.
- **`apply --dry-run --quiet` no longer prints its dry-run notice.** Every other
  status line in `apply` is gated on `--quiet` by hand; the announcement that
  opens a dry run was the one that was not, so a run asked for in silence still
  wrote a line to stdout ahead of its results. The gating happens at each call
  site rather than inside the output helper, so nothing type-checks it and no
  unit test could see the omission. Only text output was affected: under
  `--format json` this helper already writes to stderr, so no JSON consumer ever
  saw it. The test drives the built binary and asserts the notice is present
  without the flag as well as absent with it, since an absence claim alone would
  hold just as well for a line that had been deleted.
- **`apply` acts on the `--config` file it is given, instead of hardening the
  host against defaults it was never shown.** The flag is global and every other
  policy-reading command honoured it; `apply` alone built its loader with
  `ConfigLoader::new()` and never passed the path, so the file decided nothing.
  That file selects which plugins run, the target values they write and the
  violations deliberately excepted, which makes this the one verb where losing
  it changes what is written to the system. It also failed open: a path that
  does not exist is exit 1 on `scan` and `report`, and was exit 0 on `apply`,
  which then hardened the host from built-in defaults. A mistyped `--config` was
  therefore refused by the read-only commands and silently ignored by the one
  that changes the host. The `nothing_ran()` guard, which exists to refuse
  exiting 0 having hardened nothing, could not fire for a `--config`-supplied
  policy either, because the config that would have populated its skip list was
  never loaded. Naming a `--config` path now makes any configuration failure
  fatal for that run, whichever source it came from: the loader merges all
  sources into one result and cannot attribute a parse error to one file, and a
  run told to use a named policy should not proceed on a guess about policy.
  Without the flag, a broken config at a default location still degrades to
  defaults with a warning, which is the behaviour that shipped. `batch apply`
  was not covered by this change and is fixed by its own entry above. All four
  commands that build a loader now share one definition of
  what the flag means. `docs/reference/cli.md` and `docs/reference/configuration.md`
  described the old behaviour accurately and have been corrected: they recorded a
  defect, and the workaround they offered ("install it at one of the default
  locations first") did not work for a privileged `apply`, which skips the user
  config by design.
- **The cross-distro runner's clean run no longer reads as three silent
  failures.** A complete, correct sweep printed `146/149 passed, 9 skipped` and
  named no failure count at all, so a reader was left to infer one from
  arithmetic that does not work: `TESTS_TOTAL` counts announcements, a skip
  taken after one occupies a slot that never becomes a pass, and a skip taken
  before one never enters the total. The maintainer read that line as three
  failures on a run that had none. Both result-line paths now come from one shared
  function, and both summary tables from another, so a clean run and a failed one
  carry the same fields wherever they are printed. The skips are split into the
  ones the total holds and the ones it never saw: `149 declared, 146 passed, 0
  failed, 9 skipped (3 declared without a verdict, 6 never declared)`. That
  first number is derived as declared minus resolved, so it is named for what it
  measures rather than for what it is usually taken to mean: a check announced
  and then left without any verdict at all would land there too, and calling it
  a skip would report a hole confidently. The two summary tables gain the same
  split, and an `Unask` column beside it, because `summary.txt` is the file this
  project's own suite calls the one most likely to be looked at first. A
  `--differential` run reconciles by construction, since a check it cannot
  determine is recorded as a failure rather than as a skip, so the reconciliation
  was nothing but zeroes there while the count that does move between fixtures,
  the rows declared unaskable and never asked, went unmentioned: the runner reads
  that line now and the result line names it. Counts that cannot be reconciled
  print `?` rather than a negative, and the serial failure line now reports the
  exit status it never used to. The shared formatter refuses a call it cannot
  read rather than reporting one, because nothing binds its single call site to
  its seven arguments and the transposition that costs the most is silent: with
  the distribution's name where the exit code belongs, the arithmetic test reads
  an unset name as zero and every distribution reports a pass. The runner gains
  its first `--self-test`, 33 assertions over the parser, the arithmetic, both
  result paths and that refusal, needing no root, no container and no binary, and
  it refuses any other argument beside it: it runs above the pre-flight and above
  the line that creates the results directory, so `--apply --booted --self-test`
  would otherwise exit 0 in a second having entered no container, leaving the
  previous run's `summary.txt` to be read as this run's. Closes the reporting
  half of the "146 is correct and complete" confusion; the counts themselves
  never moved.

- **`report --interactive` scanned the controller after announcing a connection
  to a remote, and scored every host against the generic profile.** Two faults
  in one surface. The wizard built its own `LocalExecutor` instead of taking the
  one the CLI had already connected, so `hardener --ssh user@remote report
  --interactive` printed "Connecting to remote...", scanned the operator's own
  workstation, and produced a CIS, STIG or HIPAA report of it. Nothing in a
  report names the host it describes, so there was nothing on the page to give
  it away. Separately the wizard passed `ComplianceProfile::default()`, which is
  `generic`, where the non-interactive `hardener report` resolves the profile
  from the scanned host: a RHEL 10 host was therefore scored against two
  different identifier sets depending on which of the two surfaces the operator
  used, and the pair gave no way to tell which answer was right. The wizard now
  takes the caller's executor and resolves the profile through it, so both
  inputs come off the host that was actually scanned. `docs/reference/cli.md`
  already claimed the wizard "cannot score a host differently from `hardener
  report`"; the documentation was the correct witness and the code was the
  defect. `--profile` reaches the wizard for the same reason: `hardener report`
  honours the flag and falls back to detection, so a wizard that detected
  regardless overruled the operator without saying so. It is parsed before the
  first prompt, so a name it cannot read is refused before five questions have
  been answered, and the resolved profile is now printed before the reports are
  generated, whichever way it was arrived at: no wizard output named it before,
  and a report scored against the RHEL 10 identifiers looks exactly like one
  scored against the generic set.

- **The differential suite's kernel pre-apply control reports a torn capture
  rather than ending the run from an assignment.** The control read each
  parameter out of the pre-apply capture with a bare `reading="$(grep ... | cut
  ...)"`, and under `set -euo pipefail` a parameter the capture holds no line
  for fails the grep, fails the pipeline, and ends the whole suite from that
  assignment: exit 1 with not one check printed, which reads as a finding and is
  not. The capture is built from the same table the control walks, so the two
  coming apart is a fault in the suite rather than in the host; it is now
  reported as a named failure. Counting the missing row as a parameter away
  from target was rejected as the worse answer, because the control would then
  pass on the strength of a reading nobody took. Two further assignments of the same shape are guarded with it: a `jq`
  capture in the rollback reload check, which is reached directly and whose
  `2>/dev/null` would have swallowed the only explanation, and a `pwscore`
  capture whose non-zero exit is the normal case on the path that calls it. That
  one is latent rather than live, because every caller today reaches it from
  inside a command substitution, where `set -e` does not apply unless
  `inherit_errexit` is set, and this project never sets it. The self-test case
  that proves all of this carried one of its own, since it arranges a torn
  capture with a `grep -v`: it is guarded now, and the count of what survives
  the guard is asserted, because an empty capture would be missing every row and
  the assertion below it would still have passed, for a reason that has nothing
  to do with what it claims.

- **`scan --ssh` filed a remote host's findings under the operator's own host
  name.** The scan itself was already remote-correct, because `--ssh` builds an
  `SshExecutor` and every plugin asks the host through it. Only the history key
  was not: the session was identified by reading the **controller's**
  `/etc/hostname` with `std::fs`, so scanning a fleet from one workstation piled
  every remote's findings into the workstation's own row. Anything derived from
  that database read the wrong host: `history trends` and `history regressions`
  reported an invented history for the controller and none at all for the hosts
  actually scanned, and a regression on a remote could be masked by, or falsely
  attributed to, a change on the controller. A remote is now keyed by the target it was
  reached at, the same derivation that scopes checkpoints, rather than by the
  name it reports: `/etc/hostname` is neither unique, since two fresh Rocky
  hosts both answer `localhost.localdomain`, nor stable, since a session that
  could not read it would key the same host differently. A host reached both by
  name and by address therefore gets two rows, which loses continuity but
  corrupts nothing, and is what `batch` has always done. The local key stays the
  host's own name so that history written by earlier releases keeps its rows,
  and an unreadable or empty name there falls back to the same derivation rather
  than to the literal `localhost`, which cannot be told apart from a real
  remote's row. The scheduler daemon writes the same table and derived that key
  separately, by asking the kernel for its nodename and falling back to the
  literal `localhost`, so a machine whose static name and transient name differ,
  or whose `/etc/hostname` cannot be read, held two disjoint histories: each
  side saw no earlier scan, and the daemon's own regression comparison ran on
  half the rows. Both surfaces now share one derivation, which lives beside the
  checkpoint host key. It also reads `/etc/hostname` as `hostname(5)` defines
  it, taking the first line that is neither blank nor a comment, where a
  whole-file trim would have made a commented file's key the name, a newline and
  the comment. `batch` never shared this path and its history is unaffected;
  existing rows are not rewritten, so a database written by an earlier release
  still holds the mixed rows it recorded, and a host the daemon had keyed on a
  transient name keeps those rows under it.

- **Arch hosts were told `PASS_MIN_DAYS` was enforced when no account receives
  it.** `apply` writes the directive into `/etc/login.defs`, and `scan` reported
  no finding for it, but Arch builds shadow with no minimum password age at all:
  `chage` there has no `-m/--mindays`, and `useradd` leaves the field empty
  while honouring `PASS_MAX_DAYS` and `PASS_WARN_AGE` from the same file. One
  `useradd` run taking two of the three directives and dropping the third is
  what rules out a file-reading problem. The scan now asks `chage` whether the
  field exists at all, through the executor so a remote scan asks the remote
  host, and reports the directive as **not enforced** where it does not. The
  value is left in `/etc/login.defs`, because it is already correct and would
  take effect if the build ever gained the field. A probe that cannot be run is
  reported as unchecked rather than as either answer. Affected hosts should
  rely on `pam_pwhistory`, which this plugin also manages, for password reuse.
  Other distributions are unaffected.

- **Arch hosts were told `PASS_MIN_DAYS` was enforced when no account receives
  it.** `apply` writes the directive into `/etc/login.defs`, and `scan` reported
  no finding for it, but Arch builds shadow with no minimum password age at all:
  `chage` there has no `-m/--mindays`, and `useradd` leaves the field empty
  while honouring `PASS_MAX_DAYS` and `PASS_WARN_AGE` from the same file. One
  `useradd` run taking two of the three directives and dropping the third is
  what rules out a file-reading problem. The scan now asks `chage` whether the
  field exists at all, through the executor so a remote scan asks the remote
  host, and reports the directive as **not enforced** where it does not. The
  value is left in `/etc/login.defs`, because it is already correct and would
  take effect if the build ever gained the field. A probe that cannot be run is
  reported as unchecked rather than as either answer. Affected hosts should
  rely on `pam_pwhistory`, which this plugin also manages, for password reuse.
  Other distributions are unaffected.

- **The differential suite declares `PASS_MIN_DAYS` unaskable where shadow has
  no minimum-password-age field**, rather than failing a host for a target it
  cannot reach. `SHADOW_MIN_DAYS` is a second mode signal beside
  `KERNEL_BOOTED`: probed once from `chage --help`, printed in the run header,
  and the expected totals branch on it, so a run asks for 68 checks unbooted
  and 81 booted on such a host against 70 and 83 elsewhere. Both rows are
  declared rather than one, so the totals stay comparable. Arch therefore
  reaches a clean run again now that the product reports the directive
  honestly.

- **The differential test suite can reach a clean run on Arch and on RHEL.**
  Two of its own pre-apply controls could never be satisfied there, so neither
  distribution could be used as a merge gate however often the run was
  repeated. On Arch the login.defs oracle had no reader for `PASS_MIN_DAYS`:
  that shadow build has no minimum-days field at all, so `chage -l` prints no
  such line and `chage --help` offers no `-m`. The row now carries a second
  reader, the `passwd -S` field holding the same setting, consulted only where
  the first comes up empty; the other four distributions go on using the label
  they always used. On RHEL every managed kernel parameter already met its
  target before the apply, so the control correctly refused to certify checks
  that would have passed whether or not the tool had run. A seed now loosens
  one row, `net.ipv4.conf.all.accept_source_route`, before the pre-apply
  capture, and reads it back rather than trusting the write. Where neither
  login.defs reader has a directive, the failure now carries what each of them
  printed, so the cause can be read off the log instead of needing a container.

- **An Arch upgrade no longer replaces the configuration the operator wrote.**
  `package()` installs `config.toml` into `/etc` and the PKGBUILD declared no
  `backup` array, so pacman treated it as an ordinary owned file: a routine
  `pacman -Syu` overwrote it with the shipped default, taking the operator's
  policy exceptions with their reasons, approvers and expiry dates, along with
  any directive overrides, and left no `.pacnew` to recover them from. Nothing
  was printed at any point. The other packagings were never affected, since the
  RPM marks the same path `%config(noreplace)` and the Debian package gets
  conffile handling from debhelper for anything under `/etc`, which is what
  `docs/guide/installation.md` has always promised for all of them.

  The array is declared now, and pacman applies it retroactively: a host
  installed before this release is protected by the upgrade that carries the
  fix, not only by the ones after it. An operator who has edited the file gets a
  `.pacnew` to merge whenever the shipped default changes, exactly as RPM and
  Debian users already do.

- **A rollback no longer reports success for a file whose bytes it never
  restored.** A checkpoint that could not read a file's content stored a row
  identical to one captured metadata-only on purpose: no content, a real mode,
  no link target. Restore re-applied permissions to both and reported success,
  so an operator who asked for a file's contents back was told the rollback
  worked while the contents were whatever the apply had left there. The only
  trace was a warning at capture time that the checkpoint did not keep.

  `FileState` records why a row carries no content, and a rollback of a row
  whose bytes could not be read now restores the permissions and owner, says
  what it could not restore, and exits non-zero. A row with no bytes by design,
  a directory or an account database captured metadata-only so its contents
  never enter the checkpoint database, is unaffected and still a plain success.

  Reached only through a declared directory: a declared file is captured
  strictly and a read failure refuses the capture outright. So the paths at risk
  were the recursed ones, `/etc/pam.d`, `/etc/sysctl.d`, `/etc/audit/rules.d`,
  `/etc/systemd/system` and their kin.

  **Existing checkpoints are unaffected and keep verifying.** The new column is
  added by an idempotent migration, an older row reads as "not recorded" rather
  than as either answer, and the field is hashed into the signature only when
  present, so a checkpoint signed before it existed hashes to what it hashed
  then. `hardener checkpoint show --format json` gains a field.

- **A dry run now warns before PAM hardening can lock every password change on
  the host.** libpwquality's `dictcheck` defaults on and fails closed: with
  `pam_pwquality` in the stack and no cracklib dictionary installed, every
  password change is refused, strong ones included, and the refusal names no
  cause. This tool does not create that condition, but it is what ran
  immediately before the symptom appears, so an operator who hardens PAM and
  then cannot change a password will reasonably blame it.

  `apply --dry-run --plugin pam` reports it at Medium, naming both remedies
  (install `cracklib-dicts` on dnf hosts or `cracklib-runtime` on apt hosts, or
  set `dictcheck = 0`). Medium rather than High on purpose: High blocks the dry
  run, and refusing to preview an otherwise sound hardening run over a missing
  package would be the wrong lever. **The tool will not install a package on
  your behalf.**

  It stays silent unless all three conditions hold, and silent when it cannot
  tell: a stack that does not load `pam_pwquality`, a `dictcheck = 0` already in
  `pwquality.conf`, a dictionary present at either of the two paths
  distributions use, or a probe that failed, each mean nothing is said.

- **Two plugins told you to try again as root for failures root cannot fix.**
  The firewall plugin replaced every `ufw status` failure with the literal
  string "Unable to determine UFW status (permission denied)", discarding
  whatever ufw had actually said, so a ufw whose iptables backend was broken
  reported a privilege problem. It now carries the real error, and the shared
  permission predicate learned the wording ufw actually prints
  (`You need to be root to run this script`), which nothing else in the tree
  emits and which was the only reason the fabricated string had been getting
  away with it.

  The audit plugin returned "permission denied" from the arm that catches a
  failure to spawn `auditctl` at all, and `LocalExecutor` turns a missing
  binary into exactly that failure, so **a host that has never had the audit
  package installed was told that listing its audit rules requires root**. A
  spawn failure is now its own outcome, and whether it is worth a privileged
  retry is decided by asking whether the binary exists rather than assuming.
  Its refusal test also stopped being `stderr.contains("root")`, which matched
  any message naming a path under `/root`.

- **The Rust 1.85 minimum is now declared, so cargo enforces it instead of
  three documents merely asserting it.** The rust badge, `README.md` and
  `docs/contributing/building.md` all stated a 1.85 floor while no `Cargo.toml`
  carried a `rust-version` key, so building on an older toolchain produced
  whatever compiler error the code happened to hit first rather than cargo's
  message naming the required version. It is declared in `[workspace.package]`
  beside the edition that sets it, since edition 2024 stabilised in 1.85, and
  inherited by all eleven members: a workspace key nothing inherits enforces
  nothing, which was confirmed by removing the inheritance from one crate and
  watching it build under a floor every other crate refused. The rust badge is
  now checked against the declared value too, so the three assertions cannot
  drift from it. **The declaration states the intended floor rather than a
  verified one**: nothing builds the tree on 1.85, so code that starts requiring
  a newer release still passes here and in CI, and a CI job on the declared
  version is what would close that.
- **Two README badges were wrong, and regenerating them from their own source
  would have made two others worse.** `scripts/badges/generate.js` is the
  declared source for the badge SVGs and the release procedure regenerates from
  it, but the artefacts had been edited without the source: the generator
  declared version 1.5.0 and tests 1100+ while the committed SVGs read 1.5.1 and
  1191+, so running the documented step would have reverted both. Beside that,
  the AUR badge read 1.5.0 against a 1.5.1 that is already published, and the
  test count was well behind the tree. The generator now declares 1.5.1, 1.5.1
  and 1400+, and the SVGs are regenerated from it. `validate_badges.py` holds
  them together from now on, and additionally compares the `aur` and `version`
  badges against `packaging/PKGBUILD` and `Cargo.toml`, which is the check that
  catches a badge agreeing with its generator about a release both are behind.
- **`hardener scan` no longer reports a PAM directive as set in a file it could
  not read.** Where the PAM stack does not load the module that reads a
  configuration file, the scan reports the directive as unenforced whatever the
  file holds, which is correct and deliberate: the check runs before the value
  is read, because a file nothing consults makes its own value irrelevant. The
  finding then narrated a premise that check had skipped, opening "PAM directive
  'minlen' is set in /etc/security/pwquality.conf", and its impact line said the
  setting "appears configured". One sentence covered four different hosts: one
  whose file sets the directive, one whose file could not be read, one with no
  such file at either layer, and one whose file simply omits it. Only the first
  made the claim true. Reproduced on an unprivileged scan of an Arch host whose
  `/etc/security/pwquality.conf` is mode 0600, where the tool logged the failed
  read and then reported six directives as set in it. Both sentences now describe
  the PAM stack, which is the thing that was actually read, and the remediation
  is unchanged. No verdict, severity or compliance mapping moves; a control that
  failed still fails.
- **A PAM configuration file that cannot be read now says why in the log.** The
  warning printed the path twice and the cause never, so an operator could not
  tell a privilege failure, which a privileged re-run fixes, from an I/O or
  encoding failure, which it does not. The distinction was already computed one
  line above and discarded, while the audit and firewall plugins say "requires
  root" plainly in the same scan.
- **`hardener apply --plugin firewall-hardening` now reports turning the
  firewall on.** Enabling a firewall that was off is the most consequential
  thing this plugin does, taking a host from no firewall to a firewall, and it
  appeared only in the log: the change list named the rules and said nothing
  about the enable that made them mean anything. An operator reading the
  summary, or the desktop's confirmation, was told about two or three rules and
  not about the firewall being switched on. It is now recorded like any other
  change, and a backend that was already enabled is recorded as a skipped
  no-op, consistent with how already-satisfied rules are reported. Nothing
  about what the tool does to a host has changed; this makes the record match
  it. The omission was previously masked by the ufw and firewalld overcounts
  fixed below, which made the totals look right for the wrong reason.
- **`hardener apply --plugin firewall-hardening` no longer reports adding ufw
  rules that were already in force.** The ufw backend read nothing before
  running `ufw allow`, and ufw exits 0 for a rule it already has, so every
  apply recorded every baseline rule as newly added. On the Debian test
  container the second apply printed the same "3 change(s) applied" as the
  first, on a host the first had already hardened, while SSH, PAM and file
  permissions in the same run all correctly reported needing no changes.
  ufw was in fact saying so all along, printing "Skipping adding existing
  rule" in output the backend discarded, and that is now read and recorded as
  a skipped no-op. The default incoming policy is the one rule that cannot
  report its own outcome, because `ufw default deny incoming` prints the same
  line whether or not the policy moved, so it is read from `ufw status
  verbose` before the run instead. Together with the firewalld fix below, all
  three firewall backends now behave as the documented state-aware apply
  describes; nftables already did. Nothing about which traffic is permitted
  has changed. A host whose state cannot be read is treated as unhardened, so
  its rules are applied and reported rather than skipped.
- **`hardener apply --plugin firewall-hardening` no longer reports adding a
  firewalld port or setting a zone target that was already in place.** On
  Fedora, RHEL and openSUSE the backend ran `firewall-cmd --add-port` and
  `--set-target=DROP` without first asking what the zone already held.
  `firewall-cmd` exits 0 either way, printing `ALREADY_ENABLED` for a port that
  is present, so the exit status could not tell an addition from a no-op and
  both were recorded as applied changes on every run. A second apply on the
  Fedora test container printed the same "3 change(s) applied" as the first, on
  a zone the first had already hardened. That count is what the CLI summary and
  the desktop's confirmation both read, so an operator re-running a hardened
  host was told three things changed when nothing had. The backend now reads
  the zone's permanent port list and target before writing, records an
  already-satisfied rule as a skipped no-op, and skips the reload entirely when
  nothing was written, so an already-hardened firewalld host reads "no changes
  needed". Nothing about which traffic is permitted has changed: the port was
  allowed either way, and this is a reporting fix. A zone whose state cannot be
  read is treated as unhardened, so the rules are applied and reported rather
  than skipped on a host the tool cannot see.
- **`hardener apply --dry-run` no longer hides a firewall rule it is leaving
  alone because a policy exception documents it.** An excepted rule was filtered
  out of the "Apply N baseline firewall rules" count and recorded nowhere, so the
  number shrank with nothing anywhere saying why, and once every baseline rule
  was excepted the count reached zero and the line was not emitted at all. A
  preview that would skip four rules, and that `apply` reports as four skipped
  changes, rendered identically to a host whose firewall already matches the
  baseline. The count and the line naming a waived rule are now computed in one
  pass over the baseline, so a rule cannot leave the count without being
  reported. No plugin returns an unconditionally empty exceptions list any more;
  this was the second of the two the 1.5.1 sweep missed.
- **`hardener apply --dry-run` no longer hides a permission path it is leaving
  alone because a policy exception documents it.** The preview honoured the
  exception and then recorded nothing about it, so a host whose only drift was
  excepted previewed as no pending change beside an empty exceptions list, which
  is byte-identical to a host that needs nothing doing. The real `apply` has
  always reported such a path as a skipped change naming the reason, so the dry
  run did not preview what the run it previews would do, and a stale exception
  still suppressing work stayed invisible to the operator reviewing it. The
  1.5.1 sweep that recorded excepted settings across seven sites reached six
  plugins; `[permissions]` received only the struct field it needed in order to
  compile, because its exception check sits in a helper and returns "nothing to
  predict" rather than reaching the `continue` in a loop that sweep read. The
  deviation is now recorded through the same shared helper as the rest, naming
  the mode the path keeps and why, and the exception is honoured in the loop
  where `apply` honours its own.
- **`hardener apply --dry-run` previews the persistent sysctl file the kernel
  apply is about to write.** The plugin's validate path looped over the
  parameters, estimated where the observed value differed from the target and
  returned, so the file
  the whole plugin exists to leave behind was never part of that answer. On a
  host where every parameter already reaches its target the preview was
  therefore empty, and the apply then wrote `/etc/sysctl.d/99-hardener.conf` and
  reported it: an operator on a fully compliant host was told nothing was
  pending and approved a run that put a file into `/etc`. The RHEL test
  container is the one fixture where that shows, because the other four have
  non-empty previews for unrelated reasons that mask the missing line.
  Predicting the write means knowing the content, and the content carries two
  rules that lived inside apply alone: an excepted parameter is written as a
  comment rather than a setting, and the value written is clamped so a host
  already stricter than the baseline keeps its own. Rather than copy either into
  validate, a parameter's plan is now decided once from one observation and
  consumed by the runtime write and by the file alike.
- **`hardener apply --dry-run` previews the firewall boot enable it is about to
  make.** The boot-persistence repair above is performed by `apply` in the arm
  where the firewall was already running, and that arm of the preview asked
  about rules and nothing else, so the preview omitted a line the run would
  write and asked an operator to approve something they were never shown. It is
  not a rare corner: Fedora, RHEL and openSUSE all took that arm in the
  container runs of 2026-07-30. The preview now asks the same question through
  the same classifier `apply` uses, ahead of the rule estimate because that is
  where `apply` pushes it. A unit already wanted at boot is nothing pending,
  because `apply` records that as a skipped no-op and a preview line standing
  for a no-op would be counted into the change count a renderer prints and into
  the fleet's `would_change`. An install state that cannot be read becomes an
  issue for the same reason, at Medium rather than High because failing the dry
  run over it would fail it everywhere a unit has no `[Install]` section.
- **`hardener apply --dry-run` previews the SSH configuration the apply will
  read.** The plugin's validate path parsed the main file alone while scan and
  apply both resolve
  `Include` first, so on the layout Fedora, RHEL and openSUSE ship a main file
  already holding the target previewed no change at all while the apply went on
  to write a fragment. Failing to resolve is now a blocking issue rather than a
  quiet fall back to the main file, because that fall back is precisely the
  reading that was wrong. The crypto directives were previewed by nothing
  whatsoever: validate had no loop over them, so an apply writing three
  cryptographic lists announced none of them beforehand. The preview asks
  `ssh -Q` exactly as the apply does, so both compute the same intersection of
  the allow-list with what the host supports, and a host that cannot answer
  yields an empty intersection which both of them skip. The fragment is named
  once, because an operator approving a run should know a file will appear in
  `/etc`.
- **A kernel parameter this host does not have is no longer previewed as a
  read-only one, and a probe that failed is no longer previewed as absence.**
  Kernel validate wired three answers to two messages and got both wrong. A
  positively confirmed absence arrives carrying a zero mode, and a zero mode has
  no write bit, so a parameter this kernel does not carry was announced "is
  read-only" at High, which blocks the dry run; a probe that could not be
  determined announced "does not exist on this kernel" at Low, which does not.
  The missing parameter failed the run for the wrong reason and the unreadable
  one passed it. Absence is now answered before the mode is consulted and stays
  Low, since `apply` cannot set a parameter the kernel does not have and there
  is nothing for an operator to fix; the failed probe becomes a High issue
  carrying its reason, because the preview cannot describe what apply would do.
  `kernel.yama.ptrace_scope` is the ordinary case rather than a theoretical one,
  being absent on any kernel built without that LSM. The read-only wording is
  kept and is now reachable only for a parameter that is present with no write
  bit on its inode.
- **`hardener scan` no longer reports a critical permission check as clean on a
  distribution that keeps the file under `/usr/etc`.** Measured on the openSUSE
  test container: `/etc/sudoers` does not exist there, `/usr/etc/sudoers` does, at
  mode **0444**, and the directive requires **0440** exactly at Critical severity.
  The file in force is therefore world readable, which discloses the sudo policy,
  and the plugin reported **neither a finding nor an unchecked check**, because a
  confirmed absence from `/etc` was treated as nothing to report. A Critical
  severity check was passing on evidence nobody had collected. The permissions
  plugin now consults the same vendor layer the ssh and pam plugins already read,
  and reports what it finds there. The mechanism differs from theirs because this
  plugin audits modes rather than content: where those two read the contents of
  whichever copy is in force, this one takes the `/usr/etc` counterpart of a path
  confirmed absent from `/etc` and probes that counterpart's mode. Only paths under
  `/etc` have a counterpart at all, so `/root` and `/boot` are unaffected.
  **The vendor file is never written.** The finding names `/usr/etc/sudoers` and its
  remediation is a copy into `/etc` at the required mode, which is where a
  distribution layering its configuration expects a deviation to be stated, and
  which survives the next package update where editing the vendor file in place
  would not. The finding is keyed on the `/etc` path, so the report, the
  deduplication between a path's finding and its unchecked entry, and any
  compliance mappings the path carries all resolve it by the identifier they
  already ask for. `/etc/sudoers` carried no compliance mapping in this tool when this
  entry was written, so no framework report changed for the measured case; it
  and `/etc/sudoers.d` gained one later (issue #39). The permission paths
  carrying one at the time were `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `/etc/gshadow` and
  `/etc/ssh`. A policy exception written for the `/etc` path still annotates the
  finding, matched against the vendor copy's mode because that is the mode in
  force.
  **`apply` is unchanged, and so is the preview:** apply does nothing for a path
  absent from `/etc`, so `apply --dry-run` still reports no pending change for a
  vendor violation, and `scan` is the command that tells you about it. A path absent
  from both layers is still nothing to report, which is what `/etc/gshadow` reads on
  that same container, and a vendor path whose existence or mode cannot be read is
  reported as unchecked rather than as absence.

- **A kernel parameter that could not be read is no longer a compliance pass.**
  The scan judged the value it read and said nothing at all when the read
  failed, under a comment asserting a single cause it could not establish:
  reading `/proc/sys` fails for a kernel that does not carry the parameter, for
  a read an LSM or DAC refuses, for a `/proc` mounted `subset=pid` or not
  mounted at all, and over SSH for any failed command or dropped channel. All of
  it became the same silence. `coverage()` declares all eighteen parameters
  assessed and the report generator passes an assessed control on the mere
  absence of a finding, so a host whose ASLR value was never read rendered CIS
  1.5.1 as a Pass. Each unreadable parameter now leaves an unchecked entry
  carrying that parameter's own compliance mappings, which is what holds those
  controls at Manual Review, and the other seventeen keep their verdicts. Its
  own mappings rather than the plugin's whole coverage, deliberately: an
  unreadable `sysctl.d` file says nothing about any parameter, while an
  unreadable `/proc/sys` entry says nothing about exactly one. Whether a
  privileged re-run would reach it is derived from the failure rather than
  asserted, since a refused read is what root fixes and a parameter this kernel
  does not carry is not.

- **A permission path whose probe failed is no longer treated as a path that is
  absent.** `path_exists` has three outcomes by contract, and two callers in the
  permissions plugin collapsed them behind `unwrap_or(false)`, one of them under
  a comment calling the error "not an error". In validate the consequence was a
  preview that omitted a Critical path entirely, so an operator read a dry run,
  saw nothing about `/etc/shadow` and approved an apply whose scope they were
  never shown; it is now reported at High with the reason the probe gave, which
  is the first issue this plugin's validate can raise. In apply the consequence
  was quieter and worse: returning nothing recorded no change at all, and an
  omitted change cannot be a failed one, so the run reported success and the
  change list, which is the operator's record of what was hardened, held nothing
  for the path, indistinguishable from a host that was already correct. It is
  now a failed change carrying the probe's error, so the remaining paths are
  still hardened and the summary still says something went wrong. A confirmed
  absence still skips silently in both.

- **`auditd` enabled for this boot only is no longer read as enabled at boot.**
  `systemctl is-enabled` was judged on its exit status, and the exit status is
  not the answer: `static` and `indirect` each print their own word and exit 0,
  and so does `enabled-runtime`, which is an enablement held in
  `/run/systemd/system` that the next boot discards. The consequence ran through
  all three callers in the same direction, so scan reported a compliance the
  host did not have, validate previewed no change, and apply skipped the
  `systemctl enable` that would have made it true. Only the exact word `enabled`
  is now read as a permanent enablement. Everything else is not enabled, which
  is the safe direction: at worst it costs an enable attempt on a unit that
  cannot be enabled, recorded honestly as a failed change, where the other
  direction costs an operator their audit trail in silence. The services plugin
  asks systemd the same question and keeps the exit status deliberately, because
  a static unit reaches its unconditional mask only through that reading and
  taking the word there would leave a startable unit unmasked; its site now says
  so rather than looking like the same defect unfixed.

- **A configuration file is created in a directory that exists.** `write_file`
  lands content through a temporary file in the target directory, so it cannot
  create a missing parent. On the RHEL family `/etc/sysctl.d` belongs to
  systemd-udev rather than to systemd, so an install carrying systemd without it
  has no such directory, and the kernel plugin's apply reported "Failed to write
  file /etc/sysctl.d/99-hardener.conf" with no cause while kernel hardening
  never survived a reboot. The same gap sat behind every PAM write, where a host
  without the pam package has no `/etc/security`. Both now ensure the parent
  first, and the ordering is the subtle half: the creation runs **above** the
  checkpoint, because the checkpoint captures the directory, an absent path is
  stored with a zero mode, and a rollback reads a zero mode as "remove this", so
  a directory created after the capture would have turned a clean rollback into
  a refusal on exactly the hosts the fix is for. The audit plugin already
  created its rules directory but took its checkpoint first, which is that same
  defect in its ordering and the one instance whose rollback had no backstop;
  its installed-check moves above both, so a host with no audit package is
  neither given a stray directory nor checkpointed before being left alone. The
  four private copies of probe-then-mkdir are now one `ensure_directory` in the
  plugins crate. The comments claiming that no apply can create an undeletable
  path are corrected rather than left false, and every entry stays in that list.

- **A backup copy keeps the file's mode and does not follow a symlink.** Three
  plugins copy a configuration file before rewriting it, and all three asked
  `cp` the same question with three different answers: pam passed no flags, ssh
  passed `-p`, audit passed `--no-dereference`. Each was losing exactly what the
  other two kept, so there was no correct copy in the tree to copy from. A copy
  taken without `-p` carries none of the source's mode, ownership or timestamps,
  which matters most on the audit rules file, whose 0640 exists precisely so
  that the map of every path and syscall the host watches is not readable by
  everyone. A copy taken without `--no-dereference` follows a link and records
  the target, so a config that is a link elsewhere is backed up as some other
  file and the object about to be overwritten has no backup at all, which is
  likeliest at the ssh site on a host managed by configuration management.
  **Behaviour change worth stating:** `cp -p` exits non-zero when it cannot
  preserve ownership, which an unprivileged copy of a root-owned file cannot,
  and all three sites check the exit status and abort, so a non-root run now
  refuses at the backup rather than producing a copy that is not one. That is
  the fail-closed direction, and apply runs as root.

- **A configuration file this tool creates arrives at 0644 rather than 0600.**
  `update_file_atomically` stages content in a temporary file, which is right
  for a temporary file and wrong for the configuration file it becomes, and it
  only ever put a mode back where there was an original to restore. A file that
  did not exist therefore arrived at 0600 silently, and at 0600 the
  ordinary-user tools that read these files cannot: `pwscore` and `pwmake` fall
  back to their built-in defaults without saying so, which is a configuration
  that appears to apply and does not. 0644 is not a guess. It is what the
  distributions ship and what the remote path already produced, since
  `SshExecutor` writes through `tee` and a remote create lands 0644 under the
  standard umask, so one operation behaved differently depending on where it ran
  and nobody had recorded that divergence. The mode is set explicitly rather
  than left to the umask, because a hardening tool whose output depends on the
  shell it was launched from cannot be reasoned about, and it is set before the
  rename, so the target never exists at 0600 for even an instant.

- **The candidate `sshd_config` is cleaned up on the host it was staged on.**
  Validation stages a candidate, runs `sshd -t` against it and removes it. The
  staging and the check went through the executor, so on a remote target they
  happened there, while the removal was a bare local filesystem call that always
  ran on the controller. Every remote apply therefore left a complete copy of
  the incoming configuration in the target's `/tmp`, on the host it had just
  finished hardening, and asked the controller to delete a path of its own it
  had never written. The rejection path is the worse of the two, because a
  candidate the daemon refused is exactly the content an operator would least
  like left readable somewhere. The removal now goes through the executor like
  the three deletions already in this tree, cleanup stays best-effort so a
  failure to tidy up cannot mask the validation result, and both failure shapes
  are reported. The candidate also states 0600 for itself rather than inheriting
  the created-file 0644 above, which would otherwise have left a predictable
  filename in a world-writable directory holding the configuration about to be
  applied.

- **A second SSH apply no longer hands the host back to the drop-in it was
  hardened against.** The apply path asked whether anything *other than this
  tool's own fragment* overrode the main configuration, and read the empty
  answer as "nothing overrides it". Those stopped being the same question the
  moment the fragment existed. On Fedora and RHEL the first apply routes
  `X11Forwarding` to `00-hardener.conf` because `50-redhat.conf` outranks
  `sshd_config`; the second apply then found its own fragment supplying the
  value, discarded it, saw nothing left, wrote the directive into `sshd_config`
  where `50-redhat.conf` still beats it, and pruned the fragment that was
  holding the host. The run reported success while the host went from hardened
  back to unhardened, and because the scheduler applies on a cadence, a fleet
  host would do exactly that on its second scheduled run and report success
  every time. The question that decides where a directive belongs is now what
  would win if the fragment were not there. The same conflation reached the
  remote-root lockout guard through a different variable: a value the fragment
  alone supplied counted as "already safe enough", and every branch reaching
  that conclusion falls through to a rewrite of the fragment built from the
  directives that did need writing, so a second apply over a root session
  rewrote it without `PermitRootLogin` and handed a vendor-layer host back to
  the vendor's `yes`. Such a value is now carried into the rewrite; a fragment
  the file underneath has made genuinely redundant is still pruned.

- **A rollback command the host refused is no longer reported as a restore that
  worked.** Rollback issues `rm`, `chmod` and `chown` through the executor and
  none of the three looked at whether the command did anything.
  `execute_command` returns `Ok` for a process that started and exited non-zero,
  so all three inspected only the half of the answer that reports the command
  never starting. A removal blocked by a read-only mount or an unwritable parent
  directory came back successful, so the operator was told the host was back at
  its checkpoint while the file the apply had created was still there, still
  hardening the host they were trying to undo. The metadata half is worse for
  being anticipated: the design already expects a remote restore by a user who
  does not own the target to degrade to content only, and that degradation is
  exactly a command that runs and is refused, so the one failure the design
  expects was the one it could not see. For a rollback that puts `/etc/shadow`
  back, the difference between the recorded mode and whatever the file happens
  to carry is the whole point of recording it. All three now go through one
  function that runs the command and describes why it did not happen, and a
  refusal that prints nothing on stderr is reported by its exit status rather
  than as an empty string.

- **Rolling a remote host back restores the MAC mode that host recorded, not the
  controller's.** The rollback restored the target's files through the executor
  and then read `/etc/selinux/config` off the controller with a bare local
  filesystem call to decide what mode to put the target in, while every other
  file operation in that function goes through the executor. On a controller
  without that file the read failed, the failure folded into "no mode", and the
  default turned it into enforcing: three ways to be wrong stacked in one
  expression, and the outcome looked identical to a correct restore. The read
  now goes through the executor and its three outcomes are kept apart. A mode
  that was read is applied. A configuration confirmed absent means the target is
  not an SELinux host, which is what an AppArmor host looks like, and the
  AppArmor reload follows. A file that exists and could not be read, or that
  names no mode, leaves the running system alone and says so, because enforcing
  a mode nobody read is not restoring one; the file the rollback just put back
  still governs the next boot either way. Found in the same twenty lines:
  `setenforce`'s exit status was never checked, so `setenforce: SELinux is
  disabled` was logged as "SELinux policy reloaded" and, because the branch was
  chosen on that result, the AppArmor reload beside it was never attempted. On
  an ordinary Debian carrying `policycoreutils`, the rollback reloaded nothing
  and reported success.

- **Asking whether a command is installed works on a host without `which`.** The
  probe ran `which`, which is a separate package that Fedora, RHEL and openSUSE
  do not install, so on those three every question about every command came back
  as an error rather than as an answer and each caller turned that error into
  whatever it does with a failure. Service minimisation aborted its entire
  validate, and the firewall plugin fared worse: all three backend probes ask
  the same question, and the first error aborted backend classification before
  any backend was considered. Both audit paths and the AppArmor probe ask it
  too. `command -v` replaces it, because a shell is the one thing a host running
  this tool is guaranteed to have. It runs under `sh` with the program name
  passed as a positional argument rather than spliced into the script, so a name
  carrying shell metacharacters cannot alter what runs, and its answer is
  required to be an absolute path, since `command -v` also reports builtins and
  shell functions that this executor cannot spawn. The probe existed in two
  copies, one per executor, and is now one provided method on the trait, each
  executor still routing through its own `execute_command` so the probe runs on
  whichever host that executor targets.

- **Three configuration sections were validated by nothing.** `validate_config`
  named five plugin sections in five separate calls and left `[audit]`, `[mac]`
  and `[services]` out. The omission was invisible because the only code
  mentioning those three read the `custom_directives` table removed below; with
  that gone, their `directives` maps were checked by nothing at all, neither the
  key check that exists to stop path traversal through the kernel plugin's
  sysctl rewrite nor the universal shell metacharacter check. The configuration
  reference has been promising the opposite for as long as the gap existed, so
  the documentation was right and the code was wrong and nothing there needed
  changing. No unvalidated value reaches plugin code today, because none of the
  three reads a directive yet, which is exactly why it was worth fixing: a
  validation layer that is only correct while its consumers stay unwritten is
  not defence in depth. The five calls are now one table of eight rows, since a
  section absent from a list of separate calls is not validated leniently, it is
  not validated at all.

- **A plugin registry failure passes no compliance control.**
  `flatten_persisted_scans` resolved plugin metadata with a call that folded an
  error into an empty list, and an empty list is indistinguishable from a build
  that registers no plugins. Both loops beneath it are driven by that list, so
  the unchecked list came back holding only what the results themselves carried,
  and the generator passes any control it finds neither failed nor unchecked:
  every control the engine covers would have reported Pass on evidence nobody
  collected. The path is unreachable as the code stands, since the registry is
  built and read inside one expression and nothing else can hold the lock; it
  becomes reachable the moment that registry is hoisted to a shared `OnceLock`,
  which is a natural thing to do to a function that builds eight plugins on
  every report. It was also the only such call in production that did not
  propagate its error. The failure now takes the shape this module already uses
  for every other reason a plugin produced no evidence: an unchecked entry
  carrying declared coverage, which routes those controls to manual review.

- **A checkpoint can now record a symlink, so `systemctl disable` and
  `systemctl mask` are undoable for the first time.** `file_metadata` follows a
  link, so capturing `/etc/systemd/system` stored the *contents of the packaged
  unit files* its enablement links point at. Restoring that meant writing those
  bytes back through the link into `/usr/lib/systemd/system`, and chmod and chown
  follow a link just as readily, so the rollback allowlist refused the path. The
  result was that service enable, disable and mask state has never been
  recoverable on any distribution: rollback either skipped those entries or, until
  the fix above, abandoned the whole run over them.
  `FileState` gained a link target, `file_states` gained a `link_target` column,
  and a captured link is now restored by recreating the link rather than by
  writing through it, so nothing outside the allowlist is touched and the
  allowlist question becomes the link's own path. A path that is a link to a
  directory is recorded as a link instead of being walked into, which had captured
  the target directory's files under paths that resolved back through it.
  **Existing checkpoints keep working.** The new column reads back as NULL for
  them, which means "not a symlink" and restores exactly as before, and the
  signature digest includes the target only when one is present, so a checkpoint
  signed before this release still verifies.

- **`hardener rollback` now recreates a directory that was removed after the
  checkpoint, which is what `systemctl disable` leaves behind.** Recording a
  symlink, above, made the enablement link storable; placing one whose directory
  had gone was still impossible. `systemctl disable` removes the enablement
  symlink and then the `*.target.wants` directory it emptied, which is the
  ordinary case for a service that is the only thing wanting its target, and a
  rollback restored one recorded path at a time without creating anything on the
  way. Measured on all five test distributions: rollback of a
  `service-minimisation-pre-apply` checkpoint exited 1 with exactly two failures
  per host, `chmod: cannot access
  '/etc/systemd/system/bluetooth.target.wants'` and `ln: failed to create
  symbolic link ...: No such file or directory`, while a sibling link in the
  surviving `/etc/systemd/system` came back in the same run. Both sites now
  create the directory they need first, independently of each other: the
  directory's own row and the link's parent, each probed before any `mkdir -p`
  so a directory already present is never written to. A row is treated as a
  directory by the file-type bit in its recorded mode, never by the absence of
  content: the permissions plugin checkpoints `/etc/passwd`, `/etc/shadow`,
  `/etc/gshadow` and `/etc/sudoers` metadata-only, deliberately, so that no
  password file's contents reach the checkpoint database, and those rows are
  content-less too. Restoring one whose file had since been removed must not put
  a directory named `/etc/shadow` in its place; it reports that it could not
  restore the path, which is the honest answer for a checkpoint holding nothing
  to rebuild the file from. Checkpoints written before capture recorded the type
  bit store a directory as bare permission bits and are unaffected, restoring
  exactly as before.

- **`systemctl mask` is now recorded well enough to be reversed.** The services
  plugin's pre-apply checkpoint declared only the directory a mask link lands
  in, and a recursive capture emits one row for that directory and one for each
  child that is there when it runs, so the link, which by definition is not
  there yet, was carried by no row at all. Rollback walks only the rows a
  checkpoint holds and has no sweep for anything else, so the mask survived it:
  the state was recorded well enough to describe and not well enough to reverse.
  Each masked unit's path is now named to the checkpoint the way the kernel and
  ssh plugins already name the files their own applies create, and an absent
  declared path is stored with a zero mode that the restore reads as an
  instruction to remove what is there, so the existing mechanism does the work
  and nothing new deletes anything. Only the units the host actually has
  installed contribute a path, because that directory is also where an
  administrator's own unit overrides live.

- **`hardener rollback` now removes the `/dev/null` symlink `systemctl mask`
  leaves behind, rather than refusing it.** The services plugin declares each
  masked unit's path to its pre-apply checkpoint, and a path absent at capture is
  stored with a zero mode meaning "remove on restore", so the row that undoes a
  mask was present and correct. The restore refused it: the guard that stops a
  rollback writing captured content *through* a symlink asks what the path
  resolves to now, and at rollback time the path is the mask link, which resolves
  to `/dev/null`, outside every allowlist. Measured in a container:
  `[skipped] /etc/systemd/system/bluetooth.service`, "Rollback symlink
  /etc/systemd/system/bluetooth.service resolves outside allowed directories",
  and the mask outlived the rollback meant to undo it. A row recorded absent is
  restored by `rm -f` on the path, which unlinks the entry itself and follows
  nothing, so it now carries the same exemption a recorded symlink already had,
  for the same reason: the write lands on that path and nowhere else. The
  exemption is deliberately narrow, keyed on what the row records rather than on
  what stands at the path. A row carrying content is still refused when its path
  is now a link out of bounds, because that write would go through the link, and
  so is a directory row, whose `chmod` and `chown` follow one just as readily.
  The paths a rollback may never delete are unaffected: that rule is enforced
  after this guard, and a protected path recorded as absent is still probed and
  still never removed.

- **Rolling back an audit apply now restores the compiled rule set auditd
  actually loads, instead of leaving the hardening in force at the next boot.**
  `apply --plugin audit-rules` writes `/etc/audit/rules.d/hardening.rules` and
  then runs `augenrules --load`, which compiles everything in `rules.d` into
  `/etc/audit/audit.rules` and saves the previous compiled copy as
  `/etc/audit/audit.rules.prev`. Neither of those two lives in `rules.d`, so the
  recursive capture of that directory never reached them, and the pre-apply
  checkpoint named neither. Measured on all five test distributions:
  `/etc/audit/audit.rules` went from 5 lines to 30 on Arch and from 6 to 31 on
  Debian, Fedora, RHEL and openSUSE during the apply, and read **exactly the
  same after a rollback that reported success**, so the rollback removed the
  source file and left the compiled output auditd reads at start-up. The `.prev`
  file was created by the apply and survived the rollback on Arch, Debian,
  Fedora and RHEL; openSUSE's `augenrules` writes no `.prev`, and the gap was
  present there too. Both paths are now declared to the checkpoint alongside the
  three that were already there, which handles the two cases separately:
  `audit.rules` exists before the apply on every host measured, so it is
  captured with its content and restored to its pre-apply bytes, while `.prev`
  usually does not exist, so it is stored absent and removed, and an
  administrator's own earlier copy is captured and restored instead.
  Re-running `augenrules` after the restore was considered and rejected: it
  would load rules as a side effect of an undo, it fails in exactly the
  environments where the apply already fails, and it does nothing about `.prev`.
  **The rollback returns the persistent state only.** Rules already loaded into
  the running kernel stay loaded until a reload or a reboot, which is the same
  limit the kernel plugin's rollback has always had with runtime sysctl values.

- **`hardener rollback` no longer refuses to restore anything because one file
  in the checkpoint cannot be restored.** Measured on the five test
  distributions: four of them failed rollback outright, restoring nothing, with
  `Rollback aborted: symlink /etc/systemd/system/autovt@.service resolves
  outside allowed directories`. The services plugin declares
  `/etc/systemd/system` so a checkpoint captures what a distribution ships
  there, including stock unit symlinks pointing into the package-owned
  `/usr/lib/systemd/system`. Refusing to write a captured copy through such a
  link is correct and unchanged: it would overwrite a packaged unit file. What
  was wrong is what happened next. The pre-validation pass returned an error on
  the first such path and abandoned the whole rollback, while the restore pass
  had always recorded the identical condition as one skipped file, so two copies
  of one guard disagreed and the fatal copy ran first. They are now one
  definition. A refused path is skipped with its reason named in the result, the
  rollback restores everything in bounds, and it reports failure so the exit code
  is non-zero. A checkpoint in which no path at all may be restored is still an
  error, and still leaves no pre-rollback snapshot behind.

- **A configuration file that is not there is no longer reported as a malformed
  one, and no longer fails the dry run.** PAM's validate probed
  `/etc/security/pwquality.conf` and `/etc/login.defs` with `file_metadata` and
  read `is_file` alone. That field is false both for a file which is absent and
  for a directory standing where a file should, because a positively confirmed
  absence is reported as existing-false with is-file-false, so both states
  rendered as "exists but is not a regular file" at High severity, which fails
  `apply --dry-run`. Measured on the five test distributions: three of them do
  not keep `pwquality.conf` under `/etc` and openSUSE keeps `login.defs` under
  `/usr/etc`, so the run called a file malformed on every host that merely kept
  it somewhere else. The probe is removed rather than corrected: the layered read
  beside it already answers the same question across both configuration layers
  with three outcomes, previewing an absent file's directives as "currently not
  set" for apply to create, and naming any file that exists but cannot be read.

- **A dry run no longer counts a check it could not make as a pending change.**
  `hardener apply --dry-run` prints "N change(s) to apply" from the plugin's
  list of pending changes, and `hardener batch --dry-run` sums that same list
  into the fleet's `would_change` total. The PAM plugin put a line there for
  every directive whose configuration file it could not read, and the firewall
  plugin put one there when the live ruleset could not be read without root, so
  a host on which the tool will attempt no write at all was previewed as six
  changes, or as one. Both now report the limitation as a validation issue,
  which the terminal already prints beneath the count and the desktop already
  renders, so nothing an operator was told disappears. The PAM issue is High,
  matching what apply does with the same host: it refuses to rewrite a file
  whose contents it could not see, records the refusal as a failed change and
  exits non-zero, so an unprivileged dry run against a root-only
  `/etc/security/*.conf` now fails instead of reporting a clean nothing-to-do.
  The firewall issue is Medium, because a privileged apply reads the ruleset
  and succeeds: the limit is on what an unprivileged preview can see, not on
  the run.

- **The kernel plugin no longer writes a host's stricter sysctl back down to
  the baseline, at runtime or at the next boot.** All eighteen parameters were
  compared for equality, which has no direction. A host with
  `kernel.yama.ptrace_scope = 3`, which forbids `ptrace` outright, was reported
  as violating a baseline of 2 and written down to 2; the same held for
  `net.ipv4.tcp_syncookies = 2`. The persistent half was worse than the runtime
  half: `/etc/sysctl.d/99-hardener.conf` was written with the plain baseline for
  every parameter, outside the check that skipped an already-compliant runtime
  write, so even where the runtime value was left alone the file restored the
  looser value at the next boot. Both now write the stricter of the target and
  what the host already runs.

  Three parameters needed more than a direction, because their strictness is
  not what their integer says. `net.ipv4.conf.all.rp_filter` and its `default`
  twin rank strict mode `1` above loose mode `2` above off `0`, so the
  strongest value is the middle number and no numeric direction can express it.
  `fs.suid_dumpable` ranks `0` above `2` above `1` for the same reason.

  **Behaviour change worth noting:** a `[kernel]` directive override in
  `config.toml` is now clamped tighten-only, as `[pam]` and `[ssh]` are, so
  `kernel.kptr_restrict = "0"` yields 2. `[permissions]` is now the only plugin
  where an override is applied as given. Record a deliberate deviation as a
  policy exception, which the report labels.

- **The SSH plugin no longer writes a host's stricter setting back up to the
  baseline.** `MaxAuthTries`, `ClientAliveInterval` and `ClientAliveCountMax`
  were compared for equality, which has no direction, so a host allowing two
  authentication attempts against a baseline of three counted as violating and
  apply wrote the three over it, through the drop-in that sshd reads first.
  Measured on a mock host: `MaxAuthTries 2`, `ClientAliveInterval 60` and
  `ClientAliveCountMax 1` were all reported as findings and all three were
  loosened by an apply that reported success. This is the same defect that was
  fixed in the PAM plugin below, in a second plugin, and rather than copy the
  rule a third time the comparison now has one definition that pam, ssh and
  kernel share. `ClientAliveInterval 0` stops sshd probing an idle client at
  all, so zero is treated as the loosest value that setting has rather than the
  smallest; `MaxAuthTries 0` and `ClientAliveCountMax 0` really are the strict
  end and are honoured as such. `PermitRootLogin` is now ordered explicitly
  (`no` over `forced-commands-only` over `prohibit-password` over `yes`, with
  `without-password` ranking alongside the modern spelling of the same
  setting), which replaces a hand-written list that expressed the same ordering
  only for the remote-root lockout guard. **Behaviour change worth noting:** an
  `[ssh]` directive override in `config.toml` is now clamped tighten-only, as
  `[pam]` already was, so `MaxAuthTries = "10"` yields 3 and
  `X11Forwarding = "yes"` yields `no`; record a deliberate deviation as a policy
  exception instead, which the report labels rather than silently lowering the
  bar.

- **`apply` no longer makes a host less secure than it found it.** Nine of the
  eleven PAM directives compared for equality, so any value other than the
  baseline counted as a violation, stricter ones included, and apply then wrote
  the baseline over it. Measured on a mock host: `PASS_MAX_DAYS 30`,
  `PASS_MIN_DAYS 7` and `PASS_WARN_AGE 14` came out of an apply as `90`, `1`
  and `7`, relaxing a 30-day password expiry to 90 days while reporting
  success. The same held for `minlen`, the four credit settings and
  `maxrepeat`. The no-loosen rule and the machinery for it already existed and
  had been applied to shadow permissions, `PermitRootLogin` and the
  faillock/pwhistory thresholds; these nine were never swept into it. Every PAM
  directive now carries a direction, apply writes the stricter of the baseline
  and the host's own value, and the direction-less comparison has been removed
  outright so a directive added later cannot be given one. `maxrepeat = 0` is
  treated as the check being switched off rather than as the strictest possible
  value. **Behaviour change worth noting:** a `[pam]` directive override in
  `config.toml` is now clamped tighten-only like `deny` and `remember` always
  were, so an override that loosens the baseline no longer takes effect; record
  a deliberate deviation as a policy exception instead.

- **A PAM configuration file no module reads is no longer reported as the
  host's policy.** `/etc/security/pwquality.conf` is consumed by
  `pam_pwquality.so` and by nothing else, and the plugin never checked that the
  module was in the stack: it read the file, found `minlen = 14`, and passed the
  control. A host whose stack does not load the module enforces no minimum
  length at all, and `minlen` alone carries mappings to CIS, STIG
  RHEL-08-020230, NIST IA-5(1)(a), 800-171 3.5.7, ISO 27001, SOC 2 and FedRAMP,
  so the silent pass was seven frameworks wide. `faillock.conf` and
  `pwhistory.conf` had the same gap. `scan` now reads
  `/etc/pam.d/{system-auth,password-auth,common-*}` and reports every directive
  in an unread file as not enforced, naming the module to add;
  `apply` writes the file but records the missing module as a failed change; and
  `apply --dry-run` raises it as a High issue, so the preview and the apply
  reach the same verdict. Absence is concluded only from a stack file that was
  actually read: an unreadable stack, or a distribution whose stack layout this
  tool does not recognise, is reported unchecked instead. `/etc/login.defs` is
  unaffected, since shadow-utils reads it with no module loaded.
  Measured on a stock Arch workstation: `/etc/pam.d/system-auth` loads
  `pam_faillock.so` four times and `pam_pwquality.so` not at all,
  `libpwquality` is not installed, and `/etc/security/pwquality.conf` is 0600.
  A privileged scan there used to read that file and pass six controls on it.
  `pam_pwhistory.so` is present on disk but likewise absent from the stack, so
  `remember` was passing the same way. Measured again across the five
  distribution images the project tests against: **three of the five do not
  load `pam_pwquality.so`** (Arch, Debian and openSUSE; Fedora and Rocky do),
  so six password-quality directives were passing on three of five images. The
  differential suite gained a check that asks the stack and holds it against
  the tool's own verdict, and the two now agree on all five.
- **The unchecked roll-up no longer tells an operator to re-run with sudo for
  a check sudo cannot reach.** Every check a scan could not evaluate was
  summarised as needing root, in four separate renderers that had each written
  their own sentence: the scan footer, the per-plugin note, the per-host batch
  line and the report wizard. Privilege is only one of the causes. A plugin
  disabled in the configuration, a path on a filesystem with no POSIX
  permission bits, a service list that could not be read and a probe that
  failed for its own reasons all land in the same list, and none of them
  improves with root; a container already running as root printed
  `1 check(s) require root`. `UncheckedCheck` now carries
  `unchecked_needs_privilege`, set by the producer that knows, and one shared
  `unchecked_summary` builds the line for all four renderers. Sudo is offered
  when every entry wants it, withheld when none does, and a mixed run says how
  many of the total root would reach. A scan persisted before the field existed
  reads as claiming nothing rather than as promising a remedy. The desktop's
  score hero and findings tab had the same two copies of the claim and a
  "Run with sudo" button offered whatever the cause; both now share one honesty
  line, and the button appears only when a privileged re-run would reach
  something. Measured on a developer workstation: 33 unchecked checks, 32 of
  them privilege-blocked and one a `/boot` on vfat that no privilege can give
  POSIX permission bits.

- **`batch apply --dry-run` and `apply --dry-run` no longer disagree about
  whether a host failed.** The single-host dry run fails on Critical and High
  validation issues only, treating anything lower as advisory so a note cannot
  become a non-zero exit. The fleet path instead counted every host whose report
  carried any issue at all, and that count feeds the exit code, so one host and
  one report exited 0 through `apply --dry-run` and 1 through
  `batch apply --dry-run`. A CI gate built on the fleet verb therefore failed on
  advisory notes. The rule now has one definition, `ValidationReport::
  has_blocking_issue`, which both paths call. `validation_report_is_valid` is
  unchanged and still means "this report has something to say"; it is what the
  text renderer's marker reads.

- **`apply --dry-run` reports layer drift, which only `scan` did.** The preview
  an operator reads before applying listed the directives that would change and
  said nothing about masked keys, so a host whose vendor settings had already
  reverted previewed identically to one whose had not. Drift is reported as a
  Medium validation issue, not as an estimated change: `apply` does not import
  keys an existing `/etc` file omits, so listing it as a pending change would
  inflate the change count and promise a write that never happens. Medium is
  advisory, so a dry run still exits zero; only Critical and High fail it.

- **Layer drift is reported for every layered PAM configuration file, not only
  `/etc/login.defs`.** The whole-file override belongs to the layering, not to
  one path, so a hand-rolled `/etc/security/pwquality.conf` masks its
  `/usr/etc` counterpart exactly as `/etc/login.defs` does. The check was
  wired to `login.defs` alone, so masked password-quality, lockout and
  reuse-prevention settings were reported nowhere and the host scanned clean
  while running those modules on their built-in defaults.
  `/etc/security/{pwquality,faillock,pwhistory}.conf` are now checked too, each
  with its own Medium finding (`pam-pwquality-conf-masked-keys`,
  `pam-faillock-conf-masked-keys`, `pam-pwhistory-conf-masked-keys`) naming the
  keys that file hides. `pam-login-defs-masked-keys` is unchanged.

- **Configuration layered across `/etc` and `/usr/etc` is read from the layer
  that supplies it.** openSUSE Leap 15.6+, Tumbleweed and MicroOS ship vendor
  configuration under `/usr/etc` and reserve `/etc` for administrator
  overrides, and Fedora is moving the same way. The tool read `/etc` only, so
  on such a host every directive the vendor set read as unset: an unprivileged
  scan reported findings against a host that was already compliant, and apply
  wrote a short `/etc` file that silenced the rest. Both the SSH and PAM
  plugins now resolve the file the system actually obeys. `/usr/etc` is
  consulted only on absence positively confirmed at `/etc`, so a root-only
  `/etc` file that cannot be read is never answered with the vendor copy's
  values.
- **SSH hardening is written where sshd will actually read it.** Fedora and
  RHEL ship `/etc/ssh/sshd_config.d/50-redhat.conf`, which sets
  `X11Forwarding yes`, and sshd takes the **first** value it obtains, so the
  distribution's fragment beat everything the tool wrote to the main file and
  the host was left unhardened while the tool reported success. Hardening now
  goes to `/etc/ssh/sshd_config.d/00-hardener.conf`, which sorts before what
  distributions ship, and the precedence is verified after writing by
  re-resolving the configuration rather than assumed from the filename.
- **A vendor configuration file is copied into `/etc` before it is edited.**
  Where the setting being hardened lives in a `/usr/etc` file, the whole file
  is carried over first and the managed directives edited into that copy, so
  nothing the distribution set is lost. 1.5.1 refused the write instead, which
  was honest and left the host unhardened. The copy is given the vendor file's
  own permissions rather than the temporary file's, because at 0600 the
  ordinary-user tools that read `/etc/security/pwquality.conf`, `pwscore` and
  `pwmake`, silently fall back to their built-in defaults.
- **`scan` reports keys an `/etc` file masks.** New Medium finding
  `pam-login-defs-masked-keys`, naming every key `/usr/etc/login.defs` sets
  that `/etc/login.defs` does not. It fires on the drift rather than on its
  cause, so it covers an operator's hand-rolled file and a vendor that adds a
  key in a later package as well as the file an older release of this tool
  wrote.

- **A configuration file this tool writes ends with a newline.**
  `set_config_directive` read its input with `str::lines`, which discards the
  terminator, and reassembled it with `join("\n")`, which does not put one
  back, so every file it produced was one byte short and the next thing
  appended landed on the last directive rather than below it. The symptom that
  found it was sshd refusing a `MACs` value with a `MaxAuthTries` welded onto
  its end. The loss was never conditional on appending: a directive merely
  rewritten where it already stood came back truncated too, so a host needed no
  new directive to end up one `echo >>` away from an sshd that will not start.
- **A permissions directive override may tighten a target and never relax it.**
  The permissions plugin was the last one applying an operator's override
  exactly as given, so a configured mode replaced the shipped target with
  nothing comparing the two. The rule could not be borrowed from the type the
  other plugins use, which scores every value on one scale: a permission mode
  is a bitmask whose order is partial, and 0640 and 0604 are neither stricter
  nor looser than one another but different. It is stated here as a subset
  test, so an override earns its place by setting no bit the baseline does not
  already set.
- **A kernel dry run stops promising a write to a read-only mount.** The plugin
  decided a parameter was read-only from the write bit of its inode under
  `/proc/sys`, a test that can never observe the thing it is asked about:
  read-only is a property of the mount and every file under `/proc/sys` is 0644
  either way. Inside a container whose `/proc/sys` is the host's and mounted
  read-only, `apply --dry-run` previewed writes the apply could not perform and
  raised nothing, on exactly the surface an operator uses to decide whether a
  run is safe. The mount is asked directly now.
- **A dry run stops reporting an unchecked value as the host's state.** For
  services, mac, audit and firewall a policy exception's value field is
  advisory: the key already names the deviating item and nothing ever matches
  the value, which the configuration reference has stated for some time. Three
  of the four passed that field into the slot of the preview line documented as
  the value the host keeps, so a stale or placeholder declaration was printed
  as though it had been read from the machine. On a Permissive host an
  exception declaring Enforcing made the preview state the opposite of the
  truth.
- **An approved deviation an operator wrote down reaches compliance.** Six scan
  findings across firewall, mac and audit hardcoded their policy exception to
  `None`, so the configuration could not excuse them however the operator wrote
  it. A control is failed by any finding carrying no exception, which means a
  documented deviation was honoured by apply and by the dry run and ignored by
  scan and by report, against what the configuration reference promises. Each
  now takes a key naming the subsystem state, the shape mac already used for
  `selinux-enforcing`. Keying on the finding identifier was rejected because
  firewall builds its identifiers from the detected backend, so an exception
  written on a ufw host would have stopped matching on a firewalld one.
- **A release run completes rather than aborting on a target that had moved.**
  Step 3c of `scripts/release/release.sh` asserted on a README alt-text pattern
  that stopped existing when the test badge became status-only, so a real
  release aborted after `Cargo.toml`, `architecture.md`, the man page and
  `tauri.conf.json` had already been rewritten, leaving a half-versioned tree.
  The dry run could not report any of this, because it skipped the step
  outright: the one step able to abort a release was the one step a rehearsal
  never reached. It now runs the same assertions and writes nothing.

- **`packaging/.SRCINFO` describes the package the PKGBUILD builds.** It read
  `pkgver = 1.2.2` against a PKGBUILD of 1.5.1, and the `source` line derived
  from it pointed at the v1.2.2 tarball. The AUR reads `.SRCINFO` and never the
  PKGBUILD beside it, so its web page, its search index and every helper
  resolved this package's version and sources from a file three releases behind.
  Regenerated, and held there by `validate_srcinfo.py`.

- **A firewall directive override can no longer weaken a rule's action.** The
  firewall plugin was the last one applying an operator's override exactly as
  given, so `[firewall] directives` carrying `"drop_default.action" = "accept"`
  passed validation and apply wrote an ACCEPT catch-all where the baseline had
  DROP, against what the configuration reference promised for every plugin. A
  blocking rule can no longer be overridden into an accepting one; tightening an
  accepting rule, and swapping `drop` for `reject`, both still work. `action` is
  the only field clamped, because it is the only one whose direction holds for
  any rule, and `docs/reference/configuration.md` now says exactly that rather
  than promising a clamp on `port`, `source` and `protocol` that is not
  performed.

- **`hardener rollback` restored files but never asked the services reading
  them to reload, so a host could stay on the configuration the rollback was
  meant to undo.** Restoring `/etc/ssh/sshd_config` did not restart sshd,
  restoring a sysctl drop-in did not re-run `sysctl --system`, and the same
  gap existed for the firewall, audit, service-unit and MAC plugins: the file
  on disk changed while the running process kept whatever it had loaded at the
  last apply. An operator who rolled back to undo an unwanted apply saw the
  rollback reported as successful while the host went on enforcing the
  configuration the rollback was supposed to have reverted, which is not the
  host running weaker security than asked, but the recovery path failing to
  recover. PAM and file-permission changes take effect immediately and were
  never affected.

  Every plugin now answers whether a restored path is one it needs to reload,
  and a rollback asks each plugin that claims one of its restored paths to do
  so once apply finishes restoring files. `RollbackResult` carries the outcome
  of each reload alongside the existing restore result, and the CLI now exits
  non-zero when either half failed, naming which one. **Check an affected
  host rolled back by any release up to and including 1.5.1: the running
  configuration may not match the restored files, and a reboot resolves it.**

### Removed
- `hardener_scheduler::systemd::user_unit_path` and `system_unit_path`, two
  accessors nothing in the workspace called. The first returned
  `/etc/systemd/user` under a doc comment promising a path relative to home,
  and described neither the value nor what the product does: both places that
  install a user unit build `$HOME/.config/systemd/user` themselves. Correcting
  it was rejected, because the right answer depends on `HOME` and a
  `&'static str` cannot hold it. `service_name` and `timer_name` stay; the CLI
  and the crate's own tests call both.
- `custom_directives`, the per-plugin config table that was accepted, merged
  across config sources, counted towards the directive limit and validated at
  load time, while no plugin ever read it. Anything set there had no effect,
  and the configuration reference's own SSH example put `ClientAliveInterval`
  and `ClientAliveCountMax` in it, two directives the SSH plugin does support,
  so an operator following the documentation set two real settings in the one
  place they could not take effect. The table has been removed rather than
  implemented. **A config file that still names it loads unchanged**, because
  nothing sets `deny_unknown_fields` and an unknown key is ignored. Move any
  entry the plugin does support into `directives`, where it takes effect.

## [1.5.1] - 2026-07-27

### Changed
- `scan --exit-code` exits non-zero on an incomplete scan as well as on
  findings. A clean exit is a positive claim about the host, and a plugin that
  never ran has not earned it. **A CI gate built on this flag can now fail where
  it previously passed**, on a host where a plugin cannot complete its scan
  rather than on one with new findings. `--format json` names which plugin and
  why.

### Removed
- `scan --compliance`, which never did anything. clap accepted it, it conflicted
  with `--audit` as though the two were alternatives, and the behaviour it
  documented ("only show findings without valid policy exceptions") was
  implemented nowhere: the flag set a mode value no code read, so every run it
  appeared in produced exactly the default scan. It was documented as a working
  feature in the manual page, the CLI reference, the architecture overview, the
  getting-started guide and the roadmap, and exercised by the cross-distro test
  suite, none of which could tell that it did nothing. `hardener report
  --framework <id>` is the real compliance output, and a finding covered by an
  exception is now labelled everywhere rather than hidden anywhere.

### Fixed
- Hardening no longer destroys vendor configuration on openSUSE. That
  distribution keeps vendor files in `/usr/etc` and reserves `/etc` for
  administrator overrides, and the override is whole-file rather than per
  directive: the first file found wins entirely. None of the PAM plugin's
  configuration files exists under `/etc` on such a host, so `apply` treated
  each as absent, merged its directives into an empty buffer and wrote it. The
  three-directive `/etc/login.defs` that produced silenced the other 35 keys
  `/usr/etc/login.defs` sets, among them `ENCRYPT_METHOD`, which selects the
  password hashing algorithm for every password set afterwards, and `UMASK`,
  `HOME_MODE`, `FAIL_DELAY`, `LOGIN_RETRIES` and `LOGIN_TIMEOUT`. Four of those
  are login-hardening settings, so the tool was disabling controls in its own
  subject area, and it defeated itself as well: it set `PASS_MAX_DAYS` while
  clearing `PASS_WARN_AGE`, so accounts expired with no warning. `apply` now
  refuses to create a file under `/etc` when a vendor counterpart exists, names
  it, and asks the operator to copy it first; the run is reported unsuccessful
  rather than clean. **If you have run this tool on openSUSE, check
  `/etc/login.defs`, `/etc/security/faillock.conf` and
  `/etc/security/pwhistory.conf`. All three have vendor counterparts under
  `/usr/etc`, and a file of a few lines is this defect. Restoring the vendor
  settings means copying the `/usr/etc` version over each short file and
  re-applying your intended values.** `/etc/security/pwquality.conf` is not
  affected: openSUSE ships no vendor copy of it, so creating it masks nothing.
  Hardening the refused directives on openSUSE is declined rather than done
  until layered vendor configuration is supported; scanning is unaffected.
- The desktop could mark a compliance control as passed for a plugin that never
  ran, with nothing having failed. A compliance report decides `Pass` from
  statically declared plugin coverage plus the absence of a finding, so a plugin
  contributing no evidence passes every control it covers on the silence its own
  absence caused. The desktop reached that state three ways, and none of them
  needs an error: it discarded `scan_success` when flattening a stored scan
  session, so the value survived the database round trip and was then thrown
  away; it swallowed a plugin whose scan returned an error; and it dropped the
  plugins the configuration had disabled, so **turning a plugin off was on its
  own enough to pass every control that plugin covers**. A scan filtered to a
  single plugin did the same for the other seven. Any plugin that contributed no
  results now reports its controls as **Manual Review**, and the rule lives in
  one place shared with the CLI rather than being reimplemented on each side.
  Regenerate any compliance report the desktop produced, whether or not you ever
  saw a scan fail.
- A plugin whose scan did not complete passed its compliance controls. The same
  mechanism from the command line: `report` dropped an errored plugin entirely
  and kept no record of one that returned successfully while reporting
  `scan_success: false`, so neither failure reached the generator and every
  control that plugin covers was marked `Pass` on evidence nobody collected. A
  plugin that did not complete now contributes an unchecked entry carrying its
  whole declared coverage, which routes those controls to Manual Review through
  the mechanism already built for checks that could not run. A report filed or
  forwarded from a host where a plugin's scan failed states passes that were
  never assessed, so regenerate it rather than trusting the copy you have.
- A drop-in under `/etc/ssh/sshd_config.d/` no longer overrides the tool
  silently. The shipped `sshd_config` on several distributions carries
  `Include /etc/ssh/sshd_config.d/*.conf` on line 2, sshd uses the first value
  it obtains for a keyword, and everything this tool writes lands below that
  line, so a drop-in always won while the tool reported the value it had
  written. `sshd -t` does not object to this. Scan now resolves `Include`
  directives in sshd's own order and reports the value sshd will actually use,
  naming the file that supplies it; apply refuses to claim success for a write
  a drop-in overrides and tells the operator which file to edit. A pattern that
  cannot be expanded faithfully, or a drop-in directory that cannot be listed,
  is an error rather than an assumption that there are no drop-ins.
- An `sshd_config` directive inside a `Match` block is no longer read as the
  host's global setting. `Match Address 10.0.0.0/8` followed by
  `PermitRootLogin no` was read back as though root login were closed
  everywhere. Apply then found the target value apparently in place, wrote
  nothing and recorded no change at all, leaving the real global directive at
  sshd's compiled default while the tool reported the host compliant.
- `apply --dry-run` shows the validation issues it found. Every operator-facing
  renderer read the estimated changes and never the issues alongside them, so a
  plugin that could not read its own configuration file rendered as
  "0 change(s) to apply" and exited 0, which is byte-identical to a host that
  needs nothing: an unreadable `sshd_config` looked exactly like a compliant
  one. Issues now render with their severity and the configuration key they
  concern, in the CLI and in the desktop preview. A Critical or High issue fails
  the run while lower severities stay advisory, and a group carrying an issue
  can no longer present itself as already compliant.
- The MAC plugin no longer reports success when it merely failed to detect
  SELinux or AppArmor. Detection folded a failed filesystem probe into "no MAC
  system present", so `apply` recorded a successful change reading "nothing to
  configure": a deliberate-looking no-op on a host that may have carried a real
  and misconfigured SELinux or AppArmor installation. Detection now
  distinguishes absent from indeterminate. Scan reports the latter as unchecked,
  carrying the plugin's coverage so its controls reach Manual Review, apply
  records a failed change, and validation raises a High issue, which the dry run
  treats as blocking.
- `hardener apply --plugin <name>` refuses a name that matches no plugin,
  as `scan` already did. It previously dropped such names, so
  `hardener apply -p services` (the plural of a real plugin, matching nothing)
  hardened nothing, printed nothing and exited 0. The same applies to
  `batch apply` and `batch rollback`.
- `hardener apply` no longer exits 0 having hardened nothing when the config
  disables every plugin selected. A clean exit is a positive claim about the
  host, and `scan` already refused the same situation. Per host, `batch apply`
  reported this as "0 ok, 0 failed", which reads as complete success.
- The checkpoint signing key can no longer be destroyed by a failed migration.
  Loading a legacy plaintext key re-read the file to decide whether it needed
  migrating, folded any read failure into "not yet encrypted", then deleted the
  key and wrote a new one. A failure at that second step left the host with no
  signing key at all and logged only a warning, taking the tamper-evidence of
  every existing checkpoint with it. The format is now decided from the bytes
  already read, and the replacement is written alongside and renamed into place,
  so a failure leaves the original key exactly as it was and the migration
  simply happens next time.
- The audit plugin no longer overwrites its rules file after a backup that
  failed. The backup ran only when an existence probe returned true, so a probe
  that errored skipped it, and the `cp` exit code was never checked, so a failed
  copy reported success and the write went ahead. A failed backup now aborts
  before the write.
- `hardener rollback` now restores what the services plugin changed. That
  plugin checkpointed `/etc/systemd/system` and `/usr/lib/systemd/system`,
  neither of which was in the rollback allow-list, and rollback validates every
  captured path before writing anything, so it aborted with "path outside
  allowed directories" and restored nothing at all. Services rollback had never
  worked. `/etc/systemd/system` is now allow-listed, and the packaged unit
  directory is no longer captured: nothing this tool does writes there, and
  keeping it out means a restore can never overwrite a distribution's unit
  files with copies taken before a package update.
- `LocalExecutor::path_exists` distinguishes "absent" from "could not tell".
  It answered with `Path::exists`, which folds every error into `false`, so a
  path the process could not stat read as confirmed absence. That left the
  rollback guard protecting the account databases unreachable on a local target.
- `scan --format json` reports whether each plugin's scan completed. The
  renderer took a findings triple, so `scan_success` and `scan_error` had
  nowhere to live and could not have reached the JSON even in principle, and the
  desktop's parser hardcoded `scan_success: true`. A machine consumer therefore
  could not distinguish a plugin that found nothing wrong from a plugin that
  never ran. Both fields are part of the JSON contract now, the terminal prints
  a trailing count of incomplete scans, and an entry arriving without the field
  fails closed rather than being assumed successful.
- A critical path whose permissions cannot be read is reported as unchecked.
  `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/passwd`, `/root` and
  `/etc/ssh` previously produced neither a finding nor an unchecked entry when
  unreadable, which is silence indistinguishable from a verified clean result.
- A failed service listing is reported instead of read as a clean host. It
  degraded to zero findings, which is byte-identical to a host with nothing
  wrong; every managed service is now reported as unchecked so a compliance
  report renders ManualReview.
- A plugin that reports its own scan failed is named in the output rather than
  rendering as a plugin with no findings.
- A rewritten configuration file keeps its own permissions. The shared write
  path for every non-kernel configuration file captured the original mode with a
  call that folded a failed `stat` into "the file does not exist", so a stat
  failure left the rewritten file wearing the temporary file's 0600 rather than
  the mode it had before, with no error and no log line. Only a genuinely
  missing file now means there is nothing to restore; any other stat failure
  refuses the write and names the path. **On a host where stat fails but writes
  succeed, hardening now stops where it previously appeared to succeed.** The
  refusal happens before anything is written, so the target is left exactly as
  it was.
- A permissions change that could not be verified is no longer blamed on a vfat
  filesystem. `apply` named a non-POSIX filesystem whenever verification came
  back unsatisfied, including when the verification read itself failed, and scan
  diverts a path positively confirmed to be on a non-POSIX filesystem long
  before apply runs, so the one cause the message named had already been
  excluded by the time it could fire. Three outcomes are now distinct: verified,
  a mode that did not move (reporting the mode observed and the mode wanted),
  and a verification that failed (carrying its error, rather than implying the
  `chmod` did not work).
- A finding covered by a policy exception is labelled rather than hidden, and
  never mistaken for a violation. The compliance reports had this right all
  along: they render a documented deviation as `POLICY EXCEPTION` in place of
  its severity and keep it under the control it belongs to, so a pass resting on
  an exception stays distinguishable from a genuinely clean one. Three other
  places did not. The desktop's Compliance view dropped excepted findings
  outright, so a deviation the operator had recorded was indistinguishable from
  a finding that never existed. The desktop's audit view and the `scan` terminal
  both kept them and labelled nothing, so a documented deviation read as a live
  violation. The rule now lives once, in the crate both front ends share. The
  desktop lists deviations in their own group below the severity groups, where
  they can neither vanish nor inflate a severity count, and the expanded detail
  carries the reason the deviation was accepted. The desktop's All/Compliance
  view switch is gone: hiding them was its only function. The fleet host panel
  gets the same treatment, and it is the reason the split happens where each
  view renders rather than inside the shared severity grouping: that grouping
  also decides whether the fleet panel shows a Findings section at all, so
  filtering there would have made a host whose findings are all excepted read
  as a host with nothing wrong.
- The apply preview shows a setting it is leaving alone because a policy
  exception documents it. This was the same defect one surface further on:
  each plugin's validation reached the exception check and skipped the setting
  outright, so it entered neither the estimated changes nor anything else, and
  a host whose only drift was excepted previewed as "0 change(s) to apply" over
  an empty panel. That is byte-identical to a host needing nothing done, so an
  operator could not see that a deviation was in play, nor notice a stale
  exception still suppressing work they wanted done. Excepted settings are now
  reported separately from the pending changes, in the terminal and in the
  desktop, so they can neither be mistaken for changes nor inflate the count
  the confirm button is named after. Seven sites across six plugins skipped an
  exception this way; all now record it through one shared helper.
- A damaged scan-history record is reported instead of read as a scan that
  covered no plugins. The list of plugins a session covered is stored as JSON
  and was parsed with a fallback to the empty list, so a row that would not
  parse produced the same answer as a scan that genuinely ran nothing, and
  `history show` printed the same empty line either way. Parsing is fallible now
  and the reason is printed. A short list remains perfectly legitimate: a
  session records the plugins the configuration selected, not everything in the
  registry.
- A plugin's own `enabled = false` now stops it running. The key existed in the
  config schema, was validated on load, and was read by nothing: only
  `[global] disabled_plugins` and `[global] enabled_plugins` were ever
  consulted. Anyone who turned a plugin off in its own section has been scanned
  and hardened by it ever since, without a word. `apply` carried a third,
  narrower copy of the rule that consulted only `disabled_plugins`, so it also
  ignored the `[global] enabled_plugins` allow-list that `scan` honoured, and
  the two commands disagreed about which plugins the config selects. All three
  call sites now share one predicate, and disabled anywhere is final: `enabled`
  defaults to `true`, so it can only turn a plugin off, never re-enable one the
  `[global]` lists have refused. **After upgrading, plugins you disabled in
  their own section will disappear from your output.** That is the configuration
  you asked for; if you did not intend it, remove the `enabled = false` line.
- Scheduled scans honour plugin enablement. `PluginManager::execute_scan`, the
  entry point the daemon runs scans through, resolved each plugin's settings
  without ever asking whether the config enabled that plugin, so a daemon
  scanned plugins the operator had turned off. The session row naming which
  plugins a scan covered is written before any plugin runs and was derived from
  dependency order alone, so it is now derived from the same rule the scan
  obeys and can no longer name a plugin that never ran.
- `hardener report` honours the plugin lists. It ran every registered plugin
  regardless of configuration, while `scan` on the same host skipped the
  disabled ones, so the two commands disagreed about which plugins the config
  selects. Controls covered by a disabled plugin now report Manual Review
  rather than being assessed by a plugin the operator turned off.
- Every `batch` subcommand honours the global `-C`, `--config` flag. clap
  accepted it and all four verbs threw it away. `batch scan` and `batch report`
  went further and evaluated every host against the compiled-in defaults, so a
  fleet was assessed against the raw baseline and then hardened to the
  operator's actual policy: directive overrides, policy exceptions and the
  plugin lists applied to `batch apply` but not to the scan that justified it.
  Remote hosts are evaluated against the controller's configuration, matching
  single-host `--ssh`.
- The PAM plugin no longer reports every read failure as needing root. An I/O
  error, or a configuration file that is not valid UTF-8, sent the operator to
  `sudo`, which cannot help with either. Reads are classified with the same
  permission-denied helper the SSH plugin already used, and the wording follows
  the actual cause in the unchecked reason and in both dry-run estimates.
- A privileged operation no longer runs with its audit trail silently absent.
  Resolving the audit log path folded every failure into "no logger" and every
  caller matched on exactly that, so `apply`, `checkpoint` and `batch` could run
  unlogged on a host whose log directory could not be created or opened, and say
  nothing about it. Path resolution now reports the directory it could not use.
  Callers still continue without a logger, deliberately: refusing to harden a
  host because its log directory is unwritable would be the worse failure. The
  operator is told either way.
- The CLI installs a log subscriber. Without one the tracing macros were a
  no-op, so every warning the engine raised was discarded, including warnings
  that have no `Change` counterpart and were the only record that a step
  degraded. Records go to stderr, so `--format json` stays parseable.
- `--format json` output is a single document again. An informational message
  was written to stdout ahead of the payload, so a strict parser rejected the
  whole stream with "Extra data" even though the payload itself was well formed.

### Known Limitations
- **SSH cannot be hardened on openSUSE, and could not be in any earlier release
  either.** That distribution ships `sshd_config` at
  `/usr/etc/ssh/sshd_config`, and every path in this tool is a hardcoded
  constant under `/etc`, so the scan reports that it could not read
  `/etc/ssh/sshd_config` and `apply` fails outright. Nothing is damaged and
  nothing is falsely reported as hardened; the plugin simply does not work
  there. This is disclosed now rather than at the fix because a user running
  the tool on openSUSE should know that a clean SSH section means the check did
  not run, not that the host is secure. Every other distribution is unaffected,
  and the other plugins work on openSUSE.
- Where a drop-in under `/etc/ssh/sshd_config.d/` sets a directive this tool
  manages, on Fedora and RHEL typically `50-redhat.conf`, `apply` reports that
  it cannot make the change and names the file to edit, rather than writing a
  value sshd will ignore. The host is left unhardened for that directive until
  the drop-in is edited by hand. Writing a drop-in that wins is the fix, and it
  is not in this release.

## [1.5.0] - 2026-07-27

### Added
- Desktop Settings page: a visual theme picker (a swatch grid across all
  seven themes, Midnight Teal, Fortress, Sentinel, Command, Guardian,
  Daywatch and High Contrast) applies a theme live on selection, plus an
  About block naming the application, version and build identity.
- Differential test suite (`scripts/test/differential-suite.sh`, run inside a
  container via `run-cross-distro-tests.sh --differential`). It applies
  hardening and then asks each setting's real consumer what is in force,
  `sshd -T` for SSH and `chage -l` on an account created after the apply for
  `/etc/login.defs`, rather than re-reading the file with this tool's own
  parser. Every directive is checked twice: the system holds the target value,
  and `scan` agrees with the system. A value that cannot be determined is a
  failure rather than a skip, including the tool's own "could not check", and
  a pre-apply control proves the checks match real output rather than passing
  by matching nothing. This is the first test in the project that can catch a
  defect where the reader and the writer share one mistake and therefore agree
  with each other, which is how the `/etc/login.defs` fault below survived
  every release since 1.0.0.

### Changed
- `hardener scan` now honours the configuration file. `Plugin::scan` receives
  the plugin's config, so a `directives` entry overrides the target value a
  check is measured against, and a finding matching a valid policy exception is
  annotated with that exception instead of being reported as a plain violation.
  `hardener report` treats an annotated finding as satisfied, so a documented
  deviation no longer fails a compliance control, and the text, HTML, PDF and
  JSON reports still list the finding as evidence labelled `POLICY EXCEPTION`
  so a pass carried by an exception is never presented as a clean pass. An
  exception is honoured only when its `value` matches the value found on the
  system for `[ssh]`, `[kernel]`, `[pam]` and `[permissions]`; one that does
  not match is ignored and the finding stays a live violation. `scan --audit`
  still ignores the config entirely and evaluates the unmodified secure
  baseline. `scan` also names the plugins the config kept it from running, and
  fails instead of reporting an empty scan when the config disables every
  selected plugin. This covers the local scan path only: `batch scan`,
  `batch report` and the desktop's fleet scan still evaluate every host against
  the unmodified baseline, because loading a config per remote host is a
  separate design question.
- Desktop UI redesigned end to end. The flat top navigation bar is gone,
  replaced by a grouped left sidebar (Local: Dashboard, Analysis,
  Hardening; Fleet: Hosts, Fleet Apply, Scheduler; plus a pinned Settings
  area) with a collapsible icon rail for narrow windows. Dashboard now
  shows the security score as a bar; Analysis groups findings by severity;
  Hardening is restyled to match. The former Remote and Fleet screens are
  merged into a single Hosts page (old `/remote` links redirect there
  automatically). Fleet Apply is now a staged Preview/Execute flow with a
  segmented Apply/Roll back control and a sticky summary bar. Scheduler
  moves to a single Save action over schedule presets, with a custom-cron
  option behind an Advanced disclosure. This is a frontend-only change:
  no behaviour, IPC, or backend logic changed.
- Rollback is now reversible. Before restoring a checkpoint, `hardener rollback`
  (CLI, desktop, and fleet) first captures the current state of exactly the
  files it is about to overwrite as a new signed checkpoint, named after the
  checkpoint being restored, so a rollback can itself be undone from History.
  Account databases (`/etc/shadow`, `/etc/gshadow`) are captured metadata-only,
  matching apply-time behaviour, so no password hashes enter the checkpoint
  database. The snapshot is fail-closed: if the current state cannot be
  captured, the rollback is refused and nothing is written, rather than running
  a restore that could not be undone. This closes the asymmetry where apply
  checkpointed before changing but rollback did not.
- A policy exception is now honoured by `apply` and `apply --dry-run` only when
  its `value` matches the value found on the system, which `scan` and
  `hardener report` already required. An exception describing a deviation the
  host does not have no longer stops that setting being hardened, so a host
  carrying a stale exception may see changes it did not see before. For
  `[pam]`'s `deny` and `remember` thresholds, that hardening can itself fail
  rather than apply quietly: if an inline `pam.d` override is present,
  `apply` refuses to auto-edit the authentication stack and marks the run
  unsuccessful instead of editing `faillock.conf` or `pwhistory.conf`
  underneath it. A value that cannot be read never matches, so for `[ssh]`
  and `[kernel]` the setting is hardened rather than silently skipped.
  `[pam]` renders an unreadable directive the same as an absent one, both as
  `"not set"`, so an exception documenting `value = "not set"` still
  matches when the file could not be read; outside that gap, an unreadable
  `[pam]` value is hardened the same way as `[ssh]` and `[kernel]`.
  `[permissions]` treats a missing path, which is left alone, differently
  from one that exists but could not be stat'd: the seven paths with a
  single exact target mode are hardened anyway, chmod'd to their baseline
  with a note that the prior mode was unknown, while the two mask-based
  paths, `/etc/shadow` and `/etc/gshadow`, cannot compute a safe target
  without a verified mode and are skipped instead, now with the skip and a
  warning recorded rather than silent. `[services]`, `[mac]`, `[audit]` and
  `[firewall]` are unaffected: their exception key names the deviating item
  rather than a value.
- SSH `apply --dry-run` now honours the configuration file.
  `SshHardeningPlugin::validate` bound its config parameter as `_config` and
  never read it, so directive overrides and policy exceptions had no effect
  on the SSH preview and it could not agree with what `apply` then did.
- A rollback that meets a protected path recorded as absent, but present on the
  host, reports that file as skipped and the run as unsuccessful rather than
  deleting it. The remaining files in the same checkpoint are still restored.
  This can also happen for an innocent reason: a package installed after the
  checkpoint was taken supplies a file that genuinely was not there before.
- A checkpoint no longer records "no content" for a path passed to it
  directly, whether by a plugin's pre-apply checkpoint or by `hardener
  checkpoint create` (which declares `/etc/ssh/sshd_config` and
  `/etc/audit/auditd.conf` among others). Capture now fails when such a path
  exists and its content cannot be read, rather than storing a row a rollback
  could not restore from. This can fail a checkpoint that used to succeed
  silently: `checkpoint create` against a remote host as a non-root user, for
  one, since a declared file this project's own hardening has locked down to
  root can no longer be read over a plain SSH session. Files found by
  recursing into a declared directory keep the previous best-effort
  behaviour and are logged, so a single unreadable file somewhere under a
  captured directory does not stop an apply.
- `hardener scan` no longer reports a `[pam]` directive as "not set" because
  it could not read the file that holds it. Only a permission denial counted
  as unverifiable before; every other read failure of
  `/etc/security/pwquality.conf`, `faillock.conf` or `pwhistory.conf` (a file
  that is not valid UTF-8, or an I/O error, for instance) was treated as empty
  content, so each directive in it became a finding claiming it was unset.
  Such a file now produces one unchecked check per directive instead, the same
  treatment a root-only file already received. On an affected host the finding
  count falls, the "could not be verified" count rises, and a compliance
  control covered only by those checks reports ManualReview rather than a
  false Fail. A file confirmed to be absent still reports its directives as
  genuinely not set, and `/etc/login.defs` is unaffected: `scan` still reads it
  leniently. `apply --dry-run` follows the same rule, listing the directive as
  "current value requires root" instead of "currently not set".
- Which line `apply` rewrites in a configuration file has changed. Within the
  part of a file that sets a host's global policy, a live definition is now
  always the line it targets. `/etc/ssh/sshd_config` ships its defaults
  commented out, and wherever a commented directive preceded the live one, the
  comment was the line that got rewritten, leaving the live directive
  untouched below it and the file carrying two live definitions of the same
  directive. That global part ends at the first live `Match` line, since every
  directive below one applies only to the connections its block matches; see
  the related entry under Fixed. In `/etc/security/pwquality.conf`, `/etc/login.defs`,
  `/etc/security/faillock.conf` and `/etc/security/pwhistory.conf`, a
  commented directive is now activated where it sits when the file holds no
  live definition of it, rather than a new line being appended at the end of
  the file; and when `apply` rewrites one of these four, a second live
  definition of the same key is dropped, since each takes one definition per
  key and a second is stale. `sshd_config` keeps every definition it has,
  because a repeated directive there is scoped by the `Match` block it sits
  in and dropping one would change which connections a rule applies to.

### Fixed
- Rollback could delete the files it was meant to protect. Over SSH,
  `file_metadata` ran `stat ... || echo 'NOTFOUND'`, so a host whose `stat`
  output this tool cannot parse reported every path as missing. Checkpoint
  capture records a missing path with permissions `0`, and rollback removes any
  path recorded that way, so `apply` followed by `rollback` on such a host
  deleted `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` and
  `/etc/sudoers`. The probe now confirms absence with `test -e` and reports a
  path it cannot read as an error, which capture propagates, so the operation
  stops instead of recording a file as absent. Hosts with a working `stat` are
  unaffected.
- Rollback now refuses to delete a protected system path that a checkpoint
  records as absent while the file is present on the host. Fixing the probe
  stops new checkpoints recording a false absence, but does not rewrite rows
  already stored, so a checkpoint taken before this release can still carry one.
  Deleting any of these paths is never a correct restore, because an apply never
  creates them. A path that is genuinely still absent is a silent no-op, so
  hosts legitimately lacking an optional file are unaffected.
- `SshExecutor::path_exists` reported a path as absent whenever its probe
  returned anything other than `yes`, so unexpected output from a remote shell
  read as a missing file. It now reports output it cannot interpret as an error.
- The PAM plugin could replace a configuration file with one containing only
  its own directives. Every read on the apply path turned a failure into an
  empty string, so a file that existed but could not be read was merged into
  nothing and written back, discarding the host's settings. Neither recovery
  path worked: `create_config_backup` checked only that `cp` started, not that
  it succeeded, so a failed backup was reported as created; and checkpoint
  capture stored an unreadable file with no content, which rollback restores as
  permissions only. `apply` now stops before writing anything: the pre-apply
  checkpoint refuses to record a declared file whose contents it could not
  read, which aborts the apply for the whole plugin, and this is what every
  `hardener` command that applies now does. The plugin also refuses on its own,
  per file, reporting that one file as failed and hardening the rest, which is
  what protects an embedding of the plugin crate that applies with no
  checkpoint manager configured. A `cp` that exits non-zero is reported as a
  failed backup rather than as a created one. This covers `pwquality.conf`,
  `login.defs`, `faillock.conf` and `pwhistory.conf`.
- Password ageing was never applied, and was then reported as compliant.
  `/etc/login.defs` takes `NAME VALUE`, but every release since v1.0.0 wrote
  `NAME = VALUE`, a syntax the file does not accept. The directive matcher
  trimmed a line before testing whether the name was followed by whitespace,
  so that test was false for every possible input: the live line was never
  recognised and a new one was appended instead. The reader had the same
  fault, so a later scan skipped the live line, found the tool's own appended
  line, and reported `PASS_MAX_DAYS`, `PASS_MIN_DAYS` and `PASS_WARN_AGE`
  compliant on the strength of a line the tool had written itself, in a syntax
  `login.defs(5)` does not define, while the file's own syntax was left saying
  exactly what it said before the apply. Both now recognise a whitespace
  separated directive, `apply` writes the syntax the file accepts and rewrites
  the line that is in force rather than a comment that names it, and the line
  an earlier release appended is removed even where the live value already
  matches the target and there is nothing else about the file to change. A host
  hardened by an earlier release will report a violation it previously reported
  as a pass; running `apply` repairs the file and the report together. A
  definition that already holds the target value but is written in another form
  the reader accepts, such as a tab separator in `login.defs` or a bare space
  in `pwquality.conf`, is rewritten once into the form `apply` writes for that
  file and converges there; only that line's separator changes, so the first
  run after this release can report a change that hardens nothing.
- `scan` and `apply` now recognise a directive written as `Key=Value`. The
  writer took a directive's name to end at whitespace, so `PermitRootLogin=yes`
  in `/etc/ssh/sshd_config` and `deny=10` in `/etc/security/faillock.conf`
  matched nothing, though `ssh_config(5)` and the `security/*.conf` files all
  accept that syntax and `sshd -t` passes it: `apply` left the operator's line
  where it stood and defined the key a second time elsewhere in the file, so
  the file carried two definitions of the same directive, never converged
  however often `apply` ran, and the tool could report a value the host does
  not enforce. Reading was blind to the same syntax only where a file is read
  as space separated, which is `/etc/ssh/sshd_config` alone, so `scan` reported
  an `=` separated directive there as not set; `faillock.conf` and
  `pwhistory.conf` are read as key-value, which already accepted `deny=10`. A
  name now ends at whitespace or at `=`, whichever comes first, for both
  reading and writing. On a host whose `sshd_config` carries such a directive
  the reported value changes from "not set" to the value the file holds, which
  can turn a finding into a pass or the reverse, and the first `apply` after
  this release rewrites that line rather than adding to it. An exception for
  such a directive written as
  `value = "not set"` stops matching, since the directive was never unset.
- `apply` could scope a global SSH setting to a single `Match` block. A
  directive `/etc/ssh/sshd_config` did not mention at all was appended to the
  end of the file, and because `sshd_config(5)` puts `Match` blocks last, that
  is inside the final block on any host that has one. The setting then applied
  only to the users, groups or addresses that block matches, while the rest of
  the host kept sshd's compiled default. `apply` now treats the first live
  `Match` line as the end of the file's global section: it never rewrites a
  directive below one, and inserts a new directive above the block instead of
  at the end of the file. On such a host the damage was usually larger than one
  mis-scoped directive: `sshd_config(5)` permits neither `KexAlgorithms`,
  `Ciphers` nor `MACs` inside a `Match` block, so once one of those was the
  directive being appended, the `sshd -t` validation added in v1.2.0 rejected
  the candidate file and the apply aborted having written nothing at all. On a
  host whose `sshd_config` ends with a live `Match` block and does not already
  name those three above it, no release since v1.2.0 has hardened any SSH
  directive; `apply` reported the failure each time. Hosts with a `Match` block
  that were hardened by an earlier release should be checked for a hardening
  directive sitting inside it, which `apply` cannot move on its own.

## [1.4.0] - 2026-07-19

### Added
- `hardener scan` (CLI and desktop) now distinguishes checks it could not
  verify at the current privilege level from checks that ran and found
  nothing wrong. Plugins can report `UncheckedCheck` entries (new shared
  `hardener-types` type, `ScanResult.scan_unchecked`, additive) alongside
  findings; text output dims a per-plugin "N check(s) could not be
  verified without root" list with the reason for each, plus a closing
  "N check(s) require root; run with sudo for a full scan" hint, and
  `--format json` carries a per-plugin `unchecked` array beside
  `findings`. `report`, the report wizard and the desktop Fleet view's
  posture scoring all thread unchecked checks into compliance scoring: a
  control covered only by an unchecked check now reports ManualReview
  instead of a false Pass (a real Fail against the same control still
  wins). `batch report` now carries unchecked data per host too, so an
  unprivileged remote fleet assessment gets the same honest ManualReview
  treatment as a local one.
  Scan history persists unchecked checks (a new `unchecked_json`
  column, added by an idempotent in-place migration; existing rows
  round-trip with an empty list) so restored and exported sessions keep
  the distinction.
- Desktop "deep scan": a new `run_deep_scan` command (pkexec, the same
  privileged-op guard and rate limit as apply) re-runs `hardener scan
  --format json` as root and replaces the current results, matching
  what `sudo hardener scan` would report; results persist as a new scan
  session, so restarting the app keeps the privileged results. An
  unchecked-checks banner above the Dashboard and Analysis pages names
  the outstanding count and offers a "Run deep scan" button that also
  regenerates compliance reports; because report generation reads the
  persisted scan session (see Changed below), the regenerated report
  reflects the deep scan's privileged results and the score moves
  accordingly. The findings tab lists the unverifiable checks
  (deduplicated by check id,
  since the audit plugin emits one entry per underlying rule) under a
  "Not verifiable without privileges" heading, and the score gauge
  shows a muted "N check(s) not verified (needs privileges)" note. All
  of this presentation is muted-only, never severity-coloured.
- `hardener checkpoint list` accepts `--limit <N>` (default 20, newest
  first) and `--all`, and prints a "showing N of M; use --all to see all"
  footer when the list is capped, so a long-lived host no longer dumps
  every checkpoint at once. The limit applies to `--format json` too, so
  scripted output matches the table; pass `--all` for the full set.

### Changed
- Dry-run and apply are now state-aware for the kernel and PAM plugins, so
  scan, dry-run and apply tell one coherent story: settings already at their
  target are reported as such (tallied separately in dry-run and never
  listed among pending changes, Skipped "already set"/"already compliant"
  entries in apply) instead of being re-applied on every run. Kernel apply
  writes only drifted
  sysctls and rewrites `/etc/sysctl.d/99-hardener.conf` only when a
  parameter changed or the file's content no longer matches; PAM rewrites
  `pwquality.conf`/`login.defs` only when at least one directive actually
  differs, and creates a backup only when a file will be rewritten (no more
  backup churn in /etc on already-compliant hosts). Already-compliant and
  policy-exception entries are typed `Skipped` and the pre-apply rollback
  checkpoint is typed `Checkpoint`, so "N change(s) applied" counts real
  hardening work only. The no-loosen threshold semantics for
  faillock/pwhistory are unchanged.
- Batch text output (`batch scan`/`report`/`apply`/`rollback`) now groups
  results in per-host sections instead of one compact table: each host
  gets a coloured header rule naming the inventory name, full
  `user@host:port` target (and, for `batch report`, the compliance
  profile), followed by short labelled status/detail lines (green ok,
  yellow partial or pending, red FAILED; severity counts reuse the scan
  palette), so an admin hardening several hosts can see at a glance
  which output belongs to which machine. Scan sections list the
  unchecked-check count when non-zero, and every verb keeps (apply and
  rollback: gains) a fleet summary footer after the sections. Colour
  degrades automatically on pipes and `NO_COLOR`, and files written via
  `--output` are always colour-free; `--format json` output is
  byte-identical and exit codes are unchanged.
- Desktop compliance reports (and the security score derived from them)
  now source findings and unchecked checks from the latest persisted
  completed scan session instead of always re-running a fresh
  unprivileged in-process scan. A privileged deep scan's results,
  including root-only checks, therefore flow into the compliance report
  and move the score: controls previously stuck at ManualReview for
  lack of privileges resolve to Pass or Fail once verified. Export uses
  the same sourcing, so an exported report matches the one on screen.
  With no completed session yet (fresh install, compliance tab opened
  before any scan) or an unreadable history database, report generation
  falls back to the previous fresh in-process scan; both paths stay
  unprivileged and never prompt. This also removes the double
  in-process scan the GUI previously paid on every report regeneration.

### Fixed
- Ad-hoc SSH targets with invalid hostname characters are now rejected at
  entry. A mistyped `user@host, note:port` previously parsed the hostname as
  everything between `@` and the last `:` (e.g. `10.242.117.2, scan`) and
  failed confusingly at connect time; the ad-hoc input and the Tauri backend
  now share one conservative hostname check (ASCII letters/digits, `.`, `-`,
  plus `:` `[` `]` for IPv6 literals), so bad input fails immediately whilst
  every valid host, IPv6 included, is still accepted.
- SSH connection failures now report the underlying reason instead of a bare
  "Failed to connect to <host>". The real ssh cause (connection refused,
  timeout, name resolution, permission denied, and so on) is folded into the
  error message so batch and the Fleet view both show it; when the failure is
  an authentication or agent problem an actionable ssh-agent/key hint is
  appended, and a genuine network failure never gets that hint.
- The firewall dry-run preview no longer falsely reports "Enable ufw
  firewall" when the active ruleset cannot be verified without root. The
  validator now shares the scan's backend-activity classification
  (Verified / unit-active-but-unverifiable / Unknown / positively
  inactive) and selects the same winning backend the apply drives, so
  preview and apply can never disagree: a verified-active firewall reports
  only its baseline rule estimate, a genuinely disabled firewall keeps the
  honest "Enable X firewall" line, and an unverifiable ruleset (e.g.
  nftables loaded in-kernel but root-only on a hardened host) reports
  "Firewall ruleset could not be verified without root - run with sudo (or
  a deep scan) for an accurate preview" instead of a guess.
- The desktop "Preview Changes" dry-run now marks plugins the last deep
  scan verified fully compliant as "0 changes - Verified compliant by last
  deep scan" instead of listing conditional estimates the real apply
  would skip. A plugin is suppressed only when the latest persisted scan
  holds a matching, successful result with zero findings and zero
  unchecked checks (only a privileged/deep scan clears the root-only
  unchecked list); any uncertainty - no matching result, a failed scan, or
  any finding or unchecked entry - shows the estimate as before. The
  annotation is display-only and never alters what apply does; the
  privileged apply re-checks everything and stays authoritative.
- The permissions plugin no longer reports a false finding or attempts a
  futile chmod for directories on filesystems that cannot hold POSIX
  permissions (e.g. a vfat `/boot` ESP, where chmod exits 0 but the mode
  is fixed by the mount's fmask/dmask); it reports the situation with
  fstab mount-option guidance instead. Scan, apply and validate share one
  probe-driven filesystem gate (`findmnt`, falling back to `stat -f`):
  scan emits an `UncheckedCheck` in place of the finding, apply records a
  `Skipped` change with the guidance, and validate omits the path from
  pending changes. The gate is fail-safe: a finding or chmod is only
  suppressed when a non-POSIX filesystem is positively confirmed, so any
  probe failure or unrecognised filesystem falls back to today's
  behaviour and a real permissions gap is never hidden.
- Creating a rollback checkpoint before applying no longer counts as an
  applied hardening change. The checkpoint entry is typed `Checkpoint` (a
  new `ChangeType`) and excluded from both the applied and the failed
  counts, so a plugin whose only action was the checkpoint now reads "no
  changes needed" with the checkpoint listed beneath it, instead of the
  misleading "1 change(s) applied". The CLI, batch and desktop apply
  summaries all inherit the corrected count.
- A fully compliant host no longer reports phantom pending changes in
  dry-run. The kernel and PAM validators carry a structured
  `validation_report_compliant_count` instead of appending an "N already
  compliant" line to the estimated changes, so the pending count reflects
  only genuine changes: the CLI shows "0 change(s) to apply (18 already
  compliant)", and batch and the desktop fleet view append "(N already
  compliant)" beside a true "0 change(s) pending"/"0 would change" rather
  than counting the summary line as an item to apply.
- The compliance report wizard's summary no longer shows scores an order of
  magnitude too small: colouring the score string before applying `{:.1}`
  in the `println!` template truncated the coloured string to one
  character wide instead of formatting the number (75.0% rendered as
  "7%"). The number is now formatted first and the finished string
  coloured afterwards.
- The compliance report wizard's output path prompt now expands a leading
  `~` or `~/` to the user's home directory and treats an existing
  directory (or input ending in `/`) as a destination folder, joining a
  default `compliance-report` filename, instead of saving a literal file
  named `~.txt` in the current directory.
- "N change(s) applied" no longer counts failed changes: the shared
  `ApplyResult` count helpers now treat only successful non-skipped
  changes as applied, with failures counted separately, so a partial
  apply reads "1 of 5 change(s) applied, 4 failed" in the CLI and the
  desktop summaries name failed changes instead of folding them into
  the applied or skipped totals.
- Privilege-blocked ("unchecked") checks in CLI scan output are now
  labelled with their own plugin's header instead of rendering an
  anonymous block that visually attached to the previous plugin, and
  duplicate entries sharing an `unchecked_check_id` collapse to a
  single line with an `(xN)` multiplier (matching the GUI), so an
  unprivileged audit scan shows 7 labelled lines instead of 25
  repeating ones while headers keep the honest raw count.
- Applying SSH hardening over a remote root session no longer locks the
  session out of the target host: when the apply itself runs as root
  through `--ssh`, `PermitRootLogin` is downgraded from `no` to
  `prohibit-password` (password root login stays blocked, key-based
  access survives the sshd restart) with an honest change description
  naming the downgrade. An existing `no` is never loosened, and a value
  already at `prohibit-password` (or stricter, e.g.
  `forced-commands-only`) is reported as a skipped change instead of
  being overwritten. Local applies still write the strict `no`, the
  scan recommendation stays `no` so a rescan reports the residual gap,
  and setting `no` remains a deliberate console step.
- `apply`, `checkpoint create` and `rollback` no longer demand LOCAL root
  when targeting a remote host with `--ssh`: the three commands checked
  the euid of the CLI's own process, so a remote root session was
  rejected with "Root privileges required" even though it was fully
  capable of doing the work through the executor. Privilege is now
  probed on the target session (`id -u`, falling back to `sudo -n
  true`), matching the check `batch apply`/`batch rollback` already
  used; the apply error message now also mentions connecting as root
  with `--ssh`.
- The desktop security score is restored on launch: the app now
  regenerates compliance reports from the last persisted scan session
  when it loads saved results, instead of showing "--" until a new scan
  is run.
- ConfigFormat::Auto now tries KeyValue format before SpaceSeparated
  when parsing config files, fixing a bug where directives with spaces
  around the `=` (e.g. `max_retries = 3` in `/etc/security/pwquality.conf`)
  were parsed with the current value as a literal `=` symbol, causing
  secure settings to appear insecure when scanned as root.
- firewall scan now checks all installed backends in a single pass
  instead of stopping after the first inaccessible probe, fixing a false
  `Firewall disabled` finding when the selected backend was inactive but
  another backend was permission-blocked and unknowable; unverifiable
  backends now report as unchecked instead of a red finding.
- pam, firewall, audit, ssh and mac no longer report false findings
  when scanned without root on a hardened host. Each previously treated
  a permission-denied read of a privilege-gated source as "value not
  set" or "feature absent" and raised a High/Critical finding for
  something it never actually inspected; each now classifies the
  permission failure and reports the affected checks as unchecked
  instead of a finding:
  - pam: `/etc/security/pwquality.conf` and the faillock/pwhistory
    threshold configs are root-only on a hardened host; a denied read
    no longer produces a "not set" finding per directive.
  - firewall: probing the live ruleset (nftables/ufw/firewalld) needs
    root; a denied probe now falls back to a root-free `systemctl
    is-active <unit>` hint for backend selection and reports the
    ruleset itself unchecked instead of "disabled".
  - audit: `auditctl -l` needs root to list loaded rules; a denied
    listing now reports one unchecked entry per expected rule instead
    of treating every rule as missing.
  - ssh: `/etc/ssh/sshd_config` is root-only on a hardened host; a
    denied read now reports every directive and crypto setting
    unchecked instead of "not configured".
  - mac: `aa-status --verbose` needs root; a permission-denied probe
    with AppArmor actually installed now reports enforcement unchecked
    instead of "no profiles enforced".

  kernel, services and permissions were audited for the same failure
  mode and need no change: kernel reads `/proc/sys/*`, world-readable
  on stock Linux (a scan error there means the sysctl does not exist,
  not that it is unreadable); the services scan issues two batched
  listings, `systemctl list-unit-files` and `systemctl list-units`,
  both unprivileged queries; permissions only needs directory traversal
  for `stat`, and `/etc/shadow` metadata (not content) reads fine
  unprivileged.
- Dark-theme select dropdowns rendered unreadable popup lists on the
  Schedule page, Notifications page and Compliance export control: the
  `<option>` entries fell back to the browser's native white popup with
  pale text because only `.theme-select` (theme toggle) and
  `.severity-filter select` (findings filter) carried the appearance
  reset, custom arrow and forced option colours needed for a themed
  popup. `.form-select` and `.format-select` are now part of the same
  shared rule group, so every select in the app (theme toggle, findings
  severity filter, schedule, notifications, compliance export) gets
  matching hover, focus and daywatch light-theme treatment from one
  definition instead of a partial or missing copy. As a side effect,
  `.format-select` also picks up a real border and focus colour again;
  it previously referenced two custom properties (`--border-default`,
  `--accent-primary`) that are not defined anywhere in the stylesheet,
  so its border and focus outline were silently dropped.
- `hardener batch report` now threads each host's unchecked checks
  through to the compliance generator instead of discarding them: a
  covered control whose only evidence is an unchecked check (root-only
  read, unprivileged remote scan) reports ManualReview, matching what a
  local `report` run already did, instead of a false Pass. The report
  wizard's closing summary now prints a "N check(s) could not be
  evaluated without root privileges" hint when the scan left any checks
  unverified.
- aborted scans (e.g. cancelled authentication) no longer leave running
  session rows in scan history.
- dismissing the polkit authentication prompt during a deep scan or an
  apply no longer shows a red error toast; cancellation is treated as a
  non-error and only resets the in-progress UI state.
- the "Run deep scan" button now shares one running flag across the
  Dashboard and Analysis pages, so both disable together for the
  duration of a single deep scan instead of only the page that
  triggered it.
- a failed compliance-report refresh after a successful deep scan is
  now surfaced as an error message instead of only a console warning,
  so the user knows the displayed score may be stale until the next
  scan.
- the desktop rate-limit notice now clears itself once its cooldown
  elapses instead of lingering as a red error banner demanding manual
  dismissal: the privileged-op cooldown is a transient wait, not a
  genuine failure, so the shared error banner parses the wait time out
  of the backend message and arms a timer for that wait plus five
  seconds, clearing the message when it fires - but only while the
  banner still holds the exact message the timer was armed for, so a
  later, unrelated error reusing the same banner is never wiped by a
  stale timer.
- firewall apply is now idempotent on nftables hosts: `nft add rule`
  always appends a fresh handle, so re-running apply previously stacked
  a duplicate of every baseline rule each time. Apply now ensures the
  managed `inet filter` table and `input` chain first (idempotent
  `nft add table`/`add chain`, fixing an ENOENT when a foreign
  `hook input` chain made the scan-time heuristic skip `enable()`), then
  reads the live chain and only adds rules whose canonical form is
  absent, reporting the rest as skipped. Matching is tolerant of nft's
  output formatting (quoted interface names, comma-joined state lists)
  and fails closed, re-adding a rule it cannot match rather than leaving
  a gap. ufw and firewalld already dedupe rule adds natively and were
  left unchanged.
- SSH apply no longer rewrites `sshd_config` or restarts sshd when
  nothing changed: the plugin now compares the hardened config against
  what it read and, when byte-identical, skips the backup, the write and
  the restart entirely (reporting a single skipped change) rather than
  restarting the very daemon that can drop the admin's own session for
  no reason. A remote-root PermitRootLogin guard-skip with no other
  drift is now a full no-op too. A drifting config still backs up,
  validates with `sshd -t`, writes and restarts exactly as before.
- Audit apply is now idempotent: it compares the rules file it would
  write against the current `/etc/audit/rules.d/hardening.rules` and,
  when byte-identical, skips the backup, the rewrite and the daemon
  reload entirely (reporting a single skipped change) instead of
  rewriting the file, churning a fresh timestamped backup and reloading
  auditd on every run. A drifting or absent file still backs up, writes
  and reloads with the same "Rule exists" flush-and-retry semantics as
  before; a failed read of the current file fails safe toward rewriting.
- Every plugin's deliberate no-op skips now carry `ChangeType::Skipped`
  uniformly: the SSH crypto and directive exception skips, the firewall,
  services and permissions policy exceptions, the SELinux "already
  enforcing" path and the audit category exception join the kernel and
  PAM skips in leaving the "N change(s) applied" count, so a fully
  compliant host reports zero applied changes across all eight plugins.

## [1.3.2] - 2026-07-18

### Fixed
- Local sysctl apply no longer fails on every runtime write: `LocalExecutor`
  wrote all files through a temp-file-plus-rename, but `/proc` and `/sys`
  reject file creation and cannot be renamed onto, so every live
  `/proc/sys/...` write failed outright. Kernel-interface paths now write
  directly (already atomic as a single syscall); persistent config paths
  such as `/etc/sysctl.d` keep the atomic-rename path unchanged.
- The dashboard's recent-activity card now appends ", N skipped" to its
  apply summary when skips occurred, matching the history section's
  wording; previously it showed only the applied-change count.
- Firewall backend selection now prefers the ACTIVE backend over the
  first one merely installed: on a host with ufw installed but disabled
  and nftables actually running the firewall (a common Arch setup),
  hardening previously drove the inactive ufw and left nftables
  untouched. Backends are now probed in the existing priority order
  (firewalld, ufw, nftables) and the first one reporting itself enabled
  wins; if none are active, selection falls back to the prior
  installed-order behaviour. The nftables activity check itself was
  tightened to require an actual input-hook chain in the ruleset rather
  than a bare `table`, since Docker, libvirt, and iptables-nft create
  their own nftables tables (NAT/routing, not filtering) that must not
  be mistaken for an intentional firewall.
- ufw rule mapping no longer sends two baseline rules through the wrong
  syntax: "allow established and related connections" is not a ufw rule
  at all (ufw tracks connection state implicitly) and is now recorded as
  a no-op instead of running `ufw allow` with no criteria, which ufw
  rejected as invalid syntax; "drop all other inbound by default" now
  runs ufw's real default-policy command, `ufw default deny incoming`,
  instead of the invalid `ufw deny` with no criteria.
- Applying audit rules no longer fails outright when the kernel audit
  configuration is immutable (`-e 2`, locked until reboot): both reload
  legs (`augenrules --load` and the `systemctl restart auditd` fallback)
  are expected to fail in that state, and on Arch the fallback is always
  refused anyway (the auditd unit ships `RefuseManualStop=yes`). The
  plugin now probes `auditctl -s` after a reload failure; if it reports
  the immutable state, the rules file is recorded as written with a
  reboot required to load it (a skipped change, not a failure) instead of
  failing the whole apply. A genuinely broken reload (immutability probe
  says otherwise) still fails as before.
- Applying audit rules a second time on the same host no longer fails at
  reload. `augenrules --load` merges `/etc/audit/rules.d/*.rules` but
  never clears kernel-resident rules from a prior load, so nothing in a
  standard setup ever ran the `-D` delete-all first; the second and every
  later apply collided with the still-loaded rules and augenrules
  refused with "Rule exists". When (and only when) the load fails with
  that duplicate collision, the reload now flushes the kernel rule set
  with a best-effort `auditctl -D` and retries the load once. A load
  failing for any other reason performs no flush, so the previously
  loaded rules keep running, and the healthy first-apply path never
  flushes at all. If the retried load still fails after a flush, the
  reported error discloses that audit rules may currently be unloaded
  and names the manual reload (`auditctl -R /etc/audit/audit.rules` or
  reboot); without a flush it states the previous rules are still
  active.
- A partial-failure apply no longer hides which plugins failed and why.
  The desktop app discarded the CLI's per-plugin JSON whenever `apply` or
  `rollback` exited 1 (both print their result before failing on a
  partial failure), so the GUI could only show the generic "One or more
  plugins failed to apply" banner; it now parses that payload on exit 1
  the same way Fleet Apply already did, so failed plugins render with
  their real per-change status. `apply --dry-run` had the identical gap
  and is fixed the same way. The CLI's human-readable table also printed
  a bare cross mark for a failed change with no indication why; it now
  prints the change's error message, indented and dimmed, underneath.
- The findings tab's "Min severity" and "View" dropdowns rendered
  legibly when closed but showed native white option lists with pale
  text once opened, because a themed `<select>`'s colour and background
  are not automatically inherited by its `<option>` entries. They now
  force option background and text colour explicitly, get a themed
  custom arrow in place of the native one, and pick up the same
  hover/focus treatment already used for the colour-theme picker.

## [1.3.1] - 2026-07-18

### Fixed
- The build identity no longer picks up an unrelated git repository: a
  tarball extracted inside a foreign checkout (such as yay's AUR package
  clone) stamped that repository's commit into `--version` instead of the
  `release` marker. The build script now only trusts a git toplevel that
  contains `scripts/build_identity.rs` itself.
- The PKGBUILD now pins `CARGO_TARGET_DIR` inside the build root, so a
  user-level cargo configuration with a global `[build] target-dir` no
  longer relocates the artifacts that `package()` installs from relative
  `target/` paths (published to AUR as 1.3.0-2).

## [1.3.0] - 2026-07-18

### Fixed
- The container test suite now aborts its pre-flight when the hardener
  binary cannot execute (for example a glibc version mismatch between the
  build host and the container), printing the loader error instead of
  reporting a passing version check and then failing every test.
- Applying hardening no longer fails on hosts without a MAC system: the
  mac-hardening plugin treated an absent SELinux/AppArmor as a plugin
  failure, which aborted every all-plugin apply (CLI and desktop) with
  "One or more plugins failed to apply". An absent MAC system is now
  recorded as a successful no-op skip, matching the scan finding and the
  dry-run preview.
- The Analysis run-scan handler and the global scan shortcut auto-generated
  compliance reports for only six frameworks, omitting ISO 27001, SOC 2,
  NIST 800-171 and FedRAMP. All framework lists (including the report
  picker) now derive from a single `ComplianceFramework::ALL` source, with
  a test locking every canonical id to the CLI and desktop parsers.
- The no-MAC-system no-op apply was recorded as a fabricated `ConfigFile`
  change, so a host without SELinux or AppArmor read as "1 change(s)
  applied" in the CLI and "1 changes made" on the desktop; the audit log
  continues to record the apply action itself. A new `ChangeType::Skipped`
  variant (matching the existing `ControlStatus::NotApplicable` and
  `FileRestoreAction::Skipped` idioms) marks no-op changes distinctly; the
  CLI and desktop renderers now count only real changes towards "N
  change(s) applied" and list skips separately. Applies to the
  no-MAC-system skip and the SELinux/AppArmor policy-exception skips alike.
- The AppArmor advisory that apply emits when AppArmor is present with no policy
  exception ("AppArmor detected - use aa-enforce...") also inflated the
  applied-change count despite touching nothing on the host; it now reports
  as a skip, consistent with the no-MAC-system fix above.
- The services plugin's existence probe called
  `systemctl list-unit-files <name>` without the `.service` suffix, which
  `list-unit-files` does not mangle the way `is-enabled`/`is-active` do: the
  pattern matched nothing, so every service looked absent and the plugin
  scanned, validated and applied as a silent no-op. The batched scan listings
  and the suffixed per-service probe now detect enabled services again
  (enabled Avahi/CUPS correctly fail CIS 2.2.3/2.2.4 instead of
  false-passing).
- The ssh plugin's three STIG crypto mappings carried V-IDs that name
  unrelated rules in the real RHEL 8 STIG (V-230290/1/2 are known-hosts
  authentication, Kerberos and separate-/var). Ciphers and MACs now carry
  their true V2R7 identifiers (`RHEL-08-010291`/V-230252 and
  `RHEL-08-010290`/V-230251, both CAT I), and the KexAlgorithms check no
  longer claims a STIG control at all: its rule was removed from the RHEL 8
  STIG in V2R6 and none exists in the RHEL 10 STIG.
- The SSH executor's remote `write_file` no longer appends a spurious
  trailing newline to newline-terminated content, so files written over
  `--ssh` (apply, checkpoint restore) round-trip byte-exact instead of
  growing by one newline per write. Caught by the new live-sshd
  integration tests.
- Scan-history findings are now persisted with the official display strings
  for severity and category (`CRITICAL`, `File System`) instead of Rust
  variant names (`Critical`, `FileSystem`). Existing rows are unaffected:
  severity counting is case-insensitive and the stored category string is
  never parsed back.
- A corrupted policy-exception entry in the desktop scan-history database now
  surfaces as a database error instead of being silently read back as "no
  exception". A stored exception suppresses findings, so an unreadable one
  must not vanish quietly.

### Added
- Build identity in version output: `hardener --version` and a quiet chip
  beside the desktop wordmark now show the git short SHA and build date
  alongside the semantic version, so a stale installed build is visible at
  a glance. Tarball builds without git report `release`;
  `SOURCE_DATE_EPOCH` is honoured for reproducible packaged builds.
- FedRAMP compliance framework: `report --framework fedramp` (CLI and desktop,
  including the fleet posture set, `--scenario all` and
  `--scenario government`) assesses against the FedRAMP Moderate baseline
  (Rev 5). FedRAMP's control set is NIST 800-53 at a baseline, so no new ids
  are invented: every mapping mirrors a plugin's existing 800-53 entry
  verbatim, filtered to membership in the official GSA rev5 Moderate baseline
  (version 5.1.1+fedramp-20240111-0, 323 controls). All 18 base controls the
  plugins cite are baseline members (including SC-5, SI-11 and SI-16, which
  800-171r3 tailors out), giving 19 distinct printed control ids across six
  800-53 families. Like SOC 2 and 800-171, the catalogue is derived from live
  plugin coverage, so every reported control is genuinely assessed.
- NIST SP 800-171 compliance framework: `report --framework 800-171` (CLI and
  desktop, including the fleet posture set, `--scenario all` and
  `--scenario government`) assesses against SP 800-171 Revision 3 (May 2024),
  the protection standard for Controlled Unclassified Information in
  nonfederal systems. Every requirement id is crosswalked from the plugins'
  existing 800-53 control entries via the official r3 source-control table:
  14 distinct requirements across six families (access control, audit,
  configuration management, identification & authentication, communications
  protection, system integrity). Controls that 800-171r3 tailors out as not
  CUI-related (SC-5, SI-11, SI-16) map nothing: the report never over-claims.
  Like SOC 2, the catalogue is derived from live plugin coverage, so every
  reported requirement is genuinely assessed.
- SOC 2 compliance framework: `report --framework soc2` (CLI and desktop,
  including the fleet posture set and `--scenario all`) assesses against the
  AICPA 2017 Trust Services Criteria (with the 2022 points of focus). All
  eight plugins map their checks onto five common criteria, CC6.1 (logical
  access), CC6.6 (boundary protection), CC6.8 (unauthorised software), CC7.1
  (configuration-change detection) and CC7.2 (anomaly monitoring), each
  mapping mirroring the check's existing sourced NIST/CIS intent. SOC 2 has no
  curated catalogue: its control list is derived from live plugin coverage, so
  every reported criterion is genuinely assessed (Pass/Fail, never a false
  pass). The desktop compliance tab also gains the previously missing
  ISO 27001 checkbox.
- RHEL 10 compliance profiles: `report` and `batch report` render DISA RHEL 10
  STIG V1R1 and CIS RHEL 10 Benchmark v1.0.1 control identifiers on
  RHEL-10-family hosts (RHEL/Rocky/Alma 10). Profiles resolve automatically
  from the scanned system's `/etc/os-release` (per host in batch, through the
  scan executor for `--ssh` targets) and are overridable with
  `--profile <generic|rhel10>`. Translation happens at report time from
  sourced tables (official DISA V1R1 XCCDF; ComplianceAsCode's `cis_rhel10.yml`
  v1.0.1 encoding): canonical controls without a sourced counterpart are
  omitted from the profiled report rather than guessed, and generic STIG
  headings now name their RHEL 8 baseline honestly. Desktop report and fleet
  posture resolve the same way.
- Per-host scan history in the desktop fleet view: expanding a host row now
  shows its persisted sessions (from the scheduler database that `batch scan`
  and scheduled scans write) with severity counts and a better/worse/same
  trend per scan. Ad-hoc targets are stored in their canonical
  `user@host:port` form so the GUI's display names match the CLI's history
  keys.
- Live per-host progress during desktop fleet scans: the Fleet page now
  shows each host as pending/finished/failed with an n-of-total counter
  while the scan runs, driven by a `fleet-progress` Tauri event emitted as
  each host completes. Progress is best-effort and purely cosmetic: the
  scan's outcome remains the awaited command result.
- Ad-hoc SSH targets in the desktop fleet pages: both **Fleet** (scan) and
  **Fleet Apply** (apply/rollback) now accept `user@host[:port]` targets that
  are not saved in the inventory, matching the CLI's `--ssh` flag. The
  target parser is shared between CLI and GUI (one definition in
  `hardener-types`), and the Fleet Apply dry-run gate treats a changed
  ad-hoc set as a new selection.
- End-to-end integration tests for `batch scan/report/apply/rollback` against
  a live sshd (`#[ignore]`, `SSH_TEST_HOST` convention), closing the gap where
  a *successful* SSH connection was never exercised by the suite, plus a
  `boot-ssh-test-container.sh` fixture that boots a test container with
  networking and an authorised test key.
- Docker image for containerised read-only auditing
  (`packaging/docker/Dockerfile`, built from the repository root): a
  `FROM scratch` image carrying only the static musl `hardener` binary. `scan`
  and `report` run read-only against mounted host state (`--pid=host`,
  `-v /etc:/etc:ro` and friends); `systemctl`/D-Bus-dependent checks degrade
  to tool-unavailable findings, and `apply` is deliberately unsupported
  in-container. Usage and the capability boundary are documented in
  `packaging/docker/README.md`.

- `hardener scan --timings`: per-plugin timing table (slowest first, from each
  plugin's self-reported `scan_duration_us`) plus summed plugin time and wall
  clock, written to stderr so JSON stdout stays machine-parseable.

### Changed
- Desktop layout compacted: the shared spacing scale, card and control
  paddings, summary tiles and page title sizes all tighten so more content
  fits above the fold on every page.
- Documentation restructured into `docs/guide/`, `docs/reference/`,
  `docs/architecture/`, `docs/contributing/`, `docs/design/` and
  `docs/security/` (with archived plans and the resolved 2026-02-25
  internal audit under `archive/`); `ROADMAP.md` and `NEXT.md` moved under
  `docs/`. All intra-repo links and the doc validators follow the new
  tree. New docs: a documentation index, a getting-started guide, a
  symptom-organised troubleshooting guide, a full configuration
  reference and a plugin-authoring guide; the README single-sources
  usage, configuration and roadmap content to them.
- Test tooling consolidated: the five per-distribution container
  scripts became `scripts/containers/create-container.sh <distro>`, the
  four per-desktop polkit wrappers became
  `scripts/test/polkit/test-polkit.sh <desktop>`, and the separate
  parallel runner variants merged behind a `--parallel` flag. Scripts
  now live in `scripts/{containers,test,validate,release,dev}`
  subdirectories.
- Packaging inputs moved under `packaging/`: `data/` is now
  `packaging/assets/` and `systemd/` is `packaging/systemd/`. Install
  destinations are unchanged; built packages are identical.
- Test tooling deduplicated: the six copies of `resolve_target_dir`, the
  three `CONTAINERS`/`DISTRO_ORDER` distro tables (plus the same names
  hardcoded in `create-container.sh`), the colour/box-banner preambles, and
  the parallel job-pool frame duplicated across the cross-distro and Web UI
  GUI runners now live in `scripts/lib/common.sh` and
  `scripts/lib/parallel.sh`. Each runner's serial and `--parallel` code
  paths share one `run_single_distro` instead of carrying two near-identical
  bodies, and the cross-distro parallel runner reads its pass/fail/skip
  counts back from the persisted per-distro logfile instead of a
  `.passed`/`.failed`/`.skipped`/`.total` temp-file relay. `create-container.sh`'s
  Fedora and Rocky (RHEL) bootstraps, identical bar the image and one
  package name, are now one parameterised `bootstrap_dnf_family` (openSUSE's
  zypper bootstrap stayed separate; its user/group setup diverges enough
  that folding it in would cost more clarity than it would save). No CLI
  flag, invocation path or output file changed.
- The CLI `--framework` flag and the desktop framework parser each
  hand-maintained their own alias table for legacy framework spellings
  (`pci`, `iso`, `soc-2` and similar). Both now delegate to a new
  `ComplianceFramework::from_id`, the single source of truth for framework
  identifiers; every spelling either parser accepted before still parses,
  and the two alias sets are merged so `iso-27001` (desktop-only) and `iso`
  (CLI-only) are both accepted everywhere now.
- README presentation overhaul (issue #23): new Midnight Teal wordmark
  (`docs/assets/logo.svg` + dark variant, selected via `<picture>` and
  `prefers-color-scheme`), shields badges recoloured to the same teal palette
  plus a CI workflow-status badge, the long CLI usage fence folded into a short
  "most common commands" block with one collapsible `<details>` section per
  verb, plugin/distro table statuses and completed roadmap headings rendered
  as ✅ glyphs, and the ASCII crate tree replaced by a Mermaid dependency
  graph verified against the workspace manifests (directory layout kept in a
  collapsible block). Stale counts refreshed: tests badge now reads 750+ and
  the compliance crate is annotated with its 10 frameworks.
- Scan performance: the `scan` and `report`/`batch` scan paths now run all
  plugins concurrently (`futures::future::join_all`; output order is
  preserved by rendering in plugin order), `LocalExecutor` spawns commands
  through `tokio::process` so concurrent scans genuinely overlap, and the
  services plugin batches its systemctl probing: two pattern-filtered
  listings (`list-unit-files`/`list-units`) for the whole scan instead of up
  to three spawns per service. Measured locally (debug build, 8 plugins):
  wall clock ~25 ms → ~10 ms per scan; the services plugin ~13 ms → ~8 ms and
  15 spawns → 2. Remote scans gain more: each spawn saved is an SSH
  round-trip. The scheduler's `PluginManager::execute_scan` stays
  deliberately sequential: it honours the dependency graph and only the
  daemon uses it. Criterion benches remain deliberately out of scope; the
  `--timings` flag plus these recorded numbers are the measurement story.

### Security
- Per-command Tauri capability ACLs for the desktop app (SAM-039, issue #22):
  `src-tauri/build.rs` now declares all 29 IPC commands via
  `tauri_build::AppManifest`, autogenerating an `allow-*`/`deny-*` permission
  pair per command and enabling Tauri's runtime ACL check for application
  commands. The main-window capability grants each permission explicitly,
  ordered by risk tier, so any single command can be revoked by removing one
  line from `capabilities/default.json`. Enforcement is verified by
  mock-runtime tests (`src-tauri/src/acl_tests.rs`): invoking an ungranted
  command is rejected by the ACL layer before dispatch. Layers on top of the
  existing IPC validation, `PrivilegedOpGuard`, and pkexec boundary.

## [1.2.2] - 2026-07-02

### Fixed
- **Checkpoint rollback could delete files with `0000` permissions.** The
  executor captured a file's mode with the type bits masked off, so a regular
  file whose permissions are `0000` (as `/etc/shadow` and `/etc/gshadow` ship on
  Arch Linux) was recorded as mode `0` (indistinguishable from "did not exist
  at checkpoint time") and rollback removed it instead of restoring its
  permissions. The local and SSH (`--ssh`) executors now preserve the file-type
  bit, so an existing file is never mistaken for an absent one.
- **The permissions plugin's apply → rollback cycle aborted with a
  path-not-allowed error.** The account-database files newly checkpointed for
  CIS 6.1.2-6.1.5 (`/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`)
  were absent from the rollback allowlist, so rolling back a permissions
  checkpoint failed outright (the cross-distro suite's per-plugin lifecycle
  exited 1 on every distribution). They are now allow-listed. Regression tests
  cover both issues at the unit, executor, and end-to-end rollback levels.

## [1.2.1] - 2026-07-01

### Fixed
- Documentation version references and the README version badge now read the
  current release. The v1.2.0 source tarball shipped a README still showing the
  1.1.0 badge (the fix landed just after the v1.2.0 tag); this patch makes the
  packaged docs consistent.

## [1.2.0] - 2026-07-01

### Added
- **CIS compliance coverage completion.** Eleven curated CIS controls are now
  genuinely assessed instead of `ManualReview`: file permissions on
  `/etc/{passwd,group,shadow,gshadow}` (6.1.2-6.1.5), ICMP redirect and
  martian-packet sysctls (3.2.2-3.2.4), `xinetd` removal (2.1.1), firewall
  installed (3.4.1.1), and faillock/pwhistory (5.3.2/5.3.3). `report --framework
  cis` now reports 6 `ManualReview` (down from 17): the remainder are honestly
  out of scope (cron.allow, sshd_config perms, SSH Protocol 2, SELinux
  bootloader/policy, X11). Each newly-checked item also gains a
  checkpoint-protected apply action.
- **Polkit desktop-environment test tooling.** New `scripts/detect-polkit-agent.sh`
  diagnostic plus a `test-polkit-matrix.sh` harness and GNOME/KDE/XFCE/no-agent
  wrappers that validate `pkexec` privilege escalation across desktops, and a
  `docs/de-compatibility.md` matrix documenting the polkit agent each DE needs.

- **Desktop Fleet Apply page**: apply and roll back hardening across saved
  hosts over SSH from the GUI, by shelling out to the audited `batch apply`/`rollback`
  CLI. Mandatory dry-run preview + confirmation before any change; the page is
  read-only until you confirm.
- **Desktop fleet view.** A new read-only **Fleet** page scans several saved
  inventory hosts concurrently and shows each host's severity posture
  (per-host critical/high/medium/low/info tallies, expandable to that host's
  findings). Reuses the single-host scan path in-process; per-host failure is
  isolated. Fleet apply/rollback and compliance scoring remain CLI-only.
- **Desktop fleet view: compliance scores.** Each fleet host row now shows a
  colour-coded CIS compliance score, and the row's expander lists every
  framework's score with pass/fail/manual/NA counts. Derived in-process from the
  findings already scanned (no extra SSH); the view remains read-only.

### Fixed
- **`polkit` was missing from the Arch package's `depends`.** Installing the AUR
  package could leave a system without polkit, so `pkexec` privilege escalation
  (apply / rollback) would fail. `polkit` is now a hard dependency, with
  `optdepends` recommending an agent per desktop; RPM gains `Recommends`/`Supplements`
  and Debian a `Suggests` for the same.

### Security
- **RUSTSEC-2026-0190**: Updated `anyhow` 1.0.100 → 1.0.103, fixing an
  unsoundness (undefined behaviour) in `Error::downcast_mut()` after
  `Error::context()`.
- **RUSTSEC-2026-0192**: `ttf-parser` flagged unmaintained with no safe upgrade;
  accepted in `deny.toml`. Transitive via `krilla`→`rustybuzz` for PDF
  compliance-report export; no first-party usage, no runtime attack surface.
- **Permission checks never loosen `/etc/shadow`/`/etc/gshadow`.** These files
  are distro-variant (`0000` on RHEL, `0640` on Debian); the check now uses an
  allowed-bits mask so a stricter mode is compliant and apply only ever strips
  disallowed bits, never adding them.
- **faillock/pwhistory apply never loosens a stricter setting.** `deny`/`remember`
  use a threshold comparison (`deny ≤ 5`, `remember ≥ 5`); a stricter existing
  value is compliant and apply writes the CIS boundary only when the current
  value actually violates it. The effective value is read from either
  `/etc/security/{faillock,pwhistory}.conf` **or** an inline `pam_faillock.so`/
  `pam_pwhistory.so` argument in the PAM stack (which overrides the `.conf`), so
  a host configured inline is no longer misreported. A stricter per-host override
  is honoured (clamped so it can never loosen below the CIS baseline); when a
  non-compliant value is set inline in the PAM stack, apply refuses to auto-edit
  the auth stack and reports the manual action instead.

## [1.1.0] - 2026-06-24

### Added
- **`hardener batch apply`**: apply hardening across many hosts concurrently.
  Dry-run by default (validates each host and reports what would change); pass
  `--execute` to perform real changes. Before executing on a host the command
  probes for privilege (uid 0 or passwordless `sudo`); a non-privileged host is
  isolated as failed while the others proceed. On `--execute` each host gets an
  automatic host-keyed checkpoint and a best-effort audit-log entry. Tiered exit
  codes: 0 all clean, 1 any apply or validation failure, 2 any connect, privilege
  or usage error. Flags mirror `batch scan`: `--all`, `--host`, `--ssh`,
  `--plugin`, `--concurrency`, `--format`, `--output`, `--quiet`.
- **`hardener batch rollback`**: roll back many hosts concurrently to their
  latest per-plugin checkpoint (`<plugin-id>-pre-apply`). Dry-run by
  default (previews per host which checkpoint(s) would be restored); pass
  `--execute` to restore. Before executing on a host it probes for privilege
  (uid 0 or passwordless `sudo`) and isolates a non-privileged host as failed
  while the others proceed. Restores reuse the host-keyed checkpoints created by
  `batch apply`, so a checkpoint is never restored onto a different host; each
  `--execute` host gets a best-effort audit-log entry. Tiered exit codes: 0 all
  clean, 1 any checkpoint restore failure, 2 any connect, privilege or usage
  error. Flags mirror `batch apply`: `--all`, `--host`, `--ssh`, `--plugin`,
  `--execute`, `--concurrency`, `--format`, `--output`, `--quiet`.
- **`hardener batch report`**: assess multiple hosts against a compliance
  framework or scenario in one concurrent run, printing a fleet posture table
  (host × framework → score and pass/fail/manual/N-A control counts) with a
  tiered exit code (0 compliant / 1 failing control / 2 host error) for CI
  gating. Reuses the `batch scan` engine; `--format json` and `--output`
  supported.
- **Per-host security trend.** `hardener history trends --host <key>` charts a
  host's completed scans oldest-first: per-severity counts, the change in total
  findings, and a per-scan direction (`better`/`worse`/`same`) computed by
  severity priority (a new critical outranks any number of lower-severity
  improvements). Derived on query from the persisted scan history; no score is
  stored. `--format json` emits the trend points for automation.
- **Regression detection / CI gate.** `hardener history regressions [--host <key>]`
  reports hosts whose latest completed scan is worse than the previous one (by the
  same severity priority as trends) and exits `1` when any regression is found, so
  it can gate CI; `0` when clean. `--format json` emits the regression records.
- **Scheduled-scan regression alerts.** The scheduler can now notify (email/webhook)
  when a scheduled scan is *worse than the host's previous scan*, not only when it
  has findings above a threshold. New `notify_mode` setting: `findings` (default,
  unchanged behaviour), `regression` (quiet until the posture worsens), or `both`.
  Regressions are measured at the existing `notify_min_severity` floor and the
  alert is annotated with the per-severity deltas. Self-deduping: fires only on
  the scan where the posture changes.
- **Batch scan persists per-host history.** `hardener batch scan` now records each
  host's results to the scan-history database keyed by host (the inventory name,
  or `user@host:port` for ad-hoc `--ssh` hosts); read them back with
  `hardener history list --host <key>`. Persistence is best-effort: a history
  write failure never changes a host's scan result. The history pool now uses
  SQLite WAL so concurrent per-host writes are safe.
- **Multi-host batch scanning.** `hardener batch scan` scans many hosts at once
  (`--all`, `--host a,b`, ad-hoc `--ssh user@host`) with bounded concurrency
  (`--concurrency`), a per-host + rollup report (text or `--format json`), and
  tiered CI exit codes (0 clean / 1 findings / 2 host or usage error). The host
  inventory (`~/.config/linux-hardener/hosts.toml`) is now shared between the CLI
  and the desktop GUI via `hardener_core::inventory`.
- **ISO/IEC 27001:2022 compliance framework.** The empty `ISO27001` stub is
  replaced with the full 93-control Annex A:2022 catalogue (Organizational,
  People, Physical, Technological themes), and plugin findings map to the
  Technological controls, so ISO 27001 reports now assess real system state.
- **Multi-framework compliance mappings.** All 8 plugins now tag findings with
  STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR and ISO 27001:2022 control IDs
  (sourced from ComplianceAsCode/SSG and the project catalogues) alongside CIS,
  so every framework genuinely fails on insecure systems instead of only
  reporting `ManualReview`. A wrong mapping can only cause a false *failure*,
  never a false pass.
- **Plugin-declared compliance coverage (single source of truth).** Each plugin
  now exposes `coverage()` (the complete set of `(framework, control)` it can
  assess) aggregated by `hardener_plugins::compliance_coverage()` and injected
  into the report generator. This replaces the framework-level
  `AUTOMATED_FRAMEWORKS` flag with per-control coverage, so partial framework
  support is reported honestly.
- **Accurate `Pass` for hardened systems.** A control the engine assesses and
  finds compliant now reports `Pass` for *every* framework, not just CIS, so a
  genuinely hardened host scores accurately instead of being buried under
  `ManualReview`.
- **SSH crypto-algorithm hardening.** The SSH plugin now hardens `KexAlgorithms`,
  `Ciphers` and `MACs`, including post-quantum key exchange
  (`mlkem768x25519-sha256`). It auto-detects what the host's OpenSSH supports
  (`ssh -Q …`) and only ever writes the intersection with a strong allow-list, so
  it cannot set an unknown algorithm (no lockout) or a weak one (no downgrade),
  and validates the candidate config with `sshd -t` before restarting.

### Fixed
- **Corrected HIPAA citations on kernel hardening controls.** The kernel plugin
  cited HIPAA `164.312(c)(1)` (Integrity) on six exploit-mitigation sysctls,
  which guard against memory disclosure rather than ePHI alteration. Cross-checked
  against the upstream SSG `references:` blocks: where SSG maps these rules to
  HIPAA it cites `164.312(a)` (Access Control), never `(c)(1)`, and for several it
  carries no HIPAA reference at all. ASLR, `dmesg_restrict` and `suid_dumpable`
  are re-cited to `164.312(a)(1)`; `kptr_restrict`, `yama.ptrace_scope` and
  `protected_hardlinks/symlinks` (no SSG HIPAA reference) drop the mapping. The
  permissions plugin (credential files) and MAC plugin, which already carried
  `164.312(a)(1)` alongside the `(c)(1)` citation, drop the redundant `(c)(1)` to
  match the same SSG preference. NIST, STIG, CIS, GDPR and ISO mappings are
  unchanged.
- **Removed an unsourced CIS mapping.** The kernel plugin tagged
  `fs.protected_hardlinks` / `fs.protected_symlinks` with CIS `1.6.1`, but the
  upstream SSG rules (`sysctl_fs_protected_hardlinks/symlinks`) carry no CIS
  reference, and `1.6.1` is the Mandatory Access Control subsection header (the
  curated catalogue already lists `1.6.1.1`-`1.6.1.4` there). The mapping is
  dropped; the sourced NIST `CM-6(a)`/`AC-6(1)` and STIG `OL08-00-010373/4`
  mappings are kept.
- **Desktop compliance commands build again.** The phase-3 coverage change gave
  `ReportGenerator::new` a second `coverage` parameter but the Tauri
  `generate_compliance_report` / `export_compliance_report` commands still called
  the one-argument form, so the desktop crate failed to compile. Both now inject
  `hardener_plugins::compliance_coverage()`, matching the CLI. (The frontend
  `dist/` already exists, so this was the desktop crate's only build blocker.)
- **Ad-hoc batch SSH targets honour a `:port` suffix.** `hardener batch scan
  --ssh user@host:2222` now connects on the given port instead of always
  defaulting to 22; an unbracketed IPv6 literal keeps the default port (it has no
  unambiguous `host:port` form).
- **Honest reporting for not-yet-assessed frameworks.** Control results are
  derived from scan findings, which initially carried CIS control IDs only. For
  frameworks without mappings yet (STIG, NIST, PCI-DSS, HIPAA, GDPR), a control
  with no matching finding previously defaulted to `Pass`, reporting coverage the
  engine had not actually evaluated. Such controls now report `ManualReview`
  until a mapping exists, and the generator surfaces any finding-referenced
  control missing from a framework's catalogue, so an incomplete mapping can
  only ever over-report a failure, never a pass.
- **Remote checkpoint capture and restore now operate on the remote host.**
  Previously, `apply --ssh` and `rollback --ssh` would snapshot and restore files
  on the controller rather than the target. Checkpoint operations now run through
  the active `SystemExecutor`, so remote sessions correctly read and write files on
  the remote. Checkpoints are keyed by host; rollback refuses to restore one host's
  checkpoint onto another.

### Changed
- **`tauri` 2.11.2 → 2.11.3.** Routine patch bump (no CVE); pulls the matching
  `tauri-runtime`/`tauri-utils`/`wry` updates in the lockfile.
- **Curated CIS SSH section completed.** The curated CIS catalogue now lists the
  strong-crypto SSH controls `5.2.14`-`5.2.16` (Key Exchange, Ciphers, MACs)
  alongside the existing `5.2.x` entries, so the SSH plugin's crypto assessment
  is reflected in the curated standard rather than surfacing only via the
  coverage merge.
- **Non-CIS catalogues are derived from plugin coverage.** The hand-written
  STIG / NIST 800-53 / PCI-DSS / HIPAA / GDPR catalogues (whose identifier
  schemes diverged from the upstream (SSG) IDs the plugins emit, producing
  duplicate and `ManualReview`-only noise) are removed. Each of those
  frameworks' reports now lists exactly the controls the engine assesses, on a
  single identifier scheme. CIS and ISO/IEC 27001:2022 keep their curated
  catalogues (the full standard, with unassessed controls flagged
  `ManualReview`).
- **Executor abstraction relocated to `hardener-common`.** `SystemExecutor`,
  `FileMetadata`, `CommandOutput`, and `MockExecutor` now live in
  `hardener-common` (under `executor/`), re-exported from `hardener-core` for
  source compatibility. `SystemExecutor` gained a `read_dir` method;
  `FileMetadata` gained `uid` and `gid` fields.

### Removed
- **Obsolete SSH `Protocol 2` directive.** Modern OpenSSH ignores the `Protocol`
  keyword (SSHv1 was removed years ago), so enforcing it was vestigial.
- **Hand-written non-CIS framework catalogues** (`frameworks/{stig,nist,pci,
  hipaa,gdpr}.rs`) and the `AUTOMATED_FRAMEWORKS` / `is_automated` API, replaced
  by coverage-derived catalogues and per-control coverage (see above).

### Security
- **RUSTSEC-2026-0185**: Updated `quinn-proto` 0.11.14 → 0.11.15 (remote memory
  exhaustion, CVSS 7.5: unbounded out-of-order QUIC stream reassembly; pulled
  transitively).
- **RUSTSEC-2026-0173**: `proc-macro-error2` flagged unmaintained with no safe
  upgrade; accepted in `deny.toml`. Compile-time-only proc-macro, transitive via
  the Leptos macro stack (`leptos_macro`/`leptos_router`/`rstml`), no runtime
  attack surface.
- Pruned two stale `deny.toml` advisory ignores no longer present in the resolved
  dependency graph: `RUSTSEC-2024-0429` (`glib`) and `RUSTSEC-2026-0097` (`rand`).

## [1.0.5] - 2026-05-24

### Security
- **CVE-2026-42184 / GHSA-7gmj-67g7-phm9**: Updated `tauri` 2.9.5 → 2.11.2, fixing an origin-confusion flaw that could let remote pages invoke local-only IPC commands.
- **RUSTSEC-2026-0141**: Updated `lettre` 0.11.19 → 0.11.22 (TLS hostname verification bypass in the Boring TLS backend; not exposed: the project builds `lettre` with the rustls backend).
- **RUSTSEC-2026-0104**: Updated `rustls-webpki` 0.103.12 → 0.103.13 (reachable panic when parsing a certificate revocation list).

## [1.0.4] - 2026-04-15

### Changed
- Updated to Rust edition 2024.
- Bumped all dependencies to latest compatible versions.

## [1.0.3] - 2026-02-28

### Added (Testing Infrastructure)
- **Parallel test runners**: 4 new scripts for concurrent cross-distro testing
  - `run-gui-tests-parallel.sh`: Web UI tests across 5 distros simultaneously
  - `run-cross-distro-tests-parallel.sh`: CLI tests across 5 distros simultaneously
  - `run-desktop-tests.sh`: Tauri desktop GUI tests (auto-starts app)
  - `run-all-tests-parallel.sh`: Master runner with `--desktop` flag
- **Scripts documentation**: `scripts/README.md` expanded with +207 lines covering all parallel test workflows

### Fixed (GUI Tests)
- **TabBar selector migration**: GUI tests now use `getByRole('tab', { name: '...' })` instead of deprecated `.section-btn` class selectors
  - Aligns with Analysis and Hardening pages' migration to shared `TabBar` component (v1.0.2)
  - Affects `hardening.spec.js`, `themes.spec.js`, `errors.spec.js`, `helpers.js`

### Changed
- Removed unused theme screenshots from `pics-debug/`

## [1.0.2] - 2026-02-28

### Fixed (CLI)
- **Daemon status crash**: `daemon status` no longer panics when no scan history exists
- **Checkpoint list crash**: `checkpoint list` handles empty database gracefully
- **Report wizard crash**: Interactive wizard no longer panics on empty scan results
- **Stderr routing**: Progress messages now sent to stderr, keeping stdout clean for piping (`report` command)
- **Idempotent directory creation**: State initialisation no longer fails if directories already exist
- **User-mode systemd**: `systemd install --user` now generates correct user-scoped unit paths

### Added (Desktop UX)
- **Keyboard navigation**: Global shortcuts: Ctrl+1-5 (page nav), Alt+T (theme cycle), Escape (close panels/fullscreen), F11 (fullscreen)
- **ARIA accessibility**: Full WAI-ARIA tabs pattern (`role="tab"`, `role="tablist"`, `role="tabpanel"`), skip link, `aria-selected`, `aria-live` regions
- **Shared TabBar component**: Reusable `TabBar` with keyboard nav (ArrowLeft/Right, Home, End) and ARIA, migrated Analysis and Hardening pages
- **CopyButton component**: Async Clipboard API integration with visual feedback for compliance reports
- **ConfirmDelete component**: Inline delete confirmation to prevent accidental checkpoint deletion
- **Findings grid keyboard nav**: Arrow keys, Enter/Space to open detail, full focus management
- **95 automated desktop tests**: `tauri-ux-test.sh` (49 tests), `tauri-functional-test.sh` (46 tests), `run-tests.mjs` (21 Playwright tests)

### Changed
- **TabBar migration**: Analysis page (Findings/Compliance/History) and Hardening page (Configure/History) now use shared `TabBar` component instead of page-specific tab implementations
- **Focus management**: Tab focus race condition resolved; keyboard focus properly tracked across tab switches

## [1.0.1] - 2026-02-27

### Fixed
- Source checksum updated for AUR package

## [1.0.0] - 2026-02-27

### 1.0.0: Production Release

First stable release. Feature-complete Linux system hardener with 8 security plugins, CLI and desktop GUI, compliance reporting across 6 frameworks, remote SSH scanning, scheduled scanning with notifications, and checkpoint/rollback. Validated across 5 Linux distributions (Arch, Debian, Fedora, Rocky 9, openSUSE).

### Added
- Installation guide covering all 5 distro families (`docs/INSTALL.md`)
- Package install validation scripts for cross-distro packaging QA
- Distribution packages: AUR PKGBUILD, RPM spec, Debian packaging tree

### Changed
- All 53 internal security audit findings resolved
- Extracted shared helpers to reduce code duplication across UI and package crates
- SECURITY.md updated with 8 security practices, corrected 3 stale Known Limitations
- 505+ tests pass, clippy clean, native + WASM builds clean

### Fixed
- Systemd `ReadWritePaths` covers all required runtime directories
- Man page URL corrected to project homepage
- Tauri plugin ID matches canonical `service-minimisation`
- AUR, RPM, and Debian packaging install all data files correctly

## [0.3.3] - 2026-02-25

### Added (v1.0.0 Infrastructure 2026-02-25)
- **Packaging Infrastructure**: Complete build specs for three distribution families
  - AUR `PKGBUILD` with musl CLI + Tauri desktop builds
  - RPM `.spec` for Fedora/RHEL/openSUSE with systemd integration
  - Debian packaging (`debian/control`, `rules`, `changelog`, `postinst`, `prerm`, `copyright`)
- **Systemd Units**: `linux-hardener.service` (oneshot) and `linux-hardener.timer` (daily at 02:00)
  - Security hardened: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTemp`
- **Desktop Entry**: XDG `.desktop` file for application launcher integration
- **Config Example**: Comprehensive `data/config.toml.example` with all 8 plugin sections documented
- **Polkit Policy**: `com.tidynest.linux-hardener.policy` for nicer pkexec authentication dialogs
  - Separate actions for apply and rollback with descriptive messages
  - `auth_admin_keep` for active sessions (avoids repeated password prompts)
- **Man Page**: `data/hardener.1` troff man page covering all commands, options, and examples
- **High Contrast Theme**: WCAG AAA accessibility theme with 7:1+ contrast ratios
  - Pure black background with bright white text for maximum readability
  - High-saturation semantic colours chosen for colour-blind distinguishability
  - Available in theme selector dropdown alongside existing 6 themes

### Changed (Test Quality 2026-02-25)
- **Assertion Messages**: Added descriptive messages to 178+ bare `assert!()` calls across 12 test files
  - Failure output now shows what was expected and the actual value
  - Consistent patterns: `.is_ok()` shows error, `.contains()` shows searched value, `.is_empty()` shows contents
- **Test Output Cleanup**: Removed 80+ `println!`/`eprintln!` calls from test code
  - Some replaced with proper assertions; others simply removed (test output noise)
  - Net reduction of 422 lines while improving test diagnostics

### Changed (UI Polish Pass 2026-02-24)
- **Dashboard**: `RecentActivity` card no longer stretches to fill remaining page height
  - Removed `flex: 1 1 auto` and `min-height: 150px`, card sizes to content
  - Empty-state hint directs users to Quick Actions above
- **Remote Page**: Empty right panel replaced with numbered quick-start guide
  - Dropped `min-height: 400px` on `.remote-layout`
  - "Getting Started" guide with CSS-counter numbered steps
- **Hardening Configure Tab**: Security Profile and Plugin Control now side-by-side
  - Shared `.two-col-row` CSS class for consistent two-column layouts
  - Preview Changes button is standalone (removed unnecessary Card wrapper)
- **Hardening History Tab**: Latest Apply and Latest Rollback now side-by-side
  - Directional empty-state guidance ("Configure and apply hardening in the Configure tab...")
  - System Checkpoints table remains full-width below
- **Scheduler Page**: Cards no longer height-stretch to match sibling
  - `align-self: start` prevents shorter Notifications card from expanding
  - Removed `margin-top: auto` that pinned buttons to bottom of stretched cards

### Added (Config File Picker 2026-02-24)
- **Config File Picker**: GUI equivalent of CLI `--config FILE` flag on Hardening page
  - Text input + native file dialog (Browse button) via `tauri-plugin-dialog`
  - Inline validation with one-line summary (plugin count, directives, exceptions)
  - Config path threaded through scan, apply, dry-run, and rollback commands
  - `ConfigSummary` type in `hardener-types` for WASM-safe validation results

### Added (Scheduler UI 2026-02-24)
- **Scheduler Configuration Page**: New top-level "Scheduler" page for configuring scan scheduling and notifications
  - Schedule section: enabled toggle, cron presets (Daily/6h/12h/Weekly) with custom cron input, plugin checkboxes, severity threshold
  - Notification section: email recipients and from address, webhook endpoint with Slack/Discord/Generic format
  - Test notification button with inline success/failure feedback
- **WASM-safe Scheduler Types**: `SchedulerUiConfig`, `NotificationUiConfig`, `EmailUiConfig`, `WebhookUiConfig`, `TestNotificationResult` in `hardener-types`
- **Tauri IPC Commands**: `get_scheduler_config`, `save_scheduler_config`, `test_notification` with `toml_edit` for surgical config updates
- **Mock Handlers**: 3 new scheduler IPC mock handlers for GUI testing

### Added (Rollback JSON Output 2026-02-23)
- **Structured Rollback Results**: `checkpoint rollback` now returns per-file restore status
  - `RollbackResult` with `rollback_success`, `rollback_checkpoint_id`, `rollback_files`
  - `FileRestoreResult` per file: path, action (Restored/Removed/PermissionsRestored/Skipped), success, error
  - `FileRestoreAction` enum for discriminating restore types
  - CLI outputs JSON (`--format json`) or human-readable summary with colour-coded status
  - Non-zero exit code on partial rollback failure
- **GUI Rollback Detail**: Tauri GUI now parses and displays per-file rollback results
  - Rollback types (`RollbackResult`, `FileRestoreResult`, `FileRestoreAction`) canonicalised in `hardener-types` for WASM compatibility; `hardener-state` re-exports to avoid duplication
  - `run_rollback` Tauri command returns `RollbackResult` instead of `bool`
  - WASM bindings deserialise structured result; `AppState.rollback_result` reactive signal stores it
  - "Latest Rollback" card in History section shows success/failure, file count, and per-file restore actions
- **Extended Tauri IPC Mock**: 8 new mock handlers for GUI testing
  - `run_scan_filtered`, `run_scan_with_options`, `create_checkpoint`, `delete_checkpoint`
  - `export_report`, `get_scan_history`, `get_scan_session`, plus mock scan history data
- **Severity Filter**: Full severity filtering for the analysis view
  - `severity_filter` reactive signal in `AppState` with `severity_rank()` and `parse_severity()` helpers
  - `FindingsGrid` refactored to accept a `findings` prop (filtered externally)
  - Dropdown in `FindingsTab` for selecting minimum severity threshold
  - "X of Y findings" count display updates reactively
  - `ViewMode` filter (All / Compliance) for toggling compliance-only findings
  - CSS styling for the severity dropdown and filter controls

### Fixed (2026-02-23)
- **Checkpoint Directory Permissions**: Checkpoints now capture and restore directory metadata (mode/uid/gid)
  - Added `capture_directory_entry()` to `CheckpointManager` for metadata-only directory snapshots
  - `capture_directory_recursive()` now includes the directory entry itself, not just child files
  - `restore_file_state()` distinguishes directories (restore permissions) from absent paths (delete)
- **Metadata-Only Checkpoints**: Permissions plugin uses `create_checkpoint_metadata_only()` instead of recursive file snapshots
  - Captures 5 `FileState` entries (~200 bytes) instead of recursively snapshotting entire directory trees (e.g., 156MB `/boot` ESP)
  - Apply operations complete instantly instead of minutes
- **FAT32/vfat chmod Detection**: Post-chmod verification detects filesystems where `chmod` is a no-op
  - Re-reads actual permissions after `chmod` and reports failure if unchanged
  - Clear error message explaining mount-option-governed permissions
- **Scan History Persistence**: `hardener scan` now persists results to the history database
  - `history list` and `history show` commands now display CLI scan results
  - Best-effort persistence (failures silently ignored to avoid disrupting scan output)
- **Audit Rules Reload**: Uses `augenrules --load` instead of `systemctl restart auditd`
  - On Arch/RHEL/Fedora, auditd ignores SIGTERM from systemd; direct restart fails
  - `augenrules --load` is the supported mechanism, with systemctl as fallback
  - Fixed in both apply and rollback code paths
- **CLI Apply Output**: Partial failures now show individual change status instead of blanket "Unknown error"

### PluginConfig Wiring (2026-02-23)
- **All 8 plugins now consume PluginConfig**: Directives override default values; exceptions exempt specific items from hardening
  - Two families: **value-override** (directives + exceptions) for SSH, Kernel, Firewall, PAM, Permissions; **binary** (exceptions only) for Services, Audit, MAC
  - SSH (`755bc35`), Kernel (`ca53286`), Firewall (`820f406`), PAM (`95bf62b`), Services (`f97e33b`), Permissions (`d01432a`), Audit (`2ec356a`), MAC (`ef0f8f6`)
  - `HardeningPlugin` trait receives `&PluginConfig` per-plugin; `HardenerConfig` decomposed by callers
  - 418 tests pass, clippy clean

### Added (GUI/CLI Feature Parity - Phase 1)
- **Preview & Apply Flow**: Users can now preview changes before applying hardening
  - "Preview Changes" button runs dry-run and displays estimated changes
  - Preview panel shows changes grouped by plugin with Cancel/Confirm actions
  - "Confirm & Apply" triggers actual apply with pkexec authentication
  - Safer workflow prevents accidental system modifications
- **`run_apply_dry_run` Tauri Command**: Backend support for dry-run preview
  - Calls CLI with `--dry-run --format json` without pkexec (read-only operation)
  - Returns `Vec<ValidationReport>` with estimated changes per plugin
- **Preview State Signals**: Leptos reactive state for preview workflow
  - `preview_results`, `is_previewing`, `show_preview` signals in AppState
- **Short Plugin Name Support for Apply**: `apply --plugin kernel` now works
  - Expands short names to full IDs (e.g., "kernel" → "kernel-hardening")
  - Consistent with scan command behaviour

### Fixed (GUI/CLI Feature Parity - Phase 1)
- **CLI Output Format Inverted**: Fixed 7 functions in `output.rs` where `--format json` outputted text
  - `scan_results`, `apply_results`, `plugin_list`, `checkpoint_list`, `checkpoint_created`, `checkpoint_details`, `validation_reports`
- **Dry-run JSON Not Array**: Changed from per-plugin JSON objects to single array output
  - Added `validation_reports()` function for proper array formatting

### Added (Cross-Distro Validation 2026-02-23)
- **Cross-Distro Test Runner**: `scripts/run-cross-distro-tests.sh` orchestrates testing across all distributions
  - Single command: `sudo ./scripts/run-cross-distro-tests.sh --apply`
  - Uses `systemd-nspawn --pipe` for non-interactive container execution
  - Per-distro logs saved to `test-results/<distro>.log`
  - Aggregated summary in `test-results/summary.txt`
  - Options: `--apply`, `--distro NAME`, `--rebuild`, `--help`
- **Expanded Test Suite**: `scripts/full-test-suite.sh` expanded from 102 to 123 tests (26 sections)
  - Section 20: Scan history persistence (scan -> history list verification)
  - Section 21: History filtering (--limit, --status)
  - Section 22: Plugin filter combinations (short names, mixed, multi-plugin)
  - Section 23: Per-plugin apply/rollback lifecycle (gated behind --apply)
  - Section 24: Config file loading (valid/invalid paths)
  - Section 25: Report framework + scenario combinations
  - Section 26: Flag combinations (--quiet + --format, --audit + --format)
- **Container-Aware Testing**: Auto-detects container environment and skips impossible tests
  - 6 tests correctly SKIPPED instead of falsely FAILED in containers
  - Partial apply treated as pass in container mode (expected behaviour)
  - `--apply` flag gates destructive tests (apply + rollback)
- **3-Layer Host Safety**: Prevents accidental execution on real systems
  - Layer 1: nspawn container isolation
  - Layer 2: Container detection with hard `exit 1` if not in container
  - Layer 3: `--apply` flag gates all destructive operations
- **Rocky Linux 9 Validation**: Added 5th distribution (RHEL family)
  - Container created via podman export at `/var/lib/machines/hardener-test-rhel`
  - 123/123 tests pass, 6 skipped (container limitations)
- **5-Distro Validation Results**: 123/123 tests pass on all distributions
  - Arch Linux (Rolling): 123/123 pass, 6 skip
  - Debian 12 (Bookworm): 123/123 pass, 6 skip
  - Fedora 41: 123/123 pass, 6 skip
  - Rocky Linux 9: 123/123 pass, 6 skip
  - openSUSE Leap 15.6: 123/123 pass, 6 skip

### Added (GUI Testing 2026-02-23)
- **Web UI Test Suite**: 84 Playwright tests covering all GUI functionality
  - Dashboard (9 tests): score display, scan trigger, navigation, activity feed
  - Findings (10 tests): scan, table, detail panel, finding count
  - Compliance (8 tests): framework selection, report generation, score colours
  - Configure (10 tests): profiles, plugin toggles, preview, cancel
  - History (6 tests): checkpoints, rollback, apply results
  - Themes (7 tests + 30 screenshots): all 6 themes verified
  - Error handling (4 tests): scan/apply/checkpoint errors, dismiss
- **Tauri IPC Mock**: JavaScript mock of `window.__TAURI__` with all IPC commands
- **Cross-Distro GUI Validation**: 84/84 tests pass on all 5 distros
- **GUI Test Runner**: `scripts/run-gui-tests.sh` orchestrates Playwright tests inside nspawn containers
- **`--gui` flag for cross-distro runner**: `run-cross-distro-tests.sh --gui` runs GUI tests after CLI tests

### Fixed (GUI Testing 2026-02-23)
- **GUI Test HTML Generation**: `mock-index.html` removed; `gui-test-inner.sh` now generates `index.html` at
  serve-time by reading `dist/index.html`, stripping SRI integrity attributes, and injecting `tauri-mock.js`,
  eliminating hash drift when the WASM bundle changes

### Added (Distribution Validation)
- **Container Test Scripts**: Distribution-specific container creation scripts
  - `scripts/create-debian-container.sh` - Debian/Ubuntu testing
  - `scripts/create-fedora-container.sh` - Fedora/RHEL testing
  - `scripts/create-opensuse-container.sh` - openSUSE/SUSE testing
- **Musl Static Build**: Cross-distribution binary using musl libc for maximum compatibility

### Fixed (2025-12-10)
- **Invalid Plugin Name Accepted Silently**: `--plugin nonexistent` now returns error with valid plugin list
  - Added `validate_plugin_filter()` in scan.rs to check plugin names before scanning
  - Supports both full IDs (`kernel-hardening`) and short names (`kernel`)
  - Exit code 1 for invalid plugins, enabling proper CI/CD error detection
- **Test Script 105% Pass Rate**: Fixed test counter bug in `full-test-suite.sh`
  - Preflight checks were incrementing PASSED without incrementing TOTAL
  - Added `log_check()` function for non-test verification steps

### Fixed (2025-12-09)
- **Security Score Calculation**: Redesigned from findings-based to compliance-based weighted scoring
  - Pass = 100pts, Critical fail = 0pts, High = 25pts, Medium = 50pts, Low = 75pts
  - Overall score = average of framework weighted scores
  - Added expandable "Framework Breakdown" showing per-framework scores
- **UFW False Positive**: Firewall plugin now uses `systemctl is-active ufw` first (no root needed)
  - Falls back to `ufw status` only when systemctl unavailable
- **Audit Rules False Positives**: Added `AuditRulesResult` enum to distinguish permission denied from missing rules
  - No longer reports 25 false positives when running without root
- **Empty validate() Stubs**: Implemented proper validate() for permissions, SSH, and firewall plugins
  - Now reports estimated changes like "PermitRootLogin: yes → no"
- **Kernel Rollback Gap**: apply() now creates `/etc/sysctl.d/99-hardener.conf`
  - Kernel hardening persists across reboot
  - Rollback properly removes config and reloads sysctl

### Fixed (GUI Issues 2025-12-09)
- **Theme Selector Unreadable**: Added `appearance: none` CSS reset for cross-browser styling
  - Custom SVG dropdown arrow for dark and light themes
  - WebKit now respects CSS colours instead of native controls
- **Generate Reports No Feedback**: Added status message display for report generation
  - Shows success message with report count after generation
  - Shows error message if generation fails
- **Checkpoints Not Visible After Apply**: Now reads from both user and system databases
  - GUI reads from `~/.local/share/linux-hardener/checkpoints.db` (user) AND `/var/lib/linux-hardener/checkpoints.db` (system)
  - Added refresh button to checkpoint list
  - Checkpoints from privileged apply operations (pkexec) now visible
- **Score Mismatch Dashboard vs Analysis**: Unified score calculation
  - `MiniSecurityScore` component now uses shared `calculate_all_scores()` function
  - Both pages display identical compliance-based weighted scores

### Added
- **GUI Dark Terminal Theme**: Complete CSS styling with professional dark aesthetic
- **Fluid Typography**: Score ring text uses `clamp()` for proportional scaling across viewport widths
- **Card Component**: Reusable `Card` component in `card.rs` with `CardVariant` (Default, Compact, Empty) and `HeadingLevel` (H2, H3, H4) props for consistent section styling
- **CSS Transitions**: Added transition variables (`--transition-fast`, `--transition-normal`, `--transition-slow`) for smooth hover animations
- **Empty State Icons**: Consistent empty states with contextual icons across all pages: activity, findings, compliance, apply operations, checkpoints
- **Button Hover Effects**: Subtle `translateY(-1px)` lift effect with box-shadow on hover for action buttons
- **E2E Test Cases**: Added TC-11 to TC-14 covering empty states, animations, themes, and responsive layout

### Changed
- **Responsive Dashboard Layout**: Improved single-column mode with compact sections and proper stacking order (Score → Actions → Activity)
- **Refactored Section Containers**: All page sections now use the `Card` component instead of raw `<section>` tags for consistent styling
- **Score Ring Sizing**: Changed from fixed 160px to proportional `min(160px, 45vw)` with `aspect-ratio: 1` for smooth scaling
- **No Minimum Width**: Removed 320px minimum width constraint; content now shrinks/wraps at any viewport width
- **Playwright MCP Documentation**: Added `MCP_INSTRUCTIONS.md` with detailed instructions for automated UI testing
- **Accessibility: Skip Link**: Added keyboard-accessible skip link for screen reader users (`lib.rs`)
- **Accessibility: Tab ARIA**: Full WAI-ARIA tabs pattern with `aria-controls`, `aria-labelledby`, `tabindex` management
- **CSS Utility Classes**: Added `.truncate`, `.line-clamp-2`, `.line-clamp-3`, `.sr-only`, `.min-w-0`, `.skip-link`
- **CSS Flex/Grid Utilities**: Added `.flex`, `.flex-col`, `.flex-wrap`, `.flex-1`, `.items-center`, `.items-start`, `.justify-center`, `.justify-between`, `.grid`, `.gap-xs`, `.gap-sm`, `.gap-md`, `.gap-lg`, `.gap-xl`
- **CSS Variables**: Extended spacing scale (`--space-xs` to `--space-2xl`), border radius scale, z-index scale
- **Responsive Testing**: Verified layouts at 320px, 640px, 1920px viewports
- Test suite expanded from 220 to 428+ tests (95% increase)
- PDF findings now display with better visual hierarchy and spacing
- All 8 plugins converted to async with `#[async_trait]`
- HardeningPlugin trait methods now async: `scan()`, `apply()`, `rollback()`, `validate()`
- **hardener-ui** now depends only on `hardener-types` (removed hardener-core, hardener-common, hardener-compliance dependencies)
- Types re-exported from source crates for backwards compatibility

### Fixed
- **WCAG AA Text Contrast**: Brightened `--text-secondary` (#a1aebe → #a8b8c8) and `--text-muted` (#7a8a9e → #8a9aae) to meet 4.5:1 contrast ratio
- **Theme Select Dropdown**: Added `!important` rules for option styling to override browser defaults in all themes
- **Section Header Readability**: Increased section headers (Security-Score, Quick Actions, Recent Activity) from 0.875rem to 0.9375rem
- **CSS Cleanup**: Removed redundant container styles (`.dashboard-section`, `.profile-selector`, `.plugin-toggles`, `.apply-controls`, `.framework-selection`) - Card component now provides these styles
- **GUI Responsive Layout (Ultra-Wide)**: Content now constrained to 1600px max-width and centred on ultra-wide screens (4K)
- **GUI Value Cell Overflow**: Long file paths in tables now truncate with ellipsis instead of breaking layout
- **Flex Container Overflow**: Added `min-width: 0` to flex children (`.navigation`, `.nav-links`, `.header-content`, `.activity-content`)
- **Grid Container Overflow**: Updated grid templates to use `minmax(0, 1fr)` pattern (`.dashboard-grid`, `.scanner-layout`, `.report-summary`)
- **Auto-fill Grid Overflow**: Used `minmax(min(Xpx, 100%), 1fr)` for `.plugin-grid` and `.framework-grid` to prevent narrow viewport overflow
- **GUI "Loading..." text persistence**: Fixed by mounting app to `#app` element instead of body and clearing inner HTML
- **Security score showing 100/100 before scan**: Added `has_scan_results()` check, now shows "--/100" and "Run a scan to see your score" initially
- **"View Findings" appearing as hyperlink**: Changed from `<A>` link to styled `<button>` with programmatic navigation

- Configuration file support with layered loading (system → user → CLI → env vars)
- `HardenerConfig`, `GlobalConfig`, `PluginConfig` structs for configuration management
- `ConfigLoader` with multi-source config merging
- `PolicyException` support for documenting security deviations with audit trail
- `FindingPolicyException` field on `Finding` struct for policy annotation
- CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code` for scan command
- Three scan modes: Default (annotated), Audit (pure), Compliance (violations only)
- Config paths: `/etc/linux-hardener/config.toml` (system), `~/.config/linux-hardener/config.toml` (user)
- Interactive report wizard with `--interactive` flag for guided report generation
- CSV and HTML output format support in CLI report command
- `dialoguer` dependency for interactive terminal prompts
- PDF report formatter with professional multi-page layout and embedded fonts (NotoSans)
- Automatic timestamped PDF filenames (`compliance-report-YYYYMMDD-HHMMSS.pdf`)
- Colour-coded status badges in PDF reports (PASS=green, FAIL=red, PARTIAL=amber)
- `krilla` dependency for PDF generation
- Full compliance framework names in report titles (e.g., "CIS Benchmark" instead of "CIS")
- `full_name()` and `description()` methods on `ComplianceFramework` enum
- Improved PDF findings formatting: bold 10pt text, proper indentation, spacing after FAIL rows
- GUI compliance report page with framework selection and report generation
- Tauri command `generate_compliance_report` for GUI integration
- Compliance page route `/compliance` with navigation link

### Added (continued)
- CSS Variables for consistent theming (colours, typography, spacing)
- JetBrains Mono for data/code, Inter for UI text
- Colour-coded security states (green/amber/red for good/warning/critical)
- Horizontal navigation bar with hover effects
- Security score circular gauge with glow effects
- Styled buttons, tables, forms, badges, and empty states
- Foundation styles for 3-page architecture: Dashboard, Analysis (tabbed), Hardening (sectioned)
- **WASM-Compatible Types Crate**: New `hardener-types` crate for shared type definitions
  - Extracted all shared types (PluginId, Severity, Finding, ScanResult, etc.) to dedicated crate
  - WASM-safe dependencies only (serde, chrono)
  - Enables GUI frontend to compile to `wasm32-unknown-unknown` target
- **PDF Feature Gate**: krilla PDF library now behind optional `pdf` feature in hardener-compliance
- **WASM Entry Point**: Added `#[wasm_bindgen(start)]` entry point for Leptos app mounting
- `.cargo/config.toml` for WASM rustflags (getrandom backend configuration)
- `crates/hardener-ui/styles.css` - Complete dark terminal theme CSS (~2700 lines)

### Added (v0.3.0 Features)
- **SSH Remote Scanning**: Scan, apply, and rollback on remote hosts via SSH
- `SystemExecutor` trait for abstracting local/remote operations
- `LocalExecutor` implementation (wraps std::fs and std::process)
- `SshExecutor` implementation (uses openssh crate for remote operations)
- `MockExecutor` implementation for unit testing without filesystem access
- CLI SSH flags: `--ssh`, `--ssh-key`, `--port`, `--ssh-timeout`, `--ssh-no-verify`
- `SshConnectionConfig` helper for CLI argument parsing
- SSH remote scanning user guide (`docs/SSH_REMOTE_SCANNING.md`)
- Context now holds executor via `ctx.executor()` accessor
- 94 new mock-based unit tests for plugin testing
- SSH integration tests (Docker-compatible)
- `testing.rs` module with `MockPlugin` builder for test infrastructure
- **Scheduled Scanning (Phase 1 + 1.5)**: Foundation for scheduled security scans
- `hardener-scheduler` crate with configuration, SQLite storage, JSON output, and scan orchestration
- `SchedulerConfig` structs for TOML configuration
- `ScanHistoryManager` for SQLite scan history storage
- `JsonStore` for timestamped JSON file output with SHA-256 integrity hashing
- `ScanRunner` for orchestrating plugin scans with database and JSON persistence
- `TriggerType` enum (Scheduled, Manual, Systemd) for session tracking
- `ScanSummary` struct for notification payloads with severity counts
- `SeverityCounts` shared helper for consistent severity counting across crate
- Severity filtering with configurable minimum threshold
- Compliance mapping conversion for scheduled scan findings
- **Scheduled Scanning Daemon**: Cron-based scheduling with graceful shutdown
- `Daemon` struct with tokio-cron-scheduler for automated scans
- Signal handling (SIGTERM, SIGINT) for graceful daemon shutdown
- Atomic scan guard to prevent overlapping scans
- CLI daemon commands: `hardener daemon start`, `run-once`, `status`
- Scan history display with session ID, status, trigger type, and severity counts
- **Notification System**: Email and webhook notifications for scan results
- `Notifier` trait with `NotificationResult` for consistent notification handling
- `EmailNotifier` implementation using lettre for SMTP delivery
- `WebhookNotifier` for Slack, Discord, and generic HTTP endpoints
- `NotificationDispatcher` for coordinating multiple notification channels
- Configurable severity thresholds for notification triggers
- **Systemd Integration**: Generate and manage systemd unit files
- `SystemdGenerator` for creating `.service` and `.timer` unit files
- `cron_to_calendar()` function for cron-to-systemd calendar conversion
- CLI commands: `hardener systemd generate`, `install`, `uninstall`, `status`
- Security hardening directives in generated service unit (NoNewPrivileges, ProtectSystem, etc.)
- Support for both system and user service installation
- **History CLI Commands**: View and export scan history
- CLI commands: `hardener history list`, `show`, `export`
- Session filtering by host, status, and limit
- JSON export for session data and findings

### Documentation
- Added `docs/SSH_REMOTE_SCANNING.md` - comprehensive user guide for SSH remote scanning

### CI/CD Status
- GitHub Actions CI/CD workflows connected and functional
- Runs on push/PR to `main`: check, test, clippy, fmt, security audit, multi-platform builds
- GitLab CI also functional for builds and releases

## [0.3.2] - 2025-12-09

GUI major redesign with dark terminal theme, responsive layouts, accessibility improvements (WCAG AA contrast, WAI-ARIA tabs, skip link), and multiple bug fixes including security score calculation, UFW false positives, audit rules false positives, and checkpoint visibility.

## [0.3.1] - 2025-12-05

GUI polish pass: CSS transitions, empty state icons, button hover effects, fluid typography, reusable Card component, and E2E test cases TC-11 through TC-14.

## [0.3.0] - 2025-12-01

Remote SSH scanning (`--ssh` flag), scheduled scanning daemon with cron-based scheduling, notification system (email via SMTP, webhooks for Slack/Discord), systemd integration for service/timer generation, and scan history CLI commands.

## [0.2.0] - 2025-11-28

Configuration file support with layered loading, compliance framework reporting (CIS, STIG, NIST 800-53, PCI-DSS, HIPAA, GDPR), PDF report generation, interactive report wizard, and CSV/HTML output formats.

## [0.1.0] - 2025-11-25

### Added

#### Core Infrastructure
- Plugin trait system for modular security checks
- Plugin manager with dependency resolution and topological sorting
- Distribution detection (Debian, Red Hat, Arch, SUSE families)
- Package manager abstraction (apt, dnf, pacman, zypper)
- Checkpoint system with SQLite storage
- Ed25519 cryptographic signatures for checkpoints
- Hash chain audit logging with tamper detection
- Full plugin rollback integration with checkpoint system

#### Security Plugins (8 Total)
- **Kernel Hardening**: 12 sysctl security parameters (ASLR, ptrace, dmesg, etc.)
- **SSH Hardening**: 8 SSH configuration directives with secure defaults
- **Firewall Hardening**: firewalld/nftables/ufw backend support
- **PAM Hardening**: Password policies and authentication configuration
- **Services Minimisation**: Disable unnecessary services
- **Audit Hardening**: auditd configuration and rules
- **Permissions Hardening**: File permission security checks
- **MAC Hardening**: SELinux/AppArmor detection and status

#### Command Line Interface
- `hardener scan` - Scan system for security issues
- `hardener apply` - Apply hardening recommendations
- `hardener report` - Generate compliance reports
- `hardener checkpoint` - Manage system checkpoints
- `hardener plugins` - List available plugins
- Severity filtering and JSON output support

#### Compliance Report Generation
- **CIS Benchmark** framework (35+ controls)
- **STIG** framework - DISA Security Technical Implementation Guides (20+ controls)
- **NIST 800-53** framework - US Federal security controls (20+ controls)
- **PCI-DSS v4.0** framework - Payment Card Industry standards (20+ controls)
- **HIPAA** Security Rule framework (15+ controls)
- **GDPR** Article 32 framework (12+ controls)
- Output formats: Text, JSON, CSV, HTML

#### User Interface
- Tauri-based desktop application
- Leptos (Rust) frontend with reactive state
- Dashboard with security score
- Scanner page with real-time progress
- Configuration page for plugin selection
- Results page with severity filtering
- Checkpoints page for rollback management

#### Developer Tools
- Naming convention validator script
- Pre-commit hook for validation
- Comprehensive test suite (220 tests)

### Security
- Disabled unused sqlx database backends (mysql, postgres) to reduce attack surface

### Test Coverage
- 48 plugin tests
- 59 core infrastructure tests
- 113 new unit/integration tests added
- >90% code coverage

### Known Limitations
- Some hardening requires system reboot
- SELinux/AppArmor policies detected but not fully managed
- Certain checks require root privileges
- Wayland/GBM issues on some Linux configurations

### Dependencies
- Rust 1.85+
- Tauri 2.0
- Leptos 0.8
- SQLite (via sqlx)
- tokio async runtime

---

## Version History

- **1.2.1** (2026-07-01): Documentation / version-badge consistency patch
- **1.2.0** (2026-07-01): CIS compliance coverage completion, PAM/permissions no-loosen hardening, polkit DE test tooling, security dependency fixes
- **1.0.5** (2026-05-24): Security dependency pass (tauri 2.11.2, lettre 0.11.22, rustls-webpki 0.103.13), cargo-deny gate
- **1.0.4** (2026-04-15): Rust edition 2024 migration
- **1.0.3** (2026-02-28): Parallel test runners, GUI test selector fixes for TabBar component
- **1.0.2** (2026-02-28): CLI crash fixes, desktop UX enhancements (keyboard nav, ARIA, clipboard, 95 tests)
- **1.0.1** (2026-02-27): AUR source checksum fix
- **1.0.0** (2026-02-27): First stable production release
- **0.3.3** (2026-02-25): Distribution validation complete (5 distributions across 4 families)
- **0.3.2** (2025-12-09): GUI major redesign, bug fixes, accessibility
- **0.3.1** (2025-12-05): GUI polish and testing
- **0.3.0** (2025-12-01): Remote SSH scanning, scheduled scanning, notifications
- **0.2.0** (2025-11-28): Compliance frameworks, PDF reports, configuration system
- **0.1.0** (2025-11-25): Initial development release

[Unreleased]: https://github.com/tidynest/linux-system-hardener/compare/v1.5.1...HEAD
[1.5.1]: https://github.com/tidynest/linux-system-hardener/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/tidynest/linux-system-hardener/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/tidynest/linux-system-hardener/compare/v1.3.2...v1.4.0
[1.3.2]: https://github.com/tidynest/linux-system-hardener/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/tidynest/linux-system-hardener/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/tidynest/linux-system-hardener/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/tidynest/linux-system-hardener/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/tidynest/linux-system-hardener/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.5...v1.2.0
[1.0.5]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/tidynest/linux-system-hardener/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.3...v1.0.0
[0.3.3]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/tidynest/linux-system-hardener/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tidynest/linux-system-hardener/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tidynest/linux-system-hardener/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tidynest/linux-system-hardener/releases/tag/v0.1.0

**Last Updated**: 2026-08-01
