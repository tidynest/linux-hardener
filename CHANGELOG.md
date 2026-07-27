# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
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
- `hardener rollback` now restores what the services plugin changed. That
  plugin checkpointed `/etc/systemd/system` and `/usr/lib/systemd/system`,
  neither of which was in the rollback allow-list, and rollback validates every
  captured path before writing anything, so it aborted with "path outside
  allowed directories" and restored nothing at all. Services rollback had never
  worked. `/etc/systemd/system` is now allow-listed, and the packaged unit
  directory is no longer captured: nothing this tool does writes there, and
  keeping it out means a restore can never overwrite a distribution's unit
  files with copies taken before a package update.
- An `sshd_config` directive inside a `Match` block is no longer read as the
  host's global setting. `Match Address 10.0.0.0/8` followed by
  `PermitRootLogin no` was read back as though root login were closed
  everywhere. Apply then found the target value apparently in place, wrote
  nothing and recorded no change at all, leaving the real global directive at
  sshd's compiled default while the tool reported the host compliant.
- `hardener apply --plugin <name>` refuses a name that matches no plugin,
  as `scan` already did. It previously dropped such names, so
  `hardener apply -p services` (the plural of a real plugin, matching nothing)
  hardened nothing, printed nothing and exited 0. The same applies to
  `batch apply` and `batch rollback`.
- The audit plugin no longer overwrites its rules file after a backup that
  failed. The backup ran only when an existence probe returned true, so a probe
  that errored skipped it, and the `cp` exit code was never checked, so a failed
  copy reported success and the write went ahead. A failed backup now aborts
  before the write.
- A failed service listing is reported instead of read as a clean host. It
  degraded to zero findings, which is byte-identical to a host with nothing
  wrong; every managed service is now reported as unchecked so a compliance
  report renders ManualReview.
- A critical path whose permissions cannot be read is reported as unchecked.
  `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/passwd`, `/root` and
  `/etc/ssh` previously produced neither a finding nor an unchecked entry when
  unreadable, which is silence indistinguishable from a verified clean result.
- `LocalExecutor::path_exists` distinguishes "absent" from "could not tell".
  It answered with `Path::exists`, which folds every error into `false`, so a
  path the process could not stat read as confirmed absence. That left the
  rollback guard protecting the account databases unreachable on a local target.
- A plugin that reports its own scan failed is named in the output rather than
  rendering as a plugin with no findings.
- The CLI installs a log subscriber. Without one the tracing macros were a
  no-op, so every warning the engine raised was discarded, including warnings
  that have no `Change` counterpart and were the only record that a step
  degraded. Records go to stderr, so `--format json` stays parseable.
- `--format json` output is a single document again. An informational message
  was written to stdout ahead of the payload, so a strict parser rejected the
  whole stream with "Extra data" even though the payload itself was well formed.

### Known issues
- `scan --format json` still omits `scan_success` and `scan_error`, so a
  consumer of the JSON cannot yet distinguish a plugin whose scan failed from a
  compliant host. The text output now names such a plugin.

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

### Added
- Build identity in version output: `hardener --version` and a quiet chip
  beside the desktop wordmark now show the git short SHA and build date
  alongside the semantic version, so a stale installed build is visible at
  a glance. Tarball builds without git report `release`;
  `SOURCE_DATE_EPOCH` is honoured for reproducible packaged builds.

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

### Added
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

### Fixed
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

### Fixed
- **Remote checkpoint capture and restore now operate on the remote host.**
  Previously, `apply --ssh` and `rollback --ssh` would snapshot and restore files
  on the controller rather than the target. Checkpoint operations now run through
  the active `SystemExecutor`, so remote sessions correctly read and write files on
  the remote. Checkpoints are keyed by host; rollback refuses to restore one host's
  checkpoint onto another.

### Changed
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

### Fixed
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

### Changed
- Test suite expanded from 220 to 428+ tests (95% increase)
- PDF findings now display with better visual hierarchy and spacing
- All 8 plugins converted to async with `#[async_trait]`
- HardeningPlugin trait methods now async: `scan()`, `apply()`, `rollback()`, `validate()`
- **hardener-ui** now depends only on `hardener-types` (removed hardener-core, hardener-common, hardener-compliance dependencies)
- Types re-exported from source crates for backwards compatibility

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

[Unreleased]: https://github.com/tidynest/linux-system-hardener/compare/v1.2.1...HEAD
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

**Last Updated**: 2026-07-27
