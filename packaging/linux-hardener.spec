Name:           linux-hardener
Version:        1.7.0
Release:        1%{?dist}
Summary:        Linux security automation: scanning, hardening, and rollback
License:        Apache-2.0
URL:            https://github.com/tidynest/linux-hardener
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  cargo rust gcc openssl-devel libxcb-devel libxkbcommon-devel
BuildRequires:  gtk3-devel webkit2gtk4.1-devel pkg-config librsvg2-devel
BuildRequires:  desktop-file-utils trunk

Requires:       glibc openssl-libs gtk3 libxcb libxkbcommon systemd
Requires:       polkit
Recommends:     polkit-gnome
Supplements:    (polkit-kde-agent and plasma-workspace)

# Carries an existing install across the rename from linux-system-hardener
# (#51). Obsoletes drives the upgrade, Provides keeps the old name
# satisfiable for anything that requires it. Left unversioned, matching the
# equivalent PKGBUILD (`replaces`/`conflicts`/`provides`) and debian/control
# (`Replaces`/`Breaks`/`Provides`) entries: the rename commit (2026-08-07)
# postdates the last version ever released under the old name (v1.5.1,
# 2026-07-27), so linux-system-hardener will never see another release and
# there is no future threshold to encode. Do not add a version bound here
# that tracks this file's own Version: field above; a release script owns
# that field and does not know about this line.
Obsoletes:      linux-system-hardener
Provides:       linux-system-hardener = %{version}-%{release}

%description
Linux Hardener automates security through scanning, hardening, and
safe rollback across 8 security domains (kernel, SSH, firewall, PAM, audit,
MAC, permissions, services) with multi-distribution support.

%prep
%setup -q

%build
# Strip GCC LTO from CFLAGS - incompatible with Rust linkers
export CFLAGS="${CFLAGS//-flto=auto/}"
export CXXFLAGS="${CXXFLAGS//-flto=auto/}"

# Build CLI (static musl)
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli

# Build WASM frontend (Tauri embeds from dist/)
cd crates/hardener-ui && trunk build --release --public-url="." && cd ../..

# Build desktop app
cd src-tauri && cargo build --release --features tauri/custom-protocol

%install
install -Dm755 target/x86_64-unknown-linux-musl/release/hardener \
    %{buildroot}%{_bindir}/hardener

# Desktop binary + wrapper (WebKit Wayland workaround)
install -Dm755 src-tauri/target/release/linux-hardener-desktop \
    %{buildroot}%{_libdir}/linux-hardener/linux-hardener-desktop
cat > %{buildroot}%{_bindir}/linux-hardener-desktop << 'WRAPPER'
#!/bin/sh
export WEBKIT_DISABLE_COMPOSITING_MODE=1
exec /usr/lib/linux-hardener/linux-hardener-desktop "$@"
WRAPPER
chmod 755 %{buildroot}%{_bindir}/linux-hardener-desktop

install -Dm644 packaging/systemd/linux-hardener.service \
    %{buildroot}%{_unitdir}/linux-hardener.service
install -Dm644 packaging/systemd/linux-hardener.timer \
    %{buildroot}%{_unitdir}/linux-hardener.timer

install -Dm644 packaging/assets/linux-hardener.desktop \
    %{buildroot}%{_datadir}/applications/linux-hardener.desktop

install -Dm644 packaging/assets/hardener.1 \
    %{buildroot}%{_mandir}/man1/hardener.1

install -Dm644 packaging/assets/com.tidynest.linux-hardener.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/com.tidynest.linux-hardener.policy

install -Dm644 packaging/assets/config.toml.example \
    %{buildroot}%{_docdir}/%{name}/config.toml.example
install -Dm644 packaging/assets/config.toml.example \
    %{buildroot}%{_sysconfdir}/linux-hardener/config.toml

install -d -m 755 %{buildroot}%{_sysconfdir}/linux-hardener
install -d -m 700 %{buildroot}%{_localstatedir}/lib/linux-hardener
install -d -m 700 %{buildroot}%{_localstatedir}/log/linux-hardener

%post
systemctl daemon-reload || true

%preun
systemctl stop linux-hardener.timer 2>/dev/null || true
systemctl disable linux-hardener.timer 2>/dev/null || true

%postun
systemctl daemon-reload || true

%files
%license LICENSE
%doc README.md
%doc packaging/assets/config.toml.example
%{_bindir}/hardener
%{_bindir}/linux-hardener-desktop
%{_libdir}/linux-hardener/linux-hardener-desktop
%{_unitdir}/linux-hardener.service
%{_unitdir}/linux-hardener.timer
%{_datadir}/applications/linux-hardener.desktop
%{_mandir}/man1/hardener.1*
%{_datadir}/polkit-1/actions/com.tidynest.linux-hardener.policy
%config(noreplace) %{_sysconfdir}/linux-hardener/config.toml
%dir %{_sysconfdir}/linux-hardener
%dir %attr(700,root,root) %{_localstatedir}/lib/linux-hardener
%dir %attr(700,root,root) %{_localstatedir}/log/linux-hardener
%dir %{_libdir}/linux-hardener

%changelog
* Sat Aug 29 2026 Eric Jingryd <tidynest@proton.me> - 1.7.0-1
- Added: the Analysis tab names any registered plugin that produced no result. A domain nobody scanned shows no findings, which looks the same as a clean one; the CLI has always said so on stderr, which the desktop discards
- Fixed: a scan whose every selected plugin the configuration disables is refused with the CLI's own wording, rather than returning an empty result the interface rendered as "No findings yet"
- Fixed: a hardening preview that could stage nothing no longer claims the host is already compliant. Zero changes has two causes and only one is good news; the per-area rows already drew that distinction and the summary beneath them did not
- Fixed: the preview says that it runs unprivileged while Apply does not, which is why a privileged scan and the preview beneath it can disagree
- Fixed: every packaging shipped /var/lib/linux-hardener at 0755 while the code sets it to 0700 on first use. No install was exposed, since the directory is empty until then, but the packaged mode contradicted the enforced one

* Fri Aug 28 2026 Eric Jingryd <tidynest@proton.me> - 1.6.0-1
- Security: a compliance report can no longer be scored from a hand-flattened scan. The rule that stops a control passing on silence sat in front of the report generator, so every caller had to remember it and one did not; a fleet row scanned with one plugin reported the same 38 passing CIS controls as a row scanned with all eight. The generator now flattens the scan results itself and there is no flattened pair a new caller can hand to scoring. Regenerate any report kept, filed or forwarded
- Security: hardener systemd install put a root timer on the host and recorded nothing, and uninstall took it away in the same silence. Both are audited now, and the unit files are written atomically so a daemon-reload cannot read a half-written unit
- Security: two files sharing a stem in one directory shared a temporary write path, so concurrent writes could interleave
- Security: the desktop wrote three kinds of host state in process and recorded none of them. All three are audited and atomic now
- Security: exception add and exception remove wrote a root-owned configuration without an audit entry
- Security: an unprivileged scan and a root apply silently resolved different configuration sources, and a source that could not be reached was indistinguishable from one that was empty
- Added: hardener scope exclude|include, declaring a compliance control not applicable to this host, with the declaration itself audited
- Added: a finding can be accepted as a documented policy exception without editing the configuration by hand, from the CLI or the Analysis tab
- Added: multi-host SSH fleet operations reach the desktop: fleet scan with per-host compliance columns, fleet apply behind a mandatory dry run and confirmation, and per-host history
- Changed: remote checkpoints capture and restore over SSH, keyed by host, and a cross-host rollback is refused
- 978 non-merge commits since 1.5.1. The full list is in CHANGELOG.md

* Mon Jul 27 2026 Eric Jingryd <tidynest@proton.me> - 1.5.1-1
- Security: compliance reports could mark controls as passed for a plugin that produced no evidence. From the command line this needed a plugin's scan to fail; in the desktop it needed no failure at all, as disabling a plugin or scanning a subset was enough. Regenerate any report kept, filed or forwarded
- Security: on openSUSE, apply created a short /etc/login.defs, /etc/security/faillock.conf and /etc/security/pwhistory.conf, which mask the vendor files under /usr/etc whole rather than per setting; 35 settings including ENCRYPT_METHOD and UMASK silently stopped applying. Apply now refuses to create these files rather than masking the vendor copy
- A drop-in under /etc/ssh/sshd_config.d/ no longer silently overrides what the tool wrote; scan reports the value sshd will actually use and names the file supplying it
- An sshd_config directive inside a Match block is no longer read as the host's global setting
- hardener rollback now restores what the services plugin changed; the systemd unit directory was missing from the rollback allow-list, so it aborted without restoring anything
- A failed signing-key migration can no longer destroy the key, taking the tamper-evidence of every existing checkpoint with it
- Changed: scan --exit-code exits non-zero on an incomplete scan as well as on findings, so a CI gate can fail where it previously passed
- Changed: a plugin disabled in its own config section now actually stops running
- Removed: scan --compliance, which never did anything; hardener report --framework <id> is the compliance path
* Mon Jul 27 2026 Eric Jingryd <tidynest@proton.me> - 1.5.0-1
- Security: rollback over SSH could delete /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow and /etc/sudoers on a remote host whose stat output could not be parsed; the probe now fails closed and rollback refuses to delete a protected path that is present on the host
- Security: the PAM plugin could replace /etc/security/*.conf with a file containing only its own directives when the original could not be read; a read failure is now distinguished from an absent file and apply refuses to rewrite what it could not read
- Security: password ageing was never applied and was then reported as compliant; /etc/login.defs was written as "KEY = value", which the file does not accept, and the reader carried the matching fault. PASS_MAX_DAYS, PASS_MIN_DAYS and PASS_WARN_AGE now take effect. Re-apply on hosts hardened by an earlier release
- Desktop UI redesigned end to end: grouped left sidebar with a collapsible rail, the Remote and Fleet screens merged into one Hosts page, a staged Fleet Apply flow, and a new Settings page with a seven-theme picker
- hardener scan now honours the configuration file: directive overrides apply, and a finding covered by a valid exception is annotated rather than reported as a plain violation
- Rollback is now reversible: the current state is captured as a signed checkpoint before any restore, and a rollback that cannot be captured is refused
- New differential test suite verifies hardening against the system's own readers (sshd -T, chage -l) rather than against this tool's parser

* Sun Jul 19 2026 Eric Jingryd <tidynest@proton.me> - 1.4.0-1
- Honest apply counts: "N applied" tallies only real changes; no-op plugins read "no changes needed"; failures surfaced
- Idempotent, state-aware apply across all 8 plugins (already-compliant settings skipped; no duplicate nftables rules; ssh/audit not rewritten when unchanged)
- Honest unchecked reporting: privilege-blocked checks render as per-plugin "could not verify" entries, not false findings; /boot on a vfat ESP reports fstab guidance
- Deep scan moves the score: desktop compliance report and security score derive from the latest persisted scan session
- Remote/SSH: privilege gate probes the executor session; PermitRootLogin lockout guard over remote root; ad-hoc hostname validation with real connect errors; coloured per-host batch output
- CLI: checkpoint list --limit/--all; report wizard score display and output-path fix
- Desktop: rate-limit banner auto-dismisses; shared deep-scan button; pkexec cancel is not an error

* Sat Jul 18 2026 Eric Jingryd <tidynest@proton.me> - 1.3.2-1
- Fix: runtime sysctl writes failed on every local apply (atomic rename is impossible on procfs)
- Fix: firewall drove an installed-but-inactive ufw instead of the active nftables backend
- Fix: audit rule re-apply collided with already-loaded rules (flush and retry on duplicate)
- Fix: audit reload reports a reboot-required skip when the audit config is immutable (-e 2)
- Fix: partial-failure applies now surface per-plugin errors in the desktop and CLI output
- Fix: findings-tab dropdowns and recent-activity skip counts in the desktop app

* Sat Jul 18 2026 Eric Jingryd <tidynest@proton.me> - 1.3.1-1
- Fix: build identity stamped an unrelated repository's commit into --version
  when the tarball was extracted inside a foreign git checkout
- Packaging: PKGBUILD pins CARGO_TARGET_DIR inside the build root

* Sat Jul 18 2026 Eric Jingryd <tidynest@proton.me> - 1.3.0-1
- RHEL 10 compliance profiles: report-time STIG/CIS identifier translation (--profile override)
- New frameworks: SOC 2, NIST 800-171 r3, FedRAMP Moderate (10 frameworks total)
- Scan performance: concurrent plugin execution (~25ms to ~10ms local), scan --timings flag
- Fix: services existence probe matched nothing, causing false PASS on CIS 2.2.3/2.2.4
- Fix: apply no longer fails, or reports a fabricated change, on hosts without SELinux/AppArmor
- New ChangeType::Skipped: no-op applies report as skips, not applied changes
- Per-command Tauri ACLs: build.rs declares the command allow-list, granted by risk tier
- Docker image (scratch, static musl CLI); build identity (git SHA + date) in --version
- Docs restructured under docs/{guide,reference,architecture,contributing,design,security}
- Scripts consolidated under scripts/ with a shared helper library

* Thu Jul 02 2026 Eric Jingryd <tidynest@proton.me> - 1.2.2-1
- Fix: checkpoint rollback could delete 0000-permission files (e.g. /etc/shadow, /etc/gshadow)
- Fix: permissions apply/rollback aborted when account-database paths were not allow-listed
- Security: accept RUSTSEC-2026-0097 (rand unsound; build-time transitive, first-party key-gen on rand 0.9)

* Tue Jul 01 2026 Eric Jingryd <tidynest@proton.me> - 1.2.1-1
- Documentation and README version-badge consistency (patch on 1.2.0)

* Tue Jul 01 2026 Eric Jingryd <tidynest@proton.me> - 1.2.0-1
- CIS compliance coverage completion (11 controls moved off ManualReview)
- PAM faillock/pwhistory and shadow/gshadow no-loosen hardening
- Polkit desktop-environment test tooling; polkit runtime dependency
- Security: fix RUSTSEC-2026-0190 (anyhow), accept RUSTSEC-2026-0192 (ttf-parser)

* Tue Jul 01 2026 Eric Jingryd <tidynest@proton.me> - 1.1.0-1
- Version alignment to 1.1.0

* Sun May 24 2026 Eric Jingryd <tidynest@proton.me> - 1.0.5-1
- v1.0.5: Security - patch tauri (CVE-2026-42184), lettre (RUSTSEC-2026-0141),
  and rustls-webpki (RUSTSEC-2026-0104) advisories

* Wed Apr 15 2026 Eric Jingryd <tidynest@proton.me> - 1.0.4-1
- v1.0.4: Rust edition 2024; dependency refresh

* Fri Feb 28 2026 Eric Jingryd <tidynest@proton.me> - 1.0.3-1
- v1.0.3: Parallel test runners, GUI test selector fixes

* Fri Feb 28 2026 Eric Jingryd <tidynest@proton.me> - 1.0.2-1
- v1.0.2: CLI crash fixes, desktop UX (keyboard nav, ARIA, clipboard)
- Added trunk build dependency for WASM frontend
- Added wrapper script for WebKit Wayland workaround
- Added polkit runtime dependency

* Fri Feb 27 2026 Eric Jingryd <tidynest@proton.me> - 1.0.0-1
- v1.0.0 release: 8 hardening plugins, CLI + GUI, multi-distro support

* Tue Feb 25 2026 Eric Jingryd <tidynest@proton.me> - 0.3.3-1
- Initial RPM packaging
