# Troubleshooting

**Last Updated**: 2026-07-30

Symptom-organised fixes for the most common problems. Installation steps live
in the [installation guide](installation.md); the per-desktop polkit agent
matrix and autostart snippets live in the
[desktop environment compatibility guide](desktop-environment-compatibility.md).

---

## The GUI fails to launch

The desktop app needs GTK 3 and WebKit2GTK 4.1. Check they are installed:

```bash
# Arch
pacman -Q gtk3 webkit2gtk-4.1

# Fedora
rpm -q gtk3 webkit2gtk4.1

# Debian/Ubuntu
dpkg -l libgtk-3-0t64 libwebkit2gtk-4.1-0
```

Install the missing package with your distribution's package manager, then
relaunch.

## The GUI "Apply" button shows an authentication error

Applying hardening runs through `pkexec`, which needs a running polkit
authentication agent to show the password dialog. Most desktop environments
start one automatically; tiling window managers (Hyprland, Sway, i3) and some
XFCE setups do not.

```bash
# Diagnose: checks for an agent and the installed policy
./scripts/test/polkit/detect-polkit-agent.sh

# Quick fix on Arch: install and start an agent
sudo pacman -S polkit-gnome
/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
```

To make the agent permanent, add it to your compositor or session autostart;
the exact lines for Hyprland, Sway, i3, and XFCE are in the
[desktop environment compatibility guide](desktop-environment-compatibility.md#autostart-configuration).

### What the error message means

The GUI maps `pkexec` outcomes to messages as follows:

| Scenario | pkexec exit code | Error message |
|----------|-----------------|---------------|
| Authentication succeeded | 0 | (none: operation proceeds) |
| You cancelled the dialog | 126 | "Authentication cancelled. Root privileges are required for this operation." |
| No agent running | 127 | "No Polkit authentication agent found..." with install instructions |
| Binary not found | 127 | "Command failed: ..." |
| Permission denied | non-zero | "Command failed: ..." (sanitised) |

## The systemd timer is not running scans

```bash
systemctl status linux-hardener.timer
journalctl -u linux-hardener.service --since today
```

If the timer unit is missing, install it: `sudo hardener systemd install`
followed by `sudo systemctl enable --now linux-hardener.timer`.

## Scan shows dimmed "unchecked" entries or looks incomplete

Scanning runs as a regular user, but some checks need root to read protected
files or query the service manager (PAM, SSH, firewall, audit, MAC and file
permissions are the usual ones). Rather than guess and raise a false finding,
the scan lists each privilege-blocked check as a dimmed "unchecked" entry under
its plugin - deduplicated per plugin - and prints a footer such as
`3 check(s) require root; run with sudo for a full scan`. With `--format json`
these arrive in a separate `unchecked` array, never mixed into `findings`.

Not every unchecked entry is a privilege problem, and the footer says so. A
plugin disabled in the config, a path on a filesystem with no POSIX permission
bits, or a probe that failed for its own reasons all appear here too, and
re-running as root changes nothing for them. Where none of the entries wants
privilege the footer reads `N check(s) could not be verified` and offers no
sudo; on a mixed run it names how many of the total root would reach. Read the
reason printed beside each entry before reaching for sudo.

For the complete picture, re-run as root:

```bash
sudo hardener scan
```

## Scan flags /boot (or another FAT partition) but apply cannot fix it

When /boot is the EFI System Partition it is normally formatted vfat (FAT32),
which cannot hold POSIX permission bits. `chmod` there silently no-ops, so the
scan does not raise a false HIGH "insecure permissions" finding and apply does
not attempt a futile change: /boot is reported as an "unchecked" entry with
fstab guidance instead. Harden the mount rather than the mode - add mask
options to the /boot line in `/etc/fstab`, for example `fmask=0077,dmask=0077`,
then remount. The same handling covers msdos, exfat, ntfs, iso9660 and udf
mounts.

## Scan reports a permissions finding under /usr/etc, and apply changes nothing

openSUSE keeps its packaged configuration under `/usr/etc` and reserves `/etc`
for administrator overrides, and Fedora is moving the same way. On such a host a
critical file can be missing from `/etc` while the copy actually in force sits
under `/usr/etc`, so when `/etc` holds nothing the scan reads the vendor copy
rather than concluding there is nothing to check. Where that copy violates its
required mode the finding names it. On openSUSE, `/etc/sudoers` does not exist,
`/usr/etc/sudoers` is mode 0444 and the directive requires 0440, so the sudo
policy is readable by every account on the host; earlier releases reported
nothing at all about it, which let a Critical control pass on evidence nobody had
collected.

`apply` deliberately does nothing for such a path and `apply --dry-run` previews
no change for it, so `scan` is the only command that mentions it. Apply looking
idle here is the designed outcome rather than a bug: the vendor file belongs to a
package, so a mode this tool set there would be reverted by the next package
update, and `/etc` is where a layering distribution expects a deviation to be
stated. The remediation is therefore one you perform yourself, and the finding
prints it as an `install` command that creates the `/etc` copy at the required
mode:

```bash
sudo install -o root -g root -m 0440 /usr/etc/sudoers /etc/sudoers
```

That copy takes precedence over the vendor file and survives package updates,
where editing `/usr/etc/sudoers` in place would not. Re-run `hardener scan`
afterwards and the finding is gone, because the path now exists under `/etc` and
is compliant, which also means `apply` can maintain its mode from then on.

Two neighbouring cases stay quiet for good reasons. A path absent from both
layers is genuinely nothing to report, which is what `/etc/gshadow` reads on
openSUSE, so no finding appears for a file the host does not have anywhere. A
vendor path whose existence or mode could not be determined becomes a dimmed
"unchecked" entry instead of a finding, because a probe that errored is not the
same answer as an absence.

## The scheduled daemon refuses to start

`hardener daemon start` exits immediately when the scheduler is disabled.
Set `enabled = true` in the `[scheduler]` section of the config file; see the
[configuration reference](../reference/configuration.md#scheduler).

## Fleet or batch SSH scans fail to authenticate

Remote hosts authenticate with an SSH key or agent only - there is no password
path. When a connection fails on authentication the error names the underlying
reason and appends a hint to load a key, for example
`(no usable SSH key - load one with ssh-add or configure a key file for this
host)`; genuine network failures (refused, timeout, no route) keep their own
reason and never get the key hint.

A desktop app launched from a menu or icon often does not inherit the
`SSH_AUTH_SOCK` of your login shell, so keys added with `ssh-add` are invisible
to it even though `ssh host` works in a terminal. Either set an explicit key
file for the host in the inventory, or start the GUI from a shell where
`echo $SSH_AUTH_SOCK` is non-empty. Ad-hoc `user@host[:port]` targets with
spaces or commas are rejected at entry, so a malformed target never reaches the
connection attempt.

## Apply fails over SSH with "Failed to determine metadata"

`hardener --ssh ... apply` prints something like `Failed to apply File
Permissions Hardening: System error: Failed to determine metadata for
/etc/passwd`, that plugin makes no changes, and the run still exits non-zero
even though other plugins in the same `apply --all` continue and may succeed.

The cause is on the remote host, not the local one: before changing anything,
apply takes a checkpoint of the paths it is about to touch, which needs a
working `stat` on the remote end. If `stat -c '%F %a %s %u %g' <path>` cannot
be run there (an incompatible build such as BusyBox, or a permission problem
reading the path) the checkpoint cannot be trusted, so apply refuses to guess
and stops before touching that path rather than risk a later `rollback`
deleting it.

Confirm the remote `stat` accepts that format and that the connecting user (or
its sudo) can read the path in question, then re-run. Nothing was changed by
the plugin that failed while you fix this.

## Docker scan reports tools as unavailable

Inside the container, `systemctl`/D-Bus-dependent checks (services, parts of
audit/MAC/firewall) cannot see the host's service manager and report
tool-unavailable findings or dimmed "unchecked" entries instead. Treat those
as unverifiable in-container rather than as host truth. Widen filesystem coverage with more
read-only mounts; `apply` is unsupported in a container by design. See the
[Docker section of the installation guide](installation.md#run-with-docker-scan-and-report-only).
