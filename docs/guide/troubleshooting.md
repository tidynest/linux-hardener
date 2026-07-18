# Troubleshooting

**Last Updated**: 2026-07-18

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

## Scan reports "permission denied" or looks incomplete

Scanning runs as a regular user for most checks, but some plugins (audit
rules, service status) return partial results without root. For the complete
picture:

```bash
sudo hardener scan
```

## The scheduled daemon refuses to start

`hardener daemon start` exits immediately when the scheduler is disabled.
Set `enabled = true` in the `[scheduler]` section of the config file; see the
[configuration reference](../reference/configuration.md#scheduler).

## Docker scan reports tools as unavailable

Inside the container, `systemctl`/D-Bus-dependent checks (services, parts of
audit/MAC/firewall) cannot see the host's service manager and report
tool-unavailable findings instead. Treat those findings as unverifiable
in-container rather than as host truth. Widen filesystem coverage with more
read-only mounts; `apply` is unsupported in a container by design. See the
[Docker section of the installation guide](installation.md#run-with-docker-scan-and-report-only).
