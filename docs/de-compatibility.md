# Desktop Environment Compatibility

Linux System Hardener uses `pkexec` (polkit) for privilege escalation when
applying hardening rules or rolling back checkpoints. This requires a running
polkit authentication agent that presents the password dialog.

## Polkit Agent Requirements

| Desktop | Agent Process | Package (Arch) | Package (Fedora) | Package (Debian/Ubuntu) | Notes |
|---------|--------------|----------------|-------------------|------------------------|-------|
| GNOME (Wayland) | gnome-shell (built-in) | -- | -- | -- | No additional package needed |
| GNOME (Xorg) | polkit-gnome-authentication-agent-1 | polkit-gnome | polkit-gnome | policykit-1-gnome | Must be running in session |
| KDE Plasma | polkit-kde-authentication-agent-1 | polkit-kde-agent | polkit-kde | polkit-kde-agent-1 | Started by plasma-session |
| XFCE | xfce-polkit | xfce-polkit | xfce-polkit | xfce4-session (included) | Add to Session autostart |
| XFCE (fallback) | polkit-gnome-authentication-agent-1 | polkit-gnome | polkit-gnome | policykit-1-gnome | If xfce-polkit unavailable |
| Hyprland | polkit-gnome-authentication-agent-1 | polkit-gnome | polkit-gnome | policykit-1-gnome | Add to hyprland.conf exec-once |
| Sway | polkit-gnome-authentication-agent-1 | polkit-gnome | polkit-gnome | policykit-1-gnome | Add to sway config exec |
| i3 | polkit-gnome-authentication-agent-1 | polkit-gnome | polkit-gnome | policykit-1-gnome | Add to i3 config exec |

## Autostart Configuration

Tiling window managers and some XFCE installations do not autostart a polkit
agent. Add one of these lines to your compositor/WM config:

**Hyprland** (`~/.config/hypr/hyprland.conf`):
```
exec-once = /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
```

**Sway** (`~/.config/sway/config`):
```
exec /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
```

**i3** (`~/.config/i3/config`):
```
exec --no-startup-id /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
```

**XFCE** (if no agent is running):
Settings -> Session and Startup -> Application Autostart -> Add:
- Name: Polkit Agent
- Command: `/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1`

## Polkit Policy Actions

The hardener registers two polkit actions:

| Action ID | Description | Default |
|-----------|-------------|---------|
| `com.tidynest.linux-hardener.apply` | Apply system hardening | auth_admin_keep (5 min cache) |
| `com.tidynest.linux-hardener.rollback` | Rollback hardening changes | auth_admin_keep (5 min cache) |

Both actions use `auth_admin_keep` for active sessions, which caches
credentials for approximately 5 minutes. This means users only need to
authenticate once when applying multiple operations in quick succession.

## Error Handling

| Scenario | pkexec Exit Code | Tauri Error Message |
|----------|-----------------|---------------------|
| Auth success | 0 | (none -- operation proceeds) |
| User cancels dialog | 126 | "Authentication cancelled. Root privileges are required for this operation." |
| No agent running | 127 | "No Polkit authentication agent found..." with install instructions |
| Binary not found | 127 | "Command failed: ..." |
| Permission denied | non-zero | "Command failed: ..." (sanitised) |

## Known Quirks

### GNOME
- The built-in agent on Wayland auto-focuses the password field
- On Xorg, the standalone `polkit-gnome` agent must be explicitly started
- GNOME 45+ changed dialog styling (rounded corners, header bar)

### KDE Plasma
- The agent reads `icon_name` from the policy file and displays it in the dialog
- The "Details" expander shows the action ID (`com.tidynest.linux-hardener.apply`)
- On Wayland, the dialog uses layer-shell and appears above all windows
- KDE system settings can override credential caching duration

### XFCE
- `xfce-polkit` was added in XFCE 4.18 -- older versions need polkit-gnome
- The agent is not always autostarted even when installed
- Dialog is plain GTK3 without XFCE-specific theming

### Tiling WMs (Hyprland, Sway, i3)
- No built-in polkit agent -- user must install and autostart one
- `polkit-gnome` is the most common choice (lightweight, no DE dependencies)
- `polkit-kde-agent` also works if KDE frameworks are already installed

## Testing

Run the diagnostic tool to check your system:

```bash
./scripts/detect-polkit-agent.sh
```

Run the full automated test matrix:

```bash
./scripts/test-polkit-matrix.sh
```

Run with interactive auth dialog tests:

```bash
./scripts/test-polkit-matrix.sh --interactive
```

Run DE-specific tests:

```bash
./scripts/test-polkit-gnome.sh --interactive   # GNOME session
./scripts/test-polkit-kde.sh --interactive     # KDE session
./scripts/test-polkit-xfce.sh --interactive    # XFCE session
./scripts/test-polkit-no-agent.sh              # No-agent fallback
```
