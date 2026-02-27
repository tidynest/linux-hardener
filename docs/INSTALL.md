# Installation Guide

## Requirements

- Linux kernel 5.4+
- x86_64 architecture
- One of: Arch, Debian 12+, Ubuntu 22.04+, Fedora 39+, RHEL/Rocky 9+, openSUSE Leap 15.5+

### GUI Requirements (optional)

The desktop application additionally requires:

- GTK 3
- WebKit2GTK 4.1
- A polkit authentication agent (GNOME, KDE, Hyprland, etc.)

---

## Install from Package (Recommended)

### Arch Linux / Manjaro / EndeavourOS

```bash
# From AUR (using your preferred AUR helper)
yay -S linux-system-hardener

# Or manually
git clone https://aur.archlinux.org/linux-system-hardener.git
cd linux-system-hardener
makepkg -si
```

### Fedora / RHEL 9+ / Rocky / AlmaLinux

```bash
# Install the RPM
sudo dnf install linux-system-hardener-*.rpm

# Or build from source RPM
rpmbuild -ba linux-system-hardener.spec
sudo dnf install ~/rpmbuild/RPMS/x86_64/linux-system-hardener-*.rpm
```

### Debian / Ubuntu / Linux Mint

```bash
# Install the .deb
sudo dpkg -i linux-system-hardener_*.deb
sudo apt-get install -f   # resolve dependencies

# Or build from source
dpkg-buildpackage -us -uc
sudo dpkg -i ../linux-system-hardener_*.deb
```

### openSUSE

```bash
# Install the RPM
sudo zypper install linux-system-hardener-*.rpm
```

---

## Install from Static Binary

A portable musl-linked binary works on any Linux distribution without dependencies:

```bash
# Download the latest release
curl -LO https://github.com/tidynest/linux-system-hardener/releases/latest/download/hardener-linux-x86_64-musl.tar.gz

# Extract
tar xzf hardener-linux-x86_64-musl.tar.gz

# Install system-wide
sudo install -Dm755 hardener /usr/bin/hardener

# Create required directories
sudo install -dm755 /etc/linux-hardener
sudo install -dm755 /var/lib/linux-hardener
sudo install -dm700 /var/log/linux-hardener

# Optional: install default config
sudo install -Dm644 data/config.toml.example /etc/linux-hardener/config.toml
```

---

## Install from Source

### Build Dependencies

**Arch:**
```bash
sudo pacman -S rust cargo trunk pkg-config openssl gtk3 webkit2gtk-4.1 libxcb libxkbcommon librsvg
```

**Fedora/RHEL:**
```bash
sudo dnf install cargo rust gcc openssl-devel libxcb-devel libxkbcommon-devel gtk3-devel webkit2gtk4.1-devel pkg-config librsvg2-devel
```

**Debian/Ubuntu:**
```bash
sudo apt-get install cargo rustc gcc libssl-dev pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libxcb1-dev libxkbcommon-dev librsvg2-dev
```

**openSUSE:**
```bash
sudo zypper install cargo rust gcc libopenssl-devel libxcb-devel libxkbcommon-devel gtk3-devel webkit2gtk-4_1-devel pkg-config librsvg-devel
```

### Build

```bash
git clone https://github.com/tidynest/linux-system-hardener.git
cd linux-system-hardener

# CLI only (static musl binary)
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli

# Desktop GUI
cd src-tauri && cargo build --release && cd ..

# Install
sudo install -Dm755 target/x86_64-unknown-linux-musl/release/hardener /usr/bin/hardener
sudo install -Dm755 src-tauri/target/release/linux-hardener-desktop /usr/bin/linux-hardener-desktop
```

---

## Post-Install Setup

### Create System Directories

Packages create these automatically. For manual installs:

```bash
sudo install -dm755 /etc/linux-hardener
sudo install -dm755 /var/lib/linux-hardener
sudo install -dm700 /var/log/linux-hardener
```

### Optional: Install Systemd Timer

Enable scheduled daily security scans:

```bash
# Using the built-in command
sudo hardener systemd install
sudo systemctl enable --now linux-hardener.timer

# Verify
sudo hardener systemd status
```

### Optional: Install Polkit Policy

Required for GUI privilege escalation. Packages install this automatically:

```bash
sudo install -Dm644 data/com.tidynest.linux-hardener.policy \
    /usr/share/polkit-1/actions/com.tidynest.linux-hardener.policy
```

### Optional: Install Desktop Entry

```bash
sudo install -Dm644 data/linux-hardener.desktop \
    /usr/share/applications/linux-hardener.desktop
```

---

## Verify Installation

```bash
# Check CLI
hardener --help

# Run a scan (no root required for scanning)
hardener scan

# Check version
hardener scan --format json 2>/dev/null | head -1
```

---

## Upgrading

### From Package Manager

Use your distribution's standard upgrade mechanism:

```bash
# Arch
yay -Syu linux-system-hardener

# Fedora/RHEL
sudo dnf upgrade linux-system-hardener

# Debian/Ubuntu
sudo apt-get upgrade linux-system-hardener

# openSUSE
sudo zypper update linux-system-hardener
```

### From Binary

Replace the binary and restart the timer if active:

```bash
sudo install -Dm755 hardener /usr/bin/hardener
sudo systemctl restart linux-hardener.timer 2>/dev/null || true
```

### Configuration

Upgrades preserve your configuration at `/etc/linux-hardener/config.toml`. New config options use built-in defaults until explicitly set. No manual migration is needed between patch or minor versions.

---

## Uninstalling

### From Package Manager

```bash
# Arch
sudo pacman -Rns linux-system-hardener

# Fedora/RHEL
sudo dnf remove linux-system-hardener

# Debian/Ubuntu
sudo apt-get remove --purge linux-system-hardener

# openSUSE
sudo zypper remove linux-system-hardener
```

### Manual Cleanup

After uninstalling, optionally remove state and configuration:

```bash
sudo rm -rf /etc/linux-hardener
sudo rm -rf /var/lib/linux-hardener
sudo rm -rf /var/log/linux-hardener
```

---

## Troubleshooting

### GUI fails to launch

Ensure GTK 3 and WebKit2GTK 4.1 are installed:

```bash
# Arch
pacman -Q gtk3 webkit2gtk-4.1

# Fedora
rpm -q gtk3 webkit2gtk4.1

# Debian/Ubuntu
dpkg -l libgtk-3-0t64 libwebkit2gtk-4.1-0
```

### GUI "Apply" button shows authentication error

A polkit authentication agent must be running. Most desktop environments provide one. For window managers (Hyprland, Sway, i3):

```bash
# Install and run a standalone polkit agent
# Arch
sudo pacman -S polkit-gnome
/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &
```

### Systemd timer not running

```bash
systemctl status linux-hardener.timer
journalctl -u linux-hardener.service --since today
```

### Permission denied on scan

Scanning runs as a regular user for most checks. Some plugins (audit rules, service status) may return partial results without root. For full results:

```bash
sudo hardener scan
```
