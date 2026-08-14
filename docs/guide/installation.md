# Installation Guide

**Last Updated**: 2026-08-10

## Requirements

- Linux kernel 5.4+
- x86_64 architecture
- systemd
- A distribution in one of the four detected families: Debian, Red Hat, Arch or
  SUSE. Detection is family-based, so any release in a family is routed the same
  way and a derivative works without a code change. The tested floors are Debian
  12+, Ubuntu 22.04+, Fedora 40+, RHEL 9+ (and rebuilds such as Rocky and
  AlmaLinux), Arch rolling, and openSUSE Leap 15.6+ or Tumbleweed. openSUSE Leap
  15.x reached end of life in April 2026, so the validated SUSE target is now
  Leap 16.0.

### GUI Requirements (optional)

The desktop application additionally requires:

- GTK 3
- WebKit2GTK 4.1
- A polkit authentication agent (GNOME, KDE, Hyprland, etc.)

---

## Install from Package (Recommended)

> **The project renamed to `linux-hardener`, but on the AUR the package is still
> `linux-system-hardener`.** The rename needs a fresh AUR submission rather than
> a push, because the AUR does not redirect the way the git remotes do, and that
> submission happens at the next release. Until then `linux-system-hardener` is
> the package that exists, and the commands below name it. Installing it now is
> carried across when the new one lands, because that package carries
> `provides`/`conflicts`/`replaces`. See
> [upgrading](upgrading.md#151-and-earlier-the-package-and-the-project-are-renamed).
> The RPM and deb packages are named `linux-hardener` already.

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
sudo dnf install linux-hardener-*.rpm

# Or build from source RPM
rpmbuild -ba linux-hardener.spec
sudo dnf install ~/rpmbuild/RPMS/x86_64/linux-hardener-*.rpm
```

### Debian / Ubuntu / Linux Mint

```bash
# Install the .deb
sudo dpkg -i linux-hardener_*.deb
sudo apt-get install -f   # resolve dependencies

# Or build from source
dpkg-buildpackage -us -uc
sudo dpkg -i ../linux-hardener_*.deb
```

### openSUSE

```bash
# Install the RPM
sudo zypper install linux-hardener-*.rpm
```

---

## Install from Static Binary

A portable musl-linked binary works on any Linux distribution without dependencies:

```bash
# Download the latest release
curl -LO https://github.com/tidynest/linux-hardener/releases/latest/download/hardener-linux-x86_64-musl.tar.gz

# Extract
tar xzf hardener-linux-x86_64-musl.tar.gz

# Install system-wide
sudo install -Dm755 hardener /usr/bin/hardener

# Create required directories
sudo install -dm755 /etc/linux-hardener
sudo install -dm755 /var/lib/linux-hardener
sudo install -dm700 /var/log/linux-hardener

# Optional: install default config
sudo install -Dm644 packaging/assets/config.toml.example /etc/linux-hardener/config.toml
```

---

## Run with Docker (Scan and Report Only)

A minimal container image supports read-only auditing of the host. The image
is built `FROM scratch` and contains a single file: the statically linked
musl `hardener` binary. No shell, no libraries, no package manager.

### Build

From the repository root (the build context must be the repository root,
where `.dockerignore` lives):

```bash
docker build -f packaging/docker/Dockerfile -t linux-hardener .
```

`--build-arg BUILD_JOBS=<n>` caps rustc parallelism on thermally constrained
hosts; unset, the build uses all cores.

### Usage

```bash
# Read-only scan of the host's config surface
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var/log:/var/log:ro -v /usr/lib:/usr/lib:ro \
  linux-hardener scan --format json
```

Compliance reports work the same way:

```bash
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var/log:/var/log:ro -v /usr/lib:/usr/lib:ro \
  linux-hardener report --framework cis
```

### Why these flags

- `--pid=host`: the container shares the host's PID namespace, so `/proc/sys`
  exposes the host's global sysctls (`kernel.*`, `fs.*`, `vm.*`) and the
  kernel plugin reads real values. Network sysctls (`net.*`) are read from
  the container's own network namespace; add `--network=host` if those
  checks should reflect the host's tuning rather than namespace defaults.
- `-v /etc:/etc:ro`: SSH, PAM, permissions and distro-detection checks read
  the host's real configuration and cannot write to it. On a host that layers
  its configuration this is only half of what they read; see the `/usr/etc`
  bullet below.
- `-v /var/log:/var/log:ro`: log-file permission checks.
- `-v /usr/lib:/usr/lib:ro`: vendor systemd unit and library permission
  checks.
- `-v /usr/etc:/usr/etc:ro`, on a host that has that directory: openSUSE keeps
  its packaged configuration there and reserves `/etc` for overrides, and Fedora
  is moving the same way. The SSH, PAM and permissions checks fall through to
  that layer when `/etc` holds nothing, so without the mount they find an empty
  vendor layer and stay silent about a file that is genuinely in force on the
  host. Leave the flag off where the directory does not exist.

Filesystem checks only evaluate paths visible inside the container; anything
outside the mounts is silently absent from the results. Widen coverage with
further read-only mounts, e.g. `-v /boot:/boot:ro -v /root:/root:ro` for the
permissions plugin's boot- and root-directory checks.

### Capability boundary

In a container the hardener can meaningfully run **scan and report,
read-only, against mounted host state**. `systemctl`/D-Bus-dependent checks
(services and parts of the audit/MAC/firewall plugins) degrade: they report
tool-unavailable findings rather than lying. For example, on a host with
auditd running, the in-container scan reports `audit_not_installed` because
it cannot see the host's service manager: treat such findings as
*unverifiable in-container*, not as host truth.

**`apply` is unsupported in a container by design.** Writing host state would
require `--privileged` plus host namespaces, which defeats the isolation
that justifies the container in the first place. Use a native install
(package, static binary, or source) to apply hardening.

Remote (`--ssh`) operations are also unavailable: the image ships no `ssh`
client binary.

The Docker section of
[distribution-validation.md](../reference/distribution-validation.md)
records exactly what has been validated with this image.

---

## Install from Source

### Build Dependencies

Building the desktop GUI additionally needs [trunk](https://trunkrs.dev), which
compiles the Leptos frontend to WASM. Arch packages it; elsewhere install it with
`cargo install trunk`.

**Arch:**
```bash
sudo pacman -S rust cargo musl trunk pkg-config openssl gtk3 webkit2gtk-4.1 libxcb libxkbcommon librsvg
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
git clone https://github.com/tidynest/linux-hardener.git
cd linux-hardener

# CLI only (static musl binary)
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli

# Desktop GUI, step 1: build the WASM frontend that Tauri embeds.
# --public-url="." keeps asset paths relative, which Tauri's custom protocol
# requires; absolute paths such as /foo.js do not resolve.
cd crates/hardener-ui && trunk build --release --public-url="." && cd ../..

# Desktop GUI, step 2: build the binary against those embedded assets
cd src-tauri && cargo build --release --features tauri/custom-protocol && cd ..

# Install
sudo install -Dm755 target/x86_64-unknown-linux-musl/release/hardener /usr/bin/hardener
sudo install -Dm755 target/release/linux-hardener-desktop /usr/bin/linux-hardener-desktop
```

The trunk step is not optional for a fresh clone. `crates/hardener-ui/dist/` is
generated, and therefore not in git, while `src-tauri/tauri.conf.json` points
`frontendDist` at it, so a desktop build attempted before that directory exists
has nothing to embed. This is the same three-step order every packaging recipe
in `packaging/` uses.

If `CARGO_TARGET_DIR` or a `[build] target-dir` in `~/.cargo/config.toml` is
configured, substitute that directory for `target/` in the install paths above.
`src-tauri` is a member of the root workspace, so building from inside it still
writes to the workspace target directory and both binaries land under the same
`target/`.

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
# Writes the unit files, reloads systemd, then enables and starts the timer
sudo hardener systemd install

# Verify
sudo hardener systemd status
```

`systemd install` runs `systemctl daemon-reload` and
`systemctl enable --now linux-hardener.timer` itself, so no separate `systemctl`
step is needed. Pass `--user` to install into `~/.config/systemd/user` instead,
and `--schedule` to change the calendar expression from the `daily` default.

### Optional: Install Polkit Policy

Required for GUI privilege escalation. Packages install this automatically:

```bash
sudo install -Dm644 packaging/assets/com.tidynest.linux-hardener.policy \
    /usr/share/polkit-1/actions/com.tidynest.linux-hardener.policy
```

### Optional: Install Desktop Entry

```bash
sudo install -Dm644 packaging/assets/linux-hardener.desktop \
    /usr/share/applications/linux-hardener.desktop
```

---

## Verify Installation

```bash
# Check CLI
hardener --help

# Check version (prints "hardener <version> (<commit> <date>)")
hardener --version

# Run a scan (no root required for scanning)
hardener scan
```

---

## Upgrading

Some releases fixed defects that a host keeps carrying after the upgrade,
because installing a newer version repairs the tool and not the system it
already changed. Read the [upgrading guide](upgrading.md) for the version you
are coming from before or after doing any of the below.

### From Package Manager

Use your distribution's standard upgrade mechanism:

```bash
# Arch
yay -Syu linux-system-hardener

# Fedora/RHEL
sudo dnf upgrade linux-hardener

# Debian/Ubuntu
sudo apt-get upgrade linux-hardener

# openSUSE
sudo zypper update linux-hardener
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
sudo dnf remove linux-hardener

# Debian/Ubuntu
sudo apt-get remove --purge linux-hardener

# openSUSE
sudo zypper remove linux-hardener
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

Moved to the [troubleshooting guide](troubleshooting.md), which covers GUI
launch failures, polkit authentication errors, timer issues, and partial
scan results, organised by symptom.
