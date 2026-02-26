# Linux Distribution Packaging Specifications

**Date**: 2026-02-25
**Scope**: AUR, RPM, DEB packaging for CLI + Desktop app
**Status**: Specs ready for implementation

---

## Package Overview

| Property | Value |
|----------|-------|
| CLI binary | `hardener` (crate: `hardener-cli`) |
| Desktop binary | `linux-hardener-desktop` (crate in `src-tauri/`) |
| Version | 0.3.3 |
| Licence | Apache-2.0 |
| Config directory | `/etc/linux-hardener/` |
| State directory | `/var/lib/linux-hardener/` |
| User config | `~/.config/linux-hardener/config.toml` |

### Prerequisites Before Packaging

1. **Create systemd unit files** (not yet in repo):
   - `systemd/hardener-scheduler.service`
   - `systemd/hardener-scheduler.timer`
2. **Create `.desktop` file** for application menu entry
3. **Consider man page generation** (`hardener.1`)

---

## 1. AUR — PKGBUILD

```bash
pkgname=linux-system-hardener
pkgver=0.3.3
pkgrel=1
pkgdesc="Linux security automation: scanning, hardening, and rollback"
arch=('x86_64')
url="https://github.com/tidynest/linux-system-hardener"
license=('Apache-2.0')
depends=(
    'cairo' 'desktop-file-utils' 'gcc-libs' 'gdk-pixbuf2' 'glib2' 'glibc'
    'gtk3' 'hicolor-icon-theme' 'libsoup3' 'openssl' 'pango'
    'webkit2gtk-4.1' 'libxcb' 'libxkbcommon' 'systemd'
)
makedepends=(
    'git' 'openssl' 'librsvg' 'rust' 'cargo' 'trunk' 'pkg-config'
)
source=("$pkgname-$pkgver.tar.gz::https://github.com/tidynest/$pkgname/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('PLACEHOLDER')

build() {
    cd "$pkgname-$pkgver"
    cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
    cd src-tauri && cargo build --release
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 "target/x86_64-unknown-linux-musl/release/hardener" "$pkgdir/usr/bin/hardener"
    install -Dm755 "src-tauri/target/release/linux-hardener-desktop" "$pkgdir/usr/bin/linux-hardener-desktop"
    # install -Dm644 "systemd/hardener-scheduler.service" "$pkgdir/usr/lib/systemd/system/hardener-scheduler.service"
    # install -Dm644 "systemd/hardener-scheduler.timer" "$pkgdir/usr/lib/systemd/system/hardener-scheduler.timer"
    install -dm755 "$pkgdir/etc/linux-hardener"
    install -dm755 "$pkgdir/var/lib/linux-hardener"
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
```

**Notes**: `trunk` is needed for Leptos WASM compilation. Musl target for CLI ensures cross-distro compatibility. Consider splitting into `linux-system-hardener-cli` and `linux-system-hardener-desktop` packages.

---

## 2. RPM — .spec File

```spec
Name:           linux-system-hardener
Version:        0.3.3
Release:        1%{?dist}
Summary:        Linux security automation: scanning, hardening, and rollback
License:        Apache-2.0
URL:            https://github.com/tidynest/linux-system-hardener
Source0:        https://github.com/tidynest/%{name}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  cargo rust gcc openssl-devel libxcb-devel libxkbcommon-devel
BuildRequires:  gtk3-devel webkitgtk6-devel pkg-config librsvg-devel desktop-file-utils
Requires:       glibc openssl-libs gtk3 libxcb libxkbcommon systemd

%description
Automates Linux security through scanning, hardening, and safe rollback
across 8 security domains with multi-distribution support.

%prep
%setup -q

%build
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cd src-tauri && cargo build --release

%install
install -Dm755 target/x86_64-unknown-linux-musl/release/hardener %{buildroot}%{_bindir}/hardener
install -Dm755 src-tauri/target/release/linux-hardener-desktop %{buildroot}%{_bindir}/linux-hardener-desktop
install -d -m 755 %{buildroot}%{_sysconfdir}/linux-hardener
install -d -m 755 %{buildroot}%{_localstatedir}/lib/linux-hardener
install -Dm644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

%post
systemctl daemon-reload || true

%preun
systemctl stop hardener-scheduler.timer 2>/dev/null || true
systemctl disable hardener-scheduler.timer 2>/dev/null || true

%postun
systemctl daemon-reload || true

%files
%license LICENSE
%doc README.md
%{_bindir}/hardener
%{_bindir}/linux-hardener-desktop
%dir %{_sysconfdir}/linux-hardener
%dir %{_localstatedir}/lib/linux-hardener
```

**Notes**: `webkitgtk6-devel` is the Fedora/RHEL equivalent of `webkit2gtk-4.1`. Consider COPR or OBS for automated builds.

---

## 3. DEB — debian/ Directory

### debian/control
```
Source: linux-system-hardener
Section: admin
Priority: optional
Maintainer: Eric Jingryd <tidynest@proton.me>
Build-Depends: debhelper-compat (= 13), cargo, rustc, gcc, libssl-dev, pkg-config,
 libgtk-3-dev, libwebkit2gtk-4.1-dev, libxcb1-dev, libxkbcommon-dev, librsvg2-dev

Package: linux-system-hardener
Architecture: amd64
Depends: ${misc:Depends}, ${shlibs:Depends}, libgtk-3-0, libwebkit2gtk-4.1,
 libxcb1, libxkbcommon0, systemd
Description: Linux security automation: scanning, hardening, and rollback
 Automates Linux security through comprehensive scanning, automated hardening
 recommendations, and safe rollback across 8 security domains.
```

### debian/rules
```makefile
#!/usr/bin/make -f
export CARGO_HOME=$(CURDIR)/debian/.cargo

%:
	dh $@ --with systemd

override_dh_auto_build:
	cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
	cd src-tauri && cargo build --release

override_dh_auto_install:
	install -Dm755 target/x86_64-unknown-linux-musl/release/hardener \
	    debian/linux-system-hardener/usr/bin/hardener
	install -Dm755 src-tauri/target/release/linux-hardener-desktop \
	    debian/linux-system-hardener/usr/bin/linux-hardener-desktop
	install -dm755 debian/linux-system-hardener/etc/linux-hardener
	install -dm755 debian/linux-system-hardener/var/lib/linux-hardener

override_dh_auto_test:
	cargo test --release || true
```

### debian/postinst
```bash
#!/bin/bash
set -e
case "$1" in
    configure)
        [ -d /var/lib/linux-hardener ] && chown root:root /var/lib/linux-hardener
        command -v systemctl >/dev/null && systemctl daemon-reload || true
        ;;
esac
#DEBHELPER#
```

### debian/prerm
```bash
#!/bin/bash
set -e
case "$1" in
    remove)
        command -v systemctl >/dev/null && {
            systemctl stop hardener-scheduler.timer 2>/dev/null || true
            systemctl disable hardener-scheduler.timer 2>/dev/null || true
        }
        ;;
esac
#DEBHELPER#
```

### debian/copyright
```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Files: *
Copyright: 2024-2026 Eric Jingryd
License: Apache-2.0
```

### debian/changelog
```
linux-system-hardener (0.3.3-1) unstable; urgency=medium

  * Initial Debian package release

 -- Eric Jingryd <tidynest@proton.me>  Tue, 25 Feb 2026 00:00:00 +0000
```

**Notes**: Consider `cargo-deb` as alternative. Upload to PPA for Ubuntu auto-builds.

---

## 4. Common Infrastructure Needed

### Systemd Units (to create in `systemd/` directory)

**hardener-scheduler.service**:
```ini
[Unit]
Description=Linux System Hardener Scheduler Daemon
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/hardener scheduler daemon
Restart=on-failure
RestartSec=30
StandardOutput=journal
SyslogIdentifier=hardener-scheduler

[Install]
WantedBy=multi-user.target
```

**hardener-scheduler.timer**:
```ini
[Unit]
Description=Linux System Hardener Scheduled Scan Timer
Requires=hardener-scheduler.service

[Timer]
OnBootSec=15min
OnUnitActiveSec=24h
Persistent=true

[Install]
WantedBy=timers.target
```

### Desktop Entry (for GUI)
```ini
[Desktop Entry]
Type=Application
Name=Linux System Hardener
Comment=System security hardening and compliance tool
Exec=/usr/bin/linux-hardener-desktop
Icon=linux-hardener
Categories=System;Security;
Terminal=false
```

### Build Dependencies Cross-Reference

| Library | Arch | Fedora/RHEL | Debian/Ubuntu |
|---------|------|-------------|---------------|
| WebKit (Tauri) | `webkit2gtk-4.1` | `webkitgtk6-devel` | `libwebkit2gtk-4.1-dev` |
| GTK3 | `gtk3` | `gtk3-devel` | `libgtk-3-dev` |
| OpenSSL | `openssl` | `openssl-devel` | `libssl-dev` |
| XCB | `libxcb` | `libxcb-devel` | `libxcb1-dev` |
| SVG | `librsvg` | `librsvg-devel` | `librsvg2-dev` |

---

## Recommended Packaging Order

1. Create systemd units + .desktop file (prerequisite)
2. **AUR first** — simplest packaging, fast iteration
3. **DEB** — PPA for Ubuntu auto-builds
4. **RPM** — COPR (Fedora) or OBS (openSUSE)
5. **AppImage** (optional) — single portable binary
