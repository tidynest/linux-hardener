Name:           linux-system-hardener
Version:        1.0.5
Release:        1%{?dist}
Summary:        Linux security automation: scanning, hardening, and rollback
License:        Apache-2.0
URL:            https://github.com/tidynest/linux-system-hardener
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  cargo rust gcc openssl-devel libxcb-devel libxkbcommon-devel
BuildRequires:  gtk3-devel webkit2gtk4.1-devel pkg-config librsvg2-devel
BuildRequires:  desktop-file-utils trunk

Requires:       glibc openssl-libs gtk3 libxcb libxkbcommon systemd
Requires:       polkit

%description
Linux System Hardener automates security through scanning, hardening, and
safe rollback across 8 security domains (kernel, SSH, firewall, PAM, audit,
MAC, permissions, services) with multi-distribution support.

%prep
%setup -q

%build
# Strip GCC LTO from CFLAGS — incompatible with Rust linkers
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

install -Dm644 systemd/linux-hardener.service \
    %{buildroot}%{_unitdir}/linux-hardener.service
install -Dm644 systemd/linux-hardener.timer \
    %{buildroot}%{_unitdir}/linux-hardener.timer

install -Dm644 data/linux-hardener.desktop \
    %{buildroot}%{_datadir}/applications/linux-hardener.desktop

install -Dm644 data/hardener.1 \
    %{buildroot}%{_mandir}/man1/hardener.1

install -Dm644 data/com.tidynest.linux-hardener.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/com.tidynest.linux-hardener.policy

install -Dm644 data/config.toml.example \
    %{buildroot}%{_docdir}/%{name}/config.toml.example
install -Dm644 data/config.toml.example \
    %{buildroot}%{_sysconfdir}/linux-hardener/config.toml

install -d -m 755 %{buildroot}%{_sysconfdir}/linux-hardener
install -d -m 755 %{buildroot}%{_localstatedir}/lib/linux-hardener
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
%doc data/config.toml.example
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
%dir %{_localstatedir}/lib/linux-hardener
%dir %attr(700,root,root) %{_localstatedir}/log/linux-hardener
%dir %{_libdir}/linux-hardener

%changelog
* Sun May 24 2026 Eric Jingryd <tidynest@proton.me> - 1.0.5-1
- v1.0.5: Security — patch tauri (CVE-2026-42184), lettre (RUSTSEC-2026-0141),
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
