Name:           linux-system-hardener
Version:        0.3.3
Release:        1%{?dist}
Summary:        Linux security automation: scanning, hardening, and rollback
License:        Apache-2.0
URL:            https://github.com/tidynest/linux-system-hardener
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  cargo rust gcc openssl-devel libxcb-devel libxkbcommon-devel
BuildRequires:  gtk3-devel webkit2gtk4.1-devel pkg-config librsvg2-devel
BuildRequires:  desktop-file-utils

Requires:       glibc openssl-libs gtk3 libxcb libxkbcommon systemd

%description
Linux System Hardener automates security through scanning, hardening, and
safe rollback across 8 security domains (kernel, SSH, firewall, PAM, audit,
MAC, permissions, services) with multi-distribution support.

%prep
%setup -q

%build
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cd src-tauri && cargo build --release

%install
install -Dm755 target/x86_64-unknown-linux-musl/release/hardener \
    %{buildroot}%{_bindir}/hardener
install -Dm755 src-tauri/target/release/linux-hardener-desktop \
    %{buildroot}%{_bindir}/linux-hardener-desktop

install -Dm644 systemd/linux-hardener.service \
    %{buildroot}%{_unitdir}/linux-hardener.service
install -Dm644 systemd/linux-hardener.timer \
    %{buildroot}%{_unitdir}/linux-hardener.timer

install -Dm644 data/linux-hardener.desktop \
    %{buildroot}%{_datadir}/applications/linux-hardener.desktop

install -Dm644 data/config.toml.example \
    %{buildroot}%{_docdir}/%{name}/config.toml.example

install -d -m 755 %{buildroot}%{_sysconfdir}/linux-hardener
install -d -m 755 %{buildroot}%{_localstatedir}/lib/linux-hardener

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
%{_unitdir}/linux-hardener.service
%{_unitdir}/linux-hardener.timer
%{_datadir}/applications/linux-hardener.desktop
%dir %{_sysconfdir}/linux-hardener
%dir %{_localstatedir}/lib/linux-hardener

%changelog
* Tue Feb 25 2026 Eric Jingryd <tidynest@proton.me> - 0.3.3-1
- Initial RPM packaging
