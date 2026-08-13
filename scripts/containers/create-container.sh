#!/bin/bash
# Create an isolated distribution container for safe root testing
# Uses systemd-nspawn for full systemd support
#
# One script for all six test distributions. Container names are stable and
# relied upon by the test runners and docs:
#   arch     -> hardener-test
#   debian   -> hardener-test-debian
#   ubuntu   -> hardener-test-ubuntu
#   fedora   -> hardener-test-fedora
#   rhel     -> hardener-test-rhel
#   opensuse -> hardener-test-opensuse
# Plus one fixture variant, which is a second Arch rather than a seventh
# distribution and is deliberately absent from DISTRO_ORDER:
#   arch-nftables -> hardener-test-nftables
#
# Usage:
#   sudo ./scripts/containers/create-container.sh <distro>        # Create container
#   sudo ./scripts/containers/create-container.sh <distro> enter  # Enter existing container
#   sudo ./scripts/containers/create-container.sh <distro> clean  # Remove container
#   sudo ./scripts/containers/create-container.sh <distro> verify # Check the contract
#
# --no-confirm may be added in any position to answer the clean prompt, for the
# recreate-then-measure loop that removes all six in sequence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Create an isolated Linux container for safe hardener testing.

Usage: sudo $0 <distro> [command] [--no-confirm]

Options:
  --no-confirm  Answer the 'clean' deletion prompt with yes. Intended for the
                recreate-then-measure loop, where six containers are removed
                in sequence and a baseline is worthless if any of them
                survives. May appear in any argument position.

Distros:
  arch      Arch Linux (pacstrap)                     -> hardener-test
  debian    Debian 13 Trixie (debootstrap)            -> hardener-test-debian
  ubuntu    Ubuntu 24.04 LTS Noble (debootstrap)      -> hardener-test-ubuntu
  fedora    Fedora 44 (podman image export)           -> hardener-test-fedora
  rhel      Rocky Linux 10 (podman image export)      -> hardener-test-rhel
  opensuse  openSUSE Leap 16.0 (podman image export)  -> hardener-test-opensuse

Fixture variants:
  arch-nftables  Arch with ufw left out           -> hardener-test-nftables
                 Same bootstrap as arch. With no ufw and no firewalld,
                 nftables is the only backend the plugin can select, which is
                 the path none of the six standard fixtures reaches (#47).

Commands:
  (none)    Create new test container
  enter     Enter container (full boot with systemd)
  shell     Quick shell access (no systemd)
  clean     Remove the container
  verify    Check an existing container against the contract below
  help      Show this help

Exit codes:
  0  the requested command did what it says
  1  bad argument, missing dependency, or not root
  3  create was asked for a container that already exists, and built nothing.
     Distinct from 1 so a caller can tell "already there, possibly stale" from
     "the bootstrap failed"; both are distinct from the 0 that used to be
     returned for a container this script did not build.

All containers provide, and the 'verify' command checks rather than assumes:
  - Full systemd support (for service testing)
  - Pre-installed: openssh, audit, firewall tooling, nftables
  (checked as binaries: sshd, auditd, nft, systemctl, and ufw or firewall-cmd
   by distribution. arch-nftables carries neither firewall tool on purpose.)
  - Project mounted at /project
  - Root password: test
  - Test user: testuser / test (passwordless sudo)

Example workflow:
  1. sudo $0 debian
  2. sudo $0 debian enter
  3. Inside container:
     cd /project
     ./target/release/hardener scan
     sudo ./scripts/test/full-test-suite.sh
  4. Exit and optionally clean up:
     sudo $0 debian clean

Notes:
  - Non-Arch containers should use the musl static binary for
    cross-distribution compatibility.
  - Debian and Ubuntu bootstrap with debootstrap, which verifies the archive's
    Release signature only when the matching keyring is installed on the host
    (debian-archive-keyring, ubuntu-keyring). Without it debootstrap warns and
    continues, so the rootfs arrives unverified.
  - Fedora/RHEL/openSUSE bootstraps pull the official image via podman
    (needs podman on the host).
  - Fedora, Rocky Linux (RHEL) and openSUSE use firewalld by default
    (not ufw); Rocky Linux uses SELinux (limited in a container).
EOF
}

# =============================================================================
# Distro selection
# =============================================================================

# Flags are stripped before the positional arguments are read, so --no-confirm
# can sit anywhere without displacing <distro> or <command>. An unrecognised
# flag is refused rather than passed through: nothing reads a third positional,
# so a mistyped --no-confirm would otherwise be discarded in silence and the
# recreate loop would sit waiting for a keypress nobody is there to give.
# --help and -h are deliberately let through, being handled as verbs below.
NO_CONFIRM=false
# Which bootstrap function runs, and whether the Arch one installs ufw. Both
# are overridden only by `arch-nftables`, which shares Arch's bootstrap rather
# than duplicating it: a second copy of a pacstrap line is how one of them
# acquires a package the other never gets.
BOOTSTRAP_DISTRO=""
ARCH_INSTALL_UFW=true
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --no-confirm) NO_CONFIRM=true ;;
        --help|-h) POSITIONAL+=("$arg") ;;
        -*)
            log_error "Unknown option: $arg"
            usage
            exit 1
            ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done
set -- "${POSITIONAL[@]}"

DISTRO="${1:-}"
VERB="${2:-}"

case "$DISTRO" in
    arch)
        CONTAINER_NAME="${CONTAINERS[arch]}"
        DISTRO_LABEL="Arch Linux"
        EXIT_HINT="Exit with 'exit' or Ctrl+D"
        DEPS=("pacstrap:arch-install-scripts" "systemd-nspawn:systemd")
        POST_CREATE_NOTE=""
        ;;
    arch-nftables)
        # The same Arch bootstrap with ufw left out (#47). All six standard
        # fixtures reach ufw or firewalld, so the plugin's nftables branch and
        # the differential suite's nftables oracle had nothing to run against.
        # With ufw absent and firewalld never installed on Arch, nftables is
        # the only backend `classify_installed` finds, so `detect_backend`
        # selects it whether or not it is active.
        CONTAINER_NAME="${CONTAINERS[arch-nftables]}"
        DISTRO_LABEL="Arch Linux (nftables only)"
        EXIT_HINT="Exit with 'exit' or Ctrl+D"
        DEPS=("pacstrap:arch-install-scripts" "systemd-nspawn:systemd")
        BOOTSTRAP_DISTRO="arch"
        ARCH_INSTALL_UFW=false
        POST_CREATE_NOTE="Note: ufw is deliberately absent; nftables is the only backend"
        ;;
    debian)
        DEBIAN_RELEASE="trixie"  # Debian 13
        CONTAINER_NAME="${CONTAINERS[debian]}"
        DISTRO_LABEL="Debian ${DEBIAN_RELEASE}"
        EXIT_HINT="Exit with 'poweroff' or Ctrl+]]]"
        DEPS=("debootstrap:debootstrap" "systemd-nspawn:systemd-container")
        POST_CREATE_NOTE=""
        ;;
    ubuntu)
        # 24.04 LTS rather than the newest LTS on purpose. It is the release a
        # newcomer is most likely to be running, it is in standard support
        # until 2029, and its archive layout is settled: debootstrap's suite
        # script resolves it through 'ubuntu-distro-info --supported' where
        # that exists and through a network query to endoflife.date where it
        # does not, and a release the query does not yet know is sent to
        # old-releases.ubuntu.com, which does not carry it. Moving to 26.04
        # "resolute" is this one line plus the label, once someone has run it.
        UBUNTU_RELEASE="noble"
        CONTAINER_NAME="${CONTAINERS[ubuntu]}"
        DISTRO_LABEL="Ubuntu 24.04 LTS (${UBUNTU_RELEASE})"
        EXIT_HINT="Exit with 'poweroff' or Ctrl+]]]"
        DEPS=("debootstrap:debootstrap" "systemd-nspawn:systemd-container")
        POST_CREATE_NOTE=""
        ;;
    fedora)
        FEDORA_VERSION="44"
        # Official Fedora container image, pulled and exported via podman.
        FEDORA_IMAGE="docker.io/library/fedora:${FEDORA_VERSION}"
        CONTAINER_NAME="${CONTAINERS[fedora]}"
        DISTRO_LABEL="Fedora ${FEDORA_VERSION}"
        EXIT_HINT="Exit with 'poweroff' or Ctrl+]]]"
        DEPS=("podman:podman" "systemd-nspawn:systemd-container" "tar:tar")
        POST_CREATE_NOTE="Note: Fedora uses firewalld by default (not ufw)"
        ;;
    rhel)
        ROCKY_VERSION="10"
        # Official Rocky Linux container image, pulled and exported via podman.
        # Rocky Linux is a 1:1 binary-compatible RHEL rebuild.
        ROCKY_IMAGE="docker.io/rockylinux/rockylinux:${ROCKY_VERSION}"
        CONTAINER_NAME="${CONTAINERS[rhel]}"
        DISTRO_LABEL="Rocky Linux ${ROCKY_VERSION} (RHEL)"
        EXIT_HINT="Exit with 'poweroff' or Ctrl+]]]"
        DEPS=("podman:podman" "systemd-nspawn:systemd-container" "tar:tar")
        POST_CREATE_NOTE="Note: Rocky Linux (RHEL) uses firewalld by default (not ufw)
Note: Rocky Linux (RHEL) uses SELinux (limited in container)"
        ;;
    opensuse)
        OPENSUSE_VERSION="16.0"
        # Official openSUSE Leap container image, pulled and exported via podman.
        OPENSUSE_IMAGE="docker.io/opensuse/leap:${OPENSUSE_VERSION}"
        CONTAINER_NAME="${CONTAINERS[opensuse]}"
        DISTRO_LABEL="openSUSE Leap ${OPENSUSE_VERSION}"
        EXIT_HINT="Exit with 'poweroff' or Ctrl+]]]"
        DEPS=("systemd-nspawn:systemd-container" "podman:podman" "tar:tar")
        POST_CREATE_NOTE="Note: openSUSE uses firewalld by default (not ufw)"
        ;;
    help|--help|-h)
        usage
        exit 0
        ;;
    "")
        log_error "Missing distro argument"
        echo "Distros: arch debian ubuntu fedora rhel opensuse arch-nftables"
        echo "Usage: sudo $0 <distro> [enter|shell|clean|help]"
        exit 1
        ;;
    *)
        log_error "Unknown distro: $DISTRO"
        echo "Distros: arch debian ubuntu fedora rhel opensuse arch-nftables"
        echo "Usage: sudo $0 <distro> [enter|shell|clean|help]"
        exit 1
        ;;
esac

CONTAINER_PATH="/var/lib/machines/${CONTAINER_NAME}"
SELF="$0 $DISTRO"

# =============================================================================
# Shared frame
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (for container management)"
        echo "Usage: sudo $SELF [enter|clean]"
        exit 1
    fi
}

check_dependencies() {
    local missing=() dep

    for dep in "${DEPS[@]}"; do
        if ! command -v "${dep%%:*}" &>/dev/null; then
            missing+=("${dep#*:}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required packages: ${missing[*]}"
        echo ""
        echo "Install with:"
        if command -v pacman &>/dev/null; then
            echo "  sudo pacman -S ${missing[*]}"
        elif command -v apt &>/dev/null; then
            echo "  sudo apt install ${missing[*]}"
        else
            echo "  Install: ${missing[*]}"
        fi
        exit 1
    fi
}

# Generates the container's SSH host keys.
#
# Without them `sshd -t` exits with "no hostkeys available". The ssh plugin
# validates its candidate config with `sshd -t` before writing, so it correctly
# aborts every apply, and the differential suite then reports the whole plugin
# as "apply did not take effect" for reasons that have nothing to do with the
# plugin.
#
# Run under systemd-nspawn, not chroot: ssh-keygen needs /dev/urandom and a
# bare chroot does not provide one, so the chroot form failed on every distro
# that used it. The error text is kept rather than discarded, because a bare
# "it failed" is what made the first attempt at this undiagnosable.
#
# Callers invoke this bare, so under `set -e` a failure aborts creation rather
# than producing a container that looks fine and then fails every ssh test for
# a reason with nothing to do with the code under test. That silent
# degradation is what this is here to prevent, so it is not worth trading for
# a container that boots.
generate_host_keys() {
    local keygen_output
    if keygen_output=$(systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        ssh-keygen -A 2>&1); then
        return 0
    fi
    log_warn "ssh-keygen -A failed, so sshd -t will reject every config: ${keygen_output:-no output}"
    return 1
}

# Enables the services the suites test.
#
# These calls decide whether sshd, auditd and bluetooth exist in the finished
# container, and every bootstrap installs those packages a few lines above its
# own call, so a failure means the bootstrap did not do what it just reported
# doing rather than that a unit is legitimately absent. Written
# `2>/dev/null || true`, it produced a container that built cleanly and tested
# nothing: a service that was never enabled reads, several layers later,
# exactly like a service the tool correctly left alone.
#
# bluetooth is here for a reason of its own. The service-minimisation plugin
# assesses five units and every image shipped with none of them, so the plugin
# had no subject matter and an oracle over it could only read the same
# "nothing to report" on all six distributions. bluez is installed everywhere
# to supply that subject matter, and enabling it is what makes installing it
# count: the plugin raises a finding only for a unit that is enabled or active,
# so an installed but disabled bluetooth.service would leave the fixture with
# nothing to find. Leaving that to the packaging would not do either, because
# Debian enables a daemon on install where Arch does not, and the six images
# would then disagree with each other. The enable is also the backstop for the
# openSUSE install below, which warns and continues rather than failing: a
# bluez that did not install there cannot reach the end of creation unnoticed,
# because enabling an absent unit fails and this function is called bare.
#
# Called bare for the same reason `generate_host_keys` is, and the error text
# is kept for the same reason too.
#
# The whole command is passed in because the bootstraps reach into the
# container differently, `chroot` where that works and `systemd-nspawn` for
# openSUSE, and that difference is deliberate.
enable_test_services() {
    local output
    if output=$("$@" 2>&1); then
        return 0
    fi
    log_error "enabling the test services failed: ${output:-no output}"
    log_error "  command: $*"
    return 1
}

# Pull an official image with podman and export its root filesystem to
# $CONTAINER_PATH. Used by the Fedora, Rocky (RHEL) and openSUSE bootstraps:
# - Red Hat family: Arch's rpm enforces %_pkgverify_level=all, which
#   `dnf --nogpgcheck` cannot override, so a host-dnf bootstrap of a keyless
#   installroot always fails GPG. The image runs its own scriptlets/keys
#   natively.
# - openSUSE: Leap 16 dropped the OBS lxc rootfs tarball, and cross-host
#   `zypper --root` bootstrap fails on the filesystem package's usrmerge
#   scriptlet; the prebuilt image runs its scriptlets natively instead.
podman_export_rootfs() {
    local image="$1" tmp_container="$2"

    if ! podman pull "$image"; then
        log_error "Failed to pull $image"
        exit 1
    fi

    mkdir -p "$CONTAINER_PATH"
    log_info "Exporting image root filesystem to $CONTAINER_PATH..."
    podman create --name "$tmp_container" "$image" >/dev/null
    if ! podman export "$tmp_container" | tar -x -C "$CONTAINER_PATH"; then
        podman rm -f "$tmp_container" >/dev/null 2>&1 || true
        rm -rf "$CONTAINER_PATH"
        log_error "Failed to export image filesystem"
        exit 1
    fi
    podman rm -f "$tmp_container" >/dev/null 2>&1 || true

    # Sanity: the export must contain a usable base system.
    if [[ ! -x "$CONTAINER_PATH/usr/bin/bash" ]]; then
        log_error "Image export incomplete: /usr/bin/bash missing"
        rm -rf "$CONTAINER_PATH"
        exit 1
    fi
    log_info "Base system extracted from official image"
}

# =============================================================================
# Per-distro bootstrap mechanics (create verb)
# =============================================================================

bootstrap_arch() {
    # Bootstrap minimal Arch system
    mkdir -p "$CONTAINER_PATH"
    # ufw is the one package the arch-nftables variant leaves out, and leaving
    # it out is the whole point of that fixture: with no ufw and no firewalld,
    # nftables is the only backend the plugin can select. iptables stays, since
    # it is not a backend in its own right and removing it would change more
    # than the question being asked.
    local firewall_packages=(iptables nftables)
    [[ "$ARCH_INSTALL_UFW" == true ]] && firewall_packages+=(ufw)
    # bluez gives service-minimisation a unit to assess; see enable_test_services.
    pacstrap -c "$CONTAINER_PATH" base base-devel \
        openssh audit bluez "${firewall_packages[@]}" \
        sudo polkit jq --noconfirm

    # Set up container
    log_info "Configuring container..."

    # Set root password to 'test' (container only!)
    echo "root:test" | chroot "$CONTAINER_PATH" chpasswd

    # Create test user
    chroot "$CONTAINER_PATH" useradd -m -G wheel testuser 2>/dev/null || true
    echo "testuser:test" | chroot "$CONTAINER_PATH" chpasswd

    # Allow wheel group sudo
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel"


    generate_host_keys

    # Enable services that hardener tests
    enable_test_services chroot "$CONTAINER_PATH" systemctl enable sshd auditd bluetooth
}

# Shared by the apt-family distros (Debian, Ubuntu): both bootstrap with
# debootstrap and then install the same package set, differing only in the suite
# they target, the archive that carries it, and which of that archive's
# components have to be enabled to reach what the suites install.
#
# --components is passed for both. Debian's value is debootstrap's own default,
# so the Debian path is unchanged by this having been made a parameter, which
# matters because that path is the one with a dated cross-distribution result
# behind it.
bootstrap_apt_family() {
    local label="$1" suite="$2" mirror="$3" components="$4"

    log_info "Bootstrapping $label '$suite' from $mirror. This may take a few minutes..."

    # Bootstrap a minimal system with essential utilities
    mkdir -p "$CONTAINER_PATH"
    debootstrap --components="$components" \
        --include=systemd,systemd-sysv,dbus,passwd,login,sudo \
        "$suite" "$CONTAINER_PATH" "$mirror"

    # Set up container
    log_info "Configuring container..."

    # Set root password to 'test' (container only!)
    # Use full path since PATH may not be set in chroot
    echo "root:test" | chroot "$CONTAINER_PATH" /usr/sbin/chpasswd

    # Create test user
    chroot "$CONTAINER_PATH" /usr/sbin/useradd -m -s /bin/bash testuser 2>/dev/null || true
    echo "testuser:test" | chroot "$CONTAINER_PATH" /usr/sbin/chpasswd
    chroot "$CONTAINER_PATH" /usr/sbin/usermod -aG sudo testuser 2>/dev/null || true

    # Install required packages for hardener testing
    log_info "Installing test dependencies..."
    chroot "$CONTAINER_PATH" apt-get update
    # bluez gives service-minimisation a unit to assess; see enable_test_services.
    chroot "$CONTAINER_PATH" apt-get install -y \
        openssh-server \
        auditd \
        bluez \
        ufw \
        iptables \
        nftables \
        sudo \
        polkitd \
        pkexec \
        procps \
        iproute2 \
        jq

    # Ubuntu's systemd pulls systemd-resolved, whose install replaces
    # /etc/resolv.conf with a symlink to a stub under /run that nothing in this
    # container ever starts. systemd-nspawn's --resolv-conf=auto manages a
    # regular file or a missing one and leaves a symlink alone, so the
    # container was left unable to resolve any name: the Web UI suite reported
    # "Temporary failure resolving archive.ubuntu.com" and installed nothing.
    # Debian does not package systemd-resolved with systemd and was unaffected,
    # which is why one apt-family container worked and the other did not.
    #
    # Replaced with a regular copy, the shape the four working containers
    # already have, rather than merely deleted: nspawn then supplies the host's
    # resolver at run time exactly as it does for them.
    rm -f "$CONTAINER_PATH/etc/resolv.conf"
    cp /etc/resolv.conf "$CONTAINER_PATH/etc/resolv.conf"

    # Allow sudo without password for testuser
    echo "testuser ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/testuser"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/testuser"

    generate_host_keys

    # Enable services that hardener tests
    enable_test_services chroot "$CONTAINER_PATH" systemctl enable ssh auditd bluetooth

    # Clean up apt cache to save space
    chroot "$CONTAINER_PATH" apt-get clean
}

bootstrap_debian() {
    bootstrap_apt_family "Debian" "$DEBIAN_RELEASE" "http://deb.debian.org/debian" "main"
}

# universe is enabled because Ubuntu splits its archive where Debian does not.
# The package set above is believed to be in main on 24.04, and jq and auditd
# were checked there; npm is in universe, which the Web UI suite installs, and
# a real Ubuntu host has universe enabled either way. A main-only container
# would be a fixture no operator runs, and would fail on a package name nobody
# had reason to expect.
bootstrap_ubuntu() {
    bootstrap_apt_family "Ubuntu" "$UBUNTU_RELEASE" "http://archive.ubuntu.com/ubuntu" "main,universe"
}

# Shared by the dnf-family distros (Fedora, Rocky/RHEL): both bootstrap from
# an official podman-exported image, install systemd + base tooling, create
# the test user, then install the same package set bar the iptables variant
# (Fedora ships plain iptables; Rocky 10 dropped it in favour of iptables-nft).
bootstrap_dnf_family() {
    local label="$1" image="$2" export_prefix="$3" iptables_pkg="$4"

    log_info "Pulling official $label image via podman..."

    # Pull + export the official image. Nothing rpm-related runs on the host,
    # so the Arch %_pkgverify_level=all policy never applies.
    podman_export_rootfs "$image" "hardener-${export_prefix}-export-$$"

    # The image ships minimal; install systemd and base tooling so it can boot
    # and so the config steps below (useradd/chpasswd) have their binaries.
    # Native dnf, native keys: GPG verification works.
    cp /etc/resolv.conf "$CONTAINER_PATH/etc/resolv.conf" 2>/dev/null || true
    log_info "Installing systemd and base tooling..."
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        dnf -y install systemd sudo passwd shadow-utils util-linux \
        || log_warn "base package install returned non-zero"

    # Set up container
    log_info "Configuring container..."

    # Copy DNS configuration for network access in chroot
    cp /etc/resolv.conf "$CONTAINER_PATH/etc/resolv.conf"

    # Set root password to 'test' (container only!)
    echo "root:test" | chroot "$CONTAINER_PATH" /usr/sbin/chpasswd

    # Create test user
    chroot "$CONTAINER_PATH" /usr/sbin/useradd -m -s /bin/bash testuser 2>/dev/null || true
    echo "testuser:test" | chroot "$CONTAINER_PATH" /usr/sbin/chpasswd
    chroot "$CONTAINER_PATH" /usr/sbin/usermod -aG wheel testuser 2>/dev/null || true

    # Install required packages for hardener testing
    # Use systemd-nspawn for proper /proc /sys mounts that dnf requires
    #
    # cracklib-dicts is here because libpwquality's dictionary check is on by
    # default and fails CLOSED: with no dictionary to load it refuses every
    # password, strong ones included, so a container without it cannot answer
    # whether a password policy works. Rocky's base image already carries it
    # and Fedora's does not, which is a difference nobody chose and which made
    # one distribution's reading incomparable with the other's. Installing it
    # is not the suite being made to pass: the differential check that found
    # this reports the refusal and names the missing dictionary either way.
    #
    # bluez is here for the neighbouring reason: it gives service-minimisation
    # a unit to assess. See enable_test_services for why it is also enabled.
    #
    # openssh-clients is here for `ssh -Q`, which is how the ssh plugin asks the
    # host which algorithms it supports. Without it the allow-list intersection
    # is empty, the plugin skips all three crypto directives with "leaving host
    # default", and the crypto path is unreachable on this distribution. That is
    # not a cosmetic gap: these images carry
    # /etc/ssh/sshd_config.d/40-redhat-crypto-policies.conf, which includes
    # crypto-policies' own Ciphers and MACs, and those hold aes256-ctr and
    # hmac-sha1, which this tool's allow-list rejects. So this is the one
    # fixture where the drop-in override the plugin exists to beat can actually
    # be produced, and it could not be produced until this package was here.
    log_info "Installing test dependencies..."
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        dnf -y install \
        openssh-server \
        openssh-clients \
        audit \
        bluez \
        cracklib-dicts \
        firewalld \
        nftables \
        "$iptables_pkg" \
        polkit \
        procps-ng \
        iproute \
        jq

    # Allow sudo without password for testuser (wheel group)
    mkdir -p "$CONTAINER_PATH/etc/sudoers.d"
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"


    generate_host_keys

    # Enable services that hardener tests
    enable_test_services chroot "$CONTAINER_PATH" systemctl enable sshd auditd bluetooth

    # Clean up dnf cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" dnf clean all 2>/dev/null || true
}

bootstrap_fedora() {
    bootstrap_dnf_family "Fedora" "$FEDORA_IMAGE" "fedora" "iptables"
}

bootstrap_rhel() {
    bootstrap_dnf_family "Rocky Linux" "$ROCKY_IMAGE" "rhel" "iptables-nft"
}

bootstrap_opensuse() {
    log_info "Pulling official openSUSE Leap image via podman..."

    # Pull the official image and export its root filesystem. Scriptlets run
    # inside the native image at build time, so nothing executes on the host,
    # this is what makes it work where `zypper --root` from Arch does not.
    podman_export_rootfs "$OPENSUSE_IMAGE" "hardener-opensuse-export-$$"

    # The minimal image ships without systemd; install it plus base tooling so
    # the container can boot and manage services. Native zypper, native repos.
    cp /etc/resolv.conf "$CONTAINER_PATH/etc/resolv.conf" 2>/dev/null || true
    log_info "Installing systemd and base tooling..."
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        zypper --gpg-auto-import-keys --non-interactive install --no-recommends \
        systemd \
        sudo \
        shadow \
        util-linux || log_warn "base package install returned non-zero"

    # Set up container
    log_info "Configuring container..."

    # Ensure DNS is configured
    cp /etc/resolv.conf "$CONTAINER_PATH/etc/resolv.conf" 2>/dev/null || true

    # Set root password to 'test' (container only!)
    if [[ -x "$CONTAINER_PATH/usr/sbin/chpasswd" ]]; then
        echo "root:test" | chroot "$CONTAINER_PATH" /usr/sbin/chpasswd
    elif [[ -x "$CONTAINER_PATH/usr/bin/chpasswd" ]]; then
        echo "root:test" | chroot "$CONTAINER_PATH" /usr/bin/chpasswd
    else
        log_warn "chpasswd not found, setting password via shadow file"
        # Generate password hash for 'test' and set directly
        HASH=$(openssl passwd -6 test)
        sed -i "s|^root:[^:]*:|root:${HASH}:|" "$CONTAINER_PATH/etc/shadow" 2>/dev/null || true
    fi

    # Create test user (openSUSE uses 'users' group, wheel may not exist)
    log_info "Creating test user..."
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        useradd -m testuser 2>/dev/null || true

    # Set testuser password
    if [[ -x "$CONTAINER_PATH/usr/sbin/chpasswd" ]]; then
        echo "testuser:test" | chroot "$CONTAINER_PATH" /usr/sbin/chpasswd 2>/dev/null || true
    elif [[ -x "$CONTAINER_PATH/usr/bin/chpasswd" ]]; then
        echo "testuser:test" | chroot "$CONTAINER_PATH" /usr/bin/chpasswd 2>/dev/null || true
    fi

    # Add to wheel group if it exists, otherwise create it
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        bash -c "getent group wheel || groupadd wheel" 2>/dev/null || true
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        usermod -aG wheel testuser 2>/dev/null || true

    # Install required packages for hardener testing
    log_info "Installing test dependencies..."
    # bluez gives service-minimisation a unit to assess; see enable_test_services.
    # openssh-clients for `ssh -Q`, the same reason as the dnf block above: with
    # no ssh binary the plugin cannot ask the host what it supports and skips
    # every crypto directive.
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        zypper --gpg-auto-import-keys --non-interactive install \
        openssh-server \
        openssh-clients \
        audit \
        bluez \
        firewalld \
        nftables \
        iptables \
        polkit \
        procps \
        jq \
        iproute2 2>/dev/null || log_warn "Some packages may not have installed"

    # Allow sudo without password for testuser (wheel group)
    mkdir -p "$CONTAINER_PATH/etc/sudoers.d"
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"


    generate_host_keys

    # Enable services that hardener tests
    enable_test_services systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        systemctl enable sshd auditd bluetooth

    # Clean up zypper cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        zypper clean --all 2>/dev/null || true
}

# =============================================================================
# Verbs
# =============================================================================

# The binaries every finished container must carry, by distribution.
#
# Named as binaries rather than packages because five package managers spell
# the same software five ways, and what the suites need is a command that runs.
# The firewall entry differs by design: arch, debian and ubuntu get ufw, the
# Red Hat family and openSUSE get firewalld, and `arch-nftables` deliberately
# has neither so that nftables is the only backend its plugin can select.
contract_binaries() {
    case "$DISTRO" in
        arch-nftables) echo sshd auditd nft systemctl ;;
        arch | debian | ubuntu) echo sshd auditd nft systemctl ufw ;;
        *) echo sshd auditd nft systemctl firewall-cmd ;;
    esac
}

# Checks a container against the contract this script's own help publishes,
# instead of trusting that whatever built it did what it said.
#
# The rhel container walked all five phases of a full cross-distribution run
# carrying no openssh-server, no audit and no firewalld. Three of its eight
# plugins could not scan, it produced 14 findings where every other
# distribution produced 49, and every suite that used it exited 0 throughout.
# `enable_test_services` already refuses at creation when a unit cannot be
# enabled, so a container this script builds today cannot end up that way; what
# nothing checked was a container built by an older version of the script.
# `create` on an existing path exits 3 without looking inside it, so a fixture
# that predates a package being added to the list stays in service for as long
# as nobody deletes it, and every suite run against it measures less than it
# reports while reading exactly like one that measured everything.
verify_contract() {
    local binary missing=()
    for binary in $(contract_binaries); do
        systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
            sh -c "command -v $binary >/dev/null 2>&1" 2>/dev/null ||
            missing+=("$binary")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_info "Contract check passed: $(contract_binaries | wc -w) binaries present"
        return 0
    fi

    log_error "Container at $CONTAINER_PATH does not satisfy the fixture contract"
    log_error "  missing: ${missing[*]}"
    log_error "  A suite run against it measures less than it reports, and says so nowhere."
    log_error "  Rebuild it: sudo $SELF clean --no-confirm && sudo $SELF"
    return 1
}

create_container() {
    check_dependencies

    # Refused, and refused with a status of its own. This used to exit 0, so a
    # caller that asked for a container and was handed an older one could not
    # tell that apart from a container this run built. That distinction is the
    # whole of the problem: a container a previous --apply run left hardened
    # fails a rotating subset of the next suite, and every one of those failures
    # reads as a regression in the tool. release-readiness-root.sh cleans before
    # every create and judges this status, so reaching this branch there means
    # the clean did not take.
    if [[ -d "$CONTAINER_PATH" ]]; then
        log_error "Container already exists at $CONTAINER_PATH, so nothing was built"
        log_info "Use '$SELF enter' to enter or '$SELF clean' to remove"
        # Checked before refusing, because "already there" is the branch a stale
        # container reaches and the caller is about to run suites against it.
        # The status stays 3 either way: release-readiness-root.sh judges that
        # value, and a container failing the contract is still the same fact
        # about this run, which is that it built nothing.
        verify_contract || true
        exit 3
    fi

    log_info "Creating $DISTRO_LABEL container at $CONTAINER_PATH..."
    "bootstrap_${BOOTSTRAP_DISTRO:-$DISTRO}"

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

    # Called bare, so a bootstrap that reported installing these and did not
    # fails here rather than handing back a container that tests less than the
    # caller believes. Same reasoning as `enable_test_services` above.
    verify_contract

    log_info "Container created successfully!"
    echo ""
    echo "To enter the container:"
    echo "  sudo $SELF enter"
    echo ""
    echo "Inside the container, the project is at /project"
    echo "Root password: test"
    echo "Test user: testuser / test (passwordless sudo)"
    if [[ -n "$POST_CREATE_NOTE" ]]; then
        echo ""
        echo "$POST_CREATE_NOTE"
    fi
}

enter_container() {
    if [[ ! -d "$CONTAINER_PATH" ]]; then
        log_error "Container does not exist. Run '$SELF' first to create it."
        exit 1
    fi

    log_info "Entering $DISTRO_LABEL container (project mounted at /project)..."
    log_info "$EXIT_HINT"
    echo ""

    # Start container with:
    # - Project directory bind-mounted
    # - Network access (for package installation if needed)
    # - Boot into systemd
    systemd-nspawn \
        --machine="$CONTAINER_NAME" \
        --directory="$CONTAINER_PATH" \
        --bind="$PROJECT_DIR:/project" \
        --boot \
        --network-veth
}

enter_container_shell() {
    # Quick shell access without full boot
    if [[ ! -d "$CONTAINER_PATH" ]]; then
        log_error "Container does not exist. Run '$SELF' first to create it."
        exit 1
    fi

    log_info "Opening shell in $DISTRO_LABEL container..."
    systemd-nspawn \
        --machine="$CONTAINER_NAME" \
        --directory="$CONTAINER_PATH" \
        --bind="$PROJECT_DIR:/project"
}

clean_container() {
    if [[ ! -d "$CONTAINER_PATH" ]]; then
        log_warn "Container does not exist at $CONTAINER_PATH"
        exit 0
    fi

    log_warn "This will permanently delete the $DISTRO_LABEL test container!"
    if [[ "$NO_CONFIRM" == true ]]; then
        # Still announced. A destructive step that proceeds in silence is how a
        # scripted loop deletes something nobody meant to include.
        log_warn "Proceeding without asking (--no-confirm)."
        REPLY=y
    else
        read -p "Are you sure? [y/N] " -n 1 -r
        echo
    fi

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Stop container if running
        machinectl stop "$CONTAINER_NAME" 2>/dev/null || true
        sleep 1

        log_info "Removing container..."
        rm -rf "$CONTAINER_PATH"
        log_info "Container removed."
    else
        log_info "Cancelled."
    fi
}

# Main
case "$VERB" in
    enter)
        check_root
        enter_container
        ;;
    shell)
        check_root
        enter_container_shell
        ;;
    clean)
        check_root
        clean_container
        ;;
    verify)
        check_root
        if [[ ! -d "$CONTAINER_PATH" ]]; then
            log_error "Container does not exist at $CONTAINER_PATH"
            exit 1
        fi
        verify_contract
        ;;
    help|--help|-h)
        usage
        ;;
    "")
        check_root
        create_container
        ;;
    *)
        log_error "Unknown command: $VERB"
        usage
        exit 1
        ;;
esac
