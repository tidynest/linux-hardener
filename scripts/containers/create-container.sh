#!/bin/bash
# Create an isolated distribution container for safe root testing
# Uses systemd-nspawn for full systemd support
#
# One script for all five test distributions. Container names are stable and
# relied upon by the test runners and docs:
#   arch     -> hardener-test
#   debian   -> hardener-test-debian
#   fedora   -> hardener-test-fedora
#   rhel     -> hardener-test-rhel
#   opensuse -> hardener-test-opensuse
#
# Usage:
#   sudo ./scripts/containers/create-container.sh <distro>        # Create container
#   sudo ./scripts/containers/create-container.sh <distro> enter  # Enter existing container
#   sudo ./scripts/containers/create-container.sh <distro> clean  # Remove container

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Create an isolated Linux container for safe hardener testing.

Usage: sudo $0 <distro> [command]

Distros:
  arch      Arch Linux (pacstrap)                     -> hardener-test
  debian    Debian 13 Trixie (debootstrap)            -> hardener-test-debian
  fedora    Fedora 44 (podman image export)           -> hardener-test-fedora
  rhel      Rocky Linux 10 (podman image export)      -> hardener-test-rhel
  opensuse  openSUSE Leap 16.0 (podman image export)  -> hardener-test-opensuse

Commands:
  (none)    Create new test container
  enter     Enter container (full boot with systemd)
  shell     Quick shell access (no systemd)
  clean     Remove the container
  help      Show this help

All containers provide:
  - Full systemd support (for service testing)
  - Pre-installed: openssh, audit, firewall tooling, nftables
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
  - Fedora/RHEL/openSUSE bootstraps pull the official image via podman
    (needs podman on the host).
  - Fedora, Rocky Linux (RHEL) and openSUSE use firewalld by default
    (not ufw); Rocky Linux uses SELinux (limited in a container).
EOF
}

# =============================================================================
# Distro selection
# =============================================================================

DISTRO="${1:-}"
VERB="${2:-}"

case "$DISTRO" in
    arch)
        CONTAINER_NAME="hardener-test"
        DISTRO_LABEL="Arch Linux"
        EXIT_HINT="Exit with 'exit' or Ctrl+D"
        DEPS=("pacstrap:arch-install-scripts" "systemd-nspawn:systemd")
        POST_CREATE_NOTE=""
        ;;
    debian)
        DEBIAN_RELEASE="trixie"  # Debian 13
        CONTAINER_NAME="hardener-test-debian"
        DISTRO_LABEL="Debian ${DEBIAN_RELEASE}"
        EXIT_HINT="Exit with 'poweroff' or Ctrl+]]]"
        DEPS=("debootstrap:debootstrap" "systemd-nspawn:systemd-container")
        POST_CREATE_NOTE=""
        ;;
    fedora)
        FEDORA_VERSION="44"
        # Official Fedora container image, pulled and exported via podman.
        FEDORA_IMAGE="docker.io/library/fedora:${FEDORA_VERSION}"
        CONTAINER_NAME="hardener-test-fedora"
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
        CONTAINER_NAME="hardener-test-rhel"
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
        CONTAINER_NAME="hardener-test-opensuse"
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
        echo "Distros: arch debian fedora rhel opensuse"
        echo "Usage: sudo $0 <distro> [enter|shell|clean|help]"
        exit 1
        ;;
    *)
        log_error "Unknown distro: $DISTRO"
        echo "Distros: arch debian fedora rhel opensuse"
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
    pacstrap -c "$CONTAINER_PATH" base base-devel \
        openssh audit ufw iptables nftables \
        sudo polkit --noconfirm

    # Set up container
    log_info "Configuring container..."

    # Set root password to 'test' (container only!)
    echo "root:test" | chroot "$CONTAINER_PATH" chpasswd

    # Create test user
    chroot "$CONTAINER_PATH" useradd -m -G wheel testuser 2>/dev/null || true
    echo "testuser:test" | chroot "$CONTAINER_PATH" chpasswd

    # Allow wheel group sudo
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel"

    # Enable services that hardener tests
    chroot "$CONTAINER_PATH" systemctl enable sshd auditd 2>/dev/null || true
}

bootstrap_debian() {
    log_info "This may take a few minutes..."

    # Bootstrap minimal Debian system with essential utilities
    mkdir -p "$CONTAINER_PATH"
    debootstrap --include=systemd,systemd-sysv,dbus,passwd,login,sudo \
        "$DEBIAN_RELEASE" "$CONTAINER_PATH" http://deb.debian.org/debian

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
    chroot "$CONTAINER_PATH" apt-get install -y \
        openssh-server \
        auditd \
        ufw \
        iptables \
        nftables \
        sudo \
        policykit-1 \
        procps \
        iproute2

    # Allow sudo without password for testuser
    echo "testuser ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/testuser"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/testuser"

    # Enable services that hardener tests
    chroot "$CONTAINER_PATH" systemctl enable ssh auditd 2>/dev/null || true

    # Clean up apt cache to save space
    chroot "$CONTAINER_PATH" apt-get clean
}

bootstrap_fedora() {
    log_info "Pulling official Fedora image via podman..."

    # Pull + export the official image. Nothing rpm-related runs on the host,
    # so the Arch %_pkgverify_level=all policy never applies.
    podman_export_rootfs "$FEDORA_IMAGE" "hardener-fedora-export-$$"

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
    log_info "Installing test dependencies..."
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        dnf -y install \
        openssh-server \
        audit \
        firewalld \
        nftables \
        iptables \
        polkit \
        procps-ng \
        iproute

    # Allow sudo without password for testuser (wheel group)
    mkdir -p "$CONTAINER_PATH/etc/sudoers.d"
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"

    # Enable services that hardener tests
    chroot "$CONTAINER_PATH" systemctl enable sshd auditd 2>/dev/null || true

    # Clean up dnf cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" dnf clean all 2>/dev/null || true
}

bootstrap_rhel() {
    log_info "Pulling official Rocky Linux image via podman..."

    # Pull + export the official image. Nothing rpm-related runs on the host,
    # so the Arch %_pkgverify_level=all policy never applies.
    podman_export_rootfs "$ROCKY_IMAGE" "hardener-rhel-export-$$"

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
    log_info "Installing test dependencies..."
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        dnf -y install \
        openssh-server \
        audit \
        firewalld \
        nftables \
        iptables-nft \
        polkit \
        procps-ng \
        iproute

    # Allow sudo without password for testuser (wheel group)
    mkdir -p "$CONTAINER_PATH/etc/sudoers.d"
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"

    # Enable services that hardener tests
    chroot "$CONTAINER_PATH" systemctl enable sshd auditd 2>/dev/null || true

    # Clean up dnf cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" dnf clean all 2>/dev/null || true
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
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        zypper --gpg-auto-import-keys --non-interactive install \
        openssh-server \
        audit \
        firewalld \
        nftables \
        iptables \
        polkit \
        procps \
        iproute2 2>/dev/null || log_warn "Some packages may not have installed"

    # Allow sudo without password for testuser (wheel group)
    mkdir -p "$CONTAINER_PATH/etc/sudoers.d"
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"

    # Enable services that hardener tests
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        systemctl enable sshd auditd 2>/dev/null || true

    # Clean up zypper cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        zypper clean --all 2>/dev/null || true
}

# =============================================================================
# Verbs
# =============================================================================

create_container() {
    check_dependencies

    if [[ -d "$CONTAINER_PATH" ]]; then
        log_warn "Container already exists at $CONTAINER_PATH"
        log_info "Use '$SELF enter' to enter or '$SELF clean' to remove"
        exit 0
    fi

    log_info "Creating $DISTRO_LABEL container at $CONTAINER_PATH..."
    "bootstrap_$DISTRO"

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

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
    read -p "Are you sure? [y/N] " -n 1 -r
    echo

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
