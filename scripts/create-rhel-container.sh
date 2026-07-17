#!/bin/bash
# Create an isolated Rocky Linux 10 container for safe root testing
# Rocky Linux is a 1:1 binary-compatible RHEL rebuild
# Uses systemd-nspawn for full systemd support
#
# Bootstraps by pulling the official Rocky Linux container image with podman and
# exporting its root filesystem. Arch's rpm enforces %_pkgverify_level=all,
# which `dnf --nogpgcheck` cannot override, so a host-dnf bootstrap of a keyless
# installroot always fails GPG. The image runs its own scriptlets/keys natively.
#
# Usage:
#   ./scripts/create-rhel-container.sh        # Create container
#   ./scripts/create-rhel-container.sh enter  # Enter existing container
#   ./scripts/create-rhel-container.sh clean  # Remove container

set -euo pipefail

CONTAINER_NAME="hardener-test-rhel"
CONTAINER_PATH="/var/lib/machines/${CONTAINER_NAME}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROCKY_VERSION="10"

# Official Rocky Linux container image, pulled and exported via podman.
ROCKY_IMAGE="docker.io/rockylinux/rockylinux:${ROCKY_VERSION}"

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (for container management)"
        echo "Usage: sudo $0 [enter|clean]"
        exit 1
    fi
}

check_dependencies() {
    local missing=()

    if ! command -v podman &>/dev/null; then
        missing+=("podman")
    fi

    if ! command -v systemd-nspawn &>/dev/null; then
        missing+=("systemd-container")
    fi

    if ! command -v tar &>/dev/null; then
        missing+=("tar")
    fi

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

create_container() {
    check_dependencies

    if [[ -d "$CONTAINER_PATH" ]]; then
        log_warn "Container already exists at $CONTAINER_PATH"
        log_info "Use '$0 enter' to enter or '$0 clean' to remove"
        exit 0
    fi

    log_info "Creating Rocky Linux ${ROCKY_VERSION} (RHEL-equivalent) container at $CONTAINER_PATH..."
    log_info "Pulling official Rocky Linux image via podman..."

    # Pull + export the official image. Nothing rpm-related runs on the host, so
    # the Arch %_pkgverify_level=all policy never applies.
    local tmp_container="hardener-rhel-export-$$"

    if ! podman pull "$ROCKY_IMAGE"; then
        log_error "Failed to pull $ROCKY_IMAGE"
        exit 1
    fi

    mkdir -p "$CONTAINER_PATH"
    log_info "Exporting image root filesystem to $CONTAINER_PATH..."
    podman create --name "$tmp_container" "$ROCKY_IMAGE" >/dev/null
    if ! podman export "$tmp_container" | tar -x -C "$CONTAINER_PATH"; then
        podman rm -f "$tmp_container" >/dev/null 2>&1 || true
        rm -rf "$CONTAINER_PATH"
        log_error "Failed to export image filesystem"
        exit 1
    fi
    podman rm -f "$tmp_container" >/dev/null 2>&1 || true

    if [[ ! -x "$CONTAINER_PATH/usr/bin/bash" ]]; then
        log_error "Image export incomplete: /usr/bin/bash missing"
        rm -rf "$CONTAINER_PATH"
        exit 1
    fi
    log_info "Base system extracted from official image"

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

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

    # Clean up dnf cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" dnf clean all 2>/dev/null || true

    log_info "Container created successfully!"
    echo ""
    echo "To enter the container:"
    echo "  sudo $0 enter"
    echo ""
    echo "Inside the container, the project is at /project"
    echo "Root password: test"
    echo "Test user: testuser / test (has sudo via wheel group)"
    echo ""
    echo "Note: Rocky Linux (RHEL) uses firewalld by default (not ufw)"
    echo "Note: Rocky Linux (RHEL) uses SELinux (limited in container)"
}

enter_container() {
    if [[ ! -d "$CONTAINER_PATH" ]]; then
        log_error "Container does not exist. Run '$0' first to create it."
        exit 1
    fi

    log_info "Entering Rocky Linux ${ROCKY_VERSION} (RHEL) container (project mounted at /project)..."
    log_info "Exit with 'poweroff' or Ctrl+]]]"
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
        log_error "Container does not exist. Run '$0' first to create it."
        exit 1
    fi

    log_info "Opening shell in Rocky Linux ${ROCKY_VERSION} (RHEL) container..."
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

    log_warn "This will permanently delete the Rocky Linux (RHEL) test container!"
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

show_help() {
    cat << EOF
Create an isolated Rocky Linux ${ROCKY_VERSION} (RHEL-equivalent) container for safe hardener testing.

Usage: sudo $0 [command]

Commands:
  (none)    Create new Rocky Linux ${ROCKY_VERSION} container
  enter     Enter container (full boot with systemd)
  shell     Quick shell access (no systemd)
  clean     Remove the container
  help      Show this help

The container provides:
  - Rocky Linux ${ROCKY_VERSION} (1:1 RHEL binary compatible)
  - Full systemd support (for service testing)
  - Pre-installed: openssh-server, audit, firewalld, nftables
  - Project mounted at /project
  - Root password: test
  - Test user: testuser / test (has sudo via wheel)

Example workflow:
  1. sudo ./scripts/create-rhel-container.sh
  2. sudo ./scripts/create-rhel-container.sh enter
  3. Inside container:
     cd /project
     ./target/release/hardener scan
     sudo ./scripts/full-test-suite.sh
  4. Exit and optionally clean up:
     sudo ./scripts/create-rhel-container.sh clean

Note: Use the musl static binary for cross-distribution compatibility.
      Bootstrap pulls ${ROCKY_IMAGE} via podman (needs podman on the host).
EOF
}

# Main
check_root

case "${1:-}" in
    enter)
        enter_container
        ;;
    shell)
        enter_container_shell
        ;;
    clean)
        clean_container
        ;;
    help|--help|-h)
        show_help
        ;;
    "")
        create_container
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
