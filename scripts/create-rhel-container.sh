#!/bin/bash
# Create an isolated Rocky Linux 9 container for safe root testing
# Rocky Linux is a 1:1 binary-compatible RHEL rebuild
# Uses systemd-nspawn for full systemd support
#
# Usage:
#   ./scripts/create-rhel-container.sh        # Create container
#   ./scripts/create-rhel-container.sh enter  # Enter existing container
#   ./scripts/create-rhel-container.sh clean  # Remove container

set -euo pipefail

CONTAINER_NAME="hardener-test-rhel"
CONTAINER_PATH="/var/lib/machines/${CONTAINER_NAME}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROCKY_VERSION="9"

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

    if ! command -v dnf &>/dev/null; then
        missing+=("dnf")
    fi

    if ! command -v systemd-nspawn &>/dev/null; then
        missing+=("systemd-container")
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
    log_info "This may take a few minutes..."

    # Bootstrap Rocky Linux system using dnf
    mkdir -p "$CONTAINER_PATH"

    # Create temporary repo config for bootstrapping (needed on non-RHEL hosts)
    TEMP_REPO=$(mktemp)
    cat > "$TEMP_REPO" << 'REPOEOF'
[baseos]
name=Rocky Linux $releasever - BaseOS
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-$releasever
enabled=1
gpgcheck=0

[appstream]
name=Rocky Linux $releasever - AppStream
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=AppStream-$releasever
enabled=1
gpgcheck=0
REPOEOF

    # Install minimal Rocky Linux system
    # Note: Rocky 9 uses dnf (not dnf5)
    dnf --releasever="$ROCKY_VERSION" \
        --installroot="$CONTAINER_PATH" \
        --setopt=install_weak_deps=False \
        --setopt=keepcache=False \
        --setopt=reposdir= \
        --config="$TEMP_REPO" \
        -y install \
        basesystem \
        rocky-release \
        systemd \
        dnf \
        passwd \
        sudo \
        util-linux

    rm -f "$TEMP_REPO"

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
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"
    chmod 440 "$CONTAINER_PATH/etc/sudoers.d/wheel-nopasswd"

    # Enable services that hardener tests
    chroot "$CONTAINER_PATH" systemctl enable sshd auditd 2>/dev/null || true

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

    # Clean up dnf cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" dnf clean all

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

    log_info "Entering Rocky Linux 9 (RHEL) container (project mounted at /project)..."
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

    log_info "Opening shell in Rocky Linux 9 (RHEL) container..."
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
Create an isolated Rocky Linux 9 (RHEL-equivalent) container for safe hardener testing.

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
      Build with: cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
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
