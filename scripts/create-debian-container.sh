#!/bin/bash
# Create an isolated Debian container for safe root testing
# Uses systemd-nspawn for full systemd support
#
# Usage:
#   ./scripts/create-debian-container.sh        # Create container
#   ./scripts/create-debian-container.sh enter  # Enter existing container
#   ./scripts/create-debian-container.sh clean  # Remove container

set -euo pipefail

CONTAINER_NAME="hardener-test-debian"
CONTAINER_PATH="/var/lib/machines/${CONTAINER_NAME}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEBIAN_RELEASE="trixie"  # Debian 13

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

    if ! command -v debootstrap &>/dev/null; then
        missing+=("debootstrap")
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

    log_info "Creating Debian ${DEBIAN_RELEASE} container at $CONTAINER_PATH..."
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

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

    # Clean up apt cache to save space
    chroot "$CONTAINER_PATH" apt-get clean

    log_info "Container created successfully!"
    echo ""
    echo "To enter the container:"
    echo "  sudo $0 enter"
    echo ""
    echo "Inside the container, the project is at /project"
    echo "Root password: test"
    echo "Test user: testuser / test"
}

enter_container() {
    if [[ ! -d "$CONTAINER_PATH" ]]; then
        log_error "Container does not exist. Run '$0' first to create it."
        exit 1
    fi

    log_info "Entering Debian container (project mounted at /project)..."
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

    log_info "Opening shell in Debian container..."
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

    log_warn "This will permanently delete the Debian test container!"
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
Create an isolated Debian container for safe hardener testing.

Usage: sudo $0 [command]

Commands:
  (none)    Create new Debian ${DEBIAN_RELEASE} container
  enter     Enter container (full boot with systemd)
  shell     Quick shell access (no systemd)
  clean     Remove the container
  help      Show this help

The container provides:
  - Debian ${DEBIAN_RELEASE} (Debian 13)
  - Full systemd support (for service testing)
  - Pre-installed: openssh-server, auditd, ufw, nftables
  - Project mounted at /project
  - Root password: test
  - Test user: testuser / test (has sudo)

Example workflow:
  1. sudo ./scripts/create-debian-container.sh
  2. sudo ./scripts/create-debian-container.sh enter
  3. Inside container:
     cd /project
     ./target/release/hardener scan
     sudo ./scripts/full-test-suite.sh
  4. Exit and optionally clean up:
     sudo ./scripts/create-debian-container.sh clean

Note: The pre-built binary from Arch should work on Debian (static linking).
      If not, you may need to build inside the container.
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
