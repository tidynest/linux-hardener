#!/bin/bash
# Create an isolated Arch Linux container for safe root testing
# Uses systemd-nspawn for full systemd support
#
# Usage:
#   ./scripts/create-test-container.sh        # Create container
#   ./scripts/create-test-container.sh enter  # Enter existing container
#   ./scripts/create-test-container.sh clean  # Remove container

set -euo pipefail

CONTAINER_NAME="hardener-test"
CONTAINER_PATH="/var/lib/machines/${CONTAINER_NAME}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

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

    if ! command -v pacstrap &>/dev/null; then
        missing+=("arch-install-scripts")
    fi

    if ! command -v systemd-nspawn &>/dev/null; then
        missing+=("systemd")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required packages: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  sudo pacman -S ${missing[*]}"
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

    log_info "Creating Arch Linux container at $CONTAINER_PATH..."

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

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

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

    log_info "Entering container (project mounted at /project)..."
    log_info "Exit with 'exit' or Ctrl+D"
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

    log_info "Opening shell in container..."
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

    log_warn "This will permanently delete the test container!"
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
Create an isolated Arch Linux container for safe hardener testing.

Usage: sudo $0 [command]

Commands:
  (none)    Create new test container
  enter     Enter container (full boot with systemd)
  shell     Quick shell access (no systemd)
  clean     Remove the container
  help      Show this help

The container provides:
  - Full systemd support (for service testing)
  - Pre-installed: openssh, audit, ufw, nftables
  - Project mounted at /project
  - Root password: test
  - Test user: testuser / test (has sudo)

Example workflow:
  1. sudo ./scripts/create-test-container.sh
  2. sudo ./scripts/create-test-container.sh enter
  3. Inside container:
     cd /project
     cargo build --release
     ./target/release/hardener scan
     sudo ./target/release/hardener apply --all
  4. Exit and optionally clean up:
     sudo ./scripts/create-test-container.sh clean
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
