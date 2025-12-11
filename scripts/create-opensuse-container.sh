#!/bin/bash
# Create an isolated openSUSE container for safe root testing
# Uses systemd-nspawn for full systemd support
#
# This script downloads a pre-built openSUSE image from the official registry
# which is more reliable than cross-distribution bootstrapping with zypper.
#
# Usage:
#   ./scripts/create-opensuse-container.sh        # Create container
#   ./scripts/create-opensuse-container.sh enter  # Enter existing container
#   ./scripts/create-opensuse-container.sh clean  # Remove container

set -euo pipefail

CONTAINER_NAME="hardener-test-opensuse"
CONTAINER_PATH="/var/lib/machines/${CONTAINER_NAME}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPENSUSE_VERSION="15.6"

# Official openSUSE Leap rootfs tarball
ROOTFS_URL="https://download.opensuse.org/distribution/leap/${OPENSUSE_VERSION}/appliances/openSUSE-Leap-${OPENSUSE_VERSION}-Minimal-VM.x86_64-Cloud.qcow2"
# Alternative: use the JeOS (Just enough OS) image which is smaller
JEOS_URL="https://download.opensuse.org/distribution/leap/${OPENSUSE_VERSION}/appliances/"

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

    if ! command -v systemd-nspawn &>/dev/null; then
        missing+=("systemd-container")
    fi

    if ! command -v curl &>/dev/null; then
        missing+=("curl")
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

    log_info "Creating openSUSE Leap ${OPENSUSE_VERSION} container at $CONTAINER_PATH..."
    log_info "Using machinectl pull-tar for official openSUSE image..."

    # Method 1: Try machinectl pull-tar (cleanest approach)
    # openSUSE provides container images at registry.opensuse.org
    if machinectl pull-tar --verify=no \
        "https://download.opensuse.org/repositories/Virtualization:/containers:/images/openSUSE_Leap_${OPENSUSE_VERSION}/opensuse-leap-image.x86_64-lxc.tar.xz" \
        "$CONTAINER_NAME" 2>/dev/null; then
        log_info "Downloaded official openSUSE container image"
    else
        # Method 2: Manual bootstrap with proper SSL handling
        log_warn "machinectl pull failed, trying manual bootstrap..."

        mkdir -p "$CONTAINER_PATH"

        # Download and extract the openSUSE-Toolbox image (minimal container-ready image)
        TOOLBOX_URL="https://registry.opensuse.org/v2/opensuse/leap/blobs/sha256:latest"

        # Alternative: Use debootstrap-like approach with zypper from within a working container
        # For now, create minimal structure and use zypper with SSL workaround

        log_info "Creating minimal openSUSE structure..."

        # Create basic directory structure
        mkdir -p "$CONTAINER_PATH"/{bin,boot,dev,etc,home,lib,lib64,mnt,opt,proc,root,run,sbin,srv,sys,tmp,usr,var}
        mkdir -p "$CONTAINER_PATH"/usr/{bin,lib,lib64,sbin,share}
        mkdir -p "$CONTAINER_PATH"/var/{cache,lib,log,tmp}
        mkdir -p "$CONTAINER_PATH"/etc/{zypp,sysconfig}

        # Copy SSL certificates from host (fixes curl error 60)
        if [[ -d /etc/ssl/certs ]]; then
            mkdir -p "$CONTAINER_PATH/etc/ssl"
            cp -a /etc/ssl/certs "$CONTAINER_PATH/etc/ssl/"
        fi
        if [[ -f /etc/ssl/cert.pem ]]; then
            cp /etc/ssl/cert.pem "$CONTAINER_PATH/etc/ssl/"
        fi
        if [[ -d /etc/pki ]]; then
            cp -a /etc/pki "$CONTAINER_PATH/etc/"
        fi
        if [[ -d /etc/ca-certificates ]]; then
            cp -a /etc/ca-certificates "$CONTAINER_PATH/etc/"
        fi

        # Copy DNS configuration
        cp /etc/resolv.conf "$CONTAINER_PATH/etc/resolv.conf"

        # Use zypper from host to bootstrap (with SSL certs now available)
        if command -v zypper &>/dev/null; then
            log_info "Bootstrapping with zypper..."

            REPO_BASE="https://download.opensuse.org/distribution/leap/${OPENSUSE_VERSION}/repo/oss"
            REPO_UPDATE="https://download.opensuse.org/update/leap/${OPENSUSE_VERSION}/oss"

            zypper --root "$CONTAINER_PATH" \
                --gpg-auto-import-keys \
                --non-interactive \
                addrepo --refresh "$REPO_BASE" "repo-oss" || true

            zypper --root "$CONTAINER_PATH" \
                --gpg-auto-import-keys \
                --non-interactive \
                addrepo --refresh "$REPO_UPDATE" "repo-update" || true

            zypper --root "$CONTAINER_PATH" \
                --gpg-auto-import-keys \
                --non-interactive \
                refresh || log_warn "Repository refresh had issues, continuing..."

            # Install base packages - zypper may return non-zero due to posttrans warnings
            # which are harmless, so we check for key files afterward instead
            zypper --root "$CONTAINER_PATH" \
                --gpg-auto-import-keys \
                --non-interactive \
                install --no-recommends \
                patterns-base-minimal_base \
                systemd \
                zypper \
                shadow \
                sudo \
                util-linux \
                ca-certificates \
                ca-certificates-mozilla || log_warn "zypper returned non-zero (may be harmless posttrans warnings)"

            # Verify essential files exist
            if [[ ! -x "$CONTAINER_PATH/usr/bin/bash" ]] || [[ ! -x "$CONTAINER_PATH/usr/lib/systemd/systemd" ]]; then
                log_error "zypper bootstrap failed - essential files missing"
                log_error "Consider using a Fedora or Debian container instead for testing"
                rm -rf "$CONTAINER_PATH"
                exit 1
            fi
            log_info "Base system installed successfully"
        else
            log_error "zypper not available and image download failed"
            log_error "Install zypper: sudo pacman -S zypper"
            rm -rf "$CONTAINER_PATH"
            exit 1
        fi
    fi

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

    # Create bind mount point for project
    mkdir -p "$CONTAINER_PATH/project"

    # Clean up zypper cache to save space
    systemd-nspawn --quiet --directory="$CONTAINER_PATH" \
        zypper clean --all 2>/dev/null || true

    log_info "Container created successfully!"
    echo ""
    echo "To enter the container:"
    echo "  sudo $0 enter"
    echo ""
    echo "Inside the container, the project is at /project"
    echo "Root password: test"
    echo "Test user: testuser / test (has sudo via wheel group)"
    echo ""
    echo "Note: openSUSE uses firewalld by default (not ufw)"
}

enter_container() {
    if [[ ! -d "$CONTAINER_PATH" ]]; then
        log_error "Container does not exist. Run '$0' first to create it."
        exit 1
    fi

    log_info "Entering openSUSE container (project mounted at /project)..."
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

    log_info "Opening shell in openSUSE container..."
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

    log_warn "This will permanently delete the openSUSE test container!"
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
Create an isolated openSUSE container for safe hardener testing.

Usage: sudo $0 [command]

Commands:
  (none)    Create new openSUSE Leap ${OPENSUSE_VERSION} container
  enter     Enter container (full boot with systemd)
  shell     Quick shell access (no systemd)
  clean     Remove the container
  help      Show this help

The container provides:
  - openSUSE Leap ${OPENSUSE_VERSION}
  - Full systemd support (for service testing)
  - Pre-installed: openssh, audit, firewalld, nftables
  - Project mounted at /project
  - Root password: test
  - Test user: testuser / test (has sudo via wheel)

Example workflow:
  1. sudo ./scripts/create-opensuse-container.sh
  2. sudo ./scripts/create-opensuse-container.sh enter
  3. Inside container:
     cd /project
     ./target/release/hardener scan
     sudo ./scripts/root-test-suite.sh
  4. Exit and optionally clean up:
     sudo ./scripts/create-opensuse-container.sh clean

Note: Use the musl static binary for cross-distribution compatibility.
      openSUSE uses firewalld by default, similar to Fedora/RHEL.
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
