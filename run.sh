#!/bin/bash
# ================================================================
# run.sh — Full Automation Script
# CSC1107 Operating Systems — Project 12
# Raspberry Pi 4 · aarch64 · Raspberry Pi OS 64-bit
#
# This script automates every step end-to-end:
#   1. Pre-flight checks (root, kernel headers)
#   2. Compile the kernel module        (make module)
#   3. Compile the user-space app       (make user_app)
#   4. Remove any stale module instance (rmmod)
#   5. Load the new module              (insmod)
#   6. Verify /dev/secure_dev exists
#   7. Set device permissions
#   8. Print initial dmesg output
#   9. Run the user-space demo          (./user_app --demo)
#  10. Print final dmesg output
#  11. Offer to unload the module
#
# Usage:
#   sudo bash run.sh
#
# Optional: custom credentials
#   sudo bash run.sh --username myuser --password mypassword
# ================================================================

# ── Strict mode: exit on error, undefined var, or pipe failure ──
set -euo pipefail

# ── Configuration ───────────────────────────────────────────────
MODULE_NAME="secure_driver"
MODULE_FILE="${MODULE_NAME}.ko"
DEVICE_PATH="/dev/secure_dev"
USER_APP="./user_app"

# Default credentials (overridable via --username / --password flags)
CUSTOM_USERNAME=""
CUSTOM_PASSWORD=""

# ── Terminal colours ────────────────────────────────────────────
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'   # No colour / reset

# ================================================================
# Helper functions
# ================================================================

print_header() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}"
}

ok()   { echo -e "${GREEN}[  OK  ]${NC}  $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC}  $*"; }
info() { echo -e "${CYAN}[ INFO ]${NC}  $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC}  $*"; }

# Prints a step header (numbered)
step() {
    echo ""
    echo -e "${BOLD}── Step $1: $2 ─${NC}"
}

# ================================================================
# Argument parsing
# ================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --username)
                CUSTOM_USERNAME="$2"
                shift 2 ;;
            --password)
                CUSTOM_PASSWORD="$2"
                shift 2 ;;
            --help|-h)
                echo "Usage: sudo bash run.sh [--username <user>] [--password <pass>]"
                exit 0 ;;
            *)
                warn "Unknown argument: $1 (ignoring)"
                shift ;;
        esac
    done
}

# ================================================================
# Pre-flight checks
# ================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        fail "This script must be run as root."
        echo "  → Run: sudo bash run.sh"
        exit 1
    fi
    ok "Running as root"
}

check_kernel_headers() {
    local KVER
    KVER="$(uname -r)"
    local KDIR="/lib/modules/${KVER}/build"

    if [[ ! -d "$KDIR" ]]; then
        warn "Kernel headers not found at ${KDIR}"
        info "Attempting to install: linux-headers-${KVER}"
        apt-get update -qq
        apt-get install -y "linux-headers-${KVER}" || {
            fail "Could not install kernel headers. Install manually:"
            echo "  sudo apt-get install linux-headers-\$(uname -r)"
            exit 1
        }
    fi
    ok "Kernel headers found: ${KDIR}"
}

check_build_tools() {
    local missing=()
    for tool in make gcc; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing build tools: ${missing[*]}"
        info "Installing build-essential..."
        apt-get install -y build-essential || {
            fail "Could not install build tools."
            exit 1
        }
    fi
    ok "Build tools available (make, gcc)"
}

check_source_files() {
    local missing=()
    for f in core.c crypto.c fops.c peripheral.c session.c secure_driver.h user_app.c Makefile; do
        [[ -f "$f" ]] || missing+=("$f")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "Missing source files: ${missing[*]}"
        echo "  → Make sure you are running this script from the project directory."
        exit 1
    fi
    ok "All source files present"
}

# ================================================================
# Build steps
# ================================================================

compile_module() {
    step "1" "Compile kernel module (make module)"
    make module
    if [[ ! -f "$MODULE_FILE" ]]; then
        fail "Kernel module ${MODULE_FILE} not found after build."
        exit 1
    fi
    ok "Kernel module built: ${MODULE_FILE}"
    ls -lh "${MODULE_FILE}"
}

compile_user_app() {
    step "2" "Compile user-space application (gcc)"
    make user_app
    ok "User application built: user_app"
}

# ================================================================
# Module management
# ================================================================

unload_existing_module() {
    if lsmod | grep -q "^${MODULE_NAME}[[:space:]]"; then
        warn "Module '${MODULE_NAME}' is already loaded — removing it first"
        rmmod "${MODULE_NAME}" || {
            fail "Could not unload existing module."
            echo "  → It may be in use. Try: sudo fuser /dev/secure_dev"
            exit 1
        }
        ok "Existing module removed"
        sleep 1
    fi
}

load_module() {
    step "3" "Load kernel module (insmod)"
    unload_existing_module

    # Build the insmod command; add custom credentials if provided
    local INSMOD_CMD="insmod ${MODULE_FILE}"
    if [[ -n "$CUSTOM_USERNAME" ]]; then
        INSMOD_CMD+=" param_username=${CUSTOM_USERNAME}"
        info "Using custom username: ${CUSTOM_USERNAME}"
    fi
    if [[ -n "$CUSTOM_PASSWORD" ]]; then
        INSMOD_CMD+=" param_password=${CUSTOM_PASSWORD}"
        info "Using custom password: (hidden)"
    fi

    eval "$INSMOD_CMD" || {
        fail "insmod failed. Kernel log:"
        dmesg | tail -20
        exit 1
    }

    ok "Module loaded: ${MODULE_NAME}"

    # Give udev a moment to create the device node
    sleep 1
}

verify_device_node() {
    step "4" "Verify device node exists at ${DEVICE_PATH}"

    if [[ ! -e "$DEVICE_PATH" ]]; then
        warn "udev has not yet created ${DEVICE_PATH}, attempting manual creation..."

        # Look up the major number assigned to our device
        local MAJOR
        MAJOR=$(awk "\$2 == \"${MODULE_NAME}\" {print \$1}" /proc/devices 2>/dev/null || true)

        if [[ -z "$MAJOR" ]]; then
            fail "Could not find major number for '${MODULE_NAME}' in /proc/devices"
            dmesg | grep secure_dev | tail -10
            exit 1
        fi

        mknod "${DEVICE_PATH}" c "${MAJOR}" 0
        ok "Device node created manually: ${DEVICE_PATH} (major ${MAJOR})"
    else
        ok "Device node exists: ${DEVICE_PATH}"
    fi

    # Allow any user to open the device.
    # Authentication is enforced by the driver itself.
    chmod 666 "${DEVICE_PATH}"
    ok "Permissions set: $(ls -la ${DEVICE_PATH})"
}

# ================================================================
# Logging helpers
# ================================================================

show_dmesg() {
    local label="${1:-}"
    echo ""
    echo -e "${CYAN}──────────────── dmesg (secure_dev) ${label} ────────────────${NC}"
    dmesg | grep --color=never "secure_dev" | tail -40 || true
    echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"
}

# ================================================================
# Cleanup / unload
# ================================================================

offer_unload() {
    echo ""
    read -rp "$(echo -e "${BOLD}Unload the kernel module now? [y/N]: ${NC}")" choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        rmmod "${MODULE_NAME}" 2>/dev/null && ok "Module '${MODULE_NAME}' unloaded" \
            || warn "Could not unload (it may still be open by another process)"
    else
        warn "Module '${MODULE_NAME}' left loaded."
        info "To unload later: sudo rmmod ${MODULE_NAME}"
    fi
}

# ================================================================
# Main execution flow
# ================================================================

main() {
    parse_args "$@"

    print_header "Secure Character Device Driver — Automation Script"
    echo -e "  CSC1107 Operating Systems — Project 12"
    echo -e "  Kernel: $(uname -r)   Arch: $(uname -m)"
    echo ""

    # ── Pre-flight ──
    print_header "Pre-flight Checks"
    check_root
    check_kernel_headers
    check_build_tools
    check_source_files

    # ── Build ──
    print_header "Build"
    compile_module
    compile_user_app

    # ── Load ──
    print_header "Load Kernel Module"
    load_module
    verify_device_node

    # ── Initial dmesg ──
    show_dmesg "[after module load]"

    # ── Run demo ──
    print_header "Running User-Space Demo (./user_app --demo)"
    echo ""
    ${USER_APP} --demo
    # Note: set -e is active, but user_app returning non-zero shouldn't
    # abort the script — we still want to show dmesg.  Use || true.
    true

    # ── Final dmesg ──
    show_dmesg "[after demo]"

    # ── Done ──
    print_header "All Steps Complete"
    ok "Kernel module: /proc/modules entry:"
    lsmod | grep "^${MODULE_NAME}" || true

    ok "Device node:  $(ls -la ${DEVICE_PATH} 2>/dev/null || echo 'not found')"

    echo ""
    info "Useful commands:"
    echo "   dmesg | grep secure_dev          — view all driver log messages"
    echo "   cat /proc/modules | grep secure  — confirm module is loaded"
    echo "   ls -la /dev/secure_dev           — inspect device node"
    echo "   sudo rmmod ${MODULE_NAME}              — unload the module"
    echo ""

    offer_unload
    echo ""
    ok "run.sh finished."
}

# ── Entry point ──
main "$@"
