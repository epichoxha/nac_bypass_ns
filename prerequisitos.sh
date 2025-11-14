#!/bin/bash

# -----------------------------------------------------------------------------
# Script: prerequisitos.sh
# Function: automates environment preparation for using the NAC bypass.
#   - Checks base packages and installs them if missing.
#   - Verifies that the br_netfilter kernel module is loaded and persistent.
#   - Shows available network interfaces with usage suggestions.
#   - Checks that main scripts exist and have execution permissions.
#   - Validates that essential tools are available (apt-get, modprobe, ip, etc.).
#   - Checks basic system data (distribution, number of useful interfaces, etc.).
#   - DETECTS AND REMOVES AVAHI (mDNS/ZeroConf) if installed/active.
# -----------------------------------------------------------------------------

set -euo pipefail

PACKAGES=(
  bridge-utils
  ethtool
  macchanger
  arptables
  ebtables
  iptables
  net-tools
  tcpdump
)

SCRIPT_FILES=(
  "nac_bypass_setup.sh"
  "awareness.sh"
)

BASE_COMMANDS=(
  "apt-get"
  "modprobe"
  "ip"
  "lsmod"
  "dpkg"
  "chmod"
  "systemctl"
  "timedatectl"
  "ifconfig"
  "brctl"
  "tcpdump"
  "sysctl"
  "ethtool"
)

NETWORK_SERVICES=(
  "NetworkManager.service"
  "network-manager.service"
  "systemd-networkd.service"
)

COLOR_INFO="\e[1;34m"
COLOR_OK="\e[1;32m"
COLOR_WARN="\e[1;31m"
COLOR_RESET="\e[0m"

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    echo -e "${COLOR_WARN}[!] Run this script as root (use sudo).${COLOR_RESET}"
    exit 1
  fi
}

info() {
  echo -e "${COLOR_INFO}[*] $1${COLOR_RESET}"
}

ok() {
  echo -e "${COLOR_OK}[+] $1${COLOR_RESET}"
}

warn() {
  echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"
}

verify_os() {
  info "Checking system information..."

  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    local name="${NAME:-Unknown}"
    local version="${VERSION_ID:-}"
    info "Detected system: ${name} ${version}"

    local base="${ID_LIKE:-$ID}"
    if [[ "${base,,}" != *"debian"* && "${ID,,}" != "debian" && "${ID,,}" != "ubuntu" ]]; then
      warn "This script was tested on Debian/Ubuntu-like systems; check commands manually if using another distribution."
    fi
  else
    warn "/etc/os-release not found. Could not identify distribution."
  fi
}

verify_base_commands() {
  info "Checking basic commands available in the system..."
  local missing=()

  for cmd in "${BASE_COMMANDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      ok "Command found: $cmd"
    else
      warn "Command not found: $cmd"
      missing+=("$cmd")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Missing basic commands: ${missing[*]}."
    warn "Install necessary packages or adjust PATH before continuing."
  fi
}

install_packages() {
  info "Verifying necessary packages..."
  local missing=()

  for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      ok "Package present: $pkg"
    else
      warn "Missing package: $pkg"
      missing+=("$pkg")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    if command -v apt-get >/dev/null 2>&1; then
      info "Installing missing packages: ${missing[*]}"
      apt-get update
      apt-get install -y "${missing[@]}"
    else
      warn "apt-get not available. Install manually: ${missing[*]}"
    fi
  else
    info "No pending packages."
  fi
}

ensure_module() {
  local module="br_netfilter"
  info "Checking kernel module $module..."

  if lsmod | grep -qw "$module"; then
    ok "Module $module already loaded."
  else
    warn "Module $module not loaded. Attempting to load it."
    modprobe "$module"
    ok "Module $module loaded successfully."
  fi

  local modules_file="/etc/modules"
  if grep -E "^${module}$" "$modules_file" >/dev/null 2>&1; then
    info "Module $module already configured to load at boot."
  else
    info "Adding $module to $modules_file to load on each boot."
    echo "$module" >> "$modules_file"
    ok "Persistent module $module configured."
  fi
}

detect_interfaces() {
  info "Detecting available network interfaces..."

  if ! command -v ip >/dev/null 2>&1; then
    warn "Command 'ip' not available; cannot list interfaces."
    return
  fi

  local interfaces
  interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')

  if [ -z "$interfaces" ]; then
    warn "No network interfaces found other than lo."
    return
  fi

  echo ""
  echo "Detected interfaces:"
  local counter=1
  local total=0
  local recommended_switch=""
  local recommended_victim=""
  local wifi_present=0
  local -a summaries=()

  while IFS= read -r iface; do
    local detail
    detail=$(ip -o -4 addr show "$iface" | awk '{print $4}' || true)

    local carrier_val=""
    local carrier_text="link status unknown"
    if [ -f "/sys/class/net/$iface/carrier" ]; then
      carrier_val=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo "")
      if [ "$carrier_val" = "1" ]; then
        carrier_text="link active"
      elif [ "$carrier_val" = "0" ]; then
        carrier_text="no link"
      fi
    fi

    local type="wired"
    if [[ "$iface" == wl* || "$iface" == wifi* ]]; then
      type="wireless"
      wifi_present=1
    fi

    local line="  $counter) $iface -> ${type}, ${carrier_text}"
    if [ -n "$detail" ]; then
      line="$line, IPs: $detail"
    else
      line="$line, no IP assigned currently"
    fi

    summaries+=("$line")

    if [ "$type" = "wired" ]; then
      if [ "$carrier_val" = "1" ] && [ -z "$recommended_switch" ]; then
        recommended_switch="$iface"
      fi
      if [ -z "$detail" ] && [ "$carrier_val" != "1" ] && [ -z "$recommended_victim" ]; then
        recommended_victim="$iface"
      fi
    fi

    counter=$((counter + 1))
    total=$((total + 1))
  done <<< "$interfaces"

  for line in "${summaries[@]}"; do
    echo "$line"
  done

  if [ "$total" -lt 2 ]; then
    warn "Only $total useful interface(s) detected. Bypass requires at least two (switch and victim)."
  else
    info "Total useful interfaces detected: $total"
  fi

  echo ""
  echo "Automatic suggestions:"
  if [ -n "$recommended_switch" ]; then
    echo "  - Suggested switch side: $recommended_switch (wired, active link)."
  else
    echo "  - Suggested switch side: connect a cable and run script again; no wired interface with active link detected."
  fi

  if [ -n "$recommended_victim" ]; then
    echo "  - Suggested victim side: $recommended_victim (wired without IP assigned, ideal for victim machine)."
  else
    echo "  - Suggested victim side: use a wired interface without IP (for example, disconnect and retry with another NIC)."
  fi

  if [ "$wifi_present" -eq 1 ]; then
    echo "  - At least one wireless interface detected; avoid using it for bridging, requires Ethernet interfaces."
  fi

  echo "  - If in doubt, run 'sudo ethtool <interface>' to check link status."
}

prepare_scripts() {
  info "Checking main scripts in current directory..."
  local missing=()

  for script in "${SCRIPT_FILES[@]}"; do
    if [ -f "$script" ]; then
      ok "Found: $script"
      if [ ! -x "$script" ]; then
        info "Assigning execution permissions to $script"
        chmod +x "$script"
        ok "Execution permissions applied to $script"
      else
        info "$script already has execution permissions."
      fi
    else
      warn "File $script not found in $(pwd)."
      missing+=("$script")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Copy missing files before continuing: ${missing[*]}"
  fi
}

check_interfering_services() {
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not available; cannot check network service status."
    return
  fi

  info "Checking network services that could interfere with manual configuration..."
  local detected=0

  for svc in "${NETWORK_SERVICES[@]}"; do
    if systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$svc"; then
      local state=$(systemctl is-active "$svc" 2>/dev/null || true)
      local enabled=$(systemctl is-enabled "$svc" 2>/dev/null || true)

      if [ "$state" = "active" ]; then
        warn "Active service detected: $svc (will be stopped during bypass)."
        detected=1
      fi

      if [ "$enabled" = "enabled" ]; then
        info "Service $svc is enabled. Consider disabling it if you want a more static environment."
      fi
    fi
  done

  if [ "$detected" -eq 0 ]; then
    info "No active network services detected that interfere immediately."
  fi
}

# ---------------------------
# New function: disable_avahi
# - Stops/disables/masks Avahi if active
# - Attempts to uninstall avahi-daemon and avahi-utils packages via apt-get if available
# - Checks if mDNS port (UDP 5353) remains free afterwards
# ---------------------------
disable_avahi() {
  info "Checking for Avahi (mDNS/ZeroConf) presence..."

  # We need systemctl and dpkg to verify status/installation
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not available: only performing check via dpkg/ps/ss."
  fi

  local installed=0
  if dpkg -s avahi-daemon >/dev/null 2>&1 || dpkg -s avahi-utils >/dev/null 2>&1; then
    installed=1
  fi

  if [ "$installed" -eq 0 ]; then
    info "Avahi doesn't seem to be installed (no avahi-daemon/avahi-utils packages found)."
  else
    info "Avahi detected: proceeding to stop, disable, mask and (optionally) uninstall."
    # stop and disable (if systemctl available)
    if command -v systemctl >/dev/null 2>&1; then
      info "Stopping avahi (systemctl)..."
      systemctl stop avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || true
      info "Disabling avahi for future boot..."
      systemctl disable avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || true
      info "Masking avahi to prevent reactivations..."
      systemctl mask avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || true
    else
      info "systemctl not available; attempting to kill processes manually."
      pkill -f avahi-daemon || true
    fi

    # attempt uninstallation via apt-get if exists
    if command -v apt-get >/dev/null 2>&1; then
      info "Uninstalling avahi packages (apt-get)..."
      apt-get update
      apt-get remove --purge -y avahi-daemon avahi-utils || warn "Failed to remove avahi packages with apt-get."
      apt-get autoremove --purge -y || true
      ok "Uninstall command executed (if packages were present)."
    else
      warn "apt-get not available: avahi disabled but not uninstalled."
    fi
  fi

  # final checks: processes and UDP port 5353
  if pgrep -af avahi-daemon >/dev/null 2>&1; then
    warn "avahi-daemon processes still active detected. Attempting to terminate..."
    pkill -f avahi-daemon || true
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -lunp 2>/dev/null | grep -q ":5353"; then
      warn "UDP port 5353 (mDNS) still in use. Check active processes manually."
    else
      ok "UDP port 5353 not detected: mDNS appears inactive."
    fi
  else
    info "Cannot check port 5353: 'ss' not available."
  fi
}

main() {
  require_root
  verify_os
  verify_base_commands
  install_packages
  ensure_module
  detect_interfaces
  prepare_scripts
  check_interfering_services

  # Added call: detect and remove Avahi if exists
  disable_avahi

  ok "Ready. Environment is now prepared to run bypass scripts."
}

main "$@"
