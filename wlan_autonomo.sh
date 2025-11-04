#!/bin/bash

# -----------------------------------------------------------------------------
# Script: wlan_autonomo.sh
# Function: Keep Wi-Fi interface alive (default wlan0) even if
#           NetworkManager stops during bypass. Configures
#           wpa_supplicant and dhcpcd to manage the interface
#           independently and allows easy reversal of changes.
# Basic usage:
#   sudo ./wlan_autonomo.sh apply --ssid "MyWiFi" --psk "MySuperSecretKey"
#   sudo ./wlan_autonomo.sh status
#   sudo ./wlan_autonomo.sh restore
# -----------------------------------------------------------------------------

set -euo pipefail

VERSION="0.1.0"
WLAN_IFACE="wlan0"
WPACFG_PREFIX="/etc/wpa_supplicant/wpa_supplicant"
WPACFG_FILE="${WPACFG_PREFIX}-${WLAN_IFACE}.conf"
NM_OVERRIDE="/etc/NetworkManager/conf.d/wlan_autonomo.conf"

COLOR_INFO="\e[1;34m"
COLOR_OK="\e[1;32m"
COLOR_WARN="\e[1;31m"
COLOR_RESET="\e[0m"

info() { echo -e "${COLOR_INFO}[*] $1${COLOR_RESET}"; }
ok()   { echo -e "${COLOR_OK}[+] $1${COLOR_RESET}"; }
warn() { echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"; }

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    warn "Run this script as root (use sudo)."
    exit 1
  fi
}

ensure_tools() {
  local missing=()
  for cmd in wpa_passphrase systemctl ip; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Missing tools: ${missing[*]}"
    warn "Install 'wpasupplicant' and 'dhcpcd5' (or equivalents) before continuing."
    exit 1
  fi
}

install_packages_if_needed() {
  local pkgs=(wpasupplicant dhcpcd5)
  local missing=()
  for pkg in "${pkgs[@]}"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    if command -v apt-get >/dev/null 2>&1; then
      info "Installing missing packages: ${missing[*]}"
      apt-get update
      apt-get install -y "${missing[@]}"
    else
      warn "Cannot automatically install packages: ${missing[*]}"
      exit 1
    fi
  fi
}

create_wpa_config() {
  local ssid="$1"
  local psk="$2"
  info "Creating wpa_supplicant configuration for ${WLAN_IFACE}"
  mkdir -p "$(dirname "$WPACFG_FILE")"
  wpa_passphrase "$ssid" "$psk" > "$WPACFG_FILE"
  chmod 600 "$WPACFG_FILE"
  ok "Configuration saved to $WPACFG_FILE"
}

mark_nm_unmanaged() {
  info "Instructing NetworkManager to ignore ${WLAN_IFACE}."
  mkdir -p /etc/NetworkManager/conf.d
  cat > "$NM_OVERRIDE" <<CONF
[keyfile]
unmanaged-devices=interface-name:${WLAN_IFACE}
CONF
  ok "NetworkManager will ignore ${WLAN_IFACE}."
}

reload_nm() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | grep -Fxq "NetworkManager.service"; then
    info "Restarting NetworkManager to apply changes."
    systemctl restart NetworkManager.service || warn "Could not restart NetworkManager."
  else
    info "NetworkManager not present; skipping this step."
  fi
}

enable_wifi_services() {
  info "Enabling wpa_supplicant and dhcpcd for ${WLAN_IFACE}."
  systemctl enable --now "wpa_supplicant@${WLAN_IFACE}.service"
  systemctl enable --now "dhcpcd@${WLAN_IFACE}.service"
  ok "Services enabled."
}

bring_up_interface() {
  info "Bringing up ${WLAN_IFACE}."
  ip link set "$WLAN_IFACE" up || warn "Could not bring up ${WLAN_IFACE}."
  ok "${WLAN_IFACE} up."
}

apply_guard() {
  require_root
  install_packages_if_needed
  ensure_tools

  local ssid=""
  local psk=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssid)
        ssid="$2"; shift 2 ;;
      --psk)
        psk="$2"; shift 2 ;;
      --iface)
        WLAN_IFACE="$2"
        WPACFG_FILE="${WPACFG_PREFIX}-${WLAN_IFACE}.conf"
        shift 2 ;;
      *)
        warn "Unknown parameter: $1"
        exit 1 ;;
    esac
  done

  if [ -z "$ssid" ] || [ -z "$psk" ]; then
    warn "You must provide SSID and PSK: --ssid \"MyWiFi\" --psk \"MyKey\""
    exit 1
  fi

  create_wpa_config "$ssid" "$psk"
  mark_nm_unmanaged
  reload_nm
  enable_wifi_services
  bring_up_interface
  ok "Autonomous shielding of ${WLAN_IFACE} completed."
  echo ""
  info "From now on you can stop NetworkManager without losing Wi-Fi."
}

restore_guard() {
  require_root
  info "Reverting autonomous Wi-Fi configuration."
  systemctl disable --now "dhcpcd@${WLAN_IFACE}.service" 2>/dev/null || true
  systemctl disable --now "wpa_supplicant@${WLAN_IFACE}.service" 2>/dev/null || true

  if [ -f "$NM_OVERRIDE" ]; then
    rm -f "$NM_OVERRIDE"
    info "Removed $NM_OVERRIDE"
  fi
  reload_nm

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | grep -Fxq "NetworkManager.service"; then
    info "Returning ${WLAN_IFACE} to NetworkManager."
    nmcli device set "$WLAN_IFACE" managed yes 2>/dev/null || true
    systemctl restart NetworkManager.service || true
  fi

  if [ -f "$WPACFG_FILE" ]; then
    info "Keeping $WPACFG_FILE (delete manually if not wanted)."
  fi
  ok "Restoration completed."
}

show_status() {
  require_root
  info "wlan_autonomo.sh v$VERSION status"
  echo "Target interface: $WLAN_IFACE"
  if [ -f "$WPACFG_FILE" ]; then
    ok "WPA configuration exists at $WPACFG_FILE"
  else
    warn "No WPA configuration created by this script."
  fi

  if [ -f "$NM_OVERRIDE" ]; then
    ok "NetworkManager ignores ${WLAN_IFACE}."
  else
    info "NetworkManager manages ${WLAN_IFACE}."
  fi

  systemctl is-active "wpa_supplicant@${WLAN_IFACE}.service" >/dev/null 2>&1 && ok "wpa_supplicant@${WLAN_IFACE} active" || warn "wpa_supplicant@${WLAN_IFACE} not active"
  systemctl is-active "dhcpcd@${WLAN_IFACE}.service" >/dev/null 2>&1 && ok "dhcpcd@${WLAN_IFACE} active" || warn "dhcpcd@${WLAN_IFACE} not active"

  if command -v nmcli >/dev/null 2>&1; then
    nmcli -t -f DEVICE,STATE,CONNECTION dev status | grep "$WLAN_IFACE" || true
  fi
}

usage() {
  cat <<'USO'
Usage: wlan_autonomo.sh <action> [options]

Actions:
  apply --ssid "SSID" --psk "PASS" [--iface wlanX]   Prepares interface to be autonomous
  restore                                               Reverts changes and returns control to NetworkManager
  status [--iface wlanX]                                Shows current status
  help                                                  Shows this help

Examples:
  sudo ./wlan_autonomo.sh apply --ssid "MyWiFi" --psk "MyKey"
  sudo ./wlan_autonomo.sh status
  sudo ./wlan_autonomo.sh restore
USO
}

main() {
  local action="${1:-}" || true
  case "$action" in
    apply)
      shift || true
      apply_guard "$@"
      ;;
    restore)
      restore_guard
      ;;
    status)
      shift || true
      if [ "${1:-}" = "--iface" ]; then
        WLAN_IFACE="$2"
        WPACFG_FILE="${WPACFG_PREFIX}-${WLAN_IFACE}.conf"
        shift 2
      fi
      show_status
      ;;
    help|""|-h|--help)
      usage
      ;;
    *)
      warn "Unknown action: $action"
      usage
      exit 1
      ;;
  esac
}

main "$@"
