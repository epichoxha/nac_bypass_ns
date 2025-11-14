#!/bin/bash

###############################################################################
# Name: awareness.sh
# Description: Monitors the status of a network interface and adjusts the
#              NAC bypass configuration when changes are detected.
# Usage: ./awareness.sh [-i <interface>] [-h]
# Dependencies: bash, basic GNU tools, nac_bypass_setup.sh
###############################################################################

# Script version, useful for debugging and support.
VERSION="0.1.1-1746786622"

# Basic configuration that controls how the interface is monitored.
NETWORK_INTERFACE="eth0"
PREVIOUS_INTERFACE_STATE=0
STATE_CHANGE_COUNTER=0
ACTIVATION_THRESHOLD=3
DEACTIVATION_THRESHOLD=5
WAIT_INTERVAL="5s"

# Absolute path to the directory where this script and auxiliary files reside.
SCRIPT_DIRECTORY=$(dirname "$(readlink -f "$0")")

# Shows help with a quick description of available parameters.
show_help() {
  echo -e "$0 v$VERSION usage:"
  echo "    -h          shows this help"
  echo "    -i <eth>    network interface connected to the switch"
  exit 0
}

# Reports only the script version.
show_version() {
  echo -e "$0 v$VERSION"
  exit 0
}

# Reads command line options and adjusts configuration.
parse_arguments() {
  while getopts ":hi:" option; do
    case "$option" in
      h)
        show_help
        ;;
      i)
        NETWORK_INTERFACE=$OPTARG
        ;;
      *)
        NETWORK_INTERFACE="eth0"
        ;;
    esac
  done
}

# Executes the first phase of the NAC bypass to get everything ready.
execute_initial_configuration() {
  bash "${SCRIPT_DIRECTORY}/nac_bypass_setup.sh" -a -i
}

# Returns the physical status of the interface (1 = active, 0 = inactive).
read_interface_state() {
  local link_file="/sys/class/net/${NETWORK_INTERFACE}/carrier"
  cat "$link_file"
}

# Decides what to do with the current state: report or relaunch bypass phases.
apply_state_actions() {
  local current_state=$1

  if [[ $current_state -ne $PREVIOUS_INTERFACE_STATE ]]; then
    STATE_CHANGE_COUNTER=0

    if [[ $current_state -eq 1 ]]; then
      echo "[!] ${NETWORK_INTERFACE} is active!"
    else
      echo "[!] ${NETWORK_INTERFACE} is inactive!"
    fi
    return
  fi

  if [[ $STATE_CHANGE_COUNTER -eq $ACTIVATION_THRESHOLD && $current_state -eq 1 ]]; then
    echo "[!!] Setting new configuration"
    bash "${SCRIPT_DIRECTORY}/nac_bypass_setup.sh" -a -c
  elif [[ $STATE_CHANGE_COUNTER -eq $DEACTIVATION_THRESHOLD && $current_state -eq 0 ]]; then
    echo "[!!] Restoring configuration"
    bash "${SCRIPT_DIRECTORY}/nac_bypass_setup.sh" -a -r
    bash "${SCRIPT_DIRECTORY}/nac_bypass_setup.sh" -a -i
  fi

  echo "[*] Waiting"
  ((STATE_CHANGE_COUNTER++))
}

# Main flow: interpret parameters, configure and maintain monitoring.
parse_arguments "$@"
execute_initial_configuration

while true; do
  CURRENT_INTERFACE_STATE=$(read_interface_state)
  apply_state_actions "$CURRENT_INTERFACE_STATE"
  PREVIOUS_INTERFACE_STATE=$CURRENT_INTERFACE_STATE
  sleep "$WAIT_INTERVAL"
done
