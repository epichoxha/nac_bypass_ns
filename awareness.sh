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
INTERFAZ_RED="eth0"
ESTADO_ANTERIOR_INTERFAZ=0
CONTADOR_CAMBIO_ESTADO=0
UMBRAL_ACTIVACION=3
UMBRAL_DESACTIVACION=5
INTERVALO_ESPERA="5s"

# Absolute path to the directory where this script and auxiliary files reside.
DIRECTORIO_SCRIPT=$(dirname "$(readlink -f "$0")")

# Shows help with a quick description of available parameters.
mostrar_ayuda() {
  echo -e "$0 v$VERSION usage:"
  echo "    -h          shows this help"
  echo "    -i <eth>    network interface connected to the switch"
  exit 0
}

# Reports only the script version.
mostrar_version() {
  echo -e "$0 v$VERSION"
  exit 0
}

# Reads command line options and adjusts configuration.
analizar_argumentos() {
  while getopts ":hi:" option; do
    case "$option" in
      h)
        mostrar_ayuda
        ;;
      i)
        INTERFAZ_RED=$OPTARG
        ;;
      *)
        INTERFAZ_RED="eth0"
        ;;
    esac
  done
}

# Executes the first phase of the NAC bypass to get everything ready.
ejecutar_configuracion_inicial() {
  bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -i
}

# Returns the physical status of the interface (1 = active, 0 = inactive).
leer_estado_interfaz() {
  local archivo_enlace="/sys/class/net/${INTERFAZ_RED}/carrier"
  cat "$archivo_enlace"
}

# Decides what to do with the current state: report or relaunch bypass phases.
aplicar_acciones_estado() {
  local estado_actual=$1

  if [[ $estado_actual -ne $ESTADO_ANTERIOR_INTERFAZ ]]; then
    CONTADOR_CAMBIO_ESTADO=0

    if [[ $estado_actual -eq 1 ]]; then
      echo "[!] ${INTERFAZ_RED} is active!"
    else
      echo "[!] ${INTERFAZ_RED} is inactive!"
    fi
    return
  fi

  if [[ $CONTADOR_CAMBIO_ESTADO -eq $UMBRAL_ACTIVACION && $estado_actual -eq 1 ]]; then
    echo "[!!] Setting new configuration"
    bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -c
  elif [[ $CONTADOR_CAMBIO_ESTADO -eq $UMBRAL_DESACTIVACION && $estado_actual -eq 0 ]]; then
    echo "[!!] Restoring configuration"
    bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -r
    bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -i
  fi

  echo "[*] Waiting"
  ((CONTADOR_CAMBIO_ESTADO++))
}

# Main flow: interpret parameters, configure and maintain monitoring.
analizar_argumentos "$@"
ejecutar_configuracion_inicial

while true; do
  ESTADO_INTERFAZ_ACTUAL=$(leer_estado_interfaz)
  aplicar_acciones_estado "$ESTADO_INTERFAZ_ACTUAL"
  ESTADO_ANTERIOR_INTERFAZ=$ESTADO_INTERFAZ_ACTUAL
  sleep "$INTERVALO_ESPERA"
done
