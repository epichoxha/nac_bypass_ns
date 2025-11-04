This repository extends the **NAC Bypass** from [scipag](https://github.com/scipag/nac_bypass) without modifying its original functionality. It maintains flags, dependencies, and flow intact, allowing for direct integration.

## Key improvements

* **Real-time EAPOL monitoring:** during the `initial_phase`, `tcpdump` is executed to capture 802.1X traffic and analyze authentication before proceeding.
* **Isolated namespace (`bypass`):** the `nac_bypass_setup_ns.sh` script creates a `macvlan` interface inside a namespace, blocking host access to the bridge (`br0`). All bypass traffic is contained, preventing attacker MAC leakage.
* **Switch port shutdown prevention:** encapsulating the legitimate MAC/IP within the namespace and blocking bridge access prevents the switch from detecting anomalous activity, preventing errors like `security-violation` or the port entering `err-disable` state.
* **Complete cleanup (`-r`):** removes bridge, rules, namespace, and residual configurations, leaving the system clean for new attempts.

**Summary:** respects scipag's original logic, but adds network isolation, MAC leakage prevention, and a cleanup routine. Ideal for stealthy NAC evasion and reusable in Red Team exercises.
