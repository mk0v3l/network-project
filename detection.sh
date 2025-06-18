#!/bin/bash

IFACE="eth0"
LOG="/var/log/arp_spoof_detect.log"
BLOCKED="/tmp/blocked_macs.txt"

# Set router IP + router MAC manually here:
ROUTER_IP="192.168.1.1"
ROUTER_MAC="aa:bb:cc:dd:ee:ff"

# Init blocked list
touch $BLOCKED

echo "[*] Starting tcpdump ARP monitor on $IFACE..."
echo "[*] Logging to $LOG"

tcpdump -l -i $IFACE arp | while read line; do
	echo "$line" >>$LOG

	if echo "$line" | grep -q "Reply"; then

		if echo "$line" | grep "$ROUTER_IP" | grep -v "$ROUTER_MAC"; then
			echo "[!] Possible ARP spoof detected! $line"

			ATTACKER_MAC=$(echo "$line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}')

			# Already blocked? Skip.
			if grep -q "$ATTACKER_MAC" $BLOCKED; then
				echo "[*] Already blocked $ATTACKER_MAC — skipping"
				continue
			fi

			echo "[*] Blocking new attacker MAC $ATTACKER_MAC"

			iptables -I INPUT -m mac --mac-source "$ATTACKER_MAC" -j DROP
			iptables -I OUTPUT -m mac --mac-source "$ATTACKER_MAC" -j DROP
			iptables -I FORWARD -m mac --mac-source "$ATTACKER_MAC" -j DROP

			if command -v ebtables >/dev/null 2>&1; then
				echo "[*] ebtables found — adding L2 block for $ATTACKER_MAC"
				ebtables -A INPUT -s "$ATTACKER_MAC" -j DROP
				ebtables -A OUTPUT -s "$ATTACKER_MAC" -j DROP
				ebtables -A FORWARD -s "$ATTACKER_MAC" -j DROP
			else
				echo "[*] ebtables not installed — skipping L2 block"
			fi

			echo "$ATTACKER_MAC" >>$BLOCKED

			echo "Block rule inserted for $ATTACKER_MAC"
		fi
	fi
done
