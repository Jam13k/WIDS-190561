#!/bin/bash
set -e

echo "=== 1. Reloading mac80211_hwsim radios (wlan0-wlan3) ==="
modprobe -r mac80211_hwsim 2>/dev/null || true
modprobe mac80211_hwsim radios=4
sleep 1
iw dev

echo ""
echo "=== 2. Releasing wlan0-3 from NetworkManager ==="
for i in 0 1 2 3; do
    nmcli dev set wlan$i managed no 2>/dev/null || true
done

echo ""
echo "=== 3. Setting wlan2 (attacker) and wlan3 (sniffer) to monitor mode ==="
for i in 2 3; do
    ip link set wlan$i down
    iw dev wlan$i set type monitor
    ip link set wlan$i up
    iw dev wlan$i set channel 6
done
iw dev | grep -E "Interface|type"

echo ""
echo "=== 4. Starting AP (hostapd, daemonized) on wlan0 ==="
pkill hostapd 2>/dev/null || true
sleep 1
hostapd -B /home/james/wids/ap.conf

echo ""
echo "=== 5. Connecting client (wpa_supplicant, daemonized) on wlan1 ==="
pkill wpa_supplicant 2>/dev/null || true
sleep 1
wpa_supplicant -i wlan1 -c /home/james/wids/client.conf -B
sleep 5
iw dev wlan1 link

echo ""
echo "=== Setup complete ==="
