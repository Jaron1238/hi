#!/bin/bash
# Automatisches Nexmon Monitor-Setup für Raspberry Pi 4
# Erstellt: Jaron + ChatGPT

IFACE="wlan0"
MON_IFACE="mon0"
CHANNEL=6
PCAP_FILE="/home/pi/wifi_capture.pcap"

echo "[*] Stoppe störende Dienste..."
sudo systemctl stop wpa_supplicant 2>/dev/null
sudo systemctl stop NetworkManager 2>/dev/null
sudo systemctl stop dhcpcd 2>/dev/null

echo "[*] Interface $IFACE deaktivieren..."
sudo ifconfig $IFACE down

# Prüfen ob mon0 schon existiert
if iw dev | grep -q "$MON_IFACE"; then
    echo "[*] Entferne vorhandenes $MON_IFACE..."
    sudo iw dev $MON_IFACE del
fi

echo "[*] Erstelle Monitor-Interface $MON_IFACE..."
sudo iw phy `iw dev $IFACE info | awk '/wiphy/ {print "phy"$2}'` interface add $MON_IFACE type monitor

echo "[*] Bringe $MON_IFACE hoch..."
sudo ifconfig $MON_IFACE up

echo "[*] Setze Kanal auf $CHANNEL..."
sudo iw dev $MON_IFACE set channel $CHANNEL

echo "[*] Starte Capture – Ausgabe in $PCAP_FILE"
sudo tcpdump -i $MON_IFACE -n -vvv -w $PCAP_FILE
