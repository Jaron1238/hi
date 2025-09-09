#!/bin/bash

# Pfade
PCAP_FILE="/home/pi/handshakes.pcap"
HC22000_FILE="/home/pi/handshakes.hc22000"
WORDLIST="/usr/share/wordlists/rockyou.txt"
LOGFILE="/home/pi/hashcat.log"

# Schritt 1: Prüfen, ob hcxtools installiert ist
if ! command -v hcxpcapngtool &> /dev/null; then
    echo "[INFO] hcxtools nicht gefunden. Installation..."
    sudo apt update && sudo apt install -y hcxtools
fi

# Schritt 2: Prüfen, ob hashcat installiert ist
if ! command -v hashcat &> /dev/null; then
    echo "[INFO] hashcat nicht gefunden. Installation..."
    sudo apt update && sudo apt install -y hashcat
fi

# Schritt 3: Prüfen, ob rockyou.txt vorhanden ist
if [ ! -f "$WORDLIST" ]; then
    echo "[INFO] rockyou.txt nicht gefunden. Installation..."
    sudo apt install -y wordlists
    gzip -d /usr/share/wordlists/rockyou.txt.gz
fi

# Schritt 4: pcap -> hc22000 konvertieren
echo "[INFO] Konvertiere $PCAP_FILE nach $HC22000_FILE..."
hcxpcapngtool -o "$HC22000_FILE" "$PCAP_FILE"

# Schritt 5: Hashcat im Hintergrund starten
echo "[INFO] Starte Hashcat im Hintergrund..."
nohup hashcat -m 22000 "$HC22000_FILE" "$WORDLIST" --force > "$LOGFILE" 2>&1 &

echo "[INFO] Hashcat läuft jetzt im Hintergrund."
echo "[INFO] Logfile: $LOGFILE"
echo "[INFO] Fortschritt live ansehen mit: tail -f $LOGFILE"
