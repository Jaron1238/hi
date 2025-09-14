#!/bin/bash

# ==============================================================================
# Installationsskript für den WLAN-Scanner systemd Service
#
# Dieses Skript muss als root oder mit 'sudo' ausgeführt werden.
# Es installiert und aktiviert einen Service, der beim Systemstart automatisch
# für eine Stunde WLAN-Daten erfasst.
# ==============================================================================

# --- Konfiguration ---
# Pfad zum Projektverzeichnis. Das Skript geht davon aus, dass es sich selbst
# im Projektverzeichnis befindet.
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Name der systemd-Service-Datei
SERVICE_NAME="wifi-scanner.service"

# Pfad zum Python-Interpreter im Virtual Environment
# Passe dies an, wenn dein venv-Ordner anders heißt.
PYTHON_EXEC="${PROJECT_DIR}/venv/bin/python"

# Name der physischen und der zu erstellenden WLAN-Schnittstelle
WLAN_IFACE="wlan0"
MONITOR_IFACE="mon0"
WLAN_PHY="phy0" # Normalerweise phy0, prüfe mit 'iw dev'

# Dauer des Scans in Sekunden (1 Stunde = 3600 Sekunden)
SCAN_DURATION=3600

# --- Sicherheitscheck: Als root ausführen ---
if [ "$EUID" -ne 0 ]; then
  echo "Fehler: Dieses Skript muss als root oder mit 'sudo' ausgeführt werden."
  exit 1
fi

echo "--- Installationsskript für den WLAN-Scanner ---"
echo "Projektverzeichnis: ${PROJECT_DIR}"
echo "Service-Datei wird erstellt: /etc/systemd/system/${SERVICE_NAME}"

# --- Überprüfen, ob das Python-Skript und venv existieren ---
if [ ! -f "${PROJECT_DIR}/main.py" ]; then
    echo "Fehler: 'main.py' nicht in ${PROJECT_DIR} gefunden!"
    exit 1
fi

if [ ! -f "${PYTHON_EXEC}" ]; then
    echo "Warnung: Python-Interpreter in '${PYTHON_EXEC}' nicht gefunden."
    echo "Stelle sicher, dass du ein Virtual Environment namens 'venv' erstellt hast ('python3 -m venv venv')."
    echo "Fahre fort, aber der Service wird wahrscheinlich fehlschlagen."
fi

# --- Erstelle die systemd Service-Datei ---
# Das Here-Document (<<EOF) erlaubt es uns, eine mehrzeilige Datei direkt zu schreiben.
# Die Variablen ($PROJECT_DIR etc.) werden automatisch ersetzt.
cat > /etc/systemd/system/${SERVICE_NAME} <<EOF
[Unit]
Description=WLAN Analysis Sniffer (${SCAN_DURATION}s capture on boot)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${PROJECT_DIR}

# Schritt 1: Monitor-Interface einrichten
ExecStartPre=/bin/sh -c 'systemctl stop NetworkManager && ip link set ${WLAN_IFACE} down && iw phy ${WLAN_PHY} interface add ${MONITOR_IFACE} type monitor && ip link set ${MONITOR_IFACE} up'

# Schritt 2: Sniffing-Skript ausführen
ExecStart=${PYTHON_EXEC} main.py --iface ${MONITOR_IFACE} --duration ${SCAN_DURATION}

# Schritt 3: Aufräumen
ExecStopPost=/bin/sh -c 'iw dev ${MONITOR_IFACE} del && systemctl start NetworkManager'

Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "Service-Datei erfolgreich erstellt."

# --- Systemd anweisen, die neue Datei zu laden und den Service zu aktivieren ---
echo "Lade systemd daemon neu..."
systemctl daemon-reload

echo "Aktiviere den Service, damit er beim Systemstart ausgeführt wird..."
systemctl enable ${SERVICE_NAME}

echo "Service wird jetzt gestartet (zum ersten Test)..."
systemctl start ${SERVICE_NAME}

echo ""
echo "--- Installation abgeschlossen! ---"
echo "Der Service '${SERVICE_NAME}' ist jetzt installiert und läuft."
echo ""
echo "Du kannst den Status jederzeit überprüfen mit:"
echo "  systemctl status ${SERVICE_NAME}"
echo ""
echo "Um die Live-Logs anzuzeigen, benutze:"
echo "  journalctl -u ${SERVICE_NAME} -f"
echo ""
