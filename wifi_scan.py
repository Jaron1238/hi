#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifi_listener_web_bootstrap_v2.py
Passive WiFi listener with:
 - device-busy fix, monitor interface creation
 - extended channel hopping (2.4 + 5GHz)
 - PCAP streaming + CSV raw + aggregated summary CSV
 - improved vendor/model detection (OUI DB + Vendor IE parsing)
 - Web UI (Bootstrap) that only starts when Pi is in LAN (shows last summary)
 - Tooling to install/download OUI DB (--install-oui)
Passive only — no active attacks.
"""

import os
import sys
import argparse
import logging
import threading
import signal
import subprocess
import time
import csv
import re
import json
import socket
import shutil
from datetime import datetime
from logging.handlers import RotatingFileHandler
from scapy.all import sniff, RadioTap, Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeResp
from scapy.utils import PcapWriter

# Flask optional import
try:
    from flask import Flask, jsonify, send_file, render_template_string
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

# ----------------------------
# CLI args
# ----------------------------
parser = argparse.ArgumentParser(description="Passive WiFi listener with web UI (bootstrap) v2")
parser.add_argument("--iface", "-i", default="mon0")
parser.add_argument("--pcap", default="/home/pi/wifi_capture.pcap")
parser.add_argument("--csv-aps", default="/home/pi/wifi_aps.csv")
parser.add_argument("--csv-clients", default="/home/pi/wifi_clients.csv")
parser.add_argument("--summary-csv", default="/home/pi/wifi_aps_summary.csv")
parser.add_argument("--auto", action="store_true")
parser.add_argument("--hopsleep", type=float, default=4.0)
parser.add_argument("--agg-interval", type=int, default=30)
parser.add_argument("--web", action="store_true")
parser.add_argument("--web-port", type=int, default=8080)
parser.add_argument("--debug", action="store_true")
parser.add_argument("--rotatelogs", action="store_true")
parser.add_argument("--logfile", default="/home/pi/wifi_listener_web_bootstrap_v2.log")
parser.add_argument("--oui-db", default="/usr/share/nmap/nmap-mac-prefixes", help="Path to OUI file (nmap-mac-prefixes)")
parser.add_argument("--install-oui", action="store_true", help="Try to install or download OUI DB now and exit")
args = parser.parse_args()

INTERFACE = args.iface
PCAP_FILE = args.pcap
CSV_APS = args.csv_aps
CSV_CLIENTS = args.csv_clients
SUMMARY_CSV = args.summary_csv
AUTO_MODE = args.auto
HOP_SLEEP = args.hopsleep
AGG_INTERVAL = args.agg_interval
ENABLE_WEB = args.web
WEB_PORT = args.web_port
DEBUG = args.debug
OUI_DB_PATH = args.oui_db
INSTALL_OUI_NOW = args.install_oui

# ----------------------------
# Logging
# ----------------------------
logger = logging.getLogger("wifi_listener_v2")
logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
if args.rotatelogs:
    fh = RotatingFileHandler(args.logfile, maxBytes=5*1024*1024, backupCount=3)
else:
    fh = logging.FileHandler(args.logfile)
fh.setFormatter(fmt)
logger.addHandler(fh)
if DEBUG:
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

logger.info("Start listener v2: iface=%s pcap=%s web=%s", INTERFACE, PCAP_FILE, ENABLE_WEB)

# ----------------------------
# Utilities: OUI loader + vendor/model heuristics
# ----------------------------
oui_map = {}

def load_oui_db(path=None):
    """Load OUI DB from provided path(s) into oui_map."""
    global oui_map
    oui_map = {}
    candidates = []
    if path:
        candidates.append(path)
    # common locations
    candidates += [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
        "/usr/share/manuf",
        "/usr/local/share/nmap-mac-prefixes"
    ]
    for p in candidates:
        if not p:
            continue
        if os.path.exists(p):
            logger.info("Loading OUI DB from %s", p)
            try:
                with open(p, errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        # nmap format "00:11:22   Vendor"
                        m = re.match(r"^([0-9A-Fa-f:\-]{6,8})\s+(.+)$", line)
                        if m:
                            prefix = m.group(1).replace("-", ":").upper()
                            prefix = ":".join(prefix.split(":")[:3])
                            oui_map[prefix] = m.group(2).strip()
                            continue
                        # ieee.txt format "XX-XX-XX   (hex) Vendor"
                        m2 = re.match(r"^([0-9A-Fa-f\-]{6})\s+\(hex\)\s+(.+)$", line)
                        if m2:
                            raw = m2.group(1)
                            prefix = ":".join([raw[i:i+2] for i in range(0, 6, 2)]).upper()
                            oui_map[prefix] = m2.group(2).strip()
            except Exception as e:
                logger.debug("Error parsing OUI file %s: %s", p, e)
    logger.info("Loaded OUI entries: %d", len(oui_map))

def vendor_from_mac(mac):
    if not mac:
        return "unknown"
    try:
        prefix = ":".join(mac.upper().split(":")[:3])
        return oui_map.get(prefix, prefix)
    except Exception:
        return "unknown"

# ----------------------------
# Try to install / download OUI DB
# ----------------------------
def ensure_oui_installed(preferred_path=OUI_DB_PATH):
    """
    Ensure an OUI DB exists. Strategy:
      1) check common locations
      2) if none and apt available: apt update && apt install -y nmap
      3) if still none: try curl/wget from nmap repo raw file and save to /usr/local/share/nmap-mac-prefixes
    Returns path if installed/found, else None.
    """
    common = [
        preferred_path,
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap-mac-prefixes",
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/manuf"
    ]
    for p in common:
        if p and os.path.exists(p):
            logger.info("Found existing OUI DB: %s", p)
            return p

    # try apt if available
    if shutil.which("apt") or shutil.which("apt-get"):
        logger.info("Attempting to install 'nmap' (provides nmap-mac-prefixes) via apt")
        try:
            subprocess.run("apt-get update -y", shell=True, check=False)
            subprocess.run("DEBIAN_FRONTEND=noninteractive apt-get install -y nmap", shell=True, check=False)
        except Exception as e:
            logger.debug("apt install failed: %s", e)
        for p in common:
            if p and os.path.exists(p):
                logger.info("OUI DB found after apt: %s", p)
                return p

    # try download from nmap GitHub raw
    download_url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes"
    dest = "/usr/local/share/nmap-mac-prefixes"
    for tool in ("curl", "wget"):
        if shutil.which(tool):
            try:
                logger.info("Downloading OUI DB via %s from %s", tool, download_url)
                if tool == "curl":
                    subprocess.run(f"curl -fsSL {download_url} -o {dest}", shell=True, check=False)
                else:
                    subprocess.run(f"wget -q -O {dest} {download_url}", shell=True, check=False)
                if os.path.exists(dest):
                    logger.info("Downloaded OUI DB to %s", dest)
                    return dest
            except Exception as e:
                logger.debug("Download with %s failed: %s", tool, e)

    logger.warning("Could not install or download OUI DB automatically. You can provide one via --oui-db PATH")
    return None

# If user asked to install OUI now, try and exit
if INSTALL_OUI_NOW:
    path = ensure_oui_installed(OUI_DB_PATH)
    if path:
        print(f"OUI DB installed/located: {path}")
    else:
        print("OUI DB not found/installed. See logs or provide --oui-db")
    sys.exit(0)

# Try to load OUI DB if available
load_oui_db(OUI_DB_PATH)

# ----------------------------
# Device busy fix: stop common services and reset wlan0
# ----------------------------
def free_interface(base_iface="wlan0"):
    blockers = ["wpa_supplicant", "dhcpcd", "NetworkManager"]
    for svc in blockers:
        try:
            logger.debug("Stopping %s if active", svc)
            subprocess.run(f"systemctl stop {svc}", shell=True, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    try:
        subprocess.run(f"ip link set {base_iface} down", shell=True, check=False)
    except Exception:
        pass
    try:
        subprocess.run(f"iw dev {base_iface} del", shell=True, check=False)
    except Exception:
        pass
    time.sleep(0.1)

# ----------------------------
# Create monitor interface
# ----------------------------
def setup_monitor(iface):
    if os.path.exists(f"/sys/class/net/{iface}"):
        logger.debug("Interface %s exists", iface)
        subprocess.run(f"ip link set {iface} up", shell=True, check=False)
        return True
    phy = ""
    try:
        phy = subprocess.check_output("iw dev wlan0 info | awk '/wiphy/ {print \"phy\"$2}'", shell=True, text=True).strip()
    except Exception:
        pass
    if not phy:
        try:
            phy = subprocess.check_output("iw dev | awk '/wiphy/ {print \"phy\"$2; exit}'", shell=True, text=True).strip()
        except Exception:
            phy = ""
    if not phy:
        logger.warning("No phy found for wlan0")
        return False
    try:
        subprocess.run(f"iw {phy} interface add {iface} type monitor", shell=True, check=False)
        subprocess.run(f"ip link set {iface} up", shell=True, check=False)
        logger.info("Created monitor iface %s (phy=%s)", iface, phy)
        return True
    except Exception:
        logger.exception("Failed to create monitor iface")
        return False

# ----------------------------
# Channel lists & hopper
# ----------------------------
CH_24 = list(range(1, 15))
CH_5 = [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165]

def channel_hopper(iface, stop_event, dwell=HOP_SLEEP, use_5ghz=True):
    channels = CH_24 + (CH_5 if use_5ghz else [])
    logger.info("Channel hopper channels=%s dwell=%.1fs", channels, dwell)
    idx = 0
    while not stop_event.is_set():
        ch = channels[idx % len(channels)]
        try:
            subprocess.run(f"iw dev {iface} set channel {ch}", shell=True, check=False)
            if DEBUG:
                logger.debug("Set %s -> CH %d", iface, ch)
        except Exception:
            logger.debug("Could not set channel %d", ch)
        idx += 1
        steps = max(1, int(dwell * 10))
        for _ in range(steps):
            if stop_event.is_set(): break
            time.sleep(dwell / steps)

# ----------------------------
# Dot11 helpers & vendor-IE parsing
# ----------------------------
def iter_dot11elts(pkt):
    el = pkt.getlayer(Dot11Elt)
    while el and isinstance(el, Dot11Elt):
        yield el
        el = el.payload.getlayer(Dot11Elt)

_printable_re = re.compile(rb'[\x20-\x7E]{4,}')
def extract_vendor_strings(elt):
    if not elt or not elt.info:
        return []
    found = _printable_re.findall(bytes(elt.info))
    return [s.decode('utf-8', errors='ignore') for s in found]

def try_extract_model_from_vendor_info(vendor_info_list, bssid):
    if not vendor_info_list:
        return None
    combined = " | ".join(vendor_info_list).lower()
    m = re.search(r"(?:model[:\s\-]*)([A-Za-z0-9\-\_\/\.]+)", combined)
    if m:
        return m.group(1)
    # pick longest printable
    longest = ""
    for s in vendor_info_list:
        if len(s) > len(longest):
            longest = s
    if longest and len(longest) >= 4:
        return longest[:128]
    return vendor_from_mac(bssid)

# ----------------------------
# CSV ensure
# ----------------------------
def ensure_csv(path, header):
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(header)

ensure_csv(CSV_APS, ["Timestamp","SSID","BSSID","Vendor","Channel","Signal_dBm","Beacons","Enc","HT","VHT","VendorInfo","ModelHint"])
ensure_csv(CSV_CLIENTS, ["Timestamp","ClientMAC","Vendor","Type","AssociatedBSSID","RequestedSSID","Signal_dBm"])
ensure_csv(SUMMARY_CSV, ["BSSID","SSID","Vendor","ModelHint","LastSeen","Channels","Beacons","AvgSignal","HT","VHT","VendorInfo"])

# ----------------------------
# Shared stores & locks
# ----------------------------
aps = {}
clients = {}
aps_lock = threading.Lock()
clients_lock = threading.Lock()

# ----------------------------
# PCAP writer
# ----------------------------
try:
    pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)
    logger.info("PcapWriter opened: %s", PCAP_FILE)
except Exception:
    logger.exception("Could not open pcap file")
    sys.exit(1)

# ----------------------------
# Packet handler
# ----------------------------
def packet_handler(pkt):
    try:
        pcap_writer.write(pkt)
    except Exception:
        logger.debug("pcap write failed")
    sig = None
    try:
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            sig = getattr(rt, 'dBm_AntSignal', None)
    except Exception:
        pass

    # AP
    try:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            if not pkt.haslayer(Dot11): return
            bssid = pkt.addr2
            if not bssid: return
            ssid = ""
            channel = ""
            enc = "open"
            ht = False
            vht = False
            vendor_info = []
            for elt in iter_dot11elts(pkt):
                if elt.ID == 0:
                    ssid = elt.info.decode(errors="ignore") if elt.info else ""
                elif elt.ID == 3:
                    if elt.info and len(elt.info) >= 1:
                        channel = int(elt.info[0])
                elif elt.ID == 48 or elt.ID == 221:
                    enc = "wpa/rsn"
                    vendor_info += extract_vendor_strings(elt)
                elif elt.ID == 45:
                    ht = True
                elif elt.ID == 191:
                    vht = True
                elif elt.ID == 221:
                    vendor_info += extract_vendor_strings(elt)
            with aps_lock:
                info = aps.get(bssid, {"ssid": ssid, "channels": set(), "beacons": 0, "signals": [], "enc": enc, "ht": ht, "vht": vht, "vendor_info": set(), "model_hint": ""})
                info["ssid"] = ssid or info.get("ssid", "")
                if channel:
                    info["channels"].add(str(channel))
                info["beacons"] = info.get("beacons", 0) + 1
                if sig is not None:
                    info["signals"].append(sig)
                info["enc"] = enc or info.get("enc", info.get("enc"))
                info["ht"] = info["ht"] or ht
                info["vht"] = info["vht"] or vht
                for v in vendor_info:
                    if v:
                        info["vendor_info"].add(v)
                info["vendor"] = vendor_from_mac(bssid)
                info["model_hint"] = try_extract_model_from_vendor_info(list(info["vendor_info"]), bssid)
                info["last_seen"] = datetime.now().isoformat()
                aps[bssid] = info

                # append raw CSV
                try:
                    with open(CSV_APS, "a", newline="") as f:
                        csv.writer(f).writerow([
                            datetime.now().isoformat(), ssid, bssid, info.get("vendor", ""), ",".join(sorted(info.get("channels", []))),
                            sig if sig is not None else "", info["beacons"], info.get("enc", ""), str(info.get("ht")), str(info.get("vht")),
                            "|".join(sorted(info.get("vendor_info", []))), info.get("model_hint", "")
                        ])
                except Exception:
                    logger.debug("Could not write raw AP CSV")
    except Exception:
        logger.exception("AP handler error")

    # Clients
    try:
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                client = pkt.addr2
                if not client: return
                if client.upper().startswith("02:"): return
                requested = ""
                for elt in iter_dot11elts(pkt):
                    if elt.ID == 0:
                        requested = elt.info.decode(errors="ignore") if elt.info else ""
                        break
                with clients_lock:
                    info = clients.get(client, {})
                    info.update({"type": "probe", "requested": requested, "signal": sig, "vendor": vendor_from_mac(client), "last_seen": datetime.now().isoformat()})
                    clients[client] = info
                    try:
                        with open(CSV_CLIENTS, "a", newline="") as f:
                            csv.writer(f).writerow([datetime.now().isoformat(), client, info.get("vendor", ""), info.get("type", ""), "", requested, sig if sig is not None else ""])
                    except Exception:
                        logger.debug("Client CSV write failed (probe)")
            elif pkt.type == 2:
                client = pkt.addr2
                apmac = pkt.addr1
                if not client: return
                if client.upper().startswith("02:"): return
                with clients_lock:
                    info = clients.get(client, {})
                    info.update({"type": "data", "associated": apmac, "signal": sig, "vendor": vendor_from_mac(client), "last_seen": datetime.now().isoformat()})
                    clients[client] = info
                    try:
                        with open(CSV_CLIENTS, "a", newline="") as f:
                            csv.writer(f).writerow([datetime.now().isoformat(), client, info.get("vendor", ""), info.get("type", ""), apmac, "", sig if sig is not None else ""])
                    except Exception:
                        logger.debug("Client CSV write failed (data)")
    except Exception:
        logger.exception("Client handler error")

# ----------------------------
# Aggregation worker
# ----------------------------
def aggregation_worker(stop_event, interval=AGG_INTERVAL):
    logger.info("Aggregation worker started (interval=%ds)", interval)
    while not stop_event.is_set():
        try:
            rows = []
            with aps_lock:
                for bssid, info in aps.items():
                    signals = info.get("signals", [])
                    avg_sig = sum(signals)/len(signals) if signals else None
                    rows.append([
                        bssid,
                        info.get("ssid", ""),
                        info.get("vendor", ""),
                        info.get("model_hint", ""),
                        info.get("last_seen", ""),
                        ",".join(sorted(info.get("channels", []))),
                        info.get("beacons", 0),
                        "{:.1f}".format(avg_sig) if avg_sig is not None else "",
                        str(info.get("ht", False)),
                        str(info.get("vht", False)),
                        "|".join(sorted(info.get("vendor_info", [])))
                    ])
            tmp = SUMMARY_CSV + ".tmp"
            try:
                with open(tmp, "w", newline="") as f:
                    csv.writer(f).writerow(["BSSID","SSID","Vendor","ModelHint","LastSeen","Channels","Beacons","AvgSignal","HT","VHT","VendorInfo"])
                    for r in rows:
                        csv.writer(f).writerow(r)
                os.replace(tmp, SUMMARY_CSV)
                logger.debug("Wrote summary CSV %s (%d rows)", SUMMARY_CSV, len(rows))
            except Exception:
                logger.exception("Failed to write summary CSV")
        except Exception:
            logger.exception("Aggregation error")
        for _ in range(max(1, int(interval))):
            if stop_event.is_set():
                break
            time.sleep(1)
    logger.info("Aggregation worker stopped")

# ----------------------------
# decide if Pi is on LAN
# ----------------------------
def is_on_lan():
    # default route?
    try:
        out = subprocess.check_output("ip -4 route show default", shell=True, text=True).strip()
        if out:
            return True
    except Exception:
        pass
    # hostname -I for private IP ranges
    try:
        addrs = subprocess.check_output("hostname -I", shell=True, text=True).strip()
        if addrs:
            for ip in addrs.split():
                if ip.startswith("10.") or ip.startswith("192.168.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
                    return True
    except Exception:
        pass
    return False

# ----------------------------
# Web UI (Bootstrap) with full template
# ----------------------------
app = None
if ENABLE_WEB:
    if not FLASK_AVAILABLE:
        logger.warning("Flask not installed: web UI disabled. Install python3-flask")
        ENABLE_WEB = False
    else:
        if not is_on_lan():
            logger.info("Pi not in LAN — web UI will NOT start.")
            ENABLE_WEB = False

if ENABLE_WEB and FLASK_AVAILABLE:
    app = Flask(__name__)

    INDEX_HTML = r"""
<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WiFi Listener Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
      <div class="container-fluid">
        <a class="navbar-brand" href="#">WiFi Listener</a>
        <span class="navbar-text text-white">Iface: {{iface}} • PCAP: {{pcap}}</span>
        <span class="navbar-text text-white ms-3">Letzter Summary Run: {{last_run}}</span>
      </div>
    </nav>
    <div class="container">
      <div class="row mb-3">
        <div class="col-md-6">
          <div class="card shadow-sm">
            <div class="card-body">
              <h5 class="card-title">Erweiterte Kanalliste (1)</h5>
              <p class="card-text small">
                Die Kanalliste inkludiert die komplette 2.4GHz Reihe (1–14) und zahlreiche 5GHz-Kanäle.
                Channel-Hopping scannt diese Kanäle sequentiell (dwell Zeit einstellbar), damit der Listener
                APs auf allen regional erlaubten Kanälen erkennen kann.
              </p>
            </div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="card shadow-sm">
            <div class="card-body">
              <h5 class="card-title">Aggregation &amp; Summary-CSV (2)</h5>
              <p class="card-text small">
                Die Aggregation schreibt alle ~{{agg_interval}}s eine Zusammenfassung pro BSSID:
                letzte SSID, beobachtete Kanäle, durchschnittliche Signalstärke,
                HT/VHT-Unterstützung und extrahierte Vendor-Strings (z.B. Modell/Hersteller).
                Die Summary-CSV ist ideal für schnelle Übersicht & Export.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div class="d-flex justify-content-between align-items-center mb-2">
        <h4>Access Points <small class="text-muted" id="apcount"></small></h4>
        <div>
          <a class="btn btn-sm btn-outline-primary" href="/download/pcap">Download PCAP</a>
          <a class="btn btn-sm btn-outline-secondary" href="/download/summary">Download Summary CSV</a>
          <button class="btn btn-sm btn-primary" onclick="loadData()">Refresh</button>
        </div>
      </div>

      <div class="table-responsive mb-4">
        <table class="table table-sm table-hover table-bordered">
          <thead class="table-dark">
            <tr>
              <th>SSID</th><th>BSSID</th><th>Vendor</th><th>Model</th><th>Channels</th><th>Beacons</th>
              <th>AvgSignal</th><th>HT</th><th>VHT</th><th>VendorInfo</th><th>LastSeen</th>
            </tr>
          </thead>
          <tbody id="aptable"></tbody>
        </table>
      </div>

      <footer class="text-muted small mb-5">Passive Listener — nur für Testnetzwerke. Web UI refresh alle 5s.</footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
      async function loadData(){
        let r = await fetch('/api/aps'); let aps = await r.json();
        document.getElementById('apcount').innerText = '('+aps.length+')';
        let body = '';
        for(let a of aps){
          body += `<tr>
            <td>${a.ssid||''}</td>
            <td>${a.bssid}</td>
            <td>${a.vendor||''}</td>
            <td>${a.model||''}</td>
            <td>${a.channels||''}</td>
            <td>${a.beacons||''}</td>
            <td>${a.avgsignal||''}</td>
            <td>${a.ht}</td>
            <td>${a.vht}</td>
            <td>${a.vendorinfo||''}</td>
            <td>${a.lastseen||''}</td>
          </tr>`;
        }
        document.getElementById('aptable').innerHTML = body;
      }
      loadData();
      setInterval(loadData, 5000);
    </script>
  </body>
</html>
"""

    @app.route("/")
    def index():
        last_run = ""
        try:
            if os.path.exists(SUMMARY_CSV):
                last_run = datetime.fromtimestamp(os.path.getmtime(SUMMARY_CSV)).isoformat()
        except Exception:
            last_run = ""
        return render_template_string(INDEX_HTML, iface=INTERFACE, pcap=PCAP_FILE, agg_interval=AGG_INTERVAL, last_run=last_run)

    @app.route("/api/aps")
    def api_aps():
        out = []
        with aps_lock:
            for bssid, info in aps.items():
                signals = info.get("signals", [])
                avg_sig = sum(signals)/len(signals) if signals else None
                out.append({
                    "bssid": bssid,
                    "ssid": info.get("ssid", ""),
                    "vendor": info.get("vendor", ""),
                    "model": info.get("model_hint", ""),
                    "channels": ",".join(sorted(info.get("channels", []))),
                    "beacons": info.get("beacons", 0),
                    "avgsignal": "{:.1f}".format(avg_sig) if avg_sig is not None else "",
                    "ht": info.get("ht", False),
                    "vht": info.get("vht", False),
                    "vendorinfo": "|".join(sorted(info.get("vendor_info", []))),
                    "lastseen": info.get("last_seen", "")
                })
        out.sort(key=lambda x: int(x.get("beacons", 0)), reverse=True)
        return jsonify(out)

    @app.route("/api/clients")
    def api_clients():
        with clients_lock:
            out = [{ "mac": k, **v } for k, v in clients.items()]
        return jsonify(out)

    @app.route("/download/pcap")
    def dl_pcap():
        try:
            return send_file(PCAP_FILE, as_attachment=True)
        except Exception:
            return "PCAP not available", 404

    @app.route("/download/summary")
    def dl_summary():
        try:
            return send_file(SUMMARY_CSV, as_attachment=True)
        except Exception:
            return "Summary not available", 404

    def run_flask():
        logger.info("Starting Flask UI on 0.0.0.0:%d", WEB_PORT)
        app.run(host="0.0.0.0", port=WEB_PORT, threaded=True)

# ----------------------------
# Main & threads
# ----------------------------
stop_event = threading.Event()

def sig_handler(sig, frame):
    logger.info("Signal %s received, stopping...", sig)
    stop_event.set()
    try:
        pcap_writer.close()
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)

def main():
    # prepare interface
    free_interface("wlan0")
    ok = setup_monitor(INTERFACE)
    if not ok:
        logger.warning("Monitor setup may have failed (capture may not work)")

    # start channel hopper
    hopper = threading.Thread(target=channel_hopper, args=(INTERFACE, stop_event, HOP_SLEEP, True), daemon=True)
    hopper.start()

    # start aggregation worker
    agg = threading.Thread(target=aggregation_worker, args=(stop_event, AGG_INTERVAL), daemon=True)
    agg.start()

    # start flask only if allowed / available
    if ENABLE_WEB and FLASK_AVAILABLE:
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()

    logger.info("Starting sniff loop (auto=%s)", AUTO_MODE)
    try:
        if not AUTO_MODE:
            sniff(iface=INTERFACE, prn=packet_handler, store=0, timeout=HOP_SLEEP*2)
        else:
            while not stop_event.is_set():
                sniff(iface=INTERFACE, prn=packet_handler, store=0, timeout=5)
    except Exception:
        logger.exception("Sniffer error / interrupted")
    finally:
        logger.info("Shutting down, closing pcap")
        try:
            pcap_writer.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
