# START OF FILE hacking Kopie/utils.py

# -*- coding: utf-8 -*-
"""
Hilfsfunktionen, OUI-Lookup, IE-Parsing und LED-Steuerung.
"""
from __future__ import annotations
import hashlib
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# --- OUI Map (Cached) ---
def build_oui_map() -> Dict[str, str]:
    candidates = [
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/wireshark/manuf"),
        Path("/usr/local/share/wireshark/manuf"),
    ]
    mapping: Dict[str, str] = {}
    for p in candidates:
        if not p.exists():
            continue
        try:
            for line in p.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "\t" in line:
                    a, b = line.split("\t", 1)
                else:
                    parts = line.split()
                    a = parts[0] if parts else None
                    b = " ".join(parts[1:]) if len(parts) > 1 else None
                if a and b:
                    # Fall 1: Kompaktes Format (z.B. "000000")
                    if len(a) == 6 and all(c in '0123456789ABCDEFabcdef' for c in a):
                        # Formatiere es in das Standardformat "00:00:00"
                        pref = f"{a[0:2]}:{a[2:4]}:{a[4:6]}".upper()
                        mapping[pref] = b.strip()
                    # Fall 2: Standardformat (z.B. "00:1A:2B" oder "00-1A-2B")
                    elif ":" in a or "-" in a:
                        pref = a.replace("-", ":").upper()[:8]
                        mapping[pref] = b.strip()
        except Exception as exc:
            print(f"!!! KRITISCHER FEHLER beim Lesen von {p}: {exc}")
            logger.debug("Fehler beim Lesen der OUI-Datei %s: %s", p, exc)
            continue
    return mapping

OUI_MAP = build_oui_map()

# --- MAC Address Helpers ---
def is_local_admin_mac(mac: Optional[str]) -> bool:
    """Prüft, ob das 'locally administered' Bit im ersten Oktett der MAC gesetzt ist."""
    try:
        if not mac: return False
        first_octet = mac.split(":")[0]
        val = int(first_octet, 16)
        # Das zweite Bit von rechts (0x02) kennzeichnet eine lokal administrierte Adresse.
        return bool(val & 0x02)
    except (ValueError, IndexError):
        return False

def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """
    Sucht den Hersteller einer MAC-Adresse und erkennt intelligent
    lokal administrierte / randomisierte Adressen.
    """
    if not mac:
        return None
    
    # --- NEUE, VERBESSERTE LOGIK ---
    # Zuerst prüfen, ob es eine randomisierte MAC ist.
    if is_local_admin_mac(mac):
        return "(Lokal / Randomisiert)"
        
    # Nur wenn es keine randomisierte MAC ist, in der Datenbank nachschlagen.
    pref = mac.replace("-", ":").upper()[:8]
    return OUI_MAP.get(pref)


# --- IE Parsing & Fingerprinting ---
_IE_FP_CACHE: Dict[int, str] = {}

def ie_fingerprint_hash(ies: Dict[int, List[str]]) -> str:
    key = hash(tuple((k, tuple(v)) for k, v in sorted(ies.items())))
    if key in _IE_FP_CACHE:
        return _IE_FP_CACHE[key]
    items = []
    for k in sorted(ies.keys()):
        arr = sorted(ies[k])
        items.append(f"{k}:" + ",".join(arr))
    s = "|".join(items)
    h = hashlib.sha1(s.encode()).hexdigest()
    _IE_FP_CACHE[key] = h
    return h

def _parse_ht_capabilities(hex_data: str) -> Dict:
    """Parst HT Capabilities (ID 45) IE für Kanalbreite und MIMO-Streams."""
    caps = {}
    try:
        data = bytes.fromhex(hex_data)
        cap_info = int.from_bytes(data[:2], 'little')
        caps['40mhz_support'] = bool(cap_info & 0x0002)
        
        if len(data) >= 12:
            rx_mcs = data[4:8]
            if rx_mcs[3] != 0: caps['streams'] = 4
            elif rx_mcs[2] != 0: caps['streams'] = 3
            elif rx_mcs[1] != 0: caps['streams'] = 2
            elif rx_mcs[0] != 0: caps['streams'] = 1
    except (ValueError, IndexError): pass
    return caps

def _parse_vht_capabilities(hex_data: str) -> Dict:
    """Parst VHT Capabilities (ID 191) IE für Kanalbreite und MU-MIMO."""
    caps = {}
    try:
        data = bytes.fromhex(hex_data)
        cap_info = int.from_bytes(data[:4], 'little')
        ch_width = (cap_info >> 2) & 0b11
        if ch_width == 1: caps['160mhz_support'] = True
        caps['mu_beamformer_capable'] = bool(cap_info & (1 << 19))
    except (ValueError, IndexError): pass
    return caps

def parse_ies(ies_dict: Dict[int, List[str]], detailed: bool = False) -> Dict[str, any]:
    """Extrahiert nützliche Informationen aus den Roh-IEs."""
    parsed = {"security": set(), "standards": set(), "vendor_specific": {}}
    
    # RSN IE (ID 48) -> Security
    if 48 in ies_dict:
        parsed["security"].add("WPA2/3") 
    
    # HT/VHT/HE Capabilities -> Standards
    if 45 in ies_dict or 61 in ies_dict:
        parsed["standards"].add("802.11n")
        if detailed and 45 in ies_dict:
            parsed["ht_caps"] = _parse_ht_capabilities(ies_dict[45][0])

    if 191 in ies_dict:
        parsed["standards"].add("802.11ac")
        if detailed and 191 in ies_dict:
            parsed["vht_caps"] = _parse_vht_capabilities(ies_dict[191][0])

    # HE Capabilities (ID 35 in Extension IE 255)
    if 255 in ies_dict:
        for hex_data in ies_dict[255]:
            if hex_data.startswith('23'): # 35 = 0x23
                parsed["standards"].add("802.11ax")
                if detailed:
                    parsed["he_caps"] = {"present": True}

    # Vendor Specific (ID 221)
    if 221 in ies_dict:
        for hex_data in ies_dict[221]:
            try:
                # Wi-Fi Alliance OUI for Wi-Fi Direct
                if hex_data.startswith("506f9a09"): 
                    parsed["vendor_specific"]["Wi-Fi Direct"] = True
                
                oui = hex_data[:6]
                vendor = OUI_MAP.get(f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}".upper())
                if vendor:
                    parsed["vendor_specific"][vendor] = hex_data[6:]
            except IndexError:
                continue

    # Konvertiere Sets zu sortierten Listen für konsistente JSON-Ausgabe
    parsed["security"] = sorted(list(parsed["security"]))
    parsed["standards"] = sorted(list(parsed["standards"]))
    return parsed

# --- LED Helpers ---
def discover_rpi_led() -> Optional[Path]:
    candidates = [Path("/sys/class/leds/led0"), Path("/sys/class/leds/act"), Path("/sys/class/leds/led1")]
    for p in candidates:
        if p.is_dir() and os.access(p / "brightness", os.W_OK):
            return p
    base = Path("/sys/class/leds")
    if base.is_dir():
        for e in base.iterdir():
            if e.is_dir() and os.access(e / "brightness", os.W_OK):
                return e
    return None

def _write_file(path: Path, content: str) -> bool:
    try:
        path.write_text(str(content))
        return True
    except OSError as exc:
        logger.debug("write_file fail %s: %s", path, exc)
        return False

def led_set(led_path: Optional[Path], on: bool = True) -> bool:
    if not led_path: return False
    trig, br = led_path / "trigger", led_path / "brightness"
    try:
        if trig.exists():
            try: trig.write_text("none")
            except OSError: logger.debug("failed setting trigger to none")
        return _write_file(br, "1" if on else "0")
    except OSError as exc:
        logger.debug("led_set error: %s", exc)
        return False
