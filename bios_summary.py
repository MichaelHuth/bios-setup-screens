"""
One-call overview of a system BIOS image: vendor and version, BIOS ID string, date, chipset,
Super I/O and CPU hints, board vendor hints, setup page titles, features, compressed modules,
and which other tools apply. Packed images are searched including their decompressed modules.
"""

from __future__ import annotations

import re
from typing import Any, Dict

import ami
import award_setup
import ami_setup
import lzh
import phoenix

MAX_PER_GROUP = 12
STRING = re.compile(rb"[\x20-\x7e]{4,}")

PATTERNS = {
    "version": re.compile(
        r"(Award [\w ]*BIOS v[\w.]+|Award Modular BIOS v?[\w.]*|"
        r"AMIBIOS(?: \w+)?(?: \(C\)\s*\d{4})?|American Megatrends|"
        r"Phoenix\w* ?(?:BIOS|FirstBIOS|ServerBIOS|TrustedCore|SecureCore)"
        r"[\w .]*|Release \d\.\d|Version \d+\.\d+\w*|MR BIOS[\w .]*|"
        r"Quadtel[\w .]*|SystemSoft[\w .]*)",
        re.I,
    ),
    "bios_id": re.compile(
        r"(\d\d/\d\d/\d{4}-[0-9A-Z]{3,8}-[0-9A-Z]{3,8}-[0-9A-Z]{6,12}-[0-9A-Z]{2}|"
        r"\d\d-\d{4}-\d{6}-\d{8}-\d{6}-[0-9A-Z]{3,8}-[0-9A-Z])"
    ),
    "chipset": re.compile(
        r"(82[34]\d\d\w*|4[34]0[A-Z]{2}\b|i8[1-6]\d\w?\b|VT8\d{3}\w*|VT82C\w+|"
        r"SiS ?\d{3}\w*|ALi ?M?\d{4}\w*|Aladdin\w*|Apollo ?\w+|KT\d{3}A?\b|"
        r"KX133|nForce\d?\w*|OPTi ?\d+\w*|UMC ?\d+\w*|Headland\w*|HT\d{2}\w*|"
        r"\bNEAT\b|\bSCAT\b|82C\d{3}\w*|Symphony\w*|Contaq\w*|Chips and Tech\w*)"
    ),
    "super_io": re.compile(
        r"(W83\d{3}\w*|IT87\d\d\w*|FDC37\w+|LPC47\w+|PC87\d{3}\w*|UM8663\w*|SMC ?\d{3,}\w*)"
    ),
    "cpu": re.compile(
        r"(Pentium(?:\s?(?:II|III|4|Pro|MMX))?|Celeron|Athlon\w*|Duron|"
        r"K6-?(?:2|III)?\+?|Cyrix|6x86\w*|WinChip|486DX\d?|486SX|386DX|386SX|"
        r"80[234]86|AMD-K5|Sempron|Xeon|NexGen|Nx586)"
    ),
    "board": re.compile(
        r"(ABIT|ASUS\w*|GIGABYTE|GA-\w+|Micro-Star|\bMSI\b|ASRock|\bDFI\b|EPoX|"
        r"Shuttle|SOYO|Tyan|Supermicro|Biostar|Elitegroup|\bECS\b|Chaintech|\bQDI\b|"
        r"Jetway|\bFIC\b|AOpen|Compaq|Dell|Fujitsu|Packard Bell|"
        r"\b[0-9A-Z]{4}-[0-9A-Z]{3,5}\([\w ,+-]+\))",
        re.I,
    ),
    "setup_page": re.compile(
        r"^\s*([A-Z][A-Z0-9 &/-]{3,40}(?:SETUP|CONFIGURATION|FEATURES|"
        r"PERIPHERALS|SETTINGS|MANAGEMENT|PROTECTION|MONITOR))\s*$"
    ),
}
FEATURES = {
    "ACPI": [b"RSD PTR ", b"ACPI"],
    "APM": [b"APM"],
    "Plug and Play": [b"$PnP"],
    "SMBIOS/DMI": [b"_SM_", b"_DMI_"],
    "USB": [b"USB"],
    "PCI": [b"$PIR", b"PCI"],
    "Ultra DMA": [b"Ultra DMA", b"UDMA"],
    "Hardware monitor": [b"Fan Speed", b"Temperature", b"VCORE", b"Vcore"],
    "Wake on LAN": [b"Wake On LAN", b"Wake on LAN", b"WOL"],
    "Boot virus protection": [b"Virus"],
    "Flash/BIOS update": [b"Flash", b"BIOS Update"],
}


def _blobs(data: bytes) -> tuple[list[tuple[str, bytes]], list[str]]:
    """The image plus every module that can be decompressed from it."""
    blobs, notes = [("image", data)], []
    mods = lzh.find_modules(data)
    for m in mods:
        try:
            out = lzh.decompress(
                data[m["data_start"] : m["data_start"] + m["packed"]],
                m["size"],
                m["method"].encode(),
            )
            blobs.append((f"Award/LHA module {m['name'] or m['offset']}", out))
        except Exception:  # damaged module
            continue
    if mods:
        notes.append(f"{len(mods)} LHA (Award) modules, searched decompressed")
    elif ami.find_core(data) >= 0:
        try:
            info, amods = ami.extract(data)
            blobs += [(f"AMI module {m['name']}", m["data"]) for m in amods if "data" in m]
            notes.append(
                f"AMIBIOS core {info['version']} with {len(amods)} modules, searched "
                "decompressed"
            )
        except ValueError:
            pass
    elif phoenix.find_segment(data) >= 0:
        try:
            info, pmods = phoenix.extract(data)
            blobs += [(f"Phoenix module {m['name']}", m["data"]) for m in pmods if "data" in m]
            if any("data" in m for m in pmods):
                notes.append(f"Phoenix BIOS with {len(pmods)} modules, searched decompressed")
        except ValueError:
            pass
    return blobs, notes


def summarize(data: bytes) -> Dict[str, Any]:
    blobs, notes = _blobs(data)
    strings = []
    for source, blob in blobs:
        strings += [(source, m.group().decode("latin-1").strip()) for m in STRING.finditer(blob)]
    result: Dict[str, Any] = {"size": f"{len(data)} bytes ({len(data) // 1024} KB)"}
    if notes:
        result["compression"] = notes

    tail = data[-16:]
    date = tail[5:13].decode("latin-1")
    if re.fullmatch(r"\d\d/\d\d/\d\d", date):
        result["bios_date"] = date

    for key, pattern in PATTERNS.items():
        hits, seen = [], set()
        for source, text in strings:
            for m in pattern.finditer(text) if key != "setup_page" else [pattern.match(text)]:
                if not m:
                    continue
                value = text if key in ("version", "board") else m.group(1).strip()
                if len(value) > 120:
                    value = value[:120] + "..."
                if value.lower() in seen:
                    continue
                seen.add(value.lower())
                hits.append(value)
        if hits:
            result[key] = hits[:MAX_PER_GROUP] + (
                [f"... {len(hits) - MAX_PER_GROUP} more"] if len(hits) > MAX_PER_GROUP else []
            )
    everything = b"\0".join(blob for _, blob in blobs)
    result["features"] = [
        name for name, needles in FEATURES.items() if any(n in everything for n in needles)
    ]

    tools = ["rom_info (layout, signatures, reset vector)", "strings/search_bytes (batched)"]
    if notes:
        tools.append("unpack_rom (save the modules as files)")
    setup = None
    for source, blob in blobs:
        try:
            award_setup._find(blob)
            setup = f"Award 4.5x screen scripts in {source}"
            break
        except ValueError:
            pass
        try:
            ami_setup.find_entry(blob)
            setup = f"classic AMIBIOS setup code in {source}"
            break
        except ValueError:
            pass
    if setup:
        tools.append(f"bios_setup_screens ({setup})")
    result["next_tools"] = tools
    return result
