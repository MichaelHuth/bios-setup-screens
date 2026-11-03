"""
AMIBIOS module lists (AMIBIOS 95, 98, 7 and 8 images; not AMI '94 or Aptio/UEFI).

The modules form a chain that is read backwards: the core header ("AMIBIOSC" and a four-digit
version) holds the address of the last module's header, and every 20-byte module header the
address of the one before it. A compressed body is a bare LH5 stream (no LHA header).
"""

from __future__ import annotations

import struct

import lzh

MODULE_NAMES = {  # (by module id, as AMI's tools name them)
    0x00: "POST",
    0x01: "Setup Server",
    0x02: "Runtime",
    0x03: "DIM",
    0x04: "Setup Client",
    0x05: "Remote Server",
    0x06: "DMI data",
    0x07: "Green PC",
    0x08: "Interface",
    0x09: "MP",
    0x0A: "Notebook",
    0x0B: "INT 10h",
    0x0C: "ROM ID",
    0x0D: "INT 13h",
    0x0E: "OEM logo",
    0x0F: "ACPI tables",
    0x10: "ACPI AML",
    0x11: "CPU microcode",
    0x12: "Configuration",
    0x13: "DMI code",
    0x14: "System health",
    0x15: "Memory sizing",
    0x16: "Memory test",
    0x17: "Debug",
    0x18: "ADM (display manager)",
    0x19: "ADM Font",
    0x1A: "Small logo",
    0x1B: "SLAB",
    0x1C: "BCP info",
    0x1D: "Dual logo",
    0x20: "PCI option ROM",
    0x21: "Multilanguage",
    0x22: "User defined",
    0x23: "ASCII font",
    0x24: "BIG5 font",
    0x25: "OEM logo",
    0x2A: "User ROM",
    0x2B: "PXE",
    0x2C: "AMI font",
    0x2F: "Serial redirection",
    0x30: "Font database",
    0x36: "Anti-virus",
    0x37: "Online menu",
    0x40: "AMD CIM-X NB",
    0x60: "AMD CIM-X SB",
    0x80: "Image info",
}
CORE = b"AMIBIOSC"
# previous offset, previous segment (or high word), stored length, id, flags, load address,
# packed length, unpacked length
HEADER = struct.Struct("<HHHBBIII")
LAST = 0xFFFF  # a previous-module word that ends the list
STORED_IDS = (0x40, 0x60)  # AMD CIM-X binaries: stored, whatever their flag says
MAX_MODULES = 0x80
MB = 0x100000


def _versioned(data: bytes, at: int) -> bool:
    return data[at + 8 : at + 12].isdigit()


def _hits(data: bytes) -> list[int]:
    out, at = [], data.find(CORE)
    while at >= 0:
        out.append(at)
        at = data.find(CORE, at + 1)
    return out


def find_core(data: bytes) -> int:
    """Offset of the AMIBIOSC core header, or -1. The header has a version of four digits;
    other hits are "AMINCBLK" or code that looks for the header (ASUS P6TD Deluxe)."""
    hits = _hits(data)
    at = next((h for h in hits if _versioned(data, h)), -1)
    if at < 0 and hits:
        at = hits[0]
        if data[at + 8 : at + 12] == b"AMIN":
            at = hits[1] if len(hits) > 1 else -1
    return at if 0 <= at and at + 22 <= len(data) else -1


class _Addresses:
    """How module addresses map to file offsets. An image of up to 1 MB ends at 1 MB and its
    addresses are segment:offset; a larger one ends at 4 GB with 32-bit addresses, except
    when the first address is a file offset already (ASUS 2 MB images, "ASUSTEK" header) or
    only fits as segment:offset in the last 1 MB (2 MB images of Intel 5-series boards, flash
    descriptor and ME region first)."""

    def __init__(self, size: int, low: int, high: int):
        self.wide = size > MB
        self.base = (1 << 32) - size if self.wide else (MB - size) % MB
        if self.wide:
            flat = high << 16 | low
            if flat < size:
                self.base = 0
            if not 0 <= flat - self.base <= size - HEADER.size:
                real = (high << 4) + low
                if 0 <= real + size - MB <= size - HEADER.size:
                    self.wide, self.base = False, MB - size

    def offset(self, low: int, high: int) -> int:
        return ((high << 16 | low) if self.wide else (high << 4) + low) - self.base


def _file_name(ident: int, load: int) -> str:
    if ident == 0x20:  # (its load address is the card's vendor and device)
        return f"pci_{load & 0xFFFF:04x}_{load >> 16:04x}.rom"
    if ident == 0x21:  # (and the language's two letters)
        return f"lang_{chr(load >> 8 & 0xFF)}{chr(load & 0xFF)}.bin"
    return f"module_{ident:02x}.bin"


def _module(data: bytes, at: int) -> tuple[dict, int, int]:
    """The module whose header is at at, and its previous-module words."""
    prev_low, prev_high, stored_len, ident, flags, load, packed, unpacked = HEADER.unpack_from(
        data, at
    )
    compressed = not flags & 0x80 and ident not in STORED_IDS
    if compressed:
        body = at + HEADER.size
    else:
        body, unpacked = at + 0x0C, stored_len
        if unpacked in (0, 0xFFFF) and at >= 8:  # (a large one: its length is before the header)
            unpacked = struct.unpack_from("<I", data, at - 8)[0]
        packed = unpacked
    mod: dict = {
        "id": ident,
        "name": MODULE_NAMES.get(ident, "unknown"),
        "file_name": _file_name(ident, load),
        "offset": at,
        "compressed": compressed,
        "packed": packed,
        "size": unpacked,
    }
    if body + packed > len(data) or unpacked > 16 << 20:
        mod["error"] = "sizes in the header point outside the image"
    elif not compressed:
        mod["data"] = data[body : body + unpacked]
    else:
        try:
            mod["data"] = lzh.decompress(data[body : body + packed], unpacked, b"-lh5-")
        except Exception as e:  # pylint: disable=broad-exception-caught
            mod["error"] = f"decompression failed: {e}"
    return mod, prev_low, prev_high


def _read(data: bytes, core: int | None = None) -> tuple[dict, list[dict]]:
    """The core header's information and the modules along its chain."""
    core = find_core(data) if core is None else core
    if core < 0:
        raise ValueError("no AMIBIOSC core header (not an AMIBIOS 95/8 image)")
    size = len(data)
    info: dict = {
        "version": data[core + 8 : core + 12].decode("latin-1"),
        "date": data[-11:-3].decode("latin-1"),
        "core_header": core,
    }
    if (boot := data.find(b"AMIBOOT ROM")) >= 0:
        start = boot & ~0xFFFF
        info["boot_block"] = {"offset": start, "size": size - start}
    low, high = struct.unpack_from("<HH", data, core + 18)
    addresses = _Addresses(size, low, high)
    modules: list[dict] = []
    visited: set[int] = set()
    while len(modules) < MAX_MODULES:
        at = addresses.offset(low, high)
        if at in visited:
            break
        if not 0 <= at <= size - HEADER.size:
            address = (high << 16 | low) if addresses.wide else (high << 4) + low
            modules.append({"error": f"module pointer 0x{address:X} is outside the image"})
            break
        visited.add(at)
        mod, low, high = _module(data, at)
        modules.append(mod)
        if LAST in (low, high):
            break
    return info, modules


def _good(modules: list[dict]) -> int:
    return sum("error" not in m for m in modules)


def extract(data: bytes) -> tuple[dict, list[dict]]:
    """Returns (image info, modules). Each module has id, name, file_name, offset, packed,
    size, compressed, and either 'data' or 'error'. Of several core headers with a version
    (a stray one in data: ASRock K7 Upgrade-600) the one whose list gives most good modules
    is taken; a flash image over 2 MB whose BIOS region is only its end (flash descriptor and
    ME first) is also read from its last 2 or 1 MB (offsets stay those in the whole image)."""
    info, modules = _read(data)
    for at in _hits(data):
        if at == info["core_header"] or not _versioned(data, at):
            continue
        try:
            other = _read(data, at)
        except (ValueError, struct.error):
            continue
        if _good(other[1]) > _good(modules):
            info, modules = other
    if len(data) > 2 * MB and _good(modules) < 8:
        for part in (2 * MB, MB):
            try:
                part_info, part_modules = _read(data[-part:])
            except ValueError:
                continue
            if _good(part_modules) <= _good(modules):
                continue
            shift = len(data) - part
            for m in part_modules:
                if isinstance(m.get("offset"), int):
                    m["offset"] += shift
            part_info["core_header"] += shift
            if "boot_block" in part_info:
                part_info["boot_block"]["offset"] += shift
            info, modules = part_info, part_modules
    return info, modules
