"""
Static VESA BIOS Extensions (VBE) analysis of a video BIOS image.

1. Looks for a VbeInfoBlock template ("VESA" + version + far pointers) in the ROM; if its
   mode-list pointer points into the ROM, that list is authoritative.
2. Otherwise finds candidate mode lists (16-bit mode numbers 0x100-0x1FF ending in 0xFFFF) and
   ranks them by how often their address appears in the code.
3. Translates standard modes (100h-11Bh); for OEM modes it looks for a nearby width/height pair
   and collects resolution strings from the ROM as hints.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Dict

STANDARD_MODES = {
    0x100: "640x400 256 colors",
    0x101: "640x480 256 colors",
    0x102: "800x600 16 colors",
    0x103: "800x600 256 colors",
    0x104: "1024x768 16 colors",
    0x105: "1024x768 256 colors",
    0x106: "1280x1024 16 colors",
    0x107: "1280x1024 256 colors",
    0x108: "80x60 text",
    0x109: "132x25 text",
    0x10A: "132x43 text",
    0x10B: "132x50 text",
    0x10C: "132x60 text",
    0x10D: "320x200 15-bit",
    0x10E: "320x200 16-bit",
    0x10F: "320x200 24-bit",
    0x110: "640x480 15-bit",
    0x111: "640x480 16-bit",
    0x112: "640x480 24-bit",
    0x113: "800x600 15-bit",
    0x114: "800x600 16-bit",
    0x115: "800x600 24-bit",
    0x116: "1024x768 15-bit",
    0x117: "1024x768 16-bit",
    0x118: "1024x768 24-bit",
    0x119: "1280x1024 15-bit",
    0x11A: "1280x1024 16-bit",
    0x11B: "1280x1024 24-bit",
}
VBE_VERSIONS = {0x0100, 0x0101, 0x0102, 0x0110, 0x0120, 0x0200, 0x0300}
WIDTHS = {
    320,
    360,
    400,
    512,
    640,
    720,
    800,
    848,
    960,
    1024,
    1152,
    1280,
    1360,
    1400,
    1440,
    1600,
    1680,
    1792,
    1856,
    1920,
    2048,
}
HEIGHTS = {
    200,
    240,
    300,
    350,
    384,
    400,
    480,
    600,
    720,
    768,
    864,
    900,
    960,
    1024,
    1050,
    1080,
    1200,
    1344,
    1392,
    1440,
    1536,
}


def _mode_list_at(data: bytes, off: int, max_len: int = 128) -> list[int] | None:
    modes: list[int] = []
    for j in range(off, min(len(data) - 1, off + 2 * max_len), 2):
        m = struct.unpack_from("<H", data, j)[0]
        if m == 0xFFFF:
            return modes or None
        if not 0x100 <= m <= 0x1FF or m in modes:
            return None
        modes.append(m)
    return None


def _candidates(data: bytes) -> list[dict]:
    found, i = [], 0
    while i < len(data) - 8:
        if data[i + 1] == 0x01:
            modes = _mode_list_at(data, i)
            if modes and len(modes) >= 3:
                refs = data.count(struct.pack("<H", i))  # address used as an immediate/pointer
                found.append({"offset": i, "modes": modes, "references": refs})
                i += 2 * len(modes) + 2
                continue
        i += 1
    return found


def _info_blocks(data: bytes) -> list[dict]:
    blocks = []
    for m in re.finditer(rb"VESA", data):
        p = m.start()
        if p + 20 > len(data):
            continue
        version, oem_off, oem_seg, _caps, list_off, list_seg, mem = struct.unpack_from(
            "<HHHIHHH", data, p + 4
        )
        if version not in VBE_VERSIONS:
            continue
        block: Dict[str, Any] = {"offset": p, "vbe_version": f"{version >> 8}.{version & 0xFF}"}
        if oem_seg in (0xC000, 0xE000) and oem_off < len(data):
            end = data.find(b"\0", oem_off, oem_off + 120)
            text = data[oem_off : end if end > 0 else oem_off + 80].decode("latin-1")
            if text.isprintable():
                block["oem_string"] = text
        if 0 < mem <= 0x400:
            block["video_memory_in_template"] = f"{mem * 64} KB (often filled in at runtime)"
        if list_seg in (0xC000, 0xE000):
            modes = _mode_list_at(data, list_off)
            if modes:
                block["mode_list_offset"] = list_off
                block["modes"] = modes
        blocks.append(block)
    return blocks


def _resolution(desc: str) -> tuple[int, int] | None:
    m = re.match(r"(\d+)x(\d+) ", desc)
    return (int(m[1]), int(m[2])) if m and "text" not in desc else None


def _pairs_at(data: bytes, mode: int, dist: int) -> list[tuple[int, int]]:
    """Width/height pairs found 'dist' bytes after each occurrence of the mode number."""
    needle, out, pos = struct.pack("<H", mode), [], data.find(struct.pack("<H", mode))
    while pos >= 0:
        if pos + dist + 4 <= len(data):
            out.append(struct.unpack_from("<HH", data, pos + dist))
        pos = data.find(needle, pos + 1)
    return out


def _mode_table_layout(data: bytes, modes: list[int]) -> tuple[int, int] | None:
    """Find a distance d at which the known standard modes have their real width/height.
    Returns (d, number of standard modes confirming it) if at least 4 and at least half of
    the listed standard graphics modes agree."""
    known = {m: _resolution(STANDARD_MODES[m]) for m in modes if m in STANDARD_MODES}
    known = {m: r for m, r in known.items() if r}
    best = None
    for d in range(2, 40):
        hits = sum(1 for m, r in known.items() if r in _pairs_at(data, m, d))
        if hits >= max(4, (len(known) + 1) // 2) and (best is None or hits > best[1]):
            best = (d, hits)
    return best


def _oem_resolution(data: bytes, mode: int, dist: int) -> str | None:
    for w, h in _pairs_at(data, mode, dist):
        if w in WIDTHS and h in HEIGHTS:
            return f"{w}x{h}"
    return None


def analyze(data: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if data[:2] != b"\x55\xaa":
        result["warning"] = "no option ROM header (55 AA); this may not be a video BIOS"
    blocks = _info_blocks(data)
    if blocks:
        result["vbe_info_templates"] = [
            {k: v for k, v in b.items() if k != "modes"} for b in blocks
        ]
    cands = _candidates(data)

    chosen, source = None, None
    with_list = [b for b in blocks if "modes" in b]
    if with_list:
        chosen, source = with_list[0]["modes"], (
            f"VbeInfoBlock template at 0x{with_list[0]['offset']:X} points to the list at "
            f"0x{with_list[0]['mode_list_offset']:X} (authoritative)"
        )
    elif cands:
        best = max(cands, key=lambda c: (c["references"] > 0, c["references"], len(c["modes"])))
        chosen = best["modes"]
        source = (
            f"candidate list at 0x{best['offset']:X}, its address appears "
            f"{best['references']} times in the ROM"
            + ("" if best["references"] else " (not referenced directly; less certain)")
        )
    if chosen is None:
        result["modes"] = []
        if blocks:
            result["note"] = (
                "the ROM supports VBE, but no static mode list was found; the BIOS "
                "probably builds it at runtime (look at the INT 10h AX=4F00h handler "
                "with disassemble)"
            )
        else:
            result["note"] = "no VBE support found; probably a plain VGA (or older) BIOS"
    else:
        result["source"] = source
        layout = _mode_table_layout(data, chosen)
        modes = []
        for m in chosen:
            if m in STANDARD_MODES:
                modes.append(f"{m:03X}h: {STANDARD_MODES[m]}")
                continue
            res = _oem_resolution(data, m, layout[0]) if layout else None
            modes.append(f"{m:03X}h: OEM mode" + (f", {res}" if res else ", resolution unknown"))
        result["modes"] = modes
        if layout:
            result["oem_resolutions_from"] = (
                f"a mode table where {layout[1]} standard modes have their correct resolution "
                f"{layout[0]} bytes after the mode number; OEM resolutions read the same way "
                "(color depth not determined)"
            )
    others = [c for c in cands if c["modes"] != chosen]
    if others:
        result["other_candidate_lists"] = [
            f"0x{c['offset']:X} ({c['references']} references): "
            + " ".join(f"{m:X}" for m in c["modes"][:24])
            for c in others[:5]
        ]
        if chosen and all(set(c["modes"]) <= set(chosen) for c in others):
            result["other_lists_note"] = (
                "the other lists are subsets of the chosen one; often one "
                "list per video memory size"
            )
    hints = sorted(set(re.findall(rb"\b\d{3,4} ?[xX] ?\d{3,4}\b", data)))
    if hints:
        result["resolution_strings_in_rom"] = [h.decode() for h in hints[:30]]
    result["caveat"] = (
        "A ROM lists every mode its BIOS knows; at runtime some are hidden "
        "depending on installed video memory, monitor or chip revision."
    )
    return result
