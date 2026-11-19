"""
A rebuilt POST screen of an Award BIOS (Modular 4.5x, 6.00PG, Phoenix-AwardBIOS, Medallion),
for the routes that read the setup from the ROM without running POST: the ROM's own texts
put where Award's POST shows them.

- the system BIOS's top 64 KB (F000) keeps the banner ("Award Modular BIOS v6.00PG") at
  E061, the board message (modbin's "BIOS message", e.g. "ASUS P2B ACPI BIOS Revision
  1014") at E0C1 and the BIOS ID ("08/01/2002-i440BX-<<P2B>>") at EC71, each ending with 0;
  the copyright line follows the banner;
- the POST messages (", An Energy Star Ally", "Memory Test : ", "Press DEL to enter SETUP")
  are in the system BIOS or, on later 6.00PG versions, in the language module _EN_CODE.BIN;
- the Energy Star logo (module AWARDEPA.BIN) is a block of characters: columns and rows,
  an attribute per character, then 14 lines of glyph per character, drawn at the top right.
The CPU and the memory size are only known at run time: the memory line shows an example.
"""

from __future__ import annotations

import re

import lzh
from textscreen import FONTS, Screen

MEMORY_EXAMPLE = b"131072K OK"  # (128 MB, a size of the 6.00PG years; only an example)
BANNER = re.compile(
    rb"(?:Award Modular|Phoenix ?- ?Award ?\w*|Award Medallion|[A-Z]\w+ Award)"
    rb" ?BIOS v\d\.\d+[A-Z]{0,4}(?![a-z])"
)  # (not "v6.00PGSave": the setup's "...BIOS v6.00PGSave To Disk Manager"; "TDVIA Award
# BIOS v6.00PG": a board maker's own name)
COPYRIGHT = re.compile(rb"Copyright \(C\) (?:19\d\d-)?\d{2,4},? [\x20-\x7e]{4,60}?(?=\x00)")
BIOS_ID = re.compile(rb"\d\d/\d\d/(?:\d\d){1,2}-[\x21-\x7e][\x20-\x7e]{4,60}?(?=\x00)")
MEMORY = re.compile(rb"Memory Test(?:ing)? : ")
SETUP_KEY = re.compile(
    rb"Press[\x00-\x1f\x7f-\xff ]{1,4}DEL[\x00-\x1f\x7f-\xff ]{1,4}to enter SETUP([/\w -]*)"
)


def _unpacked(image: bytes) -> list[tuple[str, bytes]]:
    out = []
    for m in lzh.find_modules(image):
        try:
            data = lzh.decompress(
                image[m["data_start"] : m["data_start"] + m["packed"]],
                m["size"],
                m["method"].encode(),
            )
        except Exception:  # (a module that does not unpack has no POST texts to give)
            continue
        out.append((m["name"], data))
    return out


def _text_at(seg: bytes, at: int) -> bytes:
    end = seg.find(b"\x00", at)
    text = seg[at : end if end >= 0 else at + 80]
    return text if text and all(0x20 <= c < 0x7F for c in text) else b""


def _system(image: bytes, modules: list[tuple[str, bytes]]) -> bytes:
    """The system BIOS: the largest module with the banner, or the image itself."""
    for _, data in sorted(modules, key=lambda m: -len(m[1])):
        if len(data) >= 0x10000 and BANNER.search(data):
            return data
    return image if BANNER.search(image[-0x20000:]) else b""


def _logo(modules: list[tuple[str, bytes]]) -> tuple[int, int, bytes, bytes] | None:
    """The Energy Star logo: (columns, rows, attributes, glyphs of 14 lines)."""
    for name, data in modules:
        if "EPA" not in name.upper() or len(data) < 2:
            continue
        cols, rows = data[0], data[1]
        n = cols * rows
        if 0 < n <= 128 and len(data) >= 2 + n + 14 * n:
            return cols, rows, data[2 : 2 + n], data[2 + n : 2 + n + 14 * n]
    return None


def post_screen(image: bytes) -> tuple[Screen, str] | None:
    """The rebuilt POST screen and its text (without the logo's characters), or None where
    the ROM's texts are not found."""
    modules = _unpacked(image)
    system = _system(image, modules)
    if not system:
        return None
    seg = system[-0x10000:]  # (F000; Phoenix-Award keeps its banner further down)
    texts = system + b"".join(d for _, d in modules) + image
    top = len(system) - len(seg)
    banner = BANNER.search(system, top + 0xE000, top + 0xE100) or BANNER.search(system)
    if banner is None:
        return None
    # the copyright line after the banner ("1984-2000"; not the Plug and Play extension's
    # "Copyright (C) 1998, Award Software, Inc." elsewhere)
    near = (banner.end(), banner.end() + 0x100)
    copyright_ = next(
        (
            m
            for m in (COPYRIGHT.search(system, *near), COPYRIGHT.search(system))
            if m and b"-" in m.group()[:20]
        ),
        COPYRIGHT.search(system, *near),
    )
    if copyright_ is None:
        return None
    s = Screen()
    line = banner.group()
    if b", An Energy Star Ally" in texts and not line.startswith(b"Award Medallion"):
        line += b", An Energy Star Ally"
    s.write(0, 0, line, 0x07)
    s.write(0, 1, copyright_.group(), 0x07)
    message = _text_at(seg, 0xE0C1)
    if message.strip():
        s.write(0, 3, message.strip(), 0x07)
    memory = MEMORY.search(texts)
    if memory:
        s.write(0, 5, memory.group() + b" " + MEMORY_EXAMPLE, 0x07)
    key = SETUP_KEY.search(texts)
    s.write(0, 23, b"Press DEL to enter SETUP" + (key.group(1).rstrip() if key else b""), 0x07)
    bios_id = BIOS_ID.match(seg, 0xEC71) or BIOS_ID.search(seg[0xE000:])
    if bios_id:
        s.write(0, 24, bios_id.group(), 0x07)
    text = s.text()
    logo = _logo(modules)
    if logo:
        cols, rows, attrs, glyphs = logo
        font = bytearray(FONTS[16])
        first = 0x100 - cols * rows  # (the top codes: no text of the screen uses them)
        for i in range(cols * rows):
            code = first + i
            font[code * 16 : code * 16 + 16] = glyphs[i * 14 : i * 14 + 14] + b"\x00\x00"
            s.put(80 - cols + i % cols, i // cols, code, attrs[i])
        s.font = bytes(font)
    return s, text
