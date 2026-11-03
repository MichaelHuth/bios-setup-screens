"""
Read the setup pages of Intel's own desktop-board BIOS (AMI core 6.32, BIOS ID "....86A....",
about 1999-2003) from the ROM without running it: the fallback where its POST does not run in
the emulator (intel_setup).

Worked out on Intel D845WR, VC820 and MVAP25:
- the pages are in the Setup Server module (id 1), as page scripts of the AMIBIOS 8 kind
  (ami8_static_setup: 44 title/text, 43 line, 41 item record, 42 sub-menu or action, 45
  information line), with offsets from the module's start; the texts in the English
  Multilanguage module ("GNALSU");
- the menu bar (Maintenance, Main, Advanced, Security, Power, Boot, Exit) is a list of 42
  entries ended by 00, the one a word elsewhere in the module points at and that no other such
  list's pages step over;
- the defaults are not in the ROM (no "$SDS" image as in AMIBIOS 8): the first option of each
  list is shown.
"""

from __future__ import annotations

import struct

import ami
import ami8_static_setup as a8
from textscreen import Screen

SETUP_SERVER, MULTILANGUAGE = 0x01, 0x21


def _parts(rom: bytes) -> tuple[bytes, bytes] | None:
    """(English strings, Setup Server module), or None."""
    try:
        info, modules = ami.extract(rom)
    except Exception:
        return None
    if info.get("version") != "0632":
        return None
    # (Intel CC820: its English texts are a "User ROM" module tagged "GNALsu")
    lang = next(
        (
            m["data"]
            for m in modules
            if m.get("id") in (MULTILANGUAGE, 0x2A)
            and (m.get("data") or b"")[:6].upper() == b"GNALSU"
        ),
        None,
    )
    server = next(
        (m["data"] for m in modules if m.get("id") == SETUP_SERVER and m.get("data")), None
    )
    if lang is None or server is None:
        return None
    return lang, server


def is_intel_static(rom: bytes) -> bool:
    return b".86A." in rom and _parts(rom) is not None


def _walk(buf: bytes, off: int, seen: set, depth: int = 0) -> None:
    """The offsets a page script and the pages it opens cover (for the menu bar search)."""
    o = off
    for _ in range(300):
        if not 0 <= o < len(buf) or depth > 4:
            return
        seen.add(o)
        op = buf[o]
        if op == 0x00:
            return
        if op == 0x44:
            o += 4
        elif op == 0x43:
            o += 2
        elif op == 0x41:
            o += 3
        elif op == 0x45:
            o += 6
        elif op == 0x42 and o + 8 <= len(buf):
            _, kind, target, flags = struct.unpack_from("<HBHH", buf, o + 1)
            if kind == 1 and target not in seen:
                _walk(buf, target, seen, depth + 1)
            o += 8 + 2 * (bool(flags & 0x80) + bool(flags & 0x20) + bool(flags & 0x04))
        else:
            return


def _menu_bar(buf: bytes, count: int) -> list[tuple[int, int]]:
    """[(name string id, page offset)] of the menu bar."""
    found = []
    for p in range(len(buf) - 8):
        if buf[p] != 0x42:
            continue
        q, tabs, covered = p, [], set()
        while q + 8 <= len(buf) and buf[q] == 0x42 and buf[q + 3] == 0x01:
            sid, _, target, flags = struct.unpack_from("<HBHH", buf, q + 1)
            if sid >= count or not 0 < target < len(buf):
                break
            covered.add(q)
            tabs.append((sid, target))
            q += 8 + 2 * (bool(flags & 0x80) + bool(flags & 0x20) + bool(flags & 0x04))
        pointed = buf.find(struct.pack("<H", p), 0, max(0, p - 8)) >= 0
        if len(tabs) >= 4 and q < len(buf) and buf[q] == 0x00 and pointed:
            for _, target in tabs:
                _walk(buf, target, covered)
            found.append((p, tabs, covered))
    roots = [
        (p, tabs) for p, tabs, _ in found if not any(p in other for q, _, other in found if q != p)
    ]
    if len(roots) != 1:
        raise ValueError("the menu bar of Intel's setup was not found in its Setup Server module")
    return roots[0][1]


class _Strings(a8.Strings):
    """The English texts; the header points at the offset table with a 32-bit word, or (Intel
    CC820, "GNALsu") a 16-bit one followed by FFFFh."""

    def __init__(self, data: bytes):
        self.d = data
        base = struct.unpack_from("<I", data, 8)[0]
        if base >= len(data):
            base = struct.unpack_from("<H", data, 8)[0]
        self.base = base
        self.n = struct.unpack_from("<H", data, base)[0] // 2
        self.offs = struct.unpack_from(f"<{self.n}H", data, base)


class IntelStatic(a8.AmiBios8Static):
    def __init__(self, rom: bytes):
        try:
            self._setup(rom)
        except (struct.error, IndexError) as e:
            raise ValueError(f"Intel's setup pages could not be read from the ROM: {e}") from e

    def screens(self) -> list[tuple[str, Screen, str]]:
        try:
            return super().screens()
        except (struct.error, IndexError) as e:
            raise ValueError(f"Intel's setup pages could not be read from the ROM: {e}") from e

    def _setup(self, rom: bytes) -> None:
        parts = _parts(rom)
        if parts is None:
            raise ValueError("not Intel's own BIOS on an AMI 6.32 core with a Setup Server module")
        lang, self.slab = parts
        self.S = _Strings(lang)
        self.base, self.layout = 0, "tabs"
        self.title = "BIOS SETUP UTILITY"
        self.defaults = bytes(0x200)  # (not in the ROM: index 0, the first option, is shown)
        self.copyright = ""
        legends = [
            self.S(i) for i in range(self.S.n) if "Select" in self.S(i) and "F10" in self.S(i)
        ]
        self.legend_sub = self.legend_opt = legends[0] if legends else ""
        self.main = []
        self.tabs = [
            (self.S(sid).strip(), target) for sid, target in _menu_bar(self.slab, self.S.n)
        ]
