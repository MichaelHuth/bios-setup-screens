"""
Setup screens of ASRock UEFI firmware, drawn in the setup's own look (group A of uefigui).

generation(rom) names the ASRock setup look of a flash image ("A1", "A2", "A3", or None for
firmware that is not one of them); pages(rom) draws every screen that
uefi_setup.UefiSetup.screens() would produce for the same image, in the same order and with the
same titles, as pictures:

- the background, the right-hand help panel, the tab buttons, the selected-row bar and the bottom
  legend bar are the firmware's own pictures. Unlike ASUS, an ASRock module holds its pictures
  back to back at offset 0 of one freeform/raw FFS section (no record chain), and the module's
  GUID names its role: 68BA3E2A is the page background on all 26 boards, 4A7C6E15 the right help
  panel, D4D47FB4 / FA54910A / 30C84F09 the tab buttons (normal / hover / selected), EBEE1746 the
  heading band, AA478709 the bottom legend bar, 326DCD5F the selected-row bar;
- A1 (2014-16: Z97 Pro4/Extreme4/Killer, H97M Pro4) ships its chrome twice, once at 1024x768 and
  once at 1920x1080 (the "watch the UEFI in FullHD" setting); the 1024x768 copy is used here, and
  the geometry is scaled when only the FullHD copy is present;
- A2 (2013-14: the FM2A*/Z77/A68/B85 boards) is the same skin one generation earlier, 1024x768
  only, and its accent colour follows the product line (red on the Fatal1ty boards, blue on the
  others), so the accent is sampled from the firmware's own selected-tab picture;
- A3 (2011-13: the H61/AM3+/A75 boards) is the blue bokeh skin with "ASROCK UEFI SETUP UTILITY"
  and "Tomorrow's Technology Today" printed into the background, a light help panel (so its help
  text is drawn dark) and 170x28 gradient tab bars;
- the content of the screens is the IFR, exactly as asus_gui draws it: one row per question
  (prompt left, its default value right), SUBTITLE as a section heading, a sub-menu link marked
  with a triangle, the first selectable item's help word-wrapped in the help box, and "N/A" for
  the values the setup only knows at run time.

Nothing in the image gives a screen position: the background pictures were measured
(work/ag_2.py) and the boxes below follow their bands (the tab band, the bottom bar, the panel's
own size), the rest is this module's own choice.
"""

from __future__ import annotations

import io
import re
import struct
import uuid
from typing import Any, Optional, Union

from PIL import Image, ImageDraw, ImageFont

import asus_gui as A
import tiano
import uefi_setup as U

MAX_DEPTH = 7
NA = "N/A"
Font = Union[ImageFont.FreeTypeFont, ImageFont.ImageFont]

# the modules whose role is the same on every ASRock board (GUID prefix = the FFS file name)
BG, BG_HD = "68BA3E2A", "F7625B66"  # the page background, 1024x768 and (A1 only) 1920x1080
PANEL = "4A7C6E15"  # the right-hand help panel
TAB, TAB_HOVER, TAB_SEL = "D4D47FB4", "FA54910A", "30C84F09"
BANNER = "EBEE1746"  # the heading band (A3, and some A2 boards)
LEGEND = "AA478709"  # the bottom key-legend bar (A1)
SELBAR = "326DCD5F"  # the selected-row bar (A1)
POPUP = "4CDE2C4A"  # the 800x540 dialog panel (A2)
PHOTO = "325F55E5"  # the photo of the board, on the Tool / system-browser page
POSTCOL = ("65FB984A", "7CA714AB")  # the 264x768 POST side columns (A2)
# the markers that say "this is an ASRock setup of this generation"
A2_MARK = (POPUP, PHOTO, "65FB984A", "7CA714AB", "E3D54510", "51E0D04D", "2FCCE0EA", "FEF9585E")
A3_MARK = (BANNER, "C6AD9672", "8FD5FDAD", PANEL, "112B7E7F", TAB_SEL)

GEO: dict[str, dict[str, Any]] = {
    # every number is for a 1024x768 canvas; _draw_page scales them when the background is bigger
    "A1": {
        # the background's own tab band sits at y 55-100 and its outlined bottom bar at y 735-765
        "frame": (16, 56, 1008, 722),
        "tabs": (24, 62),
        "tabh": 44,
        "items": (44, 132, 664, 700),
        "panelxy": (700, 128),
        "help": (712, 152, 996, 640),
        "legendxy": (0, 728),
        "foot": (16, 730, 1008, 762),
        "pitch": 26,
        "rowh": 24,
        "fsel": 18,
        "fhead": 19,
        "ftab": 16,
        "ftitle": 18,
        "fhelp": 15,
    },
    "A2": {
        # the background's tab band is the coloured gradient at y 60-140, its bottom bar y 726-745
        "frame": (16, 56, 1008, 720),
        "tabs": (24, 84),
        "tabh": 28,
        "items": (44, 130, 664, 700),
        "panelxy": (700, 120),
        "help": (712, 150, 998, 660),
        "legendxy": None,
        "foot": (16, 726, 1008, 762),
        "pitch": 26,
        "rowh": 24,
        "fsel": 18,
        "fhead": 19,
        "ftab": 15,
        "ftitle": 18,
        "fhelp": 15,
    },
    "A3": {
        # the title is printed at y 10-40 and the tagline bar at y 726-741, so the heading band
        # goes at y 52 and the tab row under it
        "frame": (16, 52, 1008, 720),
        "tabs": (24, 112),
        "tabh": 28,
        "items": (44, 156, 640, 700),
        "panelxy": (693, 96),
        "help": (705, 196, 990, 620),  # below the panel's own dark header band (its top 86 px)
        "bannerxy": (96, 52),
        "legendxy": None,
        "foot": (16, 744, 1008, 762),
        "pitch": 25,
        "rowh": 23,
        "fsel": 17,
        "fhead": 18,
        "ftab": 15,
        "ftitle": 17,
        "fhelp": 14,
    },
}
# the text colours; the accent of the headings, of the highlighted row and of the selected tab is
# replaced by the colour sampled from the firmware's own tab picture (see Skin)
COLOURS: dict[str, dict[str, Any]] = {
    "A1": {
        "head": (4, 246, 255),
        "item": (235, 235, 235),
        "value": (255, 255, 255),
        "sel": (4, 246, 255),
        "seltext": (12, 18, 20),
        "tab": (200, 200, 200),
        "tabtext": (240, 240, 240),
        "line": (70, 70, 70),
        "help": (215, 220, 225),
        "title": (255, 255, 255),
        "foot": (170, 175, 180),
    },
    "A2": {
        "head": (255, 90, 90),
        "item": (235, 235, 235),
        "value": (255, 255, 255),
        "sel": (255, 90, 90),
        "seltext": (18, 12, 12),
        "tab": (200, 200, 200),
        "tabtext": (240, 240, 240),
        "line": (70, 70, 70),
        "help": (215, 220, 225),
        "title": (255, 255, 255),
        "foot": (170, 175, 180),
    },
    "A3": {
        "head": (235, 245, 250),
        "item": (240, 248, 252),
        "value": (255, 255, 255),
        "sel": (19, 123, 184),
        "seltext": (255, 255, 255),
        "tab": (215, 230, 240),
        "tabtext": (16, 24, 32),
        "line": (120, 160, 190),
        "help": (18, 30, 42),  # the A3 help panel is light, so its text is dark
        "title": (255, 255, 255),
        "foot": (225, 235, 245),
    },
}


# --- the firmware volumes, keeping which module a section belongs to -------------------------


def _decompress(ctype: int, payload: bytes) -> bytes:
    if ctype == 0:
        return payload
    if ctype == 1:
        return tiano.decompress(payload)
    if ctype == 2:
        if payload[:1] == b"]":
            return U._lzma(payload)
        if payload[4:5] == b"]":
            return U._lzma(payload[4:])
        return tiano.decompress(payload)
    return b""


def _add(out: dict, guid: str, data: bytes) -> None:
    """Keep a freeform/raw section only when a picture starts at its offset 0 (an ASRock module
    holds its pictures from the first byte, so this drops the rest of the firmware's data)."""
    if _kind(data, 0) is not None:
        out.setdefault(guid, []).append(data)


def _walk_sections(data: bytes, start: int, end: int, out: dict, depth: int, guid: str) -> None:
    p = start
    while p + 4 <= end:
        size = int.from_bytes(data[p : p + 3], "little")
        stype, hdr = data[p + 3], 4
        if size == 0xFFFFFF:
            if p + 8 > end:
                break
            size, hdr = struct.unpack_from("<I", data, p + 4)[0], 8
        if size < hdr or p + size > end:
            break
        body = p + hdr
        try:
            if stype == 0x01 and depth < MAX_DEPTH:  # compression section
                inner = _decompress(data[body + 4], data[body + 5 : p + size])
                if inner:
                    before = sum(len(v) for v in out.values())
                    _walk_sections(inner, 0, len(inner), out, depth + 1, guid)
                    if sum(len(v) for v in out.values()) == before and b"_FVH" in inner:
                        _walk_volumes(inner, out, depth + 1)
            elif stype == 0x02 and depth < MAX_DEPTH:  # GUID-defined section
                g = data[body : body + 16]
                off = struct.unpack_from("<H", data, body + 16)[0]
                payload = data[p + off : p + size]
                inner = (
                    U._lzma(payload)
                    if g == U.LZMA_GUID
                    else tiano.decompress(payload) if g == U.TIANO_GUID else b""
                )
                if inner:
                    _walk_sections(inner, 0, len(inner), out, depth + 1, guid)
                else:
                    _walk_sections(data, p + off, p + size, out, depth + 1, guid)
                    _add(out, guid, payload)
            elif stype == 0x17 and depth < MAX_DEPTH:  # a firmware volume image
                _walk_volumes(data[body : p + size], out, depth + 1)
            elif stype in (0x18, 0x19):  # freeform, raw: the picture containers
                _add(out, guid, data[body : p + size])
        except (ValueError, IndexError, struct.error, EOFError):
            pass
        p = (p + size + 3) & ~3


def _walk_volumes(data: bytes, out: dict, depth: int) -> None:
    i = data.find(b"_FVH")
    while i >= 0:
        v = i - 0x28
        try:
            if v >= 0:
                length, _sig, _attrs, hlen = struct.unpack_from("<Q4sIH", data, v + 0x20)
                if 0x48 <= hlen < 0x1000 and hlen <= length <= len(data) - v:
                    f = v + hlen
                    while f + 24 <= v + length and data[f : f + 24] != b"\xff" * 24:
                        ftype = data[f + 0x12]
                        fsize = int.from_bytes(data[f + 0x14 : f + 0x17], "little")
                        if fsize < 24 or f + fsize > v + length:
                            break
                        if ftype not in (0xF0, 0x01):
                            guid = uuid.UUID(bytes_le=data[f : f + 16]).hex[:8].upper()
                            _walk_sections(data, f + 24, f + fsize, out, depth, guid)
                        f = (f + fsize + 7) & ~7
        except struct.error:
            pass
        i = data.find(b"_FVH", i + 4)


def picture_sections(rom: bytes) -> dict[str, list[bytes]]:
    """Every picture container of the image: module GUID prefix -> its section bytes."""
    out: dict[str, list[bytes]] = {}
    _walk_volumes(rom, out, 0)
    return out


# --- the pictures of one container -----------------------------------------------------------


class Pic:
    __slots__ = ("index", "kind", "off", "size", "w", "h")

    def __init__(self, index: int, kind: str, off: int, size: int, w: int, h: int) -> None:
        self.index, self.kind, self.off, self.size = index, kind, off, size
        self.w, self.h = w, h


def _kind(d: bytes, p: int) -> Optional[str]:
    s = d[p : p + 4]
    if s.startswith(b"\x89P"):
        return "png"
    if s.startswith(b"\xff\xd8"):
        return "jpg"
    if s.startswith(b"GIF8"):
        return "gif"
    if s.startswith(b"BM"):
        try:
            fsize = struct.unpack_from("<I", d, p + 2)[0]
            hdr = struct.unpack_from("<I", d, p + 14)[0]
            return "bmp" if hdr in (12, 40, 52, 56, 108, 124) and 14 < fsize < 0x400000 else None
        except struct.error:
            return None
    return None


def _dims(d: bytes, off: int, kind: str) -> tuple[int, int]:
    try:
        if kind == "png":
            return struct.unpack_from(">II", d, off + 16)
        if kind == "bmp":
            w, h = struct.unpack_from("<ii", d, off + 18)
            return abs(w), abs(h)
        if kind == "gif":
            return struct.unpack_from("<HH", d, off + 6)
        return Image.open(io.BytesIO(d[off : off + 65536])).size
    except (struct.error, IndexError, OSError, ValueError):
        return 0, 0


def _png_len(d: bytes, p: int) -> Optional[int]:
    q = p + 8
    while q + 8 <= len(d):
        ln = int.from_bytes(d[q : q + 4], "little")
        typ = d[q + 4 : q + 8]
        q += 8 + ln + 4
        if typ == b"IEND":
            return q - p
    return None


def _jpg_len(d: bytes, p: int) -> Optional[int]:
    q = p + 2
    while q + 4 <= len(d):
        if d[q] != 0xFF:
            q += 1
            continue
        m = d[q + 1]
        if m == 0xD9:
            return q + 2 - p
        if m in (0x01, 0xFF) or 0xD0 <= m <= 0xD7:
            q += 2
            continue
        ln = int.from_bytes(d[q + 2 : q + 4], "big")
        if ln < 2:
            return None
        q += 2 + ln
        if m == 0xDA:  # start of scan: the entropy stream runs to the end marker
            e = d.find(b"\xff\xd9", q)
            return e + 2 - p if e >= 0 else None
    return None


def _bmp_len(d: bytes, p: int) -> Optional[int]:
    try:
        fsize = struct.unpack_from("<I", d, p + 2)[0]
    except struct.error:
        return None
    return fsize if 14 < fsize <= len(d) - p else None


def _gif_len(d: bytes, p: int) -> Optional[int]:
    q = p + 13
    if q >= len(d):
        return None
    try:
        if d[q] & 0x80:  # a global colour table
            q += 3 << ((d[q] & 7) + 1)
        while q < len(d):
            b = d[q]
            if b == 0x3B:
                return q + 1 - p
            if b not in (0x21, 0x2C):
                return None
            q += 1
            if b == 0x2C:
                q += 8
            while q < len(d):
                sz = d[q]
                q += 1
                if sz == 0:
                    break
                q += sz
    except IndexError:
        return None
    return None


_PIC_LEN = {"png": _png_len, "jpg": _jpg_len, "bmp": _bmp_len, "gif": _gif_len}


def _pic_len(d: bytes, p: int, kind: str) -> Optional[int]:
    which = _PIC_LEN.get(kind)
    return which(d, p) if which is not None else None


def chain(data: bytes) -> list[Pic]:
    """The pictures of one container section, in order. A module usually holds one picture; some
    hold a second, smaller copy right after the first."""
    out: list[Pic] = []
    p = 0
    while p + 4 <= len(data):
        kind = _kind(data, p)
        if kind is None:
            break
        w, h = _dims(data, p, kind)
        n = _pic_len(data, p, kind) or 0
        if n < 8:
            n = len(data) - p
        out.append(Pic(len(out), kind, p, n, w, h))
        # the next picture starts at the next 4-byte boundary, but a section can also pad with a
        # few bytes, so the first offset that sniffs as a picture wins
        q, p = p + n, len(data)
        for cand in range(q, min(q + 8, len(data))):
            if _kind(data, cand) is not None:
                p = cand
                break
    return out


def pictures_of(secs: dict[str, list[bytes]]) -> dict[str, list[Pic]]:
    """module GUID prefix -> its picture records."""
    out: dict[str, list[Pic]] = {}
    for guid, blobs in secs.items():
        recs: list[Pic] = []
        for s in blobs:
            recs.extend(chain(s))
        if recs:
            out[guid] = recs
    return out


def pictures(rom: bytes) -> dict[str, list[Pic]]:
    return pictures_of(picture_sections(rom))


def _generation_of(mods: dict[str, list[Pic]]) -> Optional[str]:
    if not mods:
        return None
    if BG_HD in mods or BG in mods:
        if BG_HD in mods:
            return "A1"
        if any(g in mods for g in A2_MARK):
            return "A2"
        if any(g in mods for g in A3_MARK):
            return "A3"
        return None
    return None


def generation(rom: bytes) -> Optional[str]:
    """ "A1", "A2" or "A3" for an ASRock setup of that look, None for anything else."""
    return _generation_of(pictures(rom))


# --- drawing ---------------------------------------------------------------------------------


def _load(data: bytes, pic: Pic) -> Optional[Image.Image]:
    for cut in (pic.size, len(data) - pic.off):
        try:
            im = Image.open(io.BytesIO(data[pic.off : pic.off + cut]))
            im.load()
            return im.convert("RGBA")
        except (OSError, ValueError):
            im = None
    return None


def _biggest(mods: dict[str, list[bytes]], guid: str) -> Optional[Image.Image]:
    """The largest picture of one module, as RGBA."""
    for blob in mods.get(guid, []):
        recs = chain(blob)
        if not recs:
            continue
        p = max(recs, key=lambda r: r.w * r.h)
        im = _load(blob, p)
        if im is not None:
            return im
    return None


def _tabart(mods: dict[str, list[bytes]], gen: str) -> tuple[Optional[Image.Image], ...]:
    """(the tab button, the selected-tab button), named by module on A2/A3. A1 has one
    glossy light button module per tab and no selected state, and where its text goes on
    them is not known: its tabs are drawn plain on the background's own dark tab band."""
    if gen == "A1":
        return None, None
    return _biggest(mods, TAB), _biggest(mods, TAB_SEL)


def _bright(c: Optional[tuple[int, int, int]]) -> Optional[tuple[int, int, int]]:
    """The same hue with its strongest channel at 255."""
    if c is None or max(c) == 0:
        return c
    r, g, b = (min(255, v * 255 // max(c)) for v in c)
    return r, g, b


class Skin:
    """The firmware's own chrome for one generation: background, help panel, tab buttons."""

    def __init__(self, secs: dict[str, list[bytes]], gen: str) -> None:
        self.gen = gen
        self.geo = dict(GEO[gen])
        self.col = dict(COLOURS[gen])
        # the 1024x768 copy is used when the board has one (A1 ships both), so every page this
        # module draws is the same size; only a board with nothing else renders FullHD
        self.bg = _biggest(secs, BG)
        if self.bg is None or self.bg.width < 800:
            self.bg = _biggest(secs, BG_HD) or self.bg
        self.panel = _biggest(secs, PANEL)
        self.legend = _biggest(secs, LEGEND)
        self.selbar = _biggest(secs, SELBAR)
        self.banner = _biggest(secs, BANNER) if gen == "A3" else None
        self.tab, self.tabsel = _tabart(secs, gen)
        if self.bg is not None:
            self._scale()
        # the accent follows the firmware's own selected-tab picture (red on the Fatal1ty boards,
        # cyan on the Z97 ones), and the help text follows the panel's own brightness
        art = self.tabsel or self.tab
        accent = A._accent(art) if art is not None else None
        if accent is None:  # A1: the hue of its bottom legend bar, at full brightness
            # (a JPEG background has too many colours for _accent)
            accent = _bright(A._accent(self.legend)) if self.legend is not None else None
        if accent is not None:
            self.col["head"] = self.col["sel"] = accent
            self.col["seltext"] = (255, 255, 255) if A._lum(accent) < 140 else (12, 18, 20)
        if self.panel is not None:
            light = A._lum(self._panel_mean()) > 128
            self.col["help"] = (18, 30, 42) if light else (215, 220, 225)
        if art is None:  # plain dark tabs
            self.col["tabtext"] = (240, 240, 240)

    def _panel_mean(self) -> tuple[int, int, int]:
        """The panel as it shows over the background (970 Extreme4's is mostly transparent)."""
        assert self.panel is not None
        panel = self.panel.convert("RGBA")
        under = Image.new("RGBA", panel.size, (0, 0, 0, 255))
        if self.bg is not None:
            x, y = self.geo["panelxy"]
            under = self.bg.convert("RGBA").crop((x, y, x + panel.width, y + panel.height))
        under.alpha_composite(panel)
        r, g, b = under.convert("RGB").resize((1, 1), Image.Resampling.BOX).getpixel((0, 0))  # type: ignore[misc]
        return int(r), int(g), int(b)

    def _scale(self) -> None:
        """The geometry is written for 1024x768; a FullHD background scales all of it."""
        assert self.bg is not None
        w, h = self.bg.width, self.bg.height
        if (w, h) == (1024, 768):
            return
        sx, sy = w / 1024.0, h / 768.0
        g = self.geo
        for key in ("frame", "items", "help", "foot"):
            x0, y0, x1, y1 = g[key]
            g[key] = (int(x0 * sx), int(y0 * sy), int(x1 * sx), int(y1 * sy))
        for key in ("tabs", "panelxy", "legendxy", "bannerxy"):
            at = g.get(key)
            if at is not None:
                g[key] = (int(at[0] * sx), int(at[1] * sy))
        for key in ("tabh", "pitch", "rowh", "fsel", "fhead", "ftab", "ftitle", "fhelp"):
            g[key] = max(int(g[key] * sy), 8)

    def fonts(self) -> dict[str, Font]:
        g = self.geo
        return {
            "head": A._font("arialbd.ttf", g["fhead"]),
            "item": A._font("arial.ttf", g["fsel"]),
            "value": A._font("arial.ttf", g["fsel"]),
            "tab": A._font("arialbd.ttf", g["ftab"]),
            "title": A._font("arialbd.ttf", g["ftitle"]),
            "help": A._font("arial.ttf", g["fhelp"]),
            "foot": A._font("arial.ttf", max(g["fhelp"] - 2, 11)),
        }


def _split_run_time(prompt: str) -> tuple[str, bool]:
    """("Processor Speed : %dMHz" -> ("Processor Speed", True)): ASRock writes the value the setup
    fills in at run time straight into the string, so the format is taken out of the prompt and
    the value column shows N/A instead."""
    last = None
    for m in U.PRINTF.finditer(prompt):
        last = m
    if last is None or last.start() < len(prompt) - 16:
        return prompt, False
    head = prompt[: last.start()].rstrip(" :")
    return (head, True) if head else (prompt, False)


def rows_of(su: U.UefiSetup, items: list, geo: dict) -> list:
    """The IFR items of one form as drawable rows, as asus_gui.rows_of does, but splitting each
    prompt at the firmware's column escape: an ASRock string is usually
    "UEFI Version<ESC>{p90#: %a %a", where the part after the escape is a value the setup fills in
    at run time (a printf format), which UefiSetup.prompt_value drops and this module shows as
    "N/A"."""
    rowh = geo["rowh"]
    out: list[Any] = []
    for it in items:
        kind = it["kind"]
        prompt, inline = su.prompt_value(it.get("prompt"))
        # a printf format anywhere in the raw string means the setup fills that value in at run
        # time, which is shown as N/A (prompt_value has already removed it from the prompt)
        run_time = bool(U.PRINTF.search(su.str(it.get("prompt"))))
        prompt = A._clean(prompt)
        prompt, _cut = _split_run_time(prompt)
        prompt = prompt.rstrip(" :") if prompt.endswith(":") else prompt
        if kind == "ref" and U.link_name(prompt) == U.RUN_TIME_NAME:
            prompt = U.RUN_TIME_NAME
        elif U.PRINTF.search(prompt):  # "XMP %d.%d Profile 1: %d-%d-%d-%d ...": the value
            # starts at the colon; formats left in the name are numbers ("XMP x.x Profile 1")
            prompt = U.PRINTF.sub("x", re.split(r"\s*:\s*(?=%)", prompt, maxsplit=1)[0])
            inline = inline or NA
        if (run_time or _cut) and not inline:
            inline = NA
        if kind == "subtitle":
            if prompt:
                out.append(A.Row("head", prompt, inline, it.get("help") or 0, rowh + 6, False))
            elif out and out[-1].kind != "sep":
                out.append(A.Row("sep", "", "", 0, 12, False))
            continue
        if kind == "text":
            value = A._clean(su.str(it.get("text2"))) or inline or NA
            out.append(A.Row("item", prompt, value, it.get("help") or 0, rowh, False))
            continue
        if kind in ("ref", "action"):
            if not prompt:
                continue
            value = "" if prompt == U.RUN_TIME_NAME else inline  # (a link has no value)
            out.append(A.Row(kind, prompt, value, it.get("help") or 0, rowh, True))
            continue
        value = A._clean(su._value_text(it)) or inline
        if not prompt and out and out[-1].kind == "item" and out[-1].prompt and not out[-1].value:
            last = out[-1]
            out[-1] = A.Row(
                "item", last.prompt, value, last.help or it.get("help") or 0, rowh, True
            )
            continue
        out.append(A.Row("item", prompt, value, it.get("help") or 0, rowh, True))
    return out


def _draw_tabs(
    im: Image.Image, dr: ImageDraw.ImageDraw, skin: Skin, font: Font, tabs: list, sel: int
) -> None:
    """The tab row: the background has the band but no names, so the firmware's own button is
    repeated and the tab name from the IFR is drawn on it."""
    geo, col = skin.geo, skin.col
    x, y = geo["tabs"]
    h = geo["tabh"]
    _fx0, _fy0, fx1, _fy1 = geo["frame"]
    names = [n for n, _ in tabs]
    textw = [dr.textlength(n, font=font) for n in names]
    widths = [max(96.0, tw + 24) for tw in textw]
    avail = fx1 - x - 4 - 2 * (len(names) - 1)
    total = sum(widths)
    if total > avail:
        shrink = (total - avail) / len(names)
        widths = [max(w - shrink, tw + 10) for w, tw in zip(widths, textw)]
    for k, name in enumerate(names):
        w = int(widths[k])
        art = skin.tabsel if (k == sel and skin.tabsel is not None) else skin.tab
        if art is not None:
            tile = art.resize((max(w, 1), h))
            im.paste(tile, (x, y), tile)
        elif k == sel:
            dr.rectangle((x, y, x + w, y + h), fill=col["sel"])
        else:
            dr.rectangle((x, y, x + w, y + h), fill=(22, 24, 28))
        if k == sel and skin.tabsel is None:
            # A1 has one button picture per tab and no separate selected state, so the selected
            # tab is marked with a bar of the accent along its bottom edge
            dr.rectangle((x, y + h - 4, x + w, y + h - 1), fill=col["sel"])
        tw = dr.textlength(name, font=font)
        on = k == sel
        dr.text(
            (x + (w - tw) / 2, y + (h - getattr(font, "size", 11)) / 2 + 2),
            name,
            font=font,
            fill=col["seltext"] if on else col["tabtext"],
        )
        x += w + 2


def _draw_page(
    skin: Skin,
    fonts: dict,
    tabs: list,
    tab: int,
    title: str,
    rows: list,
    n: int,
    total: int,
    help_text: str,
    copyright_: str,
) -> Image.Image:
    geo, col = skin.geo, skin.col
    if skin.bg is not None:
        im = skin.bg.copy()
    else:
        im = Image.new("RGBA", (1024, 768), (0, 0, 0, 255))
    dr = ImageDraw.Draw(im)
    _fx0, _fy0, fx1, fy1 = geo["frame"]
    ix0, iy0, ix1, _iy1 = geo["items"]
    hx0, hy0, hx1, hy1 = geo["help"]

    if skin.banner is not None:
        im.paste(skin.banner, geo["bannerxy"], skin.banner)
        dr = ImageDraw.Draw(im)
    if skin.panel is not None:
        im.paste(skin.panel, geo["panelxy"], skin.panel)
        dr = ImageDraw.Draw(im)
    if skin.legend is not None and geo.get("legendxy") is not None:
        im.paste(skin.legend, geo["legendxy"], skin.legend)
        dr = ImageDraw.Draw(im)

    _draw_tabs(im, dr, skin, fonts["tab"], tabs, tab)

    # the page title heads the help panel (above the frame it ran into the setup's name that
    # the A2/A3 backgrounds print there); a deep sub-menu title is shortened from the front
    while dr.textlength(title, font=fonts["title"]) > (hx1 - hx0) * 2 and " > " in title:
        title = "... > " + title.removeprefix("... > ").split(" > ", 1)[1]
    for line in A._wrap(title, fonts["title"], dr, hx1 - hx0):
        # (on a light panel, A3's, in the dark help colour)
        fill = col["head"] if A._lum(col["help"]) > 128 else col["help"]
        dr.text((hx0, hy0), line, font=fonts["title"], fill=fill)
        hy0 += geo["ftitle"] + 6
    hy0 += 8

    # the rows: the bar of the highlighted row first (the firmware's own bar picture when the
    # generation has one), then all the text on top. The highlighted row is the first selectable
    # one on the page, as in uefi_setup._render.
    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y, ys = iy0, []
    for i, r in enumerate(rows):
        ys.append(y)
        if i == sel:
            if skin.selbar is not None:
                bar = skin.selbar.resize((ix1 + 12 - ix0 + 16, geo["rowh"]))
                im.paste(bar, (ix0 - 16, y), bar)
                dr = ImageDraw.Draw(im)
            else:
                dr.rectangle((ix0 - 16, y, ix1 + 10, y + geo["rowh"] - 2), fill=col["sel"])
        y += r.h
    for i, r in enumerate(rows):
        at = ys[i]
        on = i == sel
        seltext = (255, 255, 255) if skin.selbar is not None else col["seltext"]
        text = seltext if on else col["item"]
        if r.kind == "head":
            dr.text((ix0, at + 3), r.prompt, font=fonts["head"], fill=col["head"])
            if r.value:  # (the system-information lines of the Main page carry a run-time value)
                vw = dr.textlength(r.value, font=fonts["value"])
                dr.text((ix1 - vw, at + 3), r.value, font=fonts["value"], fill=col["value"])
        elif r.kind == "sep":
            dr.line((ix0, at + 6, ix1, at + 6), fill=col["line"])
        else:
            if r.kind == "ref":
                dr.polygon([(ix0 - 12, at + 5), (ix0 - 12, at + 17), (ix0 - 3, at + 11)], fill=text)
            dr.text((ix0, at + 3), r.prompt, font=fonts["item"], fill=text)
            if r.value:
                vw = dr.textlength(r.value, font=fonts["value"])
                dr.text(
                    (ix1 - vw, at + 3),
                    r.value,
                    font=fonts["value"],
                    fill=seltext if on else col["value"],
                )

    if help_text:
        for i, line in enumerate(A._wrap(help_text, fonts["help"], dr, hx1 - hx0)):
            if hy0 + i * (geo["fhelp"] + 4) > hy1:
                break
            dr.text((hx0, hy0 + i * (geo["fhelp"] + 4)), line, font=fonts["help"], fill=col["help"])
    if copyright_:
        dr.text(
            ((im.width - dr.textlength(copyright_, font=fonts["foot"])) / 2, geo["foot"][1] + 2),
            copyright_,
            font=fonts["foot"],
            fill=col["foot"],
        )
    if total > 1:
        mark = f"{n}/{total}"
        dr.text(
            (fx1 - dr.textlength(mark, font=fonts["foot"]) - 4, fy1 - 18),
            mark,
            font=fonts["foot"],
            fill=col["foot"],
        )
    return im.convert("RGB")


def pages(rom: bytes) -> list[tuple[str, Image.Image, str]]:
    """[(title, picture, text)] for every screen of an ASRock A1/A2/A3 setup, in the order and
    with the titles uefi_setup.UefiSetup.screens() gives (a continued form: "Title (2/3)");
    [] when the image is not one of those."""
    secs = picture_sections(rom)
    gen = _generation_of(pictures_of(secs))
    if gen not in ("A1", "A2", "A3"):
        return []
    su = U.UefiSetup(rom)
    skin = Skin(secs, gen)
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in A._page_list(su):
        rows = rows_of(su, su.forms[form_id][1], geo)
        chunks = A._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            help_text = A._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page(
                skin, fonts, su.tabs, tab, name, chunk, n, len(chunks), help_text, su.copyright
            )
            out.append((name, image, A._text(name, chunk, help_text)))
    return out
