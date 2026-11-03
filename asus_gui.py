"""
Setup screens of ASUS UEFI firmware, drawn in the setup's own Advanced Mode look.

generation(rom) names the ASUS setup look of a flash image ("G2", "G3", "G4", "G5", or None for
firmware that is not one of them); pages(rom) draws every screen that uefi_setup.UefiSetup
.screens() would produce for the same image, in the same order and with the same titles, as
1024x768 pictures:

- the background, the frame and the help-box divider are the firmware's own pictures: the
  1024x768 Advanced-Mode background is the record with id 101h of the freeform FFS file
  3D9D911C-... (a PNG on G3/G4, a JPEG on G2), and its id 13Eh picture (418x150, the F3/hand/
  mouse drawing) goes into the help box on G3;
- on G5 (2014-15: X99-A, H97I-PLUS, Crossblade Ranger) all setup graphics are in the freeform
  module CC5840D2 and the page is built from four of them: id 4000h (the 1024x768 background with
  the cyan circuit traces), id 1h (the translucent page plate: the list column and the narrow
  right column), id 2h (the 836x466 list area) and id 10Ah (the 836x26 tab-row strip); id 5h is
  the drawn title "UEFI BIOS Utility - Advanced Mode" and id 4h the ASUS logo, and the tab buttons
  are the 188x25 gradient bars of ids 100h (plain) and 101h (cyan);
- the content of the screens is the IFR: one row per question (prompt left, its default value
  right), SUBTITLE as a section heading (an empty one as a separator line), a sub-menu link
  marked with a triangle, and the first selectable item's help text word-wrapped in the help box;
- values the setup only knows at run time (TEXT questions: BIOS version, CPU speed, memory size)
  show the firmware's own placeholder "N/A".

The picture containers are a chain of records inside one raw/freeform section per module:
UINT32 byte count | UINT32 header length (20h or 24h) | ... | UINT16 picture id | ... | the
picture bytes, records 4-byte aligned, a count of 0 an empty slot. On G2 the id field is FFFFh
for every widget but the first three, so those widgets are addressed by their index in the
module. Nothing in the image gives a screen position: the frame and divider below were measured
off the background picture (work/asg7.py, asg8.py), the rest of the layout is this module's own
choice.
"""

from __future__ import annotations

import io
import os
import struct
import uuid
from typing import Any, Optional, Union

from PIL import Image, ImageChops, ImageDraw, ImageFont

import tiano
import uefi_setup as U

MAX_DEPTH = 7
# the freeform FFS files that hold the setup's pictures (by the first block of their GUID)
PIC_MODULES = ("4B13CE01", "3D9D911C", "0E0DB566", "3DCE5A33", "CC5840D2")
BG_ID = 0x101  # the 1024x768 Advanced-Mode background, in 3D9D911C, on all three generations
HINT_ID = 0x13E  # the 418x150 hint drawing: G3 and G4 only
ROG_ID0, ROG_ID1 = 0x210, 0x220  # the 174x40 Republic of Gamers banner: G4 only
# the G5 pictures, all of them in module CC5840D2
G5_BG, G5_PANEL, G5_LIST, G5_STRIP = 0x4000, 0x0001, 0x0002, 0x010A
G5_TITLE, G5_LOGO = 0x0005, 0x0004  # "UEFI BIOS Utility - Advanced Mode", the ASUS logo
G5_TAB, G5_TABSEL = 0x0100, 0x0101  # the 188x25 tab bars: plain and cyan
FONTS = ("arialbd.ttf", "arial.ttf", "segoeui.ttf", "tahoma.ttf")
NA = "N/A"

# measured off the firmware's own background picture (asg7.py / asg8.py): the outer frame, the
# item column and the help box, as (x0, y0, x1, y1)
TITLE_WIDTH = 470  # room for the page title right of the painted setup name

Font = Union[ImageFont.FreeTypeFont, ImageFont.ImageFont]

GEO: dict[str, dict[str, Any]] = {
    "G3": {
        "frame": (21, 46, 1005, 689),
        "items": (40, 100, 660, 680),
        "tabs": (24, 56),
        "help": (700, 92, 1000, 415),
        "hintbox": (688, 421, 1004, 688),
        "foot": (21, 695, 1004, 760),
        "pitch": 26,
        "rowh": 24,
        "fsel": 19,
        "fhead": 20,
        "ftab": 17,
        "ftitle": 19,
        "fhelp": 16,
    },
    "G4": {
        "frame": (22, 46, 1005, 688),
        "items": (40, 100, 660, 680),
        "tabs": (24, 56),
        "help": (700, 92, 1000, 415),
        "hintbox": (688, 421, 1004, 688),
        "foot": (22, 694, 1004, 760),
        "pitch": 26,
        "rowh": 24,
        "fsel": 19,
        "fhead": 20,
        "ftab": 17,
        "ftitle": 19,
        "fhelp": 16,
    },
    "G2": {
        "frame": (8, 122, 1015, 740),
        "items": (24, 160, 660, 726),
        "tabs": (16, 88),
        "help": (712, 490, 1010, 726),
        "hintbox": None,
        "foot": (8, 744, 1015, 764),
        "pitch": 24,
        "rowh": 22,
        "fsel": 17,
        "fhead": 18,
        "ftab": 16,
        "ftitle": 17,
        "fhelp": 15,
    },
    "G5": {
        # measured off the firmware's own pictures (work/g5d.py, work/g5e.py): the plate of id 1h
        # covers y 96-701 and is split into a list column x 0-836 and a right column x 844-1023;
        # inside the list column the 836x466 list area (id 2h) sits at y 126-591 and the 836x26
        # tab strip (id 10Ah) at y 96-124, so the help band is the plate's y 599-701
        "frame": (0, 96, 1023, 701),
        "items": (16, 132, 820, 591),
        "tabs": (0, 97),
        "help": (16, 604, 820, 698),
        "hintbox": None,
        "foot": (0, 705, 1023, 764),
        "pitch": 25,
        "rowh": 23,
        "fsel": 18,
        "fhead": 19,
        "ftab": 16,
        "ftitle": 19,
        "fhelp": 15,
        # where the firmware's own layers are pasted, and how wide the tab row is
        "panelxy": (0, 0),
        "listxy": (0, 126),
        "strixy": (0, 96),
        "titlexy": (14, 62),
        "logoxy": (14, 14),
        "stripw": 836,
        "titlepad": 8,  # the plate reaches the right screen edge, the title needs a little air
    },
}
# the text colours; the ones for G2 are sampled from its own background (asg10.py: the item
# panel is #54707B, the surround #263437), the G3/G4 ones are the blue ramp of the mock-up
COLOURS: dict[str, dict[str, Any]] = {
    "G3": {
        "head": (120, 190, 240),
        "item": (235, 235, 235),
        "value": (255, 255, 255),
        "sel": (0, 92, 168),
        "seltext": (255, 255, 255),
        "tab": (190, 190, 190),
        "tabtext": (255, 255, 255),
        "tabfill": (0, 92, 168),
        "line": (70, 70, 70),
        "help": (210, 210, 210),
        "title": (255, 255, 255),
        "foot": (150, 150, 150),
    },
    "G4": {
        "head": (240, 90, 90),
        "item": (235, 235, 235),
        "value": (255, 255, 255),
        "sel": (140, 0, 0),
        "seltext": (255, 255, 255),
        "tab": (190, 190, 190),
        "tabtext": (255, 255, 255),
        "tabfill": (140, 0, 0),
        "line": (70, 70, 70),
        "help": (210, 210, 210),
        "title": (255, 255, 255),
        "foot": (150, 150, 150),
    },
    "G2": {
        "head": (245, 250, 250),
        "item": (16, 26, 29),
        "value": (12, 20, 23),
        "sel": (38, 52, 55),
        "seltext": (245, 250, 250),
        "tab": (200, 215, 220),
        "tabtext": (16, 26, 29),
        "tabfill": (200, 215, 220),
        "line": (38, 52, 55),
        "help": (225, 235, 238),
        "title": (235, 242, 245),
        "foot": (190, 205, 210),
    },
    # the cyan of the firmware's own tab bar (18BAC8h in id 101h) is the accent of this look; the
    # rest follows the plate (#232323 at alpha 128 over the black background)
    "G5": {
        "head": (24, 186, 200),
        "item": (235, 235, 235),
        "value": (255, 255, 255),
        "sel": (24, 186, 200),
        "seltext": (10, 16, 18),
        "tab": (205, 205, 205),
        "tabtext": (10, 16, 18),
        "tabfill": (24, 186, 200),
        "line": (60, 60, 60),
        "help": (200, 200, 200),
        "title": (255, 255, 255),
        "foot": (150, 150, 150),
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
    if guid in PIC_MODULES:
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


# --- the picture records of one container ----------------------------------------------------


class Pic:
    __slots__ = ("index", "pid", "lang", "hdr", "off", "size", "kind", "w", "h")

    def __init__(
        self,
        index: int,
        pid: int,
        lang: int,
        hdr: int,
        off: int,
        size: int,
        kind: str,
        w: int,
        h: int,
    ) -> None:
        self.index, self.pid, self.lang, self.hdr = index, pid, lang, hdr
        self.off, self.size, self.kind, self.w, self.h = off, size, kind, w, h


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


def chain(data: bytes) -> list[Pic]:
    """The picture records of one container section, in order (empty slots skipped)."""
    out: list[Pic] = []
    p = 0
    while p + 8 <= len(data):
        size, hdr = struct.unpack_from("<II", data, p)
        if hdr not in (0x20, 0x24) or size > len(data) - p - hdr:
            break
        if size:
            kind = _kind(data, p + hdr)
            if kind:
                pid = struct.unpack_from("<H", data, p + (0x0E if hdr == 0x20 else 0x10))[0]
                lang = struct.unpack_from("<H", data, p + (0x16 if hdr == 0x20 else 0x1A))[0]
                w, h = _dims(data, p + hdr, kind)
                out.append(Pic(len(out), pid, lang, hdr, p + hdr, size, kind, w, h))
        p = (p + hdr + size + 3) & ~3
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
    if "CC5840D2" in mods:
        return "G5"
    adv = mods.get("3D9D911C")
    if not adv:
        return None
    if any(p.w == 174 and p.h == 40 and ROG_ID0 <= p.pid <= ROG_ID1 for p in adv):
        return "G4"
    if any(p.pid == HINT_ID for p in adv):
        return "G3"
    return "G2"


def generation(rom: bytes) -> Optional[str]:
    """ "G2", "G3", "G4" or "G5" for an ASUS setup of that look, None for anything else."""
    return _generation_of(pictures(rom))


# --- drawing ---------------------------------------------------------------------------------


def _font(name: str, size: int) -> Font:
    """A font that ships with Windows; PIL's built-in font when there is none."""
    for cand in (name, "arial.ttf", "segoeui.ttf", "tahoma.ttf"):
        path = os.path.join("C:/Windows/Fonts", cand)
        if cand and os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                pass
    return ImageFont.load_default(size=size)


def _lum(c: tuple[int, int, int]) -> int:
    return (299 * c[0] + 587 * c[1] + 114 * c[2]) // 1000


def _accent(im: Image.Image) -> Optional[tuple[int, int, int]]:
    """The accent of one of the firmware's own pictures: the brightest of its common saturated
    colours (cyan on X99-A / H97I-PLUS, red on the ROG boards)."""
    pal = im.convert("RGB").getcolors(8192)
    if not pal:
        return None
    rgb = [((c[0], c[1], c[2]), n) for n, c in pal if isinstance(c, tuple)]
    sat = [(c, n) for c, n in rgb if max(c) - min(c) >= 60 and max(c) >= 60]
    if not sat:
        return None
    top = max(n for _c, n in sat)
    return max((c for c, n in sat if n >= top // 4), key=_lum)


def _keyed(im: Image.Image) -> Image.Image:
    """Flat magenta in these pictures is the setup's transparency key."""
    im = im.convert("RGBA")
    r, g, b, _a = im.split()
    key = ImageChops.multiply(
        ImageChops.multiply(
            r.point(lambda v: 255 if v > 200 else 0), g.point(lambda v: 255 if v < 60 else 0)
        ),
        b.point(lambda v: 255 if v > 200 else 0),
    )
    return Image.composite(Image.new("RGBA", im.size, (0, 0, 0, 0)), im, key)


def _load(data: bytes, pic: Pic) -> Optional[Image.Image]:
    try:
        return Image.open(io.BytesIO(data[pic.off : pic.off + pic.size]))
    except (OSError, ValueError):
        return None


class Skin:
    """The firmware's own chrome for one generation: background, hint graphic, geometry."""

    def __init__(self, secs: dict[str, list[bytes]], gen: str) -> None:
        self.gen = gen
        self.geo = GEO[gen]
        self.col = COLOURS[gen]
        self.bg: Optional[Image.Image] = None
        self.hint: Optional[Image.Image] = None
        self.rog: Optional[Image.Image] = None
        # the G5 layers: the page plate, the list area, the tab-row strip, the drawn title and
        # logo, and the two states of the tab button
        self.panel: Optional[Image.Image] = None
        self.listarea: Optional[Image.Image] = None
        self.strip: Optional[Image.Image] = None
        self.title: Optional[Image.Image] = None
        self.logo: Optional[Image.Image] = None
        self.tab: Optional[Image.Image] = None
        self.tabsel: Optional[Image.Image] = None
        if gen == "G5":
            want = {
                G5_BG: "bg",
                G5_PANEL: "panel",
                G5_LIST: "listarea",
                G5_STRIP: "strip",
                G5_TITLE: "title",
                G5_LOGO: "logo",
                G5_TAB: "tab",
                G5_TABSEL: "tabsel",
            }
            for s in secs.get("CC5840D2", ()):
                for p in chain(s):
                    which = want.get(p.pid)
                    if which is None or getattr(self, which) is not None:
                        continue
                    im = _load(s, p)
                    if im is not None:
                        setattr(self, which, im.convert("RGBA"))
            # the accent of the headings, of the highlighted row and of the selected tab is the
            # colour of the firmware's own selected-tab bar, which differs by board
            if self.tabsel is not None:
                accent = _accent(self.tabsel)
                if accent is not None:
                    self.col = dict(self.col)
                    self.col["head"] = self.col["sel"] = self.col["tabfill"] = accent
                    on = (255, 255, 255) if _lum(accent) < 140 else (10, 16, 18)
                    self.col["seltext"] = self.col["tabtext"] = on
        for s in secs.get("3D9D911C", ()):
            for p in chain(s):
                if self.bg is None and p.pid == BG_ID and p.w == 1024:
                    im = _load(s, p)
                    if im is not None:
                        self.bg = im.convert("RGBA")
                elif self.hint is None and p.pid == HINT_ID:
                    im = _load(s, p)
                    if im is not None:
                        self.hint = _keyed(im)
                elif self.rog is None and p.w == 174 and p.h == 40 and ROG_ID0 <= p.pid <= ROG_ID1:
                    im = _load(s, p)
                    if im is not None:
                        self.rog = _keyed(im)

    def fonts(self) -> dict[str, Font]:
        g = self.geo
        return {
            "head": _font(FONTS[0], g["fhead"]),
            "item": _font(FONTS[1], g["fsel"]),
            "value": _font(FONTS[1], g["fsel"]),
            "tab": _font(FONTS[1], g["ftab"]),
            "title": _font(FONTS[0], g["ftitle"]),
            "help": _font(FONTS[1], g["fhelp"]),
            "foot": _font(FONTS[1], max(g["fhelp"] - 2, 11)),
        }


class Row:
    """One drawn line of a screen: heading, separator, item, sub-menu link or action.

    `sel` marks the rows the setup can actually land on: a TEXT question (run-time information)
    and a SUBTITLE are shown but not selectable, so they get neither the bar nor the help text.
    """

    __slots__ = ("kind", "prompt", "value", "help", "h", "sel")

    def __init__(self, kind: str, prompt: str, value: str, help_: int, h: int, sel: bool) -> None:
        self.kind, self.prompt, self.value = kind, prompt, value
        self.help, self.h, self.sel = help_, h, sel


def _clean(text: str) -> str:
    # (the strings keep printf's escaped percent sign: "100%%" is shown as "100%")
    return " ".join(text.split()).replace("%%", "%")


def rows_of(su: U.UefiSetup, items: list, geo: dict) -> list[Row]:
    """The IFR items of one form as drawable rows (the same items, in the same order, that
    UefiSetup._render writes into its text screen)."""
    rowh = geo["rowh"]
    out: list[Row] = []
    for it in items:
        kind = it["kind"]
        prompt = _clean(su.str(it.get("prompt")))
        if kind == "subtitle":
            if prompt:
                out.append(Row("head", prompt, "", it.get("help") or 0, rowh + 6, False))
            else:
                out.append(Row("sep", "", "", 0, 12, False))
            continue
        if kind == "text":
            # a TEXT question with no prompt is a bare value line: the text renderer keeps it, so
            # we keep it too (m5a97-evo2 has one, under Ai Tweaker)
            value = _clean(su.str(it.get("text2"))) or NA
            out.append(Row("item", prompt, value, it.get("help") or 0, rowh, False))
            continue
        if kind in ("ref", "action"):
            if not prompt:
                continue  # (a link with no name: the text renderer leaves it out too)
            out.append(Row(kind, prompt, "", it.get("help") or 0, rowh, True))
            continue
        value = _clean(su._value_text(it))
        if not prompt and out and out[-1].kind == "item" and out[-1].prompt and not out[-1].value:
            # a question with no prompt after a STRING that names it (ASUS: the current value
            # read at run time, then the setting): the setup shows both on one line
            last = out[-1]
            out[-1] = Row("item", last.prompt, value, last.help or it.get("help") or 0, rowh, True)
            continue
        out.append(Row("item", prompt, value, it.get("help") or 0, rowh, True))
    return out


def _wrap(text: str, font: Font, dr: ImageDraw.ImageDraw, width: int) -> list[str]:
    out: list[str] = []
    for para in text.split("\n"):
        line = ""
        for word in para.split():
            trial = f"{line} {word}".strip()
            if line and dr.textlength(trial, font=font) > width:
                out.append(line)
                line = word
            else:
                line = trial
        out.append(line)
    return out


def _page_list(su: U.UefiSetup) -> list[tuple[str, int, int, int]]:
    """(title, tab index, form id, depth) in the order and with the titles and the depth that
    UefiSetup.screens() uses; depth == 0 is a tab's own form, which is the only case where the
    setup shows the whole tab strip."""
    out: list[tuple[str, int, int, int]] = []
    seen: set[int] = set()

    def add(tab: int, title: str, form_id: int, depth: int) -> None:
        if form_id in seen or form_id not in su.forms:
            return
        seen.add(form_id)
        out.append((title, tab, form_id, depth))
        if depth < U.MAX_SUB_DEPTH:
            for it in su.forms[form_id][1]:
                name = U.link_name(_clean(su.str(it.get("prompt"))))
                if it["kind"] == "ref" and "formset" not in it and name:
                    add(tab, f"{title} > {name}", it.get("form"), depth + 1)

    for k, (name, form_id) in enumerate(su.tabs):
        add(k, name or f"Tab {k + 1}", form_id, 0)
    return out


def _draw_tabs(
    im: Image.Image,
    dr: ImageDraw.ImageDraw,
    skin: Skin,
    font: Font,
    tabs: list[tuple[str, int]],
    sel: int,
) -> None:
    """The tab strip: the firmware's background has no tabs painted in it, so this is drawn.
    The graphical setup keeps the whole strip inside sub-menus, the parent tab highlighted. (The
    188x25 bars 100h-109h of G5 are its Enabled/Disabled switches, not tabs: they only give the
    accent colour.)"""
    geo, col = skin.geo, skin.col
    x, y = geo["tabs"]
    _fx0, _fy0, fx1, _fy1 = geo["frame"]
    names = [n for n, _ in tabs]
    art = skin.tab is not None and skin.tabsel is not None
    gap = 2 if art else 4
    textw = [dr.textlength(n, font=font) for n in names]
    widths = [max(96 if art else 112, tw + 26) for tw in textw]
    if art:
        # G5: the tabs share the width of the firmware's own tab-row picture, and a tab is never
        # narrower than its own name plus a little air
        avail = int(geo.get("stripw", 0)) or (fx1 - x - 4)
        avail -= gap * (len(names) - 1)
        total = sum(widths)
        if total < avail:
            widths = [w + (avail - total) / len(names) for w in widths]
        else:
            shrink = (total - avail) / len(names)
            widths = [max(w - shrink, tw + 10) for w, tw in zip(widths, textw)]
        scale = 1.0
    else:
        scale = min(1.0, (fx1 - x - 4) / sum(widths))
    for k, name in enumerate(names):
        w = int(widths[k] * scale)
        dr.rounded_rectangle(
            (x, y, x + w, y + 26), 5, fill=col["tabfill"] if k == sel else col["line"]
        )
        tw = dr.textlength(name, font=font)
        dr.text(
            (x + (w - tw) / 2, y + 5),
            name,
            font=font,
            fill=col["tabtext"] if k == sel else col["tab"],
        )
        x += w + gap


def _draw_page(
    skin: Skin,
    fonts: dict,
    tabs: list[tuple[str, int]],
    tab: int,
    title: str,
    rows: list[Row],
    n: int,
    total: int,
    help_text: str,
    copyright_: str,
) -> Image.Image:
    geo, col = skin.geo, skin.col
    im = skin.bg.copy() if skin.bg is not None else Image.new("RGBA", (1024, 768), (0, 0, 0, 255))
    dr = ImageDraw.Draw(im)
    fx0, fy0, fx1, fy1 = geo["frame"]
    ix0, iy0, ix1, _iy1 = geo["items"]
    hx0, hy0, hx1, hy1 = geo["help"]

    if skin.gen == "G5":
        # the page plate, the list area and the tab-row strip go under everything else, and the
        # firmware's own logo and "UEFI BIOS Utility - Advanced Mode" drawing into the band above
        # the frame (the page title is drawn at the right of that same band below)
        for which, at in (
            ("panel", geo["panelxy"]),
            ("listarea", geo["listxy"]),
            ("strip", geo["strixy"]),
            ("logo", geo["logoxy"]),
            ("title", geo["titlexy"]),
        ):
            layer = getattr(skin, which)
            if layer is not None:
                im.paste(layer, at, layer)
        dr = ImageDraw.Draw(im)

    _draw_tabs(im, dr, skin, fonts["tab"], tabs, tab)
    if skin.rog is not None:  # the ROG banner: on G4 the background has no logo painted in
        im.paste(skin.rog, (fx0 - 14, 2), skin.rog)
        dr = ImageDraw.Draw(im)
    # the page title goes at the right of the band above the frame: the background already has
    # "UEFI BIOS Utility - Advanced Mode" painted at its left
    # (a deep sub-menu: its leading menus are left out so the title does not run into that)
    while dr.textlength(title, font=fonts["title"]) > TITLE_WIDTH and " > " in title:
        title = "... > " + title.removeprefix("... > ").split(" > ", 1)[1]
    tw = dr.textlength(title, font=fonts["title"])
    dr.text(
        (fx1 - tw - int(geo.get("titlepad", 0)), fy0 - geo["ftitle"] - 12),
        title,
        font=fonts["title"],
        fill=col["title"],
    )

    # the rows of this page: the bar of the highlighted row first, then all the text on top. The
    # highlighted row is the first selectable one on the page, as the text renderer's `first`.
    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y, ys = iy0, []
    for i, r in enumerate(rows):
        ys.append(y)
        if i == sel:
            dr.rectangle((ix0 - 16, y, ix1 + 10, y + geo["rowh"] - 2), fill=col["sel"])
        y += r.h
    for i, r in enumerate(rows):
        at = ys[i]
        on = i == sel
        text = col["seltext"] if on else col["item"]
        if r.kind == "head":
            dr.text((ix0, at + 3), r.prompt, font=fonts["head"], fill=col["head"])
        elif r.kind == "sep":
            dr.line((ix0, at + 6, ix1, at + 6), fill=col["line"])
        else:
            if r.kind == "ref":  # a sub-menu: the setup marks it with a triangle
                dr.polygon([(ix0 - 12, at + 5), (ix0 - 12, at + 17), (ix0 - 3, at + 11)], fill=text)
            dr.text((ix0, at + 3), r.prompt, font=fonts["item"], fill=text)
            if r.value:
                vw = dr.textlength(r.value, font=fonts["value"])
                dr.text(
                    (ix1 - vw, at + 3),
                    r.value,
                    font=fonts["value"],
                    fill=col["seltext"] if on else col["value"],
                )

    # the help box: the highlighted item's help text, and the firmware's own hint drawing
    if help_text:
        for i, line in enumerate(_wrap(help_text, fonts["help"], dr, hx1 - hx0)):
            if hy0 + i * (geo["fhelp"] + 4) > hy1:
                break
            dr.text((hx0, hy0 + i * (geo["fhelp"] + 4)), line, font=fonts["help"], fill=col["help"])
    if skin.hint is not None and geo["hintbox"] is not None:
        bx0, by0, bx1, by1 = geo["hintbox"]
        w = bx1 - bx0
        h = int(skin.hint.height * w / skin.hint.width)
        if h > by1 - by0:
            h = by1 - by0
            w = int(skin.hint.width * h / skin.hint.height)
        hint = skin.hint.resize((max(w, 1), max(h, 1)))
        im.paste(hint, (bx0 + (bx1 - bx0 - w) // 2, by1 - h), hint)
        dr = ImageDraw.Draw(im)
    if copyright_:
        dr.text(
            ((1024 - dr.textlength(copyright_, font=fonts["foot"])) / 2, geo["foot"][1] + 4),
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


def _split(rows: list[Row], height: int) -> list[list[Row]]:
    """Rows into pages of at most `height` pixels (headings and separators stay with their row)."""
    chunks: list[list[Row]] = []
    cur: list[Row] = []
    used = 0
    for r in rows:
        if used + r.h > height and cur:
            chunks.append(cur)
            cur, used = [], 0
        cur.append(r)
        used += r.h
    if cur:
        chunks.append(cur)
    return chunks or [[]]


def _text(title: str, rows: list[Row], help_text: str) -> str:
    """The page as plain text (what the picture shows): title, rows, help."""
    lines = [title, ""]
    for r in rows:
        if r.kind == "sep":
            lines.append("")
        elif r.kind == "head":
            lines.append(r.prompt)
        else:
            prompt = ("> " if r.kind == "ref" else "  ") + r.prompt
            lines.append(f"{prompt:<40} {r.value}".rstrip())
    if help_text:
        lines += ["", f"Help: {help_text}"]
    return "\n".join(lines)


def pages(rom: bytes) -> list[tuple[str, Image.Image, str]]:
    """[(title, picture, text)] for every screen of an ASUS G2/G3/G4/G5 setup, in the order and
    with the titles uefi_setup.UefiSetup.screens() gives (a continued form: "Title (2/3)");
    [] when the image is not one of those."""
    secs = picture_sections(rom)
    gen = _generation_of(pictures_of(secs))
    if gen not in ("G2", "G3", "G4", "G5"):
        return []
    su = U.UefiSetup(rom)
    skin = Skin(secs, gen)
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in _page_list(su):
        rows = rows_of(su, su.forms[form_id][1], geo)
        chunks = _split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            # the help box holds the help of the first selectable item of this page, as in _render
            help_text = _clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page(
                skin, fonts, su.tabs, tab, name, chunk, n, len(chunks), help_text, su.copyright
            )
            out.append((name, image, _text(name, chunk, help_text)))
    return out
