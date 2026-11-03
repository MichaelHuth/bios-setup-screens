"""
Setup screens of MSI Click BIOS firmware, drawn in the setup's own look. Three looks are drawn:

- "C4", Click BIOS 4 of 2014-15 (Z87-G45 GAMING, B85M GAMING, B85M-E45): the page background, the
  top status band, the menu column panel and the menu tiles are the firmware's own pictures, all of
  them in one raw FFS file (374CC63D-...) behind MSI's own container: "$MsI$!\0", then for every
  picture a UINT16 index counting from 1, a UINT32 length and the picture (JPEG for all 33 of them),
  the chain running to the end of the section. The container holds the 1024x768 background with the
  silver dragon, "GAMING MOTHERBOARD", the Gaming G Series shield and the msi logo; the 1024x224
  band above the page, which prints "Click BIOS 4", the msi logo, the F1 help mark, and the labels
  "Temperature", "CPU", "Motherboard System" and "<<< Boot device priority >>>"; the 212x542 panel
  behind the menu column, with its up and down scroll arrows; and the six menu tiles 212x178 in a
  plain and a highlighted state, with their names and captions printed in the picture: SETTINGS, OC,
  OC PROFILE, HARDWARE MONITOR, BOARD EXPLORER, M-FLASH.
- "C5", Click BIOS 5 of 2018-19 (X99A GODLIKE GAMING, X99A GODLIKE GAMING CARBON): the same
  container form, but the skin is split over fourteen of them. 374CC63D holds the 1024x253 band
  printed "msi CLICK BIOS 5" (two variants: one with GAME BOOST and XMP boxes, one with CPU Temp and
  Motherboard Temp), the 210x514 help panel at the right of the page, the seven menu tiles 210x170
  in a plain and a lit state (SETTINGS, OC, OC PROFILE, HARDWARE MONITOR, BOARD EXPLORER, M-FLASH,
  SYSTEM EXPLORER) and the 94x28 tabs of the help panel; E0E30C98 the 45x40 digits of the band's
  clock. The page background is not in a container: it is a bare one-picture FFS file
  (A44E52DE), a 1024x768 JPEG of the red dragon with "NO. 1 IN GAMING" printed in it.
- "C2", Click BIOS II of 2013-16 (970A-G43, Z77A-G45 Thunderbolt): no container at all - every
  picture is a bare FFS file of its own, one picture from the first byte of its section, which is
  the form asrock_gui reads. AFD94715 is the whole page frame (the blue swoosh with the msi logo,
  the F12 mark, "Temperature / CPU / Mainboard System", the "Boot device priority >>" box, two
  hatched tabs and the dark content box at x 221-803, y 287-763); A91052B5 is the 583x477 splash
  printed "CLICK BIOS II - Efficient, Flexible, Intelligent", which is exactly the size of that
  content box and names the look; the buttons above the box and the Language and X buttons are
  files of their own; the six menu tiles 212x157 are 24 files, four states each, with
  their names and captions printed in them (SETTINGS "Mainboard settings", OC "Overclocking
  setting", ECO "Energy saving", BROWSER "Internet Message and Mail", UTILITIES "Live Update
  M-Flash", SECURITY "Password").

generation(rom) names the look of a flash image ("C4", "C5", "C2", or None for firmware that is not
one of them); pages(rom) draws every screen that uefi_setup.UefiSetup.screens() would give for the
same image, in the same order and with the same titles, as 1024x768 pictures.

In every look the values the band leaves open (the temperatures, the clock, the boot device icons,
the OC Genie lamp) are run-time information the image does not hold, so they are left empty. The
content of the screens is the IFR, exactly as asus_gui draws it: one row per question (prompt left,
its default value right), SUBTITLE as a section heading, a sub-menu link marked with a triangle, the
first selectable item's help word-wrapped in the help box, and "N/A" for the values the setup only
knows at run time.

The Click BIOS 4 skin has no picture of an item row, of a help panel or of a selection bar: the
setup draws those itself. Their place follows two measured anchors of the firmware's own art (the
band ends at y 224, the menu panel is 212 px wide and 542 px tall and holds three 212x178 tiles) and
the areas the board manual names for this setup ("BIOS menu selection", "Menu display"); the row
pitch, the fonts and the help box are this module's own choice. Where Click BIOS 5 and II place
their parts follows screenshots of the real setups in PC Perspective's reviews (Z170A XPower Gaming
Titanium, Z77A-GD80): Click BIOS 5 has three tiles on the left, the item list in the middle and the
help panel on the right; Click BIOS II three tiles on either side of the content box. The row pitch
and the fonts are this module's own choice, and the X99A boards' setups were not seen themselves.
"""

from __future__ import annotations

import struct
from typing import Any, Optional, Union

from PIL import Image, ImageDraw, ImageFont

import asrock_gui as R
import asus_gui as A
import tiano
import uefi_setup as U

NA = "N/A"
Font = Union[ImageFont.FreeTypeFont, ImageFont.ImageFont]

# the module that holds the whole Click BIOS 4 skin (GUID prefix = the FFS file name)
SKIN = "374CC63D"
BAND_W, BAND_H = 1024, 224  # the printed top band
BG_W, BG_H = 1024, 768  # the page background
PANEL_W, PANEL_H = 212, 542  # the panel behind the menu column
TILE_W, TILE_H = 212, 178  # one menu tile
TILE_NAMES = (
    "SETTINGS",
    "OC",
    "OC PROFILE",
    "HARDWARE MONITOR",
    "BOARD EXPLORER",
    "M-FLASH",
)
# which tile the setup lights for each of the image's top-level forms
TILE_OF_TAB = {
    "settings": 0,
    "main": 0,
    "advanced": 0,
    "chipset": 0,
    "boot": 0,
    "security": 0,
    "save & exit": 0,
    "overclocking": 1,
    "overclocking profiles": 2,
    "green power": 3,
    "m-flash": 5,
}
VISIBLE_TILES = 3  # what the firmware's own 542-pixel panel holds

# --- Click BIOS 5 (the same container form, the skin split over fourteen of them) --------------

C5_BAND_W, C5_BAND_H = 1024, 253  # the printed top band, "msi CLICK BIOS 5"
C5_PANEL_W, C5_PANEL_H = 210, 514  # the help panel at the right (253+514 = 767)
C5_TILE_W, C5_TILE_H = 210, 170  # one menu tile (three of them fill the column)
C5_HELPTAB_W, C5_HELPTAB_H = 94, 28  # the HELP and INFO tabs, three states
C5_BG = "A44E52DE"  # the bare module holding the 1024x768 page background
C5_TILE_NAMES = (
    "SETTINGS",
    "OC",
    "OC PROFILE",
    "HARDWARE MONITOR",
    "BOARD EXPLORER",
    "M-FLASH",
    "SYSTEM EXPLORER",
)
C5_LEFT_TILES = (0, 1, 5)  # (in C5_TILE_NAMES) what the real setup keeps left of its menus
C5_KEYS = (
    "\u2191\u2193: Move",
    "\u2192\u2190: Group Jump",
    "Enter: Select",
    "+/-: Value",
    "F1: General Help",
)
C5_TILE_OF_TAB = {
    "settings": 0,
    "main": 0,
    "advanced": 0,
    "chipset": 0,
    "boot": 0,
    "security": 0,
    "save & exit": 0,
    "overclocking": 1,
    "oc profiles": 2,
    "oc profile": 2,
    "eco": 3,
    "hardware monitor": 3,
    "board explorer": 4,
    "system explorer": 6,
    "m-flash": 5,
}

# --- Click BIOS II (no container: one bare picture per FFS file) -------------------------------

C2_FRAME = "AFD94715"  # the whole page frame, 1024x768, with the content box drawn in it
C2_TILE_W, C2_TILE_H = 212, 157
C2_SPLASH_W, C2_SPLASH_H = 583, 477
# the content box of the frame picture, measured out of it (work/msi2_7.py)
C2_BOX = (221, 287, 803, 763)
# the six tiles, as (plain, lit) module GUIDs: both boards of this look hold the same 24 tile
# modules byte for byte (work/msi2_9.py), and the lit state is the blue one
C2_TILES = {
    "settings": ("280C054C", "DF13FFFD"),
    "oc": ("02A1CD7B", "17AFCFED"),
    "eco": ("7EEE3F1A", "7FF416C4"),
    "browser": ("A9DD9433", "90AA64D2"),
    "security": ("A6C47431", "720EF5B2"),
    "utilities": ("FD223111", "A268C6D4"),
}
C2_TILE_ORDER = ("settings", "oc", "eco", "browser", "security", "utilities")
# where they sit, as on the real setup: three left of the content box, three right of it
C2_TILE_AT = ((0, 284), (0, 445), (0, 606), (812, 284), (812, 606), (812, 445))
# the buttons above the box and the language and close buttons, as the setup opens
C2_CHROME = (
    ("AFF7115F", (352, 228)),  # ECO mode, off
    ("60D3724D", (461, 228)),  # STANDARD mode, on
    ("779A004A", (570, 228)),  # OC Genie II mode, off
    ("FE26E767", (893, 6)),  # Language
    ("2709FB87", (984, 6)),  # X
)
C2_TILE_OF_TAB = {
    "settings": 0,
    "overclocking": 1,
    "green power": 2,
    "games": 3,
    "security": 4,
    "utilities": 5,
}

GEO: dict[str, dict[str, Any]] = {
    # every number is for a 1024x768 canvas
    "C4": {
        "bandxy": (0, 0),
        "panelxy": (16, 224),  # the band ends at y 224 and the panel is 542 tall: 224+542=766
        "tilexy": (16, 228),  # the first tile inside the panel (its own arrows are at its edges)
        "tilepitch": TILE_H,
        "items": (252, 244, 1004, 636),
        "help": (252, 650, 1004, 736),
        # the Click BIOS 4 skin has no picture of a panel behind the item list, so the module
        # draws a dark one of its own: the artwork behind it is too busy to read text on
        "sheet": (236, 230, 1016, 738),
        "sheetfill": (10, 10, 14, 168),
        "page": (1004, 224),
        "rowh": 24,
        "fsel": 17,
        "fhead": 18,
        "ftitle": 18,
        "fhelp": 15,
    },
    "C5": {
        "bandxy": (0, 0),
        "panelxy": (814, 253),  # the band is 253 tall and the panel 514: 253+514 = 767
        "tilexy": (0, 255),
        "tilepitch": C5_TILE_H,
        "sheet": (211, 253, 813, 767),
        "sheetfill": (8, 8, 8, 205),
        "titlexy": (228, 264),
        "items": (262, 296, 796, 758),
        "help": (828, 322, 1002, 640),
        "keysxy": (828, 672),
        "helptabs": ((818, 256), (918, 256)),
        "rowh": 22,
        "fsel": 16,
        "fhead": 17,
        "ftitle": 18,
        "fhelp": 15,
    },
    "C2": {
        "framexy": (0, 0),
        # the content box of the frame picture itself
        "titlexy": (236, 296),
        "items": (250, 326, 786, 700),
        "help": (236, 706, 790, 758),
        "rowh": 22,
        "fsel": 16,
        "fhead": 17,
        "ftitle": 18,
        "fhelp": 15,
    },
}
COLOURS: dict[str, dict[str, Any]] = {
    # "sel" / "head" are replaced by the accent sampled from the firmware's own band or frame
    "C4": {
        "head": (215, 30, 40),
        "item": (232, 232, 232),
        "value": (255, 255, 255),
        "sel": (215, 30, 40),
        "seltext": (255, 255, 255),
        "help": (205, 205, 205),
        "title": (255, 255, 255),
        "foot": (170, 170, 170),
        "line": (120, 30, 34),
    },
    "C5": {
        "head": (215, 30, 40),
        "item": (236, 236, 236),
        "value": (255, 255, 255),
        "sel": (215, 30, 40),
        "seltext": (255, 255, 255),
        "help": (205, 205, 205),
        "title": (255, 255, 255),
        "foot": (170, 170, 170),
        "line": (120, 30, 34),
    },
    "C2": {
        "head": (60, 150, 220),
        "item": (232, 232, 232),
        "value": (255, 255, 255),
        "sel": (60, 150, 220),
        "seltext": (255, 255, 255),
        "help": (200, 200, 200),
        "title": (255, 255, 255),
        "foot": (170, 170, 170),
        "line": (30, 80, 120),
    },
}


# --- the skin's pictures ---------------------------------------------------------------------
#
# MSI keeps its setup art in its own container, not as bare pictures: "$MsI$", a UINT8 picture
# count and a zero byte, then for every picture a UINT16 index counting from 1, a UINT32 length and
# the picture itself (JPEG and BMP on the boards surveyed). The chain runs to the end of the section
# with no padding, so the record list is fully given by the header; the index is the order the setup
# draws the pictures in, not a role, so the role of each picture comes from its size.
#
# On Click BIOS 4 the whole skin is one such container (33 pictures in the raw FFS file
# 374CC63D-... on the boards surveyed); Click BIOS 5 splits it over 14 of them (196 pictures in
# 374CC63D alone, plus the 293x42 option rows in 10006A45 and the rest). Click BIOS II uses no
# container at all: its pictures are bare FFS files, read by asrock_gui.


Pic = R.Pic  # (one picture of a container: the same record as ASRock's)

MAGIC = b"$MsI$"
HEAD = 7  # "$MsI$", a UINT8 picture count, and a zero byte


def _records(data: bytes, base: int) -> list[Pic]:
    """The pictures of the $MsI container that starts at `base`, or [] if the chain is not sane."""
    out: list[Pic] = []
    count = data[base + 5]
    if data[base + 6]:
        return []
    p = base + HEAD
    want = 1
    while want <= count and p + 6 <= len(data):
        index, size = struct.unpack_from("<HI", data, p)
        off = p + 6
        if index != want or size < 12 or off + size > len(data):
            break
        kind = R._kind(data, off)
        if kind is None:
            break
        w, h = R._dims(data, off, kind)
        out.append(Pic(index, kind, off, size, w, h))
        p = off + size
        want += 1
    return out


def containers(rom: bytes) -> list[tuple[bytes, list[Pic]]]:
    """Every $MsI skin container of the image, as (its bytes, its record list) — usually just one.
    The module is compressed, so this walks the firmware volumes the way asrock_gui does and keeps
    the sections that start with the magic instead of the ones that start with a picture."""
    blobs: list[bytes] = []
    _walk_volumes(rom, blobs, 0)
    out = [(b, r) for b in blobs if (r := _records(b, 0))]
    # an image can hold more than one skin (a small one for the flasher screen); the setup's own
    # chrome is the fullest container
    out.sort(key=lambda t: -len(t[1]))
    return out


MAX_DEPTH = 7


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


def _add(out: list[bytes], data: bytes) -> None:
    if data.startswith(MAGIC):
        out.append(data)


def _walk_sections(data: bytes, start: int, end: int, out: list, depth: int) -> None:
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
                    _walk_sections(inner, 0, len(inner), out, depth + 1)
                    if inner and b"_FVH" in inner:
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
                    _walk_sections(inner, 0, len(inner), out, depth + 1)
                else:
                    _walk_sections(data, p + off, p + size, out, depth + 1)
                    _add(out, payload)
            elif stype == 0x17 and depth < MAX_DEPTH:  # a firmware volume image
                _walk_volumes(data[body : p + size], out, depth + 1)
            elif stype in (0x18, 0x19):  # freeform, raw: the picture containers
                _add(out, data[body : p + size])
        except (ValueError, IndexError, struct.error, EOFError):
            pass
        p = (p + size + 3) & ~3


def _walk_volumes(data: bytes, out: list, depth: int) -> None:
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
                            _walk_sections(data, f + 24, f + fsize, out, depth)
                        f = (f + fsize + 7) & ~7
        except struct.error:
            pass
        i = data.find(b"_FVH", i + 4)


def _all(rom: bytes) -> list[Pic]:
    recs: list[Pic] = []
    for _blob, c in containers(rom):
        recs.extend(c)
    return recs


def bare(rom: bytes) -> dict[str, list[Pic]]:
    """The pictures MSI keeps outside its container, as asrock_gui reads them: module GUID prefix ->
    its pictures. Click BIOS II holds its whole skin here; Click BIOS 5 its page background."""
    return R.pictures(rom)


def look(rom: bytes) -> Optional[str]:
    """ "C4" for the Click BIOS 4 skin, "C5" for Click BIOS 5, "C2" for Click BIOS II, None for
    anything else. The two container looks use the same container; the band picture tells them apart
    (224 px against 253 px). Click BIOS II has no container at all: its marker is the 583x477
    "CLICK BIOS II" splash and the column of 212x157 tile files."""
    recs = _all(rom)
    if recs:
        if any(p.w == BAND_W and p.h == BAND_H for p in recs) and any(
            p.w == TILE_W and p.h == TILE_H for p in recs
        ):
            return "C4"
        if any(p.w == C5_BAND_W and p.h == C5_BAND_H for p in recs):
            return "C5"
    mods = bare(rom)
    tiles = sum(1 for ps in mods.values() if any(p.w == C2_TILE_W and p.h == C2_TILE_H for p in ps))
    splash = any(p.w == C2_SPLASH_W and p.h == C2_SPLASH_H for ps in mods.values() for p in ps)
    if tiles >= 12 and splash:
        return "C2"
    return None


def generation(rom: bytes) -> Optional[str]:
    """ "C4", "C5" or "C2" for an MSI setup this module draws, None for anything else."""
    return look(rom)


def _tiles(
    recs: list[Pic], data: bytes
) -> list[tuple[Optional[Image.Image], Optional[Image.Image]]]:
    """The six menu tiles as (plain, highlighted), in the order SETTINGS, OC, OC PROFILE,
    HARDWARE MONITOR, BOARD EXPLORER, M-FLASH. The firmware stores them in that order, two states
    after each other; the names are printed in the pictures themselves."""
    pics = [p for p in recs if p.w == TILE_W and p.h == TILE_H]
    out: list[tuple[Optional[Image.Image], Optional[Image.Image]]] = []
    for k in range(0, len(pics) - 1, 2):
        plain = R._load(data, pics[k])
        lit = R._load(data, pics[k + 1])
        out.append((plain, lit))
    return out


class Skin:
    """The firmware's own chrome for the Click BIOS 4 look."""

    def __init__(self, rom: bytes, gen: str) -> None:
        self.gen = gen
        self.geo = dict(GEO[gen])
        self.col = dict(COLOURS[gen])
        self.band = self.bg = self.panel = None
        self.tiles: list[tuple[Optional[Image.Image], Optional[Image.Image]]] = []
        for blob, recs in containers(rom):
            for p in recs:
                if p.w == BAND_W and p.h == BAND_H and self.band is None:
                    self.band = R._load(blob, p)
                elif p.w == BG_W and p.h == BG_H and self.bg is None:
                    self.bg = R._load(blob, p)
                elif p.w == PANEL_W and p.h == PANEL_H and self.panel is None:
                    self.panel = R._load(blob, p)
            if not self.tiles:
                self.tiles = _tiles(recs, blob)
        # the accent is the red of the firmware's own band (its gradient is the page's colour key)
        accent = A._accent(self.band) if self.band is not None else None
        if accent is not None:
            self.col["head"] = self.col["sel"] = accent
            self.col["seltext"] = (255, 255, 255) if A._lum(accent) < 140 else (18, 12, 12)
            self.col["line"] = (max(accent[0] // 2, 40), accent[1] // 4, accent[2] // 4)

    def fonts(self) -> dict[str, Font]:
        g = self.geo
        return {
            "head": A._font("arialbd.ttf", g["fhead"]),
            "item": A._font("arial.ttf", g["fsel"]),
            "value": A._font("arial.ttf", g["fsel"]),
            "title": A._font("arialbd.ttf", g["ftitle"]),
            "help": A._font("arial.ttf", g["fhelp"]),
            "foot": A._font("arial.ttf", max(g["fhelp"] - 2, 11)),
        }


def _draw_menu(skin: Skin, im: Image.Image, tile: int) -> None:
    """The menu column: the firmware's own panel and its own tiles, three of them visible, the
    window of three chosen so the tile of this page is inside it."""
    if skin.panel is not None:
        im.paste(skin.panel, skin.geo["panelxy"], skin.panel)
    if not skin.tiles:
        return
    n = len(skin.tiles)
    first = 0
    if n > VISIBLE_TILES and tile is not None:
        first = min(max(tile - VISIBLE_TILES // 2, 0), n - VISIBLE_TILES)
    x0, y0 = skin.geo["tilexy"]
    for k in range(VISIBLE_TILES):
        which = first + k
        if which >= n:
            break
        on = which == tile
        art = skin.tiles[which][1] if on else skin.tiles[which][0]
        if art is None:
            art = skin.tiles[which][0]
        if art is None:
            continue
        im.paste(art, (x0, y0 + k * skin.geo["tilepitch"]))


def _draw_page(
    skin: Skin,
    fonts: dict,
    title: str,
    tile: int,
    rows: list,
    n: int,
    total: int,
    help_text: str,
) -> Image.Image:
    geo, col = skin.geo, skin.col
    im = skin.bg.copy() if skin.bg is not None else Image.new("RGBA", (1024, 768), (0, 0, 0, 255))
    if skin.band is not None:
        im.paste(skin.band, geo["bandxy"])
    _draw_menu(skin, im, tile)
    # the dark sheet behind the item list and the help text (the skin has no picture of one)
    sx0, sy0, sx1, sy1 = geo["sheet"]
    ov = Image.new("RGBA", im.size, (0, 0, 0, 0))
    ImageDraw.Draw(ov).rectangle((sx0, sy0, sx1, sy1), fill=geo["sheetfill"])
    im = Image.alpha_composite(im, ov)
    dr = ImageDraw.Draw(im)

    ix0, iy0, ix1, _iy1 = geo["items"]
    hx0, hy0, hx1, hy1 = geo["help"]

    # the page title and the page marker go in the band's own empty right-hand area
    shown = title
    while dr.textlength(shown, font=fonts["title"]) > (ix1 - ix0) - 8 and " > " in shown:
        shown = "... > " + shown.removeprefix("... > ").split(" > ", 1)[1]
    tw = dr.textlength(shown, font=fonts["title"])
    dr.text((ix1 - tw, 196), shown, font=fonts["title"], fill=col["title"])
    if total > 1:
        mark = f"{n}/{total}"
        dr.text(
            (geo["page"][0] - dr.textlength(mark, font=fonts["foot"]), geo["page"][1] + 2),
            mark,
            font=fonts["foot"],
            fill=col["foot"],
        )

    # the rows: the bar of the highlighted row first, then all the text on top. The highlighted
    # row is the first selectable one on the page, as in uefi_setup._render.
    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y, ys = iy0, []
    for i, r in enumerate(rows):
        ys.append(y)
        if i == sel:
            dr.rectangle((ix0 - 12, y, ix1 + 4, y + geo["rowh"] - 2), fill=col["sel"])
        y += r.h
    for i, r in enumerate(rows):
        at = ys[i]
        on = i == sel
        text = col["seltext"] if on else col["item"]
        if r.kind == "head":
            dr.text((ix0, at + 3), r.prompt, font=fonts["head"], fill=col["head"])
            # a static line of the image repeats its own label as its value (the temperature
            # monitor of the main page); the band already prints those, so show it once
            if r.value and r.value != r.prompt:
                vw = dr.textlength(r.value, font=fonts["value"])
                dr.text((ix1 - vw, at + 3), r.value, font=fonts["value"], fill=col["value"])
        elif r.kind == "sep":
            dr.line((ix0, at + 6, ix1, at + 6), fill=col["line"])
        else:
            if r.kind == "ref":
                dr.polygon([(ix0 - 10, at + 5), (ix0 - 10, at + 17), (ix0 - 2, at + 11)], fill=text)
            dr.text((ix0, at + 3), r.prompt, font=fonts["item"], fill=text)
            if r.value and r.value != r.prompt:
                vw = dr.textlength(r.value, font=fonts["value"])
                dr.text(
                    (ix1 - vw, at + 3),
                    r.value,
                    font=fonts["value"],
                    fill=col["seltext"] if on else col["value"],
                )

    if help_text:
        for i, line in enumerate(A._wrap(help_text, fonts["help"], dr, hx1 - hx0)):
            if hy0 + i * (geo["fhelp"] + 4) > hy1 - geo["fhelp"]:
                break
            dr.text((hx0, hy0 + i * (geo["fhelp"] + 4)), line, font=fonts["help"], fill=col["help"])
    return im.convert("RGB")


def _tile_of(name: str) -> int:
    return TILE_OF_TAB.get(" ".join(name.split()).lower(), 0)


# --- Click BIOS 5 ------------------------------------------------------------------------------


class Skin5:
    """The firmware's own chrome for the Click BIOS 5 look: the band, the menu tiles, the help
    panel and its HELP and INFO tabs, all out of the $MsI$ containers, and the page background
    out of its own bare FFS file."""

    def __init__(self, rom: bytes) -> None:
        self.gen = "C5"
        self.geo = dict(GEO["C5"])
        self.col = dict(COLOURS["C5"])
        self.band = self.panel = None
        self.tiles: list[tuple[Optional[Image.Image], Optional[Image.Image]]] = []
        self.helptabs: list[Optional[Image.Image]] = []
        for blob, recs in containers(rom):
            for p in recs:
                if p.w == C5_BAND_W and p.h == C5_BAND_H and self.band is None:
                    self.band = R._load(blob, p)
                elif p.w == C5_PANEL_W and p.h == C5_PANEL_H and self.panel is None:
                    self.panel = R._load(blob, p)
            t = [p for p in recs if p.w == C5_TILE_W and p.h == C5_TILE_H]
            if t and not self.tiles:
                for k in range(0, len(t) - 1, 2):
                    self.tiles.append((R._load(blob, t[k]), R._load(blob, t[k + 1])))
                # the container of one board can hold the tiles of more than one skin; the menu
                # column of this look has the seven names of C5_TILE_NAMES
                self.tiles = self.tiles[: len(C5_TILE_NAMES)]
            tb = [p for p in recs if p.w == C5_HELPTAB_W and p.h == C5_HELPTAB_H]
            if tb and not self.helptabs:
                self.helptabs = [R._load(blob, p) for p in tb]
        self.bg = None
        for blob in R.picture_sections(rom).get(C5_BG, []):
            for p in R.chain(blob):
                if p.w == BG_W and p.h == BG_H:
                    self.bg = R._load(blob, p)
                    break
            if self.bg is not None:
                break
        accent = A._accent(self.band) if self.band is not None else None
        if accent is not None:
            self.col["head"] = self.col["sel"] = accent
            self.col["seltext"] = (255, 255, 255) if A._lum(accent) < 140 else (18, 12, 12)
            self.col["line"] = (max(accent[0] // 2, 40), accent[1] // 4, accent[2] // 4)

    def fonts(self) -> dict[str, Font]:
        g = self.geo
        return {
            "head": A._font("arialbd.ttf", g["fhead"]),
            "item": A._font("arial.ttf", g["fsel"]),
            "value": A._font("arial.ttf", g["fsel"]),
            "title": A._font("arialbd.ttf", g["ftitle"]),
            "help": A._font("arial.ttf", g["fhelp"]),
            "foot": A._font("arial.ttf", max(g["fhelp"] - 2, 11)),
        }


def _fit(dr: ImageDraw.ImageDraw, text: str, font: Font, width: int) -> str:
    """`text` cut to `width` pixels, with "..." when it no longer fits (the firmware's own row
    pictures are a fixed 293 px wide, so a long prompt has to give way to the value)."""
    if dr.textlength(text, font=font) <= width:
        return text
    while text and dr.textlength(text + "...", font=font) > width:
        text = text[:-1]
    return text + "..." if text else ""


def _draw_items(dr: ImageDraw.ImageDraw, fonts: dict, geo: dict, col: dict, rows: list) -> None:
    """The item list of Click BIOS 5 and II, which the setup draws itself: prompts on the left,
    values on the right, a triangle in front of a sub-menu."""
    ix0, iy0, ix1, _iy1 = geo["items"]
    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y, ys = iy0, []
    for i, r in enumerate(rows):
        ys.append(y)
        if i == sel:
            dr.rectangle((ix0 - 12, y, ix1 + 6, y + geo["rowh"] - 2), fill=col["sel"])
        y += r.h
    for i, r in enumerate(rows):
        at = ys[i]
        on = i == sel
        text = col["seltext"] if on else col["item"]
        if r.kind == "head":
            hv = r.value if r.value and r.value != r.prompt else ""
            hw = dr.textlength(hv, font=fonts["value"]) if hv else 0
            dr.text(
                (ix0, at + 2),
                _fit(dr, r.prompt, fonts["head"], (ix1 - hw - 16) - ix0),
                font=fonts["head"],
                fill=col["head"],
            )
            if hv:
                dr.text((ix1 - hw, at + 2), hv, font=fonts["value"], fill=col["value"])
        elif r.kind == "sep":
            dr.line((ix0, at + 6, ix1, at + 6), fill=col["line"])
        else:
            if r.kind == "ref":
                dr.polygon([(ix0 - 10, at + 4), (ix0 - 10, at + 16), (ix0 - 2, at + 10)], fill=text)
            show = r.value if r.value and r.value != r.prompt else ""
            vw = dr.textlength(show, font=fonts["value"]) if show else 0
            dr.text(
                (ix0, at + 2),
                _fit(dr, r.prompt, fonts["item"], (ix1 - vw - 16) - ix0),
                font=fonts["item"],
                fill=text,
            )
            if show:
                dr.text(
                    (ix1 - vw, at + 2),
                    show,
                    font=fonts["value"],
                    fill=col["seltext"] if on else col["value"],
                )


def _draw_title(dr: ImageDraw.ImageDraw, fonts: dict, geo: dict, col: dict, title: str) -> None:
    """The page's title at the top left of the item list, its front cut off if it is too long."""
    width = geo["items"][2] - geo["titlexy"][0]
    shown = title
    while dr.textlength(shown, font=fonts["title"]) > width and " > " in shown:
        shown = "... > " + shown.removeprefix("... > ").split(" > ", 1)[1]
    dr.text(geo["titlexy"], shown, font=fonts["title"], fill=col["title"])


def _draw_help(dr: ImageDraw.ImageDraw, fonts: dict, geo: dict, col: dict, text: str) -> None:
    hx0, hy0, hx1, hy1 = geo["help"]
    for i, line in enumerate(A._wrap(text, fonts["help"], dr, hx1 - hx0)):
        if hy0 + i * (geo["fhelp"] + 4) > hy1 - geo["fhelp"]:
            break
        dr.text((hx0, hy0 + i * (geo["fhelp"] + 4)), line, font=fonts["help"], fill=col["help"])


def _draw_page5(
    skin: Skin5, fonts: dict, title: str, tile: int, rows: list, help_text: str
) -> Image.Image:
    geo, col = skin.geo, skin.col
    im = skin.bg.copy() if skin.bg is not None else Image.new("RGBA", (1024, 768), (0, 0, 0, 255))
    if skin.band is not None:
        im.paste(skin.band, geo["bandxy"])
    # the left column: SETTINGS, OC and M-FLASH, the current one lit
    x0, y0 = geo["tilexy"]
    for k, which in enumerate(C5_LEFT_TILES):
        if which < len(skin.tiles):
            plain, lit = skin.tiles[which]
            art = (lit if which == tile else plain) or plain
            if art is not None:
                im.paste(art, (x0, y0 + k * geo["tilepitch"]))
    # the artwork behind the item list is too busy to read text on
    sx0, sy0, sx1, sy1 = geo["sheet"]
    sheet = Image.new("RGBA", (sx1 - sx0, sy1 - sy0), geo["sheetfill"])
    im.paste(sheet, (sx0, sy0), sheet)
    # the right column: the firmware's help panel and its two tabs
    if skin.panel is not None:
        im.paste(skin.panel, geo["panelxy"])
    dr = ImageDraw.Draw(im)
    for name, state, at in zip(("HELP", "INFO"), (2, 1), geo["helptabs"]):
        art = skin.helptabs[state] if state < len(skin.helptabs) else None
        if art is not None:
            im.paste(art, at)
        w = dr.textlength(name, font=fonts["foot"])
        dr.text(
            (at[0] + (C5_HELPTAB_W - w) / 2, at[1] + 7), name, font=fonts["foot"], fill=col["title"]
        )
    _draw_title(dr, fonts, geo, col, title)
    _draw_items(dr, fonts, geo, col, rows)
    if help_text:
        _draw_help(dr, fonts, geo, col, help_text)
    kx, ky = geo["keysxy"]
    for i, line in enumerate(C5_KEYS):
        dr.text((kx, ky + i * 18), line, font=fonts["help"], fill=col["help"])
    return im.convert("RGB")


# --- Click BIOS II -----------------------------------------------------------------------------


class Skin2:
    """The firmware's own chrome for the Click BIOS II look: the page frame with its content box,
    the six menu tiles in their plain and lit state, and the accent sampled from the frame."""

    def __init__(self, rom: bytes) -> None:
        self.gen = "C2"
        self.geo = dict(GEO["C2"])
        self.col = dict(COLOURS["C2"])
        secs = R.picture_sections(rom)
        self.frame = None
        for blob in secs.get(C2_FRAME, []):
            pics = R.chain(blob)
            if pics and pics[0].w == BG_W and pics[0].h == BG_H:
                self.frame = R._load(blob, pics[0])
                break
        self.chrome = [(_load_guid(secs, guid), at) for guid, at in C2_CHROME]
        self.tiles: list[tuple[Optional[Image.Image], Optional[Image.Image]]] = []
        for name in C2_TILE_ORDER:
            plain, lit = C2_TILES[name]
            a = _load_guid(secs, plain)
            b = _load_guid(secs, lit)
            self.tiles.append((a, b))
        accent = A._accent(self.frame) if self.frame is not None else None
        if accent is not None:
            self.col["head"] = self.col["sel"] = accent
            self.col["seltext"] = (255, 255, 255) if A._lum(accent) < 140 else (18, 12, 12)
            self.col["line"] = (accent[0] // 4, accent[1] // 2, max(accent[2] // 2, 40))

    def fonts(self) -> dict[str, Font]:
        g = self.geo
        return {
            "head": A._font("arialbd.ttf", g["fhead"]),
            "item": A._font("arial.ttf", g["fsel"]),
            "value": A._font("arial.ttf", g["fsel"]),
            "title": A._font("arialbd.ttf", g["ftitle"]),
            "help": A._font("arial.ttf", g["fhelp"]),
            "foot": A._font("arial.ttf", max(g["fhelp"] - 2, 11)),
        }


def _load_guid(secs: dict[str, list[bytes]], guid: str) -> Optional[Image.Image]:
    for blob in secs.get(guid, []):
        pics = R.chain(blob)
        if pics:
            im = R._load(blob, pics[0])
            if im is not None:
                return im
    return None


def _draw_page2(
    skin: Skin2, fonts: dict, title: str, tile: int, rows: list, help_text: str
) -> Image.Image:
    geo, col = skin.geo, skin.col
    im = (
        skin.frame.copy()
        if skin.frame is not None
        else Image.new("RGBA", (1024, 768), (0, 0, 0, 255))
    )
    for art, at in skin.chrome:
        if art is not None:
            im.paste(art, at)
    for k, (plain, lit) in enumerate(skin.tiles):
        art = (lit if k == tile else plain) or plain
        if art is not None:
            im.paste(art, C2_TILE_AT[k])
    dr = ImageDraw.Draw(im)
    _draw_title(dr, fonts, geo, col, title)
    _draw_items(dr, fonts, geo, col, rows)
    if help_text:
        _draw_help(dr, fonts, geo, col, help_text)
    return im.convert("RGB")


def _tile_of5(name: str) -> int:
    return C5_TILE_OF_TAB.get(" ".join(name.split()).lower(), 0)


def _tile_of2(name: str) -> int:
    return C2_TILE_OF_TAB.get(" ".join(name.split()).lower(), 0)


def pages(rom: bytes) -> list[tuple[str, Image.Image, str]]:
    """[(title, picture, text)] for every screen of an MSI setup of one of the three looks, in the
    order and with the titles uefi_setup.UefiSetup.screens() gives (a continued form: "Title
    (2/3)"); [] when the image is not one of those."""
    gen = generation(rom)
    if gen not in ("C4", "C5", "C2"):
        return []
    su = U.UefiSetup(rom)
    if gen == "C4":
        return _pages4(su, rom)
    if gen == "C5":
        return _pages5(su, rom)
    return _pages2(su, rom)


def _pages4(su: U.UefiSetup, rom: bytes) -> list[tuple[str, Image.Image, str]]:
    skin = Skin(rom, "C4")
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in A._page_list(su):
        tabname = su.tabs[tab][0] if 0 <= tab < len(su.tabs) else ""
        rows = R.rows_of(su, su.forms[form_id][1], geo)
        chunks = A._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            help_text = A._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page(
                skin, fonts, name, _tile_of(tabname), chunk, n, len(chunks), help_text
            )
            out.append((name, image, A._text(name, chunk, help_text)))
    return out


def _pages5(su: U.UefiSetup, rom: bytes) -> list[tuple[str, Image.Image, str]]:
    skin = Skin5(rom)
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in A._page_list(su):
        tabname = su.tabs[tab][0] if 0 <= tab < len(su.tabs) else ""
        rows = R.rows_of(su, su.forms[form_id][1], geo)
        chunks = A._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            help_text = A._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page5(skin, fonts, name, _tile_of5(tabname), chunk, help_text)
            out.append((name, image, A._text(name, chunk, help_text)))
    return out


def _pages2(su: U.UefiSetup, rom: bytes) -> list[tuple[str, Image.Image, str]]:
    skin = Skin2(rom)
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in A._page_list(su):
        tabname = su.tabs[tab][0] if 0 <= tab < len(su.tabs) else ""
        rows = R.rows_of(su, su.forms[form_id][1], geo)
        chunks = A._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            help_text = A._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page2(skin, fonts, name, _tile_of2(tabname), chunk, help_text)
            out.append((name, image, A._text(name, chunk, help_text)))
    return out
