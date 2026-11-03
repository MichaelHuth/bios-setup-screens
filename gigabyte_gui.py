"""
Setup screens of Gigabyte UEFI DualBIOS firmware, drawn in the setup's own look (group B of
uefigui): the "Classic Mode" list pages of the 2011-2015 boards, which is the look all 13 cached
Gigabyte images carry.

generation(rom) names the Gigabyte setup look of a flash image ("B1", or None for firmware that is
not one of them); pages(rom) draws every screen that uefi_setup.UefiSetup.screens() would produce
for the same image, in the same order and with the same titles, as pictures:

- the page background and the bottom key-legend bar are the firmware's own pictures. Like ASRock's
  (and unlike ASUS's), a Gigabyte module holds its pictures back to back at offset 0 of one
  freeform/raw FFS section, so asrock_gui.picture_sections / pictures_of / chain are used here
  unchanged. The module GUIDs name their role: EFCB2FDB is the skin (its largest picture is the
  1024x768 navy background with "GIGABYTE UEFI DualBIOS" printed in its top band; the same module
  also holds the App-Center tile page and the scroll bars, arrows and buttons of the graphical
  modes), 86EE84E1 is the 1024x47 key-legend bar ("DEL : BIOS SETUP \\ Q-FLASH / F9 : SYSTEM
  INFORMATION  F12 : BOOT MENU / END : Q-FLASH"), and 86EE84E2 is a second bar of the same size
  that is all black on every board checked;
- one generation only: the 13 boards share that skin. Six of them also hold the pictures of the
  3D BIOS application (6B389ACF, 64023E54, CD4275AA, C55C4A64, A609BD4E, 52359378: the rotatable
  board renders, its 195x195 side-menu tiles and its icons), which are not chrome of the list
  pages, so they are not used for drawing and do not name a generation of their own;
- the content of the screens is the IFR, exactly as asus_gui draws it: one row per question
  (prompt left, its default value right), SUBTITLE as a section heading, a sub-menu link marked
  with a triangle, the first selectable item's help word-wrapped in the help box, and the values
  the setup only knows at run time as they come out of UefiSetup ("-" / N/A).

The Gigabyte skin has no tab buttons, no help panel and no selected-row bar of its own - the
classic mode draws those itself - so their place is this module's choice, taken from the two
measured bands of the background (the printed title band at y 0-79 and the 47-pixel legend bar at
the bottom). The accent colour and the colour of the highlighted row are sampled from the
background's own title band and gradient.
"""

from __future__ import annotations

import struct
import uuid
from typing import Any, Optional, Union

from PIL import Image, ImageDraw, ImageFont

import asrock_gui as R
import asus_gui as A
import tiano
import uefi_setup as U

NA = "N/A"
Font = Union[ImageFont.FreeTypeFont, ImageFont.ImageFont]

# the modules whose role is the same on every Gigabyte board (GUID prefix = the FFS file name)
BG = "EFCB2FDB"  # the skin: the page background, the App-Center page and the widgets
LEGEND = "86EE84E1"  # the 1024x47 key-legend bar
LEGEND2 = "86EE84E2"  # the second bar of the same size, all black on every board checked
# the pictures of the 3D BIOS application (only on 6 of the 13 boards, never used for drawing)
D3_MARK = ("6B389ACF", "64023E54", "CD4275AA", "C55C4A64", "A609BD4E", "52359378")

GEO: dict[str, dict[str, Any]] = {
    # every number is for a 1024x768 canvas; _scale() scales them when the background is bigger
    "B1": {
        # measured on the background itself: its printed title band runs to y 79, and the legend
        # bar (47 px tall) is put at the bottom edge, so the frame is what is left between them
        "frame": (16, 84, 1008, 716),
        "tabs": (24, 84),  # (the classic mode has no tab pictures: this row is this module's own)
        "tabh": 24,
        "head": (48, 114, 1000, 134),  # the sub-menu title, and the page marker at its right end
        "items": (48, 142, 1000, 634),
        "help": (48, 650, 1000, 712),
        "legendxy": (0, 721),
        "foot": (16, 56, 1008, 78),  # the copyright, right-aligned in the printed title band
        "pitch": 26,
        "rowh": 24,
        "fsel": 18,
        "fhead": 19,
        "ftab": 15,
        "ftitle": 18,
        "fhelp": 15,
    },
}
COLOURS: dict[str, dict[str, Any]] = {
    "B1": {
        # head / sel are replaced by the colours sampled from the background (see Skin)
        "head": (255, 86, 86),
        "item": (232, 236, 240),
        "value": (255, 255, 255),
        "sel": (0, 74, 148),
        "seltext": (255, 255, 255),
        "tab": (206, 214, 222),
        "tabbg": (0, 34, 70),
        "tabtext": (236, 240, 244),
        "line": (58, 96, 138),
        "help": (206, 216, 226),
        "title": (255, 255, 255),
        "foot": (150, 162, 174),
        "box": (44, 84, 128),
    },
}


# --- the firmware volumes, keeping which module a section belongs to -------------------------
# as asrock_gui's walk, with one difference: a Gigabyte picture section does not start with its
# first picture. EFCB2FDB's raw section starts with a 48-byte container header ("GTSE", version 1,
# then five counts) and its first picture (a JPEG) is at offset 48; 86EE84E1 / 86EE84E2 start with
# the 16-byte GUID 7BB28B99-61BB-11D5-9A5D-0090273FC14D and their BMP is at offset 16. asrock_gui's
# _add keeps only a section whose offset 0 is a picture, so its walk finds none of these.

HEAD_SCAN = 512  # how far into a section to look for the first picture


def _next_pic(data: bytes, start: int) -> int:
    """The next offset at or after `start` where a picture starts, or -1."""
    cands = sorted(
        j
        for sig in (b"\x89P", b"\xff\xd8", b"GIF8", b"BM")
        for j in (data.find(sig, start),)
        if j >= 0
    )
    for j in cands:
        if R._kind(data, j) is not None:
            return j
    return -1


def _first_pic(data: bytes) -> int:
    """The offset of the first picture of a container section, or -1 when it holds none."""
    j = _next_pic(data, 0)
    return j if 0 <= j < HEAD_SCAN else -1


def _add(out: dict, guid: str, data: bytes) -> None:
    if _first_pic(data) >= 0:
        out.setdefault(guid, []).append(data)


def _decompress(ctype: int, payload: bytes) -> bytes:
    return R._decompress(ctype, payload)


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
            if stype == 0x01 and depth < R.MAX_DEPTH:  # compression section
                inner = _decompress(data[body + 4], data[body + 5 : p + size])
                if inner:
                    before = sum(len(v) for v in out.values())
                    _walk_sections(inner, 0, len(inner), out, depth + 1, guid)
                    if sum(len(v) for v in out.values()) == before and b"_FVH" in inner:
                        _walk_volumes(inner, out, depth + 1)
            elif stype == 0x02 and depth < R.MAX_DEPTH:  # GUID-defined section
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
            elif stype == 0x17 and depth < R.MAX_DEPTH:  # a firmware volume image
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


def chain(data: bytes) -> list[R.Pic]:
    """The pictures of one container section, with their offsets in it. Unlike ASRock's, a Gigabyte
    module does not hold its pictures back to back: after the container header each one sits behind
    a few bytes of its own, so the next picture is found by looking for the next picture signature
    after the end of the previous one (asrock_gui.chain stops at the first gap)."""
    out: list[R.Pic] = []
    p, n = 0, len(data)
    while p + 4 <= n:
        at = _next_pic(data, p)
        if at < 0:
            break
        kind = R._kind(data, at)
        if kind is None:
            p = at + 2
            continue
        w, h = R._dims(data, at, kind)
        size = R._pic_len(data, at, kind) or 0
        if size < 8 or at + size > n:
            p = at + 2
            continue
        out.append(R.Pic(len(out), kind, at, size, w, h))
        p = at + size
    return out


def pictures_of(secs: dict[str, list[bytes]]) -> dict[str, list[R.Pic]]:
    """module GUID prefix -> its picture records."""
    out: dict[str, list[R.Pic]] = {}
    for guid, blobs in secs.items():
        recs: list[R.Pic] = []
        for s in blobs:
            recs.extend(chain(s))
        if recs:
            out[guid] = recs
    return out


def pictures(rom: bytes) -> dict[str, list[R.Pic]]:
    return pictures_of(picture_sections(rom))


def _generation_of(mods: dict[str, list[R.Pic]]) -> Optional[str]:
    if BG not in mods or LEGEND not in mods:
        return None
    # the skin module has to hold the page background itself, and the legend module a bar of the
    # measured size (1024x47); both together say "Gigabyte classic mode", and neither module alone
    # does: 86EE84E1 / 86EE84E2 are AMI Aptio reference modules that hold other boards' pictures
    if not any(p.w >= 800 and p.h >= 600 for p in mods[BG]):
        return None
    if not any(p.w >= 800 and 32 <= p.h <= 96 for p in mods[LEGEND]):
        return None
    return "B1"


def generation(rom: bytes) -> Optional[str]:
    """ "B1" for a Gigabyte UEFI DualBIOS setup of the classic look, None for anything else."""
    return _generation_of(pictures(rom))


# --- drawing ---------------------------------------------------------------------------------


def _biggest(secs: dict[str, list[bytes]], guid: str) -> Optional[Image.Image]:
    """The largest picture of one module, as RGBA (as asrock_gui._biggest does)."""
    for blob in secs.get(guid, []):
        recs = chain(blob)
        if not recs:
            continue
        p = max(recs, key=lambda r: r.w * r.h)
        im = R._load(blob, p)
        if im is not None:
            return im
    return None


def _bright(c: Optional[tuple[int, int, int]]) -> Optional[tuple[int, int, int]]:
    """The same hue with its strongest channel at 255."""
    if c is None or max(c) == 0:
        return c
    r, g, b = (min(255, v * 255 // max(c)) for v in c)
    return r, g, b


def _band(bg: Image.Image) -> Image.Image:
    """The printed title band of the background (measured: y 0-79 of 768)."""
    return bg.crop((0, 0, bg.width, max(int(bg.height * 79 / 768), 8)))


def _highlight(bg: Image.Image) -> Optional[tuple[int, int, int]]:
    """The colour of the highlighted row: the most common mid-bright blue of the background's own
    gradient (the navy of the content area is too dark to read white text on)."""
    pal = bg.convert("RGB").getcolors(65536)
    if not pal:
        return None
    cands: list[tuple[int, tuple[int, int, int]]] = []
    for n, seen in pal:
        if not isinstance(seen, tuple) or len(seen) < 3:
            continue
        c: tuple[int, int, int] = (seen[0], seen[1], seen[2])
        if c[2] >= 70 and c[2] > c[0] + 25 and 60 < A._lum(c) < 175:
            cands.append((n, c))
    if not cands:
        return None
    return max(cands)[1]


class Skin:
    """The firmware's own chrome for one generation: the background and the key-legend bar."""

    def __init__(self, secs: dict[str, list[bytes]], gen: str) -> None:
        self.gen = gen
        self.geo = dict(GEO[gen])
        self.col = dict(COLOURS[gen])
        self.bg = _biggest(secs, BG)
        self.legend = _biggest(secs, LEGEND)
        if self.bg is not None:
            self._scale()
            # the accent is the hue of the printed title band (the red of "UEFI" and of the rule
            # under the title), at full brightness; the highlighted row takes the blue of the
            # gradient under it
            accent = _bright(A._accent(_band(self.bg)))
            if accent is not None:
                self.col["head"] = accent
            hl = _highlight(self.bg)
            if hl is not None:
                self.col["sel"] = hl
            self.col["seltext"] = (255, 255, 255) if A._lum(self.col["sel"]) < 140 else (12, 18, 20)

    def _scale(self) -> None:
        """The geometry is written for 1024x768; a bigger background scales all of it."""
        assert self.bg is not None
        w, h = self.bg.width, self.bg.height
        if (w, h) == (1024, 768):
            return
        sx, sy = w / 1024.0, h / 768.0
        g = self.geo
        for key in ("frame", "items", "help", "foot", "head"):
            x0, y0, x1, y1 = g[key]
            g[key] = (int(x0 * sx), int(y0 * sy), int(x1 * sx), int(y1 * sy))
        for key in ("tabs", "legendxy"):
            g[key] = (int(g[key][0] * sx), int(g[key][1] * sy))
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


def _draw_tabs(
    im: Image.Image, dr: ImageDraw.ImageDraw, skin: Skin, font: Font, tabs: list, sel: int
) -> None:
    """The top menu row of the classic mode. The firmware has no picture for it (the background
    only prints the vendor title), so the row is drawn flat: the selected tab in the blue sampled
    from the background, the others on a navy one shade lighter than the content area."""
    geo, col = skin.geo, skin.col
    x, y = geo["tabs"]
    h = geo["tabh"]
    _fx0, _fy0, fx1, _fy1 = geo["frame"]
    names = [n for n, _ in tabs]
    textw = [dr.textlength(n, font=font) for n in names]
    widths = [max(88.0, tw + 22) for tw in textw]
    avail = fx1 - x - 4 - 2 * (len(names) - 1)
    total = sum(widths)
    if total > avail:
        shrink = (total - avail) / len(names)
        widths = [max(w - shrink, tw + 10) for w, tw in zip(widths, textw)]
    for k, name in enumerate(names):
        w = int(widths[k])
        on = k == sel
        dr.rectangle((x, y, x + w, y + h), fill=col["sel"] if on else col["tabbg"])
        if on:
            dr.rectangle((x, y + h - 3, x + w, y + h - 1), fill=col["head"])
        tw = dr.textlength(name, font=font)
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
    ix0, iy0, ix1, _iy1 = geo["items"]
    hx0, hy0, hx1, hy1 = geo["help"]

    if skin.legend is not None and geo.get("legendxy") is not None:
        im.paste(skin.legend, geo["legendxy"], skin.legend)
        dr = ImageDraw.Draw(im)

    _draw_tabs(im, dr, skin, fonts["tab"], tabs, tab)

    # the sub-menu title under the tab row (a tab's own page needs none: the tab row names it);
    # a deep sub-menu title is shortened from the front, and the page marker goes at its right end
    dx0, dy0, dx1, _dy1 = geo["head"]
    tabname = tabs[tab][0] if 0 <= tab < len(tabs) else ""
    shown = title
    if title != tabname:
        while dr.textlength(shown, font=fonts["title"]) > (dx1 - dx0) - 60 and " > " in shown:
            shown = "... > " + shown.removeprefix("... > ").split(" > ", 1)[1]
        dr.text((dx0, dy0), shown, font=fonts["title"], fill=col["title"])
    if total > 1:
        mark = f"{n}/{total}"
        dr.text(
            (dx1 - dr.textlength(mark, font=fonts["foot"]), dy0 + 3),
            mark,
            font=fonts["foot"],
            fill=col["foot"],
        )

    # the help box of the classic mode sits under the item list; the firmware draws it, so the box
    # is this module's own outline and the help text of the first selectable item goes in it
    dr.rectangle((hx0 - 12, hy0 - 8, hx1, hy1), outline=col["box"])

    # the rows: the bar of the highlighted row first, then all the text on top. The highlighted
    # row is the first selectable one on the page, as in uefi_setup._render.
    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y, ys = iy0, []
    for i, r in enumerate(rows):
        ys.append(y)
        if i == sel:
            dr.rectangle((ix0 - 16, y, ix1 + 4, y + geo["rowh"] - 2), fill=col["sel"])
        y += r.h
    for i, r in enumerate(rows):
        at = ys[i]
        on = i == sel
        text = col["seltext"] if on else col["item"]
        if r.kind == "head":
            dr.text((ix0, at + 3), r.prompt, font=fonts["head"], fill=col["head"])
            if r.value:
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
                    fill=col["seltext"] if on else col["value"],
                )

    if help_text:
        for i, line in enumerate(A._wrap(help_text, fonts["help"], dr, hx1 - hx0 - 16)):
            if hy0 + i * (geo["fhelp"] + 4) > hy1 - geo["fhelp"]:
                break
            dr.text((hx0, hy0 + i * (geo["fhelp"] + 4)), line, font=fonts["help"], fill=col["help"])
    if copyright_:
        # the printed title band is empty at its right edge, so the version line goes there
        dr.text(
            (geo["foot"][2] - dr.textlength(copyright_, font=fonts["foot"]) - 4, geo["foot"][1]),
            copyright_,
            font=fonts["foot"],
            fill=col["foot"],
        )
    return im.convert("RGB")


def pages(rom: bytes) -> list[tuple[str, Image.Image, str]]:
    """[(title, picture, text)] for every screen of a Gigabyte B1 setup, in the order and with the
    titles uefi_setup.UefiSetup.screens() gives (a continued form: "Title (2/3)"); [] when the
    image is not one of those."""
    secs = picture_sections(rom)
    gen = _generation_of(pictures_of(secs))
    if gen != "B1":
        return []
    su = U.UefiSetup(rom)
    skin = Skin(secs, gen)
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in A._page_list(su):
        # asrock_gui.rows_of, not asus_gui's: a Gigabyte string often carries the setup's own
        # column escape ("Setup Prompt Timeout<ESC>{p100: %d") or a printf format at the end of the
        # name ("Boot Option #%d"), and that module takes the run-time part out of the prompt and
        # shows N/A in the value column instead
        rows = R.rows_of(su, su.forms[form_id][1], geo)
        chunks = A._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            # the help box holds the help of the first selectable item of this page, as in _render
            help_text = A._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page(
                skin, fonts, su.tabs, tab, name, chunk, n, len(chunks), help_text, su.copyright
            )
            out.append((name, image, A._text(name, chunk, help_text)))
    return out
