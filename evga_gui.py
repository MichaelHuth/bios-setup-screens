"""The EVGA Aptio V setup look (the EVGA boards of 2013-2020 in data\\guilook).

The firmware paints the whole page into one picture, module EFCB2FDB: the header with the CPU,
memory, PCI-Express, voltage and temperature labels, the row of five tab buttons, the dark item
area and the bordered help panel. The button art, the ON/OFF pills and the slider are separate
pictures with the same role names in both looks (E1 of 2013-2016, E2 of 2019-2020). What this
module draws is the item rows, the page title and the help text - all of them the firmware's own
strings, read by uefi_setup - plus the selected button, whose art is the firmware's too.
"""

from __future__ import annotations

from typing import Any, Optional

from PIL import Image, ImageDraw

import asrock_gui as AR  # (the picture reader that fits these boards: one picture per FFS file)
import asus_gui as AU
import uefi_setup as U

Font = Any

BG = "EFCB2FDB"  # the whole setup page, painted by the firmware

# the five buttons, in the order the frame paints them; each is (normal, hover, selected).
# The label is baked into the art, so the role name is the label.
TABS = {
    "OVERCLOCK": ("6B841D20", "7324F5B5", "DE70761B"),
    "MEMORY": ("3B9F57BB", "5166EC3F", "5B12E6B8"),
    "ADVANCED": ("0C5A1C8A", "0F108032", "65016E53"),
    "BOOT": ("A5D2E1B9", "D3ADF95D", "63A5C5B5"),
    "SAVE & EXIT": ("07F7E045", "E30A0C06", "3F6CB11A"),
}

# the setup's own tab names (uefi_setup names a tab after its form set's title) onto those five
NAME = {
    "main": "OVERCLOCK",  # (its form holds the CPU overclocking items)
    "overclock": "OVERCLOCK",
    "overclocking": "OVERCLOCK",
    "oc": "OVERCLOCK",
    "tweaker": "OVERCLOCK",
    "cell menu": "OVERCLOCK",
    "memory": "MEMORY",
    "advanced": "ADVANCED",
    "boot": "BOOT",
    "save & exit": "SAVE & EXIT",
    "save and exit": "SAVE & EXIT",
    "exit": "SAVE & EXIT",
}

# where the firmware painted its own parts (measured off the frame picture: work\gl_7.py,
# work\gl_8.py, work\gl_13.py and the gridded copy work\guilook\...\grid_EFCB2FDB.png)
GEO: dict[str, dict[str, Any]] = {
    "E1": {
        "w": 1024,
        "h": 768,
        "tabs": [(48, 243), (234, 243), (420, 243), (603, 243), (789, 243)],
        "title": (40, 300),
        "items": (40, 328, 700, 716),
        "help": (740, 312, 950, 585),
        "legend": (740, 590, 950, 704),
        "rowh": 22,
        "fsel": 17,
        "fhead": 17,
        "fitem": 16,
        "ftitle": 20,
        "fhelp": 13,
        "ffoot": 12,
        "foot": (0, 740),
    },
    "E2": {
        "w": 1024,
        "h": 768,
        # the frame prints the five labels; these are their centres, and the art is centred on them
        "tabc": [245, 415, 580, 730, 930],
        "taby": 162,
        "title": (24, 214),
        "items": (24, 242, 690, 712),
        "help": (748, 242, 972, 640),
        "legend": (748, 652, 972, 712),
        "rowh": 22,
        "fsel": 17,
        "fhead": 17,
        "fitem": 16,
        "ftitle": 19,
        "fhelp": 13,
        "ffoot": 12,
        "foot": (0, 736),
    },
}

COLOURS: dict[str, dict[str, Any]] = {
    "E1": {
        "head": (255, 255, 255),
        "item": (226, 226, 226),
        "value": (190, 226, 240),
        "sel": (0, 150, 190, 90),
        "seltext": (255, 255, 255),
        "line": (80, 80, 80),
        "help": (206, 226, 236),
        "title": (255, 255, 255),
        "foot": (206, 226, 236),
    },
    "E2": {
        "head": (255, 255, 255),
        "item": (222, 222, 222),
        "value": (150, 226, 235),
        "sel": (0, 170, 200, 80),
        "seltext": (255, 255, 255),
        "line": (70, 70, 70),
        "help": (196, 222, 232),
        "title": (255, 255, 255),
        "foot": (160, 160, 160),
    },
}

LEGEND = ("F1 General Help", "F9 Optimized Defaults", "F10 Save & Exit Setup", "ESC Exit")


def pictures_of(secs: dict[str, list[bytes]]) -> dict[str, Any]:
    """The biggest picture of every module, as an image (or None when it cannot be decoded)."""
    out: dict[str, Any] = {}
    for guid, blobs in secs.items():
        img = None
        for blob in blobs:
            pics = AR.chain(blob)
            if not pics:
                continue
            pic = max(pics, key=lambda r: r.w * r.h)
            got = AR._load(blob, pic)
            if got is not None and (img is None or got.width * got.height > img.width * img.height):
                img = got
        out[guid] = img
    return out


def _generation_of(pics: dict[str, Any]) -> Optional[str]:
    """E1 or E2 by the button art, None for anything else. The five button labels are baked into
    the art, so these role names exist only on EVGA's boards; the two looks differ in the size of
    the same role pictures."""
    if BG not in pics:
        return None
    sizes = []
    for norm, _hover, sel in TABS.values():
        got = [pics.get(g) for g in (norm, sel)]
        if any(im is None for im in got):
            return None
        sizes.append(pics[norm].size)
    if any(w < 100 or h < 30 for w, h in sizes):  # blanked-out placeholders
        return None
    if all(s == (185, 52) for s in sizes):
        return "E1"
    if all(s == (173, 59) for s in sizes):
        return "E2"
    return None


def generation(rom: bytes) -> Optional[str]:
    secs = AR.picture_sections(rom)
    if BG not in secs or any(g not in secs for pair in TABS.values() for g in pair):
        return None  # (before any picture is decoded)
    return _generation_of(pictures_of(secs))


class Skin:
    def __init__(self, secs: dict[str, list[bytes]], gen: str) -> None:
        pics = pictures_of(secs)
        self.gen, self.geo, self.col = gen, GEO[gen], COLOURS[gen]
        self.bg = pics[BG].convert("RGBA")
        if self.bg.size != (self.geo["w"], self.geo["h"]):
            self.bg = self.bg.resize((self.geo["w"], self.geo["h"]))
        self.tabs: dict[str, Any] = {}
        for label, (_norm, _hover, sel) in TABS.items():
            im = pics[sel]
            self.tabs[label] = im.convert("RGBA") if im is not None else None
        self.accent = AU._accent(self.bg) or (0, 170, 200)

    def fonts(self) -> dict[str, Font]:
        g = self.geo
        return {
            "title": AU._font("consola.ttf", g["ftitle"]),
            "head": AU._font("consola.ttf", g["fhead"]),
            "item": AU._font("consola.ttf", g["fitem"]),
            "value": AU._font("consola.ttf", g["fitem"]),
            "help": AU._font("consola.ttf", g["fhelp"]),
            "foot": AU._font("consola.ttf", g["ffoot"]),
        }


def _tab_of(name: str) -> Optional[str]:
    return NAME.get(" ".join(name.split()).lower())


def _draw_tabs(
    im: Image.Image, dr: ImageDraw.ImageDraw, skin: Skin, names: list[str], sel: Optional[str]
) -> None:
    """The frame already has the five buttons painted in their normal state, so only the selected
    one is pasted over it. A tab of the firmware's forms that has no button (Main, Security) gets
    nothing: the strip is the firmware's and it has five buttons, not six."""
    if sel is None:
        return
    art = skin.tabs.get(sel)
    if art is None:
        return
    geo = skin.geo
    order = list(TABS)
    if "tabs" in geo:
        for label, xy in zip(order, geo["tabs"]):
            if label == sel:
                im.paste(art, xy, art)
                break
    else:
        for label, cx in zip(order, geo["tabc"]):
            if label == sel:
                im.paste(art, (cx - art.width // 2, geo["taby"]), art)
                break


def _draw_page(
    skin: Skin,
    fonts: dict[str, Font],
    names: list[str],
    tab: Optional[str],
    title: str,
    rows: list[AU.Row],
    help_text: str,
) -> Image.Image:
    geo, col = skin.geo, skin.col
    im = skin.bg.copy()
    dr = ImageDraw.Draw(im)
    _draw_tabs(im, dr, skin, names, tab)

    ix0, iy0, ix1, _iy1 = geo["items"]
    hx0, hy0, hx1, hy1 = geo["help"]
    tx, ty = geo["title"]
    while dr.textlength(title, font=fonts["title"]) > ix1 - tx and " > " in title:
        title = "... > " + title.removeprefix("... > ").split(" > ", 1)[1]
    dr.text((tx, ty), title, font=fonts["title"], fill=col["title"])

    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y, ys = iy0, []
    for i, r in enumerate(rows):
        ys.append(y)
        if i == sel:
            dr.rectangle((ix0 - 12, y, ix1 + 8, y + geo["rowh"] - 2), fill=col["sel"])
            dr.rectangle((ix0 - 12, y, ix0 - 9, y + geo["rowh"] - 2), fill=skin.accent)
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
            if r.kind == "ref":
                dr.polygon(
                    [(ix0 - 10, at + 5), (ix0 - 10, at + 16), (ix0 - 2, at + 10.5)], fill=text
                )
            vw = dr.textlength(r.value, font=fonts["value"]) if r.value else 0
            prompt = r.prompt
            while prompt and dr.textlength(prompt, font=fonts["item"]) > ix1 - vw - 16 - ix0:
                prompt = prompt[:-1]
            dr.text((ix0, at + 3), prompt, font=fonts["item"], fill=text)
            if r.value:
                dr.text(
                    (ix1 - vw, at + 3),
                    r.value,
                    font=fonts["value"],
                    fill=col["seltext"] if on else col["value"],
                )

    if help_text:
        for i, line in enumerate(AU._wrap(help_text, fonts["help"], dr, hx1 - hx0)):
            if hy0 + i * (geo["fhelp"] + 4) > hy1:
                break
            dr.text((hx0, hy0 + i * (geo["fhelp"] + 4)), line, font=fonts["help"], fill=col["help"])
    if geo["legend"] is not None:  # the frames leave it out
        lx0, ly0, _lx1, ly1 = geo["legend"]
        y = ly0
        for line in LEGEND:
            if y > ly1:
                break
            dr.text((lx0, y), line, font=fonts["foot"], fill=col["foot"])
            y += geo["ffoot"] + 4
    return im.convert("RGB")


def pages(rom: bytes) -> list[tuple[str, Image.Image, str]]:
    """(name, picture, text) for every screen of this setup, in the order UefiSetup.screens()
    walks them, drawn in the firmware's own page."""
    secs = AR.picture_sections(rom)
    gen = _generation_of(pictures_of(secs))
    if gen is None:
        return []
    su = U.UefiSetup(rom)
    skin = Skin(secs, gen)
    fonts = skin.fonts()
    geo = skin.geo
    names = [n for n, _ in su.tabs]
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, _depth in AU._page_list(su):
        rows = AU.rows_of(su, su.forms[form_id][1], geo)
        chunks = AU._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            help_text = AU._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page(
                skin,
                fonts,
                names,
                _tab_of(su.tabs[tab][0]),
                name,
                chunk,
                help_text,
            )
            out.append((name, image, AU._text(name, chunk, help_text)))
    return out
