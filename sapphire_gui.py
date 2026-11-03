"""The Sapphire "Q-BIOS" setup look (the Sapphire motherboards of 2010-2013).

The firmware paints most of the page into one picture, module EFCB2FDB (800x600): the top band with
the SAPPHIRE logo, the web address and the Q-BIOS mark, the grey item panel, the narrower right
panel with the key legend printed in it, the round knob on the divider and the bottom band with
the three
monitor boxes. The seven tab buttons are separate pictures with the label baked in, in a grey and a
blue state. What this module draws is the tab row, the page title, the item rows and the help text -
the last two from the firmware's own strings, read by uefi_setup.
"""

from __future__ import annotations

from typing import Any, Optional

from PIL import Image, ImageDraw

import asrock_gui as AR
import asus_gui as AU
import uefi_setup as U

Font = Any

BG = "EFCB2FDB"

# the seven buttons, in the order the setup's own tabs come (the review of the Pure Black X58 names
# them Main, Performance, ... Boot, Security, and the forms come in that order too)
TABS = {
    "Main": ("0A872E6E", "71A2AE42"),
    "Performance": ("3F0DB4EA", "E25CAB1C"),
    "Advanced": ("008BED26", "F025907B"),
    "Chipset": ("01BEB6FC", "BAA17DDF"),
    "Boot": ("2FF39C5D", "C17A6FEF"),
    "Security": ("0C247F78", "3854CA91"),
    "Exit": ("9E23E5E9", "5550449B"),
}

# the form-set titles onto those seven labels: six match by name, and the one tab that is named
# after what it tunes (Memory / Frequency / CPU Configuration, OverClock) is the seventh button
NAME = {
    "main": "Main",
    "performance": "Performance",
    "memory configuration": "Performance",
    "frequency configuration": "Performance",
    "cpu configuration": "Performance",
    "overclock": "Performance",
    "advanced": "Advanced",
    "chipset": "Chipset",
    "boot": "Boot",
    "security": "Security",
    "save & exit": "Exit",
    "exit": "Exit",
}

# measured off the frame picture (module EFCB2FDB):
# item panel x 10-610 y 110-480, right panel x 625-790 with its legend printed at y 305-465,
# bottom band y 490-600. The frame leaves the tab row empty; the seven buttons are 800 px wide, the
# screen's width. Where the row and the items sit follows photos of the real setup (the Pure
# Platinum A85XT in overclockers.ru's review): the tabs stand on the panel's top edge, and a
# sub-menu
# shows only its own tab.
GEO: dict[str, dict[str, Any]] = {
    "S1": {
        "w": 800,
        "h": 600,
        "taby": 67,
        "tabx": 0,
        "title": (18, 46),
        "items": (24, 122, 578, 476),  # stops short of the knob the frame paints at x 590-640
        "valuex": 410,
        "help": (632, 124, 786, 296),  # the right panel's empty upper part
        "legend": None,
        "rowh": 19,
        "fsel": 15,
        "fhead": 14,
        "fitem": 14,
        "ftitle": 13,
        "fhelp": 13,
        "ffoot": 11,
        "foot": (0, 585),
    }
}

COLOURS: dict[str, dict[str, Any]] = {
    "S1": {
        "head": (26, 26, 26),
        "item": (26, 26, 26),
        "value": (18, 52, 96),
        "sel": (66, 128, 196),
        "edge": (16, 40, 70),
        "seltext": (255, 255, 255),
        "line": (150, 150, 150),
        "help": (30, 50, 170),
        "title": (230, 230, 230),
        "foot": (60, 60, 60),
    }
}


def pictures_of(secs: dict[str, list[bytes]]) -> dict[str, Any]:
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
    """S1, or None. The seven tab labels are baked into the art, so these role names are
    Sapphire's own; the frame picture has to be there as well."""
    if BG not in pics or pics[BG] is None:
        return None
    sizes = []
    for _label, (norm, sel) in TABS.items():
        a, b = pics.get(norm), pics.get(sel)
        if a is None or b is None:
            return None
        sizes.append(a.size)
    if not all(100 <= w <= 130 and h == 42 for w, h in sizes):
        return None
    return "S1"


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
        self.tabs: dict[str, tuple[Optional[Image.Image], Optional[Image.Image]]] = {}
        for label, (n, s) in TABS.items():
            self.tabs[label] = (
                pics[n].convert("RGBA") if pics.get(n) else None,
                pics[s].convert("RGBA") if pics.get(s) else None,
            )

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


def _draw_tabs(im: Image.Image, skin: Skin, sel: Optional[str], alone: bool) -> None:
    """The frame has no tab row painted in it, so the row is drawn here from the firmware's own
    button art: the grey state for every tab, the blue state for the current one; a sub-menu
    shows its own tab only."""
    geo = skin.geo
    x = geo["tabx"]
    for label in TABS:
        norm, selected = skin.tabs[label]
        art = selected if label == sel else norm
        if art is None:
            continue
        if label == sel or not alone:
            im.paste(art, (x, geo["taby"]), art)
        x += art.width


def _draw_page(
    skin: Skin,
    fonts: dict[str, Font],
    tab: Optional[str],
    title: str,
    rows: list[AU.Row],
    help_text: str,
    depth: int,
) -> Image.Image:
    geo, col = skin.geo, skin.col
    im = skin.bg.copy()
    _draw_tabs(im, skin, tab, depth > 0)
    dr = ImageDraw.Draw(im)

    ix0, iy0, ix1, _iy1 = geo["items"]
    hx0, hy0, hx1, hy1 = geo["help"]
    tx, ty = geo["title"]
    while dr.textlength(title, font=fonts["title"]) > ix1 - tx and " > " in title:
        title = "... > " + title.removeprefix("... > ").split(" > ", 1)[1]
    dr.text((tx, ty), title, font=fonts["title"], fill=col["title"])

    sel = next((i for i, r in enumerate(rows) if r.sel), None)
    y = iy0
    for i, r in enumerate(rows):
        # as on the real setup: no selection bar, the selected item is white
        text = col["seltext"] if i == sel else col["item"]
        if r.kind == "head":
            dr.text((ix0, y + 2), r.prompt, font=fonts["head"], fill=col["head"])
        elif r.kind == "sep":
            dr.line((ix0, y + 6, ix1, y + 6), fill=col["line"])
        else:
            if r.kind == "ref":
                dr.polygon([(ix0 - 11, y + 4), (ix0 - 11, y + 14), (ix0 - 4, y + 9)], fill=text)
            prompt = r.prompt
            limit = geo["valuex"] - 12 - ix0 if r.value else ix1 - ix0
            while prompt and dr.textlength(prompt, font=fonts["item"]) > limit:
                prompt = prompt[:-1]
            dr.text((ix0, y + 2), prompt, font=fonts["item"], fill=text)
            if r.value:
                dr.text(
                    (geo["valuex"], y + 2),
                    r.value,
                    font=fonts["value"],
                    fill=text if i == sel else col["value"],
                )
        y += r.h

    if help_text:
        for i, line in enumerate(AU._wrap(help_text, fonts["help"], dr, hx1 - hx0)):
            if hy0 + i * (geo["fhelp"] + 3) > hy1:
                break
            dr.text((hx0, hy0 + i * (geo["fhelp"] + 3)), line, font=fonts["help"], fill=col["help"])
    return im.convert("RGB")


def pages(rom: bytes) -> list[tuple[str, Image.Image, str]]:
    secs = AR.picture_sections(rom)
    gen = _generation_of(pictures_of(secs))
    if gen is None:
        return []
    su = U.UefiSetup(rom)
    skin = Skin(secs, gen)
    fonts = skin.fonts()
    geo = skin.geo
    height = geo["items"][3] - geo["items"][1]
    out: list[tuple[str, Image.Image, str]] = []
    for title, tab, form_id, depth in AU._page_list(su):
        rows = AU.rows_of(su, su.forms[form_id][1], geo)
        chunks = AU._split(rows, height)
        for n, chunk in enumerate(chunks, 1):
            help_text = AU._clean(su.str(next((r.help for r in chunk if r.sel and r.help), 0)))
            name = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
            image = _draw_page(
                skin,
                fonts,
                _tab_of(su.tabs[tab][0]),
                name,
                chunk,
                help_text,
                depth,
            )
            out.append((name, image, AU._text(name, chunk, help_text)))
    return out
