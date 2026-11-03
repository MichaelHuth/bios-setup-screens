"""
AMIBIOS 8 setup screens read from the ROM without running it, for boards whose chipset the
emulator does not know (VIA, SiS, NVIDIA ...). Reverse-engineered on an ASUS P4P800 (core 08.00,
setup v2.51) and checked against its emulated setup (ami8_setup): 68 of 70 option values agree,
the other two were mismatches of the comparison itself.

Layout of the data:
- Strings: the English "Multilanguage" module (id 21h, starting "GNALSU"): u32 at +8 is the base
  of a u16 table; string n is at base + table[n] (NUL-terminated, CR = new line).
- Setup pages: page scripts in the SLAB module (id 1Bh). Pages and item records are addressed
  relative to one base, found from the tab list (42 SSSS 01 PPPP 01 00, four to eight times, then
  00) whose pointers land on page starts (44 01 ...).
  Page ops: 00 end; 44 ff SSSS text (01: the title, 00: a heading); 43 01 a line, 43 00 a blank
  line; 41 IIII an item; 42 SSSS tt PPPP FFFF a sub-menu (tt 01: page PPPP; flag 80h: help
  follows, 20h: a condition follows); 45 ff SSSS VVVV an information line (value from code).
  Items: type (01 option, 02 date, 03 time, 06 number), prompt, location (bit address in the
  CMOS in bits 0-11, width in bits 12-15), flags (80h: help follows, 10h: a condition, a count and
  that many words follow, 40h: a routine that supplies the options follows), kind (02: a list
  follows: count, then the option strings, FFFFh unused; the value is the index).
- Defaults: the CMOS image after the "$SDS" header (the list of CMOS indexes it names, then six
  bytes), which POST loads into an empty CMOS; later builds: the "$SDSPOST" block (from 5 bytes
  before it).
Items whose visibility or options depend on code (e.g. IDE devices) cannot be evaluated here:
all are shown, values found only at run time are left open.
"""

from __future__ import annotations

import bisect
import collections
import re
import struct

import ami
from textscreen import Screen

TITLE_ATTR, BAR_ATTR, BAR_SEL_ATTR = 0x0F, 0x17, 0x71
BOX_ATTR, HILITE_ATTR, COPY_ATTR = 0x71, 0x7F, 0x17
LEFT, RIGHT, TOP, BOTTOM = 0, 54, 2, 23  # box columns and rows
VALUE_COL = 36
MENU_ATTR, MENU_TITLE_ATTR, MENU_ITEM_ATTR, MENU_SEL_ATTR = 0x1F, 0x1F, 0x1E, 0x4F  # "menu" layout
MAX_DEPTH = 2
H = bytes.fromhex


def _write(s: Screen, col: int, row: int, text: str, attr: int) -> None:
    s.write(col, row, text.encode("cp437", "replace"), attr)


class Strings:
    def __init__(self, data: bytes):
        self.d = data
        self.base = struct.unpack_from("<I", data, 8)[0]
        self.n = struct.unpack_from("<H", data, self.base)[0] // 2
        self.offs = struct.unpack_from(f"<{self.n}H", data, self.base)

    def __call__(self, i: int) -> str:
        if not 0 <= i < self.n:
            return ""
        o = self.base + self.offs[i]
        return self.d[o : self.d.find(b"\0", o)].decode("cp437").replace("\r", "\n")


def _parts(rom: bytes) -> tuple[bytes, bytes, bytes] | None:
    """(English strings, SLAB data, Setup Client data), or None."""
    try:
        info, modules = ami.extract(rom)
    except Exception:
        return None
    if info.get("version") != "0800":
        return None
    lang = next(
        (
            m["data"]
            for m in modules
            if m.get("id") == 0x21 and (m.get("data") or b"").startswith(b"GNALSU")
        ),
        None,
    )
    slab = next((m["data"] for m in modules if m.get("id") == 0x1B and m.get("data")), None)
    client = next((m["data"] for m in modules if m.get("id") == 0x04 and m.get("data")), b"")
    if lang is None or slab is None:
        return None
    return lang, slab, client


def _find_base(slab: bytes) -> tuple | None:
    """(base, offset of the tab or main-menu list, page pointers, layout), or None. Layout "tabs":
    the menu bar of a tab list (42 SSSS 01 PPPP 01 00, four to eight times, then 00). Layout
    "menu" (later builds, an Award-style main menu): no tab list; the base is the one most
    sub-menu entries anywhere (42 SSSS 01 PPPP ...) point to page starts from, and the main menu
    is the longest run of sub-menu entries (42 SSSS 01 PPPP FFFF ...) that all point to a page
    (these pages need not start with a title: after the 00 that ends the one before)."""
    starts = {m.start() for m in re.finditer(re.escape(H("4401")), slab)}
    entry = re.escape(H("42")) + b".." + re.escape(H("01")) + b".." + re.escape(H("0100"))
    best = None
    for m in re.finditer(b"(?:" + entry + b"){4,8}" + re.escape(H("00")), slab, re.S):
        ptrs = [
            struct.unpack_from("<H", slab, m.start() + k + 4)[0]
            for k in range(0, len(m.group()) - 1, 8)
        ]
        for base in {s - q for s in starts for q in ptrs}:
            hits = sum(
                1
                for p in ptrs
                if 0 <= base + p < len(slab)
                and (base + p in starts or (slab[base + p] == 0x43 and base + p + 2 in starts))
            )
            if hits >= len(ptrs) - 1 and (best is None or hits > best[3]):
                best = (base, m.start(), ptrs, hits)
    if best:
        return best[:3] + ("tabs",)
    targets = [
        struct.unpack_from("<H", slab, m.start() + 4)[0]
        for m in re.finditer(re.escape(H("42")) + b".." + re.escape(H("01")), slab, re.S)
    ]
    votes = collections.Counter(s - q for s in starts for q in set(targets))
    if not votes:
        return None
    base, hits = votes.most_common(1)[0]
    if hits < 6:
        return None
    runs = []
    for m in re.finditer(re.escape(H("42")), slab):
        o, ptrs = m.start(), []
        while o + 8 <= len(slab) and slab[o] == 0x42 and slab[o + 3] == 0x01:
            ptrs.append(struct.unpack_from("<H", slab, o + 4)[0])
            fl = struct.unpack_from("<H", slab, o + 6)[0]
            o += 8 + (2 if fl & 0x80 else 0) + (2 if fl & 0x20 else 0) + (2 if fl & 0x04 else 0)
        if len(ptrs) >= 4 and sum(
            1
            for p in ptrs
            if 0 < base + p < len(slab)
            and slab[base + p - 1] == 0
            and 0x41 <= slab[base + p] <= 0x45
        ) == len(ptrs):
            runs.append((len(ptrs), -m.start(), ptrs))
    if not runs:
        return None
    # the main menu is the run from which most pages can be reached through sub-menu
    # entries (the longest may be a sub-menu: EVGA P55's IDE menu with twelve drives)
    # (pages start at a title, 44 01, or - in this layout - wherever an entry points)
    entries = [
        (m.start(), base + struct.unpack_from("<H", slab, m.start() + 4)[0])
        for m in re.finditer(re.escape(H("42")) + b".." + re.escape(H("01")), slab, re.S)
    ]
    sorted_starts = sorted(starts | {t for _, t in entries if 0 < t < len(slab)})

    def page_of(pos: int) -> int | None:
        i = bisect.bisect_right(sorted_starts, pos) - 1
        return sorted_starts[i] if i >= 0 else None

    links = collections.defaultdict(set)  # page -> pages its sub-menu entries open
    for at, target in entries:
        page = page_of(at)
        if page is not None:
            links[page].add(target + 2 if target not in starts and target + 2 in starts else target)

    def reach(ptrs: list[int]) -> set[int]:
        seen: set[int] = set()
        todo = [base + p for p in ptrs]
        while todo and len(seen) < 1000:
            page = todo.pop()
            if page in seen:
                continue
            seen.add(page)
            todo.extend(links.get(page, set()) | links.get(page + 2, set()))
        return seen

    # (only whole runs: the tail of one starts at each of its entries)
    spans = [(-r[1], -r[1] + 10 * r[0]) for r in runs]
    runs = [r for r in runs if not any(a < -r[1] < b for a, b in spans)]
    reached = [reach(r[2]) for r in runs]
    pages = [{page_of(-r[1]), (page_of(-r[1]) or 0) - 2} for r in runs]
    # (a run on a page another run leads to, but not back, is a sub-menu: Standard CMOS
    # Features' drives)
    roots = [
        k
        for k in range(len(runs))
        if not any(
            pages[k] & reached[j] and not pages[j] & reached[k] for j in range(len(runs)) if j != k
        )
    ]
    _, _, at, ptrs = max(
        (len(reached[k]), runs[k][0], runs[k][1], runs[k][2]) for k in (roots or range(len(runs)))
    )
    at = -at
    return base, at, ptrs, "menu"


def _defaults_at(slab: bytes) -> int | None:
    """Offset of the default CMOS image: after a "$SDS" header (four zero bytes, four more,
    a list of u16 CMOS indexes ending in 0000, six bytes). Later builds keep the image POST
    loads in a "$SDSPOST" block instead, whose header covers the clock bytes (the image starts
    5 bytes before it: the floppy type, CMOS 10h, follows the header)."""
    post = slab.find(b"$SDSPOST")
    if post >= 5:
        return post - 5
    for m in re.finditer(re.escape(b"$SDS"), slab):
        o = m.start()
        if slab[o + 4 : o + 8] != bytes(4):
            continue
        q = o + 12
        while q + 2 <= len(slab) and slab[q : q + 2] != bytes(2):
            q += 2
        return q + 2 + 6
    return None


def is_amibios8_static(rom: bytes) -> bool:
    parts = _parts(rom)
    return parts is not None and _find_base(parts[1]) is not None


class AmiBios8Static:
    def __init__(self, rom: bytes):
        parts = _parts(rom)
        if parts is None:
            raise ValueError("not an AMIBIOS 8 image with a SLAB setup module")
        lang, self.slab, client = parts
        found = _find_base(self.slab)
        if found is None:
            raise ValueError("the AMIBIOS 8 setup pages were not found in the SLAB module")
        self.base, tabs_at, ptrs, self.layout = found
        self.S = Strings(lang)
        self.title = next(
            (self.S(i) for i in range(self.S.n) if self.S(i).startswith("CMOS Setup Utility")),
            "CMOS Setup Utility",
        )
        image = _defaults_at(self.slab)
        self.defaults = (self.slab[image : image + 0x200] if image is not None else b"").ljust(
            0x200, b"\xff"
        )
        m = re.search(rb"v\d+\.\d+ \(C\)Copyright[ -~]+", client)
        self.copyright = m.group().decode() if m else "(C)Copyright American Megatrends, Inc."
        legends = [
            self.S(i)
            for i in range(self.S.n)
            if "Select Screen" in self.S(i) and "F10" in self.S(i)
        ]
        self.legend_sub = next(
            (t for t in legends if "Sub Screen" in t), legends[0] if legends else ""
        )
        self.legend_opt = next((t for t in legends if "Change Option" in t), self.legend_sub)
        # the main menu of the "menu" layout: the run of sub-menus and the actions after it
        self.main = self._page(tabs_at - self.base) if self.layout == "menu" else []
        if self.layout == "menu":
            self.tabs = [(e[1].strip(), e[2]) for e in self.main if e[0] == "sub"]
        else:
            self.tabs = [
                (self.S(struct.unpack_from("<H", self.slab, tabs_at + 8 * k + 1)[0]).strip(), p)
                for k, p in enumerate(ptrs)
            ]

    # --- reading ------------------------------------------------------------------------------

    def _value(self, loc: int) -> int:
        width, bit = loc >> 12, loc & 0xFFF
        width = width or 16
        word = int.from_bytes(self.defaults[bit >> 3 : (bit >> 3) + 3], "little")
        return word >> (bit & 7) & ((1 << width) - 1)

    def _item(self, ref: int) -> tuple | None:
        """(prompt, value text or None, help string id)."""
        slab, S = self.slab, self.S
        o = self.base + ref
        if not 0 <= o < len(slab) - 12:
            return None
        typ = slab[o]
        prompt = struct.unpack_from("<H", slab, o + 1)[0]
        if typ == 0x03:  # time: hour, minute, second locations, flags, help
            return S(prompt).strip(), "hh:mm:ss", struct.unpack_from("<H", slab, o + 10)[0]
        if typ == 0x02:  # date: four locations, flags, help
            return S(prompt).strip(), "ddd mm/dd/yyyy", struct.unpack_from("<H", slab, o + 12)[0]
        if typ == 0x07:  # language: the language's name, help
            name, hlp = (
                struct.unpack_from("<H", slab, o + 5)[0],
                struct.unpack_from("<H", slab, o + 9)[0],
            )
            return S(prompt).strip(), S(name).strip(), hlp
        if typ == 0x06:  # a number: location, flags, minimum, maximum
            loc = struct.unpack_from("<H", slab, o + 3)[0]
            return S(prompt).strip(), str(self._value(loc)), None
        if typ != 0x01:
            return S(prompt).strip(), None, None
        prompt, loc, flags, kind = struct.unpack_from("<HHBB", slab, o + 1)
        q, hlp = o + 7, None
        if flags & 0x80:
            hlp = struct.unpack_from("<H", slab, q)[0]
            q += 2
        if flags & 0x10:  # a condition: u16, a count (bits 0-6), that many u16 more
            q += 3 + 2 * (slab[q + 2] & 0x7F)
        if flags & 0x40:
            q += 2
        if kind != 2:
            return S(prompt).strip(), "", hlp
        count = slab[q]
        opts = struct.unpack_from(f"<{count}H", slab, q + 1)
        v = self._value(loc)
        text = S(opts[v]).strip() if v < count and opts[v] != 0xFFFF else ""
        return S(prompt).strip(), text, hlp

    def _page(self, ptr: int) -> list[tuple]:
        """Entries of a page: ("text", s) ("line",) ("blank",) ("item", prompt, value, help)
        ("sub", prompt, target page, help) ("info", label)."""
        slab, S = self.slab, self.S
        o = self.base + ptr
        out: list[tuple] = []
        for _ in range(200):
            if not 0 <= o < len(slab):
                break
            op = slab[o]
            if op == 0x00:
                break
            if op == 0x44:
                sid = struct.unpack_from("<H", slab, o + 2)[0]
                if slab[o + 1] == 0x00:
                    out.append(("text", S(sid).rstrip()))
                o += 4
            elif op == 0x43:
                out.append(("line",) if slab[o + 1] else ("blank",))
                o += 2
            elif op == 0x41:
                it = self._item(struct.unpack_from("<H", slab, o + 1)[0])
                if it:
                    out.append(("item",) + it)
                o += 3
            elif op == 0x45:
                out.append(("info", S(struct.unpack_from("<H", slab, o + 2)[0]).rstrip()))
                o += 6
            elif op == 0x42:
                sid, t, tgt, fl = struct.unpack_from("<HBHH", slab, o + 1)
                hlp = struct.unpack_from("<H", slab, o + 8)[0] if fl & 0x80 else None
                out.append(
                    ("sub" if t == 1 else "action", S(sid).rstrip(), tgt if t == 1 else None, hlp)
                )
                o += 8 + (2 if fl & 0x80 else 0) + (2 if fl & 0x20 else 0) + (2 if fl & 0x04 else 0)
            else:
                break
        return out

    # --- drawing ------------------------------------------------------------------------------

    def _render(
        self, tab: int, entries: list[tuple], start: int = 0, top: bool = True
    ) -> tuple[Screen, bool]:
        """The page as AMIBIOS 8 draws it (help of the first entry with one); and whether
        entries are left for a further screen."""
        s = Screen(80, 25)
        title = "BIOS SETUP UTILITY"
        _write(s, (80 - len(title)) // 2, 0, title, TITLE_ATTR)
        for col in range(80):
            s.put(col, 1, ord(" "), BAR_ATTR)
        col = 2
        for k, (name, _) in enumerate(self.tabs):
            if top or k == tab:  # a sub-page shows only its tab's name
                _write(s, col, 1, name, BAR_SEL_ATTR if top and k == tab else BAR_ATTR)
            col += len(name) + 4
        for row in range(TOP, BOTTOM + 1):
            for c in range(80):
                s.put(c, row, ord(" "), BOX_ATTR)
        s.put(0, TOP, 0xDA, BOX_ATTR)
        s.put(79, TOP, 0xBF, BOX_ATTR)
        s.put(RIGHT, TOP, 0xC2, BOX_ATTR)
        s.put(0, BOTTOM, 0xC0, BOX_ATTR)
        s.put(79, BOTTOM, 0xD9, BOX_ATTR)
        s.put(RIGHT, BOTTOM, 0xC1, BOX_ATTR)
        for c in range(1, 79):
            if c != RIGHT:
                s.put(c, TOP, 0xC4, BOX_ATTR)
                s.put(c, BOTTOM, 0xC4, BOX_ATTR)
        for row in range(TOP + 1, BOTTOM):
            s.put(0, row, 0xB3, BOX_ATTR)
            s.put(RIGHT, row, 0xB3, BOX_ATTR)
            s.put(79, row, 0xB3, BOX_ATTR)
        _write(s, (80 - len(self.copyright)) // 2, 24, self.copyright, COPY_ATTR)
        row, help_id, first, has_items, k = TOP + 1, None, True, False, start
        while k < len(entries) and row < BOTTOM:
            e = entries[k]
            kind = e[0]
            if kind == "text":
                for line in e[1].split("\n"):
                    _write(s, 2, row, line[:51], BOX_ATTR)
                    row += 1
            elif kind == "line":
                for c in range(2, RIGHT - 1):
                    s.put(c, row, 0xC4, BOX_ATTR)
                row += 1
            elif kind == "blank":
                row += 1
            elif kind == "info":
                _write(s, 2, row, e[1][:51], BOX_ATTR)
                row += 1
            elif kind == "item":
                prompt, value, hlp = e[1], e[2], e[3]
                attr = HILITE_ATTR if first else BOX_ATTR
                _write(s, 2, row, prompt[:33], attr)
                if value:  # (values supplied by code at run time stay open)
                    _write(s, VALUE_COL, row, f"[{value}]"[: RIGHT - VALUE_COL - 1], BOX_ATTR)
                if first:
                    help_id, first = hlp, False
                has_items = True
                row += 1
            elif kind in ("sub", "action"):
                s.put(2, row, 0x10, BOX_ATTR)
                _write(s, 4, row, e[1][:49], HILITE_ATTR if first else BOX_ATTR)
                if first:
                    help_id, first = e[3], False
                row += 1
            k += 1
        if help_id is not None:
            for i, line in enumerate(self.S(help_id).split("\n")[:11]):
                _write(s, RIGHT + 2, TOP + 1 + i, line[:22], BOX_ATTR)
        legend = (self.legend_opt if has_items else self.legend_sub).split("\n")
        for i, line in enumerate(legend):
            _write(s, RIGHT + 1, BOTTOM - len(legend) - 1 + i, line[:24], BOX_ATTR)
        return s, k < len(entries)

    # --- the Award-style layout of later builds -------------------------------------------------

    def _frame(self, s: Screen, top: int, bottom: int, split: int | None) -> None:
        """A double-line box on the blue screen, optionally split by a vertical line."""
        for row in range(25):
            for c in range(80):
                s.put(c, row, ord(" "), MENU_ATTR)
        _write(s, (80 - len(self.title)) // 2, 0, self.title, MENU_TITLE_ATTR)
        for c in range(1, 79):
            s.put(c, top, 0xCD, MENU_ATTR)
            s.put(c, bottom, 0xCD, MENU_ATTR)
        for row in range(top + 1, bottom):
            s.put(0, row, 0xBA, MENU_ATTR)
            s.put(79, row, 0xBA, MENU_ATTR)
        s.put(0, top, 0xC9, MENU_ATTR)
        s.put(79, top, 0xBB, MENU_ATTR)
        s.put(0, bottom, 0xC8, MENU_ATTR)
        s.put(79, bottom, 0xBC, MENU_ATTR)
        if split is not None:
            s.put(split, top, 0xD1, MENU_ATTR)
            s.put(split, bottom, 0xCF, MENU_ATTR)
            for row in range(top + 1, bottom):
                s.put(split, row, 0xB3, MENU_ATTR)

    def _legend(self, s: Screen, row: int, main: bool) -> None:
        legends = [self.S(i) for i in range(self.S.n) if "F10:Save" in self.S(i)]
        legend = next((t for t in legends if ("F8" in t) == main), legends[0] if legends else "")
        for i, line in enumerate(legend.split("\n")[:2]):
            _write(s, 1, row + i, line.strip().center(78)[:78], MENU_ATTR)

    def _render_main(self) -> Screen:
        """The main menu: sub-menus in the left column, the other entries in the right one."""
        s = Screen(80, 25)
        self._frame(s, 1, 20, 40)
        subs = [e for e in self.main if e[0] == "sub"]
        rest = [e for e in self.main if e[0] in ("action", "item")]
        for col, entries in ((2, subs), (42, rest)):
            for k, e in enumerate(entries[:9]):
                row = 2 + 2 * k
                if e[0] == "sub":
                    s.put(col, row, 0x10, MENU_ITEM_ATTR)
                _write(
                    s,
                    col + 2,
                    row,
                    e[1].strip()[:35],
                    MENU_SEL_ATTR if e is self.main[0] else MENU_ITEM_ATTR,
                )
        for c in range(1, 79):
            s.put(c, 23, 0xCD, MENU_ATTR)
        self._legend(s, 21, True)
        if self.main and self.main[0][3] is not None:
            _write(
                s,
                1,
                24,
                self.S(self.main[0][3]).replace("\n", " ").strip().center(78)[:78],
                MENU_ATTR,
            )
        return s

    def _render_page(self, name: str, entries: list[tuple], start: int = 0) -> tuple[Screen, bool]:
        """A page: its name under the title, entries and values on the left, the first entry's
        help on the right ("Item Help"), the keys at the bottom."""
        s = Screen(80, 25)
        self._frame(s, 2, 22, 56)
        _write(s, (80 - len(name)) // 2, 1, name, MENU_ATTR)
        _write(s, 63, 3, "Item Help", MENU_ATTR)
        for c in range(57, 79):
            s.put(c, 4, 0xC4, MENU_ATTR)
        row, help_id, first, k = 3, None, True, start
        while k < len(entries) and row < 22:
            e = entries[k]
            kind = e[0]
            if kind in ("text", "info"):
                for line in e[1].split("\n"):
                    if row < 22:
                        _write(s, 2, row, line[:53], MENU_ATTR)
                        row += 1
            elif kind == "line":
                for c in range(2, 55):
                    s.put(c, row, 0xC4, MENU_ATTR)
                row += 1
            elif kind == "blank":
                row += 1
            elif kind == "item":
                _write(s, 2, row, e[1][:30], MENU_SEL_ATTR if first else MENU_ITEM_ATTR)
                if e[2]:
                    _write(s, 33, row, f"[{e[2]}]"[:22], MENU_ATTR)
                if first:
                    help_id, first = e[3], False
                row += 1
            else:  # sub-menus and actions
                s.put(2, row, 0x10, MENU_ITEM_ATTR)
                _write(s, 4, row, e[1].strip()[:50], MENU_SEL_ATTR if first else MENU_ITEM_ATTR)
                if first:
                    help_id, first = e[3], False
                row += 1
            k += 1
        if help_id is not None:
            for i, line in enumerate(self.S(help_id).split("\n")[:16]):
                _write(s, 58, 5 + i, line[:21], MENU_ATTR)
        self._legend(s, 23, False)
        return s, k < len(entries)

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, note)]: each tab (or the main menu and its entries), then the pages
        their sub-menus open (two levels), long pages continued on further screens."""
        out, seen = [], set()
        menu = self.layout == "menu"

        def add(tab: int, title: str, ptr: int, depth: int) -> None:
            if ptr in seen:
                return
            seen.add(ptr)
            # labels are padded for the value column ("SATA3          :")
            title = " > ".join(" ".join(part.split()).rstrip(" :") for part in title.split(" > "))
            entries = self._page(ptr)
            start, n = 0, 1
            while True:
                if menu:
                    screen, more = self._render_page(
                        title.rsplit(" > ", maxsplit=1)[-1], entries, start
                    )
                else:
                    screen, more = self._render(tab, entries, start, depth == 0)
                out.append((title if n == 1 else f"{title} ({n})", screen, "static"))
                if not more:
                    break
                start, n = start + 18, n + 1
            if depth < MAX_DEPTH:
                for e in entries:
                    if e[0] == "sub" and e[2] is not None:
                        add(tab, f"{title} > {e[1].strip(' :')}", e[2], depth + 1)

        if menu:
            out.append(("Main Menu", self._render_main(), "static"))
        for k, (name, ptr) in enumerate(self.tabs):
            add(k, name, ptr, 0)
        return out
