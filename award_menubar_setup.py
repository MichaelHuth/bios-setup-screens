"""
Rebuild the menu-bar setup screens of Phoenix-Award BIOS 6.00PG (Main / Advanced / ... / Exit
along the top, values in brackets, Item Help panel on the right), as used on ASUS boards around
2002-2004, from a full flash image.

Reverse-engineered from an ASUS A7N8X 2.0 Deluxe BIOS (rev. 1007, nForce2) and checked against
the screenshots in the board's manual:
- the item tables are those of 6.00PG (award6_setup), but labels, option lists and help texts
  are text IDs (section << 8 | index) into a language module (_EN_CODE.BIN), and the screen
  script command 15h prints such a text; texts are scripts themselves, and their sub-script
  calls address the language module;
- the extension module (awardext.rom) sets "mov si,list / mov [bp+302],si / mov si,bar /
  mov [bp+304],si": bar is a table of 3-byte records (page, tab script in F000) ending where the
  item-table list starts, page FFh = unused; a tab is shown when its page has items;
- frame: title row, the bar on row 1 (from column 2; tabs in color 4, the selected one in
  color 7), box rows 2-22 split at column 54 for the Item Help panel, key help on rows 23-24;
  a sub-menu shows only the tab it belongs to, its title centered on row 3 above a line;
- page layout: items with pos & 1Fh = page, sorted by line ((pos >> 5) & 3Fh), one row each
  from the top of the box (row 3, or 5 in a sub-menu); flag 0010h adds an empty row before an
  item, flags 0008h/8000h hide it; "►" before items that open a page ((pos >> 11) & 1Fh);
  label at column 5, value in brackets with the text at column 36 (item column 3 + 21h);
- items linked in a "$SpeXY" table (word count, then (item, parent) pairs) share their parent's
  row and are drawn where the label script leaves the cursor, without brackets (date and time);
- option lists are texts whose entries end in 00h or 01h; colors come from an 8-entry scheme.
The value column is adjusted per page at run time (a few pages draw values four columns further
left); that adjustment is not reproduced.
"""

from __future__ import annotations

import datetime
import functools
import re
import struct
import textwrap
from collections.abc import Iterator

import award_setup as a
import award6_setup
import lzh
from textscreen import Screen

# mov si,list / mov [bp+X],si / mov si,bar / mov [bp+X+2],si (X = 302h; ASUS P4GE-MX: 315h)
BAR_SETUP = re.compile(rb"\xbe(..)\x89\xb6(..)\xbe(..)\x89\xb6(..)", re.S)
TITLES = (b"Phoenix - AwardBIOS CMOS Setup Utility", b"Phoenix - Award BIOS CMOS Setup Utility")
LINKS = b"$SpeXY"
# scheme entries: 0 text, 1 selected label, 2 selected value, 3 title/keys, 4 bar, 5 -,
# 6 status (grey), 7 selected tab
SCHEME = [0x71, 0x7F, 0x07, 0x30, 0x17, 0x70, 0x78, 0x71]
LABEL_COL, VALUE_COL, BOTTOM = 5, 36, 21
CLOCK = datetime.datetime(2000, 1, 1, 0, 0, 0)  # shown in the date/time fields (RTC at run time)
HELP_COL, HELP_WIDTH = 56, 22
MENU_LEVEL = 0x0148  # "Menu Level" in the A7N8X's language module (found by its text)


def _u16(b: bytes) -> int:
    return struct.unpack("<H", b)[0]


def _language_module(image: bytes) -> bytes | None:
    for m in lzh.find_modules(image):
        if re.fullmatch(r"_[A-Z]{2}_CODE\.BIN", m["name"].upper()):
            try:
                return lzh.decompress(
                    image[m["data_start"] : m["data_start"] + m["packed"]],
                    m["size"],
                    m["method"].encode(),
                )
            except Exception:
                return None
    return None


def is_menubar_award(image: bytes) -> bool:
    return b"awardext" in image.lower() and b"_CODE.BIN" in image.upper()


class AwardMenuBar:
    def __init__(self, image: bytes):
        system, ext = award6_setup._modules(image)
        lang = _language_module(image)
        m = next(
            (
                m
                for m in BAR_SETUP.finditer(ext)
                if 0x300 <= _u16(m.group(2)) < 0x400 and _u16(m.group(4)) == _u16(m.group(2)) + 2
            ),
            None,
        )
        # the frame script with the title: in awardext, or in the language module (ASUS
        # M2NBP-VM, 2007)
        self.title = next((t for t in TITLES if t in ext or (lang and t in lang)), None)
        if lang is None or not m or self.title is None:
            raise ValueError(
                "not a Phoenix-Award menu-bar setup (needs awardext with the "
                "menu bar and a language module)"
            )
        self.system, self.seg = system, system[len(system) - 0x10000 :]
        self.ext = ext + bytes(max(0, 0x10000 - len(ext)))
        self.lang = lang + bytes(max(0, 0x10000 - len(lang)))
        self.list_ptr, self.bar_ptr = _u16(m.group(1)), _u16(m.group(3))
        self.frame_data = ext if self.title in ext else self.lang
        self.frame = self._frame_script(self.frame_data)
        self.items = self._items()
        self.links = self._links()
        self.tabs = self._tabs()
        self.parents = self._parents()

    # --- data ---------------------------------------------------------------------------

    def _frame_script(self, ext: bytes) -> int:
        """The frame script: color, goto(0,0), a row of spaces, goto, the title ..."""
        assert self.title is not None
        title = ext.find(self.title)
        start = ext.rfind(b"\x05\x00\x00", max(0, title - 120), title)
        if start <= 0:
            raise ValueError("menu-bar frame not found in the extension or language module")
        return start - 1 if ext[start - 1] <= 0x14 else start

    def _items(self) -> dict[int, list[tuple[int, int]]]:
        """page -> [(line, entry)] in table order."""
        seg, p = self.seg, self.list_ptr
        pages: dict[int, list[tuple[int, int]]] = {}
        while p + 6 <= len(seg):
            start, end = struct.unpack_from("<HH", seg, p)
            if start == 0xFFFF or not start < end or (end - start) % a.ITEM_SIZE:
                break
            for e in range(start, end, a.ITEM_SIZE):
                pos = self._word(e + 0x11)
                pages.setdefault(pos & 0x1F, []).append(((pos >> 5) & 0x3F, e))
            p += 6
        return pages

    def _links(self) -> dict[int, int]:
        """item -> parent item for fields drawn on another item's row (date, time)."""
        links, i = {}, self.seg.find(LINKS)
        while i >= 0:
            count = self._word(i + 6)
            for k in range(count):
                item, parent = struct.unpack_from("<HH", self.seg, i + 8 + 4 * k)
                links[item] = parent
            i = self.seg.find(LINKS, i + 1)
        return links

    def _tabs(self) -> list[tuple[int, int]]:
        """[(page, tab script)] of the menu bar, only tabs whose page has items."""
        tabs, p = [], self.bar_ptr
        while p < self.list_ptr - 2:
            page, script = self.seg[p], self._word(p + 1)
            if page <= 0x1F and self._visible(page):
                tabs.append((page, script))
            p += 3
        return tabs

    def _parents(self) -> dict[int, tuple[int, int]]:
        """sub-menu page -> (opening item, tab page)."""
        out: dict[int, tuple[int, int]] = {}
        todo = [page for page, _ in self.tabs]
        tab_of = {page: page for page in todo}
        while todo:
            page = todo.pop(0)
            for _, e in self.items.get(page, []):
                target = self._word(e + 0x11) >> 11
                if target and target not in out and target not in tab_of and self._visible(target):
                    out[target] = (e, tab_of[page])
                    tab_of[target] = tab_of[page]
                    todo.append(target)
        return out

    def _word(self, off: int) -> int:
        return struct.unpack_from("<H", self.seg, off)[0]

    def _hidden(self, e: int) -> bool:
        return bool(self._word(e) & 0x8008)

    def _visible(self, page: int) -> bool:
        return any(not self._hidden(e) for _, e in self.items.get(page, []))

    def text(self, ident: int) -> str:
        """A text of the language module as plain text (control codes dropped)."""
        off = self._interp(Screen()).lang_offset(ident)
        if off is None:
            return ""
        out: list[str] = []
        i = off
        while self.lang[i] and len(out) < 300:
            c = self.lang[i]
            if c >= 0x20:
                out.append(chr(c))
            elif c == 0x0B:
                out.append("\n")
            elif c in (0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x13):
                i += 1
            elif c in (0x04,):
                i += 4
            elif c in (0x05, 0x14, 0x15):
                i += 2
            i += 1
        return "".join(out)

    def _text_id(self, text: str) -> int | None:
        """The ID of the language module's text that starts with text (the usual one first)."""
        if self.text(MENU_LEVEL).startswith(text):
            return MENU_LEVEL
        lang = self.lang
        for section in range(min(struct.unpack_from("<H", lang, 0x10)[0], 64)):
            table = struct.unpack_from("<H", lang, 0x12 + 2 * section)[0]
            for index in range(min(struct.unpack_from("<H", lang, table)[0], 256)):
                if self.text(section << 8 | index).startswith(text):
                    return section << 8 | index
        return None

    def label(self, e: int) -> str:
        return self.text(self._word(e + 2)).strip()

    def options(self, e: int) -> list[str]:
        off = self._interp(Screen()).lang_offset(self._word(e + 0x0B))
        if off is None:
            return []
        entries, current, i = [], bytearray(), off
        for _ in range(self.seg[e + 0x0F] + 1):
            while self.lang[i] not in (0, 1):
                current.append(self.lang[i])
                i += 1
            entries.append(current.decode("latin-1"))
            current, i = bytearray(), i + 1
        return entries

    def page_titles(self) -> dict[int, str]:
        titles = {page: self._tab_text(script) for page, script in self.tabs}
        for page, (e, _) in self.parents.items():
            titles[page] = self.label(e)
        return titles

    def _tab_text(self, script: int) -> str:
        m = re.match(rb" ?\x15(..)\x00", self.seg[script : script + 5], re.S)
        return self.text(struct.unpack("<H", m.group(1))[0]).strip() if m else "?"

    def clock_fields(self, page: int) -> dict[int, str]:
        """Date/time fields (RTC registers, F8h at +5, linked to a parent row): sample values,
        as the BIOS shows the running clock."""
        groups: dict[int, list[int]] = {}
        for _, e in sorted(self.items.get(page, [])):
            parent = self.links.get(e)
            if parent is not None and self.seg[parent + 5] == 0xF8:
                groups.setdefault(parent, []).append(e)
        out = {}
        for parent, fields in groups.items():
            rest = [e for e in fields if e != parent]
            if self.options(parent)[:1] and self.options(parent)[0].strip().endswith(","):
                out[parent] = CLOCK.strftime("%a,")  # weekday, then month, day, year
                values = [CLOCK.strftime("%b"), f"{CLOCK.day:02d}", str(CLOCK.year)]
            else:
                rest = fields  # hour (the parent), minute, second
                values = [f"{CLOCK.hour:02d}", f"{CLOCK.minute:02d}", f"{CLOCK.second:02d}"]
            out.update(zip(rest, values))
        return out

    def value(self, e: int, defaults: str = "setup") -> str | None:
        flags = self._word(e)
        mask = self._word(e + 9)
        if not mask or flags & 0x0004 or mask == 0xFFFF:
            return None
        default = self._word(e + (0x15 if defaults == "setup" else 0x13))
        shift = (mask & -mask).bit_length() - 1
        index, maximum = (default & mask) >> shift, self.seg[e + 0x0F]
        if flags & 0x0100 or not self._word(e + 0x0B) or self._word(e + 0x0B) == 1:
            if self._word(e + 0x0B) == 1:  # 0001: Disabled/Enabled
                return ["Disabled", "Enabled"][index & 1]
            return str(index).rjust(len(str(maximum))) if flags & 0x0100 else None
        options = self.options(e)
        return (options[index] or None) if index < len(options) else None

    # --- drawing ------------------------------------------------------------------------

    def _interp(self, screen: Screen) -> a.Interpreter:
        it = a._make(self.system, screen)
        it.lang = self.lang
        it.ops = dict(it.ops)
        it.ops[0x15] = ("lang", 2, -1)
        it.scheme = list(SCHEME)
        it.attr = SCHEME[0]
        return it

    @staticmethod
    def _write(it: a.Interpreter, col: int, row: int, text: str, attr: int) -> None:
        it.col, it.row, it.attr = col, row, attr
        for ch in text.encode("cp437", "replace"):
            it.putc(ch)

    def _draw_bar(self, it: a.Interpreter, page: int, tab_page: int, submenu: bool) -> None:
        it.screen.fill(0, 1, 79, 1, SCHEME[4])
        it.col, it.row, it.margin = 2, 1, 2
        for p, script in self.tabs:
            start = it.col
            saved = it.data, it.base
            it.data, it.base = self.system, len(self.system) - 0x10000
            it.attr = SCHEME[7] if p == tab_page else SCHEME[4]
            it.run(script)
            it.data, it.base = saved
            if submenu and p != tab_page:  # a sub-menu shows only its own tab
                it.screen.fill(start, 1, it.col - 1, 1, SCHEME[4])
                for x in range(start, it.col):
                    it.screen.put(x, 1, 0x20, SCHEME[4])

    def _rows(self, page: int) -> list[tuple[int, int, bool]]:
        """[(entry, row offset, linked)] in drawing order; linked items share their parent's
        row."""
        entries = [e for _, e in sorted(self.items.get(page, []), key=lambda t: t[0])]
        row_of, n = {}, -1
        for e in entries:
            parent = self.links.get(e)
            if (parent is not None and parent != e) or self._word(e) & 0x8008:
                continue
            n += 1
            if self._word(e) & 0x0010 and n:
                n += 1
            row_of[e] = n
        rows = []
        for e in entries:
            parent = self.links.get(e, e)
            if parent in row_of:  # fields of a linked parent go on the parent's row
                rows.append((e, row_of[parent], e in self.links))
        return rows

    def screen(self, page: int, defaults: str = "setup") -> tuple[Screen, dict]:
        screen = Screen()
        it = self._interp(screen)
        screen.fill(0, 0, 79, 24, SCHEME[0])
        saved = it.data, it.base
        it.data, it.base = self.frame_data, 0
        it.run(self.frame)
        it.data, it.base = saved
        submenu = page in self.parents
        tab_page = self.parents[page][1] if submenu else page
        self._draw_bar(it, page, tab_page, submenu)
        titles = self.page_titles()
        top = 3
        if submenu:  # title above a line across the left panel
            title = titles.get(page, "")
            self._write(it, 1 + (53 - len(title)) // 2, 3, title, SCHEME[0])
            screen.put(0, 4, 0xC3, SCHEME[0])
            for x in range(1, 54):
                screen.put(x, 4, 0xC4, SCHEME[0])
            screen.put(54, 4, 0xC5, SCHEME[0])
            top = 5
        level = 1 + sum(1 for _ in self._ancestors(page))
        menu_level = self.menu_level
        if menu_level is not None:  # (not in every version's language module)
            it.attr, it.col, it.row = SCHEME[0], HELP_COL, 5
            it.run_lang(menu_level)
            for _ in range(level):
                it.putc(0x10)  # ►

        rows = self._rows(page)
        clock = self.clock_fields(page)
        selectable = [e for e, row, _ in rows if not self._word(e) & 0x0004 and row is not None]
        selected = selectable[0] if selectable else None
        selected_row = next((row for e, row, _ in rows if e == selected), None)
        items, help_item = [], selected
        for e, row, linked in rows:
            flags = self._word(e)
            label = self.label(e)
            value = clock[e] if e in clock else self.value(e, defaults)
            y = top + row
            if y > BOTTOM:
                if not linked:
                    items.append({"label": label, "value": value, "note": "further down, scroll"})
                continue
            status = flags & 0x0004
            dependent = flags & 0x0800  # greyed out while its parent is on Auto
            target = self._word(e + 0x11) >> 11
            opens = bool(target)  # some sub-menus are filled at run time (not shown)
            is_child = linked and self.links.get(e) != e
            label_attr = (
                SCHEME[1]
                if row == selected_row
                else (SCHEME[6] if status or dependent else SCHEME[0])
            )
            if not is_child:
                screen.put(3, y, 0x10 if opens else 0x20, SCHEME[0])
                it.attr, it.col, it.row, it.margin = label_attr, LABEL_COL, y, LABEL_COL
                it.run_lang(self._word(e + 2))
                items.append(
                    {"label": label, "value": value} if value is not None else {"label": label}
                )
            else:  # the field's label repeats the parent's label, moves right and may add ':'
                parent_status = self._word(self.links[e]) & 0x0004
                it.attr = (
                    SCHEME[1]
                    if row == selected_row
                    else (SCHEME[6] if parent_status else SCHEME[0])
                )
                it.col, it.row, it.margin = LABEL_COL, y, LABEL_COL
                it.run_lang(self._word(e + 2))
            if value is None:
                continue
            attr = SCHEME[2] if e == selected else (SCHEME[6] if status else SCHEME[0])
            if linked:  # date/time fields: at the cursor, no brackets
                self._write(it, it.col, y, value.rstrip(), attr)
            elif dependent:
                self._write(it, VALUE_COL, y, value.strip(), SCHEME[6])
            else:
                self._write(it, VALUE_COL - 1, y, "[", SCHEME[0])
                self._write(it, VALUE_COL, y, value.rstrip(), attr)
                self._write(it, it.col, y, "]", SCHEME[0])
        if help_item is not None:
            lines = []
            for part in self.text(self._word(help_item + 0x17)).split("\n"):
                lines += textwrap.wrap(part, HELP_WIDTH) or [""]
            for n, line in enumerate(lines[: BOTTOM - 7 + 1]):
                self._write(it, HELP_COL, 7 + n, line, SCHEME[0])
        return screen, {
            "title": titles.get(page, f"page {page}"),
            "items": items,
            "values": f"{defaults} defaults stored in the ROM",
        }

    @functools.cached_property
    def menu_level(self) -> int | None:
        """The language module's "Menu Level" text, if it has one."""
        return self._text_id("Menu Level")

    def _ancestors(self, page: int) -> Iterator[int]:
        while page in self.parents:
            e, _ = self.parents[page]
            parent_page = self._word(e + 0x11) & 0x1F
            yield parent_page
            page = parent_page

    def pages(self) -> list[int]:
        """Tabs in bar order, each followed by its sub-menus."""
        out = []

        def walk(page: int) -> None:
            out.append(page)
            for _, e in sorted(self.items.get(page, [])):
                target = self._word(e + 0x11) >> 11
                if target in self.parents and self.parents[target][0] == e and target not in out:
                    walk(target)

        for page, _ in self.tabs:
            walk(page)
        return out
