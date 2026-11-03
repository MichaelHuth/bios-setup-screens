"""
Rebuild the setup screens of Award Medallion BIOS 6.0 (about 2001-2004: "AwardBIOS Setup
Utility" with a menu bar Main / Advanced / Power / Boot / Exit, values in brackets and an
"Item Specific Help" panel) from a full flash image.

Reverse-engineered from an ASUS A7V8X-X BIOS (rev. 1012) and checked against the screenshots in
the ASUS A7V8X manual. Unlike Award 6.00PG there are no screen scripts: the setup module
(Group2.ROM, run with CS = the module) draws everything in code and keeps all texts as plain
NUL-terminated strings; the items are 25-byte records in the system BIOS (F000) as in 6.00PG:
  +0 flags  +2 label  +4 value routine (FFFFh = none)  +8 CMOS register  +9 mask (word)
  +0Bh option list (NUL-separated strings)  +0Fh maximum  +11h position: page = bits 0-4,
  line = bits 5-10 (0 = table order), sub-menu opened = bits 11-15  +13h/+15h defaults
  (Fail-safe / Setup)  +17h help text (0Ah = new line).
Flags: 01h value drawn by the routine at +4 (date, time, drives, memory), 02h no value,
04h value greyed out, 10h hidden, 20h empty line before the item.
Found in the setup module by their code:
- "mov si,list / push di / mov bx,fs:[si]": the list of item tables (start, end) in F000;
- "mov si,end / sub si,3 / mov [bp+C0h],si / mov si,bar": the menu bar, 3-byte records
  (page, tab text); a tab is shown when its page has items;
- the title ("AwardBIOS Setup Utility", row 0, centred), the two legend rows (pairs of key and
  text strings, keys in colour 8) and the "Item Specific Help" title;
- the colour table (pointer set after the mono/colour check): 0 label, 1 selected label,
  2 selected value, 3 title and legend, 4 menu bar, 5 frame and values, 6 greyed out,
  7 selected tab, 8 legend keys.
Layout (from the drawing code): menu bar on row 1 from column 3, each tab " text " followed by
three spaces; box rows 2-22 with the help panel right of column 53; items from row 3 (a
sub-menu: title on row 3, a line on row 4, items from row 6), "►" in column 2 before items that
open a sub-menu, label in column 4, values in brackets at column (longest label + 6); help text
from row 6, column 55, 24 columns wide.
"""

from __future__ import annotations

import re
import struct
import textwrap

import lzh
from textscreen import Screen

LIST = re.compile(rb"\xbe(..)\x57\x64\x8b\x1c", re.S)
BAR = re.compile(rb"\xbe(..)\x81\xee\x03\x00\x89\xb6..\xbe(..)\x89\xb6", re.S)
TITLE = re.compile(rb"\xbe(..)(?:\xe8..)?\xc6\x86\x83\x00\x00\xb9\x00\x4f", re.S)  # P4PE: a call
LEGEND = re.compile(rb"\xc6\x86\x83\x00\x17\xbe(..).{3,6}?\xc6\x86\x83\x00\x18\xbe(..)", re.S)
HELP_TITLE = re.compile(rb"\xb9\x36\x4e\xbe(..)", re.S)
COLORS = re.compile(rb"\xb4\x01\xc7\x86\xc4\x00(..)", re.S)
ITEM_SIZE = 0x19
TOP, SUB_TOP, BOTTOM = 3, 6, 21
LABEL_COL, DIVIDER, HELP_COL, HELP_WIDTH, HELP_ROW = 4, 53, 55, 24, 6
SAMPLE = {"time": "00:00:00", "date": "01/01/2000"}  # the clock, as BIOS reads it at run time


def _modules(image: bytes) -> tuple[bytes, bytes]:
    """(setup module, system BIOS with F000 at its end)."""
    setup = system = None
    for m in lzh.find_modules(image):
        try:
            data = lzh.decompress(
                image[m["data_start"] : m["data_start"] + m["packed"]],
                m["size"],
                m["method"].encode(),
            )
        except Exception:
            continue
        if setup is None and b"AwardBIOS Setup Utility" in data and LIST.search(data):
            setup = data
        elif system is None and len(data) >= 0x10000 and b"Award" in data:
            system = data
    if setup is None or system is None:
        raise ValueError(
            "not an Award Medallion flash image (needs the setup module with "
            '"AwardBIOS Setup Utility" and the system BIOS)'
        )
    return setup, system


def is_medallion(image: bytes) -> bool:
    return b"Award Medallion" in image or b"MAINBIOS.BIN" in image


class AwardMedallion:
    def __init__(self, image: bytes):
        self.code, system = _modules(image)
        self.seg = system[len(system) - 0x10000 :]
        found = [p.search(self.code) for p in (LIST, BAR, TITLE, LEGEND, HELP_TITLE, COLORS)]
        if not all(found):
            raise ValueError("Award Medallion setup module in an unknown layout")
        lst, bar, title, legend, help_title, colors = found
        assert lst and bar and title and legend and help_title and colors
        self.list_ptr = self._u16(lst.group(1))
        bar_end, self.bar_ptr = self._u16(bar.group(1)) - 3, self._u16(bar.group(2))
        self.bar_end = bar_end
        self.title = self.string(self._u16(title.group(1)))
        self.legend = [self._u16(legend.group(1)), self._u16(legend.group(2))]
        self.help_title = self.string(self._u16(help_title.group(1)))
        table = self._u16(colors.group(1))
        self.colors = list(self.code[table : table + 16])
        self.items = self._items()
        self.tabs = self._tabs()
        self.parents = self._parents()

    # --- data ---------------------------------------------------------------------------

    @staticmethod
    def _u16(b: bytes) -> int:
        return struct.unpack("<H", b)[0]

    def _word(self, off: int) -> int:
        return struct.unpack_from("<H", self.seg, off)[0]

    def string(self, ptr: int) -> str:
        if not 0 < ptr < len(self.code):
            return ""
        end = self.code.find(b"\0", ptr)
        return self.code[ptr : end if end >= 0 else ptr + 80].decode("cp437")

    def strings(self, ptr: int, count: int) -> list[str]:
        """count strings in a row; option lists also end an entry with 01h."""
        out = []
        for _ in range(count):
            end = ptr
            while end < len(self.code) and self.code[end] not in (0, 1):
                end += 1
            out.append(self.code[ptr:end].decode("cp437"))
            ptr = end + 1
        return out

    def _items(self) -> dict[int, list[int]]:
        """page -> entries in display order (explicit lines in their slots, the others in
        table order)."""
        p, entries = self.list_ptr, []
        while p + 4 <= len(self.seg):
            start, end = struct.unpack_from("<HH", self.seg, p)
            if start == 0xFFFF or not start < end or (end - start) % ITEM_SIZE:
                break
            entries += list(range(start, end, ITEM_SIZE))
            p += 4
        pages: dict[int, list[tuple[int, int]]] = {}
        for e in entries:
            pos = self._word(e + 0x11)
            pages.setdefault(pos & 0x1F, []).append(((pos >> 5) & 0x3F, e))
        ordered = {}
        for page, items in pages.items():
            explicit = sorted((t for t in items if t[0]), key=lambda t: t[0])
            zeros = [e for line, e in items if not line]
            out, slot = [], 1
            while explicit or zeros:
                if explicit and (explicit[0][0] <= slot or not zeros):
                    out.append(explicit.pop(0)[1])
                else:
                    out.append(zeros.pop(0))
                slot += 1
            ordered[page] = out
        return ordered

    def _tabs(self) -> list[tuple[int, int]]:
        tabs, p = [], self.bar_ptr
        while p <= self.bar_end:
            page, text = self.code[p], self._u16(self.code[p + 1 : p + 3])
            if page <= 0x1F and self.items.get(page):
                tabs.append((page, text))
            p += 3
        return tabs

    def _parents(self) -> dict[int, tuple[int, int]]:
        """sub-menu page -> (opening item, tab page)."""
        out: dict[int, tuple[int, int]] = {}
        tab_of = {page: page for page, _ in self.tabs}
        todo = list(tab_of)
        while todo:
            page = todo.pop(0)
            for e in self.items.get(page, []):
                target = self._word(e + 0x11) >> 11
                if (
                    target
                    and target not in tab_of
                    and target not in out
                    and self.items.get(target)
                    and not self._word(e) & 0x10
                ):
                    out[target] = (e, tab_of[page])
                    tab_of[target] = tab_of[page]
                    todo.append(target)
        return out

    def label(self, e: int) -> str:
        return self.string(self._word(e + 2))

    def page_titles(self) -> dict[int, str]:
        titles = {page: self.string(text) for page, text in self.tabs}
        for page, (e, _) in self.parents.items():
            titles[page] = self.label(e).strip()
        return titles

    def pages(self) -> list[int]:
        out = []

        def walk(page: int) -> None:
            out.append(page)
            for e in self.items.get(page, []):
                target = self._word(e + 0x11) >> 11
                if target in self.parents and self.parents[target][0] == e and target not in out:
                    walk(target)

        for page, _ in self.tabs:
            walk(page)
        return out

    def value(self, e: int, defaults: str = "setup") -> str | None:
        flags = self._word(e)
        if flags & 0x02:
            return None
        if flags & 0x01:  # drawn by a routine: the clock is shown as a sample, otherwise the
            label = self.label(e).lower()  # option list is used when it gives a clear text
            if self._word(e + 4) != 0xFFFF and label.strip() in ("system time", "system date"):
                return SAMPLE[label.split()[-1]]
        mask = self._word(e + 9)
        if not mask or mask == 0xFFFF:
            return None
        default = self._word(e + (0x15 if defaults == "setup" else 0x13))
        shift = (mask & -mask).bit_length() - 1
        index, maximum = (default & mask) >> shift, self._word(e + 0x0F)
        options = self.strings(self._word(e + 0x0B), min(maximum, 255) + 1)
        if not options or not options[0]:  # an empty first entry: no option list
            return None
        if (
            index < len(options)
            and options[index]
            and all(32 <= ord(c) < 127 for c in options[index])
        ):
            return options[index]
        return None

    # --- drawing ------------------------------------------------------------------------

    def _put(self, screen: Screen, col: int, row: int, text: str, attr: int) -> int:
        for ch in text.encode("cp437", "replace"):
            if 0 <= col < 80:
                screen.put(col, row, ch, attr)
            col += 1
        return col

    def _frame(self, screen: Screen) -> None:
        c = self.colors
        screen.fill(0, 0, 79, 24, c[5])
        screen.fill(0, 0, 79, 0, c[3])
        self._put(screen, (80 - len(self.title)) // 2, 0, self.title, c[3])
        for x in range(1, 79):  # box rows 2-22
            screen.put(x, 2, 0xC4, c[5])
            screen.put(x, 22, 0xC4, c[5])
        for y in range(3, 22):
            screen.put(0, y, 0xB3, c[5])
            screen.put(79, y, 0xB3, c[5])
            screen.put(DIVIDER, y, 0xB3, c[5])
        for (x, y), ch in {
            (0, 2): 0xDA,
            (79, 2): 0xBF,
            (0, 22): 0xC0,
            (79, 22): 0xD9,
            (DIVIDER, 2): 0xC2,
            (DIVIDER, 22): 0xC1,
            (DIVIDER, 4): 0xC3,
            (79, 4): 0xB4,
        }.items():
            screen.put(x, y, ch, c[5])
        for x in range(DIVIDER + 1, 79):
            screen.put(x, 4, 0xC4, c[5])
        left, right = DIVIDER + 1, 78
        self._put(
            screen, left + (right - left + 1 - len(self.help_title)) // 2, 3, self.help_title, c[5]
        )
        for row, ptr in zip((23, 24), self.legend):  # 4 pairs of key and text
            col, texts = 0, self.strings(ptr, 8)
            for n, text in enumerate(texts):
                col = self._put(screen, col, row, text, c[8] if n % 2 == 0 else c[3])
            if col < 80:
                screen.fill(col, row, 79, row, c[3])

    def _bar(self, screen: Screen, tab_page: int, submenu: bool) -> None:
        c = self.colors
        screen.fill(0, 1, 79, 1, c[4])
        for x in range(80):
            screen.put(x, 1, 0x20, c[4])
        col = 3
        for page, text in self.tabs:
            name = " " + self.string(text) + " "
            if page == tab_page:
                self._put(screen, col, 1, name, c[7])
            elif not submenu:
                self._put(screen, col, 1, name, c[4])
            col += len(name) + 3

    def screen(self, page: int, defaults: str = "setup") -> tuple[Screen, dict]:
        c, screen = self.colors, Screen()
        self._frame(screen)
        submenu = page in self.parents
        self._bar(screen, self.parents[page][1] if submenu else page, submenu)
        titles = self.page_titles()
        title = titles.get(page, f"page {page}")
        top = TOP
        if submenu:
            self._put(screen, 1 + (DIVIDER - 1 - len(title)) // 2, 3, title, c[0])
            screen.put(0, 4, 0xC3, c[5])
            for x in range(1, DIVIDER):
                screen.put(x, 4, 0xC4, c[5])
            screen.put(DIVIDER, 4, 0xC5, c[5])
            top = SUB_TOP
        entries = [e for e in self.items.get(page, []) if not self._word(e) & 0x10]
        widths = [len(self.label(e)) for e in entries if not self._word(e) & 0x12]
        value_col = max([w for w in widths if w < 0x2C] or [20]) + 6
        selected = next((e for e in entries if not self._word(e) & 0x02), None)
        row, items = top, []
        for n, e in enumerate(entries):
            flags = self._word(e)
            if n and flags & 0x20:
                row += 1
            label, value = self.label(e), self.value(e, defaults)
            if row > BOTTOM:
                items.append(
                    {"label": label.strip(), "value": value, "note": "further down, scroll"}
                )
                continue
            if self._word(e + 0x11) >> 11:
                screen.put(2, row, 0x10, c[0])
            self._put(screen, LABEL_COL, row, label, c[1] if e == selected else c[0])
            if value is not None:
                attr = c[2] if e == selected else c[6] if flags & 0x04 else c[5]
                col = self._put(screen, value_col, row, "[", c[5])
                col = self._put(screen, col, row, value.rstrip(), attr)
                self._put(screen, col, row, "]", c[5])
            items.append(
                {"label": label.strip(), "value": value}
                if value is not None
                else {"label": label.strip()}
            )
            row += 1
        if selected is not None:
            lines = []
            for part in self.string(self._word(selected + 0x17)).split("\n"):
                lines += textwrap.wrap(part, HELP_WIDTH) or [""]
            for n, line in enumerate(lines[: BOTTOM - HELP_ROW + 1]):
                self._put(screen, HELP_COL, HELP_ROW + n, line, c[5])
        return screen, {
            "title": title,
            "items": items,
            "values": f"{defaults} defaults stored in the ROM",
        }
