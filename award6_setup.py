"""
Rebuild Award Modular BIOS 6.00PG setup screens from a full flash image.

6.00PG keeps the setup logic and the screen frames in the extension module (awardext.rom,
loaded into its own segment at run time) and the item tables in the system BIOS (F000). Both
use the same screen-script interpreter as 4.5x (award_setup). Reverse-engineered from an
Abit KT7 BIOS (awardext.rom):
- the list builder walks a list of item tables (6-byte records start, end, 0; ends with FFFF)
  and assigns an item to page (pos & 1Fh) at line ((pos >> 5) & 3Fh), pos = word at +11h;
- main menu entries open page (pos >> 8) >> 3 (0 = an action such as Save & Exit);
- main menu: 8 entries per column, two lines apart, the second column 40 columns further
  right; "►" (10h) before entries that open a page, then a space and the label;
- pages: label at column 3, value 29 columns further right (column 32), one item per line;
- help texts (pointer at +17h) are plain text in the extension module; their placement
  (centered in the main menu's bottom box, word-wrapped in the Item Help panel) is done by
  code and is reconstructed here, not read from the ROM.
Item entries are otherwise laid out as in 4.5x (CMOS register, mask, option list, defaults).

Phoenix-AwardBIOS images with this classic main menu (e.g. ABIT IC7) keep all texts in a
language module (_EN_CODE.BIN): labels, option lists and help are text IDs there
(section << 8 | index), and scripts print them with opcode 15h.
"""

from __future__ import annotations

import re
import struct
import textwrap

import award_setup as a
import lzh
from textscreen import Screen

TABLE_LIST = re.compile(
    rb"\xbe(..)\x57\x26\x8b\x1c", re.S
)  # mov si,list / push di / mov bx,es:[si]
LABEL_COL, VALUE_OFFSET, PER_COLUMN = 3, 29, 8
# menu bar names (OEM setups, HP) and what the first entry of the page they open says
BAR_PAGES = (
    ("Main", ("System Date", "System Time", "Date (", "Time (")),
    ("Exit", ("Exit Saving", "Exit discarding", "Exit Discarding", "Save & Exit")),
    ("Advanced", ("Setting items on this menu",)),
    ("Security", ("Password",)),
    ("Power", ("ACPI", "Power Management")),
    ("Defaults", ("Load System Default", "Load Fail-Safe", "Load Optimized")),
    ("HW Monitor", ("Temperature", "FAN Speed")),
    ("PC Health", ("Temperature", "FAN Speed")),
)


def language_module(image: bytes) -> bytes | None:
    """The language module of a Phoenix-AwardBIOS (_EN_CODE.BIN and the like; some name it
    EN.STF), if any."""
    for m in lzh.find_modules(image):
        if re.fullmatch(r"_[A-Z]{2}_CODE\.BIN|EN\.STF", m["name"].upper().split("\0")[0]):
            try:
                return lzh.decompress(
                    image[m["data_start"] : m["data_start"] + m["packed"]],
                    m["size"],
                    m["method"].encode(),
                )
            except Exception:
                return None
    return None


def item_module(image: bytes) -> bytes | None:
    """The item tables module of later Phoenix-AwardBIOSes (_ITEM.BIN), if any."""
    for m in lzh.find_modules(image):
        if m["name"].upper() == "_ITEM.BIN":
            try:
                return lzh.decompress(
                    image[m["data_start"] : m["data_start"] + m["packed"]],
                    m["size"],
                    m["method"].encode(),
                )
            except Exception:
                return None
    return None


def content_list(seg: bytes, lim: int) -> int | None:
    """The item table list found by its content instead of by the code that names it: the
    offset of the longest chain (at least 3) of (start, end, 0) records whose lengths are whole
    items and that end within lim, closed by a record starting with FFFFh, or None."""
    best, at = 0, None
    for q in range(len(seg) - 6):  # (any offset: the Dell C521's list is at 0B21h)
        p, n = q, 0
        while p + 6 <= len(seg):
            s, e = struct.unpack_from("<HH", seg, p)
            if s == 0xFFFF:
                if n > best:
                    best, at = n, q
                break
            if s != e and (not 0 < s < e <= lim or (e - s) % a.ITEM_SIZE):
                break
            n += s != e  # (an empty table: the list goes on, as in Award6._items)
            p += 6
    return at if best >= 3 else None


def _modules(image: bytes) -> tuple[bytes, bytes]:
    """(system BIOS with E000+F000, extension module) from a full 6.00PG flash image."""
    system = ext = listed = titled = None
    for m in lzh.find_modules(image):
        try:
            out = lzh.decompress(
                image[m["data_start"] : m["data_start"] + m["packed"]],
                m["size"],
                m["method"].encode(),
            )
        except Exception:  # damaged module
            continue
        if system is None and len(out) >= 0x10000:
            try:
                a._find(out)
                system = out
                continue
            except ValueError:
                pass
        if ext is None and b"CMOS Setup Utility" in out and TABLE_LIST.search(out):
            ext = out
        if listed is None and TABLE_LIST.search(out):
            listed = out
        if (
            titled is None
            and b"CMOS Setup Utility" in out
            and m["name"].lower().startswith("awardext")
        ):
            titled = out
    if ext is None and listed is not None and language_module(image) is not None:
        ext = listed  # (its texts, the title too, in the language module: HP Leucite3)
    if ext is None and system is not None:
        # (awardext.rom without the code that names the item table list, which is in the
        # system BIOS all the same: Dell OptiPlex 740; found by its content, Award6._items)
        ext = titled
    if system is None or ext is None:
        raise ValueError(
            "not an Award 6.00PG flash image (needs the system BIOS and the "
            "awardext extension module)"
        )
    return system, ext


class Award6:
    lang: bytes | None
    main_page: int | None
    items: dict[int, list[tuple[int, int]]]

    def __init__(self, image: bytes, pages_only: bool = False, drawn_frames: bool = False):
        """pages_only: for OEM setups whose main menu is built by code (Soltek, HP: no page
        lists the others with Save & Exit), only the item pages are drawn, each in the page
        frame; their titles come from the entries that open them. drawn_frames: OEM setups
        without a page frame script (see _frames), tried after the menu-bar reader."""
        self.allow_drawn = drawn_frames
        # Gigabyte's BIOSes (with tgroup modules, t1group.bin ...): those of about 2009-11 have
        # more pages, 6 bits of page in the position word, 4 of line, the target page above;
        # later ones (GA-E350N, 2012) the usual 5. Abit's (AB9) have 5 bits of page, 5 of line
        # and the target page from bit 10 on. Whichever layout gives the main menu more
        # entries that open distinct pages is taken (the usual one on a tie). Gigabyte's and
        # Abit's main menus put the pages left, the actions right.
        self.gigabyte = any(
            re.fullmatch(r"T\d?GROUP\.BIN", m["name"].upper().split("\0")[0])
            for m in lzh.find_modules(image)
        )
        self.system, ext = _modules(image)
        self.ext = ext + bytes(max(0, 0x10000 - len(ext)))
        lang = language_module(image)
        self.lang = lang + bytes(max(0, 0x10000 - len(lang))) if lang else None
        self.pages_only = pages_only
        best = None
        # (the extension module's own decoding "shr ax,6 / and al,0Fh": 6 bits of page,
        # whoever built it - MSI MS-7548 for HP)
        six = self.gigabyte or b"\xc1\xe8\x06\x24\x0f" in self.ext
        layouts = ((6, 10), (5, 11), (5, 10)) if six else ((5, 11), (5, 10))
        for self.page_bits, self.target_shift in layouts:
            self.seg = self.system[len(self.system) - 0x10000 :]
            self.items = self._items(item_module(image))
            try:
                main_page = None if pages_only else self._main_page()
            except ValueError:
                if best is None and (self.page_bits, self.target_shift) == layouts[-1]:
                    raise
                continue
            self.main_page = main_page
            score = (
                0
                if main_page is None
                else len(
                    {self._target(e) for _, e in self.items[main_page]} & set(self.items) - {0}
                )
            )
            if best is None or score > best[0]:
                best = (
                    score,
                    self.page_bits,
                    self.target_shift,
                    self.seg,
                    self.items,
                    self.main_page,
                )
        if best is None:
            raise ValueError("main menu not found")
        _, self.page_bits, self.target_shift, self.seg, self.items, self.main_page = best
        self.split = self.gigabyte or self.target_shift == 10  # pages left, actions right
        self.drawn_page = False
        if self.target_shift == 10 and self.main_page is not None:  # (Abit: lines repeat)
            self.items[self.main_page].sort(key=lambda item: (item[0], self._target(item[1])))
        if self.gigabyte and self.main_page is not None:
            # Gigabyte's boards share one main menu table; entries whose page this board does
            # not have (P55: Advanced Chipset, PnP/PCI) are left out
            self.items[self.main_page] = [
                (line, e)
                for line, e in self.items[self.main_page]
                if not self._target(e) or self._target(e) in self.items
            ]
        self.frames = self._frames()

    # --- data ---------------------------------------------------------------------------

    def _items(self, item: bytes | None = None) -> dict[int, list[tuple[int, int]]]:
        """page -> [(line, entry offset in F000)] from all item tables. Later Phoenix-Award
        BIOSes keep the entries in a module of their own (_ITEM.BIN), which the table list in
        F000 points into: the entries are then read from it (self.seg becomes that module)."""
        m = TABLE_LIST.search(self.ext)
        if m is not None:
            p = struct.unpack("<H", m.group(1))[0]
        elif (q := content_list(self.seg, len(item) if item else 0x10000)) is not None:
            p = q
        else:
            raise ValueError("no item table list in the system BIOS")
        tables = self.seg
        if item is not None:
            start, end = struct.unpack_from("<HH", tables, p)
            if start < end <= len(item) and not (end - start) % a.ITEM_SIZE:
                self.seg = item + bytes(max(0, 0x10000 - len(item)))
        pages: dict[int, list] = {}
        while p + 6 <= len(tables):
            start, end = struct.unpack_from("<HH", tables, p)
            if start == end != 0xFFFF:  # an empty table (Epox 8KHA+), the list goes on
                p += 6
                continue
            if start == 0xFFFF or not start < end or (end - start) % a.ITEM_SIZE:
                break
            for e in range(start, end, a.ITEM_SIZE):
                pos = struct.unpack_from("<H", self.seg, e + 0x11)[0]
                if self.page_bits == 6:
                    pages.setdefault(pos & 0x3F, []).append(((pos >> 6) & 0x0F, e))
                else:
                    pages.setdefault(pos & 0x1F, []).append(
                        ((pos >> 5) & (0x1F if self.target_shift == 10 else 0x3F), e)
                    )
            p += 6
        if self.gigabyte or self.target_shift == 10:  # several items per line number: in the
            # order of the tables
            return {k: sorted(v, key=lambda item: item[0]) for k, v in pages.items()}
        return {k: sorted(v) for k, v in pages.items()}

    def _target(self, e: int) -> int:
        """The page an entry opens (0: none, an action such as Save & Exit)."""
        return struct.unpack_from("<H", self.seg, e + 0x11)[0] >> self.target_shift

    def _in_language(self, word: int) -> bool:
        """Is word a text of the language module? Some BIOSes with a small one (4-11 KB; QDI's
        of 1 KB) keep most labels and option lists as scripts in the system BIOS, as those
        without a language module do: a word that names no text there is such an offset."""
        return bool(self.lang) and self._interp(Screen(), ext=False).lang_offset(word) is not None

    def _label(self, e: int) -> str:
        word = struct.unpack_from("<H", self.seg, e + 2)[0]
        if self._in_language(word):
            return self.text(word).strip()
        text = a._label_text(self.seg, struct.unpack_from("<H", self.seg, e + 2)[0])
        if any(not 32 <= ord(c) < 127 for c in text):  # a script that calls another one
            text = " ".join(self._drawn_label(e).split())  # (USI PRO-263: "Date (mm:dd:yyyy)")
        return text

    def text(self, ident: int) -> str:
        """A text of the language module as plain text (control codes dropped)."""
        off = self._interp(Screen(), ext=False).lang_offset(ident)
        if off is None:
            return ""
        assert self.lang is not None
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
            elif c == 0x04:
                i += 4
            elif c in (0x05, 0x14, 0x15):
                i += 2
            i += 1
        return "".join(out)

    def _option_text(self, opt: int, index: int) -> bytes | None:
        """Entry index of an option list (NUL-separated; in the language module: an ID)."""
        if self.lang is None or not self._in_language(opt):
            return a._option(self.seg, opt, index)
        off = self._interp(Screen(), ext=False).lang_offset(opt)
        if off is None:
            return None
        while (
            off < len(self.lang) - 3
            and self.lang[off] in (0x14, 0x15)
            and not all(32 <= c < 127 for c in self.lang[off : off + 3])
        ):
            off += 3  # (ASUS P5VDC-TVM: a list may start with script jumps, "14 87 00")
        for _ in range(index):
            while self.lang[off] not in (0, 1):
                off += 1
            off += 1
        end = off
        while self.lang[end] not in (0, 1):
            end += 1
        return bytes(self.lang[off:end])

    def _run_label(self, it: a.Interpreter, e: int) -> None:
        """Draw an item's label (a script, or a text of the language module)."""
        word = struct.unpack_from("<H", self.seg, e + 2)[0]
        if self._in_language(word):
            it.run_lang(word)
        else:
            it.run(word)

    def _main_page(self) -> int:
        for page, entries in self.items.items():
            labels = " ".join(self._label(e) for _, e in entries)
            if "Save & Exit" in labels and ("Exit Without" in labels or "Load" in labels):
                return page
            if "Exit Saving" in labels and "Exit Discarding" in labels:  # (MSI MS-7548, HP)
                return page
        raise ValueError("main menu not found")

    def main_entries(self) -> list[tuple[int, str, int]]:
        """(index, label, target page) of the main menu."""
        assert self.main_page is not None
        out = []
        for index, e in self.items[self.main_page]:
            out.append((index, self._label(e), self._target(e)))
        return out

    def page_titles(self) -> dict[int, str]:
        # (with a menu bar instead of a main menu, MSI MS-7548 for HP: all pages, as below)
        if not self.pages_only and not self.drawn_main:
            return {t: label for _, label, t in self.main_entries() if t and t in self.items}
        titles: dict[int, str] = (
            {}
        )  # the label of an entry that opens the page ("Onboard Device"), if any
        for page in sorted(self.items):
            for _, e in self.items[page]:
                target = self._target(e)
                label = self._label(e).strip(" :")
                if target and target != page and target in self.items and label:
                    titles.setdefault(target, label)
        # the menu bar's names (HP: a table of 16-byte names in the language module; which
        # page each opens is in code) for pages no entry opens, recognised by their contents
        bar = [
            n.decode().strip()
            for n in re.findall(rb"([A-Z][A-Za-z ]+?) *\x00+(?=[A-Z])", self._bar_table())
        ]
        for page in sorted(self.items):
            if page in titles:
                continue
            first = next(
                (label for label in (self._label(e) for _, e in self.items[page]) if label), ""
            )
            for name, marks in BAR_PAGES:
                if name in bar and name not in titles.values() and any(m in first for m in marks):
                    titles[page] = name
                    break
        # a page no entry opens, whose entries open three or more pages and end the setup, is
        # the main menu (the OEM menus built by code list the pages as such an item page)
        for page in sorted(self.items):
            opens = {self._target(e) for _, e in self.items[page]} - {0, page}
            labels = " ".join(self._label(e) for _, e in self.items[page])
            if (
                page not in titles
                and "Main Menu" not in titles.values()
                and len(opens & set(self.items)) >= 3
                and "Exit" in labels
            ):
                titles[page] = "Main Menu"
        return {p: titles.get(p, f"Page {p}") for p in sorted(self.items)}

    def _bar_table(self) -> bytes:
        """The language module's table of menu bar names, 16 bytes each (HP), or nothing."""
        for m in re.finditer(rb"(?:[A-Z][A-Za-z ]{1,14}\x00{1,15}){4,}", self.lang or b""):
            if all(len(n) == 16 for n in re.findall(rb"[A-Z][A-Za-z ]+\x00+", m.group(0))):
                return m.group(0) + b"X"
        return b""

    def _frames(self) -> dict[str, int]:
        """The main-menu and page frame scripts in the extension module. Some OEM builds have
        no page frame script (it is drawn by code) and their main frame may follow code
        rather than a 00 byte (Maxdata/ASUS P5VDC-TVM, IBM's USI
        PRO-263): then the main frame is the widest box script that names a key, and pages get
        a frame drawn here (self.drawn_page)."""
        self.drawn_page = self.drawn_main = False
        try:
            return self._frame_scripts()
        except ValueError:
            if not self.allow_drawn:
                raise
        main = []
        for i in range(len(self.ext) - 5):
            if self.ext[i] != 0x02:  # box: x1, y1, x2, y2, style
                continue
            x1, y1, x2, y2, style = self.ext[i + 1 : i + 6]
            if not (x1 < x2 <= 80 and y1 < y2 <= 25 and style <= 0x0F) or x2 - x1 < 60:
                continue
            best = None
            for off in range(max(0, i - 0x40), i + 1):
                if self.ext[off] not in (0x00, 0xC3):  # after a 00 or a ret
                    continue
                screen = self._render_script(off + 1)
                boxes = sum(1 for line in screen.chars for c in line if 0xB3 <= c <= 0xDA)
                if best is None or boxes > best[0]:
                    best = (boxes, off + 1, screen.text().lower())
            if best and ("quit" in best[2] or "select item" in best[2]):
                main.append(best)
        if not main and not self.pages_only and self.lang and b"Enter:Select" in self.lang:
            # no frame script at all, both frames drawn by code (MSI MS-7548 for HP: its
            # legend is a text of the language module): drawn here, with the title from there
            self.drawn_page = self.drawn_main = True
            return {}
        if not main or self.pages_only:
            raise ValueError("setup frames not found in the extension module")
        self.drawn_page = True
        return {"main": max(main)[1]}

    def _drawn_title(self) -> str:
        """The setup's title from the language module ("... CMOS Setup Utility")."""
        m = re.search(rb"[ -~]{0,40}Setup Utility", self.lang or b"")
        return m.group().decode("latin-1").strip() if m else "CMOS Setup Utility"

    def _frame_scripts(self) -> dict[str, int]:
        found = {}
        for m in re.finditer(rb"\x00(?=[\x02\x05\x06\x08\x12][\x00-\x4f][\x00-\x18])", self.ext):
            off = m.start() + 1
            screen = self._render_script(off)
            text = screen.text()
            boxes = sum(1 for line in screen.chars for c in line if 0xB3 <= c <= 0xDA)
            if "main" not in found and "Esc : Quit" in text and boxes > 300:
                found["main"] = off
            if (
                "page" not in found
                and ("Item Help" in text or "Item Specific Help" in text)
                and boxes > 200
            ):  # (HP Vienna: "Item Specific Help")
                found["page"] = off
        if len(found) < (1 if self.pages_only else 2) or "page" not in found:
            raise ValueError("setup frames not found in the extension module")
        return found

    def _help(self, e: int) -> str:
        p = struct.unpack_from("<H", self.seg, e + 0x17)[0]
        if self.lang:
            text = " ".join(self.text(p).split())
            return "" if re.fullmatch(r"[A-Z_]+", text) else text
        end = self.ext.find(b"\0", p)
        raw = self.ext[p : end if end > p else p]
        if not raw or not all(32 <= c < 127 for c in raw):
            return ""
        if re.fullmatch(rb"[A-Z_]+", raw):  # placeholder such as STD_HELP (standard help)
            return ""
        return raw.decode("latin-1")

    @staticmethod
    def _write(it: a.Interpreter, col: int, row: int, text: str) -> None:
        it.col, it.row = col, row
        for ch in text.encode("latin-1", "replace"):
            it.putc(ch)

    # --- drawing ------------------------------------------------------------------------

    def _interp(self, screen: Screen, ext: bool) -> a.Interpreter:
        it = a._make(self.system, screen)
        if self.lang:
            it.lang = self.lang
            it.ops = dict(it.ops)
            it.ops[0x15] = ("lang", 2, -1)
        if ext:
            it.data, it.base = self.ext, 0
        return it

    def _render_script(self, off: int) -> Screen:
        screen = Screen()
        it = self._interp(screen, ext=True)
        screen.fill(0, 0, 79, 24, it.attr)
        it.run(off)
        return screen

    def _frame(self, which: str) -> tuple[Screen, a.Interpreter]:
        if which == "main" and self.drawn_main:  # a box under the title (see _frames)
            screen = Screen()
            it = self._interp(screen, ext=False)
            screen.fill(0, 0, 79, 24, it.scheme[0])
            for c in range(80):
                screen.put(c, 2, 0xCD, it.scheme[0])
                screen.put(c, 22, 0xCD, it.scheme[0])
            for r in range(3, 22):
                for c in (0, 79):
                    screen.put(c, r, 0xBA, it.scheme[0])
            for c, (top, bottom) in ((0, (0xC9, 0xC8)), (79, (0xBB, 0xBC))):
                screen.put(c, 2, top, it.scheme[0])
                screen.put(c, 22, bottom, it.scheme[0])
            title = self._drawn_title()
            self._write(it, (80 - len(title)) // 2, 0, title)
            return screen, it
        if which == "page" and self.drawn_page:  # a 6.00PG page frame: box, Item Help panel
            screen = Screen()
            it = self._interp(screen, ext=False)
            screen.fill(0, 0, 79, 24, it.scheme[0])
            for c in range(80):
                screen.put(c, 2, 0xCD, it.scheme[0])
                screen.put(c, 22, 0xCD, it.scheme[0])
            for r in range(3, 22):
                for c in (0, 54, 79):
                    screen.put(c, r, 0xBA if c != 54 else 0xB3, it.scheme[0])
            for c, (top, bottom) in ((0, (0xC9, 0xC8)), (54, (0xD1, 0xCF)), (79, (0xBB, 0xBC))):
                screen.put(c, 2, top, it.scheme[0])
                screen.put(c, 22, bottom, it.scheme[0])
            self._write(it, 62, 3, "Item Help")
            if self.drawn_main:
                title = self._drawn_title()
                self._write(it, (80 - len(title)) // 2, 0, title)
                return screen, it
            main = self._render_script(self.frames["main"])  # the title line as there
            for c in range(80):
                screen.put(c, 0, main.chars[0][c], main.attrs[0][c])
            return screen, it
        screen = self._render_script(self.frames[which])
        return screen, self._interp(screen, ext=False)

    @staticmethod
    def _top(screen: Screen) -> int:
        """First line inside the frame's box."""
        for row in range(25):
            if screen.chars[row][0] in (0xC9, 0xDA):  # ╔ or ┌ at the left edge
                return row + 1
        return 3

    def main_menu(self) -> tuple[Screen, dict]:
        assert self.main_page is not None
        screen, it = self._frame("main")
        top = self._top(screen)
        entries = self.main_entries()
        # the place is the line from the item's position word, or (where those are not one
        # per entry, e.g. Epox 8KHA+) the order of the table
        by_order = len({index for index, _, _ in entries}) < len(entries)
        # one column with an entry per line (USI PRO-263's "MENU IN BIOS", found without a
        # page frame script)
        single = self.drawn_page and not by_order and len(entries) > PER_COLUMN
        pages_seen = actions_seen = 0
        for n, (index, label, target) in enumerate(entries):
            index = n if by_order else index
            if self.split:  # Gigabyte, Abit: the pages in the left column, actions right
                if target:
                    index, pages_seen = pages_seen, pages_seen + 1
                else:
                    index, actions_seen = PER_COLUMN + actions_seen, actions_seen + 1
            col = 3 + (40 if index >= PER_COLUMN and not single else 0)
            row = top + (n if single else 2 * (index % PER_COLUMN))
            it.attr = it.scheme[2] if n == 0 else it.scheme[0]
            it.col, it.row = col, row
            it.putc(0x10 if target and target in self.items else 0x20)  # ► opens a page
            it.putc(0x20)
            self._run_label(it, self.items[self.main_page][n][1])
        help_text = self._help(self.items[self.main_page][0][1])[:76]
        if help_text:  # bottom box of the main menu: centered on its middle line
            it.attr = it.scheme[0]
            self._write(it, (80 - len(help_text)) // 2, 22, help_text)
        return screen, {"items": [label for _, label, _ in entries], "help": help_text}

    def page(self, page: int, defaults: str = "setup") -> tuple[Screen, dict]:
        screen, it = self._frame("page")
        title = self.page_titles().get(page, f"page {page}")
        it.attr = it.scheme[0]
        it.col, it.row = (80 - len(title)) // 2, 1
        for ch in title.encode("latin-1", "replace"):
            it.putc(ch)
        top, bottom = self._top(screen), 21
        items: list[dict[str, str | None]] = []
        row, first = top, True
        last, value_col = None, 0
        for line, e in self.items.get(page, []):
            flags = struct.unpack_from("<H", self.seg, e)[0]
            if flags & 8 and not (self.drawn_page and self._label(e)):  # not shown (USI
                continue  # PRO-263 sets it on items it shows)
            if self.gigabyte and 0 < struct.unpack_from("<H", self.seg, e + 2)[0] < 0x100:
                continue  # (GA-P55M-UD2: an item labelled with a value's text, "Enabled")
            if row > bottom:
                items.append({"label": self._label(e), "value": "(further down, scroll)"})
                continue
            value = self._value(e, flags, defaults)
            drawn = (line, self._drawn_label(e).split("  ")[0])
            if (
                last
                and last[1]
                and row > top
                and (drawn[1] == last[1] or (not drawn[1] and drawn[0] == last[0]))
            ):
                # another field with the same label (the parts of the date and the time),
                # or with none on the same line (later BIOSes number lines, not items): its
                # value goes beside the last one
                row -= 1
                if value:
                    it.attr, it.col, it.row = it.scheme[1], value_col + 1, row
                    for ch in value:
                        it.putc(ch)
                    value_col = it.col
                items.append(
                    {"label": self._label(e), "value": value.decode("cp437") if value else None}
                )
                row += 1
                continue
            last = drawn
            it.attr, it.col, it.row = it.scheme[0], LABEL_COL, row
            self._run_label(it, e)
            value_col = LABEL_COL + VALUE_OFFSET
            if value:
                it.attr = it.scheme[2] if first else it.scheme[1]
                first = False
                it.col = LABEL_COL + VALUE_OFFSET
                for ch in value:
                    it.putc(ch)
                value_col = it.col
            items.append(
                {"label": self._label(e), "value": value.decode("cp437") if value else None}
            )  # (° in °C)
            if row == top:  # help of the selected (first) item in the Item Help panel
                it.attr = it.scheme[0]
                line_no = top + 2
                for help_line in textwrap.wrap(self._help(e), 22)[: bottom - line_no + 1]:
                    self._write(it, 56, line_no, help_line)
                    line_no += 1
            row += 1
        return screen, {
            "title": title,
            "items": items,
            "values": f"{defaults} defaults stored in the ROM",
        }

    def _drawn_label(self, e: int) -> str:
        """An item's label as its script draws it."""
        screen = Screen()
        it = self._interp(screen, ext=False)
        it.col, it.row = 0, 0
        try:
            self._run_label(it, e)
        except Exception:
            return ""
        return screen.text().split("\n", maxsplit=1)[0].strip()

    def _value(self, e: int, flags: int, defaults: str) -> bytes | None:
        seg = self.seg
        mask, opt = (
            struct.unpack_from("<H", seg, e + 9)[0],
            struct.unpack_from("<H", seg, e + 0x0B)[0],
        )
        if not mask or flags & 0x0004:  # 0004: status line (e.g. temperatures), filled at run time
            return None
        default = struct.unpack_from("<H", seg, e + (0x15 if defaults == "setup" else 0x13))[0]
        shift = (mask & -mask).bit_length() - 1
        index, maximum = (default & mask) >> shift, seg[e + 0x0F]
        if flags & 0x0100:
            return f"{index:0{len(str(maximum))}d}".encode()
        if opt and index <= maximum:
            return self._option_text(opt, index)
        return None
