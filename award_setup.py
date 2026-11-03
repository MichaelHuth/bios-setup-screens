"""
Rebuild Award BIOS setup screens (Award Modular BIOS 4.5x, e.g. 4.51PG) from the system BIOS
module, by interpreting Award's screen-script byte code the way the BIOS does.

Reverse-engineered from an Asus P2B BIOS (Award 4.51PG, interpreter at F000:2C1A):
  00/01 end                         02 x1 y1 x2 y2 f   box (f bit0 double, bit1 clear,
                                                      bit3 no frame)
  03 x1 y1 x2 y2  clear area        04 x y ptr          run sub-script at (x,y), FF = keep
  05 x y          cursor, FF = keep 06/07/08/0A         color = scheme[1]/[2]/[0]/[3]
  09              blink on          0B                  new line
  0C/0D/0E/0F n   cursor right/left/down/up
  10 ptr          native call (dynamic content, not reproduced)
  11 n            select color scheme n>>4
  >= 0x15         print character
Menus are described by records (item table start, item table end, frame script, ...); items are
25 bytes: +2 label script, +0x0B text (main menu), +0x11 column, +0x12 row, +0x17 help script.
The main menu is drawn in scheme[0] with the selected item in scheme[2].

Command numbers differ between BIOS versions (e.g. in another 4.51PG variant 0A is "next row"
and 0D "back to the left margin"), so each command is identified from its handler code in the
ROM (HANDLER_SIGNATURES) rather than from its number. Unknown handlers stop the script.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

import capstone as cs

import lzh
from textscreen import Screen

# lodsb / end on 0 or 1 / (6.00PG: extra checks, e.g. for 0Bh) / cmp al,N / jbe dispatch /
# else print the character / dispatch through a jump table: call cs:[bx+table]
DISPATCH = re.compile(  # (between the jbe and the jump table: a call for characters, or
    # first a check for a double-byte font, INT 10h AH=AAh, as in BIOSes with Chinese texts;
    # Gigabyte's of 2003 and later swap the attributes after the lodsb)
    rb"\xac(?:\x50\xf6\x86.{3}\x74.{12,16}?\x58)?\x3c\x00\x74.\x3c\x01\x74..{0,24}?\x3c(.)\x76."
    rb"(?:\xe8..\xeb.|.{6,80}?)"  # (30 bytes on Gigabyte GA-8N SLI Pro: a call and the check;
    # 58 on MSI MS-7548 for HP, a double-byte font check with INT 10h AH=AAh)
    rb"\x32\xff\xd0\xe0\x8a\xd8\x2e\xff\x97(..)",
    re.S,
)
# Color scheme table: set right after the mono/color check (cmp al,7 / je / mov ah,1 /
# mov word [bp+X], table); 4.51PG keeps the pointer at [bp+14Bh], 6.00PG at [bp+19Eh]
SCHEME_BASE = re.compile(
    rb"\x3c\x07\x74.\xb4\x01\xc7\x86..(..)|\xb9(..)\x03\xc1\x89\x86\x4b\x01", re.S
)
DEFAULT_SCHEME = [0x1F, 0x1E, 0x4F, 0x1F]
ITEM_SIZE = 0x19
LABEL_MARK = 0xFF00  # a label word from here on: the row's label is in the extension module

# Handlers are recognized from their disassembly (first instructions joined with " | "), so the
# same rules cover 4.51PG and 6.00PG, which keep their variables at different [bp+X] offsets.
# {COL}/{ROW} stand for the cursor variables, taken from the goto handler.
HANDLER_RULES = [
    (r"ret", "end", 0),
    (r"push bx \| dec si \| mov bx, si \| test byte ptr \[bx \+ 5\]", "box", 5),
    (
        r"push bx \| dec si \| mov bx, si \| push ax \| mov al, byte ptr \[si \+ 3\] \| "
        r"sub al, byte ptr \[si \+ 1\]",
        "box",
        5,
    ),  # (centre first: ASUS M2NBP-VM, 2007)
    (
        r"pushaw \| lodsw ax, word ptr \[si\] \| mov cx, ax \| lodsw ax, word ptr \[si\] \| "
        r"mov dx, ax \| mov ax, 0x600",
        "clear",
        4,
    ),
    (r"push bx \| dec si \| mov bx, si \| mov al, byte ptr \[bx \+ 1\] \| cmp al, 0xff", "call", 4),
    (r"push ax \| lodsb al, byte ptr \[si\] \| cmp al, 0xff", "goto", 2),
    (
        r"push ax \| push bx \| mov bx, word ptr \[bp \+ 0x\w+\] \| mov al, byte ptr cs:\[bx\] \| "
        r"mov byte ptr \[bp \+ 0x\w+\], al",
        "color0",
        0,
    ),
    (
        r"push ax \| push bx \| mov bx, word ptr \[bp \+ 0x\w+\] \| mov al, byte ptr cs:"
        r"\[bx \+ (\d+)\] \| mov byte ptr \[bp \+ 0x\w+\], al",
        "color",
        0,
    ),
    (
        r"(?:test byte ptr \[bp \+ 0x\w+\], \w+ \| jne 0x\w+ \| )?push ax \| mov ax, (\d+) \| "
        r"call 0x\w+ \| pop ax \| ret",
        "color",
        0,
    ),
    (r"or byte ptr \[bp \+ 0x\w+\], 0x80 \| ret", "blink", 0),
    (r"push ax \| pushf \| (?:inc byte ptr \[bp \+ {ROW}\]|test byte ptr)", "newline", 0),
    (r"push ax \| mov al, byte ptr \[bp \+ {ROW}\] \| cmp al", "next_row", 0),
    (
        r"push ax \| mov al, byte ptr \[bp \+ 0x\w+\] "
        r"\| mov byte ptr \[bp \+ {COL}\], al \| pop ax",
        "margin",
        0,
    ),
    (r"lodsb al, byte ptr \[si\] \| add byte ptr \[bp \+ {COL}\], al \| ret", "right", 1),
    (r"lodsb al, byte ptr \[si\] \| sub byte ptr \[bp \+ {COL}\], al \| ret", "left", 1),
    (r"lodsb al, byte ptr \[si\] \| add byte ptr \[bp \+ {ROW}\], al \| ret", "down", 1),
    (r"lodsb al, byte ptr \[si\] \| sub byte ptr \[bp \+ {ROW}\], al \| ret", "up", 1),
    (r"lodsw ax, word ptr \[si\] \| push ds \| push si \| call ax", "native", 2),
    (r"lodsb al, byte ptr \[si\] \| call 0x\w+ \| ret", "scheme", 1),
    (r"mov si, word ptr \[si\] \| ret", "jump", 2),
    (r"push ds \| push si \| mov si, word ptr \[si\] \| call 0x\w+", "subscript", 2),
]
_md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_16)


def _code_text(seg: bytes, handler: int, count: int = 8) -> str:
    return " | ".join(
        f"{i.mnemonic} {i.op_str}".strip()
        for i in list(_md.disasm(seg[handler : handler + 48], handler))[:count]
    )


def classify_ops(seg: bytes, table: int, count: int) -> dict[int, tuple[str, int, int]]:
    """Map command number -> (kind, argument bytes, color index) from the handler code."""
    handlers = [struct.unpack_from("<H", seg, table + 2 * op)[0] for op in range(count)]
    texts = [_code_text(seg, h) for h in handlers]
    col = row = r"0x\w+"
    for t in texts:  # the goto handler stores the column first, the row is the next byte
        m = re.match(
            r"push ax \| lodsb al, byte ptr \[si\] \| cmp al, 0xff \| je 0x\w+ \| "
            r"mov byte ptr \[bp \+ (0x\w+)\], al",
            t,
        )
        if m:
            col, row = m.group(1), hex(int(m.group(1), 16) + 1)
            break
    ops = {}
    for op, text in enumerate(texts):
        ops[op] = ("unknown", 0, -1)
        for pattern, kind, nargs in HANDLER_RULES:
            m = re.match(pattern.replace("{COL}", col).replace("{ROW}", row), text)
            if m:
                index = 0 if kind == "color0" else int(m.group(1)) if kind == "color" else -1
                ops[op] = ("color" if kind == "color0" else kind, nargs, index)
                break
    return ops


@dataclass
class Interpreter:
    data: bytes
    base: int  # file offset of segment F000
    screen: Screen
    schemes: list[list[int]]
    col: int = 0
    row: int = 0
    attr: int = 0x1F
    scheme: list[int] = field(default_factory=lambda: list(DEFAULT_SCHEME))
    interp: int = 0  # interpreter offset in segment F000
    ops: dict = field(default_factory=dict)  # command number -> (kind, args, color index)
    last_char: int = 0x14  # commands are 02..last_char, higher bytes are characters
    margin: int = 0
    dynamic: int = 0  # native calls skipped
    unknown: set = field(default_factory=set)  # commands whose handler was not recognized
    lang: bytes | None = None  # language module (Phoenix-Award: "lang" prints a text by its ID)

    def lang_offset(self, ident: int) -> int | None:
        """Offset of text ident (section << 8 | index) in the language module: a word count of
        sections at 10h, their offsets after it; each section is a count and text offsets."""
        lang = self.lang
        section, index = ident >> 8, ident & 0xFF
        if lang is None or section >= struct.unpack_from("<H", lang, 0x10)[0]:
            return None
        table = struct.unpack_from("<H", lang, 0x12 + 2 * section)[0]
        if index >= struct.unpack_from("<H", lang, table)[0]:
            return None
        return struct.unpack_from("<H", lang, table + 2 + 2 * index)[0]

    def run_lang(self, ident: int, depth: int = 0) -> None:
        """Print a text of the language module; its scripts address the module itself."""
        off = self.lang_offset(ident)
        if off is None:
            return
        assert self.lang is not None
        self.run_in(self.lang, off, depth)

    def run_in(self, module: bytes, off: int, depth: int = 0) -> None:
        """Run a script of another module (language, extension), which addresses itself."""
        # (a text's lines start where the text does: ASUS P4GE-MX's key help in the panel)
        saved = self.data, self.base, self.margin
        self.data, self.base, self.margin = module, 0, self.col
        try:
            self.run(off, depth + 1)
        finally:
            self.data, self.base, self.margin = saved

    def byte(self, off: int) -> int:
        return self.data[self.base + (off & 0xFFFF)]

    def word(self, off: int) -> int:
        return self.byte(off) | self.byte(off + 1) << 8

    def putc(self, ch: int) -> None:
        self.screen.put(self.col, self.row, ch, self.attr)
        self.col += 1

    def box(self, x1: int, y1: int, x2: int, y2: int, flags: int) -> None:
        if flags & 2:
            self.screen.fill(x1, y1, x2, y2, self.attr)
        if flags & 8:
            return
        dbl = flags & 1
        h, v = (0xCD, 0xBA) if dbl else (0xC4, 0xB3)
        for x in range(x1, x2 + 1):
            self.screen.put(x, y1, h, self.attr)
        for x in range(x1, x2):
            self.screen.put(x, y2, h, self.attr)
        start, count = y1 + 1, y2 - y1 - 1
        if x1 == x2:
            start, count = y1, count + 2
        for y in range(start, start + max(0, count)):
            self.screen.put(x1, y, v, self.attr)
            self.screen.put(x2, y, v, self.attr)
        if x1 == x2 or y1 == y2:
            return
        corners = (0xC9, 0xBB, 0xC8, 0xBC) if dbl else (0xDA, 0xBF, 0xC0, 0xD9)
        for (x, y), ch in zip(((x1, y1), (x2, y1), (x1, y2), (x2, y2)), corners):
            self.screen.put(x, y, ch, self.attr)

    def _native_script(self, target: int, depth: int) -> bool:
        """Many native helpers only check a condition and then print another script
        ("mov si, script / call interpreter", sometimes followed by "inc row"). Run that script
        (assuming the condition holds) instead of skipping the call."""
        code = bytes(self.byte(target + i) for i in range(28))
        for i in range(len(code) - 6):
            if code[i] == 0xBE and code[i + 3] == 0xE8:
                rel = struct.unpack_from("<h", code, i + 4)[0]
                if (target + i + 6 + rel) & 0xFFFF == self.interp:
                    self.run(struct.unpack_from("<H", code, i + 1)[0], depth + 1)
                    if b"\xfe\x86\x82\x00" in code[i + 6 : i + 14]:  # inc byte [bp+82]: next row
                        self.row += 1
                    return True
        return False

    def run(self, off: int, depth: int = 0) -> None:
        if depth > 8:
            return
        for _ in range(4000):  # guard against runaway scripts
            op = self.byte(off)
            off += 1
            if op > self.last_char:
                self.putc(op)
                continue
            kind, nargs, index = self.ops.get(op, ("end", 0, -1))
            args = [self.byte(off + i) for i in range(nargs)]
            off += nargs
            if kind == "end":
                return
            if kind == "unknown":
                self.unknown.add(op)
                return
            if kind == "box":
                self.box(*args)
            elif kind == "clear":
                self.screen.fill(args[0], args[1], args[2], args[3], self.attr)
            elif kind in ("goto", "call"):
                if args[0] != 0xFF:
                    self.col = self.margin = args[0]
                if args[1] != 0xFF:
                    self.row = args[1]
                if kind == "call":
                    self.run(args[2] | args[3] << 8, depth + 1)
            elif kind == "color":
                self.attr = self.scheme[index] if index < len(self.scheme) else self.attr
            elif kind == "blink":
                self.attr |= 0x80
            elif kind == "newline":
                self.row, self.col = self.row + 1, self.margin
            elif kind == "next_row":
                self.row += 1
            elif kind == "margin":
                self.col = self.margin
            elif kind in ("right", "left", "down", "up"):
                n = args[0] if kind in ("right", "down") else -args[0]
                if kind in ("right", "left"):
                    self.col += n
                else:
                    self.row += n
            elif kind == "native":
                if not self._native_script(args[0] | args[1] << 8, depth):
                    self.dynamic += 1
            elif kind == "jump":  # continue the script at another address
                off = args[0] | args[1] << 8
            elif kind == "lang":
                self.run_lang(args[0] | args[1] << 8, depth)
            elif kind == "subscript":  # run another script at the current position
                self.run(args[0] | args[1] << 8, depth + 1)
            elif kind == "scheme":
                if args[0] >> 4 < len(self.schemes):
                    self.scheme = self.schemes[args[0] >> 4]


def _find(data: bytes) -> tuple[int, int, int]:
    """Returns (F000 base, interpreter offset, jump table offset) or raises."""
    if len(data) < 0x10000:
        raise ValueError("too small for an Award system BIOS module")
    base = len(data) - 0x10000
    m = DISPATCH.search(data, base)
    if not m:
        raise ValueError(
            "no Award screen-script interpreter found (needs the unpacked system "
            "BIOS module of an Award 4.5x BIOS, e.g. from unpack_rom)"
        )
    return base, m.start() - base - 4, struct.unpack("<H", m.group(2))[0]


def _dispatch(data: bytes) -> tuple[int, dict]:
    """(highest command number, command map) for this ROM's interpreter."""
    base = len(data) - 0x10000
    m = DISPATCH.search(data, base)
    assert m is not None
    last_char = m.group(1)[0]
    table = struct.unpack("<H", m.group(2))[0]
    seg = data[base:]
    # the jump table ends where the first handler begins
    handlers = [struct.unpack_from("<H", seg, table + 2 * i)[0] for i in range(last_char + 1)]
    count = 0
    while count <= last_char and table + 2 * count < min(h for h in handlers if h > table):
        count += 1
    return last_char, classify_ops(seg, table, count)


def _schemes(data: bytes, base: int) -> list[list[int]]:
    m = SCHEME_BASE.search(data, base)
    if not m:
        return [list(DEFAULT_SCHEME)]
    tab = base + struct.unpack("<H", m.group(1) or m.group(2))[0]
    out = []
    for i in range(8):
        s = list(data[tab + 4 * i : tab + 4 * i + 4])
        if len(s) < 4 or any(a == 0 for a in s):
            break
        out.append(s)
    return out or [list(DEFAULT_SCHEME)]


def _make(data: bytes, screen: Screen) -> Interpreter:
    base, interp, _ = _find(data)
    schemes = _schemes(data, base)
    last_char, ops = _dispatch(data)
    it = Interpreter(
        data,
        base,
        screen,
        schemes,
        scheme=list(schemes[0]),
        interp=interp,
        ops=ops,
        last_char=last_char,
    )
    it.attr = it.scheme[0]
    return it


def _is_text(data: bytes, base: int, ptr: int) -> bool:
    s = data[base + ptr : base + ptr + 40]
    end = s.find(b"\0")
    return end >= 3 and all(0x20 <= c < 0x7F for c in s[:end])


def _menu_tables(data: bytes, base: int, any_script: bool = False) -> list[tuple[int, int, int]]:
    """Descriptor records (item table start, end, frame script) found in segment F000. The
    frame script must start with a drawing command unless any_script (the main menu is
    recognised by its texts; some versions start its script with other commands)."""
    found = []
    seg = data[base:]
    for i in range(0, len(seg) - 6, 1):
        start, end, script = struct.unpack_from("<HHH", seg, i)
        if (
            not (0 < start < end <= 0xFFF0)
            or (end - start) % ITEM_SIZE
            or not 2 <= (end - start) // ITEM_SIZE <= 40
        ):
            continue
        ok = True
        for e in range(start, end, ITEM_SIZE):
            col, row = seg[e + 0x11], seg[e + 0x12]
            if col >= 80 or row >= 25:
                ok = False
                break
        if (
            ok
            and script < 0xFFF0
            and (any_script or seg[script] in (2, 3, 4, 5, 6, 7, 8, 0x0A, 0x11))
        ):
            found.append((start, end, script))
    return found


def _string(seg: bytes, ptr: int) -> str:
    end = seg.find(b"\0", ptr)
    return seg[ptr : end if end >= 0 else ptr + 80].decode("cp437")


def _option(seg: bytes, ptr: int, index: int) -> bytes | None:
    """The index-th string of an option list. Entries end with NUL or with 01h (the I/O
    recovery times: "NA", then blanks for the values the enable bit leaves unused, then
    "8", "1" ... "7", the blanks ended by 01h)."""

    def end_of(at: int) -> int:
        while at < len(seg) and seg[at] > 1:
            at += 1
        return at

    for _ in range(index):
        ptr = end_of(ptr) + 1
        if ptr >= len(seg):
            return None
    text = seg[ptr : end_of(ptr)]
    return text if text and all(0x20 <= c < 0x7F for c in text) else None


def _label_text(seg: bytes, ptr: int) -> str:
    out: list[str] = []
    i = ptr
    while i < len(seg) and seg[i] and len(out) < 60:  # (a stray pointer may run off the end)
        if seg[i] >= 0x20:
            out.append(chr(seg[i]))
        elif seg[i] in (0x0C, 0x0D, 0x0E, 0x0F, 0x11):
            i += 1  # skip the argument byte
        i += 1
    return "".join(out).strip()


LabelTable = tuple[bytes, list[tuple[int, str]]]


def _module_text(module: bytes, off: int) -> str | None:
    """The printable NUL-ended text at off, or None."""
    end = module.find(b"\0", off) if 0 < off < len(module) else -1
    text = module[off:end]
    if end < 0 or not 4 <= len(text) <= 120 or not all(0x20 <= c < 0x7F for c in text):
        return None
    return text.decode("latin-1")


def extension_labels(image: bytes) -> list[LabelTable]:
    """The label tables of the image's Award extension modules (awardext.rom): runs of three or
    more words that each point at a text, most of the texts ending in a colon. An item whose
    label word is FF00h + n takes its label from entry n of such a table (ABIT BH6's BIOS
    FEATURES SETUP and CPU SOFT MENU II)."""
    tables: list[LabelTable] = []
    for m in lzh.find_modules(image):
        if "ext" not in m["name"].lower():
            continue
        try:
            module = lzh.decompress(
                image[m["data_start"] : m["data_start"] + m["packed"]],
                m["size"],
                m["method"].encode(),
            )
        except Exception:  # pylint: disable=broad-exception-caught
            continue
        at = 0
        while at + 4 <= len(module):  # (byte by byte: BH6's CPU menu table is at an odd offset)
            run: list[tuple[int, str]] = []
            while at + 4 <= len(module):
                off = struct.unpack_from("<H", module, at)[0]
                if (text := _module_text(module, off)) is None:
                    break
                run.append((off, text))
                at += 2
            if len(run) >= 3 and 2 * sum(t.rstrip().endswith(":") for _, t in run) >= len(run):
                tables.append((module, run))
            at += 1
    return tables


def _page_labels(tables: list[LabelTable], marks: list[int]) -> LabelTable | None:
    """The label table of a page whose rows carry markers: the shortest one long enough for the
    largest marker, if only one is that long (the page record does not name it)."""
    if not marks:
        return None
    fits = [t for t in tables if len(t[1]) > max(marks)]
    shortest = [t for t in fits if len(t[1]) == min(len(f[1]) for f in fits)]
    return shortest[0] if len(shortest) == 1 else None


def setup_page(
    data: bytes,
    table: tuple[int, int, int],
    defaults: str = "setup",
    labels: list[LabelTable] | None = None,
) -> tuple[Screen, dict]:
    """A sub-page (BIOS FEATURES SETUP etc.): frame, item labels and default values. labels
    are the extension modules' label tables (extension_labels)."""
    base, _, _ = _find(data)
    seg = data[base:]
    start, end, script = table
    screen = Screen()
    it = _make(data, screen)
    screen.fill(0, 0, 79, 24, it.attr)
    it.run(script)
    marks = [struct.unpack_from("<H", seg, e + 2)[0] for e in range(start, end, ITEM_SIZE)]
    page_labels = _page_labels(labels or [], [m - LABEL_MARK for m in marks if m >= LABEL_MARK])
    items, first = [], True
    for e in range(start, end, ITEM_SIZE):
        flags, label_ptr = struct.unpack_from("<HH", seg, e)
        if flags & 8:  # not drawn
            continue
        cmos, mask, opt_ptr = (
            seg[e + 8],
            struct.unpack_from("<H", seg, e + 9)[0],
            struct.unpack_from("<H", seg, e + 0x0B)[0],
        )
        it.col, it.row = seg[e + 0x11], seg[e + 0x12]
        it.attr = it.scheme[0]
        if label_ptr < LABEL_MARK:
            it.run(label_ptr)
            label = _label_text(seg, label_ptr)
        else:  # (F000:FF00h + n holds code: no label rather than its bytes)
            label = ""
            if page_labels is not None and label_ptr - LABEL_MARK < len(page_labels[1]):
                off, label = page_labels[1][label_ptr - LABEL_MARK]
                it.run_in(page_labels[0], off)
        default = struct.unpack_from("<H", seg, e + (0x15 if defaults == "setup" else 0x13))[0]
        value = None
        if mask:
            shift = (mask & -mask).bit_length() - 1
            index, maximum = (default & mask) >> shift, seg[e + 0x0F]
            low = struct.unpack_from("<H", seg, e + 0x0D)[0]
            if flags & 0x0100:  # numeric field (e.g. alarm time): the value itself
                value = f"{index:0{len(str(maximum))}d}".encode()
            elif low and opt_ptr:
                # enable bit + count (8/16 Bit I/O Recovery Time): +0Dh masks the count, the
                # options are NA (enable bit clear), then count 0, 1, 2, ...
                value = _option(seg, opt_ptr, (index & low) + 1 if index > low else 0)
            elif opt_ptr and index <= maximum:
                value = _option(seg, opt_ptr, index)
        if value is not None:
            it.attr = it.scheme[2] if first else it.scheme[1]
            first = False
            for ch in value:
                it.putc(ch)
        items.append(
            {
                "label": label,
                "value": value.decode("cp437") if value else None,
                "cmos": f"{cmos:02X}h mask {mask:04X}" if mask else None,
            }
        )
    info = {
        "item_table": f"F000:{start:04X}-F000:{end:04X}",
        "frame_script": f"F000:{script:04X}",
        "unknown_commands": [f"{c:02X}h" for c in sorted(it.unknown)],
        "values": f"{defaults} defaults stored in the ROM (a real PC shows the values in its CMOS)",
        "items": items,
    }
    return screen, info


def pages(data: bytes) -> list[tuple[int, int, int]]:
    """Sub-page tables (items with label scripts), in ROM order."""
    base, _, _ = _find(data)
    seg = data[base:]
    out = []
    for s, e, sc in _menu_tables(data, base):
        labels = [struct.unpack_from("<H", seg, x + 2)[0] for x in range(s, e, ITEM_SIZE)]
        if sum(1 for p in labels if _label_text(seg, p)) >= (e - s) // ITEM_SIZE // 2:
            # a real page has a title in its frame script; random data matching the table
            # layout does not
            if not page_title(data, (s, e, sc)).startswith("page F000:"):
                out.append((s, e, sc))
    return out


def page_title(data: bytes, table: tuple[int, int, int]) -> str:
    """The page title from the frame script (the first all-caps text it prints)."""
    screen = Screen()
    _make(data, screen).run(table[2])
    for line in screen.text().splitlines()[:4]:
        words = line.strip(" ║│")
        if (
            words.isupper()
            and len(words) > 5
            and "AWARD SOFTWARE" not in words
            and not words.startswith("ROM ")
        ):
            return words
    return f"page F000:{table[0]:04X}"


def main_menu(data: bytes) -> tuple[Screen, dict]:
    base, interp_off, _ = _find(data)
    schemes = _schemes(data, base)
    seg = data[base:]

    def texts(s: int, e: int) -> list[str | None]:
        out = []
        for x in range(s, e, ITEM_SIZE):
            p = struct.unpack_from("<H", seg, x + 0x0B)[0]
            out.append(_string(seg, p) if _is_text(data, base, p) else None)
        return out

    menus = []
    for s, e, sc in _menu_tables(data, base, any_script=True):
        t = texts(s, e)
        # main menu entries are upper-case commands like "BIOS FEATURES SETUP", "SAVE & EXIT SETUP"
        # - mostly: OEMs mix their own names in ("SpeedEasy CPU SETUP", " PC Health Status ")
        # - (a hidden entry or two may have no text, e.g. Gigabyte GA-6BXC)
        shown = [x for x in t if x]
        if (
            len(shown) >= max(2, len(t) - 2)
            and sum(1 for x in shown if x == x.upper()) * 2 >= len(shown)
            and any(k in x for x in shown for k in ("SETUP", "SAVE", "EXIT"))
        ):
            menus.append((s, e, sc))
    if not menus:
        raise ValueError("main menu table not found in this file")
    start, end, script = menus[0]
    screen = Screen()
    it = _make(data, screen)
    screen.fill(0, 0, 79, 24, it.attr)
    it.run(script)
    items = []
    for n, e in enumerate(range(start, end, ITEM_SIZE)):
        text_ptr = struct.unpack_from("<H", seg, e + 0x0B)[0]
        help_ptr = struct.unpack_from("<H", seg, e + 0x17)[0]
        if not _is_text(data, base, text_ptr):  # a hidden entry
            continue
        it.col, it.row = seg[e + 0x11], seg[e + 0x12]
        it.attr = it.scheme[2] if n == 0 else it.scheme[0]  # first item selected
        it.run(text_ptr)
        name = seg[text_ptr : seg.index(b"\0", text_ptr)].decode("latin-1")
        items.append(name)
        # the first entry's help line: a script that places itself (some versions keep other
        # data in this field of the main menu's entries, e.g. ABIT BH6)
        if n == 0 and help_ptr and seg[help_ptr] < 0x20 and seg[help_ptr] in it.ops:
            it.attr = it.scheme[0]
            it.run(help_ptr)
    info = {
        "interpreter": f"F000:{interp_off:04X}",
        "frame_script": f"F000:{script:04X}",
        "item_table": f"F000:{start:04X}-F000:{end:04X}",
        "items": items,
        "unknown_commands": [f"{c:02X}h" for c in sorted(it.unknown)],
        "color_schemes": [" ".join(f"{a:02X}" for a in s) for s in schemes],
    }
    return screen, info
