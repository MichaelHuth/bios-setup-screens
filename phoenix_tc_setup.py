"""
Read the setup of Phoenix TrustedCore / SecureCore firmware (about 2006-10, "BCPFFV") from
the image without running it, and draw it in the layout of PhoenixBIOS's text-mode setup.

How the data is laid out:
- the modules are in Phoenix's own flash file volumes (not UEFI's): a volume directory module
  "volumedir.bin2" (GUID, base, length per volume) or the older "volumedir.bin" (type,
  base, length), bases being addresses below 4 GB; files of 24-byte headers (F8h, flags,
  checksum, 24-bit length, type, a 16-byte name with FFh at index 8), not always back to back;
  every module body is one compression section holding an LH5 stream;
- the setup is three modules: _E00 (the code), _T00 (the template: records of mode, length
  and 16-bit fields) and _S00 (a STRPACK-BIOS string pack, reached in two hops: a field is a
  reference, S + 20h + reference holds the offset of the text, also from S + 20h);
- a pick record (mode 00h/01h) holds the prompt, the help, four entry points, the NVRAM token
  and the options; mode 10h records are texts (titles, blank lines, notes);
- between the template's header and its records are tables of (record, table) pairs ended by
  (0, 0), the pointers counting from the end of the module's 4-byte section header: the menu
  bar is one (a title record and the menu's item table per entry), each menu's items another,
  and an item with a table of its own opens a sub-menu.
PhoenixBIOS 4.0 of about 1998-2000 has the same template and string pack as modules of its
own (Intel's, a server board's), read when its POST cannot run: the
pointers count from the module's start, the string pack's base is 1Ch (found per image).
The defaults are not in the template (the setup keeps its values in NVRAM, erased in the
images), so the first option is shown. Templates without a menu-bar table are listed in the
order of their records, several screens in a row.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

import lzh
from textscreen import Screen

FFV_MODULES = bytes.fromhex("BA1FD9FE7BD3EA4E87292EF29FB37A78")  # FED91FBA-D37B-4EEA-...
STRINGS_BASE = 0x20  # the string pack's header in the module
PICK, TEXT, INFO, DATE, TIME, PASSWORD = (0x00, 0x01), 0x10, 0x11, 0x20, 0x21, 0x22
MODES = (0x00, 0x01, 0x10, 0x11, 0x20, 0x21, 0x22, 0x24, 0xFF)
TREE_MODES = MODES + (0x23, 0x27, 0x35)  # (more modes of the templates, meaning unknown)
PTR = 4  # (pointers in _T00 count from the end of its section header)
MIN_RECORDS = 10  # (a chain of records shorter than this is taken for chance)
MAX_DEPTH = 4  # sub-menus followed
ROWS = 17  # items per screen (rows 4-20)
TITLE_ATTR, BAR_ATTR, BAR_SEL_ATTR = 0x1F, 0x17, 0x71
BODY_ATTR, ITEM_ATTR, VALUE_ATTR, SEL_ATTR = 0x70, 0x71, 0x71, 0x1F
HELP_ATTR, KEYS_ATTR = 0x70, 0x30
VALUES = {DATE: "[01/01/2008]", TIME: "[00:00:00]", PASSWORD: "[Enter]"}
TAB_ORDER = (
    "Main",
    "Advanced",
    "Security",
    "Power",
    "Power Management",
    "Server",
    "Boot",
    "Exit",
)


def is_trustedcore(rom: bytes) -> bool:
    return b"BCPFFV" in rom and b"volumedi\xffr.bin" in rom


def _files(rom: bytes, off: int, end: int) -> list[tuple[str, int, int]]:
    """(name, body start, body end) of each file in a volume; a byte that starts no file
    header is skipped."""
    out = []
    while off + 0x18 <= end:
        size = int.from_bytes(rom[off + 4 : off + 7], "little")
        if rom[off] != 0xF8 or size < 0x18 or off + size > end + 1:
            off += 1
            continue
        name = rom[off + 8 : off + 16] + rom[off + 17 : off + 24]
        if rom[off + 16] == 0xFF and rom[off + 7] == 0x02:  # (a named file of sections)
            text = name.split(b"\0")[0].split(b"\xff")[0].decode("latin-1")
            out.append((text, off + 0x18, off + size))
        off += size - 1
    return out


def _volumes(rom: bytes) -> list[tuple[int, int]]:
    """(offset, end) in the file of each module volume of the volume directory."""
    top = 1 << (len(rom).bit_length() - 1)  # (the image at the top of 4 GB, power of two)
    out: list[tuple[int, int]] = []
    at, v2 = rom.find(b"volumedi\xffr.bin2"), True
    if at < 8:
        at, v2 = rom.find(b"volumedi\xffr.bin"), False
    if at < 8:
        return out
    entries = at - 8 + 0x18
    if v2:
        count = (struct.unpack_from("<I", rom, entries + 4)[0] - 8) // 24
        for i in range(min(max(count, 0), 200)):
            e = entries + 8 + 24 * i
            if e + 24 > len(rom):
                break
            if rom[e : e + 16] == FFV_MODULES:
                base, length = struct.unpack_from("<II", rom, e + 16)
                out.append(((base + top) & 0xFFFFFFFF, length))
    else:
        size = int.from_bytes(rom[at - 4 : at - 1], "little")
        for i in range(min((size - 0x18) // 9, 200)):
            e = entries + 9 * i
            if e + 9 > len(rom):
                break
            if rom[e] == 2:  # (a volume of files)
                base, length = struct.unpack_from("<II", rom, e + 1)
                out.append(((base + top) & 0xFFFFFFFF, length))
    return [(off, min(len(rom), off + length)) for off, length in out if 0 <= off < len(rom)]


def _unpacked(rom: bytes, start: int, end: int) -> bytes | None:
    """The body of a file: its compression section's LH5 stream, unpacked (the compression
    header overlaps the section header: size, type, packed size, -, real size, -)."""
    if start + 12 > end or rom[start + 3] != 0x01:
        return None
    packed = int.from_bytes(rom[start + 4 : start + 7], "little")
    real = int.from_bytes(rom[start + 8 : start + 11], "little")
    if not packed or not real:
        return None
    try:
        return lzh.decompress(rom[start + 12 : start + 12 + packed], real, b"-lh5-")
    except (ValueError, IndexError, EOFError):
        return None


def setup_modules(rom: bytes) -> tuple[bytes, bytes]:
    """(_S00, _T00) unpacked."""
    found: dict[str, bytes] = {}
    for off, end in _volumes(rom):
        for name, start, stop in _files(rom, off, end):
            if name in ("_S00", "_T00") and name not in found:
                if (body := _unpacked(rom, start, stop)) is not None:
                    found[name] = body
    if "_S00" not in found or "_T00" not in found:
        raise ValueError(
            "this Phoenix TrustedCore/SecureCore image has no setup template and strings "
            "(_T00, _S00) that could be unpacked"
        )
    return found["_S00"], found["_T00"]


def _u16(data: bytes, at: int) -> int:
    return int.from_bytes(data[at : at + 2], "little") if 0 <= at and at + 2 <= len(data) else 0


def strings_base(pack: bytes) -> int:
    """Where a string pack's references count from: the base at which most of the first
    entries point at a text just after a NUL (20h in TrustedCore, 1Ch in PhoenixBIOS 4.0)."""

    def texts(base: int) -> int:
        found = 0
        for at in range(base, min(len(pack) - 1, base + 0x1000), 2):
            text = base + _u16(pack, at)
            found += base < text < len(pack) and pack[text - 1] == 0 and 32 <= pack[text] < 127
        return found

    return max(range(0x10, 0x30), key=texts)


class Strings:
    """The _S00 string pack, by two-hop reference."""

    def __init__(self, pack: bytes, base: int = STRINGS_BASE):
        self.pack, self.base = pack, base

    def __call__(self, ref: int) -> str:
        if not ref:
            return ""
        offset = _u16(self.pack, self.base + ref)
        return self._at(self.base + offset) if offset else ""

    def after(self, ref: int) -> str:
        """The text that follows ref's in the pack (after the language prompt: the name of
        the pack's own language, "English  (US)")."""
        if not ref or not (offset := _u16(self.pack, self.base + ref)):
            return ""
        end = self.pack.find(b"\0", self.base + offset)
        return self._at(end + 1) if end >= 0 else ""

    def _at(self, at: int) -> str:
        if at >= len(self.pack):
            return ""
        end = self.pack.find(b"\0", at)
        text = self.pack[at:end] if 0 < end - at <= 400 else b""
        for i, c in enumerate(text):  # (some texts are followed by data bytes: cut there)
            if c >= 0x80:
                text = text[:i]
                break
        if not text or any(not (32 <= c < 127 or c in (9, 10, 13)) for c in text):
            return ""
        return text.decode("latin-1").rstrip()


def _chains(template: bytes) -> list[tuple[int, int]]:
    """(start, end) of each run of at least MIN_RECORDS back-to-back records."""
    out, p = [], 0
    while p + 2 <= len(template):
        q, count = p, 0
        while q + 2 <= len(template) and template[q] in MODES and 4 <= template[q + 1] <= 0x40:
            count += 1
            q += template[q + 1]
        if count >= MIN_RECORDS:
            out.append((p, q))
            p = q
        else:
            p += 1
    return out


def _record(template: bytes, at: int) -> tuple[int, list[int]] | None:
    """(mode, fields) of the record at `at`."""
    if not 0 <= at < len(template) - 1 or template[at] not in TREE_MODES:
        return None
    length = template[at + 1]
    if length < 4 or at + length > len(template):
        return None
    return template[at], [_u16(template, at + 2 + 2 * k) for k in range((length - 2) // 2)]


def _table(template: bytes, at: int, ptr: int = PTR) -> list[tuple[int, int]]:
    """A table of (record, table) pairs, ended by (0, 0)."""
    out: list[tuple[int, int]] = []
    while at + 3 < len(template) and len(out) < 200:
        rec, sub = _u16(template, at), _u16(template, at + 2)
        if not rec and not sub:
            break
        out.append((rec + ptr, sub + ptr if sub else 0))
        at += 4
    return out


def _stream_start(template: bytes) -> int | None:
    """Where the records begin (the first run of 30 back-to-back records): the tables are
    before it."""
    for p in range(0x60, len(template) - 4):
        q, n = p, 0
        while q + 2 <= len(template) and template[q] in TREE_MODES and 4 <= template[q + 1] <= 0x40:
            n += 1
            q += template[q + 1]
        if n >= 30:
            return p
    return None


def _menu_bar(template: bytes, strings: Strings, end: int, ptr: int = PTR) -> int | None:
    """The menu-bar table: its first three entries are titles (text records, mode 10h or
    11h) with an item table each; of those the first with "Main" (a row of help keys has the
    same form: F9, F10, ALT-F on Dell's XPS T), else the first."""
    first = None
    for p in range(0x60, end - 12, 2):
        values = [_u16(template, p + 2 * k) for k in range(6)]
        if not all(values[1::2]):
            continue
        records = [_record(template, v + ptr) for v in values[0::2]]
        if all(r and r[0] in (TEXT, INFO) and r[1] and strings(r[1][0]).strip() for r in records):
            if any(r and strings(r[1][0]).strip() == "Main" for r in records):
                return p
            first = p if first is None else first
    return first


def _text_start(strings: Strings, ref: int) -> bool:
    """Does ref lead to the start of a text (after a NUL)? A run of FF00h + n (the language
    list) or a word table read as a record leads into the middle of one."""
    at = strings.base + _u16(strings.pack, strings.base + ref) if ref else 0
    return 0 < at < len(strings.pack) and strings.pack[at - 1] == 0


def _options(strings: Strings, mode: int, fields: list[int], ptr: int) -> list[str]:
    """The texts of a pick item. In PhoenixBIOS 4.0 (no pointer offset) mode 01h is a list
    filled at run time (boot order, drive type): its last fields are a text and a CMOS
    index, whose number as a reference would show some other setting's text."""
    if mode == 0x01 and ptr == 0:
        return []
    refs = fields[7:]
    # (references step by 2, one table word each: a run stepping by 1, FF00h, FF01h, ..., is a
    # marker of a list built at run time, the languages: the pack's own is shown, named by the
    # text after the prompt)
    if any(refs[i + 2] == refs[i + 1] + 1 == refs[i] + 2 for i in range(len(refs) - 2)):
        name = strings.after(fields[0])
        return [name] if name and name != strings(fields[1]) else []
    return [o for o in (strings(f) for f in refs if _text_start(strings, f)) if o]


def _items(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    template: bytes, strings: Strings, table: int, depth: int, seen: set[int], ptr: int = PTR
) -> list[dict]:
    """The items of a menu's table, in screen order; "sub" holds a sub-menu's items."""
    out: list[dict] = []
    if table in seen:
        return out
    seen.add(table)
    for at, sub in _table(template, table, ptr):
        if (record := _record(template, at)) is None:
            continue
        mode, fields = record
        if mode in PICK and not (
            fields and _text_start(strings, fields[0]) and strings(fields[0]).strip()
        ):
            continue  # (no prompt, or the end of a text: not a record but a word table)
        item: dict = {
            "prompt": strings(fields[0]).strip() if fields else "",
            "help": strings(fields[1]) if len(fields) > 1 and mode not in (TEXT, INFO) else "",
            "options": [],
            "mode": mode,
            "sub": None,
        }
        if mode in PICK and len(fields) > 7:
            item["options"] = _options(strings, mode, fields, ptr)
        if mode in VALUES:
            item["value"] = VALUES[mode]
        if sub and mode not in PICK and depth < MAX_DEPTH:
            item["sub"] = _items(template, strings, sub, depth + 1, seen, ptr)
        out.append(item)
    return out


def menu_tree(
    pack: bytes, template: bytes, base: int = STRINGS_BASE, ptr: int = PTR
) -> list[tuple[str, list[dict]]]:
    """[(menu title, items)] of the menu bar; empty if the template has no menu-bar table."""
    strings = Strings(pack, base)
    end = _stream_start(template)
    bar = _menu_bar(template, strings, end, ptr) if end is not None else None
    if bar is None:
        return []
    menus = []
    for at, table in _table(template, bar, ptr):
        record = _record(template, at)
        title = strings(record[1][0]).strip() if record and record[1] else ""
        menus.append((title, _items(template, strings, table, 0, set(), ptr) if table else []))
    return menus


def _walk(items: list[dict], depth: int = 0) -> Iterator[tuple[int, dict]]:
    for item in items:
        yield depth, item
        if item["sub"]:
            yield from _walk(item["sub"], depth + 1)


def _settable(item: dict) -> bool:
    return bool(item["options"] or item.get("value") or item.get("sub"))


class TrustedCoreSetup:
    def __init__(self, rom: bytes, modules: tuple[bytes, bytes] | None = None):
        """modules: (string pack, template) of a PhoenixBIOS 4.0 image (not TrustedCore)."""
        base, ptr = STRINGS_BASE, PTR
        if modules is not None:
            pack, template = modules
            base, ptr = strings_base(pack), 0
        elif not is_trustedcore(rom):
            raise ValueError("not a Phoenix TrustedCore/SecureCore image")
        else:
            pack, template = setup_modules(rom)
        self.menus = menu_tree(pack, template, base, ptr)
        if sum(1 for _, items in self.menus for _ in _walk(items)) < 10 or not all(
            title for title, _ in self.menus
        ):  # (a table of sub-menus taken for the bar: Samsung Alioth 50C)
            self.menus = []
        strings = Strings(pack, base)
        self.items: list[dict] = []
        self.titles: list[str] = [title for title, _ in self.menus]
        for start, end in [] if self.menus else _chains(template):
            q = start
            while q < end:
                mode, length = template[q], template[q + 1]
                fields = [_u16(template, q + 2 + 2 * k) for k in range((length - 2) // 2)]
                q += length
                if mode in PICK and fields and (prompt := strings(fields[0])):
                    options = _options(strings, mode, fields, ptr)
                    help_text = strings(fields[1]) if len(fields) > 1 else ""
                    self.items.append({"prompt": prompt, "help": help_text, "options": options})
                elif mode in VALUES and fields and (prompt := strings(fields[0])):
                    self.items.append(
                        {"prompt": prompt, "help": "", "options": [], "value": VALUES[mode]}
                    )
                elif mode == TEXT and fields and (title := strings(fields[0]).strip()):
                    # (text records are also notes and headings: the menu bar's are named)
                    if title not in self.titles and title in TAB_ORDER:
                        self.titles.append(title)
        if not self.menus:
            if len(self.items) < 10:
                raise ValueError(
                    f"the setup template of this Phoenix image gave "
                    f"only {len(self.items)} settings"
                )
            self.titles.sort(key=lambda t: TAB_ORDER.index(t) if t in TAB_ORDER else len(TAB_ORDER))
        self.utility = next(
            (
                text.decode("latin-1")
                for text in template.split(b"\0")
                if text.endswith(b"Setup Utility") and text.isascii() and len(text) < 60
            ),
            "PhoenixBIOS Setup Utility",
        )

    def _render(self, items: list[dict], menu: str | None) -> Screen:
        s = Screen(80, 25)
        s.fill(0, 0, 79, 24, BODY_ATTR)
        s.fill(0, 0, 79, 0, TITLE_ATTR)
        s.write(
            (80 - len(self.utility)) // 2, 0, self.utility.encode("cp437", "replace"), TITLE_ATTR
        )
        s.fill(0, 1, 79, 1, BAR_ATTR)
        col = 2
        for k, title in enumerate(self.titles):
            if col + len(title) + 2 > 79:  # (the titles that do not fit are left out)
                break
            selected = title == menu if menu is not None else k == 0
            s.write(
                col,
                1,
                f" {title} ".encode("cp437", "replace"),
                BAR_SEL_ATTR if selected else BAR_ATTR,
            )
            col += len(title) + 3
        # the frame: items left, "Item Specific Help" right
        split = 56
        for c in range(1, 79):
            s.put(c, 2, 0xC4, BODY_ATTR)
            s.put(c, 22, 0xC4, BODY_ATTR)
        for row in range(3, 22):
            s.put(0, row, 0xB3, BODY_ATTR)
            s.put(split, row, 0xB3, BODY_ATTR)
            s.put(79, row, 0xB3, BODY_ATTR)
        for col_, ch_top, ch_bottom in ((0, 0xDA, 0xC0), (split, 0xC2, 0xC1), (79, 0xBF, 0xD9)):
            s.put(col_, 2, ch_top, BODY_ATTR)
            s.put(col_, 22, ch_bottom, BODY_ATTR)
        s.write(split + 3, 3, b"Item Specific Help", BODY_ATTR)
        # the cursor is on the first setting (a text line cannot be selected)
        first = next((it for it in items if _settable(it)), items[0])
        for i, it in enumerate(items[:ROWS]):
            row = 4 + i
            prompt = it["prompt"].strip()[:30]
            if it.get("sub"):
                prompt = "\x10 " + prompt[:28]
            value = it.get("value") or (f"[{it['options'][0]}]" if it["options"] else "")
            s.write(
                2, row, prompt.encode("cp437", "replace"), SEL_ATTR if it is first else ITEM_ATTR
            )
            s.write(33, row, value[: split - 34].encode("cp437", "replace"), VALUE_ATTR)
        lines, line = [], ""
        for word in " ".join(first["help"].replace("\r", " ").split()).split():
            if len(line) + len(word) + 1 > 20:
                lines.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        lines.append(line)
        if first["options"]:
            lines += ["", "Options:"] + [f" {o}"[:21] for o in first["options"]]
        for i, text in enumerate(lines[:16]):
            s.write(split + 2, 5 + i, text.encode("cp437", "replace"), HELP_ATTR)
        s.fill(0, 23, 79, 24, KEYS_ATTR)
        s.write(
            1,
            23,
            b"F1  Help  \x18\x19 Select Item  -/+  Change Values      F9   Setup Defaults",
            KEYS_ATTR,
        )
        s.write(
            1,
            24,
            b"Esc Exit  \x1b\x1a Select Menu  Enter Select \x10 Sub-Menu  F10  Save and Exit",
            KEYS_ATTR,
        )
        return s

    def _pages(self, name: str, items: list[dict], menu: str) -> list[tuple[str, Screen, str]]:
        count = max(1, (len(items) + ROWS - 1) // ROWS)
        return [
            (
                name if count == 1 else f"{name} ({n + 1}/{count})",
                self._render(
                    items[n * ROWS : (n + 1) * ROWS] or [{"prompt": "", "help": "", "options": []}],
                    menu,
                ),
                "static",
            )
            for n in range(count)
        ]

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, note)]: the menus of the menu bar, then their sub-menus; without a
        menu bar the settings in the template's order, ROWS per screen."""
        if not self.menus:
            return self._pages("Settings", self.items, self.titles[0] if self.titles else "")
        out = []
        for title, items in self.menus:
            out += self._pages(title, items, title)
        for title, items in self.menus:
            for depth, item in _walk(items):
                if item["sub"] and depth < 2 and any(_settable(it) for it in item["sub"]):
                    # (a dialog - Save Changes, a password - is a box, not a screen)
                    name = item["prompt"].rstrip(":").strip() or title
                    out += self._pages(name, item["sub"], title)
        return out
