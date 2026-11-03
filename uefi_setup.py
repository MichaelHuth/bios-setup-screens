"""
Setup screens of UEFI firmware (AMI Aptio and others with standard HII forms) read from the image
without running it.

How the data is found:
- firmware volumes ("_FVH" at +28h of their header) hold FFS files; their sections are walked,
  and compressed ones unpacked: compression sections (type 01h; compression type 1 = EFI/Tiano,
  2 = LZMA as AMI uses it, with the usual 13-byte LZMA header) and GUID-defined sections with the
  LZMA or Tiano GUID; firmware volume image sections (17h) are walked as volumes;
- in every section's bytes the HII packages are searched (IFRExtractor's tests): a form package
  (24-bit length, type 02h, a FORM_SET opcode first, END at its end) and string packages (type
  04h, header size 34h, then the language, "en-US");
- the forms are read from their IFR opcodes: FORM_SET, FORM, SUBTITLE, TEXT, REF (sub-menu),
  ONE_OF with its options, CHECKBOX, NUMERIC, DATE, TIME, STRING, PASSWORD, ACTION; defaults
  from the options' default flags and DEFAULT opcodes; strings from the string package's SIBT
  blocks (UCS-2 and SCSU).
The setup is the module with the most forms (AMI: "Setup"); its form sets are the tabs (Main,
Advanced, Chipset, Boot, Security, Save & Exit). Conditions (suppressif, grayoutif) are
evaluated only when constant: other items the setup hides at run time are listed too, and values
the setup supplies at run time (time, devices found) stay open.
"""

from __future__ import annotations

import lzma
import builtins
import functools
import re
import struct
import uuid

import tiano
from textscreen import Screen

LZMA_GUID = uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF").bytes_le
LZMAF86_GUID = uuid.UUID("D42AE6BD-1352-4BFB-909A-CA72A6EAE889").bytes_le
TIANO_GUID = uuid.UUID("A31280AD-481E-41B6-95E8-127F4C984779").bytes_le
MAX_DEPTH = 6  # nested volumes and sections
TITLE_ATTR, BAR_ATTR, BAR_SEL_ATTR = 0x1F, 0x1F, 0x71
BOX_ATTR, ITEM_ATTR, HILITE_ATTR, VALUE_ATTR, HELP_ATTR = 0x71, 0x71, 0x7F, 0x71, 0x71
LEFT, SPLIT, TOP, BOTTOM = 0, 54, 2, 23
VALUE_COL = 30
# ASRock's strings place their value with an escape, ESC {p90# (column 90 %), and the value is
# a printf format the setup fills at run time: "UEFI Version<ESC>{p90#: %a %a"
# (also colour escapes, ESC [1;37;m ... ESC [;;m, and an indent, ESC {s1#: left out; a value set
# off by a run of spaces is split off like a positioned one)
POSITION = re.compile(r"\x1b\{p\d+#| {3,}")
ESCAPES = re.compile(r"\x1b(?:\[[\d;]*m|\{s\d+#)")
PRINTF = re.compile(r"%[-+ 0#]*\d*(?:\.\d+)?[a-zA-Z]")
ALL_ONES = (0xFF, 0xFFFF, 0xFFFFFFFF)  # a numeric field's "not set" value
RUN_TIME_NAME = "(named at run time)"  # a sub-menu whose name is only a format ("%s")


def link_name(name: str) -> str:
    """A sub-menu link's name for a page title: one the setup fills in (ASRock's SATA ports,
    "%s") is named as such."""
    return RUN_TIME_NAME if name and not PRINTF.sub("", name).strip(" :-") else name


ROWS_PER_SCREEN = BOTTOM - TOP - 1
TAB_ORDER = ("main", "advanced", "chipset", "power", "boot", "security", "save & exit", "exit")
# Aptio's form set titles are blank (the tab names are in AMI's setup data): named by what their
# first form holds
TAB_RULES = [
    ("Main", ("System Date", "System Time", "BIOS Information", "BIOS Vendor")),
    (
        "Advanced",
        (
            "ACPI Settings",
            "CPU Configuration",
            "SATA Configuration",
            "USB Configuration",
            "Super IO",
            "H/W Monitor",
            "Trusted Computing",
        ),
    ),
    (
        "Chipset",
        (
            "North Bridge",
            "South Bridge",
            "PCH-IO",
            "System Agent",
            "NB Configuration",
            "SB Configuration",
        ),
    ),
    (
        "Boot",
        (
            "Boot Option",
            "Boot Configuration",
            "Quiet Boot",
            "Bootup NumLock",
            "Setup Prompt Timeout",
            "CSM",
        ),
    ),
    ("Security", ("Administrator Password", "User Password", "Secure Boot")),
    ("Save & Exit", ("Save Changes", "Discard Changes", "Restore Defaults")),
]
MAX_SUB_DEPTH = 2


def _known(name: str) -> bool:
    """A usual tab name (Main, Advanced, Chipset, Boot, Security, Exit ...)."""
    return name.lower() in TAB_ORDER or name.lower() in {n.lower() for n, _ in TAB_RULES}


def is_uefi(rom: bytes) -> bool:
    return b"_FVH" in rom


def _write(s: Screen, col: int, row: int, text: str, attr: int) -> None:
    s.write(col, row, text.encode("cp437", "replace"), attr)


# --- unpacking ------------------------------------------------------------------------------


def _lzma(data: bytes) -> bytes:
    """LZMA with the 13-byte header (properties byte, dictionary size, unpacked size)."""
    props = data[0]
    lc, rest = props % 9, props // 9
    lp, pb = rest % 5, rest // 5
    dict_size = max(struct.unpack_from("<I", data, 1)[0], 1 << 12)
    size = struct.unpack_from("<Q", data, 5)[0]
    dec = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}],
    )
    out = dec.decompress(data[13:], max_length=size if size < 1 << 30 else -1)
    return out


def _walk_sections(
    data: bytes, start: int, end: int, out: list, depth: int, scan: bool = False
) -> None:
    # Intel's Framework images keep a module's string packs in a section of type 1Ch beside
    # the PE32 with its form packs: the file's payloads go out together too
    parts, resources = [], False
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
                ctype = data[body + 4]  # (after the unpacked size)
                payload = data[body + 5 : p + size]
                # (type 2, "customized", is LZMA: with AMI right away, with Intel's own EFI
                # after 4 bytes, the size with a flag in its top byte)
                inner = (
                    payload
                    if ctype == 0
                    else (
                        tiano.decompress(payload)
                        if ctype == 1
                        else (
                            _lzma(payload)
                            if ctype == 2 and payload[:1] == b"]"
                            else (
                                _lzma(payload[4:])
                                if ctype == 2 and payload[4:5] == b"]"
                                else tiano.decompress(payload) if ctype == 2 else b""
                            )
                        )
                    )
                )
                if inner:
                    before = len(out)
                    _walk_sections(inner, 0, len(inner), out, depth + 1, scan)
                    if len(out) == before and b"_FVH" in inner:  # (Intel: a header, then
                        _walk_volumes(inner, out, depth + 1, scan)  # the volume)
            elif stype == 0x02 and depth < MAX_DEPTH:  # GUID-defined section
                guid = data[body : body + 16]
                offset = struct.unpack_from("<H", data, body + 16)[0]
                payload = data[p + offset : p + size]
                inner = (
                    _lzma(payload)
                    if guid == LZMA_GUID
                    else tiano.decompress(payload) if guid == TIANO_GUID else b""
                )
                if inner:
                    _walk_sections(inner, 0, len(inner), out, depth + 1, scan)
                else:  # another GUID (a checksum, a signature): plain sections inside
                    _walk_sections(data, p + offset, p + size, out, depth + 1, scan)
                    out.append(data[p + offset : p + size])
            elif stype == 0x17 and depth < MAX_DEPTH:  # a firmware volume image
                _walk_volumes(data[body : p + size], out, depth + 1, scan)
            elif stype in (0x10, 0x18, 0x19):  # PE32, freeform, raw: where HII data lives
                out.append(data[body : p + size])
                parts.append(data[body : p + size])
            elif stype == 0x1C:  # (Framework HII resources: string packs)
                parts.append(data[body : p + size])
                resources = True
        except (ValueError, IndexError, lzma.LZMAError, struct.error, EOFError):
            pass  # a damaged or unknown section: skipped
        p = (p + size + 3) & ~3
    if resources:
        out.append(b"\0".join(parts))


def _walk_volumes(data: bytes, out: list, depth: int = 0, scan: bool = False) -> None:
    """Every firmware volume in data: its files' sections into out. scan: every address
    that holds a plausible file header is taken, not just the chain of 8-byte aligned
    files (Intel's Framework images)."""
    if scan:
        _scan_volumes(data, out, depth)
        return
    i = data.find(b"_FVH")
    while i >= 0:
        v = i - 0x28
        try:
            if v >= 0:
                length, _sig, _attrs, hlen = struct.unpack_from("<Q4sIH", data, v + 0x20)
                if 0x48 <= hlen < 0x1000 and hlen <= length <= len(data) - v:
                    f = v + hlen
                    # (free space is all FFh; a pad file's name is FFh too, its header not)
                    while f + 24 <= v + length and data[f : f + 24] != b"\xff" * 24:
                        ftype = data[f + 0x12]
                        fsize = int.from_bytes(data[f + 0x14 : f + 0x17], "little")
                        if fsize < 24 or f + fsize > v + length:
                            break
                        if ftype not in (0xF0, 0x01):  # padding, raw (no sections)
                            _walk_sections(data, f + 24, f + fsize, out, depth)
                        f = (f + fsize + 7) & ~7
        except struct.error:
            pass
        i = data.find(b"_FVH", i + 4)


SECTION_TYPES = (0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19)


def _file_at(data: bytes, f: int, end: int) -> int:
    """The size of the used file whose header is at f with a plausible first section, or 0."""
    if f + 24 > end or data[f + 0x17] != 0xF8 or data[f + 0x12] > 0x0F:
        return 0
    size = int.from_bytes(data[f + 0x14 : f + 0x17], "little")
    if size < 24 or f + size > end:
        return 0
    sh = f + 24
    ssize = int.from_bytes(data[sh : sh + 3], "little")
    if 4 <= ssize <= size and data[sh + 3] in SECTION_TYPES or data[sh : sh + 4] == bytes(4):
        return size
    return 0


def _scan_volumes(data: bytes, out: list, depth: int = 0) -> None:
    i = data.find(b"_FVH")
    while i >= 0:
        v = i - 0x28
        try:
            if v >= 0:
                length, _sig, _attrs, hlen = struct.unpack_from("<Q4sIH", data, v + 0x20)
                if 0x18 <= hlen < 0x1000 and hlen <= length <= len(data) - v:
                    f, end = v + hlen, v + length
                    while f <= end - 24:
                        size = _file_at(data, f, end)
                        if size and data[f + 0x12] not in (0xF0, 0x01):
                            _walk_sections(data, f + 24, f + size, out, depth, True)
                            f += 24  # (the next header cannot start inside this one)
                        else:
                            f += 1
        except struct.error:
            pass
        i = data.find(b"_FVH", i + 4)


# --- HII packages ---------------------------------------------------------------------------


def _form_packages(blob: bytes) -> list[bytes]:
    out, p = [], blob.find(b"\x02\x0e")
    while p >= 3:
        start = p - 3
        length = int.from_bytes(blob[start : start + 3], "little")
        if (
            0x20 < length < 0x400000
            and start + length <= len(blob)
            and blob[p + 2] & 0x80
            and blob[start + length - 2 : start + length] == b"\x29\x02"
        ):
            out.append(blob[start : start + length])
            p = blob.find(b"\x02\x0e", start + length)
        else:
            p = blob.find(b"\x02\x0e", p + 1)
    return out


def _string_packages(blob: bytes) -> list[tuple[str, bytes]]:
    out, p = [], blob.find(b"\x04\x34\x00\x00\x00")
    while p >= 3:
        start = p - 3
        length = int.from_bytes(blob[start : start + 3], "little")
        if 0x40 < length < 0x1000000 and start + length <= len(blob):
            lang = blob[start + 0x2E : start + 0x34].split(b"\0")[0].decode("latin-1", "replace")
            out.append((lang, blob[start : start + length]))
            p = blob.find(b"\x04\x34\x00\x00\x00", start + length)
        else:
            p = blob.find(b"\x04\x34\x00\x00\x00", p + 1)
    return out


def _strings(pkg: bytes) -> dict[int, str]:
    """String ID -> text from a string package's SIBT blocks."""
    off = struct.unpack_from("<I", pkg, 8)[0]
    p, sid, out = off, 1, {}

    def ucs2(at: int) -> tuple[str, int]:
        end = at
        while end + 1 < len(pkg) and pkg[end : end + 2] != b"\0\0":
            end += 2
        return pkg[at:end].decode("utf-16-le", "replace"), end + 2

    def scsu(at: int) -> tuple[str, int]:
        end = pkg.find(b"\0", at)
        end = len(pkg) if end < 0 else end
        return pkg[at:end].decode("latin-1"), end + 1

    while p < len(pkg):
        t = pkg[p]
        if t == 0x00:
            break
        if t in (0x14, 0x15):  # UCS-2 (with a font byte)
            text, p = ucs2(p + 1 + (t == 0x15))
            out[sid] = text
            sid += 1
        elif t in (0x16, 0x17):  # several UCS-2 strings
            q = p + 1 + (t == 0x17)
            count = struct.unpack_from("<H", pkg, q)[0]
            q += 2
            for _ in range(count):
                out[sid], q = ucs2(q)
                sid += 1
            p = q
        elif t in (0x10, 0x11):  # SCSU (8-bit here)
            text, p = scsu(p + 1 + (t == 0x11))
            out[sid] = text
            sid += 1
        elif t in (0x12, 0x13):
            q = p + 1 + (t == 0x13)
            count = struct.unpack_from("<H", pkg, q)[0]
            q += 2
            for _ in range(count):
                out[sid], q = scsu(q)
                sid += 1
            p = q
        elif t == 0x20:  # duplicate
            out[sid] = out.get(struct.unpack_from("<H", pkg, p + 1)[0], "")
            sid, p = sid + 1, p + 3
        elif t == 0x21:  # skip2
            sid, p = sid + struct.unpack_from("<H", pkg, p + 1)[0], p + 3
        elif t == 0x22:  # skip1
            sid, p = sid + pkg[p + 1], p + 2
        elif t == 0x30:  # ext1: type, length (u8)
            p += max(pkg[p + 2], 3)
        elif t == 0x31:  # ext2
            p += max(struct.unpack_from("<H", pkg, p + 2)[0], 4)
        elif t == 0x32:  # ext4
            p += max(struct.unpack_from("<I", pkg, p + 2)[0], 6)
        else:
            break
    return out


# --- IFR ------------------------------------------------------------------------------------


def _value(data: bytes, at: int, vtype: int) -> int:
    width = {0: 1, 1: 2, 2: 4, 3: 8, 4: 1}.get(vtype, 0)
    return int.from_bytes(data[at : at + width], "little") if width else 0


class FormSet:
    def __init__(self, title: int, help_: int):
        self.title, self.help = title, help_
        self.forms: dict[int, tuple[int, list]] = {}  # form id -> (title, items)
        self.first: int | None = None


# expression opcodes (they follow SUPPRESS_IF, DISABLE_IF, GRAY_OUT_IF ... in postfix order)
EXPR_OPS = (
    {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x20, 0x21, 0x22} | set(range(0x2A, 0x5B)) | {0x5E}
)


def _evaluate(expr: list, values: dict) -> bool | None:
    """A condition's value with the questions at their defaults: True, False, or None when it
    uses something else (variables read at run time, vendor opcodes)."""
    stack: list = []
    try:
        for op, d in expr:
            if op == 0x12:  # EQ_ID_VAL: question == value
                qid, value = struct.unpack_from("<HH", d)
                v = values.get(qid)
                stack.append(None if v is None else v == value)
            elif op == 0x14:  # EQ_ID_VAL_LIST: question in values
                qid, n = struct.unpack_from("<HH", d)
                listed = struct.unpack_from(f"<{n}H", d, 4)
                v = values.get(qid)
                stack.append(None if v is None else v in listed)
            elif op == 0x13:  # EQ_ID_ID
                a, b = (values.get(q) for q in struct.unpack_from("<HH", d))
                stack.append(None if a is None or b is None else a == b)
            elif op == 0x3F:  # QUESTION_REF1: the question's value
                stack.append(values.get(struct.unpack_from("<H", d)[0]))
            elif op in (0x41, 0x42, 0x43, 0x44):  # UINT8 ... UINT64
                stack.append(int.from_bytes(d[: 1 << (op - 0x41)], "little"))
            elif op in (0x46, 0x47, 0x52, 0x53):  # TRUE, FALSE, ZERO, ONE
                stack.append({0x46: True, 0x47: False, 0x52: 0, 0x53: 1}[op])
            elif op == 0x17:  # NOT
                x = stack.pop()
                stack.append(None if x is None else not x)
            elif op in (0x15, 0x16):  # AND, OR (three-valued)
                b, a = stack.pop(), stack.pop()
                if op == 0x15:
                    stack.append(
                        False
                        if a is False or b is False
                        else None if a is None or b is None else True
                    )
                else:
                    stack.append(
                        True
                        if a is True or b is True
                        else None if a is None or b is None else False
                    )
            elif op in (0x2F, 0x30, 0x31, 0x32, 0x33, 0x34):  # comparisons
                b, a = stack.pop(), stack.pop()
                if a is None or b is None:
                    stack.append(None)
                else:
                    stack.append(
                        {
                            0x2F: a == b,
                            0x30: a != b,
                            0x31: a > b,
                            0x32: a >= b,
                            0x33: a < b,
                            0x34: a <= b,
                        }[op]
                    )
            else:
                return None
    except (IndexError, struct.error):
        return None
    return stack[-1] if len(stack) == 1 and isinstance(stack[-1], bool) else None


def _parse_ifr(pkg: bytes) -> list[FormSet]:
    """The form sets of a form package; items as dicts (kind, prompt, help, ...). Items under a
    SUPPRESS_IF or DISABLE_IF whose condition holds with the questions at their defaults are left
    out (one that cannot be evaluated is kept)."""
    sets: list[FormSet] = []
    stack: list[tuple[int, object]] = []  # (opcode, item or condition) of the open scopes
    fs: FormSet | None = None
    items: list | None = None
    question: dict | None = None
    collecting: list | None = None  # the expression of the condition just opened
    p = 4
    while p + 2 <= len(pkg):
        op, ln = pkg[p], pkg[p + 1] & 0x7F
        scope = pkg[p + 1] & 0x80
        if ln < 2:
            break
        d = pkg[p + 2 : p + ln]
        if collecting is not None and op in EXPR_OPS:
            collecting.append((op, d))
            if scope:
                stack.append((op, None))
            p += ln
            continue
        collecting = None
        item = None
        conds = [mark for _, mark in stack if isinstance(mark, list)]
        if op == 0x0E and len(d) >= 20:  # FORM_SET
            fs = FormSet(*struct.unpack_from("<HH", d, 16))
            sets.append(fs)
        elif op in (0x01, 0x5D) and fs is not None and len(d) >= 4:  # FORM, FORM_MAP
            form_id, title = struct.unpack_from("<HH", d)
            items = []
            fs.forms[form_id] = (title, items)
            if fs.first is None:
                fs.first = form_id
        elif items is not None:
            if op == 0x02 and len(d) >= 4:  # SUBTITLE
                item = {"kind": "subtitle", "prompt": struct.unpack_from("<H", d)[0]}
            elif op == 0x03 and len(d) >= 6:  # TEXT
                prompt, help_, text2 = struct.unpack_from("<HHH", d)
                item = {"kind": "text", "prompt": prompt, "help": help_, "text2": text2}
            elif (
                op in (0x05, 0x06, 0x07, 0x08, 0x0C, 0x0F, 0x1A, 0x1B, 0x1C, 0x23) and len(d) >= 11
            ):
                prompt, help_, qid = struct.unpack_from("<HHH", d)
                item = {
                    "kind": {
                        0x05: "oneof",
                        0x06: "checkbox",
                        0x07: "numeric",
                        0x08: "password",
                        0x0C: "action",
                        0x0F: "ref",
                        0x1A: "date",
                        0x1B: "time",
                        0x1C: "string",
                        0x23: "list",
                    }[op],
                    "prompt": prompt,
                    "help": help_,
                    "options": [],
                    "default": None,
                    "qid": qid,
                }
                rest = d[11:]
                if op == 0x0F and len(rest) >= 2:
                    item["form"] = struct.unpack_from("<H", rest)[0]
                    if len(rest) >= 20:  # REF3: another form set
                        item["formset"] = rest[4:20]
                elif op == 0x06 and rest:
                    item["default"] = 1 if rest[0] & 0x01 else 0
                elif op == 0x07 and rest:
                    width = rest[0] & 3
                    item["min"] = _value(rest, 1, width)
                    item["max"] = _value(rest, 1 + (1 << width), width)
                if scope:
                    question = item
            elif op == 0x0D and len(d) >= 4:  # RESET_BUTTON
                prompt, help_ = struct.unpack_from("<HH", d)
                item = {"kind": "action", "prompt": prompt, "help": help_}
        if op == 0x09 and question is not None and len(d) >= 4:  # ONE_OF_OPTION
            text, flags, vtype = struct.unpack_from("<HBB", d)
            value = _value(d, 4, vtype)
            question["options"].append((text, value))
            if flags & 0x10 and question["default"] is None:
                question["default"] = value
        elif op == 0x5B and question is not None and len(d) >= 3:  # DEFAULT
            default_id, vtype = struct.unpack_from("<HB", d)
            if default_id == 0:
                question["default"] = _value(d, 3, vtype)
        if item is not None:
            assert items is not None
            item["conds"] = conds
            items.append(item)
        if op in (0x0A, 0x1E) and scope:  # SUPPRESS_IF, DISABLE_IF: a condition follows
            collecting = []
            stack.append((op, collecting))
        elif op == 0x19 and scope:  # GRAY_OUT_IF: shown; its expression is skipped
            collecting = []
            stack.append((op, None))
        elif op == 0x29:  # END
            if stack:
                top_op, mark = stack.pop()
                if mark is question and question is not None:
                    question = None
                if top_op in (0x01, 0x5D):
                    items = None
        elif scope:
            stack.append((op, item if item is not None and item is question else None))
        p += ln
    # the questions at their defaults (a list's first option if none is named): only those
    # under no condition themselves - hidden ones are flags the platform's code sets at run
    # time (Gigabyte: "suppressif flag == 0" with the flag's default 0 hid real items)
    for fs in sets:
        values = {}
        for _, items in fs.forms.values():
            for it in items:
                if (
                    "qid" in it
                    and it["kind"] in ("oneof", "checkbox", "numeric")
                    and not it.get("conds")
                ):
                    v = it["default"]
                    if v is None and it["options"]:
                        v = it["options"][0][1]
                    if v is None and it["kind"] == "numeric":
                        v = it.get("min")
                    if v is not None:
                        values[it["qid"]] = v
        for form_id, (title, items) in fs.forms.items():
            items[:] = [
                it
                for it in items
                if not any(_evaluate(c, values) is True for c in it.get("conds", ()))
            ]
    return sets


# --- Framework HII (EFI 1.10, the Intel Platform Innovation Framework, before UEFI 2.1) -----
# Pack header: u32 length, u16 type (2 strings, 3 IFR); IFR opcodes have a plain 8-bit length (no
# scope bit) and scopes end with END_FORM (0Bh), END_FORM_SET (0Dh), END (10h, of ONE_OF) and
# END_IF (18h); string IDs index a table of u32 offsets from the pack's start, from 0.


def _fw_form_packages(blob: bytes) -> list[bytes]:
    out, p = [], blob.find(b"\x03\x00\x0e")
    while p >= 4:
        start = p - 4
        length = struct.unpack_from("<I", blob, start)[0]
        if (
            0x2A < length < 0x400000
            and start + length <= len(blob)
            and blob[start + length - 2 : start + length] == b"\x0d\x02"
        ):
            out.append(blob[start : start + length])
            p = blob.find(b"\x03\x00\x0e", start + length)
        else:
            p = blob.find(b"\x03\x00\x0e", p + 1)
    return out


def _fw_string_packages(blob: bytes) -> list[tuple[str, bytes]]:
    out, p = [], blob.find(b"\x02\x00")
    while 0 <= p:
        start = p - 4
        if start >= 0:
            length = struct.unpack_from("<I", blob, start)[0]
            if (
                0x26 < length < 0x1000000
                and start + length <= len(blob)
                and blob[start + length - 2 : start + length] == b"\0\0"
            ):
                lang_at, _, count = struct.unpack_from("<III", blob, start + 6)
                if 0 < count < 0x10000 and 22 + 4 * count <= length and lang_at < length:
                    end = lang_at
                    while end + 1 < length and blob[start + end : start + end + 2] != b"\0\0":
                        end += 2
                    lang = blob[start + lang_at : start + end].decode("utf-16-le", "replace")
                    out.append((lang, blob[start : start + length]))
                    p = blob.find(b"\x02\x00", start + length + 4)
                    continue
        p = blob.find(b"\x02\x00", p + 1)
    return out


def _fw_strings(pkg: bytes) -> dict[int, str]:
    count = struct.unpack_from("<I", pkg, 14)[0]
    out = {}
    for sid in range(count):
        at = struct.unpack_from("<I", pkg, 22 + 4 * sid)[0]
        end = at
        while end + 1 < len(pkg) and pkg[end : end + 2] != b"\0\0":
            end += 2
        text = pkg[at:end].decode("utf-16-le", "replace")
        out[sid] = "".join(c for c in text if c not in "\ufff0\ufff1\ufff2")
    return out


def _parse_fw_ifr(pkg: bytes) -> list[FormSet]:
    """The form sets of a Framework IFR pack, items as _parse_ifr makes them."""
    sets: list[FormSet] = []
    fs: FormSet | None = None
    items: list | None = None
    question: dict | None = None
    conds: list[bool] = []  # open SUPPRESS_IF / GRAYOUT_IF: whether they hide (constant TRUE)
    expect = None  # the condition just opened, waiting for its first expression opcode
    p = 6
    while p + 2 <= len(pkg):
        op, ln = pkg[p], pkg[p + 1]
        if ln < 2:
            break
        d = pkg[p : p + ln]

        def u16(o: int, d: bytes = d) -> int:
            return struct.unpack_from("<H", d, o)[0] if o + 2 <= len(d) else 0

        if expect is not None:
            conds.append(expect and op == 0x27)  # SUPPRESS_IF TRUE
            expect = None
        hidden = any(conds)
        item = None
        if op == 0x0E and ln >= 22:  # FORM_SET
            fs = FormSet(u16(18), u16(20))
            sets.append(fs)
        elif op == 0x01 and fs is not None:  # FORM
            items = []
            fs.forms[u16(2)] = (u16(4), items)
            if fs.first is None:
                fs.first = u16(2)
        elif op == 0x0B:  # END_FORM
            items = None
        elif op == 0x10:  # END (of ONE_OF)
            question = None
        elif op == 0x0A:  # SUPPRESS_IF
            expect = True
        elif op == 0x19:  # GRAYOUT_IF: shown
            expect = False
        elif op == 0x18:  # END_IF
            if conds:
                conds.pop()
        elif op == 0x09 and question is not None and not hidden:  # ONE_OF_OPTION
            question["options"].append((u16(2), u16(4)))
            if d[6] & 0x01 and question["default"] is None:
                question["default"] = u16(4)
        elif items is not None and not hidden:
            if op == 0x02:
                item = {"kind": "subtitle", "prompt": u16(2)}
            elif op == 0x03:
                item = {"kind": "text", "prompt": u16(4), "help": u16(2), "text2": u16(6)}
            elif op == 0x05:
                item = question = {
                    "kind": "oneof",
                    "prompt": u16(5),
                    "help": u16(7),
                    "options": [],
                    "default": None,
                }
            elif op == 0x06:
                item = {
                    "kind": "checkbox",
                    "prompt": u16(5),
                    "help": u16(7),
                    "options": [],
                    "default": 1 if ln > 9 and d[9] & 0x01 else 0,
                }
            elif op == 0x07:
                item = {
                    "kind": "numeric",
                    "prompt": u16(5),
                    "help": u16(7),
                    "options": [],
                    "min": u16(12),
                    "default": u16(18) if ln >= 20 else None,
                }
            elif op in (0x1A, 0x1B):
                item = {
                    "kind": "date" if op == 0x1A else "time",
                    "prompt": u16(5),
                    "help": u16(7),
                    "options": [],
                    "default": None,
                }
            elif op in (0x08, 0x1C):
                item = {
                    "kind": "password" if op == 0x08 else "string",
                    "prompt": u16(5),
                    "help": u16(7),
                    "options": [],
                    "default": None,
                }
            elif op == 0x0F:
                item = {"kind": "ref", "form": u16(2), "prompt": u16(4), "help": u16(6)}
            elif op in (0x1E, 0x1F):  # SAVE_DEFAULTS / RESTORE_DEFAULTS
                item = {"kind": "action", "prompt": u16(4), "help": u16(6)}
        if item is not None:
            assert items is not None
            items.append(item)
        if op == 0x0D:  # END_FORM_SET
            fs = None
        p += ln
    return sets


def _renumber(fs: FormSet, offset: int) -> None:
    """Moves a form set's form ids (and its links to them) up by offset."""
    ids = set(fs.forms)
    for _, items in fs.forms.values():
        for it in items:
            if it["kind"] == "ref" and it.get("form") in ids:
                it["form"] += offset
    fs.forms = {fid + offset: form for fid, form in fs.forms.items()}
    assert fs.first is not None
    fs.first += offset


# --- the setup ------------------------------------------------------------------------------


class UefiSetup:
    def __init__(self, rom: bytes):
        # (Intel's Framework images pack their files without the 8-byte alignment: when
        # following the chain finds no setup, every header in a volume is looked for)
        for scan in (False, True):
            blobs: list = []
            _walk_volumes(rom, blobs, scan=scan)
            candidates = []  # (number of settings, form sets, strings) per module with forms
            title, marked = "Aptio Setup Utility", False
            for blob in blobs:
                for marker in ("Aptio Setup Utility", "InsydeH2O Setup Utility"):
                    if marker.encode("utf-16-le") in blob:
                        title, marked = marker, True
                forms = _form_packages(blob)
                langs = _string_packages(blob) if forms else []
                if forms and langs:
                    pkg = next(
                        (p for lang, p in langs if lang.lower().startswith("en")), langs[0][1]
                    )
                    sets = [fs for f in forms for fs in _parse_ifr(f)]
                    strings = functools.partial(_strings, pkg)
                    framework = False
                else:  # Framework HII (EFI 1.10, before UEFI 2.1: Intel's own EFI of 2007-12)
                    forms = _fw_form_packages(blob)
                    packs = _fw_string_packages(blob) if forms else []
                    if not packs:
                        continue
                    # (the largest English pack: the only one holding every id the forms
                    # use, measured on Intel's parts)
                    english = [p for lang, p in packs if lang.lower().startswith("en")]
                    pkg = max(english, key=len) if english else packs[0][1]
                    sets = [fs for f in forms for fs in _parse_fw_ifr(f)]
                    strings = functools.partial(_fw_strings, pkg)
                    framework = True
                n = sum(
                    1
                    for fs in sets
                    for _, items in fs.forms.values()
                    for it in items
                    if it["kind"] in ("oneof", "checkbox", "numeric")
                )
                if n >= 10:  # (HP's business desktops: their Computer Setup is a program of HP's
                    candidates.append((n, sets, strings, framework))  # own; only AMI's
                    # browser has a few)
            if candidates:
                break
        if not candidates:
            raise ValueError("no HII forms with setup settings found in the firmware volumes")
        if not marked and all(c[3] for c in candidates):
            # Intel's own EFI (Framework HII) is no Aptio; the name is not in its strings
            title = "BIOS Setup Utility"
        self.title = title
        # the module with the most settings whose tabs have the usual names: not AMI's setup
        # browser ("Item Help", "Language" ...) nor Intel's reference code settings
        # ("IntelRCSetup", thousands of settings, linked from the setup's Advanced tab)
        for _, sets, strings, _ in sorted(candidates, key=lambda c: -c[0]):
            self.S = strings()
            sets = [fs for fs in sets if fs.first is not None]
            self.forms: dict[int, tuple[int, list]] = {}
            for k, fs in enumerate(sets):
                if fs.first in self.forms:  # (Framework form sets all number their forms
                    _renumber(fs, (k + 1) << 16)  # from 1: kept apart)
                for fid, form in fs.forms.items():
                    self.forms.setdefault(fid, form)
            tabs = self._name_tabs(sets)
            if len(tabs) == 1 and not _known(tabs[0][0]):  # Aptio V: one form set "Setup"
                links = [
                    (" ".join(self.str(it.get("prompt")).split()), it.get("form"))  # whose
                    for it in self.forms[tabs[0][1]][1]
                    if it["kind"] == "ref"
                ]  # first form
                if len(links) >= 3 and all(name and form in self.forms for name, form in links):
                    tabs = links  # links the tabs
            if any(_known(name) for name, _ in tabs):
                break
        else:
            raise ValueError(
                "the HII forms found are not a setup with the usual tabs (Main, "
                "Advanced, Boot ...)"
            )
        self.tabs = tabs  # [(name, form id)]
        copy = next(
            (t for t in self.S.values() if "American Megatrends" in t and "Copyright" in t), ""
        )
        self.copyright = copy.strip()[:78]

    def _name_tabs(self, sets: list[FormSet]) -> list[tuple[str, int]]:
        """The tabs in the order of their form sets (the setup's own order), each named by its
        title, or for Aptio's blank titles by the tab whose typical entries its first form
        holds most of (each name once, the best match first); a form set with none of them
        is named after its first sub-menu (a board maker's own tab, e.g. ASRock's overclocking
        one), one with no entries at all is left out."""
        names: dict[int, str] = {}
        scored = []
        for k, fs in enumerate(sets):
            title = self.str(fs.title).strip()
            if title:
                names[k] = title
                continue
            assert fs.first is not None
            prompts = " | ".join(self.str(it.get("prompt")) for it in fs.forms[fs.first][1])
            for name, keys in TAB_RULES:
                score = sum(key in prompts for key in keys)
                if score:
                    scored.append((score, -k, name, k))
        taken = set(names.values())
        for score, _, name, k in sorted(scored, reverse=True):
            if k not in names and name not in taken:
                names[k] = name
                taken.add(name)
        tabs: list[tuple[str, int]] = []
        for k, fs in enumerate(sets):
            assert fs.first is not None
            tab_name = names.get(k)
            if tab_name is None:
                items = fs.forms[fs.first][1]
                first = next(
                    (
                        self.str(it.get("prompt")).strip()
                        for it in items
                        if it["kind"] == "ref" and self.str(it.get("prompt")).strip()
                    ),
                    "",
                )
                if not first:
                    continue
                tab_name = first
            tabs.append((tab_name, fs.first))
        return tabs

    def str(self, sid: int | None) -> str:
        text = self.S.get(sid or 0, "")
        return ESCAPES.sub("", text) if "\x1b" in text else text

    def prompt_value(self, sid: int | None) -> tuple[builtins.str, builtins.str]:
        """A prompt string split at a position escape into (prompt, inline value); the value
        is empty when it is filled in at run time (a printf format)."""
        parts = [" ".join(p.split()) for p in POSITION.split(self.str(sid))]
        tail = next((p for p in reversed(parts[1:]) if p.strip(": ")), "").strip(": ")
        if PRINTF.search(tail):
            tail = ""
        if not parts[0]:  # (only text after the escape: that is the prompt)
            return tail, ""
        return parts[0], tail

    def _value_text(self, item: dict) -> builtins.str:
        kind = item["kind"]
        if kind in ("oneof", "list"):
            opts = item["options"]
            chosen = next((t for t, v in opts if v == item["default"]), None)
            if chosen is None and opts:
                chosen = opts[0][0]
            return self.str(chosen) if chosen is not None else ""
        if kind == "checkbox":
            return "Enabled" if item["default"] else "Disabled"
        if kind == "numeric":
            value = item["default"] if item["default"] is not None else item.get("min", 0)
            top, low = item.get("max"), item.get("min")
            if top is not None and top == low and top in ALL_ONES and value != top:
                return ""  # (a value the setup shows at run time: Gigabyte's CPU Frequency)
            if top is not None and (value > top or (value == top and top in ALL_ONES)):
                # (Gigabyte: FFFFh, beyond the range or the field's all-ones top, is Auto)
                return "Auto"
            return str(value)
        if kind == "date":
            return "mm/dd/yyyy"
        if kind == "time":
            return "hh:mm:ss"
        return ""

    def _render(self, tab: int, items: list, start: int, top: bool) -> tuple[Screen, bool]:
        s = Screen(80, 25)
        for row in range(25):
            for c in range(80):
                s.put(c, row, ord(" "), BOX_ATTR if TOP <= row <= BOTTOM else TITLE_ATTR)
        _write(s, (80 - len(self.title)) // 2, 0, self.title, TITLE_ATTR)
        col = 1
        for k, (name, _) in enumerate(self.tabs):
            if top or k == tab:
                _write(s, col, 1, f" {name} ", BAR_SEL_ATTR if top and k == tab else BAR_ATTR)
            col += len(name) + 3
        s.put(0, TOP, 0xDA, BOX_ATTR)
        s.put(79, TOP, 0xBF, BOX_ATTR)
        s.put(SPLIT, TOP, 0xC2, BOX_ATTR)
        s.put(0, BOTTOM, 0xC0, BOX_ATTR)
        s.put(79, BOTTOM, 0xD9, BOX_ATTR)
        s.put(SPLIT, BOTTOM, 0xC1, BOX_ATTR)
        for c in range(1, 79):
            if c != SPLIT:
                s.put(c, TOP, 0xC4, BOX_ATTR)
                s.put(c, BOTTOM, 0xC4, BOX_ATTR)
        for row in range(TOP + 1, BOTTOM):
            s.put(0, row, 0xB3, BOX_ATTR)
            s.put(SPLIT, row, 0xB3, BOX_ATTR)
            s.put(79, row, 0xB3, BOX_ATTR)
        if self.copyright:
            _write(s, (80 - len(self.copyright)) // 2, 24, self.copyright, TITLE_ATTR)
        row, k, help_id, first = TOP + 1, start, None, True
        while k < len(items) and row < BOTTOM:
            it = items[k]
            kind = it["kind"]
            prompt, inline = self.prompt_value(it.get("prompt"))
            if kind == "subtitle":
                _write(s, 2, row, prompt[: SPLIT - 3], BOX_ATTR)
            elif kind == "text":
                _write(s, 2, row, prompt[: VALUE_COL - 3], BOX_ATTR)
                value = " ".join(self.str(it.get("text2")).split()) or inline
                _write(s, VALUE_COL, row, value[: SPLIT - VALUE_COL - 1], BOX_ATTR)
            elif kind in ("ref", "action") and not prompt:  # (no name: a hidden link)
                k += 1
                continue
            elif kind in ("ref", "action"):
                if kind == "ref":
                    s.put(2, row, 0x10, BOX_ATTR)
                _write(s, 4, row, prompt[: SPLIT - 5], HILITE_ATTR if first else ITEM_ATTR)
                if first:
                    help_id, first = it.get("help"), False
            else:
                _write(s, 2, row, prompt[: VALUE_COL - 3], HILITE_ATTR if first else ITEM_ATTR)
                value = self._value_text(it)
                if value or kind in ("oneof", "checkbox", "numeric", "date", "time"):
                    _write(s, VALUE_COL, row, f"[{value}]"[: SPLIT - VALUE_COL - 1], VALUE_ATTR)
                if first:
                    help_id, first = it.get("help"), False
            row += 1
            k += 1
        if help_id:
            lines = []
            for para in self.str(help_id).split("\n"):
                words, line = para.split(), ""
                for w in words:
                    if len(line) + len(w) + 1 > 22:
                        lines.append(line)
                        line = w
                    else:
                        line = f"{line} {w}".strip()
                lines.append(line)
            for i, line in enumerate(lines[:10]):
                _write(s, SPLIT + 2, TOP + 1 + i, line, HELP_ATTR)
        legend = [
            "\x1a\x1b: Select Screen",
            "\x18\x19: Select Item",
            "Enter: Select",
            "+/-: Change Opt.",
            "F1: General Help",
            "F9: Optimized Defaults",
            "F10: Save & Exit",
            "ESC: Exit",
        ]
        for i, line in enumerate(legend):
            _write(s, SPLIT + 2, BOTTOM - len(legend) + i, line, HELP_ATTR)
        return s, k < len(items)

    def screens(self) -> list[tuple[builtins.str, Screen, builtins.str]]:
        """[(title, screen, note)]: each tab's first form, then the forms its sub-menus open
        (MAX_SUB_DEPTH levels), long forms continued on further screens."""
        out, seen = [], set()

        def add(tab: int, title: builtins.str, form_id: int, depth: int) -> None:
            if form_id in seen or form_id not in self.forms:
                return
            seen.add(form_id)
            items = [
                it
                for it in self.forms[form_id][1]
                if not (
                    it["kind"] == "subtitle" and not self.str(it.get("prompt")).strip() and False
                )
            ]
            start, n = 0, 1
            while True:
                screen, more = self._render(tab, items, start, depth == 0)
                out.append((title if n == 1 else f"{title} ({n})", screen, "static"))
                if not more:
                    break
                start, n = start + ROWS_PER_SCREEN, n + 1
            if depth < MAX_SUB_DEPTH:
                for it in items:
                    name = link_name(" ".join(self.str(it.get("prompt")).split()))
                    if it["kind"] == "ref" and "formset" not in it and name:
                        add(tab, f"{title} > {name}", it.get("form"), depth + 1)

        for k, (name, form_id) in enumerate(self.tabs):
            add(k, name or f"Tab {k + 1}", form_id, 0)
        return out
