"""
Firmware images built by the tests: small, made of our own bytes, laid out as the readers
expect them (the layouts are those the bot's readers document). Each builder returns the image
and what a reader should find in it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import lzh
from encoders import lh5_stream, lzss

ROM_SIZE = 0x20000  # 128 KB: mapped below 1 MB (AMI) or masked by the size (Phoenix)


def lha_module(name: bytes, payload: bytes, method: bytes = b"-lh5-") -> bytes:
    """An LHA member with a level-0 header, as Award BIOSes store their modules."""
    packed = lh5_stream(payload) if method == b"-lh5-" else payload
    body = (
        method
        + struct.pack("<IIIBB", len(packed), len(payload), 0, 0x20, 0)
        + bytes([len(name)])
        + name
        + struct.pack("<H", lzh.crc16(payload))
    )
    return bytes([len(body), sum(body) & 0xFF]) + body + packed


# --- AMIBIOS 95/8 ----------------------------------------------------------------------------


@dataclass
class AmiModule:
    ident: int
    data: bytes
    compressed: bool = True
    load: int = 0
    big: bool = False  # stored with length 0: the real length 8 bytes before the header


def ami_image(modules: list[AmiModule], size: int = ROM_SIZE, boot: bool = True) -> bytes:
    """An AMIBIOS image whose module chain is the given modules, first to last (the core
    header points at the last; each header at the one before)."""
    image = bytearray(b"\xff" * size)
    base = 0x100000 - size  # (the image ends at 1 MB: addresses are segment:offset)
    at, prev = 0x1000, (0xFFFF, 0xFFFF)
    for m in modules:
        if m.big:
            at += 8
            struct.pack_into("<I", image, at - 8, len(m.data))
        if m.compressed:
            body = lh5_stream(m.data)
            header = struct.pack("<HHHBBIII", *prev, 0, m.ident, 0, m.load, len(body), len(m.data))
        else:
            body = m.data
            header = struct.pack(
                "<HHHBBI", *prev, 0 if m.big else len(m.data), m.ident, 0x80, m.load
            )
        image[at : at + len(header) + len(body)] = header + body
        phys = base + at
        prev = (phys & 0xF, phys >> 4)
        at = (at + len(header) + len(body) + 0x1F) & ~0xF
    core = size - 0x2000
    image[core : core + 12] = b"AMIBIOSC0800"
    struct.pack_into("<HH", image, core + 18, *prev)
    if boot:
        image[size - 0x1000 : size - 0x1000 + 11] = b"AMIBOOT ROM"
    image[-11:-3] = b"01/01/99"
    return bytes(image)


# --- PhoenixBIOS 4.0/6.0 (BCP) ---------------------------------------------------------------


@dataclass
class PhoenixModule:
    letter: str
    data: bytes
    comp: int = 5  # 0 stored, 3 LZSS, 5 LH5
    ident: int = 0
    fragments: int = 1  # bodies split into this many pieces
    load: tuple[int, int] = (0, 0)  # (segment, offset)


def top(size: int) -> int:
    """Where an image of this size starts below 4 GB: addresses as the BIOS sees them."""
    return (1 << 32) - size


def phoenix_image(modules: list[PhoenixModule], size: int = ROM_SIZE) -> bytes:
    """A PhoenixBIOS image: BCPSEGMENT, a BCPSYS block pointing at the last module, and the
    modules' 27-byte headers, each pointing at the one before."""
    image = bytearray(b"\xff" * size)
    image[0x10:0x1A] = b"BCPSEGMENT"
    sys_at = 0x1A
    block = bytearray(0x80)
    block[0:6] = b"BCPSYS"
    struct.pack_into("<HH", block, 6, 0, len(block))
    block[0x0F:0x17] = b"01/01/00"
    block[0x18:0x20] = b"12:00:00"
    block[0x37:0x3F] = b"4.0 R6.0"
    image[sys_at : sys_at + len(block)] = block
    image[sys_at + len(block)] = 0  # (the end of the blocks)
    at, prev = 0x400, 0
    frag_at = size - 0x8000  # fragments go to the end of the image
    for m in modules:
        if m.comp == 5:
            body = struct.pack("<I", len(m.data)) + lh5_stream(m.data)
        elif m.comp == 3:
            body = lzss(m.data)
        else:
            body = m.data
        pieces = [body]
        if m.fragments > 1:
            step = -(-len(body) // m.fragments)
            pieces = [body[i : i + step] for i in range(0, len(body), step)]
        first, rest = pieces[0], pieces[1:]
        next_frag = 0
        if rest:  # fragments chained from the last back to the first's successor
            addresses = []
            for piece in rest:
                addresses.append(frag_at)
                frag_at += 9 + len(piece) + 7
            for k, (piece, where) in enumerate(zip(rest, addresses)):
                nxt = top(size) + addresses[k + 1] if k + 1 < len(addresses) else 0
                image[where : where + 9 + len(piece)] = (
                    struct.pack("<IBI", nxt, 0, len(piece)) + piece
                )
            next_frag = 0xF0000000 | addresses[0]
        header = (
            struct.pack("<I", prev)
            + b"\x00\x31\x31"
            + struct.pack("<BBBB", m.ident, ord(m.letter), 27, m.comp)
            + struct.pack("<HHIII", m.load[1], m.load[0], len(m.data), len(first), next_frag)
        )
        image[at : at + 27 + len(first)] = header + first
        prev = top(size) + at
        at = (at + 27 + len(first) + 0xF) & ~0xF
    struct.pack_into("<I", image, sys_at + 0x77, prev)
    return bytes(image)


@dataclass
class FfvFile:
    name: str  # "_E00": type letter and number
    data: bytes
    compressed: bool = False


def ffv_image(files: list[FfvFile], size: int = ROM_SIZE) -> bytes:
    """A TrustedCore/SecureCore image: a BCPSEGMENT whose BCPSYS has no module list, a BCPFFV
    block, the volume directory ("volumedir.bin2") and one file volume."""
    image = bytearray(phoenix_image([], size))
    sys_at = 0x1A
    struct.pack_into("<I", image, sys_at + 0x77, 0)
    ffv = sys_at + 0x80
    image[ffv : ffv + 10] = b"BCPFFV" + struct.pack("<HH", 0, 0x10)
    image[ffv + 0x10] = 0
    name_at = 0x1000
    image[name_at : name_at + 15] = b"volumedi\xffr.bin2"
    directory = name_at + 0x10
    struct.pack_into("<HHI", image, directory, 0, 0, 8 + 24)
    volume = 0x2000
    entry = bytearray(24)
    entry[0] = 0xBA  # (a file volume's GUID)
    struct.pack_into("<II", entry, 16, (volume - (size & 0xFFFF0000)) & 0xFFFFFFFF, 0x4000)
    image[directory + 8 : directory + 32] = entry
    at = volume
    for f in files:
        section = struct.pack("<I", 4 + len(f.data))[:3] + b"\x10" + f.data
        if f.compressed:
            packed = lh5_stream(section)
            section = (
                struct.pack("<I", 12 + len(packed))[:3]
                + b"\x01"
                + struct.pack("<II", len(packed), len(section))
                + packed
            )
        record = bytearray(0x18)
        record[0] = 0xF8
        length = 0x18 + len(section) + 1  # (one pad byte: the next file is looked for there)
        record[4:7] = struct.pack("<I", length)[:3]
        record[8:12] = f.name.encode()
        image[at : at + length] = bytes(record) + section + b"\xff"
        at += length
    return bytes(image)


# --- PhoenixBIOS 4.0 setup templates ---------------------------------------------------------


@dataclass
class StringPack:
    """A string pack read in two hops: a reference is a word at base + ref holding the
    text's offset from base; texts follow a NUL."""

    texts: list[str]
    base: int = 0x1C
    refs: dict[str, int] = field(default_factory=dict)
    pack: bytes = b""

    def __post_init__(self) -> None:
        table = bytearray(self.base + 2 * (len(self.texts) + 2))
        body = bytearray(b"\0")
        offsets = {}
        for text in self.texts:
            offsets[text] = len(table) - self.base + len(body)
            body += text.encode() + b"\0"
        for k, text in enumerate(self.texts, 1):
            struct.pack_into("<H", table, self.base + 2 * k, offsets[text])
            self.refs[text] = 2 * k
        self.pack = bytes(table + body)

    def mid_text(self, text: str, skip: int = 3) -> int:
        """A reference that leads into the middle of text (as a stray word would)."""
        k = len(self.texts) + 1
        offset = struct.unpack_from("<H", self.pack, self.base + self.refs[text])[0] + skip
        pack = bytearray(self.pack)
        struct.pack_into("<H", pack, self.base + 2 * k, offset)
        self.pack = bytes(pack)
        return 2 * k


def pick_record(prompt: int, help_ref: int, options: list[int], mode: int = 0x00) -> bytes:
    """A pick record: mode, length, prompt, help, four entry points, an NVRAM token, options."""
    fields = [prompt, help_ref, 0x4000, 0x4010, 0x4020, 0x4030, 0x0135, *options]
    return bytes([mode, 2 + 2 * len(fields)]) + struct.pack(f"<{len(fields)}H", *fields)


def template(records: list[bytes]) -> tuple[bytes, int]:
    """A template holding the records and one table of (record, 0) pairs naming them, in
    PhoenixBIOS 4.0's layout (pointers from the module's start). Returns it and the table."""
    data = bytearray(0x40)
    where = []
    for r in records:
        where.append(len(data))
        data += r
    table = len(data)
    for w in where:
        data += struct.pack("<HH", w, 0)
    data += b"\0\0\0\0"
    return bytes(data), table
