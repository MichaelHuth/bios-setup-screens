"""
Read SQX archives (Squeez / SpeedProject, Sven Ritter, from 1993), which MSI used for the
self-extracting BIOS updates of about 2004-2010 (the archive sits behind a Windows program,
"SQ5SFX"; 7-Zip does not read it). Read here, never run.

Worked out from the format description in seb3773/Squeez-c's
FORMAT.md (MIT licence; the token rules follow the semantics of its src/lz.c and src/huff.c,
written anew) and https://justsolve.archiveteam.org/wiki/SQX:
- blocks [crc16][type][flags][size], the checksum the low 16 bits of an un-inverted CRC-32 over
  the block from its type on; the main block "R" has "-sqx-" at +7, files are "D" blocks,
  "V" directories, "S" the end;
- methods 0 (stored) and 1-4 (LZH: LZ77 with canonical Huffman trees per block) of both
  revisions, 1.1 (file header +0Bh = 0Bh: 310 literal/length and 56 distance codes) and 2.0
  (14h: 311 and 54, a low-16 distance sub-tree); solid archives share one window across the
  members. Methods 5-7 (audio, PPMd, range coder) and the delta / IA-32 post-transforms are
  not decoded: a member after them in a solid archive may come out with wrong bytes (MSI
  H67H2's image fails its CRC-32 by a few, but its setup reads).
"""

from __future__ import annotations

import struct
import zlib

BLOCK_MAIN, BLOCK_FILE, BLOCK_DIR, BLOCK_END, BLOCK_RECOVERY = 0x52, 0x44, 0x56, 0x53, 0x58
OTHER_BLOCKS = (BLOCK_DIR, 0x43, 0x41, 0x49)  # directories, comments, ...
EXT_HDR_FLAG = 0x8000  # a further header block follows
SIZES_64_FLAG = 0x80  # 64-bit packed / unpacked sizes
SOLID_FLAG = 0x0004
DIC_EXT_FLAG = 0x800  # (2.0's dictionaries of 8-32 MB: not supported)
VER_11, VER_20 = 0x0B, 0x14
EXT_DELTA = 0x0004  # the extended-compressor header carries delta parameters
MAX_CHAIN = 64 * 1024 * 1024  # bytes decoded along a solid chain before giving up


def _crc(data: bytes) -> int:
    """SQX's CRC-32: reflected 0xEDB88320, start 0xFFFFFFFF, no final inversion."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


def _block_at(raw: bytes, p: int) -> tuple[int, int, int, int] | None:
    """(crc16, type, flags, size) of the block header at p, or None."""
    if p < 0 or p + 7 > len(raw):
        return None
    crc, typ, flags, size = struct.unpack_from("<HBHH", raw, p)
    if not 7 <= size <= 0x10000 or p + size > len(raw):
        return None
    return crc, typ, flags, size


def _headers_end(raw: bytes, p: int) -> int | None:
    """The offset just past a block header and its extension headers, or None."""
    block = _block_at(raw, p)
    if block is None:
        return None
    flags, end = block[2], p + block[3]
    for _ in range(64):
        if not flags & EXT_HDR_FLAG:
            return end
        ext = _block_at(raw, end)
        if ext is None:
            return None
        flags, end = ext[2], end + ext[3]
    return None


def _checked(raw: bytes, p: int, block: tuple[int, int, int, int]) -> bool:
    return (_crc(raw[p + 2 : p + block[3]]) & 0xFFFF) == block[0]


def _chain_ok(raw: bytes, p: int) -> bool:
    """The blocks from p on parse, with good checksums, to an end block or the end of the
    data (MSI 7366's archive has no end block)."""
    files = 0
    for _ in range(4096):
        block = _block_at(raw, p)
        end = _headers_end(raw, p)
        if block is None or end is None:
            return files > 0 and block is None
        typ, flags = block[1], block[2]
        if typ in (BLOCK_END, BLOCK_RECOVERY):
            return _checked(raw, p, block)
        if typ == BLOCK_FILE:
            if not _checked(raw, p, block) or p + 0x29 > len(raw):
                return False
            files += 1
            p = end + struct.unpack_from("<Q" if flags & SIZES_64_FLAG else "<I", raw, p + 0x19)[0]
        elif typ in (BLOCK_MAIN, *OTHER_BLOCKS):
            p = end
        else:
            return False
    return False


def find_archive(raw: bytes) -> int | None:
    """The offset of the SQX main block in raw, or None."""
    p = raw.find(b"-sqx-")
    while p >= 0:
        block = _block_at(raw, p - 7)
        if (
            block is not None
            and block[1] == BLOCK_MAIN
            and _checked(raw, p - 7, block)
            and _chain_ok(raw, p - 7)
        ):
            return p - 7
        p = raw.find(b"-sqx-", p + 1)
    return None


def members(raw: bytes, offset: int) -> list[dict]:
    """The archive's files: index, name, method, ver, compflags, packed, size, crc32, data
    (offset of the packed data), dic (window size), solid."""
    main = _block_at(raw, offset)
    p = _headers_end(raw, offset)
    if main is None or main[1] != BLOCK_MAIN or p is None:
        raise ValueError("no SQX main header there")
    out: list[dict] = []
    while p + 7 <= len(raw) and len(out) < 65536:
        block = _block_at(raw, p)
        end = _headers_end(raw, p)
        if block is None or end is None:
            raise ValueError(f"SQX block at {p:#x} is broken")
        typ, flags = block[1], block[2]
        if typ in (BLOCK_END, BLOCK_RECOVERY):
            break
        if typ in OTHER_BLOCKS:
            p = end
            continue
        if typ != BLOCK_FILE:
            raise ValueError(f"unknown SQX block type {typ:#04x} at {p:#x}")
        big = bool(flags & SIZES_64_FLAG)
        if p + 0x2B > len(raw):
            raise ValueError("SQX file header runs past the end")
        packed, size = struct.unpack_from("<QQ" if big else "<II", raw, p + 0x19)
        name_length = struct.unpack_from("<H", raw, p + (0x29 if big else 0x21))[0]
        name = raw[p + (0x2B if big else 0x23) :][:name_length]
        out.append(
            {
                "index": len(out),
                "name": name.split(b"\0")[0].decode("cp437"),
                "method": raw[p + 12],
                "ver": raw[p + 11],
                "compflags": raw[p + 7],
                "packed": packed,
                "size": size,
                "crc32": struct.unpack_from("<I", raw, p + 13)[0],
                "data": end,
                "dic": 0x8000 << (flags >> 8 & 7),
                "dic_ext": bool(flags & DIC_EXT_FLAG),
                "solid": bool(main[2] & SOLID_FLAG and flags & SOLID_FLAG),
            }
        )
        p = end + packed
    return out


class _Bits:
    """An MSB-first bit reader: SQX stores its bits in 32-bit little-endian words, read from
    the top bit down."""

    __slots__ = ("data", "pos", "buf", "count")

    def __init__(self, data: bytes):
        padded = bytes(data) + b"\0" * (-len(data) % 4)
        swapped = bytearray(len(padded))
        for k in range(4):
            swapped[k::4] = padded[3 - k :: 4]
        self.data, self.pos, self.buf, self.count = bytes(swapped) + b"\0" * 8, 0, 0, 0

    def get(self, n: int) -> int:
        while self.count < n:
            if self.pos >= len(self.data):
                raise ValueError("SQX stream ends early")
            self.buf = self.buf << 8 | self.data[self.pos]
            self.pos += 1
            self.count += 8
        self.count -= n
        value = self.buf >> self.count
        self.buf &= (1 << self.count) - 1
        return value

    def give(self, value: int, n: int) -> None:
        """Push back the n low bits of value (the Huffman decoder peeks a whole code's
        length and returns what the code did not use)."""
        self.buf |= (value & ((1 << n) - 1)) << self.count
        self.count += n


class _Huffman:
    """A canonical Huffman code, decoded through one table of its longest code's width."""

    __slots__ = ("lengths", "table", "bits")

    def __init__(self, lengths: list[int]):
        self.lengths, self.bits = lengths, max(lengths, default=0)
        if not 0 < self.bits <= 16:
            raise ValueError("bad SQX Huffman table")
        if sum(1 << (self.bits - n) for n in lengths if n) != 1 << self.bits:
            raise ValueError("incomplete SQX Huffman table")
        self.table = [-1] * (1 << self.bits)
        code = 0
        for length in range(1, self.bits + 1):
            for symbol, n in enumerate(lengths):
                if n == length:
                    shift = self.bits - length
                    self.table[code << shift : (code + 1) << shift] = [symbol] * (1 << shift)
                    code += 1
            code <<= 1

    def decode(self, bits: _Bits) -> int:
        value = bits.get(self.bits)
        symbol = self.table[value]
        unused = self.bits - self.lengths[symbol]
        if unused:
            bits.give(value, unused)
        return symbol


def _meta(bits: _Bits) -> _Huffman:
    """The tree (19 lengths of 4 bits) that codes the other trees' lengths."""
    return _Huffman([bits.get(4) for _ in range(19)])


def _tree_lengths(bits: _Bits, meta: _Huffman, n: int) -> list[int]:
    """n code lengths coded through meta, with the runs 16 (repeat), 17 and 18 (zeros)."""
    lengths, i = [0] * n, 0
    while i < n:
        code = meta.decode(bits)
        if code < 16:
            lengths[i] = code
            i += 1
        elif code == 16:
            previous = lengths[i - 1] if i else 0
            for _ in range(3 + bits.get(2)):
                if i < n:
                    lengths[i] = previous
                    i += 1
        else:
            i = min(n, i + (3 + bits.get(3) if code == 17 else 11 + bits.get(7)))
    return lengths


def _flat_lengths(bits: _Bits, n: int) -> list[int]:
    """n code lengths, each a step from the one before through a little bit tree."""
    lengths = [bits.get(4)]
    for _ in range(1, n):
        length = lengths[-1]
        if not bits.get(1):
            pass  # the same
        elif not bits.get(1):
            length += 1
        elif bits.get(1):
            length = bits.get(4)
        elif not bits.get(1):
            length -= 1
        else:
            length += 2
        lengths.append(length)
    return lengths


LEN_BASE: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 20, 24, 32, 40, 48, 64)
LEN_BASE += (80, 96, 128, 160, 192, 224)
LEN_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5)
LEN2_BASE, LEN2_EXTRA = (0, 4, 8, 16, 32, 64, 128, 192), (2, 2, 3, 4, 5, 6, 6, 6)
LEN3_BASE = (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384)
LEN3_EXTRA = (0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)  # (16384: 2.0 only)


# distance bases and extra bits by window size (Squeez-c's tables, MB keys)
BASE = {
    1: (
        (
            0,
            1,
            2,
            3,
            4,
            6,
            8,
            12,
            16,
            24,
            32,
            48,
            64,
            96,
            128,
            192,
            256,
            384,
            512,
            768,
            1024,
            1536,
            2048,
            3072,
            4096,
            6144,
            8192,
            12288,
            16384,
            24576,
            32768,
            49152,
            65536,
            98304,
            131072,
            196608,
            262144,
            327680,
            393216,
            458752,
            524288,
            589824,
            655360,
            720896,
            786432,
            851968,
            917504,
            983040,
            1048576,
        ),
        (
            0,
            0,
            0,
            0,
            1,
            1,
            2,
            2,
            3,
            3,
            4,
            4,
            5,
            5,
            6,
            6,
            7,
            7,
            8,
            8,
            9,
            9,
            10,
            10,
            11,
            11,
            12,
            12,
            13,
            13,
            14,
            14,
            15,
            15,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
            16,
        ),
    ),
    2: (
        (
            0,
            1,
            2,
            3,
            4,
            6,
            8,
            12,
            16,
            24,
            32,
            48,
            64,
            96,
            128,
            192,
            256,
            384,
            512,
            768,
            1024,
            1536,
            2048,
            3072,
            4096,
            6144,
            8192,
            12288,
            16384,
            24576,
            32768,
            49152,
            65536,
            98304,
            131072,
            196608,
            262144,
            393216,
            524288,
            655360,
            786432,
            917504,
            1048576,
            1179648,
            1310720,
            1441792,
            1572864,
            1703936,
            1835008,
            1966080,
            2097152,
        ),
        (
            0,
            0,
            0,
            0,
            1,
            1,
            2,
            2,
            3,
            3,
            4,
            4,
            5,
            5,
            6,
            6,
            7,
            7,
            8,
            8,
            9,
            9,
            10,
            10,
            11,
            11,
            12,
            12,
            13,
            13,
            14,
            14,
            15,
            15,
            16,
            16,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
            17,
        ),
    ),
    4: (
        (
            0,
            1,
            2,
            3,
            4,
            6,
            8,
            12,
            16,
            24,
            32,
            48,
            64,
            96,
            128,
            192,
            256,
            384,
            512,
            768,
            1024,
            1536,
            2048,
            3072,
            4096,
            6144,
            8192,
            12288,
            16384,
            24576,
            32768,
            49152,
            65536,
            98304,
            131072,
            196608,
            262144,
            393216,
            524288,
            786432,
            1048576,
            1310720,
            1572864,
            1835008,
            2097152,
            2359296,
            2621440,
            2883584,
            3145728,
            3407872,
            3670016,
            3932160,
            4194304,
        ),
        (
            0,
            0,
            0,
            0,
            1,
            1,
            2,
            2,
            3,
            3,
            4,
            4,
            5,
            5,
            6,
            6,
            7,
            7,
            8,
            8,
            9,
            9,
            10,
            10,
            11,
            11,
            12,
            12,
            13,
            13,
            14,
            14,
            15,
            15,
            16,
            16,
            17,
            17,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
            18,
        ),
    ),
    8: (
        (
            0,
            1,
            2,
            3,
            4,
            6,
            8,
            12,
            16,
            24,
            32,
            48,
            64,
            96,
            128,
            192,
            256,
            384,
            512,
            768,
            1024,
            1536,
            2048,
            3072,
            4096,
            6144,
            8192,
            12288,
            16384,
            24576,
            32768,
            49152,
            65536,
            98304,
            131072,
            196608,
            262144,
            393216,
            524288,
            786432,
            1048576,
            1572864,
            2097152,
            2621440,
            3145728,
            3670016,
            4194304,
            4718592,
            5242880,
            5767168,
            6291456,
            6815744,
            7340032,
            7864320,
        ),
        (
            0,
            0,
            0,
            0,
            1,
            1,
            2,
            2,
            3,
            3,
            4,
            4,
            5,
            5,
            6,
            6,
            7,
            7,
            8,
            8,
            9,
            9,
            10,
            10,
            11,
            11,
            12,
            12,
            13,
            13,
            14,
            14,
            15,
            15,
            16,
            16,
            17,
            17,
            18,
            18,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
            19,
        ),
    ),
}


def _distance_table(dic: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Squeez-c's thresholds (8, 4, 2 MB) compared with the window in KB, as measured: by
    bytes, the large members ask for distances before their data."""
    for mb in (8, 4, 2, 1):
        if dic // 1024 >= mb * 1024:
            return BASE[mb]
    return BASE[1]


class _Window:
    """The LZ state of one (solid) chain of members: the window and the last distances."""

    def __init__(self, dic: int):
        self.dic = dic
        self.bases, self.extra = _distance_table(dic)
        self.window = bytearray()
        self.last_length = self.last_distance = self.distance = self.tree = 0
        self.previous = [0, 0, 0, 0]
        self.turn = 0
        self.low16: _Huffman | None = None
        self.literal = self.literal2 = self.repeat = self.distances = _Huffman([1, 1])
        self.two_trees = False
        self.boundary = 0

    def feed(self, data: bytes) -> None:
        """A stored member's bytes, into the shared window."""
        self.window += data
        del self.window[: max(0, len(self.window) - self.dic)]

    def _copy(self, out: bytearray, length: int, distance: int) -> None:
        if not length:
            return  # ("repeat the last match" before any match)
        window = self.window
        if not 0 < distance <= min(self.dic, len(window)):
            raise ValueError("SQX match points before the start of the data")
        start = len(window) - distance
        if distance >= length:
            chunk = window[start : start + length]
        else:
            pattern = window[start:]
            chunk = pattern * (length // distance) + pattern[: length % distance]
        window += chunk
        out += chunk

    def _remember(self, distance: int) -> None:
        self.distance = distance
        self.previous[self.turn & 3] = distance
        self.turn += 1

    def _block(self, bits: _Bits, v20: bool) -> int:
        """Read a block header (its trees); returns the number of tokens in it."""
        if bits.get(1):
            raise ValueError("SQX range-coded (multimedia) block not supported")
        tokens = bits.get(15)
        if not tokens:
            raise ValueError("empty SQX block")
        self.low16 = None
        if v20 and bits.get(1):
            width = bits.get(4)
            self.low16 = _Huffman([bits.get(width) for _ in range(16)])
        literals, distances = (311, 54) if v20 else (310, 56)
        self.two_trees = bool(bits.get(1))
        if self.two_trees:  # two literal/length trees, chosen by the last code
            self.boundary = bits.get(9)
            meta = _meta(bits)
            self.literal = _Huffman(_tree_lengths(bits, meta, literals))
            self.literal2 = _Huffman(_tree_lengths(bits, meta, literals))
            self.repeat = _Huffman(_flat_lengths(bits, 25))
            self.distances = _Huffman(_flat_lengths(bits, distances))
        elif not bits.get(1):
            self.boundary = 0
            meta = _meta(bits)
            self.literal = _Huffman(_tree_lengths(bits, meta, literals))
            self.repeat = _Huffman(_tree_lengths(bits, meta, 25))
            self.distances = _Huffman(_tree_lengths(bits, meta, distances))
        else:
            self.boundary = 0
            self.literal = _Huffman(_flat_lengths(bits, literals))
            self.repeat = _Huffman(_flat_lengths(bits, 25))
            self.distances = _Huffman(_flat_lengths(bits, distances))
        self.tree = self.boundary  # (the new block's boundary, before its first token)
        return int(tokens)

    def _far(self, bits: _Bits, v20: bool) -> int:
        code = self.distances.decode(bits)
        if code >= len(self.extra):
            raise ValueError("SQX distance code out of range")
        base, extra = self.bases[code], self.extra[code]
        if v20 and self.low16 is not None and extra >= 4:
            high = bits.get(extra - 4) if extra > 4 else 0
            return base + (high << 4) + self.low16.decode(bits) + 1
        return base + bits.get(extra) + 1

    def decode(self, bits: _Bits, size: int, v20: bool) -> bytes:
        """One member's bytes (each member has its own bit stream and blocks)."""
        out = bytearray()
        left = 0
        while len(out) < size:
            if left <= 0:
                left = self._block(bits, v20)
            left -= 1
            if self.two_trees:
                tree = self.literal if self.tree < self.boundary + 1 else self.literal2
                code = self.tree = tree.decode(bits)
            else:
                code = self.literal.decode(bits)
            if not v20:  # (1.1 has no codes 257 and 284)
                code += (code > 256) + (code > 283)
            if code < 256:
                self.window.append(code)
                out.append(code)
            elif code == 256:  # the last match again
                self._copy(out, self.last_length, self.last_distance)
                self._remember(self.last_distance)
            elif code == 257 and v20:  # one byte at the last distance
                self._copy(out, 1, self.distance)
            elif code < 262:  # a match at one of the last four distances
                distance = self.previous[(self.turn - (code - 257)) & 3]
                self.last_distance = self.distance = distance
                n = self.repeat.decode(bits)
                length = 257 + bits.get(14) if n == 24 else LEN_BASE[n] + bits.get(LEN_EXTRA[n]) + 2
                length += distance > 0x7FFF if v20 else (distance > 16383) + (distance > 262143)
                self.last_length = length
                self._copy(out, length, distance)
                self._remember(distance)
            elif code < 270:  # length 2, near
                n = code - 262
                distance = LEN2_BASE[n] + bits.get(LEN2_EXTRA[n]) + 1
                self._copy(out, 2, distance)
                self._remember(distance)
            elif code < 286:  # length 3
                n = code - 270
                if n >= (16 if v20 else 15):
                    raise ValueError("SQX length-3 code out of range")
                distance = LEN3_BASE[n] + bits.get(LEN3_EXTRA[n]) + 1
                self._copy(out, 3, distance)
                self._remember(distance)
            else:  # length 4 and more
                if code >= 310:
                    length = 257 + bits.get(14)
                    distance = self._far(bits, v20)
                else:
                    n = code - 286
                    length = LEN_BASE[n] + bits.get(LEN_EXTRA[n]) + 4
                    distance = self._far(bits, v20)
                    length += not v20 and distance > 262143
                self._copy(out, length, distance)
                self._remember(distance)
        del self.window[: max(0, len(self.window) - self.dic)]
        return bytes(out[:size])


def extract(raw: bytes, offset: int, index: int) -> tuple[bytes, bool, bool]:
    """(the bytes of member index, whether they match its CRC-32, whether the window it was
    decoded against is whole). A solid archive is decoded from its first member on; members
    of methods 5-7 leave a gap in the window, post-transformed ones wrong bytes."""
    files = members(raw, offset)
    if sum(m["size"] for m in files[: index + 1]) > MAX_CHAIN:
        raise ValueError("this SQX archive unpacks to too much")
    window: _Window | None = None
    data, whole = b"", True
    for m in files[: index + 1]:
        data = b""
        packed = raw[m["data"] : m["data"] + m["packed"]]
        if m["method"] == 0:
            data = packed
            if window is not None:
                window.feed(data)
        elif m["method"] in (1, 2, 3, 4):
            if m["ver"] not in (VER_11, VER_20) or m["dic_ext"]:
                raise ValueError(f"{m['name']}: an SQX variant not supported")
            if window is None or not m["solid"]:
                window, whole = _Window(m["dic"]), True
            bits = _Bits(packed)
            if m["compflags"]:  # an extended-compressor header (post-transform: skipped)
                whole = False
                if (bits.get(8) | bits.get(8) << 8) & EXT_DELTA:
                    bits.get(48)
            data = window.decode(bits, m["size"], m["ver"] == VER_20)
        elif m["index"] == index:
            raise ValueError(f"{m['name']} is packed with SQX method {m['method']}")
        else:
            whole = False
    return data, _crc(data) == files[index]["crc32"], whole
