"""
Minimal LHA (LZH) support: find -lh0-/-lh4-/-lh5-/-lh6-/-lh7- archive headers inside a binary
(Award BIOS modules are stored this way) and decompress them. Pure Python, decoding only.
"""

from __future__ import annotations

import struct

NC = 510  # literal/length alphabet: 256 bytes + 254 match lengths
NT = 19  # alphabet of the code-length code
CBIT = 9
TBIT = 5
THRESHOLD = 3
METHODS = {b"-lh0-": 0, b"-lh4-": 12, b"-lh5-": 13, b"-lh6-": 15, b"-lh7-": 16}


def crc16(data: bytes) -> int:
    """CRC-16/ARC as used by LHA."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class _Bits:
    def __init__(self, data: bytes):
        self.data = data + b"\0\0\0\0"
        self.pos = 0  # in bits
        self.limit = len(data) * 8

    def peek(self, n: int) -> int:
        i = self.pos >> 3
        chunk = int.from_bytes(self.data[i : i + 4], "big")
        return (chunk >> (32 - (self.pos & 7) - n)) & ((1 << n) - 1)

    def get(self, n: int) -> int:
        if n == 0:
            return 0
        v = self.peek(n)
        self.pos += n
        if self.pos > self.limit + 32:
            raise ValueError("compressed data ended early")
        return v


class _Huffman:
    """Canonical Huffman decoder (same code assignment as LHA's make_table)."""

    def __init__(self, lengths: list[int], single: int | None = None):
        self.single = single
        if single is not None:
            return
        self.lengths = lengths
        self.bits = max(lengths)
        if self.bits > 16:
            raise ValueError("bad Huffman table")
        self.table = [-1] * (1 << self.bits)
        code = 0
        for length in range(1, self.bits + 1):
            for sym, l in enumerate(lengths):
                if l == length:
                    shift = self.bits - length
                    start = code << shift
                    if start + (1 << shift) > len(self.table):
                        raise ValueError("bad Huffman table")
                    self.table[start : start + (1 << shift)] = [sym] * (1 << shift)
                    code += 1
            code <<= 1

    def decode(self, bits: _Bits) -> int:
        if self.single is not None:
            return self.single
        sym = self.table[bits.peek(self.bits)]
        if sym < 0:
            raise ValueError("invalid Huffman code")
        bits.pos += self.lengths[sym]
        return sym


def _read_pt_len(bits: _Bits, nn: int, nbit: int, special: int) -> _Huffman:
    n = bits.get(nbit)
    if n == 0:
        return _Huffman([], single=bits.get(nbit))
    lengths = [0] * nn
    i = 0
    while i < n and i < nn:
        c = bits.peek(3)
        if c == 7:
            bits.pos += 3
            while bits.get(1):
                c += 1
        else:
            bits.pos += 3
        lengths[i] = c
        i += 1
        if i == special:
            for _ in range(bits.get(2)):
                if i < nn:
                    lengths[i] = 0
                    i += 1
    return _Huffman(lengths)


def _read_c_len(bits: _Bits, pt: _Huffman) -> _Huffman:
    n = bits.get(CBIT)
    if n == 0:
        return _Huffman([], single=bits.get(CBIT))
    lengths = [0] * NC
    i = 0
    while i < n and i < NC:
        c = pt.decode(bits)
        if c <= 2:
            zeros = 1 if c == 0 else bits.get(4) + 3 if c == 1 else bits.get(CBIT) + 20
            i += zeros  # lengths already 0
        else:
            lengths[i] = c - 2
            i += 1
    return _Huffman(lengths)


MAX_OUT = 64 << 20


def decompress(data: bytes, out_size: int, method: bytes, partial: bool = False) -> bytes:
    """The unpacked data; with partial, what the blocks before a broken one gave (EXB130's
    self-extracting Award image: its last block's table does not decode)."""
    if out_size > MAX_OUT:  # (the size comes from the file: no room is made for just anything)
        raise ValueError(f"an LHA member of {out_size} bytes")
    dicbit = METHODS[method]
    if dicbit == 0:
        return data[:out_size]
    np_ = 14 if dicbit <= 13 else dicbit + 1
    pbit = 4 if dicbit <= 13 else 5
    bits = _Bits(data)
    out = bytearray()
    while len(out) < out_size:
        blocksize = bits.get(16)
        try:
            pt = _read_pt_len(bits, NT, TBIT, 3)
            c_table = _read_c_len(bits, pt)
            p_table = _read_pt_len(bits, np_, pbit, -1)
        except (ValueError, IndexError):
            if partial and out:
                break
            raise
        for _ in range(blocksize):
            c = c_table.decode(bits)
            if c < 256:
                out.append(c)
            else:
                length = c - (256 - THRESHOLD)
                j = p_table.decode(bits)
                if j:
                    j = (1 << (j - 1)) + bits.get(j - 1)
                start = len(out) - j - 1
                if start < 0:
                    raise ValueError("match points before start of data")
                for k in range(length):
                    out.append(out[start + k])
            if len(out) >= out_size:
                break
    return bytes(out[:out_size])


def find_modules(data: bytes, limit: int = 64) -> list[dict]:
    """Find LHA headers (levels 0, 1, 2) in data; returns their fields and data position."""
    modules: list[dict] = []
    pos = 0
    while len(modules) < limit:
        hits = [i for i in (data.find(m, pos) for m in METHODS) if i >= 0]
        if not hits:
            break
        m = min(hits)
        pos = m + 1
        h = m - 2  # header starts two bytes before the method id
        if h < 0 or h + 24 > len(data):
            continue
        method = bytes(data[m : m + 5])
        packed, size = struct.unpack_from("<II", data, h + 7)
        loader = struct.unpack_from("<I", data, h + 15)[0]  # date/time; Award stores load info
        level = data[h + 20]
        name, crc = "", None
        if level in (0, 1):
            hsize, checksum = data[h], data[h + 1]
            if hsize < 22 or (sum(data[h + 2 : h + 2 + hsize]) & 0xFF) != checksum:
                continue
            nlen = data[h + 21]
            name = data[h + 22 : h + 22 + nlen].decode("latin-1")
            if 22 + nlen + 2 <= hsize + 2:
                crc = struct.unpack_from("<H", data, h + 22 + nlen)[0]
            start = h + 2 + hsize
            if level == 1:  # extended headers follow and count toward the packed size
                ext = struct.unpack_from("<H", data, start - 2)[0]
                while ext and start + ext <= len(data):
                    start += ext
                    packed -= ext
                    ext = struct.unpack_from("<H", data, start - 2)[0]
        elif level == 2:
            hsize = struct.unpack_from("<H", data, h)[0]
            if hsize < 26 or h + hsize > len(data):
                continue
            crc = struct.unpack_from("<H", data, h + 21)[0]
            e = h + 24
            ext = struct.unpack_from("<H", data, e)[0]
            e += 2
            while ext and e + ext - 2 <= h + hsize:
                if data[e] == 0x01:  # file name
                    name = data[e + 1 : e + ext - 2].decode("latin-1")
                e += ext - 2
                ext = struct.unpack_from("<H", data, e)[0]
                e += 2
            start = h + hsize
        else:
            continue
        if packed < 0 or start + packed > len(data) or size > 16 * 1024 * 1024:
            continue
        modules.append(
            {
                "offset": h,
                "method": method.decode(),
                "level": level,
                "name": name,
                "packed": packed,
                "size": size,
                "loader": loader,
                "crc": crc,
                "data_start": start,
            }
        )
        pos = start + packed
    return modules
