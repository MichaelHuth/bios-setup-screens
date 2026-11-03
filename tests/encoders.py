"""
Encoders for the tests (the bot only decodes): LH5 block streams, which EFI and Tiano
compression share, and Okumura's LZSS. They make known input into compressed data, so the
decoders can be checked against the input they must give back.

The LH5 encoder uses one fixed code instead of codes fitted to the data: literals take 9 bits,
match lengths 3-130 take 8, and matches reach back 1 byte or 17-32 bytes. That is a valid
stream as the format defines it, and it still uses every part of the block layout: the
code-length code with its run of zeros, the literal/length code, the position code and
several blocks.
"""

from __future__ import annotations

import struct

MAX_MATCH = 130  # (match symbols 256-383: lengths 3-130)
BACKS = (1, *range(17, 33))  # (position symbols 0 and 5)


class BitWriter:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def write(self, value: int, n: int) -> None:
        self.bits += [(value >> k) & 1 for k in range(n - 1, -1, -1)]

    def bytes(self) -> bytes:
        padded = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(int("".join(map(str, padded[i : i + 8])), 2) for i in range(0, len(padded), 8))


def tokens(data: bytes, backs: tuple[int, ...] = BACKS, max_match: int = MAX_MATCH) -> list:
    """Greedy LZ77: ("lit", byte) or ("match", length, back)."""
    out: list = []
    i = 0
    while i < len(data):
        best_len, best_back = 0, 0
        for back in backs:
            if back > i:
                continue
            n = 0
            while n < max_match and i + n < len(data) and data[i + n] == data[i + n - back]:
                n += 1
            if n > best_len:
                best_len, best_back = n, back
        if best_len >= 3:
            out.append(("match", best_len, best_back))
            i += best_len
        else:
            out.append(("lit", data[i]))
            i += 1
    return out


def lh5_stream(data: bytes, pbit: int = 4, block: int = 2000, bad_block: bool = False) -> bytes:
    """The LH5 bit stream of data (no LHA header); pbit is 4 for -lh5- and EFI, 5 for Tiano.
    bad_block: one more block follows whose literal/length table does not decode (nine
    codes of one bit)."""
    w = BitWriter()
    items = tokens(data)
    for start in range(0, len(items), block):
        chunk = items[start : start + block]
        w.write(len(chunk), 16)
        # the code-length code: symbol 10 (a length of 8) is "0", 11 (a length of 9) is "1"
        w.write(12, 5)
        for _ in range(3):
            w.write(0, 3)
        w.write(3, 2)  # (entries 3-5 are zero, the format's run after the third)
        for _ in range(4):
            w.write(0, 3)
        w.write(1, 3)
        w.write(1, 3)
        # literal/length code lengths: 256 literals of 9 bits, 128 match lengths of 8 bits
        w.write(384, 9)
        for i in range(384):
            w.write(1 if i < 256 else 0, 1)
        # position code: symbol 0 (1 back) is "0", symbol 5 (17-32 back) is "1"
        w.write(6, pbit)
        for length in (1, 0, 0, 0, 0, 1):
            w.write(length, 3)
        for item in chunk:
            if item[0] == "lit":
                w.write(256 + item[1], 9)
                continue
            _, length, back = item
            w.write(length - 3, 8)
            if back == 1:
                w.write(0, 1)
            else:
                w.write(1, 1)
                w.write(back - 17, 4)
    if bad_block:
        w.write(10, 16)
        w.write(0, 5)  # (a code-length code of one symbol, 3: every length is 1)
        w.write(3, 5)
        w.write(9, 9)  # (nine codes of one bit: more than one bit can hold)
    return w.bytes()


def efi_compress(data: bytes, version: int = 1) -> bytes:
    """EFI (version 1) or Tiano (2) compressed data: sizes, then the block stream."""
    stream = lh5_stream(data, pbit=4 if version == 1 else 5)
    return struct.pack("<II", len(stream), len(data)) + stream


def lzss(data: bytes) -> bytes:
    """Okumura's LZSS: a 4 KB ring filled from FEEh, a flag byte (lowest bit first, 1 = a
    literal) before every eight items, a match as 12-bit ring position and length - 3."""
    out = bytearray()
    items = tokens(data, backs=tuple(range(1, 2049)), max_match=18)
    pos = 0
    for start in range(0, len(items), 8):
        group = items[start : start + 8]
        flags, body = 0, bytearray()
        for k, item in enumerate(group):
            if item[0] == "lit":
                flags |= 1 << k
                body.append(item[1])
                pos += 1
            else:
                _, length, back = item
                ring = (0xFEE + pos - back) & 0xFFF
                body += bytes((ring & 0xFF, (ring >> 4) & 0xF0 | (length - 3)))
                pos += length
        out.append(flags)
        out += body
    return bytes(out)
