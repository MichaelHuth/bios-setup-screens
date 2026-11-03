"""Undo LZEXE 0.91 on a DOS program, as data (nothing is run). Dell's flash programs of about
1997-2002 are packed with it, with its "LZ91" mark removed; the stub's entry and stack give it
away. The stream, right behind the header: control bits, lowest first, in 16-bit words, each
word read as soon as the one before is used up. 1: a literal byte. 01: a match of 2-9 bytes (or
longer, or the end) within 8 KB, in two bytes. 00: a match of 2-5 bytes within 256 bytes, its
length in the next two bits and its distance in one byte.
"""

from __future__ import annotations

import struct

MAX_OUT = 16 * 1024 * 1024


def is_packed(raw: bytes) -> bool:
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        return False
    header, sp, ip = (struct.unpack_from("<H", raw, at)[0] for at in (0x08, 0x10, 0x14))
    return header == 2 and sp == 0x80 and ip == 0x0E


def unpack(raw: bytes) -> bytes | None:
    """The program's load image (without its relocations), or None if the stream is not LZEXE's."""
    pos = struct.unpack_from("<H", raw, 0x08)[0] * 16
    out = bytearray()
    try:
        word, left = raw[pos] | raw[pos + 1] << 8, 16
        pos += 2

        def bit() -> int:
            nonlocal word, left, pos
            value = word & 1
            word >>= 1
            left -= 1
            if not left:
                word, left = raw[pos] | raw[pos + 1] << 8, 16
                pos += 2
            return value

        while len(out) < MAX_OUT:
            if bit():
                out.append(raw[pos])
                pos += 1
                continue
            if not bit():
                count = (bit() << 1 | bit()) + 2
                distance = 0x100 - raw[pos]
                pos += 1
            else:
                low, high = raw[pos], raw[pos + 1]
                pos += 2
                distance = 0x2000 - (low | (high & 0xF8) << 5)
                count = (high & 7) + 2
                if count == 2:
                    count = raw[pos]
                    pos += 1
                    if count == 0:
                        return bytes(out)
                    if count == 1:  # (the end of a 64 KB segment of the stream)
                        continue
                    count += 1
            start = len(out) - distance
            if start < 0:
                return None
            for k in range(count):
                out.append(out[start + k])
    except IndexError:
        return None
    return None
