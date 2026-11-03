"""
Compaq/HP Softpaq ROMPaq updates (SP*.EXE, about 1994-2000): the flash images out of them.

The Softpaq is a self-extracting container: the PKLITE-packed extractor, a few text blobs and IMAGE1.IMG, a
1.44 MB ROMPaq diskette packed with PKWARE's Data Compression Library ("implode", the DCL the
extractor links; header bytes 00 06: literals stored, a 4 KB window). A "[FIT]" block names the
image's directory record. On the diskette, ROMPAQ.EXE and one file per ROM (CARS6U10.EB9,
TORCH000.562, MONO4G00.CB4 ...): a header (the ROM's size as u32 at 0, a checksum, the ROM's name
and date at 0Ch and 14h) and the ROM, again DCL-imploded, from 48h (4Ah in the files with 01 01
at 0Ah).
"""

from __future__ import annotations

import struct

MAXBITS = 13
# PKWARE DCL "implode" code tables (as in zlib's contrib/blast): bit lengths, run-length packed
# (high nibble = repeat count - 1, low nibble = length)
LITLEN = bytes(
    [
        11,
        124,
        8,
        7,
        28,
        7,
        188,
        13,
        76,
        4,
        10,
        8,
        12,
        10,
        12,
        10,
        8,
        23,
        8,
        9,
        7,
        6,
        7,
        8,
        7,
        6,
        55,
        8,
        23,
        24,
        12,
        11,
        7,
        9,
        11,
        12,
        6,
        7,
        22,
        5,
        7,
        24,
        6,
        11,
        9,
        6,
        7,
        22,
        7,
        11,
        38,
        7,
        9,
        8,
        25,
        11,
        8,
        11,
        9,
        12,
        8,
        12,
        5,
        38,
        5,
        38,
        5,
        11,
        7,
        5,
        6,
        21,
        6,
        10,
        53,
        8,
        7,
        24,
        10,
        27,
        44,
        253,
        253,
        253,
        252,
        252,
        252,
        13,
        12,
        45,
        12,
        45,
        12,
        61,
        12,
        45,
        44,
        173,
    ]
)
LENLEN = bytes([2, 35, 36, 53, 38, 23])
DISTLEN = bytes([2, 20, 53, 230, 247, 151, 248])
LEN_BASE = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
DISKETTE = 0x168000
TRACK = 0x4800
ROM_STARTS = (0x48, 0x4A)


def _table(packed: bytes, n: int) -> tuple[list[int], list[int]]:
    """(codes per length, symbols in code order) of a canonical code."""
    lengths = [b & 15 for b in packed for _ in range((b >> 4) + 1)]
    if len(lengths) != n:
        raise AssertionError("bad DCL table")
    count = [0] * (MAXBITS + 1)
    for length in lengths:
        count[length] += 1
    offs = [0] * (MAXBITS + 1)
    for length in range(1, MAXBITS):
        offs[length + 1] = offs[length] + count[length]
    symbol = [0] * n
    for s, length in enumerate(lengths):
        if length:
            symbol[offs[length]] = s
            offs[length] += 1
    return count, symbol


LIT, LEN, DIST = _table(LITLEN, 256), _table(LENLEN, 16), _table(DISTLEN, 64)


def explode(data: bytes, size: int) -> bytes:
    """PKWARE DCL "implode" data unpacked, up to size bytes (Compaq's streams have no end
    code: they stop when the output is full)."""
    pos, buf, cnt = 0, 0, 0

    def bits(need: int) -> int:
        nonlocal pos, buf, cnt
        while cnt < need:
            if pos >= len(data):
                raise ValueError("the packed data ends early")
            buf |= data[pos] << cnt
            pos, cnt = pos + 1, cnt + 8
        value = buf & ((1 << need) - 1)
        buf, cnt = buf >> need, cnt - need
        return value

    def decode(table: tuple[list[int], list[int]]) -> int:
        count, symbol = table
        code = first = index = 0
        for length in range(1, MAXBITS + 1):
            code |= bits(1) ^ 1  # (the codes are stored inverted)
            if code < first + count[length]:
                return symbol[index + code - first]
            index += count[length]
            first = (first + count[length]) << 1
            code <<= 1
        raise ValueError("a bad code in the packed data")

    coded, dict_bits = bits(8), bits(8)
    if coded > 1 or not 4 <= dict_bits <= 6:
        raise ValueError("not PKWARE DCL implode data")
    out = bytearray()
    while len(out) < size:
        if not bits(1):
            out.append(decode(LIT) if coded else bits(8))
            continue
        sym = decode(LEN)
        length = LEN_BASE[sym] + bits(LEN_EXTRA[sym])
        if length == 519:  # end code
            break
        low = 2 if length == 2 else dict_bits
        dist = (decode(DIST) << low) + bits(low) + 1
        if dist > len(out):
            raise ValueError("the packed data points before its start")
        for _ in range(length):
            out.append(out[-dist])
    return bytes(out[:size])


def diskette(raw: bytes) -> bytes | None:
    """The ROMPaq diskette (1.44 MB) packed in a Softpaq, or None if it is not one."""
    fit = raw.find(b"[FIT]")
    if not raw.startswith(b"MZ") or fit < 0 or fit + 0x25 > len(raw):
        return None
    usize, _, _, data_end, name = struct.unpack_from("<IIIII", raw, fit + 8)
    if usize != DISKETTE or not 0 < name <= len(raw) - 38:  # (sp2165's record ends the file)
        return None
    size, csize, _, offset = struct.unpack_from("<IIHI", raw, name + 24)
    if size != usize or offset + csize != data_end or data_end > len(raw) + 1:
        return None
    try:
        return explode(raw[offset : offset + csize - 1], size)
    except ValueError:
        return None


def tracks(raw: bytes) -> bytes | None:
    """The 1.44 MB diskette of an NTUNDSK update (NEC HX4100, Packard Bell PB Houston and
    Tacoma), or None: one DCL stream per track; a table of their file offsets near the end."""
    for at in range(max(0, len(raw) - 0x1000), len(raw) - 3):
        table = [struct.unpack_from("<I", raw, at)[0]]
        pos = at + 4
        while pos + 4 <= len(raw) and table[-1] < struct.unpack_from("<I", raw, pos)[0] < at:
            table.append(struct.unpack_from("<I", raw, pos)[0])
            pos += 4
        if len(table) <= DISKETTE // TRACK:  # (the last entry is not a track)
            continue
        try:
            image = b"".join(
                explode(raw[start:end], TRACK)
                for start, end in zip(table, table[1 : DISKETTE // TRACK + 1])
            )
        except ValueError:
            continue
        if len(image) == DISKETTE and image[0x1FE:0x200] == b"\x55\xaa":
            return image
    return None


def rom_image(data: bytes) -> bytes | None:
    """A ROMPaq ROM file unpacked (its size from the header), or None if it is not one."""
    if len(data) < 0x50 or data[:2] != b"\0\0":
        return None
    size = struct.unpack_from("<I", data, 0)[0]
    if size not in (0x10000, 0x20000, 0x40000, 0x80000, 0x100000):
        return None
    # (where the header ends differs: 48h, 4Ah; the later files with a short name, TRIGGRC1.093
    # and MONSTE50.D8A, elsewhere: the first start whose data fills the ROM to its reset vector)
    for start in [*ROM_STARTS, *range(0x40, 0x80)]:
        if data[start] > 1 or not 4 <= data[start + 1] <= 6:
            continue
        try:
            image = explode(data[start:], size)
        except ValueError:
            continue
        if len(image) == size and image[-16] in (0xEA, 0xE9):
            return image
    # (a 256 KB ROM can also be one stream per 64 KB, each behind a copy of the header:
    # MONSTE50.D8A, TRIGGRC1.093)
    image = b""
    for start in range(0x20, len(data) - 2):
        if data[start] > 1 or not 4 <= data[start + 1] <= 6:
            continue
        want = min(0x10000, size - len(image))
        try:
            part = explode(data[start:], want)
        except ValueError:
            continue
        if len(part) == want:
            image += part
            if len(image) == size:
                return image if image[-16] in (0xEA, 0xE9) else None
    return None
