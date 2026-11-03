"""
Sydex SXD self-extracting diskette images (IBM's BIOS updates of the 1990s, e.g. PC 365
lujt43a.exe: a DOS stub, an OS/2 program "extract.exe", then the image). Read here, never run.

Layout (worked out on lujt43a.exe; the OS/2 Museum's "Cracking DXP and SXD" names the
compression):
- "SXD\\0", then at +5 sectors per track, +6 heads, +7 cylinders, +8 cylinders stored (the
  unused ones at the end are left out), +13h the length of a text (a notice shown before
  extracting) that follows the 21h-byte header;
- then one record per track (cylinder by cylinder, heads inside): CRC-16 (ARC, of the
  unpacked track), a signed 16-bit length n, n bytes (n >= 0) or -n bytes (n < 0) of data;
- n >= 0: LZHUF (Okumura's LZHUF.C, LHA's lh1) with the ring preset to zeros, not spaces;
- n < 0: CopyQM's run-length code: signed 16-bit counts, k > 0 copies k bytes, k < 0 repeats
  the next byte -k times.

Fujitsu-Siemens' (Siemens Nixdorf) "PC QS Service" diskettes use the same LZHUF: a header with
"Siemens Nixdorf (PC QS Service)" and the diskette's descriptions (space-filled text), then the
unpacked size (32 bit) and one LZHUF stream of the whole diskette (Xpert 6xxx, Celsius 620: in
the overlay of an LZEXE-packed writer program).
"""

from __future__ import annotations

import struct

N, F, THRESHOLD = 4096, 60, 2
N_CHAR = 256 - THRESHOLD + F
T = N_CHAR * 2 - 1
R = T - 1
MAX_FREQ = 0x8000
D_CODE = bytes(
    [0] * 32
    + [1] * 16
    + [2] * 16
    + [3] * 16
    + [c for c in range(4, 12) for _ in range(8)]
    + [c for c in range(12, 24) for _ in range(4)]
    + [c for c in range(24, 48) for _ in range(2)]
    + list(range(48, 64))
)
D_LEN = bytes([3] * 32 + [4] * 48 + [5] * 64 + [6] * 48 + [7] * 48 + [8] * 16)


def lzhuf(data: bytes, out_size: int, fill: int = 0) -> bytes:
    """Okumura's LZHUF: LZSS with a 4 KB ring and adaptive Huffman codes."""
    freq = [0] * (T + 1)
    prnt = [0] * (T + N_CHAR)
    son = [0] * T
    for i in range(N_CHAR):
        freq[i], son[i], prnt[i + T] = 1, i + T, i
    i, j = 0, N_CHAR
    while j <= R:
        freq[j] = freq[i] + freq[i + 1]
        son[j] = i
        prnt[i] = prnt[i + 1] = j
        i, j = i + 2, j + 1
    freq[T], prnt[R] = 0xFFFF, 0
    pos, bitbuf, bitcount = 0, 0, 0

    def getbit() -> int:
        nonlocal pos, bitbuf, bitcount
        if bitcount == 0:
            bitbuf = data[pos] if pos < len(data) else 0
            pos += 1
            bitcount = 8
        bitcount -= 1
        return (bitbuf >> bitcount) & 1

    def reconst() -> None:
        j = 0
        for i in range(T):
            if son[i] >= T:
                freq[j] = (freq[i] + 1) // 2
                son[j] = son[i]
                j += 1
        i, j = 0, N_CHAR
        while j < T:
            f = freq[i] + freq[i + 1]
            k = j - 1
            while f < freq[k]:
                k -= 1
            k += 1
            freq[k + 1 : j + 1] = freq[k:j]
            freq[k] = f
            son[k + 1 : j + 1] = son[k:j]
            son[k] = i
            i, j = i + 2, j + 1
        for i in range(T):
            k = son[i]
            if k >= T:
                prnt[k] = i
            else:
                prnt[k] = prnt[k + 1] = i

    def update(c: int) -> None:
        if freq[R] == MAX_FREQ:
            reconst()
        c = prnt[c + T]
        while True:
            freq[c] += 1
            k = freq[c]
            l = c + 1
            if k > freq[l]:
                l += 1
                while k > freq[l]:
                    l += 1
                l -= 1
                freq[c], freq[l] = freq[l], k
                i = son[c]
                prnt[i] = l
                if i < T:
                    prnt[i + 1] = l
                j = son[l]
                son[l] = i
                prnt[j] = c
                if j < T:
                    prnt[j + 1] = c
                son[c] = j
                c = l
            c = prnt[c]
            if c == 0:
                break

    ring = bytearray([fill]) * N
    r = N - F
    out = bytearray()
    while len(out) < out_size:
        if pos > len(data) + 4:
            raise ValueError("LZHUF data ends early")
        c = son[R]
        while c < T:
            c = son[c + getbit()]
        c -= T
        update(c)
        if c < 256:
            out.append(c)
            ring[r] = c
            r = (r + 1) & (N - 1)
            continue
        i = 0
        for _ in range(8):
            i = i << 1 | getbit()
        hi = D_CODE[i] << 6
        for _ in range(D_LEN[i] - 2):
            i = (i << 1) + getbit()
        p = (r - (hi | (i & 0x3F)) - 1) & (N - 1)
        for k in range(c - 255 + THRESHOLD):
            ch = ring[(p + k) & (N - 1)]
            out.append(ch)
            ring[r] = ch
            r = (r + 1) & (N - 1)
    return bytes(out[:out_size])


def _rle(src: bytes) -> bytes:
    out, i = bytearray(), 0
    while i + 2 <= len(src):
        k = struct.unpack_from("<h", src, i)[0]
        i += 2
        if k > 0:
            out += src[i : i + k]
            i += k
        elif k < 0:
            out += src[i : i + 1] * -k
            i += 1
    return bytes(out)


def _crc(data: bytes) -> int:
    c = 0
    for x in data:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def disk_image(raw: bytes) -> bytes | None:
    """The diskette image of an SXD self-extracting program, or None if it is none (or
    damaged)."""
    b = raw.find(b"SXD\x00")
    if b < 0 or b + 0x21 > len(raw):
        return None
    spt, heads, cyls, stored = raw[b + 5], raw[b + 6], raw[b + 7], raw[b + 8]
    if not (8 <= spt <= 40 and heads in (1, 2) and 40 <= cyls <= 84 and 0 < stored <= cyls):
        return None
    track = spt * 512
    p, out = b + 0x21 + struct.unpack_from("<H", raw, b + 0x13)[0], bytearray()
    for _ in range(stored * heads):
        if p + 4 > len(raw):  # (trailing unused cylinders may be left out)
            break
        crc, n = struct.unpack_from("<Hh", raw, p)
        try:
            data = _rle(raw[p + 4 : p + 4 - n]) if n < 0 else lzhuf(raw[p + 4 : p + 4 + n], track)
        except (ValueError, IndexError):
            return None
        if len(data) != track or _crc(data) != crc:
            return None
        out += data
        p += 4 + abs(n)
    return bytes(out) + bytes(cyls * heads * track - len(out)) if out else None


QS_MARK = b"(PC QS Service)"
FLOPPY_SIZES = (368640, 737280, 1228800, 1474560, 1720320, 2949120)


def qs_image(raw: bytes) -> bytes | None:
    """The diskette image of a Fujitsu-Siemens "PC QS Service" update, or None."""
    m = raw.find(QS_MARK)
    if m < 0:
        return None
    for p in range(m, min(len(raw) - 8, m + 0x1000)):
        size = struct.unpack_from("<I", raw, p)[0]
        if size not in FLOPPY_SIZES:
            continue
        try:
            boot = lzhuf(raw[p + 4 : p + 4 + 0x800], 512)
        except (ValueError, IndexError):
            continue
        if boot[510:512] == b"\x55\xaa" and boot[:1] in (b"\xeb", b"\xe9"):
            try:
                return lzhuf(raw[p + 4 :], size)
            except (ValueError, IndexError):
                return None
    return None
