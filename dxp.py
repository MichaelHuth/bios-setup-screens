"""Unpack a Disk eXPress (DXP 2.x, Albert J. Shan) self-extracting diskette image (Dell's
BIOS update diskettes of about 2002, OptiPlex GX240), worked out from the self-extractor's
code; the files are data, never run.

Returns the raw diskette image (boot sector first, zero padded to the size the
boot sector's BPB describes), or raises ValueError for images this code does
not understand.

Format, as recovered from the self-extractor: after a 512-byte header the packed area is a flat chain of
records `[u16 size][size bytes]`, one record per track, tiling the area to EOF.
size == 1 -> the track is the single following byte repeated; size >= the track
size -> the track is stored raw; otherwise the record is a dynamic-Huffman
LZ77 stream (two trees, 8 KB window) for that track.
"""

from __future__ import annotations

import struct

COUNT_A, MAXBITS_A = 0x1FE, 0xC
COUNT_B1, CBITS_B1, MARK_B1 = 19, 5, 3
COUNT_B2, CBITS_B2 = 14, 4
MAXBITS_B = 8
WINDOW = 0x2000


class _Bits:
    """MSB-first 16-bit bit buffer refilled a byte at a time (0x1495/0x14DE)."""

    def __init__(self, data: bytes, pos: int) -> None:
        self.d, self.p, self.buf, self.cnt, self.part = data, pos, 0, 0, 0

    def consume(self, n: int) -> None:
        self.buf = (self.buf << n) & 0xFFFF
        si = n
        while self.cnt < si:
            si -= self.cnt
            self.part = (self.part << si) & 0xFFFF
            self.buf |= self.part
            self.part = self.d[self.p] if self.p < len(self.d) else 0
            self.p += 1
            self.cnt = 8
        self.cnt -= si
        self.buf |= (self.part >> self.cnt) & 0xFFFF

    def read(self, n: int) -> int:
        v = self.buf >> (16 - n) if n else 0
        self.consume(n)
        return v


def _get(cell: tuple[str, int], table: list[int], ch1: dict[int, int], ch0: dict[int, int]) -> int:
    kind, idx = cell
    return table[idx] if kind == "tab" else (ch1[idx] if kind == "n1" else ch0[idx])


def _set(
    cell: tuple[str, int],
    val: int,
    table: list[int],
    ch1: dict[int, int],
    ch0: dict[int, int],
) -> None:
    kind, idx = cell
    if kind == "tab":
        table[idx] = val
    elif kind == "n1":
        ch1[idx] = val
    else:
        ch0[idx] = val


def _build(
    lengths: list[int], count: int, maxbits: int
) -> tuple[list[int], dict[int, int], dict[int, int]]:
    """Canonical Huffman tables (0x1298): a direct table of 2**maxbits entries
    plus node arrays for the longer codes. Raises ValueError on a tree that is
    not complete (Kraft sum != 1), which is how bad offsets are rejected."""
    freq = [0] * 17
    for ln in lengths[:count]:
        if ln:
            freq[ln] += 1
    total = sum(f * 2.0**-ln for f, ln in zip(freq, range(17)) if ln and f)
    if abs(total - 1.0) > 1e-9:
        raise ValueError("incomplete Huffman tree")
    A = [0] * 17
    for k in range(2, 17):
        A[k] = (A[k - 1] + freq[k - 1] * (1 << (17 - k))) & 0xFFFF
    sh = 16 - maxbits
    for k in range(1, maxbits + 1):
        A[k] >>= sh
    base = [0] * 17
    for k in range(1, maxbits + 1):
        base[k] = 1 << (maxbits - k)
    for k in range(maxbits + 1, 17):
        base[k] = 1 << (16 - k)
    table = [0] * (1 << maxbits)
    ch1: dict[int, int] = {}
    ch0: dict[int, int] = {}
    node = count
    for sym in range(count):
        ln = lengths[sym]
        if not ln:
            continue
        end = (A[ln] + base[ln]) & 0xFFFF
        if maxbits >= ln:
            while A[ln] < end:
                table[A[ln]] = sym
                A[ln] += 1
        else:
            cell = ("tab", A[ln] >> sh)
            code, bit = A[ln], 1 << (15 - maxbits)
            for _ in range(ln - maxbits):
                if _get(cell, table, ch1, ch0) == 0:
                    ch1[node] = 0
                    ch0[node] = 0
                    _set(cell, node, table, ch1, ch0)
                    node += 1
                nxt = _get(cell, table, ch1, ch0)
                cell = ("n1", nxt) if (code & bit) else ("n0", nxt)
                code = (code << 1) & 0xFFFF
            _set(cell, sym, table, ch1, ch0)
        A[ln] = end
    return table, ch1, ch0


class _Dec:
    def __init__(self, data: bytes, pos: int) -> None:
        self.b = _Bits(data, pos)
        self.lenA: list[int] = []  # (the Huffman tables, built by the block headers)
        self.tabA: list[int] = []
        self.n1A: dict[int, int] = {}
        self.n0A: dict[int, int] = {}
        self.lenB: list[int] = []
        self.tabB: list[int] = []
        self.n1B: dict[int, int] = {}
        self.n0B: dict[int, int] = {}
        self.refresh = 0
        self.cnt, self.ring = -1, 0

    def _treeB(self, count: int, cbits: int, marker: int) -> None:  # 0x14F0
        b = self.b
        n = b.read(cbits)
        lens = [0] * max(count, 32)
        if n == 0:
            root = b.read(cbits)
            self.lenB = lens
            self.tabB, self.n1B, self.n0B = [root] * (1 << MAXBITS_B), {}, {}
            return
        i = 0
        while i < n:
            di = b.buf >> 13
            if di == 7:
                m = 0x1000
                while b.buf & m:
                    m >>= 1
                    di += 1
                    if di > 24:
                        raise ValueError("bad code length")
            b.consume(di - 3 if di >= 7 else 3)
            if i >= len(lens):
                raise ValueError("too many code lengths")
            lens[i] = di
            i += 1
            if i == marker:
                i += b.read(2)
        self.lenB = lens
        self.tabB, self.n1B, self.n0B = _build(lens, count, MAXBITS_B)

    def _symB(self) -> int:
        b = self.b
        si = self.tabB[b.buf >> 8]
        di = 0x80
        while si >= COUNT_B1:
            si = self.n1B[si] if (b.buf & di) else self.n0B[si]
            di >>= 1
        b.consume(self.lenB[si])
        return si

    def _treeA(self) -> None:  # 0x15CC
        b = self.b
        n = b.read(9)
        lens = [0] * COUNT_A
        if n == 0:
            root = b.read(9)
            self.lenA = lens
            self.tabA, self.n1A, self.n0A = [root] * (1 << MAXBITS_A), {}, {}
            return
        i = 0
        while i < n:
            s = self._symB()
            if s > 2:
                if i >= COUNT_A:
                    raise ValueError("tree A overflow")
                lens[i] = s - 2
                i += 1
            else:
                k = 1 if s == 0 else (b.read(4) + 3 if s == 1 else b.read(9) + 0x14)
                for _ in range(k):
                    if i < COUNT_A:
                        lens[i] = 0
                    i += 1
        self.lenA = lens
        self.tabA, self.n1A, self.n0A = _build(lens, COUNT_A, MAXBITS_A)

    def _symA(self) -> int:  # 0x16D3
        if self.refresh == 0:
            self.refresh = self.b.read(16)
            self._treeB(COUNT_B1, CBITS_B1, MARK_B1)
            self._treeA()
            self._treeB(COUNT_B2, CBITS_B2, 0xFFFF)
        self.refresh -= 1
        b = self.b
        si = self.tabA[b.buf >> 4]
        di = 8
        while si >= COUNT_A:
            si = self.n1A[si] if (b.buf & di) else self.n0A[si]
            di >>= 1
        b.consume(self.lenA[si])
        return si

    def _distance(self) -> int:  # 0x1748
        b = self.b
        si = self.tabB[b.buf >> 8]
        di = 0x80
        while si >= COUNT_B2:
            si = self.n1B[si] if (b.buf & di) else self.n0B[si]
            di >>= 1
        b.consume(self.lenB[si])
        if si == 0:
            return 0
        return b.read(si - 1) + (1 << (si - 1))

    def _chunk(self, n: int, buf: bytearray) -> int:  # 0x17A0
        si = 0
        while si < n:
            self.cnt -= 1
            if self.cnt >= 0:
                buf[si] = buf[self.ring]
                self.ring = (self.ring + 1) & (WINDOW - 1)
                si += 1
                continue
            sym = self._symA()
            if sym <= 0xFF:
                buf[si] = sym
                si += 1
                continue
            self.cnt = sym - 0xFD
            self.ring = (si - self._distance() - 1) & (WINDOW - 1)
            self.cnt -= 1
            while self.cnt >= 0:
                buf[si] = buf[self.ring]
                self.ring = (self.ring + 1) & (WINDOW - 1)
                si += 1
                if si == n:  # (the next chunk goes on with the match: its first step counts)
                    break
                self.cnt -= 1
        return si

    def track(self, size: int) -> bytes:  # 0x182C
        self.b.consume(16)
        self.refresh, self.cnt, self.ring = 0, -1, 0
        buf = bytearray(WINDOW)
        out = bytearray()
        left = size
        while left > 0:
            n = min(left, WINDOW)
            self._chunk(n, buf)
            out += buf[:n]
            left -= n
        return bytes(out)


def _records(raw: bytes, start: int, max_size: int) -> list[tuple[int, int]] | None:
    """Walk the [u16 size][data] chain from `start`; None if it does not tile
    the tail of the file exactly with sane sizes."""
    out: list[tuple[int, int]] = []
    p, end = start, len(raw)
    while p + 2 <= end:
        size = int.from_bytes(raw[p : p + 2], "little")
        if size == 0 or size > max_size or len(out) >= 4096:
            return None
        out.append((p, size))
        p += 2 + size
        if p == end:
            return out
    return None


def _bpb(track: bytes) -> tuple[int, int, int] | None:
    """(bytes/sector, total sectors, sectors per track) from a FAT boot
    sector, or None if this is not one."""
    if len(track) < 512 or track[510:512] != b"\x55\xaa":
        return None
    bps, spc, _res, nfats, _nroot, total16, _media, spf = struct.unpack_from("<HBHBHHBH", track, 11)
    spt, heads = struct.unpack_from("<HH", track, 24)
    if bps not in (128, 256, 512, 1024, 2048) or not spc or not nfats or not spf:
        return None
    if not spt or not heads:
        return None
    total = total16 or int.from_bytes(track[32:36], "little")
    if not 1 <= total <= 0x100000:
        return None
    return bps, total, spt


MAX_TRACK = 0x2400  # the largest standard track (18 x 512)


def disk_image(raw: bytes) -> bytes:
    if len(raw) < 0x1000:
        raise ValueError("too small for a DXP image")
    # The header carries no signature, so find the record chain by its shape:
    # it must tile the tail of the file exactly, and its first record must
    # decode to a FAT boot sector.
    for start in range(0x200, len(raw) - 2):
        recs = _records(raw, start, MAX_TRACK)
        if not recs:
            continue
        p, size = recs[0]
        try:
            if size == 1:
                continue
            probe = (
                raw[p + 2 : p + 2 + size]
                if size >= MAX_TRACK
                else _Dec(raw[p + 2 : p + 2 + size] + b"\x00\x00", 0).track(0x4000)
            )
        except Exception:
            continue
        bpb = _bpb(probe)
        if not bpb:
            continue
        bps, total, spt = bpb
        track_size = bps * spt
        img = bytearray()
        for rec in recs:
            if len(img) >= total * bps:
                break
            img += _decode(raw, rec, track_size, total * bps - len(img))
        if len(img) < total * bps:
            img += bytes(total * bps - len(img))  # tracks not stored are empty
        return bytes(img)
    raise ValueError("no DXP record chain found")


def _decode(raw: bytes, rec: tuple[int, int], track_size: int, room: int) -> bytes:
    p, size = rec
    if size == 1:  # fill the track with one byte
        return bytes([raw[p + 2]]) * min(track_size, room)
    if size >= track_size:  # stored raw (0x1151 jge)
        return raw[p + 2 : p + 2 + track_size][:room]
    return _Dec(raw[p + 2 : p + 2 + size] + b"\x00\x00", 0).track(track_size)[:room]
