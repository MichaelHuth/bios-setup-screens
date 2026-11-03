"""
EFI / Tiano decompression (the "EFI standard compression" of UEFI firmware volumes: compression
sections of type 01h and the Tiano GUID-defined section), after the algorithm of EDK2's
BaseUefiDecompressLib: LZ77 with Huffman-coded literals/lengths and positions, in blocks.

The stream starts with the compressed and the original size (32 bits each). Version 1 (EFI)
codes positions with 4 bits for their table, version 2 (Tiano) with 5.
"""

from __future__ import annotations

import struct

BITBUFSIZ = 32
MAXMATCH = 256
THRESHOLD = 3
CODE_BIT = 16
NC = 0xFF + MAXMATCH + 2 - THRESHOLD  # 510 literals and lengths
CBIT = 9
MAXPBIT = 5
TBIT = 5
MAXNP = (1 << MAXPBIT) - 1
NT = CODE_BIT + 3
NPT = max(NT, MAXNP)


class _Decoder:
    def __init__(self, src: bytes, pbit: int):
        self.src, self.pos, self.pbit = src, 8, pbit
        self.bitbuf = self.subbitbuf = self.bitcount = 0
        self.left = [0] * (2 * NC - 1)
        self.right = [0] * (2 * NC - 1)
        self.c_len = [0] * NC
        self.pt_len = [0] * NPT
        self.c_table = [0] * 4096
        self.pt_table = [0] * 256
        self.block_size = 0
        self._fill(BITBUFSIZ)

    def _fill(self, n: int) -> None:
        self.bitbuf = (self.bitbuf << n) & 0xFFFFFFFF
        while n > self.bitcount:
            n -= self.bitcount
            self.bitbuf |= (self.subbitbuf << n) & 0xFFFFFFFF
            if self.pos < len(self.src):
                self.subbitbuf = self.src[self.pos]
                self.pos += 1
            else:
                self.subbitbuf = 0
            self.bitcount = 8
        self.bitcount -= n
        self.bitbuf |= self.subbitbuf >> self.bitcount

    def _bits(self, n: int) -> int:
        out = self.bitbuf >> (BITBUFSIZ - n)
        self._fill(n)
        return out

    def _make_table(self, nchar: int, bitlen: list[int], tablebits: int, table: list[int]) -> None:
        count = [0] * 17
        for i in range(nchar):
            count[bitlen[i]] += 1
        start = [0] * 18
        for i in range(1, 17):
            start[i + 1] = (start[i] + (count[i] << (16 - i))) & 0xFFFF
        if start[17] != 0:
            raise ValueError("bad Huffman table")
        jutbits = 16 - tablebits
        weight = [0] * 17
        for i in range(1, tablebits + 1):
            start[i] >>= jutbits
            weight[i] = 1 << (tablebits - i)
        for i in range(tablebits + 1, 17):
            weight[i] = 1 << (16 - i)
        index = start[tablebits + 1] >> jutbits
        if index != 0:
            for i in range(index, 1 << tablebits):
                table[i] = 0
        avail, mask = nchar, 1 << (15 - tablebits)
        left, right = self.left, self.right
        for char in range(nchar):
            length = bitlen[char]
            if length == 0:
                continue
            nextcode = start[length] + weight[length]
            if length <= tablebits:
                for i in range(start[length], nextcode):
                    table[i] = char
            else:
                index3 = start[length]
                # the "pointer" walks table -> left/right as (array, index)
                arr, idx = table, index3 >> jutbits
                for _ in range(length - tablebits):
                    if arr[idx] == 0:
                        right[avail] = left[avail] = 0
                        arr[idx] = avail
                        avail += 1
                    node = arr[idx]
                    arr, idx = (right, node) if index3 & mask else (left, node)
                    index3 <<= 1
                arr[idx] = char
            start[length] = nextcode

    def _read_pt_len(self, nn: int, nbit: int, special: int) -> None:
        number = self._bits(nbit)
        if number == 0:
            char = self._bits(nbit)
            for i in range(256):
                self.pt_table[i] = char
            for i in range(nn):
                self.pt_len[i] = 0
            return
        if number > nn:
            raise ValueError("bad position table")
        index = 0
        while index < number:
            char = self.bitbuf >> (BITBUFSIZ - 3)
            if char == 7:
                mask = 1 << (BITBUFSIZ - 1 - 3)
                while mask & self.bitbuf:
                    mask >>= 1
                    char += 1
            self._fill(3 if char < 7 else char - 3)
            self.pt_len[index] = char
            index += 1
            if index == special:
                for _ in range(self._bits(2)):
                    self.pt_len[index] = 0
                    index += 1
        while index < nn:
            self.pt_len[index] = 0
            index += 1
        self._make_table(nn, self.pt_len, 8, self.pt_table)

    def _read_c_len(self) -> None:
        number = self._bits(CBIT)
        if number == 0:
            char = self._bits(CBIT)
            for i in range(NC):
                self.c_len[i] = 0
            for i in range(4096):
                self.c_table[i] = char
            return
        index = 0
        while index < number:
            char = self.pt_table[self.bitbuf >> (BITBUFSIZ - 8)]
            if char >= NT:
                mask = 1 << (BITBUFSIZ - 1 - 8)
                while char >= NT:
                    char = self.right[char] if mask & self.bitbuf else self.left[char]
                    mask >>= 1
            self._fill(self.pt_len[char])
            if char <= 2:
                if char == 0:
                    char = 1
                elif char == 1:
                    char = self._bits(4) + 3
                else:
                    char = self._bits(CBIT) + 20
                for _ in range(char):
                    if index < NC:
                        self.c_len[index] = 0
                    index += 1
            else:
                self.c_len[index] = char - 2
                index += 1
        while index < NC:
            self.c_len[index] = 0
            index += 1
        self._make_table(NC, self.c_len, 12, self.c_table)

    def _decode_c(self) -> int:
        if self.block_size == 0:
            self.block_size = self._bits(16)
            self._read_pt_len(NT, TBIT, 3)
            self._read_c_len()
            self._read_pt_len(MAXNP, self.pbit, -1)
        self.block_size -= 1
        index = self.c_table[self.bitbuf >> (BITBUFSIZ - 12)]
        if index >= NC:
            mask = 1 << (BITBUFSIZ - 1 - 12)
            while index >= NC:
                index = self.right[index] if mask & self.bitbuf else self.left[index]
                mask >>= 1
        self._fill(self.c_len[index])
        return index

    def _decode_p(self) -> int:
        val = self.pt_table[self.bitbuf >> (BITBUFSIZ - 8)]
        if val >= MAXNP:
            mask = 1 << (BITBUFSIZ - 1 - 8)
            while val >= MAXNP:
                val = self.right[val] if mask & self.bitbuf else self.left[val]
                mask >>= 1
        self._fill(self.pt_len[val])
        if val > 1:
            val = (1 << (val - 1)) + self._bits(val - 1)
        return val

    def run(self, size: int) -> bytes:
        out = bytearray(size)
        n = 0
        while n < size:
            c = self._decode_c()
            if c < 256:
                out[n] = c
                n += 1
            else:
                length = c - (0x100 - THRESHOLD)
                src = n - self._decode_p() - 1
                if src < 0:
                    raise ValueError("bad back reference")
                for _ in range(min(length, size - n)):
                    out[n] = out[src]
                    n += 1
                    src += 1
        return bytes(out)


def decompress(data: bytes, version: int = 0) -> bytes:
    """The data of an EFI (version 1) or Tiano (2) compressed stream; version 0 tries both, EFI
    first. Raises ValueError for data that is neither."""
    if len(data) < 8:
        raise ValueError("too short")
    comp_size, orig_size = struct.unpack_from("<II", data)
    if comp_size + 8 > len(data) or orig_size > 64 * 1024 * 1024:
        raise ValueError("bad header")
    errors = []
    for pbit in ((4, 5) if version == 0 else (4 if version == 1 else 5,)):
        try:
            return _Decoder(data[: comp_size + 8], pbit).run(orig_size)
        except (ValueError, IndexError) as e:
            errors.append(str(e))
    raise ValueError("; ".join(errors))
