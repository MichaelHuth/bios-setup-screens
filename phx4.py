"""PhoenixBIOS 4.0 module compression "type 4" (Apricot/Mitsubishi HN440, Intel boards of about
1999): LZ77 over a 4 KB window whose symbols come from an adaptive Huffman tree.

- Symbols: 00h-FFh literal bytes; 102h end of stream; 103h and above a match of (symbol - 100h)
  bytes. Two escapes bring in symbols the tree does not hold yet: 100h, then 8 raw bits (a new
  literal); 101h, then 6 raw bits v (the new symbol 102h + v).
- The tree starts with three leaves (100h, 101h, 102h) and grows: a new symbol splits the last
  node into that node's old content and a leaf for the new symbol. Nodes are kept in order of
  falling weight; after each symbol its leaf and all nodes above it gain one, and a node that
  outweighs the one before it changes places with the first node of lower weight (the escape
  leaves gain nothing). An inner node names its child for bit 0; the child for bit 1 is the
  node just before that one.
- A match's distance: 8 raw bits select the upper bits of the distance and how many raw bits
  follow (DISTANCE_CODES); the low 6 bits of the selector, with those bits shifted in, give the
  rest. The copy starts distance + 1 bytes behind the write position, which starts at FC4h in
  a window of zeros.
- Bits are read most significant first.

decode(packed, size) -> bytes; size 0 runs to the end symbol.
"""

from __future__ import annotations

WINDOW = 0x1000
START = 0xFC4
END_SYMBOL = 0x102
NEW_LITERAL, NEW_LENGTH = 0x100, 0x101

# the 8-bit distance selector, in runs: (number of selectors, upper bits of their distances or
# the first of a range that rises every `step` selectors, extra raw bits)
_RUNS = [
    (4, 0x3E, 2, 5),
    (4, 0x3C, 2, 5),
    (8, 0x03, 8, 3),
    (16, 0x01, 16, 2),
    (32, 0x0C, 2, 5),
    (64, 0x00, 64, 0),
    (16, 0x08, 4, 4),
    (16, 0x02, 16, 2),
    (32, 0x04, 8, 3),
    (64, 0x1C, 2, 5),
]


def _distance_codes() -> list[tuple[int, int]]:
    codes: list[tuple[int, int]] = []
    for count, first, step, extra in _RUNS:
        codes += [(first + k // step, extra) for k in range(count)]
    return codes


DISTANCE_CODES = _distance_codes()  # selector -> (upper distance bits, extra raw bits)


class _Bits:
    def __init__(self, data: bytes):
        self.data, self.at, self.byte, self.mask = data, 0, 0, 0

    def bit(self) -> int:
        self.mask >>= 1
        if not self.mask:
            self.byte, self.mask = self.data[self.at], 0x80
            self.at += 1
        return 1 if self.byte & self.mask else 0

    def bits(self, n: int, value: int = 0) -> int:
        for _ in range(n):
            value = (value << 1 | self.bit()) & 0xFFFF
        return value


class _Tree:
    """The adaptive tree as parallel lists by node (0 the root): for an inner node `item` is
    its bit-0 child, for a leaf the symbol."""

    def __init__(self) -> None:
        self.parent = [-1, 0, 0, 1, 1]
        self.item = [2, 4, NEW_LITERAL, NEW_LENGTH, END_SYMBOL]
        self.weight = [3, 2, 1, 1, 1]
        self.inner = [True, True, False, False, False]

    def symbol_leaf(self, bits: _Bits) -> int:
        node = 0
        while True:
            node = self.item[node] - bits.bit()
            if not self.inner[node]:
                return node

    def add(self, symbol: int) -> int:
        """Split the last node: its content moves one place on, the new symbol's leaf after
        it (weight 0). Returns the new leaf."""
        last = len(self.item) - 1
        self.parent += [last, last]
        self.item += [self.item[last], symbol]
        self.weight += [self.weight[last], 0]
        self.inner += [self.inner[last], False]
        self.item[last], self.inner[last] = last + 2, True
        return last + 2

    def _adopt(self, node: int, parent: int) -> None:
        if self.inner[node]:
            child = self.item[node]
            self.parent[child] = self.parent[child - 1] = parent

    def update(self, node: int) -> None:
        while True:
            self.weight[node] += 1
            if node == 0:
                return
            w = self.weight[node]
            if w <= self.weight[node - 1]:
                node = self.parent[node]
                continue
            other = node - 1
            while other > 0 and w > self.weight[other - 1]:
                other -= 1
            self._adopt(node, other)
            self._adopt(other, node)
            self.item[node], self.item[other] = self.item[other], self.item[node]
            self.weight[node], self.weight[other] = self.weight[other], self.weight[node]
            self.inner[node], self.inner[other] = self.inner[other], self.inner[node]
            node = self.parent[other]


def decode(packed: bytes, size: int = 0) -> bytes:
    """Expand one type-4 stream."""
    bits, tree = _Bits(packed), _Tree()
    window, at = bytearray(WINDOW), START
    out = bytearray()
    while not size or len(out) < size:
        leaf = tree.symbol_leaf(bits)
        symbol = tree.item[leaf]
        if symbol in (NEW_LITERAL, NEW_LENGTH):
            if symbol == NEW_LITERAL:
                symbol = bits.bits(8)
            else:
                symbol = END_SYMBOL + bits.bits(6)
            leaf = tree.add(symbol)
        tree.update(leaf)
        if symbol < 0x100:
            out.append(symbol)
            window[at] = symbol
            at = (at + 1) & (WINDOW - 1)
            continue
        if symbol == END_SYMBOL:
            break
        selector = bits.bits(8)
        upper, extra = DISTANCE_CODES[selector]
        low = bits.bits(extra, selector) & 0x3F
        source = at - (upper << 6 | low) - 1
        for k in range(symbol - 0x100):
            c = window[(source + k) & (WINDOW - 1)]
            out.append(c)
            window[at] = c
            at = (at + 1) & (WINDOW - 1)
    return bytes(out[:size]) if size else bytes(out)
