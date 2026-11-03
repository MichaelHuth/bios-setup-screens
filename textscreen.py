"""
80x25 VGA text screen: a cell buffer (CP437 character + attribute byte) rendered to PNG with
the original 9x16 VGA font, as a PC in text mode shows it.

The fonts (fonts/vga8x16.bin, vga8x14.bin, vga8x8.bin: 256 glyphs each) were extracted from a
VGA BIOS.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from PIL import Image

FONTS = {h: (Path(__file__).parent / "fonts" / f"vga8x{h}.bin").read_bytes() for h in (8, 14, 16)}
FONT = FONTS[16]
# Standard VGA text-mode palette
PALETTE = [
    (0, 0, 0),
    (0, 0, 170),
    (0, 170, 0),
    (0, 170, 170),
    (170, 0, 0),
    (170, 0, 170),
    (170, 85, 0),
    (170, 170, 170),
    (85, 85, 85),
    (85, 85, 255),
    (85, 255, 85),
    (85, 255, 255),
    (255, 85, 85),
    (255, 85, 255),
    (255, 255, 85),
    (255, 255, 255),
]
COLOR_NAMES = [
    "black",
    "blue",
    "green",
    "cyan",
    "red",
    "magenta",
    "brown",
    "lightgray",
    "darkgray",
    "lightblue",
    "lightgreen",
    "lightcyan",
    "lightred",
    "lightmagenta",
    "yellow",
    "white",
]


# CP437 shows glyphs for 00h-1Fh and 7Fh, which Python's codec decodes as control characters
LOW_GLYPHS = " ☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼"
TO_CP437 = {ch: i for i, ch in enumerate(LOW_GLYPHS) if i} | {"⌂": 0x7F}


def cp437_to_unicode(data: bytes) -> str:
    return "".join(
        LOW_GLYPHS[b] if b < 0x20 else "⌂" if b == 0x7F else bytes([b]).decode("cp437")
        for b in data
    )


def unicode_to_cp437(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        if ch in TO_CP437:
            out.append(TO_CP437[ch])
        else:
            try:
                out += ch.encode("cp437")
            except UnicodeEncodeError:
                out.append(ord("?"))
    return bytes(out)


class Screen:
    def __init__(self, cols: int = 80, rows: int = 25, attr: int = 0x07):
        self.cols, self.rows = cols, rows
        # what a program may have changed: its own font (4096 bytes), palette (16 RGB colors)
        # and blinking (off: attribute bit 7 selects a bright background)
        self.font: bytes = FONT
        self.palette: Sequence[tuple[int, ...]] = PALETTE
        self.blink = True
        self.char_height = 16  # 14 in 350-line modes (EGA-style), 8 in 200-line modes
        self.chars = [[0x20] * cols for _ in range(rows)]
        self.image: Any = None  # a graphics screen's pixels (the text is read from them)
        self.image_factory: Callable[[], Any] | None = None  # or what makes them when needed
        self.attrs = [[attr] * cols for _ in range(rows)]

    def put(self, col: int, row: int, ch: int, attr: int) -> None:
        if 0 <= col < self.cols and 0 <= row < self.rows:
            self.chars[row][col] = ch & 0xFF
            self.attrs[row][col] = attr & 0xFF

    def write(self, col: int, row: int, text: bytes, attr: int) -> None:
        for i, ch in enumerate(text):
            self.put(col + i, row, ch, attr)

    def fill(self, x1: int, y1: int, x2: int, y2: int, attr: int, ch: int = 0x20) -> None:
        for row in range(max(0, y1), min(self.rows - 1, y2) + 1):
            for col in range(max(0, x1), min(self.cols - 1, x2) + 1):
                self.put(col, row, ch, attr)

    def text(self) -> str:
        """The screen as Unicode text (CP437 glyphs, including 01h-1Fh), trailing spaces removed."""
        return "\n".join(cp437_to_unicode(bytes(line)).rstrip() for line in self.chars).rstrip("\n")

    def render(self, path: Path, scale: int = 2) -> Path:
        if self.image is None and self.image_factory is not None:
            self.image = self.image_factory()
        if self.image is not None:  # a graphics screen: its own pixels
            img = self.image
            if scale > 1:
                img = img.resize((img.width * scale, img.height * scale), Image.Resampling.NEAREST)
            img.save(path)
            return path
        h = self.char_height
        img = Image.new("RGB", (self.cols * 9, self.rows * h))
        px = img.load()
        assert px is not None
        for row in range(self.rows):
            for col in range(self.cols):
                ch, attr = self.chars[row][col], self.attrs[row][col]
                fg = self.palette[attr & 0x0F]
                bg = self.palette[(attr >> 4) & (0x07 if self.blink else 0x0F)]  # bit 7 = blink
                glyph = self.font[ch * h : ch * h + h]
                x0, y0 = col * 9, row * h
                for y in range(h):
                    bits = glyph[y]
                    for x in range(8):
                        px[x0 + x, y0 + y] = fg if bits & (0x80 >> x) else bg
                    # VGA repeats column 8 into column 9 for the line-drawing characters
                    px[x0 + 8, y0 + y] = fg if (0xC0 <= ch <= 0xDF and bits & 1) else bg
        if scale > 1:
            img = img.resize((img.width * scale, img.height * scale), Image.Resampling.NEAREST)
        img.save(path)
        return path


def color_attr(fg: str | int = "lightgray", bg: str | int = "black") -> int:
    f = fg if isinstance(fg, int) else COLOR_NAMES.index(fg)
    b = bg if isinstance(bg, int) else COLOR_NAMES.index(bg)
    return (b & 7) << 4 | (f & 15)
