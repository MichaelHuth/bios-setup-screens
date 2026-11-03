"""
Capture AMI BIOS setup screens (classic AMIBIOS setup, about 1988-1994) by running the BIOS's
own setup code in the emulator (bios_emu): start at the setup entry, let it draw the main menu,
and feed keys (Down/Enter, F2 for other color schemes) to open the sub-pages.

The setup entry is found by its first instructions (save SS:SP to 0040:0067/0069, the same in
all versions seen): xor ax,ax / mov ds,ax / mov [0469],ss / mov [0467],sp.
"""

from __future__ import annotations

import re

from bios_emu import KEYS, BiosEmulator
from textscreen import Screen

ENTRY = re.compile(
    rb"\xfc\x33\xc0\x8e\xd8\x8c\x16\x69\x04\x89\x26\x67\x04|"
    rb"\x33\xc0\x8e\xd8\x8c\x16\x69\x04\x89\x26\x67\x04"
)
# Older AMI (about 1988-1990, menu "RUN CMOS SETUP / RUN XCMOS SETUP / RUN DIAGNOSTICS"):
# call / cli / push bp / mov cx,N / sub sp,cx / mov bp,sp / mov sp,FD00h
ENTRY_OLD = re.compile(rb"\xe8..\xfa\x55\xb9.\x00\x2b\xe1\x8b\xec\xbc\x00\xfd", re.S)
# the same without the call and CLI before it (04/09/90 core, menu "RUN DIAGNOSTICS / RUN CMOS
# SETUP / EXIT FOR BOOT", Laser 386SX)
ENTRY_OLD2 = re.compile(rb"\x55\xb9.\x00\x2b\xe1\x8b\xec\xbc\x00\xfd", re.S)
F2 = 0x3C00


def _bcd(n: int) -> int:
    return (n // 10) << 4 | n % 10


def default_cmos() -> bytes:
    """A plausible CMOS: running clock (12:00:00, 01/01/1994), one 1.44 MB floppy, VGA,
    640 KB base + 3 MB extended memory, valid checksum."""
    c = bytearray(128)
    c[0x00], c[0x02], c[0x04] = 0, 0, _bcd(12)
    c[0x06], c[0x07], c[0x08], c[0x09] = 7, _bcd(1), _bcd(1), _bcd(94)  # Saturday 01/01/94
    c[0x0A], c[0x0B], c[0x0D] = 0x26, 0x02, 0x80
    c[0x10] = 0x40  # drive A: 1.44 MB
    c[0x14] = 0x4D  # one floppy; AMI: bit 2 keyboard installed, bit 3 VGA/EGA display
    c[0x15], c[0x16] = 0x80, 0x02  # 640 KB
    c[0x17], c[0x18] = 0x00, 0x0C  # 3072 KB extended
    c[0x30], c[0x31] = 0x00, 0x0C
    c[0x32] = 0x19
    checksum = sum(c[0x10:0x2E])
    c[0x2E], c[0x2F] = checksum >> 8, checksum & 0xFF
    return bytes(c)


def find_entry(rom: bytes) -> int:
    m = ENTRY.search(rom) or ENTRY_OLD.search(rom) or ENTRY_OLD2.search(rom)
    if not m:
        raise ValueError(
            "no AMI setup entry found (supported: classic AMIBIOS setup, about 1988-1994)"
        )
    return (m.start() - len(rom)) & 0xFFFF  # offset in segment F000


def capture(rom: bytes, keys: list[int]) -> tuple[Screen, str]:
    emu = BiosEmulator(
        rom[-0x10000:] if len(rom) >= 0x10000 else rom, keys=keys, cmos=default_cmos()
    )
    screen = emu.run(0xF000, find_entry(rom))
    return screen, emu.stopped_reason


def menu_items(screen: Screen) -> list[str]:
    """Main menu entries: the centered lines between the title block and the help area."""
    lines = screen.text().splitlines()
    items = []
    for line in lines[4:18]:
        text = line.strip(" ║│")
        if text and text == text.upper() and any(ch.isalpha() for ch in text):
            items.append(text)
    return items


LOAD_DEFAULTS = {"bios": 0x4000, "power-on": 0x4100}  # F6 / F7 on pages that offer them
YES = 0x1559


def setup_screens(
    rom: bytes, pages: list[int] | None = None, color: int = 0, defaults: str = "bios"
) -> tuple[list[tuple[str, Screen, str]], list[str]]:
    """Returns [(title, screen, stop reason)]: the main menu, then the chosen sub-pages
    (by menu position, 1-based; default: every entry containing SETUP). On pages whose key
    bar offers F6/F7, the BIOS Setup or Power-On defaults are loaded first (defaults="cmos"
    shows the values of the emulated, mostly empty CMOS instead)."""
    colors = [F2] * max(0, color)
    main, reason = capture(rom, colors)
    out = [("MAIN MENU", main, reason)]
    items = menu_items(main)
    if pages is None:
        pages = [i + 1 for i, t in enumerate(items) if "SETUP" in t]
    for p in pages:
        if 1 <= p <= len(items):
            keys = colors + [KEYS["down"]] * (p - 1) + [KEYS["enter"]]
            screen, reason = capture(rom, keys)
            for _ in range(3):  # confirm prompts like the WARNING INFORMATION screen
                text = screen.text().lower()
                if "any other key to continue" not in text and "press any key" not in text:
                    break
                keys = keys + [KEYS["enter"]]
                screen, reason = capture(rom, keys)
            key = LOAD_DEFAULTS.get(defaults)
            label = {"bios": "F6:", "power-on": "F7:"}.get(defaults, "")
            if key and label and label in screen.text():
                loaded, r2 = capture(rom, keys + [key, YES, KEYS["enter"]])
                if r2 == "waiting for a key":
                    screen, reason = loaded, r2
            out.append((items[p - 1], screen, reason))
    return out, items
