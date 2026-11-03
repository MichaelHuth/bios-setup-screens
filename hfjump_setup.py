"""
Start the AMI Simple/Hi-Flex setup directly, without running POST:
the fallback for boards whose emulated POST never gets to setup (memory-block chain walk, DRAM
sizing, time limits).

- The AMI modules need no relocation fixups, so they are placed in RAM straight from the file:
  each at its header's real_cs:real_off, the Setup Client (module 04) at 6000:0000 as POST does,
  the setup database (module 52, real_cs 0) at 1B000.
- The Setup Server calls the client through `mov al,0 / lcall cs:[ptr]`; that pointer (in the
  RunTime module) gets the client's entry, the RunTime's "$SUP" service table is copied to
  5000:0166, and the interrupt vectors are those the RunTime installs itself.
- The keyboard plumbing POST leaves running (8042 command byte, IRQ 1 unmasked, the BIOS key
  ring, IF) is set, then the client is entered with AL=0 and DS=ES=5000.
Measured: 10 of 12 working boards reach setup with the same pages; values POST measures (memory
sizes, drives, chipset registers) are missing. On some boards a second module builds the item
list, and their item names come out garbled: those pages are dropped.
"""

from __future__ import annotations

import re
import struct
from typing import Any

from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_EFLAGS

import ami
import ami_setup
import bios_emu
from award_emu_setup import cursor
from textscreen import Screen

# keys as 8042 scan codes (make and break), as the bot's own setups press them
K_DOWN = [0xE0, 0x50, 0xE0, 0xD0]
K_UP = [0xE0, 0x48, 0xE0, 0xC8]
K_ENTER = [0x1C, 0x9C]
K_Y = [0x15, 0x95]
MAX_ENTRIES = 24
DEFAULTS = ("LOAD OPTIMAL SETTINGS", "AUTO CONFIGURATION WITH OPTIMAL")
ACTIONS = (
    "LOAD",
    "SAVE",
    "EXIT",
    "PASSWORD",
    "AUTO-DETECT",
    "DETECT",
    "CHANGE",
    "AUTO CONFIGURATION",
)
SEG4 = 0x6000  # the paragraph the Setup Client runs from (POST uses the same one)
DB_SEG = 0x1B00  # where POST loads module 52, the setup database
# control characters drawn as CP437 symbols: a page with many of them shows an item list read
# from a table that only POST builds (garbled names)
GLYPHS = set("☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨∟↔▲▼⌂")
MAX_GLYPHS = 8  # (the key help of every page has 2-4 arrows)
# mov si,<table> ; mov cx,20h ; movsw cs:[si] -> es:[di] ; inc di ; inc di ; loop - the RunTime
# routine that puts its own handler offsets into the interrupt vector table
IVT_INSTALL = re.compile(rb"\xbe(..)\xb9\x20\x00\x2e\xa5\x47\x47\xe2\xfa", re.S)


def _real(mod: dict[str, Any], rom: bytes) -> tuple[int, int]:
    """The real_cs field of a module header: (paragraph, offset)."""
    cs = struct.unpack_from("<HHHBBIII", rom, mod["offset"])[5]
    return cs >> 16, cs & 0xFFFF


def _linear(mod: dict[str, Any], rom: bytes) -> int:
    seg, off = _real(mod, rom)
    return ((seg << 4) + off) & 0xFFFFF


def _install_vectors(emu: bios_emu.BiosEmulator, m2: bytes, base2: int, default: int) -> None:
    """The interrupt vectors the RunTime module installs itself: all 256 to its own entry point,
    then the handler offsets of its own table (INT 00h-1Fh, 70h-77h)."""
    uc = emu.uc
    uc.mem_write(0, struct.pack("<HH", default, 0xF000) * 256)
    m = IVT_INSTALL.search(m2)
    if not m:
        return
    # the code runs with CS = the module's own paragraph: cs:[imm] is imm - (the module's offset
    # in that paragraph) bytes into the image
    off = struct.unpack("<H", m.group(1))[0] - (base2 & 0xFFFF)
    if not 0 <= off <= len(m2) - 80:
        return
    words = struct.unpack_from("<40H", m2, off)
    for i, handler in enumerate(words[:32]):
        uc.mem_write(i * 4, struct.pack("<HH", handler, 0xF000))
    for i, handler in enumerate(words[32:]):
        uc.mem_write((0x70 + i) * 4, struct.pack("<HH", handler, 0xF000))


def _key_state(emu: bios_emu.BiosEmulator) -> None:
    """The keyboard plumbing POST leaves running: the 8042 command byte with INT 9 and the
    keyboard enabled, IRQ 1 unmasked, the BIOS key ring in the BDA, IF set. Without it the
    RunTime's INT 09h never runs and the setup's INT 16h poll sees an empty buffer for ever."""
    uc = emu.uc
    emu.kbc_command_byte = 0x65
    emu.pic_mask &= ~0x02
    uc.mem_write(0x41A, struct.pack("<HH", 0x001E, 0x001E))  # key ring head, tail
    uc.mem_write(0x480, struct.pack("<HH", 0x001E, 0x003E))  # key ring start, end
    uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) | 0x200)


def _label(screen: Screen, row: int, col: int, end: int) -> str:
    return bytes(screen.chars[row][col : end + 1]).decode("cp437").strip()


def garbled(screen: Screen) -> bool:
    return sum(c in GLYPHS for c in screen.text()) > MAX_GLYPHS


class Direct:
    """The setup of an AMIBIOS Simple/Hi-Flex image, started without POST."""

    def __init__(self, rom: bytes, max_instructions: int = 50_000_000) -> None:
        _info, mods = ami.extract(rom)
        by_id = {m["id"]: m for m in mods if m.get("data")}
        m1, m2, m4 = by_id.get(1), by_id.get(2), by_id.get(4)
        if not (m1 and m2 and m4):
            raise ValueError("no Setup Server / RunTime / Setup Client module in this image")
        hints = b"".join(m.get("data") or b"" for m in mods)
        base1, base2 = _linear(m1, rom), _linear(m2, rom)
        i = m1["data"].find(b"\xb0\x00\x2e\xff\x1e")  # mov al,0 ; lcall cs:[disp]
        if i < 0:
            raise ValueError("the Setup Server has no call into the Setup Client")
        ptr = (base1 + struct.unpack_from("<H", m1["data"], i + 5)[0]) & 0xFFFFF
        entry = struct.unpack_from("<H", m4["data"], 0)[0]  # module 04's own entry offset

        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=max_instructions, hints=hints
        )
        self.emu = emu
        uc = emu.uc
        # the RunTime owns the F000 half from its real_off on: a module whose header also names
        # a place there (module 0B Int-10) is loaded elsewhere by POST, so it is left out
        rt_lo, rt_hi = base2, base2 + len(m2["data"])
        for m in sorted(mods, key=lambda m: m["id"] == 4):
            data = m.get("data")
            if not data or m["id"] == 0:  # (module 00, POST, shares module 01's paragraph)
                continue
            if m["id"] == 4:
                lin = SEG4 << 4
            elif m["id"] == 0x52:
                lin = DB_SEG << 4
            else:
                if _real(m, rom)[0] == 0:
                    continue
                lin = _linear(m, rom)
                if m["id"] != 2 and rt_lo <= lin < rt_hi:
                    continue
            uc.mem_write(lin, data[: 0x100000 - lin])
        uc.mem_write(ptr, struct.pack("<HH", entry, SEG4))
        sup = m2["data"].find(b"$SUP")  # the service table the Setup Server copies to ES:0166
        if sup >= 0:
            uc.mem_write(0x50166, bytes(uc.mem_read((base2 + sup + 4) & 0xFFFFF, 0x4C)))
        _install_vectors(emu, m2["data"], base2, _real(m2, rom)[1])
        _key_state(emu)
        uc.reg_write(UC_X86_REG_AX, 0x2000)  # AL = 0: the "enter setup" branch
        self.blob = rom + hints
        screen = self._as_text(emu.run(SEG4, entry, ss=0x0030, sp=0xFFFE, ds=0x5000, es=0x5000))
        if "SETUP UTIL" not in screen.text().upper():
            raise ValueError(f"the setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 50_000_000
        self.main, self.start = screen, emu.snapshot()

    def _as_text(self, screen: Screen) -> Screen:
        """Setups drawn in 640x480 graphics with AMI's own font: read back as text."""
        emu = self.emu
        if (
            bios_emu.PLANAR_MODES.get(emu.video_mode) == (640, 480)
            and emu.graphics_font is None
            and "AMERICAN" not in screen.text().upper()
        ):
            font = bios_emu.guess_graphics_font(emu.vga_planes, self.blob)
            if font:
                emu.graphics_font = font
                return emu.screen()
        return screen

    def _capture(self, keys: list[int]) -> tuple[Screen, str]:
        """The screen after the setup has taken these keys, pressed one by one."""
        self.emu.restore(self.start)
        self.emu.press_keys(list(keys), paced=True)
        return self._as_text(self.emu.resume()), self.emu.stopped_reason

    def screens(self) -> list[tuple[str, Screen, str]]:
        """The main menu with the optimal defaults loaded, then every entry that opens a page
        (pages with garbled item names left out)."""
        entries: list[tuple[int, str]] = []
        first = cursor(self.main)
        for downs in range(MAX_ENTRIES):
            here = self.main if not downs else self._capture(K_DOWN * downs)[0]
            at = cursor(here)
            if at is None or (downs and at == first):
                break
            entries.append((downs, _label(here, *at)))
        prefix: list[int] = []
        for downs, text in entries:
            if text.upper().startswith(DEFAULTS):
                prefix = K_DOWN * downs + K_ENTER + K_Y + K_ENTER + K_UP * downs
        main, reason = self._capture(prefix) if prefix else (self.main, "waiting for a key")
        out = [("MAIN MENU", main, reason)]
        for downs, text in entries:
            if not text or any(w in text.upper() for w in ACTIONS):
                continue
            page, reason = self._capture(prefix + K_DOWN * downs + K_ENTER)
            if page.text() != main.text() and not garbled(page):
                out.append((text, page, reason))
        if len(out) < 2:
            raise ValueError("the setup started, but none of its pages could be read without POST")
        return out
