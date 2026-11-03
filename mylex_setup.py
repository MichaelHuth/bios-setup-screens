"""
Capture the setup screens of Mylex's own BIOS (Mylex MVI486, 386/486 boards of about 1993:
"MYLEX MVI486 BIOS Version 6.27 10/29/93") by running the whole ROM in the x86 emulator.

Worked out on Mylex MVI486:
- the reset vector at F000:FFF0 jumps to F000:E05B, whose first instruction is "jmp 1006Eh": the
  ROM seen again above 1 MB (the chipset mirrors F0000-FFFFF at 100000h until shadowing is on);
  the BIOS's INT 16h handler is reached as F000:15F34, so the whole BIOS runs from that copy. The
  emulator maps plain RAM at 100000h, so the ROM is written there too;
- POST's 8042 driver (F000:1247) reads port 60h once after every command, a dummy read: the
  replies must come a moment later (emu.kbc_reply_later);
- POST's "word splitter / byte shifter" test (F000:0E13) writes and reads the DMA page
  registers as words (the emulator models that); its refresh test counts port 61h toggles
  (timer_irq), and with page register 8Bh at 40h it skips a DMA walk over all memory;
- after sizing the memory POST reboots the machine on purpose (F000:1A94 -> F000:705A: the size
  into CMOS 30h/31h, out 64h FEh), so kbc_reset_in_place lets the run go on;
- POST then offers "Press "F1" key to Continue, Press "F2" key to run SETUP" (F000:B797). Typed
  keys do not get in: the wait loop at F000:6033 keeps IF clear except for two instructions, so
  IRQ 1 never reaches the BIOS's INT 09h handler. The key goes into the BIOS's own keyboard ring
  instead, as its INT 09h handler would have put it, which F000:6022 reads back;
- the setup is five pages of 16-byte item records (page table at F000:8978); PgDn/PgUp move
  between pages (PgDn on the last wraps to the first), Q quits and S saves (both reboot).
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
from textscreen import Screen

TITLE = b"MYLEX"  # (MVI486; other Mylex boards: Northgate Slimline ZXP)
F2, PGDN = 0x3C, 0x51
PAGES = 5
PROMPT = "key to run SETUP"


def is_mylex(rom: bytes) -> bool:
    return TITLE in rom.upper() and PROMPT.encode() in rom and b"SHADOW" in rom.upper()


class MylexSetup:
    def __init__(self, rom: bytes):
        if not is_mylex(rom):
            raise ValueError("not a Mylex MVI486 BIOS with its CMOS Setup")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=400_000_000,
            ram_mb=2,
            timer_irq=True,
        )
        emu.kbc_reset_in_place = True  # (POST reboots itself after sizing the memory)
        emu.kbc_reply_later = True
        emu.max_seconds = 150
        emu.mylex_counter = True
        emu.uc.mem_write(0x100000, rom[-0x10000:])  # the ROM's alias above 1 MB
        emu._video_rom(hook_int10=True)
        emu.dma_pages[0x0B] = 0x40  # (POST skips its DMA page register walk)
        emu.press_keys([0x01, 0x81] * 10)  # Esc: "any other key to Skip Memory Test"
        self.emu = emu
        screen = emu.run(0xF000, 0xFFF0)
        if PROMPT not in screen.text():
            raise ValueError(f"POST did not reach the setup prompt (stopped: {emu.stopped_reason})")
        emu.max_seconds = 40
        self.put_key(F2)  # "Press "F2" key to run SETUP"
        screen = emu.resume()
        if "CMOS Setup" not in screen.text():
            raise ValueError(f"the Mylex setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 40_000_000
        self.main = screen

    def put_key(self, scan: int, char: int = 0) -> None:
        """One key (scan code, character) in the BIOS's own keyboard ring, as its INT 09h handler
        would leave it: head 0040:001A, tail 0040:001C, the ring between the pointers at
        0040:0080 (start) and 0040:0082 (end)."""
        rd, wr = self.emu.uc.mem_read, self.emu.uc.mem_write
        head = int.from_bytes(rd(0x41A, 2), "little")
        tail = int.from_bytes(rd(0x41C, 2), "little")
        start = int.from_bytes(rd(0x480, 2), "little")
        end = int.from_bytes(rd(0x482, 2), "little")
        if not start <= tail < end:  # POST has not set the ring up
            return
        wr(0x400 + tail, bytes((char, scan)))
        following = start if tail + 2 >= end else tail + 2
        if following != head:  # (a full ring drops the key)
            wr(0x41C, following.to_bytes(2, "little"))

    @staticmethod
    def page_title(screen: Screen) -> str:
        m = re.search(r"page\s+(\d+)\s+of\s+(\d+)", screen.text(), re.I)
        return f"Page {m.group(1)} of {m.group(2)}" if m else "Main Menu"

    def screens(self) -> list[tuple[str, Screen, str]]:
        """One entry per page, in order: the setup waits in its own key loop after drawing a
        page, so one key in the ring and one resume is one page (no snapshots: restoring one
        would put the cursor back on page 1)."""
        out = [(self.page_title(self.main), self.main, self.emu.stopped_reason)]
        for _ in range(PAGES - 1):
            self.put_key(PGDN)
            screen = self.emu.resume()
            title = self.page_title(screen)
            if screen.text() == out[-1][1].text() or (
                title.startswith("Page") and title in (t for t, _, _ in out)
            ):
                break  # (PgDn past the last page: back to the first)
            out.append((self.page_title(screen), screen, self.emu.stopped_reason))
        return out
