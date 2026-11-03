"""
Capture the setup screens of DTK's own BIOS (Datatech Enterprises, 286/386 boards of about
1988-90: "ROM SETUP PROGRAM VERSION 1.0x") by running the whole ROM in the x86 emulator.

Worked out on DTK PEM-2030B and PEM-3301 (DTK 386 ROM BIOS 4.26):
- POST runs with a small memory (2 MB: the memory test of a larger one takes minutes in the
  emulator) and stops at "System memory mismatch, run SETUP", offering F1;
- POST checks that a video BIOS has taken over INT 10h, and resets the PC otherwise (the
  emulator's VGA ROM does so, as a real one);
- the setup's main menu lists numbered items, chosen by typing the number and Enter; each
  item's page is captured from the main menu (preformatting the hard disk and the password
  are left out).
"""

from __future__ import annotations

import re

from unicorn import UC_HOOK_CODE, Uc
from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_DX, UC_X86_REG_IP

import ami_setup
import bios_emu
from textscreen import Screen

TITLE = b"ROM SETUP PROGRAM"
F1, ENTER = [0x3B, 0xBB], [0x1C, 0x9C]
DIGITS = {str(n): [n + 1, n + 0x81] for n in range(1, 10)}  # scan codes of 1-9
DIGITS["0"] = [0x0B, 0x8B]
SKIP = ("PREFORMAT", "PASSWORD", "QUIT", "EXIT")
WAITING = ("waiting for a key", "polling the keyboard")
# DTK PPM-1631D-S (1990): in protected mode, POST rebuilds the resume address at 40:67 from its
# code descriptor read through ES = 0, and gets it wrong (the base's top byte in dl is shifted
# in dh, then "or ah, dl": 0F00h, not F000h). On the PC that read through a null selector
# faults, the 286 shuts down and resumes at the address written before (F000h); the emulator
# lets it read, so the "or" takes dl shifted there
# (a hook, not a patch: POST checks the ROM's checksum)
RESUME_SEGMENT = bytes.fromhex("D3E8D2E60AE2A36900")


def _or_dl_shifted(uc: Uc, address: int, size: int, _: object) -> None:
    """ "or ah, dl << 4" in place of the ROM's "or ah, dl" (RESUME_SEGMENT)."""
    ax, dx = uc.reg_read(UC_X86_REG_AX), uc.reg_read(UC_X86_REG_DX)
    uc.reg_write(UC_X86_REG_AX, ax | ((dx & 0x0F) << 12))
    uc.reg_write(UC_X86_REG_IP, uc.reg_read(UC_X86_REG_IP) + 2)


def is_dtk(rom: bytes) -> bool:
    return TITLE in rom and b"DATATECH" in rom.upper()


class DtkSetup:
    def __init__(self, rom: bytes):
        if not is_dtk(rom):
            raise ValueError("not a DTK BIOS with its ROM SETUP PROGRAM")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=400_000_000,
            ram_mb=2,
            timer_irq=True,  # (PKM-3330Y: POST counts 8 timer ticks in its own INT 8)
        )
        emu.kbc_reset_in_place = True  # (POST returns from protected mode by a CPU reset)
        emu._video_rom(hook_int10=True)
        if (at := rom.find(RESUME_SEGMENT)) >= 0:
            pc = 0x100000 - len(rom) + at + 4
            emu.uc.hook_add(UC_HOOK_CODE, _or_dl_shifted, None, pc, pc)
        screen = emu.run(0xF000, 0xFFF0)
        for _ in range(3):
            if "ROM SETUP PROGRAM" in screen.text() or emu.stopped_reason not in WAITING:
                break
            emu.press_keys(F1, paced=True)  # "Press F1 key to enter SETUP program"
            screen = emu.resume()
        if "ROM SETUP PROGRAM" not in screen.text():
            raise ValueError(f"the DTK setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 50_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

    def items(self) -> list[tuple[str, str]]:
        """(number, title) of the main menu's items that open a page."""
        out = []
        for line in self.main.text().split("\n"):
            # (setup 3.0 of 1992: the menu in a frame, "▌│  1. SET UP ... │▐")
            m = re.match(r"[\s▌│]*(\d)\.\s+(.*?)\.?[\s│▐]*$", line)
            if m and not any(w in m.group(2).upper() for w in SKIP):
                out.append((m.group(1), m.group(2).strip().rstrip(".")))
        return out

    def capture(self, number: str) -> Screen:
        self.emu.restore(self.start)
        for keys in (DIGITS[number], ENTER):
            self.emu.press_keys(keys, paced=True)
            screen = self.emu.resume()
        if "PRESS ANY KEY TO CONTINUE" in screen.text():  # (the built-in utilities' notice)
            self.emu.press_keys(ENTER, paced=True)
            screen = self.emu.resume()
        return screen

    def screens(self) -> list[tuple[str, Screen, str]]:
        out = [("Main Menu", self.main, "waiting for a key")]
        for number, title in self.items():
            screen = self.capture(number)
            if screen.text() != self.main.text():
                out.append((title.title(), screen, self.emu.stopped_reason))
        return out
