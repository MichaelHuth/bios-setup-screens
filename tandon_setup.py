"""
Capture the setup screen of Tandon's own BIOS of the early 1990s ("SYSTEM SETUP", one screen in
several languages) by running the whole ROM in the x86 emulator.

Worked out on a Tandon 486 (BIOS 3.88, 1992):
- POST keeps the CPU signature that DX holds after a reset in CMOS 7Ch/7Ah and its setup reads it
  back (with 0 there it returns to a wrong address), and tests the timer interrupt;
- POST's messages wait for Enter with interrupts off, reading the 8042 directly, which the emulator
  does not notice by itself: the driver stops when that loop has run for a while;
- without a valid CMOS POST reports its errors and enters the setup by itself after Enter.
"""

from __future__ import annotations

import ami_setup
import bios_emu
from textscreen import Screen

ENTER = [0x1C, 0x9C]
WAIT_ENTER = bytes.fromhex("E464E7EDA80174F8E4603C1C")  # in 64h; bit 0; in 60h; Enter?
PROMPT, TITLE = 'Press "Enter"', "SYSTEM SETUP"
RESET_DX = 0x0435  # (a 486)
MAX_PROMPTS = 6


def is_tandon(rom: bytes) -> bool:
    return b"Tandon Corporation" in rom and WAIT_ENTER in rom  # (the setup texts are packed)


class TandonSetup:
    def __init__(self, rom: bytes):
        if not is_tandon(rom):
            raise ValueError("not a Tandon BIOS with its SYSTEM SETUP")
        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=3_000_000_000
        )
        emu.kbc_reset_in_place = True
        emu.timer_irq = True
        emu.uc.reg_write(bios_emu.UC_X86_REG_EDX, RESET_DX)
        self.polls = 0
        wait = 0xF0000 + rom.rindex(WAIT_ENTER) - (len(rom) - 0x10000)
        emu.uc.hook_add(bios_emu.UC_HOOK_CODE, self._poll, emu, wait, wait)
        screen = emu.run(0xF000, 0xFFF0)
        for _ in range(MAX_PROMPTS):
            if TITLE in screen.text() or PROMPT not in screen.text():
                break
            self.polls = 0
            emu.press_keys(ENTER)
            screen = emu.resume()
        if TITLE not in screen.text():
            raise ValueError(f"the Tandon setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.screen = emu, screen

    def _poll(self, uc: bios_emu.Uc, _addr: int, _size: int, emu: bios_emu.BiosEmulator) -> None:
        self.polls += 1
        if self.polls > 300:
            emu.stopped_reason = "polling the keyboard"
            uc.emu_stop()

    def screens(self) -> list[tuple[str, Screen, str]]:
        return [("System Setup", self.screen, self.emu.stopped_reason)]
