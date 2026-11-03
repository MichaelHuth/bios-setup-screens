"""
Capture the setup screens of Chips and Technologies' own BIOS for its SCAT chipset ("Chips and
Technologies, Inc. System Configuration Utility") by running the whole ROM in the x86 emulator.

Worked out on a GW-286CT GEAR (F82C235, "CHIPS SCAT BIOS Version 1.5.0", 1991):
- after a reset POST reads CR0 and restarts until the cache bits are set, as on a real CPU;
- POST tests all 384 KB of its shadow RAM over the ROM, so the emulator needs the chipset's
  registers (bios_emu.scat);
- POST stops at its configuration errors with "Press <F1> to continue, <F2> to Setup";
- the pages are turned with PgDn: each one names the next in its help at the bottom.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
from textscreen import Screen

F2, PGDN, ENTER = [0x3C, 0xBC], [0x51, 0xD1], [0x1C, 0x9C]
WAITING = ("waiting for a key", "polling the keyboard")
TITLE = "System Configuration Utility"
MAX_PAGES = 8


def is_chips_scat(rom: bytes) -> bool:
    return b"CHIPS SCAT BIOS" in rom and b"Technologies, Inc. " + TITLE.encode() in rom


def page_title(screen: Screen) -> str:
    """The name in the frame under the heading, e.g. "STANDARD SETUP OPTIONS"."""
    for line in screen.text().split("\n")[:4]:
        m = re.search(r"─ (\S.*?) ─", line)
        if m:
            return m.group(1).strip()
    return ""


class ChipsSetup:
    def __init__(self, rom: bytes):
        if not is_chips_scat(rom):
            raise ValueError("not a Chips and Technologies SCAT BIOS")
        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=1_500_000_000
        )
        emu.kbc_reset_in_place = True  # (POST returns from protected mode by a CPU reset)
        emu.scat = True
        emu.cr0_at_reset = 0x60000010
        screen = emu.run(0xF000, 0xFFF0)
        if emu.stopped_reason not in WAITING or "to Setup" not in screen.text():
            raise ValueError(f"C&T POST did not offer setup (stopped: {emu.stopped_reason})")
        emu.max_instructions = 150_000_000
        emu.press_keys(F2)
        screen = emu.resume()
        if TITLE not in screen.text():
            raise ValueError(f"the C&T setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.first = emu, screen

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: each page, turned with PgDn."""
        out: list[tuple[str, Screen, str]] = []
        screen, seen = self.first, set()
        for _ in range(MAX_PAGES):
            title = page_title(screen)
            if not title or title in seen:
                break
            seen.add(title)
            out.append((title.title(), screen, self.emu.stopped_reason))
            if "PgDn" not in screen.text():
                break
            self.emu.press_keys(PGDN, paced=True)
            screen = self.emu.resume()
        return out
