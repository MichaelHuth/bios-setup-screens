"""
Capture the setup of the BIOS of Novell's ATterminal (a 286 station of 1987-88, "ROM SETUP"
Version 1.15) by running the whole ROM in the x86 emulator.

POST stops at its diskette error and offers F2. The setup is a dialogue, not menus: it lists all
settings and asks "Is this correct?", answered with Y or N and Enter; N goes through the settings
group by group, each asked the same way.
"""

from __future__ import annotations

import ami_setup
import bios_emu
from textscreen import Screen

MARK = b"Novell Hardware Products"
PROMPT, TITLE, QUESTION = "to run ROM SETUP", "S E T U P", "Is this correct?"
F2, ENTER = [0x3C, 0xBC], [0x1C, 0x9C]
N, Y = [0x31, 0xB1], [0x15, 0x95]
MAX_GROUPS = 12
WAITING = ("waiting for a key", "polling the keyboard")


def is_novell(rom: bytes) -> bool:
    return MARK in rom and b"ROM SETUP" in rom


def group_title(screen: Screen) -> str:
    """The setting a question of the dialogue is about: the first line of what it shows."""
    lines = [line.strip() for line in screen.text().split("\n") if line.strip()]
    return lines[0].split("=")[0].split(" is ")[0].rstrip(": ") if lines else "Setup"


class NovellSetup:
    def __init__(self, rom: bytes):
        if not is_novell(rom):
            raise ValueError("not the BIOS of a Novell ATterminal")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=1_500_000_000,
            timer_irq=True,
            ram_mb=4,
        )
        emu.kbc_reset_in_place = True
        emu.max_seconds = 240  # (its memory test: 50 s on an idle PC)
        screen = emu.run(0xF000, 0xFFF0)
        if emu.stopped_reason not in WAITING or PROMPT not in screen.text():
            raise ValueError(f"the Novell POST did not offer setup (stopped: {emu.stopped_reason})")
        screen = self._key(emu, F2)
        if TITLE not in screen.text():
            raise ValueError(f"the Novell setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.summary = emu, screen

    @staticmethod
    def _key(emu: bios_emu.BiosEmulator, *keys: list[int]) -> Screen:
        screen = emu.screen()
        for key in keys:
            emu.press_keys(key, paced=True)
            screen = emu.resume()
        return screen

    def screens(self) -> list[tuple[str, Screen, str]]:
        """The list of all settings, then each group the dialogue asks about (a line answered with
        Enter for the date and the time, which ask for new values first)."""
        emu = self.emu
        out = [("Settings", self.summary, emu.stopped_reason)]
        screen = self._key(emu, N, ENTER, ENTER, ENTER)
        seen = set()
        for _ in range(MAX_GROUPS):
            title = group_title(screen)
            if QUESTION not in screen.text() or title in seen:
                break
            seen.add(title)
            if TITLE not in screen.text():  # (the list again, before the first group)
                out.append((title, screen, emu.stopped_reason))
            screen = self._key(emu, Y, ENTER)
        return out
