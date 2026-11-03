"""
Capture the setup of BIOSes that keep it simple: POST stops at an error and names the key for
the setup, which
is then one screen. Found by running the whole ROM in the x86 emulator;
each family is a line in FAMILIES.
"""

from __future__ import annotations

from typing import NamedTuple

import ami_setup
import bios_emu
from textscreen import Screen

CTRL_ALT_ESC = [0x1D, 0x38, 0x01, 0x81, 0xB8, 0x9D]
WAITING = ("waiting for a key", "polling the keyboard")
MAX_PAGES = 8


class Family(NamedTuple):
    name: str  # what the result calls it
    mark: bytes  # in the ROM: its own name for itself
    prompt: str  # what POST shows when it waits
    key: list[int]
    title: str  # what the setup's screen shows
    next_page: list[int] | None = None  # the key to the next page
    during: bool = False  # POST offers it in passing, without stopping


FAMILIES = (
    Family(
        "TriGem's TG286 BIOS with its CMOS SETUP",
        b"TG286 CMOS SETUP",
        "FOR SETUP",
        CTRL_ALT_ESC,
        "TG286 CMOS SETUP",
    ),
    Family(
        "AST's BIOS of the Premium 386SX with its CMOS SETUP UTILITY",
        b"AST Premium 386SX/16 CMOS SETUP UTILITY",
        "CTRL-ALT-ESC",
        CTRL_ALT_ESC,
        "CMOS SETUP UTILITY",
        [0x3C, 0xBC],
        True,
    ),
)


def family(rom: bytes) -> Family | None:
    return next((f for f in FAMILIES if f.mark in rom), None)


class PromptSetup:
    def __init__(self, rom: bytes):
        found = family(rom)
        if found is None:
            raise ValueError("not a BIOS of the families with a simple setup")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=1_500_000_000,
            timer_irq=True,
            ram_mb=4,
        )
        emu.kbc_reset_in_place = True
        emu.max_seconds = 240
        if found.during:
            emu.press_keys(found.key, when_text=found.prompt)
        screen = emu.run(0xF000, 0xFFF0)
        if not found.during:
            if emu.stopped_reason not in WAITING or found.prompt not in screen.text():
                raise ValueError(f"POST did not offer the setup (stopped: {emu.stopped_reason})")
            emu.press_keys(found.key, paced=True)
            screen = emu.resume()
        if found.title not in screen.text():
            raise ValueError(f"the setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.screen, self.next_page = emu, screen, found.next_page

    def screens(self) -> list[tuple[str, Screen, str]]:
        emu, screen = self.emu, self.screen
        out = [("Setup", screen, emu.stopped_reason)]
        if self.next_page is None:
            return out
        seen = {screen.text()}
        for n in range(2, MAX_PAGES + 1):
            emu.press_keys(self.next_page, paced=True)
            screen = emu.resume()
            if screen.text() in seen or emu.stopped_reason not in WAITING:
                break
            seen.add(screen.text())
            out.append((f"Page {n}", screen, emu.stopped_reason))
        return out
