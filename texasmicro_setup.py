"""
Capture the setup of Texas Micro's industrial computers (L486-DX, 1998: "Texas Micro Inc. Setup
Utility") by running the whole ROM in the x86 emulator.

The update's FLASH.CFG puts the setup in a block of its own at E0000 (screen_tools._flash_cfg).
POST stops at its configuration error and offers F2. Its memory test also fills E0000-EFFFF,
here plain RAM because the chipset is not emulated, so the block is put back before F2. A list
on the left, Down to each entry, Enter opens its dialog or a list of its own (Advanced Options).
"""

from __future__ import annotations

import ami_setup
import bios_emu
from textscreen import Screen

MARK = b"Texas Micro Inc.  Setup Utility"
PROMPT, TITLE = "F2 to run the setup", "Setup Utility"
F2, DOWN, ENTER = [0x3C, 0xBC], [0x50, 0xD0], [0x1C, 0x9C]
SKIP = (
    "Park Hard Drive",
    "Flash It",
    "Password Edit",
    "Basic Options",
    "Save",
    "Exit",
)  # (they act, or ask for a password)
LIST_COLUMNS = range(4, 30)
MAX_ENTRIES, LEVELS = 16, 1
WAITING = ("waiting for a key", "polling the keyboard")


def is_texas_micro(rom: bytes) -> bool:
    return MARK in rom


def selected(screen: Screen) -> str:
    """The entry under the cursor: the cells of the left list with a light background."""
    for row in range(3, screen.rows - 2):
        cells = [c for c in LIST_COLUMNS if screen.attrs[row][c] >> 4 & 7 == 7]
        if cells:
            return bytes(screen.chars[row][cells[0] : cells[-1] + 1]).decode("cp437").strip()
    return ""


def list_title(screen: Screen) -> str:
    """The title in the frame of the left list."""
    return bytes(screen.chars[3][4:30]).decode("cp437").strip(" ═╒╕╞╡╣╠╔╗")


class TexasMicroSetup:
    def __init__(self, rom: bytes):
        if not is_texas_micro(rom) or len(rom) < 0x20000:
            raise ValueError("not a Texas Micro BIOS with its setup block")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=6_000_000_000,
            timer_irq=True,
            ram_mb=4,
        )
        emu.kbc_reset_in_place = True
        emu.max_seconds = 480  # (its POST: about 130 s on an idle PC)
        screen = emu.run(0xF000, 0xFFF0)
        if emu.stopped_reason not in WAITING or PROMPT not in screen.text():
            raise ValueError(
                f"the Texas Micro POST did not offer setup (stopped: {emu.stopped_reason})"
            )
        emu.uc.mem_write(0xE0000, bytes(rom[-0x20000:-0x10000]))
        emu.max_seconds = 120
        emu.press_keys(F2, paced=True)
        screen = emu.resume()
        if TITLE not in screen.text():
            raise ValueError(f"the Texas Micro setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.main = emu, screen

    def _walk(self, screen: Screen, levels: int) -> list[tuple[str, Screen, str]]:
        """Each entry of a list: Enter from the state with the cursor on it."""
        emu, title = self.emu, list_title(screen)
        out = [(title, screen, emu.stopped_reason)]
        state, seen = emu.snapshot(), set()
        for _ in range(MAX_ENTRIES):
            entry = selected(screen)
            if not entry or entry in seen:
                break
            seen.add(entry)
            if not any(word in entry for word in SKIP):
                emu.press_keys(ENTER, paced=True)
                page = emu.resume()
                if list_title(page) != title and levels:
                    out += self._walk(page, levels - 1)
                elif page.text() != screen.text():
                    out.append((entry, page, emu.stopped_reason))
                emu.restore(state)
            emu.press_keys(DOWN, paced=True)
            screen = emu.resume()
            state = emu.snapshot()
        return out

    def screens(self) -> list[tuple[str, Screen, str]]:
        return self._walk(self.main, LEVELS)
