"""
Capture the setup of a BIOS with a pull-down menu bar ("586 System BIOS 1998": General,
Peripherals, PnP/PCI, Hard Disk, Misc., Exit; "Use arrow to move, Enter to select or modify
item, Esc to exit.") by running the whole ROM in the x86 emulator.

Worked out on an Eagle PowerTX image (128 KB, 1998):
- its reset vector jumps into a block of zeros (the dump lacks it): POST is started at
  F000:E05B, the entry the far jump at F000:E000 and other AT BIOSes use;
- POST stops at "CMOS checksum failure ... RUN SETUP UTILITY / Press <F1> to RESUME", and F1
  starts the setup;
- Enter opens a tab's pull-down list (Right goes to the next tab); its entries marked with ►
  open a dialog each (Down to the entry, Enter), Esc closes it.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
from textscreen import Screen

MARK = b"arrow to move, Enter to select or modify item, Esc to exit."
F1, ENTER = [0x3B, 0xBB], [0x1C, 0x9C]
DOWN, RIGHT = [0xE0, 0x50, 0xE0, 0xD0], [0xE0, 0x4D, 0xE0, 0xCD]
WAITING = ("waiting for a key", "polling the keyboard")
SUBMENU = "►"
MAX_TABS, MAX_ENTRIES = 8, 16


def is_pulldown(rom: bytes) -> bool:
    return MARK in rom


def _entry(rom: bytes) -> int:
    """Where POST starts in segment F000: the reset vector, or E05Bh when the near jump there
    lands in a block of zeros."""
    top = rom[-0x10000:]
    if top[0xFFF0] == 0xE9:
        target = (0xFFF3 + int.from_bytes(top[0xFFF1:0xFFF3], "little")) & 0xFFFF
        if not any(top[target : target + 8]):
            return 0xE05B
    return 0xFFF0


def menu_bar(screen: Screen) -> list[str]:
    """The tab names on the bar's line ("General    Peripherals ...")."""
    for line in screen.text().split("\n")[:3]:
        names = [n.strip() for n in re.split(r" {3,}", line.strip(" │║")) if n.strip()]
        if len(names) >= 3 and "Exit" in names:
            return names
    return []


def pulldown_entries(screen: Screen) -> list[str]:
    """The entries of the open pull-down list: the lines inside its box, under the bar."""
    out = []
    for line in screen.text().split("\n")[3:22]:
        m = re.search(r"[║│]  (\S.*?)\s*[║│]", line)
        if m and not m.group(1).startswith(("═", "─")):
            out.append(m.group(1).strip())
    return out


class PulldownSetup:
    def __init__(self, rom: bytes):
        if not is_pulldown(rom):
            raise ValueError("not a BIOS with the pull-down menu setup")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=600_000_000,
            timer_irq=True,
            ram_mb=16,
        )
        emu.kbc_reset_in_place = True
        emu.max_seconds = 200
        screen = emu.run(0xF000, _entry(rom))
        if emu.stopped_reason in WAITING and "<F1>" in screen.text() and not menu_bar(screen):
            emu.max_instructions = 60_000_000
            emu.press_keys(F1, paced=True)  # "RUN SETUP UTILITY / Press <F1> to RESUME"
            screen = emu.resume()
        self.tabs = menu_bar(screen)
        if not self.tabs:
            raise ValueError(f"the pull-down setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 60_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

    def _keys(self, keys: list[list[int]]) -> Screen:
        """From the bar: each key on its own, after the setup has read the one before."""
        self.emu.restore(self.start)
        screen = self.emu.screen()
        for key in keys:
            self.emu.press_keys(key, paced=True)
            screen = self.emu.resume()
        return screen

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: each tab's pull-down list (the Exit tab's is only
        actions), then the dialogs its ► entries open (not the password prompts)."""
        out: list[tuple[str, Screen, str]] = []
        for i, tab in enumerate(self.tabs[:MAX_TABS]):
            if tab == "Exit":
                continue
            path = [RIGHT] * i + [ENTER]
            screen = self._keys(path)
            entries = pulldown_entries(screen)
            if not entries:
                continue
            out.append((tab, screen, self.emu.stopped_reason))
            for k, entry in enumerate(entries[:MAX_ENTRIES]):
                if not entry.endswith(SUBMENU) or "Password" in entry:  # (a prompt, no page)
                    continue
                dialog = self._keys(path + [DOWN] * k + [ENTER])
                if dialog.text() != screen.text() and self.emu.stopped_reason in WAITING:
                    name = entry.rstrip(SUBMENU).strip()
                    out.append((f"{tab} > {name}", dialog, self.emu.stopped_reason))
        return out
