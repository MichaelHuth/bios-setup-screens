"""
Capture the setup screens of Dell's Phoenix "ROM BIOS PLUS Version 1.10" of about 2003-04
(Dimension 3000, OptiPlex GX270: a Pentium 4 with an ICH5; Dell's own text-mode System Setup)
by running the whole image in the x86 emulator.

Worked out on the Dimension 3000 (A03):
- POST sends an SMI to its own CPU through the local APIC (to move SMBASE) and waits for the
  handler's flag; there is no SMM here, so bios_emu leaves the wait out (DELL_SMI_WAIT);
- its shutdown test resets the CPU through the 8042 and comes back through the ROM's reset
  code at 4 GB, not through the shadowed F000 segment (bios_emu's _reset_alias);
- the memory test polls the keyboard; F2 pressed there starts setup once POST is done;
- the setup is one list ("↑↓ to select") in a frame that scrolls with Down; an entry
  showing <ENTER> opens a box of its own, Esc closes it;
- the OptiPlex GX270 stops with "Chipset heat sink not detected" unless port C50h (a Super
  I/O input) reads 0.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
from textscreen import Screen

F2 = [0x3C, 0xBC]
DOWN = [0xE0, 0x50, 0xE0, 0xD0]
ENTER = [0x1C, 0x9C]
IN_SETUP = "to select"
WAITING = ("waiting for a key", "polling the keyboard")
SCROLLBAR = "▲▼█░"
MAX_ENTRIES = 60
HOST_440FX = 0x1237
CTRL_ALT_ENTER = [0x1D, 0x38, 0x1C, 0x9C, 0xB8, 0x9D]
ALT_P = [0x38, 0x19, 0x99, 0xB8]
PAGED_PROMPT = "for System Setup"
PAGES = re.compile(r"Page 1 of (\d+)")


def is_dell_phoenix(rom: bytes) -> bool:
    return b"Phoenix ROM BIOS PLUS Version 1.10" in rom and bios_emu.DELL_MARK in rom


def list_rows(screen: Screen) -> list[str]:
    """The rows of the setup's list: the lines inside the double frame (scroll bar left out)."""
    lines = screen.text().split("\n")
    start = next((i + 1 for i, line in enumerate(lines) if line.startswith("╔")), len(lines))
    rows = []
    for line in lines[start:]:
        if line.startswith("╚"):
            break
        rows.append(line.strip("║ ").rstrip(SCROLLBAR).strip())
    return rows


def is_dell_paged(rom: bytes) -> bool:
    """The older PLUS images (WorkStation 400 of 1997): the version string lies in the BIOS's
    packed text, with the packer's control bytes in it, so only its first words are whole."""
    at = rom.find(b"Phoenix ROM BIOS")
    return bios_emu.DELL_MARK in rom and at >= 0 and b"PLUS" in rom[at + 16 : at + 24]


class DellPagedSetup:
    """The setup of the older PLUS images: "Page 1 of 2", Alt-P for the next. Ctrl-Alt-Enter
    at POST's prompt starts it; the board's 440FX is named nowhere in the packed code."""

    def __init__(self, rom: bytes):
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=900_000_000,
            timer_irq=True,
            ram_mb=64,
            host_id=HOST_440FX,
        )
        emu.kbc_reset_in_place = True
        emu.max_seconds = 200
        screen = emu.run(0xF000, 0xFFF0)
        if PAGED_PROMPT not in screen.text():
            raise ValueError(f"the Dell System Setup did not start (stopped: {emu.stopped_reason})")
        emu.press_keys(CTRL_ALT_ENTER, paced=True)
        for _ in range(40):
            if PAGES.search(screen.text()) or emu.stopped_reason not in WAITING:
                break
            screen = emu.resume()
        if (pages := PAGES.search(screen.text())) is None:
            raise ValueError(f"the Dell System Setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.main, self.pages = emu, screen, int(pages[1])

    def screens(self) -> list[tuple[str, Screen, str]]:
        out = [("Page 1", self.main, self.emu.stopped_reason)]
        for page in range(2, self.pages + 1):
            self.emu.press_keys(ALT_P, paced=True)
            for _ in range(40):
                screen = self.emu.resume()
                if f"Page {page} of" in screen.text():
                    out.append((f"Page {page}", screen, self.emu.stopped_reason))
                    break
        return out


class DellSetup:
    def __init__(self, rom: bytes):
        if not is_dell_phoenix(rom):
            raise ValueError("not Dell's Phoenix ROM BIOS PLUS 1.10")
        # (64 MB: with less POST still sizes 64 MB and reports memory errors)
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=900_000_000,
            timer_irq=True,
            ram_mb=64,
        )
        emu.kbc_reset_in_place = True  # (the shutdown test resets the CPU)
        emu.io_reads = {0xC50: 0x00}  # the chipset heat sink is fitted (OptiPlex GX270)
        emu.max_seconds = 150
        screen = emu.run(0xF000, 0xFFF0)
        emu.press_keys(F2)
        for _ in range(40):
            if emu.stopped_reason not in WAITING or IN_SETUP in screen.text():
                break
            screen = emu.resume()
        if IN_SETUP not in screen.text():
            raise ValueError(f"the Dell System Setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 60_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

    def _keys(self, keys: list[list[int]]) -> Screen:
        screen = self.emu.screen()
        for key in keys:
            self.emu.press_keys(key, paced=True)
            screen = self.emu.resume()
        return screen

    def _scroll(self) -> tuple[list[Screen], list[str]]:
        """The list's pages (screens that together show every row) and all its rows, from
        the top with Down until the selection is on the last entry."""
        pages, rows = [self.main], list_rows(self.main)
        first, page_first = 0, 0  # (index in rows of the top row shown; of the last page's)
        shown, screen, still = rows, self.main, 0
        for _ in range(MAX_ENTRIES):
            screen = self._keys([DOWN])
            now = list_rows(screen)
            if now == shown:
                still += 1  # the selection moved within the frame (or stays on the last)
                if still > len(now):
                    break
                continue
            still = 0
            shift = next((k for k in range(1, len(now)) if now[: len(now) - k] == shown[k:]), 0)
            if not shift:
                break  # back at the top, or not a scroll
            first += shift
            rows += now[len(now) - shift :]
            shown = now
            if first - page_first >= len(now) - 1:  # a new page: the last one's rows all gone
                pages.append(screen)
                page_first = first
        if first != page_first:
            pages.append(screen)  # the list's end
        return pages, rows

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: the list's pages, then each <ENTER> entry's box."""
        pages, rows = self._scroll()
        out = [
            (f"System Setup ({n}/{len(pages)})" if len(pages) > 1 else "System Setup", page, "")
            for n, page in enumerate(pages, 1)
        ]
        entries = [row for row in rows if row]  # (the selection skips the empty rows)
        for index, entry in enumerate(entries):
            if not entry.endswith("<ENTER>"):
                continue
            self.emu.restore(self.start)
            screen = self._keys([DOWN] * index + [ENTER])
            if screen.text() != self.main.text():
                out.append((entry.split(" ..")[0].strip(), screen, self.emu.stopped_reason))
        return [(title, screen, reason or "waiting for a key") for title, screen, reason in out]
