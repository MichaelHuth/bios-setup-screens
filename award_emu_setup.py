"""
Capture the setup screens of early Award Modular BIOSes (v3.x-4.50, about 1989-1994: 286, 386
and 486 boards), whose setup code is not in the screen-script form award_setup reads, by
running the whole ROM in the x86 emulator.

Worked out on three 386 BIOSes (Award v4.20 for an MXIC cache board and a Forex 386, v4.50 for
a UMC 491 board):
- POST runs with an emulated 16 MB AT; it offers "PRESS ESC TO SKIP MEMORY TEST" and polls the
  keyboard, where ESC and the setup key are pressed (DEL; v4.20 asks for CTRL-ALT-ESC at its
  error prompt "PRESS F1 TO CONTINUE OR CTRL-ALT-ESC TO ENTER SETUP");
- v4.20 has a setup of pages ("Page 01: Status Page", PgDn to the next); F4 then F5 loads the
  page's defaults;
- v4.50 has the main menu of later Award BIOSes ("CMOS SETUP UTILITY"): the selected entry is
  drawn in another color; the menu is walked by following it with Down, LOAD SETUP DEFAULTS is
  confirmed with Y, and the entries that open pages are opened with Enter.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
import phoenix_setup
from phoenix_setup import DOWN, ENTER
from textscreen import Screen

ESC, DEL, F1 = [0x01, 0x81], [0x53, 0xD3], [0x3B, 0xBB]
F4, F5, Y = [0x3E, 0xBE], [0x3F, 0xBF], [0x15, 0x95]
UP = [0xE0, 0x48, 0xE0, 0xC8]
PGDN = [0xE0, 0x51, 0xE0, 0xD1]
PGUP = [0xE0, 0x49, 0xE0, 0xC9]
CTRL_ALT_ESC = [0x1D, 0x38, 0x01, 0x81, 0xB8, 0x9D]
CTRL_ALT_INS = [0x1D, 0x38, 0x52, 0xD2, 0xB8, 0x9D]  # (Award 3.x: Siemens-Nixdorf, DTK)
PAGE = re.compile(r"Page (\d\d): ([A-Za-z][A-Za-z ]+?)(?:\s{2,}|$)", re.M)
WAITING = ("waiting for a key", "polling the keyboard", "instruction limit reached")
MAX_PAGES = 8
POST_LIMIT = 30_000_000  # instructions per run of POST (a 386 POST needs a few million)
MAX_ENTRIES = 24
# main menu entries that only do something (no page to show)
ACTIONS = ("SAVE", "EXIT", "LOAD", "PASSWORD", "HDD", "IDE", "FORMAT", "DETECT")


def is_early_award(rom: bytes) -> bool:
    # (Award's XT BIOS of 1987-88 has no setup: Hyosung Topstar 88T, Volleman MB-088)
    if b"8088/86 Modular BIOS" in rom and b"SETUP" not in rom.upper():
        return False
    return (
        b"Award" in rom
        # (an OEM's V before the number: Hyundai Super-286E, "Version V3.13c")
        and re.search(rb"Modular BIOS (?:v|Version )V?[34]\.\d", rom) is not None
        or (b"Award Software" in rom and b"Status Page" in rom)
        # (OEM builds of 3.x name only their own version: "BIOS Version 3.20  Rev. 3.",
        # "WGM386-25/33 BIOS VER 3.04")
        or (b"Award Software" in rom and re.search(rb"BIOS (?:Version|VER) 3\.\d", rom) is not None)
    )


def cursor(screen: Screen) -> tuple[int, int, int] | None:
    """(row, first column, last column) of the selected entry: the letters in rows 2-21 in the
    rarest color there (the menu may use two colors for its entries)."""
    colors: dict[int, int] = {}
    for row in range(2, 22):
        for col in range(screen.cols):
            if chr(screen.chars[row][col]).isalpha():
                colors[screen.attrs[row][col]] = colors.get(screen.attrs[row][col], 0) + 1
    colors = {a: n for a, n in colors.items() if n >= 3}
    if len(colors) < 2:
        return None
    rare = min(colors, key=lambda a: colors[a])
    for row in range(2, 22):
        cols = [
            c
            for c in range(screen.cols)
            if chr(screen.chars[row][c]).isalpha() and screen.attrs[row][c] == rare
        ]
        if cols:
            return row, cols[0], cols[-1]
    return None


def _label(screen: Screen, row: int, col: int, end: int) -> str:
    return bytes(screen.chars[row][col : end + 1]).decode("cp437").strip()


class AwardEmu(phoenix_setup.PhoenixSetup):
    # main menu entries that load the defaults (Y to confirm)
    DEFAULTS: str | tuple[str, ...] = "LOAD SETUP DEFAULTS"
    ACTIONS = ACTIONS  # words of main menu entries that open no page

    def __init__(self, rom: bytes):
        if not is_early_award(rom):
            raise ValueError("not an early Award Modular BIOS")
        self.kind = None
        # the setup key is the one the error prompt names ("PRESS F1 TO CONTINUE OR CTRL-ALT-ESC
        # TO ENTER SETUP"); POST runs without an error on some versions, or halts before the
        # prompt (one v4.20 on a ROM checksum): then again with the key pressed already during
        # the memory test
        # (and a last run with the timer ticking: the 286 versions wait in JMP $ for IRQ 0;
        # with 4 MB, a 286 board's size, as their protected-mode test of 15 MB runs too long
        # in timer slices)
        attempts: list[tuple[list[int], bool]] = [([], False)]
        offered = ""
        while attempts:
            early, timer = attempts.pop(0)
            emu = bios_emu.BiosEmulator(
                rom,
                cmos=ami_setup.default_cmos(),
                max_instructions=POST_LIMIT * (10 if timer else 1),
                timer_irq=timer,
                ram_mb=4 if timer else 16,
            )
            # (the 286 versions return from the protected-mode memory test by a CPU
            # reset through the 8042, with a CMOS shutdown code: PETER286, BABY-286)
            emu.kbc_reset_in_place = True
            if timer:  # (timer slices are slow: MCS WGM386 needs 94 s alone, more under load)
                emu.max_seconds = 240
            screen = emu.run(0xF000, 0xFFF0)
            before = None
            for _ in range(8):
                # ("CTRL-ALT ESC FOR SETUP" in the 286 Modular BIOS 3.03HL, "CNTL-ALT-ESC"
                # and "F10 RECORDS" in the Kentech KT-0286 V3's)
                text = (
                    screen.text()
                    .replace("CTRL-ALT ESC", "CTRL-ALT-ESC")
                    .replace("CNTL-ALT-ESC", "CTRL-ALT-ESC")
                )
                offered += text
                if text == before or "HALTED" in text:  # nothing goes on any more
                    break
                before = text
                if PAGE.search(text):
                    self.kind = "pages"
                    break
                if "SAVE & EXIT SETUP" in text and cursor(screen) is not None:
                    self.kind = "menu"
                    break
                if "AWARD SOFTWARE CMOS SETUP" in text and "F10 RECORDS" in text.upper():
                    self.kind = "single"  # (the 286 Modular BIOS 3.03: one page)
                    break
                if "CMOS SETUP" in text.upper() and "SYSTEM CONFIGURATION" in text.upper():
                    self.kind = "oem"  # (OEM 3.x builds: Siemens-Nixdorf, DTK PEM-2530)
                    break
                if emu.stopped_reason not in WAITING:
                    break
                if "SKIP MEMORY TEST" in text:  # skip it (asking for setup on the way)
                    emu.press_keys(ESC + early)
                elif "CTRL-ALT-ESC" in text:
                    emu.press_keys(CTRL_ALT_ESC)
                elif "CTRL-ALT-INS" in text:
                    emu.press_keys(CTRL_ALT_INS)
                elif "DEL" in text:
                    emu.press_keys(DEL)
                else:
                    break
                screen = emu.resume()
            if self.kind:
                break
            if not early and not timer:  # again, with the key POST offered pressed during
                # the memory test
                keys = [
                    key
                    for key, name in (
                        (CTRL_ALT_ESC, "CTRL-ALT-ESC"),
                        (CTRL_ALT_INS, "CTRL-ALT-INS"),
                        (DEL, "DEL"),
                    )
                    if name in offered
                ] or [DEL]
                attempts = [(key, False) for key in keys] + [([], True)]
        if self.kind is None:
            raise ValueError(f"the early Award setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 50_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.states = {}

    def screens(self) -> list[tuple[str, Screen, str]]:
        if self.kind == "single":
            return [("CMOS SETUP", self.main, "waiting for a key")]
        if self.kind == "oem":
            return self._oem_pages()
        return self._pages() if self.kind == "pages" else self._menu()

    def _oem_pages(self) -> list[tuple[str, Screen, str]]:
        """OEM 3.x: "CMOS Setup" over the page's name ("System Configuration", "Additional
        System Options"); PgDn (PgUp where the page says so) to the next, until the first
        comes again."""
        out: list[tuple[str, Screen, str]] = []
        key = PGUP if "PgUp for additional" in self.main.text() else PGDN
        screen, reason = self.main, "waiting for a key"
        for pages in range(1, MAX_PAGES + 1):
            lines = [line.strip() for line in screen.text().split("\n")]
            at = next((i for i, line in enumerate(lines) if line.upper() == "CMOS SETUP"), -1)
            title = lines[at + 1] if 0 <= at < len(lines) - 1 else ""
            if not title or title in (t for t, _, _ in out):
                break
            out.append((title, screen, reason))
            screen, reason = self.capture(0, key * pages)
        return out

    def _pages(self) -> list[tuple[str, Screen, str]]:
        """v4.20: each page with its defaults loaded (F4, F5), PgDn to the next."""
        out: list[tuple[str, Screen, str]] = []
        keys: list[int] = []
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            screen, reason = self.capture(0, keys + F4 + F5)
            m = PAGE.search(screen.text())
            if not m or m.group(1) in seen:
                break
            seen.add(m.group(1))
            out.append((m.group(2).strip(), screen, reason))
            keys = keys + F4 + F5 + PGDN
        return out

    def _menu(self) -> list[tuple[str, Screen, str]]:
        """v4.50: the main menu; the defaults entry confirmed, then each entry with a page."""
        first = cursor(self.main)
        entries = []  # (downs, label)
        for downs in range(MAX_ENTRIES):
            here = self.main if not downs else self.capture(0, DOWN * downs)[0]
            at = cursor(here)
            if at is None or (downs and at == first):
                break
            entries.append((downs, _label(here, *at)))
        prefix = []
        for downs, label in entries:  # the defaults first, as in the later Award setups
            if label.upper().startswith(self.DEFAULTS):
                prefix = DOWN * downs + ENTER + Y + ENTER + UP * downs
        main, reason = self.capture(0, prefix) if prefix else (self.main, "waiting for a key")
        out = [("MAIN MENU", main, reason)]
        for downs, label in entries:
            if not label or any(word in label.upper() for word in self.ACTIONS):
                continue
            page, reason = self.capture(0, prefix + DOWN * downs + ENTER)
            if page.text() != main.text():
                out.append((label, page, reason))
        return out
