"""
Capture the setup screens of Acer's own BIOS of the mid 1990s ("BIOS Utility" with "Basic
System Configuration", "Advanced System Configuration", ...) by running the whole ROM in the
x86 emulator.

Worked out on an Acer V30L (BIOS V2.0, ACR9AE00, 1995):
- POST stops at its configuration errors with "Press Ctrl_Alt_Esc key to enter SETUP or F1
  key to continue..."; Ctrl-Alt-Esc is caught in INT 15h AH=4Fh (keyboard intercept) and
  calls the setup, which lives in E800;
- the setup asks for the password first when bit 2 of the 8042's input port (command C0h,
  a jumper on the board) is set: the emulator answers with it clear;
- the setup first lists the POST errors it has configured ("Press any key to continue"),
  then shows its main menu: entries chosen with Down and Enter, Esc back; the pages of an
  entry ("Page 1/2") turned with PgDn;
- "Load Setup Default Settings" (confirmed with Enter, [Yes] is preselected) loads the
  defaults before the pages are captured.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
from textscreen import Screen

CTRL_ALT_ESC = [0x1D, 0x38, 0x01, 0x81, 0xB8, 0x9D]
SPACE, ENTER, ESC = [0x39, 0xB9], [0x1C, 0x9C], [0x01, 0x81]
DOWN, UP, PGDN = [0x50, 0xD0], [0x48, 0xC8], [0x51, 0xD1]
LOAD_DEFAULTS = "Load Setup Default Settings"
WAITING = ("waiting for a key", "polling the keyboard")
MAX_PAGES = 8


def is_acer(rom: bytes) -> bool:
    # (or Acer's module records A!00 and A!F0: images whose texts are packed, V35ND1S1)
    # (or only its prompt in the clear: V50LC, with its menus packed)
    return (
        b"Acer Incorporated" in rom
        and (b"Ctrl_Alt_Esc" in rom or bios_emu.ALI_P54C in rom)  # (R02-E1: both packed)
    ) or (
        b"ACER" in rom
        and (
            b"BIOS Utility" in rom
            and b"Basic System Configuration" in rom
            or b"A!00" in rom
            and b"A!F0" in rom
        )
    )


def page_title(screen: Screen) -> tuple[str, int, int]:
    """(title, page, pages) from the frame at the top, e.g. ("Basic System Configuration", 1, 2)."""
    for line in screen.text().split("\n")[:3]:
        m = re.search(r"│\s*(.+?)\s{2,}Page (\d+)/(\d+)", line)
        if m:
            return m.group(1).strip(), int(m.group(2)), int(m.group(3))
        m = re.search(r"│\s*(.+?)\s{2,}Page (\d+)\s*│", line)  # (no count: A1 R2.6)
        if m:
            return m.group(1).strip(), int(m.group(2)), MAX_PAGES
        m = re.search(r"│\s*(\S.*?)\s*│", line)
        if m and m.group(1) != "BIOS Utility":
            return m.group(1).strip(), 1, 1
    return "", 0, 0


def menu_entries(screen: Screen) -> list[str]:
    """The main menu's entries: the lines between the title frame and the help frame."""
    lines = screen.text().split("\n")
    start = next((i + 1 for i, line in enumerate(lines) if "╘" in line), len(lines))
    out = []
    for line in lines[start:]:
        if "╒" in line or "▄" in line:
            break
        if line.strip():
            out.append(line.strip())
    return out


HOST_430FX = 0x122D  # (any host bridge of the kind will do: the 440BX's works as well)


class AcerSetup:
    def __init__(self, rom: bytes):
        if not is_acer(rom):
            raise ValueError("not an Acer BIOS with its BIOS Utility")
        try:
            emu, screen, entries = self._start(rom, b"")
        except ValueError as e:
            # (V65: Ctrl-Alt-Esc jumps to a setup POST could not unpack from its other bank)
            if len(rom) == 0x40000 and "setup did not start" in str(e):
                emu, screen, entries = self._start(rom, bytes(rom[:0x20000]))
            elif "instruction limit" in str(e):  # (V12C: its IDs are not in the ROM)
                emu, screen, entries = self._start(rom, b"", HOST_430FX)
            else:
                raise
        self.emu = emu
        if LOAD_DEFAULTS in entries:  # (not on the Cx486 of A1 R2.6: two entries only)
            n = entries.index(LOAD_DEFAULTS)
            self._keys([DOWN] * n + [ENTER, ENTER])  # [Yes]
            screen = self._keys([UP] * n)  # back to the first entry
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.entries = [e for e in entries if e != LOAD_DEFAULTS]

    @staticmethod
    def _start(
        rom: bytes, flash_low: bytes, host_id: int = 0
    ) -> tuple[bios_emu.BiosEmulator, Screen, list[str]]:
        """POST up to the setup's main menu: (emulator, its screen, the menu's entries)."""
        # (V35ND1S1's memory test runs in protected mode: about 1 G instructions, 40 s)
        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=1_500_000_000, host_id=host_id
        )
        emu.kbc_reset_in_place = True  # (POST returns from protected mode by a CPU reset)
        emu.keep_rom = True  # (the ROM stays ROM when the bot gives up on its PAM)
        emu.flash_low = flash_low
        emu.kbc_input_port = 0xBB  # the password jumper open
        emu.cf9_resets_in_place = 4  # (the first boot sets CMOS 8Fh and resets)
        # ALi M1541 PM2C/GCKCTL at their reset value 00h: POST reads bit 1 of EBh into the
        # flag that lets the setup module start (V35ND1S1)
        emu.io_reads = {0xEA: 0x00, 0xEB: 0x00}
        screen = emu.run(0xF000, 0xFFF0)
        if emu.stopped_reason not in WAITING or "Ctrl_Alt_Esc" not in screen.text():
            raise ValueError(f"Acer POST did not offer setup (stopped: {emu.stopped_reason})")
        emu.max_instructions = 60_000_000
        emu.press_keys(CTRL_ALT_ESC)  # caught by the keyboard interrupt, not read as a key
        screen = emu.resume()
        if "Ctrl_Alt_Esc" in screen.text():  # (V65: Alt lost while it set the keyboard's LEDs)
            emu.press_keys(CTRL_ALT_ESC, paced=True)
            screen = emu.resume()
        if "Press any key to continue" in screen.text():  # the errors POST configured
            emu.press_keys(SPACE, paced=True)
            screen = emu.resume()
        entries = menu_entries(screen)
        if "BIOS Utility" not in screen.text() or not entries:
            raise ValueError(f"the Acer setup did not start (stopped: {emu.stopped_reason})")
        return emu, screen, entries

    def _keys(self, keys: list[list[int]]) -> Screen:
        """Each key on its own, after the setup has looked for the one before (keys typed
        together are lost: the setup reads the next one only after redrawing)."""
        screen = self.emu.screen()
        for key in keys:
            self.emu.press_keys(key, paced=True)
            screen = self.emu.resume()
        return screen

    def capture(self, path: list[list[int]], pages: int) -> tuple[Screen, str]:
        self.emu.restore(self.start)
        screen = self._keys(path + [PGDN] * pages)
        return screen, self.emu.stopped_reason

    def walk(self, path: list[list[int]]) -> list[tuple[str, Screen, str]]:
        """The pages behind an entry; a menu (Cx486 of A1 R2.6: "System Configuration", whose
        help line says "= Select") with the pages behind each of its entries."""
        out: list[tuple[str, Screen, str]] = []
        for page in range(MAX_PAGES):
            screen, reason = self.capture(path, page)
            title, number, count = page_title(screen)
            if not title or number != page + 1:
                break
            label = f"{title} ({number}/{count})" if count not in (1, MAX_PAGES) else title
            out.append((f"{title} ({number})" if count == MAX_PAGES else label, screen, reason))
            if not page and "= Select" in screen.text():
                for sub in range(len(menu_entries(screen))):
                    out += self.walk(path + [DOWN] * sub + [ENTER])
                break
            if number >= count:
                break
        return out

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: the main menu, then each entry's pages."""
        out = [("Main Menu", self.main, "waiting for a key")]
        for index in range(len(self.entries)):
            out += self.walk([DOWN] * index + [ENTER])
        return out
