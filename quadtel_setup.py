"""
Capture the setup screens of Quadtel's BIOS of the early 1990s ("System SETUP Version 1.xx",
pages of options chosen with PgDn/PgUp) by running the whole ROM in the x86 emulator.

Worked out on an ADDX Systemes board (Quadtel BIOS 7.71, 128 KB with a Cirrus VGA BIOS):
- POST draws the board maker's logo in 640x480 graphics (INT 10h pixel functions) and tests
  the timer interrupt and the three PIT channels, so it runs with the timer interrupt on; it
  returns from protected mode by a CPU reset;
- ESC skips the memory test;
- setup is entered from the bootstrap (INT 19h): with no disk to boot from POST offers
  "F1 ==> Boot , F2 ==> SETUP" (F2 typed earlier is only kept for that moment);
- the setup asks for its language first (English is the first entry) and lists the errors
  POST found ("[Enter] to continue"), then shows its first page; it waits for keys while
  watching the RTC's periodic flag for its clock.
The 3.0x generation (Mecer B639, HT18C 386SX 3.06.01) offers setup as
"Press <F1> to resume, <F2> to Setup", draws its frames without a ►title◄ marker and
chooses its pages from a menu; some images' reset vector jumps outside the ROM, and POST
is started at its boot entry instead.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
from textscreen import Screen

TITLE = b"System SETUP      Version"
F2, ENTER, ESC = [0x3C, 0xBC], [0x1C, 0x9C], [0x01, 0x81]
PGDN = [0x51, 0xD1]
DOWN = [0x50, 0xD0]
MENU_ITEMS = 6
# cli; mov al,0BFh; out 70h,al; jmp ...; in al,64h; test al,4: the 3.0x boot entry
BOOT_ENTRY = re.compile(rb"\xfa\xb0\xbf\xe6\x70\xe9..\xe4\x64\xa8\x04", re.S)
FRAME = set("█▀▄─│┌┐└┘├┤┬┴┼═║╔╗╚╝╠╣╦╩╬░▒▓ ")
MAX_PAGES = 12
WAITING = ("waiting for a key", "polling the keyboard")


def is_quadtel(rom: bytes) -> bool:
    if b"Quadtel" not in rom:
        return False
    if TITLE in rom and b"F2 ==> SETUP" in rom:
        return True
    return b"BIOS Version 3.0" in rom and BOOT_ENTRY.search(rom) is not None


def page_title(screen: Screen) -> str:
    """The page's name in its frame (e.g. ►STANDARD OPTIONS◄)."""
    m = re.search(r"►\s*(.+?)\s*◄", screen.text())
    if m:
        return m.group(1).strip()
    for line in screen.text().split("\n"):  # (3.0x: the first line with a word)
        core = " ".join("".join(" " if ch in FRAME else ch for ch in line).split())
        core = re.split(r"[\s,-]*Copyright", core)[0].rstrip(" :")
        if len(core) >= 3 and any(ch.isalpha() for ch in core):
            return core[:40]
    return ""


class QuadtelSetup:
    def __init__(self, rom: bytes):
        if not is_quadtel(rom):
            raise ValueError("not a Quadtel BIOS with its System SETUP")
        self.menu = TITLE not in rom
        if len(rom) >= 16 and rom[-16] == 0xEA and int.from_bytes(rom[-13:-11], "little") < 0xC000:
            if (m := BOOT_ENTRY.search(rom)) is not None:  # (a vector outside the ROM)
                off = (m.start() - len(rom)) & 0xFFFF
                rom = rom[:-15] + bytes([off & 0xFF, off >> 8, 0x00, 0xF0]) + rom[-11:]
        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=200_000_000, timer_irq=True
        )
        emu.kbc_reset_in_place = True  # (POST returns from protected mode by a CPU reset)
        emu.boot_without_disk = True  # no system disk: POST offers F2 for setup
        emu.press_keys(ESC * 3)  # skip the memory test
        screen = emu.run(0xF000, 0xFFF0)
        if emu.stopped_reason not in WAITING:
            raise ValueError(f"Quadtel POST did not offer setup (stopped: {emu.stopped_reason})")
        emu.max_instructions = 60_000_000
        emu.press_keys(F2, paced=True)
        screen = emu.resume()
        for _ in range(4):  # the language, then the errors POST found
            if page_title(screen) or emu.stopped_reason not in WAITING:
                break
            emu.press_keys(ENTER, paced=True)
            screen = emu.resume()
        if not page_title(screen):
            raise ValueError(f"the Quadtel setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

    def capture(self, pages: int) -> tuple[Screen, str]:
        emu = self.emu
        if not pages:
            return self.main, "waiting for a key"
        emu.restore(self.start)
        emu.press_keys(PGDN * pages, paced=True)
        return emu.resume(), emu.stopped_reason

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(page title, screen, stop reason)] for every page, PgDn after PgDn (or for
        each item of the 3.0x menu)."""
        out, seen = [], set()
        if self.menu:
            for n in range(MENU_ITEMS):
                self.emu.restore(self.start)
                self.emu.press_keys(DOWN * n + ENTER, paced=True)
                screen = self.emu.resume()
                title = page_title(screen)
                if not title or title in seen:
                    break
                seen.add(title)
                out.append((title.title(), screen, self.emu.stopped_reason))
            return out
        for n in range(MAX_PAGES):
            screen, reason = self.capture(n)
            title = page_title(screen)
            if not title or title in seen:
                break
            seen.add(title)
            out.append((title.title(), screen, reason))
        return out
