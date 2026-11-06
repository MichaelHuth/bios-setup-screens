"""
Capture the setup screens of Phoenix BIOSes before PhoenixBIOS 4.0 (PhoenixBIOS 1.x, "ROM
BIOS PLUS", about 1988-1994: "Phoenix SETUP Utility") by running the whole ROM in the x86
emulator.

Worked out on an ALR PhoenixBIOS 1.02.07m (Phoenix SETUP Utility 1.00.01):
- POST returns from protected mode by resetting the CPU through the keyboard controller (CMOS
  shutdown code), so the emulator resets the CPU in place;
- with an empty CMOS POST stops at "Press the F1 key to continue, F2 to run the setup
  utility"; F2 starts setup, which first lists the errors it corrected ("<Press any Key>");
- the setup has pages ("Page 1 of 4", a "** title **" line), PgDn goes to the next.

Phoenix 80386 ROM BIOS PLUS 1.10 (Micronics G19-2W, "System Configuration Setup 4.03") has
one main page instead, and PgUp switches to the chipset's "special options" page and back.
Others (DTK PEM, 1.10.01) have only the main page. Its POST waits for the RTC's
update-in-progress bit and writes the setup with INT 10h AH=13h,
CR LF inside the strings.
"""

from __future__ import annotations

import re

import ami_setup
import bios_emu
import phoenix_setup
from textscreen import Screen

F1, F2, SPACE = [0x3B, 0xBB], [0x3C, 0xBC], [0x39, 0xB9]
CTRL_ALT_S = [0x1D, 0x38, 0x1F, 0x9F, 0xB8, 0x9D]
ALT_ESC = [0x1D, 0x38, 0x01, 0x81, 0xB8, 0x9D]  # Ctrl-Alt-Esc (Commodore PC 50 says so)
PGDN = [0xE0, 0x51, 0xE0, 0xD1]
PGUP = [0x49, 0xC9]
# 1.10: a main page and the pages its frame names ("PgUp for special options"; ALR's
# "PgUp for EMS and RAM/ROM SWAP options" and "PgDn for SOFT SWITCH options")
HINT = r" for (.{1,40}?) options"
SPECIAL = "PgUp for special options"
ONE_PAGE = "System Configuration Setup"  # 1.10 without special options: just this page
PAGE = re.compile(r"Page (\d+) of (\d+)")
# a setup page that names itself on a line of its own ("COMMODORE SETUP UTILITY") or in a
# box next to its values ("D386WB Configuration Utility"); a POST prompt does neither
TITLE_LINE = re.compile(
    r"(?m)^[\s║]*[A-Za-z][A-Za-z0-9 ./-]*\b(SETUP|Configuration) (UTILITY|Utility)[\s║]*$"
)
BOX_TITLE = re.compile(r"║[^║\n]*\b(SETUP|Configuration) (UTILITY|Utility)[^║\n]*║")
TITLE = re.compile(r"\*\* *(.+?) *\*\*")
WAITING = ("waiting for a key", "polling the keyboard")
MAX_PAGES = 12


# what later Phoenix families (SecureCore, Dell's own, the VGA BIOS) say of themselves
NOT_OLD = (b"SecureCore", b"mrcHostSetup", b"Enhanced VGA BIOS", b"Copyright 1988-200")


# what only a setup page in the ROM prints
MENU_WORDS = re.compile(
    rb"SETUP UTILITY|Configuration Setup|F1 for help|F10 to exit|Boot Sequence|Esc to reboot"
    rb"|to run the setup|to enter setup|Page [0-9]",
    re.I,
)


def setup_on_diskette(rom: bytes) -> bool:
    """Phoenix's 286 and early 386 ROM BIOS: POST asks to run SETUP, a program on a diskette,
    and the ROM holds no menu (Essex MB286VE, NEC 819-074, FT-286-12)."""
    return (
        len(rom) <= 0x20000
        and b"Phoenix" in rom
        and b"please run SETUP program" in rom
        and not MENU_WORDS.search(rom)
    )


def is_old_phoenix(rom: bytes) -> bool:
    return (
        b"Phoenix Technologies" in rom
        and not any(s in rom for s in NOT_OLD)
        and b"SETUP" in rom.upper()
        and not setup_on_diskette(rom)
        and not phoenix_setup.is_phoenix_setup(rom)
    )


def _images(rom: bytes) -> list[bytes]:
    """The image as it is, then its other 64 KB blocks that end with a far jump into segment
    F000, from the end: a dump whose last block is a flash boot block or has no reset
    vector has its BIOS in another one (Dell Dimension XPS, Emerson XT). When the image's own
    end has no reset vector, the whole image turned so that such a block is last comes first
    of those: its halves were stored the other way round (Intel's 1992 Premiere update, whose
    E000 half the BIOS needs too)."""
    out = [rom]
    ends_with_vector = rom[-16] == 0xEA and rom[-13:-11] == b"\x00\xf0"
    for end in range(len(rom) // 0x10000 * 0x10000 - 0x10000, 0, -0x10000):
        v = rom[end - 16 : end - 11]
        if v[0] == 0xEA and v[3:5] == b"\x00\xf0":
            if not ends_with_vector and len(out) == 1:
                out.append(rom[end:] + rom[:end])
            out.append(rom[end - 0x10000 : end])
    return out


def in_setup(text: str) -> bool:
    return (
        bool(PAGE.search(text))
        or SPECIAL in text
        or ONE_PAGE in text
        or bool(TITLE_LINE.search(text))
        or bool(BOX_TITLE.search(text))
    )


def frame_title(screen: Screen) -> str:
    """1.10: the page's name on the line below "Phoenix Technologies Ltd." (version left out)."""
    lines = [l.strip(" ║") for l in screen.text().split("\n")]
    for i, line in enumerate(lines[:-1]):
        if "Phoenix Technologies" in line:
            return re.sub(r"\s+[\d.]+(\s+\d+)?$", "", lines[i + 1].strip())
    for line in lines:
        if TITLE_LINE.match(line):
            return line.strip(" ║")
    if m := BOX_TITLE.search(screen.text()):
        return m.group(0).strip("║ ")
    return ""


class PhoenixOld:
    def __init__(self, rom: bytes):
        if not is_old_phoenix(rom):
            raise ValueError("not a Phoenix BIOS before 4.0")
        screen: Screen | None = None
        emu: bios_emu.BiosEmulator | None = None
        spoilt = bytearray(ami_setup.default_cmos())
        spoilt[0x2E] ^= 0xFF  # a bad CMOS checksum: POST stops at its error and offers setup
        attempts = [
            (False, ami_setup.default_cmos()),
            (True, ami_setup.default_cmos()),
            (False, bytes(spoilt)),
            (True, bytes(spoilt)),
            # (bytes 10h-7Fh reading FFh, its configuration invalid: Intel 301 v1.10)
            (False, ami_setup.default_cmos()[:0x10] + b"\xff" * 0x70),
        ]
        for image in _images(rom):  # (the image as it is first)
            booted = False
            for k, (timer, cmos) in enumerate(attempts):  # some POSTs only go on with the timer
                # interrupt running; one that boots without an error pause is tried again with a
                # bad CMOS checksum (Chaintech ELT-286B 120GM)
                if k >= 2 and not booted:
                    break
                # (4 MB, as on boards of that time: POST's memory test of 16 MB took 40 s on the
                # Chaintech ELT-286B and ran out of time under load)
                emu = bios_emu.BiosEmulator(
                    image, cmos=cmos, max_instructions=100_000_000, timer_irq=timer, ram_mb=4
                )
                emu.kbc_reset_in_place = True  # back from protected mode through a CPU reset
                emu.dma_pages_ext = True  # (the 4.03 M1 POST tests 40xh/4Cxh as page ports)
                emu.max_seconds = 40
                screen = emu.run(0xF000, 0xFFF0)
                if (
                    emu.stopped_reason.startswith("booting")
                    and "F2 to run the setup" in screen.text()
                ):
                    # POST offered F2 while it ran and then booted (4.03 M1): again, with
                    # F2 pressed during POST (F1, its continue key, would boot)
                    emu = bios_emu.BiosEmulator(
                        image, cmos=cmos, max_instructions=100_000_000, timer_irq=timer, ram_mb=4
                    )
                    emu.kbc_reset_in_place, emu.dma_pages_ext = True, True
                    emu.max_seconds = 40
                    emu.press_keys(F2, paced=True)
                    screen = emu.run(0xF000, 0xFFF0)
                for _ in range(6):
                    text = screen.text()
                    if "<Hit any Key>" in text and emu.stopped_reason in WAITING:
                        emu.press_keys(SPACE, paced=True)  # SETUP's corrections (J-Bond)
                        screen = emu.resume()
                        continue
                    if in_setup(text) or emu.stopped_reason not in WAITING:
                        break
                    if "any key" in text.lower():  # the corrected errors (ALR: no word of
                        # setup on that page)
                        emu.press_keys(SPACE, paced=True)
                    elif "[ctrl][alt][s]" in text.lower().replace(" ", ""):
                        emu.press_keys(CTRL_ALT_S, paced=True)  # (J-Bond E450C-D, EISA)
                    elif "ctrl-alt-esc" in text.lower().replace(" ", ""):
                        emu.press_keys(ALT_ESC, paced=True)  # Commodore PC 50
                    elif (
                        "F2" in text
                    ):  # "Press the F1 key to continue, F2 to run the setup utility"
                        emu.press_keys(F2, paced=True)
                    elif "to enter setup press" in text.lower() and "[f1]" in text.lower().replace(
                        " ", ""
                    ):
                        emu.press_keys(F1, paced=True)  # DEC DECpc 400 MT (Esc goes on)
                    else:
                        break
                    screen = emu.resume()
                if in_setup(screen.text()):
                    break
                booted = booted or emu.stopped_reason.startswith("booting")
            if screen is not None and in_setup(screen.text()):
                break
        assert screen is not None and emu is not None
        if not in_setup(screen.text()):
            raise ValueError(
                f"the Phoenix SETUP Utility did not start (stopped: {emu.stopped_reason})"
            )
        emu.max_instructions = 30_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

    def capture(self, pages: int) -> tuple[Screen, str]:
        if not pages:
            return self.main, "waiting for a key"
        emu = self.emu
        emu.restore(self.start)
        emu.press_keys(PGDN * pages, paced=True)
        return emu.resume(), emu.stopped_reason

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(page title, screen, stop reason)], from page 1 with PgDn to the last."""
        if not PAGE.search(self.main.text()):  # 1.10: the main page and those it names
            out = [(frame_title(self.main) or "Main", self.main, "waiting for a key")]
            text = self.main.text()
            seen, titles = {text}, {frame_title(self.main)}
            for key, word in ((PGUP, "PgUp"), (PGDN, "PgDn")):
                hint = re.search(word + HINT, text)
                if not hint:
                    continue
                for n in range(1, MAX_PAGES):  # (the pages form a ring: ALR)
                    self.emu.restore(self.start)
                    self.emu.press_keys(key * n, paced=True)
                    screen = self.emu.resume()
                    framed = frame_title(screen)
                    if screen.text() in seen or (framed and framed in titles):
                        break
                    seen.add(screen.text())
                    titles.add(framed)
                    name = framed or f"{hint.group(1)} options".title()
                    out.append((name, screen, self.emu.stopped_reason))
            return out
        out, seen = [], set()
        for n in range(MAX_PAGES):
            screen, reason = self.capture(n)
            m = PAGE.search(screen.text())
            if not m or m.group(1) in seen:
                break
            seen.add(m.group(1))
            title = TITLE.search(screen.text())
            out.append((title.group(1) if title else f"Page {m.group(1)}", screen, reason))
            if m.group(1) == m.group(2):
                break
        return out
