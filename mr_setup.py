"""
Capture the setup screens of MR BIOS (Microid Research, 1990s) by running the whole ROM in the
x86 emulator, with timer and RTC interrupts (its POST tests them).

With an empty CMOS, POST reports "Battery Backed Memory (CMOS) is Corrupt", waits for a key and
then starts the Setup Utility on its own (with valid CMOS a person presses ESC during POST).
The setup program is unpacked from the ROM and entered through INT C0h. Its menu bar has two
halves (Summary ... Ports, More---> Security ... Advanced); the right arrow moves to the next
page. As the CMOS was empty, the values shown are the BIOS's own defaults.
Reverse-engineered on a Shuttle HOT-555 BIOS (MR BIOS 3.46, Intel 430VX).
"""

from __future__ import annotations

import collections

import ami_setup
import bios_emu
from textscreen import Screen, cp437_to_unicode

RIGHT = [0xE0, 0x4D, 0xE0, 0xCD]
SPACE = [0x39, 0xB9]
ESC = [0x01, 0x81]
MAX_PAGES = 20


def is_mr_bios(rom: bytes) -> bool:
    return b"Microid Research" in rom or b"MR BIOS" in rom


def selected_item(screen: Screen) -> str:
    """The highlighted entry of the menu bar (row 3)."""
    attrs = screen.attrs[3]
    common = collections.Counter(attrs).most_common(1)[0][0]
    text = cp437_to_unicode(bytes(c for c, a in zip(screen.chars[3], attrs) if a != common))
    return text.strip(" ║")


class MrBios:
    def __init__(self, rom: bytes):
        if not is_mr_bios(rom):
            raise ValueError("not an MR BIOS image")
        cmos = ami_setup.default_cmos()
        for _ in range(3):  # a reboot during POST (OPTi 895 board): again with the CMOS left
            emu = bios_emu.BiosEmulator(
                rom, cmos=cmos, max_instructions=300_000_000, timer_irq=True
            )
            emu.kbc_reset_in_place = True  # POST restarts itself through the 8042
            emu.protect_socket = True
            emu._protect()
            # the CPU's signature in EDX after power-on too (as after its resets): MR BIOS
            # V1.41 keeps it in ports 85h/86h, and its restart goes wrong with 0
            emu.uc.reg_write(bios_emu.UC_X86_REG_EDX, 0x0435)
            screen = emu.run(0xF000, 0xFFF0)
            if emu.stopped_reason != "reset":
                break
            cmos = bytes(emu.cmos)
        if "Press Any Key" in screen.text():  # empty CMOS: a key starts the Setup Utility
            emu.press_keys(SPACE, paced=True)
            screen = emu.resume()
        if "Record and Exit" not in screen.text():
            raise ValueError(f"MR BIOS setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 60_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

    def capture(self, rights: int) -> tuple[Screen, str]:
        emu = self.emu
        emu.restore(self.start)
        if rights:
            emu.press_keys(RIGHT * rights, paced=True)
            return emu.resume(), emu.stopped_reason
        return self.main, "waiting for a key"

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(page title, screen, stop reason)] for every page of the menu bar."""
        out, seen = [], set()
        for n in range(MAX_PAGES):
            screen, reason = self.capture(n)
            title = selected_item(screen)
            if not title or title in seen:
                break
            seen.add(title)
            out.append((title, screen, reason))
        return out
