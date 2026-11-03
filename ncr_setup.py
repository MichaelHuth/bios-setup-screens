"""
Capture the setup screens of NCR's version of IBM's AT ROM BIOS (NCR 3230, ROM BIOS 01.00.00 of
1992 and 02.08.00 of 1997: "Setup, Version x (3230)") by running the whole ROM in the x86
emulator.

How it works:
- POST's timer test (F280C) loads 0FF00h into PIT channel 2 and wants it to run out after
  9000h-0FE00h polls of 24 emulated cycles: with the emulator's 33 MHz the count never runs
  out; the emulator's PIT runs as for a 10 MHz CPU instead (POST still reports 25 MHz);
- POST writes CMOS 0Fh and resets the CPU through the 8042 before it prints anything, and
  waits at HLT for the timer interrupt;
- with an empty CMOS it stops at "Press <F1> for SETUP or <ENTER> to go on"; F1 starts the
  setup's first screen, F2 its second ("Software Controlled Registers and Memory Setup").

NCR 3315 (Setup 5.2.2) and an NCR 4.7 of 1989: the 3315's channel-2 test
wants the PIT as for a 9 MHz CPU (10 MHz is just over its window, the 3230 passes either
way); with 16 MB the extended-memory test outlasts the time limit, so the emulator has 2 MB,
as an AT of that time; a latch of PIT channel 0 advances it by at least 0Ch, not 25h (the
3315's channel-0 test); the 3315's second page is "Summit Chip Set Feature Control".
"""

from __future__ import annotations

import ami_setup
import bios_emu
from textscreen import Screen

F1, F2 = [0x3B, 0xBB], [0x3C, 0xBC]
PROMPT = "Press <F1> for SETUP"
EARLY = "PRESS <F1> IF HARDWARE SETUP IS DESIRED"
IN_SETUP = "Setup, Version"
PAGE2 = "Software Controlled Registers and Memory Setup"
CHIPSET = "Chip Set Feature Control"  # (the 3315's: also named in page 1's key line)
VENDOR = b"NCR'S VERSION IBM CORP. AT ROM"


def is_ncr_at(rom: bytes) -> bool:
    return VENDOR in rom and PROMPT.encode() in rom


class NcrSetup:
    def __init__(self, rom: bytes):
        if not is_ncr_at(rom):
            raise ValueError("not NCR's version of IBM's AT ROM BIOS")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            ram_mb=2,
            max_instructions=600_000_000,
            timer_irq=True,
        )
        emu.pit_ticks_per_cycle = 1.193182 / 9  # (the timer test, see above)
        emu.pit0_latch_floor = 0x0C  # (the 3315's channel-0 test)
        emu.kbc_reset_in_place = True
        emu.max_seconds = 240  # (the 1997 image's POST: about 170 s)
        # F1 as soon as POST offers it (with a valid CMOS it boots without the prompt)
        emu.press_keys(F1, when_text=EARLY)
        screen = emu.run(0xF000, 0xFFF0)
        if IN_SETUP not in screen.text() and PROMPT in screen.text():
            emu.press_keys(F1, paced=True)
            screen = emu.resume()
        emu.max_instructions = 60_000_000
        if IN_SETUP not in screen.text():
            raise ValueError(f"the NCR setup did not start (stopped: {emu.stopped_reason})")
        self.emu, self.main = emu, screen

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: the first screen, then F2's."""
        out = [("Setup", self.main, "waiting for a key")]
        self.emu.press_keys(F2, paced=True)
        screen = self.emu.resume()
        text = screen.text()
        if PAGE2 in text:
            out.append((PAGE2, screen, self.emu.stopped_reason))
        elif text != self.main.text() and "Summit " + CHIPSET in text:
            out.append(("Summit " + CHIPSET, screen, self.emu.stopped_reason))
        return out
