"""
Capture the question-and-answer CMOS setup of AMI's 286 BIOS of about 1988 with built-in
diagnostics ("286-ROM DIAGNOSTICS", "SETUP or DIAGS (1/2)?") by running the whole ROM in the
x86 emulator.

Worked out on an MG 12 MHz 286 board (VLSI, AMI 09/25/88, ID D286-9987-092588-KH):
- POST stops at its errors with "RUN SETUP UTILITY / Press <F1> to RESUME"; F1 goes on;
- it then asks "Want to run SETUP or DIAGS (Y/N)?" - Y, Enter - and "SETUP or DIAGS (1/2)?"
  - 1, Enter;
- the setup is one screen of questions ("Enter new date (MM-DD-YYYY)?", screen width ...),
  each answered with Enter (keeping the value shown), up to "Are these options correct
  (Y/N)?".
This setup has no entry point of the kind the classic AMI reader (ami_setup) looks for.
"""

from __future__ import annotations

import ami_setup
import bios_emu
from textscreen import Screen

F1, ENTER = [0x3B, 0xBB], [0x1C, 0x9C]
Y, ONE = [0x15, 0x95], [0x02, 0x82]
WAITING = ("waiting for a key", "polling the keyboard")
MAX_KEYS = 40


def is_ami_qa_setup(rom: bytes) -> bool:
    return b"SETUP or DIAGS (1/2)?" in rom and b"Are these options correct" in rom


class AmiQaSetup:
    def __init__(self, rom: bytes):
        if not is_ami_qa_setup(rom):
            raise ValueError("not an AMI BIOS with the question-and-answer CMOS setup")
        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=100_000_000, ram_mb=4
        )
        emu.kbc_reset_in_place = True
        screen = emu.run(0xF000, 0xFFF0)
        for _ in range(MAX_KEYS):
            text = screen.text()  # (its last line is the BIOS ID before setup)
            if "Are these options correct" in text or emu.stopped_reason not in WAITING:
                break
            if "C M O S     S E T U P" in text:
                keys = [ENTER]  # a question: the value shown is kept
            elif "(1/2)?" in text:
                keys = [ONE, ENTER]
            elif "(Y/N)?" in text:
                keys = [Y, ENTER]
            elif "to RESUME" in text:
                keys = [F1]
            else:
                keys = [ENTER]
            for key in keys:  # (one at a time: typed together, the Enter got lost)
                emu.press_keys(key)
                screen = emu.resume()
        if "C M O S     S E T U P" not in screen.text():
            raise ValueError(f"the AMI CMOS setup did not start (stopped: {emu.stopped_reason})")
        self.screen = screen

    def screens(self) -> list[tuple[str, Screen, str]]:
        return [("CMOS Setup", self.screen, "waiting for a key")]
