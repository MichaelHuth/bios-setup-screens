"""
Capture the setup screens of AMIBIOS with the text-mode Simple Setup / Hi-Flex setup (AMIBIOS
core 07/15/95, about 1996-99: "AMIBIOS SIMPLE SETUP UTILITY", "AMIBIOS HIFLEX SETUP UTILITY")
by running the whole ROM in the x86 emulator.

Worked out on a PCChips M572 BIOS (02/24/1999, Intel 430TX + PIIX4):
- the image is in AMI's compressed module format ("AMIBIOSC0626"); the chipset's PCI IDs are
  in the modules (passed to the emulator as hints);
- with an empty CMOS POST goes into setup by itself (otherwise DEL is pressed);
- the main menu has the layout of Award's (two columns, the selected entry in another color)
  and is walked the same way (award_emu_setup): Down to each entry, Load Optimal Settings
  confirmed with Y, Enter on the entries that open pages.
"""

from __future__ import annotations

import time

import ami
import ami_setup
import award_emu_setup
import bios_emu

# (Aaeon SBC-570's says "HIFLEX SETUP UTILTY")
# (Biostar MB-8500TUR, AMIBIOS 0622: "AMIBIOS SETUP - BIOS SETUP UTILITIES", the second part
# a string of its own after the \H of the title line)
TITLES = (
    b"SIMPLE SETUP UTILITY",
    b"HIFLEX SETUP UTILITY",
    b"HIFLEX SETUP UTILTY",
    rb"\HBIOS SETUP UTILITIES",
)
DEL, F1 = [0x53, 0xD3], [0x3B, 0xBB]


def _modules(rom: bytes) -> list[dict]:
    try:
        return ami.extract(rom)[1]
    except Exception:
        return []


def is_hiflex(rom: bytes) -> bool:
    texts = rom + b"".join(m.get("data") or b"" for m in _modules(rom))
    return any(t in texts.upper() for t in TITLES)


class AmiHiFlex(award_emu_setup.AwardEmu):
    DEFAULTS = ("LOAD OPTIMAL SETTINGS", "AUTO CONFIGURATION WITH OPTIMAL")
    ACTIONS = (
        "LOAD",
        "SAVE",
        "EXIT",
        "PASSWORD",
        "AUTO-DETECT",
        "DETECT",
        "CHANGE",
        "AUTO CONFIGURATION",
    )

    def __init__(self, rom: bytes):
        modules = _modules(rom)
        hints = b"".join(m.get("data") or b"" for m in modules)
        if not any(t in hints.upper() or t in rom.upper() for t in TITLES):
            raise ValueError("not an AMIBIOS with the Simple/Hi-Flex setup")
        cmos, cmos_hi, spoils = ami_setup.default_cmos(), None, 0
        # PCChips M768VMR (VIA 691/586): its RAM sizing looks for the RAM again
        # above its end (as on DIMMs of fewer rows), and POST waits for a device at I/O 5F00h
        # (unknown) to read 02h, ready; POST takes long
        m768 = b"$PCCHIPSM768VMR" in rom + hints
        for _ in range(5):  # some boards reset early in POST (Zida LX98: after setting the
            # CPU ratio in the CMOS): POST again with the CMOS they left. One that boots
            # without an error pause: again, with DEL tapped once POST offers it
            emu = bios_emu.BiosEmulator(rom, cmos=cmos, max_instructions=100_000_000, hints=hints)
            if not emu.pci_devices:
                raise ValueError(
                    f"this board's chipset is not emulated ({bios_emu.EMULATED}), "
                    "so its POST cannot run"
                )
            if m768:
                emu.row_aliased, emu.io_reads = emu.ram_top * 12, {0x5F00: 0x02}
                emu.max_instructions = 500_000_000
            if cmos_hi is not None:
                emu.cmos_hi[:] = cmos_hi
            screen = emu.run(0xF000, 0xFFF0)
            if emu.stopped_reason == "reset":
                cmos, cmos_hi = bytes(emu.cmos), bytes(emu.cmos_hi)
            elif emu.stopped_reason.startswith("booting") and spoils < 2:
                # the CMOS the reset left is valid: spoil its checksum, so that POST stops at
                # "CMOS checksum bad" and goes into setup as with an empty CMOS; where 2Eh is
                # not the checksum (PCChips M768VMR), all of 0Eh-7Fh
                spoilt = bytearray(cmos)
                for i in ((0x2E,), range(0x0E, 0x80))[spoils]:
                    spoilt[i] ^= 0xFF
                spoils += 1
                cmos = bytes(spoilt)
            else:
                break
        before, slow = None, False
        for _ in range(4):
            if (
                emu.video_mode in bios_emu.PLANAR_MODES
                and emu.graphics_font is None
                and bios_emu.PLANAR_MODES[emu.video_mode] == (640, 480)
                and "AMERICAN" not in screen.text().upper()
            ):
                # POST drawn in graphics with AMI's own font (Gigabyte GA-7ZXE; where the
                # screen reads well as it is, GA-7VKMP, a guessed font would spoil the setup)
                emu.graphics_font = bios_emu.guess_graphics_font(emu.vga_planes, rom + hints)
                screen = emu.screen()
            if "SETUP UTIL" in screen.text() and award_emu_setup.cursor(screen) is not None:
                break
            if emu.stopped_reason not in award_emu_setup.WAITING:
                break
            # the error pause: "Press F1 to RUN SETUP" (Zida LX98), otherwise DEL - and F1
            # when DEL changed nothing (Zida BXi98: a full-screen logo hides the error list)
            text = screen.text()
            if text == before and emu.stopped_reason == "instruction limit reached" and slow:
                break  # (busy for long, not waiting: more keys would only cost minutes)
            emu.press_keys(F1 if "F1 TO RUN SETUP" in text.upper() or text == before else DEL)
            before = text
            started = time.monotonic()
            screen = emu.resume()
            slow = time.monotonic() - started > 20  # (PCChips M748LMRT: 3 s a run, it gets there)
        if "SETUP UTIL" not in screen.text():
            # with the timer interrupt running and DEL pressed when POST offers it (Top Star
            # TM-845GL: POST waits for a timer tick after copying its SMM handler, and
            # boots without an error pause); it gets the error pause's keys too (6351v20: with
            # the timer running POST waits 170 ticks, then pauses with "Press F1 to Run SETUP",
            # about 500 M instructions in)
            retry = bios_emu.BiosEmulator(
                rom,
                cmos=ami_setup.default_cmos(),
                max_instructions=600_000_000,
                hints=hints,
                timer_irq=True,
            )
            retry.max_seconds = 400
            # (400 s for all rounds: each one after an instruction limit would run another
            # 600 M instructions, and a board the retry does not help took 1270 s, s08-11)
            deadline = time.monotonic() + retry.max_seconds
            hits = bios_emu.time_limits_hit.get()
            hits_before = len(hits) if hits is not None else 0
            retry.press_keys(DEL, when_text="DEL")
            again = retry.run(0xF000, 0xFFF0)
            for _ in range(3):
                if "SETUP UTIL" in again.text() and award_emu_setup.cursor(again) is not None:
                    break
                if retry.stopped_reason not in award_emu_setup.WAITING:
                    break
                if (left := deadline - time.monotonic()) <= 1:
                    break
                retry.max_seconds = int(left)
                retry.press_keys(F1 if "F1 TO RUN SETUP" in again.text().upper() else DEL)
                again = retry.resume()
            if "SETUP UTIL" in again.text() and award_emu_setup.cursor(again) is not None:
                emu, screen = retry, again
            elif hits is not None:  # (a retry whose result is not used cuts nothing short)
                del hits[hits_before:]
        if "SETUP UTIL" not in screen.text():
            raise ValueError(
                f"AMIBIOS Simple/Hi-Flex setup did not start (stopped: " f"{emu.stopped_reason})"
            )
        emu.max_instructions = 50_000_000
        self.kind = "menu"
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.states = {}
