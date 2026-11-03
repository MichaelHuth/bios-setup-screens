"""
Capture the setup screens of AMIBIOS 8 ("BIOS SETUP UTILITY", about 2002-2008, the menu bar
Main / Advanced / Power / Boot / Exit) by running the whole ROM in the x86 emulator.

Worked out on an ASUS P4P800 BIOS (rev. 1019, Intel 865PE + ICH5):
- the image's modules (AMIBIOS 8 format, "AMIBIOSC0800") are unpacked; the chipset's PCI IDs
  in them make the emulator build the i865 (PAM at 90h-96h) and ICH5 devices, memory is
  sized from DDR SPD data, the TCO "chassis intrusion" status is clear;
- the BIOS shows nothing before it has found a VGA card on the PCI bus and run its option
  ROM; the emulator provides a plain one;
- POST draws in 640x480 graphics with AMI's display manager font ("ADM Font" module: "TNOF"
  and 256 glyphs of 8x19, CP437 order); the screen is read back as 25 rows of text with it;
- with an empty CMOS POST stops at its error list and offers setup ("Press F1 to Run SETUP",
  otherwise DEL is pressed there; DEL early in POST makes this BIOS reset). The clock
  registers are set valid (01/01/2000);
- the menu bar and the sub-menus (entries marked with ►) are walked as in PhoenixBIOS
  (phoenix_setup.PhoenixSetup): right arrow, down arrows to the entry, Enter;
- the setup's timer handler posts "refresh the clock" messages for the controls of the page
  shown (the Main page's time and date) into a message queue that the idle loop works off.
  When the setup is captured, a few are still queued; after a page change they would draw
  the time and date over the new page. The queue is emptied before keys are pressed (its
  count is found in the setup module: "cmp word cs:[count],0 / jz / mov ax,cs:[index] /
  call").
"""

from __future__ import annotations

import re
import struct

import ami
import bios_emu
import phoenix_setup

TITLE = "BIOS SETUP UTILITY"
QUEUE = re.compile(
    re.escape(bytes([0x2E, 0x83, 0x3E]))
    + b"(..)"
    + re.escape(bytes([0x00, 0x74]))
    + b"."
    + re.escape(bytes([0x2E, 0xA1]))
    + b".."
    + re.escape(bytes([0xE8])),
    re.S,
)
F1, F2, DEL = [0x3B, 0xBB], [0x3C, 0xBC], [0x53, 0xD3]
SETUP_KEY = re.compile(r"Press (DEL|F2) to (?:run|enter) Setup", re.I)
RESUME = re.compile(r"F1 to (?:Resume|Continue)", re.I)


def _modules(rom: bytes) -> tuple[dict, list[dict]]:
    try:
        return ami.extract(rom)
    except Exception:
        return {}, []


def is_amibios8(rom: bytes) -> bool:
    info, modules = _modules(rom)
    return info.get("version", "").startswith("08") and any(
        m.get("name") == "ADM Font" for m in modules
    )


def _queue_count(memory: bytes, setup: bytes) -> int | None:
    """Linear address of the setup's message count: the module's place in memory is where
    its code is found with the same offsets."""
    m = QUEUE.search(setup)
    if not m or len(setup) < 0x1040:
        return None
    count = struct.unpack("<H", m.group(1))[0]
    for found in QUEUE.finditer(memory):
        base = found.start() - m.start()
        if (
            base >= 0
            and base % 16 == 0
            and memory[base + 0x1000 : base + 0x1040] == setup[0x1000:0x1040]
        ):
            return base + count
    return None


class AmiBios8(phoenix_setup.PhoenixSetup):
    def __init__(self, rom: bytes):
        _, modules = _modules(rom)
        font = next((m.get("data") or b"" for m in modules if m.get("name") == "ADM Font"), b"")
        if not font.startswith(b"TNOF"):
            raise ValueError("not an AMIBIOS 8 image with its display manager font")
        setup = next(
            (m.get("data") or b"" for m in modules if m.get("name") == "Setup Client"), b""
        )
        hints = b"".join(m.get("data") or b"" for m in modules)
        # an empty CMOS, but a working clock (status registers A, B and D: battery good)
        cmos = bytearray(128)
        cmos[0x0A], cmos[0x0B], cmos[0x0D] = 0x26, 0x02, 0x80
        cmos[0x06:0x0A] = bytes([0x07, 0x01, 0x01, 0x00])  # Saturday, 01/01/(20)00, BCD
        cmos[0x32] = 0x20
        emu = bios_emu.BiosEmulator(
            rom, cmos=bytes(cmos), max_instructions=150_000_000, hints=hints, ram_mb=64
        )
        emu.graphics_font = (font[4 : 4 + 256 * 19], 19)
        if not emu.pci_devices:  # the POST would only wander about
            raise ValueError(
                f"this board's chipset is not emulated ({bios_emu.EMULATED}), "
                "so its POST cannot run"
            )
        screen = emu.run(0xF000, 0xFFF0)
        setup_key = DEL
        for _ in range(4):
            text = screen.text()
            if TITLE in text:
                break
            if emu.stopped_reason not in (
                "waiting for a key",
                "polling the keyboard",
                "instruction limit reached",
            ):
                break
            # POST names the setup key ("Press DEL to run Setup", ASRock: F2)
            named = SETUP_KEY.search(text)
            if named:
                setup_key = F2 if named.group(1).upper() == "F2" else DEL
            # the error pause: "Press F1 to Run SETUP"; where it only offers to go on
            # ("Press F1 to Resume"), the setup key first, then F1
            if "F1 to Run SETUP" in text or "F1 to Run Setup" in text:
                emu.press_keys(F1)
            elif RESUME.search(text):
                emu.press_keys(setup_key + F1)
            else:
                emu.press_keys(setup_key)
            screen = emu.resume()
        if TITLE not in screen.text():
            hint = (
                f"; POST stopped on purpose, most likely on a chipset part that is not "
                f"emulated ({bios_emu.EMULATED})"
                if emu.stopped_reason == "halted"
                else ""
            )
            raise ValueError(
                f"AMIBIOS 8 setup did not start (stopped: {emu.stopped_reason}" f"{hint})"
            )
        emu.max_instructions = 200_000_000
        self.queue_count = _queue_count(bytes(emu.uc.mem_read(0, 0xA0000)), setup)
        self.emu, self.start, self.main = emu, emu.snapshot(), screen

        self.states = {}

    def _before_keys(self) -> None:
        if self.queue_count is not None:  # stale clock refreshes for the page shown
            self.emu.uc.mem_write(self.queue_count, bytes(2))
