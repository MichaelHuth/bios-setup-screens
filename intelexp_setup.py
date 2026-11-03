"""
Capture the setup screens of Intel's Express BIOS of 1995-97 (an AMIBIOS core of 1992 with a
menu bar: Main, Advanced, Security, Exit; Intel's boards and AST's with Intel's parts) by running
the image screen_tools._intel_bio assembles from the update's parts in the x86 emulator.
Dell's Dimensions of 1997-98 have the same core with Dell's own setup: "Screen 1 of 2" on the
colour page, Alt-P for the next.

How it works:
- the parts are raw flash blocks: the boot block expands the BIOS during POST and programs the
  flash with Intel's 28Fxxx commands (20h/60h/D0h erase, 40h program), then reads the status
  (70h) until bit 7 (ready) is set - plain RAM reads back the command, so POST would spin;
- AST's board reads a configuration pair at 0F86h/0F87h: with FFh it probes a Sound Blaster
  and an MPU-401 forever, with 0 it skips them;
- POST leaves interrupts off and reads "Press <F1> for Setup" from the 8042 itself;
- the setup draws in video mode 7 (monochrome, its page at B0000h, 24 rows) and reads its keys
  from the BIOS key ring through INT 16h, still with interrupts off; Right moves to the next
  menu.
"""

from __future__ import annotations

import re
import struct

import ami_setup
import bios_emu
from bios_emu import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_X86_REG_CS, UC_X86_REG_EFLAGS
from textscreen import Screen

# Intel's boot block code of these updates (no text in the image: the body is packed)
SIGNATURE = bytes.fromhex("00bb440066535167662e8b730867662e8b7b04672e8b4b02")
F1 = [0x3B, 0xBB]
RIGHT = (0x00, 0x4D)  # (ASCII, scan code) as the key ring holds it
ALT_P = [0x38, 0x19, 0x99, 0xB8]  # (make and break codes: Dell's reads the keyboard itself)
DELL_PAGES = re.compile(r"Screen 1 of (\d+)")
PROMPT = "for Setup"
MENUS = ("Main", "Advanced", "Security", "Exit")
MENUS_POWER = ("Main", "Advanced", "Security", "Power", "Exit")
ENTER, ESC = [0x1C, 0x9C], [0x01, 0x81]
DOWN = [0xE0, 0x50, 0xE0, 0xD0]
IBM_OPTIONS = 9  # (System Summary ... Advanced Power Management; then Save and Exit)
MDA, MDA_ROWS = 0xB0000, 24
WAITING = ("waiting for a key", "polling the keyboard")
MAX_SLICES = 400  # (POST: 22-38 slices of the timer interrupt)
SETTLE = 40


def is_intel_express(rom: bytes) -> bool:
    return SIGNATURE in rom


class Flash:
    """The flash chip's command set over C0000h-FFFFFh: after a program or erase and 70h (read
    status) the next read of that address answers 80h (ready). The command sequence, not the
    byte value, says what a write is (a programmed byte may be 20h)."""

    def __init__(self, emu: bios_emu.BiosEmulator):
        self.cmd: dict[int, str] = {}
        self.hook = None
        emu.uc.hook_add(UC_HOOK_MEM_WRITE, self.write, None, 0xC0000, 0xFFFFF)

    def write(self, uc, _access, addr, size, value, _user) -> None:  # type: ignore[no-untyped-def]
        if size != 1:
            return
        block, value, state = addr >> 16, value & 0xFF, self.cmd.get(addr >> 16)
        if state == "program":
            self.cmd[block] = "data"
        elif value == 0x70 and state in ("data", "erase"):
            self.cmd[block] = ""
            if self.hook is None:  # (only while a status read is due: a read hook over the
                # whole window would see every instruction fetch there)
                self.hook = uc.hook_add(UC_HOOK_MEM_READ, self.status, None, addr, addr)
        elif value == 0x40:
            self.cmd[block] = "program"
        elif value == 0xD0 and state in ("20", "60"):
            self.cmd[block] = "erase"
        elif value == 0x20:
            self.cmd[block] = "20"
        elif value == 0x60 and state == "20":
            self.cmd[block] = "60"

    def status(self, uc, _access, addr, _size, _value, _user) -> None:  # type: ignore[no-untyped-def]
        uc.mem_write(addr, b"\x80")  # (the write hook runs before the store lands: so here)
        uc.hook_del(self.hook)
        self.hook = None


def mda_screen(emu: bios_emu.BiosEmulator) -> Screen:
    """The monochrome text page (B0000h, 80 x 24), which emu.screen() does not read."""
    colour = emu.screen()
    s = Screen(80, MDA_ROWS)
    s.font, s.palette, s.char_height = colour.font, colour.palette, colour.char_height
    raw = bytes(emu.uc.mem_read(MDA, 80 * MDA_ROWS * 2))
    for i in range(80 * MDA_ROWS):
        s.put(i % 80, i // 80, raw[2 * i] or 0x20, raw[2 * i + 1])
    return s


def current_screen(emu: bios_emu.BiosEmulator) -> Screen:
    """The setup's screen: the monochrome page, or a picture if it draws in 640x480 (the same
    setup with its own font, which is not in the data: the text cannot be read from it)."""
    if emu.video_mode == 3:  # (Dell's)
        return emu.screen()
    if emu.video_mode not in bios_emu.PLANAR_MODES:
        return mda_screen(emu)
    screen = emu.screen()
    screen.chars = [[0x20] * screen.cols for _ in range(screen.rows)]
    screen.write(0, 0, b"(a graphical page: its text is in the attached image)", 0x07)
    return screen


def fingerprint(screen: Screen) -> bytes:
    """What tells two pages apart: their pixels, or their text."""
    if screen.image is None and screen.image_factory is not None:
        screen.image = screen.image_factory()
    return screen.image.tobytes() if screen.image is not None else screen.text().encode()


def ring_key(emu: bios_emu.BiosEmulator, ascii_: int, scan: int) -> None:
    """A key word put in the BIOS key ring, as INT 09h would (the setup runs with IF clear)."""
    start, end = struct.unpack("<HH", emu.uc.mem_read(0x480, 4))
    tail = struct.unpack("<H", emu.uc.mem_read(0x41C, 2))[0]
    emu.uc.mem_write(0x400 + tail, bytes([ascii_, scan]))
    emu.uc.mem_write(0x41C, struct.pack("<H", tail + 2 if tail + 2 < end else start))


class IntelExpressSetup:
    def __init__(self, rom: bytes):
        if not is_intel_express(rom):
            raise ValueError("not Intel's Express BIOS of 1995-97")
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=bios_emu.TIMER_SLICE,
            timer_irq=True,
        )
        emu.max_seconds = 240
        Flash(emu)
        emu.cf9_resets_in_place = 4  # (the first boot sets CMOS 0Fh to FEh and resets)
        emu.event_wait_over = True
        for port in range(0xF80, 0xF90):  # (AST's sound and MIDI probe, see above)
            emu.io_reads[port] = 0
        screen = emu.run(0xF000, 0xFFF0)
        pressed = False
        for _ in range(MAX_SLICES):
            reason = emu.stopped_reason
            if reason in WAITING and emu.uc.reg_read(UC_X86_REG_CS) != 0xF000 and pressed:
                break  # the setup's own key wait (its module runs in RAM)
            # (POST done at its logo, the prompt not in the text: Celsius, 680MB)
            if (
                reason in WAITING
                and not pressed
                and (PROMPT in screen.text() or 0xFF in emu.post_codes_seen)
            ):
                flags = emu.uc.reg_read(UC_X86_REG_EFLAGS)
                emu.uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x200)  # (so IRQ 1 is taken)
                emu.press_keys(F1, paced=True)
                pressed = True
            elif reason not in ("", "instruction limit reached", "waiting for a key"):
                break
            screen = emu.resume()
        main = current_screen(emu)
        graphics = emu.video_mode in bios_emu.PLANAR_MODES  # (680MB, in its setup's key wait)
        text = main.text()
        if not pressed or not (
            graphics or text.lstrip().startswith(MENUS[0]) or DELL_PAGES.search(text)
        ):
            raise ValueError(
                f"the Intel Express setup did not start (stopped: {emu.stopped_reason})"
            )
        self.emu, self.main = emu, main

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(menu, screen, stop reason)] for the menus of the bar, Right after Right."""
        if (pages := DELL_PAGES.search(self.main.text())) is not None:
            out = [("Screen 1", self.main, self.emu.stopped_reason)]
            for page in range(2, int(pages[1]) + 1):
                flags = self.emu.uc.reg_read(UC_X86_REG_EFLAGS)
                self.emu.uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x200)
                self.emu.press_keys(ALT_P, paced=True)
                self.emu.resume()
                screen = current_screen(self.emu)
                out.append((f"Screen {page}", screen, self.emu.stopped_reason))
            return out
        out = [(MENUS[0], self.main, self.emu.stopped_reason)]
        seen = {fingerprint(self.main)}
        for _ in MENUS_POWER[1:]:  # (until Right comes back to a page already seen)
            if self.emu.video_mode in bios_emu.PLANAR_MODES:  # (reads the keyboard itself)
                flags = self.emu.uc.reg_read(UC_X86_REG_EFLAGS)
                self.emu.uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x200)
                self.emu.press_keys([0xE0, 0x4D, 0xE0, 0xCD], paced=True)
            else:
                ring_key(self.emu, *RIGHT)
            self.emu.resume()
            screen = current_screen(self.emu)
            if self.emu.video_mode in bios_emu.PLANAR_MODES:
                # (it looks for keys while it draws: on until the picture stands still)
                for _ in range(SETTLE):
                    self.emu.resume()
                    again = current_screen(self.emu)
                    if fingerprint(again) == fingerprint(screen):
                        break
                    screen = again
            if fingerprint(screen) in seen:
                break
            seen.add(fingerprint(screen))
            out.append(("", screen, self.emu.stopped_reason))
        if len(out) == 1 and self.emu.video_mode in bios_emu.PLANAR_MODES:
            return self._ibm_pages() or out
        names = MENUS_POWER if len(out) == len(MENUS_POWER) else MENUS
        return [(name, page[1], page[2]) for name, page in zip(names, out)]

    def _press(self, key: list[int]) -> Screen:
        # (in the pictures' mode: it reads the keyboard itself and looks for keys while it draws)
        flags = self.emu.uc.reg_read(UC_X86_REG_EFLAGS)
        self.emu.uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x200)
        self.emu.press_keys(key, paced=True)
        self.emu.resume()
        screen = current_screen(self.emu)
        for _ in range(SETTLE):
            self.emu.resume()
            again = current_screen(self.emu)
            if fingerprint(again) == fingerprint(screen):
                break
            screen = again
        return screen

    def _ibm_pages(self) -> list[tuple[str, Screen, str]]:
        """IBM's Configuration/Setup Utility on this core (no menu bar: Right does nothing; its
        text is in pictures only). After F1 a help box over POST's errors: Esc closes it, Enter
        is Continue, and the list of options comes up; Enter opens one, each from the list
        (Save and Exit below them are left alone)."""
        self._press(ESC)
        menu = self._press(ENTER)
        if fingerprint(menu) == fingerprint(self.main):
            return []
        out = [("Configuration/Setup Utility", menu, self.emu.stopped_reason)]
        start = self.emu.snapshot()
        seen = {fingerprint(menu)}
        for option in range(IBM_OPTIONS):
            self.emu.restore(start)
            for _ in range(option):
                self._press(DOWN)
            screen = self._press(ENTER)
            if fingerprint(screen) not in seen:
                seen.add(fingerprint(screen))
                out.append((f"Option {option + 1}", screen, self.emu.stopped_reason))
        return out
