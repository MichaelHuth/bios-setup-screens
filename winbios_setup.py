"""
Capture the setup screens of AMI WinBIOS (AMIBIOS 1994-97 with the graphical "WinBIOS" setup)
by running the whole ROM in the x86 emulator: POST first, then the setup program, operated
with the keyboard like a user would.

Two generations are supported:
- '94 (AMIBIOS 10/10/94, e.g. HOT-419): the ROM starts with an "AMIBIOSC" header and keeps the
  setup program as a compressed module ("AMIBIOSS") that the runtime unpacks when setup is
  entered. The runtime has a loader per module: mov al,<n> / mov di,<"AMIBIOSx" signature>;
  setup is entered by a run of calls ending in the call to the "AMIBIOSS" loader, and the
  loader looks for a copy of the ROM at 2000:0. Keys are given through INT 16h.
- '95 format (AMI 95 module list with "Setup Server"/"Setup Client", e.g. AMI Merlin, setup
  version 2.4): setup is entered as a person does, by pressing DEL during POST (POST polls the
  keyboard controller for it while it counts memory); keys are then typed as scan codes
  through the BIOS's own keyboard handler.
Both draw windows with icons in their own 8x14 font (350-line text mode, bright backgrounds).
The main screen has four windows; Tab moves between them, Left/Right between icons, Enter
opens one, PgDn scrolls long lists. Default > Optimal asks "Load Optimal values ?" with No
selected; Right selects Yes. The '94 setup has Utility > Color Set (LCD, the default with
cleared CMOS, Army, Pastel, Sky); version 2.4 has a Setup Color Scheme item instead.
"""

from __future__ import annotations

import re
import struct

import ami
import ami_setup
import bios_emu
from bios_emu import KEYS
from textscreen import FONTS, Screen, cp437_to_unicode

COLOR_SETS = ["LCD", "Army", "Pastel", "Sky"]
MAX_SCROLL = 4  # PgDn screens per list page
DEFAULT_WINDOW = 3  # Tab presses from the Setup window to the Default window
# scan codes (set 1) as a keyboard sends them: make and break, arrows with the E0 prefix
SCANCODES = {
    "tab": [0x0F, 0x8F],
    "enter": [0x1C, 0x9C],
    "esc": [0x01, 0x81],
    "right": [0xE0, 0x4D, 0xE0, 0xCD],
    "left": [0xE0, 0x4B, 0xE0, 0xCB],
    "down": [0xE0, 0x50, 0xE0, 0xD0],
    "up": [0xE0, 0x48, 0xE0, 0xC8],
    "pgdn": [0xE0, 0x51, 0xE0, 0xD1],
    "pgup": [0xE0, 0x49, 0xE0, 0xC9],
}
DEL_KEY = [0x53, 0xD3]
SPACE_KEY = [0x39, 0xB9]  # (TriGem: "Hit SPACE if you want to run SETUP")


def winbios_kind(rom: bytes) -> str:
    """'94', '95' or '' (not a WinBIOS)."""
    if any(rom[off : off + 8] == b"AMIBIOSC" for off in range(0, len(rom), 0x10000)):
        return "94"
    if ami.find_core(rom) >= 0:
        try:
            _, modules = ami.extract(rom)
        except Exception:  # damaged image
            return ""
        for m in modules:
            if m.get("name") == "Setup Client" and b"Select window" in (m.get("data") or b""):
                return "95"
    return ""


def is_winbios(rom: bytes) -> bool:
    return bool(winbios_kind(rom))


def find_entry(runtime: bytes) -> int:
    """Offset in the F000 runtime where setup is entered."""
    sigs = [m.start() for m in re.finditer(b"AMIBIOSS", runtime)]
    if not sigs:
        raise ValueError("no setup module loader (AMIBIOSS) in the runtime BIOS")
    for sig in sigs:
        for m in re.finditer(rb"\xb0.\xbf" + re.escape(struct.pack("<H", sig)), runtime, re.S):
            loader = m.start()
            for c in re.finditer(rb"(?=\xe8(..))", runtime, re.S):
                if (c.start() + 3 + struct.unpack("<h", c.group(1))[0]) & 0xFFFF != loader:
                    continue
                start = c.start()
                while start >= 3 and runtime[start - 3] == 0xE8:  # the calls before it
                    start -= 3
                return start
    raise ValueError("setup entry not found in the runtime BIOS")


def _pixels(glyph: bytes) -> set:
    return {(y, x) for y, bits in enumerate(glyph) for x in range(8) if bits & (0x80 >> x)}


def _similarity(glyph: bytes, rom_glyph: bytes) -> float:
    """Overlap of two glyphs (intersection over union), allowing a 1-pixel shift and bold."""
    a, b = _pixels(glyph), _pixels(rom_glyph)
    if not a and not b:
        return 1.0
    best = 0.0
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            moved = {(y + dy, x + dx) for y, x in b}
            for other in (moved, moved | {(y, x + 1) for y, x in moved}):
                best = max(best, len(a & other) / len(a | other))
    return best


def _text_codes(font: bytes, h: int) -> frozenset:
    """Character codes the setup's font still shows as text. WinBIOS redraws the letters in its
    own bold style and puts icon pieces, the background pattern and 3D borders on other codes,
    also ASCII symbols like $ < > @ [ ] (overlap with the ROM glyphs <= 0.32 on the HOT-419
    and the AMI Merlin), never on letters and digits (>= 0.33)."""
    rom = FONTS[h]

    def keep(c: int) -> bool:
        sim = _similarity(font[c * h : c * h + h], rom[c * h : c * h + h])
        if chr(c).isalnum():
            return sim > 0.2
        if chr(c) in " .,:;/()-+%&*!#'\"?":
            return sim > 0.25
        return sim > 0.45

    return frozenset(c for c in range(0x20, 0x7F) if keep(c))


def plain_text(screen: Screen) -> str:
    """The screen as text without the setup's own glyphs (icons, background pattern, 3D
    borders), which become spaces."""
    keep = _text_codes(screen.font, screen.char_height)
    lines = []
    for row in screen.chars:
        line = bytes(c if c in keep else 0x20 for c in row)
        lines.append(cp437_to_unicode(line).rstrip())
    return "\n".join(lines).strip("\n")


def _segments(line: str) -> dict[int, str]:
    return {m.start(): m.group() for m in re.finditer(r"\S+(?: \S+)*", line)}


def _title(screen: Screen, main: Screen) -> str:
    """Title of the window opened over the main screen: the first new text from the top."""
    now, before = plain_text(screen).splitlines(), plain_text(main).splitlines()
    for row in range(3, min(len(now), 22)):
        old = _segments(before[row]) if row < len(before) else {}
        for col, text in _segments(now[row]).items():
            if old.get(col) != text and re.search(r"[A-Za-z]{3}", text):
                return text
    return ""


def _in_setup(screen: Screen) -> bool:
    """WinBIOS setup's main screen: "AMIBIOS Setup", or an OEM's own title over the same
    windows with "Alt+H: Help" (TriGem Giant: "System Setup")."""
    text = plain_text(screen)
    return "AMIBIOS Setup" in text or ("Setup" in text and "Alt+H" in text)


class WinBios:
    def __init__(self, rom: bytes):
        self.kind = winbios_kind(rom)
        if not self.kind:
            raise ValueError("not an AMI WinBIOS image")
        self.rom = rom
        # some boards reset once at power-on (Supermicro P5MMS: CMOS 7Fh bit 0 set, then a
        # reset through CF9h): POST again with the CMOS it left
        cmos = ami_setup.default_cmos()
        try:  # the chipset's PCI IDs may be only in the compressed modules (Tyan S1563S)
            hints = b"".join(m.get("data") or b"" for m in ami.extract(rom)[1])
        except Exception:
            hints = b""
        for _ in range(3):
            emu = bios_emu.BiosEmulator(rom, cmos=cmos, max_instructions=300_000_000, hints=hints)
            emu.max_seconds = 240  # (the instructions decide, not how busy the machine is: a778)
            if self.kind == "94":
                emu.fill_solid_font = True
                break
            key = SPACE_KEY if b"Hit SPACE if you want to run SETUP" in rom + hints else DEL_KEY
            emu.press_keys(key * 30, when_text="KB OK")
            screen = emu.run(0xF000, 0xFFF0)
            if emu.stopped_reason != "reset":
                break
            cmos = bytes(emu.cmos)
        if self.kind != "94":  # DEL not taken during POST, but its error pause offers F1
            for _ in range(2):  # ("Press F1 to Run SETUP", Tyan TI5TV 430VX)
                if (
                    _in_setup(screen)
                    or "F1" not in screen.text()
                    or emu.stopped_reason not in ("waiting for a key", "polling the keyboard")
                ):
                    break
                emu.hw_keys = []
                # an error pause that only resumes ("Press F1 to Resume", TriGem Giant: the
                # DELs went before it): the setup key again while POST goes on
                again = [] if "Run SETUP" in screen.text() else key * 30
                emu.press_keys([0x3B, 0xBB] + again)
                screen = emu.resume()
        self.in_post = False  # setup started by POST itself (not entered from outside)
        if self.kind == "94":
            screen = emu.run(0xF000, 0xFFF0)
            for _ in range(3):  # an error pause ("CMOS checksum failure ... RUN SETUP
                # UTILITY, Press F1 to RESUME", Shuttle HOT-433 07/25/94): F1 starts setup
                if emu.stopped_reason not in ("waiting for a key", "polling the keyboard") or (
                    "F1" not in screen.text()
                ):
                    break
                emu.keys = [0x3B00]  # F1
                screen = emu.resume()
            self.in_post = "Alt+H" in plain_text(screen)
        if self.in_post:
            pass
        elif self.kind == "94":
            # (a POST that never ends, a778's PCI walks: the setup module is loaded from here
            # whichever limit stopped it)
            if not emu.stopped_reason.startswith(("booting", "instruction limit", "time limit")):
                raise ValueError(f"POST did not finish: {emu.stopped_reason}")
            runtime = bytes(emu.uc.mem_read(0xF0000, 0x10000))
            if b"AMIBIOSS" not in runtime and not emu.stopped_reason.startswith("booting"):
                # (a loop, not the end of POST: the setup module is unpacked only at its end)
                raise ValueError(f"POST did not finish: {emu.stopped_reason}")
            self.entry = find_entry(runtime)
            # the setup module loader looks for the copies of the ROM the boot block made
            # (memory tests have overwritten them since): at 2000:0 the half with the module
            # table ("AMIBIOSC"), at 1000:0 the other one (modules flagged with bit 7). Most
            # images start with the table; PCChips M918 images have it in the second half
            halves = [rom[-0x20000:-0x10000], rom[-0x10000:]] if len(rom) >= 0x20000 else [rom]
            table = next((h for h in halves if h.startswith(b"AMIBIOSC")), halves[0])
            emu.uc.mem_write(0x20000, rom[-0x20000:])
            emu.uc.mem_write(0x20000, table)
            emu.uc.mem_write(0x10000, next((h for h in halves if h is not table), halves[-1]))
        else:  # DEL tapped while POST counts memory, as a person would (above)
            if not _in_setup(screen):
                raise ValueError(
                    "POST did not start setup when DEL was pressed (stopped: "
                    f"{emu.stopped_reason})"
                )
            emu.hw_keys = []
        emu.stopped_reason = ""
        self.emu, self.start = emu, emu.snapshot()
        self.has_failsafe = False

    def capture(self, keys: list) -> tuple[Screen, str]:
        """The screen after pressing keys (names from SCANCODES) from setup's start."""
        emu = self.emu
        emu.restore(self.start)
        if self.in_post:
            emu.keys = [KEYS[k] for k in keys]
            screen = emu.resume()
        elif self.kind == "94":
            emu.keys = [KEYS[k] for k in keys]
            screen = emu.run(0xF000, self.entry, ss=0x0030, sp=0x0400)
        else:
            emu.press_keys([c for k in keys for c in SCANCODES[k]], paced=True)
            screen = emu.resume()
        return screen, emu.stopped_reason

    def _color_set(self) -> list:
        """Keys from the Utility window to the Color Set icon, found by its help line ("Select
        Color Set"): it follows one or two Auto Detect icons (AOpen AP4161: Master, Slave)."""
        for k in range(1, 4):
            screen, _ = self.capture(["tab"] + ["right"] * k)
            if "Color" in (plain_text(screen).splitlines() or [""])[-1]:
                return ["right"] * k
        return ["right"]

    def screens(self, defaults: str = "setup", color: int = 0) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: main screen, Standard Setup and the list pages
        (with their PgDn continuations), Color Set ('94)."""
        main, _ = self.capture([])
        self.has_failsafe = "Fail-safe" in plain_text(main)
        prefix, focus = [], 0
        if defaults == "setup" or (defaults == "bios" and self.has_failsafe):
            rights = 1 if defaults == "setup" else 2  # Original, Optimal, Fail-safe
            prefix = ["tab"] * DEFAULT_WINDOW + ["right"] * rights + ["enter", "right", "enter"]
            focus = DEFAULT_WINDOW
        to_color = self._color_set() if self.kind == "94" else []
        if color and self.kind == "94":  # Utility (one Tab from Setup) > Color Set
            prefix += ["tab"] * ((1 - focus) % 4) + to_color + ["enter"]
            prefix += ["down"] * (color % len(COLOR_SETS)) + ["enter"]
            focus = 1
        to_setup = ["tab"] * ((0 - focus) % 4)
        lines = plain_text(main).splitlines()
        if not lines:  # (Biostar MB-1433UIV: the setup screen stayed empty)
            raise ValueError("the WinBIOS setup screen is empty")
        help_line = lines[-1]  # "Set Date, Time, ..." on Standard
        for n in range(4):  # the Tab order differs between versions: find the Setup window
            screen, _ = self.capture(prefix + ["tab"] * n)
            if (plain_text(screen).splitlines() or [""])[-1] == help_line:
                to_setup = ["tab"] * n
                break

        out = []
        screen, reason = self.capture(prefix + to_setup)
        out.append(("MAIN MENU", screen, reason))
        seen = set()
        for i in range(9):  # icons of the Setup window, left to right
            keys = prefix + to_setup + ["right"] * i + ["enter"]
            screen, reason = self.capture(keys)
            title = _title(screen, main)
            if not title or title in seen:
                break
            seen.add(title)
            out.append((title, screen, reason))
            text = screen.text()
            for n in range(1, MAX_SCROLL + 1):  # long lists: further screens with PgDn
                more, reason = self.capture(keys + ["pgdn"] * n)
                if more.text() == text:
                    break
                out.append((f"{title} ({n + 1})", more, reason))
                text = more.text()
        if self.kind == "94":
            keys = prefix + ["tab"] * ((1 - focus) % 4) + to_color + ["enter"]
            screen, reason = self.capture(keys)
            if _title(screen, main) == "Color Set":
                out.append(("Color Set", screen, reason))
        return out
