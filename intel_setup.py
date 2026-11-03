"""
Capture the setup screens of Intel's own desktop-board BIOS (an AMI core with Intel's menu-bar
setup, BIOS ID "....86A....", about 1999-2003) by running the whole ROM in the x86 emulator.

Worked out on an Intel D845WR (845 + ICH2, WR84510A.86A, 2002):
- the boot block wants the upper CMOS bytes F8h-FDh to add up to 0 with bits 4-5 of F8h set,
  else it goes into recovery mode (looking for a recovery disk): they are preset;
- 64 MB of SDRAM (the 845 takes no 16 MB modules of 16-Mbit chips);
- POST stops at an error pause, F1 (or F2) starts the setup, drawn in 640x480 graphics with
  Intel's own 8x19 font (found in the ROM's data, see _font);
- a board may default to another language (D845WR: Chinese): "Language" is set to English
  through its pop-up (the first entry of Main);
- the menu bar (Main, Advanced, Security, Power, Boot, Exit) and the pages the ► entries open
  are walked as in PhoenixBIOS 4.0's setup (phoenix_setup.PhoenixSetup); greyed entries
  cannot be selected, and pop-up dialogs (Exit, passwords) are not pages.
"""

from __future__ import annotations

import re

import ami
import ami_setup
import bios_emu
import phoenix_setup
from textscreen import Screen

F1, F2 = [0x3B, 0xBB], [0x3C, 0xBC]
ENTER, DOWN, UP = [0x1C, 0x9C], [0xE0, 0x50, 0xE0, 0xD0], [0xE0, 0x48, 0xE0, 0xC8]
WORDS = (
    "BIOS",
    "Setup",
    "SETUP",
    "Main",
    "Advanced",
    "Security",
    "Power",
    "Boot",
    "Exit",
    "System",
    "Memory",
    "Enabled",
    "Disabled",
    "the",
    "Language",
)
GREY = 0x08  # the color of entries that cannot be selected


def is_intel_own(rom: bytes) -> bool:
    return b".86A." in rom and b"AMIBIOSC" in rom


def _font(emu: bios_emu.BiosEmulator, data: bytes) -> tuple[bytes, int] | None:
    """The setup's font, guessed from the screen and the ROM's data; of the starts a few
    characters apart the one that makes the most familiar words (the guess itself may be one
    glyph off: "CJPT" for "BIOS")."""
    found = bios_emu.guess_graphics_font(emu.vga_planes, data, heights=(14, 15, 16, 19))
    if found is None:
        return None
    font, h = found
    best: tuple[int, tuple[bytes, int]] | None = None
    for k in range(-2, 3):
        candidate = (font[k * h :] if k >= 0 else bytes(-k * h) + font)[: 256 * h], h
        emu.graphics_font = candidate
        text = emu.screen().text()  # (the frame counts too: a screen in Chinese has no words)
        score = 10 * sum(text.count(w) for w in WORDS) + sum(text.count(c) for c in "─│┌┬┐└┴┘")
        if best is None or score > best[0]:
            best = (score, candidate)
    assert best is not None
    return best[1]


def _in_setup(screen: Screen) -> bool:
    """The setup's frame, in any language and whatever the font was taken for: rows 2 and
    rows - 2 are lines of one character across most of the screen."""
    lines = screen.text().split("\n")
    return all(
        len(lines) > row
        and max((len(m.group(0)) for m in re.finditer(r"(.)\1*", lines[row])), default=0) >= 40
        for row in (2, len(lines) - 2)
    )


def _english(screen: Screen) -> bool:
    text = screen.text()
    return "Main" in text and "Exit" in text


class IntelSetup(phoenix_setup.PhoenixSetup):
    def __init__(self, rom: bytes):
        if not is_intel_own(rom):
            raise ValueError("not Intel's own BIOS (BIOS ID ....86A....)")
        try:
            hints = b"".join(m.get("data") or b"" for m in ami.extract(rom)[1])
        except Exception:
            hints = b""
        upper = bytearray(128)
        upper[0x78], upper[0x7D] = 0x30, 0xD0  # F8h-FDh: no recovery (see above)
        emu = bios_emu.BiosEmulator(
            rom,
            cmos=ami_setup.default_cmos(),
            max_instructions=1_500_000_000,
            hints=hints,
            ram_mb=64,
        )
        if not emu.pci_devices:
            raise ValueError(
                f"this board's chipset is not emulated ({bios_emu.EMULATED}), "
                "so its POST cannot run"
            )
        emu.cmos_hi[:] = upper
        emu.max_seconds = max(emu.max_seconds, 120)  # (D845WR: about 20 s to its setup)
        screen = emu.run(0xF000, 0xFFF0)
        for key in (F1, F2):
            if emu.stopped_reason not in ("waiting for a key", "polling the keyboard"):
                break
            emu.press_keys(key)
            screen = emu.resume()
            if _in_setup(screen):
                break
        if not _in_setup(screen):
            raise ValueError(f"Intel's setup did not start (stopped: {emu.stopped_reason})")
        for keys in ([], [ENTER, DOWN, ENTER], [ENTER, UP, ENTER]):
            # in another language (D845WR: Chinese) its own font is not the one read here:
            # the language pop-up (the first entry of Main) gets English
            for key in keys:
                emu.press_keys(key, paced=True)
                screen = emu.resume()
            if emu.video_mode in bios_emu.PLANAR_MODES:
                emu.graphics_font = _font(emu, rom + hints)
                screen = emu.screen()
            if _english(screen):
                break
        if not _english(screen):
            raise ValueError("Intel's setup started, but its texts could not be read")
        emu.max_instructions = 200_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.states = {}

    @staticmethod
    def submenus(screen: Screen) -> list[tuple[int, str]]:
        """As PhoenixBIOS's, but greyed entries are passed over by the cursor."""
        selectable = []
        for row in range(3, screen.rows - 3):
            line = bytes(screen.chars[row][1:53]).decode("cp437")
            if screen.attrs[row][3] & 0x0F == GREY:
                continue
            if screen.chars[row][2] == 0x10 or "[" in line:
                selectable.append((row, line))
        return [
            (n, line[2:].strip().split("  ")[0].rstrip(":"))
            for n, (row, line) in enumerate(selectable)
            if screen.chars[row][2] == 0x10
        ]

    def _open_submenus(
        self, rights: int, keys: list[int], title: str, screen: Screen, out: list, levels: int
    ) -> None:
        if levels <= 0:
            return
        before = screen.text().split("\n")[3:21]
        for downs, label in self.submenus(screen):
            path = keys + DOWN * downs + ENTER
            sub, reason = self.capture(rights, path)
            after = sub.text().split("\n")[3:21]
            if sum(a != b for a, b in zip(before, after)) < len(before) // 2:
                continue  # a pop-up dialog over the page, not a page of its own
            out.append((f"{title} > {label}", sub, reason))
            self._open_submenus(rights, path, f"{title} > {label}", sub, out, levels - 1)
