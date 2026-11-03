"""
Capture the setup screens of PhoenixBIOS 4.0 (Release 6.x, about 1998-2002: "PhoenixBIOS Setup
Utility" with the menu bar Main / Advanced / Security / Power / Boot / Exit) by running the
whole ROM in the x86 emulator.

Worked out on an MSI MS-6178-style board BIOS (mew-am-v202.bin: PhoenixBIOS 4.0 Release 6.0,
Intel 810 + ICH):
- the image is a BCPSYS archive; the chipset's PCI IDs are only in the compressed modules,
  which are handed to the emulator so it builds the right PCI devices (i810, ICH with IDE,
  SMBus and AC'97); memory is sized from a DIMM's SPD data over the SMBus;
- the setup key is named in the BIOS's texts ("Press <F2> to enter SETUP"; some OEM versions
  use F1). With an empty CMOS, POST stops at an error ("System CMOS checksum bad") and offers
  the setup key; some versions reset the PC and enter setup on the next POST;
- with Quiet Boot, setup draws in 640x480 graphics with its own 8x19 font from the strings
  module (STRPACK). The font is found by matching the setup title on row 0 against it; the
  screen is then read back as 25 rows of text;
- the right arrow moves along the menu bar; the selected tab is the one in another color;
- entries marked with ► open a sub-menu: the cursor starts on the first selectable entry (a
  value in brackets or ►), so the down arrow is pressed for each one before it, then Enter
  (two levels deep).
"""

from __future__ import annotations

import collections
import re
import zlib

import ami_setup
import bios_emu
import phoenix
from textscreen import Screen

RIGHT = [0xE0, 0x4D, 0xE0, 0xCD]
DOWN = [0xE0, 0x50, 0xE0, 0xD0]
ENTER = [0x1C, 0x9C]
F_KEYS = {1: [0x3B, 0xBB], 2: [0x3C, 0xBC]}
DEL = [0x53, 0xD3]
MAX_TABS = 10
SUB_LEVELS = 2  # sub-menus and the sub-menus they open
MAX_STATES = 64  # saved machine states (about 1.5 MB each) that later captures start from
WAITING = ("waiting for a key", "polling the keyboard")
NO = [0x31, 0xB1]  # N
SPACE = [0x39, 0xB9]
F_KEY_CODES = {n: [0x3A + n, 0xBA + n] for n in range(1, 11)}  # F1-F10
BULLETS = re.compile(r"│ • ([^│]+?)\s*│")  # "│ • System Setup   │"
FKEY_MENU = re.compile(r"F(\d)-([A-Z][A-Z0-9./]*(?: [A-Z0-9./]+)*)")
FONT_HEIGHTS = (19, 16, 14)


def _modules(rom: bytes) -> list[dict]:
    try:
        _, modules = phoenix.extract(rom)
    except Exception:
        return []
    return modules


def is_phoenix_setup(rom: bytes) -> bool:
    modules = _modules(rom)
    return any(m.get("name") == "setup" for m in modules) and any(
        (m.get("data") or b"").startswith(b"STRPACK") for m in modules
    )


def _strings(modules: list[dict]) -> bytes:
    return next(
        (m.get("data") or b"" for m in modules if (m.get("data") or b"").startswith(b"STRPACK")),
        b"",
    )


def _setup_key(strings: bytes) -> list[int]:
    for n in (2, 1):
        if f"<F{n}> to enter SETUP".encode() in strings:
            return F_KEYS[n]
    if b"<DEL> to enter SETUP" in strings:  # (TriGem Dublin, PhoenixBIOS 4.0 6.0 of 2001)
        return DEL
    return F_KEYS[2]


def _screen_key(text: str) -> list[int] | None:
    """The setup key an error pause names ("Press <F1> to resume,  <DEL> to Setup": Phoenix
    "2962 Vent", whose strings module also has the F2 prompt), or None."""
    m = re.search(r"<(DEL|F\d)> to (?:enter )?Setup", text, re.I)
    if m is None:
        return None
    name = m.group(1).upper()
    return DEL if name == "DEL" else F_KEY_CODES.get(int(name[1:]))


def _title(strings: bytes) -> bytes:
    i = strings.find(b"Setup Utility")
    if i < 0:  # (Samsung Alioth 50C: "BIOS Setup")
        i = strings.find(b"\0BIOS Setup\0") + 1 or -1
    start = strings.rfind(b"\0", 0, i) + 1
    return strings[start : strings.find(b"\0", i)]


def _cell_mask(emu: bios_emu.BiosEmulator, col: int, row: int, h: int) -> bytes:
    """The pixels of a text cell (8 x h, rows of h pixels) not in its most common color."""
    lines: list[list[int]] = []
    counts: collections.Counter[int] = collections.Counter()
    for y in range(h):
        o = (row * h + y) * 80 + col
        b = [p[o] for p in emu.vga_planes]
        line = [
            (b[0] >> 7 - x & 1)
            | (b[1] >> 7 - x & 1) << 1
            | (b[2] >> 7 - x & 1) << 2
            | (b[3] >> 7 - x & 1) << 3
            for x in range(8)
        ]
        lines.append(line)
        counts.update(line)
    bg = counts.most_common(1)[0][0]
    return bytes(sum((c != bg) << 7 - x for x, c in enumerate(line)) for line in lines)


def _find_font(
    emu: bios_emu.BiosEmulator, strings: bytes, title: bytes
) -> tuple[bytes, int] | None:
    """(font, height) the setup draws with: the title on row 0 found glyph by glyph in the
    strings module, the font's start being where the glyphs' offsets agree."""
    for h in FONT_HEIGHTS:
        cells = [_cell_mask(emu, col, 0, h) for col in range(80)]
        used = [col for col in range(80) if any(cells[col])]
        if not used:
            continue
        for start in range(max(0, used[0] - 2), used[0] + 3):
            votes: collections.Counter[int] = collections.Counter()
            for k, ch in enumerate(title):
                col = start + k
                if col >= 80 or ch == 0x20 or not any(cells[col]):
                    continue
                i = strings.find(cells[col])
                while i >= 0:
                    votes[i - ch * h] += 1
                    i = strings.find(cells[col], i + 1)
            if votes:
                base, n = votes.most_common(1)[0]
                if base >= 0 and n >= min(5, len(title.replace(b" ", b"")) - 1):
                    return strings[base : base + 256 * h], h
    return None


def bar_row(screen: Screen) -> int:
    """The menu bar's row: the one above the box (row 1; 2 below a second title line, HP;
    0 without a title line, PR11)."""
    for row in range(1, 6):
        if screen.chars[row][0] in (0xDA, 0xC9):  # ┌ or ╔ at the left edge
            return row - 1
    return 1


def selected_tab(screen: Screen) -> str:
    """The menu bar entry shown in another color than the rest of the bar."""
    row = bar_row(screen)
    cells = list(zip(screen.chars[row], screen.attrs[row]))
    counts = collections.Counter(a for c, a in cells if c != 0x20).most_common(1)
    if not counts:  # an empty bar row: no tab to name (Samsung Alioth 50C)
        return ""
    common = counts[0][0]
    text = bytes(c for c, a in cells if a != common and a >> 4 != common >> 4)
    return text.decode("cp437").strip()


class PhoenixSetup:
    def __init__(self, rom: bytes):
        modules = _modules(rom)
        strings = _strings(modules)
        if not strings:
            raise ValueError("not a PhoenixBIOS 4.0 image with a strings module")
        hints = b"".join(m.get("data") or b"" for m in modules)
        title, key = _title(strings), _setup_key(strings)
        if not title:  # (an empty title is found on any screen: Samsung Alioth 50C's blank one)
            raise ValueError("the PhoenixBIOS strings module names no setup title")
        cmos, cmos_hi, pressed = ami_setup.default_cmos(), None, False
        prosec = b"#Pro-Sec#" in rom  # Apricot/Mitsubishi (HN440, 1999): the
        # boot block goes on to the main BIOS only with CMOS 40h 5Ah or 87h, and checks a byte
        # sum over romexec in F000, which the emulator's MSR patches there would spoil
        if prosec:
            cmos = cmos[:0x40] + b"\x87" + cmos[0x41:]
        # TriGem Dublin ("31811.EM", ICH2, 2001): its INT 09h handler takes
        # DEL for setup only with I/O port 102Ch bit 6 set (a board strap or GPIO)
        ports = {0x102C: 0x40} if b"$IBIOSI$31811.EM" in rom else {}
        for _ in range(6):
            emu = bios_emu.BiosEmulator(
                rom, cmos=cmos, max_instructions=900_000_000, hints=hints, ram_mb=32
            )
            if prosec:
                emu.msr_patch_end = 0xF0000
            emu.io_reads = dict(ports)
            if not emu.pci_devices:  # the POST would only wander about
                raise ValueError(
                    f"this board's chipset is not emulated ({bios_emu.EMULATED}), "
                    "so its POST cannot run"
                )
            if cmos_hi is not None:
                emu.cmos_hi[:] = cmos_hi
            screen = emu.run(0xF000, 0xFFF0)
            if emu.stopped_reason == "booting (INT 19h)" and not pressed:
                # no error pause to offer setup: the setup key pressed while POST asks for
                # keys (Fujitsu-Siemens D1326, after its logo)
                emu = bios_emu.BiosEmulator(
                    rom, cmos=cmos, max_instructions=900_000_000, hints=hints, ram_mb=32
                )
                if prosec:
                    emu.msr_patch_end = 0xF0000
                emu.io_reads = dict(ports)
                if cmos_hi is not None:
                    emu.cmos_hi[:] = cmos_hi
                emu.press_keys(key * 3, paced=True)
                pressed = True
                screen = emu.run(0xF000, 0xFFF0)
            for _ in range(4):
                if emu.video_mode in bios_emu.PLANAR_MODES and emu.graphics_font is None:
                    emu.graphics_font = _find_font(emu, strings, title)
                    screen = emu.screen()
                if title.decode("cp437") in screen.text():
                    break
                if emu.stopped_reason not in ("waiting for a key", "polling the keyboard"):
                    break
                emu.press_keys(_screen_key(screen.text()) or key, paced=True)  # the error pause
                # offers the setup key
                pressed = True
                screen = emu.resume()
            if title.decode("cp437") in screen.text() or emu.stopped_reason not in (
                "reset",
                "halted",
            ):
                break
            if emu.stopped_reason == "halted" and bytes(emu.cmos) == cmos:
                break  # halted for good (with a CMOS flag set it waits for the board's reset
                # after a chipset change, ASUS SP-AX, and goes on from there)
            cmos, cmos_hi = bytes(emu.cmos), bytes(emu.cmos_hi)  # setup comes after a reset
        if title.decode("cp437") not in screen.text():
            raise ValueError(
                f"PhoenixBIOS setup did not start (stopped: {emu.stopped_reason}"
                f"{', setup key pressed' if pressed else ''})"
            )
        emu.max_instructions = 200_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.states: dict[tuple[int, ...], tuple] = {}

    def _before_keys(self) -> None:
        """Called after a saved state is restored, before keys are pressed."""

    def capture(self, rights: int, keys: list[int] | None = None) -> tuple[Screen, str]:
        """The screen after moving right along the menu bar (and pressing more keys). It runs
        from the screen furthest along the way that was captured before (a tab or sub-menu,
        saved with its memory compressed), so only the remaining keys are pressed."""
        emu = self.emu
        path = tuple(RIGHT * rights + (keys or []))
        if not path:
            return self.main, "waiting for a key"
        done = max((k for k in self.states if path[: len(k)] == k), key=len, default=())
        if done:
            self.states[done] = self.states.pop(done)  # used: the last to be dropped
            memory, state, cpu = self.states[done]
            emu.restore((zlib.decompress(memory), state, cpu))
        else:
            emu.restore(self.start)
        self._before_keys()
        emu.press_keys(list(path[len(done) :]), paced=True)
        screen, reason = emu.resume(), emu.stopped_reason
        if reason in WAITING and MAX_STATES:
            if len(self.states) >= MAX_STATES:  # the one used longest ago goes
                self.states.pop(next(iter(self.states)))
            memory, state, cpu = emu.snapshot()
            self.states[path] = zlib.compress(memory, 1), state, cpu
        return screen, reason

    @staticmethod
    def submenus(screen: Screen) -> list[tuple[int, str]]:
        """[(down presses, label)] of the entries marked with ► that open a sub-menu: the
        cursor starts on the first entry that can be selected (a value in brackets or ►)."""
        selectable = []
        shift = bar_row(screen) - 1  # (a second title line moves everything down)
        first = 5 if screen.chars[4 + shift][0] == 0xC3 else 3  # a sub-menu: title and a line above
        for row in range(first + shift, screen.rows - 3):
            line = bytes(screen.chars[row][1:53]).decode("cp437")
            if screen.chars[row][2] == 0x10 or "[" in line:
                selectable.append((row, line))
        return [
            (n, re.split(r"\s{2,}|\[", line[2:].strip())[0].rstrip(":"))
            for n, (row, line) in enumerate(selectable)
            if screen.chars[row][2] == 0x10
        ]

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)] for every tab of the menu bar, each followed by the
        sub-menus it opens (SUB_LEVELS deep)."""
        out, seen = [], set()
        for n in range(MAX_TABS):
            screen, reason = self.capture(n)
            title = selected_tab(screen)
            if not title or title in seen:
                break
            seen.add(title)
            out.append((title, screen, reason))
            self._open_submenus(n, [], title, screen, out, SUB_LEVELS)
        return out

    def _open_submenus(
        self, rights: int, keys: list[int], title: str, screen: Screen, out: list, levels: int
    ) -> None:
        if levels <= 0:
            return
        for downs, label in self.submenus(screen):
            path = keys + DOWN * downs + ENTER
            sub, reason = self.capture(rights, path)
            if sub.text() == screen.text():
                continue
            out.append((f"{title} > {label}", sub, reason))
            self._open_submenus(rights, path, f"{title} > {label}", sub, out, levels - 1)


BOX_MENU = "\u2561 Basic Options \u255e"
BOX_PAGES = ("Shadow RAM", "Advanced Options", "PCI Options")


def _box_entries(text: str) -> list[str]:
    """The entries of the box, in the order the Down key goes through them."""
    return [m.group(1).strip() for m in re.finditer(r"\u2551  (\S[^\u2551]*?)\s*\u2551", text)]


def _setup_heading(text: str) -> bool:
    """The setup's screen: its title, or the help column of a setup without one (a
    PhoenixBIOS 4.05 with only Main, Advanced and Exit, PR11)."""
    return "PhoenixBIOS Setup" in text or "Item Specific Help" in text


def is_phoenix_text_setup(rom: bytes) -> bool:
    """PhoenixBIOS 4.0x of 1994-96 (e.g. NuBIOS 4.04): the same menu-bar setup in text mode
    (its texts compressed in the ROM)."""
    return (b"Phoenix NuBIOS" in rom or b"PhoenixBIOS Version 4.0" in rom) and not (
        is_phoenix_setup(rom)
    )


class PhoenixTextSetup(PhoenixSetup):
    """The menu-bar setup of early PhoenixBIOS 4.0x (worked out on Micronics M54Pi, NuBIOS
    4.04, Intel 430NX "Neptune" with PCI configuration mechanism #2): POST stops at its errors
    with "Press <F1> to resume, <F2> to Setup"; the setup first says that the CMOS checksum is
    invalid and default values will be loaded ([Continue] with Enter). The rest is walked as
    in the later versions."""

    def __init__(self, rom: bytes):
        if not is_phoenix_text_setup(rom):
            raise ValueError("not an early PhoenixBIOS 4.0 with the text-mode menu-bar setup")
        emu = bios_emu.BiosEmulator(
            rom, cmos=ami_setup.default_cmos(), max_instructions=300_000_000
        )
        # (with no chipset found the POST of a whole image may still get through: Anigma
        # P4D-420TX, Intel 420TX "Saturn", which the ROM addresses by device number only)
        if not emu.pci_devices and len(rom) <= 0x10000:
            raise ValueError(
                f"this board's chipset is not emulated ({bios_emu.EMULATED}), "
                "so its POST cannot run"
            )
        emu.kbc_reset_in_place = True  # (POST returns from protected mode by a CPU reset)
        screen = emu.run(0xF000, 0xFFF0)
        if emu.stopped_reason.startswith("booting") and b"<F2> to enter SETUP" in rom:
            # the prompt goes by without a pause (Tatung TCS-9510, PhoenixBIOS 4.01): POST
            # again, F2 pressed once it is on the screen
            emu = bios_emu.BiosEmulator(
                rom, cmos=ami_setup.default_cmos(), max_instructions=300_000_000
            )
            emu.kbc_reset_in_place = True
            emu.press_keys(F_KEYS[2], when_text="to enter SETUP")
            screen = emu.run(0xF000, 0xFFF0)
        for _ in range(4):
            text = screen.text()
            if "Main" in text and "Exit" in text and _setup_heading(text):
                break
            if FKEY_MENU.search(text) or BULLETS.search(text) or BOX_MENU in text:
                break
            if emu.stopped_reason not in WAITING:
                break
            if "[Continue]" in text and (_setup_heading(text) or "Warning!" in text):
                emu.press_keys(ENTER, paced=True)  # defaults loaded
            elif "auto-configure hard drives" in text:
                emu.press_keys(NO, paced=True)  # (DTI ESP3520: defaults loaded first)
            elif "<space> to continue" in text:
                emu.press_keys(SPACE, paced=True)  # (Tatung TCS-9510: a title screen first)
            else:  # (PR11: "<F1> to Setup")
                emu.press_keys(_screen_key(text) or F_KEYS[2], paced=True)
            screen = emu.resume()
        # an OEM setup with a column of function keys (Diversified Technology ESP3520,
        # PhoenixBIOS 4.03): "F1-SYSTEM SUMMARY", "F2-SYSTEM SETUP" ... each opens a page
        self.fkeys = [
            (int(n), name.strip())
            for n, name in FKEY_MENU.findall(screen.text())
            if not re.match(r"(LOAD|SAVE)\b", name.strip())
        ]
        # PhoenixBIOS 4.01's "DragonBIOS Setup" (Tatung TCS-9510): a Main Menu box whose
        # entries marked with a bullet open pages (Down to each, Enter)
        self.bullets = [m.strip() for m in BULLETS.findall(screen.text())]
        # an OEM setup with a box of entries beside a panel of all values (RadiSys EPC-2102,
        # PhoenixBIOS 4.05a): its other panels open from entries of the box
        self.box_entries = _box_entries(screen.text()) if BOX_MENU in screen.text() else []
        if self.box_entries and emu.stopped_reason in WAITING:
            emu.max_instructions = 100_000_000
            self.emu, self.start, self.main = emu, emu.snapshot(), screen
            self.states = {}
            return
        if (self.fkeys or self.bullets) and emu.stopped_reason in WAITING:
            emu.max_instructions = 100_000_000
            self.emu, self.start, self.main = emu, emu.snapshot(), screen
            self.states = {}
            return
        if not (_setup_heading(screen.text()) and selected_tab(screen)):
            hint = (
                ""
                if emu.pci_devices
                else (f"; the board's chipset is not emulated " f"({bios_emu.EMULATED})")
            )
            raise ValueError(
                f"PhoenixBIOS setup did not start (stopped: {emu.stopped_reason}" f"{hint})"
            )
        emu.max_instructions = 100_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.states = {}

    def screens(self) -> list[tuple[str, Screen, str]]:
        if self.box_entries:
            out = [("Basic Options", self.main, self.emu.stopped_reason)]
            for label in BOX_PAGES:
                if label in self.box_entries:
                    self.emu.restore(self.start)
                    keys = DOWN * self.box_entries.index(label) + ENTER
                    self.emu.press_keys(keys, paced=True)
                    out.append((label, self.emu.resume(), self.emu.stopped_reason))
            return out
        if self.bullets and not self.fkeys:
            out = [("Main Menu", self.main, self.emu.stopped_reason)]
            for n, label in enumerate(self.bullets):
                self.emu.restore(self.start)
                self.emu.press_keys(DOWN * n + ENTER, paced=True)
                screen = self.emu.resume()
                out.append((label, screen, self.emu.stopped_reason))
            return out
        if not self.fkeys:
            return super().screens()
        out = []
        for n, name in self.fkeys:  # each page from the main menu, by its function key
            self.emu.restore(self.start)
            self.emu.press_keys(F_KEY_CODES[n], paced=True)
            screen = self.emu.resume()
            out.append((name.title(), screen, self.emu.stopped_reason))
        return out
