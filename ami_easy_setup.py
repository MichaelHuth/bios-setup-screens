"""
Capture the setup screens of AMIBIOS with the "EASY SETUP UTILITIES" (a text-mode setup with a
menu bar: Main, Advanced, Security, Exit; core 06/27/98 and later, e.g. AMD-751 + VIA 686 Athlon
boards) by running the whole ROM in the x86 emulator.

Worked out on a K7 board (AMIBIOS 08/23/99, AMD-751 north bridge, VIA VT82C686 south bridge):
- POST stops at the CMOS error ("Press F1 to Run SETUP"); F1 starts the setup;
- F5 (Setup Defaults) and Enter load the defaults;
- Right walks the menu bar (the selected tab is drawn bright, 7Fh); Down moves the cursor (the
  selected value is drawn 07h); Enter on an entry showing "[ Enter ]" (and on the IDE drives of
  Main) opens its page, whose items scroll with Down (a scroll bar with arrows at the right).
"""

from __future__ import annotations

import ami
import ami_setup
import bios_emu
from textscreen import Screen

TITLE = b"EASY SETUP UTILITIES"
F1, F2, DEL, F5 = [0x3B, 0xBB], [0x3C, 0xBC], [0x53, 0xD3], [0x3F, 0xBF]
DOWN, RIGHT, ENTER = [0xE0, 0x50, 0xE0, 0xD0], [0xE0, 0x4D, 0xE0, 0xCD], [0x1C, 0x9C]
TAB_ROW, FIRST_ROW, LAST_ROW, LEFT_COLS = 2, 4, 22, 53
TAB_ATTR, CURSOR_ATTR = 0x7F, 0x07
SKIP = ("PASSWORD", "EXIT", "LOAD", "AUTO-DETECT", "LANGUAGE", "DISCARD", "SAVING")
MAX_TABS, MAX_PAGE_SCREENS = 6, 4


def _modules(rom: bytes) -> list[dict]:
    try:
        return ami.extract(rom)[1]
    except Exception:
        return []


def is_easy_setup(rom: bytes) -> bool:
    return TITLE in rom + b"".join(m.get("data") or b"" for m in _modules(rom))


def selected_tab(screen: Screen) -> str:
    row = screen.attrs[TAB_ROW]
    cols = [c for c in range(screen.cols) if row[c] == TAB_ATTR]
    if not cols:
        return ""
    line = screen.text().split("\n")[TAB_ROW]
    return line[cols[0] : cols[-1] + 1].strip()


def cursor_row(screen: Screen) -> int | None:
    for row in range(FIRST_ROW, LAST_ROW):
        if any(screen.attrs[row][c] == CURSOR_ATTR for c in range(20, LEFT_COLS)):
            return row
    return None


class AmiEasySetup:
    def __init__(self, rom: bytes):
        modules = _modules(rom)
        hints = b"".join(m.get("data") or b"" for m in modules)
        if TITLE not in rom + hints:
            raise ValueError("not an AMIBIOS with the Easy Setup")
        cmos, cmos_hi = ami_setup.default_cmos(), None
        for _ in range(4):  # the boot block resets once to mark the CMOS (FCh = 3Dh, rc6103)
            emu = bios_emu.BiosEmulator(rom, cmos=cmos, max_instructions=100_000_000, hints=hints)
            if not emu.pci_devices:
                raise ValueError(
                    f"this board's chipset is not emulated ({bios_emu.EMULATED}), "
                    "so its POST cannot run"
                )
            if cmos_hi is not None:
                emu.cmos_hi[:] = cmos_hi
            screen = emu.run(0xF000, 0xFFF0)
            if emu.stopped_reason != "reset":
                break
            cmos, cmos_hi = bytes(emu.cmos), bytes(emu.cmos_hi)
        for _ in range(4):
            if "EASY SETUP" in screen.text() and selected_tab(screen):
                break
            if not emu.stopped_reason.startswith(("waiting", "polling")):
                break
            text = screen.text().upper()  # (MSI MS-6156ZX: F2 runs setup, F1 loads defaults)
            emu.press_keys(
                F1 if "F1 TO RUN SETUP" in text else F2 if "F2 TO RUN SETUP" in text else DEL
            )
            screen = emu.resume()
        if "EASY SETUP" not in screen.text() and emu.stopped_reason.startswith("booting"):
            # a valid CMOS and no error pause (Fujitsu-Siemens Celsius 620, whose "Hit DEL"
            # message is switched off): DEL once POST shows its AMIBIOS line
            retry = bios_emu.BiosEmulator(rom, cmos=cmos, max_instructions=100_000_000, hints=hints)
            if cmos_hi is not None:
                retry.cmos_hi[:] = cmos_hi
            retry.press_keys(DEL * 3, when_text="AMIBIOS")
            again = retry.run(0xF000, 0xFFF0)
            if "EASY SETUP" in again.text():
                emu, screen = retry, again
        if "EASY SETUP" not in screen.text():
            raise ValueError(f"AMIBIOS Easy Setup did not start (stopped: {emu.stopped_reason})")
        emu.max_instructions = 50_000_000
        self.emu = emu
        for keys in (F5, ENTER):  # Setup Defaults, confirmed
            screen = self._key(keys)
        self.start = emu.snapshot()

    def _key(self, keys: list[int]) -> Screen:
        self.emu.press_keys(keys, paced=True)
        return self.emu.resume()

    def capture(self, path: list[list[int]]) -> Screen:
        self.emu.restore(self.start)
        screen = self.emu.screen()
        for keys in path:
            screen = self._key(keys)
        return screen

    def _rows(self, path: list[list[int]], screen: Screen) -> dict[int, int]:
        """Row -> number of Down presses that bring the cursor there, from the top of a tab."""
        rows, downs = {}, 0
        row = cursor_row(screen)
        while row is not None and row not in rows and downs < 24:
            rows[row] = downs
            screen = self._key(DOWN)
            downs += 1
            row = cursor_row(screen)
        return rows

    def _page(self, path: list[list[int]], title: str, page: Screen, out: list) -> None:
        """A page and its continuations: Down past the visible items scrolls it."""
        lines = [l for l in page.text().split("\n")[FIRST_ROW:LAST_ROW] if l[:LEFT_COLS].strip()]
        out.append((title, page, self.emu.stopped_reason))
        screen, n = page, 1
        while "▼" in screen.text() and n < MAX_PAGE_SCREENS:
            before = screen.text()
            for _ in range(len(lines)):
                screen = self._key(DOWN)
            if screen.text() == before:
                break
            n += 1
            out.append((f"{title} ({n})", screen, self.emu.stopped_reason))

    def screens(self) -> list[tuple[str, Screen, str]]:
        out, seen = [], set()
        for n in range(MAX_TABS):
            tab_path = [RIGHT] * n
            screen = self.capture(tab_path)
            title = selected_tab(screen)
            if not title or title in seen:
                break
            seen.add(title)
            out.append((title, screen, self.emu.stopped_reason))
            rows = self._rows(tab_path, screen)
            lines = screen.text().split("\n")
            for row, downs in sorted(rows.items(), key=lambda r: r[1]):
                text = lines[row][:LEFT_COLS]
                label = text[:34].strip()  # (the value starts in column 34)
                opens = "[ Enter ]" in text or (
                    "IDE" in label and ("Master" in label or "Slave" in label)
                )
                if not opens or any(w in label.upper() for w in SKIP):
                    continue
                page = self.capture(tab_path + [DOWN] * downs + [ENTER])
                bar = [x.split("\n")[TAB_ROW] for x in (page.text(), screen.text())]
                if bar[0] == bar[1]:  # a page shows only its tab's name in the bar
                    continue  # nothing opened
                self._page(tab_path, f"{title} > {label}", page, out)
        return out
