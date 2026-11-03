"""
Capture the setup screens of AMIBIOS 7 boards with AMI's "NEW SETUP UTILITY" (about 2002-2005,
an Award-style main menu in two columns, e.g. MSI 865PE Neo2) by running the whole ROM in the
x86 emulator.

Worked out on an MSI 865PE Neo2-P BIOS (A6728IMS V3.9, AMIBIOS 07.00, Intel 865 + ICH5):
- the image's modules (AMIBIOS 7 format, "AMIBIOSC0700") are unpacked; the chipset's PCI IDs
  in them make the emulator build the i865 and ICH5 devices (the BIOS stops early on a host
  bridge older than stepping A2), memory is sized from DDR SPD data;
- POST shows AMI's logo screen in 640x480 graphics and, with an empty CMOS, stops at its
  error pause; F1 there starts the setup (DEL otherwise);
- the setup draws in 640x480 graphics with the VGA font (read back as 25 rows of text). The
  selected entry has a red background; the menus are walked by following it: Down until it
  is back on the first entry (Right first for the second column of the main menu), Enter on
  the entries marked with ►, which open pages, and on those pages' ► entries (two levels).

AMIBIOS 6 (core 06/26) with the same modules: Gateway 2000's 430TX board (0AAGT046)
answers its error pause ("RUN SETUP") with ESC, not F1, and draws a tabbed setup without
a title: the menu bar in row 0, the selected tab only in a lighter foreground, entries that
open a page say "Press Enter" instead of a ►.
"""

from __future__ import annotations

import collections
import re
import zlib

import ami
import bios_emu
import phoenix_setup
from phoenix_setup import DOWN, ENTER
from textscreen import Screen

TITLE = "SETUP UTILITY"
SERVERWORKS = b"CNB BootBlock Table"
LIST_MARK = "Standard CMOS Setup"
LIST_SKIP = ("Password", "Exit", "Saving", "Auto Configuration")
LIST_ENTER, LIST_DOWN = [0x1C, 0x9C], [0x50, 0xD0]
MAX_LIST, MAX_LIST_DOWNS = 20, 40
ARROW = ""
F1, F2, DEL, ESC = [0x3B, 0xBB], [0x3C, 0xBC], [0x53, 0xD3], [0x01, 0x81]
MAX_ENTRIES = 30  # Down presses before giving up on the cursor coming back
SUB_LEVELS = 2  # pages of the main menu and the pages they open
CURSOR_BG = 4  # red
TABBED_CURSOR = 0x7F  # the tabbed setup's selected entry: white on grey
MAX_DOWNS = 40  # Down presses looking for the ► entries of a tabbed page
ARROW = chr(0x10)  # ► in the screen's CP437 codes


def _modules(rom: bytes) -> tuple[dict, list[dict]]:
    try:
        return ami.extract(rom)
    except Exception:
        return {}, []


def is_amibios7(rom: bytes, version: str = "07") -> bool:
    info, modules = _modules(rom)
    names = {m.get("name") for m in modules}
    return (
        info.get("version", "").startswith(version)
        and {
            "Setup Client",
            "Setup Server",
        }
        <= names
    )


def is_amibios6(rom: bytes) -> bool:
    """AMIBIOS 6 with the same setup modules (Gateway 2000, 430TX)."""
    return is_amibios7(rom, "06")


def listed_entry(screen: Screen, first: int = 3) -> str:
    """The entry under the cursor of a list menu: the row with a light background (with what
    stands before the cursor, a triangle)."""
    for row in range(first, screen.rows - 3):
        cells = [c for c in range(screen.cols) if screen.attrs[row][c] >> 4 & 7 == 7]
        if cells:
            line = bytes(screen.chars[row][: cells[-1] + 1]).decode("cp437")
            return line.replace("║", " ").replace("│", " ").strip()
    return ""


def page_rows(screen: Screen) -> set[str]:
    """The items a page of the list menu shows: its left panel without the frame."""
    rows = (bytes(screen.chars[row][1:53]).decode("cp437").strip() for row in range(4, 22))
    return {row for row in rows if row}


def plain_tab(screen: Screen) -> str:
    """The selected tab of a menu bar in row 0 (AMIBIOS 6, Gateway): the cells of the
    bar in another color than most of it (here only the foreground differs)."""
    if "Main" not in bytes(screen.chars[0]).decode("cp437"):
        return ""
    cells = list(zip(screen.chars[0], screen.attrs[0]))
    counts = collections.Counter(a for c, a in cells if c != 0x20).most_common(1)
    if not counts:
        return ""
    return bytes(c for c, a in cells if a != counts[0][0]).decode("cp437").strip()


def cursor(screen: Screen) -> tuple[int, int, int] | None:
    """(row, first column, last column) of the selected entry: the cells with a red
    background (the first run of them)."""
    for row in range(1, screen.rows - 1):
        cols = [c for c in range(screen.cols) if screen.attrs[row][c] >> 4 & 7 == CURSOR_BG]
        if cols:
            return row, cols[0], cols[-1]
    return None


def _label(screen: Screen, row: int, col: int) -> str:
    """The entry's name: the text of its row from its frame (or the cursor) on, up to the
    gap before its value."""
    line = bytes(screen.chars[row]).decode("cp437")
    start = line.rfind("│", 0, col + 1) + 1 if "│" in line[: col + 1] else 0
    start = max(start, line.rfind("║", 0, col + 1) + 1)
    text = line[start:].replace(ARROW, " ").strip()
    return re.split(r"\s{2,}|│|║", text)[0].strip().rstrip(" .")


def _opens_page(screen: Screen, row: int, col: int) -> bool:
    """Entries marked with ► (just before the name, or at the cursor's left end)."""
    line = bytes(screen.chars[row]).decode("cp437")
    start = max(line.rfind("│", 0, col + 1), line.rfind("║", 0, col + 1)) + 1
    return ARROW in line[start : start + 4] or ARROW in line[col : col + 2]


def _marked_rows(screen: Screen) -> list[int]:
    """Rows with an entry marked "► " (the key help's "►Sub-Menu" is not one)."""
    return [
        row
        for row in range(screen.rows)
        for col in range(1, screen.cols - 1)
        if screen.chars[row][col] == 0x10
        and screen.chars[row][col + 1] == 0x20
        and screen.chars[row][col - 1] in (0x20, 0xB3, 0xBA)
    ]


def _body(screen: Screen) -> bytes:
    """The left part of the screen (the entries, not the help that follows the cursor)."""
    half = screen.cols * 2 // 3
    return b"".join(bytes(screen.chars[row][:half]) for row in range(screen.rows))


class AmiBios7(phoenix_setup.PhoenixSetup):
    def __init__(self, rom: bytes):
        if not (is_amibios7(rom) or is_amibios6(rom)):
            raise ValueError("not an AMIBIOS 7 image with the new setup utility")
        _, modules = _modules(rom)
        hints = b"".join(m.get("data") or b"" for m in modules)
        try:
            self._start(rom, hints, False)
        except ValueError as e:
            # (a time limit would only double; not emulated: nothing to try)
            if "time limit" in str(e) or str(e).startswith("this board"):
                raise
            try:  # (845GV-M, PE Pro-HT: POST stops on setup options read as zero)
                self._start(rom, hints, True)
            except ValueError:
                raise e from None

    def _start(self, rom: bytes, hints: bytes, cleared: bool) -> None:
        """POST up to the setup. cleared: the CMOS's setup bytes read FFh, not 00h."""
        # an empty CMOS, but a working clock (status registers A, B and D: battery good)
        fresh = bytearray(128)
        fresh[0x0A], fresh[0x0B], fresh[0x0D] = 0x26, 0x02, 0x80
        fresh[0x06:0x0A] = bytes([0x07, 0x01, 0x01, 0x00])  # Saturday, 01/01/(20)00, BCD
        fresh[0x32] = 0x20
        if cleared:
            fresh[0x10:0x80] = b"\xff" * 0x70
        cmos: bytes = bytes(fresh)
        cmos_hi: bytes | None = None
        serverworks = SERVERWORKS in rom  # (its POST's own table of CNB20 registers)
        for _ in range(4):  # some boards reset once early in POST (noted in the CMOS)
            emu = bios_emu.BiosEmulator(
                rom,
                cmos=cmos,
                max_instructions=300_000_000,
                hints=hints,
                ram_mb=64,
                timer_irq=serverworks,
            )
            if serverworks:
                emu.serverworks, emu.smbus_base = True, 0x580
                # (POST tests text memory if INT 10h stays in F000, with a count the APIC
                # code left in EBX: over its own copy in the F000 shadow)
                emu._video_rom(hook_int10=True)
            if not emu.pci_devices:  # the POST would only wander about
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
        for key in (F1, DEL, DEL):  # the error pause: F1 runs setup on these boards
            if TITLE in screen.text():
                break
            if emu.stopped_reason not in ("waiting for a key", "polling the keyboard"):
                break
            if "F2 to Run SETUP" in screen.text():  # ASRock: F1 would load defaults and boot
                key = F2
            emu.press_keys(key)
            screen = emu.resume()
        # (Gateway's AMIBIOS 6: the pause shows "RUN SETUP" and answers only ESC)
        if (
            TITLE not in screen.text()
            and "RUN SETUP" in screen.text()
            and emu.stopped_reason in ("waiting for a key", "polling the keyboard")
        ):
            emu.press_keys(ESC, paced=True)
            screen = emu.resume()
        self.plain = (
            TITLE not in screen.text()
            and "Save & Exit" in screen.text()
            and bool(plain_tab(screen))
        )
        # the tabbed text-mode setup ("AMIBIOS SETUP UTILITY - VERSION 3.31a", ASRock
        # 775i45GV): a menu bar Main/Advanced/..., walked like PhoenixBIOS's
        self.tabbed = "Main" in bytes(screen.chars[1]).decode("cp437") and bool(
            phoenix_setup.selected_tab(screen)
        )
        self.tabbed = self.tabbed or self.plain
        # (Soyo X533: the same title over a list of entries, one below the other)
        self.listed = TITLE in screen.text() and LIST_MARK in screen.text()
        if (
            not self.plain
            and not self.listed
            and (TITLE not in screen.text() or (cursor(screen) is None and not self.tabbed))
        ):
            hint = (
                f"; POST stopped on purpose, most likely on a chipset part that is not "
                f"emulated ({bios_emu.EMULATED})"
                if emu.stopped_reason == "halted"
                else ""
            )
            raise ValueError(
                f"AMIBIOS 7 setup did not start (stopped: {emu.stopped_reason}" f"{hint})"
            )
        emu.max_instructions = 200_000_000
        self.emu, self.start, self.main = emu, emu.snapshot(), screen
        self.states: dict[tuple[int, ...], tuple] = {}

    def _listed_screens(self) -> list[tuple[str, Screen, str]]:
        """The main menu as a list: each entry opened with Enter from the state where the cursor
        is on it (Down skips what is greyed out), long pages followed with PgDn."""
        emu, reason = self.emu, "waiting for a key"
        out = [("Main Menu", self.main, reason)]
        state, screen, seen = self.start, self.main, set()
        for _ in range(MAX_LIST):
            label = listed_entry(screen)
            if not label or label in seen:
                break
            seen.add(label)
            if not any(word in label for word in LIST_SKIP):
                emu.restore(state)
                emu.press_keys(LIST_ENTER, paced=True)
                out += self._listed_page(label, emu.resume(), 2)
            emu.restore(state)
            emu.press_keys(LIST_DOWN, paced=True)
            screen = emu.resume()
            state = emu.snapshot()
        return out

    def _listed_page(self, label: str, page: Screen, levels: int) -> list[tuple[str, Screen, str]]:
        """A page of the list menu, followed with Down: again when it has scrolled; the
        entries with a triangle (a page of their own) opened."""
        emu = self.emu
        out = [(label, page, emu.stopped_reason)]
        shown, seen, screen = page_rows(page), set(), page
        for _ in range(MAX_LIST_DOWNS):
            entry = listed_entry(screen, 5)
            if not entry or entry in seen:
                break
            seen.add(entry)
            rows = page_rows(screen)
            if not rows <= shown:
                shown |= rows
                out.append((f"{label} ({len(out) + 1})", screen, emu.stopped_reason))
            if levels and entry.startswith(ARROW):
                state = emu.snapshot()
                emu.press_keys(LIST_ENTER, paced=True)
                out += self._listed_page(entry.lstrip(ARROW + " "), emu.resume(), levels - 1)
                emu.restore(state)
            emu.press_keys(LIST_DOWN, paced=True)
            screen = emu.resume()
        return out

    def capture(self, rights: int, keys: list[int] | None = None) -> tuple[Screen, str]:
        """The tabbed setup reads a key only after it has redrawn: keys typed together are
        lost, so each one (prefix, make and break code) is pressed on its own."""
        if not self.tabbed:
            return super().capture(rights, keys)
        p = phoenix_setup
        emu = self.emu
        path = tuple(p.RIGHT * rights + (keys or []))
        if not path:
            return self.main, "waiting for a key"
        done = max((k for k in self.states if path[: len(k)] == k), key=len, default=())
        if done:
            self.states[done] = self.states.pop(done)
            memory, state, cpu = self.states[done]
            emu.restore((zlib.decompress(memory), state, cpu))
        else:
            emu.restore(self.start)
        screen, reason = self.main, "waiting for a key"
        key: list[int] = []
        for code in path[len(done) :]:
            key.append(code)
            if code >= 0x80 and code != 0xE0:  # the break code ends a key
                emu.press_keys(key, paced=True)
                screen, reason, key = emu.resume(), emu.stopped_reason, []
        if reason in p.WAITING and p.MAX_STATES:
            if len(self.states) >= p.MAX_STATES:
                self.states.pop(next(iter(self.states)))
            memory, state, cpu = emu.snapshot()
            self.states[path] = zlib.compress(memory, 1), state, cpu
        return screen, reason

    @staticmethod
    def _highlighted(screen: Screen) -> int | None:
        """The tabbed setup: the row of the left panel drawn in the cursor's colors."""
        for row in range(3, screen.rows - 3):
            if any(
                screen.attrs[row][c] == TABBED_CURSOR
                for c in range(2, 30)
                if screen.chars[row][c] != 0x20
            ):
                return row
        return None

    def _open_submenus(
        self, rights: int, keys: list[int], title: str, screen: Screen, out: list, levels: int
    ) -> None:
        """The tabbed setup: the ► entries reached by pressing Down until the cursor is on
        them (values carry no brackets here, grey entries are skipped, and Down first steps
        through the fields of the date and the time)."""
        if not self.tabbed:
            super()._open_submenus(rights, keys, title, screen, out, levels)
            return
        if levels <= 0:
            return
        if self.plain:
            self._open_plain(rights, keys, title, screen, out)
            return
        # (the ► in column 2, or 4 in AMI's new setup 3.31a: Tiga TG-810M)
        arrows = {
            row: col
            for row in range(3, screen.rows - 3)
            for col in (2, 4)
            if screen.chars[row][col] == 0x10
        }
        targets = {
            row: re.split(
                r"\s{2,}", bytes(screen.chars[row][col + 2 : 53]).decode("cp437").strip()
            )[0]
            for row, col in arrows.items()
        }
        found, start = {}, self._highlighted(screen)
        if start in targets:  # the cursor starts on a ► entry
            found[start] = 0
        for downs in range(1, MAX_DOWNS):
            if len(found) == len(targets):
                break
            here, _ = self.capture(rights, keys + DOWN * downs)
            row = self._highlighted(here)
            if row is None or row == start and downs > 1 and found:
                break
            if row in targets and row not in found:
                found[row] = downs
        for row, downs in sorted(found.items()):
            path = keys + DOWN * downs + ENTER
            sub, reason = self.capture(rights, path)
            if sub.text() == screen.text():
                continue
            out.append((f"{title} > {targets[row]}", sub, reason))
            self._open_submenus(rights, path, f"{title} > {targets[row]}", sub, out, levels - 1)

    def _open_plain(
        self, rights: int, keys: list[int], title: str, screen: Screen, out: list
    ) -> None:
        """Gateway's AMIBIOS 6: no entry is marked, so every entry the cursor visits
        with Down is opened with Enter; a page replaces the menu bar with its title (value
        lists and dialogs pop up over the menu, and are left out); one level."""
        visited: set[int] = set()
        for downs in range(1, MAX_ENTRIES):
            here, _ = self.capture(rights, keys + DOWN * downs)
            row = self._highlighted(here)
            if row is None or row in visited:
                break
            visited.add(row)
            line = bytes(here.chars[row][:53]).decode("cp437")  # (labels right-aligned)
            label = re.split(r"\s{2,}", line.strip())[0]
            sub, reason = self.capture(rights, keys + DOWN * downs + ENTER)
            if not plain_tab(sub) and sub.text() not in (screen.text(), here.text()):
                out.append((f"{title} > {label}", sub, reason))

    def entries(self, rights: int, keys: list[int], screen: Screen) -> list[tuple[list, str]]:
        """[(keys from the menu's start, label)] of the entries marked with ► that the cursor
        reaches with Down from where it starts (until it is back at the top, or past the last
        ► entry on a page that does not scroll)."""
        out: list[tuple[list[int], str]] = []
        first = cursor(screen)
        if first is None or not _marked_rows(screen):  # nothing to open on this page
            return out
        here, before, visited = screen, None, set()
        for downs in range(MAX_ENTRIES):
            if downs:
                here, _ = self.capture(rights, keys + DOWN * downs)
                if cursor(here) in (None, first):  # back at the top (or lost)
                    break
            place = cursor(here)
            assert place is not None
            row, col, _ = place
            body = _body(here)
            if (row, col, body) in visited:  # the cursor does not move any more
                break
            visited.add((row, col, body))
            if body == before and row > max(_marked_rows(here), default=-1):
                break  # past the last ► entry, and the list does not scroll
            before = body
            if _opens_page(here, row, col):
                out.append((DOWN * downs, _label(here, row, col)))
        return out

    def screens(self) -> list[tuple[str, Screen, str]]:
        """[(title, screen, stop reason)]: the main menu, the pages its ► entries open (both
        columns), then the pages those open (the first images of a call are main pages)."""
        if self.listed:
            return self._listed_screens()
        if self.plain:  # (the menu bar in row 0)
            pages: list[tuple[str, Screen, str]] = []
            tabs: set[str] = set()
            for n in range(phoenix_setup.MAX_TABS):
                screen, reason = self.capture(n)
                tab = plain_tab(screen)
                if not tab or tab in tabs:
                    break
                tabs.add(tab)
                pages.append((tab, screen, reason))
                self._open_submenus(n, [], tab, screen, pages, 1)
            return pages
        if self.tabbed:
            return super().screens()  # (with submenus below)
        out = [("MAIN MENU", self.main, "waiting for a key")]
        seen = {self.main.text()}
        level = [(0, downs + ENTER, label) for downs, label in self.entries(0, [], self.main)]
        # Down goes on into the second column on some versions; else Right goes there
        found = {label for _, _, label in level}
        rest = {
            _label(self.main, row, col)
            for row in _marked_rows(self.main)
            for col in range(self.main.cols // 2, self.main.cols)
            if self.main.chars[row][col] == 0x10
        } - found
        if rest:
            column, _ = self.capture(1)
            if cursor(column) != cursor(self.main):
                level += [
                    (1, downs + ENTER, label)
                    for downs, label in self.entries(1, [], column)
                    if label not in found
                ]
        for depth in range(SUB_LEVELS):
            deeper = []
            for rights, keys, title in level:
                page, reason = self.capture(rights, keys)
                if page.text() in seen:
                    continue
                seen.add(page.text())
                out.append((title, page, reason))
                if depth + 1 < SUB_LEVELS:
                    deeper += [
                        (rights, keys + downs + ENTER, f"{title} > {label}")
                        for downs, label in self.entries(rights, keys, page)
                    ]
            level = deeper
        return out
