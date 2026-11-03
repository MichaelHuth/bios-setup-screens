"""Intel desktop-board EFI updates: the setup forms kept in the update's .ITK part.

An Intel EFI update carries the firmware image in its .BIO member and the setup's HII
packs a second time, outside the image, in a member named .ITK.  The image's own forms
are reachable for uefi_setup only through the firmware-volume chain (which needs the
_FVH anchors); the .ITK part holds the same packs bare, one string pack per language
and one IFR form pack per menu, each group of packs behind a record naming the module
that registered them.  So the menus can be read straight from the part.

Reads data only: nothing from the update is ever run.
"""

from __future__ import annotations

import struct
import uuid
from typing import NamedTuple

import intelbio
import uefi_setup
from uefi_setup import FormSet

# the part's 16-byte magic, at its very start (measured on all 14 parts)
ITK_MAGIC = bytes.fromhex("55095f77d8ab8b4790ddba74207b6bb1")
RECORD = 0x2E  # the record in front of a group of packs ...
GUID_AT = -0x2C  # ... whose module GUID sits 0x2C before the pack it fronts
# the GUID of the setup module itself (the one holding Main, Advanced, ... ; the same on
# every board except the one Framework build whose setup module is numbered differently)
SETUP_MODULE = uuid.UUID("056e7324-a718-465b-9a84-228f06642b4f").bytes_le
MIN_SETTINGS = 10  # (the same floor uefi_setup uses to skip a module without real settings)


class Pack(NamedTuple):
    off: int  # where the pack starts in the part
    kind: int  # 2 = string pack, 3 = IFR form pack (the u16 at +4 of its header)
    lang: str  # the language of a string pack, "" for a form pack
    blob: bytes  # the pack itself, from its 4-byte length header on
    module: bytes | None  # the GUID of the record in front of it, None when it continues one


# --- finding the part and its packs -----------------------------------------------------------


def itk_part(archive: bytes) -> bytes | None:
    """The .ITK member of an Intel EFI update as downloaded: a ZIP, an EXE with a ZIP inside,
    or a ZIP stored inside a member (the bot's own unpacking walks all three).  The largest
    member that starts with the part's magic, or - only when none does - the largest one
    whose name ends in .itk; None when the update holds no such member."""
    if archive[:16] == ITK_MAGIC:
        return archive
    by_magic: list[bytes] = []
    by_name: list[bytes] = []
    for name, member in intelbio._zip_members(archive):
        if member[:16] == ITK_MAGIC:
            by_magic.append(member)
        elif name.lower().endswith(".itk"):
            by_name.append(member)
    for found in (by_magic, by_name):
        if found:
            return max(found, key=len)
    return None


def bios_id(itk: bytes) -> str:
    """The board's BIOS id as the part names it in its own header ("MQ96510J.86A.1761")."""
    for run in _ascii_runs(itk[0x30:0x200]):
        if run.count(".") >= 1 and any(c.isdigit() for c in run):
            return run
    return ""


def _ascii_runs(blob: bytes) -> list[str]:
    """The printable ASCII runs of a region, longest first."""
    runs, cur = [], bytearray()
    for byte in blob:
        if 0x20 <= byte < 0x7F:
            cur.append(byte)
        elif cur:
            runs.append(cur.decode("ascii"))
            cur.clear()
    if cur:
        runs.append(cur.decode("ascii"))
    return [r for r in runs if len(r) >= 4]


def packs(itk: bytes) -> list[Pack]:
    """Every HII pack of the part, in file order, each with the GUID of the record in front
    of it.  The record is written once in front of a group of packs and the packs of one
    module follow back to back, so a pack with no room for a record in front of it belongs
    to the group of the pack before it."""
    found: list[Pack] = []
    for kind, items in (
        (3, [("", f) for f in uefi_setup._fw_form_packages(itk)]),
        (2, list(uefi_setup._fw_string_packages(itk))),
    ):
        cursor = 0  # (each finder returns its packs in file order, so offsets only grow)
        for lang, blob in items:
            off = itk.find(blob, cursor)
            if off < 0:
                continue
            cursor = off + 1
            found.append(Pack(off, kind, lang, blob, None))
    found.sort(key=lambda p: p.off)
    out, end = [], 0
    for p in found:
        at = p.off + GUID_AT
        if p.off - end >= RECORD and at >= 0:
            p = p._replace(module=itk[at : at + 16])
        end = max(end, p.off + struct.unpack_from("<I", p.blob, 0)[0])
        out.append(p)
    return out


def groups(found: list[Pack]) -> dict[bytes, list[Pack]]:
    """The packs of the part grouped by the module record in front of them."""
    out: dict[bytes, list[Pack]] = {}
    key = b""
    for p in found:
        if p.module is not None:
            key = p.module
        out.setdefault(key, []).append(p)
    return out


def settings(sets: list[FormSet]) -> int:
    """The questions of these form sets: the one-of, check-box and numeric items."""
    return sum(
        1
        for fs in sets
        for _title, items in fs.forms.values()
        for it in items
        if it["kind"] in ("oneof", "checkbox", "numeric")
    )


def setup_group(found: list[Pack]) -> tuple[list[Pack], list[FormSet]]:
    """The packs of the setup module, and the form sets they hold: the group whose record
    carries the setup module's GUID when it is there, else the group with the most
    questions (the other groups are the board's other HII modules: the reference-code
    settings, the boot module, the language-only packs)."""
    scored: list[tuple[bool, int, list[Pack], list[FormSet]]] = []
    for key, group in groups(found).items():
        sets = [fs for p in group if p.kind == 3 for fs in uefi_setup._parse_fw_ifr(p.blob)]
        n = settings(sets)
        if n >= MIN_SETTINGS:
            scored.append((key == SETUP_MODULE, n, group, sets))
    if not scored:
        raise ValueError("the .ITK part holds no IFR form pack with setup settings")
    scored.sort(key=lambda c: (not c[0], -c[1]))
    return scored[0][2], scored[0][3]


def string_pack(itk: bytes, group: list[Pack]) -> bytes:
    """The English string pack the forms' ids index: the largest English pack of the group.
    (Which of the part's several English packs a form pack's ids index is not written down
    in the part; measured on all 14 parts, the largest one is the only pack that covers
    every id the forms use, and it is the pack stored in the setup module's own group.)"""
    cands = [p for p in group if p.kind == 2 and p.lang.lower().startswith("en")]
    if not cands:
        cands = [p for p in packs(itk) if p.kind == 2 and p.lang.lower().startswith("en")]
    if not cands:
        raise ValueError("the .ITK part holds no English string pack")
    return max(cands, key=lambda p: len(p.blob)).blob


def _title(S: dict[int, str]) -> str:
    """The title bar.  Measured: none of the 14 parts holds a string "Setup Utility" (nor that
    name in UTF-16 anywhere), so on these boards this is always the label below - a choice, not
    the part's own wording; the part's strings name the menus, not the program."""
    for text in S.values():
        name = " ".join(text.split())
        if name.endswith("Setup Utility") and len(name) < 40:
            return name
    return "BIOS Setup Utility"


# --- the setup --------------------------------------------------------------------------------


class ItkSetup(uefi_setup.UefiSetup):
    """The setup of an Intel EFI update's .ITK part.  screens() returns the same
    [(title, Screen, note)] shape, tabs and page order as uefi_setup.UefiSetup.screens():
    each menu's first form, then the forms its sub-menus open, long forms continued."""

    def __init__(self, itk: bytes) -> None:
        group, sets = setup_group(packs(itk))
        self.S = uefi_setup._fw_strings(string_pack(itk, group))
        self.title = _title(self.S)
        sets = [fs for fs in sets if fs.first is not None]
        self.forms: dict[int, tuple[int, list]] = {}
        for k, fs in enumerate(sets):
            if fs.first in self.forms:  # (every form set numbers its forms from 1)
                uefi_setup._renumber(fs, (k + 1) << 16)
            for fid, form in fs.forms.items():
                self.forms.setdefault(fid, form)
        tabs = self._name_tabs(sets)
        if not any(uefi_setup._known(name) for name, _ in tabs):
            raise ValueError("the .ITK forms are not a setup with the usual tabs")
        self.tabs = tabs
        self.copyright = next((t for t in self.S.values() if "Copyright" in t), "").strip()[:78]

    def menu_items(self) -> list[tuple[str, str, int]]:
        """(menu, item, kind count) of every question of every menu, for comparing the
        menus with what Intel's specification for the board lists."""
        out: list[tuple[str, str, int]] = []
        for name, form_id in self.tabs:
            for it in self.forms.get(form_id, (0, []))[1]:
                prompt = " ".join(self.str(it.get("prompt")).split())
                if prompt:
                    out.append((name, prompt, it["kind"]))
        return out
