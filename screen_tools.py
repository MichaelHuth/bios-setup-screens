"""
Text-screen tools: rebuild BIOS setup screens from a ROM, and render an 80x25 text screen
composed by the model. Rendered PNGs are saved to the working folder and attached to the reply.
"""

from __future__ import annotations

import asyncio
import bz2
import contextvars
import gc
import hashlib
import collections
import io
import itertools
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict

import pypdfium2 as pdfium
from PIL import Image

import ami
import ami7_setup
import asrock_gui
import asus_gui
import evga_gui
import gigabyte_gui
import msi_gui
import sapphire_gui
import intel_itk
import contact_sheet
import ami8_setup
import ami8_static_setup
import ami_easy_setup
import ami_hiflex_setup
import hfjump_setup
import ami_setup
import award6_setup
import award_emu_setup
import award_medallion_setup
import award_menubar_setup
import award_setup
import bios_emu
import dell_setup
import dtk_setup
import intelbio
import intelexp_setup
import mylex_setup
import novell_setup
import ncr_setup
import prompt_setup
import quadtel_setup
import ami_qa_setup
import uefi_setup
import acer_setup
import chips_setup
import tandon_setup
import texasmicro_setup
import lzh
import lzexe
import inno
import dxp
import intel_setup
import intel_static_setup
import mr_setup
import softpaq
import sqx
import sxd
import phoenix_old_setup
import phoenix_setup
import phoenix_tc_setup
import phoenix
import winbios_setup
import workspace
from textscreen import COLOR_NAMES, Screen, color_attr, unicode_to_cp437

MAX_IMAGES = 8  # attached images: with the ZIP and the user's own file, Discord's 10
MAX_SINGLE = 4  # up to this many screens are attached singly, more on contact sheets
MAX_TEXT = 9  # screens whose text goes back to the AI (the rest: titles only)
MAX_SCREENS = 400  # screens rendered in one call at most (all go into the ZIP)
MAX_ROM = 32 << 20  # largest flash image taken out of a ZIP archive
MAX_UNPACKED = 256 << 20  # the most an archive may unpack to, all its members together

TOOLS = [
    {
        "name": "bios_setup_screens",
        "description": "Rebuild the BIOS setup screens of a mainboard BIOS image as they appear "
        "on a real PC (main menu and sub-pages with default values), rendered as images "
        "attached to your reply. Some families are read from the ROM's own tables, others by "
        "running the ROM's POST and setup in an x86 emulator (only for boards whose chipset "
        "is emulated). Supported: Award (early Modular BIOS 3.x/4.0 of 286/386 boards, 4.5x "
        "such as 4.51PG packed or unpacked, 6.00PG, Medallion 6.0, Phoenix-AwardBIOS 6.00PG "
        "including the menu-bar setup of ASUS boards such as the A7N8X); AMI (the AMI 286 "
        "BIOS of about 1988, the classic AMIBIOS setup of about 1988-1994, the Easy and the "
        "Simple/Hi-Flex setups, WinBIOS 1994-97 with icons, AMIBIOS 7 and AMIBIOS 8); "
        "Phoenix (BIOS before 4.0, the 4.0x text setup, PhoenixBIOS 4.0, TrustedCore/"
        "SecureCore, Dell's Phoenix ROM BIOS PLUS 1.10); Intel's own desktop-board BIOS and "
        "EFI firmware; Acer, DTK, MR BIOS (Microid Research), NCR's AT ROM, Mylex and "
        "Quadtel; and UEFI firmware of about 2011 on (AMI Aptio 4 and 5: Gigabyte, ASRock, "
        "ASUS .CAP, MSI, Supermicro ...), whose setup forms are read from the image and drawn "
        "as text pages, or for ASUS boards of about 2011-2015, ASRock boards of about "
        "2011-2016, Gigabyte boards of about 2011-2015, MSI Click BIOS boards and EVGA and "
        "Sapphire boards "
        "in the setup's own graphical look "
        "(see 'style'). BIOS update packages (ZIP, self-extracting EXE) are unpacked to find "
        "the image. For a BIOS without a setup in its ROM (Compaq, IBM PS/1 and Aptiva, "
        "XT-class) or an option ROM it says so. Returns "
        "the screens as "
        "text so you can describe them; the images are attached automatically, do not try to "
        "draw them again. Up to 4 screens are attached as single images; more are combined "
        "into contact sheets of up to 3x3 screens (each captioned with its number and "
        "title); always one ZIP file with every screen image at full size and your answer "
        "as Markdown. The result's 'attached' field says exactly what is attached - report "
        "that, not the number of pages.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "File name from list_files (a ROM image, or a ZIP with one).",
                },
                "pages": {
                    "type": "string",
                    "description": "'all' (default), 'main', or page numbers like '1,3' from the "
                    "list this tool returns.",
                },
                "defaults": {
                    "type": "string",
                    "enum": ["setup", "bios"],
                    "description": "Which default values to show: the optimal set (Award: Load "
                    "Setup Defaults, AMI: BIOS Setup Defaults, WinBIOS: Optimal; default) or the "
                    "fail-safe set (Award: Load BIOS Defaults, AMI: Power-On Defaults, WinBIOS: "
                    "Fail-safe where the setup has it, otherwise "
                    "no defaults loaded, i.e. the values after POST with cleared CMOS).",
                },
                "color": {
                    "type": "integer",
                    "description": "AMI only: color scheme, i.e. how often F2 is pressed "
                    "(default 0 = the scheme of a PC with cleared CMOS). WinBIOS 1994: color set "
                    "0 LCD (default, gray), 1 Army, 2 Pastel, 3 Sky.",
                },
                "style": {
                    "type": "string",
                    "enum": ["graphical", "text"],
                    "description": "UEFI only: 'graphical' draws the setup's own look "
                    "(the firmware's own background and hint pictures) for ASUS UEFI setups "
                    "of about 2011-2015, ASRock ones of about 2011-2016 and Gigabyte ones "
                    "of about 2011-2015, MSI Click BIOS II, 4 and 5 ones and EVGA and "
                    "Sapphire ones; "
                    "'text' draws "
                    "80x25 text pages. Default: graphical where the image has those "
                    "pictures, text otherwise.",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "render_text_screen",
        "description": "Render an 80x25 PC text-mode screen (VGA font, 16 colors) as an image "
        "attached to your reply, e.g. to show what a BIOS or DOS screen looks like. Give up to "
        "25 lines of up to 80 characters; box-drawing characters (═║╔ ─│┌ etc.) and CP437 "
        "symbols work. Colors: " + ", ".join(COLOR_NAMES) + ".",
        "input_schema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Screen lines.",
                },
                "fg": {"type": "string", "description": "Default text color (default lightgray)."},
                "bg": {"type": "string", "description": "Default background (default black)."},
                "colors": {
                    "type": "array",
                    "description": "Colored areas: {row, col, length, fg, bg}; row/col start at "
                    "0, length defaults to the rest of the line.",
                    "items": {"type": "object"},
                },
                "file_name": {"type": "string", "description": "Output name (default screen.png)."},
            },
            "required": ["lines"],
        },
    },
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def _system_bios(data: bytes) -> tuple[bytes, str]:
    """The data that contains the setup code: the file itself, or an unpacked LHA module."""
    try:
        award_setup._find(data)
        # (a chance match in an updater's compressed bytes has no handler the command
        # map knows: then the image is in one of its LHA modules)
        _, ops = award_setup._dispatch(data)
        if sum(1 for k, _, _ in ops.values() if k == "unknown") <= 1:  # (one of 21 is
            return data, "file"  # not a chance match: AOpen MX3ZA)
    except (ValueError, AssertionError):
        pass
    modules = lzh.find_modules(data)

    def unpack(m: dict) -> bytes:
        return lzh.decompress(
            data[m["data_start"] : m["data_start"] + m["packed"]], m["size"], m["method"].encode()
        )

    for m in modules:
        if m["size"] < 0x10000:
            continue
        try:
            out = unpack(m)
            if m["size"] % 0x10000:  # split in two (Gigabyte: AWDBIOS1.ROM + AWDBIOS2.ROM)
                rest = 0x10000 - m["size"] % 0x10000
                out += next(unpack(n) for n in modules if n["size"] == rest)
            award_setup._find(out)
            return out, f"LHA module {m['name']!r}"
        except Exception:  # not the system BIOS module
            continue
    raise ValueError(
        "no Award 4.5x setup code found. Only Award Modular BIOS 4.5x setup "
        "screens can be rebuilt so far; for other BIOSes use strings to read the "
        "menu texts."
    )


def _chosen_pages(pages: str | None, count: int) -> list:
    wanted = pages.strip().lower() if pages else "all"
    if wanted == "all":
        return ["main"] + list(range(1, count + 1))
    if wanted == "main":
        return ["main"]
    parts = wanted.replace(" ", "").split(",")
    return ["main"] * ("main" in parts) + [int(p) for p in parts if p.isdigit()]


# the images rendered by the current bios_setup_screens call: (title, file)
_rendered: contextvars.ContextVar[list[tuple[str, Path]]] = contextvars.ContextVar("_rendered")
# the style asked for in the current bios_setup_screens call: "graphical", "text" or ""
_style: contextvars.ContextVar[str] = contextvars.ContextVar("_style", default="")


def _save(path: Path, title: str, screen: Screen | Image.Image) -> None:
    try:
        rendered = _rendered.get()
    except LookupError:  # (outside a bios_setup_screens call)
        rendered = []
    if len(rendered) >= MAX_SCREENS:
        return
    page = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")  # e.g. PNP/PCI CONFIGURATION
    out = path.parent / workspace._safe_name(f"{path.stem}.setup.{page}.png")
    if any(
        out.with_suffix("") == p.with_suffix("") for _, p in rendered
    ):  # (two pages of one title)
        out = out.with_name(f"{out.stem}_{len(rendered) + 1}.png")
    if isinstance(screen, Screen):
        screen.render(out)
    else:  # (a picture drawn in the setup's own graphical look)
        out = contact_sheet.save_compact(screen, out)
    rendered.append((title, out))


def _attach_screens(result: dict, rendered: list[tuple[str, Path]]) -> None:
    """Attach the screens: up to MAX_SINGLE singly, more on contact sheets of 3 x 3 (at
    most MAX_IMAGES sheets); every screen also goes into the reply's ZIP file, which the
    bot makes with the answer. The result says what is attached; the AI gets the text of
    the first MAX_TEXT screens."""
    if not rendered:
        return
    for _, out in rendered:
        workspace.bundle(out)
    texts = {t for t, _ in rendered[:MAX_TEXT]}
    result["screens"] = {t: s for t, s in result.get("screens", {}).items() if t in texts}
    zip_note = (
        f"one ZIP file with all {len(rendered)} screen images at full size and your "
        "answer as Markdown"
    )
    if len(rendered) <= MAX_SINGLE:
        for _, out in rendered:
            workspace.attach(out)
        titles = ", ".join(t for t, _ in rendered)
        result["attached"] = f"{len(rendered)} image(s) ({titles}), and {zip_note}"
        return
    numbered = [(n, t, p) for n, (t, p) in enumerate(rendered, start=1)]
    per = contact_sheet.SIDE * contact_sheet.SIDE
    groups = [numbered[k : k + per] for k in range(0, len(numbered), per)][:MAX_IMAGES]
    stem = rendered[0][1].name.split(".setup.")[0]
    sheets = []
    for k, group in enumerate(groups, start=1):
        out = rendered[0][1].with_name(f"{stem}.setup-sheet{k}.png")
        workspace.attach(contact_sheet.sheet(group, out))
        sheets.append(
            f"sheet {k}: screens {group[0][0]}-{group[-1][0]} ("
            + ", ".join(f"{n} {t}" for n, t, _ in group)
            + ")"
        )
    shown = sum(len(g) for g in groups)
    result["attached"] = (
        f"{len(groups)} contact sheet image(s) of up to 3x3 screens - "
        + "; ".join(sheets)
        + f" - and {zip_note}"
        + (
            f"; screens {shown + 1}-{len(rendered)} are only in the ZIP"
            if shown < len(rendered)
            else ""
        )
        + (
            f". The text of screens {MAX_TEXT + 1} on is not shown here (ask for them "
            "with pages to read them)"
            if len(rendered) > MAX_TEXT
            else ""
        )
    )


# 7-Zip, if installed: it reads the archives of update programs that unpack themselves in
# formats this module does not (7z and RAR SFX, e.g. Gigabyte, ECS). Only listed and read, the
# program itself never runs.
SEVEN_ZIP = shutil.which("7z") or next(
    (
        p
        for p in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe")
        if os.path.exists(p)
    ),
    None,
)


def _seven_zip_output(args: list[str], timeout: int) -> bytes:
    """What 7-Zip writes to its output, read up to MAX_UNPACKED: a small upload can unpack to
    gigabytes. Raises SubprocessError when it is more than that or takes too long."""
    stopped = []
    with subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL
    ) as process:

        def stop() -> None:
            stopped.append(True)
            process.kill()

        timer = threading.Timer(timeout, stop)
        timer.start()
        try:
            assert process.stdout is not None
            data = process.stdout.read(MAX_UNPACKED + 1)
        finally:
            timer.cancel()
        if len(data) > MAX_UNPACKED:
            stop()
    if stopped:
        raise subprocess.SubprocessError("7-Zip stopped: too much output, or too slow")
    return data


def _open_zip(data: bytes) -> zipfile.ZipFile:
    """A ZIP archive to read from, if its members together stay under MAX_UNPACKED. Their sizes
    in the directory bind: zipfile stops a member at the size given there."""
    archive = zipfile.ZipFile(io.BytesIO(data))  # pylint: disable=consider-using-with
    if sum(i.file_size for i in archive.infolist()) > MAX_UNPACKED:
        raise ValueError(f"this ZIP archive unpacks to more than {MAX_UNPACKED >> 20} MB")
    return archive


def _seven_zip_member(source: str, member: dict) -> bytes:
    """A member's bytes, by its path or else by its file name in any folder (7-Zip lists RAR5
    folder names it then does not match: X99-QD4's "... __BIOS\\QD4V01.bin", JGINYUE X99M's
    folders with Chinese names); b"" if neither. When the name is in several folders, 7-Zip
    writes them all one after another: the first is taken (JGINYUE X99M: two copies)."""
    path = member["Path"]
    size = int(member["Size"])
    name = path.replace("/", "\\").rsplit("\\", 1)[-1]
    assert SEVEN_ZIP is not None
    for args in ([source, path], ["-r", source, name]):
        try:
            data = _seven_zip_output([SEVEN_ZIP, "e", "-so", "-p-"] + args, 120)
        except (OSError, subprocess.SubprocessError):
            return b""
        if args[0] == "-r" and size and len(data) > size and len(data) % size == 0:
            return data[:size]
        if len(data) == size or args[0] == "-r" or "\\" not in path:
            return data
    return b""


def _diskette_program(raw: bytes) -> bytes | None:
    """The flash image on the diskette a self-extracting diskette program writes, or None."""
    # a Sydex self-extracting diskette (IBM's updates of the 1990s, ASUS P5VDC-TVM): first,
    # as tracks it stores unpacked show the LHA headers of an Award image on it
    if (floppy := sxd.disk_image(raw)) is not None and (image := _from_disk(floppy)) is not None:
        return image
    # (Fujitsu-Siemens' "PC QS Service" diskette: Xpert 6xxx, Celsius 620)
    if (floppy := sxd.qs_image(raw)) is not None and (image := _from_disk(floppy)) is not None:
        return image
    # (an Inno Setup installer with a bootable CD: Packard Bell's, NEC's)
    if (floppy := inno.boot_diskette(raw)) is not None and (image := _from_disk(floppy)):
        return image
    if b"Disk eXPress" in raw:  # a DXP diskette (Dell's updates of about 2002)
        try:
            floppy = dxp.disk_image(raw)
        except (ValueError, IndexError):
            floppy = None
        if floppy is not None and (image := _from_disk(floppy)) is not None:
            return image
    # (a Compaq Softpaq: its ROMPaq diskette, DCL-imploded)
    if (floppy := softpaq.diskette(raw)) is not None and (image := _from_disk(floppy)) is not None:
        return image
    # (NEC's and Packard Bell's NTUNDSK updates: one DCL stream per track)
    if (floppy := softpaq.tracks(raw)) is not None and (image := _from_disk(floppy)) is not None:
        return image
    # (a bzip2-packed diskette behind the program: Supermicro H8SGL's FreeDOS flash disk)
    for start in (m.start() for m in re.finditer(rb"BZh[1-9]1AY&SY", raw)):
        try:
            floppy = bz2.BZ2Decompressor().decompress(raw[start:], 4 * MAX_ROM)
        except (OSError, EOFError):
            continue
        if _floppy_header(len(floppy)) is not None and (image := _from_disk(floppy)):
            return image
    return None


def _seven_zip_image(raw: bytes, depth: int = 0) -> bytes | None:
    """The largest member of a flash chip's size in an archive 7-Zip can read, or None."""
    if SEVEN_ZIP is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "archive.bin")
        with open(source, "wb") as f:
            f.write(raw)
        try:  # -p-: never ask for a password; -slt: one "Key = value" line per property
            listing = _seven_zip_output([SEVEN_ZIP, "l", "-slt", "-p-", source], 60)
        except (OSError, subprocess.SubprocessError):
            return None
        members, current = [], {}
        for line in listing.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition(" = ")
            if sep:
                current[key.strip()] = value.strip()
            elif not line.strip() and current:
                members.append(current)
                current = {}
        if current:
            members.append(current)
        images = [
            m
            for m in members
            if m.get("Path")
            and m.get("Folder") != "+"
            and m.get("Size", "").isdigit()
            and _flash_size(int(m["Size"]))
        ]
        bio = [
            m
            for m in members
            if INTEL_PART.search(m.get("Path", ""))  # (a smaller last
            and m.get("Size", "").isdigit()
            and (
                int(m["Size"]) <= 0x10000 + 160  # part too)
                or len(members)
                and m["Path"].upper().endswith(".BIO")
            )
        ]
        disks = [
            m
            for m in members
            if m.get("Path")
            and m.get("Size", "").isdigit()
            and _floppy_header(int(m["Size"])) is not None
        ]
        pair = [
            m
            for m in members
            if m.get("Path")
            and m.get("Folder") != "+"
            and m.get("Size", "").isdigit()
            and 0x2000 <= int(m["Size"]) <= 0x40000
        ]
        sized = [m for m in members if m.get("Folder") != "+" and m.get("Size", "").isdigit()]
        if (
            raw.startswith((b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c"))
            and len(sized) == 1
            and 0x2000 <= int(sized[0]["Size"]) < 0x10000
        ):
            return _seven_zip_member(source, sized[0])  # (one small ROM alone: a 286's 32 KB)
        if not images and not bio and len(pair) == 2 and pair[0]["Size"] == pair[1]["Size"]:
            # two EPROMs of a 16-bit ROM (a RAR with "..._H_ODD.BIN" and "..._L_EVEN.BIN"):
            # put into a ZIP in memory for _rom_pair
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as two:
                for m in pair:
                    try:
                        data = _seven_zip_output(
                            [SEVEN_ZIP, "e", "-so", "-p-", source, m["Path"]], 120
                        )
                    except (OSError, subprocess.SubprocessError):
                        data = b""
                    two.writestr(m["Path"], data)
            with zipfile.ZipFile(buffer) as both:
                image = _rom_pair(both)
            if image is not None:
                return image
        for disk in disks * (not images and not bio):  # a diskette image (FSC's updates)
            try:
                data = _seven_zip_output([SEVEN_ZIP, "e", "-so", "-p-", source, disk["Path"]], 120)
            except (OSError, subprocess.SubprocessError):
                continue
            size = int(disk["Size"])  # (an entry given twice comes out twice)
            for part in {data[i : i + size] for i in range(0, len(data) - size + 1, size)}:
                if (image := _from_disk(part)) is not None:
                    return image
        cabs = [
            m
            for m in members
            if re.fullmatch(
                r"data\d+\.cab", m.get("Path", "").replace("\\", "/").rsplit("/", 1)[-1].lower()
            )
            and m.get("Size", "").isdigit()
            and int(m["Size"]) <= 4 * MAX_ROM
        ]
        for cab in cabs * (not images):  # an InstallShield setup (ASUS CUSL2-LV's SOA004:
            # before the near sizes below, where its Setup.inx is 128 KB and more)
            if (image := _installshield_image(_seven_zip_member(source, cab))) is not None:
                return image
        near = [
            m
            for m in members
            if m.get("Path")
            and m.get("Folder") != "+"
            and m.get("Size", "").isdigit()
            and _near_flash_size(int(m["Size"]))
            and not m["Path"].upper().endswith(".ISO")  # (a CD image: below)
        ]
        # a header or trailer (PHLASH16); the largest need not be it (HP's WINPHLASH.HLP)
        for best in sorted(near, key=lambda m: -int(m["Size"])) * (
            not images and not bio and not disks
        ):
            try:
                data = _seven_zip_output([SEVEN_ZIP, "e", "-so", "-p-", source, best["Path"]], 120)
            except (OSError, subprocess.SubprocessError):
                return None
            if len(data) == int(best["Size"]) and (image := _trimmed(data)) is not None:
                return image
        if not images and bio:  # (an InstallShield setup with Intel's split update)
            try:
                parts = [
                    _seven_zip_output([SEVEN_ZIP, "e", "-so", "-p-", source, m["Path"]], 120)
                    for m in bio
                ]
            except (OSError, subprocess.SubprocessError):
                return None
            return _intel_bio(parts)
        isos = [
            m
            for m in members
            if m.get("Path", "").upper().endswith(".ISO")
            and m.get("Size", "").isdigit()
            and int(m["Size"]) <= 64 * 1024 * 1024
        ]
        for iso in isos * (not images and depth == 0):  # a CD image in the package (IBM's
            # 20JZ46USA: the flash image on it as $IMAGE20.USF)
            if (image := _seven_zip_image(_seven_zip_member(source, iso), 1)) is not None:
                return image
        programs = [
            m
            for m in members
            if m.get("Path", ".exe").lower().endswith(".exe")
            and m.get("Size", "").isdigit()
            and int(m["Size"]) > 0x10000
        ]
        if not images and depth == 0 and programs:  # an update program inside (FIC: in bzip2)
            best = max(programs, key=lambda m: int(m["Size"]))
            try:  # (a bzip2 stream's one member has no name)
                data = _seven_zip_output(
                    [SEVEN_ZIP, "e", "-so", "-p-", source]
                    + ([best["Path"]] if "Path" in best else []),
                    120,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            return _seven_zip_image(data, 1) or _diskette_program(data)
        if not images:
            return None
        best = max(images, key=lambda m: int(m["Size"]))
        data = _seven_zip_member(source, best)
        return data if len(data) == int(best["Size"]) else None


def _installshield_image(cab: bytes) -> bytes | None:
    """An Award image in an InstallShield 5/6 cabinet (data2.cab: "ISc(", the files from 200h
    on as one stream of chunks, each a 16-bit packed size and raw deflate data), found by its
    reset vector at the end and an LHA module at its start; or None."""
    if not cab.startswith(b"ISc("):
        return None
    out, p = bytearray(), 0x200
    while p + 2 <= len(cab) and len(out) <= 4 * MAX_ROM:
        n = struct.unpack_from("<H", cab, p)[0]
        unpack = zlib.decompressobj(-15)
        try:
            part = unpack.decompress(cab[p + 2 : p + 2 + n]) + unpack.flush(zlib.Z_SYNC_FLUSH)
        except zlib.error:
            break
        if n < 2 or not part:
            break
        out += part
        p += 2 + n
    for vector in re.finditer(rb"\xea..\x00\xf0", out, re.S):
        if (image := _tail_image(bytes(out[: vector.start() + 16]))) is not None:
            return image
    return None


def _near_flash_size(size: int) -> bool:
    """A flash chip's size and up to 64 KB more (a header or trailer of an update tool)."""
    return 0 < size % 0x10000 and _flash_size(size - size % 0x10000)


def _trimmed(data: bytes) -> bytes | None:
    """An image with a header in front (ASRock) or a trailer behind (Phoenix's PHLASH16 .F11,
    Gigabyte GA-6KIEH): the part of a flash chip's size that ends in a reset vector, or None."""
    if mr_setup.is_mr_bios(data) and data[-16] == 0xEA:
        return data  # (MR BIOS V3.30 is 92 KB of ROM as it is: MR_FICU.BIO, MR_TYAN1.BIO)
    extra = len(data) % 0x10000
    for part in (data[extra:], data[: len(data) - extra]):
        if len(part) >= 16 and (
            part[-16] in (0xEA, 0xE9) or part[-16:-13] in (b"\x0f\x09\xe9", b"\x90\x90\xe9")
        ):  # (UEFI)
            return part
    return None


def _flash_size(size: int) -> bool:
    """A flash chip's size, or the part of one an update writes (ASUS: 384 KB of 512 KB):
    a multiple of 64 KB up to 32 MB."""
    return 0x10000 <= size <= MAX_ROM and not size % 0x10000


INTEL_PART = re.compile(r"\.(BIO|BI[\dA-F]|BBO|REC|RE[\dA-F])$", re.I)


def _reset_vector(block: bytes) -> bool:
    """A jump at the reset vector (16 bytes before the end; Intel's boot blocks start it
    with WBINVD, 0F 09)."""
    tail = block[-16:-8]
    return len(block) == 0x10000 and (
        tail[0] == 0xEA or tail[0] == 0xE9 or tail[:3] == b"\x0f\x09\xe9"
    )


def _intel_ibi(data: bytes) -> bytes | None:
    """The image in a single .BIO of Intel's Express BIOS Update (D865PERL P21-0089.BIO: a
    GUID header with UTF-16 strings, then "$IBI" - its header's length at +8, the image's at
    +0Ch - and the image, 512 KB there), or None."""
    at = data.find(b"$IBI")  # (followed by 01 00 there, by 00 00 01 00 on BZ875, 2005)
    if at < 0 or at + 0x14 > len(data):
        return None
    header = int.from_bytes(data[at + 8 : at + 12], "little")
    size = int.from_bytes(data[at + 12 : at + 16], "little")
    image = data[at + header : at + header + size]
    return image if _flash_size(size) and len(image) == size else None


def _intel_bio(parts: list[bytes]) -> bytes | None:
    """Intel's split updates as a flash image (_intel_split), or else as the parts under an
    empty boot block area (_under_boot_block)."""
    image = _intel_split(parts)
    if (under := _under_boot_block(parts)) is not None and (
        image is None or not _modules_read(image)
    ):  # (bytes that look like a reset vector in a packed part: Dell's XPS T)
        image = under
    return _by_module_table(image, parts) if image else image


def _modules_read(image: bytes) -> bool:
    """Whether at least 8 modules of an AMI or Phoenix module list decode."""
    for extract in (ami.extract, phoenix.extract):
        try:
            if sum("error" not in m for m in extract(image)[1]) >= 8:
                return True
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    return False


def _module_table_score(image: bytes) -> int:
    """How well the module table of an Intel Express image fits it: the boot block's first
    dword points at the table, 24 bytes an entry (id, address in flash, length, ...); one
    point for an entry that finds data at both ends of its module, one off for FFh."""
    base = 0x100000000 - len(image)
    table = (int.from_bytes(image[-0x2000:-0x1FFC], "little") - base) & 0xFFFFFFFF
    if table >= len(image):
        return -1
    score = 0
    for n in range(64):
        entry = image[table + n * 24 : table + n * 24 + 12]
        if len(entry) < 12 or entry[:4] == b"\xff" * 4:
            break
        source, length = struct.unpack("<II", entry[4:])
        if (
            entry[:4] == b"\xff\xff\x03\x00"
            and image.find(
                intelexp_setup.SIGNATURE,
                (source - base) & 0xFFFFFFFF,
                ((source - base) & 0xFFFFFFFF) + 0x40,
            )
            >= 0
        ):
            score += 16  # (the setup module where the table says: PC Velocity V90's 21 for
            # a wrong order, 20 for the right one, on the other modules alone)
        if source == 0xFFFFFFFF or not 0 < length <= 0x80000:
            continue
        at = (source - base) & 0xFFFFFFFF
        blank = b"\xff" * 16
        if at + 16 > len(image):
            score -= 1
        elif image[at : at + 16] == blank:
            score -= at % 0x2000 != 0
        else:
            score += 1 if image[at + length - 16 : at + length] != blank else -1
    return score


def _by_module_table(image: bytes, parts: list[bytes]) -> bytes:
    """The blocks of a split Intel Express update in the order its own module table asks
    for, if that fits better than the placement by part numbers (AMAZON 1.00.01: .BI1 lowest,
    .BIO, .BI3, .BI2 with the boot block on top; each block at a 64 KB boundary)."""
    blocks: dict[tuple[int, int], bytes] = {}
    for d in parts:
        if len(d) > 0x80 and d[0x5A:0x5F] == b"FLASH":
            size = int.from_bytes(d[0x54:0x58], "little")
            blocks.setdefault((d[0x52], size), d[len(d) - size :])
    items = list(blocks.values())
    slots = len(image) // 0x10000
    if not 2 <= len(items) <= slots <= 4 or any(len(b) > 0x10000 for b in items):
        return image
    best, found = image, _module_table_score(image)
    for order in itertools.permutations(range(slots), len(items)):
        trial = bytearray(b"\xff" * len(image))
        for block, slot in zip(items, order):
            trial[slot * 0x10000 : slot * 0x10000 + len(block)] = block
        if trial[-16] in (0xE9, 0xEA) and (score := _module_table_score(bytes(trial))) > found:
            best, found = bytes(trial), score
    return best


def _under_boot_block(parts: list[bytes]) -> bytes | None:
    """An Intel split update whose parts hold no reset vector, because the boot block area is
    never rewritten and so is not in the update (Intel SE440BX 4S4EB0X1.86A P12, 1999: three
    parts of 64 KB and one of 40 KB): the parts at the top of the chip with that area left FF
    below them. Of the chip sizes 256 KB / 512 KB / 1 MB, the one whose AMI or Phoenix module
    list reads best, if at least 8 modules decode."""
    blocks: dict = {}
    for d in parts:
        if len(d) > 0x80 and d[0x5A:0x5F] == b"FLASH" and d[0x20] in (0, 1):
            size = int.from_bytes(d[0x54:0x58], "little")
            if len(d) - size in (128, 160) and 0 < size <= 0x100000:
                blocks.setdefault(d[0x52], d[len(d) - size :])
    if not blocks or sorted(blocks) != list(range(len(blocks))):
        return None
    low = b"".join(blocks[n] for n in sorted(blocks))
    best, found = None, 7
    for size in (0x40000, 0x80000, 0x100000):
        if len(low) > size:
            continue
        image = b"\xff" * (size - len(low)) + low
        count = 0
        for extract in (ami.extract, phoenix.extract):
            try:
                count = max(count, sum("error" not in m for m in extract(image)[1]))
            except Exception:
                pass
        if count > found:
            best, found = image, count
    return best


def _intel_tail_first(parts: list[bytes]) -> bytes | None:
    """A split update whose last part (FFh at 59h) is a partial block: that part is the
    lowest block of the area, the numbered parts stack down from the top (the reset vector
    part on top), and the FF hole the sizes leave sits between them (Intel Advanced/HL
    PB570 and ALADD10: 64 KB + 13 KB). A last part of a whole block
    (biosfile81: 11 x 64 KB) keeps _intel_split's placement, and so do the 160-byte
    headers of the later updates (D845/S845WD1: 6 x 64 KB + 32 KB, their tail goes on top)."""

    def pay(d: bytes) -> bytes:
        return d[len(d) - int.from_bytes(d[0x54:0x58], "little") :]

    keep: dict[tuple[int, int], bytes] = {}
    for d in parts:
        if (
            len(d) > 0x80
            and d[0x5A:0x5F] == b"FLASH"
            and d[0x20] in (0, 1)
            and len(d) - int.from_bytes(d[0x54:0x58], "little") == 128
        ):
            keep.setdefault((d[0x52], int.from_bytes(d[0x54:0x58], "little")), d)
    if any(
        len(d) > 0x80
        and d[0x5A:0x5F] == b"FLASH"
        and len(d) - int.from_bytes(d[0x54:0x58], "little") == 160
        for d in parts
    ):
        return None
    low = [d for d in keep.values() if d[0x59] == 0xFF]
    full = max((len(pay(d)) for d in keep.values() if d[0x59] != 0xFF), default=0)
    if not low or not full or any(len(pay(d)) >= full for d in low):
        return None
    size = 1 << (sum(len(pay(d)) for d in keep.values()) - 1).bit_length()
    blob = bytearray(b"\xff" * size)
    off = 0
    for d in sorted(low, key=lambda d: d[0x52]):
        blob[off : off + len(pay(d))] = pay(d)
        off += len(pay(d))
    pos = size
    for d in sorted((d for d in keep.values() if d[0x59] != 0xFF), key=lambda d: -d[0x52]):
        pos -= len(pay(d))
        blob[pos : pos + len(pay(d))] = pay(d)
    return bytes(blob)


def _intel_split(parts: list[bytes]) -> bytes | None:
    """Intel's split updates (.BIO + .BI1 ..., or the recovery set .REC + .RE1 ...): each part
    a header of 128 bytes (1997) or 160 (with the BIOS ID, Express BIOS Update) - "FLASH" at
    5Ah, the part's number at 52h, its size at 54h - and a block, usually 64 KB. The numbered
    blocks fill the flash upwards to the one with the reset vector (its top); blocks between
    (NVRAM) are not in the update, so the flash size is the one whose gap lets the AMI or
    Phoenix module list be followed furthest (D850MV: 6 parts, 512 KB). Parts after the top
    one (a 40 KB tail, Intel 1014CD0) go elsewhere in the flash and are left out. A single
    .BIO of Intel's Express BIOS Update (2003 on) holds the whole image instead (_intel_ibi)."""
    if len(parts) == 1 and (image := _intel_ibi(parts[0])) is not None:
        return image
    if len(parts) == 1 and parts[0][:16] == intelbio.BIO_MAGIC:  # Intel's EFI update (2007
        try:  # on, here inside its Express BIOS Update program: PB94510J)
            return intelbio.image(parts[0])
        except ValueError:
            return None
    if (image := _intel_tail_first(parts)) is not None:
        return image
    blocks: dict = {}
    boot = None
    for d in parts:
        if len(d) > 0x80 and d[0x5A:0x5F] == b"FLASH" and d[0x20] in (0, 1):
            size = int.from_bytes(d[0x54:0x58], "little")
            if len(d) - size not in (128, 160):
                continue
            if d[0x20] == 1:  # (the recovery .REC repeats part 0)
                blocks.setdefault(d[0x52], d[len(d) - size :])
            elif _reset_vector(d[len(d) - size :].rjust(0x10000, b"\xff")):
                boot = d[len(d) - size :]  # a boot block of its own (.BBO, 16 or 64 KB: RC440BX)
    if not blocks or sorted(blocks) != list(range(len(blocks))):
        return None
    tops = [n for n, block in blocks.items() if _reset_vector(block.rjust(0x10000, b"\xff"))]
    if not tops and boot is not None:  # the boot block on top of the system BIOS parts
        blocks[len(blocks)] = boot
        tops = [len(blocks) - 1]
    if not tops:  # no boot block (SE440BX-2, Intel's AMIBIOS 8 boards of 2002-03): the image
        return _without_boot_block(blocks)  # cannot run, but its modules may be read
    top = max(tops)
    if top == 0 and len(blocks) > 1 and all(len(b) == 0x10000 for b in blocks.values()):
        # the boot block first, the others below it (Intel Advanced/PO "Pocono", 1996: .BIO
        # is F000, .BI1 E000)
        image = b"".join(blocks[n] for n in reversed(range(len(blocks))))
        size = 1 << (len(image) - 1).bit_length()
        return b"\xff" * (size - len(image)) + image
    low = b"".join(blocks[n] for n in range(top))
    # a top part smaller than 64 KB (JN440BX: an 8 KB boot block) ends a 64 KB block
    top_block = blocks[top].rjust(0x10000, b"\xff")
    best, found = None, -1
    for gap in range(0, 64):
        image = low + b"\xff" * (gap * 0x10000) + top_block
        size = 1 << (len(image) - 1).bit_length()
        image = b"\xff" * (size - len(image)) + image
        if not _flash_size(len(image)):
            continue
        count = 0
        for extract in (ami.extract, phoenix.extract):
            try:
                count = max(count, sum("error" not in m for m in extract(image)[1]))
            except Exception:
                pass
        if count > found:
            best, found = image, count
    return best


def _without_boot_block(blocks: dict) -> bytes | None:
    """An Intel split update that leaves the boot block out (it is never rewritten), laid out
    as the flash: either the parts from the bottom with the last one (the BIOS ID) below an
    empty boot block area at the top (Intel D845GRG, P17), or part 0 on top and the others
    downwards (P07); of those and the sizes 512 KB / 1 MB the one whose AMI module list reads
    best, if it reads well. Setup is then read from the modules (AMIBIOS 8)."""
    order = [blocks[n] for n in sorted(blocks)]
    low, last = b"".join(order[:-1]), order[-1]
    best, found = None, 7  # (at least 8 good modules)
    for size, upwards in ((0x80000, True), (0x100000, True), (0x80000, False), (0x100000, False)):
        if len(low) + len(last) > size:
            continue
        image = (
            low + b"\xff" * (size - len(low) - len(last)) + last
            if upwards
            else b"".join(reversed(order)).rjust(size, b"\xff")
        )
        try:
            count = sum("error" not in m for m in ami.extract(image)[1])
        except Exception:
            continue
        if count > found:
            best, found = image, count
    return best


PAIR_NAMES = [
    ("EVEN", "ODD"),
    ("LOW", "HIGH"),
    ("LO", "HI"),
    ("L", "H"),
    ("ROM0", "ROM1"),
    ("E", "O"),
]  # (L/H: Chaintech ELT-286B; ROM0/ROM1: PC Partner H8010; E/O: Goldstar 386)


def _award_bundle(raw: bytes) -> bytes | None:
    """The modules of an Award BIOS kept as separate LHA records in its update program, from the
    first record to the end of the last (awardext.rom among them), or None."""
    modules = lzh.find_modules(raw)
    if len(modules) < 3 or not any(m["name"].lower().endswith("awardext.rom") for m in modules):
        return None
    return raw[modules[0]["offset"] : max(m["data_start"] + m["packed"] for m in modules)]


def _lha_pair(raw: bytes) -> bytes | None:
    """An image split over two LHA members whose sizes add up to a flash chip's (AOpen's
    flasher: ORIGINAL.TMP + ORIGINAL.TM1, 129 962 + 1 110 bytes): the order that ends
    in a reset vector (a far or near jump 16 bytes before the end), or None."""
    modules = lzh.find_modules(raw)
    for i, a in enumerate(modules):
        for b in modules[i + 1 :]:
            if not _flash_size(a["size"] + b["size"]):
                continue
            for first, second in ((a, b), (b, a)):
                try:
                    image = b"".join(
                        lzh.decompress(
                            raw[m["data_start"] : m["data_start"] + m["packed"]],
                            m["size"],
                            m["method"].encode(),
                        )
                        for m in (first, second)
                    )
                except Exception:  # pylint: disable=broad-exception-caught
                    break
                if len(image) == a["size"] + b["size"] and image[-16] in (0xEA, 0xE9):
                    return _paired_halves(image)
    return None


def _rom_pair(archive: zipfile.ZipFile, named: bool = False) -> bytes | None:
    """286/386 boards with a 16-bit ROM have two EPROMs, one for the even and one for the odd
    bytes (MB-1316: EVEN-... and ODD-..., 32 KB each): the image is the two interleaved, a
    64 KB image repeated from a smaller one. Which is which comes from the names (EVEN/ODD,
    LOW/HIGH) or, for chip numbers (U71/U72), from the reset vector (a far jump 16 bytes
    before the end) being in place."""
    members = [
        i
        for i in archive.infolist()
        if 0x2000 <= i.file_size <= 0x40000
        and not i.filename.startswith("__MACOSX")
        and not i.is_dir()
    ]

    def word(name: str, w: str) -> bool:
        return re.search(rf"(?<![A-Z]){w}(?![A-Z])", name.upper()) is not None

    if len(members) > 2:  # (the pair beside a merged copy: Protech Suntac's bios_low,
        members = [  # bios_high and bios_merged_for_test)
            i for i in members if any(word(i.filename, w) for p in PAIR_NAMES for w in p)
        ]
    if len(members) != 2 or members[0].file_size != members[1].file_size:
        return None

    a, b = members
    for even_word, odd_word in PAIR_NAMES:
        if word(b.filename, even_word) and word(a.filename, odd_word):
            a, b = b, a
            break
    else:
        # (two images of a flash chip's size, not named as a pair: one only if neither is a
        # whole image, Data Expert's 286-129250 and 286-129285)
        if (
            named
            and not any(word(a.filename, e) and word(b.filename, o) for e, o in PAIR_NAMES)
            and (archive.read(a)[-16] == 0xEA or archive.read(b)[-16] == 0xEA)
        ):
            return None
    first, second = archive.read(a), archive.read(b)
    images = [
        bytes(x for pair in zip(low, high) for x in pair)
        for low, high in ((first, second), (second, first))
    ]
    # or the two halves of a larger image (DTK PEM-2530: 2 x 64 KB)
    images += [first + second, second + first]
    if named and not any(d[-16] == 0xEA for d in images):
        return None
    data = next((d for d in images if d[-16] == 0xEA), images[0])
    if len(data) < 0x10000:
        data *= 0x10000 // len(data)
    return data


# a word in quotes next to "password", or after "password is" / "password:"
QUOTES = "\"'\u201c\u201d\u2018\u2019\u00ab\u00bb\ufffe"  # (FFFEh: a PDF's unmapped quote mark)
PASSWORD_HINT = re.compile(
    rf"password[^.\n]{{0,80}}?[{QUOTES}]([^{QUOTES}\n]{{3,40}})[{QUOTES}]"
    rf"|[{QUOTES}]([^{QUOTES}\n]{{3,40}})[{QUOTES}][^.]{{0,80}}?password"
    rf"|password(?: is|:)\s*([^\s{QUOTES}.,;]{{3,40}})",
    re.I,
)


def _package_passwords(archive: zipfile.ZipFile) -> list[bytes]:
    """Passwords a package names for its own inner archive in its readme or PDF files
    (Foxconn NFPIK8AA's correction PDF: enter "Fullerton" as the password)."""
    words: list[str] = []
    for info in archive.infolist():
        name = info.filename.lower()
        if info.file_size > 0x400000 or not name.endswith((".txt", ".pdf", ".htm", ".html")):
            continue
        data = archive.read(info)
        if name.endswith(".pdf"):
            try:
                pdf = pdfium.PdfDocument(data)
                text = "\n".join(page.get_textpage().get_text_range() for page in pdf)
            except pdfium.PdfiumError:
                continue
        else:
            text = data.decode("latin-1")
        for m in PASSWORD_HINT.finditer(text):
            word = next(g for g in m.groups() if g)
            if word not in words:
                words.append(word)
    return [w.encode("latin-1", "replace") for w in words]


def _decrypted_zip(data: bytes, passwords: list[bytes]) -> bytes | None:
    """An encrypted ZIP rewritten without encryption, with the first password that opens it."""
    inner = _open_zip(data)
    for pwd in passwords:
        out = io.BytesIO()
        try:
            with zipfile.ZipFile(out, "w") as plain:
                for info in inner.infolist():
                    plain.writestr(info.filename, inner.read(info, pwd=pwd))
        except (RuntimeError, zipfile.BadZipFile, zlib.error):
            continue  # (a wrong password)
        return out.getvalue()
    return None


def _flash_cfg(archive: zipfile.ZipFile) -> bytes | None:
    """An update whose FLASH.CFG names the blocks and their segments (Texas Micro: \"L486\", then
    L486.BIN F000, SETUP.BIN E000, ADP120.BIN E800): the image from them, or None."""
    if "FLASH.CFG" not in archive.namelist():
        return None
    lines = archive.read("FLASH.CFG").decode("latin-1").split()
    try:
        blocks = [(n, int(s, 16) << 4) for n, s in zip(lines[1::2], lines[2::2])]
        low = min(at for _, at in blocks) & ~0xFFFF
        image = bytearray(b"\xff" * (0x100000 - low))
        for name, at in blocks:
            data = archive.read(name)
            image[at - low : at - low + len(data)] = data
    except (KeyError, ValueError):
        return None
    return bytes(image) if _flash_size(len(image)) and image[-16] == 0xEA else None


def _unzipped(raw: bytes, nested: int = 2) -> bytes:
    """BIOS updates are often handed out as an archive with the image and a flash tool (a ZIP,
    or a program that unpacks itself: ZIP or LHA, read here and never run): the largest member
    of a flash chip's size (a multiple of 64 KB up to 32 MB) is the image. A ZIP may hold the
    program that unpacks itself instead (AOpen AP4161), even one more level down (Intel AB9:
    ZIP, IB.EXE, SW.EXE)."""
    # (a whole flash image may begin with a program: Phoenix TrustedCore Server, Supermicro
    # X7DCA-3; its reset vector's jump is in place at the end)
    program = raw.startswith(b"MZ") and not (_flash_size(len(raw)) and raw[-16] in (0xE9, 0xEA))
    if raw[:512].lstrip().lower().startswith((b"<!doctype html", b"<html")):
        raise ValueError(
            "this file is a web page (HTML), not a BIOS image: the download "
            "probably fetched an error or info page instead of the file"
        )
    if not program and (image := _snipac(raw)) is not None:  # (Fujitsu-Siemens .OCF)
        return image
    # (a ZIP may start with "PK00", a spanning marker before the first entry: ASRock 775i65PE-M)
    if raw.startswith((b"PK\x03\x04", b"PK00PK\x03\x04")) or (
        program and zipfile.is_zipfile(io.BytesIO(raw))
    ):
        try:
            # (in memory, and its members are read all through the branches below)
            archive = _open_zip(raw)
            if (image := _flash_cfg(archive)) is not None:
                return image
            images = [i for i in archive.infolist() if _flash_size(i.file_size)]
            caps = [i for i in archive.infolist() if i.filename.upper().endswith(".CAP")]
            if not images and caps:  # (before the programs beside it: ASUS H81M-K's
                # BIOSRenamer.exe gave a 64 KB PE section as the image)
                return _capsule_body(archive.read(max(caps, key=lambda i: i.file_size)))
            if not images and nested:
                for inner in sorted(archive.infolist(), key=lambda i: -i.file_size):
                    if inner.file_size > MAX_ROM:
                        continue
                    data = archive.read(inner)
                    if data.startswith((b"MZ", b"PK\x03\x04")):
                        try:
                            return _unzipped(data, nested=nested - 1)
                        except ValueError as e:
                            if "UEFI" in str(e):
                                raise
                            if "encrypted" in str(e):  # (Foxconn NFPIK8AA's BIOS.ZIP)
                                plain = _decrypted_zip(data, _package_passwords(archive))
                                if plain is not None:  # (the password the package names)
                                    return _unzipped(plain, nested=nested - 1)
                                raise ValueError(
                                    f"the image in {inner.filename} inside this "
                                    "ZIP archive is encrypted (password "
                                    "protected): unpack it and attach the image "
                                    "itself"
                                ) from e
                            continue
            # (two 64 KB EPROMs named as a pair are one image, though each is of a flash
            # chip's size: Chaintech ELT-286B's "... L.BIN" and "... H.BIN")
            pair = (
                _rom_pair(archive)
                if not images
                else _rom_pair(archive, named=True) if len(images) == 2 else None
            )
            if pair is not None:
                return pair
            bio = [i for i in archive.infolist() if INTEL_PART.search(i.filename)]
            efi = (
                [i for i in bio if "EFI Firmware".encode("utf-16-le") in archive.read(i)[:0x400]]
                if not images
                else []
            )
            for part in efi:  # (unpacked to its firmware image)
                try:
                    return intelbio.image(archive.read(part))
                except ValueError:
                    pass
            if efi:
                raise ValueError(
                    "this is Intel's UEFI firmware (\"Intel Desktop Board EFI "
                    'Firmware" .BIO, about 2007 on), whose graphical setup is '
                    "not rebuilt"
                )
            if not images and bio and (image := _intel_bio([archive.read(i) for i in bio])):
                return image
            headed = [i for i in archive.infolist() if _near_flash_size(i.file_size)]
            if (
                not images
                and headed
                and (
                    image := _trimmed(  # a header in front (ASRock:
                        archive.read(max(headed, key=lambda i: i.file_size))
                    )
                )
                is not None
            ):  # 8 MB + 4 KB)
                return image
            for disk in [
                i for i in archive.infolist() if _floppy_header(i.file_size) is not None
            ] * (not images):
                if (image := _from_disk(archive.read(disk))) is not None:
                    return image  # (a flash diskette's image in the ZIP)
            for flash in [
                i for i in archive.infolist() if i.filename.upper().endswith((".OCF", ".OMF"))
            ] * (
                not images
            ):  # (Fujitsu-Siemens' .BUP: a ZIP)
                if (image := _snipac(archive.read(flash))) is not None:
                    return image
            for iso in [
                i
                for i in archive.infolist()
                if i.filename.upper().endswith(".ISO") and i.file_size <= 64 * 1024 * 1024
            ] * (not images):
                # a CD image (FSC's MSI MS-7293 update: its El Torito boot diskette holds the
                # flash files), read with 7-Zip like a diskette image
                if (image := _seven_zip_image(archive.read(iso))) is not None:
                    return image
            for rom in [i for i in archive.infolist() if not i.is_dir()] * (not images):
                # (HP's Online ROM Flash for ProLiants: a ROMPaq file, CPQW0201.F03)
                if (image := softpaq.rom_image(archive.read(rom))) is not None:
                    return image
            programs = [
                i
                for i in archive.infolist()
                if i.filename.upper().endswith(".EXE") and 0x10000 < i.file_size <= 4 * MAX_ROM
            ]
            for exe in sorted(programs, key=lambda i: -i.file_size)[:1] * (not images):
                # an update program inside (Intel's Express BIOS Update: PB94510J), opened
                # with 7-Zip one level deep
                packed = archive.read(exe)
                if (image := _seven_zip_image(packed, 1) or _diskette_program(packed)) is not None:
                    return image
            files = [i for i in archive.infolist() if not i.is_dir()]
            if not images and len(files) == 1 and 0x2000 <= files[0].file_size < 0x10000:
                return archive.read(files[0])  # (one small ROM alone: an XT's 8 KB, CTE-1120)
            # (a small ROM beside a readme or a video ROM: Tandon 188840, Acer 710)
            for small in sorted(
                (i for i in files if 0x2000 <= i.file_size < 0x10000),
                key=lambda i: -i.file_size,
            ) * (not images):
                if (image := archive.read(small))[-16] in (0xEA, 0xE9):
                    return image
            if not images:
                raise ValueError(
                    "this ZIP archive holds no file of a flash chip's size (a "
                    "multiple of 64 KB up to 32 MB): "
                    + ", ".join(i.filename for i in archive.infolist()[:20])
                )
            data = archive.read(max(images, key=lambda i: i.file_size))
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as e:
            # (7-Zip reads some that Python refuses: duplicate entries, odd headers)
            if (image := _seven_zip_image(raw)) is not None:
                return _paired_halves(image)
            raise ValueError(f"this ZIP archive cannot be read: {e}") from e
        if len(data) > MAX_ROM:
            raise ValueError("the image in this ZIP archive is larger than it claims")
        return _paired_halves(data)
    if program and (plain := _xored_zip(raw)) is not None:
        return _unzipped(plain, nested=nested)
    if program and (image := _dell_lzexe_image(raw)) is not None:
        return image
    if program and (image := _biofile_image(raw)) is not None:
        return image
    if program and (image := _dell_update(raw)) is not None:
        return image
    if program and (image := _diskette_program(raw)) is not None:
        return image
    if program and (image := _afu_image(raw)) is not None:
        return image  # (ASRock's DOS flash programs: AMI's AFU with the image built in)
    if program:  # an LHA archive that unpacks itself
        members = [m for m in lzh.find_modules(raw) if _flash_size(m["size"])]
        if (tail := _tail_image(raw)) is not None and all(
            m["offset"] >= len(raw) - len(tail) for m in members
        ):
            return tail  # (its first module, the system BIOS, looked like the image)
        if not members and (image := _seven_zip_image(raw)) is not None:
            return image  # (7z or RAR inside: Gigabyte, ECS)
        if not members and _near_flash_size(len(raw)) and (image := _trimmed(raw)) is not None:
            return image  # (the image behind a program header: Supermicro X7DA8's .704)
        if not members and (image := _sqx_image(raw)) is not None:
            return image  # (MSI's SQX self-extractors: 7-Zip does not read them)
        packer = next((name for marker, name in PACKED_UPDATES if marker in raw), None)
        if not members and packer:
            raise ValueError(
                f"this is {packer}, which keeps the image packed in its own "
                "format that cannot be read here: attach the image itself "
                "(e.g. a dump of the flash chip)"
            )
        if not members and (image := _lha_pair(raw)) is not None:
            return image
        if not members and (image := _gzip_image(raw)) is not None:
            return image
        if not members and (image := _cab_image(raw)) is not None:
            return image
        if not members:
            raise ValueError(
                "this is a program (perhaps a BIOS update that unpacks itself), but "
                "no image of a flash chip's size could be read from it: unpack it "
                "and attach the image itself"
            )
        m = max(members, key=lambda m: m["size"])
        packed = raw[m["data_start"] : m["data_start"] + m["packed"]]
        try:
            image = lzh.decompress(packed, m["size"], m["method"].encode())
            # (an Award update that keeps the setup module beside the image instead of inside
            # it, Dell Dimension C521's awardext.rom: the chain of modules is what is read)
            if not lzh.find_modules(image, limit=2) and (bundle := _award_bundle(raw)):
                return bundle
            return image
        except Exception as e:
            # an LHA header seen by chance in other compressed data (HP's CAB setups): what
            # 7-Zip finds instead
            if (image := _seven_zip_image(raw)) is not None:
                return image
            # (a last block that does not decode, EXB130's Award image: 97 % of it is the
            # setup code all the same; the rest as an erased flash chip)
            try:
                head = lzh.decompress(packed, m["size"], m["method"].encode(), True)
            except Exception:  # pylint: disable=broad-exception-caught
                head = b""
            if len(head) >= m["size"] * 95 // 100:
                return head + b"\xff" * (m["size"] - len(head))
            raise ValueError(
                f"the image {m['name']} in this program cannot be unpacked: {e}"
            ) from e
    if raw.startswith((b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c")):  # a RAR or 7z archive itself
        image = _seven_zip_image(raw)
        if image is None:
            raise ValueError(
                "this RAR/7z archive holds no file of a flash chip's size (a "
                "multiple of 64 KB up to 32 MB), or 7-Zip is not installed to "
                "read it: unpack it and attach the image itself"
            )
        return _paired_halves(image)
    if _floppy_header(len(raw)) is not None and (image := _from_disk(raw)) is not None:
        return image
    if _near_flash_size(len(raw)) and (image := _trimmed(raw)) is not None:
        return image  # (a header or trailer around the image: Supermicro X5DAL's .rom)
    return _paired_halves(raw)


def _capsule_body(cap: bytes) -> bytes:
    """The firmware image in a UEFI capsule (ASUS .CAP: AMI's Aptio capsule, a GUID, the
    header's length at 16, then the image), or the file itself."""
    header = int.from_bytes(cap[16:20], "little") if len(cap) > 0x20 else 0
    if 0x1C <= header < 0x1000 and b"_FVH" in cap[header : header + 0x100000]:
        body = cap[header:]
        size = 1 << (len(body).bit_length() - 1)  # (more header follows on ASUS
        if not _flash_size(len(body)) and _flash_size(size):  # Crossblade Ranger's: 2 KB)
            body = body[-size:]
        return body
    return cap


def _tail_image(raw: bytes) -> bytes | None:
    """An Award image stored as it is at the end of an update program (Shuttle AK10's
    AK10S019.EXE: 256 KB behind the flash tool, which also carries a 128 KB part in its own
    archive): the largest one of a flash chip's size that ends with a reset vector and starts
    with an LHA module, or None."""
    if len(raw) < 0x10040 or not _reset_vector(raw[-0x10000:]):
        return None
    for size in (0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000):
        start = len(raw) - size
        if start >= 0x40 and re.match(rb"..-lh[0-7]-", raw[start : start + 7], re.S):
            return raw[start:]
    return None


FLOPPY_SIZES = {368640, 737280, 1228800, 1474560, 2949120}


def _floppy_header(size: int) -> int | None:
    """The size of a header in front of a diskette image of this file size (0 for a plain
    image; AST's DISK.IMG has 4 bytes), or None if it is not one."""
    for floppy in FLOPPY_SIZES:
        if 0 <= size - floppy <= 512:
            return size - floppy
    return None


def _fat_files(img: bytes) -> dict[str, bytes]:
    """The files of a FAT12/16 diskette image (subdirectories too), by path."""
    bps, spc, res, nfats, nroot, total16, _media, spf = struct.unpack_from("<HBHBHHBH", img, 11)
    if bps not in (512, 1024, 2048) or not spc or not nfats or not spf:
        raise ValueError("no FAT boot sector")
    total = total16 or struct.unpack_from("<I", img, 32)[0]
    fat = img[res * bps : (res + spf) * bps]
    root = (res + nfats * spf) * bps
    data = root + (nroot * 32 + bps - 1) // bps * bps
    fat16 = (total * bps - data) // (spc * bps) >= 4085

    def chain(cluster: int, size: int | None = None) -> bytes:
        out, seen = bytearray(), set()
        while 2 <= cluster < (0xFFF8 if fat16 else 0xFF8) and cluster not in seen:
            seen.add(cluster)
            start = data + (cluster - 2) * spc * bps
            out += img[start : start + spc * bps]
            if fat16:
                cluster = struct.unpack_from("<H", fat, 2 * cluster)[0]
            else:
                pair = struct.unpack_from("<H", fat, cluster * 3 // 2)[0]
                cluster = pair >> 4 if cluster & 1 else pair & 0xFFF
        return bytes(out if size is None else out[:size])

    files: dict[str, bytes] = {}

    def walk(entries: bytes, prefix: str, depth: int) -> None:
        for i in range(0, len(entries) - 31, 32):
            e = entries[i : i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5 or e[11] & 0x08 or e[11] == 0x0F:  # deleted, label, long name
                continue
            name, ext = e[0:8].decode("latin-1").rstrip(), e[8:11].decode("latin-1").rstrip()
            start, size = struct.unpack_from("<H", e, 26)[0], struct.unpack_from("<I", e, 28)[0]
            if e[11] & 0x10:
                if name not in (".", "..") and depth < 4:
                    walk(chain(start), f"{prefix}{name}/", depth + 1)
            else:
                files[prefix + name + ("." + ext if ext else "")] = chain(start, size)

    walk(img[root:data], "", 0)
    return files


def _from_disk(img: bytes) -> bytes | None:
    """The flash image on a BIOS update diskette (an image of it, .IMA/.IMG): the largest file
    of a flash chip's size, else what an archive or program on it holds."""
    try:
        files = _fat_files(img[_floppy_header(len(img)) or 0 :])
    except (ValueError, struct.error):
        return None
    images = [d for d in files.values() if _flash_size(len(d))]
    if images:
        return max(images, key=len)
    roms = [image for d in files.values() if (image := softpaq.rom_image(d)) is not None]
    if roms:  # (Compaq's ROMPaq files: a header and the ROM imploded; the largest)
        return max(roms, key=len)
    for boot in [d for d in files.values() if d.startswith(b"#Pro-Sec#")]:
        # Apricot/Mitsubishi's recovery diskettes (Hornet HN440, 1999): the boot block's
        # "#Pro-Sec#" header names the main BIOS part (240 KB) that goes below it; if it
        # is not stamped yet, the .PRT files name the parts (Lightning, 1998)
        prt = [n.upper()[:-4].encode() for n in files if n.upper().endswith(".PRT")]
        for name in re.findall(rb"\b(\d{6}SW)\b", boot[:0x100]) + prt:
            main = files.get(name.decode() + ".BIN", b"")
            if main and _flash_size(len(main) + len(boot)):
                return main + boot
    bio = [d for name, d in files.items() if INTEL_PART.search(name)]
    if bio and (image := _intel_bio(bio)) is not None:  # (Intel's update diskettes)
        return image
    for data in files.values():  # Fujitsu-Siemens' run-length coded image (.OCF)
        if (image := _snipac(data)) is not None:
            return image
    near = [d for d in files.values() if _near_flash_size(len(d))]  # (PHLASH16's .WPH)
    if near and (image := _trimmed(max(near, key=len))) is not None:
        return image
    for data in sorted(files.values(), key=len, reverse=True):
        if data.startswith((b"MZ", b"PK\x03\x04")):
            try:
                return _unzipped(data, nested=False)
            except ValueError:
                continue
    return None


def _dell_lzexe_image(raw: bytes) -> bytes | None:
    """The image in Dell's LZEXE-packed flash programs (WorkStation 400, PowerEdge 2100), or
    None: raw behind the program's code, its end the reset vector's 16 bytes. A PLUS 1.10
    image starts with E0h and its copyright at +2; PhoenixBIOS 4.05 has
    only the far jump with its date, 128 KB whose bytes sum to 0 (the size is a guess: 256 KB
    sums to 0 as well)."""
    data = lzexe.unpack(raw) if lzexe.is_packed(raw) else None
    if data is None or bios_emu.DELL_MARK not in data:
        return None
    for m in re.finditer(rb"\xe0Copyright 1985-", data):
        for size in (0x20000, 0x40000, 0x80000):
            start = m.start() - 2
            slot = data[start + size - 16 : start + size]
            if start >= 0 and slot[:1] == b"\xe9" and slot[3:] == b"\xff" * 13:
                return data[start : start + size]
    for m in re.finditer(b"DELLBIOS\0", data):  # (OptiPlex 560L: Intel's core, 128 KB)
        if data[m.start() + 0x1FFF0 : m.start() + 0x1FFF5] == b"\xea\x5b\xe0\x00\xf0":
            return data[m.start() : m.start() + 0x20000]
    for m in re.finditer(rb"\xea\x5b\xe0\x00\xf0\d\d/\d\d/\d\d", data):
        image = data[m.start() + 16 - 0x20000 : m.start() + 16]
        if len(image) == 0x20000 and not sum(image) & 0xFF:
            return image
    return None


def _xored_zip(raw: bytes) -> bytes | None:
    """The ZIP archive in Zenith Data Systems' update programs (a licence screen, then the
    archive with every byte XORed with D0h), or None."""
    start = raw.find(bytes(c ^ 0xD0 for c in b"PK\x03\x04"))
    if start < 0:
        return None
    plain = bytes(c ^ 0xD0 for c in raw[start:])
    return plain if zipfile.is_zipfile(io.BytesIO(plain)) else None


def _biofile_image(raw: bytes) -> bytes | None:
    """The image in Dell's flash program of about 1997-2000 for boards with Intel's BIOS
    (Dimension M60, XPS T), or None: behind the program "BIOFILE", a name of 16 bytes, its
    size (4 bytes and 4 more) and the file, one after the other; the .BIO and .BI1 ... are
    Intel's parts."""
    parts = []
    for m in re.finditer(rb"BIOFILE\0([ -~]{1,15})\0", raw):
        size = int.from_bytes(raw[m.start() + 24 : m.start() + 28], "little")
        if INTEL_PART.search(m[1].decode()):
            parts.append(raw[m.start() + 32 : m.start() + 32 + size])
    return _intel_bio(parts) if parts else None


def _dell_update(raw: bytes) -> bytes | None:
    """The image in Dell's "Flash BIOS Update Program" of about 2003-07 (one EXE for DOS and
    Windows), or None: behind the program a "DellBIOS" or "PyldBioz" header and a gzip
    stream, which holds the image and Dell's 92-byte RBU trailer ("$RBUT"; Dimension 3000,
    OptiPlex GX270)."""
    for magic in (b"DellBIOS\0", b"PyldBioz"):
        at = raw.rfind(magic)
        packed = raw.find(b"\x1f\x8b\x08", at, at + 0x40) if at >= 0 else -1
        if packed < 0:
            continue
        try:
            data = zlib.decompressobj(31).decompress(raw[packed:], MAX_ROM + 0x10000)
        except zlib.error:
            continue
        if (image := _trimmed(data)) is not None and _flash_size(len(image)):
            return image
    return None


def _gzip_image(raw: bytes) -> bytes | None:
    """The UEFI image an update program carries as a plain gzip stream (Alienware Aurora
    R4's A07), or None; firmware volumes in it tell it from a gzip magic seen by chance."""
    for m in re.finditer(b"\x1f\x8b\x08", raw):
        try:
            data = zlib.decompressobj(31).decompress(raw[m.start() :], MAX_ROM + 0x10000)
        except zlib.error:
            continue
        if _flash_size(len(data)) and b"_FVH" in data:
            return data
    return None


def _cab_image(raw: bytes) -> bytes | None:
    """The image in a Microsoft CAB inside an update program (HP's SoftPaqs: BIOS.WPH, or
    a CD image), or None. 7-Zip reads a CAB only on its own; its header gives its size."""
    for m in re.finditer(b"MSCF", raw):
        if m.start() + 12 > len(raw):
            break
        size = struct.unpack_from("<I", raw, m.start() + 8)[0]
        if 0x10000 <= size <= len(raw) - m.start():
            image = _seven_zip_image(raw[m.start() : m.start() + size])
            if image is not None:
                return image
    return None


# update programs that pack the image in their maker's own format: (marker, description)
def _sqx_image(raw: bytes) -> bytes | None:
    """The largest member of a flash chip's size in an SQX archive inside raw, or None."""
    if (offset := sqx.find_archive(raw)) is None:
        return None
    files = [m for m in sqx.members(raw, offset) if _flash_size(m["size"])]
    if not files:
        return None
    member = max(files, key=lambda m: m["size"])
    data, crc_ok, whole = sqx.extract(raw, offset, member["index"])
    if not (crc_ok or whole):  # (a member before it is in a method not read here)
        raise ValueError(
            f"this is an SQX archive (Squeez) with the image {member['name']}, but it "
            "cannot be unpacked correctly here (it shares its dictionary with files "
            "packed in a way not read here): unpack it and attach the image itself"
        )
    # (when the window was whole a CRC mismatch is a few bytes: MSI H67H2's setup reads)
    return data


PACKED_UPDATES = [
    (b"ROMPaq", "a Compaq ROMPaq update (it writes a firmware diskette)"),
    (b"DELLBIOS", "a Dell BIOS update program"),
    (b"DELL_LZ_00000", "a Dell BIOS update program (with Dell's own DELL_LZ codec)"),
    (b"$RBUT", "a Dell BIOS update program (its $RBUT trailer, the payload not gzip)"),
]


def _afu_image(raw: bytes) -> bytes | None:
    """The image built into AMI's DOS flash program AFU (PMODE/W; ASRock 939A785GMH,
    M3A785GMH, about 2009), or None. At the
    end a chain of records (signature, u32 size), "@UAF" running to the end of the file, then
    "@UII", "@CMD" and "@ROM"; the image is an LHA -lh5- stream (no LHA header) from @ROM+18h,
    its size (the flash chip's) at @ROM+14h."""
    top = raw.rfind(b"@UAF")
    if top < 0 or top + struct.unpack_from("<I", raw, top + 4)[0] != len(raw):
        return None
    rom = raw.find(b"@ROM", top)
    if rom < 0 or rom + 0x18 > len(raw):
        return None
    size = struct.unpack_from("<I", raw, rom + 0x14)[0]
    if not _flash_size(size):
        return None
    try:
        return lzh.decompress(raw[rom + 0x18 :], size, b"-lh5-")
    except Exception:
        return None


def _snipac(data: bytes) -> bytes | None:
    """Fujitsu-Siemens' flash files (.OCF, BIOFLASH diskettes 2002-05: D1307, D1357, D1372 ...):
    a header (BIOS name, date, region letters "GGG..III..RRRRRRRR"; it ends 10h bytes after
    the R's: 70h bytes, 78h in the older .OMF), then the image, in which a run of one byte
    may be written "SNIPAC" + the byte as two hex digits ("FF", "00") + its length (32 bits);
    one byte (a checksum) follows the image. Only the top of the flash may be in it (D1372:
    384 KB), so the image is filled up in front to a power of two. None if it is not such a
    file. (D1761's and D1875's on their diskettes have 8 other bytes in place of the R's,
    their header the same 70h bytes from C1 71.)"""
    regions = data.find(b"RRRRRRRR", 0, 0x100)
    if regions < 0 and data.startswith(b"\xc1\x71") and b"GGGG" in data[:0x60]:
        regions = 0x60
    if regions < 0 or b"GGGG" not in data[:regions] or len(data) <= regions + 0x10:
        return None
    out, p = bytearray(), regions + 0x10
    while p < len(data):
        q = data.find(b"SNIPAC", p)
        if q < 0 or q + 12 > len(data):
            out += data[p:]
            break
        out += data[p:q]
        try:
            value = int(data[q + 6 : q + 8], 16)
        except ValueError:
            return None
        count = struct.unpack_from("<I", data, q + 8)[0]
        if len(out) + count > MAX_ROM:
            return None
        out += bytes([value]) * count
        p = q + 12
    if not 1 <= len(out) % 0x10000 <= 16:  # (the checksum: 1 byte, 9 after an .OMF)
        return None
    image = bytes(out[: len(out) - len(out) % 0x10000])
    size = 1 << (len(image) - 1).bit_length()
    image = b"\xff" * (size - len(image)) + image
    return image if image[-16] in (0xEA, 0xE9) else None


def _paired_halves(raw: bytes) -> bytes:
    """A 16-bit ROM's two EPROMs saved one after the other in a single file (the even bytes'
    chip first, Gigabyte GA-486QS: 2 x 32 KB): interleaved when that, and not the file as it
    is, puts a far jump at the reset vector (16 bytes before the end). An image saved into a
    larger, empty chip's size (Inside Technology 686LCD-S: 256 KB of BIOS, then 256 KB of
    zeros) is its first half when only that ends with the reset vector. Or the part before
    blank blocks (DP511A: 128 KB of 256 KB, a mark left in the third block)."""
    if len(raw) >= 0x20000 and not len(raw) % 0x10000 and raw[-16] != 0xEA:
        for block in range(len(raw) // 0x10000 - 1, 0, -1):
            tail = raw[block * 0x10000 :]
            common = collections.Counter(tail).most_common(1)[0][1]
            if raw[block * 0x10000 - 16] == 0xEA and common >= 0.99 * len(tail):
                raw = raw[: block * 0x10000]
                break
    while (
        len(raw) >= 0x20000
        and not len(raw) & (len(raw) - 1)
        and raw[-16] != 0xEA
        and raw[len(raw) // 2 - 16] == 0xEA
        and len(set(raw[len(raw) // 2 :])) == 1
        and raw[-1] in (0x00, 0xFF)
    ):
        raw = raw[: len(raw) // 2]
    # (a near jump at the reset vector is one too: Phoenix PICOBIOS 4.0)
    if not 0x8000 <= len(raw) <= 0x40000 or len(raw) & (len(raw) - 1) or raw[-16] in (0xEA, 0xE9):
        return raw
    half = len(raw) // 2
    for low, high in ((raw[:half], raw[half:]), (raw[half:], raw[:half])):
        image = bytearray(len(raw))
        image[0::2], image[1::2] = low, high
        if image[-16] == 0xEA:
            return bytes(image)
    return raw


def _bios_setup_screens(
    channel_id: int,
    name: str,
    pages: str = "all",
    defaults: str = "setup",
    color: int = 0,
    style: str = "",
) -> dict:
    token = _rendered.set([])
    style_token = _style.set(style)
    hits_token = bios_emu.time_limits_hit.set([])
    try:
        result = _setup_screens(channel_id, name, pages, defaults, color)
        _attach_screens(result, _rendered.get())
        if hits := len(bios_emu.time_limits_hit.get() or []):
            # (for diagnosis: several routes stop POST at the time limit by design, so a hit
            # alone does not mean pages are missing; not shown to the user)
            result["time_limit_hits"] = hits
        return result
    finally:
        bios_emu.time_limits_hit.reset(hits_token)
        gc.collect()  # (a finished BiosEmulator is a cycle holding its RAM)
        _rendered.reset(token)
        _style.reset(style_token)


def _setup_screens(
    channel_id: int, name: str, pages: str = "all", defaults: str = "setup", color: int = 0
) -> dict:
    path = workspace._resolve(channel_id, name)
    archive = path.read_bytes()
    raw = _unzipped(archive)
    award6_failure = None  # why an image with an awardext module was not read as 6.00PG
    try:  # Award 6.00PG full flash image (system BIOS + awardext module)
        return _award6_screens(path, award6_setup.Award6(raw), pages, defaults)
    except ValueError as award6_error:
        if any(m["name"].lower().startswith("awardext") for m in lzh.find_modules(raw)):
            try:
                return _menubar_screens(
                    path, award_menubar_setup.AwardMenuBar(raw), pages, defaults
                )
            except ValueError as menubar_error:  # (4.51PG images have awardext too)
                try:  # OEM setups whose main menu is code (Soltek, HP): the item pages
                    if lzh.find_modules(raw, limit=1) and language_module_present(raw):
                        return _award6_pages_screens(
                            path, award6_setup.Award6(raw, pages_only=True), pages, defaults
                        )
                except ValueError:
                    pass
                try:  # OEM 6.00PG setups without a page frame script (Maxdata, IBM's USI)
                    return _award6_screens(
                        path, award6_setup.Award6(raw, drawn_frames=True), pages, defaults
                    )
                except ValueError:
                    pass
                award6_failure = ValueError(
                    "this is a full Award/Phoenix-Award flash image with an awardext module, "
                    "but its setup is laid out differently from the supported ones (6.00PG "
                    f"classic main menu: {award6_error}; menu bar: {menubar_error}). Use "
                    "unpack_rom and strings on the modules for the menu texts."
                )
    # (ASUS's "v6.0" Award BIOSes, e.g. P3B-F, have the Medallion setup in an awardext module
    # without the Medallion name)
    if (
        award_medallion_setup.is_medallion(raw)
        or award6_failure is not None
        or lzh.find_modules(raw, limit=1)
    ):  # (the name may be only in packed modules)
        try:
            bios = award_medallion_setup.AwardMedallion(raw)
        except ValueError:
            bios = None
        if bios is not None:
            return _medallion_screens(path, bios, pages, defaults)
    if winbios_setup.is_winbios(raw):
        return _winbios_screens(path, raw, pages, defaults, color)
    if mr_setup.is_mr_bios(raw):
        return _mr_screens(path, raw, pages)
    if phoenix_setup.is_phoenix_setup(raw):
        return _phoenix_screens(path, raw, pages)
    if ami8_setup.is_amibios8(raw) or ami8_static_setup.is_amibios8_static(raw):
        static = ami8_static_setup.is_amibios8_static(raw)
        if static and not _intel_host(raw):  # (the emulator's AMIBIOS 8 boards are Intel's:
            # trying others first only costs minutes before the static reader takes over)
            return _ami8_static_screens(
                path,
                raw,
                pages,
                ValueError(
                    "its chipset is not an Intel one, for which the AMIBIOS 8 POST runs here"
                ),
            )
        try:
            return _ami8_screens(path, raw, pages)
        except ValueError as emulation_error:  # e.g. a chipset the emulator does not know
            if not static:
                raise
            return _ami8_static_screens(path, raw, pages, emulation_error)
    if ami_hiflex_setup.is_hiflex(raw):  # (also on AMIBIOS 7 cores: before the new setup)
        try:
            return _hiflex_screens(path, raw, pages)
        except ValueError as post_error:  # POST never got to setup: start it directly
            try:
                return _hiflex_direct_screens(path, raw, pages, post_error)
            except ValueError:
                raise post_error from None
    if ami_easy_setup.is_easy_setup(raw):
        return _easy_screens(path, raw, pages)
    if ami7_setup.is_amibios7(raw):
        return _ami7_screens(path, raw, pages)
    if ami7_setup.is_amibios6(raw):  # (Gateway 2000; other 06 images go on below)
        try:
            return _ami7_screens(path, raw, pages)
        except ValueError:
            pass
    try:
        data, source = _system_bios(raw)
    except ValueError as award_error:
        if award6_failure is not None:
            raise award6_failure from award_error
        if award_emu_setup.is_early_award(raw) and b"American Megatrends" not in raw:
            # before the AMI entry search, whose code pattern also occurs in some Award ROMs
            return _award_emu_screens(path, raw, pages)
        try:
            ami_setup.find_entry(raw)
        except ValueError:
            if b"AMIBIOSPAMIBIOSS" in raw:
                raise ValueError(
                    "this is the runtime half (F000) of an AMI WinBIOS: the setup "
                    "program is a compressed module in the other half of the ROM, "
                    "which this file lacks. A full image (starting with the "
                    "AMIBIOSC header, usually 128 KB) is needed."
                ) from award_error
            if award_emu_setup.is_early_award(raw):  # Award before the screen scripts
                return _award_emu_screens(path, raw, pages)
            if dtk_setup.is_dtk(raw):  # DTK's own BIOS
                return _dtk_screens(path, raw, pages)
            if mylex_setup.is_mylex(raw):  # Mylex's own BIOS (MVI486, 1993)
                return _mylex_screens(path, raw, pages)
            if ami_qa_setup.is_ami_qa_setup(raw):  # AMI 286 of 1988 with diagnostics
                return _ami_qa_screens(path, raw, pages)
            if quadtel_setup.is_quadtel(raw):  # Quadtel's System SETUP of the early 1990s
                return _quadtel_screens(path, raw, pages)
            if ncr_setup.is_ncr_at(raw):  # NCR's version of IBM's AT ROM BIOS (NCR 3230)
                return _ncr_screens(path, raw, pages)
            if dell_setup.is_dell_phoenix(raw):  # Dell's Phoenix 1.10 of about 2003-04
                return _dell_screens(path, raw, pages)
            if dell_setup.is_dell_paged(raw):  # the same BIOS of about 1997
                return _dell_paged_screens(path, raw, pages)
            if novell_setup.is_novell(raw):  # the ATterminal's ROM SETUP (1987-88)
                return _novell_screens(path, raw, pages)
            if texasmicro_setup.is_texas_micro(raw):  # its own Setup Utility (1998)
                return _texas_micro_screens(path, raw, pages)
            if prompt_setup.family(raw) is not None:  # a prompt, a key and a screen
                return _prompt_screens(path, raw, pages)
            if tandon_setup.is_tandon(raw):  # Tandon's own SYSTEM SETUP (early 1990s)
                return _tandon_screens(path, raw, pages)
            if chips_setup.is_chips_scat(raw):  # C&T's own BIOS for SCAT 286 boards
                return _chips_screens(path, raw, pages)
            if acer_setup.is_acer(raw):  # Acer's own BIOS Utility (mid 1990s)
                return _acer_screens(path, raw, pages)
            if phoenix_setup.is_phoenix_text_setup(raw):  # PhoenixBIOS 4.0x of 1994-96
                return _phoenix_text_screens(path, raw, pages)
            if phoenix_old_setup.is_old_phoenix(raw):  # Phoenix before 4.0
                return _phoenix_old_screens(path, raw, pages)
            uefi_failure = None
            if uefi_setup.is_uefi(raw):  # UEFI firmware: its HII forms, read statically
                try:
                    return _uefi_screens(path, raw, pages)
                except ValueError as e:
                    uefi_failure = e
                    # Intel's EFI updates keep the setup's packs once more in an .ITK
                    # part beside the image
                    part = intel_itk.itk_part(archive)
                    if part is not None:
                        try:
                            return _itk_screens(path, part, pages, e)
                        except ValueError:
                            pass
            if intel_setup.is_intel_own(raw):  # Intel's menu-bar setup on an AMI core
                try:
                    return _intel_screens(path, raw, pages)
                except ValueError as e:
                    if intel_static_setup.is_intel_static(raw):  # read from the ROM instead
                        try:
                            return _intel_static_screens(path, raw, pages, e)
                        except ValueError as static_error:
                            e = static_error
                    uefi_failure = uefi_failure or e
            if phoenix_tc_setup.is_trustedcore(raw):  # TrustedCore: its template, statically
                try:
                    return _tc_screens(path, raw, pages)
                except ValueError as e:
                    uefi_failure = uefi_failure or e
            if intelexp_setup.is_intel_express(raw):  # Intel's split updates of 1995-97
                try:
                    return _intelexp_screens(path, raw, pages)
                except ValueError as e:
                    raise ValueError(
                        "this is Intel's Express BIOS of 1995-97 (an AMIBIOS core with "
                        "a menu-bar setup), rebuilt from the update's parts, but its "
                        f"POST did not reach the setup in the emulator ({e})."
                    ) from award_error
            family = _unsupported_family(raw)
            if family and uefi_failure is not None:
                family = f"{family}: {uefi_failure}"
            if "no setup program" in family:
                raise ValueError(f"this is {family}.") from award_error
            raise ValueError(
                (
                    f"this is {family}, whose setup screens cannot be rebuilt yet. "
                    if family
                    else "no supported setup code found: neither Award 4.5x/6.00PG screen "
                    "scripts nor a classic AMIBIOS setup (about 1988-1994) nor an AMI "
                    "WinBIOS. "
                )
                + "Use strings (or unpack_rom and strings on the modules) to read the menu "
                "texts."
            ) from award_error
        return _ami_screens(path, raw, pages, defaults, color)
    return _award_screens(path, data, source, pages, defaults, raw)


# BIOS families recognised but not supported by bios_setup_screens (yet): (marker, description)
UNSUPPORTED_FAMILIES = [
    (
        b"U-Boot ",
        "the firmware of an embedded device (U-Boot), not a PC BIOS: it has no setup program",
    ),
    (
        b"coreboot",
        "a coreboot firmware, which has no setup program in the ROM: its settings are made "
        "when it is built, or in the payload it loads",
    ),
    (
        b"NeXT ROM Monitor",
        "the ROM of a NeXT computer (68k, not a PC), whose ROM monitor is not a setup "
        "program of the kind rebuilt here: it has no setup program",
    ),
    (
        b"8088/86 Modular BIOS",
        "an Award XT-class BIOS for 8088 PCs, which has no setup program at all: those "
        "machines are configured with the DIP switches on the board",
    ),
    (
        b"8088 BIOS",
        "an XT-class BIOS for 8088 PCs, which has no setup program at all: those "
        "machines are configured with the DIP switches on the board",
    ),
    (
        b"XT BIOS",
        "an XT-class BIOS, which has no setup program at all: those machines are "
        "configured with the DIP switches on the board",
    ),
    (
        b"03COMPAQ",
        "a Compaq BIOS, which has no setup program in the ROM: Compaq's Computer "
        "Setup (F10) runs from the hard disk's system partition or a diskette",
    ),
    (
        b"01COMPAQ",  # (the earlier Compaq Deskpro ROMs: "Insert COMPAQ MS-DOS diskette")
        "a Compaq BIOS, which has no setup program in the ROM: Compaq's setup runs "
        "from the diagnostics/setup diskette",
    ),
    (
        b"AMIBIOS SIMPLE SETUP UTILITY",
        "an AMIBIOS with the text-mode Simple Setup (Hi-Flex style, about 1996-98)",
    ),
    (b"HIFLEX SETUP UTILITY", "an AMIBIOS with the Hi-Flex text-mode setup (about 1996-98)"),
    (b"BCPFFV", "a Phoenix TrustedCore/SecureCore firmware (FFV volumes, about 2006-10)"),
    (
        b"PhoenixBIOS 4.0",
        "a PhoenixBIOS 4.0 (menu-bar setup: Main, Advanced, Security, Power, Boot, Exit)",
    ),
    (
        b".86A.",
        "Intel's own BIOS of an Intel desktop board (an AMI core with Intel's menu-bar "
        "setup; BIOS ID ....86A....)",
    ),
    (b"Phoenix - AwardBIOS", "a Phoenix-AwardBIOS with the menu-bar setup"),
    (b"Award Medallion", "an Award Medallion BIOS (menu-bar setup)"),
    (b"AMIBIOS(C)2001", "an AMIBIOS 8 (menu-bar setup)"),
    (b"Aptio", "an AMI Aptio UEFI firmware"),
    (b"InsydeH2O", "an InsydeH2O UEFI firmware"),
    (b"_FVH", "a UEFI firmware (firmware volumes) whose setup forms could not be read"),
]


def _unsupported_family(raw: bytes) -> str:
    """Which known but unsupported family a ROM belongs to, searching packed modules too."""
    blobs = [raw]
    try:
        _, modules = ami.extract(raw)
        blobs += [m.get("data") or b"" for m in modules]
    except Exception:  # not an AMI 95-format image
        pass
    for m in lzh.find_modules(raw):
        try:
            blobs.append(
                lzh.decompress(
                    raw[m["data_start"] : m["data_start"] + m["packed"]],
                    m["size"],
                    m["method"].encode(),
                )
            )
        except Exception:  # damaged module
            continue
    try:
        _, modules = phoenix.extract(raw)
        blobs += [m.get("data") or b"" for m in modules]
    except Exception:  # not a Phoenix image
        pass
    for marker, description in UNSUPPORTED_FAMILIES:
        if marker == b"03COMPAQ" and len(raw) > 0x40000:
            # (HP's later BIOSes keep the marker and do have Computer Setup in ROM)
            if any(marker in blob for blob in blobs):
                return (
                    "an HP business-PC BIOS (of Compaq descent: its Computer Setup, F10, is "
                    "in the ROM but is HP's own program, which this reader does not rebuild)"
                )
            continue
        if any(marker in blob for blob in blobs):
            if raw.startswith(b"MZ") and len(blobs) == 1:  # (ASUS's AWDFLASH alone)
                return (
                    "a flash program without a BIOS image (the family name is the "
                    "program's own text), so no setup program is in it: attach the "
                    "image itself"
                )
            return description
    if len(raw) <= 0x10000 and b"Phoenix Technologies" in raw and b"SETUP" not in raw.upper():
        # (Tulip TC12/TC16, Intel DB403E, GS386CT: only CMOS error messages)
        return (
            "an early Phoenix BIOS (1.x, 286/386 era) with no setup program in the ROM: "
            "those machines were set up from a setup diskette"
        )
    if phoenix_old_setup.setup_on_diskette(raw):  # (POST messages only)
        return (
            "an early Phoenix BIOS (286/386 era) with no setup program in the ROM: POST asks "
            "to run SETUP, which was a program on a diskette"
        )
    if (kind := _option_rom_kind(raw)) is not None:
        return (
            f"the BIOS of an expansion card ({kind}; an option ROM: 55 AA, no reset vector "
            "at its end), not a mainboard BIOS: it has no setup program of the kind "
            "rebuilt here"
        )
    if (  # (IBM 5160, Sanyo SPC-400D, Ericsson Portable, Corona PPC-400, Amstrad PC1640)
        len(raw) <= 0x10000
        and raw[-16:-15] == b"\xea"
        and raw[-2] in (0xFB, 0xFE, 0xFF)  # the model byte of the PC and the XT
        and not re.search(rb"(?i)setup", raw)
    ):
        return (
            "an XT-class BIOS (its model byte says PC or XT), which has no setup program "
            "at all: those machines are configured with DIP switches or a diskette"
        )
    if len(raw) <= 0x2000 and raw[-16:-15] == b"\xea":  # (Laser Turbo XT, Central Point 1987)
        return (
            "an 8 KB BIOS, the size of an XT-class PC's, which has no setup program at "
            "all: those machines are configured with the DIP switches on the board"
        )
    return ""


PCI_CLASSES = {
    0x01: "a disk controller",
    0x02: "a network card",
    0x03: "a video card",
    0x0C: "a USB or other serial bus controller",
}
VIDEO_TEXT = re.compile(
    rb"VGA|EGA|[Vv]ideo|VIDEO|Graphics|GRAPHICS|Tseng|Matrox|Diamond|"
    rb"S3 Inc|Trident|Cirrus|Paradise|Video Seven|ATI Tech|Permedia"
)


def _option_rom_kind(raw: bytes) -> str | None:
    """What an expansion card's ROM (55 AA, its length in 512-byte blocks at 2, no far jump at
    the reset vector) belongs to, from its PCI data structure's class or its texts; None if
    the file is not one. (In the samples most files with no known setup were these: video
    BIOSes saved as .VBI or as a C000 shadow dump.)"""
    if len(raw) < 0x800 or raw[:2] != b"\x55\xaa" or raw[-16] in (0xEA, 0xE9):
        return None
    pcir = int.from_bytes(raw[0x18:0x1A], "little")
    if pcir + 0x10 <= len(raw) and raw[pcir : pcir + 4] == b"PCIR":
        code = raw[pcir + 0x0D : pcir + 0x10]  # (many video BIOSes store it as 03 00 00;
        if code in (b"\x00\x01\x00", b"\x00\x00\x00") and VIDEO_TEXT.search(raw[:0x8000]):
            return "a video card"  # PCI 2.0's class 00/01 is a VGA-compatible device)
        return PCI_CLASSES.get(code[2] or code[0], "a PCI card")
    if VIDEO_TEXT.search(raw[:0x8000]):
        return "a video card"
    if re.search(rb"SCSI|IDE|Disk|DISK", raw[:0x8000]):
        return "a disk controller"
    return "an expansion card"


def _award6_screens(
    path: Path, bios: "award6_setup.Award6", pages: str | None, defaults: str
) -> dict:
    titles = bios.page_titles()
    page_ids = list(titles)
    chosen = _chosen_pages(pages, len(page_ids))
    result: Dict[str, Any] = {
        "bios": "Award 6.00PG: frames and help texts from the awardext module, menus and items "
        "from the system BIOS, drawn with the ROM's screen-script interpreter",
        "pages": {str(i + 1): titles[p] for i, p in enumerate(page_ids)},
        "note": "Values are the ROM's defaults; live readings (temperatures, fans, voltages) are "
        "empty; the placement of help texts is reconstructed. Images are attached.",
        "screens": {},
    }
    for c in chosen:
        if c == "main" and getattr(bios, "pages_only", False):
            continue  # (no main menu of its own)
        if c == "main":
            screen, _ = bios.main_menu()
            title = "MAIN MENU"
        elif 1 <= c <= len(page_ids):
            screen, _ = bios.page(page_ids[c - 1], defaults or "setup")
            title = titles[page_ids[c - 1]]
        else:
            continue
        _save(path, title, screen)
        result["screens"][title] = screen.text()
    return result


def language_module_present(raw: bytes) -> bool:
    return award6_setup.language_module(raw) is not None


def _award6_pages_screens(
    path: Path, bios: "award6_setup.Award6", pages: str | None, defaults: str
) -> dict:
    result = _award6_screens(path, bios, pages, defaults)
    result["bios"] = (
        "Phoenix-AwardBIOS 6.00PG with an OEM menu built by its code (Soltek, HP): "
        "its item pages with frames, labels, options and help texts from the ROM; "
        "the OEM menu bar itself is not rebuilt, and pages are named after the "
        "entries that open them (or numbered)"
    )
    return result


def _medallion_screens(
    path: Path, bios: "award_medallion_setup.AwardMedallion", pages: str | None, defaults: str
) -> dict:
    result = _menubar_screens(path, bios, pages, defaults)
    result["bios"] = (
        "Award Medallion BIOS 6.0: items from the system BIOS, texts and the "
        "layout of the setup module's drawing code (menu bar, values in brackets, "
        "Item Specific Help)"
    )
    result["note"] = (
        "Values are the ROM's defaults; date and time show a sample (01/01/2000), "
        "values the BIOS fills in at run time (drives, memory, boot devices, "
        "speeds) are empty unless the item's option list gives them. Images are "
        "attached."
    )
    return result


def _menubar_screens(
    path: Path,
    bios: "award_menubar_setup.AwardMenuBar | award_medallion_setup.AwardMedallion",
    pages: str | None,
    defaults: str,
) -> dict:
    titles = bios.page_titles()
    page_ids = bios.pages()
    chosen = _chosen_pages(pages, len(page_ids))
    if "main" in chosen:  # (the main menu is the first tab, page 1: drawn once)
        chosen = [1] + [c for c in chosen if c not in ("main", 1)]
    result: Dict[str, Any] = {
        "bios": "Phoenix-AwardBIOS 6.00PG with the menu-bar setup: frame from the awardext "
        "module, items from the system BIOS, labels, options and help texts from the "
        "language module, drawn with the ROM's screen-script interpreter",
        "pages": {str(i + 1): titles.get(p, f"page {p}") for i, p in enumerate(page_ids)},
        "note": "Values are the ROM's defaults; date and time show a sample (01/01/2000), live "
        "readings (memory, drives, temperatures, fans, voltages) are empty, and items "
        "that the BIOS greys out or moves at run time are shown as in the tables. Images "
        "are attached.",
        "screens": {},
    }
    for c in chosen:
        if not isinstance(c, int) or not 1 <= c <= len(page_ids):
            continue
        title = titles.get(page_ids[c - 1], f"page {page_ids[c - 1]}")
        screen, _ = bios.screen(page_ids[c - 1], defaults or "setup")
        _save(path, title, screen)
        result["screens"][title] = screen.text()
    return result


def _ami_screens(path: Path, rom: bytes, pages: str | None, defaults: str, color: int) -> dict:
    ami_defaults = {"setup": "bios", "bios": "power-on"}.get(defaults or "setup", "bios")
    screens, items = ami_setup.setup_screens(rom, color=int(color or 0), defaults=ami_defaults)
    if not screens[0][1].text().strip():  # (a blank screen is no result: DTK PEM-2530, MCS 386)
        raise ValueError(
            "the classic AMIBIOS setup code was found, but it drew nothing in the emulator "
            f"(stopped: {screens[0][2]}). Use strings for the menu texts."
        )
    page_titles = [t for t, _, _ in screens[1:]]
    chosen = _chosen_pages(pages, len(page_titles))
    result: Dict[str, Any] = {
        "bios": "classic AMIBIOS setup, captured by running the ROM's setup code in an x86 "
        "emulator (keys pressed like a user: Down/Enter, F6/F7 + Y to load defaults)",
        "main_menu_items": items,
        "pages": {str(i + 1): t for i, t in enumerate(page_titles)},
        "note": f"Values are the {'BIOS Setup' if ami_defaults == 'bios' else 'Power-On'} "
        "defaults on pages that offer loading them; STANDARD CMOS SETUP shows an emulated "
        "PC (01/01/1994, 1.44 MB floppy, 640 KB + 3 MB). Images are attached.",
        "screens": {},
    }
    warnings = []
    for i, (title, screen, reason) in enumerate(screens):
        if (i == 0 and "main" not in chosen) or (i > 0 and i not in chosen):
            continue
        if reason != "waiting for a key":
            warnings.append(
                f"{title}: emulation stopped early ({reason}); the screen may be " "incomplete"
            )
        _save(path, title, screen)
        result["screens"][title] = screen.text()
    if warnings:
        result["warnings"] = warnings
    return result


# emulated setups take up to a minute: the screens of the last ROMs are kept for follow-up calls
# (e.g. the pages beyond the first nine)
_EMULATED_SCREENS: Dict[str, list] = {}


def _cached_screens(rom: bytes, capture: Callable[[], list]) -> list:
    key = hashlib.sha256(rom).hexdigest()
    if key not in _EMULATED_SCREENS:
        if len(_EMULATED_SCREENS) >= 4:
            _EMULATED_SCREENS.pop(next(iter(_EMULATED_SCREENS)))
        _EMULATED_SCREENS[key] = capture()
    return _EMULATED_SCREENS[key]


def _tc_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: phoenix_tc_setup.TrustedCoreSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Phoenix TrustedCore/SecureCore (about 2006-10), setup read from the image "
        "without running it: the template (_T00) and strings (_S00) modules from its "
        "flash file volumes, unpacked (LH5); drawn in the layout of PhoenixBIOS's "
        "text-mode setup"
    )
    flat = bool(screens) and str(screens[0][0]).startswith("Settings")
    result["note"] = (
        (
            "The settings are listed in the order of the setup's template, several "
            "screens in a row: this template has no menu-bar table, so which menu "
            "(Main, Advanced ...) each belongs to is not read. "
            if flat
            else "The menus are the template's menu bar, in its order, then the "
            "sub-menus (items marked with a triangle). "
        )
        + "The value shown is each setting's first option, not its default (the "
        "setup keeps the values in NVRAM, which is empty in the image); all options "
        "are listed in the help column for the highlighted setting. Images are "
        "attached."
    )
    return result


def _phoenix_static_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    """PhoenixBIOS 4.0 whose POST does not reach setup in the emulator: the template and
    string pack modules read like TrustedCore's."""
    _, modules = phoenix.extract(rom)
    template = next(
        (m["data"] for m in modules if m.get("name") == "template" and m.get("data")), b""
    )
    pack = next((m["data"] for m in modules if (m.get("data") or b"").startswith(b"STRPACK")), b"")
    if not template or not pack:
        raise ValueError("no template and string pack modules")
    screens = _cached_screens(
        rom, lambda: phoenix_tc_setup.TrustedCoreSetup(rom, (pack, template)).screens()
    )
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "PhoenixBIOS 4.0, setup read from the image without running it: the template "
        "and strings modules, unpacked, drawn in the layout of PhoenixBIOS's text-mode "
        "setup"
    )
    flat = bool(screens) and str(screens[0][0]).startswith("Settings")
    result["note"] = (
        (
            "The settings are listed in the order of the setup's template, several "
            "screens in a row (no menu-bar table was found, so which menu each belongs "
            "to is not read). "
            if flat
            else "The menus are the template's menu bar, in its order, then the "
            "sub-menus (items marked with a triangle). "
        )
        + "The value shown is each setting's first option, not its default (the "
        "defaults are in code not run here); all options are listed in the help "
        "column for the highlighted setting. Images are attached."
    )
    return result


def _phoenix_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    if phoenix_tc_setup.is_trustedcore(rom):  # (read statically: POST does not get there)
        try:
            return _tc_screens(path, rom, pages)
        except ValueError:
            pass
    if b"BCPFFV" not in rom:  # the template and strings, read statically: seconds,
        try:  # where the emulated POST takes up to 90 s or fails
            return _phoenix_static_screens(path, rom, pages)
        except ValueError:
            pass
    try:
        screens = _cached_screens(rom, lambda: phoenix_setup.PhoenixSetup(rom).screens())
    except ValueError as e:
        if b"BCPFFV" not in rom:
            raise
        raise ValueError(
            "this is a Phoenix TrustedCore/SecureCore firmware (FFV volumes, "
            "about 2006-10). Its modules are unpacked (unpack_rom), but its "
            f"POST does not get to the setup in the emulator: {e}. Use strings "
            "on the setup and strings modules to read the menu texts."
        ) from e
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "PhoenixBIOS 4.0, captured by running the whole ROM in an x86 emulator "
        "(chipset from the compressed modules, memory sized from SPD data; with an "
        "empty CMOS POST stops at an error and offers the setup key; the setup "
        "drawn in graphics is read back as text with its own font; tabs selected "
        "with the right arrow, their sub-menus (two levels) with Down and Enter)"
    )
    result["note"] = (
        "Values are PhoenixBIOS's own defaults (the CMOS was empty). The PC is "
        "emulated: CPU type and speed, memory (32 MB SDRAM) and drives are what "
        "POST found in the emulator. Images are attached."
    )
    return result


def _mylex_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: mylex_setup.MylexSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Mylex BIOS with its CMOS Setup, captured by running the whole ROM in an "
        "x86 emulator (POST reboots itself once after sizing the memory, then its "
        "warnings offer F2 for setup; the pages are walked with PgDn)"
    )
    result["note"] = (
        "Values are what POST set up in the emulated PC (2 MB of memory). Images are attached."
    )
    return result


def _dtk_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: dtk_setup.DtkSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "DTK (Datatech) BIOS with its ROM SETUP PROGRAM, captured by running the "
        "whole ROM in an x86 emulator (POST with 2 MB stops at the memory "
        "mismatch and offers F1; each numbered item of the main menu chosen with "
        "its number and Enter)"
    )
    result["note"] = (
        "Values are what POST set up in the emulated PC (2 MB of memory, a 1.44 MB "
        "drive A, no hard disk). Preformatting and the password are left out. "
        "Images are attached."
    )
    return result


def _ami_qa_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: ami_qa_setup.AmiQaSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMI 286 BIOS of about 1988 with built-in diagnostics and its question-and-"
        "answer CMOS setup, captured by running the whole ROM in an x86 emulator "
        '(F1 at POST\'s error pause, "SETUP or DIAGS": Y, then 1; each question '
        "answered with Enter, keeping the value shown)"
    )
    result["note"] = (
        "Values are what POST found in the emulated PC (4 MB of memory, no hard "
        "disk). Images are attached."
    )
    return result


def _quadtel_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: quadtel_setup.QuadtelSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Quadtel BIOS with its System SETUP, captured by running the whole ROM in "
        "an x86 emulator (POST with the timer interrupt, ESC skips the memory "
        "test; with no disk to boot from it offers F2 for setup; English chosen "
        "and POST's error list passed; pages with PgDn)"
    )
    result["note"] = (
        "Values are what POST set up in the emulated PC (16 MB of memory, a 1.44 "
        "MB drive A, no hard disk; the CMOS held no Quadtel settings). "
        "Images are attached."
    )
    return result


def _intelexp_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: intelexp_setup.IntelExpressSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Intel's Express BIOS of 1995-97 (AMIBIOS core, menu-bar setup), rebuilt from "
        "the update's flash parts and captured by running it in an x86 emulator "
        "(POST programs the flash; F1 at 'Press <F1> for Setup'; the menus with Right; "
        "the setup draws in monochrome text mode)"
    )
    result["note"] = (
        "Values are what POST found in the emulated PC (the CMOS was empty, so they are "
        "the BIOS's defaults; memory and drives are the emulator's). The sub-pages "
        "behind 'Press Enter' are not opened. Images are attached."
    )
    return result


def _acer_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: acer_setup.AcerSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Acer BIOS with its BIOS Utility, captured by running the whole ROM in an "
        "x86 emulator (POST stops at its configuration errors and offers "
        "Ctrl-Alt-Esc, which the keyboard interrupt catches; the password jumper "
        "is taken as open; Load Setup Default Settings, then each entry of the "
        "main menu and its pages with PgDn)"
    )
    result["note"] = (
        "Values are Acer's setup defaults. The PC is emulated: memory (16 MB), "
        "drives and devices are what POST found in the emulator. "
        "Images are attached."
    )
    return result


def _tandon_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: tandon_setup.TandonSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Tandon's own BIOS with its SYSTEM SETUP, captured by running the whole ROM in an "
        "x86 emulator (POST reports the empty CMOS and enters the setup itself after Enter)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: memory, "
        "drives and devices are what POST found in the emulator. Images are attached."
    )
    return result


def _novell_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: novell_setup.NovellSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "The BIOS of Novell's ATterminal with its ROM SETUP, captured by running the whole "
        "ROM in an x86 emulator (POST offers F2 at its diskette error; a dialogue, group by "
        "group, not menus)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: memory, "
        "drives and the display are what POST found in the emulator. Images are attached."
    )
    return result


def _texas_micro_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: texasmicro_setup.TexasMicroSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Texas Micro's BIOS with its Setup Utility (a block of its own at E0000), captured by "
        "running the whole ROM in an x86 emulator (POST offers F2 at its configuration error; "
        "a list on the left, each entry opened with Enter)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: memory, "
        "drives and the display are what POST found in the emulator. Images are attached."
    )
    return result


def _prompt_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: prompt_setup.PromptSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    found = prompt_setup.family(rom)
    result["bios"] = (
        f"{found.name if found else 'A BIOS with a simple setup'}, captured by running the "
        "whole ROM in an x86 emulator (POST stops at its error and names the key)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: memory, "
        "drives and the display are what POST found in the emulator. Images are attached."
    )
    return result


def _chips_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: chips_setup.ChipsSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Chips and Technologies' own BIOS for its SCAT chipset (F82C235, 286 boards) with "
        "its System Configuration Utility, captured by running the whole ROM in an x86 "
        "emulator (POST stops at its configuration errors and offers F2; each page "
        "with PgDn)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: memory, "
        "drives and the display are what POST found in the emulator. Images are attached."
    )
    return result


def _ncr_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: ncr_setup.NcrSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "NCR's version of IBM's AT ROM BIOS (NCR 3230, 1992-97) with its built-in "
        "setup, captured by running the whole ROM in an x86 emulator (POST with its "
        "CPU reset and timer test; F1 at 'Press <F1> for SETUP'; F2 for the second "
        "screen)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: "
        "memory, drives and the display are what POST found in the emulator. "
        "Images are attached."
    )
    return result


def _dell_paged_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: dell_setup.DellPagedSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Dell's Phoenix ROM BIOS PLUS 1.10 (about 1997, Dell's own text-mode System Setup "
        "in pages), captured by running the whole image in an x86 emulator with a 440FX "
        "host bridge (Ctrl-Alt-Enter at POST's prompt; Alt-P for the next page)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: CPU, "
        "memory and drives are what POST found in the emulator. Images are attached."
    )
    return result


def _dell_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: dell_setup.DellSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Dell's Phoenix ROM BIOS PLUS 1.10 (about 2003-04, Dell's own text-mode System "
        "Setup), captured by running the whole image in an x86 emulator (POST with "
        "its CPU resets, the SMI it sends to itself left out; F2 during POST starts "
        "setup; the list scrolled with Down, each <ENTER> entry opened)"
    )
    result["note"] = (
        "Values are what the setup showed for an empty CMOS. The PC is emulated: "
        "CPU, memory and drives are what POST found in the emulator (the CPU name "
        "and service tag are not filled in there). Images are attached."
    )
    return result


def _phoenix_text_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: phoenix_setup.PhoenixTextSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "PhoenixBIOS 4.0x (1994-96, text-mode menu-bar setup), captured by running "
        "the whole ROM in an x86 emulator (POST stops at its errors and offers F2; "
        "the setup loads its defaults because the CMOS checksum is invalid; tabs "
        "with the right arrow, sub-menus marked with a triangle with Down and "
        "Enter, two levels)"
    )
    result["note"] = (
        "Values are PhoenixBIOS's defaults. The PC is emulated: memory, drives "
        "and devices are what POST found in the emulator. Images are attached."
    )
    return result


def _easy_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: ami_easy_setup.AmiEasySetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMIBIOS with the Easy Setup (text mode, menu bar), captured by running the "
        "whole ROM in an x86 emulator (chipset from the compressed modules; POST "
        "stops at the CMOS error, F1 starts the setup; Setup Defaults loaded with "
        "F5, then each tab and the pages its entries open, scrolled with Down)"
    )
    result["note"] = (
        "Values are AMIBIOS's Setup Defaults. The PC is emulated: CPU, memory and "
        "drives are what POST found in the emulator. Images are attached."
    )
    return result


def _hiflex_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: ami_hiflex_setup.AmiHiFlex(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMIBIOS with the Simple/Hi-Flex text-mode setup, captured by running the "
        "whole ROM in an x86 emulator (chipset from the compressed modules; with "
        "an empty CMOS POST goes into setup; Load Optimal Settings confirmed, then "
        "the main menu entries opened by following the cursor)"
    )
    result["note"] = (
        "Values are AMIBIOS's Optimal settings. The PC is emulated: CPU, memory and "
        "drives are what POST found in the emulator. Images are attached."
    )
    return result


def _hiflex_direct_screens(path: Path, rom: bytes, pages: str | None, why: Exception) -> dict:
    screens = _cached_screens(rom, lambda: hfjump_setup.Direct(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMIBIOS with the Simple/Hi-Flex text-mode setup, started directly in an x86 "
        "emulator without running POST (the BIOS's modules placed in memory, the setup "
        "entered as POST enters it; Load Optimal Settings confirmed, then the main menu "
        f"entries opened); used because the emulated POST did not reach setup: {why}"
    )
    result["note"] = (
        "Values are AMIBIOS's Optimal settings, but POST was skipped: what POST "
        "measures is missing or wrong (memory sizes 0, no drives, the CPU line), and "
        "chipset values may differ from a real board. Pages whose item list only POST "
        "builds are left out. Images are attached."
    )
    return result


def _award_emu_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: award_emu_setup.AwardEmu(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "early Award Modular BIOS (v3.x-4.50, before the screen scripts), captured "
        "by running the whole ROM in an x86 emulator (POST of an emulated 16 MB AT; "
        "memory test skipped with ESC, setup entered with the key POST offers: "
        "CTRL-ALT-ESC or DEL; v4.20 pages turned with PgDn after F4/F5 loaded each "
        "page's defaults, v4.50 main menu entries opened by following the cursor, "
        "after LOAD SETUP DEFAULTS)"
    )
    result["note"] = (
        "Values are the BIOS's own defaults where it offers them. The PC is "
        "emulated: CPU type and clock, memory and drives are what POST found in the "
        "emulator. Images are attached."
    )
    return result


def _phoenix_old_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: phoenix_old_setup.PhoenixOld(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Phoenix BIOS before 4.0 (PhoenixBIOS 1.x, Phoenix SETUP Utility), captured "
        "by running the whole ROM in an x86 emulator (POST with its CPU resets "
        "back from protected mode; F2 at the error pause starts setup; its pages "
        "turned with PgDn)"
    )
    result["note"] = (
        "Values are the defaults setup loaded for the empty CMOS. The PC is "
        "emulated: CPU, memory and drives are what POST found in the emulator. "
        "Images are attached."
    )
    return result


def _ami7_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: ami7_setup.AmiBios7(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMIBIOS 7 with AMI's new setup utility, captured by running the whole ROM "
        "in an x86 emulator (chipset from the compressed modules, memory sized from "
        "SPD data; POST stops at its error pause and F1 starts setup; the setup "
        "drawn in graphics is read back as text; the main menu's two columns and "
        "the pages their ► entries open (two levels), found by following the "
        "cursor with Down and Enter)"
    )
    if screens and screens[0][0] == "Main":  # the tabbed text-mode setup (ASRock)
        result["bios"] = (
            "AMIBIOS 7 with the tabbed AMIBIOS SETUP UTILITY (text mode), captured "
            "by running the whole ROM in an x86 emulator (POST offers F2 - or, on "
            "AMIBIOS 6, ESC - at its error pause; each tab of the menu bar with "
            "Right, and the pages its ► entries open (two levels; AMIBIOS 6: the "
            "entries saying Press Enter), reached with Down and Enter)"
        )
    result["note"] = (
        "Values are AMIBIOS's own defaults (the CMOS was empty). The PC is "
        "emulated: CPU, memory, drives and the hardware monitor readings are not "
        "the real board's. Images are attached."
    )
    return result


def _intel_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: intel_setup.IntelSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Intel's own desktop-board BIOS (AMI core, Intel's menu-bar setup), "
        "captured by running the whole ROM in an x86 emulator (chipset from the "
        "compressed modules, 64 MB SDRAM from SPD data; POST stops at its error "
        "pause and F1 starts setup, set to English; the setup drawn in graphics "
        "is read back as text with its own font; tabs with the right arrow, the "
        "pages their ► entries open with Down and Enter)"
    )
    result["note"] = (
        "Values are the BIOS's own defaults (the CMOS was empty). The PC is "
        "emulated: CPU type and speed, memory and drives are not the real "
        "board's. Images are attached."
    )
    return result


def _intel_static_screens(path: Path, rom: bytes, pages: str | None, why: Exception) -> dict:
    screens = _cached_screens(rom, lambda: intel_static_setup.IntelStatic(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "Intel's own desktop-board BIOS (AMI core 6.32, Intel's menu-bar setup), "
        "setup pages read from the ROM without running it (page scripts in the "
        "Setup Server module, texts from the English language module); used "
        f"because the emulated POST could not run: {why}"
    )
    result["note"] = (
        "The defaults are not stored in the ROM: each option list's first value "
        "is shown, not necessarily the default. Values that only exist at run "
        "time (BIOS version, processor, memory, time, date) are left open; items "
        "the BIOS shows or hides depending on the hardware are all listed. Images "
        "are attached."
    )
    return result


def _intel_host(rom: bytes) -> bool:
    """Whether the emulator takes the board's host bridge for an Intel one."""
    try:
        hints = b"".join(m.get("data") or b"" for m in ami.extract(rom)[1])
    except Exception:
        hints = b""
    host = bios_emu._pci_devices(rom + hints).get((0, 0), b"")
    return bytes(host[0:2]) == b"\x86\x80"


def _ami8_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    screens = _cached_screens(rom, lambda: ami8_setup.AmiBios8(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMIBIOS 8, captured by running the whole ROM in an x86 emulator (chipset "
        "from the compressed modules, a plain PCI VGA card, memory sized from SPD "
        "data; POST stops at its error list and offers setup; the setup drawn in "
        "graphics is read back as text with AMI's own font; tabs with the right "
        "arrow, sub-menus (two levels) with Down and Enter)"
    )
    result["note"] = (
        "Values are AMIBIOS's own defaults (the CMOS was empty). The PC is "
        "emulated: CPU (the emulator's CPUID), memory, drives and the hardware "
        "monitor readings (temperatures, voltages) are not the real board's. "
        "Images are attached."
    )
    return result


def _uefi_screens(path: Path, rom: bytes, pages: str | None) -> dict:
    style = _style.get()
    if style != "text":
        gen = asus_gui.generation(rom)
        if gen in ("G2", "G3", "G4", "G5"):
            return _gui_screens(
                path,
                asus_gui.pages(rom),
                pages,
                "ASUS",
                "Advanced Mode look - the background, frame and hint drawing are the "
                "firmware's own pictures, taken out of its picture modules",
            )
        if asrock_gui.generation(rom) in ("A1", "A2", "A3"):
            return _gui_screens(
                path,
                asrock_gui.pages(rom),
                pages,
                "ASRock",
                "look - the background, help panel, tab buttons and selection bar are "
                "the firmware's own pictures, one per file of its picture modules",
            )
        if gigabyte_gui.generation(rom) == "B1":
            return _gui_screens(
                path,
                gigabyte_gui.pages(rom),
                pages,
                "Gigabyte",
                "Classic Mode look - the page background and the bottom key-legend bar are "
                "the firmware's own pictures; the tab row, the item list and the help box "
                "are drawn by the setup itself, so their place is this reader's own",
            )
        if msi_gui.generation(rom):
            return _gui_screens(
                path,
                msi_gui.pages(rom),
                pages,
                "MSI",
                "Click BIOS look - the page background or frame, the top status band and "
                "the menu tiles are the firmware's own pictures, read out of its $MsI "
                "container (Click BIOS 4 and 5) or one FFS file each (Click BIOS II); the "
                "item list, its selection bar and the help text are drawn by the setup "
                "itself, so their exact place and font are this reader's own",
            )
        if evga_gui.generation(rom):
            return _gui_screens(
                path,
                evga_gui.pages(rom),
                pages,
                "EVGA",
                "look - the page frame with its header, five buttons and help panel and the "
                "lit button are the firmware's own pictures; the item list, its selection "
                "bar and the help text are drawn by the setup itself, so their exact "
                "place and font are this reader's own",
            )
        if sapphire_gui.generation(rom):
            return _gui_screens(
                path,
                sapphire_gui.pages(rom),
                pages,
                "Sapphire",
                "Q-BIOS look - the page frame with its key legend and the tab buttons are "
                "the firmware's own pictures; the item list and the help text are drawn "
                "by the setup itself, so their exact place and font are this reader's own",
            )
        if style == "graphical":
            raise ValueError(
                "this firmware has neither ASUS Advanced Mode pictures of 2011-2015 nor "
                "ASRock's setup pictures of 2011-2016 nor Gigabyte's Classic Mode pictures "
                "of 2011-2015 nor MSI Click BIOS II, 4 or 5 pictures nor EVGA's or "
                "Sapphire's setup pictures, so its setup "
                "can only be drawn as text pages"
            )
    screens = _cached_screens(rom, lambda: uefi_setup.UefiSetup(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "UEFI firmware (AMI Aptio and others), setup pages read from the image "
        "without running it: the HII forms (IFR) and strings of the setup module, "
        "found in its firmware volumes after unpacking LZMA and Tiano sections; "
        "drawn in the layout of AMI's text-mode setup"
    )
    result["note"] = (
        "Values are the defaults the forms name. Tab names of AMI Aptio 4 are "
        "guessed from their entries (the firmware keeps them in AMI's own setup "
        "data); items the setup shows or hides depending on the hardware are all "
        "listed, values found only at run time (time, devices, versions) are "
        "left open. The real setup is graphical on many boards (ASUS, MSI): these "
        "pages show its entries, not its look. Images are attached."
    )
    return result


def _itk_screens(path: Path, part: bytes, pages: str | None, why: Exception) -> dict:
    screens = _cached_screens(part, lambda: intel_itk.ItkSetup(part).screens())
    result = _mr_screens(path, part, pages, screens)
    result["bios"] = (
        "Intel desktop-board EFI firmware (about 2006-2013), setup pages read from the "
        ".ITK part of the update rather than from the image: the string and form packs "
        "of the setup module, which the update keeps there outside the firmware volumes; "
        "drawn in the layout of AMI's text-mode setup"
    )
    result["note"] = (
        "Values are the defaults the forms name; values found only at run time (time, "
        "devices, versions) are left open. The title bar 'BIOS Setup Utility' is this "
        "reader's label (the part does not name the program), and the menu order is the "
        "order the part stores them in. The image's own forms could not be reached: "
        f"{why}. Images are attached."
    )
    return result


def _gui_screens(
    path: Path, drawn: list[tuple[str, Image.Image, str]], pages: str | None, vendor: str, look: str
) -> dict:
    titles = [t for t, _, _ in drawn]
    chosen = _chosen_pages(pages, len(titles))
    if chosen == ["main"]:
        chosen = [1]
    result: Dict[str, Any] = {
        "bios": f"UEFI firmware (AMI Aptio, {vendor}), setup pages read from the image without "
        "running it: the HII forms (IFR) and strings of the setup module, found in its "
        "firmware volumes after unpacking LZMA and Tiano sections; drawn in the setup's own "
        f"{look}; the rows, tab strip and help text are drawn from the forms",
        "pages": {str(i + 1): t for i, t in enumerate(titles)},
        "note": "The look is rebuilt from the firmware's own pictures and its forms, not "
        "captured from a screen: row positions, fonts and the tab strip are this reader's "
        "layout. Values are the defaults the forms name; values the setup only knows at run "
        "time (versions, CPU speed, memory size) show N/A. Items the setup shows or hides "
        "depending on the hardware are all listed. Images are attached.",
        "screens": {},
    }
    for i, (title, image, text) in enumerate(drawn, start=1):
        if i not in chosen:
            continue
        _save(path, title, image)
        result["screens"][title] = text
    return result


def _ami8_static_screens(path: Path, rom: bytes, pages: str | None, why: Exception) -> dict:
    screens = _cached_screens(rom, lambda: ami8_static_setup.AmiBios8Static(rom).screens())
    result = _mr_screens(path, rom, pages, screens)
    result["bios"] = (
        "AMIBIOS 8, setup pages read from the ROM without running it (page scripts "
        "in the SLAB module, texts from the English language module, values from "
        "the default CMOS image that POST loads); used because the emulated POST "
        f"could not run: {why}"
    )
    result["note"] = (
        "Values are the BIOS's defaults. Items the BIOS shows or hides depending on "
        "the hardware (e.g. DRAM timings when SPD is used, IDE drive details) are "
        "all listed; values that only exist at run time (time, date, detected "
        "drives, options supplied by code) are left open. Images are attached."
    )
    return result


def _mr_screens(path: Path, rom: bytes, pages: str | None, screens: list | None = None) -> dict:
    if screens is None:
        screens = _cached_screens(rom, lambda: mr_setup.MrBios(rom).screens())
    titles = [t for t, _, _ in screens]
    wanted = (pages or "all").strip().lower()
    if wanted in ("all", "main"):
        chosen = list(range(1, len(titles) + 1)) if wanted == "all" else [1]
    else:
        chosen = [int(p) for p in wanted.replace(" ", "").split(",") if p.isdigit()]
    result: Dict[str, Any] = {
        "bios": "MR BIOS, captured by running the whole ROM in an x86 emulator (POST with timer "
        "and RTC interrupts; with an empty CMOS it starts its Setup Utility after a key; "
        "pages selected with the right arrow along the menu bar)",
        "pages": {str(i + 1): t for i, t in enumerate(titles)},
        "note": "Values are MR BIOS's own defaults (loaded because the CMOS was empty). The PC "
        "is emulated: CPU type, speed, memory, drives and ports are what POST found in "
        "the emulator, not the real board. Images are attached.",
        "screens": {},
    }
    for i, (title, screen, _reason) in enumerate(screens, start=1):
        if i not in chosen:
            continue
        _save(path, title, screen)
        result["screens"][title] = screen.text()
    return result


def _winbios_screens(path: Path, rom: bytes, pages: str | None, defaults: str, color: int) -> dict:
    bios = winbios_setup.WinBios(rom)
    defaults = defaults or "setup"
    color = int(color or 0) % len(winbios_setup.COLOR_SETS)
    screens = bios.screens(defaults, color)
    titles = [t for t, _, _ in screens[1:]]
    chosen = _chosen_pages(pages, len(titles))
    if defaults == "setup":
        values = "the Optimal defaults"
    elif bios.has_failsafe:
        values = "the Fail-safe defaults"
    else:
        values = "those after POST with cleared CMOS (this setup has no Fail-safe set)"
    if bios.kind == "94":
        how = "POST, then setup entered through its module loader"
        colors = f"color set {winbios_setup.COLOR_SETS[color]}"
    else:
        how = "POST with DEL pressed while it counts memory, as a person enters setup"
        colors = "colors as set by the Setup Color Scheme item (Advanced Setup)"
    result: Dict[str, Any] = {
        "bios": f"AMI WinBIOS ({bios.kind} generation), captured by running the whole ROM in an "
        f"x86 emulator ({how}; setup operated with Tab/arrows/Enter/PgDn like a user; "
        "numbered titles are the further screens of a long list)",
        "pages": {str(i + 1): t for i, t in enumerate(titles)},
        "note": f"Values are {values}; {colors}. The PC is emulated (one floppy, no hard disk, "
        "01/01/1994; CPU and memory as POST detects them in the emulator). Standard "
        "Setup opens dialogs per icon (date/time, floppies, disks), which are not "
        "captured. Images are attached.",
        "screens": {},
    }
    warnings = []
    for i, (title, screen, reason) in enumerate(screens):
        if (i == 0 and "main" not in chosen) or (i > 0 and i not in chosen):
            continue
        if reason not in ("waiting for a key", "polling the keyboard"):
            warnings.append(
                f"{title}: emulation stopped early ({reason}); the screen may be " "incomplete"
            )
        _save(path, title, screen)
        result["screens"][title] = winbios_setup.plain_text(screen)
    if warnings:
        result["warnings"] = warnings
    return result


def _award_screens(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    path: Path, data: bytes, source: str, pages: str | None, defaults: str, image: bytes
) -> dict:
    tables = award_setup.pages(data)
    if not tables:
        try:
            award_setup.main_menu(data)
        except ValueError:
            raise ValueError(  # pylint: disable=raise-missing-from
                "this Award BIOS has the setup screen interpreter, but no menu tables in a "
                "supported layout in this file. Award 6.00PG keeps its setup menus in a "
                "compressed module that is only unpacked when setup is entered, so memory dumps "
                "(e.g. F000.ROM) do not contain them; a full flash image (with the awardext "
                "module) is needed. Use strings for the menu texts."
            )
    titles = [award_setup.page_title(data, t) for t in tables]
    chosen = _chosen_pages(pages, len(tables))
    result: Dict[str, Any] = {
        "bios": f"Award 4.5x setup code in {source}",
        "pages": {str(i + 1): t for i, t in enumerate(titles)},
        "note": "Values are the ROM's defaults; the STANDARD CMOS SETUP page (date, time, drives) "
        "is not rebuilt. Images are attached to your reply.",
        "screens": {},
    }
    warnings = []
    labels = None
    for p in chosen:
        if p == "main":
            try:
                screen, info = award_setup.main_menu(data)
            except ValueError as e:
                warnings.append(f"main menu: {e}")
                continue
            title = "MAIN MENU"
        elif 1 <= p <= len(tables):
            if labels is None:
                labels = award_setup.extension_labels(image)
            screen, info = award_setup.setup_page(data, tables[p - 1], defaults, labels)
            title = titles[p - 1]
        else:
            continue
        if not any(0xB3 <= c <= 0xDA for line in screen.chars for c in line):
            warnings.append(
                f"{title}: no frame drawn; the frame script is probably outside this "
                "file (e.g. a dump of only the F000 segment)"
            )
        if info.get("unknown_commands"):
            warnings.append(
                f"{title}: stopped at unknown screen commands {info['unknown_commands']}"
            )
        _save(path, title, screen)
        result["screens"][title] = screen.text()
    if warnings:
        result["warnings"] = warnings
    return result


def _render_text_screen(
    channel_id: int,
    lines: list,
    fg: str = "lightgray",
    bg: str = "black",
    colors: list | None = None,
    file_name: str = "screen.png",
) -> str:
    base_attr = color_attr(fg or "lightgray", bg or "black")
    screen = Screen(attr=base_attr)
    for row, line in enumerate((lines or [])[:25]):
        screen.write(0, row, unicode_to_cp437(str(line))[:80], base_attr)
    for c in colors or []:
        row, col = int(c.get("row", 0)), int(c.get("col", 0))
        length = int(c.get("length", 80 - col))
        attr = color_attr(c.get("fg", fg or "lightgray"), c.get("bg", bg or "black"))
        for x in range(col, min(80, col + length)):
            screen.put(x, row, screen.chars[row][x] if 0 <= row < 25 else 0x20, attr)
    folder = workspace.channel_dir(channel_id)
    folder.mkdir(parents=True, exist_ok=True)
    name = workspace._safe_name(file_name or "screen.png")
    out = folder / (name if name.lower().endswith(".png") else name + ".png")
    screen.render(out)
    workspace.attach(out)
    return f"Rendered {out.name}; it is attached to your reply."


async def run(channel_id: int, name: str, args: Dict[str, Any]) -> Any:
    a = dict(args)
    if name == "bios_setup_screens":
        return await asyncio.to_thread(_bios_setup_screens, channel_id, a.pop("name"), **a)
    if name == "render_text_screen":
        return await asyncio.to_thread(_render_text_screen, channel_id, **a)
    raise ValueError(f"unknown tool: {name}")
