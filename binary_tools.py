"""
Tools for binary files in the channel's working folder: ROMs, BIOS images, firmware.

hexdump, strings, search_bytes, file_hashes, rom_info (overview of a ROM image), disassemble
(capstone) and unpack_rom (LHA modules, e.g. Award BIOS). Every result is size-bounded so it
fits the model's context.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import math
import re
import struct
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict

import capstone as cs

import ami
import bios_summary
import lzh
import phoenix
import vbe
import workspace

MAX_DUMP = 2048
MAX_DISASM_BYTES = 4096
MAX_DISASM_LINES = 250
MAX_STRINGS = 150
MAX_HITS = 100

INT = {"type": ["integer", "string"]}  # models sometimes pass "0xF000" as a string


def _int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return value if isinstance(value, int) else int(str(value).strip(), 0)


ARCHES = {
    "x86-16": (cs.CS_ARCH_X86, cs.CS_MODE_16),
    "x86-32": (cs.CS_ARCH_X86, cs.CS_MODE_32),
    "x86-64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
    "6502": (cs.CS_ARCH_MOS65XX, cs.CS_MODE_MOS65XX_6502),
    "65c02": (cs.CS_ARCH_MOS65XX, cs.CS_MODE_MOS65XX_65C02),
    "65816": (cs.CS_ARCH_MOS65XX, cs.CS_MODE_MOS65XX_65816),
    "68000": (cs.CS_ARCH_M68K, getattr(cs, "CS_MODE_M68K_000", cs.CS_MODE_BIG_ENDIAN)),
    "6809": (cs.CS_ARCH_M680X, cs.CS_MODE_M680X_6809),
    "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
    "thumb": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
    "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
    "mips32": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN),
    "mips32el": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN),
    "ppc32": (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN),
}

NAME = {"type": "string", "description": "File name from list_files."}
TOOLS = [
    {
        "name": "bios_summary",
        "description": "One-call overview of a system BIOS image (start here for BIOS "
        "questions): vendor and version strings, BIOS ID string, date, chipset, Super I/O, CPU "
        "and board-vendor hints, setup page titles, features (ACPI, PnP, USB, hardware monitor, "
        "...), compressed modules (searched decompressed) and which other tools apply.",
        "input_schema": {"type": "object", "properties": {"name": NAME}, "required": ["name"]},
    },
    {
        "name": "rom_info",
        "description": "Overview of a binary/ROM file: size, 8-bit checksum, fill and entropy map "
        "(code vs empty vs compressed areas), known signatures with offsets (option ROMs with PCI "
        "vendor/device, PnP, LHA modules, UEFI volumes, Intel flash descriptor, SMBIOS/ACPI/$PIR, "
        "vendor strings), the x86 reset vector and BIOS date, and 6502 vectors. Start here.",
        "input_schema": {"type": "object", "properties": {"name": NAME}, "required": ["name"]},
    },
    {
        "name": "hexdump",
        "description": f"Hex and ASCII view of a byte range (up to {MAX_DUMP} bytes). A negative "
        "offset counts from the end of the file, e.g. -16 for the x86 reset vector. To look at "
        "several places at once, give ranges=[{offset, length}, ...] instead.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": NAME,
                "offset": {**INT, "description": "Start offset; negative = from the end."},
                "length": {**INT, "description": "Number of bytes (default 256)."},
                "ranges": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Several ranges in one call: [{offset, length}, ...].",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "strings",
        "description": "Readable text in a binary file with offsets: ASCII, or UTF-16LE with "
        f"utf16=true. Returns up to {MAX_STRINGS} strings; filter with find (case-insensitive; "
        "give a list to search several terms in one call) or limit to a range with offset/length.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": NAME,
                "min_length": {**INT, "description": "Minimum string length (default 5)."},
                "find": {
                    "type": ["string", "array"],
                    "items": {"type": "string"},
                    "description": "Only strings containing this text; a list searches each term.",
                },
                "utf16": {"type": "boolean", "description": "Look for UTF-16LE strings."},
                "offset": {**INT, "description": "Start of the range to scan (default 0)."},
                "length": {**INT, "description": "Length of the range (default: to the end)."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "search_bytes",
        "description": f"Find byte patterns and list their offsets (up to {MAX_HITS} each). Give "
        'hex (e.g. "55 AA" or "EA ?? ?? 00 F0" with ?? as wildcard) and/or text; each can be '
        "a list to search several patterns in one call.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": NAME,
                "hex": {
                    "type": ["string", "array"],
                    "items": {"type": "string"},
                    "description": "Hex bytes; ?? matches any byte. A list for several.",
                },
                "text": {
                    "type": ["string", "array"],
                    "items": {"type": "string"},
                    "description": "ASCII text to find. A list for several.",
                },
                "ignore_case": {"type": "boolean", "description": "For text (default false)."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "file_hashes",
        "description": "MD5, SHA-1, SHA-256 and CRC32 of a file, e.g. to look a ROM dump up in "
        "ROM databases with web_search.",
        "input_schema": {"type": "object", "properties": {"name": NAME}, "required": ["name"]},
    },
    {
        "name": "disassemble",
        "description": "Disassemble a byte range with capstone. arch: "
        + ", ".join(ARCHES)
        + ". address is the load address of the first byte (default: the file offset); for an "
        "x86 BIOS the last 64 KB usually map to F000:0000, so offset size-0x10000 is address "
        f"0xF0000. Up to {MAX_DISASM_BYTES} bytes / {MAX_DISASM_LINES} instructions per call; "
        "bytes that are not valid code are shown as .byte.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": NAME,
                "offset": {**INT, "description": "File offset; negative = from the end."},
                "length": {**INT, "description": "Bytes to disassemble (default 256)."},
                "arch": {"type": "string", "enum": list(ARCHES), "description": "CPU."},
                "address": {**INT, "description": "Address of the first byte."},
            },
            "required": ["name", "arch"],
        },
    },
    {
        "name": "vbe_modes",
        "description": "VESA (VBE) video modes of a video BIOS: VBE version and OEM string if a "
        "VbeInfoBlock template is in the ROM, the mode list with standard modes (100h-11Bh) "
        "translated to resolution/colors, guesses for OEM modes, other candidate lists and "
        "resolution strings found in the ROM. Static analysis: says how certain the list is.",
        "input_schema": {"type": "object", "properties": {"name": NAME}, "required": ["name"]},
    },
    {
        "name": "unpack_rom",
        "description": "Extract and decompress the modules of a BIOS image: Award BIOS (embedded "
        "LHA -lh5- modules, verified by CRC) or AMIBIOS 95/98/8 (module list behind the "
        "AMIBIOSC header, plus the boot block) or PhoenixBIOS 4.0/6.0 (BCPSYS module list). Each "
        "module is saved to the working folder as a new file that the other tools can open. "
        "AMI '94, Phoenix TrustedCore/SecureCore (FFV) and UEFI/Aptio images are not supported.",
        "input_schema": {"type": "object", "properties": {"name": NAME}, "required": ["name"]},
    },
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def _load(channel_id: int, name: str) -> tuple[str, bytes]:
    path = workspace._resolve(channel_id, name)
    return path.name, path.read_bytes()


def _range(data: bytes, offset: int, length: int, limit: int) -> tuple[int, int]:
    if offset < 0:
        offset += len(data)
    if not 0 <= offset < len(data):
        raise ValueError(f"offset outside the file (size {len(data)} = 0x{len(data):X})")
    return offset, min(len(data), offset + min(length, limit))


def _as_list(value: Any) -> list:
    """Batched arguments: a single value or a list of values."""
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _hexdump(
    channel_id: int,
    name: str,
    offset: int = 0,
    length: int = 256,
    ranges: Any = None,
) -> str:
    fname, data = _load(channel_id, name)
    wanted = [
        (r.get("offset", 0), r.get("length", 256)) for r in _as_list(ranges) if isinstance(r, dict)
    ] or [(offset, length)]
    lines, budget = [], MAX_DUMP * 2  # all ranges of one call together
    for off, ln in wanted:
        if budget <= 0:
            lines.append("[further ranges skipped: byte limit of one call reached]")
            break
        start, end = _range(data, _int(off), _int(ln, 256), min(MAX_DUMP, budget))
        budget -= end - start
        lines.append(f"{fname}, 0x{start:X}-0x{end - 1:X} of 0x{len(data):X} bytes")
        for i in range(start, end, 16):
            row = data[i : min(i + 16, end)]
            hexpart = " ".join(f"{b:02X}" for b in row).ljust(47)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"{i:08X}  {hexpart}  {text}")
    return "\n".join(lines)


def _strings(
    channel_id: int,
    name: str,
    min_length: int = 5,
    find: str = "",
    utf16: bool = False,
    offset: int = 0,
    length: int | None = None,
) -> str:
    fname, data = _load(channel_id, name)
    start, end = _range(data, _int(offset), _int(length, len(data)), len(data))
    n = max(2, _int(min_length, 5))
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % n if utf16 else rb"[\x20-\x7e]{%d,}" % n
    all_strings = [
        (start + m.start(), m.group().decode("utf-16-le" if utf16 else "latin-1"))
        for m in re.finditer(pattern, data[start:end])
    ]
    terms = [str(t) for t in _as_list(find)]
    if not terms:
        shown = [f"0x{o:08X}: {t[:200]}" for o, t in all_strings[:MAX_STRINGS]]
        head = f"{fname}: {len(all_strings)} strings"
        if len(all_strings) > len(shown):
            head += f", showing the first {len(shown)} (narrow with find, offset/length)"
        return "\n".join([head] + shown)
    per_term = max(10, MAX_STRINGS // len(terms))
    out = []
    for term in terms:
        hits = [(o, t) for o, t in all_strings if term.lower() in t.lower()]
        head = f"{fname}: {len(hits)} strings containing {term!r}"
        if len(hits) > per_term:
            head += f", showing the first {per_term}"
        out.append(head)
        out += [f"  0x{o:08X}: {t[:200]}" for o, t in hits[:per_term]]
    return "\n".join(out)


def _hex_pattern(hex_text: str) -> bytes:
    parts = hex_text.replace(",", " ").split()
    if len(parts) == 1 and len(parts[0]) > 2:  # "55AA" without spaces
        parts = [parts[0][i : i + 2] for i in range(0, len(parts[0]), 2)]
    return b"".join(b"." if p == "??" else re.escape(bytes([int(p, 16)])) for p in parts)


def _search(  # (hex: the tool's argument name in its schema)
    channel_id: int,
    name: str,
    hex: Any = "",  # pylint: disable=redefined-builtin
    text: Any = "",
    ignore_case: bool = False,
) -> str:
    fname, data = _load(channel_id, name)
    searches: list[tuple[str, bytes, int]] = [
        (f"hex {h}", _hex_pattern(str(h)), re.DOTALL) for h in _as_list(hex)
    ]
    searches += [
        (f"text {t!r}", re.escape(str(t).encode("latin-1")), re.IGNORECASE if ignore_case else 0)
        for t in _as_list(text)
    ]
    if not searches:
        raise ValueError("give hex or text (a single value or a list)")
    out = []
    for label, pattern, flags in searches:
        hits = [m.start() for m in re.finditer(b"(?=" + pattern + b")", data, flags)]
        shown = ", ".join(f"0x{h:X}" for h in hits[:MAX_HITS])
        more = f" (first {MAX_HITS} shown)" if len(hits) > MAX_HITS else ""
        out.append(f"{fname} {label}: {len(hits)} matches{more}" + (f": {shown}" if hits else ""))
    return "\n".join(out)


def _bios_summary(channel_id: int, name: str) -> dict:
    fname, data = _load(channel_id, name)
    return {"name": fname, **bios_summary.summarize(data)}


def _hashes(channel_id: int, name: str) -> dict:
    fname, data = _load(channel_id, name)
    return {
        "name": fname,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "crc32": f"{zlib.crc32(data):08x}",
    }


def _entropy(block: bytes) -> float:
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _option_rom(data: bytes, off: int) -> dict | None:
    size = data[off + 2] * 512
    if not size or off + size > len(data) or off + 0x1C > len(data):
        return None
    rom = {
        "offset": f"0x{off:X}",
        "size": size,
        "checksum_ok": sum(data[off : off + size]) & 0xFF == 0,
    }
    pcir = struct.unpack_from("<H", data, off + 0x18)[0]
    if pcir and off + pcir + 0x10 <= len(data) and data[off + pcir : off + pcir + 4] == b"PCIR":
        vendor, device = struct.unpack_from("<HH", data, off + pcir + 4)
        cls = data[off + pcir + 0x0D : off + pcir + 0x10]
        rom["pci"] = (
            f"vendor {vendor:04X} device {device:04X} class base/sub/prog-if "
            f"{cls[2]:02X}/{cls[1]:02X}/{cls[0]:02X} (some vendors store these reversed)"
        )
    pnp = struct.unpack_from("<H", data, off + 0x1A)[0]
    if pnp and data[off + pnp : off + pnp + 4] == b"$PnP":
        rom["pnp_header"] = f"0x{off + pnp:X}"
    return rom


SIGNATURES = {
    b"_FVH": "UEFI firmware volume (header starts 0x28 before)",
    b"\x5a\xa5\xf0\x0f": "Intel flash descriptor",
    b"$IBIOSI$": "Intel BIOS ID",
    b"AMIBIOSC": "AMIBIOS 8 core",
    b"AMIBOOT ROM": "AMI boot block",
    b"AMIBIOS": "AMIBIOS string",
    b"Award": "Award string",
    b"Phoenix": "Phoenix string",
    b"BCPSYS": "Phoenix BCP system block",
    b"$PIR": "PCI IRQ routing table",
    b"_SM_": "SMBIOS entry point",
    b"_SM3_": "SMBIOS 3 entry point",
    b"_DMI_": "DMI entry point",
    b"RSD PTR ": "ACPI RSDP",
    b"_MP_": "MP floating pointer",
    b"$PnP": "PnP header",
}


def _rom_info(channel_id: int, name: str) -> dict:
    fname, data = _load(channel_id, name)
    size = len(data)
    info: Dict[str, Any] = {
        "name": fname,
        "size": f"{size} bytes (0x{size:X}, {size / 1024:g} KB)",
        "checksum8": f"0x{sum(data) & 0xFF:02X} (0x00 is expected for an option ROM or a "
        "complete BIOS image; a segment dump such as F000.ROM from a larger BIOS usually does "
        "not sum to 0)",
        "fill": (
            f"{data.count(0xFF) * 100 / size:.1f}% 0xFF, {data.count(0) * 100 / size:.1f}% 0x00"
        ),
    }

    # Entropy map, merged into runs of the same class
    block = max(4096, size // 64)
    runs: list = []
    for i in range(0, size, block):
        chunk = data[i : i + block]
        if chunk.count(0xFF) == len(chunk):
            cls = "empty (FF)"
        elif chunk.count(0) == len(chunk):
            cls = "empty (00)"
        else:
            e = _entropy(chunk)
            cls = (
                "high entropy, compressed/encrypted"
                if e > 7.2
                else "code/data" if e > 4.0 else "sparse/text/tables"
            )
        if runs and runs[-1][2] == cls:
            runs[-1][1] = i + len(chunk)
        else:
            runs.append([i, i + len(chunk), cls])
    info["layout"] = [f"0x{a:X}-0x{b - 1:X}: {c}" for a, b, c in runs[:40]]

    roms = [
        r
        for off in range(0, size - 3, 512)
        if data[off : off + 2] == b"\x55\xaa"
        for r in [_option_rom(data, off)]
        if r
    ]
    if roms:
        info["option_roms"] = roms[:20]

    found = {}
    for sig, label in SIGNATURES.items():
        hits = [m.start() for m in re.finditer(re.escape(sig), data)][:5]
        if hits:
            found[label] = ", ".join(f"0x{h:X}" for h in hits)
    mods = lzh.find_modules(data)
    if mods:
        found["LHA modules (unpack_rom)"] = ", ".join(
            f"{m['name'] or '?'} @0x{m['offset']:X}" for m in mods[:20]
        )
    info["signatures"] = found

    tail = data[-16:]
    if size >= 16:
        x86: Dict[str, Any] = {"last_16_bytes": tail.hex(" ")}
        if tail[0] == 0xEA:
            off, seg = struct.unpack_from("<HH", tail, 1)
            x86["reset_vector"] = f"jmp far {seg:04X}:{off:04X}"
            if seg == 0xF000 and size >= 0x10000:
                x86["reset_target_file_offset"] = f"0x{size - 0x10000 + off:X}"
        elif tail[0] == 0xE9:
            rel = struct.unpack_from("<h", tail, 1)[0]
            x86["reset_vector"] = f"jmp near F000:{(0xFFF3 + rel) & 0xFFFF:04X}"
        date = tail[5:13].decode("latin-1")
        if re.fullmatch(r"\d\d/\d\d/\d\d", date):
            x86["bios_date"] = date
            x86["model_byte"] = f"0x{tail[14]:02X}"
        info["x86_end"] = x86
    # 6502 ROMs (e.g. C64 KERNAL) end with the CPU vectors; only meaningful for non-PC ROMs
    is_pc = "reset_vector" in info.get("x86_end", {}) or data[:2] == b"\x55\xaa"
    if not is_pc and 6 <= size <= 0x10000:
        nmi, reset, irq = struct.unpack_from("<HHH", data, size - 6)
        info["6502_vectors_if_mapped_at_end"] = (
            f"NMI {nmi:04X}, RESET {reset:04X}, IRQ/BRK {irq:04X}"
        )
    return info


def _disassemble(
    channel_id: int,
    name: str,
    arch: str,
    offset: int = 0,
    length: int = 256,
    address: int | None = None,
) -> str:
    if arch not in ARCHES:
        raise ValueError(f"arch must be one of {', '.join(ARCHES)}")
    fname, data = _load(channel_id, name)
    start, end = _range(data, _int(offset), _int(length, 256), MAX_DISASM_BYTES)
    md = cs.Cs(*ARCHES[arch])
    md.skipdata = True
    addr = _int(address, start)
    lines = [f"{fname}, {arch}, file 0x{start:X}-0x{end - 1:X} at address 0x{addr:X}"]
    for ins in md.disasm(data[start:end], addr):
        if len(lines) > MAX_DISASM_LINES:
            lines.append(
                f"[stopped after {MAX_DISASM_LINES} instructions; continue at address "
                f"0x{ins.address:X}, file offset 0x{start + ins.address - addr:X}]"
            )
            break
        lines.append(
            f"{ins.address:08X}  {ins.bytes.hex(' '):<20}  {ins.mnemonic} {ins.op_str}".rstrip()
        )
    return "\n".join(lines)


def _unpack(channel_id: int, name: str) -> str:
    path = workspace._resolve(channel_id, name)
    data = path.read_bytes()
    mods = lzh.find_modules(data)
    if not mods:
        if ami.find_core(data) >= 0:
            return _unpack_ami(path, data)
        if phoenix.find_segment(data) >= 0:
            return _unpack_phoenix(path, data)
        return (
            f"{path.name}: no Award LHA modules, AMIBIOS 95/8 module list or Phoenix "
            "BCPSYS module list found. Either nothing in it is compressed (older BIOSes, "
            "segment dumps, option ROMs: use the other tools directly), or it uses a "
            "format unpack_rom does not support (AMI '94, Phoenix FFV, UEFI/Aptio)."
        )
    lines = [f"{path.name}: {len(mods)} LHA modules"]
    for i, m in enumerate(mods):
        packed = data[m["data_start"] : m["data_start"] + m["packed"]]
        desc = (
            f"#{i} @0x{m['offset']:X} {m['method']} {m['name'] or '?'}: {m['packed']} -> "
            f"{m['size']} bytes, loader/date field 0x{m['loader']:08X}"
        )
        try:
            out = lzh.decompress(packed, m["size"], m["method"].encode())
        except Exception as e:  # damaged module or unsupported variant
            lines.append(f"{desc}, FAILED: {e}")
            continue
        crc = "CRC ok" if m["crc"] is None or lzh.crc16(out) == m["crc"] else "CRC MISMATCH"
        out_name = workspace._safe_name(f"{path.stem}.{i:02d}.{m['name'] or 'module.bin'}")
        (path.parent / out_name).write_bytes(out)
        lines.append(f"{desc}, {crc}, saved as {out_name}")
    return "\n".join(lines)


def _vbe_modes(channel_id: int, name: str) -> dict:
    fname, data = _load(channel_id, name)
    return {"name": fname, **vbe.analyze(data)}


def _unpack_ami(path: Path, data: bytes) -> str:
    info, mods = ami.extract(data)
    lines = [
        f"{path.name}: AMIBIOS core {info['version']!r}, date {info['date']}, "
        f"{len(mods)} modules (AMI modules carry no checksum; a module that decompressed "
        "without error is very likely correct)"
    ]
    boot = info.get("boot_block")
    if boot:
        out_name = workspace._safe_name(f"{path.stem}.ami.bootblock.rom")
        (path.parent / out_name).write_bytes(data[boot["offset"] :])
        lines.append(f"boot block @0x{boot['offset']:X}: {boot['size']} bytes, saved as {out_name}")
    for i, m in enumerate(mods):
        if "id" not in m:
            lines.append(f"#{i}: {m['error']}")
            continue
        desc = f"#{i} @0x{m['offset']:X} id 0x{m['id']:02X} {m['name']}: " + (
            f"{m['packed']} -> {m['size']} bytes"
            if m["compressed"]
            else f"{m['size']} bytes stored"
        )
        if "error" in m:
            lines.append(f"{desc}, FAILED: {m['error']}")
            continue
        out_name = workspace._safe_name(f"{path.stem}.ami.{i:02d}.{m['file_name']}")
        (path.parent / out_name).write_bytes(m["data"])
        lines.append(f"{desc}, saved as {out_name}")
    return "\n".join(lines)


def _unpack_phoenix(path: Path, data: bytes) -> str:
    try:
        info, mods = phoenix.extract(data)
    except ValueError as e:
        return f"{path.name}: Phoenix BIOS, but {e}"
    head = (
        f"{path.name}: Phoenix BIOS version {info['version']!r}, "
        f"built {info['date']} {info['time']}"
    )
    if not any("name" in m for m in mods):
        return (
            f"{head}, but its module list does not lead to modules inside this file "
            f"({mods[0]['error'] if mods else 'empty list'}). This is probably a memory dump "
            "of the running BIOS (e.g. an F000 segment) rather than a full flash image; "
            "analyze it directly with the other tools."
        )
    lines = [
        f"{head}, {len(mods)} modules (no checksums; a module that decompressed to its "
        "expected size is very likely correct)"
    ]
    for i, m in enumerate(mods):
        if "name" not in m:
            lines.append(f"#{i}: {m['error']}")
            continue
        desc = (
            f"#{i} @0x{m['offset']:X} type {m['type']} {m['name']} id {m['id']}: "
            f"{m.get('packed', '?')} -> {m['size']} bytes {m['compression']}"
            + (f", {m['fragments']} fragments" if m.get("fragments", 1) > 1 else "")
            + (f", load {m['load']}" if m["load"] else "")
        )
        if "data" in m:
            out_name = workspace._safe_name(f"{path.stem}.phx.{i:02d}.{m['file_name']}")
            (path.parent / out_name).write_bytes(m["data"])
            lines.append(f"{desc}, saved as {out_name}")
        else:
            line = f"{desc}, FAILED: {m['error']}"
            if "raw" in m:  # keep the packed bytes so they can still be inspected
                out_name = workspace._safe_name(f"{path.stem}.phx.{i:02d}.{m['file_name']}.packed")
                (path.parent / out_name).write_bytes(m["raw"])
                line += f"; packed data saved as {out_name}"
            lines.append(line)
    return "\n".join(lines)


async def run(channel_id: int, name: str, args: Dict[str, Any]) -> Any:
    a = dict(args)
    file = a.pop("name")
    funcs: dict[str, Callable[..., Any]] = {
        "rom_info": _rom_info,
        "hexdump": _hexdump,
        "strings": _strings,
        "search_bytes": _search,
        "file_hashes": _hashes,
        "disassemble": _disassemble,
        "unpack_rom": _unpack,
        "vbe_modes": _vbe_modes,
        "bios_summary": _bios_summary,
    }
    if name not in funcs:
        raise ValueError(f"unknown tool: {name}")
    accepted = inspect.signature(funcs[name]).parameters
    a = {k: v for k, v in a.items() if k in accepted}  # ignore stray arguments from the model
    return await asyncio.to_thread(funcs[name], channel_id, file, **a)
