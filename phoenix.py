"""
Phoenix BIOS module lists: PhoenixBIOS 4.0/6.0, FirstBIOS and ServerBIOS images (BCP blocks),
and the file volumes of TrustedCore/SecureCore (ffv_modules).

"BCPSEGMENT" starts a run of BCP blocks; the BCPSYS block holds the address of the last module's
header, and every 27-byte module header (signature 00 31 31) the address of the one before it.
Bodies are stored, LH5 behind a 4-byte length (type 5), the HN440's adaptive Huffman LZ77
(type 4, phx4.py), the image's own decompressor run in the emulator (type 2, phx2.py) or LZSS
(type 3); a body may be split into fragments elsewhere in the image.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import lzh
import phx2
import phx4

MODULE_NAMES = {  # (by the type letter of the module header or of a volume file's name)
    "A": "acpi",
    "B": "bioscode",
    "C": "update",
    "D": "display",
    "E": "setup",
    "F": "font",
    "G": "decompressor",
    "I": "bootblock",
    "L": "logo",
    "M": "miser",
    "N": "rompilot",
    "O": "network",
    "P": "rompilot",
    "R": "optionrom",
    "S": "strings",
    "T": "template",
    "U": "user",
    "X": "romexec",
    "W": "sound",
    "H": "tcpa",
    "K": "tcpa",
    "Q": "tcpa",
    "<": "tcpa",
    "*": "tcpa",
    "?": "tcpa",
    "$": "biosentry",
    "J": "smartcard",
}
COMPRESSION = {0: "stored", 2: "type 2", 3: "LZSS", 4: "adaptive Huffman LZ77", 5: "LH5"}
# previous, signature, id, type, header length, compression, load offset, load segment,
# unpacked length, first fragment length, next fragment
MODULE_HEADER = struct.Struct("<I3sBBBBHHIII")
FRAGMENT = struct.Struct("<IBI")  # next, bank, length
SIGNATURE = b"\x00\x31\x31"
MAX_MODULES = 256
SHIFTED = 0x20000  # (a previous-module address 128 KB off: Intel, Fujitsu-Siemens D1761)


def find_segment(data: bytes) -> int:
    return data.find(b"BCPSEGMENT")


def lzss_decode(data: bytes) -> bytes:
    """LZSS as Okumura's: a 4 KB ring buffer filled from FEEh, a flag byte per eight items
    (lowest bit first; 1 = a literal byte, 0 = two bytes of 12-bit position and 4-bit
    length - 3)."""
    ring = bytearray(0x1000)
    r, out, i, flags = 0xFEE, bytearray(), 0, 0
    while i < len(data):
        flags >>= 1
        if not flags & 0x100:  # (the next flag byte, with eight markers above it)
            flags = data[i] | 0xFF00
            i += 1
            if i == len(data):
                break
        if flags & 1:
            ring[r] = data[i]
            out.append(data[i])
            r, i = (r + 1) & 0xFFF, i + 1
            continue
        if i + 1 >= len(data):
            raise ValueError("LZSS data ended inside a match")
        pos, count = data[i] | (data[i + 1] & 0xF0) << 4, (data[i + 1] & 0x0F) + 3
        i += 2
        for k in range(count):
            ring[r] = c = ring[(pos + k) & 0xFFF]
            out.append(c)
            r = (r + 1) & 0xFFF
    return bytes(out)


def _offset(address: int, size: int) -> int:
    """A module address as a file offset (the image is mapped at the top of memory)."""
    return address & (size - 1) if not size & (size - 1) else address % size


# --- TrustedCore / SecureCore volumes ------------------------------------------------------


def _sections(data: bytes, start: int, end: int, mod: dict) -> None:
    """Find the body of a volume file in its sections (24-bit length, type; 4-byte aligned):
    type 1 is LH5 (packed and unpacked length first) whose output is sections again; types
    10h, 12h, 18h and 19h are the data."""
    at = start
    while at + 4 <= end:
        length, kind = int.from_bytes(data[at : at + 3], "little"), data[at + 3]
        if length < 4 or at + length > end:
            return
        if "data" in mod:
            pass
        elif kind == 0x01 and length >= 12:
            packed, unpacked = struct.unpack_from("<II", data, at + 4)
            mod.update(compression="LH5", size=unpacked, packed=packed)
            try:
                out = lzh.decompress(bytes(data[at + 12 : at + 12 + packed]), unpacked, b"-lh5-")
                inner: dict = {}
                _sections(out, 0, len(out), inner)
                mod["data"] = inner.get("data", out)
            except Exception as e:  # pylint: disable=broad-exception-caught
                mod["error"] = f"decompression failed: {e}"
        elif kind in (0x10, 0x12, 0x18, 0x19):
            mod["data"] = bytes(data[at + 4 : at + length])
        at = start + ((at - start + length + 3) & ~3)


def _volume_files(data: bytes, at: int, end: int, modules: list[dict]) -> None:
    """The modules of one volume: files with state F8h, a 24-bit length and a name such as
    "_E00" (type letter and number); FFh and 00h bytes between files are skipped."""
    while at + 0x18 <= end and len(modules) < MAX_MODULES:
        if data[at] in (0x00, 0xFF):
            at += 1
            continue
        length = int.from_bytes(data[at + 4 : at + 7], "little")
        if data[at] != 0xF8 or length < 0x18 or at + length > end + 1:
            return
        name = data[at + 8 : at + 12]
        if name[:1] == b"_" and name[2:4].isdigit():
            letter, number = chr(name[1]), int(name[2:4])
            kind = MODULE_NAMES.get(letter, letter)
            mod: dict = {
                "offset": at,
                "type": letter,
                "name": kind,
                "id": number,
                "file_name": f"{kind}_{number}.bin",
                "compression": "stored",
                "size": 0,
                "load": None,
            }
            _sections(data, at + 0x18, at + length, mod)
            if "data" in mod:
                mod["size"] = len(mod["data"])
            elif "error" not in mod:
                mod["error"] = "no data section found in its FFV file"
            modules.append(mod)
        at += length - 1


def ffv_modules(data: bytes) -> list[dict]:
    """The modules of a TrustedCore/SecureCore image, by the volume directory: a file named
    "volumedir.bin2" whose body is u16, u16, u32 length and 24-byte entries (GUID, base,
    length); the file volumes are those whose GUID starts with BAh."""
    size = len(data)
    name = data.find(b"volumedi\xffr.bin2")
    if name < 8 or name + 0x18 > size:
        return []
    directory = name + 0x10
    entries = (struct.unpack_from("<I", data, directory + 4)[0] - 8) // 24
    modules: list[dict] = []
    for e in range(directory + 8, directory + 8 + 24 * min(max(entries, 0), 64), 24):
        if e + 24 > size:
            break
        base, length = struct.unpack_from("<II", data, e + 16)
        at = (base + (size & 0xFFFF0000)) & 0xFFFFFFFF
        if data[e] == 0xBA and at < size:
            _volume_files(data, at, min(size, at + length), modules)
    return modules


# --- BCP module chains ---------------------------------------------------------------------


@dataclass
class _Header:
    at: int
    previous: int
    ident: int
    letter: int
    header_len: int
    compression: int
    load_offset: int
    load_segment: int
    unpacked: int
    first: int
    next_fragment: int

    @classmethod
    def read(cls, data: bytes, at: int) -> _Header:
        previous, _, ident, letter, header_len, comp, offset, segment, unpacked, first, nxt = (
            MODULE_HEADER.unpack_from(data, at)
        )
        if comp <= 5:  # (flags in the top byte of the lengths: Fujitsu-Siemens D1219)
            unpacked, first = unpacked & 0xFFFFFF, first & 0xFFFFFF
        return cls(at, previous, ident, letter, header_len, comp, offset, segment, unpacked,
                   first, nxt)  # fmt: skip

    def plausible(self) -> bool:
        return (
            20 <= self.header_len <= 0x40
            and self.compression <= 8
            and (0 < self.unpacked & 0xFFFFFF < 0x400000)
        )

    def end(self) -> int:
        return self.at + self.header_len + (self.first & 0xFFFFFF)


def _is_header(data: bytes, at: int, size: int) -> bool:
    """A module header: the signature, or "11" after a module number other than 0 when the
    fields are plausible (Intel's web4z1us)."""
    if data[at + 4 : at + 7] == SIGNATURE:
        return True
    return (
        data[at + 5 : at + 7] == b"11"
        and at + MODULE_HEADER.size <= size
        and _Header.read(data, at).plausible()
    )


def _lh5(packed: bytes, size: int, strings: bool) -> bytes:
    """An LH5 body; one whose stream breaks off is kept when 95 % of it came out, a string
    pack when a quarter did (only texts are missing then: images cut short at the end, Intel's
    jnbios20 keeps 42 % of its pack)."""
    try:
        return lzh.decompress(packed, size, b"-lh5-")
    except (ValueError, IndexError):
        head = lzh.decompress(packed, size, b"-lh5-", partial=True)
        if len(head) * 100 < size * (25 if strings else 95) or (
            strings and not head.startswith(b"STRPACK")
        ):
            raise
        return head


def _unpack(data: bytes, h: _Header, packed: bytes) -> bytes:
    """The body of a module, unpacked; raises ValueError where it does not unpack."""
    if h.compression == 0:
        return packed
    if h.compression == 5:
        return _lh5(packed[4:], h.unpacked, chr(h.letter) == "S")
    if h.compression == 4:
        out = phx4.decode(packed, h.unpacked)
    elif h.compression == 2:
        out = phx2.unpack(data, h.at) or b""
    elif h.compression == 3:  # (not seen confirmed: taken only when the size comes out exact)
        out = lzss_decode(packed)
    else:
        raise LookupError(f"compression type {h.compression} is not supported")
    if len(out) != h.unpacked:
        raise ValueError(f"{COMPRESSION[h.compression]} gave {len(out)} bytes, not {h.unpacked}")
    return out


def _body(data: bytes, size: int, h: _Header, mod: dict) -> bytes:
    """The packed body: the first fragment, and the others when the next-fragment address has
    its top nibble set (each: next address, bank, length, bytes)."""
    start = h.at + h.header_len
    body = bytearray(data[start : start + h.first])
    if h.next_fragment & 0xF0000000 == 0xF0000000:
        visited: set[int] = set()
        at = _offset(h.next_fragment, size)
        while at and at not in visited and at + FRAGMENT.size <= size:
            visited.add(at)
            nxt, _bank, length = FRAGMENT.unpack_from(data, at)
            if len(body) + length > h.unpacked or at + FRAGMENT.size + length > size:
                mod["error"] = f"fragment at 0x{at:X} is too big"
                break
            body += data[at + FRAGMENT.size : at + FRAGMENT.size + length]
            at = _offset(nxt, size)
        mod["fragments"] = len(visited) + 1
    return bytes(body)


def _describe(h: _Header) -> dict:
    letter = chr(h.letter)
    kind = MODULE_NAMES.get(letter, f"{h.letter:02X}")
    return {
        "offset": h.at,
        "type": letter if letter.isprintable() else f"0x{h.letter:02X}",
        "name": kind,
        "id": h.ident,
        "file_name": f"{kind}_{h.ident}.bin",
        "compression": COMPRESSION.get(h.compression, f"type {h.compression}"),
        "size": h.unpacked,
        "load": (
            f"{h.load_segment << 12:04X}:{h.load_offset:04X}"
            if h.load_offset or h.load_segment
            else None
        ),
    }


def _chain(data: bytes, size: int, at: int, known: set[int]) -> list[dict]:
    """The modules from the header at at backwards, unpacked; stops at a module in known."""
    modules: list[dict] = []
    visited: set[int] = set()
    while at and len(modules) < MAX_MODULES and at not in visited and at not in known:
        visited.add(at)
        if at + MODULE_HEADER.size > size:
            modules.append({"error": f"module pointer 0x{at:X} is outside the image"})
            break
        if not _is_header(data, at, size):
            moved = [
                a
                for a in (at - SHIFTED, at + SHIFTED)
                if a >= 0 and a + MODULE_HEADER.size <= size and _is_header(data, a, size)
            ]
            if not moved:
                modules.append({"error": f"invalid module signature at 0x{at:X}"})
                break
            at = moved[0]
        h = _Header.read(data, at)
        mod = _describe(h)
        modules.append(mod)
        at = _offset(h.previous, size)
        if h.at + h.header_len + h.first > size:  # (LH5's length prefix counts in the first)
            mod["error"] = "module overruns the image"
            continue
        packed = _body(data, size, h, mod)
        mod["packed"] = len(packed)
        if "error" in mod:
            continue
        try:
            mod["data"] = _unpack(data, h, packed)
        except LookupError as e:
            mod["error"], mod["raw"] = str(e), packed
        except Exception as e:  # pylint: disable=broad-exception-caught
            mod["error"], mod["raw"] = f"decompression failed: {e}", packed
    return modules


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(a <= start < b or a < end <= b or start <= a < end for a, b in spans)


def _orphans(data: bytes, size: int, found: list[dict]) -> list[dict]:
    """Chains the walk did not reach (Intel's jnbios20: its chain ends in erased flash), from
    module headers of known types found in the image that overlap no module found so far."""
    known = {m["offset"] for m in found if "offset" in m}
    spans = [(a, _Header.read(data, a).end()) for a in known]
    out: list[dict] = []
    mark = data.find(b"11", 5)
    while mark >= 0:
        at, mark = mark - 5, data.find(b"11", mark + 1)
        if at in known or not _is_header(data, at, size):
            continue
        h = _Header.read(data, at)
        if chr(h.letter) not in MODULE_NAMES or not h.plausible():
            continue
        if _overlaps((at, h.end()), spans):
            continue
        chain = [m for m in _chain(data, size, at, known) if "offset" in m]
        out += chain
        known |= {m["offset"] for m in chain}
        spans += [(m["offset"], _Header.read(data, m["offset"]).end()) for m in chain]
    return out


def _blocks(data: bytes, segment: int) -> dict[bytes, int]:
    """The BCP blocks after BCPSEGMENT by name (6 bytes, flags, total length)."""
    found: dict[bytes, int] = {}
    at = segment + 10
    while at + 10 <= len(data) and data[at]:
        name, _flags, length = struct.unpack_from("<6sHH", data, at)
        found[name] = at
        if length < 10:
            break
        at += length
    return found


def extract(data: bytes) -> tuple[dict, list[dict]]:
    """Returns (image info, modules). Each module has offset, type, name, id, file_name,
    compression, size, load, packed, and either 'data' or 'error'."""
    size = len(data)
    if size > 0x100000 and size & (size - 1):  # (data after the flash image: Supermicro X7DB8)
        size = 1 << (size.bit_length() - 1)
        data = data[:size]
    segment = find_segment(data)
    if segment < 0:
        raise ValueError("no BCPSEGMENT (not a PhoenixBIOS 4.0-style image)")
    blocks = _blocks(data, segment)
    system = blocks.get(b"BCPSYS")
    if system is None:  # (a block the walk does not get past: Intel SE440BX-2, one byte off)
        found = data.find(b"BCPSYS", segment, segment + 0x2000)
        system = found if found >= 0 else None
    if system is None or system + 0x7B > size:
        raise ValueError("no BCPSYS block found")

    def text(at: int) -> str:
        return data[system + at : system + at + 8].split(b"\0")[0].decode("latin-1")

    info: dict[str, str | int] = {"version": text(0x37), "date": text(0x0F), "time": text(0x18)}
    if (cmp_block := data.find(b"BCPCMP")) >= 0:
        info["bcpcmp_alg"] = data[cmp_block + 11]
    last = _offset(struct.unpack_from("<I", data, system + 0x77)[0], size)
    if not last:
        if b"BCPFFV" not in blocks:
            raise ValueError("BCPSYS has no module list")
        if not (modules := ffv_modules(data)):
            raise ValueError(
                "this Phoenix image uses the FFV volume format (TrustedCore/SecureCore), "
                "whose volumes could not be read"
            )
        return info, modules
    modules = _chain(data, size, last, set())
    if any("error" in m for m in modules) and not any(m.get("name") == "setup" for m in modules):
        modules += _orphans(data, size, modules)
    return info, modules
