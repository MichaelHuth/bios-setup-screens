"""
Unpack PhoenixBIOS 4.0 modules of compression type 2 (BCPCMP algorithm 1; Compaq, Intel and
DEC boards of about 1997-98) by running the image's own decompressor in Unicorn.

How it works: the image's module loader tests the header's
compression byte (`cmp byte es:[ebx+0Ah], 0` / `jne`), loads the work-area segment from
`cs:` and calls the decompressor, an adaptive-tree LZ77 with a 4 KB window, through a thunk.
It is called with ES = 0, EBX = the module header, ESI = the packed body (header + its length),
EDI = the destination, ECX = the packed length and AX = the work segment, and writes the
expanded length's bytes to ES:EDI. Only that routine runs, bounded by an instruction count;
ports read 0, any access outside the first MB stops it.
"""

from __future__ import annotations

import struct
import zlib

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_INSN,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MODE_16,
    UC_PROT_ALL,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDI,
    UC_X86_REG_ES,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
    UC_X86_REG_FS,
    UC_X86_REG_GS,
    UC_X86_REG_SS,
)

HEADER = struct.Struct("<I3sBBBBHHIII")  # (phoenix.MODULE_HEADER)
DEST = 0x10000  # where the output goes
STOP = 0xFFFF0  # a return address that ends the run
MAX_INSTRUCTIONS = 200_000_000
MAX_CACHE = 256
_decompressors: dict[tuple[int, int], tuple[int, int] | None] = {}
_unpacked: dict[tuple[int, int, int], bytes | None] = {}


def _decompressor(image: bytes) -> tuple[int, int] | None:
    """(entry, work-segment pointer) as addresses in the F000 segment, read off the loader."""
    base = 0x100000 - len(image)
    for pattern in (b"\x80\x7b\x0a\x00\x75", b"\x26\x80\x7b\x0a\x00\x75"):
        at = image.find(pattern)
        while at >= 0:
            jne = at + len(pattern) - 1
            target = (base + jne + 2 + image[jne + 1]) & 0xFFFFF  # where jne goes
            window = image[target - base : target - base + 24]
            if (i := window.find(b"\x2e\xa1")) >= 0:  # mov ax, cs:[work] right there
                work = window[i + 2] | window[i + 3] << 8
                call = window.find(b"\xe8", i + 4)
            elif window[:1] == b"\xe8":  # (or in a little stub it calls first)
                stub = (target & 0xF0000) | ((target + 3 + (window[1] | window[2] << 8)) & 0xFFFF)
                code = image[stub - base : stub - base + 8]
                if (k := code.find(b"\x2e\xa1")) < 0:
                    at = image.find(pattern, at + 1)
                    continue
                work = code[k + 2] | code[k + 3] << 8
                call = window.find(b"\xe8", 3)
            else:
                work, call = 0, -1
            if call >= 0:
                thunk = (target & 0xF0000) | (
                    (target + call + 3 + (window[call + 1] | window[call + 2] << 8)) & 0xFFFF
                )
                jump = image[thunk - base : thunk - base + 3]
                entry = (
                    (thunk & 0xF0000) | ((thunk + 3 + (jump[1] | jump[2] << 8)) & 0xFFFF)
                    if jump[:1] == b"\xe9"
                    else thunk
                )
                return entry, work
            at = image.find(pattern, at + 1)
    return None


def unpack(image: bytes, offset: int) -> bytes | None:
    """The unpacked body of the type-2 module whose header is at offset, or None."""
    size = len(image)
    if size > 0x100000 - DEST - 0x20000:
        return None  # (no room below the image for the output)
    checksum = zlib.crc32(image)
    key = (checksum, size, offset)
    if key in _unpacked:
        return _unpacked[key]
    if (checksum, size) not in _decompressors:
        _decompressors[(checksum, size)] = _decompressor(image)
    found = _decompressors[(checksum, size)]
    if found is None or offset + HEADER.size > size:
        return None
    entry, work = found
    fields = HEADER.unpack_from(image, offset)
    head_len, expanded, packed = fields[4], fields[8] & 0xFFFFFF, fields[9] & 0xFFFFFF
    base = 0x100000 - size
    if expanded > base - DEST:
        return None
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x100000, UC_PROT_ALL)
    uc.mem_write(base, image)
    uc.mem_write(0xF7F8, b"\xf0\xff\xff\xff")  # the return address: STOP
    segment = bytes(uc.mem_read(0xF0000 + work, 2))
    for register, value in (
        (UC_X86_REG_CS, 0xF000),
        (UC_X86_REG_DS, 0),
        (UC_X86_REG_ES, 0),
        (UC_X86_REG_FS, 0),
        (UC_X86_REG_GS, 0),
        (UC_X86_REG_SS, 0),
        (UC_X86_REG_ESP, 0xF800),
        (UC_X86_REG_EAX, segment[0] | segment[1] << 8),
        (UC_X86_REG_EBX, base + offset),
        (UC_X86_REG_ESI, base + offset + head_len),
        (UC_X86_REG_EDI, DEST),
        (UC_X86_REG_ECX, packed),
    ):
        uc.reg_write(register, value)
    uc.hook_add(UC_HOOK_INSN, lambda *_: 0, None, 1, 0, UC_X86_INS_IN)
    uc.hook_add(UC_HOOK_INSN, lambda *_: None, None, 1, 0, UC_X86_INS_OUT)
    uc.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
        lambda *_: False,
    )
    end = [0]  # how far the output was written

    def wrote(_uc: Uc, _access: int, address: int, length: int, _value: int, _data: None) -> None:
        end[0] = max(end[0], address + length)

    uc.hook_add(UC_HOOK_MEM_WRITE, wrote, None, DEST, DEST + expanded - 1)
    try:
        uc.emu_start(entry, STOP, timeout=30_000_000, count=MAX_INSTRUCTIONS)
    except UcError:
        pass  # (the routine's own epilogue may fault after the output is complete)
    out = bytes(uc.mem_read(DEST, expanded)) if end[0] >= DEST + expanded else None
    if len(_unpacked) >= MAX_CACHE:
        _unpacked.pop(next(iter(_unpacked)))
    _unpacked[key] = out
    return out
