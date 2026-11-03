"""
Tiny x86 ROMs for the emulator tests, hand-assembled here (our own code, 16-bit real mode).
rom(code) puts the code at F000:E000 and a far jump to it at the reset vector.
"""

from __future__ import annotations

import struct

CODE_AT = 0xE000
OUT = 0x500  # the tests' results: 0000:0500 onward


def rom(code: bytes) -> bytes:
    """A 64 KB ROM with the code at F000:E000 and a far jump to it at the reset vector."""
    image = bytearray(b"\xff" * 0x10000)
    image[CODE_AT : CODE_AT + len(code)] = code
    image[0xFFF0:0xFFF5] = b"\xea" + struct.pack("<HH", CODE_AT, 0xF000)  # jmp far F000:E000
    return bytes(image)


DS0 = b"\x31\xc0\x8e\xd8"  # xor ax,ax ; mov ds,ax
HALT = b"\xfa\xf4"  # cli ; hlt


def putc(ch: int) -> bytes:
    return b"\xb8" + bytes((ch, 0x0E)) + b"\xcd\x10"  # mov ax,0E00h+ch ; int 10h


def text(s: bytes) -> bytes:
    return b"".join(putc(c) for c in s)


def store_al(at: int) -> bytes:
    return b"\xa2" + struct.pack("<H", at)  # mov [at],al


def set_vector(number: int, offset: int) -> bytes:
    """mov word [4n], offset ; mov word [4n+2], F000h (DS = 0)."""
    return (
        b"\xc7\x06"
        + struct.pack("<HH", 4 * number, offset)
        + b"\xc7\x06"
        + struct.pack("<HH", 4 * number + 2, 0xF000)
    )
