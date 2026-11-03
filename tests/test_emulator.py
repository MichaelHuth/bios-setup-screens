"""The emulator (bios_emu) with tiny hand-made ROMs: text output, keys through INT 16h and
through the 8042 and an INT 09h handler, CMOS, the timer, resets and the run limits."""

from __future__ import annotations

import struct
import time

import pytest

import bios_emu
from minirom import CODE_AT, DS0, HALT, OUT, putc, rom, set_vector, store_al, text


def memory(emu: bios_emu.BiosEmulator, at: int, n: int = 1) -> bytes:
    return bytes(emu.uc.mem_read(at, n))


def test_text_output_and_a_key() -> None:
    code = text(b"HELLO") + b"\xb4\x00\xcd\x16" + b"\xb4\x0e\xcd\x10" + HALT  # wait, echo, halt
    emu = bios_emu.BiosEmulator(rom(code))
    screen = emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "waiting for a key"
    assert screen.text().split("\n")[0].startswith("HELLO")
    emu.keys.append(0x1E61)  # ('a')
    screen = emu.resume()
    assert emu.stopped_reason == "halted"
    assert screen.text().split("\n")[0].startswith("HELLOa")


def test_a_key_through_the_8042_and_an_int_09h_handler() -> None:
    main = bytearray(DS0 + b"\xc6\x06" + struct.pack("<HB", OUT, 0))  # mov byte [OUT],0
    vector_at = len(main)
    main += set_vector(9, 0)  # (the handler's offset is filled in below)
    main += b"\xe4\x21\x24\xfd\xe6\x21"  # in al,21h ; and al,FDh ; out 21h,al (IRQ 1 on)
    main += b"\xfb"  # sti
    loop = len(main)
    main += b"\x80\x3e" + struct.pack("<HB", OUT, 0)  # cmp byte [OUT],0
    main += b"\x74" + bytes(((loop - (len(main) + 2)) & 0xFF,))  # jz loop
    main += HALT
    handler_offset = CODE_AT + len(main)
    handler = b"\x50\xe4\x60" + store_al(OUT) + b"\xb0\x20\xe6\x20\x58\xcf"
    # (push ax ; in al,60h ; mov [OUT],al ; mov al,20h ; out 20h,al ; pop ax ; iret)
    struct.pack_into("<H", main, vector_at + 4, handler_offset)
    emu = bios_emu.BiosEmulator(rom(bytes(main) + handler))
    emu.press_keys([0x1E, 0x9E])  # ('A' down and up)
    emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "halted"
    assert memory(emu, OUT) == b"\x1e"


def test_cmos_read_and_write() -> None:
    cmos = bytearray(128)
    cmos[0x30] = 0x42
    code = DS0
    code += b"\xb0\x30\xe6\x70\xe4\x71" + store_al(OUT)  # read CMOS 30h
    code += b"\xb0\x40\xe6\x70\xb0\x99\xe6\x71"  # write 99h to CMOS 40h
    code += b"\xb0\x40\xe6\x70\xe4\x71" + store_al(OUT + 1)  # and read it back
    code += HALT
    emu = bios_emu.BiosEmulator(rom(code), cmos=bytes(cmos))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 2) == b"\x42\x99"


def test_the_timer_counts_down() -> None:
    latch = b"\xb0\x00\xe6\x43"  # mov al,0 ; out 43h,al (latch channel 0)
    code = DS0 + b"\xb0\x34\xe6\x43\xb0\xff\xe6\x40\xe6\x40"  # channel 0, mode 2, count FFFFh
    code += latch + b"\xe4\x40" + store_al(OUT) + b"\xe4\x40" + store_al(OUT + 1)
    code += b"\xb9\xe8\x03\xe2\xfe"  # mov cx,1000 ; loop $
    code += latch + b"\xe4\x40" + store_al(OUT + 2) + b"\xe4\x40" + store_al(OUT + 3)
    code += HALT
    emu = bios_emu.BiosEmulator(rom(code))
    emu.run(0xF000, 0xFFF0)
    first, second = struct.unpack("<HH", memory(emu, OUT, 4))
    assert 0 < second < first <= 0xFFFF


def test_a_reset_through_port_cf9h_stops_the_run() -> None:
    code = putc(ord("R")) + b"\xba\xf9\x0c\xb0\x06\xee" + b"\xeb\xfe"  # out CF9h,6 ; jmp $
    emu = bios_emu.BiosEmulator(rom(code))
    emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "reset"


def test_the_instruction_limit() -> None:
    emu = bios_emu.BiosEmulator(rom(b"\x40\xeb\xfd"), max_instructions=50_000)  # inc ax ; jmp back
    emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "instruction limit reached"


def test_the_time_limit() -> None:
    emu = bios_emu.BiosEmulator(rom(b"\x40\xeb\xfd"), max_instructions=10**12)
    emu.max_seconds = 1
    started = time.time()
    emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "time limit reached"
    assert time.time() - started < 30


def test_a_reset_vector_outside_the_rom_is_refused() -> None:
    image = bytearray(rom(HALT))
    image[0xFFF0:0xFFF5] = b"\xea\x00\x00\x00\x10"  # jmp far 1000:0000 (RAM)
    emu = bios_emu.BiosEmulator(bytes(image))
    with pytest.raises(ValueError, match="outside the ROM"):
        emu.run(0xF000, 0xFFF0)


def test_halt_with_interrupts_off() -> None:
    emu = bios_emu.BiosEmulator(rom(text(b"OK") + HALT))
    screen = emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "halted" and screen.text().startswith("OK")
