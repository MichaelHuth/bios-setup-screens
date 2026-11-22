"""The emulator (bios_emu) with tiny hand-made ROMs: text output, keys through INT 16h and
through the 8042 and an INT 09h handler, CMOS, the timer, resets and the run limits."""

from __future__ import annotations

import struct
import time
import types

import pytest

import bios_emu
import screen_tools
from minirom import CODE_AT, DS0, HALT, OUT, putc, rom, set_vector, store_al, text
from textscreen import Screen


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


def test_a_recalibrate_after_one_reset_sense_reports_its_seek() -> None:
    emu = bios_emu.BiosEmulator(rom(HALT))
    fdc = lambda *values: [emu._out(emu.uc, 0x3F5, 1, v, None) for v in values]  # noqa: E731
    results = lambda: [emu._in(emu.uc, 0x3F5, 1, None) for _ in range(2)]  # noqa: E731
    emu._out(emu.uc, 0x3F2, 1, 0x08, None)  # the controller held in reset ...
    emu._out(emu.uc, 0x3F2, 1, 0x0C, None)  # ... and out of it: "ready changed" per drive
    fdc(0x08)
    assert results() == [0xC0, 0]  # (drive 0's; POST senses no more)
    fdc(0x07, 0x00)  # recalibrate drive 0
    fdc(0x08)
    assert results() == [0x20, 0]  # seek end, track 0 (not drive 1's reset result)


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


@pytest.mark.parametrize("masked_before", [False, True])
def test_a_timer_tick_lasts_as_many_refresh_cycles_as_on_a_real_machine(
    masked_before: bool,
) -> None:
    # Award's 286 POST counts refresh cycles (port 61h bit 4) between two timer interrupts
    # and shows "REFRESH TIMING ERROR" outside about 1370-2290. masked_before: IRQ 0 masked
    # while port 61h is read a million times; the tick raised then comes on the unmask
    poll = b"\xe4\x61\xa8\x10\x75\xfa"  # in al,61h ; test al,10h ; jnz (to the in)
    poll += b"\xe4\x61\xa8\x10\x74\xfa\x42\xeb\xf1"  # the same with jz ; inc dx ; jmp (first in)
    start = DS0 + b"\xb0\x36\xe6\x43\xb0\x00\xe6\x40\xe6\x40"  # channel 0, mode 3, count 0
    if masked_before:  # mask all ; sti ; bx = 8 times cx = 65536 times in al,61h
        start += b"\xb0\xff\xe6\x21\xfb\xbb\x08\x00\x31\xc9\xe4\x61\xe2\xfc\x4b\x75\xf7"
    first = CODE_AT + len(start) + 12 + 7  # (after the vector, the mask and sti ; jmp $)
    start += set_vector(8, first) + b"\xb0\xfe\xe6\x21\xfb\xeb\xfe"  # IRQ 0 only ; sti ; jmp $
    count = b"\x31\xd2\x83\xc4\x06\xb0\x20\xe6\x20\xfb" + poll  # dx = 0 ; drop the frame ; EOI
    second = first + 12 + len(count)
    code = start + set_vector(8, second) + count + b"\x89\x16" + struct.pack("<H", OUT) + HALT
    emu = bios_emu.BiosEmulator(rom(code), timer_irq=True, max_instructions=5_000_000)
    emu.run(0xF000, 0xFFF0)
    assert 1400 < struct.unpack("<H", memory(emu, OUT, 2))[0] < 2250


def test_a_gl520sm_on_the_smbus_of_a_vt82c596() -> None:
    image = bytearray(rom(HALT))
    image[0x8000:0x8004] = struct.pack("<HH", 0x1106, 0x0686)  # (a VIA south bridge's ID)
    emu = bios_emu.BiosEmulator(bytes(image))
    # the VT82C596's SMBus base at function 3, 80h (PCChips M768VMR: 5F00h)
    emu.pci_addr = 0x80000000 | 7 << 11 | 3 << 8 | 0x80
    emu._pci_write(0xCFC, 2, 0x5F01)
    assert emu.smbus_base == 0x5F00

    def transfer(address: int, command: int, protocol: int, data: int = 0) -> tuple[int, int]:
        emu._smbus_write(0, 0xFF)
        emu._smbus_write(4, address)
        emu._smbus_write(3, command)
        emu._smbus_write(5, data)
        emu._smbus_write(2, 0x40 | protocol << 2)
        return emu.smbus[5], emu.smbus[6]

    assert transfer(0x5B, 0x00, 2)[0] == 0x20  # chip ID
    transfer(0x5A, 0x0F, 2, 0x54)  # fan divisors 2 and 2
    transfer(0x5A, 0x04, 2, 0x00)  # (a reading is not written)
    assert transfer(0x5B, 0x04, 2)[0] - 130 == 38  # C
    fan1, fan2 = transfer(0x5B, 0x07, 3)  # the word of the fan counts
    assert (round(480_000 / (fan1 * 2)), round(480_000 / (fan2 * 2))) == (4528, 3000)


def test_an_ich2_lan_function_named_alone_gives_an_815_board() -> None:
    hints = struct.pack("<HHHH", 0x8086, 0x2449, 0x8086, 0x1132)  # (Acer's 815 images)
    emu = bios_emu.BiosEmulator(rom(HALT), hints=hints)
    assert bytes(emu.pci_devices[(31, 0)][0:4]) == struct.pack("<HH", 0x8086, 0x2440)
    assert bytes(emu.pci_devices[(0, 0)][0:4]) == struct.pack("<HH", 0x8086, 0x1130)


def test_the_ich_gpio_block_reads_back_and_its_inputs_read_as_set() -> None:
    hints = struct.pack("<HHHH", 0x8086, 0x2449, 0x8086, 0x1132)
    emu = bios_emu.BiosEmulator(rom(HALT), hints=hints)
    emu.ich_gpio_inputs = 0
    assert emu._in(emu.uc, 0xFC0F, 1, None) == 0xFF  # (no GPIO base yet: nothing there)
    emu.pci_addr = 0x8000F858  # GPIOBASE FC00h, on with GPIO_CNTL bit 4
    emu._pci_write(0xCFD, 1, 0xFC)
    emu.pci_addr = 0x8000F85C
    emu._pci_write(0xCFC, 1, 0x10)
    emu._out(emu.uc, 0xFC03, 1, 0x08, None)  # GPIO 27: a GPIO ...
    emu._out(emu.uc, 0xFC07, 1, 0x08, None)  # ... and an input
    emu._out(emu.uc, 0xFC0F, 1, 0x0C, None)  # (bit 2 an output, set)
    assert emu._in(emu.uc, 0xFC03, 1, None) == 0x08
    assert emu._in(emu.uc, 0xFC0F, 1, None) == 0x04  # GPIO 27 low (Acer's route)
    emu.ich_gpio_inputs = 0x08000000
    assert emu._in(emu.uc, 0xFC0F, 1, None) == 0x0C  # (or high)
    emu.ich_gpio_inputs = None
    assert emu._in(emu.uc, 0xFC0F, 1, None) == 0xFF  # (not modelled: other boards)


def test_an_amd_756_board_gets_the_amd_751_host() -> None:
    # the AMD-756's power management function in a module, an Intel host in a table
    hints = b"AMIBIOSC0627" + struct.pack("<HHHH", 0x1022, 0x740B, 0x8086, 0x122D)
    emu = bios_emu.BiosEmulator(rom(HALT), hints=hints)
    assert bytes(emu.pci_devices[(0, 0)][0:4]) == struct.pack("<HH", 0x1022, 0x7006)


def test_a_sis_730_resets_and_ends_its_acpi_command() -> None:
    hints = b"AMIBIOSC0627" + struct.pack("<HH", 0x1039, 0x0730)
    emu = bios_emu.BiosEmulator(rom(HALT), hints=hints)
    assert bytes(emu.pci_devices[(0, 0)][2:4]) == b"\x30\x07"
    emu.pci_addr = 0x80000800 | 0x74  # device 1: ACPI base 5000h
    emu._pci_write(0xCFC, 2, 0x5000)
    assert emu._in(emu.uc, 0x5060, 2, None) == 0  # (a command from 62h bit 0 ended)
    emu.pci_addr = 0x80000800 | 0x44
    emu._pci_write(0xCFE, 1, 0x31)
    with pytest.raises(bios_emu.Stop):
        emu._pci_write(0xCFE, 1, 0xF1)  # bits 6-7: the reset
    assert emu.stopped_reason == "reset"


def test_an_alis_m7101_smbus_host_on_a_board_modelled_otherwise() -> None:
    image = bytearray(rom(HALT))
    image[0x8000:0x8008] = struct.pack("<HHHH", 0x10B9, 0x7101, 0x10B9, 0x1533)  # (its table)
    emu = bios_emu.BiosEmulator(bytes(image))
    assert emu.chip_smbus == "m7101" and (17, 0) in emu.pci_devices
    for reg, value in ((0x14, 0x5001), (0xE0, 0x01)):  # SMBus base 5000h, host on
        emu.pci_addr = 0x80000000 | 17 << 11 | reg & 0xFC
        emu._pci_write(0xCFC + (reg & 3), 2 if reg == 0x14 else 1, value)
    assert emu.smbus_base == 0x5000
    # a byte-data read of the GL520SM's chip ID at 2Dh: address, command, protocol, start
    for off, value in ((0, 0xFF), (3, 0x5B), (7, 0x00), (1, 0x20), (2, 0xFF)):
        emu._out(emu.uc, 0x5000 + off, 1, value, None)
    assert emu._in(emu.uc, 0x5000, 1, None) == 0x14  # idle, done
    assert emu._in(emu.uc, 0x5004, 1, None) == 0x20


def test_an_smbus_host_set_inside_the_686s_default_pm_window_answers() -> None:
    image = bytearray(rom(HALT))
    image[0x8000:0x8004] = struct.pack("<HH", 0x1106, 0x0686)  # (a VT82C686's ID)
    emu = bios_emu.BiosEmulator(bytes(image))
    assert emu.via_pm_base == 0x5000  # (where the chip leaves its PM I/O)
    emu.pci_addr = 0x80000000 | 7 << 11 | 3 << 8 | 0x90
    emu._pci_write(0xCFC, 2, 0x5001)  # the SMBus base, 5000h (s26r26)
    emu._smbus_write(4, 0x5B)  # a byte-data read of the GL520SM's ID at 2Dh
    emu._smbus_write(3, 0x00)
    emu._smbus_write(2, 0x48)
    assert emu._in(emu.uc, 0x5005, 1, None) == 0x20  # the host's data, not a PM register


def test_the_pm_smbus_host_reaches_the_monitor() -> None:
    # the VIA/AMD host at PM I/O +E0h: the GL520SM at 2Dh written (fan divisors 2, 2 in 0Fh),
    # then its fan word at 07h read (+E6h, +E7h): 4528 and 3000 RPM
    emu = bios_emu.BiosEmulator(rom(HALT))
    for off, value in ((0xE4, 0x5A), (0xE8, 0x0F), (0xE6, 0x50), (0xE2, 0x0A)):
        emu._via_smbus(off, value)
    for off, value in ((0xE4, 0x5B), (0xE8, 0x07), (0xE2, 0x0B)):
        emu._via_smbus(off, value)
    fan1, fan2 = emu._via_smbus(0xE6), emu._via_smbus(0xE7)
    assert (round(480_000 / (fan1 * 2)), round(480_000 / (fan2 * 2))) == (4528, 3000)


def test_a_winbond_monitor_on_the_smbus() -> None:
    emu = bios_emu.BiosEmulator(rom(HALT))

    def read(address: int, command: int) -> int:
        for reg, value in ((0, 0xFF), (4, address << 1 | 1), (3, command), (2, 0x48)):
            emu._smbus_write(reg, value)
        return emu.smbus[5]

    # at 2Ch: Vcore and the temperature as at 295h, the vendor ID's high byte (bank 80h);
    # at 2Dh the GL520SM's ID below 20h and the same Winbond registers from 20h on
    assert [read(0x2C, r) for r in (0x20, 0x27, 0x4F)] == [0x64, 38, 0x5C]
    assert [read(0x2D, r) for r in (0x00, 0x20)] == [0x20, 0x64]


def test_a_post_polling_a_cmos_register_nothing_changes_stops() -> None:
    # mov al,7Eh ; out 70h,al ; in al,71h ; jmp to the start: nothing here sets 7Eh
    emu = bios_emu.BiosEmulator(rom(b"\xb0\x7e\xe6\x70\xe4\x71\xeb\xf8"), max_instructions=10**8)
    emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "polling CMOS register 7Eh"


def test_the_smbus_start_bit_reads_0() -> None:
    emu = bios_emu.BiosEmulator(rom(HALT))
    emu.smbus_base = 0x540
    emu._smbus_write(2, 0x48)  # start a byte-data read
    assert emu._in(emu.uc, 0x542, 1, None) == 0x08


@pytest.mark.parametrize(
    "out, body, writes",
    [
        (b"\xe6\xe0", b"\xeb\x00", 1),
        (b"\xe6\xe0", b"\x90\x90", 0x1000),
        (b"\xba\xe0\x00\xee", b"\xeb\x00" * 4, 1),  # (mov dx,0E0h ; out dx,al: 11 bytes)
    ],
)
def test_a_bare_delay_port_loop_ends_after_one_pass(
    monkeypatch: pytest.MonkeyPatch, out: bytes, body: bytes, writes: int
) -> None:
    # mov cx,1000h ; out E0h,al ; jmp $+2s (or two nops: not a bare delay) ; loop ; hlt
    seen = []
    original = bios_emu.BiosEmulator._end_delay_loop

    def counted(self: bios_emu.BiosEmulator, uc: object) -> None:
        seen.append(1)
        original(self, uc)  # type: ignore[arg-type]

    monkeypatch.setattr(bios_emu.BiosEmulator, "_end_delay_loop", counted)
    back = -(len(out) - (3 if len(out) > 2 else 0) + len(body) + 2)  # (to the out)
    code = b"\xb9\x00\x10" + out + body + b"\xe2" + struct.pack("b", back) + HALT
    emu = bios_emu.BiosEmulator(rom(code))
    emu.run(0xF000, 0xFFF0)
    assert len(seen) == writes


def test_an_smbus_block_read_into_the_32_byte_buffer_ends_with_intr() -> None:
    emu = bios_emu.BiosEmulator(rom(HALT))
    emu.smbus_base = 0x400
    emu.smbus_devices[0x69] = bytearray([3, 0x11, 0x22, 0x33]) + bytearray(252)
    emu._smbus_write(0x0D, 0x02)  # E32B
    emu._smbus_write(4, 0xD3)  # a block read of the clock generator at 69h
    emu._smbus_write(2, 0x54)
    emu.smbus_busy = 0
    assert emu._in(emu.uc, 0x400, 1, None) & 0x82 == 0x02  # INTR, no BYTE_DONE
    assert emu._in(emu.uc, 0x405, 1, None) == 3
    emu._in(emu.uc, 0x402, 1, None)  # (resets the buffer pointer)
    assert [emu._in(emu.uc, 0x407, 1, None) for _ in range(3)] == [0x11, 0x22, 0x33]


@pytest.mark.parametrize("reads, stops", [(1000, True), (50, False)])
def test_a_post_beeping_for_ever_stops(reads: int, stops: bool) -> None:
    # mov al,3 ; out 61h,al (speaker on) ; mov cx,reads ; in al,61h ; loop (the in) ;
    # mov al,0 ; out 61h,al ; jmp to the start. Short ones are key clicks: no beeps
    code = b"\xb0\x03\xe6\x61\xb9" + struct.pack("<H", reads) + b"\xe4\x61\xe2\xfc"
    code += b"\xb0\x00\xe6\x61\xeb\xef"
    emu = bios_emu.BiosEmulator(rom(code), max_instructions=20_000_000)
    emu.run(0xF000, 0xFFF0)
    if stops:
        assert emu.stopped_reason == "beeping without end (a POST error)"
        assert emu.beeps == bios_emu.BEEPS + 1
    else:
        assert emu.stopped_reason == "instruction limit reached" and emu.beeps == 0


def test_register_11h_through_ech_shows_the_bios_segment_at_e0000() -> None:
    # mov al,11h ; out ECh,al ; mov al,AAh ; out EDh,al ; then read E000:E000 (the code here)
    code = DS0 + b"\xb0\x11\xe6\xec\xb0\xaa\xe6\xed"
    code += b"\xb8\x00\xe0\x8e\xd8\xa0\x00\xe0"  # mov ax,E000h ; mov ds,ax ; mov al,[E000h]
    code += b"\x31\xdb\x8e\xdb" + store_al(OUT) + HALT  # xor bx,bx ; mov ds,bx ; mov [OUT],al
    image = b"Z" * 0x10000 + rom(code)  # (128 KB: its lower half is not the code)
    emu = bios_emu.BiosEmulator(image)
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == code[:1]  # (F000:E000, the code's first byte, at E000:E000)


def test_timer_channel_2_has_counted_a_little_at_a_latch_right_after_its_count() -> None:
    # gate on ; channel 2 LSB only, mode 0 ; count FFh ; latch at once ; read
    code = b"\xe4\x61\x0c\x01\xe6\x61\xb0\x90\xe6\x43\xb0\xff\xe6\x42\xb0\x80\xe6\x43\xe4\x42"
    emu = bios_emu.BiosEmulator(rom(DS0 + code + store_al(OUT) + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT)[0] < 0xFF  # (Copam PC-501's timer test wants it moving)


def test_the_tick_count_moves_for_reads_at_its_address_not_through_a_register() -> None:
    # mov ax,[46Ch] eight times, then mov si,46Ch and mov ax,[si] eight times
    direct = b"\xa1\x6c\x04" * 8 + b"\xa3" + struct.pack("<H", OUT)
    indexed = b"\xbe\x6c\x04" + b"\x8b\x04" * 8 + b"\xa3" + struct.pack("<H", OUT + 2)
    emu = bios_emu.BiosEmulator(rom(DS0 + direct + indexed + HALT))
    emu.run(0xF000, 0xFFF0)
    after_direct, after_indexed = struct.unpack("<HH", memory(emu, OUT, 4))
    assert after_direct > 0 and after_indexed == after_direct  # (a memory test sees no change)


def test_an_m6117s_registers_read_back_after_its_unlock() -> None:
    def reg(index: int, value: int) -> bytes:  # mov al,index ; out 22h,al ; mov al,v ; out 23h,al
        return b"\xb0" + bytes((index,)) + b"\xe6\x22\xb0" + bytes((value,)) + b"\xe6\x23"

    read_15 = b"\xb0\x15\xe6\x22\xe4\x23"  # mov al,15h ; out 22h,al ; in al,23h
    code = DS0 + reg(0x15, 0x50) + read_15 + store_al(OUT)  # (locked: nothing reads back)
    code += reg(0x13, 0xC5) + reg(0x15, 0x50) + read_15 + store_al(OUT + 1)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 2) == b"\xff\x50"


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


def hwmon_read(index: int, at: int) -> bytes:
    """mov dx,295h ; mov al,index ; out dx,al ; inc dx ; in al,dx ; mov [at],al"""
    return b"\xba\x95\x02\xb0" + bytes((index,)) + b"\xee\x42\xec" + store_al(at)


def test_the_hardware_monitor_reads_normal_voltages() -> None:
    # Vcore, +12 V, the battery and a temperature on an ITE layout (the default)
    code = DS0 + b"".join(hwmon_read(i, OUT + k) for k, i in enumerate((0x20, 0x24, 0x28, 0x29)))
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 4) == bytes((0x64, 0xBB, 0xBC, 0x26))  # 1.6 V, 12 V, 3 V, 38 degrees


def hwmon_write(index: int, value: int) -> bytes:
    """mov dx,295h ; mov al,index ; out dx,al ; inc dx ; mov al,value ; out dx,al"""
    return b"\xba\x95\x02\xb0" + bytes((index,)) + b"\xee\x42\xb0" + bytes((value,)) + b"\xee"


def test_a_winbond_monitor_keeps_its_own_registers_above_24h() -> None:
    # once the BIOS chooses Winbond's bank select (4Eh), 28h is a fan count again: the CPU
    # fan at 4500 RPM (divisor 2); fan 2 with divisor 4 set in 47h: 3000 RPM
    code = DS0 + hwmon_read(0x4E, OUT) + hwmon_read(0x20, OUT) + hwmon_read(0x28, OUT + 1)
    code += hwmon_write(0x47, 0x9F) + hwmon_read(0x29, OUT + 2) + hwmon_read(0x47, OUT + 3)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 4) == bytes((0x64, 150, 112, 0x9F))


def test_an_ite_monitor_counts_its_fans_with_the_divisors_set() -> None:
    code = DS0 + hwmon_read(0x0B, OUT) + hwmon_read(0x0D, OUT + 1) + hwmon_read(0x0F, OUT + 2)
    code += hwmon_write(0x0B, 0x52) + hwmon_read(0x0D, OUT + 3) + hwmon_read(0x0F, OUT + 4)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    # 09h: fans 1 and 2 divided by 2; 52h: fan 1 by 4, fan 3 by 8 (2700 RPM)
    assert memory(emu, OUT, 5) == bytes((0x09, 150, 250, 75, 62))


def test_the_first_register_only_one_chip_has_chooses_the_layout() -> None:
    # ITE's fan divisors first, then Winbond's bank select: 28h stays ITE's battery
    code = DS0 + hwmon_read(0x0B, OUT) + hwmon_write(0x4E, 0x80) + hwmon_read(0x28, OUT)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == b"\xbc" and emu.hwmon_winbond is False


@pytest.mark.parametrize("ite_first, fan", [(False, 225), (True, 0x26)])
def test_the_start_bit_and_a_fan_read_choose_winbond_unless_ite_came_first(
    ite_first: bool, fan: int
) -> None:
    # 40h = 01h, then 29h read: Winbond's fan 2 (3000 RPM, divisor 2); with ITE's 13h selected
    # in between (PCChips M586LMR) ITE's temperature there (38 C)
    code = DS0 + hwmon_write(0x40, 0x01) + (hwmon_read(0x13, OUT + 1) if ite_first else b"")
    emu = bios_emu.BiosEmulator(rom(code + hwmon_read(0x29, OUT) + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == bytes((fan,)) and emu.hwmon_winbond is not ite_first


def test_a_winbonds_second_temperature_in_its_bank_1() -> None:
    # bank select 4Eh = 81h, then 50h: temperature 2, 32 C (s147r13's CPU temperature)
    code = DS0 + hwmon_write(0x4E, 0x81) + hwmon_read(0x50, OUT)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == bytes((32,))


@pytest.mark.parametrize("config, winbond", [(0x00, True), (0x80, True), (0x01, None)])
def test_the_lm78_configuration_chooses_the_winbond_layout(config: int, winbond: bool) -> None:
    # 40h = 00h (stopped) or 80h (initialise) only on an LM78/Winbond monitor (ITE's 40h is a
    # limit; 01h comes from ITE boards too, and leaves it open): then 29h is fan 2, 3000 RPM
    # with the power-on divisor 2, and 27h a temperature, 38 C
    emu = bios_emu.BiosEmulator(rom(DS0 + hwmon_write(0x40, config) + HALT))
    emu.run(0xF000, 0xFFF0)
    assert emu.hwmon_winbond is winbond
    if winbond:
        code = DS0 + hwmon_write(0x40, config) + hwmon_read(0x29, OUT) + hwmon_read(0x27, OUT + 1)
        emu = bios_emu.BiosEmulator(rom(code + HALT))
        emu.run(0xF000, 0xFFF0)
        assert memory(emu, OUT, 2) == bytes((225, 38))


def test_an_ite_monitor_answers_at_the_base_of_its_logical_device_4() -> None:
    def sio(index: int, value: int) -> bytes:
        # mov al,index ; out 2Eh,al ; mov al,value ; out 2Fh,al
        return b"\xb0" + bytes((index,)) + b"\xe6\x2e\xb0" + bytes((value,)) + b"\xe6\x2f"

    read_806 = b"\xba\x05\x08\xb0\x20\xee\x42\xec"  # mov dx,805h ; index 20h (Vcore) ; in al,dx
    code = DS0 + read_806 + store_al(OUT)  # (not set up yet: nothing there)
    code += sio(0x07, 0x04) + sio(0x60, 0x08) + sio(0x61, 0x00) + sio(0x30, 0x01)
    code += read_806 + store_al(OUT + 1)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 2) == b"\xff\x64"  # then 1.6 V


def test_a_winbond_monitor_answers_at_the_base_of_its_logical_device_0bh() -> None:
    def sio(index: int, value: int) -> bytes:
        return b"\xb0" + bytes((index,)) + b"\xe6\x2e\xb0" + bytes((value,)) + b"\xe6\x2f"

    def read(index: int) -> bytes:  # mov dx,535h ; mov al,index ; out dx,al ; inc dx ; in al,dx
        return b"\xba\x35\x05\xb0" + bytes((index,)) + b"\xee\x42\xec"

    # logical device 0Bh at 530h (s147r13): Winbond's layout, fan 1 at 28h (4500 RPM)
    code = DS0 + sio(0x07, 0x0B) + sio(0x60, 0x05) + sio(0x61, 0x30) + sio(0x30, 0x01)
    code += read(0x28) + store_al(OUT)
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == bytes((150,)) and emu.hwmon_winbond is True


def test_a_vt82c686a_monitor_answers_in_the_window_post_opened() -> None:
    # function 4: monitor at C00h (70h), decoded (74h bit 0); 38 C and 1.6 V, the CPU fan at
    # 4500 RPM (divisor 2), the system fan at 3000 RPM with divisor 4 set in 47h
    def port_in(port: int, at: int) -> bytes:  # mov dx,port ; in al,dx ; mov [at],al
        return b"\xba" + struct.pack("<H", port) + b"\xec" + store_al(at)

    code = DS0 + port_in(0xC20, OUT) + port_in(0xC22, OUT + 1) + port_in(0xC29, OUT + 2)
    code += b"\xba\x47\x0c\xb0\x9f\xee" + port_in(0xC2A, OUT + 3)  # out C47h,9Fh
    emu = bios_emu.BiosEmulator(rom(code + HALT))
    function4 = bytearray(256)
    function4[0:4] = b"\x06\x11\x57\x30"
    emu.pci_devices[(7, 4)] = function4
    assert emu._via_hwmon_index(0xC20) is None  # (no window yet)
    function4[0x70:0x75] = b"\x01\x0c\x00\x00\x01"
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 4) == bytes((0xA0, 0x82, 150, 112))


def test_halt_with_interrupts_off() -> None:
    emu = bios_emu.BiosEmulator(rom(text(b"OK") + HALT))
    screen = emu.run(0xF000, 0xFFF0)
    assert emu.stopped_reason == "halted" and screen.text().startswith("OK")


WAIT_KEY = b"\xb4\x00\xcd\x16"  # mov ah,0 ; int 16h


def test_the_post_screen_is_the_screen_at_the_first_key() -> None:
    # POST counts memory and waits for a key; the key starts setup, which waits for more
    emu = bios_emu.BiosEmulator(
        rom(text(b"640K OK") + WAIT_KEY + text(b" SETUP") + WAIT_KEY + HALT)
    )
    emu.run(0xF000, 0xFFF0)
    assert emu.post_screen is None  # (no key taken yet)
    emu.keys.append(0x011B)
    screen = emu.resume()
    assert screen.text().startswith("640K OK SETUP")
    assert emu.post_screen is not None
    assert emu.post_screen.text() == "640K OK"
    emu.keys.append(0x011B)  # (setup's own keys leave it)
    emu.resume()
    assert emu.post_screen.text() == "640K OK"


def test_no_post_screen_where_the_program_did_not_start_at_the_reset_vector() -> None:
    # (a setup entered directly, as the classic AMIBIOS route does, has no POST screen)
    emu = bios_emu.BiosEmulator(rom(text(b"SETUP") + WAIT_KEY + HALT))
    emu.run(0xF000, 0xE000)
    emu.keys.append(0x011B)
    emu.resume()
    assert emu.post_screen is None


def test_dells_nvram_reads_empty_through_its_smi_port() -> None:
    # out B3h,01h (a scratch byte) ; out B2h,67h (Dell's SMI: next NVRAM byte) ; in al,B3h
    code = DS0 + b"\xb0\x01\xe6\xb3\xb0\x67\xe6\xb2\xe4\xb3" + store_al(OUT) + HALT
    emu = bios_emu.BiosEmulator(rom(code))
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == b"\x01"  # (any other board: the scratch byte)
    emu = bios_emu.BiosEmulator(rom(code))
    emu.dell_nvram = True
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT) == b"\x00"


def test_a_northwood_has_its_cache_descriptors_and_ratio() -> None:
    # mov eax,2 ; cpuid ; mov [OUT],eax ; mov [OUT+4],edx ; mov ecx,2Ch ; rdmsr (patched)
    code = (
        DS0
        + b"\x66\xb8\x02\x00\x00\x00\x0f\xa2"
        + b"\x66\xa3"
        + struct.pack("<H", OUT)
        + b"\x66\x89\x16"
        + struct.pack("<H", OUT + 4)
        + bios_emu.RDMSR_P4
        + b"\x66\xa3"
        + struct.pack("<H", OUT + 8)
        + HALT
    )
    emu = bios_emu.BiosEmulator(rom(code), host_id=0x1A30)  # (a Pentium 4 host)
    emu.msr_patch_end = 0x100000  # (patched in the ROM too, as POST would find it)
    emu.post_codes_seen.update(range(3))
    assert emu._patch_msr_reads()
    emu.run(0xF000, 0xFFF0)
    eax, edx, ratio = struct.unpack("<3I", memory(emu, OUT, 12))
    assert (eax, edx) == (0x665B5001, 0x007B7040)  # (7Bh: 512 KB L2)
    assert ratio >> 24 == 16 and ratio & 0x30000 == 0  # 16 x 100 MHz


def test_amis_p4_ratio_check_takes_the_ratio_for_fixed() -> None:
    # "test eax,100000h / jne": taken (the ratio fixed), so the store after it is skipped
    store = b"\xc6\x06" + struct.pack("<H", OUT) + b"\x01"  # mov byte [OUT],1
    before = b"\xc6\x06" + struct.pack("<H", OUT) + b"\x02"  # mov byte [OUT],2
    code = DS0 + before + bios_emu.P4_RATIO_FIXED + bytes([len(store)]) + store + HALT
    emu = bios_emu.BiosEmulator(rom(code), host_id=0x1A30)
    emu.msr_patch_end = 0x100000
    emu.post_codes_seen.update(range(3))
    assert emu._patch_msr_reads()
    emu.run(0xF000, 0xFFF0)
    assert memory(emu, OUT, 1) == b"\x02"


@pytest.mark.parametrize("host_id, signature", [(0, 0x0435), (0x1A30, 0xF27)])
def test_edx_holds_the_cpus_signature_after_a_reset(host_id: int, signature: int) -> None:
    # at power-on: mov [OUT],edx ; the 8042's reset (out 64h,FEh), then mov [OUT+4],edx
    code = (
        DS0
        + b"\x80\x3e\x00\x06\x01\x74\x10"  # cmp byte [600h],1 ; je again
        + b"\x66\x89\x16"
        + struct.pack("<H", OUT)
        + b"\xc6\x06\x00\x06\x01\xb0\xfe\xe6\x64\xeb\xfe"  # mov byte [600h],1 ; reset
        + b"\x66\x89\x16"
        + struct.pack("<H", OUT + 4)  # again:
        + HALT
    )
    emu = bios_emu.BiosEmulator(rom(code), host_id=host_id)
    emu.kbc_reset_in_place = True
    emu.run(0xF000, 0xFFF0)
    at_power_on, after_reset = struct.unpack("<2I", memory(emu, OUT, 8))
    assert after_reset == signature
    assert at_power_on == (signature if host_id else 0)  # (others: as before)


def test_the_post_screen_goes_with_the_setup_screens() -> None:
    def screen(s: bytes) -> Screen:
        out = Screen()
        out.write(0, 0, s, 0x07)
        return out

    class Setup:  # (a setup route's object: its emulator and its screens)
        def __init__(self, post: bytes | None) -> None:
            self.emu = types.SimpleNamespace(post_screen=post and screen(post))

        def screens(self) -> list:
            return [("MAIN", screen(b"MAIN MENU"), "")]

    screens = screen_tools._with_post(Setup(b"640K OK"))
    assert [t for t, _, _ in screens] == ["MAIN"]
    assert screens.post is not None and screens.post.text() == "640K OK"
    assert screen_tools._with_post(Setup(None)).post is None
    # (a "POST screen" that is the setup itself, taken at setup's first key, is none)
    assert screen_tools._with_post(Setup(b"MAIN MENU")).post is None
