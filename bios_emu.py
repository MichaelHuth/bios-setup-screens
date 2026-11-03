"""
Run BIOS setup code in a real-mode x86 emulator (Unicorn) to capture the text screens it draws.

The harness provides 16 MB of memory (ram_mb) with the ROM at the top of the first MB and of the
4 GB space, a BIOS data area for 80x25 color text mode, INT 10h video services writing into text
memory at B8000 (fonts, palette, blinking and 350-line mode included), a CMOS RAM, a refresh bit
on port 61h (delay loops), PIT channel 2 (CPU speed measurement), the 8042 keyboard controller
(self-tests, command byte, A20 gate, AMI extensions, a PS/2 mouse), port 92h, Intel PAM shadow
RAM for C0000-FFFFF once PCI configuration space is used, and the PIC's IRQ 1 mask.
Interrupts the ROM handles itself (INT 13h, 14h, 15h, 17h once POST installed them) go to its
own handlers, so a whole POST can run.

Keys come either from a list given to INT 16h (setup code run directly), or with press_keys()
as scan codes typed on the keyboard: put in the 8042, raised as IRQ 1 and handled by the ROM's
own INT 09h/16h (e.g. DEL during POST, then navigating a setup). When the code waits for a key
and no keys are left, emulation stops and the screen is complete; snapshot()/restore() and
resume() continue from such a point with other keys.
"""

from __future__ import annotations

import collections
import contextvars
import copy
import ctypes
import functools
import re
import struct
import threading
from collections.abc import Callable, Sequence
from typing import Any

import capstone
from PIL import Image
from unicorn import x86_const

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_X86,
    UC_MODE_16,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_INSN_INVALID,
    UC_HOOK_INSN,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_WRITE_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_READ,
)
from unicorn.x86_const import (
    UC_X86_INS_CPUID,
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AH,
    UC_X86_REG_AL,
    UC_X86_REG_AX,
    UC_X86_REG_BH,
    UC_X86_REG_BL,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
    UC_X86_REG_CH,
    UC_X86_REG_CL,
    UC_X86_REG_CR0,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DH,
    UC_X86_REG_DL,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_EIP,
    UC_X86_REG_ES,
    UC_X86_REG_GDTR,
    UC_X86_REG_IDTR,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESP,
    UC_X86_REG_EBP,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
)

from textscreen import FONTS, Screen

VRAM = 0xB8000
# the ROM fonts as a VGA BIOS would have them (INT 10h AX=1130h): character height -> address
FONT_ADDRS = {16: 0xC1000, 14: 0xC2000, 8: 0xC3000}
FONT_PLANE = 0xA0000  # fonts loaded into plane 2: 32 bytes per character
SHADOW_BASE = 0xC0000
ALI_P54C = b"PCI/ISA P54C BIOS"  # (Acer: see _ali_pam)
TIMER_SLICE = 500_000  # instructions between two timer interrupts (with timer_irq)
MAX_SECONDS = 90  # wall-clock time of one run at most (a POST that loops through slow code)
# bytes after a shadow RAM switch that the CPU still runs as it fetched them before (the 486's
# prefetch queue): UMC BIOSes switch F0000 to the ROM from code there, read a word from the
# ROM and switch back
PREFETCH = 16
# Intel chipsets a BIOS may look for on the PCI bus: device ID -> (device, function, class
# code); the vendor is 8086h. A ROM's chipset is recognised by these IDs in its code.
INTEL_PCI = {
    0x1237: (0, 0, 0x060000),  # 440FX host bridge
    0x7030: (0, 0, 0x060000),  # 430VX host bridge
    0x7100: (0, 0, 0x060000),  # 430TX host bridge
    0x7190: (0, 0, 0x060000),  # 440BX host bridge
    0x7192: (0, 0, 0x060000),  # 440BX host bridge (no AGP)
    0x7120: (0, 0, 0x060000),  # 810 host bridge
    0x7122: (0, 0, 0x060000),  # 810-DC100 host bridge
    0x7124: (0, 0, 0x060000),  # 810E host bridge
    0x122D: (0, 0, 0x060000),  # 430FX host bridge
    0x1250: (0, 0, 0x060000),  # 430HX host bridge
    0x04A3: (0, 0, 0x060000),  # 430LX/NX host bridge (82434LX/NX PCMC, mechanism #2)
    0x0484: (2, 0, 0x060100),  # 82378 SIO ISA bridge beside it (device 2 there)
    0x0482: (2, 0, 0x060200),  # 82375 PCEB EISA bridge (EISA boards instead of the SIO)
    0x7000: (7, 0, 0x060100),  # PIIX3 ISA bridge
    0x7010: (7, 1, 0x010180),  # PIIX3 IDE
    0x7110: (7, 0, 0x060100),  # PIIX4 ISA bridge
    0x7111: (7, 1, 0x010180),  # PIIX4 IDE
    0x122E: (7, 0, 0x060100),  # PIIX ISA bridge
    0x2410: (31, 0, 0x060100),  # ICH LPC bridge
    0x2420: (31, 0, 0x060100),  # ICH0 LPC bridge
    0x2570: (0, 0, 0x060000),  # 865PE/G host bridge
    0x2578: (0, 0, 0x060000),  # 875P host bridge
    0x24D0: (31, 0, 0x060100),  # ICH5 LPC bridge
    0x2560: (0, 0, 0x060000),  # 845G/GE/PE host bridge
    0x1A30: (0, 0, 0x060000),  # 845 host bridge (82845 MCH, with the ICH2)
    0x2440: (31, 0, 0x060100),  # ICH2 LPC bridge
    0x24C0: (31, 0, 0x060100),  # ICH4 LPC bridge
}
# for messages about boards whose POST cannot run here
EMULATED = (
    "only Intel chipsets are: 430FX/HX/VX/TX, 440FX/BX, 810, 845, 865 and 875 with "
    "PIIX or ICH south bridges, the SiS 5597 and 85C496, the ALi M1489, the UMC "
    "8881/8886, and VIA chipsets with a VT82C586/596/686 or VT8231/8233/8235/8237 south "
    "bridge, loosely)"
)
# hosts whose PAM registers are at 90h-96h (865/875 and later) instead of 59h-5Fh
PAM_AT_90 = {0x1A30, 0x2560, 0x2570, 0x2578}
# hosts with DRAM row boundaries at 60h-67h (row 0 at 60h) that AMI sizes row by row from
# address 0: 430FX, HX, VX, TX (4 MB units), 440BX (8 MB units) -> the units' shift
ROW_SIZED_HOSTS = {0x122D: 22, 0x1250: 22, 0x7030: 22, 0x7100: 22, 0x7190: 23}
# boards whose BIOS only shows anything once it has found a VGA card on the PCI bus (and run
# its expansion ROM): a plain one is put on bus 0 (QEMU's standard VGA IDs)
VGA_CARD_HOSTS = {0x1A30, 0x2560, 0x2570, 0x2578}
VGA_CARD = (2, 0, 0x1234, 0x1111)
DDR_HOSTS = {0x2560, 0x2570, 0x2578}
# read-only strap bits: device ID -> {register: (mask, value)} (845G/GE/PE: DRC bits 1-0 tell
# the DRAM type the board was built for, 01 = DDR)
STRAPS = {
    0x2560: {0x7C: (0x03, 0x01)},
    0x3057: {0x42: (0x50, 0x50)},  # (VT82C686 power management: 42h bits 4 and 6, which
    # POST waits for after setting up the ISA function, read 1; bit 6: TriGem Santa Fe's boot block)
    0x2440: {0xA1: (0x02, 0x02)},  # (ICH2 GEN_PMCON_1 bit 9, which FSC D1372's
    # POST waits for)
    0x8409: {0x82: (0x40, 0x40)},  # (VX855 bus control 82h bit 6: Wyse Cx0's boot block)
    0x4409: {0xE8: (0xFF, 0x40)},
}  # (VX855 D0F4 E8h: Wyse Cx0's TrustedCore sets up its
# memory pool only above 30h; meaning unknown)
# bits that start an action and read 0 once it is done (845: 57h bit 1 starts the buffer
# strength calibration)
# Intel host bridges' SMRAM control register (bit 6 D_OPEN: A0000-BFFFF is RAM for code outside
# SMM, which is how POST copies the SMM handler there): host ID -> register
SMRAM_REGS = {
    **dict.fromkeys((0x1A30, 0x2560, 0x2570, 0x2578, 0x3340, 0x3580), 0x9D),
    **dict.fromkeys((0x7180, 0x7190, 0x7192, 0x7120, 0x7122, 0x7124, 0x1130), 0x72),
}
I810_HOSTS = (0x7120, 0x7122, 0x7124)
PC133_HOSTS = (0x1A30,)  # SDRAM boards whose DIMMs must be PC133 (845)
SELF_CLEARING = {
    0x2560: {0x57: 0x02},
    0x7006: {0x5A: 0x80},
    0x0691: {0x5A: 0x80},
    0x1A30: {0x96: 0x80},  # (94h bit 23 starts a command, GA-8TM polls it)
}  # (AMD-751: 5Ah bit 7 starts
# the SDRAM mode register set)
# revision IDs of the steppings that were sold (some BIOSes stop on earlier ones; else 1)
REVISIONS = {0x2570: 2, 0x2578: 2}
# the other functions of an ICH south bridge and the devices beside it on bus 0
ICH_FUNCTIONS = {
    0x2440: {
        (31, 1): (0x244B, 0x010180),
        (31, 3): (0x2443, 0x0C0500),
        (31, 5): (0x2445, 0x040100),
        (30, 0): (0x244E, 0x060400),
        (1, 0): (0x1A31, 0x060400),
    },
    0x2410: {
        (31, 1): (0x2411, 0x010180),
        (31, 3): (0x2413, 0x0C0500),
        (31, 5): (0x2415, 0x040100),
        (30, 0): (0x2418, 0x060400),
        (1, 0): (0x7121, 0x030000),
    },
    0x24C0: {
        (31, 1): (0x24CB, 0x010180),
        (31, 3): (0x24C3, 0x0C0500),
        (31, 5): (0x24C5, 0x040100),
        (30, 0): (0x244E, 0x060400),
        (1, 0): (0x2561, 0x060400),
    },
    0x24D0: {
        (31, 1): (0x24DB, 0x010180),
        (31, 3): (0x24D3, 0x0C0500),
        (31, 5): (0x24D5, 0x040100),
        (30, 0): (0x244E, 0x060400),
        (1, 0): (0x2571, 0x060400),
    },
    0x2420: {
        (31, 1): (0x2421, 0x010180),
        (31, 3): (0x2423, 0x0C0500),
        (31, 5): (0x2425, 0x040100),
        (30, 0): (0x2428, 0x060400),
        (1, 0): (0x7123, 0x030000),
    },
}
SMBUS_FUNCTIONS = {(31, 3): 0x20, (7, 3): 0x90, (17, 0): 0xD0, (7, 4): 0x90}  # (VIA: 17.0, 7.4)
# VIA chipsets, modelled loosely: their host bridge (an ID from the ROM), the AGP bridge at
# device 1 and the south bridge with its IDE function; no shadow RAM registers (C0000-FFFFF
# stay plain RAM, which is what a BIOS sees once it has copied itself there). South bridges:
# ID -> device on bus 0 (VT8233 and later at 17, VT82C586/596/686 at 7)
VIA_SOUTH = {
    0x3074: 17,
    0x3147: 17,
    0x3177: 17,
    0x3227: 17,
    0x3109: 17,
    0x8231: 17,
    0x3372: 17,
    0x3337: 17,
    0x8324: 17,
    0x8409: 17,
    0x0686: 7,
    0x0596: 7,
    0x0586: 7,
}
# VIA's single-chip-like north bridges, by south bridge: the host bridge's base device ID
VIA_SOC_HOSTS = {0x8409: 0x0409, 0x8324: 0x0324}
# "mov ecx, C0010010h" (the K7's SYSCFG): an Athlon BIOS, which shadows C0000-FFFFF through
# the CPU's fixed-range MTRRs (RdDram/WrDram, bits 4 and 3 of each 4 KB range's type byte in
# MSRs 268h-26Fh) rather than the chipset's registers
K7_SYSCFG = bytes.fromhex("66b9100001c0")
# AMD Athlon north bridges (host ID -> its AGP bridge's ID) found beside VIA south bridges
AMD_HOSTS = {0x7006: 0x7007, 0x700E: 0x700F}
VIA_HOSTS = (
    0x0691,
    0x0693,
    0x0305,
    0x0391,
    0x0597,
    0x0598,
    0x0501,
    0x0585,
    0x0595,
    0x0601,
    0x0605,
    0x3099,
    0x3101,
    0x3102,
    0x3112,
    0x3116,
    0x3123,
    0x3128,
    0x3148,
    0x3156,
    0x3168,
    0x3188,
    0x3189,
    0x3205,
    0x3208,
    0x3213,
    0x3258,
    0x3259,
    0x0204,
    0x0259,
    0x0269,
    0x0282,
    0x0296,
    0x0314,
    0x0364,
)
# Base address registers of the emulated devices: device ID -> {register: size mask | type bits}
# (I/O: bit 0; memory: bit 3 prefetchable). Sizing writes FFFFFFFFh and reads the mask back;
# BARs not listed are not implemented and read 0.
_IO16, _IO8 = 0xFFFFFFF1, 0xFFFFFFF9
PCI_BARS = {
    0x7010: {0x20: _IO16},
    0x7111: {0x20: _IO16},
    0x2411: {0x20: _IO16},
    0x2421: {0x20: _IO16},
    0x2413: {0x20: _IO16},
    0x2423: {0x20: _IO16},
    0x24D3: {0x20: _IO16},
    0x24DB: {0x20: _IO16},
    0x24C3: {0x20: _IO16},
    0x24CB: {0x20: _IO16},
    0x24C5: {0x10: 0xFFFFFF01, 0x14: 0xFFFFFFC1},
    0x24D5: {0x10: 0xFFFFFF01, 0x14: 0xFFFFFFC1},
    0x1111: {0x10: 0xFF000008, 0x30: 0xFFFF0000},  # the plain VGA card (16 MB, 64 KB ROM)
    0x2415: {0x10: 0xFFFFFF01, 0x14: 0xFFFFFFC1},
    0x2425: {0x10: 0xFFFFFF01, 0x14: 0xFFFFFFC1},
    0x2443: {0x20: _IO16},
    0x244B: {0x20: _IO16},  # ICH2 SMBus and IDE (Tiga T-815E)
    0x2445: {0x10: 0xFFFFFF01, 0x14: 0xFFFFFFC1},
    0x7121: {0x10: 0xFC000008, 0x14: 0xFFF80000},
    0x7123: {0x10: 0xFC000008, 0x14: 0xFFF80000},
    0x7125: {0x10: 0xFC000008, 0x14: 0xFFF80000},
}  # SMBus controller: register with its I/O base


# SPD geometry of single-sided PC100 SDRAM DIMMs: MB -> (row bits, column bits, chip width,
# internal banks, bank density byte)
SPD_GEOMETRY = {
    16: (11, 9, 8, 2, 0x04),
    32: (12, 8, 16, 4, 0x08),
    64: (12, 9, 8, 4, 0x10),
    128: (12, 10, 8, 4, 0x20),
}


# DDR SDRAM (PC3200) DIMMs: MB -> (row bits, column bits, chip width, density byte)
DDR_GEOMETRY = {64: (12, 9, 16, 0x10), 128: (13, 9, 16, 0x20), 256: (13, 10, 8, 0x40)}


def _spd_ddr(mb: int) -> bytes:
    """SPD EEPROM of a single-sided DDR400 DIMM (CL 3, 4 internal banks)."""
    rows, cols, width, density = DDR_GEOMETRY.get(mb, DDR_GEOMETRY[64])
    spd = bytearray(256)
    spd[0:42] = bytes(
        [
            0x80,
            0x08,
            0x07,
            rows,
            cols,
            0x01,
            0x40,
            0x00,
            0x04,
            0x50,
            0x70,
            0x00,
            0x82,
            width,
            0x00,
            0x01,
            0x0E,
            0x04,
            0x1C,
            0x01,
            0x02,
            0x20,
            0xC1,
            0x60,
            0x70,
            0x75,
            0x75,
            0x3C,
            0x28,
            0x3C,
            0x28,
            density,
            0x60,
            0x60,
            0x40,
            0x40,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x37,
        ]
    )
    spd[42], spd[43], spd[44], spd[45] = 0x46, 0x28, 0x28, 0x50
    spd[62] = 0x10
    spd[63] = sum(spd[:63]) & 0xFF
    return bytes(spd)


def _spd(mb: int, pc133: bool = False) -> bytes:
    """SPD EEPROM of a single-sided PC100 SDRAM DIMM of the emulated RAM's size, for BIOSes
    that size memory from the DIMMs' SPD data over the SMBus; or a PC133 one (the 845 takes
    only PC133 SDRAM: Fujitsu-Siemens D1326's Phoenix checks cycle time 7.5 ns and access
    time 5.4 ns and retries its memory sizing for good otherwise)."""
    rows, cols, width, banks, density = SPD_GEOMETRY.get(mb, SPD_GEOMETRY[16])
    spd = bytearray(256)
    spd[0:36] = bytes(
        [
            0x80,
            0x08,
            0x04,
            rows,
            cols,
            0x01,
            0x40,
            0x00,
            0x01,
            0xA0,
            0x60,
            0x00,
            0x80,
            width,
            0x00,
            0x01,
            0x8F,
            banks,
            0x06,
            0x01,
            0x01,
            0x00,
            0x0E,
            0xA0,
            0x60,
            0x00,
            0x00,
            0x14,
            0x0F,
            0x14,
            0x32,
            density,
            0x20,
            0x10,
            0x20,
            0x10,
        ]
    )
    spd[62] = 0x12  # SPD revision 1.2
    spd[63] = sum(spd[:63]) & 0xFF
    spd[126], spd[127] = 0x64, 0xAF  # 100 MHz, CAS 2/3
    if pc133:  # cycle time 7.5 ns, access time 5.4 ns at CL 3; 10 ns / 6 ns at CL 2
        spd[9], spd[10], spd[23], spd[24], spd[126] = 0x75, 0x54, 0xA0, 0x60, 0x85
        spd[63] = sum(spd[:63]) & 0xFF
    return bytes(spd)


# SiS chipsets: host bridge ID -> devices (device, function, ID, class). The 85C496/497 (486)
# answers as device 5 (IDSEL AD16)
SIS_CHIPSETS = {
    0x5597: [(0, 0, 0x5597, 0x060000), (1, 0, 0x0008, 0x060100), (1, 1, 0x5513, 0x010180)],
    0x0496: [(5, 0, 0x0496, 0x060000)],
}


# UMC 486 chipset (UM8881F host bridge, UM8886 ISA bridge): device, function, ID, class.
# AMI's compressed BIOSes for it name no IDs; their boot block addresses device 16's
# configuration space (or eax,80008000h) to set up the shadow RAM.
UMC_CHIPSET = [(16, 0, 0x8881, 0x060000), (18, 0, 0x886A, 0x060100)]
# chipsets known by the device their boot block addresses (or eax,8000xx00h), for compressed
# BIOSes whose IDs are only in the unpacked code (or not at all)
BOOT_ACCESS: dict[bytes, int | str] = {
    bytes.fromhex("660d00800080"): "umc",  # device 16: UMC 8881
    bytes.fromhex("660d00280080"): 0x0496,  # device 5: SiS 85C496
}


def _umc_devices(rom: bytes) -> dict[tuple[int, int], bytearray]:
    out = {}
    for dev, fn, device_id, cls in UMC_CHIPSET:
        cfg = bytearray(256)
        cfg[0:4] = struct.pack("<HH", 0x1060, device_id)
        cfg[8:12] = struct.pack("<I", cls << 8 | 0x04)
        out[(dev, fn)] = cfg
    return out


def _named(rom: bytes, vendor: int, device_id: int) -> bool:
    return bool(
        rom.count(struct.pack("<HH", vendor, device_id))
        or rom.count(struct.pack("<HH", device_id, vendor))
    )


def _via_devices(rom: bytes) -> dict[tuple[int, int], bytearray]:
    """A VIA chipset if the ROM names one of its south bridges, else nothing."""
    south = next((i for i in VIA_SOUTH if _named(rom, 0x1106, i)), None)
    if south is None:
        # AMI's compressed BIOSes of 1996-2003 often name no chipset IDs (their chipset code
        # addresses the devices by number): taken as a VIA 686 board, which is enough for
        # POST on many of them (VIA and SiS boards alike: plain RAM shadow, flat memory)
        if not re.search(rb"AMIBIOSC0(?:62[6-9]|700)", rom):
            return {}
        south = 0x0686
    host = next(
        (i for i in VIA_HOSTS if _named(rom, 0x1106, i)),
        0x3123 if VIA_SOUTH[south] == 17 else 0x0691,
    )
    agp = (0x1106, 0xB091)
    host_vendor = 0x1106
    for amd_host, amd_agp in AMD_HOSTS.items():  # an AMD north bridge beside a VIA south
        if _named(rom, 0x1022, amd_host):
            host_vendor, host, agp = 0x1022, amd_host, (0x1022, amd_agp)
            break
    dev = VIA_SOUTH[south]
    out = {}
    functions = [
        ((0, 0), (host_vendor, host), 0x060000),
        ((1, 0), agp, 0x060400),
        ((dev, 0), (0x1106, south), 0x060100),
        ((dev, 1), (0x1106, 0x0571), 0x01018A),
    ]
    if south in (0x0686, 0x0596):  # USB, power management, AC'97 and MC'97 functions: BIOSes
        # write the board's subsystem ID to the codec functions and wait for the write to end
        functions += [
            ((dev, 2), (0x1106, 0x3038), 0x0C0300),
            ((dev, 3), (0x1106, 0x3038), 0x0C0300),
            ((dev, 4), (0x1106, 0x3057), 0x068000),
            ((dev, 5), (0x1106, 0x3058), 0x040100),
            ((dev, 6), (0x1106, 0x3068), 0x078000),
        ]
    if south in VIA_SOC_HOSTS:  # VX855/CX700: the host bridge has eight functions (DRAM
        # control at 3, power management at 4 ...), IDs f000h + the base ID
        base = VIA_SOC_HOSTS[south]
        functions = [((0, f), (0x1106, f << 12 | base), 0x060000) for f in range(8)] + functions[1:]
    for key, (vendor, device_id), cls in functions:
        cfg = bytearray(256)
        cfg[0:4] = struct.pack("<HH", vendor, device_id)
        cfg[8:12] = struct.pack("<I", cls << 8 | 0x01)
        cfg[0x0E] = {
            (1, 0): 0x01,
            (dev, 0): 0x80,
            (0, 0): 0x80 if south in VIA_SOC_HOSTS else 0,
        }.get(key, 0)
        for reg, (mask, value) in STRAPS.get(device_id, {}).items():
            cfg[reg] = cfg[reg] & ~mask | value
        if south == 0x0686 and key == (dev, 3):
            # 43h bits 0-2: this power-up was asked for (power button or wake). MSI MS-6316's
            # boot block reads it and, all clear (AC power just applied), switches the board
            # off with SLP_EN to wait for the button
            cfg[0x43] |= 0x01
        out[key] = cfg
    return out


def _sis_devices(host: int) -> dict[tuple[int, int], bytearray]:
    out = {}
    for dev, fn, device_id, cls in SIS_CHIPSETS[host]:
        cfg = bytearray(256)
        cfg[0:4] = struct.pack("<HH", 0x1039, device_id)
        cfg[8:12] = struct.pack("<I", cls << 8 | 0x01)
        cfg[0x0E] = 0x80 if (dev, fn) == (1, 0) else 0
        out[(dev, fn)] = cfg
    return out


def _boot_sum_skipped(rom: bytes) -> bytes:
    """AMI boot blocks of about 1995 add up F000:E000-FFFF as dwords and stop with "loop ... /
    jne $" when the sum is not 0. A modified image fails it (Am5tRG2, AMI 07/15/95), and its
    setup is still worth seeing: that halt is left out."""
    top = rom[-0x2000:]
    if len(top) < 0x2000 or not sum(struct.unpack("<2048I", top)) & 0xFFFFFFFF:
        return rom
    m = BOOT_SUM_HALT.search(top)
    if m is None:
        return rom
    at = len(rom) - 0x2000 + m.start() + 2
    return rom[:at] + b"\x90\x90" + rom[at + 2 :]


# SiS north bridges in front of a 96x MuTIOL south bridge (device 2), and ALi/ULi south bridges
# of the M1563 family with the north bridges beside them: AMIBIOS 7 boards whose generic VIA
# tables would otherwise win (IDs from pci.ids)
SIS_MUTIOL_HOSTS = (
    0x0645,
    0x0646,
    0x0648,
    0x0649,
    0x0650,
    0x0651,
    0x0655,
    0x0661,
    0x0662,
    0x0730,
    0x0735,
    0x0745,
    0x0755,
    0x0760,
    0x0761,
)
SIS_MUTIOL_SOUTH = {0x0961: 1, 0x0962: 2, 0x0963: 3, 0x0964: 4, 0x0965: 5}  # id -> revision
ALI_VENDORS = (0x10B9, 0x1025)
ALI_SOUTH = (0x1563, 0x1575, 0x1573, 0x1533, 0x1535, 0x1543)
ALI_HOSTS = (0x1681, 0x1687, 0x1689, 0x1695, 0x1697, 0x1671, 0x1672, 0x1651, 0x1641, 0x1647)
# (device, function) -> the configuration register their POST writes the SMBus base to
CHIP_SMBUS_BAR = {(2, 1): 0x20, (3, 0): 0x80}
# SiS 96x SMBus registers -> the host model's (VIA/ICH layout): writes and reads
SIS_SMBUS_WRITE = {0: 0, 3: 2, 4: 4, 5: 3, 8: 5, 9: 6}
SIS_SMBUS_READ = {0: 0, 4: 4, 5: 3, 8: 5, 9: 6, 10: 7}


def _config(vendor: int, device_id: int, cls: int, rev: int = 1, header: int = 0) -> bytearray:
    cfg = bytearray(256)
    cfg[0:4] = struct.pack("<HH", vendor, device_id)
    cfg[8:12] = struct.pack("<I", cls << 8 | rev)
    cfg[0x0E] = header
    return cfg


def _sis_mutiol_devices(rom: bytes, host: int) -> dict[tuple[int, int], bytearray]:
    """A SiS 645/650-era host at 0.0, its AGP bridge at 1.0, the 96x south bridge at 2.0 with
    IDE, USB, audio, modem and SMBus functions."""
    south = next((i for i in SIS_MUTIOL_SOUTH if _named(rom, 0x1039, i)), 0x0963)
    return {
        (0, 0): _config(0x1039, host, 0x060000),
        (1, 0): _config(0x1039, 0x0001, 0x060400, header=0x01),
        (2, 0): _config(0x1039, south, 0x060100, SIS_MUTIOL_SOUTH[south], header=0x80),
        (2, 1): _config(0x1039, 0x5513, 0x01018A),
        (2, 2): _config(0x1039, 0x7001, 0x0C0300),
        (2, 3): _config(0x1039, 0x7001, 0x0C0300),
        (2, 5): _config(0x1039, 0x7012, 0x040100),
        (2, 6): _config(0x1039, 0x7013, 0x070300),
        (2, 7): _config(0x1039, 0x0016, 0x0C0500),
    }


def _ali_m1563_devices(rom: bytes) -> dict[tuple[int, int], bytearray]:
    """An ALi/ULi M1681-class host at 0.0, its AGP bridge at 1.0, the M1563 south bridge at
    3.0 with IDE, USB, audio, modem, Ethernet and PMU functions."""
    host = next((i for i in ALI_HOSTS if any(_named(rom, v, i) for v in ALI_VENDORS)), 0x1681)
    south = next((i for i in ALI_SOUTH if any(_named(rom, v, i) for v in ALI_VENDORS)), 0x1563)
    v = 0x10B9 if _named(rom, 0x10B9, south) else 0x1025
    return {
        (0, 0): _config(v, host, 0x060000),
        (1, 0): _config(v, 0x5246, 0x060400, header=0x01),
        (3, 0): _config(v, south, 0x060100, 0xC3, header=0x80),
        (3, 1): _config(v, 0x5229, 0x01018A),
        (3, 2): _config(v, 0x5237, 0x0C0300),
        (3, 3): _config(v, 0x5237, 0x0C0300),
        (3, 4): _config(v, 0x5451, 0x040100),
        (3, 5): _config(v, 0x5453, 0x070300),
        (3, 6): _config(v, 0x5261, 0x020000),
        (3, 7): _config(v, 0x7101, 0x068000),
    }


def _pci_devices(rom: bytes) -> dict[tuple[int, int], bytearray]:
    """The chipset devices (see _named_devices); a VIA set where the ROM names a SiS MuTIOL
    host or an ALi/ULi M1563-family south bridge is that chipset's instead."""
    devices = _named_devices(rom)
    if not any(c[0:2] == b"\x06\x11" for c in devices.values()):
        return devices
    for host in SIS_MUTIOL_HOSTS:
        if _named(rom, 0x1039, host):
            return _sis_mutiol_devices(rom, host)
    if any(_named(rom, v, i) for i in ALI_SOUTH for v in ALI_VENDORS):
        return _ali_m1563_devices(rom)
    return devices


def _named_devices(rom: bytes) -> dict[tuple[int, int], bytearray]:
    """Configuration spaces of the chipset devices the ROM's code refers to: for Intel at most
    one host bridge and one ISA/LPC bridge (with its IDE function), or a SiS or UMC chipset."""
    if rom.count(struct.pack("<HH", 0x1060, 0x8881)) or rom.count(
        struct.pack("<HH", 0x8881, 0x1060)
    ):
        return _umc_devices(rom)
    for host in SIS_CHIPSETS:
        if rom.count(struct.pack("<HH", 0x1039, host)) or rom.count(
            struct.pack("<HH", host, 0x1039)
        ):
            return _sis_devices(host)
    if rom.count(struct.pack("<HH", 0x1039, 0x0200)):  # the 5597/5598's built-in VGA: some
        return _sis_devices(0x5597)  # AMI builds (PCChips M571) name only it and the 5571
    if b"SiS5591 Host" in rom:  # SiS 5591/5595 (PCChips M570): named only in texts; POST
        return _sis_devices(0x5597)  # gets through with the 5597's model (ISA bridge at 1)
    found: dict[tuple[int, int], tuple[int, int]] = {}
    for device_id, (dev, fn, cls) in INTEL_PCI.items():
        if rom.count(struct.pack("<HH", 0x8086, device_id)) or rom.count(
            struct.pack("<H", device_id) + b"\x86\x80"
        ):
            found.setdefault((dev, fn), (device_id, cls))
    # a BIOS may look only for its ISA bridge and take the host bridge for granted
    partners = {
        0x7000: 0x7030,
        0x122E: 0x122D,
        0x7110: 0x7190,
        0x2410: 0x7120,
        0x2420: 0x7122,
        0x24D0: 0x2570,
        0x24C0: 0x2560,
        0x0484: 0x04A3,
        0x0482: 0x04A3,
        0x2440: 0x1A30,
    }
    if found.get((31, 0), (0,))[0] in (0x2410, 0x2420) and _named(rom, 0x8086, 0x2440):
        # the ICH2 named beside the ICH/ICH0 (generic tables): the ICH2's board, and with the
        # 815's graphics (1132h) named an 815 host (Tiga T-815E)
        found[(31, 0)] = (0x2440, 0x060100)
        if _named(rom, 0x8086, 0x1132):
            found.setdefault((0, 0), (0x1130, 0x060000))
            found.setdefault((1, 0), (0x1131, 0x060400))
    if (31, 0) in found:  # an ICH board: PIIX IDs elsewhere in the ROM are generic tables
        for key in [k for k in found if k[0] == 7]:
            del found[key]
        if found.get((0, 0), (0,))[0] not in (
            0x7120,
            0x7122,
            0x7124,
            0x1A30,
            0x2560,
            0x2570,
            0x2578,
            0x1130,
        ):
            found.pop((0, 0), None)
        for key, value in ICH_FUNCTIONS.get(found[(31, 0)][0], {}).items():
            found.setdefault(key, value)
    via_named = any(_named(rom, 0x1106, i) for i in VIA_SOUTH)
    if (
        found.get((7, 1), (0,))[0] == 0x7111
        and (7, 0) not in found
        and not (via_named and set(found) <= {(0, 0), (7, 1)})
    ):
        # only the PIIX4's IDE (and power management) named: its ISA function and, through
        # the partners below, a 440BX host (Supermicro S2DG2, a 440GX board whose AMI BIOS
        # addresses host and ISA bridge by number)
        found[(7, 0)] = (0x7110, 0x060100)
    if found.get((7, 0), (0,))[0] == 0x7110:  # PIIX4: its power management function, which
        found.setdefault((7, 3), (0x7113, 0x068000))  # BIOSes address by number, not by ID
    if set(found) <= {(0, 0), (7, 1)} and via_named and found.get((7, 1), (0x7111,))[0] == 0x7111:
        # (an Intel host alone is a stray ID in a table beside a named VIA south bridge:
        # Gigabyte GA-7ZXC, 8086:122D; or the PIIX4's IDE in an IDE timing table, PCChips
        # M768VMR's VIA board)
        return _via_devices(rom)  # (before the boot block patterns: Zida 5DLX, VIA VT82C586,
        # has UMC's "or eax, 80008000h" in its boot block)
    for code, chipset in BOOT_ACCESS.items() if not found else ():
        if code in rom:
            return _umc_devices(rom) if isinstance(chipset, str) else _sis_devices(chipset)
    if found.get((2, 0), (0,))[0] in (0x0482, 0x0484) and found.get((0, 0), (0x04A3,))[0] != 0x04A3:
        del found[(2, 0)]  # (Neptune bridges named in another chipset's generic tables)
    isa = found.get((7, 0)) or found.get((31, 0)) or found.get((2, 0))
    if (0, 0) not in found and isa and isa[0] in partners:
        found[(0, 0)] = (partners[isa[0]], 0x060000)
    if not found:
        return _via_devices(rom)
    devices: dict[tuple[int, int], bytearray] = {}
    for (dev, fn), (device_id, cls) in found.items():
        cfg = bytearray(256)
        cfg[0:4] = struct.pack("<HH", 0x8086, device_id)
        cfg[8:12] = struct.pack("<I", cls << 8 | REVISIONS.get(device_id, 1))
        for reg, (_mask, fixed) in STRAPS.get(device_id, {}).items():
            cfg[reg] = fixed
        devices[(dev, fn)] = cfg
    for (dev, fn), cfg in devices.items():  # multi-function devices
        if fn == 0 and any(d == dev and f for d, f in devices):
            cfg[0x0E] = 0x80
        if cfg[0x0B] == 0x06 and cfg[0x0A] == 0x04:  # PCI-to-PCI bridge: type 1 header
            cfg[0x0E] |= 0x01
    return devices


DEFAULT_PALETTE = [0, 1, 2, 3, 4, 5, 0x14, 7, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F]
# VGA DAC defaults for the 64 EGA colors (rgbRGB bits, 6-bit levels)
DEFAULT_DAC = [
    tuple(21 * (2 * (v >> b & 1) + (v >> (b + 3) & 1)) for b in (2, 1, 0)) for v in range(64)
] + [(0, 0, 0)] * 192
COLS, ROWS = 80, 25
KEYS = {
    "down": 0x5000,
    "up": 0x4800,
    "left": 0x4B00,
    "right": 0x4D00,
    "enter": 0x1C0D,
    "esc": 0x011B,
    "pgdn": 0x5100,
    "pgup": 0x4900,
    "tab": 0x0F09,
}
# PIT channel 2 runs while port 61h bit 0 (its gate) is set; BIOSes time a block of DIV
# instructions with it to measure the CPU speed. The time passing is estimated from 486 cycle
# counts of the instructions run, for a 33 MHz CPU.
PIT_TICKS_PER_CYCLE = 1.193182 / 33
PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}


def _letters_in_font(font: bytes, h: int) -> bool:
    """Whether the letters of a font loaded by a program look like the ROM's at all (their
    pixels overlap; a setup's own bold style still does, data in the plane does not)."""
    rom, same, total = FONTS[h], 0, 0
    for c in range(0x41, 0x5B):
        for a, b in zip(font[c * h : c * h + h], rom[c * h : c * h + h]):
            same += (a & b).bit_count()
            total += (a | b).bit_count()
    return same >= 0.25 * total


def _solid_font_filled(font: bytes, h: int) -> bytes:
    """A font whose letters are all one solid block has the VGA ROM's glyphs put in their
    place: a setup that builds its font from a table POST never set up (WinBIOS 94 boards
    whose POST does not end: a778) has the right text, but draws every letter as a block."""
    glyphs = [font[c * h : c * h + h] for c in range(256)]
    block, count = collections.Counter(glyphs).most_common(1)[0]
    if count < 32 or sum(byte == 0xFF for byte in block) < h // 2:
        return font
    rom = FONTS[h]
    return b"".join(rom[c * h : c * h + h] if glyphs[c] == block else glyphs[c] for c in range(256))


UMOV_OPCODES = (b"\x0f\x10", b"\x0f\x11", b"\x0f\x12", b"\x0f\x13")
UMOV_REGS = (
    UC_X86_REG_EAX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EBX,
    UC_X86_REG_ESP,
    UC_X86_REG_EBP,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
)


class Stop(Exception):
    pass


PLANAR_MODES = {0x0D: (320, 200), 0x0E: (640, 200), 0x10: (640, 350), 0x12: (640, 480)}


def _rotate(value: int, count: int) -> int:
    count &= 7
    return (value >> count | value << (8 - count)) & 0xFF


# box-drawing characters by their arms (left, right, up, down) from the cell's middle
BOX_CHARS = {
    (1, 1, 0, 0): 0xC4,
    (0, 0, 1, 1): 0xB3,
    (0, 1, 0, 1): 0xDA,
    (1, 0, 0, 1): 0xBF,
    (0, 1, 1, 0): 0xC0,
    (1, 0, 1, 0): 0xD9,
    (1, 1, 0, 1): 0xC2,
    (1, 1, 1, 0): 0xC1,
    (0, 1, 1, 1): 0xC3,
    (1, 0, 1, 1): 0xB4,
    (1, 1, 1, 1): 0xC5,
}


def _box_char(lines: list[int]) -> int | None:
    """A cell made only of a horizontal line through its middle rows and/or a vertical line
    through its middle columns: the single-line box character with those arms."""
    h = len(lines)
    rows = [y for y in range(h) if lines[y] & 0x81]  # rows reaching the cell's edges
    vertical = 0x18
    if not rows and not any(lines[y] & vertical for y in (0, h - 1)):
        return None
    mid = [y for y in rows if abs(y - h // 2) <= 2]
    if rows and rows != mid:
        return None
    rest = [lines[y] & ~vertical & 0xFF for y in range(h) if y not in mid]
    if any(rest):
        return None
    left = any(lines[y] & 0x80 for y in mid)
    right = any(lines[y] & 0x01 for y in mid)
    up, down = bool(lines[0] & vertical), bool(lines[h - 1] & vertical)
    return BOX_CHARS.get((left, right, up, down))


# processor names shown by BIOSes of these hosts (Intel pads the name in front)
CPU_BRANDS = dict.fromkeys((0x2560, 0x2570, 0x2578), "Intel(R) Pentium(R) 4 CPU 3.00GHz")
# boards that take only a Pentium 4 and look its signature up (CPUID 1): a Northwood, family F
# model 2 stepping 7, brand index 9 (Fujitsu-Siemens D1326's Phoenix, 845: Unicorn's own
# signature 306C4h is not in its table, and it searches the table again for good)
P4_SIGNATURE_HOSTS = (0x1A30,)
CPU_BRANDS[0x1A30] = "Intel(R) Pentium(R) 4 CPU 2.00GHz"
KBC_REPLIES = (0xFA, 0xAA)  # acknowledge, self-test passed
# An interrupt the emulator delivers is entered through a stub written for it into the BIOS
# data area's inter-application communication area (0000:04F0-04FF, which no BIOS uses): the
# CPU itself pushes FLAGS, CS and IP and jumps to the handler, since the stack's hidden base
# may differ from SS * 16 (SS still holding a protected-mode selector's base after POST went
# back to real mode, Award 386), which only the CPU knows.
DELIVER_STUB_AT = 0x4F0
IDLE_LOOKS = 10  # looks at the empty key buffer before a paced key is pressed
RDMSR_RATIO = bytes.fromhex("66B92A0000000F32")  # mov ecx,2Ah / rdmsr
BOOT_SUM_HALT = re.compile(
    rb"\x66\x2E\x03\x44\xFC\xE2.\x75\xFE", re.S
)  # add eax,cs:[si-4] / loop / jne $
RDMSR_RATIO_PATCH = bytes.fromhex("66B8") + (15 << 22).to_bytes(4, "little") + bytes.fromhex("6699")
# "mov ecx,2Ch / rdmsr / shr eax,24 / cmp al,bl / je": a Pentium 4's ratio compared with the one
# wanted, else written to MSR 2Dh and the board reset (Intel D845WR's POST; the emulated CPU
# never reports the new ratio): the compare becomes "cmp al,al"
P4_RATIO_CMP = bytes.fromhex("66B92C0000000F3266C1E81838D874")
# "cmp byte es:[802Fh],1 / jne $-8": Intel's POST waits for its SMM handler (raised through the
# local APIC, ICR delivery mode SMI) to set a flag; there is no SMM here, the wait is left out
SMI_CX_WAIT = bytes.fromhex("F7D1E304F7D1EBF8")  # (see the software SMI in _out)
SMI_FLAG_WAIT = bytes.fromhex("26803E2F800175F8")
# "test byte es:[edi],1 (or 2) / je done / cmp dword es:[esi],0 / jne $-15": Dell's Phoenix 1.10
# moves SMBASE through an SMI to itself and waits for the handler to clear a flag in SMRAM
# (or for the APIC timer at FEE00390h to run out, which it takes for a failure): the je
# becomes a jmp (Dimension 3000)
DELL_SMI_WAIT = re.compile(
    rb"\x26\x67\xf6\x07[\x01\x02]\x74.\x66\x26\x67\x83\x3e\x00\x75\xf1", re.S
)
DELL_MARK = b"DELLXBIOS"
GOOD_GRID = 0.25  # share of cells recognised exactly on the grid of earlier screens


# a plane byte as 8 pixels holding its bits in the plane's place (bit 7 leftmost)
SPREAD = [
    [bytes((b >> (7 - x) & 1) << bit for x in range(8)) for b in range(256)] for bit in range(4)
]


def _cell_bits(planes: Sequence[bytes | bytearray], col: int, row: int, h: int) -> bytes:
    """The pixels of a 640-pixel-wide planar screen's text cell (8 x h, rows of h pixels)
    that are not in its most common color."""
    lines: list[list[int]] = []
    counts: collections.Counter[int] = collections.Counter()
    for y in range(h):
        o = (row * h + y) * 80 + col
        b = [p[o] for p in planes]
        line = [
            (b[0] >> 7 - x & 1)
            | (b[1] >> 7 - x & 1) << 1
            | (b[2] >> 7 - x & 1) << 2
            | (b[3] >> 7 - x & 1) << 3
            for x in range(8)
        ]
        lines.append(line)
        counts.update(line)
    bg = counts.most_common(1)[0][0]
    return bytes(sum((c != bg) << 7 - x for x, c in enumerate(line)) for line in lines)


def _font_score(
    base: int, found: dict[bytes, list[int]], src: int, cells: collections.Counter[bytes]
) -> int:
    """How many cells a font starting at base turns into letters and digits (weighted
    by how often each cell occurs; lower case counts most)."""
    total = 0
    for c, positions in found.items():
        for i in positions:
            if (i - base) % src == 0:
                ch = (i - base) // src
                if 0x61 <= ch <= 0x7A:
                    total += 3 * cells[c]
                elif 0x41 <= ch <= 0x5A or 0x30 <= ch <= 0x39:
                    total += 2 * cells[c]
                break
    return total


def guess_graphics_font(
    planes: Sequence[bytes | bytearray], data: bytes, heights: Sequence[int] = (14, 15, 16)
) -> tuple[bytes, int] | None:
    """The font a POST or setup drew its text with in 640x480 graphics (Gigabyte's AMI POST
    screens), found in the ROM's data without knowing the text: each cell's pixels are looked
    up in the data, the font's start is where most of them agree, and of the starts that
    differ by whole characters the one that turns most cells into letters and digits. AMI's
    graphics POST and setup may draw a font a pixel to the right and a line lower than its
    cells (MSI MS-6117, Zida ZX98: 8x14 glyphs in 16-line cells), so such layouts are tried
    too, with the bundled VGA fonts as well; the candidate that matches most cells exactly
    is taken."""
    cell_sets: dict[int, collections.Counter[bytes]] = {}

    def cells_of(h: int) -> collections.Counter[bytes]:
        if h not in cell_sets:
            cells: collections.Counter[bytes] = collections.Counter()
            for row in range(480 // h):
                for col in range(80):
                    m = _cell_bits(planes, col, row, h)
                    if sum(bin(b).count("1") for b in m) > 6:
                        cells[m] += 1
            cell_sets[h] = cells
        return cell_sets[h]

    def placed(glyphs: bytes, src: int, h: int, top: int, shift: int) -> bytes:
        """A font of src-line glyphs as drawn in h-line cells: top lines down, shifted right."""
        return b"".join(
            bytes(top)
            + bytes(b >> shift for b in glyphs[c * src : (c + 1) * src])
            + bytes(h - src - top)
            for c in range(256)
        )

    layouts = [(h, h, 0, 0) for h in heights]  # (cell height, glyph height, top, shift)
    layouts += [
        (h, src, top, shift)
        for h in heights
        for src in (14, 15, 16)
        if src <= h
        for top in range(h - src + 1)
        for shift in (0, 1)
        if (top, shift) != (0, 0)
    ]
    candidates: list[tuple[bytes, int]] = []
    for h, src, top, shift in layouts:
        cells = cells_of(h)
        if not cells:
            continue
        found: dict[bytes, list[int]] = {}
        for c, _ in cells.most_common(300):  # (a screen of graphics has thousands of cells)
            if any(c[:top]) or any(c[top + src :]) or shift and any(b & 1 for b in c):
                continue
            glyph = bytes(b << shift & 0xFF for b in c[top : top + src])
            positions: list[int] = []
            i = data.find(glyph)
            while i >= 0 and len(positions) < 20:
                positions.append(i)
                i = data.find(glyph, i + 1)
            found[c] = positions
        votes: collections.Counter[int] = collections.Counter()
        for positions in found.values():
            for i in positions:
                for ch in range(0x21, 0x7F):
                    votes[i - ch * src] += 1
        if not votes:
            continue
        base0, n = votes.most_common(1)[0]
        if n < 20:
            continue

        score = functools.partial(_font_score, found=found, src=src, cells=cells)
        base = max((base0 + src * k for k in range(-0x7F, 0x7F) if base0 + src * k >= 0), key=score)
        glyphs = data[base : base + 256 * src].ljust(256 * src, bytes(1))
        candidates.append((placed(glyphs, src, h, top, shift), h))
    for h, src, top, shift in layouts:  # the bundled VGA fonts in the same layouts
        if src in FONTS:
            candidates.append((placed(FONTS[src], src, h, top, shift), h))

    def exact(font: bytes, h: int) -> int:
        glyphs = {font[c * h : (c + 1) * h] for c in range(0x21, 0x7F)}
        return sum(n for cell, n in cells_of(h).items() if cell in glyphs)

    matched, font, h = max(
        ((exact(f, h), f, h) for f, h in candidates), key=lambda x: x[0], default=(0, b"", 0)
    )
    # (a screen with little text, a full-screen logo: no guess, so that a later screen is
    # looked at again - Zida BXi98)
    return (font, h) if matched >= 40 else None


def _planes_image(
    planes: Sequence[bytes | bytearray], palette: list, width: int, height: int
) -> Any:
    """16-color planes as a picture (the default EGA colors if the palette is all black)."""
    if not any(any(c) for c in palette):
        palette = [tuple(v * 255 // 63 for v in DEFAULT_DAC[p]) for p in DEFAULT_PALETTE]
    size = width // 8 * height
    data = 0
    for plane, spread in zip(planes, SPREAD):  # each plane's bits as one bit of 8 pixels
        data |= int.from_bytes(b"".join([spread[b] for b in plane[:size]]), "big")
    img = Image.frombytes("P", (width, height), data.to_bytes(width * height, "big"))
    img.putpalette([c for rgb in palette for c in rgb] + [0] * (768 - 48))
    return img.convert("RGB")


def _glyph_table(font: bytes, height: int) -> tuple[dict[int, int], list[int]]:
    """Exact lookup (glyph bitmap as an integer -> character) and the list for near matches;
    the first character wins (e.g. space before NUL and FFh)."""
    exact: dict[int, int] = {}
    glyphs: list[int] = []
    for ch in range(256):
        bits = int.from_bytes(font[ch * height : ch * height + height], "big")
        glyphs.append(bits)
        if ch in (0, 0xFF):
            continue
        exact.setdefault(bits, ch)
    return exact, glyphs


def _flush_tb(uc: Uc) -> None:
    """Drops the code Unicorn has translated (a method it adds at run time, which mypy
    does not see)."""
    uc.ctl_flush_tb()  # type: ignore[attr-defined]


# Each time a run stops at its time limit, for whoever asked (bios_setup_screens): that limit
# is on the clock, so how far a run gets depends on how busy the machine is
time_limits_hit: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "time_limits_hit", default=None
)


class BiosEmulator:
    # (attributes first set to None or to an empty container in __init__)
    post_codes_seen: set[int]
    smbus_base: int | None
    sio_regs: dict[tuple, int]
    crtc: dict[int, list[Any]]  # port -> [index, registers]
    cpu_brand: str | None
    smbus_devices: dict[int, bytearray]
    vga_card_rom: bytes | None
    kbc_queue: list[int]
    fdc_cmd: list[int]
    fdc_results: list[int]
    fdc_st0: int | None
    graphics_font: tuple[bytes, int] | None
    graphics_grid: tuple[int, int, int] | None
    pit0_mode: int | None
    pit0_latch: int | None
    pit1_latch: int | None
    pit2_latch: int | None
    pit2_mode: int | None
    pit_hook: int | None
    block_cycles: dict[tuple[int, int], int]
    div_sites: set[int]
    div_new: list[int]
    div_guard: int | None
    wanted_hooks: set[str]
    retired_hooks: list[int]
    aux_hook: int | None
    ali_alias_hook: int | None
    dram_hook: int | None
    dram_saved: bytes | None
    hwmon_polled: int | None
    shadow_before: list[bool] | None
    prefetched: tuple[int, bytes, bytes] | None
    hw_keys: list[int]
    irq_hook: int | None

    def __init__(
        self,
        rom: bytes,
        keys: list[int] | None = None,
        cmos: bytes | None = None,
        max_instructions: int = 30_000_000,
        timer_irq: bool = False,
        hints: bytes = b"",
        ram_mb: int = 16,
        host_id: int = 0,
    ):
        # timer_irq: raise IRQ 0 every TIMER_SLICE instructions (POST tests that wait for it).
        # Off by default: restarting the emulation loses hidden segment state (unreal mode),
        # which breaks some memory tests.
        self.timer_irq = timer_irq
        rom = _boot_sum_skipped(rom)
        full_rom = rom[-0x100000:]  # the whole flash chip is seen at the top of the 4 GB space
        # hints: unpacked modules of a compressed BIOS, searched for its chipset's PCI IDs
        self.pci_devices = _pci_devices(rom + hints)
        if host_id and (0, 0) not in self.pci_devices:
            # (a BIOS whose packed code hides its chipset's IDs: without a host bridge its
            # memory boundaries read FFh, about 2 GB to clear: Dell WorkStation 400)
            host_cfg = bytearray(256)
            host_cfg[0:4] = struct.pack("<HH", 0x8086, host_id)
            host_cfg[8:12] = struct.pack("<I", 0x060000 << 8 | 1)
            self.pci_devices[(0, 0)] = host_cfg
        # code in the unpacked modules that reads the CPU's bus ratio from an MSR, which the
        # emulated CPU leaves 0 (and the BIOS divides by it): patched where it lands in memory
        self.msr_patches = (
            (hints + rom).count(RDMSR_RATIO) > 0
            or P4_RATIO_CMP in hints + rom
            or SMI_FLAG_WAIT in hints + rom
        )
        self.post_codes_seen = set()  # memory is searched once per POST code, not per write
        # SMBus host controller (ICH/PIIX4 registers) with a DIMM's SPD EEPROM at address 50h
        self.smbus_base, self.smbus, self.smbus_busy = None, bytearray(16), 0
        self.smbus_block_left = -1  # bytes of a block write still to send (-1: none running)
        self.smbus_block_polls = 0  # status reads while the last BYTE_DONE waits (_in)
        # a Super I/O's configuration registers behind index/data ports 2Eh/2Fh and 4Eh/4Fh:
        # what was written reads back (registers 30h and up per logical device, register 07h);
        # the rest reads FFh as before (no chip found). Fujitsu-Siemens D1326's Phoenix clears
        # bit 5 of logical device 7's register F0h and waits until it reads clear.
        self.sio_index, self.sio_regs = {0x2E: 0, 0x4E: 0}, {}
        self.smbus_block_read = b""  # the bytes of a block read still to come
        # ICH power management I/O (PMBASE, LPC register 40h): registers read back, status
        # bits (e.g. TCO "intruder detected") are clear, the ACPI PM timer (+08h) runs
        self.pm_regs, self.pm_timer = bytearray(256), 0
        # VT82C686's SMBus host in its PM I/O space (+E0h-EFh, see _via_smbus): registers, the
        # state of a transfer (0 idle, 1 busy, 2 done) and the byte read
        self.via_smb, self.via_smb_state, self.via_smb_data = bytearray(16), 0, 0
        host = self.pci_devices.get((0, 0))
        host_id = int.from_bytes(bytes(host[2:4]), "little") if host is not None else 0
        self.spd = {
            0x50: (
                _spd_ddr(ram_mb)
                if host_id in DDR_HOSTS
                else _spd(ram_mb, pc133=host_id in PC133_HOSTS)
            )
        }
        self.spd_asked = False
        self.smbus_devices = {}  # other SMBus devices: address -> registers (_smbus_write)
        self.smbus_result, self.smbus_idle = 0, 0  # (see _in: an end bit cleared too early)
        self.pam_base = 0x90 if host_id in PAM_AT_90 else 0x59
        self.vga_card_rom = None
        if host_id in VGA_CARD_HOSTS and not any(
            c[0x0B] == 0x03 for c in self.pci_devices.values()
        ):
            dev, fn, vendor, device = VGA_CARD
            cfg = bytearray(256)
            cfg[0:4] = struct.pack("<HH", vendor, device)
            cfg[8:12] = struct.pack("<I", 0x030000 << 8 | 0x01)
            self.pci_devices[(dev, fn)] = cfg
        if len(rom) > 0x20000:
            rom = rom[-0x20000:]  # the top 128 KB is what the CPU sees below 1 MB
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        # the interrupt table as after a reset (Unicorn starts with its limit at 0)
        self.uc.reg_write(UC_X86_REG_IDTR, (0, 0, 0x3FF, 0))
        # 16 MB of RAM (boot blocks and memory sizing use 32-bit addresses above 1 MB) and
        # the ROM mirrored at the top of the 4 GB address space, as on real hardware
        # The 64 KB above 1 MB are mapped onto low memory while the A20 gate is off (8042
        # output port bit 1 or port 92h bit 1), as POST's gate A20 test expects.
        self._low = ctypes.create_string_buffer(0x100000)
        self._hma = ctypes.create_string_buffer(0x10000)
        self.uc.mem_map_ptr(0, 0x100000, UC_PROT_ALL, ctypes.addressof(self._low))
        self.uc.mem_map_ptr(0x100000, 0x10000, UC_PROT_ALL, ctypes.addressof(self._hma))
        self.ram_top = ram_mb << 20  # ram_mb: the size of the DIMM in the SPD data too
        self.uc.mem_map(0x110000, self.ram_top - 0x110000)
        self.a20 = True
        # the gate is open when the 8042 output port (bit 1) or port 92h (bit 1) opens it
        self.a20_kbc, self.a20_fast = True, False
        self.kbc_command, self.kbc_queue, self.kbc_command_byte = 0, [], 0x41
        # the 8042's input port (command C0h): jumpers and switches; bit 2 is Acer's
        # password jumper (set: Ctrl-Alt-Esc asks for the password first)
        self.kbc_input_port = 0xBF
        # the self-test (AAh) takes a moment: its reply shows after this many status reads
        self.kbc_busy = 0
        # status reads that still show the output buffer empty after a byte of a reply was
        # read: the keyboard sends the next one a moment later (Dell's Phoenix waits for
        # the buffer to be empty after the acknowledgement)
        self.kbc_gap = 0
        # the input buffer is full for a moment after a command is written, until the 8042
        # has taken it: early Award 286 BIOSes (PETER286, BABY-286) wait for that bit after
        # the self-test command and treat a controller that never shows it as missing
        self.kbc_ibf = False
        # CF9h resets done in place (the CPU only, memory and chipset kept) before one ends
        # the run: Acer's boot block resets once after setting a CMOS flag
        self.cf9_resets_in_place = 0
        self.event_wait_over = False  # (see _intr)
        self.kbc_mode = 0x01  # AMI keyboard controller mode (CAh/CBh): PS/2
        self.kbc_ram = bytearray(32)  # the 8042's internal RAM (byte 0: the command byte)
        # AMI keyboard controller version (A1h): "H" (with "F" WinBIOS 12/15/93, Jetway
        # J-403TG, tests A9h, rewrites the command byte and restarts POST, again and again)
        self.kbc_version = 0x48
        self.cpu_reset_pending = False
        # after an in-place reset with the F000 segment shadowed, CS still has the base
        # FFFF0000h of a reset (the ROM at 4 GB) until the first far jump (_cpu_reset)
        self.cs_alias, self.alias_hook = False, None
        self.eip_restored = True  # (see _go: a restart above 64 KB in protected mode)
        # the PIT's ticks per emulated cycle (a 33 MHz CPU; a driver may set another: NCR)
        self.pit_ticks_per_cycle = PIT_TICKS_PER_CYCLE
        # the least a channel-0 latch advances the count (see _out; NCR sets 0Ch)
        self.pit0_latch_floor = 0x25
        self.smi_ack_pending = False  # Dell's SMI waits to skip (DELL_SMI_WAIT)
        self.ran_in_ram, self.flush_pending = False, False  # (see _out, port 80h)
        # SMRAM (see SMRAM_REGS): open, a change still to apply, and what the side not in
        # view holds (the video memory while SMRAM is open, else the SMRAM)
        self.smram_open, self.smram_pending, self.smram_hidden = False, False, bytes(0x20000)
        # a "jmp $" with interrupts off where the hardware resets the PC (ASRock boot blocks
        # program the clock generator over the SMBus and wait for the reset that follows)
        self.spin_resets = 0
        # floppy disk controller (765/82077) without disks: commands and results, the drives'
        # cylinders, IRQ 6 after reset, recalibrate and seek (POST tests the controller)
        self.fdc_cmd, self.fdc_results, self.fdc_pcn = [], [], [0, 0, 0, 0]
        self.fdc_pending, self.fdc_dor, self.fdc_reset_sense, self.fdc_st0 = False, 0, 0, None
        self.fdc_waking = 0  # status reads after the reset that still find it not ready
        # a restart through the keyboard controller resets only the CPU (MR BIOS restarts POST
        # that way); otherwise it stops the run as "reset", for a new POST
        self.kbc_reset_in_place = False
        self.kbc_last = 0xFF
        # rtc_frozen: the clock (RTC seconds, timer ticks) stops, for a setup redrawing its
        # clock lines on every page
        self.rtc_frozen = False  # power-on: system flag 0
        self.uc.mem_write(0x100000 - len(rom), rom)
        if len(rom) == 0x10000:  # many boards mirror a 64 KB BIOS at E0000 too
            self.uc.mem_write(0xE0000, rom)
        self.uc.mem_map(0xFFF00000, 0x100000)
        self.uc.mem_write(0x100000000 - len(full_rom), full_rom)
        # Above the RAM there is no memory: writes are lost and reads return FFh, which is how
        # memory sizing finds the end of RAM. Pages are mapped on first access.
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._open_bus_map)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read, None, self.ram_top, 0xFFEFFFFF)
        self.smi_flag_wait = SMI_FLAG_WAIT in hints + rom
        if self.smi_flag_wait or DELL_MARK in full_rom:  # (the wait comes after the SMI)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._apic_smi, None, 0xFEE00300, 0xFEE00303)
        # Time passes while a program polls the BIOS tick counter (0040:006C), as if the
        # timer interrupt were running, so "wait N ticks" delay loops come to an end
        self.tick_reads = 0
        self.uc.hook_add(UC_HOOK_MEM_READ, self._tick_read, None, 0x46C, 0x46F)
        # programs that look at the BIOS key buffer themselves instead of asking INT 16h
        # (PhoenixBIOS 4.0 Release 6.0.6 setup, ASUS SP-AX): waiting is seen there too
        self.uc.hook_add(UC_HOOK_MEM_READ, self._buffer_look, None, 0x41A, 0x41B)
        # INT 09h set up: a keyboard interrupt that had no handler yet can come now
        self.uc.hook_add(UC_HOOK_MEM_WRITE, lambda *a: self._irq1_again(), None, 0x24, 0x27)
        self.keys = list(keys or [])
        self.cmos = bytearray(cmos or bytes(128))
        self.cmos_index = 0
        self.cmos_hi, self.cmos_hi_index = bytearray(128), 0  # upper 128 bytes (ports 72-75h)
        # VGA planar graphics (16-color modes): four 64 KB planes behind A0000-AFFFF, written
        # through the sequencer map mask and the graphics controller (write modes 0-3, latches)
        self.video_mode = 3
        self.graphics_font = None  # (font, height) a program draws its text with, if not VGA's
        self.graphics_grid = None  # the grid that recognised a screen well (kept on restore)
        self.vga_planes = [bytearray(0x10000) for _ in range(4)]
        self.vga_latch, self.vga_seq, self.vga_gc = [0] * 4, bytearray(8), bytearray(16)
        self.vga_seq[2], self.vga_gc[8] = 0x0F, 0xFF  # as the VGA BIOS leaves them
        self.vga_seq[2], self.vga_gc[8], self.vga_index = 0x0F, 0xFF, [0, 0]
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._vga_write, None, 0xA0000, 0xAFFFF)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._vga_read, None, 0xA0000, 0xAFFFF)
        self.port61 = 0
        self.port63 = 0x10  # bit 4: a keyboard clock line some 386 boards read at 63h
        self.vga_status = 0
        self.palette_regs, self.dac = list(DEFAULT_PALETTE), list(DEFAULT_DAC)
        self.blink, self.dac_index = True, [0, 0]
        self.char_height, self.scan_lines = 16, 400  # set by INT 10h AH=12h BL=30h + mode set
        self.pit_reload = self.pit_cycles = 0
        self.pit_read_high = self.pit_write_high = False
        self.pit2_latch = None  # channel 2's count as latched (43h <- 80h), until read
        self.pit0_access = self.pit2_access = 3  # bytes read and written: 1 low, 2 high, 3 both
        self.pit2_mode = None  # channel 2's mode once set (2 and 3 reload: periodic)
        self.pit_hook, self.pit_active, self.pit_used_in_slice = None, False, False
        # a gate left open with nobody reading the counter: the hook is parked (it costs a call
        # for every block) and comes back when the program uses channel 2 again
        self.pit_idle, self.pit_parked, self.no_hook = 0, False, None
        self.key_idle, self.key_gap = 0, 0
        self.reply_grace = 0  # blocks a command reply waits for its poll before IRQ 1
        self.irq1_in_service = False
        self.idle_looks = 0  # INT 16h looks at an empty buffer since the last key
        self.disasm, self.block_cycles = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16), {}
        # DIVs that faulted once get a hook that keeps them from faulting again: Unicorn never
        # ends an exception that a hook took over, so a second fault would be a double fault
        # and a third shuts the CPU down (Fujitsu-Siemens D1185's Phoenix)
        self.div_sites, self.div_new, self.div_guard = set(), [], None
        self.disasm_detail = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        self.disasm_detail.detail = True
        self.in_emulation, self.wanted_hooks = False, set()
        # Hooks are never removed inside a callback (Unicorn may still be using them): they are
        # retired here and removed between two runs; a retired hook does nothing meanwhile.
        self.stale_irq0 = 0  # calls of a retired irq0_hook since the last restart
        self.buffer_looks = 0  # looks at an empty key buffer in a row
        self.irq1_blocked = 0  # calls of the keyboard hook while IRQ 1 is held back
        self.irq1_parked = False  # the keyboard hook removed for that, to come back
        self.retired_hooks, self.hook_generation = [], {
            "pit_hook": 0,
            "irq_hook": 0,
            "irq0_hook": 0,
            "dram_hook": 0,
            "aux_hook": 0,
            "alias_hook": 0,
        }
        # IRQ 12 for a mouse reply in the 8042 (see _aux_irq); aux_mark: kbc_reads when the
        # last one was raised (once per byte)
        self.aux_hook, self.aux_mark = None, -1
        # ALi M1489/M6117 memory sizing (register 10h = F8h): the first 16 KB seen again
        # every 4 KB (_ali_low_alias, installed only once a ROM sets that up)
        self.ali_alias_hook = None
        # DRAM row 0 set to size 0 (ROW_SIZED_HOSTS): the memory reads as nothing meanwhile,
        # what it held is put back when the row returns
        self.dram_hook, self.dram_saved = None, None
        self.row_aliased = 0  # end of DRAM row 0 while the RAM is seen again in it (0: off)
        host = self.pci_devices.get((0, 0))
        self.row_shift = (
            ROW_SIZED_HOSTS.get(int.from_bytes(bytes(host[2:4]), "little")) if host else None
        )
        # PIT channel 0 (system timer, IRQ 0; only with timer_irq): mode, whether it counts,
        # and a raised IRQ 0 waiting until the PIC and the CPU accept it
        self.pit0_mode, self.pit0_running, self.pit0_write_high = None, False, False
        self.irq0_pending, self.irq0_hook = False, None
        self.rtc_pending, self.rtc_flags = False, 0  # RTC periodic interrupt (IRQ 8), register C
        self.rtc_flag_reads = 0  # reads of register C since its flags were last set by time
        self.rtc_a_reads = 0  # reads of register A (its update-in-progress bit comes and goes)
        self.pit0_count, self.pit0_latch, self.pit0_read_high = 0xFFFF, None, False
        # channel 1 (DRAM refresh): count, reload, access mode (1 low, 2 high, 3 both), latch
        self.pit1_count, self.pit1_reload, self.pit1_access, self.pit1_mode = 0x12, 0x12, 1, 2
        self.pit1_latch, self.pit1_read_high, self.pit1_write_high = None, False, False
        # channel 0 timed while a program latches it: cycles counted by the PIT block hook
        self.pit0_timing, self.pit0_cycles, self.pit0_mark = False, 0, 0
        self.max_instructions = max_instructions
        self.max_seconds = MAX_SECONDS
        self.key_polls = 0
        self.ticks = 0
        self.rtc_reads = 0
        self.stopped_reason = ""
        self._init_bda()
        self._clear_screen(0x07)
        for height, addr in FONT_ADDRS.items():
            self.uc.mem_write(addr, FONTS[height])
        self._video_rom()
        if (2, 0) in self.pci_devices and self.pci_devices[(2, 0)][0:4] == struct.pack(
            "<HH", 0x1234, 0x1111
        ):
            self.vga_card_rom = self._pci_option_rom(0x1234, 0x1111)
        self.crtc = {0x3B4: [0, bytearray(32)], 0x3D4: [0, bytearray(32)]}  # index, registers
        self.dma_pages = bytearray(16)
        # the page registers also at 481h-48Fh (always: Intel's 1993 Phoenix BIOS Plus tests
        # them) and, for a driver that asks, at 401h-40Fh and 4C1h-4CFh (Phoenix 4.03 M1:
        # a table of 21 page ports)
        self.dma_pages_ext = False
        # 8237 DMA controllers: 8 address/count registers each (16 bit, written and read low
        # byte then high byte through a flip-flop)
        self.dma_regs = [[0] * 8, [0] * 8]
        self.dma_flipflop = [False, False]
        # Shadow RAM for C0000-FFFFF as Intel 430/440 chipsets have it (PAM registers 59h-5Fh of
        # PCI 0:0): read from the ROM or RAM, writes dropped or kept, in 16 KB blocks. Only used
        # once the code accesses PCI configuration space; older BIOSes see plain RAM there.
        self.pci_addr, self.pci_used, self.pam = 0, False, [0] * 7
        self.pci_cse, self.pci_forward = 0, 0  # configuration mechanism #2 registers
        self.hwmon_index, self.apm_status = 0xFF, 0
        # Headland HT101/102 (286 boards, about 1988): index at 1EDh, data at 1EFh, read back
        self.headland_index, self.headland = 0, bytearray(256)
        self.hwmon_polled, self.hwmon_polls = None, 0  # (the fan count polled on and on)
        self.reset_control = 0  # port CF9h
        self.umc = self.pci_devices.get((16, 0), b"")[0:2] == bytes.fromhex("6010")
        if self.umc:  # after reset: reads from the ROM, writes to the RAM behind it
            self.pam = [0x20] + [0x22] * 6
        self.sis496 = self.pci_devices.get((5, 0), b"")[0:4] == bytes.fromhex("39109604")
        # ALi M1489 (486, configured through ports 22h/23h, unlocked with C5h in register
        # 03h before each access): found by that unlock, not in the ROM
        self.ali, self.ali_unlocked, self.ali_index = False, False, 0
        self.neat = self.not_neat = False  # C&T NEAT shadow RAM on (see _ali_write)
        # UMC UM8498F behind 28h/2Ah, found by its unlock (see _um8498_out): 0 locked, 2 open
        self.um8498_phase, self.um8498_index, self.um8498_regs = 0, 0, bytearray(256)
        self.scat = False  # C&T F82C235 registers behind 22h/23h (set by chips_setup)
        self.serverworks = False  # host register 73h as shadow control (set by ami7_setup)
        # the flash's other 128 KB (set by acer_setup), its bank register: _flash_bank
        self.flash_low, self.flash_upper = b"", True
        self.flash_sio_open, self.flash_sio_index = 0, 0
        self.scat_regs = bytearray(b"\xff" * 256)
        self.scat_regs[0x40], self.scat_regs[0x45], self.scat_regs[0x48] = 1, 0x37, 0xC0
        self.cr0_at_reset = 0  # (set by a driver whose POST checks it: chips_setup)
        self.fill_solid_font = False  # see screen() (set by winbios_setup)
        self.mylex_counter = False  # port 800h counts bytes (set by mylex_setup)
        self.protect_socket = False  # see _protect (set by mr_setup)
        self.sis471 = False  # SiS 85C471 shadow RAM in register 52h (see _ali_write)
        self.below50 = False  # a register under 50h written behind 22h/23h (not a SiS 85C471)
        self.msr_patch_end = 0xFE000  # where _patch_msr_reads stops patching
        # every 8042 reply comes a moment after its command (see _kbc_command; Mylex MVI486)
        self.kbc_reply_later = False
        self.invalid6 = 0  # invalid instructions handed to the ROM's INT 06h handler
        # a write through CS in protected mode (into the ROM): the CPU raises #GP there,
        # Unicorn checks no segment types; the address of the instruction, for the run loop
        self.gp_at: int | None = None
        self.io_reads: dict[int, int] = {}  # ports a board's set-up answers with fixed values
        self.ali_regs = bytearray(256)
        self.opti_regs = bytearray(256)  # OPTi: data port 24h behind index 22h
        self.opti_wrote = False  # (reads of 24h answer only once POST has used it)
        self.via_index, self.via_regs = 0, bytearray(256)  # VIA: ports A8h/A9h
        self.via_wrote = False  # (the same for reads of A9h)
        if self.sis496:  # AMI sizes each DRAM bank at address 0 with the others' ends at 0
            self.uc.hook_add(UC_HOOK_MEM_READ, self._sis496_bank_read, None, 0, 0xF)
        self.rom_view = bytes(self.uc.mem_read(SHADOW_BASE, 0x40000))
        self.shadow = bytearray(0x40000)
        self.shadow_used = [False] * 16  # anything written to a block's shadow RAM yet
        self.shadow_newer = [False] * 16  # shadow RAM written while a stale view is shown
        self.shadow_before = None  # what was readable before a pending register change
        self.pam_valid = True  # False once the chipset turns out not to have Intel PAM
        self.pam_at_59 = False  # (an i810 host whose BIOS uses 59h-5Fh: see _pci_write)
        # VIA: a host bridge the ROM names has shadow RAM through 61h-63h (Intel's PAM
        # registers 59h-5Fh are DRAM settings there); beside an AMD host, and for AMI BIOSes
        # that name no chipset (which may be SiS boards, whose 61h-63h are DRAM settings),
        # plain RAM. The SMBus where boot blocks expect it before they set it
        via_host = self.pci_devices.get((0, 0), b"")
        self.via_shadow = via_host[0:2] == b"\x06\x11" and _named(
            rom + hints, 0x1106, int.from_bytes(bytes(via_host[2:4]), "little")
        )
        # VT82C686: its PM I/O where the chip leaves it (5000h) for BIOSes that never set it
        # (MSI MS-6316 reads 50CAh, wants 2020h clear, and its SMBus at +E0h)
        south = self.pci_devices.get((7, 0), b"")
        self.via_pm_base = 0x5000 if bytes(south[0:4]) == b"\x06\x11\x86\x06" else 0
        # SiS 96x / ALi M1563 (ami7chip): their SMBus registers, end flag owed to a poll;
        # only the sets _sis_mutiol_devices and _ali_m1563_devices build (SiS 5597 boards
        # are SiS too, with PAM and without this SMBus)
        chip_host = bytes(self.pci_devices.get((0, 0), bytearray(4)))
        chip_south = bytes(self.pci_devices.get((3, 0), bytearray(4)))
        sis = chip_host[0:2] == b"\x39\x10" and (
            int.from_bytes(chip_host[2:4], "little") in SIS_MUTIOL_HOSTS
        )
        ali = (
            int.from_bytes(chip_south[0:2], "little") in ALI_VENDORS
            and int.from_bytes(chip_south[2:4], "little") in ALI_SOUTH
        )
        self.chip_smbus = "sis" if sis else "ali" if ali else ""
        self.chip_smbus_end, self.chip_smbus_bar = False, bytearray(2)
        if self.chip_smbus:
            self.pam_valid = False  # (no Intel PAM: C0000-FFFFF plain RAM)
        if any(c[0:2] == b"\x06\x11" for c in self.pci_devices.values()):
            self.smbus_base = 0x400
            self.pam_valid = False  # plain RAM; with a VIA host until the BIOS sets 61h-63h
            # (AMD Athlon boards shadow through the CPU's fixed-range MTRRs instead, GA-7ZXE)
        if self.via_shadow:
            self.pam_base = 0x100
        # (not beside AMD's own north bridges, whose boards ran as plain RAM before: k71001)
        self.k7_mtrr = (
            K7_SYSCFG in rom + hints
            and self.pam_base != 0x90
            and self.pci_devices.get((0, 0), b"\0\0")[0:2] != b"\x22\x10"
        )
        if self.k7_mtrr:  # reads from the ROM until the MTRRs send them to DRAM
            self.via_shadow, self.pam_valid, self.pam_base = False, True, 0x100
            self.pci_used = True
        # Acer's "PCI/ISA P54C BIOS" (V50LC, R02-E1): its ALi host bridge shadows through a mask
        # of 16 KB blocks in 4Ch/4Dh and a direction in 4Ah bits 1-2 (read off
        # POST's own use, the ID is a guess)
        self.ali_shadow: bytearray | None = None
        if ALI_P54C in rom:
            bridge = bytearray(256)
            bridge[0:4] = bytes([0xB9, 0x10, 0x11, 0x15])
            bridge[8:12] = bytes([0x00, 0x00, 0x06, 0x00])
            self.pci_devices[(0, 0)] = bridge
            self.ali_shadow, self.pam_base, self.pam_valid = bridge, 0x100, True
        self.pam_off_pending = False
        # PAM given up for a chipset the bot does not know (_pam_off): with keep_rom set the
        # blocks whose shadow RAM was never opened stay ROM, as on the board (Acer
        # V62XC0S1's memory test would otherwise clear its own BIOS; for all
        # families it cost 12 boards)
        self.pam_gone, self.keep_rom = False, False
        self.prefetched = None  # (address, bytes as fetched, bytes of the view beneath them)
        self.hw_keys, self.hw_keys_when, self.irq_hook, self.pic_mask = [], b"", None, 0xFF
        self.pic2_mask = 0xFF
        self.bios_keyboard, self.irq_pending, self.kbc_aux = False, False, False
        self.bootstrap = False  # INT 19h called: the next disk access means booting
        # no disk to boot from: the bootstrap's INT 13h calls fail (drive not ready) instead
        # of ending the run, for BIOSes that offer setup when there is nothing to boot
        # (Quadtel: "F1 ==> Boot , F2 ==> SETUP"); counted, so a retry loop still ends
        self.boot_without_disk, self.boot_failures = False, 0
        self.kbc_reads, self.irq_read_mark = 0, -1  # port 60h reads; IRQ 1 raised for a byte
        self.hw_paced, self.key_wanted, self.hw_prev = False, False, 0
        self.key_wait_blocking = False
        self.protected = [False] * 16
        self.uc.hook_add(UC_HOOK_MEM_WRITE_PROT, self._shadow_write, None, SHADOW_BASE, 0xFFFFF)
        if self.k7_mtrr:  # the reset vector: where the boot block goes on in the shadow copy
            self.uc.hook_add(
                UC_HOOK_BLOCK, lambda uc, a, sz, u: self._k7_poll(), None, 0xFFFF0, 0xFFFF0
            )
            self._protect()
        # No chipset found and nothing packed in the ROM (an ISA board's plain BIOS): E0000-
        # FFFFF stays ROM, writes there are lost (FIC 486-VAL's Award 4.20 runs over a few
        # data bytes that add to [bx+si] with DS in F000, then fails its ROM checksum)
        # (only Award's: Acer's own BIOS keeps data there, its video type went to CGA;
        # the AMI Q&A setup's and old Phoenix's write over F0000-FFFFF too, so that half is
        # shadow RAM for them: Armas 386DX's memory test, DEC DECpc 400 MT)
        isa_plain = (
            not self.pci_devices
            and len(rom) <= 0x20000
            and b"-lh5-" not in rom
            and b"AMIBIOSC" not in rom
        )
        f_half = isa_plain and (
            # (not PhoenixBIOS 4.0, BCPSYS: its text setups lost their pages so)
            (b"Phoenix Technologies" in rom and b"BCPSYS" not in rom)
            or (b"SETUP or DIAGS (1/2)?" in rom and b"Are these options correct" in rom)
        )
        if isa_plain and (b"Award" in rom or f_half):
            self.pam, self.pam_valid, self.pam_base = (
                [0x00, 0x33, 0x33, 0x33, 0x33, 0x00, 0x00],
                True,
                0x100,
            )
            if f_half and b"Award" not in rom:
                self.pam[5] = 0x33
            self.pci_used = True
            self.shadow[:] = self.uc.mem_read(SHADOW_BASE, 0x40000)
            self.shadow_used = [True] * 8 + [False] * 8
            self._protect()
        self.uc.hook_add(UC_HOOK_BLOCK, self._past_segment_end, None, 0x100000, 0xFFFEFFFF)
        self.uc.hook_add(UC_HOOK_INTR, self._intr)
        self.test_regs = [0] * 8  # 486 test registers TR3-TR7 (cache and TLB tests)
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self._invalid)
        self.uc.hook_add(UC_HOOK_INSN, self._in, None, 1, 0, UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, self._out, None, 1, 0, UC_X86_INS_OUT)
        self.cpu_brand = CPU_BRANDS.get(host_id)
        self.cpu_p4_signature = host_id in P4_SIGNATURE_HOSTS
        # a BIOS that knows only AMD processors (Socket A: no "GenuineIntel" in it) gets an
        # Athlon; with Intel's vendor GA-7ZMMH's AMI found no CPU entry and jumped through an
        # index of FFh
        self.cpu_amd = b"AuthenticAMD" in rom + hints and b"GenuineIntel" not in rom + hints
        if self.cpu_amd:
            self.cpu_brand = "AMD Athlon(tm) Processor"
        if self.cpu_brand is not None:
            self.uc.hook_add(UC_HOOK_INSN, self._cpuid, None, 1, 0, UC_X86_INS_CPUID)

    # --- machine state --------------------------------------------------------------------

    def _init_bda(self) -> None:
        w = self.uc.mem_write
        w(0x410, struct.pack("<H", 0x0021))  # equipment: color 80x25, floppy
        w(0x413, struct.pack("<H", 640))  # base memory KB
        w(0x449, bytes([3]))  # video mode 3
        w(0x44A, struct.pack("<H", COLS))
        w(0x44C, struct.pack("<H", COLS * ROWS * 2))
        w(0x463, struct.pack("<H", 0x3D4))
        w(0x484, bytes([ROWS - 1]))
        w(0x485, struct.pack("<H", 16))
        # every interrupt vector points to an IRET in a free spot (hooked INTs never get there)
        w(0x500, b"\xcf")
        w(0, struct.pack("<HH", 0x500, 0) * 256)

    def _past_segment_end(self, uc: Uc, address: int, size: int, _user: object) -> None:
        # in real mode IP wraps at 64 KB; Unicorn lets it grow, so code that runs through empty
        # memory would go on through all of RAM: stop it there
        if not uc.reg_read(UC_X86_REG_CR0) & 1 and uc.reg_read(UC_X86_REG_EIP) > 0xFFFF:
            self.stopped_reason = (
                f"code ran past the end of segment " f"{uc.reg_read(UC_X86_REG_CS):04X}"
            )
            uc.emu_stop()

    def _open_bus_map(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> bool:
        if access == UC_MEM_FETCH_UNMAPPED:  # running into nowhere: stop (a real CPU would
            self.stopped_reason = f"code ran off into unmapped memory at {addr:X}"  # have wrapped)
            return False
        if not self.ram_top <= addr < 0xFFF00000:
            return False
        uc.mem_map(addr & ~0xFFFFF, 0x100000)  # 1 MB of "nothing"
        return True

    def _advance_ticks(self, ticks: int) -> None:
        count = (struct.unpack("<I", self.uc.mem_read(0x46C, 4))[0] + ticks) % 0x1800B0
        self.uc.mem_write(0x46C, struct.pack("<I", count))
        self.ticks += ticks

    def _buffer_look(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        """A look at the key buffer's head pointer: many in a row at an empty buffer, with no
        key on its way, is a program waiting for a key. Not for memory tests that scan RAM
        with string instructions (a 386 Chips & Technologies AMI tests 0-640 KB so before it
        shows anything)."""
        try:
            code = bytes(uc.mem_read(self._code_address(), 4))
        except UcError:
            code = b""
        if code.lstrip(bytes(PREFIXES - {0xF2, 0xF3}))[:1] in (b"\xf2", b"\xf3"):
            return
        head, tail = struct.unpack("<HH", uc.mem_read(0x41A, 4))
        makes = any(b < 0x80 and b not in (0xE0, 0xE1) for b in self.hw_keys)
        if head != tail or any(b not in KBC_REPLIES for b in self.kbc_queue):
            self.buffer_looks = 0
            return
        self.buffer_looks += 1
        if self.buffer_looks >= 50 and makes and not self.key_wanted:  # the next paced key
            self.buffer_looks = 0
            self.key_wanted, self.key_wait_blocking, self.key_idle = True, False, 0
            if self.irq_hook is None:
                self._want_hook("irq_hook")
        elif self.buffer_looks > 5_000 and not makes and not self.stopped_reason:
            self.buffer_looks = 0
            self.stopped_reason = "polling the keyboard"
            uc.emu_stop()

    def _tick_read(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        if addr != 0x46C or self.rtc_frozen:
            return
        try:  # not for memory tests that scan RAM with string instructions (rep scasd,
            # or a plain scasw in a loope: NCR 3315)
            code = bytes(uc.mem_read(self._code_address(), 6))
        except UcError:
            code = b""
        body = code.lstrip(bytes(PREFIXES - {0xF2, 0xF3}))
        if body[:1] in (b"\xf2", b"\xf3") or (body[:1] and 0xA4 <= body[0] <= 0xAF):
            return
        self.tick_reads += 1
        if self.tick_reads % 4 == 0:
            count = (struct.unpack("<I", uc.mem_read(0x46C, 4))[0] + 1) % 0x1800B0  # one day
            uc.mem_write(0x46C, struct.pack("<I", count))

    def _want_hook(self, name: str) -> None:
        """Add a hook now, or, from inside a callback, right after the current instruction:
        adding a hook makes Unicorn drop its translated code, which must not happen while that
        code runs."""
        if self.in_emulation:
            self.wanted_hooks.add(name)
            self.uc.emu_stop()
        else:
            self._add_hook(name)

    def _add_hook(self, name: str) -> None:
        if getattr(self, name) is not None:
            return
        if name == "pit_hook" and (self.pit_active or self.pit0_timing):
            self.pit_hook = self.uc.hook_add(
                UC_HOOK_BLOCK, self._pit_count, self.hook_generation["pit_hook"]
            )
        elif name == "irq0_hook" and (
            self.irq0_pending
            or self.rtc_pending
            or (self.fdc_pending and self.fdc_dor & 0x08 and not self.pic_mask & 0x40)
        ):
            self.irq0_hook = self.uc.hook_add(
                UC_HOOK_CODE, self._irq0, self.hook_generation["irq0_hook"]
            )
        elif name == "irq_hook" and (self.hw_keys or self.kbc_queue):
            self.irq_hook = self.uc.hook_add(
                UC_HOOK_BLOCK, self._irq1, self.hook_generation["irq_hook"]
            )
        elif name == "div_guard" and self.div_new:
            for pc in self.div_new:
                self.uc.hook_add(UC_HOOK_CODE, self._div_guard_hook, None, pc, pc)
            self.div_new = []
        elif name == "ali_alias_hook" and self.ali_regs[0x10] == 0xF8:
            self.ali_alias_hook = self.uc.hook_add(
                UC_HOOK_MEM_WRITE, self._ali_low_alias, None, 0, 0x3FFF
            )
        elif name == "aux_hook" and self.kbc_queue and self.kbc_aux:
            self.aux_hook = self.uc.hook_add(
                UC_HOOK_BLOCK, self._aux_irq, self.hook_generation["aux_hook"]
            )
        elif name == "alias_hook" and self.cs_alias:
            self.alias_hook = self.uc.hook_add(
                UC_HOOK_BLOCK, self._alias_left, self.hook_generation["alias_hook"]
            )
        elif name == "dram_hook" and self.dram_saved is not None:
            self.dram_hook = self.uc.hook_add(
                UC_HOOK_MEM_READ,
                self._absent_dram,
                self.hook_generation["dram_hook"],
                0,
                self.ram_top - 1,
            )
        else:
            return
        # code translated before (e.g. a wait loop) does not call a new hook: translate again
        _flush_tb(self.uc)

    def _retire(self, name: str) -> None:
        handle = getattr(self, name)
        if handle is not None:
            self.retired_hooks.append(handle)
            setattr(self, name, None)
            self.hook_generation[name] += 1

    def _absent_dram(
        self, uc: Uc, access: int, addr: int, size: int, value: int, generation: int
    ) -> None:
        """A read while DRAM row 0 has size 0: no row is there (the ROM and video areas
        A0000-FFFFF are not DRAM)."""
        if generation == self.hook_generation["dram_hook"] and not 0xA0000 <= addr < 0x100000:
            # (440BX: an empty row reads 0; FSC Xpert 6xxx's AMI takes anything else for a
            # row of the wrong DRAM type and resets to try again, for good)
            uc.mem_write(addr, bytes(size) if self.row_shift == 23 else b"\xff" * size)

    def _dram_row0(self, present: bool) -> None:
        """AMI's DRAM sizing on the 430FX/HX/VX/TX sets the rows before the one it tests to
        size 0, so that the row starts at address 0. The emulated memory is row 0: while that
        has size 0 the others are tested, which are empty (54TDP: all 8 rows were taken for
        populated ones, 8 x 128 MB)."""
        if not present and self.dram_saved is None:
            self.dram_saved = bytes(self.uc.mem_read(0, self.ram_top))
            self._want_hook("dram_hook")
        elif present and self.dram_saved is not None:
            saved, self.dram_saved = self.dram_saved, None
            self.uc.mem_write(0, saved[:0xA0000])
            self.uc.mem_write(0x100000, saved[0x100000:])
            self._park("dram_hook")

    def _remove_retired_hooks(self) -> None:
        for handle in self.retired_hooks:
            self.uc.hook_del(handle)
        self.retired_hooks, self.stale_irq0 = [], 0

    def _park(self, name: str) -> None:
        """Remove a hook from inside a callback: emulation stops and goes on without it."""
        self._retire(name)
        self.wanted_hooks.add("no_hook")
        self.uc.emu_stop()

    def _pit_used(self) -> None:
        self.pit_idle = 0
        if self.pit_parked and self.pit_active and self.pit_hook is None:
            self.pit_parked = False
            self._want_hook("pit_hook")

    def _pit_count(self, uc: Uc, address: int, size: int, generation: int) -> None:
        """Time passing for PIT channel 2: estimated 486 cycles of each code block run while
        its gate is open (cached per block; DIV/MUL count fully, others 2 cycles)."""
        if generation != self.hook_generation["pit_hook"]:
            return
        if not self.pit_active and not self.pit0_timing:  # gate closed: nothing to count; a
            self.pit_idle += 1  # long while closed, the hook goes (opening the gate brings it
            # back). Not in protected mode, where the run could not go on from the right address
            if self.pit_idle > 200_000 and not uc.reg_read(UC_X86_REG_CR0) & 1:
                self.pit_parked = True
                self._park("pit_hook")
            return
        self.pit_idle += 1
        if self.pit_idle > 100_000:
            self.pit0_timing = False  # no latch of channel 0 for long: its timing ends
            if self.pit_active:
                self.pit_parked = True
                self._park("pit_hook")
                return
            self.pit_idle = 0  # the gate is closed: left to the branch above (which keeps
            # the hook in protected mode)
        cycles = self.block_cycles.get((address, size))
        if cycles is None:
            cycles = sum(
                self._insn_cycles(insn.bytes)
                for insn in self.disasm.disasm(bytes(uc.mem_read(address, size)), 0)
            )
            self.block_cycles[(address, size)] = cycles
        if self.pit_active:
            self.pit_cycles += cycles
        if self.pit0_timing:
            self.pit0_cycles += cycles

    @staticmethod
    def _insn_cycles(code: bytes) -> int:
        i = 0
        while i < len(code) - 1 and code[i] in PREFIXES:
            i += 1
        op, reg = code[i], (code[i + 1] >> 3) & 7 if i + 1 < len(code) else 0
        if op in (0xF6, 0xF7) and reg >= 4:  # MUL/IMUL/DIV/IDIV
            return (13, 26, 16, 24)[(reg >= 6) * 2 + (op == 0xF7)]
        return 2

    def _pit1_step(self) -> None:
        """Channel 1 a few ticks on (an odd step, so that every value comes round)."""
        if self.pit1_mode in (2, 3):
            reload = self.pit1_reload or 0x10000
            self.pit1_count = (self.pit1_count - 3) % reload if reload > 3 else 0
        else:
            self.pit1_count = (self.pit1_count - 3) & 0xFFFF

    def _pit_value(self) -> int:
        ticks = int(self.pit_cycles * self.pit_ticks_per_cycle)
        reload = self.pit_reload or 0x10000
        if self.pit2_mode in (2, 3) and reload > 2:
            # periodic: back to the count at the end of each period (mode 3 counts by two,
            # twice per period); POST measures the CPU against a short period this way
            # (Phoenix 4.04: count 550h, waits for the reload a number of times)
            step = 2 * ticks if self.pit2_mode == 3 else ticks
            return (reload - step % reload) & 0xFFFF
        return (reload - ticks) % 0x10000

    def _set_a20(self, on: bool) -> None:
        if on != self.a20:
            self.uc.mem_unmap(0x100000, 0x10000)
            self.uc.mem_map_ptr(
                0x100000, 0x10000, UC_PROT_ALL, ctypes.addressof(self._hma if on else self._low)
            )
            self.a20 = on

    @staticmethod
    def _dma_register(port: int) -> tuple[int, int] | None:
        """(controller, register) of a DMA address/count port, else None."""
        if 0x00 <= port <= 0x07:
            return 0, port
        if 0xC0 <= port <= 0xCE and not port & 1:
            return 1, (port - 0xC0) // 2
        return None

    def _dma_access(self, port: int, value: int | None) -> int:
        register = self._dma_register(port)
        assert register is not None
        ctl, reg = register
        high = self.dma_flipflop[ctl]
        self.dma_flipflop[ctl] = not high
        current = self.dma_regs[ctl][reg]
        if value is None:
            return current >> 8 if high else current & 0xFF
        if high:
            self.dma_regs[ctl][reg] = current & 0xFF | (value & 0xFF) << 8
        else:
            self.dma_regs[ctl][reg] = current & 0xFF00 | value & 0xFF
        return 0

    def _pci_option_rom(self, vendor: int, device: int) -> bytes:
        """The VGA stub as the card's expansion ROM: with a PCI data structure ("PCIR"), so
        the BIOS copies it to C0000 and runs it."""
        rom = bytearray(self.uc.mem_read(0xC0000, 0x8000))
        # the entry (3) jumps to 50h: INT 10h is pointed into this ROM and mode 3 is set
        # (clearing the screen), as a real VGA BIOS does. The handler at 40h passes the call
        # on with INT 10h, which the emulator answers, for callers using PUSHF / CALL FAR.
        rom[3:6] = b"\xe9\x4a\x00"  # JMP 0050h
        rom[0x40:0x43] = b"\xcd\x10\xcf"  # INT 10h / IRET
        rom[0x50:0x66] = bytes(
            [
                0x1E,
                0x31,
                0xC0,
                0x8E,
                0xD8,
                0xC7,
                0x06,
                0x40,
                0x00,
                0x40,
                0x00,
                0x8C,
                0x0E,
                0x42,
                0x00,
                0x1F,
                0xB8,
                0x03,
                0x00,
                0xCD,
                0x10,
                0xCB,
            ]
        )
        pcir = 0x7FC0
        rom[0x18:0x1A] = struct.pack("<H", pcir)
        rom[pcir : pcir + 0x18] = (
            b"PCIR"
            + struct.pack("<HHHHB", vendor, device, 0, 0x18, 0)
            + bytes([0x00, 0x00, 0x03])
            + struct.pack("<HHBBH", 0x40, 0, 0, 0x80, 0)
        )
        rom[0x7FFF] = 0
        rom[0x7FFF] = -sum(rom) & 0xFF
        return bytes(rom)

    def _ali_pam(self, cfg: bytearray) -> bytes:
        """pam[] from the mask (4Ch/4Dh, a bit per 16 KB block from C0000, the high nibble for
        F0000-FFFFF as one) and the direction (4Ah: bit 1 reads RAM, bit 2 writes it)."""
        mode, pam = cfg[0x4A] >> 1 & 3, bytearray(7)
        for block in range(12):
            on = cfg[0x4C + (block >> 3)] >> (block & 7) & 1
            pam[1 + block // 2] |= (mode if on else 0) << 4 * (block & 1)
        pam[0] = (mode if cfg[0x4D] >> 4 else 0) << 4
        return bytes(pam)

    def _serverworks_shadow(self, value: int) -> None:
        """ServerWorks CNB20 host register 73h: high nibble F0000-FFFFF, low nibble E0000-EFFFF,
        bits 3/1 read the RAM, bits 2/0 write it. Read off the BIOS's own F0h, A0h, AFh, AAh, FAh
        sequence around its copies: the datasheets are not public."""

        def bits(nibble: int) -> int:
            return (1 if nibble & 0xA else 0) | (2 if nibble & 5 else 0)

        low = bits(value & 15) * 0x11
        pam = [bits(value >> 4) << 4, 0, 0, 0, 0, low, low]
        self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), bytearray(pam)))

    def _flash_bank(self, port: int, value: int) -> None:
        """Acer V65 (not V62, whose POST runs on from this ROM: acer_setup tries without first):
        register 3 bit 7 of the Super I/O (3F0h/3F1h, opened by 55h 55h, closed by
        AAh) drives a flash address line: clear shows the lower 128 KB at E0000-FFFFF, where
        POST unpacks the setup from. Read off POST's own sequence, the chip is not named."""
        if port == 0x3F0:
            if value == 0x55:
                self.flash_sio_open += 1
            elif value == 0xAA:
                self.flash_sio_open = 0
            else:
                self.flash_sio_index = value
            return
        upper = bool(value & 0x80)
        if self.flash_sio_open < 2 or self.flash_sio_index != 3 or upper == self.flash_upper:
            return
        self.flash_upper = upper
        shown, self.flash_low = self.flash_low, self.rom_view[0x20000:]
        self.rom_view = self.rom_view[:0x20000] + shown
        for block in range(8, 16):
            if not self._reads_ram(block):
                at = block * 0x4000
                self.uc.mem_write(SHADOW_BASE + at, self.rom_view[at : at + 0x4000])
        _flush_tb(self.uc)

    def _video_rom(self, hook_int10: bool = False) -> None:
        """A VGA card's ROM as POST finds it at C0000 (55AAh, 32 KB, checksum 0): its
        initialisation returns at once, as INT 10h is provided by the emulator; the fonts lie
        in it like in a real one. Some BIOSes stop with a video error without it. hook_int10:
        the initialisation points INT 10h into it (to an INT 10h the emulator answers) and
        sets mode 3, as a real one does (DTK's POST resets the PC while INT 10h still points
        to its dummy IRET; MR BIOS on the other hand does not start its setup then)."""
        rom = bytearray(self.uc.mem_read(0xC0000, 0x8000))
        rom[0:4] = b"\x55\xaa\x40\xcb"  # signature, 64 x 512 bytes, RETF at the entry (3)
        if hook_int10:
            rom[3:6] = b"\xe9\x4a\x00"  # JMP 0050h (as in _pci_option_rom)
            rom[0x40:0x43] = b"\xcd\x10\xcf"  # INT 10h / IRET
            rom[0x50:0x66] = bytes(
                [
                    0x1E,
                    0x31,
                    0xC0,
                    0x8E,
                    0xD8,
                    0xC7,
                    0x06,
                    0x40,
                    0x00,
                    0x40,
                    0x00,
                    0x8C,
                    0x0E,
                    0x42,
                    0x00,
                    0x1F,
                    0xB8,
                    0x03,
                    0x00,
                    0xCD,
                    0x10,
                    0xCB,
                ]
            )
        rom[0x1E:0x22] = b"IBM "  # many BIOSes look for "IBM" here in a VGA ROM
        rom[0x7FFF] = 0
        rom[0x7FFF] = -sum(rom) & 0xFF
        self.uc.mem_write(0xC0000, bytes(rom))

    # --- shadow RAM (PAM) ---------------------------------------------------------------------

    def _pam_bits(self, block: int) -> int:
        """Bit 0: reads from RAM, bit 1: writes to RAM, for 16 KB block 0 (C0000) to 15."""
        if block >= 12:  # F0000-FFFFF: PAM0 bits 4-5
            return self.pam[0] >> 4 & 3
        reg = 1 + block // 2
        return self.pam[reg] >> (4 * (block & 1)) & 3

    def _reads_ram(self, block: int) -> bool:
        """Whether reads in a 16 KB block come from its shadow RAM. A BIOS fills the shadow
        RAM before reading from it, or opens it for reading and writing together; a block that
        is only switched to reading without that keeps showing the ROM (non-Intel chipsets use
        these registers for something else)."""
        bits = self._pam_bits(block)
        return bool(bits & 1) and (self.shadow_used[block] or bool(bits & 2))

    def _set_pam(self, reg: int, value: int) -> None:
        self._shadow_change(lambda: self.pam.__setitem__(reg, value & 0xFF))

    def _shadow_change(self, change: Callable[[], object]) -> None:
        """A change of the shadow registers (from inside an I/O hook): noted, and applied to
        memory between two runs, since Unicorn's memory must not be changed from its hooks."""
        if self.shadow_before is None:
            self.shadow_before = [self._reads_ram(b) for b in range(16)]
        change()
        self.uc.emu_stop()  # _go applies it and continues right after this instruction

    def _apply_shadow(self) -> None:
        """Show ROM or shadow RAM where the reads now come from, and protect what must not be
        written. Called outside emulation."""
        before, self.shadow_before = self.shadow_before, None
        changed = False
        if before is not None:
            for b in range(16):
                start, part = SHADOW_BASE + b * 0x4000, slice(b * 0x4000, (b + 1) * 0x4000)
                old, new = before[b], self._reads_ram(b)
                if old and new and self.shadow_newer[b]:  # written behind a stale view
                    self.uc.mem_write(start, bytes(self.shadow[part]))
                    changed = True
                self.shadow_newer[b] = False
                if old == new:
                    continue
                changed = True
                if old:  # the RAM contents go out of sight
                    self.shadow[part] = self.uc.mem_read(start, 0x4000)
                elif not self.shadow_used[b]:  # opened for reading and writing: the RAM
                    self.shadow[part] = self.uc.mem_read(start, 0x4000)  # starts as seen
                    self.shadow_used[b] = True
                self.uc.mem_write(start, bytes(self.shadow[part]) if new else self.rom_view[part])
        if changed:  # code translated from what was there before must not run again (Tyan
            _flush_tb(self.uc)  # S1563S runs on in F000 while it switches to its shadow)
        self._protect()

    def _protect(self) -> None:
        """Blocks whose visible contents must not change are read-only for the CPU; writes to
        them reach _shadow_write instead (to the RAM behind the ROM, or dropped)."""
        for b in range(16):
            fallback = not self.pci_used and not (self.pam_gone and not self.shadow_used[b])
            # (F0000-FFFFF is the BIOS socket, not general shadow RAM: POST's memory test
            # must not overwrite the ROM on a chipset not modelled, MR BIOS m351, m356)
            writable = (fallback and (b < 12 or not self.protect_socket)) or (
                self._pam_bits(b) & 3 == 3
            )
            if self.protected[b] == (not writable):
                continue
            self.uc.mem_protect(
                SHADOW_BASE + b * 0x4000,
                0x4000,
                UC_PROT_ALL if writable else UC_PROT_READ | UC_PROT_EXEC,
            )
            self.protected[b] = not writable

    def _k7_poll(self) -> None:
        """The K7's fixed-range MTRRs as shadow RAM settings (read and write per 16 KB block;
        F0000-FFFFF as one, as the PAM model has it)."""
        try:
            values = [self.uc.msr_read(0x268 + i) for i in range(8)]
        except UcError:
            return
        types = b"".join(v.to_bytes(8, "little") for v in values)  # one byte per 4 KB

        def bits(parts: bytes) -> int:  # as PAM bits: 0 read from RAM, 1 write to RAM
            return (1 if any(t & 0x10 for t in parts) else 0) | (
                2 if any(t & 0x08 for t in parts) else 0
            )

        pam = [bits(types[48:64]) << 4] + [0] * 6
        for b in range(12):
            pam[1 + b // 2] |= bits(types[4 * b : 4 * b + 4]) << 4 * (b & 1)
        if pam != list(self.pam):
            self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), bytearray(pam)))

    def _shadow_write(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> bool:
        if self.k7_mtrr and self.shadow_before is None:
            self._k7_poll()  # (a copy into the shadow RAM right after the MTRRs were set)
        if self.uc.reg_read(UC_X86_REG_CR0) & 1 and self.gp_at is None and self.invalid6 < 8:
            pc = self._code_address()
            if self.uc.mem_read(pc, 1)[0] == 0x2E:  # (the early Award 286 exception test)
                self.gp_at = self.uc.reg_read(UC_X86_REG_EIP)
                self.uc.emu_stop()
                return True
        off = addr - SHADOW_BASE
        block = off // 0x4000
        if self._pam_bits(block) & 2 or self.shadow_before is not None:
            visible = (
                self.shadow_before[block]
                if self.shadow_before is not None
                else self._reads_ram(block)
            )
            if visible and not self.shadow_newer[block]:
                # the CPU sees the RAM itself: the copy kept here catches up first, else
                # _apply_shadow puts an old copy back over it (Soltek SL-KT600 and
                # K7VM333: POST code in E8000 replaced by what was there long before)
                start = SHADOW_BASE + block * 0x4000
                self.shadow[block * 0x4000 : (block + 1) * 0x4000] = self.uc.mem_read(start, 0x4000)
            # writes go to the RAM behind the ROM (also while a change is pending)
            self.shadow[off : off + size] = (value & ((1 << 8 * size) - 1)).to_bytes(size, "little")
            self.shadow_used[block] = True
            self.shadow_newer[block] = True
        return True  # the visible ROM (or read-only RAM) keeps its contents

    def _pci_config(self) -> bytearray | None:
        """Configuration space addressed through port CF8h (bus 0 only), None if no device."""
        if not self.pci_addr & 0x80000000 or self.pci_addr >> 16 & 0xFF:
            return None
        slot, function = self.pci_addr >> 11 & 0x1F, self.pci_addr >> 8 & 7
        if (
            slot == 31
            and (31, 0) not in self.pci_devices
            and bytes(self.pci_devices.get((7, 0), b"")[0:2]) == b"\x86\x80"
        ):
            slot = 7  # (Phoenix 4.0 of the Tyan 440BX boards sets its PIIX4 up at device 31,
            # where ICHs sit, and resets the CPU when nothing answers)
        return self.pci_devices.get((slot, function))

    def _pci_write(self, port: int, size: int, value: int) -> None:
        reg = (self.pci_addr & 0xFC) + (port - 0xCFC)
        cfg = self._pci_config()
        if cfg is not None:
            device = int.from_bytes(bytes(cfg[2:4]), "little")
            straps, clearing = STRAPS.get(device, {}), SELF_CLEARING.get(device, {})
            was47 = cfg[0x47]
            for i in range(size):  # IDs, class and header type are read-only
                if reg + i < 0x100 and not (reg + i < 4 or 8 <= reg + i < 12 or reg + i == 0x0E):
                    byte = value >> (8 * i) & 0xFF
                    if reg + i in straps:  # and straps
                        mask, fixed = straps[reg + i]
                        byte = byte & ~mask | fixed
                    cfg[reg + i] = byte & ~clearing.get(reg + i, 0)
            if (
                0x10 <= reg < 0x28
                and not cfg[0x0E] & 0x7F
                or (0x10 <= reg < 0x18 and cfg[0x0E] & 0x7F == 1)
            ):  # BARs of an ordinary
                # device, or the two of a PCI-to-PCI bridge (VIA's AGP bridge: kept as written,
                # FFFFFFFFh made TriGem Santa Fe's Phoenix allocate with a 2-byte alignment)
                bar = reg & ~3
                mask = PCI_BARS.get(int.from_bytes(bytes(cfg[2:4]), "little"), {}).get(bar, 0)
                stored = int.from_bytes(bytes(cfg[bar : bar + 4]), "little")
                kept = (stored & mask & ~0xF) | (mask & (1 if mask & 1 else 0xF)) if mask else 0
                cfg[bar : bar + 4] = kept.to_bytes(4, "little")
            if 0x30 <= reg < 0x34 and not cfg[0x0E] & 0x7F:  # expansion ROM: size and enable
                mask = PCI_BARS.get(int.from_bytes(bytes(cfg[2:4]), "little"), {}).get(0x30, 0)
                stored = int.from_bytes(bytes(cfg[0x30:0x34]), "little")
                cfg[0x30:0x34] = ((stored & mask) | (stored & 1) if mask else 0).to_bytes(
                    4, "little"
                )
            key = (self.pci_addr >> 11 & 0x1F, self.pci_addr >> 8 & 7)
            smram = SMRAM_REGS.get(device) if key == (0, 0) else None
            if device in I810_HOSTS and reg <= 0x70 < reg + size:
                # the 810's own SMRAM control (70h bits 3-2, 01: A0000-BFFFF is DRAM for code
                # outside SMM; Fujitsu-Siemens D1185's Phoenix copies code there and calls it)
                smram = 0x70
                is_open = cfg[0x70] >> 2 & 3 == 1
            else:
                is_open = smram is not None and bool(cfg[smram] & 0x40)
            if smram is not None and reg <= smram < reg + size and is_open != self.smram_open:
                # opened or closed: applied between two runs (Top Star TM-845GL's AMI wrote its
                # SMM handler into the text screen at B8000)
                self.smram_open = not self.smram_open
                self.smram_pending = not self.smram_pending
                self.uc.emu_stop()
            if (
                device in (0x0586, 0x0596)
                and reg <= 0x47 < reg + size
                and cfg[0x47] & 1
                and not was47 & 1
            ):
                # VIA 82C586/596, ISA function 47h bit 0: resets the CPU (PCChips M768VMR's
                # AMI does so after setting the CPU up in the CMOS, at POST code CBh, and
                # waits in a loop). Not the 686: its boards set the
                # bit on every start (PCChips M754, M92)
                cfg[0x47] &= 0xFE
                self.stopped_reason = "reset"
                raise Stop()
            chip_bar = CHIP_SMBUS_BAR.get(key) if self.chip_smbus else None
            if chip_bar is not None and chip_bar <= reg + size - 1 and reg <= chip_bar + 1:
                for i in range(size):
                    if chip_bar <= reg + i <= chip_bar + 1:
                        self.chip_smbus_bar[reg + i - chip_bar] = value >> 8 * i & 0xFF
                # (ALi: IOEN and HOSTEN in the low bits)
                self.smbus_base = int.from_bytes(self.chip_smbus_bar, "little") & ~0x0F or None
            smbus_bar = SMBUS_FUNCTIONS.get(key)
            if smbus_bar is not None and smbus_bar <= reg + size - 1 and reg <= smbus_bar + 1:
                base = int.from_bytes(bytes(cfg[smbus_bar : smbus_bar + 2]), "little") & 0xFFF0
                self.smbus_base = base or None
        if self.sis496 and (self.pci_addr & 0x80FFFF00) == 0x80002800:  # SiS 85C496 (0:5.0)
            if reg <= 0x45 and 0x44 < reg + size and cfg is not None:
                self._sis496_shadow(cfg[0x44], cfg[0x45])
            return
        if self.umc and (self.pci_addr & 0x80FFFF00) == 0x80008000:  # UMC 8881 (0:10.0)
            if reg <= 0x55 and 0x54 < reg + size and cfg is not None:
                self._umc_shadow(cfg[0x54], cfg[0x55])
            return
        if self.serverworks and (self.pci_addr & 0x80FFFFFC) == 0x80000070 and port == 0xCFF:
            self._serverworks_shadow(value & 0xFF)
            return
        if (self.pci_addr & 0x80FFFF00) != 0x80000000:  # PAM: only the host bridge (0:0.0)
            return
        host = self.pci_devices.get((0, 0))
        if self.ali_shadow is not None and host is self.ali_shadow:
            if reg <= 0x4D and 0x4A < reg + size:
                ali = self._ali_pam(self.ali_shadow)
                self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), bytearray(ali)))
            return
        if self.via_shadow:
            if reg <= 0x63 and 0x61 < reg + size and not self.pam_valid:
                # the first use of the shadow registers: from here on they decide; what
                # plain RAM holds now is the shadow RAM's contents
                self.shadow[:] = self.uc.mem_read(SHADOW_BASE, 0x40000)
                self.shadow_used = [True] * 16
                self.pam_valid, self.pci_used = True, True
            if reg <= 0x63 and 0x61 < reg + size and self.pam_valid:  # VIA shadow RAM
                # two bits per block (bit 1 read from RAM, bit 0 write to RAM): 61h C0000-
                # CFFFF and 62h D0000-DFFFF per 16 KB; 63h bits 7-6 E0000-EFFFF, 5-4 F0000-FFFFF
                def bits(v: int) -> int:  # as PAM bits: 0 read, 1 write
                    return (v >> 1 & 1) | (v & 1) << 1

                assert host is not None
                fields = [host[0x61 + b // 4] >> 2 * (b % 4) & 3 for b in range(8)]
                fields += [host[0x63] >> 6 & 3] * 4
                pam = [bits(host[0x63] >> 4 & 3) << 4] + [0] * 6
                for b, v in enumerate(fields):
                    pam[1 + b // 2] |= bits(v) << 4 * (b & 1)
                self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), bytearray(pam)))
            return
        if host is not None and host[0:4] == b"\x39\x10\x97\x55":
            if reg <= 0x76 and 0x70 < reg + size and self.pam_valid:  # SiS 5597 (as 5571)
                # 70h-75h: C0000-EFFFF, one register per 32 KB; per 16 KB half a read bit
                # (80h lower, 08h upper: from RAM) and a write bit (20h, 02h: to RAM); 76h:
                # F0000-FFFFF, bit 7 read, bit 5 write. (POST sets A0h, copies, then 80h.)
                regs = host[0x70:0x77]

                def sis_bits(byte: int) -> int:  # read (80h) and write (20h) as PAM bits 0 and 1
                    return (1 if byte & 0x80 else 0) | (2 if byte & 0x20 else 0)

                pam = [sis_bits(regs[6]) << 4] + [0] * 6
                for b in range(12):  # 16 KB blocks from C0000; odd ones use the low nibble
                    half = regs[b // 2] if b % 2 == 0 else regs[b // 2] << 4 & 0xFF
                    pam[1 + b // 2] |= sis_bits(half) << 4 * (b & 1)
                self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), bytearray(pam)))
            return
        if host is not None and host[2:4] in (b"\x20\x71", b"\x22\x71", b"\x24\x71"):
            if reg <= 0x5F and 0x59 < reg + size:  # PAM written as on a 440BX: an 815 board
                self.pam_at_59 = True  # whose ROM names only its ICH (Phoenix "2962 Vent"), where
                # 51h means something else
            if reg <= 0x51 < reg + size and self.pam_valid and not self.pam_at_59:  # i810: one
                # register, 2 bits
                byte = value >> 8 * (0x51 - reg) & 0xFF  # (read, write RAM) per 64 KB from C0000
                fields = [byte >> 2 * k & 3 for k in range(4)]
                pam = [
                    fields[3] << 4,
                    fields[0] * 0x11,
                    fields[0] * 0x11,
                    fields[1] * 0x11,
                    fields[1] * 0x11,
                    fields[2] * 0x11,
                    fields[2] * 0x11,
                ]
                self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), bytearray(pam)))
            if not (reg <= 0x5F and 0x59 < reg + size):
                return
        shift = ROW_SIZED_HOSTS.get(int.from_bytes(bytes(host[2:4]), "little")) if host else None
        if shift and host is not None and reg <= 0x60 < reg + size:
            self._dram_row0(host[0x60] != 0)
            self.row_aliased = host[0x60] << shift if host[0x60] << shift > self.ram_top else 0
        for i in range(size):
            if self.pam_base <= reg + i <= self.pam_base + 6 and self.pam_valid:
                byte = value >> (8 * i) & 0xFF
                if byte & 0xCC:  # reserved PAM bits: not an Intel chipset, these mean else
                    self._pam_off()
                    return
                self._set_pam(reg + i - self.pam_base, byte)

    # command lengths (bytes with the command) of the 765/82077, by the low five bits
    FDC_LENGTHS = {
        0x03: 3,
        0x04: 2,
        0x05: 9,
        0x06: 9,
        0x07: 2,
        0x08: 1,
        0x09: 9,
        0x0A: 2,
        0x0C: 9,
        0x0D: 6,
        0x0E: 1,
        0x0F: 3,
        0x10: 1,
        0x11: 9,
        0x12: 2,
        0x13: 4,
        0x14: 1,
        0x16: 9,
        0x19: 9,
        0x1D: 9,
    }

    def _fdc_irq(self) -> None:
        self.fdc_pending = True
        self._fdc_check()

    def _fdc_check(self) -> None:
        """The interrupt hook (a call per instruction) only while IRQ 6 can get through: the
        controller's IRQ enabled (DOR bit 3) and IRQ 6 unmasked in the PIC."""
        if self.fdc_pending and self.fdc_dor & 0x08 and not self.pic_mask & 0x40:
            self._want_hook("irq0_hook")

    def _fdc_write(self, value: int) -> None:
        """A byte of a command; with the last one the command runs: no disk is in a drive,
        so reading and formatting end with "missing address mark"."""
        self.fdc_results = []
        self.fdc_cmd.append(value)
        code = self.fdc_cmd[0] & 0x1F
        if len(self.fdc_cmd) < self.FDC_LENGTHS.get(code, 1):
            return
        cmd, self.fdc_cmd = self.fdc_cmd, []
        drive = cmd[1] & 3 if len(cmd) > 1 else 0
        if code == 0x04:  # sense drive status: ready, two sides, track 0
            self.fdc_results = [0x28 | (0x10 if not self.fdc_pcn[drive] else 0) | drive]
        elif code in (0x07, 0x0F):  # recalibrate / seek: done, IRQ 6
            self.fdc_pcn[drive] = cmd[2] if code == 0x0F else 0
            self.fdc_st0 = 0x20 | drive
            self._fdc_irq()
        elif code == 0x08:  # sense interrupt status
            if self.fdc_reset_sense:  # after a reset: one per drive, "ready changed"
                self.fdc_results = [0xC0 | (4 - self.fdc_reset_sense), 0]
                self.fdc_reset_sense -= 1
            elif self.fdc_st0 is not None:
                self.fdc_results = [self.fdc_st0, self.fdc_pcn[self.fdc_st0 & 3]]
                self.fdc_st0 = None
            else:
                self.fdc_results = [0x80]  # nothing pending
        elif code == 0x10:  # version: an 82077
            self.fdc_results = [0x90]
        elif code == 0x0E:  # dump registers
            self.fdc_results = [0] * 10
        elif code == 0x14:  # lock
            self.fdc_results = [cmd[0] >> 3 & 0x10]
        elif code in (0x03, 0x12, 0x13):  # specify, perpendicular mode, configure
            pass
        elif code in self.FDC_LENGTHS:  # reading, writing, read ID, format: no disk
            c = self.fdc_pcn[drive]
            self.fdc_results = [0x40 | drive, 0x01, 0, c, 0, 1, 2]
            self._fdc_irq()
        else:
            self.fdc_results = [0x80]  # invalid command

    def _um8498_out(self, port: int, value: int) -> None:
        """UMC UM8498F (486 boards; Biostar MB-1433UIV, CH-498B; ports and shadow bits from
        MAME's um8498f.cpp, which calls them guesswork): A0h, 05h at 28h unlock, A5h locks,
        anything else selects a register at 2Ah. 35h is E0000-EFFFF, 36h F0000-FFFFF: bit 6
        reads and writes the shadow RAM, bit 4 only writes it. Without the registers POST's
        memory test overwrites the interrupt table and it beeps for ever."""
        if port == 0x2A:
            self.um8498_regs[self.um8498_index] = value
            if self.um8498_index in (0x35, 0x36):
                regs = self.um8498_regs

                def bits(reg: int) -> int:
                    return 3 if reg & 0x40 else 2 if reg & 0x10 else 0

                def shadow_on() -> None:
                    self.pam[0] = bits(regs[0x36]) << 4
                    self.pam[5] = self.pam[6] = bits(regs[0x35]) * 0x11
                    self.pci_used = True

                self._shadow_change(shadow_on)
        elif self.um8498_phase == 0:
            self.um8498_phase = 1 if value == 0xA0 else 0
        elif self.um8498_phase == 1:
            self.um8498_phase = 2 if value == 0x05 else 0
        elif value == 0xA5:
            self.um8498_phase = 0
        else:
            self.um8498_index = value

    def _scat_shadow(self) -> None:
        """C&T F82C235 (SCAT, 286 boards; register meaning from 86Box's scat.c): 4Ah-4Ch
        enable shadow RAM in 16 KB pieces from A0000 (C0000 is bit 8), only if the low
        nibble of 4Dh is at least 4; 49h write-protects C0000-FFFFF in 32 KB pieces. POST
        tests the whole of it over the ROM, which must come back afterwards."""
        regs = self.scat_regs
        enabled = regs[0x4A] | regs[0x4B] << 8 | regs[0x4C] << 16
        if regs[0x4D] & 0x0F < 4:
            enabled = 0
        blocks = []
        for b in range(16):
            on = enabled >> (b + 8) & 1
            blocks.append(on | (2 if on and not regs[0x49] >> (b // 2) & 1 else 0))
        pam = [(blocks[12] | blocks[14]) << 4] + [0] * 6
        for b in range(12):
            pam[1 + b // 2] |= blocks[b] << 4 * (b & 1)

        def shadow_on() -> None:
            self.pam[0:7] = pam
            self.pci_used = True

        self._shadow_change(shadow_on)

    def _ali_write(self, value: int) -> None:
        if self.scat:
            self.scat_regs[self.ali_index] = value
            if 0x49 <= self.ali_index <= 0x4D:
                self._scat_shadow()
            return
        if self.ali_index == 0x10 and value == 0xF8 and self.ali_alias_hook is None:
            self.ali_regs[0x10] = value  # (AMI's sizing probe: see _ali_low_alias)
            self._want_hook("ali_alias_hook")
        # (the M6117's own unlock, 13h <- C5h, is not modelled: with it, AMI 0626 boards
        # that work locked (IC08R15) end at the memory chain walk)
        if self.ali_index == 0x03:
            self.ali_unlocked = value == 0xC5
            if self.ali_unlocked and not self.ali:
                # from now on the ROM is read-only as on the board (POST probes the flash
                # chip with JEDEC commands at E5555h/E2AAAh/E0000h, which would otherwise
                # overwrite the module table there)
                self.ali = True
                self._shadow_change(lambda: setattr(self, "pci_used", True))
            return
        if not self.ali_unlocked:
            if 0x10 <= self.ali_index < 0x60 or self.ali_index >= 0x70:
                self.not_neat = True  # (other chipsets' registers: 5CDP's 40h-57h)
            self.ali_regs[self.ali_index] = value
            if 0x10 <= self.ali_index < 0x50:
                self.below50 = True  # (5CDP's chipset: 40h-57h, its 52h something else)
            if (
                self.ali_index == 0x52
                and not self.neat
                and not self.pci_devices
                and not self.below50
                and (self.sis471 or not self.pci_used)
                and self.ali_regs[0x50]
            ):
                self.sis471 = True
                self._sis471_shadow(value)
                return
            if (
                self.ali_index in (0x68, 0x69)
                and value
                and not self.neat
                and not self.not_neat
                and not self.pci_devices
                and not self.pci_used
            ):
                # Chips & Technologies NEAT (82C212, 286/386 boards, about 1989: registers
                # 60h-6Fh behind 22h/23h): 68h/69h switch on shadow RAM behind C0000-FFFFF.
                # Writes there go to that RAM, reads keep coming from the ROM (AMI clears the
                # RAM with the ROM in sight, then copies the ROM into it: ABC Compact 286)
                self.neat = True

                def neat_on() -> None:
                    self.pam[0:7] = [0x20] + [0x22] * 6
                    self.pci_used = True

                self._shadow_change(neat_on)
            return
        self.ali_regs[self.ali_index] = value
        if self.ali_index in (0x13, 0x14):
            self._ali_shadow()

    def _ali_low_alias(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        """While AMI's sizing probe holds F8h in ALi register 10h the first 16 KB is seen
        again every 4 KB, so its 4 KB test does not read back as on flat RAM (which no entry
        of its table matches: POST beeps forever)."""
        if self.ali_regs[0x10] != 0xF8 or addr & 0xFFF > 0x1000 - size:
            return
        data = (value & ((1 << 8 * size) - 1)).to_bytes(size, "little")
        for block in range(4):  # (the hook runs before the write: the value is written)
            if (addr & 0xFFF) + 0x1000 * block != addr:
                uc.mem_write((addr & 0xFFF) + 0x1000 * block, data)

    def _sis471_shadow(self, value: int) -> None:
        """SiS 85C471 (486 boards, registers 50h-75h behind 22h/23h; AMIBIOS 07/25/94 of
        Abit AH4 and Asus AN4R307, BIOS ID "...-SIS471G"). Register 52h: bit 7 reads
        F0000-FFFFF from the shadow RAM, bit 6
        write-protects it, bits 0-5 shadow C0000-EFFFF in 32 KB pieces (that split a guess).
        AMI copies the ROM in with 3Fh, runs from it write-protected (FFh), opens it for the
        runtime BIOS (BFh); its setup clears bit 7 to copy the ROM to 1000h again, which only
        works if the runtime BIOS written to F000 did not replace the ROM."""
        write = 0 if value & 0x40 else 2
        pam = [((1 if value & 0x80 else 0) | write) << 4] + [0] * 6
        for area in range(6):
            if value >> area & 1:
                pam[1 + area] = 0x33  # (both 16 KB blocks: read and write the RAM)

        def shadow_on() -> None:
            self.pam[0:7] = pam
            self.pci_used = True

        self._shadow_change(shadow_on)

    def _ali_shadow(self) -> None:
        """ALi M1489 shadow RAM: 13h enables it per 16 KB from C0000, 14h bits 0-3 per 32 KB
        from E0000; 14h bit 4 reads enabled areas from RAM, bit 5 writes them (AMI sets bit 5
        while it copies a module into F0000, then clears it)."""
        regs = self.ali_regs
        bits = (1 if regs[0x14] & 0x10 else 0) | (2 if regs[0x14] & 0x20 else 0)
        blocks = [bits if regs[0x13] >> b & 1 else 0 for b in range(8)]
        blocks += [bits if regs[0x14] >> (b // 2) & 1 else 0 for b in range(8)]
        pam = [(blocks[12] | blocks[14]) << 4] + [0] * 6  # F0000-FFFFF: one setting here
        for b in range(12):
            pam[1 + b // 2] |= blocks[b] << 4 * (b & 1)
        self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), pam))

    def _opti_shadow(self) -> None:
        """OPTi 82C546/547, 82C571/572 and 82C596/597 shadow RAM (TMC PCI58PL; the register
        meanings as in 86Box's opti5x7.c): 04h is C0000-CFFFF and 05h
        D0000-DFFFF in four 16 KB pieces, bit pair 2i reads and 2i+1 writes the RAM; 06h bits
        0-1 are E0000-EFFFF, bits 2-3 F0000-FFFFF. AMI's boot block opens F0000-FFFFF, copies
        the runtime BIOS there and jumps to the reset vector: without this it restarts."""
        regs = self.opti_regs
        blocks = [regs[0x04 + b // 4] >> 2 * (b % 4) & 3 for b in range(8)]
        blocks += [regs[0x06] & 3] * 4
        pam = [(regs[0x06] >> 2 & 3) << 4] + [0] * 6
        for b in range(12):
            pam[1 + b // 2] |= blocks[b] << 4 * (b & 1)
        self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), pam))

    def _opti895_shadow(self) -> None:
        """OPTi 82C895 (QDI V4P895P3; registers from 86Box's opti895.c): 22h bit 7 set reads
        F0000-FFFFF from the ROM and writes the RAM, clear reads the RAM and protects it. Per
        16 KB: 26h bits 0-3 C0000-CFFFF, 23h bits 0-3 D0000-DFFFF, bits 4-7 E0000-EFFFF read
        the RAM; writes unless 26h bit 5, 22h bit 4 or 22h bit 3 protects them. Unshadowed
        blocks write the RAM with 26h bit 6."""
        r22, r23, r26 = self.opti_regs[0x22], self.opti_regs[0x23], self.opti_regs[0x26]
        pam = [(2 if r22 & 0x80 else 1) << 4] + [0] * 6
        groups = (r26 & 0x0F, r26 & 0x20, r23 & 0x0F, r22 & 0x10, r23 >> 4, r22 & 0x08)
        for b in range(12):
            read, protect = groups[b // 4 * 2] >> b % 4 & 1, groups[b // 4 * 2 + 1]
            write = not protect and (read or r26 & 0x40)
            pam[1 + b // 2] |= (read | (2 if write else 0)) << 4 * (b & 1)

        def shadow_on() -> None:
            self.pam[0:7] = pam
            self.pci_used = True

        self._shadow_change(shadow_on)

    def _via_shadow(self) -> None:
        """VIA VT82C496G and VT82C570M shadow RAM (Teknor PCI-935; the registers as in Ralf
        Brown's port list): 30h is C0000-CFFFF and 31h
        D0000-DFFFF in four 16 KB pieces, bit pair 2i writes and 2i+1 reads the RAM; 32h bits
        6-7 are E0000-EFFFF, bits 4-5 F0000-FFFFF. AMI's boot block uses it as on OPTi."""
        regs = self.via_regs

        def bits(pair: int) -> int:  # (PAM order: bit 0 reads, bit 1 writes)
            return (pair >> 1 & 1) | (pair & 1) << 1

        blocks = [bits(regs[0x30 + b // 4] >> 2 * (b % 4)) for b in range(8)]
        blocks += [bits(regs[0x32] >> 6)] * 4
        pam = [bits(regs[0x32] >> 4) << 4] + [0] * 6
        for b in range(12):
            pam[1 + b // 2] |= blocks[b] << 4 * (b & 1)
        self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), pam))

    def _sis496_shadow(self, segments: int, control: int) -> None:
        """SiS 85C496 shadow RAM (44h-45h): 44h enables it per 32 KB from C0000 (bit 7:
        F8000-FFFFF); 45h bit 1 reads enabled areas from RAM, bit 0 write-protects them (AMI
        sets 02h, copies, then 03h). Areas not enabled are ROM (writes go to the bus)."""
        bits = (1 if control & 2 else 0) | (0 if control & 1 else 2)
        blocks = [bits if segments >> (b // 2) & 1 else 0 for b in range(16)]
        # F0000-FFFFF has one setting here (PAM0 bits 4-5): shadowed if either half is
        pam = [(bits if segments & 0xC0 else 0) << 4] + [0] * 6
        for b in range(12):
            pam[1 + b // 2] |= blocks[b] << 4 * (b & 1)
        self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), pam))

    def _umc_shadow(self, segments: int, control: int) -> None:
        """UMC 8881 shadow RAM: 55h bit 7 reads F0000-FFFFF from RAM and enables the reads of
        the C0000-EFFFF parts selected in 54h (bit 0: E0000-EFFFF, bit 1: C0000-C7FFF, bits
        2-7: 16 KB each from C8000); 55h bit 6 write-protects the RAM, else writes reach it."""
        write = 0 if control & 0x40 else 2
        on = bool(control & 0x80)
        masks = [2, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 1, 1, 1, 1]
        pam = [(int(on) | write) << 4] + [0] * 6
        for b, mask in enumerate(masks):
            bits = (1 if on and segments & mask else 0) | write
            pam[1 + b // 2] |= bits << 4 * (b & 1)
        self._shadow_change(lambda: self.pam.__setitem__(slice(0, 7), pam))

    def _apply_pam_off(self) -> None:
        """Plain RAM: shadow contents that were hidden become visible, nothing is protected."""
        before, self.shadow_before, self.pam_off_pending = self.shadow_before, None, False
        for b in range(16):
            if self.shadow_used[b] and before is not None and not before[b]:
                self.uc.mem_write(
                    SHADOW_BASE + b * 0x4000, bytes(self.shadow[b * 0x4000 : (b + 1) * 0x4000])
                )
        _flush_tb(self.uc)
        self._protect()

    def _pam_off(self) -> None:
        """Back to plain RAM at C0000-FFFFF: what was written to shadow RAM stays."""
        self._shadow_change(lambda: None)
        assert self.shadow_before is not None
        for b in range(16):  # shadow RAM written but not shown becomes visible
            if self.shadow_used[b] and not self.shadow_before[b]:
                self.shadow_newer[b] = True
        self.pam_valid, self.pci_used = False, False
        self.pam_off_pending, self.pam_gone = True, self.keep_rom

    def _open_bus_read(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        if self.vga_card_rom is not None:  # the VGA card's expansion ROM, where it is enabled
            bar = int.from_bytes(bytes(self.pci_devices[(2, 0)][0x30:0x34]), "little")
            base = bar & 0xFFFF0000
            if bar & 1 and base and base <= addr < base + len(self.vga_card_rom):
                uc.mem_write(addr, self.vga_card_rom[addr - base : addr - base + size])
                return
        if self.sis496 and 2 * self.ram_top <= addr <= 3 * self.ram_top - size:
            # the RAM seen again at twice its size: how AMI's sizing on the SiS 85C496 finds
            # a 16 MB bank (the pattern from address 0 at +32 MB, not at +16 MB)
            uc.mem_write(addr, bytes(uc.mem_read(addr - 2 * self.ram_top, size)))
            return
        if self.row_aliased and addr + size <= self.row_aliased:
            # within DRAM row 0 (430FX/HX/VX/TX) the RAM is seen again every ram_top bytes, as
            # DIMMs with fewer address lines than the row is set for are: AMI finds its size so
            uc.mem_write(addr, bytes(uc.mem_read(addr % self.ram_top, size)))
            return
        if 0xFFB00000 <= addr < 0xFFC00000 and addr & 0xFFFF == 2:
            # a firmware hub's block lock registers (Intel 82802, at +2 in each 64 KB block
            # of its register space) keep what is written: AMI Hi-Flex on the 810 (MSI
            # MS-6305) writes 0 to each and waits until it reads back 0
            return
        if 0xFEE00000 <= addr < 0xFEE01000:
            # the local APIC's registers keep what is written (0 at first): the interrupt
            # command register's delivery status reads idle, as multiprocessor setup waits for
            return
        if 0xFED00000 <= addr < 0xFEE00000 and bytes(self.pci_devices.get((17, 0), b"")[0:4]) in (
            b"\x06\x11\x09\x84",
            b"\x06\x11\x24\x83",
        ):
            # VX855/CX700 chipset registers there (an SPI controller like an ICH's: Wyse Cx0's
            # TrustedCore waits for its cycle-in-progress bit to clear): idle, all 0
            uc.mem_write(addr, bytes(size))
            return
        if addr >= 0xFE000000:  # (chipset space: keeps what is written; Tyan's Phoenix 4.0
            return  # puts its protected-mode stack at FEF2xxxxh)
        if addr >= 0xF8000000:  # (also kept: the OptiPlex 780 boot block keeps status
            return  # words and a descriptor table at F8xxxxxxh)
        uc.mem_write(addr, b"\xff" * size)  # whatever was written there is gone

    def _apic_smi(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        """An SMI sent through the local APIC (ICR delivery mode 010b): the code waiting for
        its handler has just been unpacked; it is patched (SMI_FLAG_WAIT) and run anew.
        Dell's wait (DELL_SMI_WAIT) is in the code running now: it is patched between two
        runs."""
        if addr != 0xFEE00300 or value >> 8 & 7 != 2:
            return
        if DELL_SMI_WAIT.search(bytes(uc.mem_read(0, 0x100000))):
            self.smi_ack_pending = self.flush_pending = True
            uc.emu_stop()
        elif self.smi_flag_wait and self._patch_msr_reads():
            self.flush_pending = True  # (once: the store is done again when the run goes on)
            uc.emu_stop()

    def _sis496_bank_read(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        """SiS 85C496 DRAM banks (ends in 48h-4Fh): the RAM is all in bank 0; while its end
        is 0, the bank being sized at address 0 is one of the empty ones."""
        if self.pci_devices[(5, 0)][0x48] == 0:
            uc.mem_write(addr, b"\xff" * size)

    def _clear_screen(self, attr: int) -> None:
        self.uc.mem_write(VRAM, bytes([0x20, attr]) * (COLS * ROWS))

    def _cursor(self) -> tuple[int, int]:
        col, row = self.uc.mem_read(0x450, 2)
        return col, row

    def _set_cursor(self, col: int, row: int) -> None:
        self.uc.mem_write(0x450, bytes([col & 0xFF, row & 0xFF]))

    def _put(self, col: int, row: int, ch: int, attr: int | None) -> None:
        if 0 <= col < COLS and 0 <= row < ROWS:
            addr = VRAM + (row * COLS + col) * 2
            self.uc.mem_write(addr, bytes([ch]) if attr is None else bytes([ch, attr]))

    def _scroll(
        self, lines: int, attr: int, top: int, left: int, bottom: int, right: int, up: bool
    ) -> None:
        bottom, right = min(bottom, ROWS - 1), min(right, COLS - 1)
        height = bottom - top + 1
        rows = [
            [self.uc.mem_read(VRAM + (r * COLS + left) * 2, (right - left + 1) * 2)]
            for r in range(top, bottom + 1)
        ]
        blank = bytes([0x20, attr]) * (right - left + 1)
        for i in range(height):
            src = i + lines if up else i - lines
            data = rows[src][0] if lines and 0 <= src < height else blank
            if lines == 0:
                data = blank
            self.uc.mem_write(VRAM + ((top + i) * COLS + left) * 2, bytes(data))

    def _teletype(self, ch: int, attr: int | None) -> None:
        col, row = self._cursor()
        if ch == 0x0D:
            col = 0
        elif ch == 0x0A:
            row += 1
        elif ch == 0x08:
            col = max(0, col - 1)
        elif ch == 0x07:
            pass
        else:
            self._put(col, row, ch, attr)
            col += 1
            if col >= COLS:
                col, row = 0, row + 1
        if row >= ROWS:
            self._scroll(1, 0x07, 0, 0, ROWS - 1, COLS - 1, True)
            row = ROWS - 1
        self._set_cursor(col, row)

    # --- interrupts -------------------------------------------------------------------------

    def _set_cf(self, value: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags | 1 if value else flags & ~1)

    def _set_zf(self, value: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x40 if value else flags & ~0x40)

    def press_keys(self, scancodes: list[int], when_text: str = "", paced: bool = False) -> None:
        """Keys pressed on the keyboard itself (scan codes), e.g. DEL during POST: each one is
        put in the 8042 and raised as IRQ 1 once the program has an INT 09h handler and
        interrupts enabled, and has read the previous one. With when_text, typing starts
        only when that text is on the screen (like a person waiting for "Hit DEL ...").
        paced: each key (prefix, make and break code) is pressed only when the program asks
        for input with nothing in its buffer, as a person reacts to the screen; programs
        that clear the buffer after a key do not lose the next one."""
        # a reply to a keyboard command nobody read (e.g. FA AB 83 for "read ID") would sit
        # in front of the keys for good: a real keyboard's bytes would long have been taken
        if self.kbc_queue and self.kbc_queue[0] in KBC_REPLIES:
            self.kbc_queue, self.irq_pending = [], False
        # releases still to come from the previous keys go first
        self.hw_keys = [b for b in self.hw_keys if b >= 0x80 or b in (0xE0, 0xE1)] + list(scancodes)
        self.hw_keys_when = when_text.encode()
        self.hw_paced, self.key_wanted, self.hw_prev = paced, False, 0
        self.bios_keyboard = True
        self._start_typing()

    def _start_typing(self) -> None:
        if self.irq_hook is not None or not self.hw_keys:
            return
        if self.hw_keys_when:
            text = bytes(self.uc.mem_read(VRAM, COLS * ROWS * 2))[0::2]
            if self.hw_keys_when not in text:
                return
        self._want_hook("irq_hook")

    def _irq1_again(self) -> None:
        """The keyboard hook back after it was parked while IRQ 1 was held back."""
        if (
            self.irq1_parked
            and self.irq_hook is None
            and self.irq_pending
            and (self.kbc_command_byte & 0x01 and not self.pic_mask & 0x02)
        ):
            self.irq1_parked = False
            self._want_hook("irq_hook")

    def _irq1(self, uc: Uc, address: int, size: int, generation: int) -> None:
        if generation != self.hook_generation["irq_hook"] or self.irq_hook is None:
            return
        # the next key goes into the 8042 output buffer as soon as it is empty and the keyboard
        # is enabled; programs may read it there directly (POST polls port 60h for DEL)
        if not self.kbc_queue:
            self.irq_pending = False
            if self.key_gap > 0:  # the INT 09h handler finishes before the next byte comes
                self.key_gap -= 1
                return
            if not self.hw_keys:
                self._retire("irq_hook")
                return
            if self.kbc_command_byte & 0x10:  # keyboard disabled
                return
            byte = self.hw_keys[0]
            # pressing and releasing are separate moments (a prefix belongs to its code):
            # programs that act on a key and then wait for its release see both in order
            starts_key = byte in (0xE0, 0xE1) or self.hw_prev not in (0xE0, 0xE1)
            if self.hw_paced and starts_key:
                if not self.key_wanted:
                    # a long wait (e.g. while a setup draws its screen) without a call per
                    # block: INT 16h brings the hook back. Short waits keep it, since adding a
                    # hook makes Unicorn translate the code again.
                    self.key_idle += 1
                    if self.key_idle > 50_000:
                        self._park("irq_hook")
                    return
                self.key_idle = 0
                code = self.hw_keys[1] if byte in (0xE0, 0xE1) and len(self.hw_keys) > 1 else byte
                # a press uses up the program's request; a release does too when the program
                # polls (AH=01h/11h), so the next press waits for another look at the keyboard,
                # but not when it waits inside INT 16h (AH=00h/10h): it gets the next key there
                if code < 0x80 or not self.key_wait_blocking:
                    self.key_wanted, self.idle_looks = False, 0
                if code < 0x80:
                    self._advance_ticks(9)  # about half a second passes between two keys
            self.hw_prev = self.hw_keys.pop(0)
            self.kbc_queue, self.irq_pending, self.kbc_aux = [self.hw_prev], True, False
        elif self.reply_grace > 0 and not self.irq_pending:
            # the program that sent the command polls for its reply at once: it reads it
            # before IRQ 1's handler can take it (ICT 54IT6, AMI WinBIOS 07/15/95: C0h,
            # then a wait for the byte without a timeout while DEL is typed)
            self.reply_grace -= 1
        elif not self.irq_pending and not self.kbc_aux and self.kbc_reads != self.irq_read_mark:
            # a byte left in the output buffer (e.g. an unread command reply) raises IRQ 1 too,
            # once: the INT 09h handler reads it, and the keys behind it can follow
            self.irq_pending, self.irq_read_mark = True, self.kbc_reads
        # IRQ 1 follows only with the interrupt enabled in the 8042 command byte, IRQ 1
        # unmasked in the PIC and interrupts enabled in the CPU
        # (and not while its handler runs: the PIC holds IRQ 1 in service until the EOI,
        # though handlers may enable interrupts before they read the byte)
        if not self.irq_pending or not uc.reg_read(UC_X86_REG_EFLAGS) & 0x200:
            return
        ip = (address - (uc.reg_read(UC_X86_REG_CS) << 4)) & 0xFFFFFFFF
        if (
            not self.kbc_command_byte & 0x01
            or self.pic_mask & 0x02
            or self.irq1_in_service
            or ip > 0xFFFF
        ):  # held back by the 8042, the PIC or protected mode
            # for long (a memory test with IRQ 1 masked): without a call per instruction; a
            # write to the PIC mask, an EOI or a new 8042 command byte brings the hook back
            self.irq1_blocked += 1
            if self.irq1_blocked > 50_000:
                self.irq1_blocked, self.irq1_parked = 0, True
                self._park("irq_hook")
            return
        uc.reg_write(UC_X86_REG_EIP, ip)  # the interrupt returns to the start of this block
        if self._deliver(uc, 9):
            self.irq_pending, self.irq1_in_service, self.irq1_blocked = False, True, 0
        else:  # no INT 09h handler yet (DEL tapped early in POST): wait for one without a
            # call per instruction; the PIC set-up or an EOI brings the hook back
            self.irq1_blocked += 1
            if self.irq1_blocked > 50_000:
                self.irq1_blocked, self.irq1_parked = 0, True
                self._park("irq_hook")

    def _aux_irq(self, uc: Uc, address: int, size: int, generation: int) -> None:
        """IRQ 12 (INT 74h) for a byte from the PS/2 mouse waiting in the 8042, once per byte,
        with the mouse interrupt on in the command byte (bit 1), IRQ 12 and the cascade
        unmasked and interrupts enabled: Apricot HN440's PhoenixBIOS sends D4h commands and
        waits until its INT 74h handler has read the reply."""
        if generation != self.hook_generation["aux_hook"] or self.aux_hook is None:
            return
        if not self.kbc_queue or not self.kbc_aux:
            self._retire("aux_hook")
            return
        if (
            self.aux_mark == self.kbc_reads
            or not self.kbc_command_byte & 0x02
            or self.pic2_mask & 0x10
            or self.pic_mask & 0x04
            or not uc.reg_read(UC_X86_REG_EFLAGS) & 0x200
        ):
            return
        ip = (address - (uc.reg_read(UC_X86_REG_CS) << 4)) & 0xFFFFFFFF
        if ip > 0xFFFF:
            return
        uc.reg_write(UC_X86_REG_EIP, ip)  # (the interrupt returns to the start of this block)
        if self._deliver(uc, 0x74):
            self.aux_mark = self.kbc_reads

    def _deliver(self, uc: Uc, intno: int) -> bool:
        """Run the handler the ROM installed itself (POST sets up INT 13h/15h etc.) like the
        CPU would: push FLAGS, CS, IP and jump through the vector. False when there is none."""
        off, seg = struct.unpack("<HH", uc.mem_read(intno * 4, 4))
        if (off, seg) == (0x500, 0) or uc.reg_read(UC_X86_REG_CR0) & 1:
            return False
        r = uc.reg_read
        flags = r(UC_X86_REG_EFLAGS)
        # push FLAGS / push CS / push IP / jmp far handler
        stub = struct.pack(
            "<BHBHBHBHH",
            0x68,
            flags & 0xFFFF,
            0x68,
            r(UC_X86_REG_CS),
            0x68,
            r(UC_X86_REG_IP),
            0xEA,
            off,
            seg,
        )
        uc.mem_write(DELIVER_STUB_AT, stub)
        uc.ctl_remove_cache(DELIVER_STUB_AT, DELIVER_STUB_AT + 16)
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x300)  # clear IF and TF
        uc.reg_write(UC_X86_REG_CS, 0)
        uc.reg_write(UC_X86_REG_EIP, DELIVER_STUB_AT)
        return True

    def _deliver_pm(self, uc: Uc, intno: int) -> bool:
        """A CPU exception in protected mode through the program's own IDT gate, as the CPU
        would (Unicorn hands every interrupt to the hook instead): FLAGS, CS, IP and, for
        the exceptions that have one, an error code (0) pushed, CS:EIP from the gate. The
        early Award 286 BIOS tests its exception handlers with BOUND (INT 5): ignored, the
        faulting instruction ran again for good. False when there is no usable gate."""
        r = uc.reg_read
        _, idt_base, idt_limit, _ = r(UC_X86_REG_IDTR)
        if intno * 8 + 7 > idt_limit:
            return False
        gate = bytes(uc.mem_read(idt_base + intno * 8, 8))
        kind = gate[5] & 0x9F  # present, type (DPL ignored: the BIOS runs in ring 0)
        if kind not in (0x86, 0x87, 0x8E, 0x8F):  # 286 / 386 interrupt and trap gates
            return False
        wide = kind >= 0x8E
        target = gate[0] | gate[1] << 8 | ((gate[6] | gate[7] << 8) << 16 if wide else 0)
        selector = gate[2] | gate[3] << 8
        _, gdt_base, gdt_limit, _ = r(UC_X86_REG_GDTR)
        ss = r(UC_X86_REG_SS)
        if ss & 4 or (ss & ~7) + 7 > gdt_limit or (selector & ~7) + 7 > gdt_limit:
            return False
        d = bytes(uc.mem_read(gdt_base + (ss & ~7), 8))
        ss_base, big_stack = d[2] | d[3] << 8 | d[4] << 16 | d[7] << 24, bool(d[6] & 0x40)
        flags, cs, eip = r(UC_X86_REG_EFLAGS), r(UC_X86_REG_CS), r(UC_X86_REG_EIP)
        words = [flags, cs, eip]
        code = bytes(uc.mem_read(self._code_address() - 2, 2))
        if intno in (8, 10, 11, 12, 13, 14, 17) and code != bytes([0xCD, intno]):
            words.append(0)  # (a fault's error code; INT n pushes none)
        size = 4 if wide else 2
        sp = r(UC_X86_REG_ESP) if big_stack else r(UC_X86_REG_SP)
        for value in words:
            sp = (sp - size) & (0xFFFFFFFF if big_stack else 0xFFFF)
            uc.mem_write(ss_base + sp, (value & (1 << 8 * size) - 1).to_bytes(size, "little"))
        uc.reg_write(UC_X86_REG_ESP if big_stack else UC_X86_REG_SP, sp)
        cleared = 0x4100 | (0x200 if kind in (0x86, 0x8E) else 0)  # TF, NT; IF for a gate
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~cleared)
        uc.reg_write(UC_X86_REG_CS, selector)
        uc.reg_write(UC_X86_REG_EIP, target)
        return True

    def _intr(self, uc: Uc, intno: int, _user: object) -> None:
        r = uc.reg_read
        ah = r(UC_X86_REG_AH)
        if self.event_wait_over and intno == 0x15 and r(UC_X86_REG_AX) == 0x8300:
            # ("set event wait interval": the wait's flag byte at ES:BX set at once; IBM's
            # beep before its setup waits on it, and no RTC interrupt ends it here)
            uc.mem_write((r(UC_X86_REG_ES) << 4) + (r(UC_X86_REG_BX) & 0xFFFF), b"\x80")
        if intno in (0, 8) and self._div_overflow(uc):
            pc = self._code_address()
            if pc not in self.div_sites:
                self.div_sites.add(pc)
                self.div_new.append(pc)
                self._want_hook("div_guard")
            return
        idt_limit = r(UC_X86_REG_IDTR)[2]
        if self.kbc_reset_in_place and idt_limit < intno * (8 if r(UC_X86_REG_CR0) & 1 else 4) + 3:
            # an interrupt outside the table: the CPU shuts down and the board resets it
            # (Phoenix NuBIOS 4.02 returns from protected mode with LIDT 0:0 and INT 1)
            self.cpu_reset_pending = True
            uc.emu_stop()
            return
        if intno < 0x20 and r(UC_X86_REG_CR0) & 1 and self._deliver_pm(uc, intno):
            return
        if intno == 8 and r(UC_X86_REG_CR0) & 1 and self.kbc_reset_in_place:
            # the double fault has no usable gate either, so the CPU shuts down and the board
            # resets itself (C386SX v1.0 leaves its protected-mode memory pass with a
            # deliberate triple fault; the gate for vector 8 holds a RAM-test pattern)
            self.cpu_reset_pending = True
            uc.emu_stop()
            return
        if intno == 0x13 and self.bootstrap and self.boot_without_disk and self.boot_failures < 200:
            self.boot_failures += 1
            self.uc.reg_write(UC_X86_REG_AX, 0x8000 | r(UC_X86_REG_AL))  # timeout: not ready
            self._set_cf(True)
            return
        if intno in (0x13, 0x18) and self.bootstrap:  # loading the operating system
            self.stopped_reason = "booting (INT 19h)"
            raise Stop()
        if intno in (0x13, 0x14, 0x15, 0x17) and self._deliver(uc, intno):
            return
        # (the tick of the ROM's own INT 08h: ServerWorks' POST shows its logo from there)
        if intno == 0x1C and self.timer_irq and self._deliver(uc, intno):
            return
        if intno == 0x1A and ah == 0xB1:  # PCI BIOS: the ROM's own services (Fujitsu-Siemens
            if self._deliver(uc, intno):  # D1185 looks for its audio device by class until
                return  # "not found"); without them nothing is found
            uc.reg_write(UC_X86_REG_AH, 0x86)
            self._set_cf(True)
            return
        if intno == 0x19:  # end of POST: the ROM's bootstrap may still run setup (MR BIOS
            self.bootstrap = True  # does); it ends at the first disk access
            if self._deliver(uc, intno):
                return
            self.stopped_reason = "booting (INT 19h)"
            raise Stop()
        if intno == 0x10:
            self._int10(ah)
            self._start_typing()
        elif intno == 0x16 and self.bios_keyboard:
            self.key_gap = 0  # asking for a key: its INT 09h handler has finished
            self.irq1_in_service = False
            # keys typed on the keyboard (press_keys) go through the ROM's own INT 09h/16h and
            # its key buffer; only when nothing is left to type does a wait end the run
            head, tail = struct.unpack("<HH", uc.mem_read(0x41A, 4))
            if head == tail and not self.kbc_queue and ah in (0, 1, 0x10, 0x11):
                # the program is ready for the next key when it waits for one, or keeps
                # looking: a single look may be a check while it redraws (a key there
                # would be taken as "stop drawing"), a person presses once the screen stands
                self.idle_looks += 1
                if ah in (0, 0x10) or self.idle_looks >= IDLE_LOOKS:
                    self.key_wanted = True
                    self.key_wait_blocking = ah in (0, 0x10)
                    self.key_idle = 0
                    if self.irq_hook is None and self.hw_keys:
                        self._want_hook("irq_hook")
            # only releases left to type: they make no key, so the program has nothing to read
            makes = any(b < 0x80 and b not in (0xE0, 0xE1) for b in self.hw_keys)
            # (a keyboard's reply nobody reads, e.g. FAh for "set LEDs", is no key either)
            pending = any(b not in KBC_REPLIES for b in self.kbc_queue)
            if makes or pending or head != tail or ah not in (0, 1, 0x10, 0x11):
                self.key_polls = 0
                if self._deliver(uc, 0x16):
                    return
            if ah in (0x00, 0x10):
                self.stopped_reason = "waiting for a key"
                raise Stop()
            self.key_polls += 1
            if self.key_polls > 200:
                self.stopped_reason = "polling the keyboard"
                raise Stop()
            self._set_zf(True)
        elif intno == 0x16:
            # Keys arrive like a person typing: one at a time, while the program waits. A
            # status check (AH=01) only reports a key once the program polls in a loop, so
            # routines that flush type-ahead before reading do not discard the keys.
            if ah in (0x00, 0x10):
                self.key_polls = 0
                if not self.keys:
                    self.stopped_reason = "waiting for a key"
                    raise Stop()
                uc.reg_write(UC_X86_REG_AX, self.keys.pop(0))
            elif ah in (0x01, 0x11):
                self.key_polls += 1
                if not self.keys:
                    if self.key_polls > 200:
                        self.stopped_reason = "polling the keyboard"
                        raise Stop()
                    self._set_zf(True)
                elif self.key_polls < 3:
                    self._set_zf(True)
                else:
                    uc.reg_write(UC_X86_REG_AX, self.keys[0])
                    self._set_zf(False)
            elif ah in (0x02, 0x12):
                uc.reg_write(UC_X86_REG_AL, 0)
        elif intno == 0x11:
            uc.reg_write(UC_X86_REG_AX, 0x0021)
        elif intno == 0x12:
            uc.reg_write(UC_X86_REG_AX, 640)
        elif intno == 0x1A:
            if ah == 0:  # timer ticks keep running, so code waiting for a tick continues
                self.ticks += 1
                uc.reg_write(UC_X86_REG_CX, self.ticks >> 16)
                uc.reg_write(UC_X86_REG_DX, self.ticks & 0xFFFF)
                uc.reg_write(UC_X86_REG_AL, 0)
            elif ah == 2:  # RTC time (BCD) from CMOS
                uc.reg_write(UC_X86_REG_CH, self.cmos[4])
                uc.reg_write(UC_X86_REG_CL, self.cmos[2])
                uc.reg_write(UC_X86_REG_DH, self.cmos[0])
            elif ah == 4:  # RTC date (BCD) from CMOS
                uc.reg_write(UC_X86_REG_CH, self.cmos[0x32])
                uc.reg_write(UC_X86_REG_CL, self.cmos[9])
                uc.reg_write(UC_X86_REG_DH, self.cmos[8])
                uc.reg_write(UC_X86_REG_DL, self.cmos[7])
            self._set_cf(False)
        elif intno == 0x15 and ah == 0x88:  # extended memory size in KB
            uc.reg_write(UC_X86_REG_AX, self.cmos[0x17] | self.cmos[0x18] << 8)
            self._set_cf(False)
        elif intno in (0x13, 0x15, 0x17, 0x14):
            uc.reg_write(UC_X86_REG_AH, 0x86 if intno == 0x15 else 0x80)
            self._set_cf(True)
        elif intno >= 0x20 and intno not in (0x21, 0x2F, 0x33):
            # other software interrupts go to the handler the ROM installed, e.g. MR BIOS
            # enters its unpacked setup program with INT C0h; without one they are ignored
            self._deliver(uc, intno)
        # all other interrupts: ignored

    def _int10(self, ah: int) -> None:
        r, uc = self.uc.reg_read, self.uc
        if ah == 0x00:  # mode set: ROM font and palette, blinking on; AL bit 7 keeps the screen
            if not r(UC_X86_REG_AL) & 0x80:
                self._clear_screen(0x07)
                for plane in self.vga_planes:  # graphics memory too
                    plane[:] = bytes(len(plane))
            # the mode's register values: all planes written, write mode 0, no set/reset
            self.vga_seq[2] = 0x0F
            self.vga_gc[0:9] = bytes([0, 0, 0, 0, 0, 0, 0x05, 0x0F, 0xFF])
            self._set_cursor(0, 0)
            self.uc.mem_write(FONT_PLANE, bytes(256 * 32))
            self.palette_regs, self.dac, self.blink = list(DEFAULT_PALETTE), list(DEFAULT_DAC), True
            self.char_height = {200: 8, 350: 14}.get(self.scan_lines, 16)
            # the BIOS data area describes the mode (programs look there rather than ask);
            # of the graphics modes the 16-color ones are kept in the planes (screen())
            mode = self.video_mode = r(UC_X86_REG_AL) & 0x7F
            self.uc.mem_write(0x449, bytes([mode]) + struct.pack("<HH", COLS, 0x1000))
            self.uc.mem_write(0x463, struct.pack("<H", 0x3B4 if mode == 7 else 0x3D4))
            self.uc.mem_write(0x484, bytes([ROWS - 1, self.char_height, 0]))
        elif ah == 0x02:
            self._set_cursor(r(UC_X86_REG_DL), r(UC_X86_REG_DH))
        elif ah == 0x03:
            col, row = self._cursor()
            uc.reg_write(UC_X86_REG_DX, row << 8 | col)
            uc.reg_write(UC_X86_REG_CX, 0x0607)
        elif ah in (0x06, 0x07):
            self._scroll(
                r(UC_X86_REG_AL),
                r(UC_X86_REG_BH),
                r(UC_X86_REG_CH),
                r(UC_X86_REG_CL),
                r(UC_X86_REG_DH),
                r(UC_X86_REG_DL),
                ah == 0x06,
            )
        elif ah == 0x08:
            col, row = self._cursor()
            ch, attr = uc.mem_read(VRAM + (row * COLS + col) * 2, 2)
            uc.reg_write(UC_X86_REG_AX, attr << 8 | ch)
        elif ah in (0x09, 0x0A):
            col, row = self._cursor()
            ch, attr = r(UC_X86_REG_AL), r(UC_X86_REG_BL) if ah == 0x09 else None
            for i in range(r(UC_X86_REG_CX)):
                pos = row * COLS + col + i
                if pos >= COLS * ROWS:
                    break
                self._put(pos % COLS, pos // COLS, ch, attr)
        elif ah in (0x0C, 0x0D) and self.video_mode in PLANAR_MODES:
            # write / read a pixel in the 16-color modes (Quadtel draws its logo with them and
            # follows the outline back by reading pixels)
            x, y = r(UC_X86_REG_CX), r(UC_X86_REG_DX)
            width, height = PLANAR_MODES[self.video_mode]
            if x < width and y < height:
                off, bit = y * (width // 8) + x // 8, 0x80 >> (x & 7)
                if ah == 0x0D:
                    color = sum(1 << p for p in range(4) if self.vga_planes[p][off] & bit)
                    uc.reg_write(UC_X86_REG_AX, r(UC_X86_REG_AX) & 0xFF00 | color)
                else:
                    color = r(UC_X86_REG_AL)
                    for p in range(4):
                        v = self.vga_planes[p][off]
                        if color & 0x80:  # bit 7: XOR into the screen
                            v ^= bit if color >> p & 1 else 0
                        else:
                            v = v | bit if color >> p & 1 else v & ~bit & 0xFF
                        self.vga_planes[p][off] = v
            elif ah == 0x0D:
                uc.reg_write(UC_X86_REG_AX, r(UC_X86_REG_AX) & 0xFF00)
        elif ah == 0x0E:
            self._teletype(r(UC_X86_REG_AL), None)
        elif ah == 0x0F:  # the mode set last (a program may switch back to text only if asked)
            uc.reg_write(
                UC_X86_REG_AX, COLS << 8 | (self.video_mode if self.video_mode is not None else 3)
            )
            uc.reg_write(UC_X86_REG_BH, 0)
        elif ah == 0x13:
            al, attr = r(UC_X86_REG_AL), r(UC_X86_REG_BL)
            n, row, col = r(UC_X86_REG_CX), r(UC_X86_REG_DH), r(UC_X86_REG_DL)
            addr = (r(UC_X86_REG_ES) << 4) + r(UC_X86_REG_BP)
            data = uc.mem_read(addr, n * (2 if al & 2 else 1))
            save = self._cursor()
            self._set_cursor(col, row)
            for i in range(n):
                ch = data[i * 2] if al & 2 else data[i]
                a = data[i * 2 + 1] if al & 2 else attr
                # BEL, BS, CR and LF are control characters here too (Phoenix 1.10's setup
                # writes its lines with CR LF in one string)
                self._teletype(ch, a)
            if not al & 1:
                self._set_cursor(*save)
        elif r(UC_X86_REG_AX) == 0x1130:  # font information: ES:BP, bytes per char, rows - 1
            height = {2: 14, 3: 8, 4: 8, 5: 14, 6: 16, 7: 16}.get(
                r(UC_X86_REG_BH), self.char_height
            )
            addr = FONT_ADDRS[height] + (0x400 if r(UC_X86_REG_BH) == 4 else 0)  # 4: upper half
            uc.reg_write(UC_X86_REG_ES, addr >> 4)
            uc.reg_write(UC_X86_REG_BP, addr & 0xF)
            uc.reg_write(UC_X86_REG_CX, self.char_height)
            uc.reg_write(UC_X86_REG_DL, ROWS - 1)
        elif ah == 0x10:
            self._int10_palette(r(UC_X86_REG_AL))
        elif ah == 0x12 and r(UC_X86_REG_BL) == 0x30:  # scan lines for the next mode set
            self.scan_lines = {0: 200, 1: 350, 2: 400}.get(r(UC_X86_REG_AL), 400)
            uc.reg_write(UC_X86_REG_AL, 0x12)
        elif ah == 0x12:
            uc.reg_write(UC_X86_REG_BL, 0x03)  # EGA/VGA present, 256 KB
            uc.reg_write(UC_X86_REG_BH, 0)
        elif ah == 0x1A:
            uc.reg_write(UC_X86_REG_AL, 0x1A)
            uc.reg_write(UC_X86_REG_BX, 0x0008)  # VGA color

    def _int10_palette(self, al: int) -> None:
        r, uc = self.uc.reg_read, self.uc
        table = (r(UC_X86_REG_ES) << 4) + r(UC_X86_REG_DX)
        if al == 0x00:  # one palette register
            self.palette_regs[r(UC_X86_REG_BL) & 0x0F] = r(UC_X86_REG_BH) & 0x3F
        elif al == 0x02:  # all 16 (+ overscan)
            self.palette_regs = [v & 0x3F for v in uc.mem_read(table, 16)]
        elif al == 0x03:  # BL=0: attribute bit 7 is a bright background, BL=1: blinking
            self.blink = bool(r(UC_X86_REG_BL) & 1)
        elif al == 0x10:  # one DAC register
            self.dac[r(UC_X86_REG_BX) & 0xFF] = (
                r(UC_X86_REG_DH) & 0x3F,
                r(UC_X86_REG_CH) & 0x3F,
                r(UC_X86_REG_CL) & 0x3F,
            )
        elif al == 0x12:  # a block of DAC registers
            start, count = r(UC_X86_REG_BX) & 0xFF, r(UC_X86_REG_CX)
            data = uc.mem_read(table, 3 * min(count, 256 - start))
            for i in range(len(data) // 3):
                self.dac[start + i] = tuple(v & 0x3F for v in data[3 * i : 3 * i + 3])

    def _vga_read(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        """A read loads the latches (what the program gets is not modelled)."""
        off = (addr + size - 1) & 0xFFFF
        self.vga_latch = [p[off] for p in self.vga_planes]

    def _vga_write(
        self, uc: Uc, access: int, addr: int, size: int, value: int, _user: object
    ) -> None:
        if self.video_mode not in PLANAR_MODES:
            return
        gc, mask = self.vga_gc, self.vga_seq[2]
        mode, func, bitmask = gc[5] & 3, gc[3] >> 3 & 3, gc[8]
        for i in range(size):
            off, v = (addr + i) & 0xFFFF, value >> 8 * i & 0xFF
            for p in range(4):
                if not mask >> p & 1:
                    continue
                latch = self.vga_latch[p]
                if mode == 1:  # copy the latches
                    self.vga_planes[p][off] = latch
                    continue
                if mode == 0:
                    d = (0xFF if gc[0] >> p & 1 else 0) if gc[1] >> p & 1 else _rotate(v, gc[3])
                    bm = bitmask
                elif mode == 2:
                    d, bm = (0xFF if v >> p & 1 else 0), bitmask
                else:
                    d, bm = (0xFF if gc[0] >> p & 1 else 0), _rotate(v, gc[3]) & bitmask
                d = (
                    d & latch
                    if func == 1
                    else d | latch if func == 2 else d ^ latch if func == 3 else d
                )
                self.vga_planes[p][off] = d & bm | latch & ~bm & 0xFF

    def _graphics_screen(self) -> Screen:
        """A 16-color graphics screen read back as text: the 8x16 VGA font, in rows of 16
        pixels or (480-line setups with 25 rows) of 19 pixels starting a few lines down; the
        grid with the most exactly recognised characters is used."""
        width, height = PLANAR_MODES[self.video_mode]
        if self.graphics_font is not None:  # the program's own font: one cell per glyph
            font, h = self.graphics_font
            font = font[: 256 * h].ljust(256 * h, bytes(1))
            grids = [(h, top, (height - top) // h) for top in range(4)]
        else:
            font, h = FONTS[16], 16
            grids = [(16, 0, height // 16)]
            if height == 480:
                grids += [(19, top, 25) for top in range(4)]
        best: tuple[Screen, int, tuple[int, int, int]] | None = None
        if self.graphics_grid in grids:  # the grid of earlier screens, if it fits this one too
            grids = [self.graphics_grid] + [g for g in grids if g != self.graphics_grid]
        hits = []
        for grid in grids:
            screen, exact_hits = self._read_cells(width, *grid, font, h)
            hits.append(exact_hits)
            if best is None or exact_hits > best[1]:
                best = (screen, exact_hits, grid)
            if grid == self.graphics_grid and exact_hits >= grid[2] * (width // 8) * GOOD_GRID:
                break
        else:  # remembered when it beats the others clearly (blank cells match on any grid)
            assert best is not None
            runner_up = sorted(hits)[-2] if len(hits) > 1 else 0
            if best[1] >= 2 * runner_up and best[1] >= best[0].rows * (width // 8) * GOOD_GRID:
                self.graphics_grid = best[2]
        assert best is not None
        s = best[0]
        s.font, s.blink, s.char_height = font, False, h
        # the picture is made when the screen is rendered (most captures only need the text)
        planes = [bytes(p) for p in self.vga_planes]
        palette = [tuple(v * 255 // 63 for v in self.dac[p]) for p in self.palette_regs]
        s.image_factory = lambda: _planes_image(planes, palette, width, height)
        s.palette = [tuple(v * 255 // 63 for v in self.dac[p]) for p in self.palette_regs]
        if not any(any(c) for c in s.palette):
            s.palette = [tuple(v * 255 // 63 for v in DEFAULT_DAC[p]) for p in DEFAULT_PALETTE]
        return s

    def _graphics_image(self, width: int, height: int) -> Any:
        """The planes as a picture, in the program's palette."""
        palette = [tuple(v * 255 // 63 for v in self.dac[p]) for p in self.palette_regs]
        return _planes_image(self.vga_planes, palette, width, height)

    def _read_cells(
        self, width: int, pitch: int, top: int, rows: int, font: bytes, h: int
    ) -> tuple[Screen, int]:
        """Each 8xh cell (two colors at most) matched against the font."""
        exact, glyphs = _glyph_table(font, h)
        cols, stride, planes = width // 8, width // 8, self.vga_planes
        s, hits = Screen(cols, rows), 0
        for row in range(rows):
            for col in range(cols):
                base = (row * pitch + top) * stride + col
                cell = [bytes(planes[p][base : base + h * stride : stride]) for p in range(4)]
                if all(c.count(c[0]) == h and c[0] in (0, 0xFF) for c in cell):  # one color
                    color = sum(1 << p for p in range(4) if cell[p][0])
                    s.put(col, row, 0x20, color << 4)
                    continue
                pixels = []  # h lines of 8 colors
                for y in range(h):
                    b = [cell[p][y] for p in range(4)]
                    pixels.append(
                        [
                            (b[0] >> 7 - x & 1)
                            | (b[1] >> 7 - x & 1) << 1
                            | (b[2] >> 7 - x & 1) << 2
                            | (b[3] >> 7 - x & 1) << 3
                            for x in range(8)
                        ]
                    )
                counts: dict[int, int] = {}
                for line in pixels:
                    for c in line:
                        counts[c] = counts.get(c, 0) + 1
                if len(counts) == 1:
                    s.put(col, row, 0x20, next(iter(counts)) << 4)
                    continue
                bg, fg = sorted(counts, key=counts.__getitem__, reverse=True)[:2]
                bits = 0
                for line in pixels:  # pixels of the foreground color (others: background)
                    for c in line:
                        bits = bits << 1 | (c == fg)
                lines = [bits >> 8 * (h - 1 - y) & 0xFF for y in range(h)]
                box = _box_char(lines)  # frames: CP437 line characters, whatever font drew them
                if box is not None:
                    s.put(col, row, box, bg << 4 | fg)
                    hits += 1
                    continue
                ch = exact.get(bits)
                full = (1 << 8 * h) - 1
                if ch is None and (bits ^ full) in exact:
                    ch, fg, bg = exact[bits ^ full], bg, fg
                if ch is not None:
                    hits += 1
                else:
                    distance = [(g ^ bits).bit_count() for g in glyphs]  # the nearest glyph
                    ch = min(range(256), key=distance.__getitem__)
                s.put(col, row, ch, bg << 4 | fg)
        return s, hits

    def _pm_offset(self, port: int) -> int | None:
        """Offset of port in the power management I/O space: an ICH's (base at LPC 40h, 128
        ports) or a PIIX4's (base at function 3 40h, 64 ports; e.g. GPI at 30h reads 0)."""
        lpc = self.pci_devices.get((31, 0))
        if lpc is not None and lpc[0:2] == bytes((0x86, 0x80)):
            base = int.from_bytes(bytes(lpc[0x40:0x42]), "little") & 0xFF80
            return port - base if base and 0 <= port - base < 0x80 else None
        pm = self.pci_devices.get((7, 3))
        if pm is not None and pm[0:4] == bytes((0x86, 0x80, 0x13, 0x71)):
            base = int.from_bytes(bytes(pm[0x40:0x42]), "little") & 0xFFC0
            return port - base if base and 0 <= port - base < 0x40 else None
        isa = self.pci_devices.get((1, 0))
        if isa is not None and isa[0:4] == bytes((0x39, 0x10, 0x08, 0x00)):
            # SiS 5597/5598 ISA bridge: ACPI/power management I/O at 90h (64 ports; ASUS SP-AX
            # halts when its status register at +0 reads bit 8 set)
            base = int.from_bytes(bytes(isa[0x90:0x92]), "little") & 0xFFC0
            return port - base if base and 0 <= port - base < 0x40 else None
        via = self.pci_devices.get((17, 0))
        if via is not None and via[0:2] == b"\x06\x11":
            # VT8233 and later (VT8237, VX855): power management I/O base at 88h, 128 ports
            base = int.from_bytes(bytes(via[0x88:0x8A]), "little") & 0xFF80
            return port - base if base and 0 <= port - base < 0x80 else None
        if self.via_pm_base and 0 <= port - self.via_pm_base < 0x100:
            return port - self.via_pm_base
        return None

    def _via_smbus(self, off: int, value: int | None = None) -> int:
        """VT82C686 SMBus host at PM I/O +E0h (as MSI MS-6316's AMI uses it): +E0h status
        (bit 3 busy, bit 4 byte done), +E1h busy (clears once read), +E2h control (a write
        starts), +E4h slave address, +E8h command (the EEPROM offset), +E6h data. Answered from
        the SPD EEPROMs. value None: a read."""
        if value is not None:
            self.via_smb[off - 0xE0] = value
            if off == 0xE2:
                eeprom = self.spd.get(self.via_smb[4] >> 1, bytes(256))
                cmd = self.via_smb[8] or self.via_smb[3]
                self.via_smb_data = eeprom[cmd] if cmd < len(eeprom) else 0
                self.via_smb_state = 1
            return 0
        if off == 0xE0:
            return {1: 0x08, 2: 0x10}.get(self.via_smb_state, 0)
        if off == 0xE1:
            busy = 0x08 if self.via_smb_state == 1 else 0
            if self.via_smb_state == 1:
                self.via_smb_state = 2
            return busy
        if off == 0xE6:
            return self.via_smb_data
        return self.via_smb[off - 0xE0]

    def _smbus_write(self, reg: int, value: int) -> None:
        """SMBus host registers: 0 status (written ones clear bits), 2 control (40h starts the
        command in bits 2-4), 3 command (the EEPROM offset), 4 slave address (bit 0: read),
        5/6 data. Byte and byte-data reads are answered from the SPD EEPROMs; a missing
        device reports a device error. A device outside the SPD addresses that is written
        byte by byte keeps what it was given (Soltek SL-KT600's AMI marks the clock
        generator as set in register 0Ah of the device at 4Eh, else it sets it and resets
        the board, again and again)."""
        if reg == 0:
            self.smbus_block_polls = 0
            self.smbus[0] &= ~value & 0xFF
            if value & 0x80 and self.smbus_block_read:
                self.smbus[7], self.smbus_block_read = (
                    self.smbus_block_read[0],
                    self.smbus_block_read[1:],
                )
                self.smbus[0] |= 0x80
                return
            if (
                value & 0x80
                and self.smbus[2] >> 2 & 7 == 5
                and self.smbus[4] & 1
                and (self.smbus_block_left == 0)
            ):
                self.smbus_block_left = -1  # the last byte of a block read was taken
                self.smbus[0] |= 0x02
                return
            if value & 0x80 and self.smbus_block_left >= 0:
                # a block transfer goes byte by byte on an ICH: each byte cleared from
                # BYTE_DONE (bit 7) is followed by the next one at once (Fujitsu-Siemens D1185
                # writes its clock generator so and waits for each byte), and after the last
                # one the transaction ends with INTR (AMI 852101 clears the last BYTE_DONE and
                # waits for INTR; Dell Dimension 3000's Phoenix counts the bytes itself)
                if self.smbus_block_left > 0:
                    self.smbus_block_left -= 1
                    self.smbus[0] |= 0x80
                else:
                    self.smbus_block_left = -1
                    self.smbus[0] |= 0x02
            return
        self.smbus[reg] = value
        if reg == 2 and value & 0x42 == 0x02:  # KILL ends the transaction: FAILED (bit 4)
            self.smbus[0] = self.smbus[0] & ~0x01 | 0x10  # (D1185 ends its block write so)
            return
        if reg != 2 or not value & 0x40:
            return
        self.smbus_busy = 1
        address, offset = self.smbus[4] >> 1, self.smbus[3]
        if 0x50 <= address <= 0x57 and not self.spd_asked:
            # the DIMM sits in the first socket the BIOS asks for (Fujitsu-Siemens D1372:
            # 54h and 55h only)
            self.spd_asked = True
            self.spd = {address: self.spd.popitem()[1]}
        if address == 0x69 and address not in self.smbus_devices:
            self.smbus_devices[address] = bytearray(256)  # the clock generator, always there
        eeprom = self.spd.get(address, self.smbus_devices.get(address))
        if (
            eeprom is None
            and not self.smbus[4] & 1
            and value >> 2 & 7 in (2, 5)
            and not 0x50 <= address <= 0x57
        ):  # (a clock generator, written to)
            eeprom = self.smbus_devices[address] = bytearray(256)
        if eeprom is None:
            self.smbus[0] |= 0x04  # device error
            self.smbus_result, self.smbus_idle = 0x04, 0
            return
        if self.smbus[4] & 1 and value >> 2 & 7 == 5:
            # a block read (the clock generator: Fujitsu-Siemens D1326's Phoenix reads it back
            # after setting it): the byte count in data 0, then each byte in the block data
            # register with BYTE_DONE, INTR after the last one is taken
            count = eeprom[0] if 0 < eeprom[0] <= 32 else 8
            self.smbus[5], data = count, bytes(eeprom[1 : count + 1])
            self.smbus[7], self.smbus_block_read = data[0], data[1:]
            self.smbus_block_left = 0
            self.smbus[0] |= 0x80
            self.smbus_result, self.smbus_idle = 0, 0
            return
        if self.smbus[4] & 1:
            protocol = value >> 2 & 7
            if protocol == 1:  # byte: the next byte
                # (set only once used: snapshots taken before keep it absent)
                # pylint: disable-next=attribute-defined-outside-init
                offset = self.smbus_next = getattr(self, "smbus_next", 0)
                # pylint: disable-next=attribute-defined-outside-init
                self.smbus_next = (offset + 1) & 0xFF
            self.smbus[5] = eeprom[offset]
            self.smbus[6] = eeprom[(offset + 1) & 0xFF]
        elif value >> 2 & 7 == 2 and address in self.smbus_devices:  # byte data written
            assert isinstance(eeprom, bytearray)
            eeprom[offset] = self.smbus[5]
        if value >> 2 & 7 == 5 and not self.smbus[4] & 1 and self.smbus[5] > 1:
            # a block written byte by byte: the first byte is out, the rest follow (above)
            self.smbus_block_left = self.smbus[5]  # (and one more BYTE_DONE: the count byte)
            self.smbus[0] |= 0x80
            self.smbus_result, self.smbus_idle = 0, 0
            return
        self.smbus_block_left = -1
        self.smbus[0] |= (
            0x82 if value >> 2 & 7 == 5 and not self.smbus[4] & 1 else 0x02  # done (block
        )  # written: a byte too)
        self.smbus_result, self.smbus_idle = 0x02, 0

    # --- I/O ports --------------------------------------------------------------------------

    def _ich2_gpe1(self) -> bool:
        """An ICH, ICH0 or ICH2 at device 31, whose PM I/O 2Ch-2Dh is GPE1_STS (later ICHs
        have GPE0_EN there)."""
        lpc = self.pci_devices.get((31, 0))
        return lpc is not None and lpc[0:4] in (
            b"\x86\x80\x10\x24",
            b"\x86\x80\x20\x24",
            b"\x86\x80\x40\x24",
            b"\x86\x80\x4c\x24",
        )

    def _via_smi_port(self) -> int:
        """The VIA software SMI command port (power management I/O base + 2Fh: the VT82C686's
        base at function 4 register 48h, VT8233 and later at 88h of function 0), or -1."""
        pm = self.pci_devices.get((7, 4))
        if pm is not None and pm[2:4] == b"\x57\x30":
            base = int.from_bytes(bytes(pm[0x48:0x4A]), "little") & 0xFF80
            return base + 0x2F if base else -1
        isa = self.pci_devices.get((17, 0))
        if isa is not None and isa[0:2] == b"\x06\x11":
            base = int.from_bytes(bytes(isa[0x88:0x8A]), "little") & 0xFF80
            return base + 0x2F if base else -1
        return -1

    def _via_pm_base(self) -> int:
        """The VIA south bridge's power management I/O base: the VT82C686's (function 4,
        register 48h) or the VT82C596's (function 3; AMI's VT693 boot block sets it there
        though the 686 is modelled), or 0."""
        for function in (4, 3):
            cfg = self.pci_devices.get((7, function))
            if cfg is not None and cfg[0:2] == b"\x06\x11":
                base = int.from_bytes(bytes(cfg[0x48:0x4A]), "little") & 0xFF80
                if base:
                    return base
        return 0

    def _mech2_address(self, port: int) -> int:
        """The mechanism #1 address of a configuration access through mechanism #2 (port
        CxRRh: device x, register RR; function and bus from CF8h and CFAh)."""
        return (
            0x80000000
            | self.pci_forward << 16
            | (port >> 8 & 0xF) << 11
            | (self.pci_cse >> 1 & 7) << 8
            | (port & 0xFC)
        )

    def _chip_smbus_read(self, off: int) -> int | None:
        """A read of a SiS 96x / ALi M1563 SMBus register, or None for the host model's own.
        The end of a transaction the BIOS cleared before it looked comes again when polled (a
        block transfer: once per byte). SiS: its register map, and the end as status bits 3
        and 4 (some boards wait for 18h); the device error is not passed on (POST stops on
        it on others)."""
        sis = self.chip_smbus == "sis"
        if sis and off != 0:
            src = SIS_SMBUS_READ.get(off)
            return 0 if src is None else self.smbus[src]
        if off != 0:
            return None
        if (self.chip_smbus_end or self.smbus_block_left >= 0) and not self.smbus[0] & 0x82:
            self.smbus[0] |= 0x82
            self.chip_smbus_end = False
        if sis:
            return 0x18 if self.smbus[0] & 0x82 else 0
        return self.smbus[0]

    def _chip_smbus_write(self, off: int, value: int) -> bool:
        """A write to a SiS 96x / ALi M1563 SMBus register: True when handled here (SiS),
        False for the host model (ALi: the VIA layout, with the end owed after a start)."""
        if self.chip_smbus != "sis":
            if off == 2 and value & 0x40 or off == 7:  # a start, a block byte
                self.chip_smbus_end = True
            return False
        dst = SIS_SMBUS_WRITE.get(off)
        if dst is None:
            return True
        if off == 3:  # HOST_CNT: start in bit 4, protocol in bits 0-2
            self.chip_smbus_end = self.chip_smbus_end or bool(value & 0x10)
            value = (value & 0x10) << 2 | (value & 0x07) << 2
        elif off == 8:
            self.chip_smbus_end = True
        self._smbus_write(dst, value)
        return True

    def _in(self, uc: Uc, port: int, size: int, _user: object) -> int:
        if port in self.io_reads:
            return self.io_reads[port]
        # HP's AMIBIOS 7 boards (BCM IN845 Rev 1.14) read a hardware-monitor data port
        # and take all ones for a stopped CPU fan, then halt; 00 is "no reading yet"
        if port == 0x0A59:
            return 0
        if (
            self.chip_smbus
            and self.smbus_base is not None
            and 0 <= (off := port - self.smbus_base) < 16
            and (value := self._chip_smbus_read(off)) is not None
        ):
            return value
        # PCI configuration mechanism #2 (Intel 430LX/NX "Neptune" boards): CF8h as a byte is
        # the enable register (key in bits 4-7, function), CFAh the forward register (bus);
        # with a key set, ports C000h-CFFFh reach the configuration spaces
        if port == 0xCF8 and size == 1:
            return self.pci_cse
        if port == 0xCF9 and size == 1:
            return self.reset_control
        if port == 0xCFA and size == 1:
            return self.pci_forward
        if 0xC000 <= port <= 0xCFFF and self.pci_cse & 0xF0:
            saved, self.pci_addr = self.pci_addr, self._mech2_address(port)
            try:
                return self._in(uc, 0xCFC + (port & 3), size, _user)
            finally:
                self.pci_addr = saved
        if port == 0x3F4:  # main status: ready; with results waiting, data to the CPU, busy;
            if not self.fdc_dor & 4 or self.fdc_waking:  # held in reset (DOR bit 2 clear,
                # as after power-on) and a moment after: not ready (PCChips M571 halts when a
                # controller is ready right after the reset; others poll until it is)
                self.fdc_waking = max(0, self.fdc_waking - 1)
                return 0x00
            return 0xD0 if self.fdc_results else 0x80
        if port == 0x3F5:
            return self.fdc_results.pop(0) if self.fdc_results else 0
        if port == 0x3F7:  # digital input: no disk change
            return 0
        if port == 0xB3 and size == 1:  # APM status: a scratch byte, 0 after power-on (an
            return self.apm_status  # AMIBIOS boot block resets while it reads non-zero, rc6103)
        if port == 0x295 and size == 1:  # Winbond hardware monitor's index: read back, not
            return self.hwmon_index & 0x7F  # busy (bit 7; AMIBIOS 7 waits for it, s85mir3l)
        if port == 0x296 and size == 1 and self.hwmon_index & 0x7F in (0x28, 0x29, 0x2A):
            # Winbond fan counts read FFh (stopped) as before, unless the same one is polled
            # on and on: MSI MS-6380E waits at a "CPU fan" prompt reading Y/N from port 60h
            # while it reads FFh (other chips keep temperatures there: setup pages stay as
            # they were)
            self.hwmon_polls = self.hwmon_polls + 1 if self.hwmon_index == self.hwmon_polled else 0
            self.hwmon_polled = self.hwmon_index
            if self.hwmon_polls > 1000:
                return 0x80
        if port == 0x800 and self.mylex_counter:  # (MVE486: the memory test's byte count,
            return uc.reg_read(UC_X86_REG_EBX) >> 16 & 0xFF  # compared with its own in EBX)
        if port == 0x2A and self.um8498_phase == 2:
            return self.um8498_regs[self.um8498_index]
        if port == 0x23 and self.scat:
            if self.ali_index > 0x4F and self.ali_index != 1:
                return 0xFF
            return self.scat_regs[self.ali_index] & (0x3F if self.ali_index == 0x45 else 0xFF)
        if port == 0x23 and (self.ali_unlocked or self.sis471):
            return self.ali_regs[self.ali_index]  # (SiS 85C471: read back as written)
        if port == 0x24 and self.opti_wrote:
            index = self.ali_index
            return self.opti_regs[index] if index < 0x12 or index >= 0x20 else 0xFF
        if port == 0xA9 and self.via_wrote:
            return self.via_regs[self.via_index]
        if port == 0x61:
            self.port61 ^= 0x10  # refresh toggle, used by delay loops
            if self.port61 & 1:  # timer 2 gate open: its output (bit 5) changes as it runs
                self.port61 ^= 0x20
            return self.port61
        if port == 0x63:  # (PC Partner H8010's AMI setup waits for a high, then a low)
            self.port63 ^= 0x10
            return self.port63
        if port == 0x82D:  # (bit 0 clear: Tyan i845 POST sets its clock and resets for ever)
            return 1
        if port == 0x71:
            if self.cmos_index == 0x0C:  # interrupt flags, cleared by reading
                # the periodic flag (PF) and update-ended flag (UF) are set by time whether
                # their interrupts are on or not: a program polling them sees them come
                # (Quadtel's setup waits for PF between two looks at its clock)
                self.rtc_flag_reads += 1
                if self.rtc_flag_reads % 8 == 0 and self.cmos[0x0A] & 0x0F:
                    self.rtc_flags |= 0x40
                if self.rtc_flag_reads % 64 == 0 and not self.cmos[0x0B] & 0x80:
                    self.rtc_flags |= 0x10
                flags, self.rtc_flags = self.rtc_flags, 0
                return flags
            if self.cmos_index & 0x7F == 0x0A:
                # update in progress (bit 7) for a moment each second while the clock runs:
                # POST checks that it comes (Phoenix 1.10 waits for it, else "RTC error")
                self.rtc_a_reads += 1
                value = self.cmos[0x0A] & 0x7F
                if (
                    self.rtc_a_reads % 64 == 0
                    and value & 0x70 == 0x20
                    and not self.cmos[0x0B] & 0x80
                ):
                    value |= 0x80
                return value
            if self.cmos_index == 0x00:  # the clock runs: seconds advance as they are read
                self.rtc_reads += 0 if self.rtc_frozen else 1
                sec = (self.rtc_reads // 20) % 60
                return (sec // 10) << 4 | sec % 10
            return self.cmos[self.cmos_index & 0x7F]
        if port in (0x73, 0x75):
            return self.cmos_hi[self.cmos_hi_index]
        pm = self._pm_offset(port)
        if pm is not None:
            if self.via_pm_base and 0xE0 <= pm < 0xF0 and size == 1:
                return self._via_smbus(pm)
            if 0x08 <= pm < 0x0C:  # PM timer, 3.58 MHz: time passes as it is read
                self.pm_timer = (self.pm_timer + 0x40) & 0xFFFFFF
                return self.pm_timer >> 8 * (pm - 8) & ((1 << 8 * size) - 1)
            return int.from_bytes(
                bytes(self.pm_regs[pm : pm + size]).ljust(size, bytes(1)), "little"
            )
        if port in (0x3C5, 0x3CF):
            regs, which = (self.vga_seq, 0) if port == 0x3C5 else (self.vga_gc, 1)
            return regs[self.vga_index[which]]
        ac97 = self.pci_devices.get((31, 5))
        if (
            ac97 is not None
            and port & ~1 == (int.from_bytes(bytes(ac97[0x14:0x16]), "little") & 0xFFC0) + 0x34
        ):
            return 0  # AC'97 codec access semaphore: free (no codec answers behind it)
        if port == 0xCF8 and size == 4:  # PCI configuration address: reads back (mechanism #1)
            return self.pci_addr
        if 0xCFC <= port <= 0xCFF and (self.pci_addr & 0x80FFFF00) == 0x80000000:
            reg = (self.pci_addr & 0xFC) + (port - 0xCFC)
            base = self.pam_base
            if base <= reg and reg + size - 1 <= base + 6 and self.pam_valid:  # PAM read back (also
                # when the host bridge itself is not recognised in the ROM)
                return int.from_bytes(bytes(self.pam[reg - base : reg - base + size]), "little")
        if 0xCFC <= port <= 0xCFF and (cfg := self._pci_config()) is not None:
            reg = (self.pci_addr & 0xFC) + (port - 0xCFC)
            return int.from_bytes(bytes(cfg[reg : reg + size]).ljust(size, b"\xff"), "little")
        if port == 0x64 and self.kbc_ibf:
            self.kbc_ibf = False
            return 0x1A | (self.kbc_command_byte & 4)
        if port == 0x64 and self.kbc_busy:  # still testing itself: nothing to read yet
            self.kbc_busy -= 1
            return 0x18 | (self.kbc_command_byte & 4)
        if port == 0x60 and self.kbc_busy:  # read too early: the byte from before
            return self.kbc_last
        if port == 0x64 and self.kbc_gap:
            self.kbc_gap -= 1
            return 0x18 | (self.kbc_command_byte & 4)
        if port == 0x64:  # input buffer empty, keyboard enabled; bit 0: a reply is waiting;
            # bit 2: system flag from the command byte (0 after power-on = cold boot)
            aux = 0x20 if self.kbc_queue and self.kbc_aux else 0  # bit 5: byte from the mouse
            if (
                self.kbc_queue
                and not self.kbc_aux
                and self.irq_hook is None
                and self.kbc_command_byte & 0x01
                and not self.pic_mask & 0x02
                and self.kbc_reads != self.irq_read_mark
            ):
                # a byte left in the output buffer raises IRQ 1 also when no keys are being
                # typed (PCChips M571LMR: POST waits with STI for the handler to take it)
                self._want_hook("irq_hook")
            return 0x18 | aux | (self.kbc_command_byte & 4) | (1 if self.kbc_queue else 0)
        if port == 0x60 and self.kbc_queue:
            self.kbc_reads += 1
            value = self.kbc_last = self.kbc_queue.pop(0)
            self.key_gap = 100  # the keyboard sends its next byte a moment later
            # (keyboard replies only: Phoenix 4.0 reads the mouse's reset reply at once, HN440)
            self.kbc_gap = 2 if self.kbc_queue and not self.kbc_aux else 0
            self.kbc_aux = self.kbc_aux and bool(self.kbc_queue)
            return value
        if port == 0x60:  # read again: the output buffer still holds the last byte
            return self.kbc_last
        if port == 0x40:
            if self.pit0_latch is None:  # not latched: read the running counter
                self.pit0_count = (self.pit0_count - 0x25) & 0xFFFF
                value = self.pit0_count
            else:
                value = self.pit0_latch
            if self.pit0_access in (1, 2):  # one byte only (Quadtel 3.05 tests each channel
                self.pit0_latch = None  # by reading its high byte until the count wraps)
                return value & 0xFF if self.pit0_access == 1 else value >> 8
            self.pit0_read_high = not self.pit0_read_high
            if not self.pit0_read_high:
                self.pit0_latch = None
                return value >> 8
            return value & 0xFF
        if port == 0x41:
            if self.pit1_latch is None:
                self._pit1_step()
            value = self.pit1_count if self.pit1_latch is None else self.pit1_latch
            if self.pit1_access == 2:
                self.pit1_latch = None
                return value >> 8
            if self.pit1_access == 3:
                self.pit1_read_high = not self.pit1_read_high
                if self.pit1_read_high:
                    return value & 0xFF
            self.pit1_latch = None
            return value >> 8 if self.pit1_access == 3 else value & 0xFF
        if port == 0x42:
            self._pit_used()
            value = self._pit_value() if self.pit2_latch is None else self.pit2_latch
            if self.pit2_access in (1, 2):
                self.pit2_latch = None
                return value & 0xFF if self.pit2_access == 1 else value >> 8
            self.pit_read_high = not self.pit_read_high
            if not self.pit_read_high:
                self.pit2_latch = None
            return value >> 8 if not self.pit_read_high else value & 0xFF
        if port == 0x92:
            return 2 if self.a20_fast else 0
        if self.smbus_base is not None and 0 <= port - self.smbus_base < 16:
            if port == self.smbus_base and self.smbus_busy:  # the transaction is seen running
                self.smbus_busy -= 1  # once (Supermicro S2DG2 waits for busy, then for idle)
                return self.smbus[0] | 0x01
            if (
                port == self.smbus_base
                and self.smbus_block_left >= 0
                and self.smbus[0] & 0x80
                and not self.smbus_block_read
            ):
                # a BYTE_DONE of a block write after its last byte (the model counts one more,
                # see _smbus_write) awaited by nobody: polled for INTR instead (Intel D845WR's AMI
                # writes its clock generator so), the transaction ends
                self.smbus_block_polls += 1
                if self.smbus_block_polls > 64:
                    self.smbus[0] = self.smbus[0] & ~0x80 | 0x02
                    self.smbus_block_left, self.smbus_block_polls = -1, 0
            if port == self.smbus_base and self.smbus_result and not self.smbus[0] & 0x1E:
                # the end of the last transaction cleared at once (the emulated one ends with
                # its start) and still awaited: it comes again after a while (PCChips M902LU
                # clears with FFh right after the start, then waits for an end bit)
                self.smbus_idle += 1
                if self.smbus_idle > 64:
                    self.smbus[0] |= self.smbus_result
                    self.smbus_result = 0
            return self.smbus[port - self.smbus_base]
        if 0x481 <= port <= 0x48F or (
            self.dma_pages_ext and (0x401 <= port <= 0x40F or 0x4C1 <= port <= 0x4CF)
        ):
            return self.dma_pages[port & 0x0F]
        if 0x80 <= port <= 0x8F:  # (a word reaches two of them, low first: Mylex MVI486's
            if size == 2 and port < 0x8F:  # "word splitter / byte shifter" test)
                return self.dma_pages[port - 0x80] | self.dma_pages[port - 0x7F] << 8
            return self.dma_pages[port - 0x80]
        if port in (0x21, 0xA1):  # PIC interrupt masks read back
            return self.pic_mask if port == 0x21 else self.pic2_mask
        if port in (0x20, 0xA0):  # no interrupt requested or in service
            return 0
        if self._dma_register(port) is not None and size == 1:
            return self._dma_access(port, None)
        if self._dma_register(port) is not None and size == 2 and port < 0x07:
            # a word read is two byte reads on the ISA bus (ASUS SP-AX reads "PM status" at
            # port 0 while its base address is still 0, and halts if bit 8 is set)
            return self._dma_access(port, None) | self._dma_access(port + 1, None) << 8
        if port in (0x3B5, 0x3D5):  # CRTC registers read back
            index, regs = self.crtc[port - 1]
            return regs[index & 0x1F]
        if port in (0x3B4, 0x3D4):
            return self.crtc[port][0]
        if (base := self._via_pm_base()) and 0x48 <= port - base < 0x4C:
            # VIA general purpose inputs (PM I/O 48h-4Bh) low: AMI on the VT693 board
            # CBVC105E reads 4Ah bit 5 high as "set the clock generator", does so, resets
            # the board and asks again, forever
            return 0
        if port == 0x1EF:  # (Award 3.03 on an HT101/102 board stops at POST code 03 on FFh)
            return self.headland[self.headland_index]
        if port == 0x863:  # (AMIBIOS 7 on SiS 645/650: goes on when 0F0h of it is clear)
            return 0
        if port == 0x860:  # SiS 961/962 ACPI (base 800h) + 60h: AMI Hi-Flex on SiS K7 boards
            return 0  # sets bit 0 at 862h and waits for this to read 0 (PCChips M841, Matsonic
            # MS8318E, run as the VIA model since a VIA ID is in their ROMs)
        # display enable / vertical retrace toggle as the screen is drawn (3BAh in monochrome
        # modes: pci450-a's video BIOS waits for it there)
        if port in (0x3DA, 0x3BA):
            self.vga_status ^= 0x09
            return self.vga_status
        if port in (0x2F, 0x4F) and size == 1:
            return self.sio_regs.get(self._sio_key(port - 1), 0xFF)
        if port in (0x2E, 0x4E) and size == 1 and self.sio_index[port]:
            return self.sio_index[port]  # (it echoes what was written: Dell's POST compares)
        return (1 << 8 * size) - 1  # nothing there: all bits set (a PCI slot without a device)

    def _sio_key(self, port: int) -> tuple:
        """The Super I/O register the index port points at: global registers below 30h,
        logical device registers (the device in register 07h) from 30h on."""
        index = self.sio_index[port]
        if index < 0x30:
            return port, None, index
        return port, self.sio_regs.get((port, None, 0x07), 0), index

    def _div_overflow(self, uc: Uc) -> bool:
        """A 32-bit DIV whose quotient does not fit: BIOSes measure the CPU clock with RDTSC
        over a delay and divide by the expected count (PCChips M571); Unicorn's time stamp
        counter follows the host clock, so the quotient overflows. The division is done
        again with EDX cleared (the clock it shows is then wrong, nothing else). 16-bit and
        8-bit DIVs the same way (Fujitsu-Siemens D1185's Phoenix works out and prints its CPU
        clock with them, also behind a segment prefix: DX and the upper half of EAX cleared,
        which its "cdq" fills from, or AH). A division by zero gives quotient 0 and is skipped
        (a loop that divides until the quotient is 0 then ends)."""
        try:
            pc = self._code_address()
            code = bytes(uc.mem_read(pc, 16))
        except UcError:
            return False
        i, wide = 0, False
        while i < 4 and code[i] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67):
            wide = wide or code[i] == 0x66
            i += 1
        if code[i] not in (0xF6, 0xF7) or code[i + 1] >> 3 & 7 != 6:
            return False
        eax, edx = uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_EDX)
        if code[i] == 0xF6 and eax & 0xFF00:
            uc.reg_write(UC_X86_REG_AH, 0)
            return True
        if code[i] == 0xF7 and wide and edx:
            uc.reg_write(UC_X86_REG_EDX, 0)
            return True
        if code[i] == 0xF7 and not wide and (edx & 0xFFFF or eax >> 16):
            uc.reg_write(UC_X86_REG_EDX, edx & 0xFFFF0000)
            uc.reg_write(UC_X86_REG_EAX, eax & 0xFFFF)
            return True
        insn = next(self.disasm.disasm(code, 0), None)  # the divisor is 0
        if insn is None:
            return False
        uc.reg_write(
            UC_X86_REG_EAX,
            eax
            & (
                0xFFFF0000 if code[i] == 0xF7 and not wide else 0xFFFF0000 if code[i] == 0xF6 else 0
            ),
        )
        if code[i] == 0xF7:
            uc.reg_write(UC_X86_REG_EDX, 0 if wide else edx & 0xFFFF0000)
        uc.reg_write(UC_X86_REG_EIP, uc.reg_read(UC_X86_REG_EIP) + insn.size)
        return True

    def _div_guard_hook(self, uc: Uc, address: int, size: int, _user: object) -> None:
        """Before a DIV that has faulted once: if its quotient would not fit, the upper part
        of the dividend is cleared first (as _div_overflow does after a fault)."""
        if uc.reg_read(UC_X86_REG_CR0) & 1:
            return
        try:
            insn = next(self.disasm_detail.disasm(bytes(uc.mem_read(address, 16)), 0), None)
        except UcError:
            return
        if insn is None or insn.mnemonic != "div" or not insn.operands:
            return
        op, x86 = insn.operands[0], capstone.x86

        def reg(r: int) -> int:
            return uc.reg_read(getattr(x86_const, "UC_X86_REG_" + insn.reg_name(r).upper()))

        if op.type == x86.X86_OP_REG:
            divisor = reg(op.reg)
        elif op.type == x86.X86_OP_MEM:
            m, off = op.mem, op.mem.disp
            if m.base:
                off += reg(m.base)
            if m.index:
                off += reg(m.index) * m.scale
            if 0x67 not in insn.prefix:
                off &= 0xFFFF
            seg = m.segment or (
                x86.X86_REG_SS
                if insn.reg_name(m.base) in ("bp", "sp", "ebp", "esp")
                else x86.X86_REG_DS
            )
            try:
                divisor = int.from_bytes(uc.mem_read((reg(seg) << 4) + off, op.size), "little")
            except UcError:
                return
        else:
            return
        if not divisor:
            return  # (the fault path skips it)
        eax, edx = uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_EDX)
        if op.size == 1 and (eax & 0xFFFF) // divisor > 0xFF:
            uc.reg_write(UC_X86_REG_AH, 0)
        elif op.size == 2 and ((edx & 0xFFFF) << 16 | eax & 0xFFFF) // divisor > 0xFFFF:
            uc.reg_write(UC_X86_REG_EDX, edx & 0xFFFF0000)
            uc.reg_write(UC_X86_REG_EAX, eax & 0xFFFF)
        elif op.size == 4 and (edx << 32 | eax) // divisor > 0xFFFFFFFF:
            uc.reg_write(UC_X86_REG_EDX, 0)

    def _cpuid(self, uc: Uc, _user: object) -> int:
        """The processor's name (CPUID 80000002h-80000004h) and extended features (80000001h)
        as on the board's own CPUs; the emulated CPU answers everything else."""
        leaf = uc.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF
        if self.cpu_p4_signature and leaf == 1 and not self.cpu_amd:
            for reg, value in zip(
                (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX),
                (0xF27, 0x00010809, 0, 0xBFEBFBFF),
            ):
                uc.reg_write(reg, value)
            return 1
        if self.cpu_amd and leaf in (0, 1):  # vendor; an Athlon (family 6, model 4)
            values = (
                (1, *struct.unpack("<3I", b"AuthenticAMD"))
                if leaf == 0
                else (0x642, 0, 0, 0x0183F9FF)
            )
            for reg, value in zip(
                (
                    (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EDX, UC_X86_REG_ECX)
                    if leaf == 0
                    else (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX)
                ),
                values,
            ):
                uc.reg_write(reg, value)
            return 1
        if leaf == 0x80000001:  # no extended features (a Pentium 4 of those years: no 64-bit)
            for reg in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX):
                uc.reg_write(reg, 0)
            return 1
        if not 0x80000002 <= leaf <= 0x80000004:
            return 0
        assert self.cpu_brand is not None
        part = (
            self.cpu_brand.rjust(47).encode().ljust(48, bytes(1))[16 * (leaf - 0x80000002) :][:16]
        )
        for reg, value in zip(
            (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX),
            struct.unpack("<4I", part),
        ):
            uc.reg_write(reg, value)
        return 1

    def _patch_msr_reads(self) -> bool:
        """ "mov ecx,2Ah / rdmsr" (EBL_CR_POWERON) becomes "mov eax, <ratio in bits 22-26> /
        cdq", as long: a P6-style CPU at 15 times its bus clock. In conventional memory (where
        modules are unpacked) from the start; in the ROM only once POST is past its first steps,
        where a boot block checksums itself (Zida LX98, which resets until the ratio it reads
        is the one it wants). Never in the last 8 KB below 1 MB: Zida's ZX98 and BXi98 boot
        blocks checksum F000:E000-FFFF again later and hang on a patched copy."""
        top = 0x100000 if len(self.post_codes_seen) >= 3 else 0xA0000
        memory = bytes(self.uc.mem_read(0, top))
        at = memory.find(RDMSR_RATIO)
        patched = False
        while 0 <= at < self.msr_patch_end:
            self.uc.mem_write(at, RDMSR_RATIO_PATCH)
            patched = True
            at = memory.find(RDMSR_RATIO, at + 1)
        for pattern, offset, replacement in (
            (P4_RATIO_CMP, 12, b"\x38\xc0"),
            (SMI_FLAG_WAIT, 6, b"\x90\x90"),
        ):
            at = memory.find(pattern)
            while 0 <= at < self.msr_patch_end:
                self.uc.mem_write(at + offset, replacement)
                patched = True
                at = memory.find(pattern, at + 1)
        if patched:
            _flush_tb(self.uc)
        return patched

    def _out(self, uc: Uc, port: int, size: int, value: int, _user: object) -> None:
        if self.flash_low and port in (0x3F0, 0x3F1):
            self._flash_bank(port, value & 0xFF)
        if (
            self.chip_smbus
            and self.smbus_base is not None
            and 0 <= port - self.smbus_base < 16
            and self._chip_smbus_write(port - self.smbus_base, value & 0xFF)
        ):
            return
        if port in (0x2E, 0x4E) and size == 1:
            self.sio_index[port] = value & 0xFF
            return
        if port in (0x2F, 0x4F) and size == 1:
            self.sio_regs[self._sio_key(port - 1)] = value & 0xFF
            return
        if port == 0xCF8 and size == 1:  # mechanism #2 (see _in)
            self.pci_cse = value & 0xFF
            return
        if port == 0xCFA and size == 1:
            self.pci_forward = value & 0xFF
            return
        if port == 0x295:
            self.hwmon_index = value & 0xFF
        if 0xC000 <= port <= 0xCFFF and self.pci_cse & 0xF0:
            if self.pam_valid and not self.pci_used:
                self._shadow_change(lambda: setattr(self, "pci_used", True))
            saved, self.pci_addr = self.pci_addr, self._mech2_address(port)
            try:
                self._pci_write(0xCFC + (port & 3), size, value)
            finally:
                self.pci_addr = saved
            return
        if port == 0x80 and value & 0xFF not in self.post_codes_seen:
            self.post_codes_seen.add(value & 0xFF)  # a new POST step: modules may be unpacked
            if self.msr_patches:
                self._patch_msr_reads()
            # POST back in the ROM after a part that ran in RAM: the code translated so far
            # is dropped (outside the run; inside a hook it spoilt Unicorn's hook list).
            # Unicorn crashed (access violation) when a REP STOSD cleared memory holding
            # code that had run there: AMI on the VT693 board CBVC105E runs its boot block
            # at 0000:C000-FFFF, then clears segment 0
            cs = uc.reg_read(UC_X86_REG_CS)
            if cs < 0xA000:
                self.ran_in_ram = True
            elif cs >= 0xC000 and self.ran_in_ram:
                self.ran_in_ram, self.flush_pending = False, True
                uc.emu_stop()
        if port == 0x70:
            self.cmos_index = value & 0x7F
        elif port in (0x3C4, 0x3CE):  # sequencer / graphics controller: index (and data)
            regs, which = (self.vga_seq, 0) if port == 0x3C4 else (self.vga_gc, 1)
            self.vga_index[which] = value & (7 if port == 0x3C4 else 15)
            if size == 2:
                regs[self.vga_index[which]] = value >> 8 & 0xFF
        elif port in (0x3C5, 0x3CF):
            regs, which = (self.vga_seq, 0) if port == 0x3C5 else (self.vga_gc, 1)
            regs[self.vga_index[which]] = value & 0xFF
        elif (pm := self._pm_offset(port)) is not None and port != self._via_smi_port():
            # (VIA's software SMI command port, PM 2Fh, raises an SMI below)
            data = (value & ((1 << 8 * size) - 1)).to_bytes(size, "little")
            if self.via_pm_base and 0xE0 <= pm < 0xF0:
                for i, b in enumerate(data):
                    if pm + i < 0xF0:
                        self._via_smbus(pm + i, b)
                return
            for i, b in enumerate(data):
                if pm + i < len(self.pm_regs):
                    # status registers (PM1, GPE0, SMI, TCO): writing ones clears bits
                    if pm + i in (0, 1, 0x28, 0x29, 0x2A, 0x2B, 0x34, 0x35, 0x64, 0x65, 0x66, 0x67):
                        self.pm_regs[pm + i] &= ~b & 0xFF
                    elif pm + i in (0x2C, 0x2D) and self._ich2_gpe1():
                        # ICH/ICH0/ICH2: GPE1_STS, the GPIO inputs' status (FSC D1372's boot
                        # block clears bits 6-7 and reads them back: set, it takes the
                        # recovery jumper as closed)
                        self.pm_regs[pm + i] &= ~b & 0xFF
                    else:
                        self.pm_regs[pm + i] = b
            if pm <= 5 < pm + size and self.pm_regs[5] & 0x20 and self.cmos[0x0B] & 0x20:
                # PM1 control bit 13, SLP_EN, with the RTC alarm interrupt on: power off,
                # wake on the alarm. ASRock K7Upgrade-600 does so at the end of POST with
                # the alarm a second ahead: a reboot, which the setup modules retry with
                # the CMOS kept. (Without the alarm: Intel PIIX4 boards write
                # 34h there during POST and go on.)
                self.stopped_reason = "reset"
                raise Stop()
        elif port == 0xCF9 and size == 1:  # reset control register: bit 2 resets (hard or
            if value & 4 and self.cf9_resets_in_place:
                self.cf9_resets_in_place -= 1
                self.reset_control = value & 0xFF
                self.cpu_reset_pending = True
                uc.emu_stop()
                return
            if value & 4:  # soft); the others are kept (bit 0: deturbo on the 430LX/NX, which
                self.stopped_reason = "reset"  # reads it back and clears it)
                raise Stop()
            self.reset_control = value & 0xFF
        elif port == 0xB2 or port == self._via_smi_port():
            # APM control (or a VIA software SMI command, PM I/O 2Fh: TriGem Santa Fe, Wyse
            # Cx0): raises an SMI. There is no SMM here; a program that waits for the handler
            # with "jp $" (the handler clears PF in the saved flags) or "jne $" (it sets ZF:
            # Intel D845WR's boot block after copying its SMM code) goes on
            lin = self._code_address()  # (in protected mode too: Intel D845WR)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            for off in (0, 1, 2):  # (after OUT imm8,AL or OUT DX,AL)
                code = bytes(uc.mem_read(lin + off, 2))
                if code == b"\x7a\xfe":
                    uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x04)
                    break
                if code == b"\x75\xfe":
                    uc.reg_write(UC_X86_REG_EFLAGS, flags | 0x40)
                    break
            # "not cx / jcxz out / not cx / jmp back" (after a delay OUT to EDh): the handler
            # sets the saved CX to FFFFh (Apricot HN440's PhoenixBIOS, after copying its SMM code)
            if SMI_CX_WAIT in bytes(uc.mem_read(lin, 8 + len(SMI_CX_WAIT))):
                uc.reg_write(UC_X86_REG_CX, 0xFFFF)
        elif port == 0x1ED:
            self.headland_index = value & 0xFF
        elif port == 0x1EF:
            self.headland[self.headland_index] = value & 0xFF
        elif port == 0xB3:
            self.apm_status = value & 0xFF
        elif port in (0x72, 0x74):
            self.cmos_hi_index = value & 0x7F
        elif port in (0x73, 0x75):
            self.cmos_hi[self.cmos_hi_index] = value & 0xFF
        elif port == 0x71:
            self.cmos[self.cmos_index & 0x7F] = value & 0xFF
            if self.cmos_index & 0x7F == 0x0B and value & 0x40 and self.timer_irq:
                self.rtc_pending = True  # periodic interrupt on: the first one comes soon
                self._want_hook("irq0_hook")
        elif port == 0x61:
            # bits 0-3 are written; 4-7 are status (refresh, timer 2, parity and I/O check
            # errors: none here)
            self.port61 = self.port61 & 0x30 | value & 0x0F
            # gate on: channel 2 counts down. The hook stays while a program toggles the gate
            # (a beep does so thousands of times) and is removed between two runs.
            opened = value & 1 and not self.pit_active
            self.pit_active = bool(value & 1)
            self.pit_used_in_slice = self.pit_used_in_slice or self.pit_active
            if opened:
                self.pit_idle, self.pit_parked = 0, False
            if self.pit_active and self.pit_hook is None and not self.pit_parked:
                self._want_hook("pit_hook")
        elif port in (0x3B4, 0x3D4):
            self.crtc[port][0] = value & 0xFF
        elif port in (0x3B5, 0x3D5):
            index, regs = self.crtc[port - 1]
            regs[index & 0x1F] = value & 0xFF
        elif port == 0x3C8:  # DAC write index, then red, green, blue
            self.dac_index = [value & 0xFF, 0]
        elif port == 0x3C9:
            index, part = self.dac_index
            rgb = list(self.dac[index])
            rgb[part] = value & 0x3F
            self.dac[index] = tuple(rgb)
            self.dac_index = [(index + (part == 2)) & 0xFF, (part + 1) % 3]
        elif port == 0x20 and (value & 0xFF in (0x20, 0x61) or value & 0x10):
            self.irq1_in_service = False  # end of interrupt (or the PIC initialised)
            self._irq1_again()
        elif port == 0x21:
            self.pic_mask = value & 0xFF
            self._fdc_check()
            self._irq1_again()
        elif port == 0xA1:
            self.pic2_mask = value & 0xFF
        elif port == 0x80:  # POST code: a moment to look at the screen
            self.dma_pages[0] = value & 0xFF
            if size == 2:  # (a word: 81h too, see _in)
                self.dma_pages[1] = value >> 8 & 0xFF
            self._start_typing()
            self._irq1_again()  # (e.g. back from a memory test in protected mode)
            if self.k7_mtrr:
                self._k7_poll()
        elif 0x81 <= port <= 0x8F:  # DMA page registers (POST tests that they read back)
            self.dma_pages[port - 0x80] = value & 0xFF
            if size == 2 and port < 0x8F:
                self.dma_pages[port - 0x7F] = value >> 8 & 0xFF
        elif self._dma_register(port) is not None and size == 1:
            self._dma_access(port, value)
        elif port in (0x0C, 0x0D, 0xD8, 0xDA):  # clear flip-flop / master clear
            self.dma_flipflop[port >= 0xD8] = False
        elif port == 0xCF8 and size == 4:
            self.pci_addr = value
            used = self.pam_valid and (self.pci_used or bool(value & 0x80000000))
            if used != self.pci_used:
                self._shadow_change(lambda: setattr(self, "pci_used", used))
        elif 0xCFC <= port <= 0xCFF:
            self._pci_write(port, size, value)
        elif port == 0x64:
            # (only for the self-test: AMI WinBIOS 95 fails when other commands show it)
            self.kbc_ibf = value & 0xFF == 0xAA
            self._kbc_command(value & 0xFF)
        elif port == 0x60:
            self._kbc_data(value & 0xFF)
        elif port == 0x3F2:  # digital output: leaving reset (bit 2) raises IRQ 6
            if value & 4 and not self.fdc_dor & 4:
                self.fdc_reset_sense, self.fdc_results, self.fdc_cmd = 4, [], []
                self.fdc_waking = 2
                self._fdc_irq()
            self.fdc_dor = value & 0xFF
            self._fdc_check()
        elif port == 0x3F5:
            self._fdc_write(value & 0xFF)
        elif not self.pci_devices and (port == 0x28 or port == 0x2A and self.um8498_phase == 2):
            self._um8498_out(port, value & 0xFF)
        elif port == 0x22:
            self.ali_index = value & 0xFF
        elif port == 0x23:
            self._ali_write(value & 0xFF)
        elif port == 0x24 and not self.pci_devices and not self.ali_unlocked:
            self.opti_regs[self.ali_index] = value & 0xFF
            self.opti_wrote = True
            if self.ali_index in (0x04, 0x05, 0x06):
                self._opti_shadow()
            elif self.ali_index in (0x22, 0x23, 0x26):
                self._opti895_shadow()
        elif port == 0xA8:
            self.via_index = value & 0xFF
        elif port == 0xA9:
            self.via_regs[self.via_index] = value & 0xFF
            self.via_wrote = True
            if self.via_index in (0x30, 0x31, 0x32):
                self._via_shadow()
        elif port == 0x92:
            self.a20_fast = bool(value & 2)
            self._set_a20(self.a20_kbc or self.a20_fast)
        elif self.smbus_base is not None and 0 <= port - self.smbus_base < 16:
            self._smbus_write(port - self.smbus_base, value & 0xFF)
        elif 0x481 <= port <= 0x48F or (
            self.dma_pages_ext and (0x401 <= port <= 0x40F or 0x4C1 <= port <= 0x4CF)
        ):
            self.dma_pages[port & 0x0F] = value & 0xFF
        elif (
            self.smbus_base is None
            and size == 1
            and value & 0xFF in (0xFF, 0x1E)
            and (port >= 0x400 and not port & 0x0F and not 0xCF8 <= port <= 0xCFF)
        ):
            # an SMBus host whose PCI function is not emulated: POST clears its status at
            # base+0 with FFh before each transfer (Acer DX34R111 at F100h, DX6GR109 at
            # 0800h, ICH layout), or its four end bits with 1Eh (Supermicro P6DGH at 440h),
            # and waits for the status to read 0
            self.smbus_base = port
            self._smbus_write(0, value & 0xFF)
        elif port == 0x43 and value >> 6 == 0 and not value & 0x30:  # latch channel 0
            # the counter runs while the program looks: each latch sees it further down, by
            # the time the code run since the last latch took (Phoenix 4.04 measures the bus
            # clock with two latches around a loop of BSRs, and divides by the difference)
            elapsed = int((self.pit0_cycles - self.pit0_mark) * self.pit_ticks_per_cycle)
            self.pit0_mark = self.pit0_cycles
            # (at least 25h; the NCR 3315's channel-0 test runs out too soon with that,
            # and old Phoenix and Dell POSTs stall with less: per driver)
            floor = self.pit0_latch_floor
            self.pit0_count = (self.pit0_count - max(floor, elapsed)) & 0xFFFF
            self.pit0_latch, self.pit0_read_high = self.pit0_count, False
            if not self.pit0_timing:
                self.pit0_timing = True
                self._want_hook("pit_hook")
            self.pit_idle = 0
        elif port == 0x43 and value >> 6 == 0 and value & 0x30 and not self.timer_irq:
            self.pit0_access, self.pit0_read_high, self.pit0_latch = value >> 4 & 3, False, None
        elif port == 0x43 and value >> 6 == 0 and value & 0x30 and self.timer_irq:
            self.pit0_access, self.pit0_read_high, self.pit0_latch = value >> 4 & 3, False, None
            # channel 0 mode: counting stops until the count is written; in modes 2 and 3 the
            # output goes high at once, a rising edge on IRQ 0
            self.pit0_mode, self.pit0_running, self.pit0_write_high = value >> 1 & 7, False, False
            if self.pit0_mode & 3 in (2, 3):
                self._raise_irq0()
        elif port == 0x40 and self.timer_irq and self.pit0_mode is not None:
            self.pit0_write_high = not self.pit0_write_high and self.pit0_access == 3
            if not self.pit0_write_high:  # low and high byte written: the channel counts
                self.pit0_running = True
        elif port == 0x43 and value >> 6 == 1 and not value & 0x30:  # latch channel 1
            # the refresh counter runs on: each latch sees it further down (the AT timer test
            # loads 0, then FFh, and wants every bit to be seen set, then cleared - Quadtel)
            self._pit1_step()
            self.pit1_latch, self.pit1_read_high = self.pit1_count, False
        elif port == 0x43 and value >> 6 == 1:  # channel 1 mode: a new count follows
            self.pit1_access, self.pit1_write_high, self.pit1_read_high = (
                value >> 4 & 3,
                False,
                False,
            )
            self.pit1_mode = value >> 1 & 3
            self.pit1_latch = None
        elif port == 0x41:
            if self.pit1_access == 1 or (self.pit1_access == 3 and not self.pit1_write_high):
                self.pit1_reload = (
                    self.pit1_reload & 0xFF00 | value & 0xFF
                    if self.pit1_access == 3
                    else value & 0xFF
                )
            else:
                self.pit1_reload = self.pit1_reload & 0xFF | (value & 0xFF) << 8
            if self.pit1_access == 3:
                self.pit1_write_high = not self.pit1_write_high
            self.pit1_count = self.pit1_reload
        elif port == 0x43 and value >> 6 == 2 and not value & 0x30:  # latch channel 2
            self._pit_used()
            self.pit2_latch, self.pit_read_high = self._pit_value(), False
        elif port == 0x43 and value >> 6 == 2:  # channel 2 mode: a new count follows
            self.pit_read_high = self.pit_write_high = False
            self.pit2_access, self.pit2_latch = value >> 4 & 3, None
            self.pit2_mode = value >> 1 & 3
            self._pit_used()
        elif port == 0x42 and self.pit2_access in (1, 2):  # one byte: the whole count
            self._pit_used()
            self.pit_reload = value & 0xFF if self.pit2_access == 1 else (value & 0xFF) << 8
            self.pit_cycles = 0
        elif port == 0x42:
            self._pit_used()
            if self.pit_write_high:
                self.pit_reload = self.pit_reload & 0xFF | (value & 0xFF) << 8
                self.pit_cycles = 0
            else:
                self.pit_reload = value & 0xFF
            self.pit_write_high = not self.pit_write_high

    def _kbc_command(self, cmd: int) -> None:
        """8042 keyboard controller commands (port 64h) as POST uses them."""
        if cmd == 0xFE and self.kbc_reset_in_place:  # only the CPU is reset (MR BIOS gets
            self.cpu_reset_pending = True  # back from protected mode that way, with a CMOS
            self.uc.emu_stop()  # shutdown code): it starts again at F000:FFF0, memory and
            return  # chipset stay as they are
        if cmd == 0xFE and self.cmos[0x0F] == 0:  # reset line pulsed for a restart (with a
            self.stopped_reason = "reset"  # CMOS shutdown code it returns from protected mode)
            raise Stop()
        if cmd in (0xAD, 0xAE):  # disable / enable the keyboard
            self.kbc_command_byte = self.kbc_command_byte & ~0x10 | (0x10 if cmd == 0xAD else 0)
        replies = {
            0x20: [self.kbc_command_byte],
            0xAA: [0x55],
            0xAB: [0x00],
            0xAC: [],
            0xC0: [self.kbc_input_port],
            0xD0: [0xDD | (2 if self.a20_kbc else 0)],
            0xE0: [0x00],
            0xCA: [self.kbc_mode],
            # AMI: set / clear an output pin (a speed switch), answered with a byte that
            # PNTHI-07's WinBIOS 95 waits for and ignores
            0xC4: [0x00],
            0xCC: [0x00],
            0xD5: [0x41],  # (AST's controller: POST beeps its fatal code without it)
        }  # AMI: read the controller mode (bit 0: PS/2)
        if 0xA0 <= cmd <= 0xBF and cmd not in replies and cmd not in (0xA7, 0xA8, 0xAD, 0xAE):
            # AMI keyboard controllers (MegaKey) answer their extra commands, e.g. A1h version
            replies[cmd] = [self.kbc_version if cmd == 0xA1 else 0x00]
        if 0x21 <= cmd <= 0x3F:  # read a byte of the internal RAM (AMI WinBIOS 12/15/93
            replies[cmd] = [self.kbc_ram[cmd & 0x1F]]  # restarts POST if none comes)
        if cmd in replies:  # a command without reply leaves a waiting byte (e.g. a key) alone
            self.kbc_queue, self.kbc_aux = list(replies[cmd]), False
            self.reply_grace = 16
        # the self-test's 55h comes a moment later (DTK's Phoenix 1.10 reads port 60h once
        # right after the command, a dummy read, and then waits for the reply)
        self.kbc_busy = 2 if cmd == 0xAA or (self.kbc_reply_later and cmd in replies) else 0
        self.kbc_command = (
            cmd if cmd in (0xCB, 0xD1, 0xD2, 0xD3, 0xD4) or (0x60 <= cmd <= 0x7F) else 0
        )

    def _kbc_data(self, value: int) -> None:
        cmd, self.kbc_command = self.kbc_command, 0
        self.kbc_aux = False
        if cmd == 0x60:  # write command byte
            self.kbc_command_byte = value
            self._irq1_again()
        elif 0x61 <= cmd <= 0x7F:  # write a byte of the internal RAM
            self.kbc_ram[cmd & 0x1F] = value
        elif cmd == 0xCB:  # AMI: write the controller mode
            self.kbc_mode = value
            if not self.kbc_queue:
                # the controller answers with the interface it now has, 24h PS/2 or 21h AT:
                # Tiga TG-810M's boot block waits for it and halts without
                self.kbc_queue, self.kbc_aux = [0x24 if value & 1 else 0x21], False
        elif cmd == 0xD1:  # write output port: bit 1 is the A20 gate
            self.a20_kbc = bool(value & 2)
            self._set_a20(self.a20_kbc or self.a20_fast)
        elif cmd in (0xD2, 0xD3):  # echo as if the keyboard / mouse had sent it
            self.kbc_queue = [value]
        elif cmd == 0xD4:  # to the PS/2 mouse: reset passes its self-test, ID 0 (standard mouse)
            self.kbc_queue = {0xFF: [0xFA, 0xAA, 0x00], 0xF2: [0xFA, 0x00]}.get(value, [0xFA])
            self.kbc_aux = True
            self._want_hook("aux_hook")
        else:  # to the keyboard: acknowledged, reset also passes its self-test
            self.kbc_queue = {0xFF: [0xFA, 0xAA], 0xEE: [0xEE], 0xF2: [0xFA, 0xAB, 0x83]}.get(
                value, [0xFA]
            )

    # --- snapshots --------------------------------------------------------------------------

    def snapshot(self) -> tuple:
        """Memory, CPU and machine state, e.g. after POST or with setup on the screen, to run
        several sessions from (run() from an entry point or resume() where it stopped)."""
        state = {
            k: copy.deepcopy(v)
            for k, v in self.__dict__.items()
            if k
            not in (
                "uc",
                "_low",
                "_hma",
                "pit_hook",
                "irq_hook",
                "irq0_hook",
                "dram_hook",
                "aux_hook",
                "ali_alias_hook",
                "alias_hook",
                "retired_hooks",
                "hook_generation",
                "wanted_hooks",
                "in_emulation",
                "disasm",
                "disasm_detail",
                "block_cycles",
                "graphics_grid",
            )
        }
        return bytes(self.uc.mem_read(0, self.ram_top)), state, self.uc.context_save()

    def restore(self, snap: tuple) -> None:
        memory, state, cpu = snap
        self._retire("pit_hook")
        self._retire("irq_hook")
        self._retire("irq0_hook")
        self._retire("dram_hook")
        self._retire("alias_hook")
        self._remove_retired_hooks()
        self._set_a20(state["a20"])
        self.uc.mem_write(0x100000, memory[0x100000:])  # with A20 off this hits low memory,
        self.uc.mem_write(0, memory[:0x100000])  # which is then rewritten
        self.__dict__.update({k: copy.deepcopy(v) for k, v in state.items()})
        self.uc.context_restore(cpu)
        restored = list(self.protected)
        self.protected = [not p for p in restored]  # force mem_protect to the restored state
        self._protect()
        _flush_tb(self.uc)  # code translated after the snapshot may have been overwritten

    # --- run --------------------------------------------------------------------------------

    def run(
        self, cs: int, ip: int, ss: int = 0x0030, sp: int = 0x0100, ds: int = 0x40, es: int = 0
    ) -> Screen:
        uc = self.uc
        if (cs, ip) == (0xF000, 0xFFF0):
            if self.cr0_at_reset:
                uc.reg_write(UC_X86_REG_CR0, self.cr0_at_reset)
            vector = bytes(uc.mem_read(0xFFFF0, 5))
            if vector[0] == 0xEA and int.from_bytes(vector[3:5], "little") < 0xC000:
                # a far jump into RAM: the file is not the top of a BIOS image (a part of one,
                # Tulip TC38's TULIP1.BIN), and the code would run off into empty memory
                raise ValueError(
                    "the reset vector (16 bytes before the end) jumps to "
                    f"{vector[4]:02X}{vector[3]:02X}:{vector[2]:02X}{vector[1]:02X}"
                    ", outside the ROM: this file is not the top of a BIOS "
                    "image (perhaps only a part of the ROM, or one of two chips)"
                )
        for reg, val in (
            (UC_X86_REG_CS, cs),
            (UC_X86_REG_DS, ds),
            (UC_X86_REG_ES, es),
            (UC_X86_REG_SS, ss),
            (UC_X86_REG_SP, sp),
        ):
            uc.reg_write(reg, val)
        return self._go((cs << 4) + ip)

    def resume(self) -> Screen:
        """Continue where the program stopped to wait for a key (after giving it keys): the
        INT 16h call it was making is repeated."""
        uc = self.uc
        cs, ip = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_IP)
        waiting = self.stopped_reason in ("waiting for a key", "polling the keyboard")
        if waiting and bytes(uc.mem_read((cs << 4) + ip - 2, 2)) == bytes([0xCD, 0x16]):
            ip -= 2
        self.stopped_reason, self.key_polls = "", 0
        return self._go((cs << 4) + ip)

    def _unfetch(self) -> tuple[int, bytes]:
        """Before a shadow switch: (address, the code the CPU has fetched there), with
        bytes left over from the last switch taken out of memory again."""
        pc = self._code_address()
        if self.prefetched is not None:
            at, fetched, beneath = self.prefetched
            self.prefetched = None
            self.uc.mem_write(at, beneath)
            if at <= pc < at + len(fetched):
                return pc, fetched[pc - at :]
        try:
            return pc, bytes(self.uc.mem_read(pc, PREFETCH))
        except UcError:
            return pc, b""

    def _prefetch(self, fetched: tuple[int, bytes]) -> None:
        """After a shadow switch that changed the code right ahead: it runs as fetched."""
        pc, code = fetched
        if not code or not SHADOW_BASE <= pc < 0x100000 - len(code):
            return
        now = bytes(self.uc.mem_read(pc, len(code)))
        if now != code:
            self.uc.mem_write(pc, code)
            self.prefetched = (pc, code, now)
            _flush_tb(self.uc)

    def _waits_for_reset(self) -> bool:
        """The program spins on "jmp $" (EB FE) with interrupts off, before POST's first
        restarts (only a hardware reset ends that)."""
        if self.spin_resets >= 2 or self.uc.reg_read(UC_X86_REG_EFLAGS) & 0x200:
            return False
        try:
            return bytes(self.uc.mem_read(self._code_address(), 2)) == b"\xeb\xfe"
        except UcError:
            return False

    def _cpu_reset(self) -> None:
        """The CPU after a reset: real mode at F000:FFF0, interrupt table at 0."""
        uc = self.uc
        self.cpu_reset_pending = False
        uc.reg_write(UC_X86_REG_CR0, self.cr0_at_reset or uc.reg_read(UC_X86_REG_CR0) & ~1)
        uc.reg_write(UC_X86_REG_IDTR, (0, 0, 0x3FF, 0))
        for reg in (
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
            x86_const.UC_X86_REG_FS,  # (J-Bond: FFFFh left by POST's register test
            x86_const.UC_X86_REG_GS,  # faults when popped in protected mode)
        ):
            uc.reg_write(reg, 0)
        uc.reg_write(UC_X86_REG_CS, 0xF000)
        uc.reg_write(UC_X86_REG_EIP, 0xFFF0)
        uc.reg_write(UC_X86_REG_EFLAGS, 2)
        uc.reg_write(UC_X86_REG_EDX, 0x0435)  # the CPU's signature after a reset (a 486; MR
        # BIOS keeps it in port 85h and checks it)
        if bytes(uc.mem_read(0xF0000, 0x10000)) != bytes(uc.mem_read(0xFFFF0000, 0x10000)):
            self._reset_alias()
        _flush_tb(self.uc)

    def _eip_back(self, uc: Uc, addr: int, size: int, eip: int) -> None:
        if not self.eip_restored:  # (once: the code may come to this address itself later)
            self.eip_restored = True
            uc.reg_write(UC_X86_REG_EIP, eip)

    def _reset_alias(self) -> None:
        """After a reset the CPU runs the ROM at 4 GB (CS F000h with the base FFFF0000h) until
        the first far jump, not the copy shadowed at F0000h, which POST may have changed:
        Dell's Phoenix 1.10 puts a jump to its reset there. The base is set through a
        descriptor for selector F000h, written for a moment (a 16-bit code segment), with
        protected mode switched on and off around the load."""
        uc, scratch = self.uc, 0x80000
        saved, gdtr = bytes(uc.mem_read(scratch, 8)), uc.reg_read(UC_X86_REG_GDTR)
        uc.mem_write(scratch, struct.pack("<HHBBBB", 0xFFFF, 0, 0xFF, 0x9B, 0, 0xFF))
        uc.reg_write(UC_X86_REG_GDTR, (0, scratch - 0xF000, 0xF007, 0))
        cr0 = uc.reg_read(UC_X86_REG_CR0)
        uc.reg_write(UC_X86_REG_CR0, cr0 | 1)
        uc.reg_write(UC_X86_REG_CS, 0xF000)
        uc.reg_write(UC_X86_REG_CR0, cr0 & ~1)
        uc.reg_write(UC_X86_REG_GDTR, gdtr)
        uc.mem_write(scratch, saved)
        self.cs_alias = True  # (until the code leaves the 4 GB alias: _alias_left)
        self._want_hook("alias_hook")

    def _alias_left(self, uc: Uc, addr: int, size: int, generation: int) -> None:
        if generation == self.hook_generation["alias_hook"] and addr < 0xFFF00000:
            self.cs_alias = False
            self._park("alias_hook")

    def _invalid(self, uc: Uc, _user: object) -> bool:
        """Instructions Unicorn does not know: MOV to and from the 486's test registers
        (0F 24 / 0F 26), with which BIOSes test the CPU cache (AMI WinBIOS 12/15/93). They
        keep what is written. Anything else goes to an Invalid-Opcode handler the ROM installed
        itself, as the CPU raises exception 6 (MR BIOS V1.41: "lock nop" at F000:A1C5 after
        putting its handler into vector 6); without one it stays an invalid
        instruction."""
        try:
            pc = self._code_address()
            code = bytes(uc.mem_read(pc, 3))
        except UcError:
            return False
        if code[:2] in UMOV_OPCODES and code[2] < 0xC0 and self._umov(uc, pc, code[1]):
            return True
        if code[0] != 0x0F or code[1] not in (0x24, 0x26) or code[2] < 0xC0:
            if self.invalid6 < 8 and uc.reg_read(UC_X86_REG_CR0) & 1:
                # (in protected mode through the IDT: the early Award 286 BIOS's test)
                if self._deliver_pm(uc, 6):
                    self.invalid6 += 1
                    return True
                return False
            if self.invalid6 < 8 and self._int6_installed() and self._deliver(uc, 6):
                self.invalid6 += 1  # (a ROM faulting in a loop must not spin for ever)
                return True
            return False
        regs = [
            UC_X86_REG_EAX,
            UC_X86_REG_ECX,
            UC_X86_REG_EDX,
            UC_X86_REG_EBX,
            UC_X86_REG_ESP,
            UC_X86_REG_EBP,
            UC_X86_REG_ESI,
            UC_X86_REG_EDI,
        ]
        tr, gpr = code[2] >> 3 & 7, regs[code[2] & 7]
        if code[1] == 0x24:
            uc.reg_write(gpr, self.test_regs[tr])
        else:
            self.test_regs[tr] = uc.reg_read(gpr)
        uc.reg_write(UC_X86_REG_EIP, uc.reg_read(UC_X86_REG_EIP) + 3)
        return True

    def _umov(self, uc: Uc, pc: int, opcode: int) -> bool:
        """UMOV (0F 10-13), the undocumented MOV of the 386 and early 486 for main memory
        behind the ICE or SMM area; a plain MOV here. TriGem's and other PhoenixBIOS 4.03
        POSTs use it (bios-95-11-02, pci450-a); Unicorn takes it for SSE. Real mode, 16-bit
        addressing, no segment prefix: anything else stays an invalid instruction."""
        r = uc.reg_read
        if r(UC_X86_REG_CR0) & 1:
            return False
        modrm, *disp = bytes(uc.mem_read(pc + 2, 3))
        mod, reg, rm = modrm >> 6, modrm >> 3 & 7, modrm & 7
        bx, bp = r(UC_X86_REG_EBX) & 0xFFFF, r(UC_X86_REG_EBP) & 0xFFFF
        si, di = r(UC_X86_REG_ESI) & 0xFFFF, r(UC_X86_REG_EDI) & 0xFFFF
        length = 3 + (mod if mod else 2 if rm == 6 else 0)
        if not mod and rm == 6:
            offset = disp[0] | disp[1] << 8
        else:
            offset = (bx + si, bx + di, bp + si, bp + di, si, di, bp, bx)[rm]
            offset += (0, disp[0] - (disp[0] & 0x80) * 2, disp[0] | disp[1] << 8)[mod]
        seg = UC_X86_REG_SS if rm in (2, 3) or (rm == 6 and mod) else UC_X86_REG_DS
        address = (r(seg) << 4) + (offset & 0xFFFF)
        wide = opcode & 1
        if wide:
            target, shift, mask = UMOV_REGS[reg], 0, 0xFFFF
        else:
            target, shift, mask = UMOV_REGS[reg & 3], 8 if reg >= 4 else 0, 0xFF
        if opcode < 0x12:  # to memory
            value = r(target) >> shift & mask
            uc.mem_write(address, value.to_bytes(1 + wide, "little"))
        else:
            value = int.from_bytes(uc.mem_read(address, 1 + wide), "little")
            uc.reg_write(target, r(target) & ~(mask << shift) | value << shift)
        uc.reg_write(UC_X86_REG_EIP, r(UC_X86_REG_EIP) + length)
        return True

    def _int6_installed(self) -> bool:
        """Vector 6 points into the ROM's own code (not left at 0 or at a shared dummy IRET)."""
        off, seg = struct.unpack("<HH", self.uc.mem_read(0x18, 4))
        if (off, seg) in ((0, 0), (0x500, 0)):
            return False
        try:
            return self.uc.mem_read((seg << 4) + off, 1) != b"\xcf"
        except UcError:
            return False

    def _after_hlt(self) -> bool:
        """Emulation stopped right after a HLT instruction (Unicorn ends the run there).
        An F4 that is the displacement of an instruction ending there (mov di,[bp-0Ch]:
        8B 7E F4) is a slice that ended after it, not a HLT (ICS SB586P-V, PCI58PL)."""
        try:
            at = self._code_address()
            before = bytes(self.uc.mem_read(at - 4, 4))
        except UcError:
            return False
        if before[-1] != 0xF4:
            return False
        for size in (3, 4):
            insn = next(self.disasm_detail.disasm(before[-size:], at - size), None)
            if (
                insn is not None
                and insn.size == size
                and insn.disp_size == 1
                and insn.disp_offset == size - 1
            ):
                return False
        return True

    def _code_address(self) -> int:
        """Linear address of CS:EIP (real mode, or protected mode through the GDT)."""
        uc = self.uc
        cs, eip = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_EIP)
        if not uc.reg_read(UC_X86_REG_CR0) & 1:
            if self.cs_alias and cs == 0xF000:  # (the ROM at 4 GB after a reset)
                return 0xFFFF0000 + (eip & 0xFFFF)
            return (cs << 4) + (eip & 0xFFFF)
        _, gdt_base, gdt_limit, _ = uc.reg_read(UC_X86_REG_GDTR)
        d = uc.mem_read(gdt_base + (cs & ~7), 8) if (cs & ~7) + 7 <= gdt_limit else bytes(8)
        if cs & 4 or not cs & ~7 or not d[5] & 0x80:
            # no usable GDT entry: right after switching to protected mode CS still holds its
            # real-mode base until the next far jump
            return (cs << 4) + eip
        return (d[2] | d[3] << 8 | d[4] << 16 | d[7] << 24) + eip

    def _timer_irq(self) -> None:
        """A timer tick between two slices: channel 0 in mode 2/3 raises IRQ 0 periodically, in
        mode 0 once at the end of its count; the RTC raises IRQ 8 while its periodic
        interrupt is on."""
        if self.cmos[0x0B] & 0x40 and not self.rtc_pending:
            self.rtc_pending = True
            self._want_hook("irq0_hook")
        if not self.pit0_running:
            return
        if self.pit0_mode == 0:
            self.pit0_running = False
        self._raise_irq0()

    def _raise_irq0(self) -> None:
        self.irq0_pending = True
        self._want_hook("irq0_hook")

    def _irq0(self, uc: Uc, address: int, size: int, generation: int) -> None:
        """Deliver a raised IRQ 0 (INT 08h) or RTC IRQ 8 (INT 70h) at the first instruction
        where the PIC lets it through and the CPU has interrupts enabled."""
        if generation != self.hook_generation["irq0_hook"]:
            # a retired hook stays until the run restarts; one that keeps firing for long
            # (DTK's POST runs on for minutes without a restart) is removed now
            self.stale_irq0 += 1
            if self.stale_irq0 == 5_000:
                self.wanted_hooks.add("no_hook")
                uc.emu_stop()
            return
        if not uc.reg_read(UC_X86_REG_EFLAGS) & 0x200 or uc.reg_read(UC_X86_REG_CR0) & 1:
            return
        if self.irq0_pending and not self.pic_mask & 1:
            vector = 8
        elif self.rtc_pending and not self.pic_mask & 4 and not self.pic2_mask & 1:
            vector = 0x70
        elif self.fdc_pending and not self.pic_mask & 0x40 and self.fdc_dor & 0x08:
            vector = 0x0E
        else:
            if not (self.irq0_pending or self.rtc_pending):  # only a masked IRQ 6 is left
                self._retire("irq0_hook")
            return
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = (address - (cs << 4)) & 0xFFFFFFFF
        if ip > 0xFFFF:
            return
        uc.reg_write(UC_X86_REG_EIP, ip)  # the interrupt returns to this instruction
        if self._deliver(uc, vector):
            if vector == 8:
                self.irq0_pending = False
            elif vector == 0x0E:
                self.fdc_pending = False
            else:
                self.rtc_pending, self.rtc_flags = False, 0xC0  # IRQF + periodic flag
            if not (self.irq0_pending or self.rtc_pending or self.fdc_pending):
                self._retire("irq0_hook")

    def _go(self, begin: int) -> Screen:
        """Run up to max_instructions; with timer_irq in slices: between two slices (about one
        tick of the 18.2 Hz system timer on a 33 MHz CPU) the timer interrupt is raised."""
        uc = self.uc
        # one watchdog per run stops it when its time is up (Unicorn's own timeout starts a
        # thread for each emu_start, which is slow when a run is restarted often)
        time_up = threading.Event()

        def watchdog() -> None:
            time_up.set()
            uc.emu_stop()

        timer = threading.Timer(self.max_seconds, watchdog)
        timer.daemon = True
        timer.start()
        try:
            remaining, pc = self.max_instructions, begin
            while True:
                # (slices also without the timer: a chunk that ends early with no flag - a
                # HLT, a double fault - is charged at most one slice, not the whole rest of
                # the budget)
                count = min(TIMER_SLICE, remaining)
                if time_up.is_set():
                    self.stopped_reason = self.stopped_reason or "time limit reached"
                    if (hits := time_limits_hit.get()) is not None:
                        hits.append(True)
                    break
                eip_back = None
                if uc.reg_read(UC_X86_REG_CR0) & 1:
                    # Unicorn sets EIP to the start address less CS * 16 even in protected
                    # mode: a run restarted there (a timer slice ending inside a memory test,
                    # Quadtel) must give the selector's "real-mode" address, not the linear one
                    eip = uc.reg_read(UC_X86_REG_EIP)
                    pc = (uc.reg_read(UC_X86_REG_CS) << 4) + eip
                    if eip > 0xFFFF:
                        # it writes only IP, so code above 64 KB would go on at EIP & FFFFh
                        # (Tyan's Phoenix 4.0 in the flash at 4 GB): a one-shot
                        # hook where it lands puts EIP back
                        low = self._code_address() - eip + (eip & 0xFFFF)
                        self.eip_restored = False
                        eip_back = uc.hook_add(UC_HOOK_CODE, self._eip_back, eip, low, low)
                        _flush_tb(uc)
                self.in_emulation = True
                try:
                    uc.emu_start(pc, 0xFFFFFFFF, count=count)
                finally:
                    self.in_emulation = False
                    if eip_back is not None:
                        uc.hook_del(eip_back)
                if time_up.is_set():
                    self.stopped_reason = self.stopped_reason or "time limit reached"
                    if (hits := time_limits_hit.get()) is not None:
                        hits.append(True)
                    break
                if self.cpu_reset_pending:
                    self._cpu_reset()
                    remaining -= 1000
                    pc = 0xFFFF0
                    continue
                if self.smram_pending:
                    self.smram_pending = False
                    view = bytes(self.uc.mem_read(0xA0000, 0x20000))
                    self.uc.mem_write(0xA0000, self.smram_hidden)
                    self.smram_hidden = view
                    _flush_tb(self.uc)
                    if not self.stopped_reason:  # stopped only for this: go on from here
                        remaining -= 1000
                        pc = self._code_address()
                        continue
                if self.gp_at is not None:
                    uc.reg_write(UC_X86_REG_EIP, self.gp_at)
                    self.gp_at = None
                    self.invalid6 += 1  # (counted with the invalid opcodes: no endless loop)
                    self._deliver_pm(uc, 13)
                    if not self.stopped_reason:
                        remaining -= 1000
                        pc = self._code_address()
                        continue
                if self.flush_pending:
                    self.flush_pending = False
                    if self.smi_ack_pending:
                        self.smi_ack_pending = False
                        memory = bytes(uc.mem_read(0, 0x100000))
                        for m in DELL_SMI_WAIT.finditer(memory):
                            uc.mem_write(m.start() + 5, b"\xeb")
                    _flush_tb(uc)
                    if not self.stopped_reason:  # stopped only for this: go on from here
                        remaining -= 1000
                        pc = self._code_address()
                        continue
                # (not while channel 0 is timing: its count would stand still, and a POST
                # that calibrates a delay against it searches for ever, J-Bond E450C-D)
                if not self.pit_active and not self.pit_used_in_slice and not self.pit0_timing:
                    self._retire("pit_hook")  # gate closed for a whole slice
                self.pit_used_in_slice = False
                self._remove_retired_hooks()
                if self.wanted_hooks:
                    for name in self.wanted_hooks:
                        self._add_hook(name)
                    self.wanted_hooks = set()
                    if not self.stopped_reason:  # stopped only for this: go on from here
                        remaining -= 1000
                        pc = self._code_address()
                        continue
                if self.shadow_before is not None or self.pam_off_pending:
                    fetched = self._unfetch()
                    if self.pam_off_pending:
                        self._apply_pam_off()
                    else:
                        self._apply_shadow()
                    self._prefetch(fetched)
                    if not self.stopped_reason:  # stopped only for this: go on from here
                        remaining -= 1000
                        pc = self._code_address()
                        continue
                remaining -= count
                if self.stopped_reason:  # stopped by a hook (uc.emu_stop)
                    break
                if (
                    not self.timer_irq
                    and not uc.reg_read(UC_X86_REG_EFLAGS) & 0x200
                    and self._after_hlt()
                ):
                    # HLT with interrupts off: nothing comes. (Only a HLT ends a run early
                    # without a hook; runs in timer slices end anywhere.)
                    self.stopped_reason = "halted"
                    break
                if remaining <= 0 and self._waits_for_reset():
                    self.spin_resets += 1
                    self._cpu_reset()  # (memory and CMOS kept: the flag that the clock is set)
                    remaining, pc = self.max_instructions, 0xFFFF0
                    continue
                if remaining <= 0:
                    self.stopped_reason = "instruction limit reached"
                    break
                if self.timer_irq:
                    self._timer_irq()
                pc = self._code_address()
        except Stop:
            self._remove_retired_hooks()
            if self.stopped_reason in ("waiting for a key", "polling the keyboard"):
                self.fire_timer()
        except UcError as e:
            cs_now, ip_now = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_IP)
            self.stopped_reason = (
                self.stopped_reason or f"emulation error {e} at {cs_now:04X}:{ip_now:04X}"
            )
        except OSError as e:  # an access violation inside Unicorn itself (code running wild)
            self.stopped_reason = f"the emulator itself failed ({e}); the code had run off"
        finally:
            timer.cancel()
        return self.screen()

    def fire_timer(self, ticks: int = 40) -> None:
        """Let time pass while the program waits for a key: call the timer-tick handler
        (INT 1Ch) the program installed, as the hardware timer would 18.2 times a second.
        Setup programs use it to keep the clock on screen up to date."""
        uc = self.uc
        off, seg = struct.unpack("<HH", uc.mem_read(0x1C * 4, 4))
        if (off, seg) == (0x500, 0):
            return
        regs = [
            UC_X86_REG_AX,
            UC_X86_REG_BX,
            UC_X86_REG_CX,
            UC_X86_REG_DX,
            UC_X86_REG_SI,
            UC_X86_REG_DI,
            UC_X86_REG_BP,
            UC_X86_REG_SP,
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
            UC_X86_REG_IP,
            UC_X86_REG_EFLAGS,
        ]
        saved = {r: uc.reg_read(r) for r in regs}
        uc.mem_write(0x510, b"\xf4")  # return address of the simulated interrupt
        for _ in range(ticks):
            # what INT 08h does before calling INT 1Ch: count the tick in the BIOS data area
            count = struct.unpack("<I", uc.mem_read(0x46C, 4))[0] + 1
            uc.mem_write(0x46C, struct.pack("<I", count))
            for r, v in saved.items():
                uc.reg_write(r, v)
            ss, sp = saved[UC_X86_REG_SS], (saved[UC_X86_REG_SP] - 6) & 0xFFFF
            frame = struct.pack("<HHH", 0x510, 0, saved[UC_X86_REG_EFLAGS] & 0xFFFF)
            uc.mem_write((ss << 4) + sp, frame)
            uc.reg_write(UC_X86_REG_SP, sp)
            uc.reg_write(UC_X86_REG_CS, seg)
            try:
                uc.emu_start((seg << 4) + off, 0x510, count=200_000)
            except (Stop, UcError):
                break
        for r, v in saved.items():
            uc.reg_write(r, v)

    def screen(self) -> Screen:
        if self.video_mode in PLANAR_MODES:
            return self._graphics_screen()
        raw = self.uc.mem_read(VRAM, COLS * ROWS * 2)
        s = Screen()
        for i in range(COLS * ROWS):
            s.put(i % COLS, i // COLS, raw[2 * i], raw[2 * i + 1])
        h = s.char_height = self.char_height
        plane = bytes(self.uc.mem_read(FONT_PLANE, 256 * 32))
        if any(plane):  # the program loaded its own font
            s.font = b"".join(plane[c * 32 : c * 32 + h] for c in range(256))
            if self.fill_solid_font:
                s.font = _solid_font_filled(s.font, h)
            elif h in FONTS and not _letters_in_font(s.font, h):
                s.font = FONTS[h]  # (junk in the plane, the text is right: AT29C010A's Hi-Flex)
        else:
            s.font = FONTS[h]
        s.palette = [tuple(v * 255 // 63 for v in self.dac[p]) for p in self.palette_regs]
        if not any(any(c) for c in s.palette):  # DAC cleared by POST and never reloaded (a
            s.palette = [
                tuple(v * 255 // 63 for v in DEFAULT_DAC[p])  # real VGA BIOS would)
                for p in DEFAULT_PALETTE
            ]
        s.blink = self.blink
        return s
