"""The firmware readers on images the tests build: AMI module chains, Phoenix BCP chains and
TrustedCore volumes, Award option lists and extension labels, PhoenixBIOS 4.0 templates and
UEFI forms.
Several cases are defects found in real images and fixed, kept here so they stay fixed."""

from __future__ import annotations

import random
import struct

import pytest

import acer_setup
import ami
import award6_setup
import award_cf_bug
import award_emu_setup
import award_setup
import bios_summary
import hfjump_setup
import phoenix
import phoenix_tc_setup as tc
import pulldown_setup
import screen_tools
import sqx
import uefi_setup
import winbios_setup
from textscreen import Screen
from builders import (
    AmiModule,
    FfvFile,
    PhoenixModule,
    StringPack,
    ami_image,
    ffv_image,
    lha_module,
    phoenix_image,
    pick_record,
    template,
)

SETUP = b"setup client " * 200
FONT = random.Random(3).randbytes(1500)


# --- AMIBIOS -------------------------------------------------------------------------------


def test_ami_chain_last_to_first() -> None:
    image = ami_image(
        [AmiModule(0x00, b"post " * 300), AmiModule(0x04, SETUP), AmiModule(0x19, FONT, False)]
    )
    info, modules = ami.extract(image)
    assert info["version"] == "0800" and info["date"] == "01/01/99"
    assert [m["id"] for m in modules] == [0x19, 0x04, 0x00]
    assert [m["name"] for m in modules] == ["ADM Font", "Setup Client", "POST"]
    assert modules[0]["data"] == FONT and not modules[0]["compressed"]
    assert modules[1]["data"] == SETUP and modules[1]["compressed"]
    assert "boot_block" in info


def test_ami_pci_and_language_modules_are_named_by_their_load_address() -> None:
    image = ami_image(
        [
            AmiModule(0x20, b"\x55\xaa rom", False, load=0x1234_8086),
            AmiModule(0x21, b"GNALSU", False, load=0x656E),
        ]
    )
    names = {m["id"]: m["file_name"] for m in ami.extract(image)[1]}
    assert names == {0x20: "pci_8086_1234.rom", 0x21: "lang_en.bin"}


def test_ami_large_stored_module_takes_its_length_from_before_the_header() -> None:
    big = bytes(range(256)) * 300
    modules = ami.extract(ami_image([AmiModule(0x2A, big, compressed=False, big=True)]))[1]
    assert modules[0]["data"] == big


def test_ami_cim_x_modules_are_stored_whatever_their_flag() -> None:
    image = bytearray(ami_image([AmiModule(0x40, b"CIM-X" * 50, compressed=False)]))
    at = 0x1000
    image[at + 7] = 0  # (the flag says compressed)
    modules = ami.extract(bytes(image))[1]
    assert modules[0]["data"] == b"CIM-X" * 50 and not modules[0]["compressed"]


def test_ami_cpu_signature_is_one_the_post_modules_table_lists() -> None:
    def post(entries: list[tuple[int, int]]) -> dict:
        data = bytearray(0x80)
        search = b"\x24\xf0\x0a\xc9\x74\x02\x0c\x0f\xbb" + struct.pack("<H", 0x40) + b"\xe8\0\0"
        data[0x10 : 0x10 + len(search)] = search
        table = b"".join(struct.pack("<HHH", s, f, 0) for s, f in entries + [(0xFFFF, 0x121)])
        data[0x40:0x44] = struct.pack("<HH", 0x44 + len(table) - 6, 0x0A00)
        data[0x44 : 0x44 + len(table)] = table
        return {"id": 0, "data": bytes(data)}

    # the first entry that allows write-back as well as write-through, an OverDrive (1xxxh)
    # last; any stepping (Fh)
    table = [(0x051F, 0x15C2), (0x153F, 0x15D3), (0x054F, 0x15D3)]
    assert ami.cpu_signature([post(table)]) == 0x0541
    assert ami.cpu_signature([post([(0x0430, 0x0329)])]) == 0x0430  # (else the first)
    assert ami.cpu_signature([post([])]) is None  # (an AMD board: Intel's table empty)
    assert ami.cpu_signature([{"id": 1, "data": post([(0x051F, 0x15CB)])["data"]}]) is None


def test_ami_broken_pointer_is_an_error_not_a_crash() -> None:
    image = bytearray(ami_image([AmiModule(0x01, b"x" * 100)]))
    core = len(image) - 0x2000
    struct.pack_into("<HH", image, core + 18, 0, 0x0100)  # (an address below the image)
    modules = ami.extract(bytes(image))[1]
    assert modules and "outside the image" in modules[0]["error"]


def test_ami_core_header_needs_a_version() -> None:
    assert ami.find_core(b"..AMIBIOSC is mentioned here..." + bytes(100)) == 2  # (no other hit)
    image = b"AMIBIOSCxx" + bytes(50) + b"AMIBIOSC0700" + bytes(50)
    assert ami.find_core(image) == 60
    with pytest.raises(ValueError):
        ami.extract(bytes(1000))


# --- PhoenixBIOS (BCP) ----------------------------------------------------------------------


def test_phoenix_chain_with_each_compression() -> None:
    text = b"PhoenixBIOS Setup Utility " * 60
    image = phoenix_image(
        [
            PhoenixModule("B", b"bios code " * 200, comp=0),
            PhoenixModule("S", b"STRPACK-BIOS" + text, comp=5),
            PhoenixModule("T", text[:900], comp=3),
            PhoenixModule("E", SETUP, comp=5, ident=1, load=(0x1, 0x0)),
        ]
    )
    info, modules = phoenix.extract(image)
    assert info["version"] == "4.0 R6.0" and info["date"] == "01/01/00"
    assert [m["type"] for m in modules] == ["E", "T", "S", "B"]
    assert [m["name"] for m in modules] == ["setup", "template", "strings", "bioscode"]
    assert modules[0]["data"] == SETUP and modules[0]["load"] == "1000:0000"
    assert modules[1]["data"] == text[:900] and modules[1]["compression"] == "LZSS"
    assert modules[2]["data"] == b"STRPACK-BIOS" + text
    assert not any("error" in m for m in modules)


def test_phoenix_fragments_are_put_together() -> None:
    data = bytes(range(256)) * 20
    modules = phoenix.extract(phoenix_image([PhoenixModule("X", data, comp=0, fragments=3)]))[1]
    assert modules[0]["data"] == data and modules[0]["fragments"] == 3


def test_phoenix_pointer_128k_off_is_followed() -> None:
    image = bytearray(
        phoenix_image([PhoenixModule("B", b"a" * 50, comp=0), PhoenixModule("E", SETUP)], 0x40000)
    )
    second = image.find(b"\x00\x31\x31", 0x400 + 1) - 4  # (the setup module's header)
    image[second + 0x20000 : second + 0x20000 + 27] = image[second : second + 27]
    image[second : second + 27] = b"\xff" * 27  # (where the pointer leads: no header)
    struct.pack_into("<I", image, 0x1A + 0x77, 0xFFFC0000 | second)
    modules = phoenix.extract(bytes(image))[1]
    assert modules[0]["offset"] == second + 0x20000


def test_phoenix_unsupported_compression_keeps_the_raw_body() -> None:
    image = bytearray(phoenix_image([PhoenixModule("D", b"z" * 40, comp=0)]))
    image[0x400 + 10] = 7  # (compression type 7)
    module = phoenix.extract(bytes(image))[1][0]
    assert "not supported" in module["error"] and module["raw"] == b"z" * 40


def test_phoenix_trailing_data_after_the_flash_is_cut() -> None:
    image = phoenix_image([PhoenixModule("E", SETUP)], 0x200000) + b"trailer" * 100
    assert phoenix.extract(image)[1][0]["data"] == SETUP


def test_trustedcore_volume_files() -> None:
    image = ffv_image([FfvFile("_E00", SETUP), FfvFile("_T01", b"template " * 40, compressed=True)])
    info, modules = phoenix.extract(image)
    assert [(m["type"], m["id"], m["name"]) for m in modules] == [
        ("E", 0, "setup"),
        ("T", 1, "template"),
    ]
    assert modules[0]["data"] == SETUP and modules[1]["data"] == b"template " * 40
    assert modules[1]["compression"] == "LH5"


def test_not_phoenix() -> None:
    with pytest.raises(ValueError, match="BCPSEGMENT"):
        phoenix.extract(bytes(4096))


# --- Award ---------------------------------------------------------------------------------


def test_award_option_lists_end_entries_at_nul_and_01h() -> None:
    # the I/O recovery times: "NA", seven blanks ended by 01h, then 8, 1 ... 7
    seg = (
        b"NA\0"
        + b"  \x01" * 6
        + b"  \x018 \x001 \x002 \x003 \x004 \x005 \x006 \x007 \x00Next label : \0"
    )
    assert award_setup._option(seg, 0, 0) == b"NA"
    assert award_setup._option(seg, 0, 8) == b"8 "
    assert award_setup._option(seg, 0, 9) == b"1 "  # (counting NULs only gave a label)
    assert award_setup._option(seg, 0, 15) == b"7 "
    assert award_setup._option(b"Disabled\0Enabled\0", 0, 1) == b"Enabled"


def _ext_module() -> tuple[bytes, list[str]]:
    labels = ["Virus Warning        : ", "CPU Level 1 Cache    : ", "Boot Sequence        : "]
    module = bytearray(0x400)
    for k, text in enumerate(labels):
        at = 0x200 + 0x40 * k
        module[at : at + len(text) + 1] = text.encode() + b"\0"
        struct.pack_into("<H", module, 0x101 + 2 * k, at)  # (an odd offset: BH6's is too)
    return bytes(module), labels


def test_award_extension_labels_found_in_the_awardext_module() -> None:
    module, labels = _ext_module()
    image = b"\xff" * 0x100 + lha_module(b"awardext.rom", module) + b"\xff" * 0x100
    tables = award_setup.extension_labels(image)
    assert [text for _, text in tables[0][1]] == labels
    assert award_setup._page_labels(tables, [0, 1, 2]) == tables[0]
    assert award_setup._page_labels(tables, [5]) is None  # (no table long enough)
    assert award_setup.extension_labels(b"\xff" * 0x100 + lha_module(b"other.bin", module)) == []


def test_award_label_tables_must_look_like_labels() -> None:
    module = bytearray(0x400)
    for k, text in enumerate([b"Intel Pentium", b"AMD-K6", b"Cyrix MII"]):
        at = 0x200 + 0x40 * k
        module[at : at + len(text) + 1] = text + b"\0"
        struct.pack_into("<H", module, 0x100 + 2 * k, at)
    assert award_setup.extension_labels(lha_module(b"awardext.rom", bytes(module))) == []


# --- PhoenixBIOS 4.0 templates --------------------------------------------------------------


def _items(records: list[bytes], strings: StringPack) -> list[dict]:
    data, table = template(records)
    return tc._items(data, tc.Strings(strings.pack, strings.base), table, 0, set(), ptr=0)


def test_template_pick_item_with_options() -> None:
    s = StringPack(["Floppy A:", "Select the drive.", "Disabled", "1.44 MB"])
    items = _items(
        [
            pick_record(
                s.refs["Floppy A:"],
                s.refs["Select the drive."],
                [s.refs["Disabled"], s.refs["1.44 MB"]],
            )
        ],
        s,
    )
    assert items[0]["prompt"] == "Floppy A:" and items[0]["options"] == ["Disabled", "1.44 MB"]


def test_template_marker_run_without_a_name_gives_no_options() -> None:
    s = StringPack(["Language:", "Pick the language."])  # (its help follows the prompt)
    items = _items(
        [pick_record(s.refs["Language:"], s.refs["Pick the language."], [0xFF00, 0xFF01, 0xFF02])],
        s,
    )
    assert items[0]["prompt"] == "Language:" and items[0]["options"] == []


def test_the_language_list_shows_the_name_after_its_prompt() -> None:
    # (the strings pack names its own language right after the prompt: "Language:\0English")
    s = StringPack(["Pick the language.", "Language:", "English  (US)"])
    items = _items(
        [pick_record(s.refs["Language:"], s.refs["Pick the language."], [0xFF00, 0xFF01, 0xFF02])],
        s,
    )
    assert items[0]["options"] == ["English  (US)"]


def test_template_references_into_the_middle_of_a_text_are_no_option() -> None:
    s = StringPack(["Type:", "help", "Write Protect:", "Auto"])
    stray = s.mid_text("Write Protect:")  # (would show "ite Protect:")
    items = _items([pick_record(s.refs["Type:"], s.refs["help"], [stray, s.refs["Auto"]])], s)
    assert items[0]["options"] == ["Auto"]


def test_template_rows_without_a_real_prompt_are_dropped() -> None:
    s = StringPack(["Real item:", "help", "Exit Saving Changes", "On"])
    cut = s.mid_text("Exit Saving Changes")  # (a prompt that is the end of another text)
    records = [
        pick_record(s.refs["Real item:"], s.refs["help"], [s.refs["On"]]),
        pick_record(0, 0, [s.refs["On"]]),  # (a word table read as a record: no prompt)
        pick_record(cut, s.refs["help"], [s.refs["On"]]),
    ]
    assert [i["prompt"] for i in _items(records, s)] == ["Real item:"]


def test_template_run_time_lists_of_phoenixbios_4_have_no_options() -> None:
    s = StringPack(["Boot order:", "help", "Floppy"])
    items = _items(
        [pick_record(s.refs["Boot order:"], s.refs["help"], [s.refs["Floppy"]], mode=0x01)], s
    )
    assert items[0]["options"] == []


# --- UEFI forms (IFR) -----------------------------------------------------------------------


def ifr(code: int, data: bytes = b"", scope: bool = False) -> bytes:
    return bytes((code, (len(data) + 2) | (0x80 if scope else 0))) + data


def checkbox(prompt: int, qid: int) -> bytes:
    # prompt, help, question id, var store, var offset, flags; then the checkbox flags
    return ifr(0x06, struct.pack("<HHHHHBB", prompt, 6, qid, 1, 0, 0, 0))


def test_a_setting_repeated_under_conditions_is_shown_once() -> None:
    # the same checkbox for three CPUs, each under its own (here: false) SUPPRESS_IF, and one
    # outside any condition twice (kept: nothing says only one is shown)
    variants = b"".join(
        ifr(0x0A, scope=True) + ifr(0x47) + checkbox(5, qid) + ifr(0x29) for qid in (10, 11, 12)
    )
    pkg = bytes(4) + (
        ifr(0x0E, bytes(16) + struct.pack("<HHB", 1, 2, 0), scope=True)
        + ifr(0x01, struct.pack("<HH", 1, 3), scope=True)
        + variants
        + checkbox(7, 20)
        + checkbox(7, 21)
        + ifr(0x29)
        + ifr(0x29)
    )
    (form_set,) = uefi_setup._parse_ifr(pkg)
    _, items = form_set.forms[1]
    assert [(i["prompt"], i["qid"]) for i in items] == [(5, 10), (7, 20), (7, 21)]


def test_award6_option_texts_skip_their_script_commands() -> None:
    # MSI's Cell Menu voltages call native code around the value (10h = native, 2
    # argument bytes, which may be 01h, the byte that also ends an entry)
    lang = bytearray(0x200)
    struct.pack_into("<HH", lang, 0x10, 1, 0x20)  # one section, its table at 20h
    struct.pack_into("<HH", lang, 0x20, 1, 0x40)  # one text, at 40h
    entries = b"\x10\xe5\x12\x10\x01\x13CPU Default\x10\xee\x12\x00" + b"1.50 V\x00"
    lang[0x40 : 0x40 + len(entries)] = entries
    bios = object.__new__(award6_setup.Award6)
    bios.lang = bytes(lang)
    interp = award_setup.Interpreter(b"", 0, None, [])  # type: ignore[arg-type]
    interp.lang = bios.lang
    interp.ops = {0x10: ("native", 2, -1)}
    interp.last_char = 0x15
    bios._interp = lambda screen, ext: interp  # type: ignore[method-assign]
    bios._in_language = lambda word: True  # type: ignore[method-assign]
    assert bios._option_text(0x0000, 0) == b"CPU Default"
    assert bios._option_text(0x0000, 1) == b"1.50 V"


def test_early_award_version_is_found_with_a_small_or_capital_v() -> None:
    for version in (b"v4.50", b"V3.03 NFS", b"Version V3.13c"):
        rom = b"Award Software  286 Modular BIOS " + version + b" SETUP"
        assert award_emu_setup.is_early_award(rom), version
    assert not award_emu_setup.is_early_award(b"Award Modular BIOS V6.00PG")


def test_award6_oem_pages_are_named_by_their_first_entries() -> None:
    # an OEM menu bar's pages that no entry opens: entries as (label, page it opens)
    pages = {
        1: [("Date (mm:dd:yy)", 0), ("Time (hh:mm:ss)", 0)],
        3: [("Virus Warning", 0)],
        4: [("DRAM Timing", 0)],
        5: [("Video Off Method", 0)],
        8: [
            ("First Boot Device", 0),
            ("Advanced BIOS Features", 3),
            ("Advanced Chipset Features", 4),
        ],
        13: [("Case Open Warning", 0), ("CPU Warning Temperature", 0), ("CPU FAN Speed", 0)],
        14: [("Init Display First", 0), ("OnChip IDE Device", 0), ("Onboard Device", 0)],
        17: [("PCI Slot 1  IRQ Select", 0), ("PCI Slot 2  IRQ Select", 0)],
        21: [  # (a page of all items: Power Management Setup is not its name)
            ("Advanced BIOS Features", 3),
            ("Advanced Chipset Features", 4),
            ("Power Management Setup", 5),
            ("ACPI Function", 0),
        ],
    }
    entries = {(page, i): entry for page, items in pages.items() for i, entry in enumerate(items)}
    bios = object.__new__(award6_setup.Award6)
    bios.items = {
        page: [(i, (page, i)) for i in range(len(items))] for page, items in pages.items()
    }
    bios.pages_only = True
    bar = ("Main", "Advanced", "Power", "Defaults", "Exit", "HW Monitor")
    table = b"".join(n.encode().ljust(16, b"\0") for n in bar) + b"X"
    bios._bar_table = lambda: table  # type: ignore[method-assign]
    bios._label = lambda e: entries[e][0]  # type: ignore[method-assign]
    bios._target = lambda e: entries[e][1]  # type: ignore[method-assign]
    assert bios.page_titles() == {
        1: "Main",
        3: "Advanced BIOS Features",
        4: "Advanced Chipset Features",
        5: "Power Management Setup",
        8: "Advanced",
        13: "HW Monitor",
        14: "Integrated Peripherals",  # (Award's own names: the bar has none for them)
        17: "PnP/PCI Configurations",
        21: "Page 21",
    }


def test_hiflex_direct_start_takes_posts_monitor_setup() -> None:
    def call(at: int, to: int) -> bytes:
        return b"\xe8" + struct.pack("<h", to - (at + 3))

    # RunTime: a write routine with the index in AH, called by a run of mov ax,imm ; call
    runtime = bytearray(bytes.fromhex("9cfa52ba950286c4eeeb0086e042ee5a9dc3"))
    for value in (0x1370, 0x50FF, 0x0B1B):
        runtime += b"\xb8" + struct.pack("<H", value) + call(len(runtime) + 3, 0)
    # a read routine (in al,dx) is not a write routine: calls into it are left alone
    reader = len(runtime)
    runtime += bytes.fromhex("ba95028ac4ee42ecc3")
    for value in (0x0B00, 0x0B01, 0x0B02):
        runtime += b"\xb8" + struct.pack("<H", value) + call(len(runtime) + 3, reader)
    writes = hfjump_setup.monitor_writes(bytes(runtime), 0)
    assert writes == [(0x13, 0x70), (0x50, 0xFF), (0x0B, 0x1B)]
    # POST, loaded at offset 100h: the index in AL, a table walked by mov si ; mov cx ;
    # mov ax,cs:[si]
    post = bytearray(bytes.fromhex("5152ba9502ee4286c4ee5a59c3"))
    table = 40
    post += b"\xbe" + struct.pack("<H", 0x100 + table) + bytes.fromhex("b903002e8b04")
    post += call(len(post), 0) + bytes.fromhex("83c602e2f5c3")
    post = post.ljust(table, b"\x90") + bytes((0x13, 0x70, 0x0B, 0x5B, 0x5D, 0x00))
    writes = hfjump_setup.monitor_writes(bytes(post), 0x100)
    assert writes == [(0x13, 0x70), (0x0B, 0x5B), (0x5D, 0x00)]
    # a VT82C686A board's: (index, value) words, then mov dh,0Ch ; mov dl,al ; mov al,ah ; out
    via = bytearray(bytes((0x2B, 0xFF, 0x2C, 0x00, 0x47, 0xF0)))
    routine = len(via)
    via += bytes.fromhex("5251b60c8ad08ac4eee6eb595ac3")
    via += b"\xbe\x00\x00\xb9\x03\x00\x2e\x8b\x04" + call(len(via) + 9, routine)
    via += bytes.fromhex("83c602e2f5c3")
    assert hfjump_setup.monitor_writes(bytes(via), 0) == []  # (not the 295h routine)
    writes = hfjump_setup.monitor_writes(bytes(via), 0, hfjump_setup.VIA_MONITOR_WRITE)
    assert writes == [(0x2B, 0xFF), (0x2C, 0x00), (0x47, 0xF0)]


# --- Award INT 13h block-mode bug (0040:0076, C4h -> C0h) ------------------------------------

# the reported 4.50G entry: the control byte ORed into 0040:0076 before the drive count check
CF_ENTRY = bytes.fromhex(
    "0ae47506c646ff00eb0f80fc08742580fc15742080fc01741b8a56ffb008e84e08baf603ee"
    "24c026080676008a46ff3a46fe7312"
)
CF_MASK = bytes.fromhex("368a740980fe91743826f6067600c0741380e6f080fe40770b")
# later images: C4h, C5h and C6h jump past the mask
CF_GUARDED = bytes.fromhex(
    "368a740980fe91744780fec4742480fec5741f80fec6741a26f6067600c0741280e6f080fe40770a"
)


def test_the_award_cf_bug_is_found_where_both_pieces_are_there() -> None:
    found = award_cf_bug.check([("image", b"\x90" * 64 + CF_ENTRY + b"\x90" * 64 + CF_MASK)])
    assert found is not None and found["verdict"].startswith("affected (both bugs, as in")
    assert "AH=41h" in found["trigger"] and "workaround" in found


def test_award_images_whose_block_commands_skip_the_mask_are_not_affected() -> None:
    found = award_cf_bug.check([("image", CF_ENTRY + b"\x90" * 64 + CF_GUARDED)])
    assert found is not None and found["verdict"].startswith("not affected")
    assert "workaround" not in found
    assert award_cf_bug.check([("image", b"\x90" * 256)]) is None


def test_the_bios_summary_reports_the_award_cf_bug() -> None:
    image = bytearray(b"\xff" * 0x10000)
    image[0x100 : 0x100 + 24] = b"Award Modular BIOS v4.50G"[:24]
    image[0x1000 : 0x1000 + len(CF_ENTRY)] = CF_ENTRY
    image[0x2000 : 0x2000 + len(CF_MASK)] = CF_MASK
    bugs = bios_summary.summarize(bytes(image))["known_bugs"]
    assert bugs[0]["verdict"].startswith("affected")


def test_pulldown_setup_reads_its_bar_and_list_and_where_post_starts() -> None:
    lines = [
        " ┌" + "─" * 76 + "┐",
        " │    General    Peripherals    PnP/PCI    Hard Disk    Misc.     Exit        │",
        " └─╔══════════════════════════════╗" + "─" * 43 + "┘",
        "░░░║                              ║",
        "░░░║  Load Default CMOS Setting   ║",
        "░░░║  Set Date                 ►  ║",
        "░░░║  [√] Internal Cache          ║",
        "░░░╚══════════════════════════════╝",
    ]
    screen = Screen()
    for row, line in enumerate(lines):
        for col, ch in enumerate(line):
            screen.put(col, row, 0x10 if ch == "►" else ch.encode("cp437")[0], 0x07)
    assert pulldown_setup.menu_bar(screen) == [
        "General",
        "Peripherals",
        "PnP/PCI",
        "Hard Disk",
        "Misc.",
        "Exit",
    ]
    entries = pulldown_setup.pulldown_entries(screen)
    assert entries == [
        "Load Default CMOS Setting",
        "Set Date                 ►",
        "[√] Internal Cache",
    ]
    # a reset vector's near jump into zeros (a damaged dump): POST from F000:E05B
    rom = bytearray(0x10000)
    rom[0xFFF0:0xFFF3] = b"\xe9\x00\xc0"
    assert pulldown_setup._entry(bytes(rom)) == 0xE05B
    rom[0xBFF3] = 0xFA
    assert pulldown_setup._entry(bytes(rom)) == 0xFFF0


def test_acers_setup_utility_menu_and_page_titles() -> None:
    menu = Screen()
    rows = {
        0: "Setup Utility",
        8: "    \x07 System Information     \xe2",
        9: "    \x07 Disk Drives            \xe2",
        16: "      Load Default Settings  \xe2",
        17: "      Abort Settings Change  \xe2",
        24: "     <ALT+H>  Key Help",
    }
    for row, text in rows.items():
        for col, ch in enumerate(text.encode("latin-1")):
            menu.put(col + 20, row, ch, 0x1F)
    assert acer_setup.utility_entries(menu) == [
        "System Information",
        "Disk Drives",
        "Load Default Settings",
        "Abort Settings Change",
    ]
    page = Screen()
    for col, ch in enumerate(b"\xc4" * 28 + b" System Information " + b"\xc4" * 28):
        page.put(col + 1, 1, ch, 0x1F)
    assert acer_setup.utility_title(page) == "System Information"


def test_sqx_distance_tables_have_a_bit_count_per_code() -> None:
    # 48/50/52 codes with a base each and one past the end; the 8 MB table 54 without it
    for mb, codes in ((1, 48), (2, 50), (4, 52), (8, 54)):
        bases, extra = sqx.BASE[mb]
        assert len(extra) == codes
        assert len(bases) == codes + (mb != 8)


def test_a_micro_channel_ps2_bios_is_named_as_one_without_setup() -> None:
    raw = bytearray(b"\xff" * 0x20000)
    raw[0x100:0x110] = b"IBM 1981, 1987 "
    raw[-16:] = bytes.fromhex("ea5be000f030342f31312f383800f834")  # model byte F8h
    assert "Reference Diskette" in screen_tools._unsupported_family(bytes(raw))
    raw[0x200:0x205] = b"SETUP"  # (a setup in the ROM: not this case)
    assert "Reference Diskette" not in screen_tools._unsupported_family(bytes(raw))


def test_a_dell_image_short_of_its_boot_block_is_named_as_one() -> None:
    raw = bytearray(0x70000)  # 448 KB of a 512 KB chip
    raw[0x1000:0x100B] = b"Dell System"
    assert "without its boot block (448 KB" in screen_tools._unsupported_family(bytes(raw))
    raw += bytes(0x10000)  # (the whole chip: not this case)
    assert "boot block" not in screen_tools._unsupported_family(bytes(raw))


def test_winbios_entry_is_the_longest_run_of_calls_before_the_setup_loader() -> None:
    runtime = bytearray(0x10000)
    sig, loader = 0xC016, 0xBFE4
    runtime[sig : sig + 8] = b"AMIBIOSS"
    runtime[loader : loader + 6] = b"\xb8\x02\x00\xbf" + struct.pack("<H", sig)  # mov ax,2

    def call(at: int, to: int) -> bytes:
        return b"\xe8" + struct.pack("<H", (to - at - 3) & 0xFFFF)

    runtime[0xA6C1:0xA6C5] = b"\x90\x90\x1f\x07"  # POST: one call, then the loader
    runtime[0xA6C5:0xA6C8] = call(0xA6C5, 0xC084)
    runtime[0xA6C8:0xA6CB] = call(0xA6C8, loader)
    setup = bytearray(b"\xe9\x00\x00")  # (a jmp before the run)
    for code in (
        call(0xBF58, 0xA62B),
        b"\x9c",  # pushf
        call(0xBF5C, 0xC08A),
        b"\xb8\x00\x10",  # mov ax,1000h
        call(0xBF62, 0xC093),
        call(0xBF65, 0xC084),
        call(0xBF68, loader),
    ):
        setup += code
    runtime[0xBF55 : 0xBF55 + len(setup)] = setup
    assert winbios_setup.find_entry(bytes(runtime)) == 0xBF58
