"""The firmware readers on images the tests build: AMI module chains, Phoenix BCP chains and
TrustedCore volumes, Award option lists and extension labels, and PhoenixBIOS 4.0 templates.
Several cases are defects found in real images and fixed, kept here so they stay fixed."""

from __future__ import annotations

import random
import struct

import pytest

import ami
import award_setup
import phoenix
import phoenix_tc_setup as tc
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


def test_template_marker_run_gives_no_options() -> None:
    s = StringPack(["Language:", "Pick the language."])
    items = _items(
        [pick_record(s.refs["Language:"], s.refs["Pick the language."], [0xFF00, 0xFF01, 0xFF02])],
        s,
    )
    assert items[0]["prompt"] == "Language:" and items[0]["options"] == []


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
