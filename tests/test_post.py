"""The rebuilt Award POST screen (award_post) from a hand-made F000 segment: the ROM's banner,
copyright, board message, BIOS ID and POST messages where Award's POST shows them."""

from __future__ import annotations

import award_post


def segment(banner: bytes = b"Award Modular BIOS v4.51PG") -> bytes:
    seg = bytearray(0x10000)

    def put(at: int, s: bytes) -> None:
        seg[at : at + len(s) + 1] = s + b"\x00"

    put(0xE061, banner)
    put(0xE091, b"Copyright (C) 1984-98, Award Software, Inc.")
    put(0xE0C1, b"ASUS P2B ACPI BIOS Revision 1014")
    put(0xEC71, b"08/01/2002-i440BX-<<P2B>>")
    # the POST messages, with the attribute bytes Award puts around the key's name
    put(0x3D00, b", An Energy Star Ally\x00Memory Test : \x00K OK")
    put(0x3E00, b"Press \x07DEL\x07 to enter SETUP")
    put(0x5000, b"Copyright (C) 1998, Award Software, Inc.")  # (the PnP extension's)
    return bytes(seg)


def test_an_award_post_screen_from_the_roms_texts() -> None:
    got = award_post.post_screen(segment())
    assert got is not None
    screen, text = got
    lines = text.split("\n")
    assert lines[0] == "Award Modular BIOS v4.51PG, An Energy Star Ally"
    assert lines[1] == "Copyright (C) 1984-98, Award Software, Inc."
    assert lines[3] == "ASUS P2B ACPI BIOS Revision 1014"
    assert lines[5] == "Memory Test :  " + award_post.MEMORY_EXAMPLE.decode()
    assert lines[23] == "Press DEL to enter SETUP"
    assert lines[24] == "08/01/2002-i440BX-<<P2B>>"
    assert screen.text() == text  # (no logo module: nothing drawn but the text)


def test_the_version_ends_before_the_next_word() -> None:
    # (the setup's "AwardBIOS v6.00PG Save To Disk Manager" packs "v6.00PGSave" elsewhere)
    seg = bytearray(segment(b"Phoenix - AwardBIOS v6.00PG"))
    seg[0x100:0x120] = b"Phoenix - AwardBIOS v6.00PGSave\x00"
    got = award_post.post_screen(bytes(seg))
    assert got is not None and got[1].startswith("Phoenix - AwardBIOS v6.00PG, An Energy")


def test_no_post_screen_without_an_award_banner() -> None:
    assert award_post.post_screen(bytes(0x10000)) is None
