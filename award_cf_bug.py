"""
Static check for the Award INT 13h bug that can turn disk reads into CompactFlash sector erases.

Award Modular BIOS keeps a "disable retries" flag in BDA 0040:0076. Two pieces of its fixed-disk
INT 13h code combine badly:

1. The entry ORs bits 7-6 of the drive's FDPT control byte (INT 41h/46h table + 8) into 0040:0076
   and never clears it: ``and al, 0C0h / or es:[76h], al`` (Award 3.x: ``and byte es:[76h],
   0C0h / or es:[76h], al``). In the layout of the reported 4.50G image (ASUS VL/I-486SV2G,
   11/03/95) this happens before the drive-count check, so any call for a drive that is not
   installed (an INT 13h extensions probe, AH=41h with DL=81h) ORs in whatever the missing
   drive's table holds (80h there). Some images skip functions above 15h there; later ones
   check the drive count first, except for AH=00h (reset), which still reaches it.
2. Before writing the ATA command, with 0040:0076 bits 7-6 set, it turns 20h/30h into their
   "without retry" forms, but masks DH first: ``and dh, 0F0h / cmp dh, 40h / ja`` jumps past
   the restore with DH changed, so READ MULTIPLE (C4h, used with IDE HDD Block Mode) becomes
   C0h, which a CompactFlash card executes as CFA ERASE SECTORS (WRITE MULTIPLE C5h and SET
   MULTIPLE MODE C6h too). Later images compare DH with C4h, C5h and C6h first and jump past
   the mask: they are not affected, whatever sets the flag.

The check finds these instruction sequences in the image and its decompressed modules and says
which variant the BIOS has. It reads code only; whether a given PC loses data also depends on
Block Mode being on, a CF card (or another CFA device) on that BIOS's IDE ports, and what the
missing drive's table holds.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable

# and al, 0C0h ; or es:[0076h], al  -  or (3.x) and byte es:[0076h], 0C0h ; or es:[0076h], al
POISON = re.compile(rb"\x24\xC0\x26\x08\x06\x76\x00|\x26\x80\x26\x76\x00\xC0\x26\x08\x06\x76\x00")
# test byte es:[0076h], 0C0h ; jz ; and dh, 0F0h ; cmp dh, 40h ; ja
MASK = re.compile(rb"\x26\xF6\x06\x76\x00\xC0\x74.\x80\xE6\xF0\x80\xFE\x40\x77", re.S)
# before MASK in fixed images: cmp dh, 0C4h ; je (past the mask; then C5h, C6h)
GUARD = re.compile(rb"\x80\xFE\xC4(?:\x74|\x0F\x84)")
# after POISON: mov al, [bp-1] ; cmp al, [bp-2] ; jae (the drive count, checked only now)
DRIVE_AFTER = re.compile(rb"\x8A\x46\xFF\x3A\x46\xFE(?:\x73|\x0F\x83)")
# before POISON: cmp ah, 15h ; ja (functions above 15h, the extensions among them, skip it)
ABOVE_15H_SKIP = re.compile(rb"\x80\xFC\x15\x77")
# before POISON: or ah, ah ; jz ; cmp dl, bl (or bl, dl) ; jae, or pushf first (6.00: the
# count checked first, but not for AH=00h)
DRIVE_BEFORE = re.compile(rb"\x0A\xE4\x74.(?:\x3A\xD3|\x38\xDA)(?:\x73|\x0F\x83|\x9C)", re.S)
BLOCK_MODE = (b"Block Mode", b"BLOCK MODE", b"Block mode")

TRIGGERS = {
    "any": "any INT 13h call for a hard disk that is not installed (except AH=00h, 01h, 08h, "
    "15h), e.g. a program probing DL=81h for INT 13h extensions (AH=41h), sets 0040:0076 from "
    "that drive's table",
    "standard": "an INT 13h call with AH=02h-15h (not 01h, 08h) for a hard disk that is not "
    "installed sets 0040:0076 from that drive's table; extensions probes (AH=41h and up) skip "
    "that code",
    "reset": "only INT 13h AH=00h (reset) for a hard disk that is not installed sets 0040:0076 "
    "from that drive's table; other calls for a missing drive return an error first",
    "unknown": "the order of the drive check and the flag update could not be told",
}


def _layout(blob: bytes, at: int, end: int) -> str:
    """'any' (the flag is set before the drive count is checked, for any function but 00h, 01h,
    08h, 15h), 'standard' (the same for functions 02h-15h only), 'reset' (the count is checked
    first, except for AH=00h) or 'unknown'."""
    if DRIVE_AFTER.search(blob, end, end + 0x40):
        return "standard" if ABOVE_15H_SKIP.search(blob, max(0, at - 0x40), at) else "any"
    if DRIVE_BEFORE.search(blob, max(0, at - 0x100), at):
        return "reset"
    return "unknown"


def check(blobs: Iterable[tuple[str, bytes]]) -> Dict[str, Any] | None:
    """The finding for a BIOS image's blobs (the image and its decompressed modules, as
    (source, bytes) pairs), or None if neither instruction sequence is there."""
    poison: list[tuple[str, int, str]] = []
    mask: list[tuple[str, int, bool]] = []  # (source, offset, guarded: C4h-C6h skip it)
    block_mode = False
    for source, blob in blobs:
        for m in POISON.finditer(blob):
            poison.append((source, m.start(), _layout(blob, m.start(), m.end())))
        for m in MASK.finditer(blob):
            guarded = bool(GUARD.search(blob, max(0, m.start() - 0x18), m.start()))
            mask.append((source, m.start(), guarded))
        block_mode = block_mode or any(text in blob for text in BLOCK_MODE)
    if not poison and not mask:
        return None
    layout = next(
        (k for k in ("any", "standard", "reset", "unknown") if k in {p[2] for p in poison}), None
    )
    unguarded = any(not guarded for _, _, guarded in mask)
    after = "; after that every block-mode read (READ MULTIPLE, C4h) goes out as C0h"
    if unguarded and layout == "any":
        verdict = "affected (both bugs, as in the reported Award 4.50G image)"
        trigger = TRIGGERS["any"] + after
    elif unguarded and layout == "standard":
        verdict = "affected (both bugs; extensions probes do not trigger it)"
        trigger = TRIGGERS["standard"] + after
    elif unguarded and layout == "reset":
        verdict = "affected, narrower trigger (both bugs; the drive count is checked first)"
        trigger = TRIGGERS["reset"] + after
    elif unguarded and layout:
        verdict = "probably affected (both bugs; the entry's drive check was not recognised)"
        trigger = TRIGGERS["unknown"]
    elif unguarded:
        verdict = "partly: bug #2 is there (C4h -> C0h once 0040:0076 bits 7-6 are set)"
        trigger = "the flag is not set by the reported INT 13h entry code in this image"
    elif mask:
        verdict = (
            "not affected (fixed version: block commands C4h-C6h skip the mask, so reads "
            "cannot become C0h)"
        )
        trigger = (
            TRIGGERS[layout] + "; with it set only 20h/30h become 21h/31h (without retry)"
            if layout
            else "0040:0076 is not set by the reported entry code"
        )
    else:
        verdict = "partly: bug #1 is there (0040:0076 set from the FDPT), not the C4h mask"
        trigger = TRIGGERS[layout or "unknown"]
    where = [f"bug #1 (0040:0076 set) at 0x{at:X} in {src}" for src, at, _ in poison[:4]] + [
        f"bug #2 mask at 0x{at:X} in {src}" + (" (guarded: C4h-C6h skip it)" if g else "")
        for src, at, g in mask[:4]
    ]
    result: Dict[str, Any] = {
        "issue": "Award INT 13h block-mode bug: disk reads can become CompactFlash sector "
        "erases (ATA C0h, CFA ERASE SECTORS)",
        "verdict": verdict,
        "trigger": trigger,
        "found": where,
    }
    if unguarded:
        result["conditions"] = (
            "data is lost only with IDE HDD Block Mode enabled and a CompactFlash card (or "
            "other CFA device) on this BIOS's IDE channel, and only if the missing drive's "
            "table has bit 7 or 6 of its control byte set; a spinning hard disk rejects C0h. "
            "The read path does not check DRQ, so the BIOS reports the read as successful"
        )
        result["workaround"] = (
            "set IDE HDD Block Mode to Disabled in setup (reads then use 20h, which the bug "
            "only turns into 21h, READ SECTORS without retry), or load an INT 13h filter that "
            "rejects drives not installed (DL >= 0040:0075) before calling the BIOS"
        )
        if not block_mode:
            result["note"] = "no 'Block Mode' setup text found in this image"
    return result
