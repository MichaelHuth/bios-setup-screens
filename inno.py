"""
The boot diskette in an Inno Setup 4.1 installer (Packard Bell's and NEC's BIOS updates), read as
data, nothing is run: the installer's last 28 bytes give the offsets; the files are one raw LZMA1
stream behind "zlb\\x1a", which here holds a bootable CD image (ISO 9660 with El Torito), whose boot
image is a DOS diskette with the flash program and the flash image on it.
"""

from __future__ import annotations

import lzma
import struct

MAX_FILES_BYTES = 128 << 20  # (a CD image; a small file must not unpack to gigabytes)
TRAILER = 28
SECTOR = 2048
BOOT_RECORD_LBA = 17


def _files(raw: bytes) -> bytes | None:
    """What the installer's file stream unpacks to, or None if this is not such an installer."""
    if len(raw) < TRAILER:
        return None
    total, _, _, _, setup0, chunk, _ = struct.unpack_from("<7I", raw, len(raw) - TRAILER)
    if total != len(raw) or not 0 < chunk < setup0 < total or raw[chunk : chunk + 4] != b"zlb\x1a":
        return None
    props = raw[chunk + 4]
    pb, rest = divmod(props, 45)
    lp, lc = divmod(rest, 9)
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "lc": lc,
            "lp": lp,
            "pb": pb,
            "dict_size": struct.unpack_from("<I", raw, chunk + 5)[0],
        }
    ]
    unpack = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
    return unpack.decompress(raw[chunk + 9 : setup0], MAX_FILES_BYTES)


def boot_diskette(raw: bytes) -> bytes | None:
    """The diskette image on the installer's CD, or None."""
    try:
        data = _files(raw)
    except (lzma.LZMAError, ValueError, struct.error):
        return None
    if data is None:
        return None
    descriptor = data.find(b"CD001") - 1
    if descriptor < 16 * SECTOR:
        return None
    iso = descriptor - 16 * SECTOR
    record = iso + BOOT_RECORD_LBA * SECTOR
    if data[record + 7 : record + 30] != b"EL TORITO SPECIFICATION":
        return None
    catalog = iso + struct.unpack_from("<I", data, record + 0x47)[0] * SECTOR
    start = iso + struct.unpack_from("<I", data, catalog + 32 + 8)[0] * SECTOR
    if data[start + 510 : start + 512] != b"\x55\xaa":
        return None
    sector = struct.unpack_from("<H", data, start + 11)[0]
    sectors = struct.unpack_from("<H", data, start + 19)[0]
    return data[start : start + sector * sectors] or None
