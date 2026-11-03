"""Unpack Intel desktop boards' EFI firmware updates to the UEFI firmware image.

    image(data: bytes) -> bytes

data is the update as downloaded (a ZIP, an EXE holding a ZIP, or a bare .BIO); the result is the
firmware image inside it: the firmware-volume image the board's flash is written from. Raises
ValueError when the input is not such an update, or when the image inside it cannot be found.

What the .BIO holds: a 0x214-byte update
header, then one firmware volume holding a single FFS file, whose GUID-defined section holds
the firmware-volume image. That image is either stored in the clear (its volumes are then
walked directly) or, on the EFI 1.10 ("Framework") boards, split: the volumes in the clear
plus one FFS file whose compression
section is raw LZMA and unpacks to the whole image. The latter is what carries the setup's strings,
so image() returns it when it is there.
"""

import io
import lzma
import re
import struct
import zipfile
from collections.abc import Iterator

BIO_MAGIC = bytes.fromhex("bd86663b760d3040b70eb5519e2fc5a0")  # the .BIO's first 16 bytes
EOCD = b"PK\x05\x06"
FVH = b"_FVH"
SEC_COMP, SEC_GUID, SEC_PE32, SEC_FVIMG, SEC_RAW = 0x01, 0x02, 0x10, 0x17, 0x19
SECT_TYPES = (0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19)
PART_EXT = re.compile(r"\.(BIO|BI[\dA-F]|BBO|REC|RE[\dA-F])$", re.I)


# --- the update container ---------------------------------------------------------------------


def _zip_members(data: bytes) -> list[tuple[str, bytes]]:
    """(name, bytes) of every member of every ZIP in data: the ZIP itself, a ZIP embedded in an
    EXE at any offset, and ZIPs stored inside members."""
    out, seen = [], set()

    def add(blob: bytes, depth: int) -> None:
        key = id(blob)
        if key in seen or depth > 4:
            return
        seen.add(key)
        try:  # (in memory: nothing to close)
            zf = zipfile.ZipFile(io.BytesIO(blob))  # pylint: disable=consider-using-with
        except (zipfile.BadZipFile, ValueError, OSError):
            return
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                raw = zf.read(info)
            except (zipfile.BadZipFile, NotImplementedError, ValueError, OSError):
                continue
            out.append((info.filename, raw))
            if raw[:4] == b"PK\x03\x04" or EOCD in raw[:0x200000]:
                add(raw, depth + 1)

    for at in (0, _embedded_zip(data)):
        if at >= 0:
            add(data[at:], 0)
    for _name, raw in list(out):
        add(raw, 1)
    return out


def _embedded_zip(data: bytes) -> int:
    """Start of the ZIP archive inside an EXE, or -1: found from its end-of-central-directory
    record, whose offset field gives the first local header."""
    at = data.rfind(EOCD)
    if at < 0:
        return -1
    if at + 22 > len(data):
        return -1
    off = struct.unpack_from("<I", data, at + 16)[0]  # (start of the central directory)
    if off >= len(data) - 4 or data[off : off + 4] != b"PK\x03\x04":
        return -1
    return off


def _find_bio(data: bytes) -> bytes:
    """The .BIO inside the update: the member that starts with the .BIO header GUID, or the input
    itself when it already is one."""
    if data[:16] == BIO_MAGIC:
        return data
    cands = []
    for name, raw in _zip_members(data):
        if raw[:16] == BIO_MAGIC:
            cands.append((0, name, raw))
        elif PART_EXT.search(name) and FVH in raw[:0x1000]:
            cands.append((1, name, raw))
    if not cands:
        raise ValueError("no Intel EFI firmware part (.BIO) in the update")
    cands.sort(key=lambda c: (c[0], -len(c[2])))
    return cands[0][2]


# --- the firmware volumes inside the .BIO ------------------------------------------------------


def _fvhdr(d: bytes, v: int) -> tuple[int, int] | None:
    """(length, header_length) of the volume header at v, or None."""
    if v < 0 or v + 0x48 > len(d) or d[v + 0x28 : v + 0x2C] != FVH:
        return None
    length, _sig, _attrs, hlen = struct.unpack_from("<Q4sIH", d, v + 0x20)
    if not (0x18 <= hlen <= 0x400 and 0x48 <= length <= len(d) - v):
        return None
    return length, hlen


def _known_volume(d: bytes, v: int) -> tuple[int, int]:
    """_fvhdr of a volume header found before (by _volumes)."""
    hdr = _fvhdr(d, v)
    assert hdr is not None
    return hdr


def _volumes(d: bytes, lo: int = 0, hi: int | None = None) -> list[int]:
    """Offsets of the volume headers in d[lo:hi] that are not inside another one."""
    hi = len(d) if hi is None else hi
    cand = []
    i = lo - 1
    while True:
        i = d.find(FVH, i + 1)
        if i < 0 or i >= hi:
            break
        if _fvhdr(d, i - 0x28):
            cand.append(i - 0x28)
    out: list[int] = []
    for v in sorted(cand):
        if not any(u < v < u + _known_volume(d, u)[0] for u in out):
            out.append(v)
    return out


def _files(d: bytes, v: int) -> Iterator[tuple[int, int, int]]:
    """The FFS files of the volume at v: (offset, type, size). Every header in the volume's range
    that looks used is taken, not just the ones the chain reaches: Intel's Framework images pack
    files with no padding (a file can start at an odd address) and the padding is not fixed
    elsewhere either, so following one chain misses files."""
    length, hlen = _known_volume(d, v)
    f, end = v + hlen, v + length
    while f + 24 <= end:
        if _used(d, f, end):
            yield f, d[f + 0x12], int.from_bytes(d[f + 0x14 : f + 0x17], "little")
            f += 24  # the next header cannot start inside these 24 bytes
        else:
            f += 1


def _used(d: bytes, f: int, end: int) -> bool:
    """Is there a used FFS file header at f?"""
    if f + 24 > end or d[f + 0x17] != 0xF8 or d[f + 0x12] > 0x0F:
        return False
    size = int.from_bytes(d[f + 0x14 : f + 0x17], "little")
    return 24 <= size <= end - f and _first_section(d, f, size)


def _first_section(d: bytes, f: int, size: int) -> bool:
    sh = f + 24
    if sh + 4 > f + size:
        return True
    ssize = int.from_bytes(d[sh : sh + 3], "little")
    return 4 <= ssize <= size and d[sh + 3] in SECT_TYPES


def _sections(d: bytes, f: int, fsize: int) -> Iterator[tuple[int, int, int]]:
    """The sections of the FFS file at f: (offset, type, size)."""
    p = f + 24
    while p + 4 <= f + fsize:
        size = int.from_bytes(d[p : p + 3], "little")
        styp, hdr = d[p + 3], 4
        if size == 0xFFFFFF:
            if p + 8 > f + fsize:
                return
            size, hdr = struct.unpack_from("<I", d, p + 4)[0], 8
        if size < hdr or p + size > f + fsize or styp not in SECT_TYPES:
            return
        yield p, styp, size
        p += ((size + 3) // 4) * 4


def _lzma(data: bytes) -> bytes:
    """LZMA with the 13-byte header (properties byte, dictionary size, unpacked size), which is
    what an EFI compression section of type 2 holds after its own 4-byte size field."""
    props = data[0]
    lc, rest = props % 9, props // 9
    lp, pb = rest % 5, rest // 5
    dict_size = max(struct.unpack_from("<I", data, 1)[0], 1 << 12)
    size = struct.unpack_from("<Q", data, 5)[0]
    dec = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}],
    )
    return dec.decompress(data[13:], max_length=size if size < 1 << 30 else -1)


def _unpacked(d: bytes, p: int, size: int) -> bytes | None:
    """The bytes of a compression section, or None."""
    try:
        ctype = d[p + 8]
    except IndexError:
        return None
    payload = d[p + 9 : p + size]
    if ctype == 0:  # stored
        return payload
    for skip in (0, 4):  # (AMI puts the LZMA header first, Intel's own EFI a 4-byte size)
        if payload[skip : skip + 1] == b"]":
            try:
                return _lzma(payload[skip:])
            except (lzma.LZMAError, ValueError, IndexError, struct.error, EOFError):
                return None
    return None


# --- the image --------------------------------------------------------------------------------


def _whole_image(d: bytes, lo: int, hi: int, depth: int = 0) -> bytes | None:
    """The bytes of a compression section that holds a whole firmware image, or None. On the EFI
    1.10 ("Framework") boards the .BIO keeps the volumes in the clear *and* one LZMA section with
    the complete image; only the latter carries the setup's strings, so it is preferred."""
    for v in _volumes(d, lo, hi):
        if depth >= 4:
            continue
        for f, _ftype, fsize in _files(d, v):
            for p, styp, size in _sections(d, f, fsize):
                if styp == SEC_COMP:
                    inner = _unpacked(d, p, size)
                    if inner and len(inner) >= 0x10000 and _volumes(inner):
                        return _whole_image(inner, 0, len(inner), depth + 1) or inner
                elif styp == SEC_GUID:
                    off = struct.unpack_from("<H", d, p + 20)[0]
                    if p + off < p + size:
                        got = _whole_image(d, p + off, p + size, depth + 1)
                        if got is not None:
                            return got
                        # nothing packed inside: the payload itself is the image, either straight
                        # away or behind the 4-byte size field Intel puts at DataOffset
                        for q in (p + off, p + off + 4):
                            hv = _fvhdr(d, q)
                            if hv:
                                return d[q : q + hv[0]]
                elif styp == SEC_FVIMG:  # a volume inside a file: look inside it too
                    got = _whole_image(d, p + 4, p + size, depth + 1)
                    if got is not None:
                        return got
    return None


def image(data: bytes) -> bytes:
    """The UEFI firmware image inside an Intel EFI firmware update."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 0x300:
        raise ValueError("not an Intel EFI firmware update: too short")
    data = bytes(data)
    bio = _find_bio(data)
    vols = _volumes(bio)
    if not vols:
        raise ValueError("not an Intel EFI firmware update: no firmware volume in the .BIO")
    got = _whole_image(bio, vols[0], len(bio))
    if got is not None:
        return got
    best = max(((_known_volume(bio, v)[0], v) for v in _volumes(bio)), default=None)
    if best is None or best[0] < 0x1000:
        raise ValueError("no firmware image found in the .BIO")
    return bio[best[1] : best[1] + best[0]]
