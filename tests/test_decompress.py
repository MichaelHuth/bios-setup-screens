"""The decompressors against known input: LH5 (Award and AMI modules), EFI/Tiano (UEFI
volumes), Okumura LZSS (Phoenix type 3), and the output caps that stop a small file from
unpacking into too much."""

from __future__ import annotations

import os
import random

import pytest

import lzh
import phoenix
import tiano
from encoders import efi_compress, lh5_stream, lzss

SAMPLES = {
    "empty-ish": b"x",
    "text": b"Award Modular BIOS v4.51PG, An Energy Star Ally\r\n" * 40,
    "runs": b"\0" * 3000 + b"\xff" * 500 + b"AB" * 700,
    "table": bytes(range(256)) * 12,
    "random": random.Random(7).randbytes(5000),
    "mixed": random.Random(8).randbytes(700) + b"setup" * 300 + bytes(900),
}


@pytest.mark.parametrize("name", SAMPLES)
def test_lh5_gives_the_input_back(name: str) -> None:
    data = SAMPLES[name]
    assert lzh.decompress(lh5_stream(data), len(data), b"-lh5-") == data


def test_lh5_several_blocks() -> None:
    data = random.Random(1).randbytes(3000) + b"Q" * 4000
    stream = lh5_stream(data, block=100)  # (many short blocks, each with its own tables)
    assert lzh.decompress(stream, len(data), b"-lh5-") == data


def test_lh5_partial_keeps_the_blocks_before_a_broken_one() -> None:
    data = bytes(range(256)) * 30
    stream = lh5_stream(data, bad_block=True)
    with pytest.raises(ValueError, match="Huffman"):
        lzh.decompress(stream, len(data) + 10, b"-lh5-")
    assert lzh.decompress(stream, len(data) + 10, b"-lh5-", partial=True) == data


def test_lh0_is_stored() -> None:
    assert lzh.decompress(b"plain bytes", 5, b"-lh0-") == b"plain"


def test_lh5_output_cap() -> None:
    with pytest.raises(ValueError, match="LHA member"):
        lzh.decompress(lh5_stream(b"x"), lzh.MAX_OUT + 1, b"-lh5-")


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("name", SAMPLES)
def test_efi_and_tiano(version: int, name: str) -> None:
    data = SAMPLES[name]
    packed = efi_compress(data, version)
    assert tiano.decompress(packed, version) == data
    assert tiano.decompress(packed) == data  # (version 0: both tried)


def test_tiano_bad_header() -> None:
    with pytest.raises(ValueError):
        tiano.decompress(b"\x10\0\0\0\x10\0\0\0abc")  # (says 16 packed bytes, has 3)
    with pytest.raises(ValueError):
        tiano.decompress(b"\x01\0\0\0" + (100 << 20).to_bytes(4, "little") + b"\0")


@pytest.mark.parametrize("name", ["text", "runs", "mixed"])
def test_lzss_gives_the_input_back(name: str) -> None:
    data = SAMPLES[name][:2500]
    assert phoenix.lzss_decode(lzss(data)) == data


def test_lzss_match_cut_off() -> None:
    packed = lzss(b"abcabcabcabcabc")
    with pytest.raises(ValueError):
        phoenix.lzss_decode(packed[:-1])


def test_random_bytes_do_not_hang_the_lh5_decoder() -> None:
    noise = os.urandom(2000)
    try:
        lzh.decompress(noise, 10_000, b"-lh5-")
    except (ValueError, IndexError):
        pass
