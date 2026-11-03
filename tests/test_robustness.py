"""Damaged and random input: the readers may fail only with ValueError (their "cannot read
this"), within the time and size caps, and the tools write nothing outside the user's folder.
Hypothesis varies the input: random bytes, and the tests' own images with bytes changed."""

from __future__ import annotations

import asyncio
import random
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as hs

import ami
import award_setup
import binary_tools
import lzh
import phoenix
import phx4
import screen_tools
import tiano
from builders import (
    AmiModule,
    FfvFile,
    PhoenixModule,
    ami_image,
    ffv_image,
    lha_module,
    phoenix_image,
)
from encoders import efi_compress, lh5_stream, lzss

SETTINGS = settings(
    max_examples=150, deadline=5000, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
IMAGES = {
    "ami": ami_image(
        [
            AmiModule(0x00, b"post " * 300),
            AmiModule(0x04, b"setup " * 200),
            AmiModule(0x19, bytes(600), False),
        ]
    ),
    "phoenix": phoenix_image(
        [
            PhoenixModule("B", b"code " * 100, comp=0),
            PhoenixModule("T", b"tmpl " * 100, comp=3),
            PhoenixModule("E", b"setup " * 200),
        ]
    ),
    "ffv": ffv_image(
        [FfvFile("_E00", b"setup " * 100), FfvFile("_S00", b"STRPACK" * 40, compressed=True)]
    ),
    "award": b"\xff" * 0x100 + lha_module(b"awardext.rom", b"ext " * 400) + b"\xff" * 0x100,
}


def mutated(image: bytes) -> hs.SearchStrategy[bytes]:
    """The image with a few bytes changed (headers and pointers among them)."""
    changes = hs.lists(
        hs.tuples(hs.integers(0, len(image) - 1), hs.integers(0, 255)), min_size=1, max_size=12
    )

    def apply(cs: list[tuple[int, int]]) -> bytes:
        out = bytearray(image)
        for at, value in cs:
            out[at] = value
        return bytes(out)

    return changes.map(apply)


def only_value_error(fn, *args) -> None:
    try:
        fn(*args)
    except ValueError:
        pass


# --- decompressors --------------------------------------------------------------------------


@SETTINGS
@given(hs.binary(max_size=3000), hs.integers(1, 20000))
def test_lh5_random(data: bytes, size: int) -> None:
    only_value_error(lzh.decompress, data, size, b"-lh5-")


@SETTINGS
@given(
    hs.binary(min_size=1, max_size=2000).flatmap(
        lambda d: mutated(lh5_stream(d)).map(lambda s: (d, s))
    )
)
def test_lh5_damaged(case: tuple[bytes, bytes]) -> None:
    data, stream = case
    only_value_error(lzh.decompress, stream, len(data), b"-lh5-")


@SETTINGS
@given(hs.binary(max_size=3000))
def test_tiano_random(data: bytes) -> None:
    only_value_error(tiano.decompress, data)


@SETTINGS
@given(hs.binary(min_size=1, max_size=2000).flatmap(lambda d: mutated(efi_compress(d, 2))))
def test_tiano_damaged(packed: bytes) -> None:
    only_value_error(tiano.decompress, packed)


@SETTINGS
@given(hs.binary(max_size=3000))
def test_lzss_random(data: bytes) -> None:
    only_value_error(phoenix.lzss_decode, data)


@SETTINGS
@given(hs.binary(max_size=3000), hs.integers(1, 20000))
def test_phx4_random(data: bytes, size: int) -> None:
    only_value_error(phx4.decode, data, size)


# --- readers --------------------------------------------------------------------------------


@SETTINGS
@given(mutated(IMAGES["ami"]))
def test_ami_damaged(image: bytes) -> None:
    only_value_error(ami.extract, image)


@SETTINGS
@given(mutated(IMAGES["phoenix"]))
def test_phoenix_damaged(image: bytes) -> None:
    only_value_error(phoenix.extract, image)


@SETTINGS
@given(mutated(IMAGES["ffv"]))
def test_trustedcore_damaged(image: bytes) -> None:
    only_value_error(phoenix.extract, image)


@SETTINGS
@given(mutated(IMAGES["award"]))
def test_award_labels_damaged(image: bytes) -> None:
    only_value_error(award_setup.extension_labels, image)


@SETTINGS
@given(hs.binary(max_size=4000))
def test_unpacking_random(data: bytes) -> None:
    only_value_error(screen_tools._unzipped, data)


# --- the tools: no writes outside the user's folder -----------------------------------------


@pytest.mark.parametrize("kind", sorted(IMAGES))
@pytest.mark.parametrize("tool", ["bios_summary", "rom_info", "unpack_rom", "strings"])
def test_tools_on_damaged_images_write_only_in_the_users_folder(
    work: Path, as_user, kind: str, tool: str
) -> None:
    folder = work / "1" / "2"
    folder.mkdir(parents=True)
    as_user(2)
    rng = random.Random(f"{kind}-{tool}")
    for k in range(8):
        image = bytearray(IMAGES[kind])
        for _ in range(rng.randint(1, 16)):
            image[rng.randrange(len(image))] = rng.randrange(256)
        (folder / f"f{k}.rom").write_bytes(bytes(image))
        try:
            asyncio.run(binary_tools.run(1, tool, {"name": f"f{k}.rom"}))
        except ValueError:
            pass
    outside = [p for p in work.rglob("*") if p.is_file() and folder not in p.parents]
    assert outside == []
