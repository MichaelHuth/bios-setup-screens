"""Unpacking limits: a small upload must not unpack into gigabytes."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

import screen_tools as st


@pytest.fixture(scope="module")
def bomb() -> bytes:
    """A ZIP of about 300 KB whose member unpacks to 300 MB of zeros."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        z.writestr("big.bin", bytes(300 << 20))
    return buf.getvalue()


def test_zip_bomb_refused(bomb: bytes) -> None:
    with pytest.raises(ValueError, match="unpacks to more"):
        st._unzipped(bomb)


def test_zip_bomb_inside_a_zip_refused(bomb: bytes) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("bomb.zip", bomb)
        z.writestr("readme.txt", "x")
    with pytest.raises(ValueError):
        st._unzipped(buf.getvalue())


@pytest.mark.skipif(st.SEVEN_ZIP is None, reason="7-Zip is not installed")
def test_seven_zip_output_is_capped(bomb: bytes, tmp_path: Path) -> None:
    import subprocess  # pylint: disable=import-outside-toplevel

    archive = tmp_path / "big.zip"
    archive.write_bytes(bomb)
    with pytest.raises(subprocess.SubprocessError):
        st._seven_zip_output([st.SEVEN_ZIP, "e", "-so", "-p-", str(archive), "big.bin"], 120)
    small = tmp_path / "small.zip"
    with zipfile.ZipFile(small, "w") as z:
        z.writestr("a.bin", b"abc")
    assert (
        st._seven_zip_output([st.SEVEN_ZIP, "e", "-so", "-p-", str(small), "a.bin"], 60) == b"abc"
    )
