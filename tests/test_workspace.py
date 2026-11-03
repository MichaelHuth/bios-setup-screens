"""The work folder: one folder per user and channel, file names that stay inside it, and the
age and size limits."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

import workspace as ws

CH, A, B = 999, 111, 222


@pytest.fixture
def two_users(work: Path, as_user) -> None:
    for user, text in ((A, "from a"), (B, "from b")):
        folder = ws.channel_dir(CH, user)
        folder.mkdir(parents=True)
        (folder / "same.txt").write_text(text)
    (ws.channel_dir(CH, A) / "only_a.txt").write_text("secret")


def test_users_see_only_their_own_files(two_users, as_user) -> None:
    as_user(B)
    assert "only_a" not in ws._list_files(CH)
    assert ws._read_file(CH, "same.txt", 0, "")["content"] == "from b"
    as_user(A)
    assert "only_a" in ws._list_files(CH)


@pytest.mark.parametrize(
    "name",
    ["only_a.txt", f"../{A}/only_a.txt", f"..\\{A}\\only_a.txt", "../../x", "C:only_a.txt"],
)
def test_another_users_file_is_not_reached(two_users, as_user, name: str) -> None:
    as_user(B)
    with pytest.raises(FileNotFoundError):
        ws._read_file(CH, name, 0, "")


def test_an_absolute_path_is_not_reached(two_users, as_user) -> None:
    as_user(B)
    with pytest.raises(FileNotFoundError):
        ws._read_file(CH, str(ws.channel_dir(CH, A) / "only_a.txt"), 0, "")


def test_reset_clears_only_the_users_own_files(two_users) -> None:
    ws.clear(CH, B)
    assert (ws.channel_dir(CH, A) / "only_a.txt").exists()
    assert not ws.channel_dir(CH, B).exists()
    assert ws.saved_path(CH, "x.bin", A) == ws.channel_dir(CH, A) / "x.bin"


@pytest.mark.parametrize(
    "name, safe",
    [
        ("CON", "_CON"),
        ("nul.txt", "_nul.txt"),
        ("com1.bin", "_com1.bin"),
        ("LPT9", "_LPT9"),
        ("console.bin", "console.bin"),
        ("../../evil.exe", "evil.exe"),
        ("a:b.txt", "b.txt"),
    ],
)
def test_safe_names(name: str, safe: str) -> None:
    assert ws._safe_name(name) == safe


def test_age_and_size_limits(work: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ws, "USER_MAX_BYTES", 1000)
    monkeypatch.setattr(ws, "WORK_MAX_BYTES", 2500)
    mine, other = ws.channel_dir(1, 11), ws.channel_dir(1, 22)
    mine.mkdir(parents=True)
    other.mkdir(parents=True)
    loose = work / "keep.rom"
    loose.write_bytes(b"x" * 5000)
    now = time.time()

    def put(folder: Path, name: str, size: int, age: float) -> Path:
        path = folder / name
        path.write_bytes(b"x" * size)
        os.utime(path, (now - age, now - age))
        return path

    old = put(mine, "old.bin", 10, 40 * 86400)
    a = put(mine, "a.bin", 400, 300)
    b = put(mine, "b.bin", 400, 200)
    c = put(other, "c.bin", 900, 100)
    ws._make_room(mine, 500)
    assert not old.exists(), "expired file stays"
    assert not a.exists() and b.exists(), "not the oldest own file first"
    assert c.exists() and loose.exists(), "other files touched"
    monkeypatch.setattr(ws, "USER_MAX_BYTES", 100000)
    ws._make_room(mine, 2000)
    assert not b.exists() and not c.exists() and loose.exists(), "the whole limit"
