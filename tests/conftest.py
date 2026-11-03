"""Shared setup: the bot's modules on the path, a scratch work folder per test, and markers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="job objects and integrity levels are Windows features"
)


@pytest.fixture
def work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty work folder for the bot's file tools (also for tool processes started from the
    test, which read WORK_DIR from the environment)."""
    import workspace  # pylint: disable=import-outside-toplevel

    folder = tmp_path / "work"
    folder.mkdir()
    monkeypatch.setattr(workspace, "WORK_DIR", folder)
    monkeypatch.setenv("WORK_DIR", str(folder))
    return folder


@pytest.fixture
def as_user(monkeypatch: pytest.MonkeyPatch):
    """Run the file tools as a given Discord user: as_user(id)."""
    import workspace  # pylint: disable=import-outside-toplevel

    def use(user_id: int | None) -> None:
        workspace.current_user.set(user_id)

    return use
