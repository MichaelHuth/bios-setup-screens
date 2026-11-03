"""The per-question tool process (isolation.py): results and errors as in the bot, time and
memory limits, and on Windows the low integrity level that keeps its writes in the work
folder."""

from __future__ import annotations

import asyncio
import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

import pytest

import binary_tools
import isolation
import screen_tools
import workspace
from builders import AmiModule, ami_image
from conftest import windows_only

CH, USER = 1, 2


@pytest.fixture
def folder(work: Path) -> Path:
    path = work / str(CH) / str(USER)
    path.mkdir(parents=True)
    (path / "bios.rom").write_bytes(ami_image([AmiModule(0x04, b"setup client " * 200)]))
    return path


def call(worker: isolation.Worker, name: str, args: dict) -> dict:
    return asyncio.run(worker.call(name, args))


def test_tool_results_images_and_errors(folder: Path) -> None:
    async def go() -> list[dict]:
        w = isolation.Worker(CH, USER)
        try:
            return [
                await w.call(
                    "render_text_screen", {"lines": ["Hello", "BIOS"], "file_name": "s.png"}
                ),
                await w.call("read_file", {"name": "nothere.txt"}),
                await w.call("list_files", {}),
                await w.call("bios_summary", {"name": "bios.rom"}),
            ]
        finally:
            await w.close()

    image, missing, listing, summary = asyncio.run(go())
    assert [Path(p) for p in image["files"]] == [folder / "s.png"] and (folder / "s.png").is_file()
    assert missing["error"].startswith("FileNotFoundError:")
    assert "bios.rom" in str(listing["result"])
    assert "result" in summary and summary["result"]["name"] == "bios.rom"


def test_another_users_file_is_not_reachable(folder: Path) -> None:
    async def go() -> dict:
        w = isolation.Worker(CH, USER + 1)
        try:
            return await w.call("bios_summary", {"name": "bios.rom"})
        finally:
            await w.close()

    assert "error" in asyncio.run(go())


def test_a_slow_call_is_stopped_and_the_next_gets_a_fresh_process(
    folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (folder / "big.txt").write_bytes(b"printable text, " * (3 << 20))

    async def go() -> tuple[dict, dict, int, int]:
        w = isolation.Worker(CH, USER)
        try:
            await w.call("list_files", {})
            assert w.proc is not None
            first = w.proc.pid
            monkeypatch.setattr(isolation, "CALL_SECONDS", 0.05)
            slow = await w.call("strings", {"name": "big.txt"})
            monkeypatch.setattr(isolation, "CALL_SECONDS", 600)
            after = await w.call("list_files", {})
            assert w.proc is not None
            return slow, after, first, w.proc.pid
        finally:
            await w.close()
            assert w.proc is None

    slow, after, first, second = asyncio.run(go())
    assert "took longer" in slow["error"]
    assert "result" in after and first != second


def test_run_tool_merges_what_the_process_made(folder: Path) -> None:
    import bot  # pylint: disable=import-outside-toplevel

    async def go() -> tuple:
        w = isolation.Worker(CH, USER)
        token = isolation.current.set(w)
        files = workspace.pending_files.set([])
        bundle, notes = workspace.pending_bundle.set([]), workspace.pending_notes.set([])
        try:
            text = await bot.run_tool(
                CH, "render_text_screen", {"lines": ["x"], "file_name": "m.png"}
            )
            made = list(workspace.pending_files.get())
            with pytest.raises(isolation.ToolFailed, match="^FileNotFoundError"):
                await bot.run_tool(CH, "read_file", {"name": "nothere.txt"})
            return text, made
        finally:
            workspace.pending_files.reset(files)
            workspace.pending_bundle.reset(bundle)
            workspace.pending_notes.reset(notes)
            isolation.current.reset(token)
            await w.close()

    text, made = asyncio.run(go())
    assert made == [folder / "m.png"] and isinstance(text, str)


# --- Windows: the job and the integrity level -------------------------------------------------


def _integrity(pid: int) -> str:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    process = k32.OpenProcess(0x1000, False, pid)  # (PROCESS_QUERY_LIMITED_INFORMATION)
    token, buf, size = wintypes.HANDLE(), ctypes.create_string_buffer(64), wintypes.DWORD()
    adv.OpenProcessToken(wintypes.HANDLE(process), 0x0008, ctypes.byref(token))
    adv.GetTokenInformation(token, 25, buf, 64, ctypes.byref(size))
    text = ctypes.c_wchar_p()
    adv.ConvertSidToStringSidW(
        ctypes.c_void_p(ctypes.c_void_p.from_buffer(buf).value), ctypes.byref(text)
    )
    k32.CloseHandle(token)
    in_job = wintypes.BOOL()
    k32.IsProcessInJob(wintypes.HANDLE(process), None, ctypes.byref(in_job))
    k32.CloseHandle(wintypes.HANDLE(process))
    return f"{text.value} {'in job' if in_job else 'not in job'}"


@windows_only
def test_the_job_refuses_more_memory_than_its_limit() -> None:
    p = subprocess.Popen(
        [sys.executable, "-I", "-c", "import sys; sys.stdin.read(); x = bytearray(6 << 30); print('allocated')"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    isolation._job_limits(p.pid)
    try:
        out, err = p.communicate("go", timeout=120)
    finally:
        isolation._close_job(p.pid)
    assert "allocated" not in out and "MemoryError" in err


@windows_only
def test_the_process_runs_at_low_integrity_inside_the_job(folder: Path) -> None:
    async def go() -> dict:
        w = isolation.Worker(CH, USER)
        try:
            return await w.call("list_files", {})
        finally:
            await w.close()

    answer = asyncio.run(go())
    assert _integrity(answer["pid"]) == f"{isolation.LOW_INTEGRITY} in job"


@windows_only
def test_low_integrity_writes_only_in_the_work_folder(work: Path, tmp_path: Path) -> None:
    isolation._label_work_dir(work.resolve())
    probe = (
        "import sys; sys.path.insert(0, sys.argv[1]); import isolation; isolation._lower_integrity()\n"
        "for target in sys.argv[2:]:\n"
        "    try:\n"
        "        open(target, 'w').write('x'); print('WROTE', target)\n"
        "    except OSError:\n"
        "        print('REFUSED', target)\n"
    )
    name = f"low-probe-{os.getpid()}.txt"
    outside = [tmp_path / name, Path.home() / name, Path(os.environ["TEMP"]) / name]
    inside = work / name
    root = Path(isolation.__file__).parent
    out = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(root), *map(str, outside), str(inside)],
        capture_output=True, text=True, timeout=60, check=True,
    ).stdout  # fmt: skip
    for path in outside:
        assert f"REFUSED {path}" in out and not path.exists()
    assert f"WROTE {inside}" in out


@windows_only
@pytest.mark.skipif(screen_tools.SEVEN_ZIP is None, reason="7-Zip is not installed")
def test_seven_zip_works_at_low_integrity(folder: Path, as_user) -> None:
    subprocess.run(
        [screen_tools.SEVEN_ZIP, "a", "-bd", str(folder / "update.7z"), str(folder / "bios.rom")],
        capture_output=True, check=True, timeout=60,
    )  # fmt: skip

    async def go() -> dict:
        w = isolation.Worker(CH, USER)
        try:
            return await w.call("bios_summary", {"name": "update.7z"})
        finally:
            await w.close()

    low = asyncio.run(go())
    as_user(USER)
    direct = asyncio.run(binary_tools.run(CH, "bios_summary", {"name": "update.7z"}))
    assert low["result"] == direct
    assert not any((folder.parent.parent / isolation.TEMP_FOLDER).iterdir())
