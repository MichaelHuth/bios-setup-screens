"""
The file, binary and screen tools in a process of their own, one per question: uploaded files
are parsed and their code emulated there, not in the bot. A crash, a hang or a memory blow-up
in a parser ends that process, not the bot; the next call starts a fresh one.

On Windows the process is put into a job object: at most MEMORY_LIMIT of memory, at most a few
processes (7-Zip is started from it), and it is killed with the job when the bot ends.

The worker reads one JSON request per line on stdin and answers one JSON line on stdout:
{"name", "args", "channel_id", "user_id"} -> {"result", "files", "bundle", "notes"} or
{"error"}. Usage (by the bot only): python -I isolation.py
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import ctypes
import io
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
CALL_SECONDS = int(os.getenv("TOOL_CALL_SECONDS", "900"))  # (an emulated setup takes minutes)
MEMORY_LIMIT = int(os.getenv("TOOL_MEMORY_MB", "4096")) << 20
MAX_PROCESSES = 8  # (the worker and the 7-Zip runs it starts)
DESCRIBE = "_describe"  # (not a model tool: a saved attachment's one-line description)


# --- in the bot ----------------------------------------------------------------------------


def _job_limits(pid: int) -> None:
    """Put the process into a job object with a memory and process limit that is killed
    when its last handle closes (the bot's, kept in _JOBS)."""
    if sys.platform != "win32":
        return

    class IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    # (limit flags: active processes, job memory, kill on job close, die on unhandled exception)
    basic = BasicLimits(LimitFlags=0x8 | 0x200 | 0x2000 | 0x400, ActiveProcessLimit=MAX_PROCESSES)
    limits = ExtendedLimits(BasicLimitInformation=basic, JobMemoryLimit=MEMORY_LIMIT)
    process = kernel32.OpenProcess(0x0101, False, pid)  # (PROCESS_SET_QUOTA | _TERMINATE)
    ok = (
        job
        and process
        and kernel32.SetInformationJobObject(
            wintypes.HANDLE(job), 9, ctypes.byref(limits), ctypes.sizeof(limits)
        )  # (JobObjectExtendedLimitInformation)
        and kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(process))
    )
    if process:
        kernel32.CloseHandle(wintypes.HANDLE(process))
    if not ok:
        error = ctypes.get_last_error()
        if job:
            kernel32.CloseHandle(wintypes.HANDLE(job))
        raise OSError(error, "the tool process could not be limited")
    _JOBS[pid] = job


_JOBS: dict[int, int] = {}


class ToolFailed(Exception):
    """A tool's error, already worded for the model ("ValueError: ...")."""


def _close_job(pid: int) -> None:
    if (job := _JOBS.pop(pid, None)) and sys.platform == "win32":
        ctypes.WinDLL("kernel32").CloseHandle(wintypes.HANDLE(job))


class Worker:
    """The tool process of one question. call() starts it when needed; close() ends it."""

    def __init__(self, channel_id: int, user_id: int | None):
        self.channel_id, self.user_id = channel_id, user_id
        self.proc: asyncio.subprocess.Process | None = None
        self.lock = asyncio.Lock()  # (the model may ask for several tools in one step)

    async def _start(self) -> asyncio.subprocess.Process:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            str(HERE / "isolation.py"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            limit=64 << 20,  # (one answer line can hold a page image)
            cwd=HERE,
        )
        try:
            _job_limits(proc.pid)
        except OSError:
            proc.kill()
            await proc.wait()
            raise
        return proc

    async def _stop(self) -> None:
        if self.proc is not None:
            if self.proc.returncode is None:
                self.proc.kill()
            await self.proc.wait()
            _close_job(self.proc.pid)
            self.proc = None

    async def call(self, name: str, args: dict) -> dict:
        """The tool's answer: {"result", "files", "bundle", "notes"} or {"error"}."""
        async with self.lock:
            if self.proc is None or self.proc.returncode is not None:
                await self._stop()
                self.proc = await self._start()
            assert self.proc.stdin is not None and self.proc.stdout is not None
            request: dict[str, Any] = {"name": name, "args": args}
            request |= {"channel_id": self.channel_id, "user_id": self.user_id}
            try:
                self.proc.stdin.write(json.dumps(request).encode() + b"\n")
                await self.proc.stdin.drain()
                line = await asyncio.wait_for(self.proc.stdout.readline(), CALL_SECONDS)
            except asyncio.TimeoutError:
                await self._stop()
                return {"error": f"the tool took longer than {CALL_SECONDS} s and was stopped"}
            except (BrokenPipeError, ConnectionResetError, ValueError):
                line = b""
            if not line:  # (the process died: out of memory, a crash in a native library)
                code = self.proc.returncode
                await self._stop()
                return {"error": f"the tool stopped unexpectedly (exit code {code})"}
            return json.loads(line)

    async def describe(self, path: Path) -> str:
        answer = await self.call(DESCRIBE, {"path": str(path)})
        return str(answer.get("result") or f"{path.name} (unreadable)")

    async def close(self) -> None:
        async with self.lock:
            await self._stop()


current: contextvars.ContextVar[Worker | None] = contextvars.ContextVar("worker", default=None)


async def run(name: str, args: dict) -> Any:
    """A tool call in the question's tool process; what it made (images, files for the
    ZIP, notes for the user) is added to the question's lists as if it had run here."""
    # pylint: disable=import-outside-toplevel
    import workspace

    worker = current.get()
    assert worker is not None
    answer = await worker.call(name, args)
    if "error" in answer:
        raise ToolFailed(answer["error"])
    workspace.pending_files.get().extend(Path(p) for p in answer["files"])
    workspace.pending_bundle.get().extend(Path(p) for p in answer["bundle"])
    workspace.pending_notes.get().extend(answer["notes"])
    return answer["result"]


# --- in the tool process -------------------------------------------------------------------


async def _serve() -> None:
    sys.path.insert(0, str(HERE))
    # pylint: disable=import-outside-toplevel
    import binary_tools
    import screen_tools
    import workspace

    out = sys.stdout
    sys.stdout = sys.stderr  # (stdout carries the answers: anything printed goes to the log)
    loop = asyncio.get_running_loop()
    while line := await loop.run_in_executor(None, sys.stdin.readline):
        request = json.loads(line)
        name, args = request["name"], request["args"]
        workspace.current_user.set(request["user_id"])
        files, bundle, notes = (workspace.pending_files.set([]), workspace.pending_bundle.set([]),
                                workspace.pending_notes.set([]))  # fmt: skip
        answer: dict[str, Any]
        try:
            if name == DESCRIBE:
                result: Any = await asyncio.to_thread(workspace._describe, Path(args["path"]))
            else:
                module = next(
                    m for m in (workspace, binary_tools, screen_tools) if name in m.TOOL_NAMES
                )
                result = await module.run(request["channel_id"], name, args)
            answer = {
                "result": result,
                "files": [str(p) for p in workspace.pending_files.get()],
                "bundle": [str(p) for p in workspace.pending_bundle.get()],
                "notes": list(workspace.pending_notes.get()),
            }
        except Exception as e:  # pylint: disable=broad-exception-caught
            answer = {"error": f"{type(e).__name__}: {e}", "raised": type(e).__name__}
        finally:
            workspace.pending_files.reset(files)
            workspace.pending_bundle.reset(bundle)
            workspace.pending_notes.reset(notes)
        out.write(json.dumps(answer, ensure_ascii=False, default=str) + "\n")
        out.flush()


def main() -> None:
    for stream in (sys.stdin, sys.stdout):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve())


if __name__ == "__main__":
    main()
