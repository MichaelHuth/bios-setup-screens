"""
The bot's BIOS and file tools as an MCP server over stdio (JSON-RPC 2.0, one message per line), for
other clients than Discord. Files are read from and written to one folder, MCP_WORK_DIR (default:
mcp-work next to this file); put the files to analyse there. Each tool call runs in a fresh
process of its own with a time limit, so a file that crashes or hangs a parser cannot take the
server down. Rebuilding setup screens can take minutes: start_setup_screens starts it as a job,
job_result fetches the result when it is done.

Usage (in a client's configuration): python mcp_server.py
"""

from __future__ import annotations

import asyncio

import contextlib
import io
import itertools
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
FOLDER = Path(os.getenv("MCP_WORK_DIR", HERE / "mcp-work")).resolve()
CALL_SECONDS = int(os.getenv("MCP_CALL_SECONDS", "600"))
MAX_JOBS = int(os.getenv("MCP_MAX_JOBS", "2"))
PROTOCOL = "2025-06-18"
ONE_PAGE_TOOLS = ("render_text_screen",)  # (the bot's own drawing tool: not useful here)

JOB_TOOLS = [
    {
        "name": "start_setup_screens",
        "description": "Start rebuilding the BIOS setup screens of a file in the folder as a job "
        "(the same as bios_setup_screens, which can take several minutes). Returns a job id; "
        "fetch the result with job_result.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "File name in the folder."},
                "pages": {"type": "string", "description": 'Pages to render (default "all").'},
            },
            "required": ["name"],
        },
    },
    {
        "name": "job_result",
        "description": "The state of a job: running, or its result (the setup pages' texts and "
        "the image files written to the folder; view them with view_image).",
        "inputSchema": {
            "type": "object",
            "properties": {"job": {"type": "string", "description": "The job id."}},
            "required": ["job"],
        },
    },
]


def _worker(name: str, args: dict) -> dict:
    """In the child process: run one tool on the folder, return its result and the files made."""
    sys.path.insert(0, str(HERE))
    # pylint: disable=import-outside-toplevel
    import binary_tools
    import screen_tools
    import workspace

    def folder(channel_id: int, user_id: int | None = None) -> Path:  # (one folder for all)
        del channel_id, user_id
        return FOLDER

    workspace.channel_dir = folder
    made = workspace.pending_files.set([])
    workspace.pending_bundle.set([])
    for module in (workspace, binary_tools, screen_tools):
        if name in module.TOOL_NAMES:
            with contextlib.redirect_stdout(io.StringIO()):  # (stdout is for the result)
                result = asyncio.run(module.run(0, name, args))
            files = [str(Path(p).name) for p in dict.fromkeys(workspace.pending_files.get())]
            workspace.pending_files.reset(made)
            return {"result": result, "files": files}
    raise ValueError(f"unknown tool: {name}")


def _run_tool(name: str, args: dict) -> dict:
    """A tool call in a fresh process; its result, or an error."""
    try:
        done = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--call", name],
            input=json.dumps(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=CALL_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"the call took longer than {CALL_SECONDS} s and was stopped"}
    try:
        return json.loads(done.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"error": f"the call ended without a result (exit code {done.returncode})"}


def _content(answer: dict) -> tuple[list[dict], bool]:
    """MCP content blocks from a tool's answer."""
    if "error" in answer:
        return [{"type": "text", "text": answer["error"]}], True
    result, blocks = answer["result"], []
    for item in result if isinstance(result, list) else [result]:
        if isinstance(item, dict) and item.get("type") == "image":
            source = item["source"]
            blocks.append(
                {"type": "image", "data": source["data"], "mimeType": source["media_type"]}
            )
        elif isinstance(item, dict) and item.get("type") == "text":
            blocks.append({"type": "text", "text": item["text"]})
        else:
            text = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
            blocks.append({"type": "text", "text": text})
    if answer.get("files"):
        blocks.append({"type": "text", "text": "Files written: " + ", ".join(answer["files"])})
    return blocks, False


class Jobs:
    def __init__(self) -> None:
        self.results: dict[str, dict | None] = {}
        self.slots = threading.Semaphore(MAX_JOBS)
        self.ids = itertools.count(1)

    def start(self, args: dict) -> str:
        job = str(next(self.ids))
        self.results[job] = None

        def work() -> None:
            with self.slots:
                self.results[job] = _run_tool("bios_setup_screens", args)

        threading.Thread(target=work, daemon=True).start()
        return job

    def result(self, job: str) -> dict:
        if job not in self.results:
            return {"error": f"no job {job}"}
        answer = self.results[job]
        return (
            answer if answer is not None else {"result": f"job {job} is still running", "files": []}
        )


def _tool_list() -> list[dict]:
    sys.path.insert(0, str(HERE))
    # pylint: disable=import-outside-toplevel
    import binary_tools
    import screen_tools
    import workspace

    tools = [
        {"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]}
        for t in workspace.TOOLS + binary_tools.TOOLS + screen_tools.TOOLS
        if t["name"] not in ONE_PAGE_TOOLS
    ]
    return tools + JOB_TOOLS


def serve() -> None:
    FOLDER.mkdir(parents=True, exist_ok=True)
    tools, jobs = _tool_list(), Jobs()
    names = {t["name"] for t in tools}
    lock = threading.Lock()

    def send(message: dict) -> None:
        with lock:
            sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def handle(request: dict) -> None:
        method, ident, params = (
            request.get("method"),
            request.get("id"),
            request.get("params") or {},
        )
        if ident is None:  # a notification (initialized, cancelled): nothing to answer
            return
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": params.get("protocolVersion", PROTOCOL),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "bios-tools", "version": "1.0"},
                "instructions": f"Files are read from and written to {FOLDER}.",
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            if name not in names:
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": ident,
                        "error": {"code": -32602, "message": f"unknown tool {name}"},
                    }
                )
                return
            if name == "start_setup_screens":
                answer = {"result": f"job {jobs.start(args)} started", "files": []}
            elif name == "job_result":
                answer = jobs.result(str(args.get("job", "")))
            else:
                answer = _run_tool(str(name), args)
            content, is_error = _content(answer)
            result = {"content": content, "isError": is_error}
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": ident,
                    "error": {"code": -32601, "message": f"no method {method}"},
                }
            )
            return
        send({"jsonrpc": "2.0", "id": ident, "result": result})

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            send(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            )
            continue
        # (tool calls run in threads, so a long one does not hold up the others)
        threading.Thread(target=handle, args=(request,), daemon=True).start()


def main() -> None:
    for stream in (sys.stdin, sys.stdout):  # (MCP is UTF-8; Windows' console default is not)
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    if len(sys.argv) == 3 and sys.argv[1] == "--call":
        try:
            answer = _worker(sys.argv[2], json.loads(sys.stdin.read() or "{}"))
        except Exception as e:  # pylint: disable=broad-exception-caught
            answer = {"error": f"{type(e).__name__}: {e}"}
        sys.stdout.write(json.dumps(answer, ensure_ascii=False, default=str) + "\n")
        return
    serve()


if __name__ == "__main__":
    main()
