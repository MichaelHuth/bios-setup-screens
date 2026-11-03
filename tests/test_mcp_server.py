"""The MCP server as a client sees it: stdio JSON-RPC, its tools, the folder it is limited to
and setup screens as a job."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from builders import AmiModule, ami_image

SERVER = Path(__file__).resolve().parent.parent / "mcp_server.py"


class Client:
    def __init__(self, folder: Path):
        env = dict(os.environ, MCP_WORK_DIR=str(folder))
        self.proc = subprocess.Popen(
            [sys.executable, "-I", str(SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", env=env,
        )  # fmt: skip
        self.ids = iter(range(1, 10_000))

    def call(self, method: str, params: dict | None = None, notify: bool = False) -> dict:
        message: dict = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            message["id"] = next(self.ids)
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        if notify:
            return {}
        while True:
            answer = json.loads(self.proc.stdout.readline())
            if answer.get("id") == message["id"]:
                return answer

    def tool(self, tool_name: str, **args: object) -> dict:
        return self.call("tools/call", {"name": tool_name, "arguments": args})["result"]

    def close(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        self.proc.wait(timeout=30)


@pytest.fixture
def client(tmp_path: Path):
    (tmp_path / "bios.rom").write_bytes(ami_image([AmiModule(0x04, b"setup client " * 200)]))
    c = Client(tmp_path)
    init = c.call(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "bios-tools"
    c.call("notifications/initialized", notify=True)
    yield c
    c.close()


def test_tools_are_listed(client: Client) -> None:
    names = {t["name"] for t in client.call("tools/list")["result"]["tools"]}
    assert {
        "bios_summary",
        "unpack_rom",
        "start_setup_screens",
        "job_result",
        "view_image",
    } <= names


def test_files_and_summary(client: Client) -> None:
    assert "bios.rom" in client.tool("list_files")["content"][0]["text"]
    summary = client.tool("bios_summary", name="bios.rom")
    assert not summary["isError"] and "bios.rom" in summary["content"][0]["text"]


def test_no_way_out_of_the_folder(client: Client) -> None:
    assert client.tool("read_file", name="../../secret.txt")["isError"]


def test_setup_screens_run_as_a_job(client: Client) -> None:
    started = client.tool("start_setup_screens", name="bios.rom")["content"][0]["text"]
    job = started.split()[1]
    deadline = time.time() + 300
    while time.time() < deadline:
        result = client.tool("job_result", job=job)
        if "still running" not in result["content"][0]["text"]:
            break
        time.sleep(1)
    assert "still running" not in result["content"][0]["text"]  # (done; this image has no setup)


def test_an_image_is_returned_as_an_image(client: Client, tmp_path: Path) -> None:
    from PIL import Image  # pylint: disable=import-outside-toplevel

    Image.new("RGB", (64, 32), "blue").save(tmp_path / "page.png")
    blocks = client.tool("view_image", name="page.png")["content"]
    assert any(b["type"] == "image" and b["mimeType"].startswith("image/") for b in blocks)


def test_the_bots_drawing_tool_is_not_offered(client: Client) -> None:
    assert "error" in client.call(
        "tools/call", {"name": "render_text_screen", "arguments": {"lines": ["x"]}}
    )


def test_unknown_tool_is_an_error(client: Client) -> None:
    assert "error" in client.call("tools/call", {"name": "nope", "arguments": {}})
