"""
The local corpus check: real BIOS files (not in the repository) rebuilt one per process and
compared with tests/corpus_manifest.json, which holds each file's SHA-256 and a fingerprint of
its result: the route, the number of pages and a hash of the page texts (clock times, dates and
the CPU speed values the emulator measures with the host's clock left out).

    python tests/corpus.py --make FOLDER_OR_@LIST [WORKERS]   write the manifest
    python tests/corpus.py --one FILE                         one file's fingerprint (JSON)

tests/test_corpus.py runs the comparison when BIOS_CORPUS names a folder.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MANIFEST = HERE / "corpus_manifest.json"
SKIP = (".png", ".jpg", ".json", ".py", ".txt", ".md", ".log", ".tsv")
CLOCK = re.compile(r"\d\d:\d\d:\d\d|\d\d/\d\d/\d{2,4}")
MEASURED = re.compile(r"(?i)mhz|ratio|speed")  # (lines with values timed by the host's clock)
FILE_SECONDS = 1200


def files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and not p.name.lower().endswith(SKIP))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(result: dict) -> dict:
    texts = {
        title: "\n".join(
            line for line in CLOCK.sub("", text).split("\n") if not MEASURED.search(line)
        )
        for title, text in result["screens"].items()
    }
    digest = hashlib.sha1(json.dumps(texts, sort_keys=True).encode("utf-8")).hexdigest()
    return {"bios": result["bios"][:60], "screens": len(result["screens"]), "text": digest[:16]}


def _one(path: Path) -> dict:
    """In a fresh process: the file's setup screens, rebuilt from a copy in a temporary folder
    (the pages are written next to it), as a fingerprint."""
    sys.path.insert(0, str(ROOT))
    # pylint: disable=import-outside-toplevel
    import screen_tools
    import workspace

    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / path.name
        shutil.copyfile(path, copy)
        workspace._resolve = lambda channel_id, name: copy.parent / name
        workspace.attach = lambda p: None
        try:
            result = screen_tools._bios_setup_screens(0, copy.name, "all", "setup", 0)
        except ValueError:
            return {"result": "unsupported"}
        except Exception as e:  # pylint: disable=broad-exception-caught
            return {"result": "crash", "error": type(e).__name__}
        return fingerprint(result)


def run(path: Path) -> dict:
    """One file's fingerprint, from a process of its own."""
    try:
        done = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--one", str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=FILE_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"result": "timeout"}
    lines = done.stdout.strip().splitlines()
    try:
        return json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        return {"result": "crash", "error": f"exit code {done.returncode}"}


def run_all(paths: list[Path], workers: int) -> dict[Path, dict]:
    with ThreadPoolExecutor(workers) as pool:
        return dict(zip(paths, pool.map(run, paths)))


def make(source: str, workers: int) -> None:
    if source.startswith("@"):
        paths = [Path(p) for p in Path(source[1:]).read_text(encoding="utf-8").split("\n") if p]
    else:
        paths = files(Path(source))
    manifest: dict[str, dict] = {}
    for path, result in run_all(paths, workers).items():
        manifest.setdefault(sha256(path), {"name": path.name, **result})
    MANIFEST.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    supported = sum("screens" in r for r in manifest.values())
    print(f"{len(manifest)} files, {supported} with setup screens: {MANIFEST}")


if __name__ == "__main__":
    for stream in (sys.stdout,):
        stream.reconfigure(encoding="utf-8")
    if sys.argv[1:2] == ["--one"]:
        print(json.dumps(_one(Path(sys.argv[2]))))
    elif sys.argv[1:2] == ["--make"]:
        make(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count() or 8)
    else:
        sys.exit(__doc__)
