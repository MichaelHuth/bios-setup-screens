"""The corpus check (tests/corpus.py): runs only when BIOS_CORPUS names a folder of BIOS files.
Every file of the folder that is in the manifest (by SHA-256) is rebuilt in a process of its
own and must give the same result as when the manifest was made. Files that rebuild now and
did not then are reported, not failures. After an intended change, remake the manifest:
python tests/corpus.py --make FOLDER."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import corpus

ROOT = os.getenv("BIOS_CORPUS")
pytestmark = pytest.mark.skipif(not ROOT, reason="set BIOS_CORPUS to a folder of BIOS files")


def test_corpus_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    assert ROOT is not None
    manifest = json.loads(corpus.MANIFEST.read_text(encoding="utf-8"))
    known: dict[str, Path] = {}
    for path in corpus.files(Path(ROOT)):
        digest = corpus.sha256(path)
        if digest in manifest:
            known.setdefault(digest, path)
    assert known, "none of the manifest's files is in BIOS_CORPUS"
    workers = int(os.getenv("BIOS_CORPUS_WORKERS", str(os.cpu_count() or 8)))
    results = corpus.run_all(list(known.values()), workers)
    lost, changed, gained = [], [], []
    for digest, path in known.items():
        want, got = manifest[digest], results[path]
        want = {k: v for k, v in want.items() if k != "name"}
        if got == want:
            continue
        if "screens" in want and "screens" not in got:
            lost.append(f"{path.name}: {want['screens']} pages -> {got}")
        elif "screens" in got and "screens" not in want:
            gained.append(f"{path.name}: {got['screens']} pages")
        else:
            changed.append(f"{path.name}: {want} -> {got}")
    with capsys.disabled():
        print(f"\ncorpus: {len(known)} of {len(manifest)} manifest files found")
        for line in gained:
            print("gained:", line)
    assert not lost and not changed, "\n".join(["lost:"] + lost + ["changed:"] + changed)
