"""
Make model output fit Discord: Discord renders a subset of Markdown without tables, so
Markdown tables are turned into aligned columns in a code block (narrow tables) or a list (wide
tables), and long replies are split into messages without breaking code blocks.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

SEPARATOR = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
MAX_CODE_WIDTH = 60  # wider tables become lists (readable on phones)
LIMIT = 2000


def _cells(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells = re.split(r"(?<!\\)\|", line)
    # Markdown inside cells would show literally in a code block
    return [re.sub(r"(\*\*|__|`)", "", c).replace("\\|", "|").strip() for c in cells]


def _table(rows: list[list[str]]) -> list[str]:
    header = rows[0]
    cols = max(len(r) for r in rows)
    rows = [r + [""] * (cols - len(r)) for r in rows]
    widths = [max(len(r[i]) for r in rows) for i in range(cols)]
    if sum(widths) + 2 * (cols - 1) <= MAX_CODE_WIDTH:

        def fmt(r: list[str]) -> str:
            return "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()

        return ["```", fmt(rows[0]), "  ".join("-" * w for w in widths), *map(fmt, rows[1:]), "```"]
    out = []
    for r in rows[1:]:
        rest = [f"{h}: {v}" for h, v in zip(header[1:], r[1:]) if v]
        out.append(f"- **{r[0]}**" + (" — " + ", ".join(rest) if rest else ""))
    return out


def convert_tables(text: str) -> str:
    lines, out, i, fence = text.split("\n"), [], 0, False
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            fence = not fence
        if (
            not fence
            and line.strip().startswith("|")
            and i + 1 < len(lines)
            and SEPARATOR.match(lines[i + 1])
        ):
            rows = [_cells(line)]
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|"):
                rows.append(_cells(lines[j]))
                j += 1
            out += _table(rows)
            i = j
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def chunks(text: str, size: int = LIMIT) -> Iterator[str]:
    """Split text into Discord messages; a code block cut by a split is closed and reopened."""
    open_fence = None  # the opening line (e.g. "```asm") of a block that continues
    while text:
        prefix = open_fence + "\n" if open_fence else ""
        room = size - len(prefix) - 4  # space for a closing fence
        if len(prefix) + len(text) <= size:
            yield prefix + text
            return
        cut = text.rfind("\n", 0, room)
        if cut <= 0:
            cut = room
        part, text = text[:cut], text[cut:].lstrip("\n")
        fence = open_fence
        for line in part.split("\n"):
            if line.strip().startswith("```"):
                fence = None if fence else line.strip()
        yield prefix + part + ("\n```" if fence else "")
        open_fence = fence
