"""
Per-user working folder in each channel for attached files, plus tools the AI uses to read
them: no user reaches, overwrites or deletes another's files.

Attachments are saved to work/<channel id>/<user id>/ before the AI is asked. The AI then reads
them on demand: text in windows (like web_fetch), PDFs page by page (text layer, or the page
rendered as an image when it has none), and images as image blocks.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import io
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict

import discord
import pypdfium2 as pdfium
from PIL import Image

from web_tools import _find_windows

WORK_DIR = Path(os.getenv("WORK_DIR", Path(__file__).parent / "work"))
MAX_DOWNLOAD_BYTES = int(os.getenv("MAX_DOWNLOAD_BYTES", str(25 * 1024 * 1024)))
MAX_FILES = 10
TEXT_WINDOW_CHARS = 40000
IMAGE_MAX_SIDE = 1568  # longest side sent to the model; larger images are scaled down
PDF_MIN_TEXT_CHARS = 20  # a page with less text than this is treated as scanned
# Uploads are kept for a while and within limits: oldest files go first
FILE_MAX_DAYS = float(os.getenv("FILE_MAX_DAYS", "30"))
USER_MAX_BYTES = int(os.getenv("USER_MAX_BYTES", str(200 << 20)))
WORK_MAX_BYTES = int(os.getenv("WORK_MAX_BYTES", str(5 << 30)))
Image.MAX_IMAGE_PIXELS = 40_000_000  # (twice this raises; a small file can be a huge picture)
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}

TOOLS = [
    {
        "name": "list_files",
        "description": "List the files this user attached in this channel (the working folder), "
        "with their type, size and, for PDFs, page count.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_file",
        "description": "Read a text file from the working folder. Long files come in windows of "
        "40000 characters: the result gives total_chars and next_start; call again with "
        'start=next_start to read on, or pass find="term" to get only the passages around '
        "each match. For PDFs use read_pdf_page, for images view_image.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "File name from list_files."},
                "start": {"type": "integer", "description": "Character offset (default 0)."},
                "find": {"type": "string", "description": "Optional search term."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "read_pdf_page",
        "description": "Read one page of a PDF from the working folder. Returns the page's text; "
        "if the page has no text layer (scanned) or as_image is true, returns the page as an "
        "image instead, which is also useful for tables, diagrams and layout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "PDF file name from list_files."},
                "page": {"type": "integer", "description": "Page number, starting at 1."},
                "as_image": {
                    "type": "boolean",
                    "description": "Return the rendered page image even if it has text.",
                },
            },
            "required": ["name", "page"],
        },
    },
    {
        "name": "view_image",
        "description": "Look at an image file from the working folder.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Image file name from list_files."}
            },
            "required": ["name"],
        },
    },
]
TOOL_NAMES = {t["name"] for t in TOOLS}


# Files a tool wants attached to the current Discord reply (set per request in bot.answer;
# asyncio.to_thread copies the context, so tools running in threads see the same list)
pending_files: contextvars.ContextVar[list] = contextvars.ContextVar("pending_files")
# Files for the ZIP that goes with the reply (all screen images, with the answer)
pending_bundle: contextvars.ContextVar[list] = contextvars.ContextVar("pending_bundle")


# Whose question is being answered (tools only get the channel; to_thread copies the context)
current_user: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "current_user", default=None
)


# What the user must be told whatever the model writes (shown above its answer)
pending_notes: contextvars.ContextVar[list] = contextvars.ContextVar("pending_notes")


def tell_user(text: str) -> None:
    try:
        pending_notes.get().append(text)
    except LookupError:  # called outside a Discord request (e.g. tests)
        pass


def bundle(path: Path) -> None:
    """Put a file into the ZIP that goes with the reply (with the answer as Markdown)."""
    try:
        pending_bundle.get().append(path)
    except LookupError:  # called outside a Discord request (e.g. tests)
        pass


def attach(path: Path) -> None:
    try:
        pending_files.get().append(path)
    except LookupError:  # called outside a Discord request (e.g. tests)
        pass


def channel_dir(channel_id: int, user_id: int | None = None) -> Path:
    user = current_user.get() if user_id is None else user_id
    folder = WORK_DIR / str(channel_id)
    return folder if user is None else folder / str(user)  # (None: outside Discord, tests)


def saved_path(channel_id: int, filename: str, user_id: int | None = None) -> Path:
    """Where save_attachments stored an attachment with this file name."""
    return channel_dir(channel_id, user_id) / _safe_name(filename)


def clear(channel_id: int, user_id: int) -> None:
    shutil.rmtree(channel_dir(channel_id, user_id), ignore_errors=True)


def _user_files(folder: Path | None = None) -> list[Path]:
    """The files in user folders, oldest first (work/<channel id>/<user id>/ only: nothing
    else in the working folder is touched)."""
    files = []
    for channel in [folder] if folder else WORK_DIR.glob("*"):
        users = [channel] if folder else channel.glob("*") if channel.name.isdigit() else []
        for user in users:
            if user.name.isdigit() and user.is_dir():
                files += [p for p in user.rglob("*") if p.is_file()]
    return sorted(files, key=lambda p: p.stat().st_mtime)


def _make_room(folder: Path, needed: int) -> None:
    """Drop files past their age, then the oldest until the upload fits both limits."""
    limit = time.time() - FILE_MAX_DAYS * 86400
    for path in _user_files():
        if path.stat().st_mtime < limit:
            path.unlink(missing_ok=True)
    for scope, maximum in ((folder, USER_MAX_BYTES), (None, WORK_MAX_BYTES)):
        files = _user_files(scope)
        used = sum(p.stat().st_size for p in files)
        for path in files:
            if used + needed <= maximum:
                break
            used -= path.stat().st_size
            path.unlink(missing_ok=True)


def _safe_name(filename: str) -> str:
    name = re.sub(r"[^\w.\- ]", "_", Path(filename).name).strip(" .")
    if re.match(r"(con|prn|aux|nul|com\d|lpt\d)(\.|$)", name, re.I):
        name = "_" + name  # (device names on Windows, whatever the extension)
    return name or "file"


def _resolve(channel_id: int, name: str) -> Path:
    """Find a file in the channel's folder; never leaves that folder."""
    path = channel_dir(channel_id) / Path(name).name
    if not path.is_file():
        raise FileNotFoundError(f"no file named {name!r}; call list_files")
    return path


def _decode(data: bytes) -> str | None:
    """Return the bytes as text, or None if they look binary."""
    if b"\x00" in data[:8192]:
        return None
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return None


def _kind(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        return "pdf"
    if path.suffix.lower() in IMAGE_SUFFIXES:
        return "image"
    with path.open("rb") as f:
        return "text" if _decode(f.read(65536)) is not None else "binary"


def _describe(path: Path) -> str:
    kind = _kind(path)
    info = f"{path.name} ({kind}, {path.stat().st_size:,} bytes"
    if kind == "pdf":
        try:
            pdf = pdfium.PdfDocument(path)
            info += f", {len(pdf)} pages"
            pdf.close()
        except pdfium.PdfiumError:
            info += ", unreadable"
    return info + ")"


def _image_block(img: Image.Image, fmt: str) -> Dict[str, Any]:
    img.thumbnail((IMAGE_MAX_SIDE, IMAGE_MAX_SIDE))
    if fmt == "JPEG" and img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    buf = io.BytesIO()
    img.save(buf, fmt, **({"quality": 85} if fmt == "JPEG" else {}))
    return {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": f"image/{fmt.lower()}",
            "data": base64.b64encode(buf.getvalue()).decode("ascii"),
        },
    }


# --- tools (synchronous, run in a thread) -------------------------------------------------


def _list_files(channel_id: int) -> str:
    folder = channel_dir(channel_id)
    files = sorted(p for p in folder.iterdir() if p.is_file()) if folder.is_dir() else []
    return "\n".join(_describe(p) for p in files) or "No files in the working folder."


def _read_file(channel_id: int, name: str, start: int = 0, find: str = "") -> Any:
    path = _resolve(channel_id, name)
    kind = _kind(path)
    if kind != "text":
        tool = {"pdf": "read_pdf_page", "image": "view_image", "binary": "rom_info"}.get(kind)
        raise ValueError(f"{path.name} is a {kind} file" + (f"; use {tool}" if tool else ""))
    text = _decode(path.read_bytes()) or ""
    res: Dict[str, Any] = {"name": path.name, "total_chars": len(text)}
    if find:
        res["matches"] = _find_windows(text, find)
        if not res["matches"]:
            res["note"] = "no match; try another term, or page through with start="
        return res
    start = max(0, min(start, len(text)))
    end = min(len(text), start + TEXT_WINDOW_CHARS)
    res.update(start=start, end=end, content=text[start:end])
    if end < len(text):
        res["next_start"] = end
        res["note"] = f"{len(text) - end} more characters: call again with start={end}"
    return res


def _read_pdf_page(channel_id: int, name: str, page: int, as_image: bool = False) -> Any:
    path = _resolve(channel_id, name)
    pdf = pdfium.PdfDocument(path)
    try:
        if not 1 <= page <= len(pdf):
            raise ValueError(f"{path.name} has pages 1 to {len(pdf)}")
        pdf_page = pdf[page - 1]
        text = pdf_page.get_textpage().get_text_range().strip()
        header = f"{path.name}, page {page} of {len(pdf)}"
        if len(text) >= PDF_MIN_TEXT_CHARS and not as_image:
            return f"{header}\n\n{text}"
        width, height = pdf_page.get_size()
        scale = min(IMAGE_MAX_SIDE / max(width, height), 4.0)
        img = pdf_page.render(scale=scale).to_pil()
        note = "rendered as image" + ("" if as_image else " (no text layer)")
        return [{"type": "text", "text": f"{header}, {note}"}, _image_block(img, "PNG")]
    finally:
        pdf.close()


def _view_image(channel_id: int, name: str) -> list[dict]:
    path = _resolve(channel_id, name)
    with Image.open(path) as img:
        img.seek(0)  # first frame of animated GIFs
        fmt = "PNG" if img.mode in ("RGBA", "LA", "P") else "JPEG"
        block = _image_block(img.copy(), fmt)
    return [{"type": "text", "text": path.name}, block]


async def run(channel_id: int, name: str, args: Dict[str, Any]) -> Any:
    """Run a file tool; returns tool_result content (text, JSON-able dict, or content blocks)."""
    if name == "list_files":
        return await asyncio.to_thread(_list_files, channel_id)
    if name == "read_file":
        return await asyncio.to_thread(
            _read_file, channel_id, args["name"], int(args.get("start", 0)), args.get("find", "")
        )
    if name == "read_pdf_page":
        return await asyncio.to_thread(
            _read_pdf_page,
            channel_id,
            args["name"],
            int(args["page"]),
            bool(args.get("as_image", False)),
        )
    if name == "view_image":
        return await asyncio.to_thread(_view_image, channel_id, args["name"])
    raise ValueError(f"unknown tool: {name}")


# --- saving attachments -------------------------------------------------------------------


async def save_attachments(
    channel_id: int,
    attachments: list[discord.Attachment],
    describe: Callable[[Path], Awaitable[str]] | None = None,
) -> tuple[list[str], list[str]]:
    """Save attachments to the channel's folder. Returns (file descriptions, notes for the user).
    describe gives a saved file's description (the bot's: in the tool process, as it opens
    PDFs)."""
    folder = channel_dir(channel_id)
    folder.mkdir(parents=True, exist_ok=True)
    saved, notes = [], []
    fitting = [a for a in attachments[:MAX_FILES] if a.size <= MAX_DOWNLOAD_BYTES]
    await asyncio.to_thread(_make_room, folder, sum(a.size for a in fitting))
    if len(attachments) > MAX_FILES:
        notes.append(f"only the first {MAX_FILES} files were saved")
        attachments = attachments[:MAX_FILES]
    for att in attachments:
        if att.size > MAX_DOWNLOAD_BYTES:
            notes.append(f"`{att.filename}` skipped: larger than {MAX_DOWNLOAD_BYTES >> 20} MB")
            continue
        path = folder / _safe_name(att.filename)
        error = None
        for _ in range(2):  # Discord's CDN occasionally drops a connection: retry once
            try:
                await att.save(path)
                error = None
                break
            except Exception as e:  # HTTP errors and broken connections (aiohttp)
                error = e
        if error:
            notes.append(f"`{att.filename}` skipped: download failed ({type(error).__name__})")
            continue
        saved.append(await describe(path) if describe else await asyncio.to_thread(_describe, path))
    return saved, notes
