import asyncio
import collections
import functools
import io
import json
import logging
import os
import time
import traceback
import zipfile
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
import anthropic
import discord
from discord import app_commands
from dotenv import load_dotenv

HERE = Path(__file__).parent
# (before the bot's own modules: they read their settings from the environment when imported)
load_dotenv(HERE / ".env")

# pylint: disable=wrong-import-position
import binary_tools
from discord_format import chunks, convert_tables
import isolation
import screen_tools
import web_tools
import workspace

# pylint: enable=wrong-import-position


def read_secret(name: str) -> str:
    path = HERE / name
    if not path.is_file():
        raise SystemExit(f"Secret file not found: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SystemExit(f"Secret file is empty: {path}")
    return value


def optional_secret(name: str) -> str | None:
    """A secret file's value, or None when there is none (importing the bot, as the tests do,
    needs no secrets; starting it does)."""
    return read_secret(name) if (HERE / name).is_file() else None


BOT_NICKNAME = os.getenv("BOT_NICKNAME", "Gwennyfer")  # set in every server; empty = leave as is

AI_BASE_URL = os.getenv("AI_BASE_URL", "http://localhost:8080")
AI_API_KEY = optional_secret("api-key.txt")  # (required when the bot starts)
# (a local server may ignore the model name and use its own model)
AI_MODEL = os.getenv("AI_MODEL", "claude-sonnet-5-5")
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "32000"))  # room for thinking + answer
SYSTEM_PROMPT = os.getenv(
    "SYSTEM_PROMPT",
    "You are a friendly assistant in a Discord server. Keep answers concise.",
)
# Appended to any system prompt: what Discord can display
FORMAT_GUIDANCE = (
    "\n\nFormatting: your answer is posted in Discord, which supports only part of Markdown: "
    "**bold**, *italic*, __underline__, ~~strikethrough~~, `inline code`, ``` code blocks "
    "(with a language name for highlighting, e.g. ```asm), > quotes, - and 1. lists, # ## ### "
    "headings (use sparingly), [masked links](https://example.com) and ||spoilers||. Discord "
    "has NO tables and no HTML: never write | column | rows. For tabular data use a short list "
    '(one item per line, e.g. "- **Name**: value"), or aligned columns inside a ``` code block. '
    "Keep lines short, as many people read on phones; long answers are split into several "
    "messages of at most 2000 characters."
)
MAX_TOOL_ROUNDS = int(os.getenv("MAX_TOOL_ROUNDS", "40"))
REPLY_CONTEXT_CHARS = 6000  # how much of an earlier answer goes with a reply to it
# The bot is open to everyone: one question at a time per user, a few at once in all (the
# others wait their turn), and so many per hour
MAX_CONCURRENT_QUESTIONS = int(os.getenv("MAX_CONCURRENT_QUESTIONS", "3"))
QUESTIONS_PER_HOUR = int(os.getenv("QUESTIONS_PER_HOUR", "30"))
# Pacing of long replies: at most MAX_MESSAGES messages per answer (the rest is attached as a
# file), MESSAGE_DELAY seconds apart, to stay clear of Discord's rate limits
MAX_MESSAGES = max(2, int(os.getenv("MAX_MESSAGES", "5")))
MESSAGE_DELAY = float(os.getenv("MESSAGE_DELAY", "1.5"))
MAX_FILE = 10 << 20  # Discord's upload limit per file (without server boosts)
MAX_UPLOAD = 24 << 20  # and, with some room for the request itself, per message
# Appended to any system prompt: how to use tools efficiently within the round limit
TOOL_GUIDANCE = (
    f"\n\nTool use: you have at most {MAX_TOOL_ROUNDS} rounds of tool calls per question. "
    "When lookups do not depend on each other, request them together in the same step (several "
    "tool calls in one answer count as one round). Prefer batched arguments: strings and "
    "search_bytes accept several search terms at once, hexdump several ranges. For a BIOS or "
    "firmware image, start with bios_summary instead of many single lookups."
)


def asker_note(author: str) -> str:
    """Appended to the system prompt: who asks. The name is not part of the question (the
    model took nicknames for words of the question when they came before it)."""
    return (
        f"\n\nThe question comes from the Discord user whose display name is {author!r}. "
        "That is only who is asking: the name is not part of the question, so do not "
        "interpret or answer it; address the user by it only if that fits naturally. Each "
        "question is answered on its own: there is no earlier conversation, except an earlier "
        "answer given with a question that replies to it. Files this user attached to earlier "
        "questions in this channel are still in the working folder (list_files) if the "
        "question refers to one; other users' files are not available. Do not end an answer "
        'with offers or questions such as "Should I also ...?": you would not remember them. '
        "Do what was asked; to go on, the user can use Discord's Reply on your answer."
    )


# Sent as "Authorization: Bearer", like ANTHROPIC_AUTH_TOKEN
ai = anthropic.AsyncAnthropic(base_url=AI_BASE_URL, auth_token=AI_API_KEY)


async def create_message(**request: Any) -> Any:
    """One model reply, streamed: with a large max_tokens the SDK refuses non-streaming
    requests (they could outlast the HTTP timeout); the complete message is returned."""
    async with ai.messages.stream(**request) as stream:
        return await stream.get_final_message()


# web_search / web_fetch: through SearXNG (by default on the AI's host, port 8888), with
# Ollama's web API as the fallback when ollama-api-key.txt exists.
# BOT_WEB=searxng|ollama|none picks one by hand.
SEARXNG_URL = os.getenv("SEARXNG_URL") or f"http://{urlparse(AI_BASE_URL).hostname}:8888"
web_client = web_tools.WebTools(
    SEARXNG_URL,
    read_secret("ollama-api-key.txt") if (HERE / "ollama-api-key.txt").is_file() else None,
    os.getenv("BOT_WEB", "auto"),
)
web: web_tools.WebTools | None = web_client if web_client.enabled else None
# File tools for the channel's working folder are always on
TOOLS = workspace.TOOLS + binary_tools.TOOLS + screen_tools.TOOLS + (web_tools.TOOLS if web else [])
# (the tools that read uploaded files: run in a process of their own, isolation.py)
ISOLATED = workspace.TOOL_NAMES | binary_tools.TOOL_NAMES | screen_tools.TOOL_NAMES


async def run_tool(channel_id: int, name: str, args: dict) -> Any:
    """Run one tool call; returns tool_result content (text or content blocks). The file,
    binary and screen tools run in the question's tool process (isolation.py)."""
    if name in ISOLATED and isolation.current.get() is not None:  # (None: outside a question)
        result = await isolation.run(name, args)
    elif name in workspace.TOOL_NAMES:
        result = await workspace.run(channel_id, name, args)
    elif name in binary_tools.TOOL_NAMES:
        result = await binary_tools.run(channel_id, name, args)
    elif name in screen_tools.TOOL_NAMES:
        result = await screen_tools.run(channel_id, name, args)
    elif web:
        result = await web.run(name, args)
    else:
        raise ValueError(f"unknown tool: {name}")
    return result if isinstance(result, (str, list)) else json.dumps(result, ensure_ascii=False)


def reply_text(response: Any) -> str:
    return "".join(b.text for b in response.content if b.type == "text").strip()


def log_reply(response: Any, label: str = "reply") -> None:
    """One line per model reply, so a missing answer can be diagnosed in the terminal."""
    blocks = ",".join(b.type for b in response.content) or "none"
    tokens = getattr(response.usage, "output_tokens", "?")
    print(f"AI {label}: stop={response.stop_reason} blocks={blocks} output_tokens={tokens}")


async def ask_ai(channel_id: int, author: str, prompt: str) -> str:
    """Answer one question on its own: no earlier questions or answers are sent along. The
    asker's name goes into the system prompt, not into the question."""
    messages: list = [{"role": "user", "content": prompt}]
    system = SYSTEM_PROMPT + FORMAT_GUIDANCE + TOOL_GUIDANCE + asker_note(author)

    try:
        # Tool loop: the model may read files or search the web several times before it answers.
        for round_no in range(MAX_TOOL_ROUNDS + 1):
            final = round_no == MAX_TOOL_ROUNDS  # limit reached: one last call to answer
            request = {
                "model": AI_MODEL,
                "max_tokens": AI_MAX_TOKENS,
                "system": system,
                "messages": messages,
                "tools": TOOLS,
            }
            if final:
                try:
                    response = await create_message(**request, tool_choice={"type": "none"})
                except anthropic.BadRequestError:  # server without tool_choice support
                    response = await create_message(**request)
            else:
                response = await create_message(**request)
            if response.stop_reason != "tool_use" or final:
                break
            messages.append({"role": "assistant", "content": response.content})
            results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                print(f"Tool {block.name}: {json.dumps(block.input, ensure_ascii=False)}")
                try:
                    output = await run_tool(channel_id, block.name, block.input)
                    results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": output}
                    )
                except Exception as e:  # report any tool failure back to the model
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": (
                                str(e)
                                if isinstance(e, isolation.ToolFailed)
                                else f"{type(e).__name__}: {e}"
                            ),
                            "is_error": True,
                        }
                    )
            if round_no == MAX_TOOL_ROUNDS - 1:
                results.append(
                    {
                        "type": "text",
                        "text": (
                            "The tool-call limit for this question is reached. Do not call "
                            "any more tools: answer now from what you found so far, and say "
                            "what is still open."
                        ),
                    }
                )
            messages.append({"role": "user", "content": results})

        log_reply(response)
        if not reply_text(response) and response.stop_reason != "refusal":
            # No answer text (e.g. the output budget went to thinking): ask once more for
            # the answer itself, without tools
            if response.content:
                messages.append({"role": "assistant", "content": response.content})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your last reply contained no answer text. Write your final answer "
                        "to the question now, concisely, from what you found so far. Do not "
                        "call any tools."
                    ),
                }
            )
            request = {
                "model": AI_MODEL,
                "max_tokens": AI_MAX_TOKENS,
                "system": system,
                "messages": messages,
                "tools": TOOLS,
            }
            try:
                response = await create_message(**request, tool_choice={"type": "none"})
            except anthropic.BadRequestError:
                response = await create_message(**request)
            log_reply(response, "retry")
    except anthropic.APIConnectionError:
        return f"Could not reach the AI server at {AI_BASE_URL}."
    except anthropic.AuthenticationError:
        return "The AI server rejected the API key (check api-key.txt)."
    except anthropic.APIStatusError as e:
        return f"AI server error {e.status_code}: {e.message}"

    if response.stop_reason == "refusal":
        return "The model declined to answer that."

    text = reply_text(response)
    if response.stop_reason == "tool_use":
        text = (
            text + "\n\n" if text else ""
        ) + "(stopped: tool-call limit reached; ask again to continue)"
    if not text:
        text = (
            f"(no answer: the model stopped with '{response.stop_reason}' without writing "
            "text; please ask again)"
        )
    return text


def everywhere(func: Any) -> Any:
    """Let a command work when the bot is in a server or installed to a user's account, and be
    used in servers, DMs with the bot, and private channels (DMs and Group DMs)."""
    func = app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)(func)
    return app_commands.allowed_installs(guilds=True, users=True)(func)


class Bot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True  # needed to read @mention text
        # Quoted questions and AI answers must never ping anyone (e.g. @everyone)
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        # Commands must be global: server-only copies would not show up in DMs or Group DMs
        await self.tree.sync()


bot = Bot()


@bot.event
async def on_ready() -> None:
    assert bot.user is not None
    print(f"Logged in as {bot.user} (id: {bot.user.id}), AI at {AI_BASE_URL}")
    print("Web tools: " + (await web.status() if web else "off"))
    print(f"Working folder: {workspace.WORK_DIR}")
    for guild in bot.guilds:
        await apply_nickname(guild)


@bot.event
async def on_guild_join(guild: discord.Guild) -> None:
    await apply_nickname(guild)


async def apply_nickname(guild: discord.Guild) -> None:
    if not BOT_NICKNAME or guild.me.nick == BOT_NICKNAME:
        return
    try:
        await guild.me.edit(nick=BOT_NICKNAME)
        print(f"Nickname set to {BOT_NICKNAME!r} in {guild.name}")
    except discord.Forbidden:
        print(f"No permission to change nickname in {guild.name} (needs Change Nickname)")
    except discord.HTTPException as e:
        print(f"Could not set nickname in {guild.name}: {e}")


async def replied_answer(message: discord.Message) -> str | None:
    """The text of the bot's own answer that this message replies to (Discord's Reply), or
    None if it is not such a reply."""
    reference = message.reference
    if reference is None or reference.message_id is None:
        return None
    target = reference.resolved if isinstance(reference.resolved, discord.Message) else None
    if target is None:
        try:
            target = await message.channel.fetch_message(reference.message_id)
        except discord.HTTPException:
            return None
    return target.content[:REPLY_CONTEXT_CHARS] if target.author == bot.user else None


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot:
        return
    is_dm = isinstance(message.channel, discord.DMChannel)
    # (a Reply with its ping switched off does not mention the bot, but it is meant for it)
    earlier = await replied_answer(message)
    if not (is_dm or bot.user in message.mentions or earlier is not None):
        return

    assert bot.user is not None
    prompt = message.content.replace(f"<@{bot.user.id}>", "").strip()
    if not prompt and not message.attachments:
        return

    async with message.channel.typing():
        reply, images = await safe_answer(
            message.channel.id,
            message.author.id,
            message.author.display_name,
            prompt,
            message.attachments,
            earlier or "",
        )

    parts = list(chunks(reply))
    await send_parts(
        lambda text, **kw: message.reply(text, mention_author=False, **kw),
        message.channel.send,
        parts,
        images,
        full_text=reply,
    )


async def send_parts(
    send_first: Callable[..., Awaitable[Any]],
    send_rest: Callable[..., Awaitable[Any]],
    parts: list[str],
    images: list[Path],
    extra: Sequence[discord.File] = (),
    full_text: str | None = None,
) -> None:
    """Send the reply; images created by tools and then the user's own files (re-attached)
    go with the first part, at most 10 in all (Discord's limit). Falls back to text only if
    Discord rejects the files (e.g. too large).
    Long replies are paced (MESSAGE_DELAY between messages) and capped at MAX_MESSAGES:
    the rest is not posted as more messages but attached as a text file, so a long answer
    neither floods the channel nor runs into Discord's rate limits."""
    # (no link previews: Discord would fetch every URL in an answer itself, also one that a
    # file or web page led the model to write, with data in it)
    send_first = functools.partial(send_first, suppress_embeds=True)
    send_rest = functools.partial(send_rest, suppress_embeds=True)
    files = [discord.File(p) for p in images if p.is_file()] + list(extra)
    overflow = len(parts) > MAX_MESSAGES
    if overflow:
        parts = parts[: MAX_MESSAGES - 1]
    try:
        if files:
            await with_retry(lambda: send_first(parts[0], files=files[:10]), files)
        else:
            await with_retry(lambda: send_first(parts[0]))
    except discord.HTTPException:
        fitting = fit_files(files[:10])
        try:
            if not fitting:
                raise
            left = [f.filename for f in files[:10] if f not in fitting]
            note = f"\n-# (too large to attach: {', '.join(left)})" if left else ""
            for f in fitting:
                f.reset()
            await with_retry(lambda: send_first(parts[0] + note, files=fitting), fitting)
        except discord.HTTPException:
            await with_retry(lambda: send_first(parts[0] + "\n-# (images could not be attached)"))
    for part in parts[1:]:
        await asyncio.sleep(MESSAGE_DELAY)
        await with_retry(functools.partial(send_rest, part))
    if overflow:
        await asyncio.sleep(MESSAGE_DELAY)
        data = (full_text or "\n\n".join(parts)).encode("utf-8")
        note = "-# The answer is longer than shown here; the full text is attached."
        await with_retry(lambda: send_rest(note, file=discord.File(io.BytesIO(data), "answer.md")))


def fit_files(files: Sequence[discord.File]) -> list[discord.File]:
    """The files that Discord takes in one message: each at most MAX_FILE, together at most
    MAX_UPLOAD, in their order (tool images first, then the user's own files)."""
    out, total = [], 0
    for f in files:
        try:
            size = f.fp.seek(0, io.SEEK_END)
        except (OSError, ValueError):
            continue
        if size <= MAX_FILE and total + size <= MAX_UPLOAD:
            out.append(f)
            total += size
    return out


async def with_retry(
    send: Callable[[], Awaitable[Any]], files: Sequence[discord.File] = (), attempts: int = 3
) -> Any:
    """Retry a send when the network connection drops (seen as WinError 64 / connection
    reset); Discord API errors such as "file too large" are not retried."""
    for attempt in range(attempts):
        try:
            return await send()
        except (aiohttp.ClientError, OSError, asyncio.TimeoutError, discord.DiscordServerError):
            if attempt == attempts - 1:
                raise
            print(f"Send failed (network), retrying in {2 ** attempt} s")
            await asyncio.sleep(2**attempt)
            for f in files:
                f.reset()  # rewind attachments that were partly sent


question_slots = asyncio.Semaphore(MAX_CONCURRENT_QUESTIONS)
busy_users: set[int] = set()
recent_questions: dict[int, collections.deque] = collections.defaultdict(collections.deque)


def refusal(user_id: int) -> str | None:
    """Why this user's question is not taken now, or None."""
    if user_id in busy_users:
        return "I am still working on your previous question. Ask again when it is answered."
    times, now = recent_questions[user_id], time.time()
    while times and now - times[0] > 3600:
        times.popleft()
    if len(times) >= QUESTIONS_PER_HOUR:
        return f"You have reached the limit of {QUESTIONS_PER_HOUR} questions per hour."
    times.append(now)
    return None


async def safe_answer(
    channel_id: int,
    user_id: int,
    author: str,
    prompt: str,
    files: list[discord.Attachment],
    context: str = "",
) -> tuple[str, list[Path]]:
    """answer(), in the user's own folder; any unexpected error becomes a reply instead of a
    silent failure. One line per question in the log, without its text, so that misuse can
    be seen and traced to a user."""
    size = sum(f.size for f in files)
    print(
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} question: user {user_id} {author!a} "
        f"channel {channel_id}, {len(prompt)} chars, {len(files)} files, {size} bytes"
    )
    if (why := refusal(user_id)) is not None:
        print(f"refused: user {user_id}: {why}")
        return why, []
    busy_users.add(user_id)
    token = workspace.current_user.set(user_id)
    try:
        async with question_slots:
            return await answer(channel_id, author, prompt, files, context)
    except Exception as e:  # network errors, tool bugs, ...
        traceback.print_exc()  # (the details stay here: they can name paths and addresses)
        return f"Something went wrong while answering (`{type(e).__name__}`).", []
    finally:
        workspace.current_user.reset(token)
        busy_users.discard(user_id)


async def answer(
    channel_id: int,
    author: str,
    prompt: str,
    files: list[discord.Attachment],
    context: str = "",
) -> tuple[str, list[Path]]:
    """Save any attached files to the user's working folder, then ask the AI (with the
    earlier answer this question replies to, if any).
    Returns the reply and the images tools created for it."""
    worker = isolation.Worker(channel_id, workspace.current_user.get())
    worker_token = isolation.current.set(worker)
    try:
        return await _answer(channel_id, author, prompt, files, context, worker)
    finally:
        isolation.current.reset(worker_token)
        await worker.close()


async def _answer(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    channel_id: int,
    author: str,
    prompt: str,
    files: list[discord.Attachment],
    context: str,
    worker: isolation.Worker,
) -> tuple[str, list[Path]]:
    question = prompt
    saved, notes = (
        await workspace.save_attachments(channel_id, files, worker.describe) if files else ([], [])
    )
    note_lines = "".join(f"-# {n}\n" for n in notes)  # small grey text in Discord
    if saved:
        prompt = (
            f"{prompt or 'Please analyze the attached file.'}\n\n"
            f"[Attached and saved to the working folder: {'; '.join(saved)}. "
            "Read them with read_file, read_pdf_page or view_image; for binary files such as "
            "ROMs or firmware start with rom_info.]"
        )
    elif not prompt:
        return note_lines or "No readable file.", []
    if context:
        prompt = f"[Your earlier answer, which this question replies to:\n{context}\n]\n\n{prompt}"
    token = workspace.pending_files.set([])
    bundled = workspace.pending_bundle.set([])
    notes_token = workspace.pending_notes.set([])
    try:
        reply = convert_tables(await ask_ai(channel_id, author, prompt))
        tool_notes = dict.fromkeys(workspace.pending_notes.get())
        reply = note_lines + "".join(f"-# {n}\n" for n in tool_notes) + reply
        images = list(dict.fromkeys(workspace.pending_files.get()))
        if files_in_zip := list(dict.fromkeys(workspace.pending_bundle.get())):
            images = images[:8] + [bundle_zip(files_in_zip, author, question, reply)]
        return reply, images[:9]
    finally:
        workspace.pending_files.reset(token)
        workspace.pending_bundle.reset(bundled)
        workspace.pending_notes.reset(notes_token)


def bundle_zip(paths: list[Path], author: str, prompt: str, reply: str) -> Path:
    """One ZIP file with all images a tool made for the reply (also those not attached
    singly) and the question and answer as Markdown, next to the first image."""
    stem = paths[0].name.split(".setup.")[0]
    out = paths[0].parent / f"{stem}.setup-screens.zip"
    text = f"**{author}:** {prompt}\n\n{reply}\n"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("answer.md", text)
        for p in paths:
            if p.is_file():
                z.write(p, p.name)
    return out


@bot.tree.command(description="Ask the AI a question, optionally about up to five files")
@everywhere
@app_commands.describe(
    question="Your question",
    file="A text, code, PDF or image file to analyze",
    file2="Another file (optional)",
    file3="Another file (optional)",
    file4="Another file (optional)",
    file5="Another file (optional)",
)
async def ask(
    interaction: discord.Interaction,
    question: str,
    file: discord.Attachment | None = None,
    file2: discord.Attachment | None = None,
    file3: discord.Attachment | None = None,
    file4: discord.Attachment | None = None,
    file5: discord.Attachment | None = None,
) -> None:
    # a slash command option holds one file: five options, the empty ones left out
    files = [f for f in (file, file2, file3, file4, file5) if f]
    assert interaction.channel_id is not None
    await interaction.response.defer(thinking=True)
    reply, images = await safe_answer(
        interaction.channel_id,
        interaction.user.id,
        interaction.user.display_name,
        question,
        files,
    )

    # Others only see "X used /ask", not the options; repeat the question and files in the answer
    header = f"> **{interaction.user.display_name}:** {question[:1000]}"
    for f in files:
        header += f"\n> 📎 {f.filename}"
    full_text = f"{header}\n\n{reply}"
    parts = list(chunks(full_text))
    # Re-attach the user's files from the copies saved in the working folder (downloading
    # them again from Discord can fail and would cost the whole answer)
    extra = []
    for f in files:
        local = workspace.saved_path(interaction.channel_id, f.filename, interaction.user.id)
        if local and local.is_file():
            extra.append(discord.File(local, filename=f.filename))
    try:
        await send_parts(
            interaction.followup.send,
            interaction.followup.send,
            parts,
            images,
            extra,
            full_text=full_text,
        )
    except discord.HTTPException:  # e.g. the user's file is too large for the bot to re-upload
        await send_parts(
            interaction.followup.send, interaction.followup.send, parts, images, full_text=full_text
        )


@bot.tree.command(description="Delete the files you attached in this channel")
@everywhere
async def reset(interaction: discord.Interaction) -> None:
    assert interaction.channel_id is not None
    workspace.clear(interaction.channel_id, interaction.user.id)
    await interaction.response.send_message("Your files in this channel are cleared.")


@bot.tree.command(description="Show bot latency")
@everywhere
async def ping(interaction: discord.Interaction) -> None:
    await interaction.response.send_message(f"Pong! {bot.latency * 1000:.0f} ms")


class ShortNetworkErrors(logging.Filter):
    """discord.py reconnects by itself after network errors; log those in one line instead of
    a full traceback (other errors keep theirs)."""

    def filter(self, record: logging.LogRecord) -> bool:
        exc = record.exc_info[1] if record.exc_info else None
        if isinstance(exc, (aiohttp.ClientError, OSError, asyncio.TimeoutError)):
            record.msg = f"{record.getMessage()} ({type(exc).__name__}: {exc})"
            record.args, record.exc_info, record.exc_text = None, None, None
        return True


if __name__ == "__main__":
    read_secret("api-key.txt")  # (stops here with a message when it is missing)
    discord.utils.setup_logging()
    for logger in ("discord.client", "discord.gateway", "discord.http"):
        logging.getLogger(logger).addFilter(ShortNetworkErrors())
    for logger in ("httpx", "httpx2", "httpcore"):  # one line per HTTP request is too much
        logging.getLogger(logger).setLevel(logging.WARNING)
    bot.run(read_secret("discord-token.txt"), log_handler=None)
