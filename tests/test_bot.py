"""The bot's message handling without Discord: which messages it answers, the question limits,
and that answers go out without link previews. Importing the bot needs no secrets."""

from __future__ import annotations

import asyncio
import collections
from types import SimpleNamespace as NS

import discord
import pytest

import bot as b

ME = NS(id=1, bot=True)
OTHER = NS(id=2, bot=False)


def test_import_needs_no_secrets() -> None:
    assert b.optional_secret("no-such-secret.txt") is None


@pytest.fixture
def fresh_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(b, "question_slots", asyncio.Semaphore(b.MAX_CONCURRENT_QUESTIONS))
    monkeypatch.setattr(b, "busy_users", set())
    monkeypatch.setattr(b, "recent_questions", collections.defaultdict(collections.deque))


# --- which messages are answered -------------------------------------------------------------


class Typing:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def no_send(*args, **kwargs):
    return None


def channel(fetched=None):
    async def fetch(_id):
        if fetched is None:
            raise discord.NotFound(NS(status=404, reason="x"), "gone")
        return fetched

    return NS(id=9, typing=Typing, send=no_send, fetch_message=fetch)


def answer_of(author, text="earlier answer"):
    message = discord.Message.__new__(discord.Message)
    message.author, message.content = author, text
    return message


def msg(text, mentions=(), ref=None, chan=None):
    author = NS(bot=False, id=5, display_name="u")
    return NS(
        author=author,
        content=text,
        mentions=list(mentions),
        attachments=[],
        reference=ref,
        channel=chan or channel(),
        reply=no_send,
    )


CASES = [
    ("plain message ignored", msg("hello"), None),
    ("mention answered", msg("<@1> hello", [ME]), ("hello", "")),
    (
        "reply with ping",
        msg("why?", [ME], NS(message_id=7, resolved=answer_of(ME))),
        ("why?", "earlier answer"),
    ),
    (
        "reply without ping",
        msg("why?", [], NS(message_id=7, resolved=answer_of(ME))),
        ("why?", "earlier answer"),
    ),
    (
        "reply, message not cached",
        msg("why?", [], NS(message_id=7, resolved=None), channel(answer_of(ME))),
        ("why?", "earlier answer"),
    ),
    (
        "reply to someone else ignored",
        msg("why?", [], NS(message_id=7, resolved=answer_of(OTHER))),
        None,
    ),
    ("reply to a deleted message ignored", msg("why?", [], NS(message_id=7, resolved=None)), None),
    (
        "mention in a reply to someone else",
        msg("<@1> what is this", [ME], NS(message_id=7, resolved=answer_of(OTHER))),
        ("what is this", ""),
    ),
]


@pytest.mark.parametrize("name, message, wanted", CASES, ids=[c[0] for c in CASES])
def test_which_messages_are_answered(
    monkeypatch: pytest.MonkeyPatch, name: str, message, wanted
) -> None:
    calls = []

    async def fake_answer(channel_id, user, author, prompt, files, context=""):
        calls.append((prompt, context))
        return "ok", []

    monkeypatch.setattr(b.bot._connection, "user", ME)
    monkeypatch.setattr(b, "safe_answer", fake_answer)
    monkeypatch.setattr(b, "send_parts", no_send)
    asyncio.run(b.on_message(message))
    assert (calls[0] if calls else None) == wanted


# --- question limits --------------------------------------------------------------------------


def test_one_question_at_a_time_and_a_limit_per_hour(
    monkeypatch: pytest.MonkeyPatch, fresh_limits
) -> None:
    async def fake(channel_id, author, prompt, files, context=""):
        await asyncio.sleep(0.05)
        return "ok", []

    monkeypatch.setattr(b, "answer", fake)
    monkeypatch.setattr(b, "QUESTIONS_PER_HOUR", 3)

    async def go():
        first, second = await asyncio.gather(
            b.safe_answer(1, 5, "u", "one", []), b.safe_answer(1, 5, "u", "two", [])
        )
        assert first[0] == "ok" and "previous question" in second[0]
        await b.safe_answer(1, 5, "u", "three", [])
        await b.safe_answer(1, 5, "u", "four", [])
        assert "limit" in (await b.safe_answer(1, 5, "u", "five", []))[0]
        assert (await b.safe_answer(1, 6, "v", "other user", []))[0] == "ok"

    asyncio.run(go())


def test_an_error_reply_names_no_details(monkeypatch: pytest.MonkeyPatch, fresh_limits) -> None:
    async def broken(*args, **kwargs):
        raise OSError("C:\\secret\\path http://192.168.1.10:8080")

    monkeypatch.setattr(b, "answer", broken)
    reply = asyncio.run(b.safe_answer(1, 7, "w", "x", []))[0]
    assert "secret" not in reply and "192" not in reply and "OSError" in reply
    assert 7 not in b.busy_users


def test_at_most_three_questions_at_once(monkeypatch: pytest.MonkeyPatch, fresh_limits) -> None:
    active, peak = 0, 0

    async def count(channel_id, author, prompt, files, context=""):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.05)
        active -= 1
        return "ok", []

    monkeypatch.setattr(b, "answer", count)

    async def go():
        return await asyncio.gather(*(b.safe_answer(1, 100 + i, "u", "q", []) for i in range(8)))

    replies = asyncio.run(go())
    assert peak == b.MAX_CONCURRENT_QUESTIONS and all(r[0] == "ok" for r in replies)


# --- link previews ----------------------------------------------------------------------------


def test_answers_go_out_without_link_previews(monkeypatch: pytest.MonkeyPatch) -> None:
    flags = []

    async def fake(text=None, **kwargs):
        flags.append(kwargs.get("suppress_embeds"))

    monkeypatch.setattr(b, "MESSAGE_DELAY", 0)
    asyncio.run(b.send_parts(fake, fake, ["one https://example.com/?x=1", "two", "three"], []))
    asyncio.run(b.send_parts(fake, fake, [f"part {i}" for i in range(b.MAX_MESSAGES + 3)], []))
    assert len(flags) == 3 + b.MAX_MESSAGES and all(flags)
