"""Duplicate check for new findings, using a local Ollama model.

A new finding is rejected when the team already has that knowledge: the same
conclusion, observation, or leak, even when the wording, names, endpoint or
payload differ. The comparison is semantic (a model, not string matching) and
is scoped to the findings of the *same* challenge.

Only confirmed findings are used as the comparison set. An `unconfirmed` note
or a `dead_end` is not a duplicate of a finding: rejecting a finding because an
unverified note said something similar would throw the knowledge away.

One conversation per challenge
------------------------------
The backend keeps a session per challenge: a single ongoing Ollama conversation
that lists every finding, newest last. Each validation appends one turn -
either the new findings plus the judgement question, or just the question when
nothing changed - so the model keeps the general context instead of starting
from zero every time. Sessions live in memory and are rebuilt after a restart.

A session is only valid while it matches the database. Each call compares the
stored fingerprint (id -> content hash) with the current findings:

- same: nothing changed, the question alone is asked;
- added: only new findings appeared, they are told to the model with the question;
- stale: something was edited or deleted, the session is reset with the full list.

If even the full list does not fit the history budget, that call falls back to
stateless judging (one fresh chat per batch, nothing stored).

How a candidate is decided (in order):

1. Near-identical text (normalized similarity >= 0.9) to an existing finding
   is rejected outright, with no model call.
2. The judge answers {"closest": <id or null>, "duplicate_of": <id or null>,
   "reason": "..."} against everything the session knows - a single turn,
   since the full list is already in the conversation. Only a valid id in
   `duplicate_of` counts as a duplicate.
3. A contradictory or vague judge answer is *not* trusted. The named pair is
   re-asked with a short yes/no question, and its answer decides. A clean
   answer whose prose still mentions a shared distinctive token (the model
   saying "same thing" while outputting null) goes to the re-check too.
4. Only a confirmed duplicate rejects the candidate.

Small models contradict themselves, so a rejection always names a real
finding id and always passes the yes/no re-check on that one pair. With a
capable model the judge's id is usually right first time and the re-check
just confirms it.

Configuration (environment variables, read per call):

    HUB_VALIDATE=0            disable validation entirely (default: enabled)
    HUB_OLLAMA_URL=...        Ollama base URL (default http://localhost:11434)
    HUB_OLLAMA_MODEL=...      model name (default llama3.1)
    HUB_OLLAMA_TIMEOUT=30     request timeout in seconds
    HUB_OLLAMA_CTX=8192       model context window requested
    HUB_VALIDATE_BATCH=25     findings judged per turn (stateless fallback)
    HUB_VALIDATE_CONFIRM=1    re-check a duplicate before dropping it
    HUB_VALIDATE_HISTORY=16000  max stored conversation chars per challenge
    HUB_VALIDATE_MAX_CHARS=2000   max characters kept per entry
    HUB_VALIDATE_DEBUG=0      print every model answer

The judge schema is sent as Ollama structured output with thinking switched
off. On HTTP 400 the request steps down (schema+no-think, schema, plain json)
and remembers where it landed. An unusable answer is a validator failure, not
a verdict: the candidate is accepted (fail-open) so the hub keeps working.
Validation never raises.
"""

import difflib
import hashlib
import json
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_BATCH = 25
DEFAULT_MAX_CHARS = 2000
DEFAULT_HISTORY_CHARS = 16000
DEFAULT_CTX = 8192
MAX_SESSIONS = 200
NEAR_DUP_RATIO = 0.9
NEAR_DUP_MIN_CHARS = 60

# Common English words carry no signal about sameness.
STOPWORDS = frozenset(
    "the a an and or of to in on for with is are was were be been this that "
    "these those it its as at by from we you they he she him her our your "
    "not no so do does did can will just about into over after before up out "
    "all any more most other some such only own same than too very can will "
    "should would could there here when where which who whom what how why "
    "look looks looked looking see found find finds get got gets let lets "
    "like use used using stuff thing things".split()
)

_COMPOUND_RE = re.compile(r"[a-z0-9]+(?:[._/\-][a-z0-9]+)+")
_SIMPLE_RE = re.compile(r"[a-z0-9]{3,}")

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "closest": {"type": ["integer", "null"]},
        "duplicate_of": {"type": ["integer", "null"]},
        "reason": {"type": "string"},
    },
    "required": ["closest", "duplicate_of", "reason"],
}

CONFIRM_SCHEMA = {
    "type": "object",
    "properties": {
        "same": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["same", "reason"],
}

SYSTEM_PROMPT = (
    "You track what a CTF team already knows about one challenge. Our "
    "conversation lists every finding, newest last. New findings arrive over "
    "time; you never forget the old ones.\n\n"
    "Now judge ONE candidate finding. Answer with ONLY this JSON:\n"
    '{"closest": <id or null>, "duplicate_of": <id or null>, '
    '"reason": "<one short sentence>"}\n\n'
    'First pick "closest": the existing finding about the same thing as the '
    "candidate - the same file, secret, endpoint or bug. If none is about the "
    "same thing at all, closest is null.\n\n"
    'Then decide "duplicate_of":\n'
    "- It IS a duplicate when it states the same result as the closest "
    "finding: the same conclusion, observation or leak - even reworded, even "
    "with different names or payloads.\n"
    '- A finding that says "look for X / try X" and a candidate that reports '
    '"found X / X works" are the SAME result when X is the same thing. The '
    "candidate adds nothing: the team already knew to look there.\n"
    "- It is NOT a duplicate when it is about something else, or adds a new "
    "endpoint, technique, step, correction, or evidence the existing finding "
    "lacks.\n\n"
    "Rules: write ids as plain numbers. If duplicate_of is an id, or if your "
    "reason says the candidate is the same as some finding, closest MUST be "
    "that id. If the candidate is new, closest MUST be null.\n\n"
    "Example - duplicate:\n"
    'Known: [#4] "we should look for the file flag-12345.txt on the server".\n'
    'Candidate: "we found this stuff flag-12345.txt".\n'
    'Answer: {"closest": 4, "duplicate_of": 4, "reason": "both are about the '
    'file flag-12345.txt, the find completes the look"}\n\n'
    "Example - new:\n"
    'Known: [#4] "we should look for the file flag-12345.txt on the server".\n'
    'Candidate: "the backup archive backup-2024.zip in /var/www holds '
    'credentials".\n'
    'Answer: {"closest": null, "duplicate_of": null, "reason": "a different '
    'file with new credentials"}'
)

CONFIRM_PROMPT = (
    "Look only at these two notes. Does NOTE B state the same result as NOTE "
    "A: the same conclusion, observation or leak, even if worded differently "
    "or with different names? If B only completes what A said to look for, "
    "that is the same result.\n\n"
    'Example: A says "look for the file flag-12345.txt", B says "found '
    'flag-12345.txt" -> {"same": true}.\n\n'
    'Answer with ONLY a JSON object: {"same": true, "reason": "<what both '
    'state>"} or {"same": false, "reason": "<what B adds>"}.'
)

ANSWER_KEYS = (
    '{"closest": <id or null>, "duplicate_of": <id or null>, '
    '"reason": "<one short sentence>"}'
)


@dataclass
class Verdict:
    ok: bool
    category: str | None = None
    reason: str = ""
    duplicate_of: int | None = None


@dataclass
class _Reading:
    """What the judge's answer means: a definite reject, a clean accept, or an
    entry id that needs the yes/no re-check to decide ("unclear")."""

    kind: str  # "duplicate" | "clean" | "unclear"
    entry_id: int | None
    reason: str


@dataclass
class _Session:
    """One ongoing conversation per challenge."""

    messages: list[dict] = field(default_factory=list)
    seen: dict[int, str] = field(default_factory=dict)


_sessions: dict[str, _Session] = {}
_sessions_lock = threading.Lock()
_chat_state: dict[str, Any] = {"url": None, "model": None, "index": None}


def _flag(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _debug() -> bool:
    return _flag("HUB_VALIDATE_DEBUG", "0")


def _warn(message: str) -> None:
    """Always printed. Fail-open must never be silent: an accepted candidate
    that should have been rejected is a leak nobody can see otherwise."""
    print(f"[validator] ACCEPTED ANYWAY: {message}", file=sys.stderr, flush=True)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _ollama_url() -> str:
    return os.environ.get("HUB_OLLAMA_URL", "http://localhost:11434").rstrip("/")


def _ollama_model() -> str:
    return os.environ.get("HUB_OLLAMA_MODEL", "llama3.1")


def _timeout() -> float:
    return float(os.environ.get("HUB_OLLAMA_TIMEOUT", "30"))


def _clip(text: str | None) -> str:
    limit = _int_env("HUB_VALIDATE_MAX_CHARS", DEFAULT_MAX_CHARS)
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + " [...]"


def _normalize(text: str | None) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _entry_text(entry: dict) -> str:
    return f"{entry.get('title', '')}\n{entry.get('content', '')}"


def _tokens(text: str | None) -> list[str]:
    """Distinctive tokens: dotted/hyphenated compounds kept whole
    ("flag-12345.txt", "/api/export"), plus plain words without stopwords."""
    low = (text or "").lower()
    compounds = _COMPOUND_RE.findall(low)
    rest = _COMPOUND_RE.sub(" ", low)
    simples = [t for t in _SIMPLE_RE.findall(rest) if t not in STOPWORDS]
    return compounds + simples


def _token_weight(token: str) -> float:
    """Absolute distinctiveness: digits, length and separators signal a
    filename, secret, endpoint or identifier rather than prose."""
    weight = 1.0
    if any(c.isdigit() for c in token):
        weight += 2.0
    if len(token) >= 8:
        weight += 1.0
    if any(c in token for c in "._/-"):
        weight += 1.0
    return weight


def _links(candidate: dict, findings: list[dict]) -> list[tuple[str, int]]:
    """(token, finding id) for the candidate's link tokens - digit-bearing,
    compound or long tokens - each pointing at a finding containing it.

    Used as a tripwire: when the judge's prose mentions one of these while
    outputting null (the "new finding about the same thing" failure), the
    pair goes to the re-check instead of being accepted.
    """
    cand_tokens = [
        t for t in set(_tokens(_entry_text(candidate))) if _is_link_token(t)
    ]
    cand_tokens.sort(key=lambda t: -_token_weight(t))
    links = []
    for token in cand_tokens:
        for entry in findings:
            eid = entry.get("id")
            if (
                isinstance(eid, int)
                and not isinstance(eid, bool)
                and token in set(_tokens(_entry_text(entry)))
            ):
                links.append((token, eid))
                break
    return links


def _is_link_token(token: str) -> bool:
    return (
        any(c.isdigit() for c in token)
        or any(c in token for c in "._/-")
        or len(token) >= 10
    )


def _history_chars(messages: list[dict]) -> int:
    return sum(len(str(m.get("content", ""))) for m in messages)


def _fingerprint(findings: list[dict]) -> dict[int, str]:
    """Map each finding id to a short hash of its text."""
    out = {}
    for entry in findings:
        eid = entry.get("id")
        if isinstance(eid, bool) or not isinstance(eid, int):
            continue
        text = f"{entry.get('title', '')}\x00{entry.get('content', '')}"
        out[eid] = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    return out


def _classify(seen: dict[int, str], current: dict[int, str]) -> str:
    """Compare the session's memory with the database: "same", "added" (only
    new findings, tell the model about them) or "stale" (edited or deleted,
    the session's memory is wrong and must be reset)."""
    if seen == current:
        return "same"
    if set(current) >= set(seen) and all(current[i] == seen[i] for i in seen):
        return "added"
    return "stale"


def _near_duplicate_id(candidate: dict, findings: list[dict]) -> int | None:
    """Id of a finding whose normalized text is nearly identical, else None.

    Deterministic net for re-posts: works even when the model is unusable.
    The threshold is deliberately high - this only fires on copies, the model
    handles everything semantic.
    """
    text = _normalize(f"{candidate.get('title', '')}\n{candidate.get('content', '')}")
    if len(text) < NEAR_DUP_MIN_CHARS:
        return None
    for entry in findings:
        other = _normalize(f"{entry.get('title', '')}\n{entry.get('content', '')}")
        if len(other) < NEAR_DUP_MIN_CHARS:
            continue
        if difflib.SequenceMatcher(None, text, other).ratio() >= NEAR_DUP_RATIO:
            return entry.get("id")
    return None


def _findings_only(existing: list[dict]) -> list[dict]:
    """The comparison set: the challenge's confirmed findings, newest first."""
    return [e for e in existing if e.get("type") == "finding"]


def _record(entry: dict) -> str:
    return f"[#{entry.get('id')}] {entry.get('title', '')}\n{_clip(entry.get('content'))}"


def _candidate_text(candidate: dict) -> str:
    return (
        "CANDIDATE\n"
        f"title: {candidate.get('title', '')}\n"
        f"author: {candidate.get('author', '')}\n"
        f"content: {_clip(candidate.get('content'))}"
    )


def _fresh_message(candidate: dict, findings: list[dict]) -> str:
    lines = ["Team findings so far, newest last:"]
    lines.extend(_record(e) for e in findings)
    lines += [
        "",
        "Judge this candidate against ALL of them:",
        _candidate_text(candidate),
        "",
        f"Answer with ONLY the JSON: {ANSWER_KEYS}",
    ]
    return "\n".join(lines)


def _delta_message(candidate: dict, new_entries: list[dict]) -> str:
    lines = []
    if new_entries:
        lines.append("New team findings since your last look:")
        lines.extend(_record(e) for e in new_entries)
        lines.append("")
    lines += [
        "Judge this candidate against everything you know from our conversation:",
        _candidate_text(candidate),
        "",
        f"Answer with ONLY the JSON: {ANSWER_KEYS}",
    ]
    return "\n".join(lines)


def _stateless_message(candidate: dict, batch: list[dict]) -> str:
    lines = ["EXISTING FINDINGS FROM THIS CHALLENGE:"]
    lines.extend(_record(e) for e in batch)
    lines += [
        "",
        _candidate_text(candidate),
        "",
        f"Answer with ONLY the JSON: {ANSWER_KEYS}",
    ]
    return "\n".join(lines)


def _pair_message(candidate: dict, entry: dict) -> str:
    return (
        "NOTE A (already in the notebook)\n"
        f"title: {entry.get('title', '')}\n"
        f"content: {_clip(entry.get('content'))}\n\n"
        "NOTE B (proposed finding)\n"
        f"title: {candidate.get('title', '')}\n"
        f"content: {_clip(candidate.get('content'))}"
    )


def _chat(messages: list[dict], schema: dict) -> dict:
    """POST to /api/chat, stepping down on an unsupported request shape.

    Tries structured output without thinking, then structured output, then
    plain JSON. Remembers the working mode per endpoint+model. Raises on any
    failure (including all modes rejected) so the caller can fail open.
    """
    url, model = _ollama_url(), _ollama_model()
    if _chat_state["url"] == url and _chat_state["model"] == model:
        start = _chat_state["index"] or 0
    else:
        start = 0
    modes = (
        {"format": schema, "think": False},
        {"format": schema},
        {"format": "json"},
    )
    for index in range(start, len(modes)):
        with httpx.Client(timeout=_timeout()) as client:
            response = client.post(
                f"{url}/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "options": {
                        "temperature": 0,
                        "num_ctx": _int_env("HUB_OLLAMA_CTX", DEFAULT_CTX),
                    },
                    "messages": messages,
                    **modes[index],
                },
            )
        if response.status_code == 400:
            if _debug():
                print(f"[validator] mode {index} rejected: {response.text[:200]}")
            continue
        response.raise_for_status()
        _chat_state.update({"url": url, "model": model, "index": index})
        return response.json()
    raise ValueError("ollama rejected every request mode")


def _decode(content: str) -> dict:
    try:
        data = json.loads(content)
    except (TypeError, ValueError):
        raise ValueError("model did not answer with JSON")
    if not isinstance(data, dict):
        raise ValueError("model answer was not a JSON object")
    return data


def _valid_id(value: Any, known_ids: set) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value in known_ids else None


def _read_answer(
    content: str, known_ids: set, links: list[tuple[str, int]] | None = None
) -> _Reading:
    """Decide what the judge's answer means. Raises ValueError when the answer
    carries no judgement at all (not a verdict - a validator failure).

    Only a valid id in `duplicate_of` is a definite duplicate. A valid
    `closest` with null `duplicate_of` - or a named [#id] without a usable
    id - is "unclear": the model hedged or contradicted itself, so the named
    pair gets the yes/no re-check. The same tripwire fires when the prose
    mentions a shared distinctive token ("about the same thing as ... holding
    flag-12345.txt") while outputting null: the pair, not the prose, decides.
    Only bracketed [#id] references count, so a port #8080 or an issue #12 in
    a reason can never flip a verdict.
    """
    data = _decode(content)
    reason = str(data.get("reason", "") or "")

    named = [int(n) for n in re.findall(r"\[#(\d+)\]", reason)]
    named = [n for n in named if n in known_ids]

    duplicate_of = _valid_id(data.get("duplicate_of"), known_ids)
    closest = _valid_id(data.get("closest"), known_ids)

    claims_duplicate = (
        data.get("duplicate") is True
        or data.get("is_duplicate") is True
        or data.get("ok") is False
    )

    if duplicate_of is not None:
        if not reason.strip():
            raise ValueError("model named a finding but gave no reason")
        return _Reading("duplicate", duplicate_of, reason)

    if closest is not None or named:
        # hedged ("closest": 4, "duplicate_of": null), contradictory
        # ("ok": true + "same as [#1]") or vague ("duplicate": true, no id):
        # never guess - re-check that pair.
        suspect = closest if closest is not None else named[0]
        return _Reading("unclear", suspect, reason or "model pointed at a finding")

    if claims_duplicate:
        # a duplicate claim with no finding attached cannot be checked
        raise ValueError("model claimed a duplicate without naming a finding")

    if not reason.strip():
        raise ValueError("model answer carried no judgement")

    lowered = reason.lower()
    for token, holder in links or []:
        if holder in known_ids and token in lowered:
            # the prose betrays sameness ("about the same thing as ... holding
            # flag-12345.txt") while the ids say null: re-check, don't accept
            return _Reading("unclear", holder, reason)
    return _Reading("clean", None, reason)


def _ask_confirm(base: list[dict], candidate: dict, entry: dict) -> tuple[bool | None, str, str]:
    """Yes/no re-check of one pair. Returns (verdict, question, answer).

    Verdict True = same result, False = new knowledge, None = no answer
    (caller fails open). The caller records the turn in the session.
    """
    question = _pair_message(candidate, entry)
    try:
        raw = _chat(
            [
                *base,
                {"role": "system", "content": CONFIRM_PROMPT},
                {"role": "user", "content": question},
            ],
            CONFIRM_SCHEMA,
        )
        if _debug():
            print(f"[validator] confirm {_chat_state['index']} {raw}")
        answer = raw["message"]["content"]
        data = _decode(answer)
        same = data.get("same")
        if not isinstance(same, bool):
            if isinstance(data.get("ok"), bool):
                same = not data["ok"]
            elif isinstance(data.get("duplicate"), bool):
                same = data["duplicate"]
            elif isinstance(data.get("is_duplicate"), bool):
                same = data["is_duplicate"]
            else:
                return None, question, answer
        return same, question, answer
    except Exception:  # noqa: BLE001 - no answer is not a rejection
        return None, question, ""


def _session_for(key: str) -> _Session:
    with _sessions_lock:
        session = _sessions.get(key)
        if session is None:
            session = _Session()
            if len(_sessions) >= MAX_SESSIONS:
                _sessions.pop(next(iter(_sessions)))
            _sessions[key] = session
        return session


def _record_turn(
    session: _Session,
    key: str,
    user_message: str,
    answer: str,
    current: dict[int, str],
    sent_ids: set[int],
) -> None:
    """Append a turn and mark exactly the findings whose text it carried.

    Merging (never overwriting) `seen` guarantees every stored finding's text
    reaches the model at least once, even with concurrent validations: an id
    enters `seen` only together with a turn that contains its text.
    """
    with _sessions_lock:
        if _sessions.get(key) is session:
            session.messages.append({"role": "user", "content": user_message})
            session.messages.append({"role": "assistant", "content": answer})
            for eid in sent_ids:
                if eid in current:
                    session.seen[eid] = current[eid]


def validate_finding(candidate: dict, existing: list[dict]) -> Verdict:
    """Return a Verdict for a candidate `finding`. Never raises."""
    if not _flag("HUB_VALIDATE"):
        return Verdict(ok=True, reason="validation disabled")

    findings = _findings_only(existing)
    if not findings:
        return Verdict(ok=True, reason="no existing finding to duplicate")

    by_id = {e.get("id"): e for e in findings}
    current = _fingerprint(findings)
    near = _near_duplicate_id(candidate, findings)
    if near is not None:
        return Verdict(
            ok=False,
            category="duplicate",
            reason=f"near-identical text to existing finding #{near}: {by_id[near].get('title', '')}",
            duplicate_of=near,
        )

    key = str(candidate.get("challenge_id") or candidate.get("challenge") or "")
    history_budget = _int_env("HUB_VALIDATE_HISTORY", DEFAULT_HISTORY_CHARS)
    confirm = _flag("HUB_VALIDATE_CONFIRM")
    size = max(1, _int_env("HUB_VALIDATE_BATCH", DEFAULT_BATCH))
    system = {"role": "system", "content": SYSTEM_PROMPT}
    links = _links(candidate, findings)

    def judge(
        base: list[dict], user_message: str, known_ids: set
    ) -> _Reading:
        raw = _chat([*base, {"role": "user", "content": user_message}], JUDGE_SCHEMA)
        if _debug():
            print(f"[validator] {_chat_state['index']} {raw}")
        content = raw["message"]["content"]
        reading = _read_answer(content, known_ids, links)
        return reading, content

    def decide(entry_id: int, reason: str, base: list[dict]) -> Verdict | None:
        """Confirm one suspect pair. Returns a rejection, or None to keep
        looking (re-check disagreed or gave no answer)."""
        entry = by_id.get(entry_id)
        if entry is None:  # cannot happen, but never drop on confusion
            return None
        if confirm:
            same, question, answer = _ask_confirm(base, candidate, entry)
            if answer:
                _record_turn(session, key, question, answer, current, set())
                base = list(session.messages)
            if same is not True:
                _warn(
                    f"judge pointed at #{entry_id} ({reason!r}) but the re-check "
                    f"said {'different' if same is False else 'nothing'} - "
                    f"candidate {candidate.get('title', '')!r} accepted"
                )
                return None
        return Verdict(
            ok=False,
            category="duplicate",
            reason=reason or f"same knowledge as existing finding #{entry_id}",
            duplicate_of=entry_id,
        )

    try:
        session = _session_for(key)
        with _sessions_lock:
            state = _classify(session.seen, current)
            history = list(session.messages)
            seen_now = dict(session.seen)

        fresh_message = _fresh_message(candidate, findings)
        if len(fresh_message) > history_budget or not history or state == "stale":
            # (re)start the conversation with the full list
            if len(fresh_message) > history_budget:
                return _validate_stateless(
                    candidate, findings, by_id, size, system, judge, decide
                )
            with _sessions_lock:
                if _sessions.get(key) is session:
                    session.messages = [system]
                    session.seen = {}
            base: list[dict] = [system]
            user_message = fresh_message
            sent_ids = set(current)
        else:
            base = history
            new_entries = [e for e in findings if e.get("id") not in seen_now]
            user_message = _delta_message(candidate, new_entries)
            sent_ids = {e.get("id") for e in new_entries}

        # The judge decides against everything the session knows - a single
        # turn, since the full list is already in the conversation.
        reading, answer = judge(base, user_message, set(by_id))
        _record_turn(session, key, user_message, answer, current, sent_ids)
        base = list(session.messages)

        if reading.kind != "clean":
            verdict = decide(reading.entry_id, reading.reason, base)
            if verdict is not None:
                return verdict

        return Verdict(
            ok=True,
            reason=f"new knowledge, not covered by {len(findings)} existing finding(s)",
        )
    except Exception as exc:  # noqa: BLE001 - never break the hub
        reason = f"validator unavailable, accepted: {exc}"
        _warn(f"{reason} (challenge {key!r}, candidate {candidate.get('title', '')!r})")
        return Verdict(ok=True, reason=reason)


def _validate_stateless(
    candidate: dict,
    findings: list[dict],
    by_id: dict,
    size: int,
    system: dict,
    judge,
    decide,
) -> Verdict:
    """Fallback when the full state does not fit the history budget: one fresh
    chat per batch, nothing stored."""
    compared = 0
    for start in range(0, len(findings), size):
        batch = findings[start : start + size]
        reading, _ = judge(
            [system],
            _stateless_message(candidate, batch),
            {e.get("id") for e in batch},
        )
        compared += len(batch)
        if reading.kind == "clean":
            continue
        verdict = decide(reading.entry_id, reading.reason, [system])
        if verdict is not None:
            return verdict
    return Verdict(
        ok=True, reason=f"new knowledge, not covered by {compared} existing finding(s)"
    )
