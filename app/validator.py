"""Duplicate check for new findings, using a local Ollama model.

A new finding is rejected when the team already has that knowledge: the same
conclusion, observation, primitive or exploit-chain link, even when the wording,
variable names, endpoint, offset or payload differ. The comparison is semantic
(a model, not string matching) and is scoped to the findings of the *same*
challenge.

Only confirmed findings are used as the comparison set. An `unconfirmed` note
or a `dead_end` is not a duplicate of a finding: rejecting a finding because an
unverified note said something similar would throw the knowledge away.

How a candidate is decided (in order):

1. Near-identical text (normalized similarity >= 0.9) to an existing finding
   is rejected outright, with no model call.
2. The model judges each batch of findings and answers
   {"duplicate_of": <id or null>, "reason": "..."}.
   - A valid id means a duplicate; the entry it names is re-checked with a
     short yes/no question before the candidate is dropped.
   - A contradictory or vague answer (e.g. "ok": true while the reason names a
     finding, or a duplicate claim without a usable id) is *not* trusted. The
     named entry is re-checked with the same short yes/no question, and its
     answer decides.
   - A clear "nothing known yet" means the batch is clean.
3. Only a confirmed duplicate rejects the candidate.

Small models contradict themselves, so the verdict is never taken from a
boolean or from prose alone: a rejection always names a real finding id, and
the yes/no re-check confirms that one pair.

Configuration (environment variables, read per call):

    HUB_VALIDATE=0            disable validation entirely (default: enabled)
    HUB_OLLAMA_URL=...        Ollama base URL (default http://localhost:11434)
    HUB_OLLAMA_MODEL=...      model name (default llama3.1)
    HUB_OLLAMA_TIMEOUT=30     request timeout in seconds
    HUB_VALIDATE_BATCH=25     existing findings per judge call
    HUB_VALIDATE_CONFIRM=1    re-check a duplicate before dropping it
    HUB_VALIDATE_MAX_CHARS=2000   max characters kept per entry
    HUB_VALIDATE_DEBUG=0      print every model answer

The judge schema is sent as Ollama structured output with thinking switched
off. On HTTP 400 the request steps down (schema+no-think, schema, plain json)
and remembers where it landed. An unusable answer is a validator failure, not
a verdict: the candidate is accepted (fail-open) so the hub keeps working.
Validation never raises.
"""

import difflib
import json
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_BATCH = 25
DEFAULT_MAX_CHARS = 2000
NEAR_DUP_RATIO = 0.9
NEAR_DUP_MIN_CHARS = 60

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "duplicate_of": {"type": ["integer", "null"]},
        "reason": {"type": "string"},
    },
    "required": ["duplicate_of", "reason"],
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
    "You decide whether a new CTF finding is already known to the team.\n\n"
    "You get a CANDIDATE finding and EXISTING findings from the same challenge. "
    "Each existing finding is labelled with its id like [#7].\n\n"
    "The candidate IS a duplicate when it states the same result as an existing "
    "finding: the same conclusion, the same observation, the same primitive, or "
    "the same link in an exploit chain. That is still true when the wording, "
    "variable names, endpoint, function, offset or payload differ, or when one "
    "is just a paraphrase or a longer version of the other. Compare the result, "
    "not the words.\n\n"
    "The candidate is NOT a duplicate when it states something the team does not "
    "know yet: a different endpoint or code path, a different technique or "
    "primitive, one more link in a chain, a wider or narrower claim, a "
    "correction, or a detail (evidence, payload, output) the existing finding "
    "left out.\n\n"
    "Answer with ONLY a JSON object with these two keys and nothing else:\n"
    '{"duplicate_of": <id of the existing finding that already covers it, or '
    'null>, "reason": "<one short sentence>"}\n\n'
    "Write an existing finding's reference exactly like [#7], including the "
    "brackets. If no existing finding states the candidate's result, "
    "duplicate_of MUST be null and the reason MUST say what is new.\n\n"
    "Example - duplicate:\n"
    'Existing finding [#4]: "the libc base can be read from the buffer returned '
    'by GET /api/export".\n'
    'Candidate: "GET /api/export hands back a pointer to __libc_start_main, so '
    'the libc base leaks from that route".\n'
    'Answer: {"duplicate_of": 4, "reason": "both state that /api/export leaks '
    'the libc base"}\n\n'
    "Example - new knowledge:\n"
    'Existing finding [#4]: "the libc base can be read from the buffer returned '
    'by GET /api/export".\n'
    'Candidate: "the same buffer from GET /api/export also contains a '
    '/bin/sh pointer, one_gadget 0x4f3c5 works on this build".\n'
    'Answer: {"duplicate_of": null, "reason": "adds the /bin/sh pointer and a '
    'working one_gadget offset"}'
)

CONFIRM_PROMPT = (
    "You decide whether two CTF notes state the same result.\n\n"
    "NOTE A is already in the team's notebook. NOTE B is proposed as a new "
    "finding. B is the same result as A only if it states the same conclusion, "
    "observation, primitive or exploit-chain link - even if worded differently "
    "or with different names, endpoints or payloads. If B adds anything A does "
    "not state, it is not the same.\n\n"
    'Answer with ONLY a JSON object: {"same": true, "reason": "<what both '
    'state>"} or {"same": false, "reason": "<what B adds>"}.'
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


def _batch_text(batch: list[dict]) -> str:
    lines = []
    for entry in batch:
        lines.append(
            f"[#{entry.get('id')}] {entry.get('title', '')}\n{_clip(entry.get('content'))}"
        )
    return "\n\n".join(lines)


def _user_message(candidate: dict, batch: list[dict]) -> str:
    challenge = (candidate.get("challenge") or "").strip()
    header = f"CHALLENGE: {challenge}\n\n" if challenge else ""
    return (
        f"{header}CANDIDATE FINDING\n"
        f"title: {candidate.get('title', '')}\n"
        f"author: {candidate.get('author', '')}\n"
        f"content: {_clip(candidate.get('content'))}\n\n"
        "EXISTING FINDINGS FROM THIS CHALLENGE\n"
        f"{_batch_text(batch)}"
    )


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
                    "options": {"temperature": 0},
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


def _read_answer(content: str, known_ids: set) -> _Reading:
    """Decide what the judge's answer means. Raises ValueError when the answer
    carries no judgement at all (not a verdict - a validator failure)."""
    data = _decode(content)
    reason = str(data.get("reason", "") or "")

    named = [int(n) for n in re.findall(r"\[#(\d+)\]", reason)]
    named = [n for n in named if n in known_ids]

    duplicate_of = data.get("duplicate_of")
    if isinstance(duplicate_of, bool) or not isinstance(duplicate_of, int):
        duplicate_of = None
    if duplicate_of is not None and duplicate_of not in known_ids:
        # an id from nowhere cannot be checked against anything
        duplicate_of = None

    claims_duplicate = (
        data.get("duplicate") is True
        or data.get("is_duplicate") is True
        or data.get("ok") is False
    )

    if duplicate_of is not None:
        if not reason.strip():
            raise ValueError("model named a finding but gave no reason")
        return _Reading("duplicate", duplicate_of, reason)

    if named:
        # the model points at a real finding but gives no usable id:
        # contradictory ("ok": true + "same as [#1]") or vague
        # ("duplicate": true, no id). Never guess - re-check that pair.
        return _Reading("unclear", named[0], reason or "model pointed at a finding")

    if claims_duplicate:
        # a duplicate claim with no finding attached cannot be checked
        raise ValueError("model claimed a duplicate without naming a finding")

    if not reason.strip():
        raise ValueError("model answer carried no judgement")
    return _Reading("clean", None, reason)


def _ask_judge(candidate: dict, batch: list[dict]) -> _Reading:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _user_message(candidate, batch)},
    ]
    raw = _chat(messages, JUDGE_SCHEMA)
    if _debug():
        print(f"[validator] {_chat_state['index']} {raw}")
    known_ids = {e.get("id") for e in batch}
    return _read_answer(raw["message"]["content"], known_ids)


def _ask_confirm(candidate: dict, entry: dict) -> bool | None:
    """Yes/no re-check of one pair. True = same result, False = new knowledge,
    None = no answer (caller fails open)."""
    try:
        messages = [
            {"role": "system", "content": CONFIRM_PROMPT},
            {"role": "user", "content": _pair_message(candidate, entry)},
        ]
        raw = _chat(messages, CONFIRM_SCHEMA)
        if _debug():
            print(f"[validator] confirm {_chat_state['index']} {raw}")
        data = _decode(raw["message"]["content"])
        same = data.get("same")
        if not isinstance(same, bool):
            if isinstance(data.get("ok"), bool):
                same = not data["ok"]
            elif isinstance(data.get("duplicate"), bool):
                same = data["duplicate"]
            elif isinstance(data.get("is_duplicate"), bool):
                same = data["is_duplicate"]
            else:
                return None
        return same
    except Exception:  # noqa: BLE001 - no answer is not a rejection
        return None


def validate_finding(candidate: dict, existing: list[dict]) -> Verdict:
    """Return a Verdict for a candidate `finding`. Never raises."""
    if not _flag("HUB_VALIDATE"):
        return Verdict(ok=True, reason="validation disabled")

    findings = _findings_only(existing)
    if not findings:
        return Verdict(ok=True, reason="no existing finding to duplicate")

    by_id = {e.get("id"): e for e in findings}
    near = _near_duplicate_id(candidate, findings)
    if near is not None:
        entry = by_id[near]
        return Verdict(
            ok=False,
            category="duplicate",
            reason=f"near-identical text to existing finding #{near}: {entry.get('title', '')}",
            duplicate_of=near,
        )

    confirm = _flag("HUB_VALIDATE_CONFIRM")
    size = max(1, _int_env("HUB_VALIDATE_BATCH", DEFAULT_BATCH))
    compared = 0
    for start in range(0, len(findings), size):
        batch = findings[start : start + size]
        try:
            reading = _ask_judge(candidate, batch)
        except Exception as exc:  # noqa: BLE001 - never break the hub
            return Verdict(ok=True, reason=f"validator unavailable, accepted: {exc}")
        compared += len(batch)

        if reading.kind == "clean":
            continue

        entry = by_id.get(reading.entry_id)
        if entry is None:  # cannot happen, but never drop on confusion
            continue
        if confirm:
            same = _ask_confirm(candidate, entry)
            if same is not True:
                if _debug():
                    print(f"[validator] re-check disagreed: {reading.reason}")
                continue
        return Verdict(
            ok=False,
            category="duplicate",
            reason=reading.reason or f"same knowledge as existing finding #{reading.entry_id}",
            duplicate_of=reading.entry_id,
        )

    return Verdict(
        ok=True, reason=f"new knowledge, not covered by {compared} existing finding(s)"
    )
