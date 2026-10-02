"""Duplicate check for new findings, using a local Ollama model.

A new finding is rejected when the team already has that knowledge: the same
conclusion, observation, primitive or exploit-chain link, even when the wording,
variable names, endpoint, offset or payload differ. The comparison is semantic
(a model, not string matching) and is scoped to the findings of the *same*
challenge.

Only confirmed findings are used as the comparison set. An `unconfirmed` note
or a `dead_end` is not a duplicate of a finding: the finding still adds
something, and suppressing it would throw the knowledge away.

Configuration (environment variables, read at call time):

    HUB_VALIDATE=0            disable validation entirely (default: enabled)
    HUB_OLLAMA_URL=...        Ollama base URL (default http://localhost:11434)
    HUB_OLLAMA_MODEL=...      model name (default llama3.1)
    HUB_OLLAMA_TIMEOUT=30     request timeout in seconds
    HUB_VALIDATE_BATCH=25     existing findings per model call
    HUB_VALIDATE_CONFIRM=1    re-check a rejection before dropping it
    HUB_VALIDATE_MAX_CHARS=2000   max characters kept per entry
    HUB_VALIDATE_DEBUG=0      print every model answer

Existing findings are compared in batches; if any batch reports a duplicate the
candidate is rejected. If Ollama is unreachable, errors, or answers with unusable
output the candidate is accepted (fail-open) so the hub keeps working.
Validation never raises.
"""

import json
import os
import re
from dataclasses import dataclass

import httpx

OLLAMA_URL = os.environ.get("HUB_OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("HUB_OLLAMA_MODEL", "llama3.1")

DEFAULT_BATCH = 25
DEFAULT_MAX_CHARS = 2000

# The model is not asked for a boolean, only for the id of the finding that
# already covers the candidate. The schema is sent to Ollama as structured
# output, so the two keys cannot go missing (a thinking model asked for plain
# JSON happily answers "{}").
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "duplicate_of": {"type": ["integer", "null"]},
        "reason": {"type": "string"},
    },
    "required": ["duplicate_of", "reason"],
}

# Preferred first: structured output and no thinking. Ollama answers 400 when the
# server or the model does not support one of them, so we step down until one
# works and remember where we landed.
MODES = (
    {"format": OUTPUT_SCHEMA, "think": False},
    {"format": OUTPUT_SCHEMA},
    {"format": "json"},
)
_mode_index: int | None = None


class _Unsupported(Exception):
    """Ollama rejected the request shape (HTTP 400): try the next mode."""

SYSTEM_PROMPT = (
    "You decide whether a new CTF finding is already known to the team.\n\n"
    "You get a CANDIDATE finding and EXISTING findings from the same challenge, "
    "each labelled with its id like [#7].\n\n"
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
    "The two rules that matter most:\n"
    "1. If your reason says the candidate covers the same knowledge as some "
    "existing finding, duplicate_of MUST be that finding's id. Never null then.\n"
    "2. duplicate_of MUST be null only when the candidate adds knowledge that no "
    "existing finding states.\n\n"
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


@dataclass
class Verdict:
    ok: bool
    category: str | None = None
    reason: str = ""
    duplicate_of: int | None = None


def _enabled() -> bool:
    return _enabled_env("HUB_VALIDATE")


def _enabled_env(name: str) -> bool:
    return os.environ.get(name, "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _timeout() -> float:
    return float(os.environ.get("HUB_OLLAMA_TIMEOUT", "30"))


def _debug() -> bool:
    return os.environ.get("HUB_VALIDATE_DEBUG", "0").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _clip(text: str | None) -> str:
    limit = _int_env("HUB_VALIDATE_MAX_CHARS", DEFAULT_MAX_CHARS)
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + " [...]"


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


def _chat(messages: list[dict]) -> dict:
    """POST to /api/chat, stepping down through MODES on an unsupported request.

    Raises _Unsupported if no mode works; other errors (unreachable, timeout,
    non-400 failure) propagate so the caller can fail open.
    """
    global _mode_index
    start = _mode_index or 0
    for index in range(start, len(MODES)):
        mode = MODES[index]
        with httpx.Client(timeout=_timeout()) as client:
            response = client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "stream": False,
                    "options": {"temperature": 0},
                    "messages": messages,
                    **mode,
                },
            )
        if response.status_code == 400:
            if _debug():
                print(f"[validator] mode {index} rejected: {response.text[:200]}")
            continue
        response.raise_for_status()
        _mode_index = index
        return response.json()
    raise _Unsupported("no supported request mode")


def _ask_model(candidate: dict, batch: list[dict]) -> Verdict:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _user_message(candidate, batch)},
    ]
    raw = _chat(messages)
    if _debug():
        print(f"[validator] {_mode_index} {raw}")
    return _parse(raw["message"]["content"], batch)


def _parse(content: str, batch: list[dict]) -> Verdict:
    """Turn the model's answer into a Verdict.

    A small model cannot be trusted with a boolean: it will happily answer
    "ok": true while the reason says the candidate is the same knowledge as an
    existing finding. So the answer is only treated as a duplicate when it names
    the finding that already covers it - either in `duplicate_of`, or as a "#id"
    reference inside the reason, or by an explicit false/true duplicate flag.
    """
    try:
        data = json.loads(content)
    except (TypeError, ValueError):
        raise ValueError("model did not answer with JSON")
    if not isinstance(data, dict):
        raise ValueError("model answer was not a JSON object")

    reason = str(data.get("reason", "") or "")

    known_ids = {e.get("id") for e in batch}
    mentioned = [int(n) for n in re.findall(r"#(\d+)", reason)]

    duplicate_of = data.get("duplicate_of")
    if isinstance(duplicate_of, bool) or not isinstance(duplicate_of, int):
        duplicate_of = None
    if duplicate_of not in known_ids:
        # the id was left out, or invented: fall back to one named in the reason
        duplicate_of = next((m for m in mentioned if m in known_ids), None)

    says_duplicate = (
        duplicate_of is not None
        or data.get("duplicate") is True
        or data.get("is_duplicate") is True
        or data.get("ok") is False
        or bool(mentioned)
    )
    if says_duplicate and duplicate_of is None:
        # a duplicate of the batch, but it did not say which one
        duplicate_of = batch[0].get("id")

    if not says_duplicate and not reason.strip():
        # "{}" or an empty object carries no judgement at all: treating that as
        # "new knowledge" would let duplicates through, so it is an error
        raise ValueError("model answer carried no judgement")

    return Verdict(
        ok=not says_duplicate,
        category="duplicate" if says_duplicate else None,
        reason=reason,
        duplicate_of=duplicate_of if says_duplicate else None,
    )


def _confirm_duplicate(candidate: dict, entry: dict) -> bool:
    """Second opinion on one candidate/finding pair before dropping it.

    Small models jump at "same" as well. A rejection only counts when a second,
    narrower pass - the candidate against that single finding - agrees. Any
    failure to get an answer counts as "not a duplicate" so real knowledge is
    never lost to a flaky model.
    """
    try:
        return _ask_model(candidate, [entry]).duplicate_of is not None
    except Exception:  # noqa: BLE001 - fail open, keep the entry
        return False


def validate_finding(candidate: dict, existing: list[dict]) -> Verdict:
    """Return a Verdict for a candidate `finding`. Never raises."""
    if not _enabled():
        return Verdict(ok=True, reason="validation disabled")

    findings = _findings_only(existing)
    if not findings:
        return Verdict(ok=True, reason="no existing finding to duplicate")

    size = max(1, _int_env("HUB_VALIDATE_BATCH", DEFAULT_BATCH))
    double_check = _enabled_env("HUB_VALIDATE_CONFIRM")
    compared = 0
    for start in range(0, len(findings), size):
        batch = findings[start : start + size]
        try:
            verdict = _ask_model(candidate, batch)
        except Exception as exc:  # noqa: BLE001 - never break the hub
            return Verdict(
                ok=True,
                reason=f"validator unavailable, accepted: {exc}",
            )
        compared += len(batch)
        if verdict.ok:
            continue

        match = next(
            (e for e in batch if e.get("id") == verdict.duplicate_of), None
        )
        if double_check and (match is None or not _confirm_duplicate(candidate, match)):
            if _debug():
                print(f"[validator] not a duplicate after re-check: {verdict.reason}")
            continue

        return Verdict(
            ok=False,
            category="duplicate",
            reason=verdict.reason
            or f"same knowledge as existing finding #{verdict.duplicate_of}",
            duplicate_of=verdict.duplicate_of,
        )

    return Verdict(
        ok=True, reason=f"new knowledge, not covered by {compared} existing finding(s)"
    )
