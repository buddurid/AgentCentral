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
    HUB_VALIDATE_MAX_CHARS=2000   max characters kept per entry

Existing findings are compared in batches; if any batch reports a duplicate the
candidate is rejected. If Ollama is unreachable, errors, or answers with unusable
output the candidate is accepted (fail-open) so the hub keeps working.
Validation never raises.
"""

import json
import os
from dataclasses import dataclass

import httpx

OLLAMA_URL = os.environ.get("HUB_OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("HUB_OLLAMA_MODEL", "llama3.1")

DEFAULT_BATCH = 25
DEFAULT_MAX_CHARS = 2000

SYSTEM_PROMPT = (
    "You check whether a new CTF finding is already known to the team.\n\n"
    "You are given a CANDIDATE finding and a list of EXISTING findings from the "
    "same challenge. Reject the candidate only if it is a duplicate.\n\n"
    "It IS a duplicate when it conveys the same knowledge as an existing "
    "finding: the same conclusion, the same observation, the same primitive, or "
    "the same link in an exploit chain. That holds even when the text is worded "
    "differently, paraphrased, translated, uses different variable names, "
    "endpoints, functions, offsets, gadgets or payloads, or is more or less "
    "verbose. Compare meaning and result, never literal strings or titles.\n\n"
    "It is NOT a duplicate when it adds anything new, for example:\n"
    "- a different endpoint, parameter, function or code path\n"
    "- a different technique, primitive, offset, gadget or workaround\n"
    "- an extra link in a chain, or a chain where only one link was known\n"
    "- a broader or narrower claim that extends the existing finding\n"
    "- a correction, refinement or qualification of the existing finding\n"
    "- evidence, a payload or output the existing finding did not have\n"
    "An existing finding may be vague or incomplete; vagueness alone is not a "
    "duplicate.\n\n"
    "Reply with ONLY a JSON object and no other text:\n"
    '{"ok": true, "category": "none", "reason": "<brief reason>"}\n'
    'When it is a duplicate reply ok=false, category="duplicate", reason="<same '
    'knowledge as existing finding #<id>: what it already covers>".'
)


@dataclass
class Verdict:
    ok: bool
    category: str | None = None
    reason: str = ""
    duplicate_of: int | None = None


def _enabled() -> bool:
    return os.environ.get("HUB_VALIDATE", "1").strip().lower() not in (
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


def _ask_model(candidate: dict, batch: list[dict]) -> Verdict:
    with httpx.Client(timeout=_timeout()) as client:
        response = client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _user_message(candidate, batch)},
                ],
            },
        )
        response.raise_for_status()
        print(response.json())  # debug
        data = json.loads(response.json()["message"]["content"])
    duplicate_of = data.get("duplicate_of")
    return Verdict(
        ok=bool(data.get("ok", True)),
        category=data.get("category") or None,
        reason=str(data.get("reason", "")),
        duplicate_of=duplicate_of if isinstance(duplicate_of, int) else None,
    )


def validate_finding(candidate: dict, existing: list[dict]) -> Verdict:
    """Return a Verdict for a candidate `finding`. Never raises."""
    if not _enabled():
        return Verdict(ok=True, reason="validation disabled")

    findings = _findings_only(existing)
    if not findings:
        return Verdict(ok=True, reason="no existing finding to duplicate")

    size = max(1, _int_env("HUB_VALIDATE_BATCH", DEFAULT_BATCH))
    accepted = 0
    for start in range(0, len(findings), size):
        batch = findings[start : start + size]
        try:
            verdict = _ask_model(candidate, batch)
        except Exception as exc:  # noqa: BLE001 - never break the hub
            return Verdict(
                ok=True,
                reason=f"validator unavailable, accepted: {exc}",
            )
        if not verdict.ok:
            return Verdict(
                ok=False,
                category=verdict.category or "duplicate",
                reason=verdict.reason,
                duplicate_of=verdict.duplicate_of,
            )
        accepted += len(batch)

    return Verdict(
        ok=True, reason=f"new knowledge, not covered by {accepted} existing finding(s)"
    )
