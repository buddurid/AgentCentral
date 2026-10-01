"""AI validation of new findings using a local Ollama model.

Before a `finding` is persisted, it is checked for being a duplicate, stale,
erroneous or malformed. The judgement is made by a local Ollama model rather
than by fixed rules, so it can reason about meaning instead of matching strings.

Configuration (environment variables):

    HUB_VALIDATE=0          disable validation entirely (default: enabled)
    HUB_OLLAMA_URL=...      Ollama base URL (default http://localhost:11434)
    HUB_OLLAMA_MODEL=...    model name (default llama3.1)
    HUB_OLLAMA_TIMEOUT=30   request timeout in seconds

If Ollama is unreachable, returns an error or gives unusable output, the entry
is accepted (fail-open) so the hub keeps working. Validation never raises.

NOTE: the exact rules below are a placeholder and will be replaced.
"""

import json
import os
from dataclasses import dataclass

import httpx

OLLAMA_URL = os.environ.get("HUB_OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("HUB_OLLAMA_MODEL", "llama3.1")

MAX_EXISTING = 30
MAX_EXISTING_CHARS = 500

# ---------------------------------------------------------------------------
# RULES (exact rejection criteria)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You validate findings for a shared CTF research notebook. You are given a "
    "CANDIDATE finding and the EXISTING entries of the same challenge. "
    "Only validated entries become confirmed findings. Unconfirmed notes are "
    "separate and not the focus.\n\n"
    "Reject the candidate if it matches any category below:\n"
    '- "duplicate": repeats knowledge already covered by existing entries, even '
    "if paraphrased or rephrased. Look for the same fact/primitive/observation.\n"
    '- "stale": outdated, superseded, or no longer true given existing entries '
    "(e.g. a path previously ruled out or a value that changed).\n"
    '- "erroneous": factually wrong, self-contradictory, unproven or clearly '
    "unsupported by evidence presented.\n"
    '- "malformed": not a usable research note (empty, gibberish, unrelated to '
    "the challenge, or is process/agent state like prompts, plans, session logs).\n\n"
    "Accept it otherwise (new, useful, non-duplicative knowledge). Keep reasons "
    "short and specific.\n\n"
    "Respond with ONLY a JSON object, no extra text:\n"
    '{"ok": true, "category": "none", "reason": "<brief reason>"}\n'
    'Set "ok": false and use one of "duplicate","stale","erroneous","malformed" '
    'for "category"; when ok is true, category may be "none".'
)


@dataclass
class Verdict:
    ok: bool
    category: str | None = None
    reason: str = ""


def _enabled() -> bool:
    return os.environ.get("HUB_VALIDATE", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _timeout() -> float:
    return float(os.environ.get("HUB_OLLAMA_TIMEOUT", "30"))


def _existing_text(existing: list[dict]) -> str:
    if not existing:
        return "(none)"
    lines = []
    for entry in existing[:MAX_EXISTING]:
        content = (entry.get("content") or "")[:MAX_EXISTING_CHARS]
        lines.append(
            f"- [{entry.get('type')}/{entry.get('status')}] "
            f"{entry.get('title')}: {content}"
        )
    return "\n".join(lines)


def validate_finding(candidate: dict, existing: list[dict]) -> Verdict:
    """Return a Verdict for a candidate `finding`. Never raises."""
    if not _enabled():
        print("validation disabled")
        return Verdict(ok=True, reason="validation disabled")

    user_message = (
        "CANDIDATE\n"
        f"title: {candidate.get('title', '')}\n"
        f"author: {candidate.get('author', '')}\n"
        f"content: {candidate.get('content', '')}\n\n"
        "EXISTING ENTRIES\n"
        f"{_existing_text(existing)}"
    )

    try:
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
                        {"role": "user", "content": user_message},
                    ],
                },
            )
            response.raise_for_status()
            content = response.json()["message"]["content"]
        data = json.loads(content)
        return Verdict(
            ok=bool(data.get("ok", True)),
            category=data.get("category") or None,
            reason=str(data.get("reason", "")),
        )
    except Exception as exc:  # noqa: BLE001 - validation must never break the hub
        return Verdict(ok=True, reason=f"validator unavailable, accepted: {exc}")
