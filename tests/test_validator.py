"""Tests for the validator's answer handling and session bookkeeping.

No Ollama involved: answer parsing is pure, and the session flow is driven
through a stubbed transport.
"""

import pytest

import app.validator as validator
from app.validator import _classify, _fingerprint, _near_duplicate_id, _read_answer

BATCH_IDS = {1}


def test_valid_id_is_a_duplicate():
    reading = _read_answer(
        '{"closest": 1, "duplicate_of": 1, "reason": "same result"}', BATCH_IDS
    )
    assert (reading.kind, reading.entry_id) == ("duplicate", 1)


def test_null_ids_are_clean():
    reading = _read_answer(
        '{"closest": null, "duplicate_of": null, "reason": "adds new evidence"}',
        BATCH_IDS,
    )
    assert reading.kind == "clean"


def test_hedged_answer_goes_to_recheck_not_reject():
    # closest names a finding but duplicate_of is null: the model hedged.
    # Must NOT auto-reject and must NOT silently accept: "unclear".
    reading = _read_answer(
        '{"closest": 1, "duplicate_of": null, "reason": "both mention the file"}',
        BATCH_IDS,
    )
    assert (reading.kind, reading.entry_id) == ("unclear", 1)


def test_contradictory_answer_goes_to_recheck_not_reject():
    # a real qwen3:0.6b shape: ok true, but the reason names the finding.
    reading = _read_answer(
        '{ "ok": true, "closest": null, "reason": "the content covers the '
        'same knowledge as existing finding [#1]." }',
        BATCH_IDS,
    )
    assert (reading.kind, reading.entry_id) == ("unclear", 1)


def test_duplicate_claim_without_id_goes_to_recheck():
    reading = _read_answer(
        '{"closest": null, "duplicate": true, "reason": "same as [#1] but reworded"}',
        BATCH_IDS,
    )
    assert (reading.kind, reading.entry_id) == ("unclear", 1)


def test_invented_id_is_not_trusted():
    reading = _read_answer(
        '{"closest": null, "duplicate_of": 99, "reason": "same"}', BATCH_IDS
    )
    assert reading.kind == "clean"


def test_bare_hash_numbers_are_not_references():
    # ports, issue numbers, offsets: only [#id] counts, so this stays clean
    reading = _read_answer(
        '{"closest": null, "duplicate_of": null, '
        '"reason": "adds the offset from issue #12 on port #8080"}',
        BATCH_IDS,
    )
    assert reading.kind == "clean"


def test_unknown_bracket_reference_is_ignored():
    reading = _read_answer(
        '{"closest": null, "duplicate_of": null, '
        '"reason": "see also [#42] which is unrelated"}',
        BATCH_IDS,
    )
    assert reading.kind == "clean"


def test_empty_object_raises():
    with pytest.raises(ValueError):
        _read_answer("{\n\n}", BATCH_IDS)


def test_unparsable_answer_raises():
    with pytest.raises(ValueError):
        _read_answer("not json", BATCH_IDS)


def test_near_identical_text_is_caught():
    candidate = {"title": "libc leak", "content": "the libc base leaks via /api/export " * 5}
    existing = [
        {
            "id": 7,
            "type": "finding",
            "title": "LIBC LEAK",
            "content": "the libc base leaks via /api/export " * 5,
        }
    ]
    assert _near_duplicate_id(candidate, existing) == 7


def test_different_text_is_not_near_duplicate():
    candidate = {"title": "libc leak", "content": "one_gadget 0x4f3c5 works on this build"}
    existing = [{"id": 7, "type": "finding", "title": "libc leak", "content": "base leaks"}]
    assert _near_duplicate_id(candidate, existing) is None


def _entry(eid, text):
    return {"id": eid, "type": "finding", "title": f"t{eid}", "content": text}


def test_classify_same_added_stale():
    base = {1: "aa", 2: "bb"}
    assert _classify(base, dict(base)) == "same"
    assert _classify(base, {**base, 3: "cc"}) == "added"
    assert _classify(base, {1: "aa", 2: "CHANGED"}) == "stale"
    assert _classify(base, {1: "aa"}) == "stale"


def test_fingerprint_stable_and_text_sensitive():
    a = _fingerprint([_entry(1, "hello world")])
    assert a == _fingerprint([_entry(1, "hello world")])
    assert a != _fingerprint([_entry(1, "hello world!")])


class _StubTransport:
    """Scripted /api/chat answers; records the messages of every call."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, messages, schema):
        self.calls.append(messages)
        content = self.answers.pop(0)
        return {"message": {"content": content}}


@pytest.fixture
def stub(monkeypatch):
    transport = _StubTransport([])
    monkeypatch.setattr(validator, "_chat", transport)
    monkeypatch.setenv("HUB_VALIDATE", "1")
    monkeypatch.setenv("HUB_VALIDATE_CONFIRM", "1")
    validator._sessions.clear()
    return transport


def _cand(text="brand new technique never seen"):
    return {"title": "c", "content": text, "challenge_id": "chall-x"}


def test_second_call_reuses_session_with_delta(stub):
    existing = [_entry(1, "first finding about the login form")]
    stub.answers = ['{"closest": null, "duplicate_of": null, "reason": "new area"}']
    v1 = validator.validate_finding(_cand(), existing)
    assert v1.ok is True
    assert len(stub.calls) == 1
    first_prompt = stub.calls[0][-1]["content"]
    assert "[#1]" in first_prompt  # full state on first contact

    existing.append(_entry(2, "second finding about the upload form"))
    stub.answers = ['{"closest": null, "duplicate_of": null, "reason": "still new"}']
    v2 = validator.validate_finding(_cand(), existing)
    assert v2.ok is True
    assert len(stub.calls) == 2
    second_prompt = stub.calls[1][-1]["content"]
    assert "since your last look" in second_prompt
    assert "[#2]" in second_prompt  # only the newcomer is re-sent...
    assert "first finding about the login form" not in second_prompt  # ...old text is memory


def test_edited_finding_resets_session(stub):
    existing = [_entry(1, "first finding about the login form")]
    stub.answers = ['{"closest": null, "duplicate_of": null, "reason": "new area"}']
    assert validator.validate_finding(_cand(), existing).ok is True

    edited = [_entry(1, "first finding COMPLETELY REWRITTEN")]
    stub.answers = ['{"closest": null, "duplicate_of": null, "reason": "new area"}']
    assert validator.validate_finding(_cand(), edited).ok is True
    resent = stub.calls[1][-1]["content"]
    assert "Team findings so far" in resent  # full state, not a delta
    assert "COMPLETELY REWRITTEN" in resent


def test_unclear_answer_is_resolved_by_recheck(stub):
    existing = [_entry(1, "look for the file flag-12345.txt on the server")]
    stub.answers = [
        '{"closest": 1, "duplicate_of": null, "reason": "both are about flag-12345.txt"}',
        '{"same": true, "reason": "the find completes the look"}',
    ]
    verdict = validator.validate_finding(
        {
            "title": "c",
            "content": "we found this stuff flag-12345.txt",
            "challenge_id": "chall-x",
        },
        existing,
    )
    assert verdict.ok is False
    assert verdict.duplicate_of == 1
    assert len(stub.calls) == 2  # judge + yes/no re-check
