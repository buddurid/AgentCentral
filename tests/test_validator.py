"""Tests for the validator's answer handling.

No Ollama involved: these check that verdicts are derived soundly from whatever
a (possibly confused) model answered.
"""

import pytest

from app.validator import _near_duplicate_id, _read_answer

BATCH_IDS = {1}


def test_valid_id_is_a_duplicate():
    reading = _read_answer('{"duplicate_of": 1, "reason": "same result"}', BATCH_IDS)
    assert (reading.kind, reading.entry_id) == ("duplicate", 1)


def test_null_id_is_clean():
    reading = _read_answer(
        '{"duplicate_of": null, "reason": "adds new evidence"}', BATCH_IDS
    )
    assert reading.kind == "clean"


def test_contradictory_answer_goes_to_recheck_not_reject():
    # a real qwen3:0.6b answer: ok true, but the reason names the finding.
    # Must NOT auto-reject (old bug) and must NOT silently accept (older bug):
    # it is "unclear", resolved by the yes/no re-check.
    reading = _read_answer(
        '{ "ok": true, "category": "none", "reason": "the content covers the '
        'same knowledge as existing finding [#1]: what it already covers." }',
        BATCH_IDS,
    )
    assert (reading.kind, reading.entry_id) == ("unclear", 1)


def test_duplicate_claim_without_id_goes_to_recheck():
    reading = _read_answer(
        '{"duplicate": true, "reason": "same as [#1] but reworded"}', BATCH_IDS
    )
    assert (reading.kind, reading.entry_id) == ("unclear", 1)


def test_invented_id_is_not_trusted():
    reading = _read_answer('{"duplicate_of": 99, "reason": "same"}', BATCH_IDS)
    assert reading.kind == "clean"


def test_bare_hash_numbers_are_not_references():
    # ports, issue numbers, offsets: only [#id] counts, so this stays clean
    reading = _read_answer(
        '{"duplicate_of": null, "reason": "adds the offset from issue #12 on port #8080"}',
        BATCH_IDS,
    )
    assert reading.kind == "clean"


def test_unknown_bracket_reference_is_ignored():
    reading = _read_answer(
        '{"duplicate_of": null, "reason": "see also [#42] which is unrelated"}',
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
