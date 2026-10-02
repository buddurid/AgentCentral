"""Tests for the model-answer parser.

These do not talk to Ollama: they check that we do not take a small model's
"ok": true at face value when its answer says the candidate is already known.
"""

import pytest

from app.validator import _parse

BATCH = [{"id": 1, "type": "finding", "title": "test finding", "content": "x"}]


def test_answer_that_says_same_knowledge_is_a_duplicate():
    # a real answer from qwen3:0.6b - ok true, but the reason names the finding
    verdict = _parse(
        '{ "ok": true, "category": "none", "reason": "the content covers the '
        'same knowledge as existing finding #1: what it already covers." }',
        BATCH,
    )
    assert verdict.ok is False
    assert verdict.duplicate_of == 1


def test_duplicate_of_is_used():
    verdict = _parse('{"duplicate_of": 1, "reason": "same result"}', BATCH)
    assert verdict.ok is False
    assert verdict.duplicate_of == 1


def test_null_duplicate_of_accepts():
    verdict = _parse('{"duplicate_of": null, "reason": "adds new evidence"}', BATCH)
    assert verdict.ok is True
    assert verdict.duplicate_of is None


def test_invented_id_is_not_trusted():
    verdict = _parse('{"duplicate_of": 99, "reason": "same"}', BATCH)
    assert verdict.ok is True


def test_unparsable_answer_raises():
    with pytest.raises(ValueError):
        _parse("not json", BATCH)