"""Tests for Aegis Tier-B LLM review.

Covers:
* Prompt construction (task body, comments, result get into the user message).
* JSON parsing — clean, fenced, prefixed, malformed.
* Verdict normalisation — APPROVED/REJECTED happy paths, unknown verdicts
  forced to REJECTED, confidence clamped to [0,1].
* End-to-end happy path with a stubbed LLM.
* Error paths: missing task, LLM call raises, malformed reply shape.
* The stub never makes a network call (call_llm_fn is injected).
"""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from plugins.aegis_attestation.llm_review import (
    LLMReviewResult,
    VERDICT_APPROVED,
    VERDICT_ERROR,
    VERDICT_REJECTED,
    _build_user_prompt,
    _normalize_verdict,
    _parse_llm_reply,
    review_task,
)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def test_build_user_prompt_includes_body_and_comments():
    task = {"id": "t_abc", "title": "Test", "body": "Do X to acceptance Y"}
    comments = [
        {"author": "worker", "body": "step 1 done", "created_at": 1000},
        {"author": "worker", "body": "step 2 done", "created_at": 2000},
    ]
    out = _build_user_prompt(task, comments, "final summary")
    assert "t_abc" in out
    assert "Do X to acceptance Y" in out
    assert "step 1 done" in out
    assert "step 2 done" in out
    assert "final summary" in out
    assert "Worker comments (2 total" in out


def test_build_user_prompt_truncates_long_inputs():
    task = {"id": "t", "title": "T", "body": "B"}
    long_comment = "x" * 5000
    out = _build_user_prompt(
        task, [{"author": "w", "body": long_comment, "created_at": 0}], "y" * 5000
    )
    assert "…[truncated]" in out
    # Comment cap is ~600; result cap is ~2000. Both should be active.
    assert out.count("…[truncated]") == 2


def test_build_user_prompt_handles_missing_body():
    out = _build_user_prompt({"id": "t", "title": "T"}, [], None)
    assert "(no body)" in out
    # No "Worker comments" section when comments empty
    assert "Worker comments" not in out


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

def test_parse_clean_json():
    s = '{"verdict": "APPROVED", "feedback": "ok", "confidence": 0.9}'
    out = _parse_llm_reply(s)
    assert out["verdict"] == "APPROVED"


def test_parse_fenced_json():
    s = '```json\n{"verdict": "REJECTED", "feedback": "no"}\n```'
    out = _parse_llm_reply(s)
    assert out["verdict"] == "REJECTED"


def test_parse_json_with_preamble():
    s = (
        "Here is my review:\n\n"
        '{"verdict": "APPROVED", "feedback": "looks good", "confidence": 0.8}\n'
        "\nThat's my call."
    )
    out = _parse_llm_reply(s)
    assert out["verdict"] == "APPROVED"
    assert out["confidence"] == 0.8


def test_parse_empty_raises():
    with pytest.raises(ValueError, match="empty"):
        _parse_llm_reply("")


def test_parse_no_json_raises():
    with pytest.raises(ValueError, match="no JSON object"):
        _parse_llm_reply("just words, no braces")


# ---------------------------------------------------------------------------
# Verdict normalisation
# ---------------------------------------------------------------------------

def test_normalize_approved_happy():
    r = _normalize_verdict({
        "verdict": "APPROVED", "feedback": "good", "confidence": 0.9
    })
    assert r.verdict == VERDICT_APPROVED
    assert r.confidence == 0.9
    assert r.feedback == "good"


def test_normalize_rejected_happy():
    r = _normalize_verdict({
        "verdict": "rejected", "feedback": "missing X", "confidence": 0.6
    })
    assert r.verdict == VERDICT_REJECTED


def test_normalize_unknown_verdict_forced_to_rejected():
    """Safety: anything not APPROVED/REJECTED is REJECTED."""
    r = _normalize_verdict({"verdict": "MAYBE", "feedback": "..."})
    assert r.verdict == VERDICT_REJECTED
    assert "unparseable verdict" in r.feedback
    assert r.confidence == 0.0


def test_normalize_clamps_confidence():
    r = _normalize_verdict({
        "verdict": "APPROVED", "feedback": "ok", "confidence": 2.5
    })
    assert r.confidence == 1.0
    r2 = _normalize_verdict({
        "verdict": "APPROVED", "feedback": "ok", "confidence": -0.3
    })
    assert r2.confidence == 0.0


def test_normalize_handles_garbage_confidence():
    r = _normalize_verdict({
        "verdict": "APPROVED", "feedback": "ok", "confidence": "high"
    })
    assert r.confidence == 0.0  # safe default


# ---------------------------------------------------------------------------
# End-to-end review_task (with stubbed LLM)
# ---------------------------------------------------------------------------

@pytest.fixture
def kanban_conn(tmp_path):
    """A minimal in-memory kanban schema with tasks + comments tables."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE tasks (
            id TEXT PRIMARY KEY,
            title TEXT,
            body TEXT,
            status TEXT,
            result TEXT
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT,
            author TEXT,
            body TEXT,
            created_at INTEGER
        );
        """
    )
    db.execute(
        "INSERT INTO tasks (id, title, body, status, result) VALUES (?, ?, ?, ?, ?)",
        ("t_real", "Sample", "Do X. Acceptance: Y.", "done", "produced X via method Z"),
    )
    db.execute(
        "INSERT INTO comments (task_id, author, body, created_at) VALUES (?, ?, ?, ?)",
        ("t_real", "worker-a", "step 1 done", 1000),
    )
    db.commit()
    return db


def _stub_llm(reply_text: str, raise_exc: Exception = None):
    """Build a call_llm_fn stub that returns the given reply or raises."""
    def stub(**kw):
        if raise_exc is not None:
            raise raise_exc
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply_text))],
            usage=SimpleNamespace(input_tokens=100, output_tokens=50),
            model="stub-model",
        )
    return stub


def test_review_task_happy_approved(kanban_conn):
    stub = _stub_llm(
        '{"verdict": "APPROVED", "feedback": "fully addresses Y", "confidence": 0.85}'
    )
    out = review_task(kanban_conn, "t_real", call_llm_fn=stub)
    assert out.verdict == VERDICT_APPROVED
    assert out.confidence == 0.85
    assert out.task_id == "t_real"
    assert out.tokens_used == 150
    assert out.model == "stub-model"
    assert out.duration_sec is not None and out.duration_sec >= 0


def test_review_task_rejected_with_feedback(kanban_conn):
    stub = _stub_llm(
        '{"verdict": "REJECTED", "feedback": "criterion Y not evidenced", "confidence": 0.7}'
    )
    out = review_task(kanban_conn, "t_real", call_llm_fn=stub)
    assert out.verdict == VERDICT_REJECTED
    assert "criterion Y" in out.feedback


def test_review_task_missing_task(kanban_conn):
    stub = _stub_llm('{"verdict": "APPROVED", "feedback": "x"}')
    out = review_task(kanban_conn, "t_missing", call_llm_fn=stub)
    assert out.verdict == VERDICT_ERROR
    assert out.error == "task-not-found"


def test_review_task_llm_exception(kanban_conn):
    stub = _stub_llm("", raise_exc=RuntimeError("upstream 503"))
    out = review_task(kanban_conn, "t_real", call_llm_fn=stub)
    assert out.verdict == VERDICT_ERROR
    assert out.error and "RuntimeError" in out.error
    assert "503" in out.feedback


def test_review_task_malformed_reply_shape(kanban_conn):
    """LLM returns wrong-shaped response object → ERROR, not crash."""
    def bad_stub(**kw):
        return SimpleNamespace()  # no .choices
    out = review_task(kanban_conn, "t_real", call_llm_fn=bad_stub)
    assert out.verdict == VERDICT_ERROR
    assert out.error == "malformed-reply"


def test_review_task_unparseable_json_reply(kanban_conn):
    """LLM returns prose, no JSON → ERROR with parse-failed marker."""
    stub = _stub_llm("Honestly the work is fine I think, ship it.")
    out = review_task(kanban_conn, "t_real", call_llm_fn=stub)
    assert out.verdict == VERDICT_ERROR
    assert out.error == "parse-failed"


def test_review_task_acceptance_check_passthrough(kanban_conn):
    """The acceptance_check list field round-trips from reply to result."""
    stub = _stub_llm(json_dump_compact({
        "verdict": "REJECTED",
        "feedback": "see breakdown",
        "confidence": 0.55,
        "acceptance_check": [
            {"criterion": "produces X", "passed": True, "evidence": "comment#1"},
            {"criterion": "covers Y", "passed": False, "evidence": "nothing addresses Y"},
        ],
    }))
    out = review_task(kanban_conn, "t_real", call_llm_fn=stub)
    assert out.verdict == VERDICT_REJECTED
    assert len(out.acceptance_check) == 2
    assert out.acceptance_check[1]["passed"] is False


def json_dump_compact(obj):
    import json as _json
    return _json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------------------
# as_dict round-trip
# ---------------------------------------------------------------------------

def test_result_as_dict_is_json_serializable():
    import json as _json
    r = LLMReviewResult(verdict=VERDICT_APPROVED, feedback="ok", confidence=0.9)
    d = r.as_dict()
    s = _json.dumps(d)
    parsed = _json.loads(s)
    assert parsed["verdict"] == VERDICT_APPROVED
    assert parsed["confidence"] == 0.9
