"""Aegis Tier-B — LLM semantic review on top of Tier-A deterministic attestation.

Tier-A (``attestation.py``) answers: "did the worker write the files they
claimed?" — sha256 + path existence, no opinions.

Tier-B (this module) answers: "did the worker actually solve the task as
specified?" — sends task body, acceptance criteria, worker comments, and
final result to an LLM with a strict reviewer prompt; parses APPROVED /
REJECTED + structured feedback.

Why two tiers:
* Tier-A is cheap (microseconds, deterministic, signable). It catches
  fabricated deliverables. Always run first.
* Tier-B is slower + costs tokens, but catches semantic failures Tier-A
  can't see — wrong content in a real file, off-spec implementation,
  missing acceptance criteria, etc.

Usage: ``review_task(conn, task_id)`` returns an ``LLMReviewResult``.
Verdict ``REJECTED`` means the worker should retry with the feedback;
``APPROVED`` means the work is good to ship; ``ERROR`` means review
itself failed (LLM unreachable, malformed reply) — caller decides whether
to retry the review or treat as inconclusive.

Idempotency: this module does NOT mutate the task. The CLI / MCP layer is
responsible for taking action on the verdict (post a comment, unblock,
re-block with feedback, etc).
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Optional

logger = logging.getLogger("hermes.aegis_attestation.llm_review")

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

VERDICT_APPROVED = "APPROVED"
VERDICT_REJECTED = "REJECTED"
VERDICT_ERROR = "ERROR"


@dataclass
class LLMReviewResult:
    """Structured outcome of one Tier-B review call.

    ``verdict``         APPROVED / REJECTED / ERROR
    ``feedback``        Human-readable explanation. For REJECTED: the
                        concrete gaps the worker must close. For APPROVED:
                        short rationale. For ERROR: failure reason.
    ``confidence``      0.0 .. 1.0 self-reported confidence the LLM has
                        in its verdict. Low confidence + APPROVED is a
                        signal to escalate to a human reviewer.
    ``acceptance_check`` Optional per-criterion pass/fail list when the
                        task body has structured acceptance criteria. Empty
                        when the task didn't enumerate them.
    ``tokens_used``     Approximate cost (input+output) — None when not
                        reported by the provider.
    ``model``           Provider:model string used, for audit.
    """

    verdict: str
    feedback: str
    confidence: float = 0.0
    acceptance_check: list[dict[str, Any]] = field(default_factory=list)
    tokens_used: Optional[int] = None
    model: Optional[str] = None
    duration_sec: Optional[float] = None
    task_id: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are Aegis Tier-B, a strict, no-praise code reviewer for a kanban worker fleet.

Your job: decide whether a worker's completed task actually solves the
specified problem to the standard the task body describes.

Hard rules:
1. Read the FULL task body. Identify acceptance criteria, explicit or
   implicit. If the body is vague ("fix the bug"), use professional
   judgment — but be skeptical of half-measures.
2. Inspect every comment from the worker and the final result. Look for:
   - Skipped steps the brief required
   - Workarounds that don't actually solve the root cause
   - Untested edge cases the brief specifically mentioned
   - Hallucinated artifacts (claims of work that aren't supported by
     comments/files)
   - "Done" decisions made under pressure (iteration budget exhaustion,
     environment failures) where the worker bailed instead of escalating
3. Do NOT praise. Do NOT summarize. Only judge.
4. Output STRICT JSON only, no preamble, no markdown. Schema:
{
  "verdict": "APPROVED" | "REJECTED",
  "confidence": 0.0..1.0,
  "feedback": "<one paragraph: for REJECTED, the specific gaps to close; for APPROVED, a one-sentence rationale>",
  "acceptance_check": [
    {"criterion": "<from task body>", "passed": true|false, "evidence": "<short>"}
  ]
}
5. When in doubt — REJECT. False-positive APPROVED costs more than false-positive REJECTED (one extra cycle vs broken downstream work).
6. confidence < 0.5 means you genuinely cannot tell — set verdict to REJECTED and explain what evidence is missing.
"""


def _build_user_prompt(
    task_row: dict,
    comments: list[dict],
    result_text: Optional[str],
) -> str:
    """Pack the worker's full task envelope into a single message."""
    lines: list[str] = []
    lines.append(f"# TASK {task_row['id']}: {task_row.get('title', '')}")
    lines.append("")
    lines.append("## Brief / acceptance criteria")
    lines.append(task_row.get("body") or "(no body)")
    lines.append("")
    if comments:
        lines.append(f"## Worker comments ({len(comments)} total, latest last)")
        for c in comments:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(c.get("created_at", 0)))
            author = c.get("author") or "unknown"
            body = c.get("body") or ""
            # Cap each comment at ~600 chars; the reviewer needs structure not novels
            if len(body) > 600:
                body = body[:600] + " …[truncated]"
            lines.append(f"### {ts} · {author}")
            lines.append(body)
            lines.append("")
    if result_text:
        lines.append("## Final result")
        # Cap result at ~2k chars
        if len(result_text) > 2000:
            result_text = result_text[:2000] + " …[truncated]"
        lines.append(result_text)
        lines.append("")
    lines.append("---")
    lines.append("Now judge. Output ONLY the JSON object specified in the system prompt.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Verdict parsing
# ---------------------------------------------------------------------------

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_llm_reply(reply: str) -> dict:
    """Tolerant JSON extraction.

    LLMs occasionally wrap the JSON in markdown fences or add a preamble
    despite the system prompt. We extract the outermost {...} block and
    json.loads it. Raises ValueError on failure.
    """
    if not reply or not reply.strip():
        raise ValueError("empty LLM reply")
    # Strip code fences first
    cleaned = reply.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    # First, try direct parse — happy path
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Fallback — first {...} blob in the response
    m = _JSON_BLOCK_RE.search(cleaned)
    if not m:
        raise ValueError(f"no JSON object found in LLM reply: {reply[:200]!r}")
    return json.loads(m.group(0))


def _normalize_verdict(parsed: dict) -> LLMReviewResult:
    """Coerce a parsed JSON dict into a typed LLMReviewResult."""
    raw_verdict = str(parsed.get("verdict", "")).strip().upper()
    if raw_verdict not in (VERDICT_APPROVED, VERDICT_REJECTED):
        # Treat unknown verdicts as REJECTED — safer than letting bad work pass
        return LLMReviewResult(
            verdict=VERDICT_REJECTED,
            feedback=(
                f"reviewer returned unparseable verdict {raw_verdict!r}; "
                "treating as REJECTED. Original feedback: "
                + str(parsed.get("feedback", ""))[:400]
            ),
            confidence=0.0,
        )
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    feedback = str(parsed.get("feedback", "")).strip()
    if not feedback:
        feedback = "(no feedback returned by reviewer)"
    acceptance = parsed.get("acceptance_check") or []
    if not isinstance(acceptance, list):
        acceptance = []
    return LLMReviewResult(
        verdict=raw_verdict,
        feedback=feedback,
        confidence=confidence,
        acceptance_check=acceptance,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def review_task(
    conn: sqlite3.Connection,
    task_id: str,
    *,
    call_llm_fn=None,  # injectable for tests
    timeout: float = 60.0,
) -> LLMReviewResult:
    """Run one Tier-B LLM review on a task. Synchronous.

    ``conn`` is a kanban DB connection (caller-owned). ``task_id`` is the
    task to review. The task does NOT need to be in any specific status —
    callers (CLI, MCP tool, chief skill) decide when to invoke review.

    ``call_llm_fn`` lets tests inject a stub; production passes None and
    we resolve ``agent.auxiliary_client.call_llm``. The model used is
    whatever the ``aegis_review`` auxiliary task is configured for in
    ``~/.hermes/config.yaml`` under ``auxiliary.aegis_review.provider``;
    falls back to the default haiku-class auxiliary model if unset.
    """
    started = time.time()
    row = conn.execute(
        "SELECT id, title, body, status, result FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        return LLMReviewResult(
            verdict=VERDICT_ERROR,
            feedback=f"task {task_id!r} not found",
            task_id=task_id,
            error="task-not-found",
        )
    task_row = dict(row)

    comments = [
        dict(r)
        for r in conn.execute(
            "SELECT author, body, created_at FROM comments "
            "WHERE task_id = ? ORDER BY created_at ASC",
            (task_id,),
        ).fetchall()
    ]

    user_prompt = _build_user_prompt(task_row, comments, task_row.get("result"))

    # Resolve call_llm at runtime so the plugin can load in test rigs that
    # haven't imported agent.auxiliary_client.
    if call_llm_fn is None:
        try:
            from agent.auxiliary_client import call_llm as _call_llm
        except Exception as e:
            return LLMReviewResult(
                verdict=VERDICT_ERROR,
                feedback=f"agent.auxiliary_client unavailable: {e}",
                task_id=task_id,
                error="llm-unavailable",
            )
        call_llm_fn = _call_llm

    try:
        resp = call_llm_fn(
            task="aegis_review",
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
            max_tokens=800,
            timeout=timeout,
        )
    except Exception as e:
        logger.exception("aegis llm-review: provider call failed")
        return LLMReviewResult(
            verdict=VERDICT_ERROR,
            feedback=f"LLM call raised: {e}",
            task_id=task_id,
            error=f"llm-call-failed:{type(e).__name__}",
            duration_sec=time.time() - started,
        )

    # Extract content from the OpenAI-shaped reply that call_llm returns.
    try:
        content = resp.choices[0].message.content
    except Exception:
        return LLMReviewResult(
            verdict=VERDICT_ERROR,
            feedback="LLM reply had unexpected shape (no choices[0].message.content)",
            task_id=task_id,
            error="malformed-reply",
            duration_sec=time.time() - started,
        )

    try:
        parsed = _parse_llm_reply(content)
    except ValueError as e:
        return LLMReviewResult(
            verdict=VERDICT_ERROR,
            feedback=f"could not parse reviewer JSON: {e}",
            task_id=task_id,
            error="parse-failed",
            duration_sec=time.time() - started,
        )

    result = _normalize_verdict(parsed)
    result.task_id = task_id
    result.duration_sec = time.time() - started
    # Best-effort token + model metadata
    try:
        result.tokens_used = (
            (resp.usage.input_tokens or 0) + (resp.usage.output_tokens or 0)
        )
    except Exception:
        pass
    try:
        result.model = getattr(resp, "model", None)
    except Exception:
        pass
    return result
