"""MCP tool surface for Aegis Tier-B LLM review.

Exposes ``aegis_review`` so a worker (typically a chief-manager) can run
LLM review on its own initial task before calling ``kanban_complete``.
The pattern (self-critique → review → fix if rejected → complete) gives
two layers of quality protection: the worker self-criticizes (driven by
the chief-manager / self-critique skill), then Aegis Tier-B catches what
self-criticism missed.

Gated on the kanban toolset being enabled in the profile (same as the
kanban tools), so plain ``hermes chat`` sessions never see this surface.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

from tools.registry import registry, tool_error

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gating: same as kanban tools — visible to workers + orchestrator profiles
# ---------------------------------------------------------------------------

def _profile_has_kanban_toolset() -> bool:
    try:
        from hermes_cli.config import load_config
        cfg = load_config()
        return "kanban" in cfg.get("toolsets", [])
    except Exception:
        return False


def _check_aegis_mode() -> bool:
    if os.environ.get("HERMES_KANBAN_TASK"):
        return True
    return _profile_has_kanban_toolset()


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def _handle_review(args: dict, **kw) -> str:
    task_id = (args.get("task_id") or "").strip() or os.environ.get("HERMES_KANBAN_TASK")
    if not task_id:
        return tool_error(
            "aegis_review: 'task_id' is required (or set HERMES_KANBAN_TASK)"
        )
    board = args.get("board") or None

    try:
        from hermes_cli import kanban_db
    except Exception as e:
        return tool_error(f"aegis_review: kanban_db unavailable: {e}")

    try:
        # First try in-plugin relative import (after externalisation the
        # plugin is loaded as hermes_plugins.aegis_attestation, not
        # plugins.aegis_attestation, so the legacy absolute path no longer
        # resolves). Fall back to legacy path for backward compat.
        try:
            from .llm_review import review_task  # type: ignore[import-not-found]
        except ImportError:
            from plugins.aegis_attestation.llm_review import review_task  # type: ignore[import-not-found]
    except Exception as e:
        return tool_error(
            f"aegis_review: aegis_attestation plugin not loaded: {e}. "
            f"Enable it in ~/.hermes/config.yaml plugins.enabled."
        )

    try:
        conn = kanban_db.connect(board=board)
    except FileNotFoundError:
        return tool_error(f"aegis_review: board {board!r} does not exist")
    except Exception as e:
        return tool_error(f"aegis_review: connect failed: {e}")

    try:
        result = review_task(conn, task_id)
    finally:
        conn.close()

    payload = result.as_dict()
    payload["ok"] = result.verdict != "ERROR"
    return json.dumps(payload, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

AEGIS_REVIEW_SCHEMA = {
    "name": "aegis_review",
    "description": (
        "Run Aegis Tier-B LLM review on a kanban task. Tier-B is the "
        "semantic quality gate (does the work actually solve the task?), "
        "complementing the deterministic Tier-A file-attestation. Returns "
        "a verdict APPROVED/REJECTED with concrete feedback. Workers "
        "typically call this on their own task right before kanban_complete "
        "— if REJECTED, fix the gaps and retry; if APPROVED, complete. "
        "If verdict=ERROR the review itself failed (LLM unreachable) — "
        "treat as inconclusive and proceed at your own judgment."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "task_id": {
                "type": "string",
                "description": (
                    "Task id to review. Defaults to HERMES_KANBAN_TASK "
                    "env var when omitted (worker's own task)."
                ),
            },
            "board": {
                "type": "string",
                "description": (
                    "Board slug if the task lives on a non-default board. "
                    "Optional."
                ),
            },
        },
        "required": [],
    },
}


registry.register(
    name="aegis_review",
    toolset="kanban",
    schema=AEGIS_REVIEW_SCHEMA,
    handler=_handle_review,
    check_fn=_check_aegis_mode,
    emoji="🛡️",
)
