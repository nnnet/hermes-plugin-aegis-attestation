"""Aegis attestation core — Tier-A deterministic deliverable verification.

Why: Every kanban task that finishes with ``review-required: ...`` blocks waiting
for a human reviewer. A *deterministic* pre-check that the worker actually wrote
the files it claims, plus a sha256 fingerprint anyone can re-verify, removes the
"is the handoff even real?" question before a human gets involved. No LLM,
no network, no opinions — just `os.stat` + `hashlib`.

What: Public surface is :func:`tick` which scans a kanban DB for all
``blocked`` tasks whose reason starts with the configured prefix
(``review-required:`` by default), parses the worker handoff JSON from the
most recent matching comment, verifies each declared deliverable exists
inside the task workspace, computes sha256s, posts an ``aegis-attest``
comment with the structured result, and optionally unblocks tasks whose
verification passed.

Test: See tests/test_attestation.py — covers happy path, missing files,
path-traversal, malformed handoff JSON, HMAC sign-with/without key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger("hermes.aegis_attestation")

# -- Tunable defaults (overridable via AegisConfig) -----------------------

DEFAULT_REASON_PREFIX = "review-required:"
DEFAULT_HANDOFF_MARKER = "review-required handoff:"
DEFAULT_REQUIRED_KEYS: tuple[str, ...] = ("changed_files",)
DEFAULT_HMAC_ENV = "AEGIS_ATTEST_HMAC_KEY"
ATTESTATION_AUTHOR = "aegis-attest"
ATTESTATION_COMMENT_MARKER = "aegis-attest v1:"
SHA256_CHUNK_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AegisConfig:
    """Why: Single typed config object so callers (CLI, tests, cron) all share
    the same defaults instead of drifting kwargs across the call sites.
    What: Holds reason_prefix, marker, required keys, workspace root override,
    auto_unblock flag, and HMAC env-var name.
    Test: Instantiate with defaults, mutate via dataclasses.replace, assert
    immutability (FrozenInstanceError on direct attr assignment).
    """

    reason_prefix: str = DEFAULT_REASON_PREFIX
    handoff_marker: str = DEFAULT_HANDOFF_MARKER
    required_keys: tuple[str, ...] = DEFAULT_REQUIRED_KEYS
    auto_unblock_on_pass: bool = True
    hmac_secret_env: str = DEFAULT_HMAC_ENV
    # When None the resolver uses kanban_db.workspaces_root(board) at call time.
    # Tests can pin a tmp_path here.
    workspace_root_override: Optional[Path] = None


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class FileCheck:
    """Why: One row per declared deliverable — lets downstream consumers
    (dashboard, reviewer) see which file failed without re-running sha256.
    What: Holds the relative path the worker declared, the resolved absolute
    path, ok flag, sha256 (when present), size, and a short reason on failure.
    Test: Construct directly in unit tests, assert serialization round-trips
    through dataclasses.asdict.
    """

    path: str
    resolved: Optional[str] = None
    ok: bool = False
    sha256: Optional[str] = None
    size: Optional[int] = None
    reason: Optional[str] = None


@dataclass
class AttestationResult:
    """Why: Structured payload that becomes the body of the attestation
    comment — must be machine-parseable so a future Tier-B can read it.
    What: ok flag, verified count, list of FileCheck, reason on failure,
    sha256 of the canonical JSON itself, optional HMAC signature.
    Test: Round-trip through to_dict/from_dict, verify signature matches
    HMAC-SHA256 of canonical bytes.
    """

    task_id: str
    ok: bool
    verified: int = 0
    declared: int = 0
    files: list[FileCheck] = field(default_factory=list)
    reason: Optional[str] = None
    handoff_keys: list[str] = field(default_factory=list)
    timestamp: int = field(default_factory=lambda: int(time.time()))
    schema: str = "aegis-attest/v1"
    signature: Optional[str] = None  # HMAC-SHA256 hex over payload sans this field

    def to_payload(self) -> dict[str, Any]:
        """Why: Canonical dict form (signature stripped) for hashing/signing.
        What: Returns dict with files as list-of-dicts, in stable key order.
        Test: Two equal AttestationResults produce identical canonical_bytes.
        """
        return {
            "schema": self.schema,
            "task_id": self.task_id,
            "ok": self.ok,
            "verified": self.verified,
            "declared": self.declared,
            "reason": self.reason,
            "handoff_keys": list(self.handoff_keys),
            "timestamp": self.timestamp,
            "files": [
                {
                    "path": f.path,
                    "resolved": f.resolved,
                    "ok": f.ok,
                    "sha256": f.sha256,
                    "size": f.size,
                    "reason": f.reason,
                }
                for f in self.files
            ],
        }


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_file(path: Path, chunk_size: int = SHA256_CHUNK_BYTES) -> str:
    """Why: Big-file safety — reading 4GB logs into RAM would OOM the host.
    What: Streams the file through hashlib.sha256 in chunk_size byte slices,
    returns the hex digest.
    Test: Hash a known-content tmp file, assert it matches the canonical
    hashlib.sha256(data).hexdigest() for the same bytes.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Why: Signature stability — anyone re-verifying must hash exactly the
    same bytes we did, so we pin sort_keys + ensure_ascii + separators.
    What: Returns the canonical JSON encoding of payload as bytes.
    Test: Two semantically-equal dicts (key order swapped) produce identical
    canonical_bytes output.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_payload(payload: dict[str, Any], hmac_env: str = DEFAULT_HMAC_ENV) -> Optional[str]:
    """Why: Reviewer needs a way to detect comment tampering — anyone with
    write access to the DB could fake an attestation row, but only the
    holder of the env-var key can produce a matching HMAC.
    What: HMAC-SHA256(env[hmac_env], canonical_bytes(payload)) as hex,
    or None when no key is configured (with a warning log).
    Test: Set env to fixture key, assert hex matches a precomputed value
    for a fixed payload; unset env, assert returns None and logs a warning.
    """
    key = os.environ.get(hmac_env, "").strip()
    if not key:
        logger.warning(
            "Aegis HMAC signing disabled: env var %s is empty/unset. "
            "Set it to a 32+ byte hex secret to enable tamper-evident comments.",
            hmac_env,
        )
        return None
    mac = hmac.new(key.encode("utf-8"), canonical_bytes(payload), hashlib.sha256)
    return mac.hexdigest()


# ---------------------------------------------------------------------------
# Handoff parsing
# ---------------------------------------------------------------------------

def parse_handoff(
    comments: Iterable[Any],
    marker: str = DEFAULT_HANDOFF_MARKER,
) -> Optional[dict[str, Any]]:
    """Why: The worker's structured handoff lives in a comment body that
    starts with a fixed marker line followed by JSON — parsing must be
    tolerant of partial garbage (a stray non-JSON comment must not break
    the whole tick) while still picking the most recent valid one.
    What: Iterates comments in reverse, finds the first body starting with
    marker, parses the post-marker text as JSON, returns the dict (or None
    if no comment matches / JSON malformed).
    Test: Mock comments list with [valid handoff, plain comment]; assert
    valid handoff dict is returned. Add malformed-JSON comment, assert
    function still returns the older valid handoff.
    """
    comment_list = list(comments)
    for comment in reversed(comment_list):
        body = getattr(comment, "body", None)
        if not isinstance(body, str) or not body.strip():
            continue
        if marker not in body:
            continue
        # Take everything after the first occurrence of marker
        _, _, after = body.partition(marker)
        candidate = after.strip()
        if not candidate:
            logger.debug("Aegis: handoff marker found but body after marker is empty")
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            logger.warning(
                "Aegis: skipping handoff comment with invalid JSON (%s): %s...",
                exc, candidate[:120].replace("\n", " "),
            )
            continue
        if not isinstance(parsed, dict):
            logger.warning(
                "Aegis: handoff JSON is not an object (got %s); skipping",
                type(parsed).__name__,
            )
            continue
        return parsed
    return None


# ---------------------------------------------------------------------------
# Path-traversal-safe deliverable resolution
# ---------------------------------------------------------------------------

def _resolve_under_root(declared: str, root: Path) -> Optional[Path]:
    """Why: A handoff JSON is worker-controlled — declaring
    ``../../../etc/passwd`` must not let aegis hash the host's secrets.
    What: Joins declared onto root, resolves symlinks, returns the path
    only if it stays inside root. Otherwise returns None.
    Test: Pass ``../../etc/passwd`` and a tmp workspace root, assert None
    is returned. Pass ``src/file.py`` and assert the returned path equals
    (root / 'src/file.py').resolve().
    """
    try:
        candidate = (root / declared).resolve(strict=False)
        root_resolved = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        logger.warning("Aegis: cannot resolve %r under %s: %s", declared, root, exc)
        return None
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None
    return candidate


# ---------------------------------------------------------------------------
# Per-task attestation
# ---------------------------------------------------------------------------

def attest_task(
    task_id: str,
    workspace: Path,
    handoff: dict[str, Any],
    cfg: AegisConfig,
) -> AttestationResult:
    """Why: One pure function from (task, workspace, handoff) to verdict
    keeps the polling loop trivially testable — no DB, no clock, no env.
    What: Validates required keys are present, resolves each deliverable
    under workspace with path-escape guard, hashes existing files,
    returns AttestationResult with per-file outcomes and an overall ok flag.
    Test: See test_attest_task_all_present / _missing_file / _path_escape.
    """
    declared_keys = sorted(handoff.keys())
    missing_keys = [k for k in cfg.required_keys if k not in handoff]
    if missing_keys:
        return AttestationResult(
            task_id=task_id,
            ok=False,
            declared=0,
            verified=0,
            reason=f"missing_handoff_keys:{','.join(missing_keys)}",
            handoff_keys=declared_keys,
        )

    raw_files = handoff.get("changed_files") or []
    if not isinstance(raw_files, list):
        return AttestationResult(
            task_id=task_id,
            ok=False,
            declared=0,
            verified=0,
            reason="changed_files_not_a_list",
            handoff_keys=declared_keys,
        )

    checks: list[FileCheck] = []
    verified = 0
    overall_ok = True
    overall_reason: Optional[str] = None

    for raw in raw_files:
        if not isinstance(raw, str) or not raw.strip():
            checks.append(FileCheck(path=str(raw), reason="invalid_path_value"))
            overall_ok = False
            overall_reason = overall_reason or "invalid_deliverable"
            continue

        declared = raw.strip()
        resolved = _resolve_under_root(declared, workspace)
        if resolved is None:
            checks.append(FileCheck(path=declared, reason="path_escape"))
            overall_ok = False
            overall_reason = "path_escape"
            continue

        if not resolved.exists():
            checks.append(
                FileCheck(path=declared, resolved=str(resolved), reason="missing_file")
            )
            overall_ok = False
            overall_reason = overall_reason or "missing_deliverables"
            continue

        if not resolved.is_file():
            checks.append(
                FileCheck(
                    path=declared,
                    resolved=str(resolved),
                    reason="not_a_regular_file",
                )
            )
            overall_ok = False
            overall_reason = overall_reason or "non_file_deliverable"
            continue

        try:
            digest = sha256_file(resolved)
            size = resolved.stat().st_size
        except OSError as exc:
            checks.append(
                FileCheck(
                    path=declared,
                    resolved=str(resolved),
                    reason=f"io_error:{exc.__class__.__name__}",
                )
            )
            overall_ok = False
            overall_reason = overall_reason or "io_error"
            continue

        checks.append(
            FileCheck(
                path=declared,
                resolved=str(resolved),
                ok=True,
                sha256=digest,
                size=size,
            )
        )
        verified += 1

    return AttestationResult(
        task_id=task_id,
        ok=overall_ok and verified > 0,
        declared=len(raw_files),
        verified=verified,
        files=checks,
        reason=None if overall_ok and verified > 0 else (overall_reason or "no_deliverables"),
        handoff_keys=declared_keys,
    )


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

def format_comment_body(result: AttestationResult) -> str:
    """Why: Reviewers should see the verdict at a glance in the dashboard
    *and* be able to re-verify the sha256s without running aegis again,
    so we put a one-line summary header followed by the canonical payload.
    What: Returns "aegis-attest v1: <PASS/FAIL>\\n<json>" — the leading
    marker lets the polling loop skip already-attested tasks.
    Test: format_comment_body(result).startswith("aegis-attest v1:") is True.
    """
    payload = result.to_payload()
    if result.signature:
        payload["signature"] = result.signature
    header = "PASS" if result.ok else f"FAIL ({result.reason or 'unknown'})"
    body = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    return f"{ATTESTATION_COMMENT_MARKER} {header}\n{body}"


def has_existing_attestation(comments: Iterable[Any]) -> bool:
    """Why: The tick loop is idempotent — running it twice must not spam
    comments. We treat the presence of any aegis-attest comment as "this
    handoff has already been attested" and skip re-running.
    What: Returns True if any comment body contains
    ATTESTATION_COMMENT_MARKER.
    Test: Mock comment with body 'aegis-attest v1: PASS ...', assert True;
    mock unrelated comment, assert False.
    """
    for comment in comments:
        body = getattr(comment, "body", None)
        if isinstance(body, str) and ATTESTATION_COMMENT_MARKER in body:
            return True
    return False


# ---------------------------------------------------------------------------
# DB-driven tick loop
# ---------------------------------------------------------------------------

@dataclass
class TickSummary:
    """Why: Callers (CLI, cron, dashboard) need a structured summary so they
    can decide whether to alert or just log; raw stdout would be fragile.
    What: Counts of tasks inspected, skipped, attested, unblocked, plus
    per-task results for debugging.
    Test: After running tick() against a synthetic DB, assert
    summary.attested + summary.skipped == summary.inspected.
    """

    inspected: int = 0
    skipped: int = 0
    attested: int = 0
    passed: int = 0
    failed: int = 0
    unblocked: int = 0
    results: list[AttestationResult] = field(default_factory=list)


def _resolve_workspace_for_task(
    task: Any,
    cfg: AegisConfig,
    board: Optional[str],
) -> Optional[Path]:
    """Why: kanban_db.resolve_workspace mutates the filesystem (creates
    scratch dirs). For verification we only need the existing path —
    creating a fresh workspace on a 'blocked' task would mask missing
    deliverables. So we compute the path ourselves from the task row.
    What: Honours cfg.workspace_root_override (tests). Otherwise imports
    kanban_db lazily and uses ``workspaces_root(board) / task.id``
    for scratch, or task.workspace_path for dir/worktree.
    Test: Pass override + dummy task with id='t_x'; assert returned path
    equals override/'t_x'.
    """
    task_id = getattr(task, "id", None)
    if not task_id:
        return None

    if cfg.workspace_root_override is not None:
        return cfg.workspace_root_override / task_id

    # Lazy import — keeps unit tests stdlib-only when override is set.
    try:
        from hermes_cli import kanban_db  # type: ignore  # noqa: PLC0415
    except Exception as exc:
        logger.warning("Aegis: cannot import kanban_db (%s); skipping task %s", exc, task_id)
        return None

    kind = getattr(task, "workspace_kind", "scratch") or "scratch"
    explicit = getattr(task, "workspace_path", None)
    if kind == "scratch":
        if explicit:
            return Path(explicit).expanduser()
        return kanban_db.workspaces_root(board=board) / task_id
    if kind in {"dir", "worktree"}:
        if not explicit:
            logger.warning(
                "Aegis: task %s has workspace_kind=%s but no workspace_path; skipping",
                task_id, kind,
            )
            return None
        return Path(explicit).expanduser()
    logger.warning("Aegis: unknown workspace_kind=%r on task %s; skipping", kind, task_id)
    return None


def _process_one_task(
    conn: sqlite3.Connection,
    kanban_db: Any,
    task: Any,
    board: Optional[str],
    cfg: AegisConfig,
    summary: TickSummary,
) -> None:
    """Why: Both batch (``tick()``) and single-task (``process_task_id()``)
    entrypoints need identical per-task semantics — extract the inner loop
    body so they cannot drift. Also makes the hybrid hook trigger trivially
    reuse the exact same idempotency / handoff-parsing logic as cron.
    What: For one ``task`` row already on a live SQLite ``conn``:
    1) skip if reason prefix doesn't match,
    2) skip if attestation comment already present (idempotent),
    3) parse handoff JSON from comments,
    4) resolve workspace, verify deliverables, sign, comment, unblock.
    Mutates ``summary`` counters and appends to ``summary.results``.
    Test: ``tests/test_attestation.py`` exercises the path through ``tick``;
    ``tests/test_hook_trigger.py`` calls this via ``process_task_id``.
    """
    summary.inspected += 1
    task_id = getattr(task, "id", "<unknown>")

    # Filter: reason prefix lives on the most recent 'blocked' event payload.
    if not _task_matches_reason_prefix(conn, kanban_db, task, cfg.reason_prefix):
        summary.skipped += 1
        return

    try:
        comments = kanban_db.list_comments(conn, task_id)
    except Exception as exc:
        logger.warning("Aegis: list_comments(%s) failed: %s; skipping", task_id, exc)
        summary.skipped += 1
        return

    # Idempotency: re-running the hook OR cron on an already-attested task
    # is a no-op. Important because the hybrid trigger model (hook + cron
    # catch-up) WILL race on the same task occasionally.
    if has_existing_attestation(comments):
        logger.debug("Aegis: task %s already has an attestation comment", task_id)
        summary.skipped += 1
        return

    handoff = parse_handoff(comments, marker=cfg.handoff_marker)
    if handoff is None:
        logger.info("Aegis: task %s has no parseable handoff; skipping", task_id)
        summary.skipped += 1
        return

    workspace = _resolve_workspace_for_task(task, cfg, board)
    if workspace is None:
        summary.skipped += 1
        return

    if not workspace.exists():
        logger.info(
            "Aegis: task %s workspace %s does not exist; recording FAIL",
            task_id, workspace,
        )
        result = AttestationResult(
            task_id=task_id,
            ok=False,
            reason="workspace_missing",
            handoff_keys=sorted(handoff.keys()),
        )
    else:
        result = attest_task(task_id, workspace, handoff, cfg)

    # Sign
    result.signature = sign_payload(result.to_payload(), cfg.hmac_secret_env)

    # Write attestation comment
    try:
        kanban_db.add_comment(
            conn,
            task_id,
            ATTESTATION_AUTHOR,
            format_comment_body(result),
        )
        summary.attested += 1
        if result.ok:
            summary.passed += 1
        else:
            summary.failed += 1
    except Exception as exc:
        logger.error("Aegis: failed to write attestation comment for %s: %s", task_id, exc)
        return

    # Optional unblock
    if result.ok and cfg.auto_unblock_on_pass:
        try:
            if kanban_db.unblock_task(conn, task_id):
                summary.unblocked += 1
                logger.info("Aegis: task %s passed attestation; unblocked", task_id)
        except Exception as exc:
            logger.warning("Aegis: unblock_task(%s) failed: %s", task_id, exc)

    summary.results.append(result)


def process_task_id(
    task_id: str,
    *,
    board: Optional[str] = None,
    cfg: Optional[AegisConfig] = None,
    db_path: Optional[Path] = None,
) -> TickSummary:
    """Why: Hybrid trigger — invoked from the ``post_tool_call`` hook the
    moment a worker fires ``kanban_block(reason='review-required: ...')``.
    Doing one task immediately (instead of waiting up to 60s for the cron
    tick) cuts the perceived handoff → attestation latency from "minute" to
    "millisecond". The cron tick remains as a safety net for tasks the hook
    missed (worker crashed, plugin not loaded, kanban_block invoked outside
    the agent process, etc.).
    What: Loads kanban_db lazily, opens the same DB ``tick`` would, fetches
    a single task row by id, then runs ``_process_one_task`` exactly as
    the batch path would. Returns a ``TickSummary`` so callers (hook,
    tests) can introspect what happened.
    Idempotent: if the task already has an attestation comment, this is a
    no-op — safe to race with cron.
    Test: ``tests/test_hook_trigger.py`` constructs a synthetic kanban,
    fires the hook, asserts ``summary.attested == 1`` and a second call
    returns ``summary.skipped == 1``.
    """
    cfg = cfg or AegisConfig()
    summary = TickSummary()

    try:
        from hermes_cli import kanban_db  # type: ignore  # noqa: PLC0415
    except Exception as exc:
        logger.error("Aegis: cannot import hermes_cli.kanban_db: %s", exc)
        return summary

    resolved_db = db_path or kanban_db.kanban_db_path(board)
    if not resolved_db.exists():
        logger.warning("Aegis: kanban db not found at %s; nothing to do", resolved_db)
        return summary

    conn = kanban_db.connect(resolved_db)
    try:
        # ``get_task`` should be cheaper than list_tasks(status='blocked')
        # because we already know the id. Fall back gracefully if the
        # function isn't available in this kanban_db version.
        get_task = getattr(kanban_db, "get_task", None)
        if get_task is not None:
            try:
                task = get_task(conn, task_id)
            except TypeError:
                # Some kanban_db versions take only ``task_id`` (no conn).
                task = get_task(task_id)
        else:
            # Fallback: enumerate blocked tasks and pick by id.
            all_blocked = kanban_db.list_tasks(conn, status="blocked")
            task = next((t for t in all_blocked if getattr(t, "id", None) == task_id), None)

        if task is None:
            logger.info(
                "Aegis: task %s not found in kanban (board=%s); nothing to do",
                task_id, board,
            )
            return summary

        # Only attest tasks that are actually in 'blocked' state. The hook
        # fires the instant kanban_block returns, so the worker may or may
        # not have transitioned yet depending on the gateway dispatch
        # ordering. Defer to cron on race.
        if getattr(task, "status", None) != "blocked":
            logger.debug(
                "Aegis: task %s is not blocked (status=%s); deferring to cron",
                task_id, getattr(task, "status", None),
            )
            return summary

        _process_one_task(conn, kanban_db, task, board, cfg, summary)
    finally:
        conn.close()

    return summary


def tick(
    *,
    board: Optional[str] = None,
    cfg: Optional[AegisConfig] = None,
    db_path: Optional[Path] = None,
    now: Optional[int] = None,
) -> TickSummary:
    """Why: Single entrypoint the CLI command and cron both hit; coordinates
    DB read, per-task verification, comment write-back, and (optional)
    unblock — all in one transaction-per-task scope so a crash mid-pass
    leaves the DB consistent.
    What: Loads kanban_db lazily, lists blocked tasks, runs ``_process_one_task``
    (shared with the hook trigger) for each, writes the attestation as a
    'aegis-attest' comment, and unblocks on pass when ``cfg.auto_unblock_on_pass``.
    Test: Manual via `hermes aegis tick` on a kanban with one synthetic
    blocked task; integration test would mock kanban_db functions.
    """
    cfg = cfg or AegisConfig()
    summary = TickSummary()

    # Lazy import so unit tests of pure functions don't pull kanban_db
    try:
        from hermes_cli import kanban_db  # type: ignore  # noqa: PLC0415
    except Exception as exc:
        logger.error("Aegis: cannot import hermes_cli.kanban_db: %s", exc)
        return summary

    resolved_db = db_path or kanban_db.kanban_db_path(board)
    if not resolved_db.exists():
        logger.warning("Aegis: kanban db not found at %s; nothing to do", resolved_db)
        return summary

    conn = kanban_db.connect(resolved_db)
    try:
        blocked_tasks = kanban_db.list_tasks(conn, status="blocked")
    except Exception as exc:
        logger.error("Aegis: list_tasks(blocked) failed: %s", exc)
        conn.close()
        return summary

    for task in blocked_tasks:
        _process_one_task(conn, kanban_db, task, board, cfg, summary)

    conn.close()
    return summary


def _task_matches_reason_prefix(
    conn: sqlite3.Connection,
    kanban_db: Any,
    task: Any,
    reason_prefix: str,
) -> bool:
    """Why: ``Task`` rows don't carry the block reason directly — it lives on
    the most recent 'blocked' event payload. We have to look it up
    defensively because event payload shape has shifted between kanban_db
    revisions.
    What: Returns True iff the latest 'blocked' event for the task has a
    payload dict containing 'reason' that starts with reason_prefix.
    Test: Synthesize a fake event list with one matching, one non-matching
    blocked event; assert the latest wins. Pass empty list, assert False.
    """
    try:
        events = kanban_db.list_events(conn, getattr(task, "id", ""))
    except Exception as exc:
        logger.debug("Aegis: list_events failed (%s); using fallback heuristic", exc)
        return False

    for event in reversed(list(events)):
        kind = getattr(event, "kind", None)
        if kind != "blocked":
            continue
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict):
            return False
        reason = payload.get("reason")
        if isinstance(reason, str) and reason.startswith(reason_prefix):
            return True
        return False
    return False
