"""aegis-attestation plugin — Tier-A deterministic deliverable verifier.

Why: Closes the "did the worker actually write the files it claims?" gap
between a `kanban_block(reason='review-required:')` handoff and a human
reviewer's eyeball-pass. Pure stdlib, no LLM, no network — runs in
microseconds per task and produces a tamper-evident (HMAC) comment that
anyone can re-verify.

What: Registers TWO complementary entry points:

  1. ``hermes aegis`` CLI subcommand (tick / status / config) — manual
     invocation, host cron, systemd timer, or the built-in Hermes cron
     scheduler. Catch-up safety net.

  2. ``post_tool_call`` plugin hook — fires the instant a worker runs
     ``kanban_block(reason='review-required: ...')`` inside the agent
     process. Cuts handoff → attestation latency from "up to a minute"
     (cron) to "milliseconds" (hook). Hook is fully idempotent and races
     safely with cron (``has_existing_attestation`` short-circuits).

The hybrid model (hook for instant reaction + cron for catch-up) was
chosen over pure-cron because:
- pure cron has up to 60s latency before the worker's hand-off is verified
- pure hook misses tasks where ``kanban_block`` is invoked outside the
  agent process (Web UI, ``hermes kanban block`` CLI, dispatcher cleanup)
- combining the two gives both responsiveness and safety with zero new
  external dependencies.

Test: ``hermes aegis tick --board <slug>`` on a board with a synthetic
blocked task; see plugins/aegis_attestation/tests/ for unit coverage
(``pytest plugins/aegis_attestation/tests/ -v -o "addopts="``).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from . import attestation as _att

logger = logging.getLogger("hermes.aegis_attestation")


# ---------------------------------------------------------------------------
# YAML config loader (optional overrides from ~/.hermes/config.yaml)
# ---------------------------------------------------------------------------

def _load_yaml_section() -> dict[str, Any]:
    """Why: Operators want to tweak reason_prefix / required_keys / unblock
    behaviour without editing source — but the plugin must still work on a
    fresh box where neither ~/.hermes/config.yaml nor hermes_cli are present.
    What: Reads the ``aegis_attestation`` section from the global hermes
    config via ``hermes_cli.config.load_config``; falls back to a direct
    ``yaml.safe_load`` of ``~/.hermes/config.yaml``; returns ``{}`` on any
    failure so callers can always ``.get(...)``.
    Test: ``test_no_yaml_section_uses_defaults`` (mock load_config -> {})
    and ``test_load_config_returns_none_safe`` (mock load_config -> None).
    """
    try:
        from hermes_cli.config import load_config  # type: ignore  # noqa: PLC0415

        cfg = load_config()
        if not isinstance(cfg, dict):
            return {}
        section = cfg.get("aegis_attestation")
        return section if isinstance(section, dict) else {}
    except Exception as exc:  # pragma: no cover - exercised via direct-yaml fallback
        logger.debug("hermes_cli.config.load_config unavailable: %s", exc)

    # Fallback: read ~/.hermes/config.yaml directly with stdlib + PyYAML.
    try:
        import yaml  # type: ignore  # noqa: PLC0415

        path = Path("~/.hermes/config.yaml").expanduser()
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text()) or {}
        section = data.get("aegis_attestation") if isinstance(data, dict) else None
        return section if isinstance(section, dict) else {}
    except Exception as exc:
        logger.debug("direct yaml fallback failed: %s", exc)
        return {}


def _build_cfg(args: argparse.Namespace) -> _att.AegisConfig:
    """Why: Single source of truth for "how does the tick command decide its
    config?" — CLI flags take precedence over YAML, YAML over dataclass
    defaults. Keeping this out of ``_cmd_tick`` makes it unit-testable
    without an argparse subprocess.
    What: Loads the optional ``aegis_attestation:`` section, maps known
    fields onto :class:`AegisConfig` kwargs (list->tuple for required_keys,
    str->Path for workspace_root_override), then applies the ``--no-unblock``
    CLI override last.
    Test: ``TestYamlConfigLoader`` covers each branch (override, type-cast,
    CLI-wins, None-safe).
    """
    section = _load_yaml_section()
    kwargs: dict[str, Any] = {}

    if isinstance(section.get("reason_prefix"), str):
        kwargs["reason_prefix"] = section["reason_prefix"]
    if isinstance(section.get("handoff_marker"), str):
        kwargs["handoff_marker"] = section["handoff_marker"]
    if isinstance(section.get("required_keys"), (list, tuple)):
        kwargs["required_keys"] = tuple(
            str(k) for k in section["required_keys"] if isinstance(k, str)
        )
    if isinstance(section.get("auto_unblock_on_pass"), bool):
        kwargs["auto_unblock_on_pass"] = section["auto_unblock_on_pass"]
    if isinstance(section.get("hmac_secret_env"), str):
        kwargs["hmac_secret_env"] = section["hmac_secret_env"]
    wro = section.get("workspace_root_override")
    if isinstance(wro, str) and wro.strip():
        kwargs["workspace_root_override"] = Path(wro).expanduser()

    # CLI --no-unblock always wins over YAML (defensive default = True).
    if getattr(args, "no_unblock", False):
        kwargs["auto_unblock_on_pass"] = False

    return _att.AegisConfig(**kwargs)


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------

def _build_argparse(subparser: argparse.ArgumentParser) -> None:
    """Why: PluginContext.register_cli_command hands us a subparser; we own
    the inner argument tree so the user sees `hermes aegis tick [--board X]`
    not a flat option soup.
    What: Adds three sub-subcommands — tick, status, config — each with its
    own argparse defaults so `func(args)` dispatch works.
    Test: argparse.parse_args(['aegis', 'tick', '--board', 'cookai']) gives
    args.aegis_command == 'tick' and args.board == 'cookai'.
    """
    subs = subparser.add_subparsers(dest="aegis_command")

    tick_p = subs.add_parser(
        "tick",
        help="Scan kanban for review-required blocked tasks, verify deliverables, "
             "post attestation comments, optionally unblock on pass.",
    )
    tick_p.add_argument(
        "--board", default=None,
        help="Kanban board slug (defaults to the active board).",
    )
    tick_p.add_argument(
        "--no-unblock", action="store_true",
        help="Verify and comment, but do not unblock on pass.",
    )
    tick_p.add_argument(
        "--json", action="store_true",
        help="Emit the TickSummary as JSON to stdout (for cron / dashboards).",
    )
    tick_p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Set log level to DEBUG.",
    )
    tick_p.set_defaults(func=_cmd_tick)

    status_p = subs.add_parser(
        "status",
        help="Print effective config and a count of currently-blocked review-required tasks.",
    )
    status_p.add_argument("--board", default=None)
    status_p.set_defaults(func=_cmd_status)

    cfg_p = subs.add_parser(
        "config",
        help="Print the default AegisConfig as JSON.",
    )
    cfg_p.set_defaults(func=_cmd_config)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _cmd_tick(args: argparse.Namespace) -> int:
    """Why: One-shot entry the cron task hits; must be idempotent.
    What: Builds an AegisConfig honouring --no-unblock, calls attestation.tick,
    prints either a human-friendly line or a JSON blob.
    Test: Mock attestation.tick to return a fake TickSummary, assert exit
    code 0 and the expected stdout shape.
    """
    if getattr(args, "verbose", False):
        logging.getLogger("hermes.aegis_attestation").setLevel(logging.DEBUG)

    cfg = _build_cfg(args)

    try:
        summary = _att.tick(board=getattr(args, "board", None), cfg=cfg)
    except Exception as exc:
        logger.exception("Aegis tick failed: %s", exc)
        return 2

    if getattr(args, "json", False):
        payload = {
            "inspected": summary.inspected,
            "skipped": summary.skipped,
            "attested": summary.attested,
            "passed": summary.passed,
            "failed": summary.failed,
            "unblocked": summary.unblocked,
            "results": [r.to_payload() for r in summary.results],
        }
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"aegis-attest tick: inspected={summary.inspected} "
            f"attested={summary.attested} passed={summary.passed} "
            f"failed={summary.failed} unblocked={summary.unblocked} "
            f"skipped={summary.skipped}"
        )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    """Why: Quick "is the plugin alive and seeing my tasks?" check without
    actually mutating the DB.
    What: Counts blocked tasks with matching reason prefix; prints config.
    Test: Run against a kanban with zero matching tasks, assert 'blocked
    review-required tasks: 0' in output.
    """
    cfg = _att.AegisConfig()
    print(f"AegisConfig: {json.dumps(_config_to_dict(cfg), indent=2, sort_keys=True)}")
    try:
        from hermes_cli import kanban_db  # type: ignore  # noqa: PLC0415
    except Exception as exc:
        print(f"kanban_db unavailable: {exc}", file=sys.stderr)
        return 1
    board = getattr(args, "board", None)
    db_path = kanban_db.kanban_db_path(board)
    if not db_path.exists():
        print(f"kanban db not found: {db_path}")
        return 0
    conn = kanban_db.connect(db_path)
    blocked = kanban_db.list_tasks(conn, status="blocked")
    matching = 0
    for task in blocked:
        if _att._task_matches_reason_prefix(conn, kanban_db, task, cfg.reason_prefix):
            matching += 1
    conn.close()
    print(f"blocked review-required tasks: {matching} / {len(blocked)} total blocked")
    return 0


def _cmd_config(_args: argparse.Namespace) -> int:
    """Why: Operators wiring up cron need a quick way to see what defaults
    look like without grepping the source.
    What: Dumps AegisConfig() as JSON to stdout.
    Test: Exit code 0, stdout contains the key 'reason_prefix'.
    """
    print(json.dumps(_config_to_dict(_att.AegisConfig()), indent=2, sort_keys=True))
    return 0


def _config_to_dict(cfg: _att.AegisConfig) -> dict[str, Any]:
    """Why: Path objects aren't JSON-serialisable; AegisConfig holds one.
    What: Returns a dict view of cfg with Path coerced to str.
    Test: Set workspace_root_override=Path('/tmp/x'); assert the resulting
    dict has 'workspace_root_override' == '/tmp/x'.
    """
    d = asdict(cfg)
    if cfg.workspace_root_override is not None:
        d["workspace_root_override"] = str(cfg.workspace_root_override)
    # tuples don't survive JSON nicely — list-ify for output stability
    d["required_keys"] = list(d.get("required_keys") or [])
    return d


# ---------------------------------------------------------------------------
# post_tool_call hook — instant trigger on kanban_block(review-required:)
# ---------------------------------------------------------------------------

# When a tool call result fields contain these markers the hook treats the
# call as a review-required handoff. Kept here (not in attestation.py) so
# the hook can decide BEFORE touching kanban_db — important because the
# hook fires for every tool call in the agent process and we want a fast
# early-exit for the 99% case.
_HOOK_TARGET_TOOL = "kanban_block"


def _extract_block_reason(args: Any, result: Any) -> Optional[str]:
    """Why: ``kanban_block`` was called via the gateway tool-dispatch path,
    so the reason can live in either the input ``args`` (most common) or
    the rendered ``result`` text. We need a tolerant extractor because the
    arg-shape is normalised by the framework slightly differently across
    versions (dict vs. JSON-string vs. argparse Namespace).
    What: Tries ``args['reason']``, ``args.get('args',{}).get('reason')``,
    JSON-decode of a string ``args``, then falls back to scanning the
    ``result`` body for the canonical 'review-required:' prefix.
    Test: Each branch is unit-tested in ``test_hook_trigger.py``.
    """
    # 1. args is a dict-like — most likely shape from gateway dispatch.
    if isinstance(args, dict):
        reason = args.get("reason")
        if isinstance(reason, str) and reason:
            return reason
        # Nested under 'args' key (some hooks pass the full tool call object).
        nested = args.get("args")
        if isinstance(nested, dict):
            reason = nested.get("reason")
            if isinstance(reason, str) and reason:
                return reason

    # 2. args is a JSON string (rare but seen in older shims).
    if isinstance(args, str):
        try:
            decoded = json.loads(args)
            if isinstance(decoded, dict):
                reason = decoded.get("reason")
                if isinstance(reason, str) and reason:
                    return reason
        except (ValueError, TypeError):
            pass

    # 3. Fallback: scan the result text for the canonical prefix. This
    # catches the case where the framework redacted args but the result
    # body echoes the reason back (typical pattern).
    if isinstance(result, str):
        for line in result.splitlines():
            stripped = line.strip()
            if stripped.startswith("review-required:"):
                return stripped

    return None


def _extract_task_and_board(args: Any) -> tuple[Optional[str], Optional[str]]:
    """Why: ``kanban_block`` needs a task id; the hook ALSO often gets the
    board slug from the same args (gateway-dispatch shape). Pull both with
    a single helper so the callback stays linear.
    What: Mirrors ``_extract_block_reason`` shape-handling: dict, nested
    'args' dict, JSON-string. Returns (task_id, board) — either may be None
    if not present (caller falls back to kanban_db active board).
    Test: ``test_extract_task_and_board`` covers all three input shapes.
    """
    def _from_dict(d: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        tid = d.get("task_id") or d.get("id")
        brd = d.get("board")
        return (
            tid if isinstance(tid, str) and tid else None,
            brd if isinstance(brd, str) and brd else None,
        )

    if isinstance(args, dict):
        tid, brd = _from_dict(args)
        if tid or brd:
            return tid, brd
        nested = args.get("args")
        if isinstance(nested, dict):
            return _from_dict(nested)

    if isinstance(args, str):
        try:
            decoded = json.loads(args)
            if isinstance(decoded, dict):
                return _from_dict(decoded)
        except (ValueError, TypeError):
            pass

    return (None, None)


def _on_post_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> None:
    """Why: Instant attestation trigger — fires the moment a worker writes
    ``kanban_block(reason='review-required: ...')``. Without this hook the
    worker's handoff would sit unverified until the next cron tick (up to
    60s); with it, the attestation comment is posted in the same agent
    turn that produced the handoff. Hook MUST be cheap when the tool is
    NOT ``kanban_block`` because it runs on every tool call in the process.
    What: Quick early-exit on tool name; load YAML config; extract reason
    and task/board from args; if the reason carries the configured prefix,
    delegate to ``attestation.process_task_id`` which is idempotent.
    Errors are caught and logged — a buggy hook must NEVER break the
    worker's tool-call dispatch.
    Test: ``tests/test_hook_trigger.py`` patches ``process_task_id`` and
    asserts it was called with the expected ``(task_id, board, cfg)``
    when ``tool_name='kanban_block'`` and reason starts with the prefix.
    """
    # --- fast early-exit (99% of tool calls) ---
    if tool_name != _HOOK_TARGET_TOOL:
        return

    try:
        # Build effective config: same source-of-truth as the CLI tick so
        # operators can tweak reason_prefix in one place and have both
        # paths honour it.
        section = _load_yaml_section()
        kwargs: dict[str, Any] = {}
        if isinstance(section.get("reason_prefix"), str):
            kwargs["reason_prefix"] = section["reason_prefix"]
        if isinstance(section.get("handoff_marker"), str):
            kwargs["handoff_marker"] = section["handoff_marker"]
        if isinstance(section.get("required_keys"), (list, tuple)):
            kwargs["required_keys"] = tuple(
                str(k) for k in section["required_keys"] if isinstance(k, str)
            )
        if isinstance(section.get("auto_unblock_on_pass"), bool):
            kwargs["auto_unblock_on_pass"] = section["auto_unblock_on_pass"]
        if isinstance(section.get("hmac_secret_env"), str):
            kwargs["hmac_secret_env"] = section["hmac_secret_env"]
        wro = section.get("workspace_root_override")
        if isinstance(wro, str) and wro.strip():
            kwargs["workspace_root_override"] = Path(wro).expanduser()

        # Operator escape hatch: ``hook_enabled: false`` in YAML disables
        # the instant trigger but leaves cron + manual CLI active. Useful
        # for debugging or when the hook is producing duplicate work for
        # some reason.
        if section.get("hook_enabled") is False:
            logger.debug("Aegis hook: disabled via aegis_attestation.hook_enabled=false")
            return

        cfg = _att.AegisConfig(**kwargs)

        reason = _extract_block_reason(args, result)
        if reason is None:
            logger.debug("Aegis hook: kanban_block call without parseable reason; skipping")
            return

        if not reason.lstrip().startswith(cfg.reason_prefix):
            logger.debug(
                "Aegis hook: reason %r does not match prefix %r; skipping",
                reason[:60], cfg.reason_prefix,
            )
            return

        # Pull task_id / board from args; fall back to the hook kwarg
        # (``task_id``) which the agent core passes as the currently-active
        # kanban task in scope.
        arg_task_id, board = _extract_task_and_board(args)
        target_task_id = arg_task_id or task_id
        if not target_task_id:
            logger.warning(
                "Aegis hook: kanban_block with review-required reason but no "
                "task_id resolvable (args=%r); skipping (cron will catch up)",
                args,
            )
            return

        logger.info(
            "Aegis hook: kanban_block(review-required) detected on task %s "
            "(board=%s) — running instant attestation",
            target_task_id, board,
        )
        summary = _att.process_task_id(target_task_id, board=board, cfg=cfg)
        logger.info(
            "Aegis hook: task=%s attested=%d passed=%d failed=%d "
            "skipped=%d unblocked=%d",
            target_task_id,
            summary.attested, summary.passed, summary.failed,
            summary.skipped, summary.unblocked,
        )
    except Exception as exc:
        # NEVER let a hook exception break tool dispatch. Log and move on —
        # cron tick will catch this task on its next pass.
        logger.exception(
            "Aegis hook: unexpected error on kanban_block (task_id=%s); "
            "deferring to cron catch-up. %s",
            task_id, exc,
        )


# ---------------------------------------------------------------------------
# Plugin entrypoints
# ---------------------------------------------------------------------------

def cli_main(argv: Optional[list[str]] = None) -> int:
    """Why: Lets the plugin be invoked as ``python -m hermes_plugins.aegis_attestation``
    when, for some reason, the hermes CLI is unavailable (rescue path).
    What: Builds a standalone argparse parser, dispatches to handlers.
    Test: cli_main(['config']) prints JSON and returns 0.
    """
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis attestation CLI")
    _build_argparse(parser)
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1
    return int(func(args) or 0)


def register(ctx: Any) -> None:
    """Why: Hermes plugin loader calls this with a PluginContext; we wire
    BOTH the CLI command (``hermes aegis ...``) AND the ``post_tool_call``
    hook for the hybrid (instant + cron catch-up) trigger model.
    What: Two registrations:
      1. ``register_cli_command`` — exposes ``hermes aegis tick/status/config``.
      2. ``register_hook("post_tool_call", _on_post_tool_call)`` — fires
         instant attestation when a worker calls
         ``kanban_block(reason='review-required: ...')``.
    Both registrations degrade gracefully if the PluginContext API is older
    than expected (older Hermes versions). The plugin's behaviour falls
    back to: CLI-only if hook API missing; ``python -m`` fallback if both
    missing.
    Test: ``test_register`` mocks ctx, asserts both register_cli_command
    AND register_hook were called.
    """
    # --- 1. CLI command ---
    try:
        ctx.register_cli_command(
            name="aegis",
            help="Tier-A deterministic attestation for kanban deliverables.",
            setup_fn=_build_argparse,
            description=(
                "Run `hermes aegis tick` (typically from cron) to scan "
                "review-required blocked tasks, verify declared deliverables "
                "via sha256, post an HMAC-signed attestation comment, and "
                "optionally unblock on pass."
            ),
        )
        logger.debug("aegis-attestation: registered `hermes aegis` CLI command")
    except AttributeError:
        logger.warning(
            "PluginContext.register_cli_command unavailable; "
            "aegis-attestation reachable only via `python -m hermes_plugins.aegis_attestation`"
        )

    # --- 2. post_tool_call hook for instant trigger ---
    # Operator may disable the hook entirely via
    # ``aegis_attestation.hook_enabled: false`` in ~/.hermes/config.yaml.
    # The check inside ``_on_post_tool_call`` honours that flag per-call so
    # operators can toggle without a Hermes restart. We still register here
    # because the registration itself is cheap.
    try:
        register_hook = getattr(ctx, "register_hook", None)
        if register_hook is None:
            logger.warning(
                "PluginContext.register_hook unavailable; aegis-attestation "
                "instant trigger disabled — cron will still catch handoffs "
                "but with up to 60s latency"
            )
        else:
            register_hook("post_tool_call", _on_post_tool_call)
            logger.debug(
                "aegis-attestation: registered post_tool_call hook for instant "
                "attestation on kanban_block(review-required)"
            )
    except Exception as exc:
        # Defensive: never let a broken hook-registration crash the loader.
        # Plugin still works in cron-only mode.
        logger.exception(
            "aegis-attestation: failed to register post_tool_call hook (%s); "
            "falling back to cron-only mode", exc,
        )
