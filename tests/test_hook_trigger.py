"""Unit tests for the post_tool_call hook trigger.

Why: The hybrid trigger model (instant hook + cron catch-up) is the headline
feature of v0.2.0. The hook MUST:
  1. Early-exit cheaply on non-kanban_block tool calls (perf — runs on every
     tool call in the agent process).
  2. Extract reason / task_id / board from multiple arg-shapes (dict, nested
     dict, JSON string) — the gateway normalises these inconsistently.
  3. Delegate to attestation.process_task_id() with a config matching what
     the CLI tick would build (single source of truth via _load_yaml_section).
  4. Honour aegis_attestation.hook_enabled=false in YAML config (operator
     escape hatch).
  5. NEVER raise — a buggy hook must not break tool dispatch.

What: Each test patches the minimum surface (process_task_id, _load_yaml_section)
and asserts the callback's behaviour. We do NOT spin up a live kanban DB —
that's the job of test_attestation.py.

Test: ``pytest plugins/aegis_attestation/tests/test_hook_trigger.py -v -o "addopts="``
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent

# Ensure the hermes-agent root is importable so ``plugins.aegis_attestation``
# resolves the same way the plugin loader sees it.
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture
def aegis_module():
    """Why: We import ``plugins.aegis_attestation`` fresh each test to clear
    module-level state and to keep tests order-independent.
    What: Returns the imported package module.
    """
    # Reimport to pick up any patches a test applies before the import.
    import importlib

    mod_name = "plugins.aegis_attestation"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import plugins.aegis_attestation as aa  # noqa: WPS433  # test-only import
    importlib.reload(aa)
    return aa


# ---------------------------------------------------------------------------
# Reason extraction (covers all arg shapes seen in the wild)
# ---------------------------------------------------------------------------


class TestExtractBlockReason:
    """Why: The gateway normalises tool-call args inconsistently across
    versions; the extractor needs to tolerate dict, nested dict, JSON-string,
    and (as a fallback) result-text scanning.
    """

    def test_dict_top_level_reason(self, aegis_module):
        """args is a plain dict with 'reason' key — most common shape."""
        out = aegis_module._extract_block_reason(
            {"reason": "review-required: foo"}, None,
        )
        assert out == "review-required: foo"

    def test_dict_nested_args_reason(self, aegis_module):
        """Some hooks pass {'tool': ..., 'args': {...}} — extractor must dive."""
        out = aegis_module._extract_block_reason(
            {"tool": "kanban_block", "args": {"reason": "review-required: x"}},
            None,
        )
        assert out == "review-required: x"

    def test_json_string_args(self, aegis_module):
        """Older shims serialise args as a JSON string."""
        out = aegis_module._extract_block_reason(
            json.dumps({"reason": "review-required: y"}),
            None,
        )
        assert out == "review-required: y"

    def test_fallback_to_result_text(self, aegis_module):
        """When args is empty, scan result text for the prefix."""
        out = aegis_module._extract_block_reason(
            None,
            "Task t_abc blocked.\nreview-required: shipped, ready for review\n",
        )
        assert out and out.startswith("review-required:")

    def test_no_match_returns_none(self, aegis_module):
        """No reason anywhere — extractor returns None (caller skips)."""
        out = aegis_module._extract_block_reason({}, "some unrelated text")
        assert out is None

    def test_args_none_safe(self, aegis_module):
        """args=None must not raise."""
        out = aegis_module._extract_block_reason(None, None)
        assert out is None


# ---------------------------------------------------------------------------
# Task / board extraction
# ---------------------------------------------------------------------------


class TestExtractTaskAndBoard:
    def test_dict_top_level(self, aegis_module):
        tid, brd = aegis_module._extract_task_and_board(
            {"task_id": "t_x", "board": "cookai"},
        )
        assert tid == "t_x"
        assert brd == "cookai"

    def test_nested_args(self, aegis_module):
        tid, brd = aegis_module._extract_task_and_board(
            {"args": {"task_id": "t_y", "board": "yt"}},
        )
        assert tid == "t_y"
        assert brd == "yt"

    def test_json_string(self, aegis_module):
        tid, brd = aegis_module._extract_task_and_board(
            json.dumps({"task_id": "t_z"}),
        )
        assert tid == "t_z"
        assert brd is None

    def test_missing_returns_none_pair(self, aegis_module):
        tid, brd = aegis_module._extract_task_and_board({})
        assert tid is None and brd is None

    def test_uses_id_as_fallback(self, aegis_module):
        """Some callers use 'id' instead of 'task_id'."""
        tid, brd = aegis_module._extract_task_and_board({"id": "t_alt"})
        assert tid == "t_alt"


# ---------------------------------------------------------------------------
# Hook callback dispatch
# ---------------------------------------------------------------------------


class TestPostToolCallHook:
    """The hottest path: hook gets called for every tool call. Must early-exit
    on the 99% case (tool_name != 'kanban_block') and must never raise."""

    def test_early_exit_on_unrelated_tool(self, aegis_module):
        """Most tool calls aren't kanban_block — hook must skip without
        importing kanban_db or building config."""
        with patch.object(aegis_module._att, "process_task_id") as p:
            aegis_module._on_post_tool_call(
                tool_name="write_file", args={"path": "x"}, result="ok",
            )
            p.assert_not_called()

    def test_kanban_block_with_matching_reason_invokes_attestation(self, aegis_module):
        """The happy path — a worker's kanban_block(review-required) handoff
        triggers process_task_id with the right (task_id, board) tuple."""
        with patch.object(aegis_module._att, "process_task_id") as p, \
             patch.object(aegis_module, "_load_yaml_section", return_value={}):
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"task_id": "t_abc", "board": "cookai",
                      "reason": "review-required: shipped"},
                result="",
            )
            p.assert_called_once()
            kwargs = p.call_args.kwargs
            assert p.call_args.args[0] == "t_abc"
            assert kwargs.get("board") == "cookai"

    def test_kanban_block_with_non_matching_reason_skips(self, aegis_module):
        """``kanban_block`` with a reason that DOESN'T carry the prefix is
        not our concern — e.g. a worker blocking for a different reason."""
        with patch.object(aegis_module._att, "process_task_id") as p, \
             patch.object(aegis_module, "_load_yaml_section", return_value={}):
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"task_id": "t_abc", "reason": "waiting for upstream merge"},
                result="",
            )
            p.assert_not_called()

    def test_falls_back_to_kwarg_task_id(self, aegis_module):
        """When args lacks task_id, the agent core passes the active kanban
        task_id as a kwarg — hook must honour it."""
        with patch.object(aegis_module._att, "process_task_id") as p, \
             patch.object(aegis_module, "_load_yaml_section", return_value={}):
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"reason": "review-required: shipped"},
                result="",
                task_id="t_from_kwarg",
            )
            p.assert_called_once()
            assert p.call_args.args[0] == "t_from_kwarg"

    def test_no_task_id_anywhere_skips_safely(self, aegis_module):
        """Reason matches but task_id cannot be resolved — hook logs and
        skips (cron will catch it)."""
        with patch.object(aegis_module._att, "process_task_id") as p, \
             patch.object(aegis_module, "_load_yaml_section", return_value={}):
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"reason": "review-required: x"},
                result="",
            )
            p.assert_not_called()

    def test_hook_disabled_via_yaml(self, aegis_module):
        """Operator escape hatch — ``hook_enabled: false`` disables instant
        trigger without restart. CLI/cron still work."""
        with patch.object(aegis_module._att, "process_task_id") as p, \
             patch.object(
                 aegis_module, "_load_yaml_section",
                 return_value={"hook_enabled": False},
             ):
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"task_id": "t_x", "reason": "review-required: x"},
                result="",
            )
            p.assert_not_called()

    def test_exception_in_process_task_id_is_swallowed(self, aegis_module):
        """A buggy ``process_task_id`` MUST NOT break tool dispatch. The
        worker's kanban_block call already succeeded — the hook is purely
        observational from the agent's perspective."""
        with patch.object(
            aegis_module._att, "process_task_id",
            side_effect=RuntimeError("boom"),
        ), patch.object(aegis_module, "_load_yaml_section", return_value={}):
            # Must not raise.
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"task_id": "t_x", "reason": "review-required: x"},
                result="",
            )

    def test_custom_reason_prefix_from_yaml(self, aegis_module):
        """Operator can override the prefix via YAML — hook must honour it
        the same way the CLI tick does (single source of truth)."""
        with patch.object(aegis_module._att, "process_task_id") as p, \
             patch.object(
                 aegis_module, "_load_yaml_section",
                 return_value={"reason_prefix": "AEGIS:"},
             ):
            # With custom prefix, the canonical 'review-required:' would NOT
            # match anymore — hook should skip.
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"task_id": "t_x",
                      "reason": "review-required: shipped"},
                result="",
            )
            p.assert_not_called()

            # But the custom prefix DOES match.
            aegis_module._on_post_tool_call(
                tool_name="kanban_block",
                args={"task_id": "t_y", "reason": "AEGIS: shipped"},
                result="",
            )
            p.assert_called_once()
            assert p.call_args.args[0] == "t_y"


# ---------------------------------------------------------------------------
# register() wires both CLI and hook
# ---------------------------------------------------------------------------


class TestRegisterBothCliAndHook:
    """Why: v0.2.0 promises hybrid trigger — the loader must wire BOTH the
    CLI command and the post_tool_call hook. Regression-guard against
    accidentally dropping one of them."""

    def test_register_calls_both(self, aegis_module):
        ctx = MagicMock()
        aegis_module.register(ctx)
        ctx.register_cli_command.assert_called_once()
        ctx.register_hook.assert_called_once()
        args, kwargs = ctx.register_hook.call_args
        assert args[0] == "post_tool_call"
        assert callable(args[1])

    def test_register_survives_missing_hook_api(self, aegis_module):
        """Older Hermes PluginContext may lack register_hook. Plugin must
        degrade gracefully to cron-only, not crash the loader."""
        ctx = MagicMock(spec=["register_cli_command"])
        # No register_hook attribute on the spec'd mock.
        aegis_module.register(ctx)
        ctx.register_cli_command.assert_called_once()

    def test_register_survives_missing_cli_api(self, aegis_module):
        """Even older PluginContext may lack register_cli_command too —
        plugin should still register the hook if available."""
        ctx = MagicMock(spec=["register_hook"])
        # Make register_cli_command raise AttributeError on access.
        del ctx.register_cli_command
        # Implementation uses try/except AttributeError → must not raise.
        try:
            aegis_module.register(ctx)
        except AttributeError:
            pytest.fail("register() leaked AttributeError from missing CLI API")
        ctx.register_hook.assert_called_once()
