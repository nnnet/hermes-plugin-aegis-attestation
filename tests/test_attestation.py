"""Unit tests for aegis-attestation pure functions.

Why: The DB-driven tick() loop is hard to exercise without a kanban DB,
but the pure verification functions (sha256, parse_handoff, attest_task,
sign_payload) carry all the security-sensitive logic — so they get
exhaustive coverage here with stdlib-only fakes and pytest fixtures.

What: Each test exercises one branch of one function. Doubles for
``Comment`` are simple namespace objects with a ``body`` attribute, matching
the shape ``kanban_db.list_comments`` produces.

Test: ``pytest plugins/aegis_attestation/tests/ -v -o "addopts="`` from
the repo root. The ``-o "addopts="`` override neutralises the project-level
``-n auto`` (pytest-xdist) addopts so plain pytest works without xdist
installed.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Import the plugin module without going through the hermes plugin loader.
# We load `attestation.py` directly via importlib.util so the tests stay
# decoupled from the package-discovery dance (sys.path tweaks, namespace
# packages, etc.) — this works regardless of whether pytest imports the
# parent `__init__.py` or not.
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_PLUGIN_DIR = _HERE.parent
_REPO_ROOT = _PLUGIN_DIR.parent.parent  # hermes-agent/


def _load_attestation() -> Any:
    """Why: We want the unit tests to exercise ``attestation.py`` in isolation
    without dragging in the plugin's argparse / kanban_db wiring from
    ``__init__.py``. Loading via importlib spec from the file path keeps
    the test independent of how pytest decides to import the parent package.
    What: Returns the attestation submodule with the expected public API.
    Test: This function itself is exercised on import of this test file.
    """
    spec = importlib.util.spec_from_file_location(
        "aegis_attestation_under_test",
        _PLUGIN_DIR / "attestation.py",
    )
    assert spec is not None and spec.loader is not None, "spec creation failed"
    module = importlib.util.module_from_spec(spec)
    sys.modules["aegis_attestation_under_test"] = module
    spec.loader.exec_module(module)
    return module


att = _load_attestation()


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeComment:
    """Why: kanban_db.Comment has more fields than we need; the parse logic
    only uses .body, so a thin namespace suffices for unit tests.
    What: Holds .body (str) and an optional .author/.created_at for shape
    parity with the real Comment dataclass.
    Test: Used in parse_handoff and has_existing_attestation tests below.
    """

    def __init__(self, body: str, author: str = "worker", created_at: int = 0) -> None:
        self.body = body
        self.author = author
        self.created_at = created_at


# ---------------------------------------------------------------------------
# sha256_file
# ---------------------------------------------------------------------------


def test_sha256_file_matches_stdlib(tmp_path: Path) -> None:
    """Why: Confidence that chunked reads produce the same digest as a
    one-shot hashlib.sha256(data).hexdigest().
    """
    f = tmp_path / "fixture.bin"
    payload = b"hermes aegis attestation fixture content " * 128
    f.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert att.sha256_file(f) == expected


def test_sha256_file_chunk_independence(tmp_path: Path) -> None:
    """Why: Digest must not change with chunk_size — guards against an
    accidental dependency on read boundaries.
    """
    f = tmp_path / "fixture.bin"
    f.write_bytes(b"X" * 200_000)
    assert att.sha256_file(f, chunk_size=1024) == att.sha256_file(f, chunk_size=64 * 1024)


# ---------------------------------------------------------------------------
# parse_handoff
# ---------------------------------------------------------------------------


def _handoff_body(payload: dict[str, Any]) -> str:
    return f"{att.DEFAULT_HANDOFF_MARKER}\n{json.dumps(payload, indent=2)}"


def test_parse_handoff_valid_json() -> None:
    """Why: Happy path — one matching comment, returns the parsed dict."""
    payload = {"changed_files": ["a.py"], "tests_run": 1}
    comments = [_FakeComment(_handoff_body(payload))]
    out = att.parse_handoff(comments)
    assert out == payload


def test_parse_handoff_no_marker() -> None:
    """Why: A comment list with no handoff-marker comment must return None
    so the tick loop skips the task instead of attesting nothing.
    """
    comments = [_FakeComment("just a chat comment")]
    assert att.parse_handoff(comments) is None


def test_parse_handoff_invalid_json_falls_back() -> None:
    """Why: A malformed handoff must not break the whole tick — older valid
    handoff in the list should still be returned.
    """
    valid = {"changed_files": ["a.py"]}
    comments = [
        _FakeComment(_handoff_body(valid)),
        _FakeComment(f"{att.DEFAULT_HANDOFF_MARKER}\n{{not json"),
    ]
    # parse_handoff walks in reverse; the malformed one (last) is skipped,
    # the valid earlier one wins.
    assert att.parse_handoff(comments) == valid


def test_parse_handoff_picks_most_recent() -> None:
    """Why: When the worker re-handoffs (e.g. after reviewer feedback), the
    newest comment should win.
    """
    old = {"changed_files": ["v1.py"]}
    new = {"changed_files": ["v2.py"]}
    comments = [_FakeComment(_handoff_body(old)), _FakeComment(_handoff_body(new))]
    assert att.parse_handoff(comments) == new


def test_parse_handoff_non_object_json() -> None:
    """Why: JSON arrays/strings must be rejected — we need an object."""
    comments = [_FakeComment(f"{att.DEFAULT_HANDOFF_MARKER}\n[1, 2, 3]")]
    assert att.parse_handoff(comments) is None


# ---------------------------------------------------------------------------
# attest_task
# ---------------------------------------------------------------------------


def test_attest_task_all_present(tmp_path: Path) -> None:
    """Why: Happy path — two declared files exist, both hashable, overall
    PASS with verified=2."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.py").write_text("print('a')\n")
    (workspace / "b.py").write_text("print('b')\n")
    handoff = {"changed_files": ["a.py", "b.py"]}

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is True
    assert result.verified == 2
    assert result.declared == 2
    assert result.reason is None
    assert all(fc.ok and fc.sha256 for fc in result.files)


def test_attest_task_missing_file(tmp_path: Path) -> None:
    """Why: A declared file that doesn't exist must FAIL with
    reason='missing_deliverables' and per-file reason='missing_file'.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "exists.py").write_text("ok\n")
    handoff = {"changed_files": ["exists.py", "gone.py"]}

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is False
    assert result.verified == 1
    assert result.declared == 2
    assert result.reason == "missing_deliverables"
    missing_check = next(fc for fc in result.files if fc.path == "gone.py")
    assert missing_check.reason == "missing_file"
    assert missing_check.ok is False


def test_attest_task_path_escape(tmp_path: Path) -> None:
    """Why: Workspace-escape via ../ must be rejected — security-critical.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    # Sibling file we should NOT be able to reach
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    handoff = {"changed_files": ["../outside.txt"]}

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is False
    assert result.reason == "path_escape"
    fc = result.files[0]
    assert fc.reason == "path_escape"
    assert fc.sha256 is None  # never hashed


def test_attest_task_missing_required_key(tmp_path: Path) -> None:
    """Why: A handoff lacking changed_files isn't even worth attesting."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    handoff = {"tests_run": 14}  # no changed_files

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is False
    assert result.reason is not None and result.reason.startswith("missing_handoff_keys")


def test_attest_task_changed_files_not_a_list(tmp_path: Path) -> None:
    """Why: Worker might write changed_files as a string by mistake — must
    fail cleanly, not crash."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    handoff = {"changed_files": "a.py"}

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is False
    assert result.reason == "changed_files_not_a_list"


def test_attest_task_empty_changed_files(tmp_path: Path) -> None:
    """Why: A handoff with empty changed_files declares zero deliverables —
    no work to verify, so OK is false (verified=0)."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    handoff = {"changed_files": []}

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is False
    assert result.verified == 0
    assert result.declared == 0


def test_attest_task_directory_not_file(tmp_path: Path) -> None:
    """Why: A declared path that resolves to a directory must FAIL — we
    only hash regular files.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "subdir").mkdir()
    handoff = {"changed_files": ["subdir"]}

    result = att.attest_task("t_x", workspace, handoff, att.AegisConfig())
    assert result.ok is False
    fc = result.files[0]
    assert fc.reason == "not_a_regular_file"


# ---------------------------------------------------------------------------
# sign_payload
# ---------------------------------------------------------------------------


def test_sign_no_key_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Why: Operators may forget to set the env var; the plugin must
    degrade gracefully (warn + return None) instead of crashing.
    """
    monkeypatch.delenv(att.DEFAULT_HMAC_ENV, raising=False)
    assert att.sign_payload({"task_id": "t_x", "ok": True}) is None


def test_sign_with_key_hmac_matches_known_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why: We must verify the HMAC algorithm is HMAC-SHA256 over
    canonical_bytes, otherwise external verifiers would compute a
    mismatching MAC."""
    key = "0" * 64  # fixture key
    monkeypatch.setenv(att.DEFAULT_HMAC_ENV, key)
    payload = {"task_id": "t_x", "ok": True, "verified": 1}

    sig = att.sign_payload(payload)
    expected = hmac.new(
        key.encode("utf-8"),
        att.canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    assert sig == expected


def test_sign_canonical_bytes_stable_across_key_order() -> None:
    """Why: Re-verification by a third party will likely reconstruct the
    payload dict in a different key order — our canonical encoding must
    be order-independent."""
    a = {"task_id": "t", "ok": True, "verified": 1}
    b = {"verified": 1, "ok": True, "task_id": "t"}
    assert att.canonical_bytes(a) == att.canonical_bytes(b)


# ---------------------------------------------------------------------------
# format_comment_body / has_existing_attestation
# ---------------------------------------------------------------------------


def test_format_comment_body_includes_marker_and_verdict() -> None:
    """Why: The leading marker is what the loop greps for to detect
    already-attested tasks — must not regress."""
    result = att.AttestationResult(task_id="t_x", ok=True, verified=1, declared=1)
    body = att.format_comment_body(result)
    assert body.startswith(att.ATTESTATION_COMMENT_MARKER)
    assert "PASS" in body.splitlines()[0]


def test_format_comment_body_failure_has_reason() -> None:
    """Why: Reviewer must see why we failed without parsing JSON."""
    result = att.AttestationResult(
        task_id="t_x", ok=False, verified=0, declared=2, reason="missing_deliverables"
    )
    header = att.format_comment_body(result).splitlines()[0]
    assert "FAIL" in header
    assert "missing_deliverables" in header


def test_has_existing_attestation_detects_marker() -> None:
    """Why: Idempotency — a second tick must skip already-attested tasks."""
    comments = [_FakeComment("plain"), _FakeComment("aegis-attest v1: PASS\n{...}")]
    assert att.has_existing_attestation(comments) is True


def test_has_existing_attestation_false_when_absent() -> None:
    comments = [_FakeComment("plain"), _FakeComment(_handoff_body({"changed_files": []}))]
    assert att.has_existing_attestation(comments) is False


# ---------------------------------------------------------------------------
# _resolve_under_root (path-escape security)
# ---------------------------------------------------------------------------


def test_resolve_under_root_accepts_normal_path(tmp_path: Path) -> None:
    """Why: Confirm the happy-path resolution still works after the
    relative_to() guard."""
    root = tmp_path / "ws"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "x.py").write_text("ok")

    resolved = att._resolve_under_root("src/x.py", root)
    assert resolved is not None
    assert resolved == (root / "src" / "x.py").resolve()


def test_resolve_under_root_rejects_parent_traversal(tmp_path: Path) -> None:
    """Why: Defense in depth — the canonical attack vector."""
    root = tmp_path / "ws"
    root.mkdir()
    assert att._resolve_under_root("../../../etc/passwd", root) is None


def test_resolve_under_root_rejects_absolute_outside(tmp_path: Path) -> None:
    """Why: An absolute path outside the root must be rejected even when
    Path.resolve() returns it intact."""
    root = tmp_path / "ws"
    root.mkdir()
    # Absolute path that doesn't begin with root
    assert att._resolve_under_root("/etc/passwd", root) is None


# ---------------------------------------------------------------------------
# AttestationResult payload shape
# ---------------------------------------------------------------------------


def test_attestation_result_to_payload_excludes_signature() -> None:
    """Why: to_payload() is what gets signed — must not include the
    signature field itself or the MAC becomes self-referential."""
    result = att.AttestationResult(task_id="t_x", ok=True)
    result.signature = "deadbeef"
    payload = result.to_payload()
    assert "signature" not in payload


def test_attestation_result_to_payload_has_required_keys() -> None:
    """Why: Downstream consumers (dashboard, Tier-B) rely on schema
    stability — guard the keys."""
    result = att.AttestationResult(task_id="t_x", ok=True, verified=1, declared=1)
    payload = result.to_payload()
    for key in ("schema", "task_id", "ok", "verified", "declared", "files", "timestamp"):
        assert key in payload


# ---------------------------------------------------------------------------
# AegisConfig
# ---------------------------------------------------------------------------


def test_aegis_config_is_frozen() -> None:
    """Why: We use AegisConfig as a sentinel passed across threads/cron —
    mutation must be impossible."""
    cfg = att.AegisConfig()
    with pytest.raises(Exception):
        cfg.reason_prefix = "other:"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# YAML config loader (plugins.aegis_attestation.__init__._build_cfg)
# ---------------------------------------------------------------------------


class TestYamlConfigLoader:
    """Why: ``_build_cfg`` is the only thing standing between YAML config and
    the immutable AegisConfig used by tick(); regressions here would silently
    break ops overrides. Each test pins one branch of the type-mapping logic.
    What: Mocks ``hermes_cli.config.load_config`` (or its package-local import
    inside the plugin's __init__) and asserts ``_build_cfg`` produces the
    expected AegisConfig field values.
    Test: ``pytest plugins/aegis_attestation/tests/ -v -k TestYamlConfigLoader``.
    """

    @staticmethod
    def _load_plugin_init() -> Any:
        """Why: Loading the plugin's ``__init__.py`` via importlib (same trick
        as :func:`_load_attestation`) avoids polluting sys.path and works
        whether or not pytest discovers the plugin as a package.
        What: Returns the module with ``_build_cfg`` and ``_load_yaml_section``.
        Test: Used by every test below.
        """
        import importlib.util  # local to keep helper self-contained

        spec = importlib.util.spec_from_file_location(
            "aegis_attestation_init_under_test",
            _PLUGIN_DIR / "__init__.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["aegis_attestation_init_under_test"] = module
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _ns(**kwargs: Any) -> Any:
        """Why: argparse.Namespace mimic for tests without importing argparse.
        What: Returns a SimpleNamespace with the requested attrs.
        Test: Used by every test below."""
        return types.SimpleNamespace(**kwargs)

    def test_no_yaml_section_uses_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why: Backward-compat — operators who never touched config.yaml must
        keep the old behaviour exactly.
        What: load_config returns {}; cfg should equal AegisConfig() except
        for the CLI-driven auto_unblock flag.
        Test: this function."""
        plugin = self._load_plugin_init()
        monkeypatch.setattr(plugin, "_load_yaml_section", lambda: {})
        cfg = plugin._build_cfg(self._ns(no_unblock=False))
        default = att.AegisConfig()
        assert cfg.reason_prefix == default.reason_prefix
        assert cfg.handoff_marker == default.handoff_marker
        assert cfg.required_keys == default.required_keys
        assert cfg.hmac_secret_env == default.hmac_secret_env
        assert cfg.workspace_root_override is None
        assert cfg.auto_unblock_on_pass is True  # default + no CLI override

    def test_yaml_reason_prefix_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why: reason_prefix is the most common operator override (project
        wants a different handoff phrase like ``audit-required:``).
        What: YAML reason_prefix='custom:' surfaces on the dataclass.
        Test: this function."""
        plugin = self._load_plugin_init()
        monkeypatch.setattr(
            plugin, "_load_yaml_section", lambda: {"reason_prefix": "custom:"}
        )
        cfg = plugin._build_cfg(self._ns(no_unblock=False))
        assert cfg.reason_prefix == "custom:"

    def test_yaml_required_keys_list_to_tuple(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why: AegisConfig is frozen and uses a tuple for required_keys;
        YAML always yields a list, so the converter must normalise.
        What: ['a','b'] in YAML -> ('a','b') in the dataclass.
        Test: this function."""
        plugin = self._load_plugin_init()
        monkeypatch.setattr(
            plugin, "_load_yaml_section", lambda: {"required_keys": ["a", "b"]}
        )
        cfg = plugin._build_cfg(self._ns(no_unblock=False))
        assert cfg.required_keys == ("a", "b")
        assert isinstance(cfg.required_keys, tuple)

    def test_cli_no_unblock_overrides_yaml(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why: CLI flags are always the most specific signal; even if YAML
        says auto_unblock_on_pass=true, --no-unblock must win.
        What: YAML true + args.no_unblock=True -> cfg.auto_unblock_on_pass=False.
        Test: this function."""
        plugin = self._load_plugin_init()
        monkeypatch.setattr(
            plugin,
            "_load_yaml_section",
            lambda: {"auto_unblock_on_pass": True},
        )
        cfg = plugin._build_cfg(self._ns(no_unblock=True))
        assert cfg.auto_unblock_on_pass is False

    def test_yaml_workspace_root_path_conversion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why: workspace_root_override is typed Optional[Path]; YAML strings
        must be wrapped in Path() so downstream resolvers can call .resolve().
        What: {'workspace_root_override': '/tmp/aegis'} -> Path('/tmp/aegis').
        Test: this function."""
        plugin = self._load_plugin_init()
        monkeypatch.setattr(
            plugin,
            "_load_yaml_section",
            lambda: {"workspace_root_override": "/tmp/aegis"},
        )
        cfg = plugin._build_cfg(self._ns(no_unblock=False))
        assert cfg.workspace_root_override == Path("/tmp/aegis")

    def test_load_config_returns_none_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why: ``hermes_cli.config.load_config`` legitimately returns None
        when no config file exists; the loader must not blow up.
        What: Mock load_config -> None at the import site; _build_cfg should
        produce a valid AegisConfig with defaults.
        Test: this function."""
        plugin = self._load_plugin_init()
        # Intercept the dynamic ``from hermes_cli.config import load_config``
        # inside ``_load_yaml_section`` by injecting a fake module first.
        fake = types.ModuleType("hermes_cli.config")
        fake.load_config = lambda: None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
        cfg = plugin._build_cfg(self._ns(no_unblock=False))
        # Both helpers load attestation.py twice (file-spec vs. package
        # import), so ``isinstance`` against the file-spec class would fail
        # even though the runtime types are equivalent. Compare by name +
        # default field values instead.
        assert type(cfg).__name__ == "AegisConfig"
        assert cfg.reason_prefix == att.DEFAULT_REASON_PREFIX
        assert cfg.auto_unblock_on_pass is True
        assert cfg.workspace_root_override is None
