# aegis-attestation

**Tier-A deterministic kanban-deliverable attestation.** No LLM, no network,
stdlib only.

> **v0.2.0 — hybrid trigger.** The plugin now fires INSTANTLY via a
> `post_tool_call` hook the moment a worker calls
> `kanban_block(reason='review-required: ...')`. The CLI tick (cron /
> systemd) remains as a catch-up safety net for handoffs the hook misses
> (Web UI / CLI / dispatcher blocks). See **[`HYBRID-GUIDE.md`](HYBRID-GUIDE.md)**
> for full operator documentation.
>
> Ready-to-install systemd-user units are in [`contrib/`](contrib/):
> `aegis-tick.sh` (wrapper, docker-aware), `aegis-tick.service`,
> `aegis-tick.timer` (5-min interval — fine since hook covers 99%).

## Quickstart

### 1. Enable the plugin

Append to `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - aegis-attestation
```

Verify it loaded:

```bash
hermes plugins list | grep aegis
```

### 2. Run it manually

```bash
hermes aegis tick                  # all blocked review-required tasks on active board
hermes aegis tick --board cookai   # specific board
hermes aegis tick --no-unblock     # verify + comment, don't unblock
hermes aegis tick --json           # machine-parseable output (cron-friendly)
```

Inspect current state without mutating anything:

```bash
hermes aegis status
hermes aegis config
```

### 3. Wire up cron

```cron
* * * * * /usr/local/bin/hermes aegis tick --json >> ~/.hermes/logs/aegis.log 2>&1
```

Or a systemd timer (`~/.config/systemd/user/aegis-tick.{service,timer}`):

```ini
# aegis-tick.service
[Unit]
Description=Aegis attestation tick

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hermes aegis tick --json
StandardOutput=append:%h/.hermes/logs/aegis.log
StandardError=append:%h/.hermes/logs/aegis.log
```

```ini
# aegis-tick.timer
[Unit]
Description=Run aegis tick every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now aegis-tick.timer
```

### 4. (Optional) Enable HMAC signing

```bash
export AEGIS_ATTEST_HMAC_KEY=$(openssl rand -hex 32)
# Persist in your shell rc / systemd Environment= entry / ~/.hermes/.env
```

Without this env var aegis logs a warning once per tick and writes
**unsigned** attestation comments — the verification still works, just
without tamper detection.

### 5. Fallback invocation (no hermes CLI)

```bash
cd /path/to/hermes-agent
python -m plugins.aegis_attestation tick --board <slug>
```

> Note: when invoked via `python -m` the package directory must be on
> `PYTHONPATH`. From the hermes-agent repo root this is automatic. The
> on-disk directory is `plugins/aegis_attestation/` (underscore — required
> by Python's import machinery); the operator-facing name in `plugin.yaml`
> and `plugins.enabled` stays `aegis-attestation` (hyphen). Hermes' plugin
> loader normalises one to the other.

## What a "worker handoff" looks like

The worker (typically the `kanban-worker` skill) finishes by writing a
comment whose body contains the marker line followed by JSON:

```python
kanban_comment(
    body="review-required handoff:\n" + json.dumps({
        "changed_files": ["src/rate_limiter.py", "tests/test_rate_limiter.py"],
        "tests_run": 14,
        "tests_passed": 14,
        "diff_path": "/abs/path/to/worktree",
        "decisions": ["user_id primary, IP fallback for unauthenticated"],
    }, indent=2),
)
kanban_block(reason="review-required: rate limiter shipped, 14/14 tests pass")
```

Aegis then verifies each entry in `changed_files` exists *inside the
task workspace*, hashes them, and posts a comment like:

```
aegis-attest v1: PASS
{
  "schema": "aegis-attest/v1",
  "task_id": "t_abc123",
  "ok": true,
  "verified": 2,
  "declared": 2,
  "files": [
    { "path": "src/rate_limiter.py", "sha256": "...", "size": 4096, "ok": true, ... },
    { "path": "tests/test_rate_limiter.py", "sha256": "...", "ok": true, ... }
  ],
  "handoff_keys": ["changed_files", "decisions", "diff_path", "tests_passed", "tests_run"],
  "signature": "<HMAC-SHA256 hex if AEGIS_ATTEST_HMAC_KEY set, else null>",
  "timestamp": 1715789432
}
```

On `PASS` the task is auto-unblocked (toggle via `--no-unblock`).

## Running the tests

```bash
cd /mnt/9/aimanager/sources/hermes-agent
python -m pytest plugins/aegis_attestation/tests/ -v -o "addopts="
```

The `-o "addopts="` override is required because the repo's `pyproject.toml`
sets `-n auto` (pytest-xdist) at project level; not every dev shell has
xdist installed. We don't pull xdist into the plugin's dev-deps just for
the override.

The unit tests are stdlib-only and stub `kanban_db` — they do not require
a live kanban DB. See `SOUL.md` for the design rationale.

## Limits (read before relying on this)

- **No content judgment.** A trivially-empty file PASSes. Aegis answers
  "did the worker write the files it claimed?", not "is the code good?".
- **No diff inspection.** If you want diff-aware verification, ship a
  Tier-B plugin that reads aegis-attest comments and adds its own.
- **Per-task workspace assumed**. Tasks with `workspace_kind=worktree`
  and no explicit `workspace_path` are skipped (worker is responsible
  for creating the worktree directory before the handoff).
- **HMAC key rotation** is out-of-scope; rotating the env var invalidates
  previously-signed comments.
