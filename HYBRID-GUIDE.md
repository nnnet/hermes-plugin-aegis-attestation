# Aegis Hybrid Trigger Guide (v0.2.0)

> The operator-facing guide for running aegis-attestation with the
> two-trigger model: instant **post_tool_call hook** + periodic **cron
> catch-up**. Companion to the design-oriented `README.md` and the
> implementation-rationale `SOUL.md`.

## TL;DR

- **The hook handles 99% of cases.** Workers calling `kanban_block(reason='review-required: ...')` inside the agent process get attestation in milliseconds — no config needed beyond enabling the plugin.
- **The cron tick is a safety net** for the other 1% (UI-issued blocks, CLI blocks, dispatcher cleanup). 5-minute interval is fine.
- **All three components are stdlib-only.** Hook + cron + plugin code = no new dependencies.

## Two-trigger model — when each fires

```
Worker process (agent turn)        Anywhere else
────────────────────────────       ───────────────────────────
kanban_block(reason="            kanban_block via:
  review-required: ...")           - Web UI button
        │                          - `hermes kanban block` CLI
        │                          - dispatcher timeout cleanup
        │                          - manual sqlite poke
        ▼                              │
post_tool_call hook fires             │
        │                              │
        ▼                              ▼
attestation.process_task_id() ←── aegis-tick.timer (5min)
        │                              │
        ▼                              ▼
   ┌──────────────────────────────────────┐
   │ ALL paths converge at _process_one_task │
   │ - parses handoff JSON                   │
   │ - sha256s declared files                │
   │ - posts aegis-attest v1 comment         │
   │ - unblocks on PASS (if auto_unblock=on) │
   │ - IDEMPOTENT: skips if comment exists   │
   └──────────────────────────────────────┘
```

### Why both?

| Scenario | Hook latency | Cron latency | Without hook | Without cron |
|---|---|---|---|---|
| Worker → kanban_block | <100ms | up to 5min | up to 5min | <100ms |
| UI → block button | (hook can't fire) | up to 5min | never attested | never attested |
| CLI → `hermes kanban block` | (hook can't fire) | up to 5min | never attested | never attested |
| Dispatcher → auto-block on timeout | (hook can't fire) | up to 5min | never attested | never attested |

Hook alone leaves ~1% of handoffs un-attested. Cron alone has up to 5min latency on every handoff. Hybrid: best of both with zero overlap (idempotency).

## Installation — fresh activation

### 1. Verify plugin is loaded

```bash
hermes plugins list | grep aegis
# → aegis-attestation v0.2.0  (kind=standalone)
```

If missing, append to `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - aegis-attestation
```

Then `hermes restart` (rebuild not required for plugin enable — but if the
plugin code is mounted into the container, you do need to restart so
register() runs).

### 2. Generate the HMAC signing key

```bash
# Random 256-bit hex secret.
HMAC_KEY=$(openssl rand -hex 32)

# Persist in ~/.hermes/.env so both the worker process AND the cron tick
# pick up the same key. Both must sign with the same key for downstream
# verification.
echo "AEGIS_ATTEST_HMAC_KEY=$HMAC_KEY" >> ~/.hermes/.env

# IMPORTANT for docker-deployed Hermes: ~/.hermes/.env is the env_file of
# the gateway container, so plugin code inside the container already sees
# the key after the next `hermes restart`.

unset HMAC_KEY
```

Without this var the plugin still works but writes **unsigned**
attestation comments (warning logged once per tick). Signature exists for
tamper detection only — verification logic still runs.

### 3. Install the systemd-user timer (catch-up cron)

```bash
# Use absolute paths so systemd can find everything regardless of $PWD.
PLUGIN_DIR=/mnt/9/aimanager/sources/hermes-agent/plugins/aegis_attestation

mkdir -p ~/.config/systemd/user
cp "$PLUGIN_DIR/contrib/aegis-tick.service" ~/.config/systemd/user/
cp "$PLUGIN_DIR/contrib/aegis-tick.timer"   ~/.config/systemd/user/

# IMPORTANT: edit ExecStart in the service file to point at the absolute
# path of your aegis-tick.sh. The default in contrib/ points at the
# canonical /mnt/9/aimanager/ install; change if yours differs.

systemctl --user daemon-reload
systemctl --user enable --now aegis-tick.timer
```

### 4. Verify

```bash
# Timer is scheduled?
systemctl --user list-timers | grep aegis
# →  Mon 2026-05-19 10:35:00 UTC  1min 23s left  aegis-tick.timer  aegis-tick.service

# Wait 30 seconds for first tick.
sleep 30

# Tick wrote to log?
tail -n 10 ~/.hermes/logs/aegis.log

# Manual one-shot check (no need to wait for timer):
hermes aegis tick --json
```

### 5. Smoke test (full path with synthetic handoff)

```bash
# 1. Create a synthetic kanban task on the default board.
TASK_ID=$(hermes kanban create --title "aegis smoke test" --body "noop" --json | jq -r .id)

# 2. Simulate worker handoff: post a review-required comment.
hermes kanban comment $TASK_ID --body "$(cat <<EOF
review-required handoff:
{
  "changed_files": [],
  "tests_run": 0, "tests_passed": 0,
  "diff_path": "/tmp",
  "decisions": ["smoke test, no real work"]
}
EOF
)"

# 3. Block the task.
hermes kanban block $TASK_ID --reason "review-required: smoke test"

# 4. Wait for either the hook (if the block went through an agent — won't
#    here since it's a CLI block) OR the cron tick (~5min). Force it
#    immediately with manual tick:
hermes aegis tick --board <board-slug> --json

# 5. Look for the aegis-attest comment.
hermes kanban comments $TASK_ID | grep -A 15 aegis-attest
# → aegis-attest v1: PASS
#   { "schema": "aegis-attest/v1", "task_id": "...", "ok": true, ... }
```

## YAML configuration (full reference)

All keys are optional; defaults are baked into `AegisConfig`.

```yaml
aegis_attestation:
  # The exact prefix Aegis looks for on the kanban_block reason. Workers
  # MUST use this prefix in the reason string for Aegis to trigger.
  # Default: "review-required:"
  reason_prefix: "review-required:"

  # The marker line in the handoff comment that precedes the JSON payload.
  # Default: "review-required handoff:"
  handoff_marker: "review-required handoff:"

  # Top-level keys the handoff JSON must contain to be considered valid.
  # Worker writes any of these; Aegis verifies their presence.
  # Default: ["changed_files"]
  required_keys:
    - changed_files

  # Whether to flip task.status from 'blocked' back to 'ready' (or whatever
  # the kanban default is) when attestation PASSes. Set false to keep the
  # task blocked for a human reviewer even after Aegis approves.
  # Default: true
  auto_unblock_on_pass: true

  # Env var name to read the HMAC signing secret from. Override only if
  # you need to share a key across multiple Hermes instances under
  # a different name.
  # Default: "AEGIS_ATTEST_HMAC_KEY"
  hmac_secret_env: "AEGIS_ATTEST_HMAC_KEY"

  # ABSOLUTE path to the workspace root override. Normally Aegis derives
  # the path from kanban_db.workspaces_root(board) / task_id. Set this
  # ONLY for testing or unusual workspace layouts.
  # Default: null  (use kanban_db default)
  workspace_root_override: null

  # === v0.2.0 new ===
  # Master switch for the post_tool_call hook. Setting false disables the
  # INSTANT trigger but leaves the CLI tick (and systemd-user timer)
  # fully functional. Useful if the hook is producing duplicate work
  # for some reason and you need to fall back to cron-only.
  # Default: true
  hook_enabled: true
```

## Operations — common tasks

### Toggle the hook without restart

The hook re-reads YAML config on every call. Change in `~/.hermes/config.yaml`:

```yaml
aegis_attestation:
  hook_enabled: false   # disables instant trigger; cron still runs
```

No restart needed — the next tool call will see the new value.

### Pause the cron tick temporarily

```bash
systemctl --user stop aegis-tick.timer        # not active until reboot or start
# OR
systemctl --user disable --now aegis-tick.timer  # stays disabled across reboots
```

### Force-attest a stuck task

```bash
hermes aegis tick --board <slug> --json
# Or with no auto-unblock (verify-only):
hermes aegis tick --no-unblock --board <slug>
```

### See what the plugin would do (read-only)

```bash
hermes aegis status --board <slug>
# → AegisConfig: {...}
# → blocked review-required tasks: 2 / 5 total blocked
```

### Tail the catch-up log

```bash
tail -f ~/.hermes/logs/aegis.log
```

The log entry format:
```
[2026-05-19T10:35:00Z] aegis-tick mode=docker start
{ "inspected": 5, "skipped": 4, "attested": 1, "passed": 1, ... }
[2026-05-19T10:35:00Z] aegis-tick mode=docker exit=0
```

## Troubleshooting

### Hook does not fire

Symptom: a worker called `kanban_block(reason='review-required: ...')`
but no aegis-attest comment was posted within the agent turn.

Check in order:

1. **Plugin loaded?**
   ```bash
   hermes plugins list | grep aegis
   ```
   If missing — add to `plugins.enabled` and restart.

2. **Hook actually registered?**
   ```bash
   hermes restart 2>&1 | grep -i aegis
   # Expect: "aegis-attestation: registered post_tool_call hook..."
   ```
   If not — your Hermes core may be older than the hook API. Plugin will
   say "PluginContext.register_hook unavailable" in startup logs. Fallback
   to cron-only mode is automatic.

3. **Hook disabled in YAML?**
   ```bash
   grep -A 1 'hook_enabled' ~/.hermes/config.yaml
   ```
   If `hook_enabled: false` — remove or set to true.

4. **Reason prefix mismatch?**
   ```bash
   # The worker's reason must start with cfg.reason_prefix.
   # Inspect what the worker actually sent:
   hermes kanban events <task_id> --json | jq '.[] | select(.event == "blocked")'
   ```

5. **Hook fired but exception swallowed?**
   The hook never raises (by design — must not break dispatch). Check
   container logs:
   ```bash
   docker logs hermes 2>&1 | grep "Aegis hook"
   ```
   Or for host-installed Hermes:
   ```bash
   tail -n 100 ~/.hermes/logs/gateway.log | grep "Aegis hook"
   ```

### Cron tick fires but no attestation posted

Most common cause: kanban task is in a workspace state Aegis doesn't recognise.

```bash
hermes aegis tick --board <slug> -v --json
```

Look for the `skipped` count and the `--verbose` log lines describing
**why** each task was skipped. Common reasons:

- `task already has an attestation comment` — idempotency saved you.
- `no parseable handoff` — worker forgot the handoff JSON, or used wrong marker.
- `workspace ... does not exist` — task is `workspace_kind=worktree`
  but the worker never created the worktree dir. This will record a FAIL
  with `reason: workspace_missing`.

### HMAC env var not set

```
WARNING aegis-attest: AEGIS_ATTEST_HMAC_KEY not set; writing unsigned attestation
```

Generate one (see Installation step 2). The unsigned mode still works —
just no tamper detection.

### Worker turn includes kanban_block but no agent process

If `kanban_block` was called from CLI/UI/dispatcher, the hook can't fire
(no agent context → no `register_hook` callbacks). Cron handles it within
5 min. If you need immediate attestation:

```bash
hermes aegis tick --board <slug> --json
```

## Security & limits — read before relying on this

### Limits (carried over from v0.1.0)

- **No content judgment.** Trivially-empty file PASSes. Aegis answers "did
  the worker write the files it claimed?", not "is the code good?". Pair
  with Tier-B `aegis_review` (LLM review) for content critique.

- **No diff inspection.** If you want diff-aware verification, ship a
  Tier-B plugin that reads aegis-attest comments and adds its own.

- **Per-task workspace assumed.** Tasks with `workspace_kind=worktree` and
  no explicit `workspace_path` are skipped (worker is responsible for
  creating the worktree directory before the handoff).

- **HMAC key rotation is out-of-scope.** Rotating the env var invalidates
  previously-signed comments. Verifiers must keep a history of keys if
  they want to re-verify old attestations across rotations.

### Hook-specific limits (new in v0.2.0)

- **Hook only fires inside an agent process.** Blocks done via Web UI,
  `hermes kanban block` CLI, or the dispatcher's auto-block on timeout
  DO NOT trigger the hook. Cron picks these up.

- **Hook is observational, not gating.** The `post_tool_call` hook fires
  AFTER `kanban_block` succeeded. It cannot prevent the block. If you
  need a gate-before-block model, write a `pre_tool_call` hook instead
  (out of scope for this plugin).

- **Hook exception → cron catch-up.** If the hook callback raises (it
  shouldn't — exception is swallowed and logged), the task is left for
  the next cron tick. Worst case: ≤5 min latency on the catch-up.

- **Hook re-reads YAML on every kanban_block call.** Negligible cost
  (single file read, cached by OS), but you may see a slight bump in
  syscall count on workers that block frequently.

## Rollback

If v0.2.0 misbehaves you have three rollback granularities:

### Soft: disable hook only (5 seconds, no restart)

```yaml
# ~/.hermes/config.yaml
aegis_attestation:
  hook_enabled: false
```

Plugin still loaded, CLI still works, cron still runs. Hook is a no-op.

### Medium: disable plugin entirely (1 minute, restart)

```yaml
# ~/.hermes/config.yaml
plugins:
  enabled: []   # remove aegis-attestation from the list
```

Then `hermes restart`. Cron tick will start failing (`hermes aegis` is
no longer a registered subcommand) — disable the timer too:

```bash
systemctl --user disable --now aegis-tick.timer
```

### Hard: downgrade to v0.1.0

```bash
cd /mnt/9/aimanager/sources/hermes-agent
git checkout <commit-before-feat/aegis-hybrid-trigger>
hermes restart
```

Existing attestation comments remain valid (HMAC keys + schema unchanged).

---

## See also

- `README.md` — design overview, worker handoff contract, schema spec
- `SOUL.md` — implementation rationale (why Tier-A is pure-stdlib)
- `tests/test_attestation.py` — core verification logic tests
- `tests/test_hook_trigger.py` — hook callback tests
- Code: `attestation.py`, `__init__.py`, `plugin.yaml`
