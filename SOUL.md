# aegis-attestation — SOUL.md

> Tier-A deterministic attestation for kanban deliverables.

## What does it do

The `aegis-attestation` plugin is a **deterministic, LLM-free pre-check** that
runs between a worker's `kanban_block(reason='review-required: …')` handoff
and a human reviewer. For every blocked task whose reason matches the
configured prefix, the plugin:

1. Reads the most recent comment containing the **handoff marker**
   (`review-required handoff:`), parses the JSON that follows.
2. Locates each path declared under `changed_files` *inside the task's
   workspace* (path-traversal is rejected — `../../etc/passwd` cannot
   escape).
3. Computes the `sha256` of each file using chunked streaming reads
   (safe for multi-GB logs).
4. Builds an `AttestationResult` payload, optionally signs it via
   `HMAC-SHA256` keyed off the env-var `AEGIS_ATTEST_HMAC_KEY`.
5. Posts the payload as a comment authored `aegis-attest` on the task,
   prefixed with the marker `aegis-attest v1: PASS|FAIL`.
6. On `PASS` and when `auto_unblock_on_pass` is enabled, calls
   `kanban_db.unblock_task` to flip the task back to `ready`/`todo`.

It never calls an LLM, never opens a network socket, and depends on
**stdlib only** (`hashlib`, `hmac`, `json`, `os`, `pathlib`, `sqlite3`,
`logging`, `time`, `dataclasses`).

## When it fires

The plugin is **poll-driven**: it does **not** start a background thread on
session-start (that would conflict with interactive user sessions and make
the lifecycle invisible). Instead, operators trigger it explicitly:

- Manually: `hermes aegis tick [--board <slug>] [--no-unblock] [--json]`
- Cron: `* * * * * /usr/local/bin/hermes aegis tick --json >> /var/log/aegis.log 2>&1`
- systemd timer: see `README.md` for a unit template.

A single `tick` run is idempotent — already-attested tasks (those that
already carry an `aegis-attest v1:` comment) are skipped, so re-runs are
cheap and safe.

## What it does **not** do

- **No content validation.** Aegis confirms a file exists and hashes it; it
  does not parse, lint, run, or in any way judge the content. A worker
  could declare `["empty.py"]` and aegis would happily PASS it. That's
  reviewer territory.
- **No LLM judgment.** Tier-A is deliberately deterministic. Routing the
  hash + handoff metadata into an LLM-backed reviewer is the planned
  Tier-B upgrade (see *Layered upgrade path* below).
- **No diff inspection.** A `diff_path` key in the handoff JSON is
  recorded in `handoff_keys` but not opened or analysed.
- **No external services.** No webhook, no HTTP, no PR comments. The
  attestation lives in the kanban comment log.

## Config

The plugin reads defaults from the dataclass `AegisConfig` in
`attestation.py` and applies optional overrides from the
`aegis_attestation:` section of `~/.hermes/config.yaml`. The section is
fully optional — if absent, the dataclass defaults apply. CLI flags
(currently `--no-unblock`) always take precedence over YAML.

```yaml
# ~/.hermes/config.yaml — optional overrides; section is fully optional
aegis_attestation:
  reason_prefix: "review-required:"
  handoff_marker: "review-required handoff:"
  required_keys: ["changed_files"]
  auto_unblock_on_pass: true                   # CLI --no-unblock overrides
  hmac_secret_env: "AEGIS_ATTEST_HMAC_KEY"
  # workspace_root_override: null              # only for tests
```

To enable the plugin, add it to the `plugins.enabled` allow-list in
`~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - aegis-attestation
```

To opt **out** of unblocking (verify and comment, but leave a human to
hit `hermes kanban unblock`), pass `--no-unblock` on each cron call **or**
set `auto_unblock_on_pass: false` in the YAML section above. CLI wins.

## Layered upgrade path

| Tier   | What it adds                                | Status                              |
| ------ | ------------------------------------------- | ----------------------------------- |
| **A**  | sha256 + exists-check + HMAC                | **shipped** (this plugin)           |
| **B**  | LLM reviewer (lint, test-result sanity)     | placeholder — wire into `ctx.llm`   |
| **C**  | Static analysis (mypy/bandit/ruff per lang) | planned                             |
| **D**  | Test re-run in sandbox                      | planned                             |

The Tier-B integration point is the comment authored `aegis-attest`: a
future plugin can scan for comments where `ok=true` and run deeper
checks before issuing its own `aegis-review` comment and unblocking
*only* on combined pass.

## Disabling

- **Soft**: set `aegis_attestation.auto_unblock_on_pass: false` in
  `~/.hermes/config.yaml` (verify-only mode).
- **Full**: remove `aegis-attestation` from `plugins.enabled` in
  `~/.hermes/config.yaml`, or add it to `plugins.disabled` (deny-list
  always wins). The next `hermes` invocation will not load it.

## Security model (short)

- **Path traversal**: `_resolve_under_root` resolves every declared path
  through `Path.resolve()` and rejects anything that escapes the task
  workspace root.
- **Tamper detection**: with `AEGIS_ATTEST_HMAC_KEY` set, the comment
  body carries `HMAC-SHA256(key, canonical_json(payload))`. A reviewer
  who knows the key can re-verify with a one-liner; an attacker writing
  a fake comment cannot produce a matching MAC.
- **Comment idempotency**: the loop short-circuits on tasks that already
  have an `aegis-attest v1:` comment so re-runs do not double-spend
  unblocks.
