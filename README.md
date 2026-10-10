# GhostSession

[![CI](https://github.com/LatticeAG/ghostsession/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/ghostsession/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/typescript-5.9%2B-blue.svg)](package.json)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-v1-blue.svg)](#protocol)

**GhostSession** is the LatticeAG local core for browser-agent session
persistence and controlled recovery. Browser agents lose authenticated
sessions, hit Cloudflare/bot walls, and fail at real-site scale. GhostSession
stores encrypted per-site cookies and local storage, reattaches sessions
across runs, classifies blocks deterministically, bounds recovery, hands
login back to a human through a local inbox, and issues signed, hash-chained
receipts for every session action.

The daemon is zero-dependency Node.js (>= 22.5, `node:sqlite`). The Python
package `ghostsession` is a protocol-equivalent client; it does not run a
second vault or implement another browser driver.

> GhostSession never transmits credentials. Human login happens in a local
> browser window owned by the device owner; the agent observes only
> allowlisted probe selectors.

## Requirements

- **Node.js >= 22.5** for the daemon and CLI (`node:sqlite`, zero deps).
- **Chromium** on PATH (or `GHOSTSESSION_CHROMIUM=/path/to/chromium`) for
  anything that drives a browser — `session attach`, `session recover`,
  `session step`, `inbox open`/`inbox resolve`. It is not needed for
  `init`, `site enroll`, `session create`, `audit export`, or
  `audit verify`. `ghostsession doctor` reports a `browser_binary` check;
  when it fails, browser RPCs return `BROWSER_UNAVAILABLE` (HTTP 423, exit
  6) — the daemon does not crash.
- **An OS keychain**: macOS Keychain or Linux Secret Service
  (`secret-tool` + a D-Bus session bus). Headless Linux has neither — set
  `GHOSTSESSION_INSECURE_FILE_KEYCHAIN=1` to fall back to owner-only files
  under `data_dir/keychain` (0600 files in a 0700 dir). This is a dev/test
  escape hatch only; without it, `init`/`enroll`/`daemon start` fail
  `SECURE_STORAGE_UNAVAILABLE`.
- **A controlling TTY for owner confirmation.** `site enroll` (masked
  account-text prompt), `session revoke`, and `session delete` (typed
  confirmations) refuse non-TTY stdin with exit 3 — there are no `--yes`
  overrides by design. Headless use needs a PTY, e.g.
  `script -qec 'ghostsession site enroll …' /dev/null` or `ssh -t`.

Conventions the CLI and RPC layer enforce:

- **IDs** are `<prefix>_` + exactly 21 chars from
  `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-`.
  Prefixes: `gs` session, `gt` site, `gd` device, `ga` actor, `gr` run,
  `gl` lease, `go` operation, `gh` handoff, `gv` receipt, `gk` key, `ge`
  encryption key, `gq` request.
- **`session step --action-file`** must be owner-private (`chmod 0600`) or
  the CLI rejects it before dispatch.
- **`site enroll`** validates the policy file before signing:
  `auth_probe.expected_account_ref` must be exactly
  `keychain:ghostsession/account/<site_id>` (and `--account-ref` must match
  it), and `recovery` must equal the fixed policy constants:

  | field | value |
  |-------|-------|
  | `challenge_base_ms` | `60000` |
  | `rate_base_ms` | `30000` |
  | `network_base_ms` | `5000` |
  | `max_retry_delay_ms` | `900000` |
  | `max_server_wait_ms` | `86400000` |
  | `max_automatic_probes` | `2` |
  | `handoff_ttl_ms` | `900000` |

  `snapshot_ttl_ms` must be within `3600000..2592000000`, probe/fallback
  paths must stay inside `agent_paths`, and `methods` must include `GET`
  and `HEAD`.

## What it does

- **Encrypted snapshots** — AES-256-GCM `chromium-storage-v1` capture,
  bound to site, device, generation, and policy hash; audit-anchored.
- **Deterministic block detection** — explicit `cf-mitigated` signals and
  probe markers only; Cloudflare branding alone never classifies a wall.
- **Bounded recovery** — persisted per-origin budgets, capped exponential
  backoff, `Retry-After` honored but never past `max_server_wait_ms`, one
  fallback probe path, then fail-closed.
- **Human-login handoff** — signed handoff cards through a local VekInbox
  boundary; owner TTY confirmation for destructive commands.
- **Receipts** — every transition emits an Ed25519-signed, hash-chained
  receipt; `audit export` + `audit verify` for offline verification.
- **Leases & fences** — one active runner, operation-level idempotency,
  request deduplication, `UNCERTAIN` for unproven dispatch.
- **Vault sync (interface)** — signed vault heads, CAS writes, tombstone
  permanence; Workers relay in `worker/`. Hosted mode is a documented,
  fail-closed interface — not a fake service.

## Quickstart

```sh
npm install -g @latticeag/ghostsession   # or: npm ci && npm run build
ghostsession init --device-label laptop
ghostsession daemon start --foreground
ghostsession site enroll --policy policy.json --account-ref keychain:ghostsession/account/gt_...
ghostsession session create --site gt_... --json
ghostsession inbox open gh_... && ghostsession inbox resolve gh_... --ready
ghostsession session attach gs_... --run gr_... --generation 1 --json
ghostsession session step gs_... --lease gl_... --fence 1 --operation go_... --action-file action.json
ghostsession session detach gs_... --lease gl_... --fence 1 --checkpoint --json
ghostsession audit export gs_... > receipts.jsonl
ghostsession audit verify --input receipts.jsonl --trust trust.json
```

Python client — requires **Python >= 3.11** and `cryptography>=41`
(`pip install ghostsession`, or `uv run --with ghostsession python`):

```python
from ghostsession import Client
client = Client.local("~/.local/share/ghostsession/run/owner.sock")
view = client.call("session.get", {"session_id": "gs_..."},
                   request_id="gq_000000000000000000004")
```

## Layout

| Path            | Contents                                             |
|-----------------|------------------------------------------------------|
| `src/`          | daemon, engine, RPC dispatch, adapters, crypto, CLI  |
| `worker/`       | Cloudflare Workers relay (narrow vault head CAS)     |
| `python/`       | `ghostsession` Python SDK                            |
| `tests/`        | TV-G--01…48 conformance vectors + fixtures           |
| `tools/`        | normative fixture generator                          |

## Development

```sh
npm run check          # typecheck
npm test               # build + TS conformance suite (57 tests)
npm run test:python    # Python contract suite (21 tests; needs python >=3.11)
```

If the system `python3` is older than 3.11 or has no pytest, let
[uv](https://docs.astral.sh/uv/) provision one:

```sh
uv run --python 3.12 --with pytest --with . python -m pytest python/tests -q
```

## License

MIT — see [LICENSE](LICENSE).
