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
ghostsession site enroll --policy policy.json --account-ref ghostsession/account/gt_...
ghostsession session create --site gt_... --json
ghostsession inbox open gh_... && ghostsession inbox resolve gh_... --ready
ghostsession session attach gs_... --run gr_... --generation 1 --json
ghostsession session step gs_... --lease gl_... --fence 1 --operation go_... --action-file action.json
ghostsession session detach gs_... --lease gl_... --fence 1 --checkpoint --json
ghostsession audit export gs_... | ghostsession audit verify --trust trust.json
```

Python client:

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
npm run test:python    # Python contract suite (21 tests)
```

## License

MIT — see [LICENSE](LICENSE).
