/**
 * SQLite persistence (spec §7): WAL, synchronous=FULL, foreign keys,
 * private directory 0700, files 0600.
 */

import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";

export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY CHECK (id LIKE 'gt\\_%' ESCAPE '\\'),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  signed_policy BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY CHECK (id LIKE 'gs\\_%' ESCAPE '\\'),
  site_id TEXT NOT NULL REFERENCES sites(id),
  state TEXT NOT NULL CHECK (state IN
    ('NEEDS_LOGIN','DETACHED','ATTACHING','ACTIVE','COOLDOWN','RECOVERABLE',
     'HANDOFF_WAIT','VERIFYING','UNCERTAIN','EXPIRED','REVOKED','DELETED','QUARANTINED')),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  fence INTEGER NOT NULL CHECK (fence >= 0),
  view_json BLOB NOT NULL,
  control_json BLOB NOT NULL,
  snapshot_eligible INTEGER NOT NULL CHECK (snapshot_eligible IN (0,1))
);
CREATE TABLE IF NOT EXISTS snapshots (
  session_id TEXT PRIMARY KEY REFERENCES sessions(id),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  key_id TEXT NOT NULL,
  cipher_json BLOB NOT NULL,
  cipher_hash TEXT NOT NULL CHECK (length(cipher_hash) = 64)
);
CREATE TABLE IF NOT EXISTS receipts (
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL CHECK (seq >= 1),
  receipt_json BLOB NOT NULL,
  hash TEXT NOT NULL CHECK (length(hash) = 64),
  PRIMARY KEY(session_id, seq)
);
CREATE TABLE IF NOT EXISTS operations (
  session_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  action_binding TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('PREPARED','DISPATCHED','SUCCEEDED','BLOCKED','DENIED','UNKNOWN','PURGED')),
  result_cipher BLOB,
  started_ms INTEGER NOT NULL,
  PRIMARY KEY(session_id, operation_id)
);
CREATE TABLE IF NOT EXISTS requests (
  owner_scope TEXT NOT NULL,
  request_id TEXT NOT NULL,
  request_hash TEXT,
  state TEXT NOT NULL CHECK (state IN ('PENDING','DONE')),
  response_cipher BLOB,
  created_ms INTEGER NOT NULL,
  PRIMARY KEY(owner_scope, request_id)
);
CREATE TABLE IF NOT EXISTS handoffs (
  id TEXT PRIMARY KEY CHECK (id LIKE 'gh\\_%' ESCAPE '\\'),
  session_id TEXT NOT NULL,
  card_json BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS handoffs_session ON handoffs(session_id);
CREATE TABLE IF NOT EXISTS outbox (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('handoff_card','vault_tombstone')),
  session_id TEXT NOT NULL,
  payload_cipher BLOB NOT NULL,
  next_try_ms INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS origin_budgets (
  owner_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  state_json BLOB NOT NULL,
  PRIMARY KEY(owner_id, origin)
);
CREATE TABLE IF NOT EXISTS nonces (
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_ms INTEGER,
  PRIMARY KEY(key_id, nonce)
);
CREATE TABLE IF NOT EXISTS vault_sync (
  session_id TEXT PRIMARY KEY,
  etag TEXT,
  generation INTEGER NOT NULL DEFAULT 0,
  pending_delete INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS rate_limits (
  subject TEXT NOT NULL,
  kind TEXT NOT NULL,
  stamps_json BLOB NOT NULL,
  PRIMARY KEY(subject, kind)
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
`;

export class Store {
  readonly db: DatabaseSync;
  private depth = 0;
  /** Test hook: number of commit attempts that should fail with EIO. */
  failCommits = 0;

  constructor(path: string) {
    if (path !== ":memory:") {
      mkdirSync(pathDir(path), { recursive: true, mode: 0o700 });
      chmodSync(pathDir(path), 0o700);
    }
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA_SQL);
    if (path !== ":memory:") {
      try { chmodSync(path, 0o600); } catch { /* fs may not support */ }
    }
    const v = this.getMeta("schema_version");
    if (v === null) {
      this.setMeta("schema_version", Buffer.from(String(SCHEMA_VERSION)));
    } else if (Number(v.toString()) !== SCHEMA_VERSION) {
      throw new Error(`schema version ${v.toString()} != ${SCHEMA_VERSION}; run migrate`);
    }
  }

  begin(): void {
    if (this.depth === 0) this.db.exec("BEGIN IMMEDIATE");
    this.depth++;
  }

  commit(): void {
    this.depth--;
    if (this.depth === 0) {
      if (this.failCommits > 0) {
        this.failCommits--;
        try { this.db.exec("ROLLBACK"); } catch { /* already rolled back */ }
        const e = new Error("simulated commit failure") as Error & { code: string };
        e.code = "EIO";
        throw e;
      }
      this.db.exec("COMMIT");
    }
  }

  rollback(): void {
    this.depth--;
    if (this.depth === 0) this.db.exec("ROLLBACK");
  }

  txn<T>(fn: () => T): T {
    this.begin();
    try {
      const r = fn();
      this.commit();
      return r;
    } catch (e) {
      this.rollback();
      throw e;
    }
  }

  get(sql: string, ...params: unknown[]): Record<string, unknown> | undefined {
    return this.db.prepare(sql).get(...(params as never[])) as Record<string, unknown> | undefined;
  }

  all(sql: string, ...params: unknown[]): Record<string, unknown>[] {
    return this.db.prepare(sql).all(...(params as never[])) as Record<string, unknown>[];
  }

  run(sql: string, ...params: unknown[]): void {
    this.db.prepare(sql).run(...(params as never[]));
  }

  close(): void {
    this.db.close();
  }

  getMeta(key: string): Buffer | null {
    const row = this.get("SELECT value FROM meta WHERE key = ?", key);
    return row ? Buffer.from(row.value as Uint8Array) : null;
  }

  setMeta(key: string, value: Buffer): void {
    this.run("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value);
  }

  schemaVersion(): number {
    const v = this.getMeta("schema_version");
    return v === null ? 0 : Number(v.toString());
  }

  setSchemaVersion(v: number): void {
    this.setMeta("schema_version", Buffer.from(String(v)));
  }

  /**
   * Nonce acceptance under the key scope `${actorOrKey}:${purpose}` —
   * atomically insert-or-reject with retention expiry. Must run inside txn.
   */
  nonceAccept(scope: string, keyId: string, nonce: string, nowMs: number, retentionMs: number): boolean {
    const k = `${scope}:${keyId}`;
    this.run("DELETE FROM nonces WHERE expires_ms IS NOT NULL AND expires_ms <= ?", nowMs);
    const r = this.get("SELECT 1 AS x FROM nonces WHERE key_id=? AND nonce=?", k, nonce);
    if (r) return false;
    this.run("INSERT INTO nonces(key_id,nonce,expires_ms) VALUES(?,?,?)", k, nonce, nowMs + retentionMs);
    return true;
  }
}

function pathDir(p: string): string {
  const idx = p.lastIndexOf("/");
  return idx <= 0 ? "." : p.slice(0, idx);
}

export function defaultDbPath(dataDir: string): string {
  return join(dataDir, "ghostsession.sqlite");
}
