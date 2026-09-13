/**
 * TV-G reducer/engine vectors (spec §16) — driven through the real Engine with
 * the scripted browser adapter, deterministic IDs, TestClock, and fixture keys.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RpcError } from "../src/errors.js";
import { signEnvelope } from "../src/crypto/envelope.js";
import { MemoryKeychain } from "../src/store/keychain.js";
import type { PolicyCore, SessionView, SignedPolicy } from "../src/schema.js";

import {
  fx, IDS, NOW, makeHarness, enroll, completeHandoff, attachActive,
  seed, thrownCode, asyncCode, jcsBytes, type Harness,
} from "./helpers.js";

const O = "go_000000000000000000001";
const L = "gl_000000000000000000001";
const S = IDS.S!;
const A = IDS.A!;
const R = IDS.R!;

const GOOD_RAW = {
  name: "sid", value: "fixture-only", host: "app.example.test", domain: null,
  path: "/", secure: true, httpOnly: true, sameSite: "Lax" as const,
  expiresMs: NOW + 60000, hasPartitionKey: false, unsupportedAttrs: false,
};

const HAPPY = { accountText: "owner-17", loggedIn: true, cookies: [GOOD_RAW] };

function code(e: unknown): string {
  return e instanceof RpcError ? e.code : `threw ${e}`;
}

/** Revision-n policy: identical core fields, bumped revision, signed by SK. */
function policyRev(n: number): SignedPolicy {
  const core = { ...(fx.policy_core as Record<string, unknown>), revision: n } as unknown as PolicyCore;
  return signEnvelope("policy", core, seed("sk_seed_b64")) as SignedPolicy;
}

async function detachedGen1(h: Harness): Promise<string> {
  const s = enroll(h);
  await completeHandoff(h, s.session_id);
  return s.session_id;
}

async function active(h: Harness): Promise<SessionView> {
  const sid = await detachedGen1(h);
  return attachActive(h, sid);
}

const clickSave = { kind: "click", selector: "#save" } as const;
const clickDelete = { kind: "click", selector: "#delete" } as const;

function receiptEvents(h: Harness, sid: string): string[] {
  return h.engine.auditList(sid, 0, 100).entries.map((r) => r.core.event);
}

// TV-G--06 — Wrong authenticated account
test("TV-G--06 account mismatch routes to HANDOFF_WAIT without snapshot write", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  h.adapter.script.accountText = "owner-18"; // probe now reports a different account
  h.engine.attach(sid, R, 1, A);
  await h.engine.drain();
  const v = h.engine.getSession(sid);
  assert.equal(v.state, "HANDOFF_WAIT");
  assert.equal(v.block?.class, "ACCOUNT_MISMATCH");
  const snap = h.store.get("SELECT generation FROM snapshots WHERE session_id=?", sid);
  assert.equal(snap?.generation, 1); // no new snapshot written
});

// TV-G--07 — Bare forbidden response is not a login
test("TV-G--07 attach probe 403 -> ACCESS_DENIED -> RECOVERABLE, no auto probe", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  h.adapter.script.responses = { "GET https://app.example.test/app/me": { status: 403 } };
  h.engine.attach(sid, R, 1, A);
  await h.engine.drain();
  const v = h.engine.getSession(sid);
  assert.equal(v.state, "RECOVERABLE");
  assert.equal(v.block?.class, "ACCESS_DENIED");
  // automatic_probe_allowed:false — retry intent is rejected for ACCESS_DENIED.
  assert.equal(thrownCode(() => h.engine.recover(sid, v.block!.revision, "retry", A)), "STATE_CONFLICT");
});

// TV-G--12 — Origin suffix confusion
test("TV-G--12 attacker suffix origin denied before dispatch", async () => {
  const h = makeHarness(HAPPY);
  const v = await active(h);
  const r = await h.engine.step(v.session_id, L, 1, O, {
    kind: "navigate", url: "https://app.example.test.attacker.test/app",
  }, A);
  assert.equal(r.outcome, "DENIED");
  assert.equal(r.code, "SCOPE_DENIED");
  assert.equal(r.block_class, "SCOPE_DENIED");
  assert.equal(h.adapter.dispatchCount(), 0);
  assert.equal(h.engine.getSession(v.session_id).state, "ACTIVE");
});

// TV-G--13 — Encoded traversal
test("TV-G--13 double-encoded traversal denied", async () => {
  const h = makeHarness(HAPPY);
  const v = await active(h);
  const reqBefore = h.adapter.requestsSent;
  const r = await h.engine.step(v.session_id, L, 1, O, {
    kind: "navigate", url: "https://app.example.test/app/%252e%252e/admin",
  }, A);
  assert.equal(r.outcome, "DENIED");
  assert.equal(r.code, "SCOPE_DENIED");
  assert.equal(h.adapter.dispatchCount(), 0);
  assert.equal(h.adapter.requestsSent, reqBefore);
});

// TV-G--14 — Redirect to private destination
test("TV-G--14 redirect to loopback denied at hop boundary", async () => {
  const h = makeHarness({
    ...HAPPY,
    responses: {
      "GET https://app.example.test/app": { status: 302, redirectTo: "http://127.0.0.1/admin" },
    },
  });
  const v = await active(h);
  const before = h.adapter.requestsSent;
  const r = await h.engine.step(v.session_id, L, 1, O, {
    kind: "navigate", url: "https://app.example.test/app",
  }, A);
  assert.equal(r.outcome, "DENIED");
  assert.equal(r.code, "SCOPE_DENIED");
  assert.equal(r.block_class, "SCOPE_DENIED");
  assert.equal(h.adapter.requestsSent - before, 1); // only the authorized first hop
});

// TV-G--15 — DNS rebinding through an allowed hostname
test("TV-G--15 second connection resolving to link-local is blocked", async () => {
  const h = makeHarness(HAPPY);
  // handoff probe, attach probe, then the action navigation → private.
  h.adapter.script.dnsAnswers = {
    "app.example.test": ["93.184.215.14", "93.184.215.14", "169.254.169.254"],
  };
  const v = await active(h);
  const before = h.adapter.requestsSent;
  const r = await h.engine.step(v.session_id, L, 1, O, {
    kind: "navigate", url: "https://app.example.test/app",
  }, A);
  assert.equal(r.outcome, "DENIED");
  assert.equal(r.code, "SCOPE_DENIED");
  assert.equal(h.adapter.requestsSent, before); // private destination got zero bytes
});

// TV-G--16 — Ciphertext site substitution
test("TV-G--16 tampered site binding quarantines the session", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  // Attacker rebinds the ciphertext header to another site.
  const row = h.store.get("SELECT cipher_json FROM snapshots WHERE session_id=?", sid)!;
  const cipher = JSON.parse(Buffer.from(row.cipher_json as Uint8Array).toString("utf8"));
  cipher.header.site_id = "gt_000000000000000000002";
  h.store.run("UPDATE snapshots SET cipher_json=? WHERE session_id=?", JSON.stringify(cipher), sid);
  h.engine.attach(sid, R, 1, A);
  await h.engine.drain();
  const v = h.engine.getSession(sid);
  assert.equal(v.state, "QUARANTINED");
  assert.equal(h.adapter.restoredSnapshots.length, 0);
});

// TV-G--17 — Ciphertext replay under changed policy (hosted restore path)
test("TV-G--17 snapshot under stale policy fails integrity before launch", async () => {
  // In-memory vault that stores whatever the engine uploads.
  const vault = { head: null as import("../src/schema.js").VaultHead | null };
  const h = makeHarness(HAPPY, {
    vaultMode: "hosted",
    vaultTransport: {
      get: async () => vault.head === null
        ? { status: 404, body: null, etag: null }
        : { status: 200, body: { head: vault.head, etag: `"${vault.head.hash}"` }, etag: `"${vault.head.hash}"` },
      put: async (_sid: string, head: import("../src/schema.js").VaultHead) => {
        vault.head = head;
        return { status: 200, body: { head, etag: `"${head.hash}"` }, etag: `"${head.hash}"` };
      },
    },
  });
  const sid = await detachedGen1(h);              // gen-1 snapshot, DETACHED
  const up = await h.engine.vaultSync(sid, "upload");
  assert.equal(up.status, "synced");
  assert.ok(vault.head !== null);                  // real head in the vault
  h.engine.putSite(policyRev(2));                  // policy drift → NEEDS_LOGIN
  const ctxBefore = h.adapter.contextsCreated;
  const restoreBefore = h.adapter.restoredSnapshots.length;
  const err = await h.engine.vaultSync(sid, "restore").then(() => "ok", (e) => code(e));
  assert.equal(err, "INTEGRITY_FAILED");
  assert.equal(h.adapter.contextsCreated, ctxBefore);   // no browser launch
  assert.equal(h.adapter.restoredSnapshots.length, restoreBefore);
  assert.equal(
    h.store.get("SELECT generation FROM snapshots WHERE session_id=?", sid)!.generation, 1,
  );
});

// TV-G--18 — Expiry equality is expired
test("TV-G--18 snapshot expiry boundary is expired", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  h.clock.advance(604800000); // exactly the snapshot TTL → expires_ms == now
  const ctxBefore = h.adapter.contextsCreated;
  const err = thrownCode(() => h.engine.attach(sid, R, 1, A));
  assert.equal(err, "SNAPSHOT_EXPIRED");
  assert.equal(h.engine.getSession(sid).state, "EXPIRED");
  assert.equal(h.adapter.contextsCreated, ctxBefore);
});

// TV-G--21 — Single writer lease race
test("TV-G--21 second concurrent attach loses with LEASE_HELD", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  const ctxBefore = h.adapter.contextsCreated;
  const v1 = h.engine.attach(sid, R, 1, A);
  assert.equal(v1.state, "ATTACHING");
  assert.equal(v1.lease?.fence, 1);
  assert.equal(
    thrownCode(() => h.engine.attach(sid, "gr_000000000000000000002", 1, A)),
    "LEASE_HELD",
  );
  await h.engine.drain();
  assert.equal(h.adapter.contextsCreated - ctxBefore, 1);
  assert.equal(h.engine.getSession(sid).state, "ACTIVE");
});

// TV-G--22 — Lease expiry equality
test("TV-G--22 step at exact lease expiry is LEASE_EXPIRED", async () => {
  const h = makeHarness(HAPPY);
  const v = await active(h);
  h.clock.advance(45000); // lease expires_ms == now
  const err = await asyncCode(h.engine.step(v.session_id, L, 1, O, clickSave, A));
  assert.equal(err, "LEASE_EXPIRED");
  assert.equal(h.engine.getSession(v.session_id).state, "DETACHED");
  assert.equal(h.engine.getSession(v.session_id).lease, null);
  assert.equal(h.adapter.dispatchCount(), 0);
});

// TV-G--23 — Fence after restart
test("TV-G--23 persisted fence rejects stale handle after restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gs-tv23-"));
  const dbp = join(dir, "state.sqlite");
  const keychain = new MemoryKeychain();
  const h1 = makeHarness(HAPPY, { dbPath: dbp, keychain });
  const v = await active(h1);
  assert.equal(v.state, "ACTIVE");
  assert.equal(v.lease?.fence, 1);
  // Restart: new store connection + engine on the same durable state.
  const h2 = makeHarness(HAPPY, { dbPath: dbp, keychain });
  h2.engine.recoverDaemon();
  const restored = h2.engine.getSession(v.session_id);
  assert.equal(restored.state, "DETACHED");
  assert.equal(restored.lease, null);
  const err = await asyncCode(h2.engine.step(v.session_id, L, 0, O, clickSave, A));
  assert.equal(err, "STALE_FENCE");
  assert.equal(h2.engine.getSession(v.session_id).state, "DETACHED");
  assert.equal(h2.adapter.dispatchCount(), 0);
});

// TV-G--24 — Completed operation retry
test("TV-G--24 completed operation replays byte-equal without dispatch", async () => {
  const h = makeHarness({
    ...HAPPY,
    responses: { click: { status: 200 } },
  });
  const v = await active(h);
  const r1 = await h.engine.step(v.session_id, L, 1, O, clickSave, A);
  assert.equal(r1.outcome, "SUCCEEDED");
  const intents = receiptEvents(h, v.session_id).filter((e) => e === "action.intent").length;
  const r2 = await h.engine.step(v.session_id, L, 1, O, clickSave, A);
  // Byte-equal replay = identical canonical JCS encoding of the recorded result.
  assert.deepEqual(jcsBytes(r2), jcsBytes(r1));
  assert.equal(h.adapter.dispatchCount(), 1);
  assert.equal(
    receiptEvents(h, v.session_id).filter((e) => e === "action.intent").length,
    intents,
  );
});

// TV-G--25 — Crash after click dispatch
test("TV-G--25 dispatched-but-unproven op resolves to UNCERTAIN on restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gs-tv25-"));
  const dbp = join(dir, "state.sqlite");
  const keychain = new MemoryKeychain();
  const h1 = makeHarness({ ...HAPPY, dispatchBehavior: "hang" }, { dbPath: dbp, keychain });
  const v = await active(h1);
  const hung = h1.engine.step(v.session_id, L, 1, O, clickSave, A).catch((e) => e);
  // Wait until the DISPATCHED marker is durable.
  for (let i = 0; i < 100; i++) {
    const r = h1.store.get(
      "SELECT state FROM operations WHERE session_id=? AND operation_id=?", v.session_id, O,
    );
    if (r?.state === "DISPATCHED") break;
    await new Promise((res) => setTimeout(res, 5));
  }
  const opState = h1.store.get(
    "SELECT state FROM operations WHERE session_id=? AND operation_id=?", v.session_id, O,
  )?.state;
  assert.equal(opState, "DISPATCHED");
  assert.equal(h1.adapter.dispatchCount(), 1);
  h1.store.close(); // process dies; the hung step rejects later and is ignored
  void hung;

  const h2 = makeHarness(HAPPY, { dbPath: dbp, keychain });
  h2.engine.recoverDaemon();
  const v2 = h2.engine.getSession(v.session_id);
  assert.equal(v2.state, "UNCERTAIN");
  assert.ok(receiptEvents(h2, v.session_id).includes("action.unknown"));
  const err = await asyncCode(h2.engine.step(v.session_id, L, 1, O, clickSave, A));
  assert.equal(err, "OUTCOME_UNKNOWN");
  assert.equal(h2.adapter.dispatchCount(), 0);
  assert.equal(h1.adapter.dispatchCount(), 1);
});

// TV-G--26 — Handoff TOCTOU on policy drift
test("TV-G--26 policy advance invalidates the open card", async () => {
  const h = makeHarness(HAPPY);
  const s = enroll(h);
  const card = h.engine.openHandoff(s.handoff_id!);
  await h.engine.drain();
  assert.equal(card.state, "OPEN");
  h.engine.putSite(policyRev(2));
  assert.equal(h.engine.getSession(s.session_id).state, "NEEDS_LOGIN");
  assert.equal(h.engine.getHandoff(s.handoff_id!).state, "CANCELLED");
  const err = thrownCode(() => h.engine.resolveHandoff(s.handoff_id!, "ready"));
  assert.equal(err, "STALE_HANDOFF");
  assert.equal(h.engine.getSession(s.session_id).state, "NEEDS_LOGIN");
});

// TV-G--28 — Card TTL boundary
test("TV-G--28 ready at exact card expiry is HANDOFF_EXPIRED", async () => {
  const h = makeHarness(HAPPY);
  const s = enroll(h);
  h.engine.openHandoff(s.handoff_id!);
  await h.engine.drain();
  h.clock.advance(900000); // expires_ms == now
  const err = thrownCode(() => h.engine.resolveHandoff(s.handoff_id!, "ready"));
  assert.equal(err, "HANDOFF_EXPIRED");
  assert.equal(h.engine.getHandoff(s.handoff_id!).state, "EXPIRED");
  assert.equal(h.engine.getSession(s.session_id).state, "NEEDS_LOGIN");
});

// TV-G--29 — Policy change during dispatch gap
test("TV-G--29 policy commit between intent and dispatch denies the action", async () => {
  const h = makeHarness(HAPPY, {
    hooks: {
      afterActionIntent: () => { h2ref().putSite(policyRev(2)); },
    },
  });
  const h2ref = () => h.engine;
  const v = await active(h);
  const r = await h.engine.step(v.session_id, L, 1, O, clickSave, A);
  assert.equal(r.outcome, "DENIED");
  assert.equal(r.code, "SCOPE_DENIED");
  assert.equal(h.adapter.dispatchCount(), 0);
  assert.equal(h.engine.getSession(v.session_id).state, "NEEDS_LOGIN");
});

// TV-G--34 — Local deletion while cloud is down
test("TV-G--34 delete persists locally with pending tombstone while offline", async () => {
  const offline = {
    get: async () => { throw new RpcError("DEVICE_OFFLINE"); },
    put: async () => { throw new RpcError("DEVICE_OFFLINE"); },
  };
  const h = makeHarness(HAPPY, { vaultMode: "hosted", vaultTransport: offline });
  const sid = await detachedGen1(h);
  const rev = h.engine.revoke(sid);
  assert.equal(rev.state, "REVOKED");
  assert.equal(rev.cloud_delete_pending, true);
  const del = h.engine.deleteSession(sid, h.engine.getSession(sid).generation);
  assert.equal(del.state, "DELETED");
  assert.equal(del.cloud_delete_pending, true);
  assert.equal(h.store.get("SELECT 1 AS x FROM snapshots WHERE session_id=?", sid), undefined);
  assert.equal(h.keychain.has(`ghostsession/encryption/${IDS.E}`), false);
  const tomb = h.store.get(
    "SELECT COUNT(*) AS n FROM outbox WHERE session_id=? AND kind='vault_tombstone'", sid,
  );
  assert.equal(tomb?.n, 1);
});

// TV-G--35 — Clock rollback safety gate
test("TV-G--35 wall-clock regression closes the effect gate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gs-tv35-"));
  const dbp = join(dir, "state.sqlite");
  const keychain = new MemoryKeychain();
  const h1 = makeHarness(HAPPY, { dbPath: dbp, keychain });
  enroll(h1); // persists last_wall_ms = NOW
  const h2 = makeHarness(HAPPY, { dbPath: dbp, keychain, clockStart: NOW - 6000 });
  assert.equal(h2.engine.clockUnsafe, true);
  assert.equal(h2.engine.status().ready, false);
  assert.equal(thrownCode(() => h2.engine.putSite(fx.policy)), "CLOCK_UNSAFE");
  assert.equal(h2.adapter.contextsCreated, 0);
});

// TV-G--36 — Recreated session cannot reset origin budget
test("TV-G--36 origin probe budget persists across sessions", async () => {
  const h = makeHarness(HAPPY);
  h.store.run(
    "INSERT INTO origin_budgets(owner_id,origin,state_json) VALUES(?,?,?)",
    A, "https://app.example.test",
    Buffer.from(JSON.stringify({
      probe_starts_ms: [NOW - 1000, NOW - 500], handoff_starts_ms: [],
      last_block_ms: null, next_allowed_ms: 0, attempts: 0,
      fallback_used: false, manual_review: false,
    })),
  );
  // Handoff path completes normally first (probe succeeds).
  const sid = await detachedGen1(h);
  h.adapter.script.responses = { "GET https://app.example.test/app/me": { status: 429 } };
  h.engine.attach(sid, R, 1, A);
  await h.engine.drain();
  const v = h.engine.getSession(sid);
  assert.equal(v.state, "COOLDOWN");
  assert.equal(v.block?.class, "RATE_LIMIT");
  h.clock.advance(30000); // retry_at reached
  const err = thrownCode(() => h.engine.recover(sid, v.block!.revision, "retry", A));
  assert.equal(err, "RECOVERY_EXHAUSTED");
  assert.equal(h.adapter.requestsSent, 2); // handoff + attach probes only; no recovery request
});

// TV-G--38 — Secret-bearing error path
test("TV-G--38 adapter exception scrubs to INTERNAL and UNCERTAIN", async () => {
  const h = makeHarness({ ...HAPPY, dispatchBehavior: "throw-secret" });
  const v = await active(h);
  const err = await asyncCode(h.engine.step(v.session_id, L, 1, O, clickSave, A));
  assert.equal(err, "INTERNAL");
  assert.equal(h.engine.getSession(v.session_id).state, "UNCERTAIN");
  // Zero secret material in receipts, session view, or error output.
  const page = h.engine.auditList(v.session_id, 0, 100);
  const blob = JSON.stringify(page) + JSON.stringify(h.engine.getSession(v.session_id));
  for (const needle of ["fixture-secret", "Cookie", "token=", "fixture-stack"]) {
    assert.ok(!blob.includes(needle), `leaked ${needle}`);
  }
});

// TV-G--39 — Crash before snapshot replacement
test("TV-G--39 lost replacement commit preserves generation-1 bytes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gs-tv39-"));
  const dbp = join(dir, "state.sqlite");
  const keychain = new MemoryKeychain();
  const h1 = makeHarness(HAPPY, { dbPath: dbp, keychain });
  const v = await active(h1);
  const before = Buffer.from(
    h1.store.get("SELECT cipher_json FROM snapshots WHERE session_id=?", v.session_id)!
      .cipher_json as Uint8Array,
  );
  // Commit the snapshot.intent, then die inside the replacement transaction.
  const origCapture = h1.adapter.capture.bind(h1.adapter);
  h1.adapter.capture = async (ctx) => {
    const r = await origCapture(ctx);
    h1.store.failCommits = 2; // replacement commit + snapshot.failed commit
    return r;
  };
  const err = await h1.engine.checkpoint(v.session_id, L, 1).then(
    () => "ok", (e) => code(e),
  );
  assert.equal(err, "AUDIT_UNAVAILABLE");
  h1.store.close();

  const h2 = makeHarness(HAPPY, { dbPath: dbp, keychain });
  h2.engine.recoverDaemon();
  const after = Buffer.from(
    h2.store.get("SELECT cipher_json,generation FROM snapshots WHERE session_id=?", v.session_id)!
      .cipher_json as Uint8Array,
  );
  const gen = h2.store.get("SELECT generation FROM snapshots WHERE session_id=?", v.session_id)!
    .generation;
  assert.equal(gen, 1);
  assert.deepEqual(after, before); // byte-for-byte preserved
  const events = receiptEvents(h2, v.session_id);
  assert.ok(events.includes("snapshot.intent"));
  assert.equal(events[events.length - 2], "snapshot.failed");
  assert.equal(h2.engine.getSession(v.session_id).generation, 1);
});

// TV-G--41 — Missing key is not a reason to accept plaintext
test("TV-G--41 absent encryption key fails closed", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  h.keychain.delete(`ghostsession/encryption/${IDS.E}`);
  h.engine.attach(sid, R, 1, A);
  await h.engine.drain();
  const v = h.engine.getSession(sid);
  assert.equal(v.state, "RECOVERABLE");
  const last = h.engine.auditList(sid, 0, 100).entries.at(-1)!;
  assert.equal(last.core.code, "KEY_UNAVAILABLE");
  assert.equal(h.adapter.restoredSnapshots.length, 0);
});

// TV-G--42 — Hard stop survives external allow
test("TV-G--42 local path denial cannot be overridden by external verdict", async () => {
  const h = makeHarness(HAPPY);
  const v = await active(h);
  // There is no RPC surface to inject an external ALLOW; the action itself
  // carries no verdict field. A denied path stays denied.
  const r = await h.engine.step(v.session_id, L, 1, O, {
    kind: "navigate", url: "https://app.example.test/admin",
  }, A);
  assert.equal(r.outcome, "DENIED");
  assert.equal(r.code, "SCOPE_DENIED");
  assert.equal(h.adapter.dispatchCount(), 0);
  assert.equal(h.engine.getSession(v.session_id).state, "ACTIVE");
});

// TV-G--43 — Fallback cannot shorten a wait
test("TV-G--43 fallback before retry_at is COOLDOWN_ACTIVE", async () => {
  const h = makeHarness(HAPPY);
  const sid = await detachedGen1(h);
  h.adapter.script.responses = {
    "GET https://app.example.test/app/me": { status: 503, headers: { "cf-mitigated": "challenge" } },
  };
  h.engine.attach(sid, R, 1, A);
  await h.engine.drain();
  const v = h.engine.getSession(sid);
  assert.equal(v.state, "COOLDOWN");
  assert.equal(v.block?.class, "CF_CHALLENGE");
  assert.equal(v.block?.retry_at_ms, NOW + 60000);
  h.clock.advance(59999);
  const reqBefore = h.adapter.requestsSent;
  const err = thrownCode(() => h.engine.recover(sid, v.block!.revision, "fallback", A));
  assert.equal(err, "COOLDOWN_ACTIVE");
  const still = h.engine.getSession(sid);
  assert.equal(still.block?.retry_at_ms, NOW + 60000);
  assert.equal(still.block?.fallback_used, false);
  assert.equal(h.adapter.requestsSent, reqBefore);
});

// TV-G--45 — Actual authenticated handoff completion
test("TV-G--45 handoff completes with probe + capture in event order", async () => {
  const h = makeHarness(HAPPY);
  const s = enroll(h);
  h.engine.openHandoff(s.handoff_id!);
  await h.engine.drain();
  const verifying = h.engine.resolveHandoff(s.handoff_id!, "ready");
  assert.equal(verifying.state, "VERIFYING");
  await h.engine.drain();
  const v = h.engine.getSession(s.session_id);
  assert.equal(v.state, "DETACHED");
  assert.equal(v.generation, 1);
  assert.equal(v.lease, null);
  assert.deepEqual(
    receiptEvents(h, s.session_id).slice(-4),
    ["handoff.verifying", "snapshot.intent", "snapshot.committed", "handoff.completed"],
  );
  assert.equal(h.engine.getHandoff(s.handoff_id!).state, "COMPLETED");
});

// TV-G--46 — Changed action under an old operation ID
test("TV-G--46 same operation id with different action is OPERATION_CONFLICT", async () => {
  const h = makeHarness(HAPPY);
  const v = await active(h);
  const r1 = await h.engine.step(v.session_id, L, 1, O, clickSave, A);
  assert.equal(r1.outcome, "SUCCEEDED");
  const err = await asyncCode(h.engine.step(v.session_id, L, 1, O, clickDelete, A));
  assert.equal(err, "OPERATION_CONFLICT");
  assert.equal(h.adapter.dispatchCount(), 1);
  // Original result intact.
  const r3 = await h.engine.step(v.session_id, L, 1, O, clickSave, A);
  assert.deepEqual(jcsBytes(r3), jcsBytes(r1));
});

// TV-G--47 — Audit unavailable before effect
test("TV-G--47 durable-intent failure closes the gate before dispatch", async () => {
  const h = makeHarness(HAPPY);
  const v = await active(h);
  h.store.failCommits = 1;
  const err = await asyncCode(h.engine.step(v.session_id, L, 1, O, clickSave, A));
  assert.equal(err, "AUDIT_UNAVAILABLE");
  assert.equal(h.adapter.dispatchCount(), 0);
  assert.equal(h.engine.status().ready, false);
});

