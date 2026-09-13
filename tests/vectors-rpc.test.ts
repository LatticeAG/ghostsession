/**
 * TV-G transport/proof vectors (spec §16): dispatcher-level request proof,
 * replay, size caps, remote authorization, response-proof binding.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { jcsBytes, jcsString } from "../src/encoding/jcs.js";
import { b64Encode } from "../src/encoding/b64.js";
import { RpcFailure } from "../src/client.js";
import { RemoteTransport } from "../src/client.js";
import type { SessionView } from "../src/schema.js";

import {
  fx, IDS, NOW, makeHarness, enroll, makeDispatcher, makeProof, proofHeader,
  rpcBody, responseProof, seed, jcsHash,
} from "./helpers.js";

const S = IDS.S!;
const Q4 = { v: 1, id: "gq_000000000000000000004", method: "session.get", params: { session_id: S } };

function errCode(r: { status: number; body: Buffer }): string | null {
  const b = JSON.parse(r.body.toString("utf8"));
  return b.ok ? null : b.error.code;
}

// TV-G--11 — Duplicate key rejection (wire level)
test("TV-G--11 duplicate-key request is a 400 INVALID_SCHEMA", async () => {
  const h = makeHarness();
  const d = makeDispatcher(h);
  const raw = Buffer.from('{"v":1,"v":1,"id":"gq_000000000000000000001","method":"system.status","params":{}}', "utf8");
  const r = await d.local(raw, "owner");
  assert.equal(r.status, 400);
  const b = JSON.parse(r.body.toString("utf8"));
  assert.equal(b.error.code, "INVALID_SCHEMA");
  assert.equal(b.id, null);
  assert.equal(h.adapter.dispatchCount(), 0);
  assert.equal(h.store.get("SELECT COUNT(*) AS n FROM receipts")!.n, 0);
});

// TV-G--27 — Remote inbox cannot approve login
test("TV-G--27 remote handoff.resolve is FORBIDDEN and card unchanged", async () => {
  const h = makeHarness();
  const s = enroll(h);
  h.engine.openHandoff(s.handoff_id!);
  await h.engine.drain();
  const d = makeDispatcher(h);
  const body = rpcBody("gq_000000000000000000013", "handoff.resolve", { handoff_id: s.handoff_id, decision: "ready" });
  const proof = makeProof({ method: "POST", path: `/v1/devices/${IDS.D}/rpc`, body: JSON.parse(body.toString("utf8")), nonce: 13 });
  const r = await d.remote(body, proofHeader(proof));
  assert.equal(r.status, 403);
  assert.equal(errCode(r), "FORBIDDEN");
  assert.equal(h.engine.getHandoff(s.handoff_id!).state, "OPEN");
  assert.equal(h.engine.getSession(s.session_id).state, "HANDOFF_WAIT");
});

// TV-G--30 — Signed request replay
test("TV-G--30 identical proof replay is REPLAY", async () => {
  const h = makeHarness();
  enroll(h); // creates session S via sequential ids
  const d = makeDispatcher(h);
  const body = rpcBody("gq_000000000000000000004", "session.get", { session_id: S });
  const proof = makeProof({ method: "POST", path: `/v1/devices/${IDS.D}/rpc`, body: Q4, nonce: 1 });
  const r1 = await d.remote(body, proofHeader(proof));
  assert.equal(r1.status, 200);
  h.clock.advance(1);
  const r2 = await d.remote(body, proofHeader(proof));
  assert.equal(r2.status, 401);
  assert.equal(errCode(r2), "REPLAY");
  assert.equal(h.adapter.dispatchCount(), 0);
});

// TV-G--31 — Oversized authorization chain
test("TV-G--31 proof header over 8 KiB is BODY_TOO_LARGE", async () => {
  const h = makeHarness();
  enroll(h);
  const d = makeDispatcher(h);
  const body = rpcBody("gq_000000000000000000031", "system.status", {});
  const giant = Buffer.from("A".repeat(8193), "utf8");
  const r = await d.remote(body, giant);
  assert.equal(r.status, 413);
  assert.equal(errCode(r), "BODY_TOO_LARGE");
  assert.equal(h.adapter.dispatchCount(), 0);
});

// TV-G--37 — Relay swaps a signed reply
test("TV-G--37 response proof bound to a different request is rejected", () => {
  const t = new RemoteTransport({
    baseUrl: "https://vault.example.test", deviceId: IDS.D!, actorId: IDS.A!,
    requestKeyId: "gk_000000000000000000003", requestSeed: seed("auth_seed_b64"),
    devicePublicKey: seed("sk_pub_b64"),
  });
  // Daemon's signed reply binds Q4's proof core; the client sent Q5.
  const q5Core = { ...makeProof({ method: "POST", path: `/v1/devices/${IDS.D}/rpc`, body: Q4, nonce: 5 }).core };
  const okBody = Buffer.from(jcsString({ v: 1, id: "gq_000000000000000000005", ok: true, result: {} }), "utf8");
  const swapped = responseProof({ requestCore: fx.proof_q4.core, status: 200, body: okBody });
  const header = Buffer.from(jcsString(swapped), "utf8");
  assert.throws(
    () => t.verifyResponse(q5Core, 200, okBody, header),
    (e) => e instanceof RpcFailure && e.code === "INTEGRITY_FAILED",
  );
  // The correctly bound proof verifies.
  const good = responseProof({ requestCore: q5Core, status: 200, body: okBody });
  t.verifyResponse(q5Core, 200, okBody, Buffer.from(jcsString(good), "utf8"));
});

// TV-G--48 — Reserved signing prefix (wire level)
test("TV-G--48 gs_-prefixed request id and oversized generation rejected", async () => {
  const h = makeHarness();
  const d = makeDispatcher(h);
  const bad1 = rpcBody("gs_000000000000000000001", "system.status", {});
  const r1 = await d.local(bad1, "owner");
  assert.equal(r1.status, 400);
  assert.equal(errCode(r1), "INVALID_SCHEMA");
  const bad2 = Buffer.from(JSON.stringify({
    v: 1, id: "gq_000000000000000000048", method: "session.attach",
    params: { session_id: S, run_id: IDS.R, expected_generation: 9007199254740992 },
  }));
  const r2 = await d.local(bad2, "owner");
  assert.equal(r2.status, 400);
  assert.equal(errCode(r2), "INVALID_SCHEMA");
});

// Remote happy path: proof + response proof bind correctly end to end.
test("remote session.get returns signed response proof", async () => {
  const h = makeHarness();
  enroll(h);
  const d = makeDispatcher(h);
  const body = rpcBody("gq_000000000000000000004", "session.get", { session_id: S });
  const proof = makeProof({ method: "POST", path: `/v1/devices/${IDS.D}/rpc`, body: Q4, nonce: 7 });
  const r = await d.remote(body, proofHeader(proof));
  assert.equal(r.status, 200);
  assert.ok(r.responseProof !== null);
  const env = JSON.parse(r.responseProof!.toString("utf8"));
  assert.equal(env.core.request_hash, jcsHash(proof.core));
  const view = (JSON.parse(r.body.toString("utf8")) as { result: SessionView }).result;
  assert.equal(view.session_id, S);
});

void fx; void jcsBytes; void b64Encode; void NOW;
