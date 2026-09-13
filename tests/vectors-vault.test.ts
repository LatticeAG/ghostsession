/**
 * TV-G hosted vault vectors (spec §16): CAS conflicts, tombstone
 * anti-resurrection, and the worker endpoint's proof binding — exercised
 * against the shared endpoint logic with an in-memory backend.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MemoryVaultBackend, handleVaultGet, handleVaultPut, type VaultDeps,
} from "../worker/src/vault.js";
import { b64Encode } from "../src/encoding/b64.js";
import { jcsString } from "../src/encoding/jcs.js";
import { jcsBytes } from "../src/encoding/jcs.js";

import { fx, IDS, NOW, makeProof, seed } from "./helpers.js";

const S = IDS.S!;

function vaultDeps(backend: MemoryVaultBackend): VaultDeps {
  return {
    backend,
    trusted: [
      {
        key_id: "gk_000000000000000000003", purpose: "request",
        public_key: fx.keys.auth_pub_b64!, actor_id: IDS.A!, device_id: IDS.D!,
      },
      {
        key_id: IDS.K!, purpose: "vault",
        public_key: fx.keys.sk_pub_b64!, actor_id: IDS.A!, device_id: IDS.D!,
      },
    ],
    now: () => NOW,
    responseKey: { keyId: "gk_000000000000000000002", seed: seed("relay_seed_b64") },
    deviceId: IDS.D!,
  };
}

function hdr(p: { core: unknown; signature: string }): string {
  return b64Encode(Buffer.from(jcsString(p), "utf8"));
}

let nonceSeq = 100;

// TV-G--32 — Hosted CAS conflict
test("TV-G--32 stale If-Match tag loses CAS with VAULT_CONFLICT", async () => {
  const backend = new MemoryVaultBackend();
  backend.objects.set(`heads/${S}`, { body: JSON.stringify(fx.vg2), nativeEtag: "mem-1" });
  const d = vaultDeps(backend);
  const body = jcsBytes({ head: fx.vg3 });
  const ifMatch = `"${fx.vault_head.hash}"`; // stale: stored head is vg2
  const proof = makeProof({
    method: "PUT", path: `/v1/vault/${S}`, body: { head: fx.vg3 },
    nonce: nonceSeq++, ifMatch,
  });
  await assert.rejects(
    () => handleVaultPut(d, S, body, { proof: hdr(proof), ifMatch, ifNoneMatch: null }),
    (e) => (e as { status: number; code: string }).status === 409 &&
      (e as { code: string }).code === "VAULT_CONFLICT",
  );
  const stored = JSON.parse(backend.objects.get(`heads/${S}`)!.body);
  assert.equal(stored.core.generation, 2);
  assert.equal(backend.writes, 0);
});

// TV-G--33 — Tombstone resurrection attempt
test("TV-G--33 tombstoned head rejects every later write", async () => {
  const backend = new MemoryVaultBackend();
  backend.objects.set(`heads/${S}`, { body: JSON.stringify(fx.vg4_tombstone), nativeEtag: "mem-1" });
  const d = vaultDeps(backend);
  const body = jcsBytes({ head: fx.vg5 });
  const ifMatch = `"${fx.vg4_tombstone.hash}"`;
  const proof = makeProof({
    method: "PUT", path: `/v1/vault/${S}`, body: { head: fx.vg5 },
    nonce: nonceSeq++, ifMatch,
  });
  await assert.rejects(
    () => handleVaultPut(d, S, body, { proof: hdr(proof), ifMatch, ifNoneMatch: null }),
    (e) => (e as { status: number }).status === 409 &&
      (e as { code: string }).code === "VAULT_CONFLICT",
  );
  const stored = JSON.parse(backend.objects.get(`heads/${S}`)!.body);
  assert.equal(stored.core.deleted, true);
  assert.equal(backend.writes, 0);
});

// Positive CAS: first write under If-None-Match:* then replace with tag.
test("vault first write and generation-advancing replace succeed", async () => {
  const backend = new MemoryVaultBackend();
  const d = vaultDeps(backend);
  const body = jcsBytes({ head: fx.vault_head });
  const proof = makeProof({
    method: "PUT", path: `/v1/vault/${S}`, body: { head: fx.vault_head },
    nonce: nonceSeq++, ifNoneMatch: "*",
  });
  const r = await handleVaultPut(d, S, body, { proof: hdr(proof), ifMatch: null, ifNoneMatch: "*" });
  assert.equal(r.status, 200);
  assert.equal(r.etag, `"${fx.vault_head.hash}"`);

  const g = await handleVaultGet(
    d, S, hdr(makeProof({ method: "GET", path: `/v1/vault/${S}`, body: null, nonce: nonceSeq++ })),
  );
  assert.equal(g.status, 200);
  const parsed = JSON.parse(g.body.toString("utf8"));
  assert.equal(parsed.head.hash, fx.vault_head.hash);
  assert.equal(parsed.etag, `"${fx.vault_head.hash}"`);

  const body2 = jcsBytes({ head: fx.vg2 });
  const p2 = makeProof({
    method: "PUT", path: `/v1/vault/${S}`, body: { head: fx.vg2 },
    nonce: nonceSeq++, ifMatch: `"${fx.vault_head.hash}"`,
  });
  const r2 = await handleVaultPut(d, S, body2, { proof: hdr(p2), ifMatch: `"${fx.vault_head.hash}"`, ifNoneMatch: null });
  assert.equal(r2.status, 200);
  const stored = JSON.parse(backend.objects.get(`heads/${S}`)!.body);
  assert.equal(stored.core.generation, 2);
});

// Replay at the vault: same proof nonce → REPLAY.
test("vault nonce replay is rejected", async () => {
  const backend = new MemoryVaultBackend();
  const d = vaultDeps(backend);
  const p = makeProof({ method: "GET", path: `/v1/vault/${S}`, body: null, nonce: nonceSeq });
  await assert.rejects(
    () => handleVaultGet(d, S, hdr(p)),
    (e) => (e as { status: number }).status === 404, // first consumes nonce, head absent
  );
  await assert.rejects(
    () => handleVaultGet(d, S, hdr(p)),
    (e) => (e as { status: number }).status === 401 &&
      (e as { code: string }).code === "REPLAY",
  );
});

// Proof/header binding: conditional headers must match the signed fields.
test("vault rejects conditional header not bound by proof", async () => {
  const backend = new MemoryVaultBackend();
  const d = vaultDeps(backend);
  const body = jcsBytes({ head: fx.vault_head });
  const proof = makeProof({
    method: "PUT", path: `/v1/vault/${S}`, body: { head: fx.vault_head },
    nonce: nonceSeq++, ifNoneMatch: "*",
  });
  await assert.rejects(
    () => handleVaultPut(d, S, body, { proof: hdr(proof), ifMatch: `"wrong"`, ifNoneMatch: null }),
    (e) => (e as { status: number }).status === 401,
  );
  assert.equal(backend.writes, 0);
});
