/**
 * TV-G pure/conformance vectors that exercise production validators and
 * reducers directly (spec §16): classifier, delay/Retry-After, JCS, strict
 * JSON, capture validation, snapshot crypto, envelope verification, ids.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { classify, probeVerified } from "../src/classify.js";
import { computeDelay, parseRetryAfter } from "../src/delay.js";
import { jcsBytes } from "../src/encoding/jcs.js";
import { parseStrictJson, StrictJsonError } from "../src/encoding/strict-json.js";
import { b64Decode, b64Encode, isCanonicalB64 } from "../src/encoding/b64.js";
import { isValidId } from "../src/ids.js";
import { verifyEnvelope, domainMessage, jcsHash } from "../src/crypto/envelope.js";
import { ed25519Verify } from "../src/crypto/ed25519.js";
import { aes256gcmDecrypt } from "../src/crypto/aes.js";
import {
  validateCapture, decryptSnapshot, liveCookies, snapshotAad,
} from "../src/browser/capture.js";
import { observationFromResponse } from "../src/browser/observe.js";
import type { RawCookie, RawResponse } from "../src/browser/types.js";
import type { CipherSnapshot, PolicyCore, SnapshotPlain } from "../src/schema.js";

import { fx, obs, NOW, IDS, seed, thrownCode } from "./helpers.js";

const POLICY = fx.policy.core as PolicyCore;

// TV-G--01 — Explicit challenge header
test("TV-G--01 explicit cf-mitigated challenge classifies CF_CHALLENGE", () => {
  assert.equal(classify(obs({ status: 503, cf_mitigated: true })), "CF_CHALLENGE");
});

// TV-G--02 — Cloudflare branding is insufficient
test("TV-G--02 cloudflare headers without markers classify NONE", () => {
  const resp: RawResponse = {
    status: 200, network: "ok",
    headers: { server: "cloudflare", "cf-ray": "fixture" },
    title: null, htmlSample: null, redirectHops: [],
  };
  const { observation } = observationFromResponse(resp, POLICY, NOW);
  assert.equal(observation.cf_mitigated, false);
  assert.equal(observation.challenge_marker, false);
  assert.equal(classify(observation), "NONE");
});

// TV-G--03 — Login selector wins over HTTP success
test("TV-G--03 login marker beats 200", () => {
  const o = obs({ login_marker: true, identity: "match" });
  assert.equal(classify(o), "LOGIN_WALL");
  assert.equal(probeVerified(o), false);
});

// TV-G--04 — Rate limit beats a generic login marker
test("TV-G--04 rate limit precedence + retry_after delay", () => {
  const o = obs({ status: 429, login_marker: true, retry_after: "120" });
  assert.equal(classify(o), "RATE_LIMIT");
  const d = computeDelay("RATE_LIMIT", "ok", 1, o.retry_after, o.received_ms);
  assert.deepEqual(d, { delay_ms: 120000, retry_at_ms: 1800000120000, exhausted: false });
});

// TV-G--05 — Challenge beats rate-limit status
test("TV-G--05 challenge beats 429", () => {
  const o = obs({ status: 429, challenge_marker: true });
  assert.equal(classify(o), "CF_CHALLENGE");
  const d = computeDelay("CF_CHALLENGE", "ok", 1, o.retry_after, o.received_ms);
  assert.deepEqual(d, { delay_ms: 60000, retry_at_ms: 1800000060000, exhausted: false });
});

// TV-G--08 — Invalid Retry-After cannot erase minimum wait
test("TV-G--08 invalid retry-after falls back to base", () => {
  const d = computeDelay("RATE_LIMIT", "ok", 1, "-1", NOW);
  assert.deepEqual(d, { delay_ms: 30000, retry_at_ms: 1800000030000, exhausted: false });
});

// TV-G--09 — Excessive Retry-After is not capped early
test("TV-G--09 over-horizon retry-after exhausts", () => {
  const d = computeDelay("RATE_LIMIT", "ok", 1, "86401", NOW);
  assert.deepEqual(d, { delay_ms: null, retry_at_ms: null, exhausted: true });
});

// TV-G--10 — Canonical object order
test("TV-G--10 JCS canonical order, no trailing newline", () => {
  const out = jcsBytes(JSON.parse('{"z":1,"a":"x"}'));
  assert.equal(out.toString("utf8"), '{"a":"x","z":1}');
  // Python generator produces identical bytes (fixture hash sanity).
  assert.equal(jcsHash(fx.policy.core), fx.policy.hash);
});

// TV-G--11 — Duplicate key rejection (parser half; wire half in vectors-rpc)
test("TV-G--11 duplicate keys rejected by strict parser", () => {
  assert.throws(
    () => parseStrictJson(Buffer.from('{"v":1,"v":1,"id":"gq_000000000000000000001","method":"system.status","params":{}}')),
    StrictJsonError,
  );
});

// TV-G--19 — Parent-domain cookie capture
test("TV-G--19 Domain cookie covering app host fails UNSUPPORTED_STORAGE", () => {
  const domainCookie: RawCookie = {
    name: "sid", value: "fixture-only", host: "app.example.test", domain: ".example.test",
    path: "/", secure: true, httpOnly: true, sameSite: "Lax",
    expiresMs: 1800000060000, hasPartitionKey: false, unsupportedAttrs: false,
  };
  const err = thrownCode(() => validateCapture(
    { cookies: [domainCookie], storage: [] }, POLICY,
    { sessionId: IDS.S!, siteId: IDS.T!, generation: 2, savedMs: NOW, expiresMs: NOW + 600000, auditSeq: 5, auditHash: fx.audit7[4]!.hash },
  ));
  assert.equal(err, "UNSUPPORTED_STORAGE");
  // A cookie for an unrelated host is simply not captured (not a failure).
  const other: RawCookie = { ...domainCookie, domain: null, host: "cdn.other.test" };
  const out = validateCapture(
    { cookies: [other], storage: [] }, POLICY,
    { sessionId: IDS.S!, siteId: IDS.T!, generation: 2, savedMs: NOW, expiresMs: NOW + 600000, auditSeq: 5, auditHash: fx.audit7[4]!.hash },
  );
  assert.deepEqual(out.cookies, []);
});

// TV-G--20 — Expired cookie is removed at restore
test("TV-G--20 expired cookie dropped at restore boundary", () => {
  const plain = fx.snapshot_plain as unknown as SnapshotPlain;
  const restoreNow = 1800000060000; // cookie expires NOW+60000 < restore
  const live = liveCookies(
    { ...plain, cookies: [fx.good_cookie as never] },
    restoreNow,
  );
  assert.deepEqual(live, []);
});

// TV-G--40 — Signature mutation and cross-language verification
test("TV-G--40 receipt signature verifies then fails on mutation", () => {
  const pub = seed("sk_pub_b64");
  const eh = fx.receipt_envelope;
  assert.equal(verifyEnvelope("receipt", eh as never, pub), true);
  const mutated = { ...eh, core: { ...eh.core, seq: 2 } };
  assert.equal(verifyEnvelope("receipt", mutated as never, pub), false);
  // Tampered signature bytes also fail.
  const sig = b64Decode(eh.signature);
  sig[0] = sig[0]! ^ 1;
  assert.equal(
    ed25519Verify(pub, domainMessage("receipt", jcsHash(eh.core)), sig),
    false,
  );
});

// TV-G--44 — IMF-fixdate Retry-After
test("TV-G--44 IMF-fixdate Retry-After parses in GMT", () => {
  const d = computeDelay("RATE_LIMIT", "ok", 1, "Thu, 01 Jan 1970 00:02:00 GMT", 0);
  assert.deepEqual(d, { delay_ms: 120000, retry_at_ms: 120000, exhausted: false });
  assert.deepEqual(parseRetryAfter("  030  ", 0), { kind: "ok", delayMs: 30000 });
  assert.equal(parseRetryAfter("Fri, 01 Jan 1970 00:02:00 GMT", 0).kind, "invalid"); // wrong weekday
});

// TV-G--48 — Reserved signing prefix and integer validation
test("TV-G--48 reserved id prefix and unsafe integer rejected", () => {
  assert.equal(isValidId("gs_000000000000000000001", "gq"), false);
  assert.throws(() => parseStrictJson(Buffer.from('{"v":1,"id":"gq_000000000000000000001","method":"session.attach","params":{"session_id":"gs_000000000000000000001","run_id":"gr_000000000000000000001","expected_generation":9007199254740992}}')));
});

// --- supporting crypto checks used by vault/engine vectors ----------------

test("fixture cipher snapshot round-trips under fixture key", () => {
  const cs = fx.cipher_snapshot as unknown as CipherSnapshot;
  const pt = aes256gcmDecrypt(
    seed("enc_key_b64"), b64Decode(cs.nonce), b64Decode(cs.ciphertext),
    snapshotAad(cs.header as never),
  );
  assert.equal(pt.toString("utf8"), Buffer.from(jcsBytes(fx.snapshot_plain)).toString("utf8"));
});

test("decryptSnapshot rejects site substitution and policy drift", () => {
  const cs = fx.cipher_snapshot as unknown as CipherSnapshot;
  const key = seed("enc_key_b64");
  const checks = {
    sessionId: IDS.S!, siteId: IDS.T!, deviceId: IDS.D!, generation: 1,
    policyHash: fx.policy_hash, nowMs: NOW,
    auditAnchorHash: () => fx.audit7[4]!.hash,
  };
  // Baseline: authentic snapshot decrypts.
  assert.equal(decryptSnapshot(cs, key, checks).session_id, IDS.S);
  // Tampered header binding fails before any plaintext use.
  const tampered: CipherSnapshot = {
    ...cs, header: { ...cs.header, site_id: "gt_000000000000000000002" },
  };
  assert.equal(thrownCode(() => decryptSnapshot(tampered, key, checks)), "INTEGRITY_FAILED");
  // Policy drift fails identically.
  assert.equal(
    thrownCode(() => decryptSnapshot(cs, key, { ...checks, policyHash: "f".repeat(64) })),
    "INTEGRITY_FAILED",
  );
  // Expiry equality is expired.
  assert.equal(
    thrownCode(() => decryptSnapshot(cs, key, { ...checks, nowMs: cs.header.expires_ms as number })),
    "SNAPSHOT_EXPIRED",
  );
});

test("b64 canonicality + id validation", () => {
  assert.equal(isCanonicalB64(b64Encode(Buffer.from("abc"))), true);
  assert.equal(isCanonicalB64("AA=="), false); // padded is non-canonical
  assert.equal(isValidId(IDS.S!, "gs"), true);
  assert.equal(isValidId(IDS.S!, "gt"), false);
});
