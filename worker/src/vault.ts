/**
 * Hosted vault endpoint logic — shared between the Worker entry and the
 * conformance runner. All storage goes through VaultBackend so the CAS +
 * nonce semantics can be exercised deterministically in tests.
 *
 * Security contract (spec §8.3):
 *  - Every request carries an X-Ghost-Proof; bad proofs yield 401 with no
 *    detail about which check failed.
 *  - Conditional writes: proof-bound if_match/if_none_match must equal the
 *    request headers; CAS uses the backend's native conditional write — never
 *    last-write-wins.
 *  - Tombstones are permanent: a stored deleted head rejects every later PUT.
 *  - Generations strictly advance; gaps are skipped checkpoints, never
 *    rollback.
 *  - The worker stores only opaque signed ciphertext: it never sees keys,
 *    cookies, account identity, or decrypted state.
 */

import { parseStrictJson } from "../../src/encoding/strict-json.js";
import { jcsBytes, jcsString } from "../../src/encoding/jcs.js";
import { b64Decode, b64Encode } from "../../src/encoding/b64.js";
import { sha256Hex, jcsHash, domainMessage } from "../../src/crypto/envelope.js";
import { ed25519Verify, ed25519Sign } from "../../src/crypto/ed25519.js";
import {
  vRequestProof, vVaultWrite, vVaultHead,
  type RequestProof, type VaultHead,
} from "../../src/schema.js";

export const MAX_PROOF_BYTES = 8192;
export const MAX_VAULT_BODY = 512 * 1024;
const PROOF_SKEW_MS = 60_000;

export interface VaultObject {
  body: string;
  /** Backend-native tag for conditional writes (R2 etag, FS inode, etc). */
  nativeEtag: string;
}

export interface VaultBackend {
  get(key: string): Promise<VaultObject | null>;
  /**
   * Atomic conditional write. `expectNativeEtag === null` means
   * "object must not exist"; otherwise it must equal the current tag.
   * Returns null when the precondition fails (never overwrites).
   */
  putIf(key: string, body: string, expectNativeEtag: string | null): Promise<{ nativeEtag: string } | null>;
  /** Atomic create-if-absent for nonce markers. Returns false when present. */
  createNonce(key: string): Promise<boolean>;
}

export interface VaultTrustedKey {
  key_id: string;
  public_key: string;
  purpose: "request" | "vault" | "receipt";
  actor_id: string;
  device_id: string;
}

export interface VaultDeps {
  backend: VaultBackend;
  trusted: VaultTrustedKey[];
  now: () => number;
  /** Worker response-proof signing key (gk_… relay purpose in fixtures). */
  responseKey: { keyId: string; seed: Uint8Array };
  /** Pinned device id this deployment serves. */
  deviceId: string;
}

export interface HttpResult {
  status: number;
  body: Buffer;
  /** base64url(JCS{core,signature}) for X-Ghost-Response-Proof. */
  responseProof: string;
  etag?: string;
}

export class VaultHttpError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

function err(status: number, code: string): never {
  throw new VaultHttpError(status, code);
}

/** In-memory backend for tests and local dev. */
export class MemoryVaultBackend implements VaultBackend {
  objects = new Map<string, VaultObject>();
  nonces = new Set<string>();
  writes = 0;
  private seq = 0;
  async get(key: string): Promise<VaultObject | null> {
    return this.objects.get(key) ?? null;
  }
  async putIf(key: string, body: string, expectNativeEtag: string | null): Promise<{ nativeEtag: string } | null> {
    const cur = this.objects.get(key);
    if (expectNativeEtag === null ? cur !== undefined : cur?.nativeEtag !== expectNativeEtag) {
      return null;
    }
    const nativeEtag = `mem-${++this.seq}`;
    this.objects.set(key, { body, nativeEtag });
    this.writes++;
    return { nativeEtag };
  }
  async createNonce(key: string): Promise<boolean> {
    if (this.nonces.has(key)) return false;
    this.nonces.add(key);
    return true;
  }
}

/**
 * Verify a request proof for this endpoint. Returns the trusted key + core.
 * Every failure is a bare 401 — no oracle about which check failed.
 */
async function verifyProof(
  deps: VaultDeps, proofHeader: string | null,
  method: "GET" | "PUT" | "POST", path: string, bodyHash: string,
  cond: { ifMatch: string | null; ifNoneMatch: string | null },
): Promise<{ key: VaultTrustedKey; core: RequestProof["core"] }> {
  if (proofHeader === null) err(401, "UNAUTHORIZED");
  let raw: Buffer;
  try {
    raw = b64Decode(proofHeader!);
  } catch {
    err(401, "UNAUTHORIZED");
  }
  if (raw!.length > MAX_PROOF_BYTES) err(413, "BODY_TOO_LARGE");
  let proof: RequestProof;
  try {
    proof = vRequestProof(parseStrictJson(raw!), "proof");
  } catch {
    err(401, "UNAUTHORIZED");
  }
  const c = proof!.core;
  const now = deps.now();
  const fieldsOk =
    c.device_id === deps.deviceId &&
    c.method === method && c.path === path &&
    c.body_hash === bodyHash &&
    c.expires_ms - c.issued_ms === PROOF_SKEW_MS &&
    Math.abs(now - c.issued_ms) <= PROOF_SKEW_MS && now < c.expires_ms &&
    c.if_match === cond.ifMatch && c.if_none_match === cond.ifNoneMatch;
  if (!fieldsOk) err(401, "UNAUTHORIZED");
  const key = deps.trusted.find(
    (k) => k.key_id === c.key_id && k.actor_id === c.actor_id && k.purpose === "request",
  );
  if (!key || key.device_id !== c.device_id) err(401, "UNAUTHORIZED");
  let sigOk = false;
  try {
    sigOk = ed25519Verify(b64Decode(key!.public_key), domainMessage("request", jcsHash(c)), b64Decode(proof!.signature));
  } catch {
    sigOk = false;
  }
  if (!sigOk) err(401, "UNAUTHORIZED");
  // Nonce: immutable conditional-create marker. Failure → REPLAY.
  const fresh = await deps.backend.createNonce(`auth/${c.key_id}/${c.nonce}`);
  if (!fresh) err(401, "REPLAY");
  return { key: key!, core: c };
}

/** Verify a vault head's signature under the pinned device identity key. */
function verifyHead(deps: VaultDeps, head: VaultHead, sessionId: string): void {
  const c = head.core;
  const key = deps.trusted.find(
    (k) => k.key_id === c.signing_key_id && k.purpose === "vault" && k.device_id === deps.deviceId,
  );
  if (!key) err(401, "UNAUTHORIZED");
  const bound =
    c.session_id === sessionId && c.device_id === deps.deviceId &&
    jcsHash(c) === head.hash;
  let sigOk = false;
  try {
    sigOk = bound && ed25519Verify(b64Decode(key!.public_key), domainMessage("vault", head.hash), b64Decode(head.signature));
  } catch {
    sigOk = false;
  }
  if (!sigOk) err(401, "UNAUTHORIZED");
}

export async function handleVaultGet(deps: VaultDeps, sessionId: string, proofHeader: string | null): Promise<HttpResult> {
  const path = `/v1/vault/${sessionId}`;
  const bodyHash = sha256Hex(Buffer.alloc(0));
  const { core: proofCore } = await verifyProof(
    deps, proofHeader, "GET", path, bodyHash, { ifMatch: null, ifNoneMatch: null },
  );
  const obj = await deps.backend.get(`heads/${sessionId}`);
  if (!obj) err(404, "NOT_FOUND");
  const head = JSON.parse(obj.body) as VaultHead;
  const etag = `"${head.hash}"`;
  return result(deps, 200, { head, etag }, { etag }, proofCore);
}

export async function handleVaultPut(
  deps: VaultDeps, sessionId: string, rawBody: Buffer,
  headers: { proof: string | null; ifMatch: string | null; ifNoneMatch: string | null },
): Promise<HttpResult> {
  const path = `/v1/vault/${sessionId}`;
  if (rawBody.length === 0 || rawBody.length > MAX_VAULT_BODY) err(413, "BODY_TOO_LARGE");
  let body: { head: VaultHead };
  try {
    body = vVaultWrite(parseStrictJson(rawBody), "body");
    vVaultHead(body.head, "head");
  } catch {
    err(400, "INVALID_SCHEMA");
  }
  const ifNone = headers.ifNoneMatch === "*" ? "*" : null;
  const ifMatch = headers.ifNoneMatch === "*" ? null : headers.ifMatch;
  const { core: proofCore } = await verifyProof(
    deps, headers.proof, "PUT", path, sha256Hex(jcsBytes(body)),
    { ifMatch, ifNoneMatch: ifNone },
  );
  verifyHead(deps, body!.head, sessionId);
  const head = body!.head;

  const key = `heads/${sessionId}`;
  const existing = await deps.backend.get(key);
  const existingHead = existing ? (JSON.parse(existing.body) as VaultHead) : null;

  if (existingHead !== null) {
    // Tombstone: permanent. No write over a deleted head, ever.
    if (existingHead.core.deleted) err(409, "VAULT_CONFLICT");
    // Generation must strictly advance.
    if (head.core.generation <= existingHead.core.generation) err(409, "VAULT_CONFLICT");
    // Replacement requires the exact current service tag.
    if (ifNone !== null || ifMatch !== `"${existingHead.hash}"`) err(409, "VAULT_CONFLICT");
  } else {
    if (ifNone !== "*") err(409, "VAULT_CONFLICT");
    // A first write may not be a tombstone or skip generation 1.
    if (head.core.deleted || head.core.generation < 1) err(409, "VAULT_CONFLICT");
  }

  const put = await deps.backend.putIf(key, JSON.stringify(head), existing?.nativeEtag ?? null);
  if (put === null) err(409, "VAULT_CONFLICT");
  const etag = `"${head.hash}"`;
  return result(deps, 200, { head, etag }, { etag }, proofCore);
}

export async function handleHealth(deps: VaultDeps, proofHeader: string | null): Promise<HttpResult> {
  await verifyProof(
    deps, proofHeader, "GET", "/v1/health", sha256Hex(Buffer.alloc(0)),
    { ifMatch: null, ifNoneMatch: null },
  );
  return result(deps, 200, { v: 1, ready: true, protocol: 1 }, {}, null);
}

function result(
  deps: VaultDeps, status: number, body: unknown,
  extra: { etag?: string }, proofCore: unknown | null,
): HttpResult {
  const bodyBuf = Buffer.from(jcsString(body), "utf8");
  const core = {
    v: 1, device_id: deps.deviceId, signing_key_id: deps.responseKey.keyId,
    request_hash: proofCore === null ? "0".repeat(64) : jcsHash(proofCore),
    status, body_hash: sha256Hex(bodyBuf), issued_ms: deps.now(),
  };
  const signature = b64Encode(ed25519Sign(Buffer.from(deps.responseKey.seed), domainMessage("response", jcsHash(core))));
  return {
    status, body: bodyBuf,
    responseProof: b64Encode(Buffer.from(jcsString({ core, signature }), "utf8")),
    ...(extra.etag ? { etag: extra.etag } : {}),
  };
}

/** Map an internal error to the wire result (proof-bound response signing). */
export function errorResult(deps: VaultDeps, e: unknown, proofCore: unknown | null): HttpResult {
  const code = e instanceof VaultHttpError ? e.code : "INTERNAL";
  const status = e instanceof VaultHttpError ? e.status : 500;
  const bodyBuf = Buffer.from(jcsString({
    v: 1, id: null, ok: false,
    error: { code, retryable: status === 429 || status === 502, retry_at_ms: null, state: null },
  }), "utf8");
  const core = {
    v: 1, device_id: deps.deviceId, signing_key_id: deps.responseKey.keyId,
    request_hash: proofCore === null ? "0".repeat(64) : jcsHash(proofCore),
    status, body_hash: sha256Hex(bodyBuf), issued_ms: deps.now(),
  };
  const signature = b64Encode(ed25519Sign(Buffer.from(deps.responseKey.seed), domainMessage("response", jcsHash(core))));
  return { status, body: bodyBuf, responseProof: b64Encode(Buffer.from(jcsString({ core, signature }), "utf8")) };
}
