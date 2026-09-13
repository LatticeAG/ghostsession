/**
 * RPC dispatch: strict request envelope, signed request proofs, nonce cache,
 * request/operation dedup, role gating, and all 18 methods.
 */

import { RpcError, type ErrorCode } from "./errors.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { sha256Hex, jcsHash, domainMessage } from "./crypto/envelope.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import { b64Decode, b64Encode } from "./encoding/b64.js";
import { isValidId } from "./ids.js";
import {
  PARAMS, vRequestProof, vRpcRequest, vSessionView,
  type BrowserAction, type RequestProof, type RpcRequest, type SessionState,
} from "./schema.js";
import type { Engine } from "./engine.js";
import type { Store } from "./store/database.js";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

export const MAX_RPC_BYTES = 256 * 1024;
export const MAX_PROOF_BYTES = 8192;
const DEDUP_MS = 86_400_000;
const NONCE_RETENTION_MS = 120_000;
const PROOF_SKEW_MS = 60_000;
const REMOTE_WINDOW_MS = 60_000;
const REMOTE_MAX = 60;

export interface Caller {
  actorId: string;
  owner: boolean;
  /** Session allowlist for remote runtime callers; null = owner (all). */
  sessions: ReadonlySet<string> | null;
}

export interface TrustedKey {
  key_id: string;
  public_key: string;
  purpose: "policy" | "request" | "relay" | "receipt";
  actor_id: string;
  sessions: string[];
}

export interface DispatchResult {
  status: number;
  body: Buffer;
  /** Serialized {core,signature} for X-Ghost-Response-Proof (remote only). */
  responseProof: Buffer | null;
}

const OWNER_ONLY = new Set([
  "site.put", "session.create", "handoff.open", "handoff.resolve",
  "session.revoke", "session.delete", "vault.sync", "vault.rotate",
]);
const RUNTIME_METHODS = new Set([
  "system.status", "session.get", "session.attach", "session.renew", "session.step",
  "session.checkpoint", "session.detach", "session.recover", "handoff.get", "audit.list",
]);
const TERMINAL: SessionState[] = ["REVOKED", "DELETED", "QUARANTINED"];

export function statusFor(code: ErrorCode): number {
  switch (code) {
    case "INVALID_SCHEMA":
    case "VERSION_UNSUPPORTED": return 400;
    case "UNAUTHORIZED":
    case "REPLAY": return 401;
    case "FORBIDDEN":
    case "SCOPE_DENIED": return 403;
    case "NOT_FOUND": return 404;
    case "STATE_CONFLICT":
    case "STALE_GENERATION":
    case "LEASE_HELD":
    case "LEASE_EXPIRED":
    case "STALE_FENCE":
    case "BUSY":
    case "NOT_READY":
    case "IDEMPOTENCY_CONFLICT":
    case "OPERATION_CONFLICT":
    case "OUTCOME_UNKNOWN":
    case "RECOVERY_EXHAUSTED":
    case "STALE_HANDOFF":
    case "VAULT_CONFLICT": return 409;
    case "RESULT_GONE":
    case "HANDOFF_EXPIRED": return 410;
    case "AUTH_NOT_VERIFIED":
    case "UNSUPPORTED_STORAGE":
    case "SNAPSHOT_EXPIRED":
    case "CONSENT_EXPIRED":
    case "INTEGRITY_FAILED": return 412;
    case "BODY_TOO_LARGE": return 413;
    case "KEY_UNAVAILABLE":
    case "SECURE_STORAGE_UNAVAILABLE":
    case "AUDIT_UNAVAILABLE":
    case "CLOCK_UNSAFE":
    case "COOLDOWN_ACTIVE": return 423;
    case "RATE_LIMITED": return 429;
    case "DEVICE_OFFLINE": return 502;
    case "TIMEOUT": return 504;
    default: return 500;
  }
}

function retryable(code: ErrorCode): boolean {
  return code === "BUSY" || code === "DEVICE_OFFLINE" || code === "RATE_LIMITED" ||
    code === "COOLDOWN_ACTIVE" || code === "TIMEOUT";
}

export function failBody(id: string | null, e: RpcError): Buffer {
  return jcsBytes({
    v: 1, id, ok: false,
    error: {
      code: e.code, retryable: retryable(e.code),
      retry_at_ms: (e.retryAtMs as number | undefined) ?? null,
      state: (e.state as SessionState | undefined) ?? null,
    },
  });
}

export function okBody(id: string, result: unknown): Buffer {
  return jcsBytes({ v: 1, id, ok: true, result });
}

export class Dispatcher {
  readonly engine: Engine;
  readonly store: Store;
  private trusted: Map<string, TrustedKey>;
  now: () => number;

  constructor(engine: Engine, trusted: TrustedKey[], now: () => number) {
    this.engine = engine;
    this.store = engine.store;
    this.trusted = new Map(trusted.map((k) => [k.key_id, k]));
    this.now = now;
  }

  /** Local-socket dispatch (no proof). socket: "owner" allows all methods. */
  async local(raw: Buffer, socket: "owner" | "driver"): Promise<DispatchResult> {
    const caller: Caller = {
      actorId: this.engine.device.ownerId,
      owner: socket === "owner",
      sessions: null,
    };
    return this.dispatch(raw, caller, null);
  }

  /** Remote/relay dispatch with an X-Ghost-Proof body. */
  async remote(raw: Buffer, proofBytes: Buffer | null): Promise<DispatchResult> {
    return this.dispatch(raw, null, proofBytes);
  }

  /** Internal dispatch with an established caller (relay forward path). */
  async dispatchWithCaller(raw: Buffer, caller: Caller): Promise<DispatchResult> {
    return this.dispatch(raw, caller, null);
  }

  trustedKey(keyId: string): TrustedKey | undefined {
    return this.trusted.get(keyId);
  }

  signResponseProof(requestProofCore: unknown, status: number, body: Buffer): Buffer {
    return this.signResponse(requestProofCore, status, body);
  }

  private async dispatch(raw: Buffer, callerIn: Caller | null, proofBytes: Buffer | null): Promise<DispatchResult> {
    // 1. Size + schema.
    if (raw.length > MAX_RPC_BYTES) {
      return this.finish(null, new RpcError("BODY_TOO_LARGE"), null, null);
    }
    let req: RpcRequest;
    try {
      req = vRpcRequest(parseStrictJson(raw), "request");
      if (!isValidId(req.id, "gq")) throw new RpcError("INVALID_SCHEMA");
      const pv = PARAMS[req.method];
      if (!pv) throw new RpcError("INVALID_SCHEMA");
      pv(req.params, "params");
    } catch (e) {
      const err = e instanceof RpcError ? e : new RpcError("INVALID_SCHEMA");
      return this.finish(err.code === "INVALID_SCHEMA" ? null : reqId(raw), err, null, null);
    }

    // 2. Authentication + nonce (remote proofs) inside the request transaction.
    let caller: Caller;
    let proofCore: unknown | null = null;
    if (proofBytes !== null) {
      try {
        const v = this.store.txn(() => this.verifyProof(proofBytes, req));
        caller = v.caller;
        proofCore = v.core;
      } catch (e) {
        const err = e instanceof RpcError ? e : new RpcError("UNAUTHORIZED");
        return this.finish(req.id, err, null, null);
      }
    } else if (callerIn) {
      caller = callerIn;
    } else {
      return this.finish(req.id, new RpcError("UNAUTHORIZED"), null, null);
    }

    // Remote caller rate limit: 60/minute per caller key.
    if (!caller.owner) {
      try {
        this.rateLimit(`remote:${caller.actorId}`, REMOTE_WINDOW_MS, REMOTE_MAX);
      } catch (e) {
        return this.finish(req.id, e as RpcError, caller, proofCore);
      }
    }

    // 3. Actor/session authorization.
    try {
      this.authorize(caller, req);
    } catch (e) {
      return this.finish(req.id, e as RpcError, caller, proofCore);
    }

    // 4. Terminal pre-gate: never serve stale runtime results on terminal sessions.
    const sessionId = sessionParam(req);
    if (sessionId) {
      const st = this.sessionState(sessionId);
      if (st !== null && TERMINAL.includes(st)) {
        const allowed = req.method === "session.get" || req.method === "audit.list" ||
          req.method === "session.revoke" || req.method === "session.delete";
        if (!allowed) {
          return this.finish(req.id, new RpcError("STATE_CONFLICT", { state: st }), caller, proofCore);
        }
      }
    }

    // 5. Request dedup → dispatch → cache.
    const scope = caller.actorId;
    const prior = this.requestRow(scope, req.id);
    if (prior === "PENDING") {
      return this.finish(req.id, new RpcError("BUSY"), caller, proofCore);
    }
    if (prior instanceof Buffer) {
      return this.finishRaw(req.id, prior, caller, proofCore);
    }

    this.store.txn(() => {
      this.store.run(
        "INSERT INTO requests(owner_scope,request_id,state,response_cipher,created_ms) VALUES(?,?,'PENDING',NULL,?)",
        scope, req.id, this.now(),
      );
      this.store.run("DELETE FROM requests WHERE created_ms < ?", this.now() - DEDUP_MS);
    });

    let out: DispatchResult;
    try {
      const result = await this.invoke(caller, req);
      out = this.finish(req.id, null, caller, proofCore, result);
    } catch (e) {
      const err = e instanceof RpcError ? e : new RpcError("INTERNAL");
      out = this.finish(req.id, err, caller, proofCore);
    }
    // Cache the completed response (success or typed failure).
    this.store.txn(() => {
      this.store.run(
        "UPDATE requests SET state='DONE', response_cipher=? WHERE owner_scope=? AND request_id=?",
        cacheEncrypt(this.engine.device.cacheKey, out.body), scope, req.id,
      );
    });
    return out;
  }

  private requestRow(scope: string, id: string): "PENDING" | Buffer | null {
    const r = this.store.get(
      "SELECT state,response_cipher FROM requests WHERE owner_scope=? AND request_id=?", scope, id,
    );
    if (!r) return null;
    if (r.state === "PENDING") return "PENDING";
    if (!r.response_cipher) return null;
    return Buffer.from(cacheDecrypt(this.engine.device.cacheKey, Buffer.from(r.response_cipher as Uint8Array)));
  }

  private rateLimit(subject: string, windowMs: number, max: number): void {
    const now = this.now();
    this.store.txn(() => {
      const row = this.store.get("SELECT stamps_json FROM rate_limits WHERE subject=? AND kind='rpc'", subject);
      let stamps: number[] = row
        ? (JSON.parse(Buffer.from(row.stamps_json as Uint8Array).toString("utf8")) as number[])
        : [];
      stamps = stamps.filter((t) => t >= now - windowMs);
      if (stamps.length >= max) {
        throw new RpcError("RATE_LIMITED", { retryAtMs: stamps[0]! + windowMs });
      }
      stamps.push(now);
      this.store.run(
        "INSERT INTO rate_limits(subject,kind,stamps_json) VALUES(?,'rpc',?) ON CONFLICT(subject,kind) DO UPDATE SET stamps_json=excluded.stamps_json",
        subject, jcsBytes(stamps),
      );
    });
  }

  private authorize(caller: Caller, req: RpcRequest): void {
    const m = req.method;
    if (OWNER_ONLY.has(m) && !caller.owner) throw new RpcError("FORBIDDEN");
    if (!caller.owner && !RUNTIME_METHODS.has(m)) throw new RpcError("FORBIDDEN");
    if (!caller.owner && (m === "session.recover")) {
      const intent = (req.params as { intent?: string }).intent;
      if (intent === "reauth" || intent === "acknowledge_unknown") throw new RpcError("FORBIDDEN");
    }
    if (caller.sessions !== null) {
      const sid = sessionParam(req);
      if (sid !== null && !caller.sessions.has(sid)) throw new RpcError("NOT_FOUND");
      if (m.startsWith("handoff.")) {
        const hid = (req.params as { handoff_id: string }).handoff_id;
        const owner = this.handoffSession(hid);
        if (owner === null || !caller.sessions.has(owner)) throw new RpcError("NOT_FOUND");
      }
    }
    if (caller.owner === false && m === "system.status") return;
    if (!caller.owner && !RUNTIME_METHODS.has(m)) throw new RpcError("FORBIDDEN");
  }

  private handoffSession(handoffId: string): string | null {
    const r = this.store.get("SELECT session_id FROM handoffs WHERE id=?", handoffId);
    return r ? (r.session_id as string) : null;
  }

  private sessionState(sessionId: string): SessionState | null {
    const r = this.store.get("SELECT state FROM sessions WHERE id=?", sessionId);
    return r ? (r.state as SessionState) : null;
  }

  private async invoke(caller: Caller, req: RpcRequest): Promise<unknown> {
    const p = req.params as Record<string, never>;
    const e = this.engine;
    switch (req.method) {
      case "system.status": return e.status();
      case "site.put": return e.putSite((req.params as { policy: unknown }).policy);
      case "session.create": return e.createSession((req.params as { site_id: string }).site_id);
      case "session.get": {
        const v = e.getSession(p["session_id" as never] as unknown as string);
        return vSessionView(v, "view");
      }
      case "session.attach":
        return e.attach(
          (req.params as { session_id: string }).session_id,
          (req.params as { run_id: string }).run_id,
          (req.params as { expected_generation: number }).expected_generation,
          caller.actorId,
        );
      case "session.renew": {
        const lp = req.params as { session_id: string; lease_id: string; fence: number };
        return e.renew(lp.session_id, lp.lease_id, lp.fence);
      }
      case "session.step": {
        const sp = req.params as {
          session_id: string; lease_id: string; fence: number;
          operation_id: string; action: BrowserAction;
        };
        return e.step(sp.session_id, sp.lease_id, sp.fence, sp.operation_id, sp.action, caller.actorId);
      }
      case "session.checkpoint": {
        const lp = req.params as { session_id: string; lease_id: string; fence: number };
        return e.checkpoint(lp.session_id, lp.lease_id, lp.fence);
      }
      case "session.detach": {
        const lp = req.params as { session_id: string; lease_id: string; fence: number; checkpoint: boolean };
        return e.detach(lp.session_id, lp.lease_id, lp.fence, lp.checkpoint);
      }
      case "session.recover": {
        const rp = req.params as {
          session_id: string; block_revision: number | null;
          intent: "retry" | "fallback" | "reauth" | "acknowledge_unknown";
        };
        return e.recover(rp.session_id, rp.block_revision, rp.intent, caller.actorId);
      }
      case "handoff.get": return e.getHandoff((req.params as { handoff_id: string }).handoff_id);
      case "handoff.open": return e.openHandoff((req.params as { handoff_id: string }).handoff_id);
      case "handoff.resolve": {
        const hp = req.params as { handoff_id: string; decision: "ready" | "cancel" };
        return e.resolveHandoff(hp.handoff_id, hp.decision);
      }
      case "session.revoke": return e.revoke((req.params as { session_id: string }).session_id);
      case "session.delete": {
        const dp = req.params as { session_id: string; confirm_generation: number };
        return e.deleteSession(dp.session_id, dp.confirm_generation);
      }
      case "audit.list": {
        const ap = req.params as { session_id: string; after_seq: number; limit: number };
        return e.auditList(ap.session_id, ap.after_seq, ap.limit);
      }
      case "vault.sync": {
        const vp = req.params as { session_id: string; mode: "upload" | "restore" };
        return e.vaultSync(vp.session_id, vp.mode);
      }
      case "vault.rotate": return e.vaultRotate((req.params as { session_id: string }).session_id);
      default: throw new RpcError("INVALID_SCHEMA");
    }
  }

  // ------------------------------------------------------------ proof path

  private verifyProof(proofBytes: Buffer, req: RpcRequest): { caller: Caller; core: unknown } {
    if (proofBytes.length > MAX_PROOF_BYTES) throw new RpcError("BODY_TOO_LARGE");
    let proof: RequestProof;
    try {
      proof = vRequestProof(parseStrictJson(proofBytes), "proof");
    } catch {
      throw new RpcError("UNAUTHORIZED");
    }
    const c = proof.core;
    if (c.device_id !== this.engine.device.deviceId) throw new RpcError("UNAUTHORIZED");
    if (c.path !== `/v1/devices/${this.engine.device.deviceId}/rpc`) throw new RpcError("UNAUTHORIZED");
    if (c.method !== "POST") throw new RpcError("UNAUTHORIZED");
    if (c.if_match !== null || c.if_none_match !== null) throw new RpcError("UNAUTHORIZED");
    if (c.expires_ms - c.issued_ms !== PROOF_SKEW_MS) throw new RpcError("UNAUTHORIZED");
    const now = this.now();
    if (Math.abs(now - c.issued_ms) > PROOF_SKEW_MS || now >= c.expires_ms) {
      throw new RpcError("UNAUTHORIZED");
    }
    if (c.body_hash !== sha256Hex(jcsBytes(req))) throw new RpcError("UNAUTHORIZED");
    const key = this.trusted.get(c.key_id);
    if (!key || key.purpose !== "request" || key.actor_id !== c.actor_id) {
      throw new RpcError("UNAUTHORIZED");
    }
    let sig: Buffer;
    try {
      sig = b64Decode(proof.signature);
    } catch {
      throw new RpcError("UNAUTHORIZED");
    }
    if (!ed25519Verify(b64Decode(key.public_key), domainMessage("request", jcsHash(c)), sig)) {
      throw new RpcError("UNAUTHORIZED");
    }
    // Nonce acceptance commits inside the request transaction.
    const ok = this.store.nonceAccept(c.actor_id, c.key_id, c.nonce, now, NONCE_RETENTION_MS);
    if (!ok) throw new RpcError("REPLAY");
    return { caller: { actorId: c.actor_id, owner: false, sessions: new Set(key.sessions) }, core: c };
  }

  // --------------------------------------------------------------- finish

  private finish(
    id: string | null, err: RpcError | null, caller: Caller | null,
    proofCore: unknown | null, result?: unknown,
  ): DispatchResult {
    const body = err ? failBody(id, err) : okBody(id!, result);
    const status = err ? statusFor(err.code) : 200;
    const responseProof = caller && !caller.owner && proofCore
      ? this.signResponse(proofCore, status, body)
      : null;
    return { status, body, responseProof };
  }

  private finishRaw(id: string, cachedBody: Buffer, caller: Caller, proofCore: unknown | null): DispatchResult {
    const status = JSON.parse(cachedBody.toString("utf8")).ok ? 200 : statusFor(
      JSON.parse(cachedBody.toString("utf8")).error.code as ErrorCode,
    );
    const responseProof = !caller.owner && proofCore ? this.signResponse(proofCore, status, cachedBody) : null;
    return { status, body: cachedBody, responseProof };
  }

  private signResponse(requestProofCore: unknown, status: number, body: Buffer): Buffer {
    const core = {
      v: 1,
      device_id: this.engine.device.deviceId,
      signing_key_id: this.engine.device.signingKeyId,
      request_hash: jcsHash(requestProofCore),
      status,
      body_hash: sha256Hex(body),
      issued_ms: this.now(),
    };
    const signature = b64Encode(
      ed25519Sign(this.engine.device.signingSeed, domainMessage("response", jcsHash(core))),
    );
    return Buffer.from(jcsString({ core, signature }), "utf8");
  }
}

import { ed25519Sign } from "./crypto/ed25519.js";

function sessionParam(req: RpcRequest): string | null {
  const p = req.params as Record<string, unknown>;
  if (typeof p.session_id === "string" && p.session_id.startsWith("gs_")) return p.session_id;
  return null;
}

function reqId(raw: Buffer): string | null {
  try {
    const v = JSON.parse(raw.toString("utf8")) as { id?: unknown };
    return typeof v.id === "string" ? v.id : null;
  } catch {
    return null;
  }
}

function cacheEncrypt(key: Buffer, plain: Buffer): Buffer {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}

function cacheDecrypt(key: Buffer, blob: Buffer): Buffer {
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
