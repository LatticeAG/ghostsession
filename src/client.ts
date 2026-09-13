/**
 * @latticeag/ghostsession client — unix-socket local transport and remote
 * HTTPS transport with request proofs + response-proof verification.
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { randomBytes } from "node:crypto";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { sha256Hex, jcsHash, domainMessage } from "./crypto/envelope.js";
import { ed25519Sign, ed25519Verify } from "./crypto/ed25519.js";
import { b64Encode, b64Decode } from "./encoding/b64.js";
import { newId } from "./ids.js";
import type { ErrorCode } from "./errors.js";

export class RpcFailure extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly retryAtMs: number | null;
  readonly state: string | null;
  constructor(e: { code: ErrorCode; retryable: boolean; retry_at_ms: number | null; state: string | null }) {
    super(`rpc ${e.code}`);
    this.code = e.code;
    this.retryable = e.retryable;
    this.retryAtMs = e.retry_at_ms;
    this.state = e.state;
  }
}

interface Transport {
  call(body: Buffer, proofHeader: Buffer | null): Promise<{ status: number; body: Buffer; responseProof: Buffer | null }>;
}

export class UnixSocketTransport implements Transport {
  constructor(private socketPath: string, private timeoutMs = 30_000) {}
  call(body: Buffer): Promise<{ status: number; body: Buffer; responseProof: Buffer | null }> {
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        { socketPath: this.socketPath, path: "/v1/rpc", method: "POST",
          headers: { "content-type": "application/json", "content-length": body.length },
          timeout: this.timeoutMs },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 500, body: Buffer.concat(chunks), responseProof: null }));
        },
      );
      req.on("timeout", () => { req.destroy(); reject(new RpcFailure({ code: "TIMEOUT", retryable: true, retry_at_ms: null, state: null })); });
      req.on("error", () => reject(new RpcFailure({ code: "DEVICE_OFFLINE", retryable: true, retry_at_ms: null, state: null })));
      req.end(body);
    });
  }
}

export interface RemoteOpts {
  baseUrl: string;
  deviceId: string;
  /** Caller's actor id (ga_…) as enrolled in the daemon's trusted keys. */
  actorId: string;
  /** Caller's request-signing key id + seed (provisioned out of band). */
  requestKeyId: string;
  requestSeed: Buffer;
  /** Pinned device public key for response-proof verification. */
  devicePublicKey: Buffer;
  timeoutMs?: number;
}

export class RemoteTransport implements Transport {
  /** The proof core most recently signed — used by Client.verifyResponse. */
  lastProofCore: unknown = null;
  constructor(private o: RemoteOpts) {}
  call(body: Buffer, _unused: Buffer | null): Promise<{ status: number; body: Buffer; responseProof: Buffer | null }> {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    const now = Date.now();
    const proofCore = {
      v: 1, actor_id: this.o.actorId,
      device_id: this.o.deviceId, key_id: this.o.requestKeyId,
      method: "POST", path: `/v1/devices/${this.o.deviceId}/rpc`,
      body_hash: sha256Hex(jcsBytes(parsed)),
      nonce: b64Encode(randomBytes(16)),
      issued_ms: now, expires_ms: now + 60_000,
      if_match: null, if_none_match: null,
    };
    this.lastProofCore = proofCore;
    const signature = b64Encode(ed25519Sign(this.o.requestSeed, domainMessage("request", jcsHash(proofCore))));
    const proofHeader = Buffer.from(jcsString({ core: proofCore, signature }), "utf8");
    const url = new URL(`${this.o.baseUrl}/v1/devices/${this.o.deviceId}/rpc`);
    return new Promise((resolve, reject) => {
      const req = httpsRequest(
        { hostname: url.hostname, port: url.port || 443, path: url.pathname, method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": body.length,
            "x-ghost-proof": b64Encode(proofHeader),
          },
          timeout: this.o.timeoutMs ?? 30_000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const rp = res.headers["x-ghost-response-proof"];
            const proofBytes = typeof rp === "string" ? b64Decode(rp) : null;
            resolve({ status: res.statusCode ?? 500, body: Buffer.concat(chunks), responseProof: proofBytes });
          });
        },
      );
      req.on("timeout", () => { req.destroy(); reject(new RpcFailure({ code: "TIMEOUT", retryable: true, retry_at_ms: null, state: null })); });
      req.on("error", () => reject(new RpcFailure({ code: "DEVICE_OFFLINE", retryable: true, retry_at_ms: null, state: null })));
      req.end(body);
    });
  }

  /** Verify the daemon's response proof against this call's request proof. */
  verifyResponse(requestProofCore: unknown, status: number, body: Buffer, proofHeader: Buffer | null): void {
    if (proofHeader === null) {
      throw new RpcFailure({ code: "INTEGRITY_FAILED", retryable: false, retry_at_ms: null, state: null });
    }
    const env = JSON.parse(proofHeader.toString("utf8")) as { core: Record<string, unknown>; signature: string };
    const c = env.core;
    const expected = jcsHash(c);
    const okFields =
      c.v === 1 && c.device_id === this.o.deviceId &&
      c.request_hash === jcsHash(requestProofCore) &&
      c.status === status && c.body_hash === sha256Hex(body);
    const sigOk = okFields && ed25519Verify(
      this.o.devicePublicKey, domainMessage("response", expected), b64Decode(env.signature),
    );
    if (!sigOk) {
      throw new RpcFailure({ code: "INTEGRITY_FAILED", retryable: false, retry_at_ms: null, state: null });
    }
  }
}

export class Client {
  constructor(
    private transport: UnixSocketTransport | RemoteTransport,
    private opts: { timeoutMs?: number } = {},
  ) {}

  async call(method: string, params: unknown, opts: { requestId?: string } = {}): Promise<unknown> {
    const requestId = opts.requestId ?? newId("gq");
    const body = jcsBytes({ v: 1, id: requestId, method, params });
    let attempts = 0;
    for (;;) {
      attempts++;
      let res: { status: number; body: Buffer; responseProof: Buffer | null };
      let proofCore: unknown = null;
      try {
        res = await this.transport.call(body, null);
        if (this.transport instanceof RemoteTransport) proofCore = this.transport.lastProofCore;
      } catch (e) {
        if (e instanceof RpcFailure && e.retryable && attempts <= 2) continue;
        throw e;
      }
      if (this.transport instanceof RemoteTransport) {
        this.transport.verifyResponse(proofCore, res.status, res.body, res.responseProof);
      }
      const parsed = parseStrictJson(res.body) as {
        ok: boolean; result?: unknown;
        error?: { code: ErrorCode; retryable: boolean; retry_at_ms: number | null; state: string | null };
      };
      if (parsed.ok) return parsed.result;
      const failure = new RpcFailure(parsed.error!);
      if (failure.retryable && attempts <= 2) continue;
      throw failure;
    }
  }
}
