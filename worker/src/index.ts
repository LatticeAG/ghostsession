/**
 * GhostSession hosted relay Worker.
 *
 * Public surface (spec §8.3):
 *   POST /v1/devices/{D}/rpc   — verify caller proof, forward frame over the
 *                                private outbound tunnel to the desktop.
 *   GET  /v1/vault/{S}         — return the signed opaque head + service etag.
 *   PUT  /v1/vault/{S}         — conditional CAS write / signed tombstone.
 *   GET  /v1/health            — signed liveness response.
 *
 * The worker never holds decryption keys, never executes a browser, and never
 * signs daemon responses — device replies are signed by the desktop only.
 */

import {
  VaultBackend, VaultDeps, MemoryVaultBackend,
  handleVaultGet, handleVaultPut, handleHealth, errorResult, VaultHttpError,
} from "./vault.js";
import { b64Encode } from "../../src/encoding/b64.js";

interface CfRequestLike {
  method: string;
  url: string;
  headers: { get(name: string): string | null };
  arrayBuffer(): Promise<ArrayBuffer>;
}

interface CfResponseInit {
  status?: number;
  headers?: Record<string, string>;
}

declare const Response: {
  new (body?: string | ArrayBuffer | null, init?: CfResponseInit): unknown;
};

interface R2ObjectLike { etag: string; text(): Promise<string> }
interface R2BucketLike {
  get(key: string): Promise<R2ObjectLike | null>;
  put(key: string, value: string, opts?: { onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } }): Promise<R2ObjectLike | null>;
}
interface Env {
  VAULT_BUCKET: R2BucketLike;
  DEVICE_ID: string;
  TRUSTED_KEYS_JSON: string;
  RESPONSE_KEY_ID: string;
  RESPONSE_SEED_B64: string;
  TUNNEL_URL: string;
  TUNNEL_TOKEN: string;
}

/** R2-backed VaultBackend using native conditional writes. */
class R2VaultBackend implements VaultBackend {
  constructor(private bucket: R2BucketLike) {}
  async get(key: string) {
    const obj = await this.bucket.get(key);
    return obj === null ? null : { body: await obj.text(), nativeEtag: obj.etag };
  }
  async putIf(key: string, body: string, expectNativeEtag: string | null) {
    const onlyIf = expectNativeEtag === null
      ? { etagDoesNotMatch: "*" }
      : { etagMatches: expectNativeEtag };
    const obj = await this.bucket.put(key, body, { onlyIf });
    return obj === null ? null : { nativeEtag: obj.etag };
  }
  async createNonce(key: string): Promise<boolean> {
    // 24h lifecycle objects; conditional create makes replays impossible.
    const obj = await this.bucket.put(`nonce:${key}`, "1", { onlyIf: { etagDoesNotMatch: "*" } });
    return obj !== null;
  }
}

function deps(env: Env): VaultDeps {
  return {
    backend: env.VAULT_BUCKET ? new R2VaultBackend(env.VAULT_BUCKET) : new MemoryVaultBackend(),
    trusted: JSON.parse(env.TRUSTED_KEYS_JSON) as VaultDeps["trusted"],
    now: () => Date.now(),
    responseKey: {
      keyId: env.RESPONSE_KEY_ID,
      seed: Uint8Array.from(atob(env.RESPONSE_SEED_B64), (c) => c.charCodeAt(0)),
    },
    deviceId: env.DEVICE_ID,
  };
}

function send(r: { status: number; body: Buffer; responseProof: string; etag?: string }): InstanceType<typeof Response> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-ghost-response-proof": r.responseProof,
    "cache-control": "no-store",
  };
  if (r.etag) headers["etag"] = r.etag;
  return new Response(new Uint8Array(r.body).buffer as ArrayBuffer, { status: r.status, headers });
}

const PATH_RE = /^\/v1\/(devices\/(gd_[0-9a-z]+)\/rpc|vault\/(gs_[0-9a-z]+)|health)$/;

export default {
  async fetch(request: CfRequestLike, env: Env): Promise<InstanceType<typeof Response>> {
    const d = deps(env);
    const url = new URL(request.url);
    const m = PATH_RE.exec(url.pathname);
    try {
      if (!m) throw new VaultHttpError(404, "NOT_FOUND");
      if (m[3]) {
        if (request.method === "GET") return send(await handleVaultGet(d, m[3], request.headers.get("x-ghost-proof")));
        if (request.method === "PUT") {
          const raw = Buffer.from(await request.arrayBuffer());
          return send(await handleVaultPut(d, m[3], raw, {
            proof: request.headers.get("x-ghost-proof"),
            ifMatch: request.headers.get("if-match"),
            ifNoneMatch: request.headers.get("if-none-match"),
          }));
        }
        throw new VaultHttpError(404, "NOT_FOUND");
      }
      if (m[1] === "health") {
        if (request.method !== "GET") throw new VaultHttpError(404, "NOT_FOUND");
        return send(await handleHealth(d, request.headers.get("x-ghost-proof")));
      }
      // POST /v1/devices/D/rpc — relay over the private outbound tunnel.
      if (request.method !== "POST" || m[2] !== env.DEVICE_ID) {
        throw new VaultHttpError(404, "NOT_FOUND");
      }
      const raw = Buffer.from(await request.arrayBuffer());
      const proof = request.headers.get("x-ghost-proof");
      if (proof === null) throw new VaultHttpError(401, "UNAUTHORIZED");
      const upstream = await fetch(env.TUNNEL_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-ghost-proof": proof,
          "x-ghost-relay": env.TUNNEL_TOKEN,
        },
        body: new Uint8Array(raw).buffer as ArrayBuffer,
      });
      const body = Buffer.from(await upstream.arrayBuffer());
      const respProof = upstream.headers.get("x-ghost-response-proof") ?? "";
      return new Response(new Uint8Array(body).buffer as ArrayBuffer, {
        status: upstream.status,
        headers: {
          "content-type": "application/json",
          ...(respProof ? { "x-ghost-response-proof": respProof } : {}),
        },
      }) as InstanceType<typeof Response>;
    } catch (e) {
      return send(errorResult(d, e, null));
    }
  },
};

void b64Encode;
