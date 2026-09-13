/**
 * Hosted vault client — HTTPS transport for GET/PUT /v1/vault/{session}
 * against the Workers relay. Local mode uses no transport.
 */

import { request as httpsRequest } from "node:https";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { b64Encode } from "./encoding/b64.js";
import type { VaultHead } from "./schema.js";
import type { VaultTransport, VaultHeadResult } from "./engine.js";

export class HttpsVaultTransport implements VaultTransport {
  constructor(private baseUrl: string, private timeoutMs = 15_000) {}

  private req(method: "GET" | "PUT", path: string, body: Buffer | null, headers: Record<string, string>): Promise<VaultHeadResult> {
    const url = new URL(`${this.baseUrl}${path}`);
    return new Promise((resolve, reject) => {
      const r = httpsRequest({
        hostname: url.hostname, port: url.port || 443, path: url.pathname, method,
        headers: { "content-type": "application/json", ...(body ? { "content-length": body.length } : {}), ...headers },
        timeout: this.timeoutMs,
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks);
          let parsed: unknown = null;
          try { parsed = parseStrictJson(raw); } catch { /* opaque */ }
          resolve({
            status: res.statusCode ?? 0,
            body: parsed,
            etag: typeof res.headers.etag === "string" ? res.headers.etag : null,
            headers: res.headers as Record<string, string>,
          });
        });
      });
      r.on("timeout", () => { r.destroy(); reject(new Error("timeout")); });
      r.on("error", reject);
      if (body) r.end(body); else r.end();
    });
  }

  async get(sessionId: string, proof: unknown): Promise<VaultHeadResult> {
    return this.req("GET", `/v1/vault/${sessionId}`, null, {
      "x-ghost-proof": b64Encode(Buffer.from(jcsString(proof), "utf8")),
    });
  }

  async put(sessionId: string, head: VaultHead, cond: { ifMatch: string | null; ifNoneMatch: "*" | null }, proof: unknown): Promise<VaultHeadResult> {
    const headers: Record<string, string> = {
      "x-ghost-proof": b64Encode(Buffer.from(jcsString(proof), "utf8")),
    };
    if (cond.ifMatch) headers["if-match"] = cond.ifMatch;
    if (cond.ifNoneMatch) headers["if-none-match"] = cond.ifNoneMatch;
    return this.req("PUT", `/v1/vault/${sessionId}`, jcsBytes({ head }), headers);
  }
}
