/**
 * Daemon lifecycle: private runtime dirs, process lock, HTTP/1.1 over unix
 * sockets (owner + driver), optional relay listener, graceful shutdown.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { chmodSync, mkdirSync, openSync, closeSync, readFileSync, rmSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { RpcError } from "./errors.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { sha256Hex, jcsHash, domainMessage } from "./crypto/envelope.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import { b64Decode, b64Encode } from "./encoding/b64.js";
import {
  vForwardFrame, vRequestProof, type ForwardFrame, type RequestProof,
} from "./schema.js";
import { Dispatcher, failBody, MAX_PROOF_BYTES, type Caller, type DispatchResult, type TrustedKey } from "./rpc.js";
import type { Engine } from "./engine.js";
import type { Store } from "./store/database.js";
import type { DaemonConfig } from "./schema.js";

const MAX_BODY = 256 * 1024 + 64;

export interface DaemonPaths {
  dataDir: string;
  runtimeDir: string;
}

export function ensurePrivateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

/** O_EXCL lock file carrying the daemon pid; stale locks are reclaimed. */
export function acquireLock(runtimeDir: string): { release(): void } {
  const lockPath = join(runtimeDir, "daemon.lock");
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      writeFileSync(fd, String(process.pid), { mode: 0o600 });
      closeSync(fd);
      let released = false;
      return {
        release() {
          if (released) return;
          released = true;
          try {
            unlinkSync(lockPath);
          } catch { /* already gone */ }
        },
      };
    } catch {
      // Held by someone — check staleness.
      try {
        const pid = Number(readFileSync(lockPath, "utf8").trim());
        if (Number.isInteger(pid) && pid > 0) {
          try {
            process.kill(pid, 0);
            throw new RpcError("BUSY");
          } catch (ke) {
            if (ke instanceof RpcError) throw ke;
            // ESRCH → stale lock; reclaim.
            rmSync(lockPath, { force: true });
            continue;
          }
        }
        rmSync(lockPath, { force: true });
      } catch (e) {
        if (e instanceof RpcError) throw e;
        throw new RpcError("BUSY");
      }
    }
  }
  throw new RpcError("BUSY");
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY) {
        reject(new RpcError("BODY_TOO_LARGE"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function send(res: ServerResponse, out: DispatchResult): void {
  res.statusCode = out.status;
  res.setHeader("content-type", "application/json");
  if (out.responseProof) {
    res.setHeader("x-ghost-response-proof", b64Encode(out.responseProof));
  }
  res.end(out.body);
}

function sendErr(res: ServerResponse, status: number, code: import("./errors.js").ErrorCode): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(failBody(null, new RpcError(code)));
}

export class Daemon {
  readonly engine: Engine;
  readonly dispatcher: Dispatcher;
  readonly config: DaemonConfig;
  private ownerSrv: Server | null = null;
  private driverSrv: Server | null = null;
  private relaySrv: Server | null = null;
  private lock: { release(): void } | null = null;
  private tickTimer: NodeJS.Timeout | null = null;
  private outboxTimer: NodeJS.Timeout | null = null;
  private shuttingDown = false;

  constructor(engine: Engine, dispatcher: Dispatcher, config: DaemonConfig) {
    this.engine = engine;
    this.dispatcher = dispatcher;
    this.config = config;
  }

  ownerSocketPath(): string {
    return join(this.config.runtime_dir, "owner.sock");
  }

  driverSocketPath(): string {
    return join(this.config.runtime_dir, "driver.sock");
  }

  /** Bind sockets, acquire the lock, recover durable state. */
  async start(): Promise<void> {
    ensurePrivateDir(this.config.data_dir);
    ensurePrivateDir(this.config.runtime_dir);
    this.lock = acquireLock(this.config.runtime_dir);
    // Startup debris resolution before serving.
    this.engine.recoverDaemon();
    // Clear stale in-flight request markers from a previous crash.
    this.engine.store.run("DELETE FROM requests WHERE state='PENDING'");

    for (const p of [this.ownerSocketPath(), this.driverSocketPath()]) {
      try {
        unlinkSync(p);
      } catch { /* absent */ }
    }

    this.ownerSrv = createServer((req, res) => this.handleLocal(req, res, "owner"));
    this.driverSrv = createServer((req, res) => this.handleLocal(req, res, "driver"));
    await Promise.all([
      this.listen(this.ownerSrv, this.ownerSocketPath()),
      this.listen(this.driverSrv, this.driverSocketPath()),
    ]);
    // Socket files are owner-only; same-UID peers are outside the OS boundary.
    chmodSync(this.ownerSocketPath(), 0o600);
    chmodSync(this.driverSocketPath(), 0o600);

    if (this.config.relay.enabled) {
      const [host, portStr] = this.config.relay.listen.split(":");
      this.relaySrv = createServer((req, res) => this.handleRelay(req, res));
      await new Promise<void>((resolve, reject) => {
        this.relaySrv!.once("error", reject);
        this.relaySrv!.listen(Number(portStr), host, resolve);
      });
    }

    this.tickTimer = setInterval(() => {
      try {
        this.engine.tick();
      } catch { /* gate failures surface via status */ }
    }, 1_000);
    this.tickTimer.unref();
    this.outboxTimer = setInterval(() => {
      void this.engine.flushOutbox().catch(() => {});
    }, 2_000);
    this.outboxTimer.unref();
  }

  private listen(srv: Server, path: string): Promise<void> {
    return new Promise((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(path, resolve);
    });
  }

  private async handleLocal(req: IncomingMessage, res: ServerResponse, socket: "owner" | "driver"): Promise<void> {
    if (req.method !== "POST" || req.url !== "/v1/rpc") {
      sendErr(res, 404, "NOT_FOUND");
      return;
    }
    let body: Buffer;
    try {
      body = await readBody(req);
    } catch (e) {
      sendErr(res, e instanceof RpcError ? 413 : 400, e instanceof RpcError ? e.code : "INVALID_SCHEMA");
      return;
    }
    try {
      const out = await this.dispatcher.local(body, socket);
      send(res, out);
    } catch {
      sendErr(res, 500, "INTERNAL");
    }
  }

  private async handleRelay(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // The relay listener accepts no browser traffic.
    const origin = req.headers.origin;
    if (origin !== undefined) {
      sendErr(res, 403, "FORBIDDEN");
      return;
    }
    if (req.method !== "POST" || req.url !== "/internal/v1/rpc") {
      sendErr(res, 404, "NOT_FOUND");
      return;
    }
    let body: Buffer;
    try {
      body = await readBody(req);
    } catch {
      sendErr(res, 413, "BODY_TOO_LARGE");
      return;
    }
    try {
      const out = await this.dispatchForward(body);
      send(res, out);
    } catch (e) {
      const err = e instanceof RpcError ? e : new RpcError("INTERNAL");
      res.statusCode = err.code === "UNAUTHORIZED" || err.code === "REPLAY" ? 401 : 400;
      res.setHeader("content-type", "application/json");
      res.end(failBody(null, err));
    }
  }

  /** ForwardFrame: dual-proof verification per §8.3. */
  private async dispatchForward(raw: Buffer): Promise<DispatchResult> {
    if (raw.length > MAX_BODY) throw new RpcError("BODY_TOO_LARGE");
    let frame: ForwardFrame;
    try {
      frame = vForwardFrame(parseStrictJson(raw), "frame");
    } catch {
      throw new RpcError("INVALID_SCHEMA");
    }
    const now = Date.now();
    const deviceId = this.engine.device.deviceId;
    const path = `/v1/devices/${deviceId}/rpc`;

    const verify = (p: RequestProof, purpose: "request" | "relay"): TrustedKey => {
      const c = p.core;
      const key = this.dispatcher.trustedKey(c.key_id);
      if (!key || key.purpose !== purpose || key.actor_id !== c.actor_id) {
        throw new RpcError("UNAUTHORIZED");
      }
      if (c.device_id !== deviceId || c.path !== path || c.method !== "POST") {
        throw new RpcError("UNAUTHORIZED");
      }
      if (c.if_match !== null || c.if_none_match !== null) throw new RpcError("UNAUTHORIZED");
      if (c.expires_ms - c.issued_ms !== 60_000) throw new RpcError("UNAUTHORIZED");
      if (Math.abs(now - c.issued_ms) > 60_000 || now >= c.expires_ms) throw new RpcError("UNAUTHORIZED");
      if (c.body_hash !== sha256Hex(jcsBytes(frame.request))) throw new RpcError("UNAUTHORIZED");
      const ok = ed25519Verify(
        b64Decode(key.public_key), domainMessage("request", jcsHash(c)), b64Decode(p.signature),
      );
      if (!ok) throw new RpcError("UNAUTHORIZED");
      return key;
    };

    const callerKey = this.engine.store.txn(() => {
      const callerKey = verify(frame.proof, "request");
      verify(frame.relay, "relay");
      const relayKeyId = this.config.relay.relay_key_id;
      if (frame.relay.core.key_id !== relayKeyId) throw new RpcError("UNAUTHORIZED");
      for (const [p, purpose] of [[frame.proof, "request"], [frame.relay, "relay"]] as const) {
        const ok = this.engine.store.nonceAccept(
          p.core.actor_id, `${p.core.key_id}:${purpose}`, p.core.nonce, now, 120_000,
        );
        if (!ok) throw new RpcError("REPLAY");
      }
      return callerKey;
    });

    const caller: Caller = {
      actorId: frame.proof.core.actor_id,
      owner: false,
      sessions: new Set(callerKey.sessions),
    };
    // Reuse the proven dispatch path with the caller context and proof core.
    const inner = jcsBytes(frame.request);
    const out = await this.dispatcher.dispatchWithCaller(inner, caller);
    if (out.responseProof === null) {
      out.responseProof = this.dispatcher.signResponseProof(frame.proof.core, out.status, out.body);
    }
    return out;
  }

  async stop(): Promise<void> {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    if (this.tickTimer) clearInterval(this.tickTimer);
    if (this.outboxTimer) clearInterval(this.outboxTimer);
    await this.engine.shutdown();
    for (const srv of [this.ownerSrv, this.driverSrv, this.relaySrv]) {
      if (srv) await new Promise<void>((r) => srv.close(() => r()));
    }
    for (const p of [this.ownerSocketPath(), this.driverSocketPath()]) {
      try {
        unlinkSync(p);
      } catch { /* absent */ }
    }
    this.lock?.release();
  }
}
