/**
 * GhostSession session engine — the reducer over the §5 transition table.
 *
 * One reducer per session; guards, event append, revision, nonce acceptance
 * and result cache commit inside a single SQLite transaction. Browser work
 * runs outside that transaction but holds the action slot and rechecks
 * fence/policy immediately before dispatch.
 */

import { RpcError } from "./errors.js";
import { newId, type IdPrefix } from "./ids.js";
import { jcsBytes } from "./encoding/jcs.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { sha256Hex, jcsHash, signEnvelope, domainMessage } from "./crypto/envelope.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import { b64Encode, b64Decode } from "./encoding/b64.js";
import { freshNonce } from "./crypto/aes.js";
import { AuditLog, actionBinding } from "./audit.js";
import { classify, isRetryableBlock, isFallbackEligible, probeVerified } from "./classify.js";
import { computeDelay } from "./delay.js";
import { validateSignedPolicy, validatePolicyCore, HANDOFF_TTL_MS } from "./policy.js";
import { checkEgress } from "./browser/egress.js";
import { observationFromResponse, observationFromProbe } from "./browser/observe.js";
import {
  buildSnapshotPlain, cipherHash, decryptSnapshot, encryptSnapshot, liveCookies, validateCapture,
} from "./browser/capture.js";
import type {
  ActionResult, AuditPage, Block, BlockClass, BrowserAction, CipherSnapshot, Handoff,
  Lease, Observation, OriginBudget, PolicyCore, Receipt, SessionControl, SessionState,
  SessionView, SignedPolicy, SnapshotPlain, VaultHead,
} from "./schema.js";
import {
  vCipherSnapshot, vHandoff, vSessionControl, vSessionView, vSnapshotPlain,
} from "./schema.js";
import type { Store } from "./store/database.js";
import type { Keychain } from "./store/keychain.js";
import type {
  BrowserAdapter, BrowserContextHandle, ContextPurpose, DispatchOutcome,
} from "./browser/types.js";
import type { OriginOptions } from "./net/origin.js";

// ------------------------------------------------------------------ clocks

export interface Clock {
  wall(): number;
  mono(): number;
}

export const systemClock: Clock = { wall: () => Date.now(), mono: () => Date.now() };

export class TestClock implements Clock {
  t: number;
  constructor(start = 1_800_000_000_000) {
    this.t = start;
  }
  wall(): number {
    return this.t;
  }
  mono(): number {
    return this.t;
  }
  advance(ms: number): void {
    this.t += ms;
  }
}

export interface DeviceIdentity {
  deviceId: string;
  ownerId: string;
  signingKeyId: string;
  signingSeed: Buffer;
  signingPub: Buffer;
  auditKey: Buffer;
  cacheKey: Buffer;
  /** Current per-session encryption key ids live under this key's namespace. */
  requestKeyId: string | null;
  requestSeed: Buffer | null;
}

export interface VaultHeadResult {
  status: number;
  body: unknown;
  etag: string | null;
  headers?: Record<string, string>;
}

export interface VaultTransport {
  get(sessionId: string, proof: unknown): Promise<VaultHeadResult>;
  put(sessionId: string, head: VaultHead, cond: { ifMatch: string | null; ifNoneMatch: "*" | null }, proof: unknown): Promise<VaultHeadResult>;
}

export interface InboxAdapter {
  deliver(card: unknown): Promise<{ external_id: string; status: "delivered" | "duplicate" }>;
}

export interface EngineHooks {
  /** Test seam: invoked after action.intent commits, before dispatch recheck. */
  afterActionIntent?: (sessionId: string, operationId: string) => Promise<void> | void;
  /** Test seam: invoked before an adapter dispatch resolves. */
  beforeDispatchResolve?: (sessionId: string) => Promise<void> | void;
}

export interface EngineDeps {
  store: Store;
  keychain: Keychain;
  adapter: BrowserAdapter;
  clock: Clock;
  device: DeviceIdentity;
  vaultMode: "local" | "hosted";
  vaultTransport?: VaultTransport | null;
  inboxAdapter?: InboxAdapter | null;
  originOpts: OriginOptions;
  hooks?: EngineHooks;
  ids?: (prefix: IdPrefix) => string;
  /** Test seam: restrict "new session per site" / consent checks off? never in prod. */
}

// ------------------------------------------------------------------ types

interface Sess {
  id: string;
  siteId: string;
  state: SessionState;
  revision: number;
  generation: number;
  fence: number;
  lease: Lease | null;
  block: Block | null;
  handoffId: string | null;
  expiresMs: number | null;
  control: SessionControl;
  snapshotEligible: boolean;
}

interface SiteRow {
  id: string;
  revision: number;
  policy: SignedPolicy;
}

const LIVE: SessionState[] = [
  "NEEDS_LOGIN", "DETACHED", "ATTACHING", "ACTIVE", "COOLDOWN",
  "RECOVERABLE", "HANDOFF_WAIT", "VERIFYING", "UNCERTAIN", "EXPIRED",
];
const TERMINAL: SessionState[] = ["REVOKED", "DELETED", "QUARANTINED"];
const CONTEXT_STATES: SessionState[] = ["ATTACHING", "ACTIVE", "VERIFYING"];

const LEASE_MS = 45_000;
const STEP_WINDOW_MS = 1_000;
const STEP_MAX = 2;
const REMOTE_WINDOW_MS = 60_000;
const REMOTE_MAX = 60;
const PROBE_WINDOW_MS = 600_000;
const PROBE_MAX = 2;
const HANDOFF_WINDOW_MS = 86_400_000;
const HANDOFF_MAX = 2;
const DEDUP_MS = 86_400_000;
const BLOCK_FREE_RESET_MS = 600_000;
const AUDIT_BYTES_LIMIT = 512 * 1024 * 1024;
const OUTBOX_CAP = 1000;
const CLOCK_REGRESSION_MS = 5_000;

function emptyControl(): SessionControl {
  return { verification: null, active_operation: null, dispatched: false, unresolved_operations: [] };
}

function emptyBudget(): OriginBudget {
  return {
    probe_starts_ms: [], handoff_starts_ms: [], last_block_ms: null,
    next_allowed_ms: 0, attempts: 0, fallback_used: false, manual_review: false,
  };
}

// ------------------------------------------------------------------ engine

export class Engine {
  readonly store: Store;
  readonly keychain: Keychain;
  readonly adapter: BrowserAdapter;
  readonly clock: Clock;
  readonly device: DeviceIdentity;
  readonly originOpts: OriginOptions;
  private readonly audit: AuditLog;
  private readonly idgen: (p: IdPrefix) => string;
  private readonly hooks: EngineHooks;
  private vaultMode: "local" | "hosted";
  private vaultTransport: VaultTransport | null;
  private inboxAdapter: InboxAdapter | null;
  private contexts = new Map<string, BrowserContextHandle>();
  /** In-flight human-context opens keyed by session (verify must await them). */
  private handoffOpenTasks = new Map<string, Promise<void>>();
  private pending: Promise<void>[] = [];
  /** Daemon-wide gates. */
  clockUnsafe = false;
  auditGateClosed = false;
  shuttingDown = false;

  constructor(deps: EngineDeps) {
    this.store = deps.store;
    this.keychain = deps.keychain;
    this.adapter = deps.adapter;
    this.clock = deps.clock;
    this.device = deps.device;
    this.originOpts = deps.originOpts;
    this.vaultMode = deps.vaultMode;
    this.vaultTransport = deps.vaultTransport ?? null;
    this.inboxAdapter = deps.inboxAdapter ?? null;
    this.hooks = deps.hooks ?? {};
    this.idgen = deps.ids ?? ((p) => newId(p));
    this.audit = new AuditLog(this.store, deps.device.signingKeyId, deps.device.signingSeed);
    this.initClockGate();
  }

  // ------------------------------------------------------------- utilities

  private now(): number {
    const last = Number((this.store.getMeta("last_wall_ms") ?? Buffer.from("0")).toString());
    return Math.max(this.clock.wall(), last);
  }

  private touchWall(): void {
    const w = this.clock.wall();
    const last = Number((this.store.getMeta("last_wall_ms") ?? Buffer.from("0")).toString());
    if (w > last) this.store.setMeta("last_wall_ms", Buffer.from(String(w)));
  }

  private initClockGate(): void {
    const last = this.store.getMeta("last_wall_ms");
    if (last !== null) {
      const prev = Number(last.toString());
      if (this.clock.wall() + CLOCK_REGRESSION_MS < prev) this.clockUnsafe = true;
    }
  }

  private id(p: IdPrefix): string {
    return this.idgen(p);
  }

  private gateOk(): void {
    if (this.clockUnsafe) throw new RpcError("CLOCK_UNSAFE");
    if (this.auditGateClosed) throw new RpcError("AUDIT_UNAVAILABLE");
    if (this.shuttingDown) throw new RpcError("BUSY");
  }

  /** Session ids touched by the in-flight transaction (for tip pinning). */
  private txSids = new Set<string>();

  /** Commit + pin the audit tip; pin failure closes the effect gate. */
  private commitAndPin<T>(sessionIds: string[], fn: () => T): T {
    void sessionIds;
    let out: T;
    this.txSids.clear();
    try {
      out = this.store.txn(fn);
    } catch (e) {
      this.txSids.clear();
      if (e instanceof RpcError) throw e;
      this.auditGateClosed = true;
      throw new RpcError("AUDIT_UNAVAILABLE");
    }
    try {
      for (const sid of this.txSids) {
        const tip = this.audit.tip(sid);
        this.keychain.set(
          `ghostsession/audit-tip/${sid}`,
          Buffer.from(JSON.stringify({ seq: tip.seq, hash: tip.hash })),
        );
      }
    } catch {
      this.auditGateClosed = true;
      throw new RpcError("AUDIT_UNAVAILABLE");
    } finally {
      this.txSids.clear();
    }
    return out;
  }

  // ----------------------------------------------------------- row access

  private loadSession(id: string): Sess | null {
    const r = this.store.get("SELECT * FROM sessions WHERE id = ?", id);
    if (!r) return null;
    const view = JSON.parse(Buffer.from(r.view_json as Uint8Array).toString("utf8")) as {
      lease: Lease | null; block: Block | null; handoff_id: string | null; expires_ms: number | null;
    };
    return {
      id: r.id as string,
      siteId: r.site_id as string,
      state: r.state as SessionState,
      revision: r.revision as number,
      generation: r.generation as number,
      fence: r.fence as number,
      lease: view.lease,
      block: view.block,
      handoffId: view.handoff_id,
      expiresMs: view.expires_ms,
      control: vSessionControl(JSON.parse(Buffer.from(r.control_json as Uint8Array).toString("utf8")), "control"),
      snapshotEligible: (r.snapshot_eligible as number) === 1,
    };
  }

  private saveSession(s: Sess): void {
    this.store.run(
      "UPDATE sessions SET state=?, revision=?, generation=?, fence=?, view_json=?, control_json=?, snapshot_eligible=? WHERE id=?",
      s.state, s.revision, s.generation, s.fence,
      jcsBytes({ lease: s.lease, block: s.block, handoff_id: s.handoffId, expires_ms: s.expiresMs }),
      jcsBytes(s.control),
      s.snapshotEligible ? 1 : 0,
      s.id,
    );
  }

  private loadSite(id: string): SiteRow | null {
    const r = this.store.get("SELECT * FROM sites WHERE id = ?", id);
    if (!r) return null;
    return {
      id: r.id as string,
      revision: r.revision as number,
      policy: JSON.parse(Buffer.from(r.signed_policy as Uint8Array).toString("utf8")) as SignedPolicy,
    };
  }

  private sessionView(s: Sess): SessionView {
    const site = this.loadSite(s.siteId);
    return {
      session_id: s.id,
      site_id: s.siteId,
      device_id: this.device.deviceId,
      state: s.state,
      revision: s.revision,
      generation: s.generation,
      policy_hash: site?.policy.hash ?? "0".repeat(64),
      lease: s.lease,
      block: s.block,
      handoff_id: s.handoffId,
      expires_ms: s.expiresMs,
      audit_seq: this.audit.tip(s.id).seq,
    };
  }

  private loadBudget(ownerId: string, origin: string): OriginBudget {
    const r = this.store.get(
      "SELECT state_json FROM origin_budgets WHERE owner_id = ? AND origin = ?",
      ownerId, origin,
    );
    if (!r) return emptyBudget();
    return JSON.parse(Buffer.from(r.state_json as Uint8Array).toString("utf8")) as OriginBudget;
  }

  private saveBudget(ownerId: string, origin: string, b: OriginBudget): void {
    b.probe_starts_ms = b.probe_starts_ms.filter((t) => t >= this.now() - PROBE_WINDOW_MS).sort((a, z) => a - z);
    b.handoff_starts_ms = b.handoff_starts_ms.filter((t) => t >= this.now() - HANDOFF_WINDOW_MS).sort((a, z) => a - z);
    this.store.run(
      "INSERT INTO origin_budgets(owner_id,origin,state_json) VALUES(?,?,?) ON CONFLICT(owner_id,origin) DO UPDATE SET state_json=excluded.state_json",
      ownerId, origin, jcsBytes(b),
    );
  }

  private loadCard(id: string): Handoff | null {
    const r = this.store.get("SELECT card_json FROM handoffs WHERE id = ?", id);
    if (!r) return null;
    return JSON.parse(Buffer.from(r.card_json as Uint8Array).toString("utf8")) as Handoff;
  }

  private cardForSession(sessionId: string): Handoff | null {
    const r = this.store.get(
      "SELECT card_json FROM handoffs WHERE session_id = ? ORDER BY rowid DESC LIMIT 1",
      sessionId,
    );
    if (!r) return null;
    return JSON.parse(Buffer.from(r.card_json as Uint8Array).toString("utf8")) as Handoff;
  }

  private saveCard(c: Handoff): void {
    this.store.run(
      "INSERT INTO handoffs(id,session_id,card_json) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET card_json=excluded.card_json",
      c.handoff_id, c.session_id, jcsBytes(c),
    );
  }

  private encKeyFor(sessionId: string): { keyId: string; key: Buffer } {
    const metaKey = `enckey:${sessionId}`;
    const existing = this.store.getMeta(metaKey);
    if (existing !== null) {
      const keyId = existing.toString();
      const key = this.keychain.get(`ghostsession/encryption/${keyId}`);
      if (key === null) throw new RpcError("KEY_UNAVAILABLE");
      return { keyId, key };
    }
    const keyId = this.id("ge");
    const key = freshKey();
    this.keychain.set(`ghostsession/encryption/${keyId}`, key);
    this.store.setMeta(metaKey, Buffer.from(keyId));
    return { keyId, key };
  }

  private snapshotRow(sessionId: string): { generation: number; keyId: string; cipher: CipherSnapshot; cipherHash: string } | null {
    const r = this.store.get("SELECT * FROM snapshots WHERE session_id = ?", sessionId);
    if (!r) return null;
    return {
      generation: r.generation as number,
      keyId: r.key_id as string,
      cipher: vCipherSnapshot(parseStrictJson(Buffer.from(r.cipher_json as Uint8Array)), "cipher"),
      cipherHash: r.cipher_hash as string,
    };
  }

  private eligibleSnapshot(s: Sess): boolean {
    if (!s.snapshotEligible) return false;
    const snap = this.snapshotRow(s.id);
    if (!snap || snap.generation !== s.generation) return false;
    return this.now() < s.expiresMs!;
  }

  private auditHashAt(sessionId: string, seq: number): string | null {
    const r = this.store.get("SELECT hash FROM receipts WHERE session_id = ? AND seq = ?", sessionId, seq);
    return r ? (r.hash as string) : null;
  }

  private lastIncidentEvent(s: Sess): string | null {
    const rows = this.store.all(
      "SELECT receipt_json FROM receipts WHERE session_id = ? ORDER BY seq DESC LIMIT 50",
      s.id,
    );
    for (const row of rows) {
      const ev = (JSON.parse(Buffer.from(row.receipt_json as Uint8Array).toString("utf8")) as Receipt).core.event;
      if (ev === "block.detected" || ev === "cooldown.elapsed" || ev === "recovery.exhausted") return ev;
      if (ev === "session.created" || ev === "policy.changed" || ev === "session.revoked" || ev === "session.deleted" || ev === "unknown.acknowledged") return null;
    }
    return null;
  }

  // ------------------------------------------------------------- emit core

  private emit(
    s: Sess,
    spec: {
      event: import("./schema.js").EventName;
      to?: SessionState;
      code?: "OK" | import("./errors.js").ErrorCode;
      operationId?: string | null;
      actionBinding_?: string | null;
      cipherHash?: string | null;
      blockClass?: BlockClass;
      generation?: number;
      actorId?: string;
    },
  ): Receipt {
    const from = s.state;
    const to = spec.to ?? s.state;
    s.revision += 1;
    if (spec.generation !== undefined) s.generation = spec.generation;
    const receipt = this.audit.append({
      receipt_id: this.id("gv"),
      recorded_ms: this.now(),
      session_id: s.id,
      actor_id: spec.actorId ?? this.device.ownerId,
      operation_id: spec.operationId ?? null,
      event: spec.event,
      from_state: from,
      to_state: to,
      revision: s.revision,
      generation: s.generation,
      fence: s.fence,
      code: spec.code ?? "OK",
      action_binding: spec.actionBinding_ ?? null,
      cipher_hash: spec.cipherHash ?? null,
      block_class: spec.blockClass ?? "NONE",
    });
    s.state = to;
    this.touchWall();
    this.txSids.add(s.id);
    return receipt;
  }

  /** Leave-with-context effects: invalidate lease, bump fence, drop block. */
  private leaveContext(s: Sess): void {
    if (s.lease) {
      // The fence only advances when a live lease is invalidated; unleased
      // VERIFYING exits (handoff/recovery) keep the counter (fixture audit7).
      s.lease = null;
      s.fence += 1;
    }
    s.control.verification = null;
    const ctx = this.contexts.get(s.id);
    if (ctx) {
      this.contexts.delete(s.id);
      void this.adapter.destroy(ctx).catch(() => {});
    }
  }

  /** Apply the block column rules for a committed event. */
  private applyEventEffects(s: Sess, event: string): void {
    if (
      event === "attach.verified" || event === "handoff.completed" || event === "policy.changed" ||
      event === "session.expired" || event === "session.revoked" || event === "session.deleted"
    ) {
      s.block = null;
    }
    if (event === "handoff.completed" || event === "handoff.cancelled" || event === "handoff.expired") {
      s.handoffId = null;
    }
    if (
      event === "block.detected" && s.block &&
      (s.block.class === "LOGIN_WALL" || s.block.class === "ACCOUNT_MISMATCH")
    ) {
      s.snapshotEligible = false;
    }
    if (
      event === "policy.changed" || event === "session.expired" ||
      event === "handoff.cancelled" || event === "handoff.expired" || event === "action.unknown"
    ) {
      s.snapshotEligible = false;
    }
    if (event === "snapshot.committed") s.snapshotEligible = true;
  }

  /** Full event commit: emit + effects + save + context cleanup. */
  private commitEvent(s: Sess, spec: Parameters<Engine["emit"]>[1]): Receipt {
    const wasCtx = CONTEXT_STATES.includes(s.state);
    const receipt = this.emit(s, spec);
    this.applyEventEffects(s, spec.event);
    const isCtx = CONTEXT_STATES.includes(s.state);
    if (wasCtx && !isCtx) {
      // Every row leaving ACTIVE/ATTACHING/VERIFYING invalidates the lease,
      // bumps the fence and destroys the context — except attach.verified's
      // ATTACHING→ACTIVE which retains both.
      this.leaveContext(s);
    }
    this.saveSession(s);
    return receipt;
  }

  // --------------------------------------------------------------- helpers

  private checkRate(subject: string, kind: string, windowMs: number, max: number): void {
    const now = this.now();
    const row = this.store.get("SELECT stamps_json FROM rate_limits WHERE subject=? AND kind=?", subject, kind);
    let stamps: number[] = row
      ? (JSON.parse(Buffer.from(row.stamps_json as Uint8Array).toString("utf8")) as number[])
      : [];
    stamps = stamps.filter((t) => t >= now - windowMs);
    if (stamps.length >= max) {
      throw new RpcError("RATE_LIMITED", { retryAtMs: stamps[0]! + windowMs });
    }
    stamps.push(now);
    this.store.run(
      "INSERT INTO rate_limits(subject,kind,stamps_json) VALUES(?,?,?) ON CONFLICT(subject,kind) DO UPDATE SET stamps_json=excluded.stamps_json",
      subject, kind, jcsBytes(stamps),
    );
  }

  private checkAuditPressure(s: Sess): void {
    if (this.audit.sizeBytes(s.id) >= AUDIT_BYTES_LIMIT) {
      throw new RpcError("AUDIT_UNAVAILABLE");
    }
  }

  /** Timers materialized before validation: deterministic in tests, periodic in prod. */
  tick(): void {
    const now = this.now();
    try {
      this.store.txn(() => {
      this.touchWall();
      const rows = this.store.all("SELECT id FROM sessions");
      for (const r of rows) {
        const s = this.loadSession(r.id as string);
        if (!s) continue;
        if ((s.state === "ATTACHING" || s.state === "ACTIVE") && s.lease && now >= s.lease.expires_ms) {
          if (s.control.dispatched && s.control.active_operation) {
            const op = s.control.active_operation;
            this.markOperationUnknown(s, op);
            s.control.unresolved_operations.push(op);
            s.control.active_operation = null;
            s.control.dispatched = false;
            this.commitEvent(s, { event: "action.unknown", to: "UNCERTAIN", operationId: op });
          } else {
            this.commitEvent(s, { event: "lease.expired", to: "DETACHED" });
          }
          continue;
        }
        if (s.state === "COOLDOWN" && s.block?.retry_at_ms !== null && s.block && now >= s.block.retry_at_ms!) {
          this.commitEvent(s, { event: "cooldown.elapsed", to: "RECOVERABLE" });
          continue;
        }
        if (s.state === "HANDOFF_WAIT" || (s.state === "VERIFYING" && s.control.verification === "handoff")) {
          const card = s.handoffId ? this.loadCard(s.handoffId) : null;
          if (card && now >= card.expires_ms) {
            card.state = "EXPIRED";
            card.session_revision = s.revision + 1;
            this.saveCard(card);
            this.commitEvent(s, { event: "handoff.expired", to: "NEEDS_LOGIN" });
            continue;
          }
        }
        if (s.state !== "UNCERTAIN" && LIVE.includes(s.state)) {
          const site = this.loadSite(s.siteId);
          if (site && now >= site.policy.core.consent_expires_ms) {
            this.commitEvent(s, { event: "session.expired", to: "EXPIRED" });
            continue;
          }
          if (s.snapshotEligible && s.expiresMs !== null && now >= s.expiresMs) {
            this.commitEvent(s, { event: "session.expired", to: "EXPIRED" });
            continue;
          }
        }
        if (s.state === "UNCERTAIN") {
          const site = this.loadSite(s.siteId);
          if (site && now >= site.policy.core.consent_expires_ms) {
            this.commitEvent(s, { event: "session.expired", to: "UNCERTAIN" });
          } else if (s.snapshotEligible && s.expiresMs !== null && now >= s.expiresMs) {
            this.commitEvent(s, { event: "session.expired", to: "UNCERTAIN" });
          }
        }
      }
      });
    } catch (e) {
      // A failed timer commit is a durable-write failure: close the gate.
      if (e instanceof RpcError) throw e;
      this.auditGateClosed = true;
      throw new RpcError("AUDIT_UNAVAILABLE");
    }
    this.pinAllTips();
  }

  private pinAllTips(): void {
    try {
      for (const r of this.store.all("SELECT id FROM sessions")) {
        const tip = this.audit.tip(r.id as string);
        this.keychain.set(
          `ghostsession/audit-tip/${r.id as string}`,
          Buffer.from(JSON.stringify({ seq: tip.seq, hash: tip.hash })),
        );
      }
    } catch {
      this.auditGateClosed = true;
    }
  }

  /** Await all pending async continuations (test determinism). */
  async drain(): Promise<void> {
    while (this.pending.length > 0) {
      const batch = this.pending;
      this.pending = [];
      await Promise.allSettled(batch);
    }
  }

  private track(p: Promise<void>): void {
    this.pending.push(p);
  }

  // ------------------------------------------------------------- block flow

  private blockCode(cls: BlockClass, network: Observation["network"]): import("./errors.js").ErrorCode {
    if (cls === "CF_CHALLENGE" || cls === "RATE_LIMIT") return "COOLDOWN_ACTIVE";
    if (cls === "NETWORK_ERROR") return network === "tls_error" ? "STATE_CONFLICT" : "COOLDOWN_ACTIVE";
    if (cls === "LOGIN_WALL" || cls === "ACCOUNT_MISMATCH") return "AUTH_NOT_VERIFIED";
    return "STATE_CONFLICT"; // ACCESS_DENIED / UNKNOWN
  }

  private reasonForBlock(cls: BlockClass): Handoff["reason"] {
    if (cls === "ACCOUNT_MISMATCH") return "ACCOUNT_MISMATCH";
    if (cls === "CF_CHALLENGE") return "CF_CHALLENGE";
    return "LOGIN_WALL";
  }

  /**
   * Commit block.detected with §5 routing. Call inside a transaction.
   * `purpose` distinguishes an initial incident (action/attach) from a failed
   * VERIFYING probe (recovery/handoff) for attempt counting and routing.
   */
  private commitBlockDetected(s: Sess, obs: Observation, opts: { purpose: "action" | "recovery" | "handoff" | "attach" }): void {
    const site = this.loadSite(s.siteId)!;
    const cls = classify(obs);
    const effective: BlockClass = cls === "NONE" ? "UNKNOWN" : cls;
    const budget = this.loadBudget(this.device.ownerId, site.policy.core.origin);
    const now = this.now();
    budget.last_block_ms = now;
    const durableObs: Observation = { ...obs, retry_after: null };

    const stampBlock = (): void => {
      s.block = { ...s.block!, revision: s.revision };
      this.saveSession(s);
    };
    const baseBlock = (retryAt: number | null): Block => ({
      class: effective as Exclude<BlockClass, "NONE">,
      revision: s.revision + 1,
      attempt: budget.attempts,
      retry_at_ms: retryAt,
      fallback_used: budget.fallback_used,
      observation: durableObs,
    });

    if (isRetryableBlock(effective, obs.network)) {
      // A failed VERIFYING probe schedules the NEXT attempt; an initial
      // incident counts attempt 1.
      const nextAttempt = opts.purpose === "recovery" || opts.purpose === "handoff"
        ? budget.attempts + 1
        : Math.max(1, budget.attempts);
      const delay = computeDelay(effective, obs.network, nextAttempt, obs.retry_after, obs.received_ms);
      const exhausted = delay.exhausted ||
        ((opts.purpose === "recovery" || opts.purpose === "handoff") && nextAttempt > 2);
      s.block = baseBlock(delay.exhausted ? null : delay.retry_at_ms);
      budget.attempts = Math.min(2, nextAttempt);
      if (delay.retry_at_ms !== null) {
        budget.next_allowed_ms = Math.max(budget.next_allowed_ms, delay.retry_at_ms);
      }
      if (delay.exhausted) budget.manual_review = true;
      this.saveBudget(this.device.ownerId, site.policy.core.origin, budget);
      this.commitEvent(s, { event: "block.detected", to: "COOLDOWN", blockClass: effective });
      stampBlock();
      if (exhausted) {
        this.commitEvent(s, { event: "recovery.exhausted", to: "RECOVERABLE", code: "RECOVERY_EXHAUSTED" });
      }
      return;
    }

    if (effective === "LOGIN_WALL" || effective === "ACCOUNT_MISMATCH") {
      s.block = baseBlock(null);
      const canCard = budget.handoff_starts_ms.filter((t) => t >= now - HANDOFF_WINDOW_MS).length < HANDOFF_MAX;
      // Per §5: the block.detected event itself transitions to HANDOFF_WAIT
      // (card created as a side effect) or NEEDS_LOGIN when budget-spent.
      const card = canCard ? this.newCard(s, site, this.reasonForBlock(effective)) : null;
      this.commitEvent(s, {
        event: "block.detected", to: card ? "HANDOFF_WAIT" : "NEEDS_LOGIN", blockClass: effective,
      });
      stampBlock();
      if (card) {
        budget.handoff_starts_ms.push(now);
        s.handoffId = card.handoff_id;
        card.session_revision = s.revision;
        this.saveCard(card);
        this.saveSession(s);
        this.enqueueCard(s, card);
      }
      this.saveBudget(this.device.ownerId, site.policy.core.origin, budget);
      return;
    }

    // ACCESS_DENIED / UNKNOWN / TLS network / probe NONE without auth.
    s.block = baseBlock(null);
    this.saveBudget(this.device.ownerId, site.policy.core.origin, budget);
    this.commitEvent(s, { event: "block.detected", to: "RECOVERABLE", blockClass: effective });
    stampBlock();
  }

  private newCard(s: Sess, site: SiteRow, reason: Handoff["reason"]): Handoff {
    const now = this.now();
    return {
      handoff_id: this.id("gh"),
      session_id: s.id,
      owner_id: this.device.ownerId,
      state: "PENDING",
      reason,
      policy_hash: site.policy.hash,
      session_revision: s.revision + 1,
      created_ms: now,
      expires_ms: now + HANDOFF_TTL_MS,
      attempts: 0,
      presentation: "local_browser_only",
    };
  }

  private enqueueCard(s: Sess, card: Handoff): void {
    if (!this.inboxAdapter) return;
    const count = this.store.get("SELECT COUNT(*) AS n FROM outbox")?.n as number;
    if (count >= OUTBOX_CAP) throw new RpcError("BUSY");
    const site = this.loadSite(s.siteId)!;
    const card2 = {
      v: 1,
      external_id: card.handoff_id,
      session_id: s.id,
      owner_id: this.device.ownerId,
      origin: site.policy.core.origin,
      reason: card.reason,
      expires_ms: card.expires_ms,
      policy_hash: card.policy_hash,
      allowed_actions: ["notify_local", "cancel"],
    };
    const payload = aesCacheEncrypt(this.device.cacheKey, jcsBytes(card2));
    this.store.run(
      "INSERT INTO outbox(id,kind,session_id,payload_cipher,next_try_ms,attempts) VALUES(?,?,?,?,?,0)",
      this.id("gq"), "handoff_card", s.id, payload, this.now() + 5_000,
    );
  }

  private markOperationUnknown(s: Sess, opId: string): void {
    this.store.run("UPDATE operations SET state='UNKNOWN' WHERE session_id=? AND operation_id=?", s.id, opId);
  }

  // ============================================================ RPC methods

  status(): { protocol: 1; device_id: string; ready: boolean; vault: "local" | "hosted"; clock_safe: boolean } {
    return {
      protocol: 1,
      device_id: this.device.deviceId,
      ready: !this.clockUnsafe && !this.auditGateClosed,
      vault: this.vaultMode,
      clock_safe: !this.clockUnsafe,
    };
  }

  putSite(rawPolicy: unknown): { site_id: string; revision: number; policy_hash: string } {
    this.gateOk();
    const now = this.now();
    const policy = validateSignedPolicy(rawPolicy, now, this.originOpts);
    const core = policy.core;
    // Signature must verify under the pinned device policy/receipt identity key.
    if (core.signing_key_id !== this.device.signingKeyId) throw new RpcError("UNAUTHORIZED");
    const sigOk = ed25519Verify(
      this.device.signingPub,
      domainMessage("policy", policy.hash),
      b64Decode(policy.signature),
    );
    if (!sigOk) throw new RpcError("UNAUTHORIZED");

    return this.commitAndPin([], () => {
      const existing = this.loadSite(core.site_id);
      if (existing) {
        if (existing.policy.hash === policy.hash && existing.revision === core.revision) {
          return { site_id: core.site_id, revision: existing.revision, policy_hash: policy.hash };
        }
        if (core.revision !== existing.revision + 1) throw new RpcError("STATE_CONFLICT");
      } else if (core.revision !== 1) {
        throw new RpcError("STATE_CONFLICT");
      }
      this.store.run(
        "INSERT INTO sites(id,revision,signed_policy) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,signed_policy=excluded.signed_policy",
        core.site_id, core.revision, jcsBytes(policy),
      );
      // policy.changed on every live session bound to this site.
      const sessions = this.store.all("SELECT id FROM sessions WHERE site_id = ?", core.site_id);
      for (const r of sessions) {
        const s = this.loadSession(r.id as string)!;
        if (TERMINAL.includes(s.state)) continue;
        if (s.state === "UNCERTAIN") {
          this.commitEvent(s, { event: "policy.changed", to: "UNCERTAIN" });
        } else {
          this.commitEvent(s, { event: "policy.changed", to: "NEEDS_LOGIN" });
          const card = s.handoffId ? this.loadCard(s.handoffId) : this.cardForSession(s.id);
          if (card && (card.state === "PENDING" || card.state === "OPEN" || card.state === "VERIFYING")) {
            card.state = "CANCELLED";
            card.session_revision = s.revision;
            this.saveCard(card);
          }
          s.handoffId = null;
          this.saveSession(s);
        }
      }
      return { site_id: core.site_id, revision: core.revision, policy_hash: policy.hash };
    });
  }

  createSession(siteId: string): SessionView {
    this.gateOk();
    const now = this.now();
    const site = this.loadSite(siteId);
    if (!site) throw new RpcError("NOT_FOUND");
    if (now >= site.policy.core.consent_expires_ms) throw new RpcError("CONSENT_EXPIRED");

    return this.commitAndPin(["__pending__"], () => {
      const dup = this.store.get(
        "SELECT id FROM sessions WHERE site_id = ? AND state != 'DELETED'", siteId,
      );
      if (dup) throw new RpcError("STATE_CONFLICT");
      const sid = this.id("gs");
      const s: Sess = {
        id: sid, siteId, state: "NEEDS_LOGIN", revision: 0, generation: 0, fence: 0,
        lease: null, block: null, handoffId: null, expiresMs: null,
        control: emptyControl(), snapshotEligible: false,
      };
      this.store.run(
        "INSERT INTO sessions(id,site_id,state,revision,generation,fence,view_json,control_json,snapshot_eligible) VALUES(?,?,?,?,?,?,?,?,0)",
        sid, siteId, "NEEDS_LOGIN", 1, 0, 0,
        jcsBytes({ lease: null, block: null, handoff_id: null, expires_ms: null }),
        jcsBytes(emptyControl()),
      );
      this.commitEvent(s, { event: "session.created", to: "NEEDS_LOGIN" });
      const budget = this.loadBudget(this.device.ownerId, site.policy.core.origin);
      const canCard = budget.handoff_starts_ms.filter((t) => t >= now - HANDOFF_WINDOW_MS).length < HANDOFF_MAX;
      if (canCard) {
        budget.handoff_starts_ms.push(now);
        this.saveBudget(this.device.ownerId, site.policy.core.origin, budget);
        const card = this.newCard(s, site, "INITIAL_LOGIN");
        card.session_revision = s.revision + 1;
        this.commitEvent(s, { event: "handoff.created", to: "HANDOFF_WAIT" });
        s.handoffId = card.handoff_id;
        card.session_revision = s.revision;
        this.saveCard(card);
        this.saveSession(s);
        this.enqueueCard(s, card);
      }
      return this.sessionView(s);
    });
  }

  getSession(sessionId: string): SessionView {
    this.tickIfDue();
    const s = this.loadSession(sessionId);
    if (!s) throw new RpcError("NOT_FOUND");
    return this.sessionView(s);
  }

  private tickIfDue(): void {
    // Deterministic tick on every call; cheap in production too.
    if (!this.shuttingDown) this.tick();
  }

  attach(sessionId: string, runId: string, expectedGeneration: number, actorId: string): SessionView {
    this.gateOk();
    this.tickIfDue();
    const s = this.mustSession(sessionId);
    const now = this.now();
    switch (s.state) {
      case "NEEDS_LOGIN": throw new RpcError("AUTH_NOT_VERIFIED", { state: s.state });
      case "EXPIRED": throw new RpcError("SNAPSHOT_EXPIRED", { state: s.state });
      case "COOLDOWN": throw new RpcError("COOLDOWN_ACTIVE", { state: s.state, retryAtMs: s.block?.retry_at_ms ?? null });
      case "ATTACHING":
      case "ACTIVE": throw new RpcError("LEASE_HELD", { state: s.state });
      case "RECOVERABLE":
      case "HANDOFF_WAIT":
      case "VERIFYING": throw new RpcError("NOT_READY", { state: s.state });
      case "UNCERTAIN":
      case "REVOKED":
      case "DELETED":
      case "QUARANTINED": throw new RpcError("STATE_CONFLICT", { state: s.state });
      case "DETACHED": break;
    }
    if (s.lease && now < s.lease.expires_ms) throw new RpcError("LEASE_HELD", { state: s.state });
    if (expectedGeneration !== s.generation) throw new RpcError("STALE_GENERATION", { state: s.state });
    const site = this.loadSite(s.siteId)!;
    if (!this.eligibleSnapshot(s)) throw new RpcError("AUTH_NOT_VERIFIED", { state: s.state });
    const budget = this.loadBudget(this.device.ownerId, site.policy.core.origin);
    if (now < budget.next_allowed_ms) {
      throw new RpcError("COOLDOWN_ACTIVE", { retryAtMs: budget.next_allowed_ms, state: s.state });
    }
    const view = this.commitAndPin([s.id], () => {
      const lease: Lease = {
        lease_id: this.id("gl"),
        run_id: runId,
        actor_id: actorId,
        fence: s.fence + 1,
        expires_ms: now + LEASE_MS,
      };
      s.fence += 1;
      s.lease = lease;
      s.control.verification = "attach";
      this.commitEvent(s, { event: "lease.acquired", to: "ATTACHING" });
      return this.sessionView(s);
    });
    this.track(this.finishAttach(s.id, s.fence));
    return view;
  }

  private async finishAttach(sessionId: string, fence: number): Promise<void> {
    let ctx: BrowserContextHandle | null = null;
    try {
      const s = this.loadSession(sessionId)!;
      const site = this.loadSite(s.siteId)!;
      const snap = this.snapshotRow(sessionId);
      if (!snap) throw new RpcError("INTEGRITY_FAILED");
      const key = this.keychain.get(`ghostsession/encryption/${snap.keyId}`);
      if (key === null) throw new RpcError("KEY_UNAVAILABLE");
      const plain = decryptSnapshot(snap.cipher, key, {
        sessionId, siteId: s.siteId, deviceId: this.device.deviceId,
        generation: s.generation, policyHash: site.policy.hash,
        nowMs: this.now(),
        auditAnchorHash: (seq) => this.auditHashAt(sessionId, seq),
      });
      const live = liveCookies(plain, this.now());
      ctx = await this.adapter.openContext("attach", site.policy.core);
      this.contexts.set(sessionId, ctx);
      await this.adapter.restore(ctx, {
        cookies: live.map((c) => ({
          name: c.name, value: c.value, host: c.host, path: c.path, secure: true,
          httpOnly: c.http_only, sameSite: c.same_site, expiresMs: c.expires_ms,
        })),
        origins: plain.origins.map((o) => ({ origin: o.origin, localStorage: o.local_storage })),
      });
      const probe = await this.adapter.probe(ctx, site.policy.core);
      const expected = this.accountExpected(site.policy.core);
      const { observation, oversizedRetryAfter } = observationFromProbe(probe, site.policy.core, expected, this.now());
      this.commitAndPin([sessionId], () => {
        const cur = this.loadSession(sessionId)!;
        if (cur.state !== "ATTACHING" || cur.fence !== fence) return; // superseded
        if (oversizedRetryAfter) {
          const b = this.loadBudget(this.device.ownerId, site.policy.core.origin);
          b.manual_review = true;
          this.saveBudget(this.device.ownerId, site.policy.core.origin, b);
        }
        if (probeVerified(observation) && site.policy.hash === this.loadSite(cur.siteId)!.policy.hash) {
          this.commitEvent(cur, { event: "attach.verified", to: "ACTIVE" });
          cur.control.verification = null;
          // Successful authenticated attach + 10 block-free minutes resets counters.
          const b = this.loadBudget(this.device.ownerId, site.policy.core.origin);
          if (b.last_block_ms === null || this.now() - b.last_block_ms >= BLOCK_FREE_RESET_MS) {
            b.attempts = 0;
            b.fallback_used = false;
            b.manual_review = false;
          }
          this.saveBudget(this.device.ownerId, site.policy.core.origin, b);
          this.saveSession(cur);
        } else {
          this.contexts.delete(sessionId);
          void ctx;
          this.commitBlockDetected(cur, observation, { purpose: "attach" });
        }
      });
    } catch (e) {
      const code = e instanceof RpcError ? e.code : "INTERNAL";
      this.failVerification(sessionId, fence, code, ctx);
    }
  }

  private failVerification(sessionId: string, fence: number, code: import("./errors.js").ErrorCode, ctx: BrowserContextHandle | null): void {
    try {
      this.commitAndPin([sessionId], () => {
        const cur = this.loadSession(sessionId)!;
        if (!CONTEXT_STATES.includes(cur.state) || cur.fence !== fence) return;
        if (code === "INTEGRITY_FAILED") {
          this.commitEvent(cur, { event: "session.quarantined", to: "QUARANTINED", code });
        } else if (code === "SNAPSHOT_EXPIRED" || code === "CONSENT_EXPIRED") {
          this.commitEvent(cur, { event: "session.expired", to: "EXPIRED", code });
        } else if (code === "KEY_UNAVAILABLE") {
          this.commitEvent(cur, { event: "recovery.exhausted", to: "RECOVERABLE", code });
        } else {
          this.commitEvent(cur, { event: "recovery.exhausted", to: "RECOVERABLE", code });
        }
      });
    } catch { /* gate closed */ }
    if (ctx) void this.adapter.destroy(ctx).catch(() => {});
  }

  private accountExpected(core: PolicyCore): string | null {
    const ref = core.auth_probe.expected_account_ref;
    const name = ref.replace(/^keychain:/, "");
    return this.keychain.has(name) ? this.keychain.get(name)!.toString("utf8") : null;
  }

  private mustSession(id: string): Sess {
    const s = this.loadSession(id);
    if (!s) throw new RpcError("NOT_FOUND");
    return s;
  }

  renew(sessionId: string, leaseId: string, fence: number): { lease: Lease; audit_seq: number } {
    this.gateOk();
    const s = this.mustSession(sessionId);
    if (TERMINAL.includes(s.state) || s.state === "UNCERTAIN") {
      throw new RpcError("STATE_CONFLICT", { state: s.state });
    }
    if (fence !== s.fence) throw new RpcError("STALE_FENCE", { state: s.state });
    if (
      (s.state === "ACTIVE" || s.state === "ATTACHING") &&
      s.lease && this.now() >= s.lease.expires_ms
    ) {
      this.commitAndPin([s.id], () => {
        this.commitEvent(s, { event: "lease.expired", to: "DETACHED" });
      });
      throw new RpcError("LEASE_EXPIRED", { state: "DETACHED" });
    }
    this.tickIfDue();
    const cur = this.mustSession(sessionId);
    this.leaseStateGate(cur, "renew");
    if (!cur.lease || cur.lease.lease_id !== leaseId) {
      throw new RpcError("STALE_FENCE", { state: cur.state });
    }
    const now = this.now();
    return this.commitAndPin([cur.id], () => {
      const fresh = this.loadSession(cur.id)!;
      fresh.lease = { ...fresh.lease!, expires_ms: now + LEASE_MS };
      const rec = this.commitEvent(fresh, { event: "lease.renewed", to: fresh.state });
      return { lease: fresh.lease!, audit_seq: rec.core.seq };
    });
  }

  /** State gate shared by renew/detach/step/checkpoint (spec §8.1). */
  private leaseStateGate(s: Sess, op: "renew" | "detach" | "step" | "checkpoint"): void {
    switch (s.state) {
      case "NEEDS_LOGIN": throw new RpcError("AUTH_NOT_VERIFIED", { state: s.state });
      case "EXPIRED": throw new RpcError("SNAPSHOT_EXPIRED", { state: s.state });
      case "COOLDOWN": throw new RpcError("COOLDOWN_ACTIVE", { state: s.state, retryAtMs: s.block?.retry_at_ms ?? null });
      case "DETACHED":
        throw new RpcError("NOT_READY", { state: s.state });
      case "ATTACHING":
        if (op === "step" || op === "checkpoint") throw new RpcError("NOT_READY", { state: s.state });
        return; // renew/detach legal in ATTACHING
      case "ACTIVE":
        return;
      case "RECOVERABLE":
      case "HANDOFF_WAIT":
      case "VERIFYING":
        throw new RpcError("NOT_READY", { state: s.state });
      case "UNCERTAIN":
      case "REVOKED":
      case "DELETED":
      case "QUARANTINED":
        throw new RpcError("STATE_CONFLICT", { state: s.state });
    }
  }

  async step(
    sessionId: string, leaseId: string, fence: number,
    operationId: string, action: BrowserAction, actorId: string,
  ): Promise<ActionResult> {
    this.gateOk();
    const s = this.mustSession(sessionId);
    const binding = actionBinding(this.device.auditKey, action);
    // Terminal/interlock gates precede dedup; the unresolved op's repeat still
    // reaches dedup inspection (OUTCOME_UNKNOWN), never a new effect.
    if (s.state === "UNCERTAIN") {
      const existing = this.opRow(sessionId, operationId);
      if (existing) {
        if (existing.binding !== binding) {
          throw new RpcError("OPERATION_CONFLICT", { state: s.state });
        }
        return this.opDedupResult(s, existing);
      }
      throw new RpcError("STATE_CONFLICT", { state: s.state });
    }
    if (TERMINAL.includes(s.state)) throw new RpcError("STATE_CONFLICT", { state: s.state });
    // Operation dedup precedes stale-lease checks but not actor/terminal gates.
    const prior = this.opRow(sessionId, operationId);
    if (prior) {
      if (prior.binding !== binding) {
        throw new RpcError("OPERATION_CONFLICT", { state: s.state });
      }
      return this.opDedupResult(s, prior);
    }
    if (fence !== s.fence) throw new RpcError("STALE_FENCE", { state: s.state });
    // Lease expiry is checked on the pre-tick row so equality yields
    // LEASE_EXPIRED (no grace), not a tick-flattened NOT_READY.
    if (
      (s.state === "ACTIVE" || s.state === "ATTACHING") &&
      s.lease && this.now() >= s.lease.expires_ms
    ) {
      this.commitAndPin([s.id], () => {
        this.commitEvent(s, { event: "lease.expired", to: "DETACHED" });
      });
      throw new RpcError("LEASE_EXPIRED", { state: "DETACHED" });
    }
    this.tickIfDue();
    const cur0 = this.mustSession(sessionId);
    this.leaseStateGate(cur0, "step");
    if (!cur0.lease || cur0.lease.lease_id !== leaseId) {
      throw new RpcError("STALE_FENCE", { state: cur0.state });
    }
    if (cur0.control.active_operation !== null) throw new RpcError("BUSY", { state: cur0.state });
    this.checkAuditPressure(cur0);
    this.checkRate(`${actorId}:${sessionId}`, "step", STEP_WINDOW_MS, STEP_MAX);

    const site = this.loadSite(cur0.siteId)!;

    // Pre-dispatch action validation → DENIED without dispatch.
    const preErr = this.validateAction(site.policy.core, action);
    if (preErr !== null) {
      return this.commitAndPin([s.id], () => {
        const rec = this.commitEvent(s, {
          event: "action.denied", to: "ACTIVE", code: preErr, operationId, actionBinding_: binding,
        });
        const bc: BlockClass = preErr === "SCOPE_DENIED" ? "SCOPE_DENIED" : "NONE";
        this.putOpRow(s.id, operationId, binding, "DENIED", this.encryptResult({
          operation_id: operationId, outcome: "DENIED", code: preErr, text: null,
          truncated: false, block_class: bc, audit_seq: rec.core.seq,
        }));
        return {
          operation_id: operationId, outcome: "DENIED" as const, code: preErr,
          text: null, truncated: false, block_class: bc, audit_seq: rec.core.seq,
        };
      });
    }

    this.commitAndPin([s.id], () => {
      s.control.active_operation = operationId;
      s.control.dispatched = false;
      this.commitEvent(s, {
        event: "action.intent", to: "ACTIVE", operationId, actionBinding_: binding,
      });
      this.putOpRow(s.id, operationId, binding, "PREPARED", null);
      this.saveSession(s);
    });

    await this.hooks.afterActionIntent?.(sessionId, operationId);

    // Pre-dispatch recheck: fence, state, policy, slot — synchronously.
    const recheck = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(sessionId)!;
      const curSite = this.loadSite(cur.siteId)!;
      if (
        cur.state !== "ACTIVE" || cur.fence !== fence ||
        cur.control.active_operation !== operationId ||
        curSite.policy.hash !== site.policy.hash ||
        !cur.lease || this.now() >= cur.lease.expires_ms
      ) {
        const code: import("./errors.js").ErrorCode =
          curSite.policy.hash !== site.policy.hash ? "SCOPE_DENIED" : "STATE_CONFLICT";
        const rec = this.commitEvent(cur, {
          event: "action.denied", to: cur.state, code, operationId, actionBinding_: binding,
        });
        const bc: BlockClass = code === "SCOPE_DENIED" ? "SCOPE_DENIED" : "NONE";
        this.store.run(
          "UPDATE operations SET state='DENIED', result_cipher=? WHERE session_id=? AND operation_id=?",
          this.encryptResult({
            operation_id: operationId, outcome: "DENIED", code, text: null,
            truncated: false, block_class: bc, audit_seq: rec.core.seq,
          }), cur.id, operationId,
        );
        cur.control.active_operation = null;
        cur.control.dispatched = false;
        this.saveSession(cur);
        return {
          operation_id: operationId, outcome: "DENIED" as const, code,
          text: null, truncated: false, block_class: bc, audit_seq: rec.core.seq,
        };
      }
      this.store.run("UPDATE operations SET state='DISPATCHED' WHERE session_id=? AND operation_id=?", cur.id, operationId);
      cur.control.dispatched = true;
      this.saveSession(cur);
      return null;
    });
    if (recheck !== null) return recheck;

    const ctx = this.contexts.get(sessionId);
    if (!ctx) throw new RpcError("INTERNAL");
    let outcome: DispatchOutcome;
    let adapterThrew = false;
    try {
      outcome = await this.dispatchWithDeadline(ctx, action, site.policy.core, sessionId);
    } catch (e) {
      // Adapter failure: the action's completion is unproven, so the durable
      // record is action.unknown → UNCERTAIN; the API error is a scrubbed
      // INTERNAL — the raw exception never reaches the wire or receipts.
      adapterThrew = true;
      outcome = { kind: "unknown" };
      void e;
    }

    const result = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(sessionId)!;
      const finish = (out: ActionResult, opState: string): ActionResult => {
        this.store.run(
          "UPDATE operations SET state=?, result_cipher=? WHERE session_id=? AND operation_id=?",
          opState, this.encryptResult(out), cur.id, operationId,
        );
        cur.control.active_operation = null;
        cur.control.dispatched = false;
        this.saveSession(cur);
        return out;
      };
      if (outcome.kind === "denied") {
        const rec = this.commitEvent(cur, {
          event: "action.denied", to: "ACTIVE", code: outcome.code, operationId, actionBinding_: binding,
        });
        return finish({
          operation_id: operationId, outcome: "DENIED", code: outcome.code, text: null,
          truncated: false, block_class: outcome.code === "SCOPE_DENIED" ? "SCOPE_DENIED" : "NONE",
          audit_seq: rec.core.seq,
        }, "DENIED");
      }
      if (outcome.kind === "unknown") {
        const rec = this.commitEvent(cur, {
          event: "action.unknown", to: "UNCERTAIN", code: "OUTCOME_UNKNOWN", operationId, actionBinding_: binding,
        });
        cur.control.unresolved_operations.push(operationId);
        return finish({
          operation_id: operationId, outcome: "UNKNOWN", code: "OUTCOME_UNKNOWN", text: null,
          truncated: false, block_class: "NONE", audit_seq: rec.core.seq,
        }, "UNKNOWN");
      }
      // ok path: classify the trusted observation.
      const { observation, oversizedRetryAfter } = observationFromResponse(outcome.response, site.policy.core, this.now());
      const cls = classify(observation);
      if (oversizedRetryAfter) {
        const b = this.loadBudget(this.device.ownerId, site.policy.core.origin);
        b.manual_review = true;
        this.saveBudget(this.device.ownerId, site.policy.core.origin, b);
      }
      if (cls === "NONE") {
        const rec = this.commitEvent(cur, {
          event: "action.finished", to: "ACTIVE", operationId, actionBinding_: binding,
        });
        return finish({
          operation_id: operationId, outcome: "SUCCEEDED", code: "OK", text: outcome.text,
          truncated: outcome.truncated, block_class: "NONE", audit_seq: rec.core.seq,
        }, "SUCCEEDED");
      }
      const code = this.blockCode(cls, observation.network);
      const rec = this.commitEvent(cur, {
        event: "action.finished", to: cur.state, code, operationId, actionBinding_: binding, blockClass: cls,
      });
      const seq = rec.core.seq;
      this.commitBlockDetected(cur, observation, { purpose: "action" });
      return finish({
        operation_id: operationId, outcome: "BLOCKED", code, text: null,
        truncated: false, block_class: cls, audit_seq: this.audit.tip(cur.id).seq || seq,
      }, "BLOCKED");
    });
    if (adapterThrew) throw new RpcError("INTERNAL");
    return result;
  }

  private async dispatchWithDeadline(
    ctx: BrowserContextHandle, action: BrowserAction, policy: PolicyCore, sessionId: string,
  ): Promise<DispatchOutcome> {
    await this.hooks.beforeDispatchResolve?.(sessionId);
    const timeout = new Promise<DispatchOutcome>((resolve) => {
      const t = setTimeout(() => resolve({ kind: "unknown" }), 16_000);
      t.unref?.();
    });
    return Promise.race([this.adapter.dispatch(ctx, action, policy), timeout]);
  }

  private validateAction(policy: PolicyCore, action: BrowserAction): import("./errors.js").ErrorCode | null {
    try {
      if (action.kind === "navigate") {
        const v = checkEgress(policy, "attach", { url: action.url, method: "GET", isTopLevel: true }, this.originOpts);
        if (v.decision !== "allow") return "SCOPE_DENIED";
      } else {
        // read/click/fill act on the scoped page; selector subset enforced.
        validateSelector(action.selector);
      }
      return null;
    } catch {
      return "SCOPE_DENIED";
    }
  }

  private opRow(sessionId: string, opId: string): { state: string; binding: string; result: Buffer | null } | null {
    const r = this.store.get(
      "SELECT state, action_binding, result_cipher FROM operations WHERE session_id=? AND operation_id=?",
      sessionId, opId,
    );
    if (!r) return null;
    return {
      state: r.state as string,
      binding: r.action_binding as string,
      result: r.result_cipher ? Buffer.from(r.result_cipher as Uint8Array) : null,
    };
  }

  private putOpRow(sessionId: string, opId: string, binding: string, state: string, result: Buffer | null): void {
    this.store.run(
      "INSERT INTO operations(session_id,operation_id,action_binding,state,result_cipher,started_ms) VALUES(?,?,?,?,?,?)",
      sessionId, opId, binding, state, result, this.now(),
    );
  }

  private opDedupResult(s: Sess, row: { state: string; binding: string; result: Buffer | null }): ActionResult {
    switch (row.state) {
      case "PREPARED":
      case "DISPATCHED":
        throw new RpcError("OUTCOME_UNKNOWN", { state: s.state });
      case "UNKNOWN":
        throw new RpcError("OUTCOME_UNKNOWN", { state: s.state });
      case "PURGED":
        throw new RpcError("RESULT_GONE", { state: s.state });
      case "SUCCEEDED":
      case "BLOCKED":
      case "DENIED": {
        if (row.result === null) throw new RpcError("RESULT_GONE", { state: s.state });
        const cached = this.decryptResult(row.result) as ActionResult;
        return { ...cached };
      }
      default:
        throw new RpcError("INTERNAL");
    }
  }

  private encryptResult(result: ActionResult): Buffer {
    return aesCacheEncrypt(this.device.cacheKey, jcsBytes(result));
  }

  private decryptResult(cipher: Buffer): unknown {
    return parseStrictJson(aesCacheDecrypt(this.device.cacheKey, cipher));
  }

  async checkpoint(sessionId: string, leaseId: string, fence: number): Promise<{ generation: number; audit_seq: number }> {
    this.gateOk();
    const s = this.mustSession(sessionId);
    if (TERMINAL.includes(s.state) || s.state === "UNCERTAIN") {
      throw new RpcError("STATE_CONFLICT", { state: s.state });
    }
    if (fence !== s.fence) throw new RpcError("STALE_FENCE", { state: s.state });
    if (
      (s.state === "ACTIVE" || s.state === "ATTACHING") &&
      s.lease && this.now() >= s.lease.expires_ms
    ) {
      this.commitAndPin([s.id], () => this.commitEvent(s, { event: "lease.expired", to: "DETACHED" }));
      throw new RpcError("LEASE_EXPIRED", { state: "DETACHED" });
    }
    this.tickIfDue();
    const cur = this.mustSession(sessionId);
    this.leaseStateGate(cur, "checkpoint");
    if (!cur.lease || cur.lease.lease_id !== leaseId) {
      throw new RpcError("STALE_FENCE", { state: cur.state });
    }
    if (cur.control.active_operation !== null) throw new RpcError("BUSY", { state: cur.state });
    this.checkAuditPressure(cur);
    const ctx = this.contexts.get(sessionId);
    if (!ctx) throw new RpcError("NOT_READY", { state: cur.state });
    return this.runCheckpoint(cur, ctx);
  }

  /** snapshot.intent → capture → encrypt → snapshot.committed (atomic). */
  private async runCheckpoint(
    s: Sess, ctx: BrowserContextHandle,
  ): Promise<{ generation: number; audit_seq: number }> {
    const site = this.loadSite(s.siteId)!;
    const nextGen = s.generation + 1;
    const intent = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      this.commitEvent(cur, { event: "snapshot.intent", to: cur.state });
      return this.audit.tip(s.id);
    });
    try {
      const raw = await this.adapter.capture(ctx);
      const expiresMs = Math.min(
        this.now() + site.policy.core.snapshot_ttl_ms,
        site.policy.core.consent_expires_ms,
      );
      const parts = validateCapture(raw, site.policy.core, {
        sessionId: s.id, siteId: s.siteId, generation: nextGen,
        savedMs: this.now(), expiresMs, auditSeq: intent.seq, auditHash: intent.hash,
      });
      const plain = buildSnapshotPlain({
        sessionId: s.id, siteId: s.siteId, generation: nextGen,
        savedMs: this.now(), expiresMs, auditSeq: intent.seq, auditHash: intent.hash,
      }, parts);
      const { keyId, key } = this.encKeyFor(s.id);
      const cipher = encryptSnapshot(plain, key, {
        deviceId: this.device.deviceId, policyHash: site.policy.hash, keyId, nonce: freshNonce(),
      });
      return this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        this.store.run(
          "INSERT INTO snapshots(session_id,generation,key_id,cipher_json,cipher_hash) VALUES(?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET generation=excluded.generation,key_id=excluded.key_id,cipher_json=excluded.cipher_json,cipher_hash=excluded.cipher_hash",
          s.id, nextGen, keyId, jcsBytes(cipher), cipherHash(cipher),
        );
        const rec = this.commitEvent(cur, {
          event: "snapshot.committed", to: cur.state, generation: nextGen, cipherHash: cipherHash(cipher),
        });
        cur.expiresMs = expiresMs;
        this.saveSession(cur);
        s.generation = cur.generation;
        return { generation: nextGen, audit_seq: rec.core.seq };
      });
    } catch (e) {
      const code = e instanceof RpcError ? e.code : "INTERNAL";
      this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        this.commitEvent(cur, { event: "snapshot.failed", to: cur.state, code });
      });
      throw e instanceof RpcError ? e : new RpcError(code === "INTERNAL" ? "INTERNAL" : code);
    }
  }

  async detach(sessionId: string, leaseId: string, fence: number, checkpoint: boolean): Promise<SessionView> {
    this.gateOk();
    const s = this.mustSession(sessionId);
    if (TERMINAL.includes(s.state) || s.state === "UNCERTAIN") {
      throw new RpcError("STATE_CONFLICT", { state: s.state });
    }
    if (fence !== s.fence) throw new RpcError("STALE_FENCE", { state: s.state });
    if (
      (s.state === "ACTIVE" || s.state === "ATTACHING") &&
      s.lease && this.now() >= s.lease.expires_ms
    ) {
      this.commitAndPin([s.id], () => this.commitEvent(s, { event: "lease.expired", to: "DETACHED" }));
      throw new RpcError("LEASE_EXPIRED", { state: "DETACHED" });
    }
    this.tickIfDue();
    const cur0 = this.mustSession(sessionId);
    this.leaseStateGate(cur0, "detach");
    if (!cur0.lease || cur0.lease.lease_id !== leaseId) {
      throw new RpcError("STALE_FENCE", { state: cur0.state });
    }
    if (checkpoint) {
      const ctx = this.contexts.get(sessionId);
      if (ctx) {
        try {
          await this.runCheckpoint(cur0, ctx);
        } catch { /* checkpoint failure does not block detach */ }
      }
    }
    const view = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      this.commitEvent(cur, { event: "session.detached", to: "DETACHED" });
      return this.sessionView(cur);
    });
    return view;
  }

  recover(sessionId: string, blockRevision: number | null, intent: "retry" | "fallback" | "reauth" | "acknowledge_unknown", actorId: string): SessionView {
    this.gateOk();
    this.tickIfDue();
    const s = this.mustSession(sessionId);
    const site = this.loadSite(s.siteId)!;
    const now = this.now();
    const budget = this.loadBudget(this.device.ownerId, site.policy.core.origin);

    if (intent === "acknowledge_unknown") {
      if (s.state !== "UNCERTAIN") throw new RpcError("STATE_CONFLICT", { state: s.state });
      return this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        const to = this.eligibleSnapshot(cur) ? "DETACHED" : "NEEDS_LOGIN";
        cur.control.unresolved_operations = [];
        this.commitEvent(cur, { event: "unknown.acknowledged", to });
        return this.sessionView(cur);
      });
    }

    if (intent === "reauth") {
      const allowed = ["DETACHED", "NEEDS_LOGIN", "EXPIRED", "COOLDOWN", "RECOVERABLE"];
      if (!allowed.includes(s.state)) throw new RpcError("STATE_CONFLICT", { state: s.state });
      const canCard = budget.handoff_starts_ms.filter((t) => t >= now - HANDOFF_WINDOW_MS).length < HANDOFF_MAX;
      if (!canCard) throw new RpcError("RECOVERY_EXHAUSTED", { state: s.state });
      return this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        budget.handoff_starts_ms.push(now);
        this.saveBudget(this.device.ownerId, site.policy.core.origin, budget);
        const card = this.newCard(cur, site, s.state === "NEEDS_LOGIN" ? "INITIAL_LOGIN" : "MANUAL");
        this.commitEvent(cur, { event: "handoff.created", to: "HANDOFF_WAIT" });
        cur.handoffId = card.handoff_id;
        card.session_revision = cur.revision;
        this.saveCard(card);
        this.saveSession(cur);
        this.enqueueCard(cur, card);
        return this.sessionView(cur);
      });
    }

    // retry / fallback
    if (blockRevision === null) throw new RpcError("INVALID_SCHEMA");
    if (!s.block || s.block.revision !== blockRevision) throw new RpcError("STATE_CONFLICT", { state: s.state });
    if (s.state === "COOLDOWN") {
      if (s.block.retry_at_ms !== null && now < s.block.retry_at_ms) {
        throw new RpcError("COOLDOWN_ACTIVE", { retryAtMs: s.block.retry_at_ms, state: s.state });
      }
      this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        this.commitEvent(cur, { event: "cooldown.elapsed", to: "RECOVERABLE" });
      });
      s.state = "RECOVERABLE";
    }
    if (s.state !== "RECOVERABLE") {
      throw new RpcError(s.state === "UNCERTAIN" || TERMINAL.includes(s.state) ? "STATE_CONFLICT" : "NOT_READY", { state: s.state });
    }
    const cls = s.block.class;
    const network = s.block.observation.network;
    if (intent === "retry") {
      if (!isRetryableBlock(cls, network)) throw new RpcError("STATE_CONFLICT", { state: s.state });
      // A recovery.exhausted incident permits no further probes.
      if (this.lastIncidentEvent(s) === "recovery.exhausted") {
        throw new RpcError("RECOVERY_EXHAUSTED", { state: s.state });
      }
    } else {
      if (site.policy.core.recovery.fallback_path === null) throw new RpcError("STATE_CONFLICT", { state: s.state });
      if (!isFallbackEligible(cls, network)) throw new RpcError("STATE_CONFLICT", { state: s.state });
      if (s.block.fallback_used || budget.fallback_used) throw new RpcError("RECOVERY_EXHAUSTED", { state: s.state });
      if (this.lastIncidentEvent(s) === "recovery.exhausted") {
        throw new RpcError("RECOVERY_EXHAUSTED", { state: s.state });
      }
    }
    if (now < budget.next_allowed_ms) {
      throw new RpcError("COOLDOWN_ACTIVE", { retryAtMs: budget.next_allowed_ms, state: s.state });
    }
    if (budget.probe_starts_ms.filter((t) => t >= now - PROBE_WINDOW_MS).length >= PROBE_MAX) {
      throw new RpcError("RECOVERY_EXHAUSTED", { state: s.state });
    }
    if (budget.manual_review) throw new RpcError("RECOVERY_EXHAUSTED", { state: s.state });

    const view = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      budget.probe_starts_ms.push(now);
      if (intent === "fallback") {
        budget.fallback_used = true;
        cur.block = { ...cur.block!, fallback_used: true };
      }
      this.saveBudget(this.device.ownerId, site.policy.core.origin, budget);
      cur.control.verification = "recovery";
      this.commitEvent(cur, { event: "recovery.started", to: "VERIFYING" });
      return this.sessionView(cur);
    });
    this.track(this.finishRecovery(s.id, s.fence, intent));
    return view;
  }

  private async finishRecovery(sessionId: string, fence: number, intent: "retry" | "fallback"): Promise<void> {
    let ctx: BrowserContextHandle | null = null;
    try {
      const s = this.loadSession(sessionId)!;
      const site = this.loadSite(s.siteId)!;
      const snap = this.snapshotRow(sessionId);
      if (!snap) throw new RpcError("INTEGRITY_FAILED");
      const key = this.keychain.get(`ghostsession/encryption/${snap.keyId}`);
      if (key === null) throw new RpcError("KEY_UNAVAILABLE");
      const plain = decryptSnapshot(snap.cipher, key, {
        sessionId, siteId: s.siteId, deviceId: this.device.deviceId,
        generation: s.generation, policyHash: site.policy.hash,
        nowMs: this.now(),
        auditAnchorHash: (seq) => this.auditHashAt(sessionId, seq),
      });
      ctx = await this.adapter.openContext("recovery", site.policy.core);
      this.contexts.set(sessionId, ctx);
      await this.adapter.restore(ctx, {
        cookies: liveCookies(plain, this.now()).map((c) => ({
          name: c.name, value: c.value, host: c.host, path: c.path, secure: true,
          httpOnly: c.http_only, sameSite: c.same_site, expiresMs: c.expires_ms,
        })),
        origins: plain.origins.map((o) => ({ origin: o.origin, localStorage: o.local_storage })),
      });
      if (intent === "fallback" && site.policy.core.recovery.fallback_path) {
        await this.adapter.dispatch(ctx, { kind: "navigate", url: `${site.policy.core.origin}${site.policy.core.recovery.fallback_path}` }, site.policy.core);
      }
      const probe = await this.adapter.probe(ctx, site.policy.core);
      const expected = this.accountExpected(site.policy.core);
      const { observation, oversizedRetryAfter } = observationFromProbe(probe, site.policy.core, expected, this.now());
      if (probeVerified(observation)) {
        // capture then attach.verified → DETACHED (no lease)
        const intentTip = this.commitAndPin([sessionId], () => {
          const cur = this.loadSession(sessionId)!;
          if (cur.state !== "VERIFYING" || cur.fence !== fence || cur.control.verification !== "recovery") return null;
          this.commitEvent(cur, { event: "snapshot.intent", to: "VERIFYING" });
          return this.audit.tip(sessionId);
        });
        if (intentTip === null) return;
        await this.verifyCapture(sessionId, fence, ctx, intentTip, "attach.verified");
      } else {
        this.commitAndPin([sessionId], () => {
          const cur = this.loadSession(sessionId)!;
          if (cur.state !== "VERIFYING" || cur.fence !== fence) return;
          if (oversizedRetryAfter) {
            const b = this.loadBudget(this.device.ownerId, site.policy.core.origin);
            b.manual_review = true;
            this.saveBudget(this.device.ownerId, site.policy.core.origin, b);
          }
          this.commitBlockDetected(cur, observation, { purpose: "recovery" });
        });
        this.contexts.delete(sessionId);
        void this.adapter.destroy(ctx).catch(() => {});
      }
    } catch (e) {
      const code = e instanceof RpcError ? e.code : "INTERNAL";
      this.failVerification(sessionId, fence, code, ctx);
    }
  }

  /** Shared VERIFYING capture+commit tail for recovery/handoff verification. */
  private async verifyCapture(
    sessionId: string, fence: number, ctx: BrowserContextHandle,
    intentTip: { seq: number; hash: string }, finalEvent: "attach.verified" | "handoff.completed",
  ): Promise<void> {
    const s = this.loadSession(sessionId)!;
    const site = this.loadSite(s.siteId)!;
    try {
      const raw = await this.adapter.capture(ctx);
      const nextGen = s.generation + 1;
      const expiresMs = Math.min(this.now() + site.policy.core.snapshot_ttl_ms, site.policy.core.consent_expires_ms);
      const parts = validateCapture(raw, site.policy.core, {
        sessionId, siteId: s.siteId, generation: nextGen, savedMs: this.now(), expiresMs,
        auditSeq: intentTip.seq, auditHash: String(intentTip.hash),
      });
      const plain = buildSnapshotPlain({
        sessionId, siteId: s.siteId, generation: nextGen, savedMs: this.now(), expiresMs,
        auditSeq: intentTip.seq, auditHash: String(intentTip.hash),
      }, parts);
      const { keyId, key } = this.encKeyFor(sessionId);
      const cipher = encryptSnapshot(plain, key, {
        deviceId: this.device.deviceId, policyHash: site.policy.hash, keyId, nonce: freshNonce(),
      });
      this.commitAndPin([sessionId], () => {
        const cur = this.loadSession(sessionId)!;
        if (cur.state !== "VERIFYING" || cur.fence !== fence) return;
        this.store.run(
          "INSERT INTO snapshots(session_id,generation,key_id,cipher_json,cipher_hash) VALUES(?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET generation=excluded.generation,key_id=excluded.key_id,cipher_json=excluded.cipher_json,cipher_hash=excluded.cipher_hash",
          sessionId, nextGen, keyId, jcsBytes(cipher), cipherHash(cipher),
        );
        this.commitEvent(cur, { event: "snapshot.committed", to: "VERIFYING", generation: nextGen, cipherHash: cipherHash(cipher) });
        cur.expiresMs = expiresMs;
        const completedCardId = cur.handoffId;
        this.commitEvent(cur, { event: finalEvent, to: "DETACHED" });
        cur.block = null;
        cur.control.verification = null;
        if (finalEvent === "handoff.completed" && completedCardId) {
          const card = this.loadCard(completedCardId);
          if (card) {
            card.state = "COMPLETED";
            card.session_revision = cur.revision;
            this.saveCard(card);
          }
          cur.handoffId = null;
        }
        this.saveSession(cur);
        this.contexts.delete(sessionId);
        void this.adapter.destroy(ctx).catch(() => {});
        const b = this.loadBudget(this.device.ownerId, site.policy.core.origin);
        b.attempts = 0;
        b.fallback_used = false;
        this.saveBudget(this.device.ownerId, site.policy.core.origin, b);
      });
    } catch (e) {
      const code = e instanceof RpcError ? e.code : "INTERNAL";
      this.commitAndPin([sessionId], () => {
        const cur = this.loadSession(sessionId)!;
        if (cur.state !== "VERIFYING") return;
        this.commitEvent(cur, { event: "snapshot.failed", to: "VERIFYING", code });
        if (cur.control.verification === "handoff" && cur.handoffId) {
          const card = this.loadCard(cur.handoffId);
          if (card) {
            card.state = "EXPIRED";
            card.session_revision = cur.revision;
            this.saveCard(card);
          }
          cur.handoffId = null;
          this.commitEvent(cur, { event: "handoff.expired", to: "NEEDS_LOGIN" });
        } else {
          this.commitEvent(cur, { event: "recovery.exhausted", to: "RECOVERABLE" });
        }
      });
      void this.adapter.destroy(ctx).catch(() => {});
    }
  }

  // ------------------------------------------------------------- handoff RPC

  getHandoff(handoffId: string): Handoff {
    this.tickIfDue();
    const c = this.loadCard(handoffId);
    if (!c) throw new RpcError("NOT_FOUND");
    return c;
  }

  openHandoff(handoffId: string): Handoff {
    this.gateOk();
    this.tickIfDue();
    const card = this.loadCard(handoffId);
    if (!card) throw new RpcError("NOT_FOUND");
    const s = this.mustSession(card.session_id);
    const site = this.loadSite(s.siteId)!;
    const now = this.now();
    if (now >= card.expires_ms || card.state === "EXPIRED") {
      throw new RpcError("HANDOFF_EXPIRED", { state: s.state });
    }
    if (card.state === "COMPLETED" || card.state === "CANCELLED") throw new RpcError("STALE_HANDOFF", { state: s.state });
    if (s.state !== "HANDOFF_WAIT") throw new RpcError("STATE_CONFLICT", { state: s.state });
    if (card.policy_hash !== site.policy.hash || card.session_revision > s.revision) {
      throw new RpcError("STALE_HANDOFF", { state: s.state });
    }
    const budget = this.loadBudget(this.device.ownerId, site.policy.core.origin);
    if (now < budget.next_allowed_ms) {
      throw new RpcError("COOLDOWN_ACTIVE", { retryAtMs: budget.next_allowed_ms, state: s.state });
    }
    if (card.state === "OPEN") return card; // idempotent re-open, no second launch
    const updated = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      const c = this.loadCard(handoffId)!;
      c.state = "OPEN";
      this.commitEvent(cur, { event: "handoff.opened", to: "HANDOFF_WAIT" });
      c.session_revision = cur.revision;
      this.saveCard(c);
      cur.handoffId = c.handoff_id;
      this.saveSession(cur);
      return c;
    });
    const openTask = this.openHumanContext(s.id, site.policy.core);
    this.handoffOpenTasks.set(s.id, openTask);
    this.track(openTask);
    return updated;
  }

  private async openHumanContext(sessionId: string, policy: PolicyCore): Promise<void> {
    try {
      const ctx = await this.adapter.openContext("handoff-human", policy);
      this.contexts.set(sessionId, ctx);
      await this.adapter.openHuman(ctx, policy);
    } catch { /* owner sees card state; context failure is retried on next open */ }
  }

  resolveHandoff(handoffId: string, decision: "ready" | "cancel"): Handoff {
    this.gateOk();
    this.tickIfDue();
    const card = this.loadCard(handoffId);
    if (!card) throw new RpcError("NOT_FOUND");
    const s = this.mustSession(card.session_id);
    const now = this.now();

    if (decision === "cancel") {
      const cancellable =
        s.state === "HANDOFF_WAIT" ||
        (s.state === "VERIFYING" && s.control.verification === "handoff");
      if (!cancellable) throw new RpcError("STATE_CONFLICT", { state: s.state });
      return this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        const c = this.loadCard(handoffId)!;
        c.state = "CANCELLED";
        this.commitEvent(cur, { event: "handoff.cancelled", to: "NEEDS_LOGIN" });
        c.session_revision = cur.revision;
        this.saveCard(c);
        this.saveSession(cur);
        return c;
      });
    }

    // ready
    if (s.state !== "HANDOFF_WAIT" || card.state !== "OPEN") {
      if (card.state === "EXPIRED" || now >= card.expires_ms) throw new RpcError("HANDOFF_EXPIRED", { state: s.state });
      throw new RpcError("STALE_HANDOFF", { state: s.state });
    }
    if (now >= card.expires_ms) throw new RpcError("HANDOFF_EXPIRED", { state: s.state });
    const site = this.loadSite(s.siteId)!;
    if (card.policy_hash !== site.policy.hash || card.session_revision !== s.revision) {
      throw new RpcError("STALE_HANDOFF", { state: s.state });
    }
    if (card.attempts >= 2) throw new RpcError("HANDOFF_EXPIRED", { state: s.state });
    const budget = this.loadBudget(this.device.ownerId, site.policy.core.origin);
    if (now < budget.next_allowed_ms) {
      throw new RpcError("COOLDOWN_ACTIVE", { retryAtMs: budget.next_allowed_ms, state: s.state });
    }
    const updated = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      const c = this.loadCard(handoffId)!;
      c.state = "VERIFYING";
      c.attempts += 1;
      cur.control.verification = "handoff";
      this.commitEvent(cur, { event: "handoff.verifying", to: "VERIFYING" });
      c.session_revision = cur.revision;
      this.saveCard(c);
      this.saveSession(cur);
      return c;
    });
    this.track(this.finishHandoffVerify(s.id, s.fence, handoffId));
    return updated;
  }

  private async finishHandoffVerify(sessionId: string, fence: number, handoffId: string): Promise<void> {
    try {
      // "ready" may arrive before the human context finishes opening.
      const openTask = this.handoffOpenTasks.get(sessionId);
      if (openTask) {
        this.handoffOpenTasks.delete(sessionId);
        await openTask;
      }
      const s = this.loadSession(sessionId)!;
      const site = this.loadSite(s.siteId)!;
      const ctx = this.contexts.get(sessionId);
      if (!ctx) throw new RpcError("INTERNAL");
      const probe = await this.adapter.probe(ctx, site.policy.core);
      const expected = this.accountExpected(site.policy.core);
      const { observation } = observationFromProbe(probe, site.policy.core, expected, this.now());
      if (probeVerified(observation) && site.policy.hash === this.loadSite(s.siteId)!.policy.hash) {
        const intentTip = this.commitAndPin([sessionId], () => {
          const cur = this.loadSession(sessionId)!;
          if (cur.state !== "VERIFYING" || cur.control.verification !== "handoff") return null;
          this.commitEvent(cur, { event: "snapshot.intent", to: "VERIFYING" });
          return this.audit.tip(sessionId);
        });
        if (intentTip === null) return;
        await this.verifyCapture(sessionId, fence, ctx, intentTip, "handoff.completed");
      } else {
        this.commitAndPin([sessionId], () => {
          const cur = this.loadSession(sessionId)!;
          if (cur.state !== "VERIFYING" || cur.control.verification !== "handoff") return;
          const card = this.loadCard(handoffId)!;
          const cls = classify(observation) === "NONE" ? "UNKNOWN" : classify(observation);
          const recoverable = isRetryableBlock(cls, observation.network) ||
            cls === "LOGIN_WALL" || cls === "ACCOUNT_MISMATCH" || cls === "ACCESS_DENIED" || cls === "UNKNOWN";
          if (!recoverable || card.attempts >= 2) {
            // second failed verification or nonrecoverable → card expires
            card.state = "EXPIRED";
            this.commitEvent(cur, { event: "block.detected", to: "HANDOFF_WAIT", blockClass: cls as Exclude<BlockClass, "NONE"> });
            cur.block = {
              class: cls as Exclude<BlockClass, "NONE">, revision: cur.revision, attempt: card.attempts,
              retry_at_ms: null, fallback_used: false,
              observation: { ...observation, retry_after: null },
            };
            this.commitEvent(cur, { event: "handoff.expired", to: "NEEDS_LOGIN" });
            card.session_revision = cur.revision;
            this.saveCard(card);
            this.saveSession(cur);
          } else {
            card.state = "PENDING";
            this.commitEvent(cur, { event: "block.detected", to: "HANDOFF_WAIT", blockClass: cls as Exclude<BlockClass, "NONE"> });
            cur.block = {
              class: cls as Exclude<BlockClass, "NONE">, revision: cur.revision, attempt: card.attempts,
              retry_at_ms: null, fallback_used: false,
              observation: { ...observation, retry_after: null },
            };
            card.session_revision = cur.revision;
            this.saveCard(card);
            this.saveSession(cur);
          }
        });
        const ctx2 = this.contexts.get(sessionId);
        if (ctx2) {
          this.contexts.delete(sessionId);
          void this.adapter.destroy(ctx2).catch(() => {});
        }
      }
    } catch (e) {
      this.failVerification(sessionId, fence, e instanceof RpcError ? e.code : "INTERNAL", null);
    }
  }

  // ------------------------------------------------------------ lifecycle

  revoke(sessionId: string): { state: "REVOKED"; audit_seq: number; cloud_delete_pending: boolean } {
    this.gateOk();
    this.tickIfDue();
    const s = this.mustSession(sessionId);
    if (TERMINAL.includes(s.state)) throw new RpcError("STATE_CONFLICT", { state: s.state });
    return this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      const newGen = cur.generation + 1;
      const rec = this.commitEvent(cur, { event: "session.revoked", to: "REVOKED", generation: newGen });
      const card = cur.handoffId ? this.loadCard(cur.handoffId) : this.cardForSession(cur.id);
      if (card && (card.state === "PENDING" || card.state === "OPEN" || card.state === "VERIFYING")) {
        card.state = "CANCELLED";
        card.session_revision = cur.revision;
        this.saveCard(card);
      }
      cur.handoffId = null;
      this.saveSession(cur);
      let pending = 0;
      if (this.vaultMode === "hosted") {
        this.enqueueTombstone(cur);
        pending = this.pendingTombstones(cur.id);
      }
      return { state: "REVOKED" as const, audit_seq: rec.core.seq, cloud_delete_pending: pending > 0 };
    });
  }

  private pendingTombstones(sessionId: string): number {
    const r = this.store.get(
      "SELECT COUNT(*) AS n FROM outbox WHERE session_id=? AND kind='vault_tombstone'", sessionId,
    );
    return (r?.n as number) ?? 0;
  }

  private enqueueTombstone(s: Sess): void {
    const head: VaultHead = signEnvelope("vault", {
      v: 1, session_id: s.id, device_id: this.device.deviceId,
      generation: s.generation, deleted: true, snapshot: null,
      signing_key_id: this.device.signingKeyId,
    }, this.device.signingSeed);
    const payload = aesCacheEncrypt(this.device.cacheKey, jcsBytes(head));
    this.store.run(
      "INSERT INTO outbox(id,kind,session_id,payload_cipher,next_try_ms,attempts) VALUES(?,?,?,?,?,0)",
      this.id("gq"), "vault_tombstone", s.id, payload, this.now(),
    );
    this.store.run(
      "INSERT INTO vault_sync(session_id,etag,generation,pending_delete,last_error) VALUES(?,?,?,1,NULL) ON CONFLICT(session_id) DO UPDATE SET pending_delete=1",
      s.id, this.syncRow(s.id)?.etag ?? null, s.generation,
    );
  }

  private syncRow(sessionId: string): { etag: string | null; generation: number; pending_delete: number } | null {
    const r = this.store.get("SELECT * FROM vault_sync WHERE session_id=?", sessionId);
    if (!r) return null;
    return { etag: r.etag as string | null, generation: r.generation as number, pending_delete: r.pending_delete as number };
  }

  deleteSession(sessionId: string, confirmGeneration: number): { state: "DELETED"; audit_seq: number; cloud_delete_pending: boolean } {
    this.gateOk();
    this.tickIfDue();
    const s = this.mustSession(sessionId);
    if (s.state !== "REVOKED") throw new RpcError("STATE_CONFLICT", { state: s.state });
    if (confirmGeneration !== s.generation) throw new RpcError("STALE_GENERATION", { state: s.state });
    return this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      const rec = this.commitEvent(cur, { event: "session.deleted", to: "DELETED" });
      // Erase cipher + session encryption key; retain tombstone + audit proof.
      this.store.run("DELETE FROM snapshots WHERE session_id=?", cur.id);
      const keyId = this.store.getMeta(`enckey:${cur.id}`);
      if (keyId) this.keychain.delete(`ghostsession/encryption/${keyId.toString()}`);
      this.saveSession(cur);
      const pending = this.vaultMode === "hosted" ? this.pendingTombstones(cur.id) : 0;
      return { state: "DELETED" as const, audit_seq: rec.core.seq, cloud_delete_pending: pending > 0 };
    });
  }

  auditList(sessionId: string, afterSeq: number, limit: number): AuditPage {
    const s = this.loadSession(sessionId);
    if (!s) throw new RpcError("NOT_FOUND");
    return this.audit.page(sessionId, afterSeq, limit);
  }

  // ------------------------------------------------------------------ vault

  async vaultSync(sessionId: string, mode: "upload" | "restore"): Promise<{ generation: number; status: "synced" | "unchanged"; cloud_delete_pending: boolean }> {
    this.gateOk();
    this.tickIfDue();
    if (this.vaultMode !== "hosted" || !this.vaultTransport) throw new RpcError("FORBIDDEN");
    const s = this.mustSession(sessionId);
    if (s.state === "QUARANTINED") throw new RpcError("INTEGRITY_FAILED", { state: s.state });
    if (s.state === "DELETED") throw new RpcError("STATE_CONFLICT", { state: s.state });
    if (mode === "upload") return this.vaultUpload(s);
    return this.vaultRestore(s);
  }

  private async vaultUpload(s: Sess): Promise<{ generation: number; status: "synced" | "unchanged"; cloud_delete_pending: boolean }> {
    const sync = this.syncRow(s.id);
    let head: VaultHead;
    if (s.state === "REVOKED") {
      head = signEnvelope("vault", {
        v: 1, session_id: s.id, device_id: this.device.deviceId,
        generation: s.generation, deleted: true, snapshot: null,
        signing_key_id: this.device.signingKeyId,
      }, this.device.signingSeed);
    } else {
      const snap = this.snapshotRow(s.id);
      if (!snap || snap.generation !== s.generation) throw new RpcError("NOT_READY", { state: s.state });
      head = signEnvelope("vault", {
        v: 1, session_id: s.id, device_id: this.device.deviceId,
        generation: s.generation, deleted: false, snapshot: snap.cipher,
        signing_key_id: this.device.signingKeyId,
      }, this.device.signingSeed);
    }
    if (sync && sync.generation === s.generation && !sync.pending_delete && s.state !== "REVOKED") {
      return { generation: s.generation, status: "unchanged", cloud_delete_pending: this.pendingTombstones(s.id) > 0 };
    }
    const cond = sync?.etag
      ? { ifMatch: sync.etag, ifNoneMatch: null }
      : { ifMatch: null, ifNoneMatch: "*" as const };
    const proof = this.deviceRequestProof("PUT", `/v1/vault/${s.id}`, { head });
    const res = await this.vaultTransport!.put(s.id, head, cond, proof);
    if (res.status === 200) {
      const etag = res.etag ?? `"${head.hash}"`;
      this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        this.store.run(
          "INSERT INTO vault_sync(session_id,etag,generation,pending_delete,last_error) VALUES(?,?,?,0,NULL) ON CONFLICT(session_id) DO UPDATE SET etag=excluded.etag,generation=excluded.generation,pending_delete=0,last_error=NULL",
          s.id, etag, s.generation,
        );
        this.store.run("DELETE FROM outbox WHERE session_id=? AND kind='vault_tombstone'", s.id);
        this.commitEvent(cur, { event: "vault.synced", to: cur.state });
      });
      return { generation: s.generation, status: "synced", cloud_delete_pending: false };
    }
    this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      this.commitEvent(cur, { event: "vault.conflict", to: cur.state, code: "VAULT_CONFLICT" });
    });
    throw new RpcError("VAULT_CONFLICT", { state: s.state });
  }

  private async vaultRestore(s: Sess): Promise<{ generation: number; status: "synced" | "unchanged"; cloud_delete_pending: boolean }> {
    if (s.state === "REVOKED" || s.state === "DELETED") throw new RpcError("STATE_CONFLICT", { state: s.state });
    if (s.state !== "DETACHED" && s.state !== "NEEDS_LOGIN") {
      throw new RpcError("NOT_READY", { state: s.state });
    }
    const proof = this.deviceRequestProof("GET", `/v1/vault/${s.id}`, null);
    const res = await this.vaultTransport!.get(s.id, proof);
    if (res.status !== 200) throw new RpcError("VAULT_CONFLICT", { state: s.state });
    const body = res.body as { head: VaultHead; etag: string };
    const head = body.head;
    // Verify signature under own identity key and bindings.
    if (head.core.session_id !== s.id || head.core.device_id !== this.device.deviceId ||
        head.core.signing_key_id !== this.device.signingKeyId) {
      throw new RpcError("INTEGRITY_FAILED");
    }
    if (!ed25519Verify(this.device.signingPub, domainMessage("vault", head.hash), b64Decode(head.signature))) {
      throw new RpcError("INTEGRITY_FAILED");
    }
    if (jcsHash(head.core) !== head.hash) throw new RpcError("INTEGRITY_FAILED");
    if (head.core.deleted) {
      this.commitAndPin([s.id], () => {
        const cur = this.loadSession(s.id)!;
        this.commitEvent(cur, { event: "vault.conflict", to: cur.state, code: "VAULT_CONFLICT" });
      });
      throw new RpcError("VAULT_CONFLICT", { state: s.state });
    }
    if (head.core.generation < s.generation) {
      return { generation: s.generation, status: "unchanged", cloud_delete_pending: false };
    }
    const cipher = head.core.snapshot!;
    // Decrypt + validate fully (we hold the key).
    const keyId = cipher.header.key_id;
    const key = this.keychain.get(`ghostsession/encryption/${keyId}`);
    if (key === null) throw new RpcError("KEY_UNAVAILABLE");
    const plain = decryptSnapshot(cipher, key, {
      sessionId: s.id, siteId: s.siteId, deviceId: this.device.deviceId,
      generation: head.core.generation,
      policyHash: this.loadSite(s.siteId)!.policy.hash,
      nowMs: this.now(),
      auditAnchorHash: (seq) => this.auditHashAt(s.id, seq),
    });
    void plain;
    return this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      this.store.run(
        "INSERT INTO snapshots(session_id,generation,key_id,cipher_json,cipher_hash) VALUES(?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET generation=excluded.generation,key_id=excluded.key_id,cipher_json=excluded.cipher_json,cipher_hash=excluded.cipher_hash",
        s.id, head.core.generation, keyId, jcsBytes(cipher), cipherHash(cipher),
      );
      cur.snapshotEligible = this.now() < cipher.header.expires_ms;
      cur.expiresMs = cipher.header.expires_ms;
      const to = cur.state === "NEEDS_LOGIN" && cur.snapshotEligible ? "DETACHED" : cur.state;
      this.commitEvent(cur, { event: "vault.synced", to, generation: head.core.generation });
      this.store.run(
        "INSERT INTO vault_sync(session_id,etag,generation,pending_delete,last_error) VALUES(?,?,?,0,NULL) ON CONFLICT(session_id) DO UPDATE SET etag=excluded.etag,generation=excluded.generation,pending_delete=0,last_error=NULL",
        s.id, body.etag, head.core.generation,
      );
      this.store.setMeta(`enckey:${s.id}`, Buffer.from(keyId));
      this.saveSession(cur);
      return { generation: head.core.generation, status: "synced", cloud_delete_pending: false };
    });
  }

  private deviceRequestProof(method: "GET" | "PUT" | "POST", path: string, body: unknown): unknown {
    if (!this.device.requestKeyId || !this.device.requestSeed) throw new RpcError("FORBIDDEN");
    const now = this.now();
    const bodyHash = method === "GET"
      ? sha256Hex(Buffer.alloc(0))
      : sha256Hex(jcsBytes(body));
    const core = {
      v: 1, actor_id: this.device.ownerId, device_id: this.device.deviceId,
      key_id: this.device.requestKeyId, method, path, body_hash: bodyHash,
      nonce: b64Encode(freshNonce16()), issued_ms: now, expires_ms: now + 60_000,
      if_match: null, if_none_match: null,
    };
    const env = signEnvelope("request", core, this.device.requestSeed);
    return { core: env.core, signature: env.signature };
  }

  async vaultRotate(sessionId: string): Promise<{ generation: number; key_id: string; audit_seq: number }> {
    this.gateOk();
    this.tickIfDue();
    const s = this.mustSession(sessionId);
    if (s.state === "QUARANTINED") throw new RpcError("INTEGRITY_FAILED", { state: s.state });
    if (s.state === "REVOKED" || s.state === "DELETED") throw new RpcError("STATE_CONFLICT", { state: s.state });
    if (s.state !== "DETACHED") throw new RpcError("NOT_READY", { state: s.state });
    const snap = this.snapshotRow(s.id);
    if (!snap) throw new RpcError("NOT_READY", { state: s.state });
    if (!this.eligibleSnapshot(s)) throw new RpcError("SNAPSHOT_EXPIRED", { state: s.state });
    const oldKey = this.keychain.get(`ghostsession/encryption/${snap.keyId}`);
    if (oldKey === null) throw new RpcError("KEY_UNAVAILABLE");
    const site = this.loadSite(s.siteId)!;
    const plain = decryptSnapshot(snap.cipher, oldKey, {
      sessionId: s.id, siteId: s.siteId, deviceId: this.device.deviceId,
      generation: s.generation, policyHash: site.policy.hash,
      nowMs: this.now(),
      auditAnchorHash: (seq) => this.auditHashAt(s.id, seq),
    });
    const newKeyId = this.id("ge");
    const newKey = freshKey();
    const nextGen = s.generation + 1;
    const intent = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      this.commitEvent(cur, { event: "snapshot.intent", to: "DETACHED" });
      return this.audit.tip(s.id);
    });
    const newPlain: SnapshotPlain = { ...plain, generation: nextGen, audit_seq: intent.seq, audit_hash: String(intent.hash) };
    const cipher = encryptSnapshot(newPlain, newKey, {
      deviceId: this.device.deviceId, policyHash: site.policy.hash, keyId: newKeyId, nonce: freshNonce(),
    });
    const out = this.commitAndPin([s.id], () => {
      const cur = this.loadSession(s.id)!;
      this.keychain.set(`ghostsession/encryption/${newKeyId}`, newKey);
      this.store.run(
        "INSERT INTO snapshots(session_id,generation,key_id,cipher_json,cipher_hash) VALUES(?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET generation=excluded.generation,key_id=excluded.key_id,cipher_json=excluded.cipher_json,cipher_hash=excluded.cipher_hash",
        s.id, nextGen, newKeyId, jcsBytes(cipher), cipherHash(cipher),
      );
      this.commitEvent(cur, { event: "snapshot.committed", to: "DETACHED", generation: nextGen, cipherHash: cipherHash(cipher) });
      const rec = this.commitEvent(cur, { event: "key.rotated", to: "DETACHED" });
      this.store.setMeta(`enckey:${s.id}`, Buffer.from(newKeyId));
      this.saveSession(cur);
      return { generation: nextGen, key_id: newKeyId, audit_seq: rec.core.seq };
    });
    // Retire old key only after atomic commit.
    this.keychain.delete(`ghostsession/encryption/${snap.keyId}`);
    return out;
  }

  // ------------------------------------------------------- daemon recovery

  /** Startup debris resolution (spec §5 sequencing). Runs before serving. */
  recoverDaemon(): void {
    this.initClockGate();
    if (this.clockUnsafe) return;
    this.store.txn(() => {
      const rows = this.store.all("SELECT id FROM sessions");
      for (const r of rows) {
        const s = this.loadSession(r.id as string)!;
        // 1. DISPATCHED operation without durable result → UNCERTAIN.
        const dispatched = this.store.all(
          "SELECT operation_id FROM operations WHERE session_id=? AND state='DISPATCHED'", s.id,
        );
        if (dispatched.length > 0 && CONTEXT_STATES.includes(s.state)) {
          for (const op of dispatched) {
            this.markOperationUnknown(s, op.operation_id as string);
            s.control.unresolved_operations.push(op.operation_id as string);
          }
          s.control.active_operation = null;
          s.control.dispatched = false;
          this.commitEvent(s, { event: "action.unknown", to: "UNCERTAIN" });
          continue;
        }
        // 2. Unfinished snapshot intent → snapshot.failed.
        const tip = this.audit.tip(s.id);
        if (tip.seq > 0) {
          const last = this.store.get(
            "SELECT receipt_json FROM receipts WHERE session_id=? AND seq=?", s.id, tip.seq,
          );
          const lastEvent = last
            ? (JSON.parse(Buffer.from(last.receipt_json as Uint8Array).toString("utf8")) as Receipt).core.event
            : null;
          if (lastEvent === "snapshot.intent" && s.state !== "QUARANTINED" && s.state !== "DELETED") {
            this.commitEvent(s, { event: "snapshot.failed", to: s.state, code: "INTERNAL" });
          }
        }
        // 3. OPEN cards return to PENDING on restart.
        if (s.state === "HANDOFF_WAIT" && s.handoffId) {
          const card = this.loadCard(s.handoffId);
          if (card && card.state === "OPEN") {
            card.state = "PENDING";
            this.saveCard(card);
          }
        }
        // 4. daemon.recovered per state row.
        if (CONTEXT_STATES.includes(s.state)) {
          // handoff-purpose VERIFYING: finalize card CANCELLED.
          if (s.state === "VERIFYING" && s.control.verification === "handoff" && s.handoffId) {
            const card = this.loadCard(s.handoffId);
            if (card) {
              card.state = "CANCELLED";
              this.saveCard(card);
            }
            s.handoffId = null;
          }
          const to = this.eligibleSnapshot(s) ? "DETACHED" : "NEEDS_LOGIN";
          this.commitEvent(s, { event: "daemon.recovered", to });
        } else if (s.state === "REVOKED" || s.state === "DELETED" || s.state === "QUARANTINED") {
          // Verify chain; corruption quarantines.
          if (!this.verifyChainIntact(s.id) && s.state !== "QUARANTINED") {
            this.commitEvent(s, { event: "session.quarantined", to: "QUARANTINED", code: "INTEGRITY_FAILED" });
          }
        } else {
          this.commitEvent(s, { event: "daemon.recovered", to: s.state });
        }
      }
    });
    this.pinAllTips();
  }

  private verifyChainIntact(sessionId: string): boolean {
    const rows = this.store.all(
      "SELECT receipt_json FROM receipts WHERE session_id=? ORDER BY seq", sessionId,
    );
    let prev = "0".repeat(64);
    for (const r of rows) {
      const rec = JSON.parse(Buffer.from(r.receipt_json as Uint8Array).toString("utf8")) as Receipt;
      if (rec.core.previous_hash !== prev || rec.hash !== jcsHash(rec.core)) return false;
      prev = rec.hash;
    }
    // Shorter chain than the pinned tip → quarantine evidence.
    const pinned = this.keychain.get(`ghostsession/audit-tip/${sessionId}`);
    if (pinned) {
      const tip = JSON.parse(pinned.toString("utf8")) as { seq: number; hash: string };
      const local = this.audit.tip(sessionId);
      if (local.seq < tip.seq) return false;
    }
    return true;
  }

  /** SIGTERM: deny new actions, brief wait, checkpoint idle ACTIVE, invalidate. */
  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    await Promise.race([this.drain(), new Promise((r) => setTimeout(r, 5_000))]);
    this.store.txn(() => {
      for (const r of this.store.all("SELECT id FROM sessions WHERE state='ACTIVE'")) {
        const s = this.loadSession(r.id as string)!;
        if (s.control.active_operation === null && this.contexts.has(s.id)) {
          try {
            this.runCheckpoint(s, this.contexts.get(s.id)!);
          } catch { /* best effort */ }
        }
      }
      for (const r of this.store.all("SELECT id FROM sessions WHERE state IN ('ACTIVE','ATTACHING','VERIFYING')")) {
        const s = this.loadSession(r.id as string)!;
        if (CONTEXT_STATES.includes(s.state)) {
          this.commitEvent(s, { event: "lease.expired", to: this.eligibleSnapshot(s) ? "DETACHED" : "NEEDS_LOGIN" });
        }
      }
    });
    this.pinAllTips();
  }

  /** Outbox delivery pass (daemon background task). */
  async flushOutbox(): Promise<void> {
    const now = this.now();
    const due = this.store.all("SELECT * FROM outbox WHERE next_try_ms <= ? ORDER BY rowid LIMIT 50", now);
    for (const row of due) {
      if (row.kind === "handoff_card" && this.inboxAdapter) {
        try {
          const card = parseStrictJson(aesCacheDecrypt(this.device.cacheKey, Buffer.from(row.payload_cipher as Uint8Array)));
          const res = await this.inboxAdapter.deliver(card);
          if (res.status === "delivered" || res.status === "duplicate") {
            this.store.run("DELETE FROM outbox WHERE id=?", row.id as string);
            continue;
          }
        } catch { /* fall through to retry */ }
      } else if (row.kind === "vault_tombstone" && this.vaultTransport) {
        try {
          const head = parseStrictJson(aesCacheDecrypt(this.device.cacheKey, Buffer.from(row.payload_cipher as Uint8Array))) as unknown as VaultHead;
          const sync = this.syncRow(row.session_id as string);
          const proof = this.deviceRequestProof("PUT", `/v1/vault/${row.session_id}`, { head });
          const res = await this.vaultTransport.put(row.session_id as string, head, {
            ifMatch: sync?.etag ?? null, ifNoneMatch: sync?.etag ? null : "*",
          }, proof);
          if (res.status === 200) {
            this.store.run("DELETE FROM outbox WHERE id=?", row.id as string);
            this.store.run(
              "INSERT INTO vault_sync(session_id,etag,generation,pending_delete,last_error) VALUES(?,?,?,0,NULL) ON CONFLICT(session_id) DO UPDATE SET etag=excluded.etag,pending_delete=0,last_error=NULL",
              row.session_id as string, res.etag ?? `"${head.hash}"`,
            );
            continue;
          }
        } catch { /* retry below */ }
      } else {
        // No adapter configured: card stays local-authoritative; keep until expiry.
        this.store.run("DELETE FROM outbox WHERE id=? AND kind='handoff_card'", row.id as string);
        continue;
      }
      const attempts = (row.attempts as number) + 1;
      const backoffMs = attempts <= 1 ? 5_000 : attempts === 2 ? 30_000 : attempts === 3 ? 120_000 : 300_000;
      this.store.run("UPDATE outbox SET next_try_ms=?, attempts=? WHERE id=?", now + backoffMs, attempts, row.id as string);
    }
  }
}

// --------------------------------------------------------------- utilities

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { validateSelector } from "./net/origin.js";

function freshKey(): Buffer {
  return randomBytes(32);
}

function freshNonce16(): Buffer {
  return randomBytes(16);
}

function aesCacheEncrypt(key: Buffer, plain: Buffer): Buffer {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}

function aesCacheDecrypt(key: Buffer, blob: Buffer): Buffer {
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
