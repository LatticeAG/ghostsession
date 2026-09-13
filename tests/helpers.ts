/**
 * Conformance harness — fixture-backed deterministic Engine construction.
 * Sequential IDs make the engine's first-run artifacts byte-comparable to
 * tests/fixtures.json (gs_…1, gh_…1, gv_…1 …) when the event order matches.
 */

import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { Engine, TestClock, type DeviceIdentity, type EngineHooks, type VaultTransport } from "../src/engine.js";
import { Store } from "../src/store/database.js";
import { MemoryKeychain } from "../src/store/keychain.js";
import { ScriptedAdapter, type AdapterScript } from "../src/browser/scripted.js";
import { Dispatcher, type TrustedKey } from "../src/rpc.js";
import { b64Decode, b64Encode } from "../src/encoding/b64.js";
import { jcsBytes, jcsString } from "../src/encoding/jcs.js";
import { sha256Hex, jcsHash, domainMessage, signEnvelope } from "../src/crypto/envelope.js";
import { ed25519PublicFromSeed, ed25519Sign } from "../src/crypto/ed25519.js";
import type { IdPrefix } from "../src/ids.js";
import type { Observation, SessionView, SignedPolicy, VaultHead } from "../src/schema.js";

export interface Fx {
  ids: Record<string, string>;
  now: number;
  keys: Record<string, string>;
  policy_core: Record<string, unknown>;
  policy: SignedPolicy;
  policy_hash: string;
  receipt_envelope: { core: Record<string, unknown>; hash: string; signature: string };
  audit7: { core: Record<string, unknown>; hash: string; signature: string }[];
  snapshot_plain: Record<string, unknown>;
  cipher_header: Record<string, unknown>;
  cipher_snapshot: { header: Record<string, unknown>; algorithm: string; nonce: string; ciphertext: string };
  vault_head: VaultHead;
  vg2: VaultHead;
  vg3: VaultHead;
  vg4_tombstone: VaultHead;
  vg5: VaultHead;
  lease: { lease_id: string; run_id: string; actor_id: string; fence: number; expires_ms: number };
  card: Record<string, unknown>;
  base_obs: Observation;
  good_cookie: Record<string, unknown>;
  block1: Record<string, unknown>;
  ready_input: Record<string, unknown>;
  trust_file: Record<string, unknown>;
  requests: { q4: Record<string, unknown> };
  proof_q4: { core: Record<string, unknown>; signature: string };
  inbox_card: Record<string, unknown>;
}

export const fx: Fx = JSON.parse(
  readFileSync(new URL("./fixtures.json", import.meta.url), "utf8"),
) as Fx;

export const NOW = fx.now;
export const IDS = fx.ids;

export function obs(patch: Partial<Observation> = {}): Observation {
  return { ...fx.base_obs, ...patch };
}

export function seed(name: string): Buffer {
  return b64Decode(fx.keys[name]!);
}

export function deviceIdentity(): DeviceIdentity {
  const signingSeed = seed("sk_seed_b64");
  return {
    deviceId: IDS.D!, ownerId: IDS.A!, signingKeyId: IDS.K!,
    signingSeed,
    signingPub: ed25519PublicFromSeed(signingSeed),
    auditKey: Buffer.alloc(32, 0xa1), cacheKey: Buffer.alloc(32, 0xc1),
    requestKeyId: "gk_000000000000000000003",
    requestSeed: seed("auth_seed_b64"),
  };
}

export function sequentialIds(): (p: IdPrefix) => string {
  const counters = new Map<string, number>();
  return (p: IdPrefix) => {
    const n = (counters.get(p) ?? 0) + 1;
    counters.set(p, n);
    return `${p}_${String(n).padStart(21, "0")}`;
  };
}

export interface Harness {
  store: Store;
  keychain: MemoryKeychain;
  adapter: ScriptedAdapter;
  clock: TestClock;
  engine: Engine;
  device: DeviceIdentity;
  dir: string;
}

export function makeHarness(
  script: AdapterScript = {},
  opts: {
    hooks?: EngineHooks;
    vaultMode?: "local" | "hosted";
    vaultTransport?: VaultTransport | null;
    dbPath?: string;
    keychain?: MemoryKeychain;
    clockStart?: number;
    adapterResolve?: (h: string) => string;
  } = {},
): Harness {
  const dir = mkdtempSync(join(tmpdir(), "gs-test-"));
  const store = new Store(opts.dbPath ?? ":memory:");
  const keychain = opts.keychain ?? new MemoryKeychain();
  keychain.set(`ghostsession/account/${IDS.T}`, Buffer.from("owner-17"));
  const adapter = new ScriptedAdapter(
    structuredClone(script) as AdapterScript, { resolve: opts.adapterResolve },
  );
  const clock = new TestClock(opts.clockStart ?? NOW);
  const device = deviceIdentity();
  const engine = new Engine({
    store, keychain, adapter, clock, device,
    vaultMode: opts.vaultMode ?? "local",
    vaultTransport: opts.vaultTransport ?? null,
    originOpts: { publicDnsOnly: false },
    hooks: opts.hooks,
    ids: sequentialIds(),
  });
  return { store, keychain, adapter, clock, engine, device, dir };
}

/** Owner puts the fixture policy and creates the session → HANDOFF_WAIT. */
export function enroll(h: Harness): SessionView {
  h.engine.putSite(fx.policy);
  return h.engine.createSession(IDS.T!);
}

/** Drive an open card to DETACHED generation 1 with a successful probe. */
export async function completeHandoff(h: Harness, sid: string): Promise<SessionView> {
  const s = h.engine.getSession(sid);
  h.engine.openHandoff(s.handoff_id!);
  h.engine.resolveHandoff(s.handoff_id!, "ready");
  await h.engine.drain();
  return h.engine.getSession(sid);
}

/** attach → drain → ACTIVE; returns the session view with lease/fence. */
export async function attachActive(h: Harness, sid: string): Promise<SessionView> {
  const v = h.engine.attach(sid, IDS.R!, 1, IDS.A!);
  await h.engine.drain();
  return h.engine.getSession(sid);
}

/** Full happy path: enroll → handoff → attach. Session is ACTIVE. */
export async function activeSession(h: Harness): Promise<SessionView> {
  const s = enroll(h);
  const d = await completeHandoff(h, s.session_id);
  return attachActive(h, d.session_id);
}

// ---------------------------------------------------------------- proofs

export function makeProof(opts: {
  method: "GET" | "PUT" | "POST";
  path: string;
  body: unknown | null;
  nonce: number;
  relay?: boolean;
  ifMatch?: string | null;
  ifNoneMatch?: "*" | null;
  issuedMs?: number;
  keyId?: string;
  seedKey?: string;
  actorId?: string;
  deviceId?: string;
}): { core: Record<string, unknown>; signature: string } {
  const bodyHash = opts.method === "GET"
    ? sha256Hex(Buffer.alloc(0))
    : sha256Hex(jcsBytes(opts.body));
  const core = {
    v: 1,
    actor_id: opts.actorId ?? IDS.A!,
    device_id: opts.deviceId ?? IDS.D!,
    key_id: opts.keyId ?? (opts.relay ? "gk_000000000000000000002" : "gk_000000000000000000003"),
    method: opts.method,
    path: opts.path,
    body_hash: bodyHash,
    nonce: b64Encode(Buffer.from(new BigUint64Array([0n, BigInt(opts.nonce)]).buffer)),
    issued_ms: opts.issuedMs ?? NOW,
    expires_ms: (opts.issuedMs ?? NOW) + 60_000,
    if_match: opts.ifMatch ?? null,
    if_none_match: opts.ifNoneMatch ?? null,
  };
  const env = signEnvelope("request", core, seed(opts.seedKey ?? (opts.relay ? "relay_seed_b64" : "auth_seed_b64")));
  return { core: env.core as Record<string, unknown>, signature: env.signature };
}

export function proofHeader(p: { core: unknown; signature: string }): Buffer {
  return Buffer.from(jcsString(p), "utf8");
}

export function rpcBody(id: string, method: string, params: unknown): Buffer {
  return jcsBytes({ v: 1, id, method, params });
}

export function trustedKeys(): TrustedKey[] {
  return [
    {
      key_id: "gk_000000000000000000003", purpose: "request",
      public_key: fx.keys.auth_pub_b64!, actor_id: IDS.A!, sessions: [IDS.S!],
    },
    {
      key_id: "gk_000000000000000000002", purpose: "relay",
      public_key: fx.keys.relay_pub_b64!, actor_id: IDS.A!, sessions: [],
    },
    {
      key_id: IDS.K!, purpose: "receipt",
      public_key: fx.keys.sk_pub_b64!, actor_id: IDS.A!, sessions: [],
    },
  ];
}

export function makeDispatcher(h: Harness): Dispatcher {
  return new Dispatcher(h.engine, trustedKeys(), () => h.clock.wall());
}

/** Signed response proof — as the daemon or relay would emit. */
export function responseProof(opts: {
  requestCore: unknown; status: number; body: Buffer; issuedMs?: number;
  relay?: boolean;
}): { core: Record<string, unknown>; signature: string } {
  const core = {
    v: 1, device_id: IDS.D!,
    signing_key_id: opts.relay ? "gk_000000000000000000002" : IDS.K!,
    request_hash: jcsHash(opts.requestCore),
    status: opts.status, body_hash: sha256Hex(opts.body), issued_ms: opts.issuedMs ?? NOW,
  };
  const env = signEnvelope("response", core, seed(opts.relay ? "relay_seed_b64" : "sk_seed_b64"));
  return { core: env.core as Record<string, unknown>, signature: env.signature };
}

export function signReq(opts: { domain: "request"; core: Record<string, unknown>; seedKey: string }) {
  const env = signEnvelope(opts.domain, opts.core, seed(opts.seedKey));
  return { core: env.core, signature: env.signature };
}

export { jcsBytes, jcsString, jcsHash, sha256Hex, domainMessage, ed25519Sign, b64Encode, b64Decode };

/** Run fn, return the thrown error's RpcError code (or a description). */
export function thrownCode(fn: () => unknown): string {
  try {
    fn();
    return "no-throw";
  } catch (e) {
    return e instanceof Error && "code" in e ? String((e as { code: unknown }).code) : `threw ${e}`;
  }
}

/** Await p, returning the rejection's RpcError code or "ok". */
export async function asyncCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof Error && "code" in e ? String((e as { code: unknown }).code) : `threw ${e}`;
  }
}
