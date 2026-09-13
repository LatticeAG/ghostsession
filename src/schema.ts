/**
 * Closed-schema validation for every protocol object (spec §4, §8, §9, §11).
 * Unknown properties fail; no coercion; nullable fields remain required.
 */

import { isValidId, type IdPrefix } from "./ids.js";
import { isCanonicalB64, b64Decode } from "./encoding/b64.js";
import { isErrorCode, type ErrorCode } from "./errors.js";

export const MAX_ORDINARY_STRING = 64 * 1024;
export const MAX_UINT = 9007199254740991;
// 4 MiB plaintext + 16-byte tag, canonical unpadded base64url length.
export const MAX_CIPHERTEXT_B64 = 5592448;

export class SchemaError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "SchemaError";
  }
}

type V<T> = (v: unknown, path: string) => T;

function fail(path: string, msg: string): never {
  throw new SchemaError(`${path}: ${msg}`);
}

export function vBool(v: unknown, p: string): boolean {
  if (typeof v !== "boolean") fail(p, "expected boolean");
  return v;
}

export function vUInt(v: unknown, p: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || v > MAX_UINT || Object.is(v, -0)) {
    fail(p, "expected non-negative safe integer");
  }
  return v;
}

export function vUIntBound(min: number, max: number): V<number> {
  return (v, p) => {
    const n = vUInt(v, p);
    if (n < min || n > max) fail(p, `out of range [${min},${max}]`);
    return n;
  };
}

export function vStr(v: unknown, p: string): string {
  if (typeof v !== "string") fail(p, "expected string");
  if (Buffer.byteLength(v, "utf8") > MAX_ORDINARY_STRING) fail(p, "string too large");
  return v;
}

export function vStrBound(maxBytes: number, minBytes = 0): V<string> {
  return (v, p) => {
    if (typeof v !== "string") fail(p, "expected string");
    const n = Buffer.byteLength(v, "utf8");
    if (n > maxBytes || n < minBytes) fail(p, `byte length out of range [${minBytes},${maxBytes}]`);
    return v;
  };
}

export function vLiteral<T extends string | number | boolean>(lit: T): V<T> {
  return (v, p) => {
    if (v !== lit) fail(p, `expected ${JSON.stringify(lit)}`);
    return lit;
  };
}

export function vEnum<T extends string>(...lits: readonly T[]): V<T> {
  const s = new Set<string>(lits);
  return (v, p) => {
    if (typeof v !== "string" || !s.has(v)) fail(p, `expected one of ${lits.join(",")}`);
    return v as T;
  };
}

export function vId(prefix: IdPrefix): V<string> {
  return (v, p) => {
    if (!isValidId(v, prefix)) fail(p, `expected ${prefix}_ id`);
    return v;
  };
}

export function vHash(v: unknown, p: string): string {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) fail(p, "expected 64-char lowercase hex");
  return v;
}

export function vB64(decodedLen?: number): V<string> {
  return (v, p) => {
    if (typeof v !== "string" || !isCanonicalB64(v)) fail(p, "expected canonical base64url");
    if (decodedLen !== undefined && b64Decode(v).length !== decodedLen) {
      fail(p, `expected ${decodedLen} decoded bytes`);
    }
    return v;
  };
}

export function vNullable<T>(inner: V<T>): V<T | null> {
  return (v, p) => (v === null ? null : inner(v, p));
}

export function vArr<T>(inner: V<T>, opts: { min?: number; max?: number; sortedUnique?: boolean } = {}): V<T[]> {
  return (v, p) => {
    if (!Array.isArray(v)) fail(p, "expected array");
    if (opts.min !== undefined && v.length < opts.min) fail(p, `array shorter than ${opts.min}`);
    if (opts.max !== undefined && v.length > opts.max) fail(p, `array longer than ${opts.max}`);
    const out = v.map((e, i) => inner(e, `${p}[${i}]`));
    if (opts.sortedUnique) {
      for (let i = 1; i < out.length; i++) {
        const a = Buffer.from(String(out[i - 1]), "utf8");
        const b = Buffer.from(String(out[i]), "utf8");
        if (a.compare(b) >= 0) fail(p, "array not strictly sorted unique (UTF-8 order)");
      }
    }
    return out;
  };
}

export function vObj<T>(name: string, fields: Record<string, V<unknown>>): V<T> {
  const keys = Object.keys(fields);
  return (v, p) => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) fail(p, `${name}: expected object`);
    const rec = v as Record<string, unknown>;
    for (const k of Object.keys(rec)) {
      if (!(k in fields)) fail(`${p}.${k}`, `${name}: unknown property`);
    }
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      if (!(k in rec)) fail(`${p}.${k}`, `${name}: missing property`);
      out[k] = fields[k]!(rec[k], `${p}.${k}`);
    }
    return out as T;
  };
}

// ---------- scalars ----------
export type UInt = number;
export type Ms = UInt;
export type Hash = string;
export type B64 = string;
export type Signature = B64;
export type SessionId = string;
export type SiteId = string;
export type DeviceId = string;
export type ActorId = string;
export type RunId = string;
export type LeaseId = string;
export type OperationId = string;
export type HandoffId = string;
export type ReceiptId = string;
export type SigningKeyId = string;
export type EncryptionKeyId = string;
export type RequestId = string;
export type Origin = string;
export type RelativePath = string;

const vSessionId = vId("gs");
const vSiteId = vId("gt");
const vDeviceId = vId("gd");
const vActorId = vId("ga");
const vRunId = vId("gr");
const vLeaseId = vId("gl");
const vOperationId = vId("go");
const vHandoffId = vId("gh");
const vReceiptId = vId("gv");
const vSigningKeyId = vId("gk");
const vEncryptionKeyId = vId("ge");
const vRequestId = vId("gq");
const vOrigin = vStr;
const vRelativePath = vStrBound(MAX_ORDINARY_STRING, 1);
const vSelector = vStrBound(256, 1);

// ---------- session enums ----------
export const SESSION_STATES = [
  "NEEDS_LOGIN", "DETACHED", "ATTACHING", "ACTIVE", "COOLDOWN", "RECOVERABLE",
  "HANDOFF_WAIT", "VERIFYING", "UNCERTAIN", "EXPIRED", "REVOKED", "DELETED",
  "QUARANTINED",
] as const;
export type SessionState = (typeof SESSION_STATES)[number];
const vSessionState = vEnum(...SESSION_STATES);

export const BLOCK_CLASSES = [
  "NONE", "CF_CHALLENGE", "LOGIN_WALL", "RATE_LIMIT", "NETWORK_ERROR",
  "ACCESS_DENIED", "UNKNOWN", "ACCOUNT_MISMATCH", "SCOPE_DENIED",
] as const;
export type BlockClass = (typeof BLOCK_CLASSES)[number];
const vBlockClass = vEnum(...BLOCK_CLASSES);
const vBlockClassNonNone = vEnum(...(BLOCK_CLASSES.filter((c) => c !== "NONE") as Exclude<BlockClass, "NONE">[]));

export const HANDOFF_STATES = ["PENDING", "OPEN", "VERIFYING", "COMPLETED", "CANCELLED", "EXPIRED"] as const;
export type HandoffState = (typeof HANDOFF_STATES)[number];

export const EVENT_NAMES = [
  "session.created", "lease.acquired", "attach.verified", "lease.renewed",
  "action.intent", "action.finished", "action.denied", "action.unknown",
  "snapshot.intent", "snapshot.committed", "snapshot.failed", "session.detached",
  "lease.expired", "block.detected", "cooldown.elapsed", "recovery.started",
  "recovery.exhausted", "handoff.created", "handoff.opened", "handoff.verifying",
  "handoff.completed", "handoff.cancelled", "handoff.expired", "session.expired",
  "session.revoked", "session.deleted", "policy.changed", "daemon.recovered",
  "session.quarantined", "unknown.acknowledged", "vault.synced", "vault.conflict",
  "key.rotated",
] as const;
export type EventName = (typeof EVENT_NAMES)[number];
const vEventName = vEnum(...EVENT_NAMES);

// ---------- §4 domain ----------
export type AuthProbe = {
  path: RelativePath;
  logged_in_selector: string;
  logged_out_selector: string;
  account_selector: string;
  expected_account_ref: string;
};

export type RecoveryPolicy = {
  challenge_base_ms: Ms;
  rate_base_ms: Ms;
  network_base_ms: Ms;
  max_retry_delay_ms: Ms;
  max_server_wait_ms: Ms;
  max_automatic_probes: UInt;
  fallback_path: RelativePath | null;
  handoff_ttl_ms: Ms;
};

export type PolicyCore = {
  v: 1;
  site_id: SiteId;
  owner_id: ActorId;
  device_id: DeviceId;
  revision: UInt;
  origin: Origin;
  login_path: RelativePath;
  agent_paths: RelativePath[];
  login_origins: Origin[];
  resource_origins: Origin[];
  methods: ("GET" | "HEAD" | "POST")[];
  auth_probe: AuthProbe;
  recovery: RecoveryPolicy;
  snapshot_ttl_ms: Ms;
  persist_session_cookies: boolean;
  automation_authorized: true;
  consent_expires_ms: Ms;
  signing_key_id: SigningKeyId;
};

export type SignedPolicy = { core: PolicyCore; hash: Hash; signature: Signature };

export type Cookie = {
  name: string;
  value: string;
  host: string;
  path: RelativePath;
  secure: true;
  http_only: boolean;
  same_site: "Strict" | "Lax" | "None";
  expires_ms: Ms | null;
};

export type LocalPair = { name: string; value: string };
export type OriginStorage = { origin: Origin; local_storage: LocalPair[] };

export type SnapshotPlain = {
  v: 1;
  session_id: SessionId;
  site_id: SiteId;
  generation: UInt;
  saved_ms: Ms;
  expires_ms: Ms;
  cookies: Cookie[];
  origins: OriginStorage[];
  audit_seq: UInt;
  audit_hash: Hash;
};

export type CipherHeader = {
  v: 1;
  format: "chromium-storage-v1";
  session_id: SessionId;
  site_id: SiteId;
  device_id: DeviceId;
  generation: UInt;
  policy_hash: Hash;
  key_id: EncryptionKeyId;
  created_ms: Ms;
  expires_ms: Ms;
};

export type CipherSnapshot = {
  header: CipherHeader;
  algorithm: "A256GCM";
  nonce: B64;
  ciphertext: B64;
};

export type VaultHeadCore = {
  v: 1;
  session_id: SessionId;
  device_id: DeviceId;
  generation: UInt;
  deleted: boolean;
  snapshot: CipherSnapshot | null;
  signing_key_id: SigningKeyId;
};

export type VaultHead = { core: VaultHeadCore; hash: Hash; signature: Signature };

// ---------- §4.1 runtime ----------
export type Observation = {
  status: UInt | null;
  network: "ok" | "timeout" | "tls_error" | "dns_error" | "aborted" | "policy_denied";
  cf_mitigated: boolean;
  challenge_marker: boolean;
  login_marker: boolean;
  logged_in_marker: boolean;
  redirected_to_login: boolean;
  identity: "match" | "missing" | "mismatch" | "not_checked";
  retry_after: string | null;
  received_ms: Ms;
};

export type Block = {
  class: Exclude<BlockClass, "NONE">;
  revision: UInt;
  attempt: UInt;
  retry_at_ms: Ms | null;
  fallback_used: boolean;
  observation: Observation;
};

export type Lease = {
  lease_id: LeaseId;
  run_id: RunId;
  actor_id: ActorId;
  fence: UInt;
  expires_ms: Ms;
};

export type SessionView = {
  session_id: SessionId;
  site_id: SiteId;
  device_id: DeviceId;
  state: SessionState;
  revision: UInt;
  generation: UInt;
  policy_hash: Hash;
  lease: Lease | null;
  block: Block | null;
  handoff_id: HandoffId | null;
  expires_ms: Ms | null;
  audit_seq: UInt;
};

export type BrowserAction =
  | { kind: "navigate"; url: string }
  | { kind: "read"; selector: string; max_chars: UInt }
  | { kind: "click"; selector: string }
  | { kind: "fill"; selector: string; text: string };

export type ActionResult = {
  operation_id: OperationId;
  outcome: "SUCCEEDED" | "BLOCKED" | "DENIED" | "UNKNOWN";
  code: "OK" | ErrorCode;
  text: string | null;
  truncated: boolean;
  block_class: BlockClass;
  audit_seq: UInt;
};

export type Handoff = {
  handoff_id: HandoffId;
  session_id: SessionId;
  owner_id: ActorId;
  state: HandoffState;
  reason: "INITIAL_LOGIN" | "LOGIN_WALL" | "CF_CHALLENGE" | "ACCOUNT_MISMATCH" | "MANUAL";
  policy_hash: Hash;
  session_revision: UInt;
  created_ms: Ms;
  expires_ms: Ms;
  attempts: UInt;
  presentation: "local_browser_only";
};

// ---------- §4.2 receipts ----------
export type ReceiptCore = {
  v: 1;
  receipt_id: ReceiptId;
  session_id: SessionId;
  seq: UInt;
  previous_hash: Hash;
  recorded_ms: Ms;
  signing_key_id: SigningKeyId;
  actor_id: ActorId;
  operation_id: OperationId | null;
  event: EventName;
  from_state: SessionState;
  to_state: SessionState;
  revision: UInt;
  generation: UInt;
  fence: UInt;
  code: "OK" | ErrorCode;
  action_binding: Hash | null;
  cipher_hash: Hash | null;
  block_class: BlockClass;
};

export type Receipt = { core: ReceiptCore; hash: Hash; signature: Signature };

export type AuditPage = {
  entries: Receipt[];
  next_after_seq: UInt;
  tip_seq: UInt;
  tip_hash: Hash;
};

// ---------- §8 RPC ----------
export type RequestProofCore = {
  v: 1;
  actor_id: ActorId;
  device_id: DeviceId;
  key_id: SigningKeyId;
  method: "POST" | "GET" | "PUT";
  path: string;
  body_hash: Hash;
  nonce: B64;
  issued_ms: Ms;
  expires_ms: Ms;
  if_match: string | null;
  if_none_match: "*" | null;
};

export type ResponseProofCore = {
  v: 1;
  device_id: DeviceId;
  signing_key_id: SigningKeyId;
  request_hash: Hash;
  status: UInt;
  body_hash: Hash;
  issued_ms: Ms;
};

export type RequestProof = { core: RequestProofCore; signature: Signature };
export type ResponseProof = { core: ResponseProofCore; signature: Signature };

export type ForwardFrame = {
  v: 1;
  proof: RequestProof;
  relay: RequestProof;
  request: RpcRequest;
};

export type VaultWrite = { head: VaultHead };
export type VaultResult = { head: VaultHead; etag: string };

export type RpcRequest = {
  v: 1;
  id: RequestId;
  method: string;
  params: unknown;
};

export type RpcSuccess<T> = { v: 1; id: RequestId; ok: true; result: T };
export type RpcFailureBody = {
  v: 1;
  id: RequestId | null;
  ok: false;
  error: { code: ErrorCode; retryable: boolean; retry_at_ms: Ms | null; state: SessionState | null };
};

export type LeaseArgs = { session_id: SessionId; lease_id: LeaseId; fence: UInt };

export type InboxCard = {
  v: 1;
  external_id: HandoffId;
  session_id: SessionId;
  owner_id: ActorId;
  origin: Origin;
  reason: Handoff["reason"];
  expires_ms: Ms;
  policy_hash: Hash;
  allowed_actions: ["notify_local", "cancel"];
};

export type InboxDelivery = { external_id: HandoffId; status: "delivered" | "duplicate" };

export type SessionControl = {
  verification: "attach" | "recovery" | "handoff" | null;
  active_operation: OperationId | null;
  dispatched: boolean;
  unresolved_operations: OperationId[];
};

export type OriginBudget = {
  probe_starts_ms: Ms[];
  handoff_starts_ms: Ms[];
  last_block_ms: Ms | null;
  next_allowed_ms: Ms;
  attempts: UInt;
  fallback_used: boolean;
  manual_review: boolean;
};

// ---------- §11 config ----------
export type DaemonConfig = {
  v: 1;
  device_id: DeviceId;
  owner_id: ActorId;
  data_dir: string;
  runtime_dir: string;
  browser: { engine: "chromium"; profile_storage: "memory"; max_contexts: UInt };
  vault: { mode: "local" | "hosted"; base_url: Origin | null };
  relay: { enabled: boolean; listen: "127.0.0.1:43191"; relay_key_id: SigningKeyId | null };
  inbox: { mode: "local" | "vekinbox_adapter" };
  trusted_keys: {
    key_id: SigningKeyId;
    public_key: B64;
    purpose: "policy" | "request" | "relay" | "receipt";
    actor_id: ActorId;
    sessions: SessionId[];
  }[];
};

export type WorkerConfig = {
  v: 1;
  routes: { device_id: DeviceId; tunnel_origin: Origin; tunnel_secret_ref: string }[];
  callers: {
    key_id: SigningKeyId;
    public_key: B64;
    actor_id: ActorId;
    device_id: DeviceId;
    sessions: SessionId[];
    vault: boolean;
  }[];
  response_key_ref: string;
  vault_bucket_binding: "GHOSTSESSION_VAULT";
  max_requests_per_minute: UInt;
};

export type TrustFile = {
  v: 1;
  keys: {
    key_id: SigningKeyId;
    device_id: DeviceId;
    purpose: "receipt";
    public_key: B64;
    valid_from_ms: Ms;
    retired_ms: Ms | null;
  }[];
};

// ---------- object validators ----------

const vAuthProbe = vObj<AuthProbe>("AuthProbe", {
  path: vRelativePath,
  logged_in_selector: vSelector,
  logged_out_selector: vSelector,
  account_selector: vSelector,
  expected_account_ref: vStr,
});

const vRecoveryPolicy = vObj<RecoveryPolicy>("RecoveryPolicy", {
  challenge_base_ms: vUInt,
  rate_base_ms: vUInt,
  network_base_ms: vUInt,
  max_retry_delay_ms: vUInt,
  max_server_wait_ms: vUInt,
  max_automatic_probes: vUInt,
  fallback_path: vNullable(vRelativePath),
  handoff_ttl_ms: vUInt,
});

const vMethod = vEnum("GET", "HEAD", "POST" as const);

export const vPolicyCore = vObj<PolicyCore>("PolicyCore", {
  v: vLiteral(1),
  site_id: vSiteId,
  owner_id: vActorId,
  device_id: vDeviceId,
  revision: vUIntBound(1, MAX_UINT),
  origin: vOrigin,
  login_path: vRelativePath,
  agent_paths: vArr(vRelativePath, { sortedUnique: true, max: 256 }),
  login_origins: vArr(vOrigin, { sortedUnique: true, max: 4 }),
  resource_origins: vArr(vOrigin, { sortedUnique: true, max: 16 }),
  methods: vArr(vMethod, { sortedUnique: true, min: 2, max: 3 }),
  auth_probe: vAuthProbe,
  recovery: vRecoveryPolicy,
  snapshot_ttl_ms: vUInt,
  persist_session_cookies: vBool,
  automation_authorized: vLiteral(true),
  consent_expires_ms: vUInt,
  signing_key_id: vSigningKeyId,
});

export const vSignedPolicy = vObj<SignedPolicy>("SignedPolicy", {
  core: vPolicyCore,
  hash: vHash,
  signature: vB64(64),
});

const vCookie = vObj<Cookie>("Cookie", {
  name: vStrBound(4096, 1),
  value: vStrBound(4096),
  host: vStrBound(1024, 1),
  path: vRelativePath,
  secure: vLiteral(true),
  http_only: vBool,
  same_site: vEnum("Strict", "Lax", "None" as const),
  expires_ms: vNullable(vUInt),
});

const vLocalPair = vObj<LocalPair>("LocalPair", {
  name: vStrBound(1024, 1),
  value: vStrBound(MAX_ORDINARY_STRING),
});

const vOriginStorage = vObj<OriginStorage>("OriginStorage", {
  origin: vOrigin,
  local_storage: vArr(vLocalPair),
});

export const vSnapshotPlain = vObj<SnapshotPlain>("SnapshotPlain", {
  v: vLiteral(1),
  session_id: vSessionId,
  site_id: vSiteId,
  generation: vUInt,
  saved_ms: vUInt,
  expires_ms: vUInt,
  cookies: vArr(vCookie, { max: 500 }),
  origins: vArr(vOriginStorage),
  audit_seq: vUInt,
  audit_hash: vHash,
});

const vCipherHeader = vObj<CipherHeader>("CipherHeader", {
  v: vLiteral(1),
  format: vLiteral("chromium-storage-v1"),
  session_id: vSessionId,
  site_id: vSiteId,
  device_id: vDeviceId,
  generation: vUInt,
  policy_hash: vHash,
  key_id: vEncryptionKeyId,
  created_ms: vUInt,
  expires_ms: vUInt,
});

export const vCipherSnapshot = vObj<CipherSnapshot>("CipherSnapshot", {
  header: vCipherHeader,
  algorithm: vLiteral("A256GCM"),
  nonce: vB64(12),
  ciphertext: vStrBound(MAX_CIPHERTEXT_B64),
});

const vVaultHeadCore = vObj<VaultHeadCore>("VaultHeadCore", {
  v: vLiteral(1),
  session_id: vSessionId,
  device_id: vDeviceId,
  generation: vUIntBound(1, MAX_UINT),
  deleted: vBool,
  snapshot: vNullable(vCipherSnapshot),
  signing_key_id: vSigningKeyId,
});

export const vVaultHead = vObj<VaultHead>("VaultHead", {
  core: vVaultHeadCore,
  hash: vHash,
  signature: vB64(64),
});

export const vVaultWrite = vObj<VaultWrite>("VaultWrite", { head: vVaultHead });
export const vVaultResult = vObj<VaultResult>("VaultResult", {
  head: vVaultHead,
  etag: vStrBound(256),
});

const vStatus = (v: unknown, p: string): UInt | null =>
  v === null ? null : vUIntBound(100, 599)(v, p);

export const vObservation = vObj<Observation>("Observation", {
  status: vStatus,
  network: vEnum("ok", "timeout", "tls_error", "dns_error", "aborted", "policy_denied" as const),
  cf_mitigated: vBool,
  challenge_marker: vBool,
  login_marker: vBool,
  logged_in_marker: vBool,
  redirected_to_login: vBool,
  identity: vEnum("match", "missing", "mismatch", "not_checked" as const),
  retry_after: vNullable(vStrBound(128)),
  received_ms: vUInt,
});

export const vBlock = vObj<Block>("Block", {
  class: vBlockClassNonNone,
  revision: vUIntBound(1, MAX_UINT),
  attempt: vUIntBound(0, 2),
  retry_at_ms: vNullable(vUInt),
  fallback_used: vBool,
  observation: vObservation,
});

export const vLease = vObj<Lease>("Lease", {
  lease_id: vLeaseId,
  run_id: vRunId,
  actor_id: vActorId,
  fence: vUInt,
  expires_ms: vUInt,
});

export const vSessionView = vObj<SessionView>("SessionView", {
  session_id: vSessionId,
  site_id: vSiteId,
  device_id: vDeviceId,
  state: vSessionState,
  revision: vUIntBound(1, MAX_UINT),
  generation: vUInt,
  policy_hash: vHash,
  lease: vNullable(vLease),
  block: vNullable(vBlock),
  handoff_id: vNullable(vHandoffId),
  expires_ms: vNullable(vUInt),
  audit_seq: vUIntBound(1, MAX_UINT),
});

export const vBrowserAction: V<BrowserAction> = (v, p) => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail(p, "BrowserAction: expected object");
  const rec = v as Record<string, unknown>;
  const kind = vEnum("navigate", "read", "click", "fill" as const)(rec.kind, `${p}.kind`);
  switch (kind) {
    case "navigate":
      return vObj<BrowserAction>("BrowserAction.navigate", { kind: vLiteral("navigate"), url: vStrBound(8192, 1) })(v, p);
    case "read":
      return vObj<BrowserAction>("BrowserAction.read", {
        kind: vLiteral("read"),
        selector: vSelector,
        max_chars: vUIntBound(1, 16384),
      })(v, p);
    case "click":
      return vObj<BrowserAction>("BrowserAction.click", { kind: vLiteral("click"), selector: vSelector })(v, p);
    case "fill":
      return vObj<BrowserAction>("BrowserAction.fill", {
        kind: vLiteral("fill"),
        selector: vSelector,
        text: vStrBound(4096),
      })(v, p);
  }
};

export const vActionResult = vObj<ActionResult>("ActionResult", {
  operation_id: vOperationId,
  outcome: vEnum("SUCCEEDED", "BLOCKED", "DENIED", "UNKNOWN" as const),
  code: ((v: unknown, p: string) => {
    if (v === "OK") return "OK" as const;
    if (!isErrorCode(v)) fail(p, "expected OK or ErrorCode");
    return v;
  }) as V<"OK" | ErrorCode>,
  text: vNullable(vStrBound(16384 * 4)),
  truncated: vBool,
  block_class: vBlockClass,
  audit_seq: vUInt,
});

const vHandoffReason = vEnum(
  "INITIAL_LOGIN", "LOGIN_WALL", "CF_CHALLENGE", "ACCOUNT_MISMATCH", "MANUAL" as const,
);

export const vHandoff = vObj<Handoff>("Handoff", {
  handoff_id: vHandoffId,
  session_id: vSessionId,
  owner_id: vActorId,
  state: vEnum(...HANDOFF_STATES),
  reason: vHandoffReason,
  policy_hash: vHash,
  session_revision: vUIntBound(1, MAX_UINT),
  created_ms: vUInt,
  expires_ms: vUInt,
  attempts: vUIntBound(0, 2),
  presentation: vLiteral("local_browser_only"),
});

export const vReceiptCore = vObj<ReceiptCore>("ReceiptCore", {
  v: vLiteral(1),
  receipt_id: vReceiptId,
  session_id: vSessionId,
  seq: vUIntBound(1, MAX_UINT),
  previous_hash: vHash,
  recorded_ms: vUInt,
  signing_key_id: vSigningKeyId,
  actor_id: vActorId,
  operation_id: vNullable(vOperationId),
  event: vEventName,
  from_state: vSessionState,
  to_state: vSessionState,
  revision: vUIntBound(1, MAX_UINT),
  generation: vUInt,
  fence: vUInt,
  code: ((v: unknown, p: string) => {
    if (v === "OK") return "OK";
    if (!isErrorCode(v)) fail(p, "expected OK or ErrorCode");
    return v;
  }) as V<"OK" | ErrorCode>,
  action_binding: vNullable(vHash),
  cipher_hash: vNullable(vHash),
  block_class: vBlockClass,
});

export const vReceipt = vObj<Receipt>("Receipt", {
  core: vReceiptCore,
  hash: vHash,
  signature: vB64(64),
});

export const vAuditPage = vObj<AuditPage>("AuditPage", {
  entries: vArr(vReceipt),
  next_after_seq: vUInt,
  tip_seq: vUInt,
  tip_hash: vHash,
});

const vProofMethod = vEnum("POST", "GET", "PUT" as const);

export const vRequestProofCore = vObj<RequestProofCore>("RequestProofCore", {
  v: vLiteral(1),
  actor_id: vActorId,
  device_id: vDeviceId,
  key_id: vSigningKeyId,
  method: vProofMethod,
  path: vStrBound(1024, 1),
  body_hash: vHash,
  nonce: vB64(16),
  issued_ms: vUInt,
  expires_ms: vUInt,
  if_match: vNullable(vStrBound(256)),
  if_none_match: vNullable(vLiteral("*")),
});

export const vRequestProof = vObj<RequestProof>("RequestProof", {
  core: vRequestProofCore,
  signature: vB64(64),
});

export const vResponseProofCore = vObj<ResponseProofCore>("ResponseProofCore", {
  v: vLiteral(1),
  device_id: vDeviceId,
  signing_key_id: vSigningKeyId,
  request_hash: vHash,
  status: vUIntBound(100, 599),
  body_hash: vHash,
  issued_ms: vUInt,
});

export const vResponseProof = vObj<ResponseProof>("ResponseProof", {
  core: vResponseProofCore,
  signature: vB64(64),
});

export const vRpcRequest = vObj<RpcRequest>("RpcRequest", {
  v: vLiteral(1),
  id: vRequestId,
  method: vStrBound(64, 1),
  params: ((v: unknown) => v) as V<unknown>,
});

export const vForwardFrame = vObj<ForwardFrame>("ForwardFrame", {
  v: vLiteral(1),
  proof: vRequestProof,
  relay: vRequestProof,
  request: vRpcRequest,
});

const vAllowedActions: V<["notify_local", "cancel"]> = (v, p) => {
  const arr = vArr(vEnum("notify_local", "cancel" as const), { min: 2, max: 2 })(v, p);
  if (arr[0] !== "notify_local" || arr[1] !== "cancel") fail(p, "expected [notify_local, cancel]");
  return arr as ["notify_local", "cancel"];
};

export const vInboxCard = vObj<InboxCard>("InboxCard", {
  v: vLiteral(1),
  external_id: vHandoffId,
  session_id: vSessionId,
  owner_id: vActorId,
  origin: vOrigin,
  reason: vHandoffReason,
  expires_ms: vUInt,
  policy_hash: vHash,
  allowed_actions: vAllowedActions,
});

export const vInboxDelivery = vObj<InboxDelivery>("InboxDelivery", {
  external_id: vHandoffId,
  status: vEnum("delivered", "duplicate" as const),
});

export const vSessionControl = vObj<SessionControl>("SessionControl", {
  verification: vNullable(vEnum("attach", "recovery", "handoff" as const)),
  active_operation: vNullable(vOperationId),
  dispatched: vBool,
  unresolved_operations: vArr(vOperationId),
});

export const vOriginBudget = vObj<OriginBudget>("OriginBudget", {
  probe_starts_ms: vArr(vUInt),
  handoff_starts_ms: vArr(vUInt),
  last_block_ms: vNullable(vUInt),
  next_allowed_ms: vUInt,
  attempts: vUIntBound(0, 2),
  fallback_used: vBool,
  manual_review: vBool,
});

const vTrustedKey = vObj<DaemonConfig["trusted_keys"][number]>("TrustedKey", {
  key_id: vSigningKeyId,
  public_key: vB64(32),
  purpose: vEnum("policy", "request", "relay", "receipt" as const),
  actor_id: vActorId,
  sessions: vArr(vSessionId),
});

export const vDaemonConfig = vObj<DaemonConfig>("DaemonConfig", {
  v: vLiteral(1),
  device_id: vDeviceId,
  owner_id: vActorId,
  data_dir: vStrBound(1024, 1),
  runtime_dir: vStrBound(1024, 1),
  browser: vObj<DaemonConfig["browser"]>("BrowserCfg", {
    engine: vLiteral("chromium"),
    profile_storage: vLiteral("memory"),
    max_contexts: vUIntBound(1, 8),
  }),
  vault: vObj<DaemonConfig["vault"]>("VaultCfg", {
    mode: vEnum("local", "hosted" as const),
    base_url: vNullable(vStrBound(1024)),
  }),
  relay: vObj<DaemonConfig["relay"]>("RelayCfg", {
    enabled: vBool,
    listen: vLiteral("127.0.0.1:43191"),
    relay_key_id: vNullable(vSigningKeyId),
  }),
  inbox: vObj<DaemonConfig["inbox"]>("InboxCfg", {
    mode: vEnum("local", "vekinbox_adapter" as const),
  }),
  trusted_keys: vArr(vTrustedKey),
});

const vWorkerRoute = vObj<WorkerConfig["routes"][number]>("WorkerRoute", {
  device_id: vDeviceId,
  tunnel_origin: vOrigin,
  tunnel_secret_ref: vStrBound(256, 1),
});

const vWorkerCaller = vObj<WorkerConfig["callers"][number]>("WorkerCaller", {
  key_id: vSigningKeyId,
  public_key: vB64(32),
  actor_id: vActorId,
  device_id: vDeviceId,
  sessions: vArr(vSessionId),
  vault: vBool,
});

export const vWorkerConfig = vObj<WorkerConfig>("WorkerConfig", {
  v: vLiteral(1),
  routes: vArr(vWorkerRoute),
  callers: vArr(vWorkerCaller),
  response_key_ref: vStrBound(256, 1),
  vault_bucket_binding: vLiteral("GHOSTSESSION_VAULT"),
  max_requests_per_minute: vUIntBound(1, 600),
});

const vTrustKey = vObj<TrustFile["keys"][number]>("TrustKey", {
  key_id: vSigningKeyId,
  device_id: vDeviceId,
  purpose: vLiteral("receipt"),
  public_key: vB64(32),
  valid_from_ms: vUInt,
  retired_ms: vNullable(vUInt),
});

export const vTrustFile = vObj<TrustFile>("TrustFile", {
  v: vLiteral(1),
  keys: vArr(vTrustKey),
});

/** Per-method params validators (spec §8.1 Methods table). */
export const PARAMS: Record<string, V<unknown>> = {
  "system.status": vObj<object>("P", {}),
  "site.put": vObj("P", { policy: vSignedPolicy }),
  "session.create": vObj("P", { site_id: vSiteId }),
  "session.get": vObj("P", { session_id: vSessionId }),
  "session.attach": vObj("P", {
    session_id: vSessionId,
    run_id: vRunId,
    expected_generation: vUInt,
  }),
  "session.renew": vObj("P", { session_id: vSessionId, lease_id: vLeaseId, fence: vUInt }),
  "session.step": vObj("P", {
    session_id: vSessionId,
    lease_id: vLeaseId,
    fence: vUInt,
    operation_id: vOperationId,
    action: vBrowserAction,
  }),
  "session.checkpoint": vObj("P", { session_id: vSessionId, lease_id: vLeaseId, fence: vUInt }),
  "session.detach": vObj("P", {
    session_id: vSessionId,
    lease_id: vLeaseId,
    fence: vUInt,
    checkpoint: vBool,
  }),
  "session.recover": vObj("P", {
    session_id: vSessionId,
    block_revision: vNullable(vUInt),
    intent: vEnum("retry", "fallback", "reauth", "acknowledge_unknown" as const),
  }),
  "handoff.get": vObj("P", { handoff_id: vHandoffId }),
  "handoff.open": vObj("P", { handoff_id: vHandoffId }),
  "handoff.resolve": vObj("P", {
    handoff_id: vHandoffId,
    decision: vEnum("ready", "cancel" as const),
  }),
  "session.revoke": vObj("P", { session_id: vSessionId }),
  "session.delete": vObj("P", { session_id: vSessionId, confirm_generation: vUInt }),
  "audit.list": vObj("P", {
    session_id: vSessionId,
    after_seq: vUInt,
    limit: vUIntBound(1, 100),
  }),
  "vault.sync": vObj("P", {
    session_id: vSessionId,
    mode: vEnum("upload", "restore" as const),
  }),
  "vault.rotate": vObj("P", { session_id: vSessionId }),
};

export const METHOD_NAMES = Object.keys(PARAMS);
