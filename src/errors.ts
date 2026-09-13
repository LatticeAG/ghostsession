/**
 * Protocol error codes, HTTP status mapping, retryability, CLI exit mapping.
 */

export const ERROR_CODES = [
  "INVALID_SCHEMA", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "STATE_CONFLICT",
  "STALE_GENERATION", "LEASE_HELD", "LEASE_EXPIRED", "STALE_FENCE", "BUSY",
  "NOT_READY", "IDEMPOTENCY_CONFLICT", "OPERATION_CONFLICT", "OUTCOME_UNKNOWN",
  "RESULT_GONE", "SCOPE_DENIED", "COOLDOWN_ACTIVE", "RECOVERY_EXHAUSTED",
  "STALE_HANDOFF", "HANDOFF_EXPIRED", "AUTH_NOT_VERIFIED", "UNSUPPORTED_STORAGE",
  "SNAPSHOT_EXPIRED", "CONSENT_EXPIRED", "KEY_UNAVAILABLE",
  "SECURE_STORAGE_UNAVAILABLE", "AUDIT_UNAVAILABLE", "INTEGRITY_FAILED",
  "CLOCK_UNSAFE", "REPLAY", "BODY_TOO_LARGE", "VERSION_UNSUPPORTED",
  "VAULT_CONFLICT", "DEVICE_OFFLINE", "TIMEOUT", "RATE_LIMITED", "INTERNAL",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export function isErrorCode(v: unknown): v is ErrorCode {
  return typeof v === "string" && (ERROR_CODES as readonly string[]).includes(v);
}

const HTTP_STATUS: Record<ErrorCode, number> = {
  INVALID_SCHEMA: 400,
  VERSION_UNSUPPORTED: 400,
  UNAUTHORIZED: 401,
  REPLAY: 401,
  FORBIDDEN: 403,
  SCOPE_DENIED: 403,
  NOT_FOUND: 404,
  STATE_CONFLICT: 409,
  STALE_GENERATION: 409,
  LEASE_HELD: 409,
  LEASE_EXPIRED: 409,
  STALE_FENCE: 409,
  BUSY: 409,
  NOT_READY: 409,
  IDEMPOTENCY_CONFLICT: 409,
  OPERATION_CONFLICT: 409,
  OUTCOME_UNKNOWN: 409,
  RECOVERY_EXHAUSTED: 409,
  STALE_HANDOFF: 409,
  VAULT_CONFLICT: 409,
  RESULT_GONE: 410,
  HANDOFF_EXPIRED: 410,
  AUTH_NOT_VERIFIED: 412,
  UNSUPPORTED_STORAGE: 412,
  SNAPSHOT_EXPIRED: 412,
  CONSENT_EXPIRED: 412,
  INTEGRITY_FAILED: 412,
  BODY_TOO_LARGE: 413,
  KEY_UNAVAILABLE: 423,
  SECURE_STORAGE_UNAVAILABLE: 423,
  AUDIT_UNAVAILABLE: 423,
  CLOCK_UNSAFE: 423,
  COOLDOWN_ACTIVE: 423,
  RATE_LIMITED: 429,
  INTERNAL: 500,
  DEVICE_OFFLINE: 502,
  TIMEOUT: 504,
};

const RETRYABLE = new Set<ErrorCode>([
  "BUSY", "DEVICE_OFFLINE", "RATE_LIMITED", "COOLDOWN_ACTIVE", "TIMEOUT",
]);

export function httpStatusFor(code: ErrorCode): number {
  return HTTP_STATUS[code];
}

export function isRetryableCode(code: ErrorCode): boolean {
  return RETRYABLE.has(code);
}

export class RpcError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly retryAtMs: number | null;
  readonly state: string | null;

  constructor(
    code: ErrorCode,
    opts: { retryable?: boolean; retryAtMs?: number | null; state?: string | null; cause?: unknown } = {},
  ) {
    super(code);
    this.name = "RpcError";
    this.code = code;
    this.retryable = opts.retryable ?? isRetryableCode(code);
    this.retryAtMs = opts.retryAtMs ?? null;
    this.state = opts.state ?? null;
    if (opts.cause !== undefined) this.cause = opts.cause;
  }

  get httpStatus(): number {
    return httpStatusFor(this.code);
  }

  toFailure(id: string | null): { v: 1; id: string | null; ok: false; error: object } {
    return {
      v: 1,
      id,
      ok: false,
      error: {
        code: this.code,
        retryable: this.retryable,
        retry_at_ms: this.retryAtMs,
        state: this.state,
      },
    };
  }
}

/** Map a thrown value to an RpcError without leaking upstream text. */
export function toRpcError(e: unknown, fallback: ErrorCode = "INTERNAL"): RpcError {
  if (e instanceof RpcError) return e;
  return new RpcError(fallback);
}

/** CLI exit-code mapping (spec §10). */
export function cliExitFor(code: ErrorCode): number {
  switch (code) {
    case "INVALID_SCHEMA":
    case "VERSION_UNSUPPORTED":
      return 2;
    case "UNAUTHORIZED":
    case "FORBIDDEN":
    case "SCOPE_DENIED":
    case "REPLAY":
    case "AUTH_NOT_VERIFIED":
      return 3;
    case "NOT_FOUND":
    case "RESULT_GONE":
    case "HANDOFF_EXPIRED":
      return 4;
    case "STATE_CONFLICT":
    case "STALE_GENERATION":
    case "LEASE_HELD":
    case "LEASE_EXPIRED":
    case "STALE_FENCE":
    case "BUSY":
    case "NOT_READY":
    case "IDEMPOTENCY_CONFLICT":
    case "OPERATION_CONFLICT":
    case "STALE_HANDOFF":
    case "VAULT_CONFLICT":
      return 5;
    case "KEY_UNAVAILABLE":
    case "SECURE_STORAGE_UNAVAILABLE":
    case "AUDIT_UNAVAILABLE":
    case "INTEGRITY_FAILED":
    case "UNSUPPORTED_STORAGE":
      return 6;
    case "DEVICE_OFFLINE":
    case "TIMEOUT":
      return 7;
    case "CLOCK_UNSAFE":
    case "CONSENT_EXPIRED":
    case "SNAPSHOT_EXPIRED":
      return 8;
    case "COOLDOWN_ACTIVE":
    case "RECOVERY_EXHAUSTED":
    case "RATE_LIMITED":
      return 10;
    case "OUTCOME_UNKNOWN":
      return 11;
    case "BODY_TOO_LARGE":
      return 2;
    case "INTERNAL":
      return 1;
  }
}
