/**
 * Signed policy semantics beyond the closed schema (spec §4):
 * fixed recovery constants, sorted unique lists, path containment,
 * selector subset, consent, account-ref binding.
 */

import { RpcError } from "./errors.js";
import type { PolicyCore, SignedPolicy } from "./schema.js";
import { vPolicyCore, vSignedPolicy } from "./schema.js";
import { jcsHash } from "./crypto/envelope.js";
import {
  validateOrigin, validateRelativePath, validateSelector, pathPrefixMatch, ScopeError,
  type OriginOptions,
} from "./net/origin.js";
import {
  CHALLENGE_BASE_MS, RATE_BASE_MS, NETWORK_BASE_MS,
  MAX_RETRY_DELAY_MS, MAX_SERVER_WAIT_MS,
} from "./delay.js";

export const HANDOFF_TTL_MS = 900_000;
export const MIN_SNAPSHOT_TTL_MS = 3_600_000;
export const MAX_SNAPSHOT_TTL_MS = 2_592_000_000;
export const MAX_AUTOMATIC_PROBES = 2;

export function policyHash(p: SignedPolicy): string {
  return p.hash;
}

export function policyCoreHash(core: PolicyCore): string {
  return jcsHash(core);
}

/**
 * Validate a PolicyCore semantically. Throws RpcError INVALID_SCHEMA.
 * `nowMs` enforces live consent at enrollment/update time.
 */
export function validatePolicyCore(
  raw: unknown,
  nowMs: number,
  opts: OriginOptions,
): PolicyCore {
  let core: PolicyCore;
  try {
    core = vPolicyCore(raw, "policy.core");
  } catch (e) {
    throw new RpcError("INVALID_SCHEMA", { cause: e });
  }
  try {
    validateOrigin(core.origin, opts);
    for (const o of [...core.login_origins, ...core.resource_origins]) validateOrigin(o, opts);
    const paths = [core.login_path, ...core.agent_paths].map(validateRelativePath);
    void paths;
    validateRelativePath(core.auth_probe.path);
    if (core.recovery.fallback_path !== null) validateRelativePath(core.recovery.fallback_path);
    // Probe and fallback must fall within agent paths.
    const inScope = (p: string) =>
      core.agent_paths.some((ap) => pathPrefixMatch(ap, p));
    if (!inScope(core.auth_probe.path)) throw new ScopeError("probe path outside agent_paths");
    if (core.recovery.fallback_path !== null && !inScope(core.recovery.fallback_path)) {
      throw new ScopeError("fallback path outside agent_paths");
    }
    const ap = core.auth_probe;
    validateSelector(ap.logged_in_selector);
    validateSelector(ap.logged_out_selector);
    validateSelector(ap.account_selector);
  } catch (e) {
    if (e instanceof RpcError) throw e;
    throw new RpcError("INVALID_SCHEMA", { cause: e });
  }
  if (!core.methods.includes("GET") || !core.methods.includes("HEAD")) {
    throw new RpcError("INVALID_SCHEMA");
  }
  const r = core.recovery;
  if (
    r.challenge_base_ms !== CHALLENGE_BASE_MS ||
    r.rate_base_ms !== RATE_BASE_MS ||
    r.network_base_ms !== NETWORK_BASE_MS ||
    r.max_retry_delay_ms !== MAX_RETRY_DELAY_MS ||
    r.max_server_wait_ms !== MAX_SERVER_WAIT_MS ||
    r.max_automatic_probes !== MAX_AUTOMATIC_PROBES ||
    r.handoff_ttl_ms !== HANDOFF_TTL_MS
  ) {
    throw new RpcError("INVALID_SCHEMA");
  }
  if (core.snapshot_ttl_ms < MIN_SNAPSHOT_TTL_MS || core.snapshot_ttl_ms > MAX_SNAPSHOT_TTL_MS) {
    throw new RpcError("INVALID_SCHEMA");
  }
  const expectedRef = `keychain:ghostsession/account/${core.site_id}`;
  if (core.auth_probe.expected_account_ref !== expectedRef) {
    throw new RpcError("INVALID_SCHEMA");
  }
  if (nowMs >= core.consent_expires_ms) throw new RpcError("CONSENT_EXPIRED");
  return core;
}

/**
 * Validate a SignedPolicy envelope: closed schema, hash consistency,
 * and PolicyCore semantics. Signature verification is the caller's job
 * (it requires the pinned device policy key).
 */
export function validateSignedPolicy(
  raw: unknown,
  nowMs: number,
  opts: OriginOptions,
): SignedPolicy {
  let p: SignedPolicy;
  try {
    p = vSignedPolicy(raw, "policy");
  } catch (e) {
    throw new RpcError("INVALID_SCHEMA", { cause: e });
  }
  validatePolicyCore(p.core, nowMs, opts);
  if (p.hash !== policyCoreHash(p.core)) throw new RpcError("INVALID_SCHEMA");
  return p;
}
