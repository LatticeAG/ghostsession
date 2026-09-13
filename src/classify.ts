/**
 * Deterministic block classifier (spec §6). Pure function over a trusted
 * Observation produced by the browser adapter — never callable on raw page
 * text supplied by an RPC client.
 */

import type { BlockClass, Observation } from "./schema.js";

export function classify(o: Observation): BlockClass {
  if (o.network === "policy_denied") return "SCOPE_DENIED";
  if (o.network !== "ok") return "NETWORK_ERROR";
  if (o.cf_mitigated || o.challenge_marker) return "CF_CHALLENGE";
  if (o.status === 429) return "RATE_LIMIT";
  if (o.identity === "mismatch") return "ACCOUNT_MISMATCH";
  if (o.status === 401 || o.login_marker || o.redirected_to_login) return "LOGIN_WALL";
  if (o.status === 403) return "ACCESS_DENIED";
  if (o.status === null || o.status < 200 || o.status >= 300) return "UNKNOWN";
  if (o.identity === "missing") return "LOGIN_WALL";
  return "NONE";
}

/** Retryable classes: challenge, rate-limit, non-TLS network errors. */
export function isRetryableBlock(cls: BlockClass, network: Observation["network"]): boolean {
  if (cls === "CF_CHALLENGE" || cls === "RATE_LIMIT") return true;
  if (cls === "NETWORK_ERROR") return network !== "tls_error";
  return false;
}

/** Classes allowed to use the configured fallback probe path. */
export function isFallbackEligible(cls: BlockClass, network: Observation["network"]): boolean {
  if (cls === "ACCESS_DENIED" || cls === "UNKNOWN") return true;
  return isRetryableBlock(cls, network);
}

/**
 * Probe success (attach/recovery/handoff verification): classification NONE
 * plus a 2xx status, identity match, present logged-in marker, no logged-out
 * marker. Policy equality is enforced by the caller.
 */
export function probeVerified(o: Observation): boolean {
  return (
    classify(o) === "NONE" &&
    o.status !== null && o.status >= 200 && o.status < 300 &&
    o.identity === "match" &&
    o.logged_in_marker === true &&
    o.login_marker === false &&
    o.redirected_to_login === false
  );
}
