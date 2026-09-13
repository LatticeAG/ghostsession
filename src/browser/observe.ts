/**
 * Observation construction from adapter evidence (spec §6).
 * Bounded markers only; no bodies, screenshots, or raw headers persist.
 */

import type { Observation, PolicyCore } from "../schema.js";
import type { ProbeResult, RawResponse } from "./types.js";

export const HTML_SAMPLE_LIMIT = 128 * 1024;

/** cf_mitigated: top-level cf-mitigated header equals 'challenge' (ASCII fold+trim). */
export function cfMitigated(headers: RawResponse["headers"]): boolean {
  const v = headers["cf-mitigated"];
  if (v === undefined) return false;
  return v.trim().toLowerCase() === "challenge";
}

/** challenge_marker: /cdn-cgi/challenge-platform/ script path AND exact title. */
export function challengeMarker(title: string | null, htmlSample: string | null): boolean {
  if (title !== "Just a moment..." || htmlSample === null) return false;
  return htmlSample.includes("/cdn-cgi/challenge-platform/");
}

/** Retry-After stays transient: >128 bytes triggers manual review, never truncation. */
export function retryAfterValue(headers: RawResponse["headers"]): { value: string | null; oversized: boolean } {
  if (headers["retry-after-oversized"]) return { value: null, oversized: true };
  const v = headers["retry-after"];
  if (v === undefined) return { value: null, oversized: false };
  if (Buffer.byteLength(v, "utf8") > 128) return { value: null, oversized: true };
  return { value: v, oversized: false };
}

export function observationFromResponse(
  r: RawResponse,
  policy: PolicyCore,
  receivedMs: number,
): { observation: Observation; oversizedRetryAfter: boolean } {
  const ra = retryAfterValue(r.headers);
  const redirectedToLogin = r.redirectHops.some((h) => h.decision === "login");
  const deniedHop = r.redirectHops.some((h) => h.decision === "denied");
  const observation: Observation = {
    status: r.status !== null && r.status >= 100 && r.status <= 599 ? r.status : null,
    network: deniedHop && r.network === "ok" ? "policy_denied" : r.network,
    cf_mitigated: cfMitigated(r.headers),
    challenge_marker: challengeMarker(r.title, r.htmlSample),
    login_marker: false,
    logged_in_marker: false,
    redirected_to_login: redirectedToLogin,
    identity: "not_checked",
    retry_after: ra.value,
    received_ms: receivedMs,
  };
  return { observation, oversizedRetryAfter: ra.oversized };
}

export function observationFromProbe(
  p: ProbeResult,
  policy: PolicyCore,
  expectedAccount: string | null,
  receivedMs: number,
): { observation: Observation; oversizedRetryAfter: boolean } {
  const { observation, oversizedRetryAfter } = observationFromResponse(p.response, policy, receivedMs);
  observation.login_marker = p.loggedOutPresent;
  observation.logged_in_marker = p.loggedInMatched;
  if (expectedAccount === null || p.accountText === null) {
    observation.identity = "missing";
  } else {
    const trimmed = p.accountText.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
    observation.identity = trimmed === expectedAccount ? "match" : "mismatch";
  }
  return { observation, oversizedRetryAfter };
}
