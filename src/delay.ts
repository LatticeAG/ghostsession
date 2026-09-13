/**
 * Bounded recovery delay computation (spec §6).
 * Deterministic: no jitter; inclusive expiry everywhere.
 */

import type { BlockClass, Observation } from "./schema.js";

export const CHALLENGE_BASE_MS = 60_000;
export const RATE_BASE_MS = 30_000;
export const NETWORK_BASE_MS = 5_000;
export const MAX_RETRY_DELAY_MS = 900_000;
export const MAX_SERVER_WAIT_MS = 86_400_000;

function baseDelay(cls: BlockClass, network: Observation["network"]): number {
  if (cls === "CF_CHALLENGE") return CHALLENGE_BASE_MS;
  if (cls === "RATE_LIMIT") return RATE_BASE_MS;
  if (cls === "NETWORK_ERROR" && network !== "tls_error") return NETWORK_BASE_MS;
  return 0;
}

export type ParsedRetryAfter =
  | { kind: "none" | "invalid" }
  | { kind: "ok"; delayMs: number }
  | { kind: "overflow" };

const IMF_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const IMF_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/**
 * Parse a Retry-After value. Valid inputs: ASCII digits (leading zeros
 * permitted) after OWS trim, or an IMF-fixdate with GMT zone. Anything else —
 * other date formats, signs, fractions, non-GMT zones — is invalid.
 */
export function parseRetryAfter(raw: string | null, receivedMs: number): ParsedRetryAfter {
  if (raw === null) return { kind: "none" };
  const t = raw.trim();
  if (t === "") return { kind: "invalid" };
  if (/^[0-9]+$/.test(t)) {
    // digit strings may be arbitrarily long — detect overflow safely
    if (t.length > 15) return { kind: "overflow" };
    const secs = Number(t);
    const ms = secs * 1000;
    if (!Number.isSafeInteger(ms) || ms > Number.MAX_SAFE_INTEGER) return { kind: "overflow" };
    return { kind: "ok", delayMs: ms };
  }
  // IMF-fixdate: `Www, DD Mmm YYYY HH:MM:SS GMT` — exactly.
  const m = /^([A-Z][a-z]{2}), (\d{2}) ([A-Z][a-z]{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$/.exec(t);
  if (!m) return { kind: "invalid" };
  const [, wday, day, mon, year, hh, mm, ss] = m;
  const monIdx = IMF_MONTHS.indexOf(mon!);
  if (monIdx < 0) return { kind: "invalid" };
  const d = Number(day);
  const y = Number(year);
  const H = Number(hh);
  const M = Number(mm);
  const S = Number(ss);
  if (d < 1 || d > 31 || H > 23 || M > 59 || S > 60) return { kind: "invalid" };
  const dateMs = Date.UTC(y, monIdx, d, H, M, S);
  // Reject impossible dates (e.g. Feb 31) — re-rendered fields must round-trip.
  const dt = new Date(dateMs);
  if (
    dt.getUTCFullYear() !== y || dt.getUTCMonth() !== monIdx || dt.getUTCDate() !== d ||
    dt.getUTCHours() !== H || dt.getUTCMinutes() !== M || dt.getUTCSeconds() !== S ||
    IMF_WEEKDAYS[dt.getUTCDay() === 0 ? 6 : dt.getUTCDay() - 1] !== wday
  ) {
    return { kind: "invalid" };
  }
  return { kind: "ok", delayMs: Math.max(0, dateMs - receivedMs) };
}

export type DelayResult = {
  delay_ms: number | null;
  retry_at_ms: number | null;
  exhausted: boolean;
};

/**
 * delay = max(backoff, parsed server delay); retry_at = received + delay.
 * A valid server delay above MAX_SERVER_WAIT_MS (or arithmetic overflow)
 * exhausts eligibility — it is never capped down for an earlier retry.
 */
export function computeDelay(
  cls: Exclude<BlockClass, "NONE">,
  network: Observation["network"],
  attempt: number,
  retryAfter: string | null,
  receivedMs: number,
): DelayResult {
  const base = baseDelay(cls, network);
  const backoff = Math.min(base * 2 ** (attempt - 1), MAX_RETRY_DELAY_MS);
  const parsed = parseRetryAfter(retryAfter, receivedMs);
  if (parsed.kind === "overflow") return { delay_ms: null, retry_at_ms: null, exhausted: true };
  const server = parsed.kind === "ok" ? parsed.delayMs : 0;
  if (parsed.kind === "ok" && server > MAX_SERVER_WAIT_MS) {
    return { delay_ms: null, retry_at_ms: null, exhausted: true };
  }
  const delay = Math.max(backoff, server);
  const retryAt = receivedMs + delay;
  if (!Number.isSafeInteger(retryAt) || retryAt > Number.MAX_SAFE_INTEGER) {
    return { delay_ms: null, retry_at_ms: null, exhausted: true };
  }
  return { delay_ms: delay, retry_at_ms: retryAt, exhausted: false };
}
