/**
 * Trusted browser adapter contract (spec §4.1, §6).
 * Only adapter-produced Observation inputs feed the classifier; RPC clients
 * and page text can never submit evidence.
 */

import type { BrowserAction, Observation, PolicyCore } from "../schema.js";

export type ContextPurpose = "attach" | "recovery" | "handoff-verify" | "handoff-human";

/** Allowlisted response headers only — bounded subset for classification. */
export interface RawResponse {
  /** Final top-level status; null when no response (network failure). */
  status: number | null;
  network: Observation["network"];
  headers: {
    server?: string;
    "cf-mitigated"?: string;
    "cf-ray"?: string;
    "retry-after"?: string;
    "retry-after-oversized"?: boolean;
  };
  /** Top-level document title (bounded). */
  title: string | null;
  /** ≤128 KiB top-level HTML sample for marker checks. */
  htmlSample: string | null;
  /** Observed redirect hop URLs (validated before each fetch). */
  redirectHops: { url: string; decision: "followed" | "login" | "denied" }[];
}

export type DispatchOutcome =
  | { kind: "ok"; response: RawResponse; text: string | null; truncated: boolean }
  | { kind: "denied"; code: "SCOPE_DENIED" }
  | { kind: "unknown" };

export interface ProbeResult {
  response: RawResponse;
  /** Raw account element text (pre-trim) or null when absent/multi. */
  accountText: string | null;
  /** Configured logged-in selector matched exactly once. */
  loggedInMatched: boolean;
  /** Configured logged-out selector or visible password input present. */
  loggedOutPresent: boolean;
}

export interface RawCookie {
  name: string;
  value: string;
  /** Effective host (Domain attribute stripped of its leading dot). */
  host: string;
  /** Original Domain attribute value when present. */
  domain: string | null;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None";
  /** Unix ms, or null for a session cookie. */
  expiresMs: number | null;
  /** Playwright-side attributes that make capture unsupported. */
  hasPartitionKey: boolean;
  unsupportedAttrs: boolean;
}

export interface RawStorage {
  origin: string;
  pairs: { name: string; value: string }[];
}

export interface RawCapture {
  cookies: RawCookie[];
  storage: RawStorage[];
}

export interface BrowserContextHandle {
  id: number;
  purpose: ContextPurpose;
}

export interface BrowserAdapter {
  /** Create a fresh isolated context; never the user's ordinary profile. */
  openContext(purpose: ContextPurpose, policy: PolicyCore): Promise<BrowserContextHandle>;
  /** Restore a decrypted snapshot into a context (cookies/localStorage). */
  restore(ctx: BrowserContextHandle, snapshot: { cookies: { name: string; value: string; host: string; path: string; secure: boolean; httpOnly: boolean; sameSite: "Strict" | "Lax" | "None"; expiresMs: number | null }[]; origins: { origin: string; localStorage: { name: string; value: string }[] }[] }): Promise<void>;
  /** Dispatch one agent action with the full egress policy enforced. */
  dispatch(ctx: BrowserContextHandle, action: BrowserAction, policy: PolicyCore): Promise<DispatchOutcome>;
  /** Run the configured auth probe (GET probe path, marker + identity reads). */
  probe(ctx: BrowserContextHandle, policy: PolicyCore): Promise<ProbeResult>;
  /** Open the human handoff window at origin+login_path (visible, human-only). */
  openHuman(ctx: BrowserContextHandle, policy: PolicyCore): Promise<void>;
  /** Capture cookies+localStorage from the context. */
  capture(ctx: BrowserContextHandle): Promise<RawCapture>;
  destroy(ctx: BrowserContextHandle): Promise<void>;
  /** Diagnostics: total dispatches performed (tests). */
  dispatchCount(): number;
}
