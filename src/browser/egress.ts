/**
 * Egress policy enforcement (spec §12). Every top-level navigation, redirect
 * hop, popup attempt, subresource fetch and request method passes through
 * checkEgress. Exact parser-normalized origins only — suffix matching is
 * forbidden. DNS answers are validated per-connection by the adapter/proxy.
 */

import { ScopeError, validateNavigationUrl, validateOrigin, pathPrefixMatch, type OriginOptions } from "../net/origin.js";
import { isPublicIp } from "../net/ipfilter.js";
import type { PolicyCore } from "../schema.js";
import type { ContextPurpose } from "./types.js";

export type EgressVerdict =
  | { decision: "allow"; origin: string; path: string }
  | { decision: "deny-login"; origin: string }
  | { decision: "deny-scope"; reason: string };

export interface EgressRequest {
  url: string;
  method: "GET" | "HEAD" | "POST";
  isTopLevel: boolean;
}

export function checkEgress(
  policy: PolicyCore,
  purpose: ContextPurpose,
  req: EgressRequest,
  opts: OriginOptions,
): EgressVerdict {
  let parsed: { origin: string; path: string };
  try {
    parsed = validateNavigationUrl(req.url, opts);
  } catch (e) {
    return { decision: "deny-scope", reason: e instanceof ScopeError ? e.message : "invalid url" };
  }
  const { origin, path } = parsed;
  const human = purpose === "handoff-human";
  if (origin === policy.origin) {
    if (human) {
      // Owner grant: GET/HEAD/POST on all paths of app + login origins.
      return { decision: "allow", origin, path };
    }
    if (!policy.methods.includes(req.method)) {
      return { decision: "deny-scope", reason: "method not in policy" };
    }
    if (!policy.agent_paths.some((ap) => pathPrefixMatch(ap, path))) {
      return { decision: "deny-scope", reason: "path outside agent_paths" };
    }
    return { decision: "allow", origin, path };
  }
  if (policy.login_origins.includes(origin)) {
    if (human) return { decision: "allow", origin, path };
    return { decision: "deny-login", origin };
  }
  if (policy.resource_origins.includes(origin)) {
    if (req.isTopLevel) return { decision: "deny-scope", reason: "resource origin cannot top-level navigate" };
    if (req.method === "POST") return { decision: "deny-scope", reason: "resource origins are GET/HEAD only" };
    return { decision: "allow", origin, path };
  }
  return { decision: "deny-scope", reason: "origin outside policy" };
}

/**
 * Per-connection destination check: the adapter/proxy resolves DNS itself and
 * calls this for every connection and every CNAME hop — no re-resolution race.
 */
export function checkDestinationIp(ip: string): boolean {
  return isPublicIp(ip);
}
