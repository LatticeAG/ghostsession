/**
 * Scripted browser adapter — the deterministic test double the conformance
 * vectors run against. It enforces the SAME egress/decision path as the real
 * adapter: every request and redirect hop passes checkEgress plus a
 * per-connection destination-IP check via the injected resolver.
 */

import { RpcError } from "../errors.js";
import type { BrowserAction, PolicyCore } from "../schema.js";
import { checkEgress } from "./egress.js";
import { isPublicIp } from "../net/ipfilter.js";
import type { OriginOptions } from "../net/origin.js";
import type {
  BrowserAdapter, BrowserContextHandle, ContextPurpose,
  DispatchOutcome, ProbeResult, RawCapture, RawCookie, RawResponse, RawStorage,
} from "./types.js";

export interface ScriptResponse {
  status?: number | null;
  network?: RawResponse["network"];
  headers?: RawResponse["headers"];
  title?: string | null;
  html?: string | null;
  redirectTo?: string | null;
  text?: string | null;
}

export interface AdapterScript {
  /** Keyed `${METHOD} ${origin}${path}` — method GET for navigations/probe. */
  responses?: Record<string, ScriptResponse>;
  /** Hostname → successive DNS answers (each lookup shifts one). */
  dnsAnswers?: Record<string, string[]>;
  /** Probe DOM evaluation. */
  accountText?: string | null;
  accountMissing?: boolean;
  loggedIn?: boolean;
  loggedOut?: boolean;
  passwordInput?: boolean;
  /** Capture payload. */
  cookies?: RawCookie[];
  storage?: RawStorage[];
  /** Special behaviors. */
  dispatchBehavior?: "normal" | "hang" | "throw-secret" | "crash-before-result";
  captureFails?: boolean;
}

export class ScriptedAdapter implements BrowserAdapter {
  script: AdapterScript;
  resolve: (host: string) => string;
  opts: OriginOptions;
  contextsCreated = 0;
  private _dispatchCount = 0;
  private _requestsSent = 0;
  private nextCtx = 1;
  liveContexts = new Map<number, ContextPurpose>();
  destroyed: number[] = [];
  restoredSnapshots: unknown[] = [];
  humanOpened: string[] = [];
  private hangLatch = false;

  constructor(script: AdapterScript = {}, opts?: { resolve?: (h: string) => string; publicDnsOnly?: boolean }) {
    this.script = script;
    this.resolve = opts?.resolve ?? (() => "93.184.215.14");
    this.opts = { publicDnsOnly: opts?.publicDnsOnly ?? false };
  }

  dispatchCount(): number {
    return this._dispatchCount;
  }

  get requestsSent(): number {
    return this._requestsSent;
  }

  private responseFor(method: string, url: string): ScriptResponse | null {
    const u = new URL(url);
    return this.script.responses?.[`${method} https://${u.hostname}${u.pathname === "/" ? "/" : u.pathname}`] ?? null;
  }

  private fetch(url: string, method: "GET" | "HEAD" | "POST"): RawResponse {
    const u = new URL(url);
    const answers = this.script.dnsAnswers?.[u.hostname];
    const ip = answers && answers.length > 0 ? answers.shift()! : this.resolve(u.hostname);
    if (!isPublicIp(ip)) {
      return {
        status: null, network: "policy_denied", headers: {}, title: null,
        htmlSample: null, redirectHops: [],
      };
    }
    this._requestsSent++;
    const r = this.responseFor(method, url) ?? { status: 200, headers: {}, title: null, html: null };
    const resp: RawResponse = {
      status: r.status ?? 200,
      network: r.network ?? "ok",
      headers: r.headers ?? {},
      title: r.title ?? null,
      htmlSample: r.html !== undefined && r.html !== null ? r.html.slice(0, 128 * 1024) : null,
      redirectHops: [],
    };
    if (r.network && r.network !== "ok") resp.status = null;
    if (r.redirectTo) {
      resp.redirectHops.push({ url: r.redirectTo, decision: "followed" });
      // Redirect target evaluation happens in followRedirects.
    }
    return resp;
  }

  /** Follow a navigation chain, applying egress at every hop. */
  private navigate(url: string, purpose: ContextPurpose, policy: PolicyCore): RawResponse {
    const hops: RawResponse["redirectHops"] = [];
    let current = url;
    for (let depth = 0; depth < 8; depth++) {
      const verdict = checkEgress(policy, purpose, { url: current, method: "GET", isTopLevel: true }, this.opts);
      if (verdict.decision !== "allow") {
        if (verdict.decision === "deny-login") hops.push({ url: current, decision: "login" });
        else hops.push({ url: current, decision: "denied" });
        return {
          status: null,
          network: verdict.decision === "deny-login" ? "ok" : "policy_denied",
          headers: {}, title: null, htmlSample: null, redirectHops: hops,
        };
      }
      const resp = this.fetch(current, "GET");
      resp.redirectHops = hops;
      if (resp.network !== "ok" || resp.status === null) return resp;
      if (resp.status >= 300 && resp.status < 400 && resp.redirectHops) {
        const r = this.responseFor("GET", current);
        if (r?.redirectTo) {
          hops.push({ url: r.redirectTo, decision: "followed" });
          current = new URL(r.redirectTo, current).toString();
          continue;
        }
      }
      resp.redirectHops = hops;
      return resp;
    }
    return {
      status: null, network: "aborted", headers: {}, title: null, htmlSample: null,
      redirectHops: hops,
    };
  }

  async openContext(purpose: ContextPurpose, _policy: PolicyCore): Promise<BrowserContextHandle> {
    const ctx: BrowserContextHandle = { id: this.nextCtx++, purpose };
    this.liveContexts.set(ctx.id, purpose);
    this.contextsCreated++;
    return ctx;
  }

  async restore(_ctx: BrowserContextHandle, snapshot: unknown): Promise<void> {
    this.restoredSnapshots.push(snapshot);
  }

  async dispatch(ctx: BrowserContextHandle, action: BrowserAction, policy: PolicyCore): Promise<DispatchOutcome> {
    this._dispatchCount++;
    const behavior = this.script.dispatchBehavior ?? "normal";
    if (behavior === "throw-secret") {
      const e = new Error("Cookie: sid=fixture-secret");
      (e as Error & { url?: string }).url = "https://app.example.test/app?token=fixture-secret";
      e.stack = "fixture-stack";
      throw e;
    }
    if (behavior === "hang" || this.hangLatch) {
      return new Promise<DispatchOutcome>(() => { /* never resolves */ });
    }
    if (behavior === "crash-before-result") {
      // Simulate a dispatch whose completion can never be proven.
      return { kind: "unknown" };
    }
    if (action.kind === "navigate") {
      const resp = this.navigate(action.url, ctx.purpose, policy);
      if (resp.network === "policy_denied") return { kind: "denied", code: "SCOPE_DENIED" };
      return { kind: "ok", response: resp, text: null, truncated: false };
    }
    if (action.kind === "read") {
      const r = this.script.responses?.["read"] ?? { status: 200, text: null };
      const resp: RawResponse = {
        status: r.status ?? 200, network: r.network ?? "ok", headers: r.headers ?? {},
        title: r.title ?? null, htmlSample: r.html ?? null, redirectHops: [],
      };
      if (resp.network !== "ok") resp.status = null;
      const text = r.text ?? null;
      const truncated = text !== null && [...text].length > action.max_chars;
      return {
        kind: "ok",
        response: resp,
        text: text !== null ? [...text].slice(0, action.max_chars).join("") : null,
        truncated,
      };
    }
    // click / fill act on the loaded page; respond with the scripted outcome.
    const key = action.kind === "click" ? "click" : "fill";
    const r = this.script.responses?.[key] ?? { status: 200 };
    const resp: RawResponse = {
      status: r.status ?? 200, network: r.network ?? "ok", headers: r.headers ?? {},
      title: r.title ?? null, htmlSample: r.html ?? null, redirectHops: [],
    };
    if (resp.network !== "ok") resp.status = null;
    if (r.redirectTo) {
      // A click may trigger navigation; run the chain.
      const nav = this.navigate(r.redirectTo, ctx.purpose, policy);
      if (nav.network === "policy_denied" || nav.redirectHops.some((h) => h.decision === "denied")) {
        return { kind: "denied", code: "SCOPE_DENIED" };
      }
      nav.redirectHops = [...(nav.redirectHops ?? [])];
      return { kind: "ok", response: nav, text: null, truncated: false };
    }
    return { kind: "ok", response: resp, text: null, truncated: false };
  }

  async probe(ctx: BrowserContextHandle, policy: PolicyCore): Promise<ProbeResult> {
    const url = `${policy.origin}${policy.auth_probe.path}`;
    const resp = this.navigate(url, ctx.purpose, policy);
    return {
      response: resp,
      accountText: this.script.accountMissing ? null : (this.script.accountText ?? null),
      loggedInMatched: this.script.loggedIn ?? false,
      loggedOutPresent: (this.script.loggedOut ?? false) || (this.script.passwordInput ?? false),
    };
  }

  async openHuman(_ctx: BrowserContextHandle, policy: PolicyCore): Promise<void> {
    this.humanOpened.push(`${policy.origin}${policy.login_path}`);
  }

  async capture(_ctx: BrowserContextHandle): Promise<RawCapture> {
    if (this.script.captureFails) throw new RpcError("UNSUPPORTED_STORAGE");
    return {
      cookies: (this.script.cookies ?? []).map((c) => ({ ...c })),
      storage: (this.script.storage ?? []).map((s) => ({ ...s, pairs: s.pairs.map((p) => ({ ...p })) })),
    };
  }

  async destroy(ctx: BrowserContextHandle): Promise<void> {
    this.liveContexts.delete(ctx.id);
    this.destroyed.push(ctx.id);
  }
}
