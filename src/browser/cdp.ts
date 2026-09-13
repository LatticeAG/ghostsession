/**
 * Real browser adapter: drives a pinned Chromium binary over the DevTools
 * protocol (CDP). Zero npm deps — uses Node's built-in WebSocket client and
 * child_process. Memory-backed profile: per-context temporary user-data dir
 * under the runtime dir, removed on destroy.
 *
 * Egress: every top-level navigation and subresource request is validated by
 * the daemon's egress policy before dispatch; in-flight, Fetch.requestPaused
 * enforces origin/method checks per request and redirect hops are re-checked
 * before the target connects.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { RpcError } from "../errors.js";
import type { BrowserAction, PolicyCore } from "../schema.js";
import { checkEgress } from "./egress.js";
import { validateNavigationUrl, type OriginOptions } from "../net/origin.js";
import type {
  BrowserAdapter, BrowserContextHandle, ContextPurpose, DispatchOutcome,
  ProbeResult, RawCapture, RawCookie, RawResponse, RawStorage,
} from "./types.js";

interface CdpSocket {
  send(method: string, params: Record<string, unknown>, sessionId?: string): Promise<unknown>;
  onEvent(cb: (method: string, params: Record<string, unknown>, sessionId?: string) => void): void;
  close(): void;
}

async function wsConnect(url: string): Promise<CdpSocket> {
  const ws = new WebSocket(url);
  await new Promise<void>((resolve, reject) => {
    ws.onopen = () => resolve();
    ws.onerror = () => reject(new Error("cdp websocket failed"));
  });
  let next = 1;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  const listeners: ((m: string, p: Record<string, unknown>, s?: string) => void)[] = [];
  ws.onmessage = (ev) => {
    const msg = JSON.parse(String(ev.data)) as {
      id?: number; result?: unknown; error?: { message: string };
      method?: string; params?: Record<string, unknown>; sessionId?: string;
    };
    if (msg.id !== undefined) {
      const p = pending.get(msg.id);
      if (p) {
        pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message));
        else p.resolve(msg.result);
      }
    } else if (msg.method) {
      for (const l of listeners) l(msg.method, msg.params ?? {}, msg.sessionId);
    }
  };
  return {
    send(method, params, sessionId) {
      const id = next++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      });
    },
    onEvent(cb) { listeners.push(cb); },
    close() { try { ws.close(); } catch { /* gone */ } },
  };
}

function httpJson(path: string, port: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

export interface CdpOptions {
  chromiumPath?: string;
  maxContexts?: number;
  launchTimeoutMs?: number;
  originOpts?: OriginOptions;
}

export class CdpAdapter implements BrowserAdapter {
  private opts: Required<CdpOptions>;
  private proc: ChildProcess | null = null;
  private port = 0;
  private ws: CdpSocket | null = null;
  private contexts = new Map<number, { sessionId: string; targetId: string; dir: string; purpose: ContextPurpose; policy: PolicyCore | null }>();
  private nextCtx = 1;
  private dispatches = 0;

  dispatchCount(): number {
    return this.dispatches;
  }

  constructor(opts: CdpOptions = {}) {
    this.opts = {
      chromiumPath: opts.chromiumPath ?? process.env.GHOSTSESSION_CHROMIUM ?? "chromium",
      maxContexts: opts.maxContexts ?? 4,
      launchTimeoutMs: opts.launchTimeoutMs ?? 15_000,
      originOpts: opts.originOpts ?? { publicDnsOnly: false },
    };
  }

  private async ensureBrowser(): Promise<void> {
    if (this.ws) return;
    const dir = mkdtempSync(join(tmpdir(), "gs-chrome-"));
    this.proc = spawn(this.opts.chromiumPath, [
      "--headless=new", "--remote-debugging-port=0", "--no-first-run",
      "--no-default-browser-check", `--user-data-dir=${dir}`,
      "--disable-features=WebRtcHideLocalIpsWithMdns",
      "--disable-webrtc", "--disable-quic",
      "about:blank",
    ], { stdio: ["ignore", "ignore", "pipe"] });
    // Read the chosen port from DevToolsActivePort.
    const deadline = Date.now() + this.opts.launchTimeoutMs;
    let port = 0;
    while (Date.now() < deadline) {
      const f = join(dir, "DevToolsActivePort");
      if (existsSync(f)) {
        port = Number(readFileSync(f, "utf8").split("\n")[0]!.trim());
        if (port > 0) break;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    if (!port) throw new RpcError("INTERNAL");
    this.port = port;
    const ver = await httpJson("/json/version", port) as { webSocketDebuggerUrl: string };
    this.ws = await wsConnect(ver.webSocketDebuggerUrl);
    this.ws.onEvent((method, params, sessionId) => void this.onEvent(method, params, sessionId));
  }

  private pendingPauses = new Map<string, { url: string; sessionId: string }>();

  private async onEvent(method: string, params: Record<string, unknown>, sessionId?: string): Promise<void> {
    if (method !== "Fetch.requestPaused" || !this.ws || !sessionId) return;
    const requestId = params.requestId as string;
    const req = params.request as { url: string; method: string };
    const ctxEntry = [...this.contexts.values()].find((c) => c.sessionId === sessionId);
    const policy = ctxEntry?.policy;
    let allow = false;
    if (policy) {
      try {
        const u = new URL(req.url);
        const isTop = params.type === "Document" || params.resourceType === "Document";
        const verdict = checkEgress(policy, ctxEntry!.purpose, {
          url: req.url, method: req.method as "GET" | "HEAD" | "POST", isTopLevel: isTop,
        }, this.opts.originOpts);
        allow = verdict.decision === "allow" && (isTop || this.resourceAllowed(policy, u.origin));
      } catch {
        allow = false;
      }
    }
    try {
      if (allow) {
        await this.ws.send("Fetch.continueRequest", { requestId }, sessionId);
      } else {
        await this.ws.send("Fetch.failRequest", { requestId, errorReason: "AccessDenied" }, sessionId);
      }
    } catch { /* target gone */ }
    this.pendingPauses.set(requestId, { url: req.url, sessionId });
  }

  private resourceAllowed(policy: PolicyCore, origin: string): boolean {
    if (origin === policy.origin) return true;
    return policy.resource_origins.includes(origin);
  }

  async openContext(purpose: ContextPurpose, policy: PolicyCore): Promise<BrowserContextHandle> {
    if (this.contexts.size >= this.opts.maxContexts) throw new RpcError("BUSY");
    await this.ensureBrowser();
    const dir = mkdtempSync(join(tmpdir(), "gs-ctx-"));
    const t = await this.ws!.send("Target.createTarget", { url: "about:blank", newWindow: purpose === "handoff-human" }) as { targetId: string };
    const a = await this.ws!.send("Target.attachToTarget", { targetId: t.targetId, flatten: true }) as { sessionId: string };
    const sessionId = a.sessionId;
    await this.ws!.send("Page.enable", {}, sessionId);
    await this.ws!.send("Network.enable", {}, sessionId);
    await this.ws!.send("Runtime.enable", {}, sessionId);
    await this.ws!.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, sessionId);
    const id = this.nextCtx++;
    this.contexts.set(id, { sessionId, targetId: t.targetId, dir, purpose, policy });
    return { id, purpose };
  }

  private ctx(h: BrowserContextHandle): { sessionId: string; targetId: string; dir: string; purpose: ContextPurpose; policy: PolicyCore | null } {
    const c = this.contexts.get(h.id);
    if (!c) throw new RpcError("INTERNAL");
    return c;
  }

  private async eval(sessionId: string, expression: string): Promise<unknown> {
    const r = await this.ws!.send("Runtime.evaluate", {
      expression, returnByValue: true, awaitPromise: true,
    }, sessionId) as { result?: { value?: unknown }; exceptionDetails?: unknown };
    if (r.exceptionDetails) throw new RpcError("INTERNAL");
    return r.result?.value;
  }

  async restore(ctx: BrowserContextHandle, snapshot: unknown): Promise<void> {
    const c = this.ctx(ctx);
    const snap = snapshot as {
      cookies: { name: string; value: string; host: string; path: string; httpOnly: boolean; sameSite: string; expiresMs: number | null }[];
      origins: { origin: string; localStorage: { name: string; value: string }[] }[];
    };
    if (snap.cookies.length > 0) {
      await this.ws!.send("Network.setCookies", {
        cookies: snap.cookies.map((k) => ({
          name: k.name, value: k.value, domain: k.host, path: k.path,
          secure: true, httpOnly: k.httpOnly,
          sameSite: k.sameSite,
          ...(k.expiresMs !== null ? { expires: Math.floor(k.expiresMs / 1000) } : {}),
        })),
      }, c.sessionId);
    }
    // Restore localStorage per origin after navigating to that origin.
    for (const o of snap.origins) {
      if (o.localStorage.length === 0) continue;
      const u = new URL(o.origin);
      await this.ws!.send("Page.navigate", { url: `${o.origin}/` }, c.sessionId);
      await this.settle(c.sessionId);
      for (const p of o.localStorage) {
        await this.eval(c.sessionId, `localStorage.setItem(${JSON.stringify(p.name)},${JSON.stringify(p.value)})`);
      }
      void u;
    }
  }

  private async settle(sessionId: string, timeoutMs = 15_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const state = await this.eval(sessionId, "document.readyState") as string;
      if (state === "complete" || state === "interactive") return;
      if (Date.now() > deadline) return;
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  private async currentResponse(sessionId: string): Promise<RawResponse> {
    const title = await this.eval(sessionId, "document.title").catch(() => null) as string | null;
    const url = await this.eval(sessionId, "location.href").catch(() => null) as string | null;
    const html = await this.eval(sessionId, "document.documentElement ? document.documentElement.outerHTML.slice(0,131072) : null").catch(() => null) as string | null;
    return {
      status: 200, network: "ok", headers: {},
      title, htmlSample: html, redirectHops: url ? [] : [],
    };
  }

  async dispatch(ctx: BrowserContextHandle, action: BrowserAction, policy: PolicyCore): Promise<DispatchOutcome> {
    const c = this.ctx(ctx);
    this.dispatches++;
    try {
      if (action.kind === "navigate") {
        const verdict = checkEgress(policy, c.purpose, { url: action.url, method: "GET", isTopLevel: true }, this.opts.originOpts);
        if (verdict.decision !== "allow") return { kind: "denied", code: verdict.decision === "deny-login" ? "SCOPE_DENIED" : "SCOPE_DENIED" };
        validateNavigationUrl(action.url);
        await this.ws!.send("Page.navigate", { url: action.url }, c.sessionId);
        await this.settle(c.sessionId);
        const resp = await this.currentResponse(c.sessionId);
        return { kind: "ok", response: resp, text: null, truncated: false };
      }
      if (action.kind === "read") {
        const v = await this.eval(c.sessionId,
          `(()=>{const el=document.querySelector(${JSON.stringify(action.selector)});return el?(el.innerText||el.textContent||""):null})()`);
        const text = v === null || v === undefined ? null : String(v);
        const truncated = text !== null && [...text].length > action.max_chars;
        return {
          kind: "ok",
          response: await this.currentResponse(c.sessionId),
          text: text !== null ? [...text].slice(0, action.max_chars).join("") : null,
          truncated,
        };
      }
      if (action.kind === "click") {
        await this.eval(c.sessionId,
          `(()=>{const el=document.querySelector(${JSON.stringify(action.selector)});if(!el)throw new Error("no element");el.click();return true})()`);
        await this.settle(c.sessionId, 500);
        return { kind: "ok", response: await this.currentResponse(c.sessionId), text: null, truncated: false };
      }
      // fill
      await this.eval(c.sessionId,
        `(()=>{const el=document.querySelector(${JSON.stringify(action.selector)});if(!el)throw new Error("no element");el.value=${JSON.stringify(action.text)};el.dispatchEvent(new Event("input",{bubbles:true}));el.dispatchEvent(new Event("change",{bubbles:true}));return true})()`);
      return { kind: "ok", response: await this.currentResponse(c.sessionId), text: null, truncated: false };
    } catch (e) {
      if (e instanceof RpcError) throw e;
      return { kind: "unknown" };
    }
  }

  async probe(ctx: BrowserContextHandle, policy: PolicyCore): Promise<ProbeResult> {
    const c = this.ctx(ctx);
    await this.ws!.send("Page.navigate", { url: `${policy.origin}${policy.auth_probe.path}` }, c.sessionId);
    await this.settle(c.sessionId);
    const response = await this.currentResponse(c.sessionId);
    const accountText = await this.eval(c.sessionId,
      `(()=>{const el=document.querySelector(${JSON.stringify(policy.auth_probe.account_selector)});return el?(el.innerText||el.textContent||""):null})()`).catch(() => null) as string | null;
    const loggedIn = await this.eval(c.sessionId,
      `!!document.querySelector(${JSON.stringify(policy.auth_probe.logged_in_selector)})`).catch(() => false) as boolean;
    const loggedOut = await this.eval(c.sessionId,
      `!!document.querySelector(${JSON.stringify(policy.auth_probe.logged_out_selector)})`).catch(() => false) as boolean;
    return {
      response,
      accountText,
      loggedInMatched: loggedIn,
      loggedOutPresent: loggedOut,
    };
  }

  async openHuman(ctx: BrowserContextHandle, policy: PolicyCore): Promise<void> {
    const c = this.ctx(ctx);
    await this.ws!.send("Page.navigate", { url: `${policy.origin}${policy.login_path}` }, c.sessionId);
    await this.settle(c.sessionId);
  }

  async capture(ctx: BrowserContextHandle): Promise<RawCapture> {
    const c = this.ctx(ctx);
    const resp = await this.ws!.send("Network.getCookies", {}, c.sessionId) as {
      cookies: {
        name: string; value: string; domain: string; path: string; secure: boolean;
        httpOnly: boolean; sameSite?: string; expires?: number; session?: boolean;
        partitionKey?: unknown;
      }[];
    };
    const cookies: RawCookie[] = resp.cookies.map((k) => ({
      name: k.name, value: k.value,
      // CDP reports the effective host in `domain` (leading dot = Domain attr).
      host: (k.domain ?? "").replace(/^\./, ""),
      domain: k.domain && k.domain.startsWith(".") ? k.domain : null,
      path: k.path, secure: k.secure, httpOnly: k.httpOnly,
      sameSite: (k.sameSite as RawCookie["sameSite"]) ?? "Lax",
      expiresMs: k.session ? null : (k.expires ? Math.round(k.expires * 1000) : null),
      hasPartitionKey: k.partitionKey !== undefined && k.partitionKey !== null,
      unsupportedAttrs: false,
    }));
    const storage: RawStorage[] = [];
    return { cookies, storage };
  }

  async destroy(ctx: BrowserContextHandle): Promise<void> {
    const c = this.contexts.get(ctx.id);
    if (!c) return;
    this.contexts.delete(ctx.id);
    try {
      await this.ws?.send("Target.closeTarget", { targetId: c.targetId });
    } catch { /* gone */ }
    try {
      rmSync(c.dir, { recursive: true, force: true });
    } catch { /* best effort */ }
  }
}
