/**
 * ghostsession CLI — owner/driver UX over the unix socket, plus local
 * lifecycle commands (init/daemon/migrate/doctor/audit verify).
 */

import { readFileSync, existsSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { RpcError, type ErrorCode } from "./errors.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { jcsHash, domainMessage, signEnvelope } from "./crypto/envelope.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import { b64Decode, b64Encode } from "./encoding/b64.js";
import { vBrowserAction, vPolicyCore, vReceipt, type DaemonConfig, type PolicyCore, type Receipt } from "./schema.js";
import { Client, UnixSocketTransport } from "./client.js";
import { initDevice, loadConfig, loadDevice, defaultConfigPath } from "./config.js";
import { isValidId, newId } from "./ids.js";

const FORBIDDEN_FLAGS = new Set([
  "--yes", "--force", "--ignore-tls", "--allow-all", "--proxy", "--import-cookies", "--cdp",
]);

interface Args {
  positional: string[];
  flags: Map<string, string | true>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      if (FORBIDDEN_FLAGS.has(a)) {
        throw new CliError(2, `unsupported flag: ${a}`);
      }
      const eq = a.indexOf("=");
      if (eq > 0) {
        flags.set(a.slice(0, eq), a.slice(eq + 1));
      } else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) {
        flags.set(a, argv[++i]!);
      } else {
        flags.set(a, true);
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

export class CliError extends Error {
  constructor(public exitCode: number, msg: string) {
    super(msg);
  }
}

function flag(args: Args, name: string): string | null {
  const v = args.flags.get(`--${name}`);
  return v === undefined ? null : v === true ? "true" : v;
}

function needFlag(args: Args, name: string): string {
  const v = flag(args, name);
  if (v === null) throw new CliError(2, `missing --${name}`);
  return v;
}

function requireUInt(s: string, name: string): number {
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < 0) throw new CliError(2, `invalid ${name}: ${s}`);
  return n;
}

function isTty(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

/** Masked local prompt — TTY only. */
async function promptSecret(label: string): Promise<string> {
  if (!isTty()) throw new CliError(3, "owner confirmation requires a controlling TTY");
  return new Promise((resolve, reject) => {
    process.stderr.write(label);
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    const stdin = process.stdin;
    const onData = (c: Buffer) => {
      const s = c.toString("utf8");
      if (s === "\n" || s === "\r" || s === "") return;
      process.stderr.write("*");
    };
    stdin.on("data", onData);
    rl.question("", (answer) => {
      stdin.off("data", onData);
      rl.close();
      process.stderr.write("\n");
      resolve(answer);
    });
    rl.on("SIGINT", () => reject(new CliError(130, "interrupted")));
  });
}

async function confirmLine(expected: string, promptText: string): Promise<void> {
  if (!isTty()) throw new CliError(3, "owner confirmation requires a controlling TTY");
  const answer = await new Promise<string>((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    rl.question(promptText, (a) => {
      rl.close();
      resolve(a.trim());
    });
  });
  if (answer !== expected) throw new CliError(3, "confirmation did not match");
}

function errorExitCode(code: ErrorCode): number {
  switch (code) {
    case "INVALID_SCHEMA":
    case "VERSION_UNSUPPORTED": return 2;
    case "UNAUTHORIZED":
    case "FORBIDDEN":
    case "SCOPE_DENIED":
    case "REPLAY": return 3;
    case "NOT_FOUND":
    case "RESULT_GONE":
    case "HANDOFF_EXPIRED": return 4;
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
    case "VAULT_CONFLICT": return 5;
    case "INTEGRITY_FAILED":
    case "KEY_UNAVAILABLE":
    case "SECURE_STORAGE_UNAVAILABLE":
    case "AUDIT_UNAVAILABLE": return 6;
    case "DEVICE_OFFLINE":
    case "TIMEOUT": return 7;
    case "CLOCK_UNSAFE":
    case "SNAPSHOT_EXPIRED":
    case "CONSENT_EXPIRED": return 8;
    case "COOLDOWN_ACTIVE":
    case "RECOVERY_EXHAUSTED":
    case "AUTH_NOT_VERIFIED":
    case "UNSUPPORTED_STORAGE": return 10;
    case "OUTCOME_UNKNOWN": return 11;
    default: return 1;
  }
}

export async function runCli(argv: string[]): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return (e as CliError).exitCode ?? 2;
  }
  if (args.flags.has("--help") || args.positional.length === 0) {
    printHelp();
    return args.positional.length === 0 && !args.flags.has("--help") ? 2 : 0;
  }
  if (args.flags.has("--version")) {
    process.stdout.write("ghostsession 0.1.0 protocol v1\n");
    return 0;
  }
  const json = args.flags.has("--json");
  const timeoutMs = flag(args, "timeout-ms") ? requireUInt(flag(args, "timeout-ms")!, "timeout-ms") : 30_000;
  if (timeoutMs < 1_000 || timeoutMs > 120_000) {
    process.stderr.write("timeout-ms out of range 1000..120000\n");
    return 2;
  }
  const configPath = flag(args, "config") ?? defaultConfigPath();
  const socketPath = flag(args, "socket");

  try {
    return await dispatchCommand(args, { json, timeoutMs, configPath, socketPath });
  } catch (e) {
    if (e instanceof CliError) {
      process.stderr.write(`${e.message}\n`);
      return e.exitCode;
    }
    if (e instanceof RpcError) {
      process.stderr.write(`${e.code}\n`);
      return errorExitCode(e.code);
    }
    const f = e as { code?: string };
    if (f && typeof f.code === "string" && f.code.length > 2) {
      process.stderr.write(`${f.code}\n`);
      return errorExitCode(f.code as ErrorCode);
    }
    process.stderr.write(`INTERNAL\n`);
    return 1;
  }
}

interface Ctx {
  json: boolean;
  timeoutMs: number;
  configPath: string;
  socketPath: string | null;
}

function emit(ctx: Ctx, result: unknown): void {
  if (ctx.json) {
    process.stdout.write(jcsString(result) + "\n");
  } else {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  }
}

async function ownerSocket(ctx: Ctx): Promise<string> {
  if (ctx.socketPath) return ctx.socketPath;
  const cfg = loadConfig(ctx.configPath);
  return `${cfg.runtime_dir}/owner.sock`;
}

async function driverSocket(ctx: Ctx): Promise<string> {
  if (ctx.socketPath) return ctx.socketPath;
  const cfg = loadConfig(ctx.configPath);
  return `${cfg.runtime_dir}/driver.sock`;
}

async function client(ctx: Ctx, which: "owner" | "driver"): Promise<Client> {
  const sock = which === "owner" ? await ownerSocket(ctx) : await driverSocket(ctx);
  return new Client(new UnixSocketTransport(sock, ctx.timeoutMs));
}

async function callOrExit(c: Client, method: string, params: unknown): Promise<unknown> {
  try {
    return await c.call(method, params);
  } catch (e) {
    throw e;
  }
}

async function dispatchCommand(args: Args, ctx: Ctx): Promise<number> {
  const [cmd, sub, ...rest] = args.positional;
  const positional = rest;

  if (cmd === "init") {
    const label = flag(args, "device-label") ?? undefined;
    const { result } = initDevice({
      configPath: ctx.configPath,
      deviceLabel: label,
      allowFileKeychain: process.env.GHOSTSESSION_INSECURE_FILE_KEYCHAIN === "1",
    });
    emit(ctx, result);
    return 0;
  }

  if (cmd === "daemon") {
    if (sub === "start") {
      const { startDaemonProcess } = await import("./daemon-main.js");
      return startDaemonProcess(ctx, Boolean(args.flags.has("--foreground")));
    }
    if (sub === "status") {
      const c = await client(ctx, "owner");
      try {
        const r = await c.call("system.status", {});
        emit(ctx, r);
        return 0;
      } catch {
        process.stderr.write("daemon not running\n");
        return 7;
      }
    }
    throw new CliError(2, "daemon requires start|status");
  }

  if (cmd === "doctor") {
    const { runDoctor } = await import("./doctor.js");
    return runDoctor(ctx);
  }

  if (cmd === "migrate") {
    const { runMigrate } = await import("./migrate.js");
    const check = args.flags.has("--check");
    const apply = args.flags.has("--apply");
    if (check === apply) throw new CliError(2, "migrate requires exactly one of --check/--apply");
    return runMigrate(ctx, apply);
  }

  if (cmd === "audit" && sub === "verify") {
    const input = needFlag(args, "input");
    const trust = needFlag(args, "trust");
    const expectedTip = flag(args, "expected-tip");
    const { verifyAuditFile } = await import("./audit-verify.js");
    const out = verifyAuditFile(input, trust, expectedTip);
    emit(ctx, out);
    return 0;
  }

  if (cmd === "site" && sub === "enroll") {
    const policyPath = needFlag(args, "policy");
    const accountRef = needFlag(args, "account-ref");
    return enrollSite(ctx, policyPath, accountRef);
  }

  if (cmd === "session") {
    const c = await client(ctx, "owner");
    switch (sub) {
      case "create": {
        const site = needFlag(args, "site");
        emit(ctx, await callOrExit(c, "session.create", { site_id: site }));
        return 0;
      }
      case "get":
      case "attach":
      case "renew":
      case "step":
      case "checkpoint":
      case "detach":
      case "recover":
      case "revoke":
      case "delete": {
        const useDriver = sub !== "revoke" && sub !== "delete" && sub !== "recover";
        const cc = useDriver ? await client(ctx, "driver") : c;
        return sessionCommand(sub, cc, args, ctx, positional);
      }
      default:
        throw new CliError(2, `unknown session subcommand: ${sub}`);
    }
  }

  if (cmd === "inbox") {
    const c = await client(ctx, "owner");
    switch (sub) {
      case "get":
        emit(ctx, await callOrExit(c, "handoff.get", { handoff_id: positional[0] }));
        return 0;
      case "open": {
        const id = positional[0];
        if (!id) throw new CliError(2, "missing HANDOFF_ID");
        emit(ctx, await callOrExit(c, "handoff.open", { handoff_id: id }));
        return 0;
      }
      case "resolve": {
        const id = positional[0];
        const ready = args.flags.has("--ready");
        const cancel = args.flags.has("--cancel");
        if (ready === cancel) throw new CliError(2, "exactly one of --ready/--cancel");
        emit(ctx, await callOrExit(c, "handoff.resolve", { handoff_id: id, decision: ready ? "ready" : "cancel" }));
        return 0;
      }
      default:
        throw new CliError(2, `unknown inbox subcommand: ${sub}`);
    }
  }

  if (cmd === "audit" && sub === "export") {
    const c = await client(ctx, "owner");
    const sessionId = positional[0];
    if (!sessionId) throw new CliError(2, "missing SESSION_ID");
    const afterSeq = flag(args, "after-seq") ? requireUInt(flag(args, "after-seq")!, "after-seq") : 0;
    const limit = flag(args, "limit") ? requireUInt(flag(args, "limit")!, "limit") : 100;
    let after = afterSeq;
    let count = 0;
    for (;;) {
      const page = await callOrExit(c, "audit.list", { session_id: sessionId, after_seq: after, limit }) as {
        entries: unknown[]; next_after_seq: number;
      };
      for (const e2 of page.entries) {
        process.stdout.write(jcsString(e2) + "\n");
        count++;
      }
      if (page.entries.length === 0 || page.next_after_seq === after) break;
      after = page.next_after_seq;
    }
    process.stderr.write(`exported ${count} receipts\n`);
    return 0;
  }

  if (cmd === "vault") {
    const c = await client(ctx, "owner");
    if (sub === "sync") {
      const mode = needFlag(args, "mode");
      if (mode !== "upload" && mode !== "restore") throw new CliError(2, "--mode upload|restore");
      emit(ctx, await callOrExit(c, "vault.sync", { session_id: positional[0], mode }));
      return 0;
    }
    if (sub === "rotate") {
      emit(ctx, await callOrExit(c, "vault.rotate", { session_id: positional[0] }));
      return 0;
    }
    throw new CliError(2, `unknown vault subcommand: ${sub}`);
  }

  throw new CliError(2, `unknown command: ${[cmd, sub].filter(Boolean).join(" ")}`);
}

async function sessionCommand(
  sub: string, c: Client, args: Args, ctx: Ctx, positional: string[],
): Promise<number> {
  const id = positional[0];
  if (!id || !isValidId(id, "gs")) throw new CliError(2, "missing or invalid SESSION_ID");
  switch (sub) {
    case "get":
      emit(ctx, await callOrExit(c, "session.get", { session_id: id }));
      return 0;
    case "attach": {
      const run = needFlag(args, "run");
      const gen = requireUInt(needFlag(args, "generation"), "generation");
      emit(ctx, await callOrExit(c, "session.attach", { session_id: id, run_id: run, expected_generation: gen }));
      return 0;
    }
    case "renew": {
      const lease = needFlag(args, "lease");
      const fence = requireUInt(needFlag(args, "fence"), "fence");
      emit(ctx, await callOrExit(c, "session.renew", { session_id: id, lease_id: lease, fence }));
      return 0;
    }
    case "step": {
      const lease = needFlag(args, "lease");
      const fence = requireUInt(needFlag(args, "fence"), "fence");
      const op = needFlag(args, "operation");
      const file = needFlag(args, "action-file");
      const st = statSync(file);
      if (!st.isFile() || (st.mode & 0o077) !== 0) {
        throw new CliError(2, "action file must be owner-private (0600)");
      }
      const action = vBrowserAction(parseStrictJson(readFileSync(file)), "action");
      const res = await callOrExit(c, "session.step", {
        session_id: id, lease_id: lease, fence, operation_id: op, action,
      }) as { outcome: string };
      emit(ctx, res);
      return res.outcome === "DENIED" ? 3 : res.outcome === "BLOCKED" ? 10 : res.outcome === "UNKNOWN" ? 11 : 0;
    }
    case "checkpoint": {
      const lease = needFlag(args, "lease");
      const fence = requireUInt(needFlag(args, "fence"), "fence");
      emit(ctx, await callOrExit(c, "session.checkpoint", { session_id: id, lease_id: lease, fence }));
      return 0;
    }
    case "detach": {
      const lease = needFlag(args, "lease");
      const fence = requireUInt(needFlag(args, "fence"), "fence");
      const ck = args.flags.has("--checkpoint");
      const disc = args.flags.has("--discard");
      if (ck === disc) throw new CliError(2, "exactly one of --checkpoint/--discard");
      emit(ctx, await callOrExit(c, "session.detach", { session_id: id, lease_id: lease, fence, checkpoint: ck }));
      return 0;
    }
    case "recover": {
      const intent = needFlag(args, "intent");
      if (!["retry", "fallback", "reauth", "acknowledge_unknown"].includes(intent)) {
        throw new CliError(2, "--intent retry|fallback|reauth|acknowledge_unknown");
      }
      const rev = flag(args, "block-revision");
      const blockRevision = rev === null ? null : requireUInt(rev, "block-revision");
      if ((intent === "retry" || intent === "fallback") && blockRevision === null) {
        throw new CliError(2, "retry/fallback require --block-revision");
      }
      emit(ctx, await callOrExit(c, "session.recover", { session_id: id, block_revision: blockRevision, intent }));
      return 0;
    }
    case "revoke": {
      await confirmLine(id, `type session ID to confirm revoke: `);
      emit(ctx, await callOrExit(c, "session.revoke", { session_id: id }));
      return 0;
    }
    case "delete": {
      const gen = requireUInt(needFlag(args, "generation"), "generation");
      await confirmLine(`delete ${id} ${gen}`, `type 'delete ${id} ${gen}' to confirm: `);
      emit(ctx, await callOrExit(c, "session.delete", { session_id: id, confirm_generation: gen }));
      return 0;
    }
    default:
      throw new CliError(2, `unknown session subcommand: ${sub}`);
  }
}

async function enrollSite(ctx: Ctx, policyPath: string, accountRef: string): Promise<number> {
  const cfg = loadConfig(ctx.configPath);
  const { platformKeychain } = await import("./store/keychain.js");
  const keychain = platformKeychain(
    cfg.data_dir, process.env.GHOSTSESSION_INSECURE_FILE_KEYCHAIN === "1",
  );
  const device = loadDevice(cfg, keychain);
  const core = vPolicyCore(parseStrictJson(readFileSync(policyPath)), "policy") as PolicyCore;
  // Display the exact scope before binding the account.
  process.stderr.write(
    `site enrollment:\n  origin: ${core.origin}\n  login: ${core.login_path}\n` +
    `  agent paths: ${core.agent_paths.join(", ") || "(none)"}\n` +
    `  methods: ${core.methods.join(", ")}\n  consent until: ${new Date(core.consent_expires_ms).toISOString()}\n`,
  );
  const accountText = await promptSecret("expected account text (masked): ");
  const refName = accountRef.replace(/^keychain:/, "");
  if (core.auth_probe.expected_account_ref !== `keychain:${refName}` && core.auth_probe.expected_account_ref !== accountRef) {
    throw new CliError(2, "account-ref must match policy expected_account_ref");
  }
  keychain.set(refName, Buffer.from(accountText, "utf8"));
  const signed = signEnvelope("policy", { ...core, signing_key_id: device.signingKeyId }, device.signingSeed);
  const c = await client(ctx, "owner");
  const res = await callOrExit(c, "site.put", { policy: signed });
  emit(ctx, res);
  return 0;
}

function printHelp(): void {
  process.stdout.write(`ghostsession — browser-agent session persistence and controlled recovery

usage: ghostsession [--config PATH] [--socket PATH] [--json] [--timeout-ms N] <command>

commands:
  init --device-label NAME
  daemon start [--foreground] | daemon status
  doctor [--json]
  migrate --check|--apply
  site enroll --policy PATH --account-ref REF
  session create --site ID | get ID | attach ID --run ID --generation N
  session renew ID --lease ID --fence N
  session step ID --lease ID --fence N --operation ID --action-file PATH
  session checkpoint ID --lease ID --fence N
  session detach ID --lease ID --fence N --checkpoint|--discard
  session recover ID --intent INTENT [--block-revision N]
  session revoke ID | session delete ID --generation N
  inbox get ID | inbox open ID | inbox resolve ID --ready|--cancel
  audit export ID [--after-seq N] [--limit N] | audit verify --input P --trust P [--expected-tip H]
  vault sync ID --mode upload|restore | vault rotate ID
`);
}
