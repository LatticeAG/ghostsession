/**
 * OS keychain abstraction (spec §7).
 *
 * Namespaces: ghostsession/signing/KEY_ID, ghostsession/encryption/KEY_ID,
 * ghostsession/account/SITE_ID, ghostsession/audit-binding/DEVICE_ID,
 * ghostsession/audit-tip/SESSION_ID, ghostsession/cache/DEVICE_ID,
 * ghostsession/backup/DEVICE_ID.
 *
 * Implementations:
 *  - SecretServiceKeychain: Linux org.freedesktop.secrets via libsecret's
 *    `secret-tool` (sync spawn, no external deps). Absent provider or tool →
 *    SECURE_STORAGE_UNAVAILABLE, fail closed.
 *  - MacosKeychain: macOS `security` CLI, same contract.
 *  - FileKeychain: owner-only files under a 0700 directory. Used by the test
 *    harness and by the explicit `--insecure-file-keychain` escape hatch —
 *    never the default.
 *  - MemoryKeychain: tests only.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { RpcError } from "../errors.js";

export interface Keychain {
  get(name: string): Buffer | null;
  set(name: string, value: Buffer): void;
  delete(name: string): void;
  has(name: string): boolean;
  describe(): string;
}

export class MemoryKeychain implements Keychain {
  private m = new Map<string, Buffer>();
  get(name: string): Buffer | null {
    const v = this.m.get(name);
    return v ? Buffer.from(v) : null;
  }
  set(name: string, value: Buffer): void {
    this.m.set(name, Buffer.from(value));
  }
  delete(name: string): void {
    this.m.delete(name);
  }
  has(name: string): boolean {
    return this.m.has(name);
  }
  describe(): string {
    return "memory";
  }
}

export class FileKeychain implements Keychain {
  constructor(private dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
  }
  private path(name: string): string {
    const fn = createHash("sha256").update(name).digest("hex") + ".key";
    return join(this.dir, fn);
  }
  get(name: string): Buffer | null {
    try {
      return readFileSync(this.path(name));
    } catch {
      return null;
    }
  }
  set(name: string, value: Buffer): void {
    const p = this.path(name);
    writeFileSync(p, value, { mode: 0o600 });
    chmodSync(p, 0o600);
  }
  delete(name: string): void {
    try { rmSync(this.path(name)); } catch { /* absent */ }
  }
  has(name: string): boolean {
    return existsSync(this.path(name));
  }
  describe(): string {
    return `insecure-file:${this.dir}`;
  }
}

function runQuiet(cmd: string, args: string[], input?: Buffer): Buffer | null {
  try {
    return execFileSync(cmd, args, { input: input ?? Buffer.alloc(0), stdio: ["pipe", "pipe", "pipe"] });
  } catch {
    return null;
  }
}

function onPath(cmd: string): boolean {
  const pathEnv = process.env.PATH ?? "/usr/bin:/bin";
  return pathEnv.split(":").some((d) => existsSync(join(d, cmd)));
}

/** Linux Secret Service via libsecret's secret-tool. */
export class SecretServiceKeychain implements Keychain {
  static available(): boolean {
    if (!onPath("secret-tool")) return false;
    // The tool exists; the service may not. A lookup that cannot reach the
    // daemon exits non-zero the same as a miss, so presence of the tool plus
    // a session bus address is our availability signal.
    return process.env.DBUS_SESSION_BUS_ADDRESS !== undefined ||
      existsSync(`/run/user/${process.getuid?.() ?? 0}/bus`);
  }

  private args(name: string): string[] {
    return ["service", "ghostsession", "item", name];
  }

  get(name: string): Buffer | null {
    const out = runQuiet("secret-tool", ["lookup", ...this.args(name)]);
    if (out === null) return null;
    const s = out.toString("utf8").replace(/\n$/, "");
    try {
      return Buffer.from(s, "base64url");
    } catch {
      return null;
    }
  }

  set(name: string, value: Buffer): void {
    const r = runQuiet(
      "secret-tool",
      ["store", "--label=GhostSession", ...this.args(name)],
      Buffer.from(value.toString("base64url")),
    );
    if (r === null) throw new RpcError("SECURE_STORAGE_UNAVAILABLE");
  }

  delete(name: string): void {
    runQuiet("secret-tool", ["clear", ...this.args(name)]);
  }

  has(name: string): boolean {
    return this.get(name) !== null;
  }

  describe(): string {
    return "secret-service";
  }
}

/** macOS Keychain via the `security` CLI, same contract. */
export class MacosKeychain implements Keychain {
  static available(): boolean {
    return process.platform === "darwin" && runQuiet("which", ["security"]) !== null;
  }

  get(name: string): Buffer | null {
    const out = runQuiet("security", [
      "find-generic-password", "-s", "ghostsession", "-a", name, "-w",
    ]);
    if (out === null) return null;
    try {
      return Buffer.from(out.toString("utf8").replace(/\n$/, ""), "base64url");
    } catch {
      return null;
    }
  }

  set(name: string, value: Buffer): void {
    const r = runQuiet("security", [
      "add-generic-password", "-U", "-s", "ghostsession", "-a", name,
      "-w", value.toString("base64url"),
    ]);
    if (r === null) throw new RpcError("SECURE_STORAGE_UNAVAILABLE");
  }

  delete(name: string): void {
    runQuiet("security", ["delete-generic-password", "-s", "ghostsession", "-a", name]);
  }

  has(name: string): boolean {
    return this.get(name) !== null;
  }

  describe(): string {
    return "macos-keychain";
  }
}

/**
 * Pick the platform keychain. `allowFileFallback` is the explicit, disclosed
 * dev/test escape — without a usable keychain enrollment must fail
 * SECURE_STORAGE_UNAVAILABLE rather than silently weaken storage.
 */
export function platformKeychain(dataDir: string, allowFileFallback: boolean): Keychain {
  if (process.platform === "darwin" && MacosKeychain.available()) return new MacosKeychain();
  if (process.platform === "linux" && SecretServiceKeychain.available()) return new SecretServiceKeychain();
  if (allowFileFallback) return new FileKeychain(join(dataDir, "keychain"));
  throw new RpcError("SECURE_STORAGE_UNAVAILABLE");
}

export function readdirKeychainStubs(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}
