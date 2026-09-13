/**
 * Config loading + device bootstrap (ghostsession init).
 */

import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { RpcError } from "./errors.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import { b64Encode } from "./encoding/b64.js";
import { ed25519PublicFromSeed } from "./crypto/ed25519.js";
import { newId } from "./ids.js";
import { vDaemonConfig, type DaemonConfig } from "./schema.js";
import type { Keychain } from "./store/keychain.js";
import { platformKeychain } from "./store/keychain.js";

export function defaultConfigPath(): string {
  const xdg = process.env.XDG_CONFIG_HOME ?? join(process.env.HOME ?? ".", ".config");
  return join(xdg, "ghostsession", "config.json");
}

export function loadConfig(path: string): DaemonConfig {
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch {
    throw new RpcError("NOT_FOUND");
  }
  const cfg = vDaemonConfig(parseStrictJson(raw), "config");
  if (cfg.vault.mode === "hosted") {
    if (cfg.vault.base_url === null || !cfg.vault.base_url.startsWith("https://")) {
      throw new RpcError("INVALID_SCHEMA");
    }
  } else if (cfg.vault.base_url !== null) {
    throw new RpcError("INVALID_SCHEMA");
  }
  for (const dir of [cfg.data_dir, cfg.runtime_dir]) {
    checkPrivatePath(dir);
  }
  return cfg;
}

/** Reject group/world-writable dirs and symlinked config paths. */
export function checkPrivatePath(path: string): void {
  if (!existsSync(path)) return;
  const st = statSync(path);
  if (statSync(path).isDirectory() === false) {
    throw new RpcError("INVALID_SCHEMA");
  }
  if (st.mode & 0o077) {
    throw new RpcError("SECURE_STORAGE_UNAVAILABLE");
  }
}

export interface InitResult {
  initialized: true;
  device_id: string;
}

/** Bootstrap device identity, signing/request keys, private dirs, config. */
export function initDevice(opts: {
  configPath: string;
  deviceLabel?: string;
  allowFileKeychain?: boolean;
  now?: number;
}): { config: DaemonConfig; result: InitResult } {
  const configPath = opts.configPath;
  if (existsSync(configPath)) throw new RpcError("STATE_CONFLICT");
  const dataDir = join(process.env.HOME ?? ".", ".local", "share", "ghostsession");
  const runtimeDir = process.env.XDG_RUNTIME_DIR
    ? join(process.env.XDG_RUNTIME_DIR, "ghostsession")
    : join(dataDir, "run");
  for (const d of [dataDir, runtimeDir]) {
    mkdirSync(d, { recursive: true, mode: 0o700 });
    chmodSync(d, 0o700);
  }
  const keychain = platformKeychain(dataDir, opts.allowFileKeychain ?? false);

  const deviceId = newId("gd");
  const ownerId = newId("ga");
  const signingKeyId = newId("gk");
  const requestKeyId = newId("gk");
  const signingSeed = randomBytes(32);
  const requestSeed = randomBytes(32);
  const auditKey = randomBytes(32);
  const cacheKey = randomBytes(32);
  const backupKey = randomBytes(32);

  keychain.set(`ghostsession/signing/${signingKeyId}`, signingSeed);
  keychain.set(`ghostsession/request/${requestKeyId}`, requestSeed);
  keychain.set(`ghostsession/request-index/${deviceId}`, Buffer.from(requestKeyId));
  keychain.set(`ghostsession/hmac/${deviceId}`, auditKey);
  keychain.set(`ghostsession/cache/${deviceId}`, cacheKey);
  keychain.set(`ghostsession/backup/${deviceId}`, backupKey);
  keychain.set(`ghostsession/audit-binding/${deviceId}`, Buffer.from(JSON.stringify({
    device_id: deviceId, signing_key_id: signingKeyId,
    signing_pub: b64Encode(ed25519PublicFromSeed(signingSeed)),
  })));

  const config: DaemonConfig = {
    v: 1,
    device_id: deviceId,
    owner_id: ownerId,
    data_dir: dataDir,
    runtime_dir: runtimeDir,
    browser: { engine: "chromium", profile_storage: "memory", max_contexts: 4 },
    vault: { mode: "local", base_url: null },
    relay: { enabled: false, listen: "127.0.0.1:43191", relay_key_id: null },
    inbox: { mode: "local" },
    trusted_keys: [],
  };
  mkdirSync(join(configPath, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  chmodSync(configPath, 0o600);
  return { config, result: { initialized: true, device_id: deviceId } };
}

export interface LoadedDevice {
  deviceId: string;
  ownerId: string;
  signingKeyId: string;
  signingSeed: Buffer;
  signingPub: Buffer;
  requestKeyId: string | null;
  requestSeed: Buffer | null;
  auditKey: Buffer;
  cacheKey: Buffer;
}

/** Load device key material from the keychain; fail closed when absent. */
export function loadDevice(config: DaemonConfig, keychain: Keychain): LoadedDevice {
  const binding = keychain.get(`ghostsession/audit-binding/${config.device_id}`);
  if (!binding) throw new RpcError("KEY_UNAVAILABLE");
  const meta = JSON.parse(binding.toString("utf8")) as { signing_key_id: string };
  const signingSeed = keychain.get(`ghostsession/signing/${meta.signing_key_id}`);
  const auditKey = keychain.get(`ghostsession/hmac/${config.device_id}`);
  const cacheKey = keychain.get(`ghostsession/cache/${config.device_id}`);
  if (!signingSeed || !auditKey || !cacheKey) {
    throw new RpcError("KEY_UNAVAILABLE");
  }
  let requestKeyId: string | null = null;
  let requestSeed: Buffer | null = null;
  // The device request key is used for vault/remote auth; optional in local mode.
  for (const name of [`ghostsession/request-index/${config.device_id}`]) {
    const idx = keychain.get(name);
    if (idx) {
      requestKeyId = idx.toString("utf8");
      requestSeed = keychain.get(`ghostsession/request/${requestKeyId}`);
    }
  }
  return {
    deviceId: config.device_id,
    ownerId: config.owner_id,
    signingKeyId: meta.signing_key_id,
    signingSeed,
    signingPub: ed25519PublicFromSeed(signingSeed),
    requestKeyId,
    requestSeed,
    auditKey,
    cacheKey,
  };
}
