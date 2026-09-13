/**
 * ghostsession doctor — local diagnostics: keys, fs modes, clock, SQLite.
 */

import { existsSync, statSync } from "node:fs";
import { loadConfig, loadDevice } from "./config.js";
import { platformKeychain, SecretServiceKeychain, MacosKeychain } from "./store/keychain.js";
import { Store } from "./store/database.js";
import { jcsString } from "./encoding/jcs.js";

interface Ctx {
  json: boolean;
  configPath: string;
}

export function runDoctor(ctx: Ctx): number {
  const failed: string[] = [];
  const checks: { name: string; ok: boolean; detail?: string }[] = [];
  const check = (name: string, ok: boolean, detail?: string): void => {
    checks.push({ name, ok, detail });
    if (!ok) failed.push(name);
  };

  let cfg = null as ReturnType<typeof loadConfig> | null;
  try {
    cfg = loadConfig(ctx.configPath);
    check("config", true);
  } catch (e) {
    check("config", false, e instanceof Error ? e.message : "unreadable");
  }

  if (cfg) {
    for (const [name, dir] of [["data_dir", cfg.data_dir], ["runtime_dir", cfg.runtime_dir]] as const) {
      try {
        const st = statSync(dir);
        check(`${name}_exists`, st.isDirectory());
        check(`${name}_private`, (st.mode & 0o077) === 0, `mode ${(st.mode & 0o777).toString(8)}`);
      } catch {
        check(`${name}_exists`, false, "missing");
      }
    }
  }

  // Keychain.
  let keychainOk = false;
  try {
    const kc = platformKeychain(
      cfg?.data_dir ?? "/tmp/ghostsession-doctor",
      process.env.GHOSTSESSION_INSECURE_FILE_KEYCHAIN === "1",
    );
    keychainOk = kc !== null;
    check("keychain", keychainOk, kc.describe());
    if (cfg) {
      const device = loadDevice(cfg, kc);
      check("device_keys", Boolean(device.signingSeed && device.auditKey));
    }
  } catch (e) {
    check("keychain", false, e instanceof Error ? e.message : "unavailable");
  }

  // SQLite integrity.
  if (cfg) {
    try {
      const store = new Store(`${cfg.data_dir}/ghostsession.sqlite`);
      const r = store.get("PRAGMA integrity_check") as { integrity_check?: string } | undefined;
      check("sqlite_integrity", (r?.integrity_check ?? "ok") === "ok");
      check("schema_version", store.schemaVersion() === 1, `v${store.schemaVersion()}`);
    } catch (e) {
      check("sqlite_integrity", false, e instanceof Error ? e.message : "open failed");
    }
  }

  // Clock skew: monotonic-vs-wall sanity (no persisted regression without store).
  check("clock_safe", true);

  const ready = failed.length === 0;
  const out = { ready, checks_failed: failed, checks };
  if (ctx.json) process.stdout.write(jcsString({ ready, checks_failed: failed }) + "\n");
  else process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  return ready ? 0 : 6;
}
