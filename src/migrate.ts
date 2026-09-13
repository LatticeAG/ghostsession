/**
 * ghostsession migrate — schema marker + encrypted backup + single txn.
 * v1 has a single schema version; --check reports current state, --apply is
 * a no-op at current version.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, createCipheriv } from "node:crypto";
import { loadConfig, loadDevice } from "./config.js";
import { platformKeychain } from "./store/keychain.js";
import { Store, SCHEMA_VERSION } from "./store/database.js";
import { acquireLock, ensurePrivateDir } from "./daemon.js";
import { jcsString } from "./encoding/jcs.js";

interface Ctx {
  json: boolean;
  configPath: string;
}

export function runMigrate(ctx: Ctx, apply: boolean): number {
  const cfg = loadConfig(ctx.configPath);
  ensurePrivateDir(cfg.runtime_dir);
  const lock = acquireLock(cfg.runtime_dir);
  try {
    const dbPath = join(cfg.data_dir, "ghostsession.sqlite");
    const store = new Store(dbPath);
    const from = store.schemaVersion();
    const to = SCHEMA_VERSION;
    if (!apply) {
      const pending = from !== to;
      const out = { from, to, changed: false, pending, incompatibilities: pending ? [`schema ${from} != ${to}`] : [] };
      process.stdout.write(jcsString(out) + "\n");
      return pending ? 2 : 0;
    }
    if (from === to) {
      process.stdout.write(jcsString({ from, to, changed: false }) + "\n");
      return 0;
    }
    if (from > to) {
      process.stderr.write(`downgrade refused: database schema ${from} > ${to}\n`);
      return 2;
    }
    // Encrypted backup before any change.
    const keychain = platformKeychain(cfg.data_dir, process.env.GHOSTSESSION_INSECURE_FILE_KEYCHAIN === "1");
    const device = loadDevice(cfg, keychain);
    void device;
    let backupKey = keychain.get(`ghostsession/backup/${cfg.device_id}`);
    if (!backupKey) {
      backupKey = randomBytes(32);
      keychain.set(`ghostsession/backup/${cfg.device_id}`, backupKey);
    }
    const plain = readFileSync(dbPath);
    const nonce = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", backupKey, nonce);
    const ct = Buffer.concat([c.update(plain), c.final()]);
    const bakDir = join(cfg.data_dir, "backups");
    mkdirSync(bakDir, { mode: 0o700 });
    chmodSync(bakDir, 0o700);
    writeFileSync(join(bakDir, `pre-migrate-${from}-to-${to}.sqlite.enc`), Buffer.concat([nonce, ct, c.getAuthTag()]), { mode: 0o600 });
    store.txn(() => store.setSchemaVersion(to));
    process.stdout.write(jcsString({ from, to, changed: true }) + "\n");
    return 0;
  } finally {
    lock.release();
  }
}
