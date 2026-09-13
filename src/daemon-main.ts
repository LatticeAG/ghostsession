/**
 * daemon start: assemble store + keychain + adapter + engine + dispatcher,
 * then serve until SIGTERM/SIGINT.
 */

import { RpcError } from "./errors.js";
import { loadConfig, loadDevice } from "./config.js";
import { platformKeychain } from "./store/keychain.js";
import { Store } from "./store/database.js";
import { Engine, systemClock } from "./engine.js";
import { Dispatcher } from "./rpc.js";
import { Daemon } from "./daemon.js";
import { CdpAdapter } from "./browser/cdp.js";
import { ScriptedAdapter } from "./browser/scripted.js";
import { HttpsVaultTransport } from "./vault.js";
import { jcsString } from "./encoding/jcs.js";

interface Ctx {
  json: boolean;
  timeoutMs: number;
  configPath: string;
  socketPath: string | null;
}

export async function startDaemonProcess(ctx: Ctx, foreground: boolean): Promise<number> {
  void foreground; // the CLI always runs the daemon in the foreground process
  const cfg = loadConfig(ctx.configPath);
  const keychain = platformKeychain(
    cfg.data_dir, process.env.GHOSTSESSION_INSECURE_FILE_KEYCHAIN === "1",
  );
  const device = loadDevice(cfg, keychain);
  const store = new Store(`${cfg.data_dir}/ghostsession.sqlite`);
  const adapter = process.env.GHOSTSESSION_TEST_ADAPTER === "scripted"
    ? new ScriptedAdapter(JSON.parse(process.env.GHOSTSESSION_TEST_SCRIPT ?? "{}"))
    : new CdpAdapter({ maxContexts: cfg.browser.max_contexts });
  const engine = new Engine({
    store, keychain, adapter, clock: systemClock,
    device: {
      deviceId: device.deviceId, ownerId: device.ownerId,
      signingKeyId: device.signingKeyId, signingSeed: device.signingSeed,
      signingPub: device.signingPub, auditKey: device.auditKey,
      cacheKey: device.cacheKey, requestKeyId: device.requestKeyId,
      requestSeed: device.requestSeed,
    },
    vaultMode: cfg.vault.mode,
    vaultTransport: cfg.vault.mode === "hosted" && cfg.vault.base_url
      ? new HttpsVaultTransport(cfg.vault.base_url)
      : null,
    inboxAdapter: null,
    originOpts: { publicDnsOnly: process.env.GHOSTSESSION_TEST_ADAPTER === "scripted" },
  });
  const dispatcher = new Dispatcher(engine, cfg.trusted_keys, () => Date.now());
  const daemon = new Daemon(engine, dispatcher, cfg);
  await daemon.start();
  const ready = {
    ready: !engine.clockUnsafe && !engine.auditGateClosed,
    device_id: cfg.device_id, protocol: 1, vault: cfg.vault.mode,
    clock_safe: !engine.clockUnsafe,
    owner_socket: daemon.ownerSocketPath(), driver_socket: daemon.driverSocketPath(),
  };
  process.stderr.write(`ghostsession daemon listening on ${daemon.ownerSocketPath()}\n`);
  process.stdout.write(jcsString(ready) + "\n");

  let stopping = false;
  const stop = async (sig: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    process.stderr.write(`received ${sig}, draining\n`);
    await daemon.stop();
    process.exit(sig === "SIGINT" ? 130 : 0);
  };
  process.on("SIGTERM", () => void stop("SIGTERM"));
  process.on("SIGINT", () => void stop("SIGINT"));
  // Keep alive.
  await new Promise(() => {});
  return 0;
}
