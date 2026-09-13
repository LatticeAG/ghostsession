/**
 * ghostsession audit verify — offline NDJSON receipt-chain verification.
 */

import { readFileSync } from "node:fs";
import { parseStrictJson } from "./encoding/strict-json.js";
import { jcsHash, domainMessage } from "./crypto/envelope.js";
import { ed25519Verify } from "./crypto/ed25519.js";
import { b64Decode } from "./encoding/b64.js";
import { vReceipt, vTrustFile, type Receipt } from "./schema.js";
import { CliError } from "./cli.js";

export function verifyAuditFile(input: string, trustPath: string, expectedTip: string | null): {
  valid: boolean; entries: number; tip_hash: string | null;
} {
  const trust = vTrustFile(parseStrictJson(readFileSync(trustPath)), "trust");
  const pubs = new Map(
    trust.keys.filter((k) => k.purpose === "receipt").map((k) => [k.key_id, b64Decode(k.public_key)]),
  );
  const lines = readFileSync(input, "utf8").split("\n").filter((l) => l.trim().length > 0);
  let prev = "0".repeat(64);
  let count = 0;
  let tip: string | null = null;
  for (const line of lines) {
    const r = vReceipt(parseStrictJson(Buffer.from(line, "utf8")), "receipt") as Receipt;
    if (r.core.seq !== count + 1) throw new CliError(6, `seq gap at ${r.core.seq}`);
    if (r.core.previous_hash !== prev) throw new CliError(6, `previous_hash mismatch at seq ${r.core.seq}`);
    if (r.hash !== jcsHash(r.core)) throw new CliError(6, `hash mismatch at seq ${r.core.seq}`);
    const pub = pubs.get(r.core.signing_key_id);
    if (!pub) throw new CliError(6, `untrusted signing key ${r.core.signing_key_id}`);
    if (!ed25519Verify(pub, domainMessage("receipt", r.hash), b64Decode(r.signature))) {
      throw new CliError(6, `signature invalid at seq ${r.core.seq}`);
    }
    prev = r.hash;
    tip = r.hash;
    count++;
  }
  if (expectedTip !== null && tip !== expectedTip) throw new CliError(6, "tip mismatch");
  return { valid: true, entries: count, tip_hash: tip };
}
