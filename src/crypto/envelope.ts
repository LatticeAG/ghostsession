/**
 * Signed envelopes (spec §3.1). Every domain signs
 *   UTF8("GhostSession/<domain>/v1\n") || SHA256(JCS(core))
 * — for receipts this equals the spec's hexDecode(receipt.hash) form because
 * receipt.hash is the hex of the same digest.
 */

import { createHash, createHmac } from "node:crypto";
import { jcsBytes } from "../encoding/jcs.js";
import { b64Decode, b64Encode } from "../encoding/b64.js";
import { ed25519Sign, ed25519Verify } from "./ed25519.js";

export type SignatureDomain = "policy" | "receipt" | "vault" | "request" | "response";

export interface SignedEnvelope<C> {
  core: C;
  hash: string;
  signature: string;
}

export function sha256(buf: Buffer): Buffer {
  return createHash("sha256").update(buf).digest();
}

export function sha256Hex(buf: Buffer): string {
  return sha256(buf).toString("hex");
}

export function jcsHash(value: unknown): string {
  return sha256Hex(jcsBytes(value));
}

export function domainMessage(domain: SignatureDomain, coreHashHex: string): Buffer {
  return Buffer.concat([
    Buffer.from(`GhostSession/${domain}/v1\n`, "utf8"),
    Buffer.from(coreHashHex, "hex"),
  ]);
}

export function signEnvelope<C>(domain: SignatureDomain, core: C, seed: Buffer): SignedEnvelope<C> {
  const hash = jcsHash(core);
  const signature = b64Encode(ed25519Sign(seed, domainMessage(domain, hash)));
  return { core, hash, signature };
}

export function verifyEnvelope<C>(
  domain: SignatureDomain,
  envelope: SignedEnvelope<C>,
  publicKey: Buffer,
): boolean {
  if (typeof envelope?.hash !== "string" || !/^[0-9a-f]{64}$/.test(envelope.hash)) return false;
  const computed = jcsHash(envelope.core);
  if (computed !== envelope.hash) return false;
  let sig: Buffer;
  try {
    sig = b64Decode(envelope.signature);
  } catch {
    return false;
  }
  return ed25519Verify(publicKey, domainMessage(domain, computed), sig);
}

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return createHmac("sha256", key).update(data).digest();
}
