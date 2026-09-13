/**
 * AES-256-GCM snapshot encryption (spec §7).
 * ciphertext field = ciphertext || 16-byte tag; nonce exactly 12 bytes.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export class IntegrityError extends Error {
  constructor(message = "authentication failed") {
    super(message);
    this.name = "IntegrityError";
  }
}

export function aes256gcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  if (key.length !== 32) throw new Error("key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("nonce must be 12 bytes");
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}

export function aes256gcmDecrypt(key: Buffer, nonce: Buffer, ciphertextWithTag: Buffer, aad: Buffer): Buffer {
  if (key.length !== 32) throw new Error("key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("nonce must be 12 bytes");
  if (ciphertextWithTag.length < 16) throw new IntegrityError("ciphertext too short");
  const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aad);
  d.setAuthTag(tag);
  try {
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    throw new IntegrityError();
  }
}

export function freshNonce(): Buffer {
  return randomBytes(12);
}
