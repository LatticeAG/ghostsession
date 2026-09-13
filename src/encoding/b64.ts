/**
 * Canonical unpadded base64url (spec §3 `B64`).
 * Decoders must reject padding, whitespace, non-canonical unused bits.
 */

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export function b64Encode(buf: Buffer): string {
  return buf.toString("base64url");
}

export function b64Decode(s: string): Buffer {
  if (!B64URL_RE.test(s)) throw new B64Error("invalid base64url characters");
  if (s.includes("=")) throw new B64Error("padding not permitted");
  const buf = Buffer.from(s, "base64url");
  // Canonicality: re-encoding must reproduce the input exactly.
  if (buf.toString("base64url") !== s) {
    throw new B64Error("non-canonical base64url");
  }
  return buf;
}

export function isCanonicalB64(s: string): boolean {
  try {
    b64Decode(s);
    return true;
  } catch {
    return false;
  }
}

export class B64Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "B64Error";
  }
}
