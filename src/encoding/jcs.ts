/**
 * RFC 8785 (JCS) canonical JSON serialization.
 *
 * Input must already be a strict protocol value: no undefined, no functions,
 * no non-safe-integer numbers, no duplicate keys (objects are plain maps).
 * Keys sort by UTF-16 code units — the default JS string ordering.
 */

import { MAX_SAFE_UINT } from "./strict-json.js";

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

function escapeString(s: string, out: string[]): void {
  out.push('"');
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x22:
        out.push('\\"');
        break;
      case 0x5c:
        out.push("\\\\");
        break;
      case 0x08:
        out.push("\\b");
        break;
      case 0x09:
        out.push("\\t");
        break;
      case 0x0a:
        out.push("\\n");
        break;
      case 0x0c:
        out.push("\\f");
        break;
      case 0x0d:
        out.push("\\r");
        break;
      default:
        if (c < 0x20) {
          out.push("\\u" + c.toString(16).padStart(4, "0"));
        } else {
          out.push(s[i]!);
        }
    }
  }
  out.push('"');
}

function write(v: unknown, out: string[]): void {
  if (v === null) {
    out.push("null");
    return;
  }
  if (typeof v === "boolean") {
    out.push(v ? "true" : "false");
    return;
  }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0 || v > MAX_SAFE_UINT || Object.is(v, -0)) {
      throw new JcsError("number not a safe non-negative integer");
    }
    out.push(String(v));
    return;
  }
  if (typeof v === "string") {
    escapeString(v, out);
    return;
  }
  if (Array.isArray(v)) {
    out.push("[");
    for (let i = 0; i < v.length; i++) {
      if (i) out.push(",");
      write(v[i], out);
    }
    out.push("]");
    return;
  }
  if (typeof v === "object") {
    const keys = Object.keys(v as object).sort();
    out.push("{");
    for (let i = 0; i < keys.length; i++) {
      if (i) out.push(",");
      escapeString(keys[i]!, out);
      out.push(":");
      write((v as Record<string, unknown>)[keys[i]!], out);
    }
    out.push("}");
    return;
  }
  throw new JcsError(`unsupported value type ${typeof v}`);
}

/** Serialize to RFC 8785 canonical UTF-8 bytes. No trailing newline. */
export function jcsBytes(value: unknown): Buffer {
  const out: string[] = [];
  write(value, out);
  return Buffer.from(out.join(""), "utf8");
}

/** Serialize to the canonical JSON text (UTF-16 string form). */
export function jcsString(value: unknown): string {
  const out: string[] = [];
  write(value, out);
  return out.join("");
}
