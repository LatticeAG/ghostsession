/**
 * Origin, path, URL and selector validation (spec §3).
 *
 * Origin = canonical HTTPS origin: lowercase IDNA-ASCII host, no credentials,
 * default port omitted, no trailing slash. Production rejects IP literals,
 * localhost, trailing dots and non-default ports.
 */

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeError";
  }
}

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function isIpLiteralHost(host: string): boolean {
  if (IPV4_RE.test(host)) return true;
  if (host.startsWith("[") && host.endsWith("]")) return true;
  // Alternate IPv4 encodings: single integer, hex, octal components.
  if (/^\d+$/.test(host)) return true;
  if (/^0x[0-9a-f]+$/i.test(host)) return true;
  if (/^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$/i.test(host) && /\d/.test(host)) {
    return true;
  }
  return false;
}

export interface OriginOptions {
  /** Production rule: public DNS names only. Fixture harnesses set false. */
  publicDnsOnly: boolean;
}

/**
 * Validate and return the canonical origin string. Throws ScopeError.
 * The input must already be canonical — non-canonical spellings are rejected,
 * never normalized into acceptance.
 */
export function validateOrigin(input: string, opts: OriginOptions = { publicDnsOnly: true }): string {
  if (typeof input !== "string" || input.length === 0 || input.length > 1024) {
    throw new ScopeError("origin must be a non-empty bounded string");
  }
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new ScopeError("origin does not parse");
  }
  if (u.protocol !== "https:") throw new ScopeError("origin must be https");
  if (u.username !== "" || u.password !== "") throw new ScopeError("origin must not carry credentials");
  if (u.port !== "" && u.port !== "443") throw new ScopeError("non-default port rejected");
  // Reject explicit :443 — default port must be omitted.
  if (u.port === "443") throw new ScopeError("default port must be omitted");
  if (u.pathname !== "/" || u.search !== "" || u.hash !== "") {
    throw new ScopeError("origin must not carry path, query or fragment");
  }
  const host = u.hostname; // punycode + lowercase via URL parser
  if (host === "") throw new ScopeError("empty host");
  if (host.endsWith(".")) throw new ScopeError("trailing dot rejected");
  if (host === "localhost" || host.endsWith(".localhost")) throw new ScopeError("localhost rejected");
  if (isIpLiteralHost(host)) throw new ScopeError("IP literal rejected");
  const canonical = `https://${host}`;
  if (input !== canonical) throw new ScopeError("origin not in canonical form");
  if (opts.publicDnsOnly) {
    const labels = host.split(".");
    if (labels.length < 2 || labels.some((l) => l.length === 0)) {
      throw new ScopeError("host is not a public DNS name");
    }
  }
  return canonical;
}

/**
 * Validate a RelativePath: exactly one leading '/', no query/fragment,
 * dot segments, backslashes, controls, or encoded slash. Malformed percent
 * escapes are rejected; decoding to a remaining '%' is unsupported.
 * Returns the decoded path used for prefix matching.
 */
export function validateRelativePath(input: string): string {
  if (typeof input !== "string" || input.length === 0) throw new ScopeError("path required");
  if (Buffer.byteLength(input, "utf8") > 8192) throw new ScopeError("path too long");
  if (!input.startsWith("/") || input.startsWith("//")) {
    throw new ScopeError("path must start with exactly one '/'");
  }
  if (input.includes("?") || input.includes("#")) throw new ScopeError("path must not contain query/fragment");
  if (input.includes("\\")) throw new ScopeError("backslash rejected");
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) throw new ScopeError("control character rejected");
  }
  const decoded = decodePathOnce(input);
  if (decoded.includes("%")) throw new ScopeError("recursively encoded path unsupported");
  if (decoded.includes("\\")) throw new ScopeError("decoded backslash rejected");
  for (let i = 0; i < decoded.length; i++) {
    const c = decoded.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) throw new ScopeError("decoded control character rejected");
  }
  const segments = decoded.split("/");
  for (const seg of segments) {
    if (seg === "." || seg === "..") throw new ScopeError("dot segment rejected");
  }
  return decoded;
}

function decodePathOnce(input: string): string {
  let out = "";
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (ch === "%") {
      const hex = input.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) throw new ScopeError("malformed percent escape");
      const byte = parseInt(hex, 16);
      if (byte === 0x2f) throw new ScopeError("encoded slash rejected");
      out += String.fromCharCode(byte);
      i += 2;
    } else {
      out += ch;
    }
  }
  return out;
}

/** Segment-boundary prefix match: '/app' matches '/app' and '/app/x', not '/apple'. */
export function pathPrefixMatch(policyPath: string, requestPath: string): boolean {
  return requestPath === policyPath || requestPath.startsWith(policyPath + "/");
}

/**
 * Validate a navigation URL (may contain a query, never credentials or
 * fragment). Returns {origin, path, query} with path decoded under
 * RelativePath rules.
 */
export function validateNavigationUrl(
  input: string,
  opts: OriginOptions = { publicDnsOnly: true },
): { origin: string; path: string; query: string } {
  if (typeof input !== "string" || input.length === 0 || input.length > 8192) {
    throw new ScopeError("url must be a bounded string");
  }
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new ScopeError("url does not parse");
  }
  if (u.protocol !== "https:") throw new ScopeError("url must be https");
  if (u.username !== "" || u.password !== "") throw new ScopeError("url must not carry credentials");
  if (u.hash !== "") throw new ScopeError("url must not carry a fragment");
  if (u.port !== "") throw new ScopeError("non-default port rejected");
  const origin = validateOrigin(`https://${u.hostname}`, opts);
  // Re-encode check: the raw path must be a legal RelativePath once decoded.
  const path = validateRelativePath(u.pathname === "/" ? "/" : u.pathname);
  return { origin, path, query: u.search };
}

const SELECTOR_IDENT = "[A-Za-z_][A-Za-z0-9_-]*";
const SELECTOR_TAG = "[a-z][a-z0-9-]*";
const SELECTOR_ATTR = `\\[${SELECTOR_IDENT}="[^"\\\\]*"\\]`;
const SELECTOR_COMPOUND = new RegExp(
  `^(?:${SELECTOR_TAG})?(?:#${SELECTOR_IDENT}|\\.${SELECTOR_IDENT}|${SELECTOR_ATTR})+$`,
);

/**
 * Restricted CSS subset: tag, #id, .class and [name="literal"] compounds.
 * No pseudo-classes, combinators, XPath, or script.
 */
export function validateSelector(input: string): string {
  if (typeof input !== "string") throw new ScopeError("selector must be a string");
  const n = Buffer.byteLength(input, "utf8");
  if (n < 1 || n > 256) throw new ScopeError("selector length out of range");
  if (!SELECTOR_COMPOUND.test(input)) throw new ScopeError("selector outside allowed subset");
  return input;
}
