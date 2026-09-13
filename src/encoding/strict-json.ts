/**
 * Strict JSON parser for GhostSession wire/protocol documents.
 *
 * Rules (spec §3):
 *  - UTF-8 input; BOM rejected.
 *  - Duplicate object keys rejected before producing a map.
 *  - Lone surrogates, NaN, infinities, negative zero rejected.
 *  - Only non-negative safe integers are valid numbers (every protocol
 *    numeric field is UInt/Ms). Non-integral numeric values are rejected.
 *  - Nesting depth limited to 32.
 */

export const MAX_JSON_DEPTH = 32;
export const MAX_SAFE_UINT = 9007199254740991;

export class StrictJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictJsonError";
  }
}

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

class Parser {
  private pos = 0;
  constructor(private readonly src: string) {}

  private peek(): string {
    return this.src[this.pos] ?? "";
  }

  private fail(msg: string): never {
    throw new StrictJsonError(`${msg} at offset ${this.pos}`);
  }

  private expect(ch: string): void {
    if (this.src[this.pos] !== ch) this.fail(`expected ${JSON.stringify(ch)}`);
    this.pos++;
  }

  private skipWs(): void {
    while (this.pos < this.src.length) {
      const c = this.src.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else break;
    }
  }

  parse(): JsonValue {
    this.skipWs();
    const v = this.value(0);
    this.skipWs();
    if (this.pos !== this.src.length) this.fail("trailing content");
    return v;
  }

  private value(depth: number): JsonValue {
    if (depth > MAX_JSON_DEPTH) this.fail("depth limit exceeded");
    const c = this.peek();
    switch (c) {
      case "{":
        return this.object(depth);
      case "[":
        return this.array(depth);
      case '"':
        return this.string();
      case "t":
        return this.literal("true", true);
      case "f":
        return this.literal("false", false);
      case "n":
        return this.literal("null", null);
      default:
        if (c === "-" || (c >= "0" && c <= "9")) return this.number();
        this.fail("unexpected character");
    }
  }

  private literal(word: string, val: JsonValue): JsonValue {
    if (this.src.startsWith(word, this.pos)) {
      this.pos += word.length;
      return val;
    }
    this.fail(`invalid literal`);
  }

  private object(depth: number): JsonValue {
    this.expect("{");
    const out: Record<string, JsonValue> = {};
    this.skipWs();
    if (this.peek() === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.skipWs();
      if (this.peek() !== '"') this.fail("expected object key");
      const key = this.string() as string;
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        this.fail("duplicate object key");
      }
      this.skipWs();
      this.expect(":");
      this.skipWs();
      out[key] = this.value(depth + 1);
      this.skipWs();
      const c = this.peek();
      if (c === ",") {
        this.pos++;
        continue;
      }
      if (c === "}") {
        this.pos++;
        return out;
      }
      this.fail("expected ',' or '}'");
    }
  }

  private array(depth: number): JsonValue {
    this.expect("[");
    const out: JsonValue[] = [];
    this.skipWs();
    if (this.peek() === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.skipWs();
      out.push(this.value(depth + 1));
      this.skipWs();
      const c = this.peek();
      if (c === ",") {
        this.pos++;
        continue;
      }
      if (c === "]") {
        this.pos++;
        return out;
      }
      this.fail("expected ',' or ']'");
    }
  }

  private string(): string {
    this.expect('"');
    const chunks: string[] = [];
    let start = this.pos;
    while (this.pos < this.src.length) {
      const c = this.src.charCodeAt(this.pos);
      if (c === 0x22) {
        chunks.push(this.src.slice(start, this.pos));
        this.pos++;
        const s = chunks.join("");
        if (hasLoneSurrogate(s)) this.fail("lone surrogate in string");
        return s;
      }
      if (c === 0x5c) {
        chunks.push(this.src.slice(start, this.pos));
        this.pos++;
        const e = this.src[this.pos];
        switch (e) {
          case '"':
          case "\\":
          case "/":
            chunks.push(e);
            this.pos++;
            break;
          case "b":
            chunks.push("\b");
            this.pos++;
            break;
          case "f":
            chunks.push("\f");
            this.pos++;
            break;
          case "n":
            chunks.push("\n");
            this.pos++;
            break;
          case "r":
            chunks.push("\r");
            this.pos++;
            break;
          case "t":
            chunks.push("\t");
            this.pos++;
            break;
          case "u": {
            const hex = this.src.slice(this.pos + 1, this.pos + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
            const cp = parseInt(hex, 16);
            // handle surrogate pairs: combine only when a low surrogate escape follows
            if (cp >= 0xd800 && cp <= 0xdbff && this.src[this.pos + 5] === "\\" && this.src[this.pos + 6] === "u") {
              const hex2 = this.src.slice(this.pos + 7, this.pos + 11);
              if (/^[0-9a-fA-F]{4}$/.test(hex2)) {
                const cp2 = parseInt(hex2, 16);
                if (cp2 >= 0xdc00 && cp2 <= 0xdfff) {
                  chunks.push(String.fromCodePoint(0x10000 + ((cp - 0xd800) << 10) + (cp2 - 0xdc00)));
                  this.pos += 11;
                  break;
                }
              }
            }
            chunks.push(String.fromCharCode(cp));
            this.pos += 5;
            break;
          }
          default:
            this.fail("bad escape");
        }
        start = this.pos;
        continue;
      }
      if (c < 0x20) this.fail("unescaped control character");
      this.pos++;
    }
    this.fail("unterminated string");
  }

  private number(): number {
    const re = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;
    const m = re.exec(this.src.slice(this.pos));
    if (!m) this.fail("invalid number");
    const lexeme = m[0];
    this.pos += lexeme.length;
    const v = Number(lexeme);
    if (!Number.isFinite(v)) this.fail("non-finite number");
    if (Object.is(v, -0)) this.fail("negative zero");
    if (!Number.isSafeInteger(v) || v < 0 || v > MAX_SAFE_UINT) {
      this.fail("number out of range");
    }
    return v;
  }
}

/** Parse a UTF-8 buffer strictly. Throws StrictJsonError. */
export function parseStrictJson(buf: Buffer): JsonValue {
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    throw new StrictJsonError("BOM rejected");
  }
  let src: string;
  try {
    src = new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch {
    throw new StrictJsonError("invalid UTF-8");
  }
  return new Parser(src).parse();
}

/** Parse a JS string strictly (for non-byte sources such as fixtures). */
export function parseStrictJsonString(src: string): JsonValue {
  return parseStrictJson(Buffer.from(src, "utf8"));
}
