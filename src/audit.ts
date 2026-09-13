/**
 * Hash-chained signed receipts (spec §4.2).
 * hash = hex(SHA256(JCS(core))); genesis previous_hash = 64 zeroes.
 */

import { createHash } from "node:crypto";
import { jcsBytes, jcsString } from "./encoding/jcs.js";
import { domainMessage, hmacSha256, jcsHash } from "./crypto/envelope.js";
import { ed25519Sign, ed25519Verify } from "./crypto/ed25519.js";
import { b64Encode, b64Decode } from "./encoding/b64.js";
import type { AuditPage, Receipt, ReceiptCore, SessionState } from "./schema.js";
import { vReceipt } from "./schema.js";
import { parseStrictJson } from "./encoding/strict-json.js";
import type { Store } from "./store/database.js";

export const GENESIS_PREVIOUS = "0".repeat(64);

export function receiptHash(core: ReceiptCore): string {
  return jcsHash(core);
}

export function actionBinding(deviceAuditKey: Buffer, action: unknown): string {
  return hmacSha256(deviceAuditKey, jcsBytes(action)).toString("hex");
}

export function dedupRequestHash(deviceAuditKey: Buffer, request: unknown): string {
  return hmacSha256(
    deviceAuditKey,
    Buffer.concat([Buffer.from("dedup/v1\n", "utf8"), jcsBytes(request)]),
  ).toString("hex");
}

export class AuditLog {
  constructor(
    private store: Store,
    private signingKeyId: string,
    private signSeed: Buffer,
  ) {}

  tip(sessionId: string): { seq: number; hash: string } {
    const row = this.store.get(
      "SELECT seq, hash FROM receipts WHERE session_id = ? ORDER BY seq DESC LIMIT 1",
      sessionId,
    );
    return row ? { seq: row.seq as number, hash: row.hash as string } : { seq: 0, hash: GENESIS_PREVIOUS };
  }

  /**
   * Append inside the caller's transaction. Returns the persisted receipt.
   * Callers own state/revision/fence/generation field values.
   */
  append(core: Omit<ReceiptCore, "v" | "receipt_id" | "seq" | "previous_hash" | "recorded_ms" | "signing_key_id"> & {
    receipt_id: string;
    recorded_ms: number;
    session_id: string;
  }): Receipt {
    const tip = this.tip(core.session_id);
    const full: ReceiptCore = {
      v: 1,
      receipt_id: core.receipt_id,
      session_id: core.session_id,
      seq: tip.seq + 1,
      previous_hash: tip.hash,
      recorded_ms: core.recorded_ms,
      signing_key_id: this.signingKeyId,
      actor_id: core.actor_id,
      operation_id: core.operation_id,
      event: core.event,
      from_state: core.from_state,
      to_state: core.to_state,
      revision: core.revision,
      generation: core.generation,
      fence: core.fence,
      code: core.code,
      action_binding: core.action_binding,
      cipher_hash: core.cipher_hash,
      block_class: core.block_class,
    };
    const hash = receiptHash(full);
    const signature = ed25519SignDigest(this.signSeed, full);
    const receipt: Receipt = { core: full, hash, signature };
    this.store.run(
      "INSERT INTO receipts(session_id, seq, receipt_json, hash) VALUES(?,?,?,?)",
      core.session_id,
      full.seq,
      jcsBytes(receipt),
      hash,
    );
    return receipt;
  }

  /** One consistent tip per page: read inside a single transaction. */
  page(sessionId: string, afterSeq: number, limit: number): AuditPage {
    return this.store.txn(() => {
      const tip = this.tip(sessionId);
      const rows = this.store.all(
        "SELECT receipt_json FROM receipts WHERE session_id = ? AND seq > ? ORDER BY seq LIMIT ?",
        sessionId,
        afterSeq,
        limit,
      );
      const entries = rows.map((r) => vReceipt(parseStrictJson(Buffer.from(r.receipt_json as Uint8Array)), "receipt"));
      const nextAfter = entries.length > 0 ? entries[entries.length - 1]!.core.seq : afterSeq;
      return { entries, next_after_seq: nextAfter, tip_seq: tip.seq, tip_hash: tip.hash };
    });
  }

  sizeBytes(sessionId: string): number {
    const row = this.store.get(
      "SELECT COALESCE(SUM(LENGTH(receipt_json)),0) AS n FROM receipts WHERE session_id = ?",
      sessionId,
    );
    return (row?.n as number) ?? 0;
  }
}

function ed25519SignDigest(seed: Buffer, core: ReceiptCore): string {
  const hash = receiptHash(core);
  return b64Encode(ed25519Sign(seed, domainMessage("receipt", hash)));
}

export interface ChainVerification {
  valid: boolean;
  entries: number;
  tipHash: string | null;
  code: "OK" | "INTEGRITY_FAILED";
}

/**
 * Offline chain + signature verification. Proves ordering and signature
 * integrity only — never that a reported browser action was truthful.
 */
export function verifyReceiptChain(
  receipts: Receipt[],
  publicKey: Buffer,
  opts: { expectedTip?: string | null } = {},
): ChainVerification {
  let prev = GENESIS_PREVIOUS;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i]!;
    const c = r.core;
    if (c.seq !== i + 1) return { valid: false, entries: i, tipHash: null, code: "INTEGRITY_FAILED" };
    if (c.previous_hash !== prev) return { valid: false, entries: i, tipHash: null, code: "INTEGRITY_FAILED" };
    if (receiptHash(c) !== r.hash) return { valid: false, entries: i, tipHash: null, code: "INTEGRITY_FAILED" };
    let sig: Buffer;
    try {
      sig = b64Decode(r.signature);
    } catch {
      return { valid: false, entries: i, tipHash: null, code: "INTEGRITY_FAILED" };
    }
    if (!ed25519Verify(publicKey, domainMessage("receipt", r.hash), sig)) {
      return { valid: false, entries: i, tipHash: null, code: "INTEGRITY_FAILED" };
    }
    prev = r.hash;
  }
  const tip = receipts.length > 0 ? receipts[receipts.length - 1]!.hash : GENESIS_PREVIOUS;
  if (opts.expectedTip !== undefined && opts.expectedTip !== null && opts.expectedTip !== tip) {
    return { valid: false, entries: receipts.length, tipHash: tip, code: "INTEGRITY_FAILED" };
  }
  return { valid: true, entries: receipts.length, tipHash: tip, code: "OK" };
}

/** Serialize receipts to NDJSON (one JCS object per line, trailing newline). */
export function receiptsToNdjson(receipts: Receipt[]): string {
  return receipts.map((r) => jcsString(r)).join("\n") + (receipts.length ? "\n" : "");
}

export function receiptsFromNdjson(text: string): Receipt[] {
  const out: Receipt[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    out.push(vReceipt(parseStrictJson(Buffer.from(line, "utf8")), "receipt"));
  }
  return out;
}
