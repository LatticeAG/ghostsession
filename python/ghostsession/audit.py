"""Offline receipt-chain verification (spec §7) — the Python equivalent of
`ghostsession audit verify`."""

from __future__ import annotations

import json
from pathlib import Path

from .crypto import domain_message, ed25519_verify, jcs_hash
from .encoding import b64_decode, strict_loads
from .errors import RpcFailure
from .schema import v_receipt, v_trust_file


def verify_chain(receipts: list, trust: dict,
                 expected_tip: str | None = None) -> dict:
    """Verify a list of signed receipt envelopes against a trust file."""
    trust = v_trust_file(trust)
    pubs = {k["key_id"]: b64_decode(k["public_key"])
            for k in trust["keys"] if k["purpose"] == "receipt"}
    prev = "0" * 64
    tip = None
    for i, r in enumerate(receipts):
        r = v_receipt(r)
        c = r["core"]
        if c["seq"] != i + 1:
            raise RpcFailure("INTEGRITY_FAILED", f"seq gap at {c['seq']}")
        if c["previous_hash"] != prev:
            raise RpcFailure("INTEGRITY_FAILED",
                             f"previous_hash mismatch at seq {c['seq']}")
        if r["hash"] != jcs_hash(c):
            raise RpcFailure("INTEGRITY_FAILED", f"hash mismatch at seq {c['seq']}")
        pub = pubs.get(c["signing_key_id"])
        if pub is None:
            raise RpcFailure("INTEGRITY_FAILED",
                             f"untrusted signing key {c['signing_key_id']}")
        if not ed25519_verify(pub, domain_message("receipt", r["hash"]),
                              b64_decode(r["signature"])):
            raise RpcFailure("INTEGRITY_FAILED",
                             f"signature invalid at seq {c['seq']}")
        prev = r["hash"]
        tip = r["hash"]
    if expected_tip is not None and tip != expected_tip:
        raise RpcFailure("INTEGRITY_FAILED", "tip mismatch")
    return {"valid": True, "entries": len(receipts), "tip_hash": tip}


def verify_audit_file(input_path: str, trust_path: str,
                      expected_tip: str | None = None) -> dict:
    trust = strict_loads(Path(trust_path).read_bytes())
    lines = [l for l in Path(input_path).read_text().split("\n") if l.strip()]
    receipts = [strict_loads(l.encode()) for l in lines]
    return verify_chain(receipts, trust, expected_tip)


def receipts_to_ndjson(receipts: list) -> str:
    return "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n"
                   for r in receipts)


def receipts_from_ndjson(text: str) -> list:
    return [strict_loads(l.encode()) for l in text.split("\n") if l.strip()]
