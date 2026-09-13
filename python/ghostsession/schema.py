"""Closed wire-object validators for the Python SDK surface (spec §3, §8).

Every validator rejects unknown fields and coercion — identical closed-set
semantics to the TypeScript `schema.ts`. Covers the objects the Python SDK
touches: RPC envelopes, receipts/trust files, proofs, observations, vault
heads, cipher snapshots, and policy envelopes.
"""

from __future__ import annotations

from .encoding import MAX_SAFE_UINT, is_canonical_b64, is_valid_id
from .errors import RpcFailure


def _fail(ctx: str, msg: str) -> None:
    raise RpcFailure("INVALID_PARAMS", f"{ctx}: {msg}")


def closed(v, fields: dict, ctx: str) -> None:
    """`fields` maps name -> required bool. Rejects unknown keys."""
    if not isinstance(v, dict):
        _fail(ctx, "expected object")
    for k in v:
        if k not in fields:
            _fail(ctx, f"unknown field {k!r}")
    for k, req in fields.items():
        if req and k not in v:
            _fail(ctx, f"missing field {k!r}")


def u(v, ctx: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > MAX_SAFE_UINT:
        _fail(ctx, "expected non-negative safe integer")
    return v


def s(v, ctx: str) -> str:
    if not isinstance(v, str):
        _fail(ctx, "expected string")
    return v


def b(v, ctx: str) -> bool:
    if not isinstance(v, bool):
        _fail(ctx, "expected boolean")
    return v


def n(v, ctx: str):
    if v is not None:
        _fail(ctx, "expected null")
    return v


def ident(v, prefix: str, ctx: str) -> str:
    if not is_valid_id(v, prefix):
        _fail(ctx, f"expected {prefix}_ id")
    return v


def b64f(v, ctx: str) -> str:
    if not isinstance(v, str) or not is_canonical_b64(v):
        _fail(ctx, "expected canonical base64url")
    return v


def hexh(v, ctx: str) -> str:
    if not isinstance(v, str) or len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
        _fail(ctx, "expected sha256 hex")
    return v


def oneof(v, allowed, ctx: str) -> str:
    if v not in allowed:
        _fail(ctx, f"expected one of {sorted(allowed)}")
    return v


def maybe(v, fn, ctx: str):
    return None if v is None else fn(v, ctx)


NETWORK_STATES = ("ok", "dns_error", "tls_error", "connect_error",
                  "timeout", "reset", "policy_denied", "hang", "crash")
IDENTITY_STATES = ("match", "mismatch", "missing", "not_checked")
BLOCK_CLASSES = ("NONE", "CF_CHALLENGE", "RATE_LIMIT", "LOGIN_WALL",
                 "ACCOUNT_MISMATCH", "ACCESS_DENIED", "NETWORK_ERROR",
                 "UNKNOWN", "SCOPE_DENIED")
SESSION_STATES = ("NEEDS_LOGIN", "DETACHED", "ATTACHING", "ACTIVE", "COOLDOWN",
                  "RECOVERABLE", "HANDOFF_WAIT", "VERIFYING", "UNCERTAIN",
                  "EXPIRED", "REVOKED", "DELETED", "QUARANTINED")


def v_observation(v, ctx="observation") -> dict:
    closed(v, {"status": True, "network": True, "cf_mitigated": True,
               "challenge_marker": True, "login_marker": True,
               "logged_in_marker": True, "redirected_to_login": True,
               "identity": True, "retry_after": True, "received_ms": True}, ctx)
    if v["status"] is not None:
        u(v["status"], f"{ctx}.status")
    oneof(v["network"], NETWORK_STATES, f"{ctx}.network")
    for k in ("cf_mitigated", "challenge_marker", "login_marker",
              "logged_in_marker", "redirected_to_login"):
        b(v[k], f"{ctx}.{k}")
    oneof(v["identity"], IDENTITY_STATES, f"{ctx}.identity")
    if v["retry_after"] is not None:
        s(v["retry_after"], f"{ctx}.retry_after")
    u(v["received_ms"], f"{ctx}.received_ms")
    return v


def v_rpc_request(v, ctx="request") -> dict:
    closed(v, {"v": True, "id": True, "method": True, "params": True}, ctx)
    if v["v"] != 1:
        _fail(ctx, "v must be 1")
    ident(v["id"], "gq", f"{ctx}.id")
    s(v["method"], f"{ctx}.method")
    return v


def v_rpc_error(v, ctx="error") -> dict:
    closed(v, {"code": True, "retryable": True, "retry_at_ms": True,
               "state": True}, ctx)
    s(v["code"], f"{ctx}.code")
    b(v["retryable"], f"{ctx}.retryable")
    if v["retry_at_ms"] is not None:
        u(v["retry_at_ms"], f"{ctx}.retry_at_ms")
    if v["state"] is not None:
        s(v["state"], f"{ctx}.state")
    return v


def v_receipt(v, ctx="receipt") -> dict:
    closed(v, {"core": True, "hash": True, "signature": True}, ctx)
    c = v["core"]
    closed(c, {"v": True, "receipt_id": True, "session_id": True, "seq": True,
               "previous_hash": True, "recorded_ms": True, "signing_key_id": True,
               "actor_id": True, "operation_id": True, "event": True,
               "from_state": True, "to_state": True, "revision": True,
               "generation": True, "fence": True, "code": True,
               "action_binding": True, "cipher_hash": True, "block_class": True},
           f"{ctx}.core")
    if c["v"] != 1:
        _fail(ctx, "v must be 1")
    ident(c["receipt_id"], "gv", f"{ctx}.receipt_id")
    ident(c["session_id"], "gs", f"{ctx}.session_id")
    u(c["seq"], f"{ctx}.seq")
    hexh(c["previous_hash"], f"{ctx}.previous_hash")
    u(c["recorded_ms"], f"{ctx}.recorded_ms")
    ident(c["signing_key_id"], "gk", f"{ctx}.signing_key_id")
    ident(c["actor_id"], "ga", f"{ctx}.actor_id")
    if c["operation_id"] is not None:
        ident(c["operation_id"], "go", f"{ctx}.operation_id")
    s(c["event"], f"{ctx}.event")
    oneof(c["from_state"], SESSION_STATES, f"{ctx}.from_state")
    oneof(c["to_state"], SESSION_STATES, f"{ctx}.to_state")
    u(c["revision"], f"{ctx}.revision")
    u(c["generation"], f"{ctx}.generation")
    u(c["fence"], f"{ctx}.fence")
    s(c["code"], f"{ctx}.code")
    if c["action_binding"] is not None:
        hexh(c["action_binding"], f"{ctx}.action_binding")
    if c["cipher_hash"] is not None:
        hexh(c["cipher_hash"], f"{ctx}.cipher_hash")
    oneof(c["block_class"], BLOCK_CLASSES, f"{ctx}.block_class")
    hexh(v["hash"], f"{ctx}.hash")
    b64f(v["signature"], f"{ctx}.signature")
    return v


def v_trust_file(v, ctx="trust") -> dict:
    closed(v, {"v": True, "keys": True}, ctx)
    if v["v"] != 1:
        _fail(ctx, "v must be 1")
    if not isinstance(v["keys"], list):
        _fail(ctx, "keys must be an array")
    for k in v["keys"]:
        closed(k, {"key_id": True, "device_id": True, "purpose": True,
                   "public_key": True, "valid_from_ms": True,
                   "retired_ms": True}, f"{ctx}.keys[]")
        ident(k["key_id"], "gk", f"{ctx}.key_id")
        ident(k["device_id"], "gd", f"{ctx}.device_id")
        s(k["purpose"], f"{ctx}.purpose")
        b64f(k["public_key"], f"{ctx}.public_key")
        u(k["valid_from_ms"], f"{ctx}.valid_from_ms")
        if k["retired_ms"] is not None:
            u(k["retired_ms"], f"{ctx}.retired_ms")
    return v


def v_request_proof_core(v, ctx="proof") -> dict:
    closed(v, {"v": True, "actor_id": True, "device_id": True, "key_id": True,
               "method": True, "path": True, "body_hash": True, "nonce": True,
               "issued_ms": True, "expires_ms": True, "if_match": True,
               "if_none_match": True}, ctx)
    if v["v"] != 1:
        _fail(ctx, "v must be 1")
    ident(v["actor_id"], "ga", f"{ctx}.actor_id")
    ident(v["device_id"], "gd", f"{ctx}.device_id")
    ident(v["key_id"], "gk", f"{ctx}.key_id")
    s(v["method"], f"{ctx}.method")
    s(v["path"], f"{ctx}.path")
    hexh(v["body_hash"], f"{ctx}.body_hash")
    b64f(v["nonce"], f"{ctx}.nonce")
    u(v["issued_ms"], f"{ctx}.issued_ms")
    u(v["expires_ms"], f"{ctx}.expires_ms")
    return v


def v_vault_head(v, ctx="vault") -> dict:
    closed(v, {"core": True, "hash": True, "signature": True}, ctx)
    c = v["core"]
    closed(c, {"v": True, "session_id": True, "device_id": True,
               "generation": True, "deleted": True, "snapshot": True,
               "signing_key_id": True}, f"{ctx}.core")
    if c["v"] != 1:
        _fail(ctx, "v must be 1")
    ident(c["session_id"], "gs", f"{ctx}.session_id")
    ident(c["device_id"], "gd", f"{ctx}.device_id")
    u(c["generation"], f"{ctx}.generation")
    b(c["deleted"], f"{ctx}.deleted")
    ident(c["signing_key_id"], "gk", f"{ctx}.signing_key_id")
    if c["snapshot"] is not None:
        v_cipher_snapshot(c["snapshot"], f"{ctx}.snapshot")
    hexh(v["hash"], f"{ctx}.hash")
    b64f(v["signature"], f"{ctx}.signature")
    return v


def v_cipher_snapshot(v, ctx="cipher") -> dict:
    closed(v, {"header": True, "algorithm": True, "nonce": True,
               "ciphertext": True}, ctx)
    h = v["header"]
    closed(h, {"v": True, "format": True, "session_id": True, "site_id": True,
               "device_id": True, "generation": True, "policy_hash": True,
               "key_id": True, "created_ms": True, "expires_ms": True},
           f"{ctx}.header")
    if h["v"] != 1:
        _fail(ctx, "v must be 1")
    if h["format"] != "chromium-storage-v1":
        _fail(ctx, "unsupported snapshot format")
    ident(h["session_id"], "gs", f"{ctx}.session_id")
    ident(h["site_id"], "gt", f"{ctx}.site_id")
    ident(h["device_id"], "gd", f"{ctx}.device_id")
    u(h["generation"], f"{ctx}.generation")
    hexh(h["policy_hash"], f"{ctx}.policy_hash")
    ident(h["key_id"], "ge", f"{ctx}.key_id")
    u(h["created_ms"], f"{ctx}.created_ms")
    u(h["expires_ms"], f"{ctx}.expires_ms")
    if v["algorithm"] != "A256GCM":
        _fail(ctx, "unsupported algorithm")
    b64f(v["nonce"], f"{ctx}.nonce")
    b64f(v["ciphertext"], f"{ctx}.ciphertext")
    return v


def v_policy_envelope(v, ctx="policy") -> dict:
    closed(v, {"core": True, "hash": True, "signature": True}, ctx)
    c = v["core"]
    closed(c, {"v": True, "site_id": True, "owner_id": True, "device_id": True,
               "revision": True, "origin": True, "login_path": True,
               "agent_paths": True, "login_origins": True,
               "resource_origins": True, "methods": True, "auth_probe": True,
               "recovery": True, "snapshot_ttl_ms": True,
               "persist_session_cookies": True, "automation_authorized": True,
               "consent_expires_ms": True, "signing_key_id": True},
           f"{ctx}.core")
    if c["v"] != 1:
        _fail(ctx, "v must be 1")
    ident(c["site_id"], "gt", f"{ctx}.site_id")
    ident(c["owner_id"], "ga", f"{ctx}.owner_id")
    ident(c["device_id"], "gd", f"{ctx}.device_id")
    u(c["revision"], f"{ctx}.revision")
    hexh(v["hash"], f"{ctx}.hash")
    b64f(v["signature"], f"{ctx}.signature")
    return v
