"""Deterministic block classifier (spec §6). Byte-identical precedence to
the TypeScript implementation; operates on a trusted Observation dict."""

from __future__ import annotations


def classify(o: dict) -> str:
    if o["network"] == "policy_denied":
        return "SCOPE_DENIED"
    if o["network"] != "ok":
        return "NETWORK_ERROR"
    if o["cf_mitigated"] or o["challenge_marker"]:
        return "CF_CHALLENGE"
    if o["status"] == 429:
        return "RATE_LIMIT"
    if o["identity"] == "mismatch":
        return "ACCOUNT_MISMATCH"
    if o["status"] == 401 or o["login_marker"] or o["redirected_to_login"]:
        return "LOGIN_WALL"
    if o["status"] == 403:
        return "ACCESS_DENIED"
    if o["status"] is None or o["status"] < 200 or o["status"] >= 300:
        return "UNKNOWN"
    if o["identity"] == "missing":
        return "LOGIN_WALL"
    return "NONE"


def is_retryable_block(cls: str, network: str) -> bool:
    if cls in ("CF_CHALLENGE", "RATE_LIMIT"):
        return True
    if cls == "NETWORK_ERROR":
        return network != "tls_error"
    return False


def is_fallback_eligible(cls: str, network: str) -> bool:
    if cls in ("ACCESS_DENIED", "UNKNOWN"):
        return True
    return is_retryable_block(cls, network)


def probe_verified(o: dict) -> bool:
    return (
        classify(o) == "NONE"
        and o["status"] is not None
        and 200 <= o["status"] < 300
        and o["identity"] == "match"
        and o["logged_in_marker"] is True
        and o["login_marker"] is False
        and o["redirected_to_login"] is False
    )
