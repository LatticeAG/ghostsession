"""TV-G conformance vectors — Python contract runner (spec §16).

Mirrors the TypeScript pure-vector suite byte-for-byte: classifier
precedence, Retry-After parsing, JCS canonical bytes, strict-JSON
rejections, snapshot crypto, envelope verification, and ID rules.
"""

import pytest

from ghostsession import audit, crypto
from ghostsession.classify import classify, probe_verified
from ghostsession.delay import compute_delay, parse_retry_after
from ghostsession.encoding import (
    StrictJsonError, b64_decode, b64_encode, is_canonical_b64,
    is_valid_id, jcs_bytes, strict_loads,
)
from ghostsession.crypto import (
    aes256gcm_decrypt, b64_decode as _bd, domain_message,
    decrypt_snapshot, ed25519_verify, jcs_hash, live_cookies,
    snapshot_aad, verify_envelope,
)
from ghostsession.errors import RpcFailure


def obs(fx, **over):
    o = dict(fx["base_obs"])
    o.update(over)
    return o


def seed(fx, name):
    return b64_decode(fx["keys"][name])


def code_of(fn):
    try:
        fn()
    except RpcFailure as e:
        return e.code
    return None


# TV-G--01 — Explicit challenge header
def test_tv01_challenge_marker_classifies_cf(fx):
    assert classify(obs(fx, status=503, cf_mitigated=True)) == "CF_CHALLENGE"


# TV-G--02 — Cloudflare branding alone is insufficient
def test_tv02_branding_without_markers_is_none(fx):
    o = obs(fx, status=200)
    assert o["cf_mitigated"] is False
    assert o["challenge_marker"] is False
    assert classify(o) == "NONE"


# TV-G--03 — Login selector wins over HTTP success
def test_tv03_login_marker_beats_200(fx):
    o = obs(fx, login_marker=True, identity="match")
    assert classify(o) == "LOGIN_WALL"
    assert probe_verified(o) is False


# TV-G--04 — Rate limit beats a generic login marker
def test_tv04_rate_limit_precedence_and_delay(fx):
    o = obs(fx, status=429, login_marker=True, retry_after="120")
    assert classify(o) == "RATE_LIMIT"
    assert compute_delay("RATE_LIMIT", "ok", 1, o["retry_after"], o["received_ms"]) == {
        "delay_ms": 120000, "retry_at_ms": 1800000120000, "exhausted": False}


# TV-G--05 — Challenge beats rate-limit status
def test_tv05_challenge_beats_429(fx):
    o = obs(fx, status=429, challenge_marker=True)
    assert classify(o) == "CF_CHALLENGE"
    assert compute_delay("CF_CHALLENGE", "ok", 1, o["retry_after"], o["received_ms"]) == {
        "delay_ms": 60000, "retry_at_ms": 1800000060000, "exhausted": False}


# TV-G--08 — Invalid Retry-After cannot erase minimum wait
def test_tv08_invalid_retry_after_falls_back(fx, now):
    assert compute_delay("RATE_LIMIT", "ok", 1, "-1", now) == {
        "delay_ms": 30000, "retry_at_ms": 1800000030000, "exhausted": False}


# TV-G--09 — Excessive Retry-After is not capped early
def test_tv09_over_horizon_retry_after_exhausts(fx, now):
    assert compute_delay("RATE_LIMIT", "ok", 1, "86401", now) == {
        "delay_ms": None, "retry_at_ms": None, "exhausted": True}


# TV-G--10 — Canonical object order, byte-identical to TS
def test_tv10_jcs_canonical_order(fx):
    assert jcs_bytes({"z": 1, "a": "x"}) == b'{"a":"x","z":1}'
    # Generator parity: fixture policy hash equals our JCS hash.
    assert jcs_hash(fx["policy"]["core"]) == fx["policy"]["hash"]


# TV-G--11 — Duplicate keys rejected
def test_tv11_duplicate_keys_rejected():
    with pytest.raises(StrictJsonError):
        strict_loads(b'{"v":1,"v":1,"id":"gq_000000000000000000001",'
                     b'"method":"system.status","params":{}}')


# TV-G--16/17/18 crypto halves — snapshot decrypt + binding checks
def test_cipher_snapshot_round_trip(fx):
    cs = fx["cipher_snapshot"]
    pt = aes256gcm_decrypt(seed(fx, "enc_key_b64"), b64_decode(cs["nonce"]),
                           b64_decode(cs["ciphertext"]), snapshot_aad(cs["header"]))
    assert pt == jcs_bytes(fx["snapshot_plain"])


def test_decrypt_snapshot_bindings(fx, ids, now):
    cs = fx["cipher_snapshot"]
    key = seed(fx, "enc_key_b64")
    checks = {"session_id": ids["S"], "site_id": ids["T"], "device_id": ids["D"],
              "generation": 1, "policy_hash": fx["policy_hash"], "now_ms": now,
              "audit_anchor_hash": lambda seq: fx["audit7"][4]["hash"]}
    assert decrypt_snapshot(cs, key, checks)["session_id"] == ids["S"]
    # Site substitution fails before plaintext use.
    tampered = dict(cs, header=dict(cs["header"], site_id="gt_000000000000000000002"))
    assert code_of(lambda: decrypt_snapshot(tampered, key, checks)) == "INTEGRITY_FAILED"
    # Policy drift fails identically.
    drift = dict(checks, policy_hash="f" * 64)
    assert code_of(lambda: decrypt_snapshot(cs, key, drift)) == "INTEGRITY_FAILED"
    # Expiry equality is expired.
    exp = dict(checks, now_ms=cs["header"]["expires_ms"])
    assert code_of(lambda: decrypt_snapshot(cs, key, exp)) == "SNAPSHOT_EXPIRED"


# TV-G--20 — Expired cookie removed at restore boundary
def test_tv20_expired_cookie_dropped(fx):
    plain = dict(fx["snapshot_plain"], cookies=[fx["good_cookie"]])
    assert live_cookies(plain, 1800000060000) == []


# TV-G--40 — Signature verifies then fails on mutation
def test_tv40_receipt_signature_verify_and_mutation(fx):
    pub = seed(fx, "sk_pub_b64")
    eh = fx["receipt_envelope"]
    assert verify_envelope("receipt", eh, pub) is True
    mutated = dict(eh, core=dict(eh["core"], seq=2))
    assert verify_envelope("receipt", mutated, pub) is False
    sig = bytearray(b64_decode(eh["signature"]))
    sig[0] ^= 1
    assert ed25519_verify(pub, domain_message("receipt", jcs_hash(eh["core"])),
                          bytes(sig)) is False


# TV-G--44 — IMF-fixdate Retry-After in GMT
def test_tv44_imf_fixdate():
    assert compute_delay("RATE_LIMIT", "ok", 1,
                         "Thu, 01 Jan 1970 00:02:00 GMT", 0) == {
        "delay_ms": 120000, "retry_at_ms": 120000, "exhausted": False}
    assert parse_retry_after("  030  ", 0) == {"kind": "ok", "delay_ms": 30000}
    # wrong weekday is invalid
    assert parse_retry_after("Fri, 01 Jan 1970 00:02:00 GMT", 0)["kind"] == "invalid"


# TV-G--48 — Reserved signing prefix and unsafe integer rejected
def test_tv48_reserved_prefix_and_unsafe_int():
    assert is_valid_id("gs_000000000000000000001", "gq") is False
    with pytest.raises(StrictJsonError):
        strict_loads(b'{"v":1,"id":"gq_000000000000000000001",'
                     b'"method":"session.attach","params":{"session_id":'
                     b'"gs_000000000000000000001","run_id":"gr_000000000000000000001",'
                     b'"expected_generation":9007199254740992}}')


# --- supporting crypto/schema checks ---------------------------------------

def test_b64_canonicality_and_ids(ids):
    assert is_canonical_b64(b64_encode(b"abc")) is True
    assert is_canonical_b64("AA==") is False  # padded is non-canonical
    assert is_valid_id(ids["S"], "gs") is True
    assert is_valid_id(ids["S"], "gt") is False


def test_strict_json_rejections():
    with pytest.raises(StrictJsonError):
        strict_loads(b"\xef\xbb\xbf{}")                      # BOM
    with pytest.raises(StrictJsonError):
        strict_loads(b'{"a":-0}')                            # negative zero
    with pytest.raises(StrictJsonError):
        strict_loads(b'{"a":1.5}')                           # non-integral
    with pytest.raises(StrictJsonError):
        strict_loads(b'{"a":"\\ud800"}')                     # lone surrogate
    with pytest.raises(StrictJsonError):
        strict_loads(b'{"a":NaN}')                           # non-finite
    with pytest.raises(StrictJsonError):
        strict_loads(b'[' * 40 + b'0' + b']' * 40)           # depth limit


def test_ed25519_strictness():
    # small-order public key rejected
    assert crypto.is_valid_public_key(bytes(32)) is False
    # S >= L rejected
    assert crypto.is_canonical_signature(
        b"\x00" * 32 + b"\xff" * 32) is False


def test_audit_chain_verifies(fx):
    out = audit.verify_chain(fx["audit7"], fx["trust_file"])
    assert out["entries"] == 7
    assert out["tip_hash"] == fx["audit7"][-1]["hash"]
    # mutated chain fails
    bad = [dict(r) for r in fx["audit7"]]
    bad[3] = dict(bad[3], core=dict(bad[3]["core"], fence=9))
    with pytest.raises(RpcFailure):
        audit.verify_chain(bad, fx["trust_file"])


def test_request_proof_fixture_verifies(fx):
    p = fx["proof_q4"]
    env = {"core": p["core"], "hash": jcs_hash(p["core"]),
           "signature": p["signature"]}
    assert verify_envelope("request", env, seed(fx, "auth_pub_b64")) is True
    # wrong key fails
    assert verify_envelope("request", env, seed(fx, "sk_pub_b64")) is False


def test_vault_heads_verify(fx):
    pub = seed(fx, "sk_pub_b64")
    for name in ("vault_head", "vg2", "vg3", "vg4_tombstone", "vg5"):
        assert verify_envelope("vault", fx[name], pub) is True, name
