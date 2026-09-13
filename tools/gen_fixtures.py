#!/usr/bin/env python3
"""Generate tests/fixtures.json per GHOSTSESSION spec §8.4.

Reproduces the normative fixture generator exactly (restricted canonicalizer is
correct for these ASCII/integer fixture objects only). The all-fixed seed,
encryption key, and nonce are published test material — production bootstrap
rejects them.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def digest(value):
    return hashlib.sha256(jcs(value)).hexdigest()


def ident(prefix, n=1):
    return prefix + "_" + str(n).zfill(21)


S, T, D, A, R, L, H, O, K, E = [ident(p) for p in ["gs", "gt", "gd", "ga", "gr", "gl", "gh", "go", "gk", "ge"]]
NOW = 1800000000000
Z = "0" * 64
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
RELAY_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
AUTH_SK = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))


def pub(key):
    return b64(key.public_key().public_bytes_raw())


def signed(domain, core, key=SK):
    h = digest(core)
    signature = key.sign(("GhostSession/" + domain + "/v1\n").encode() + bytes.fromhex(h))
    return {"core": core, "hash": h, "signature": b64(signature)}


PC = {"v": 1, "site_id": T, "owner_id": A, "device_id": D, "revision": 1,
      "origin": "https://app.example.test", "login_path": "/login", "agent_paths": ["/app"], "login_origins": [],
      "resource_origins": [], "methods": ["GET", "HEAD"],
      "auth_probe": {"path": "/app/me", "logged_in_selector": "#account", "logged_out_selector": "#login",
                     "account_selector": "#account", "expected_account_ref": "keychain:ghostsession/account/" + T},
      "recovery": {"challenge_base_ms": 60000, "rate_base_ms": 30000, "network_base_ms": 5000,
                   "max_retry_delay_ms": 900000, "max_server_wait_ms": 86400000,
                   "max_automatic_probes": 2, "fallback_path": "/app/status", "handoff_ttl_ms": 900000},
      "snapshot_ttl_ms": 604800000, "persist_session_cookies": True, "automation_authorized": True,
      "consent_expires_ms": NOW + 2592000000, "signing_key_id": K}
P = signed("policy", PC)
PH = P["hash"]

RC = {"v": 1, "receipt_id": ident("gv"), "session_id": S, "seq": 1, "previous_hash": Z,
      "recorded_ms": NOW, "signing_key_id": K, "actor_id": A, "operation_id": None,
      "event": "session.created", "from_state": "NEEDS_LOGIN", "to_state": "NEEDS_LOGIN",
      "revision": 1, "generation": 0, "fence": 0, "code": "OK", "action_binding": None,
      "cipher_hash": None, "block_class": "NONE"}
EH = signed("receipt", RC)
AUDIT7 = [EH]


def append_receipt(event, before, after, generation, cipher_hash=None):
    seq = len(AUDIT7) + 1
    core = dict(RC, receipt_id=ident("gv", seq), seq=seq, revision=seq, previous_hash=AUDIT7[-1]["hash"],
                event=event, from_state=before, to_state=after, generation=generation, cipher_hash=cipher_hash)
    AUDIT7.append(signed("receipt", core))


append_receipt("handoff.created", "NEEDS_LOGIN", "HANDOFF_WAIT", 0)
append_receipt("handoff.opened", "HANDOFF_WAIT", "HANDOFF_WAIT", 0)
append_receipt("handoff.verifying", "HANDOFF_WAIT", "VERIFYING", 0)
append_receipt("snapshot.intent", "VERIFYING", "VERIFYING", 0)

SP = {"v": 1, "session_id": S, "site_id": T, "generation": 1, "saved_ms": NOW,
      "expires_ms": NOW + 604800000, "cookies": [], "origins": [], "audit_seq": 5,
      "audit_hash": AUDIT7[4]["hash"]}
CH = {"v": 1, "format": "chromium-storage-v1", "session_id": S, "site_id": T, "device_id": D,
      "generation": 1, "policy_hash": PH, "key_id": E, "created_ms": NOW,
      "expires_ms": NOW + 604800000}
NONCE = bytes(range(12))
CS = {"header": CH, "algorithm": "A256GCM", "nonce": b64(NONCE),
      "ciphertext": b64(AESGCM(bytes(range(32))).encrypt(NONCE, jcs(SP), b"GhostSession/snapshot/v1\n" + jcs(CH)))}
append_receipt("snapshot.committed", "VERIFYING", "VERIFYING", 1, digest(CS))
append_receipt("handoff.completed", "VERIFYING", "DETACHED", 1)

VH = signed("vault", {"v": 1, "session_id": S, "device_id": D, "generation": 1,
                      "deleted": False, "snapshot": CS, "signing_key_id": K})


def VG(generation, deleted=False):
    header = dict(CH, generation=generation)
    nonce = generation.to_bytes(12, "big")
    payload = dict(SP, generation=generation)
    cipher = {"header": header, "algorithm": "A256GCM", "nonce": b64(nonce),
              "ciphertext": b64(AESGCM(bytes(range(32))).encrypt(nonce, jcs(payload),
              b"GhostSession/snapshot/v1\n" + jcs(header)))}
    return signed("vault", dict(VH["core"], generation=generation, deleted=deleted,
                                snapshot=None if deleted else cipher))


def proof(method, path, body, nonce_number, relay=False, if_match=None):
    core = {"v": 1, "actor_id": A, "device_id": D, "key_id": ident("gk", 2 if relay else 3),
            "method": method, "path": path,
            "body_hash": hashlib.sha256(b"" if method == "GET" else jcs(body)).hexdigest(),
            "nonce": b64(nonce_number.to_bytes(16, "big")), "issued_ms": NOW,
            "expires_ms": NOW + 60000,
            "if_match": if_match, "if_none_match": "*" if method == "PUT" and if_match is None else None}
    envelope = signed("request", core, RELAY_SK if relay else AUTH_SK)
    return {"core": envelope["core"], "signature": envelope["signature"]}


def forward(request, nonce_number):
    path = "/v1/devices/" + D + "/rpc"
    return {"v": 1, "proof": proof("POST", path, request, nonce_number),
            "relay": proof("POST", path, request, nonce_number, True), "request": request}


def response_proof(request_proof, status, body, relay=False):
    core = {"v": 1, "device_id": D, "signing_key_id": ident("gk", 2) if relay else K,
            "request_hash": digest(request_proof["core"]), "status": status,
            "body_hash": digest(body), "issued_ms": NOW}
    envelope = signed("response", core, RELAY_SK if relay else SK)
    return {"core": envelope["core"], "signature": envelope["signature"]}


def q(n, m, p):
    return {"v": 1, "id": "gq_" + str(n).zfill(21), "method": m, "params": p}


LEASE = {"lease_id": L, "run_id": R, "actor_id": A, "fence": 1, "expires_ms": NOW + 45000}
CARD = {"handoff_id": H, "session_id": S, "owner_id": A, "state": "PENDING",
        "reason": "INITIAL_LOGIN", "policy_hash": PH, "session_revision": 2,
        "created_ms": NOW, "expires_ms": NOW + 900000, "attempts": 0,
        "presentation": "local_browser_only"}
BASE_OBS = {"status": 200, "network": "ok", "cf_mitigated": False, "challenge_marker": False,
            "login_marker": False, "logged_in_marker": False, "redirected_to_login": False,
            "identity": "not_checked", "retry_after": None, "received_ms": NOW}
GOOD_COOKIE = {"name": "sid", "value": "fixture-only", "host": "app.example.test", "path": "/",
               "secure": True, "http_only": True, "same_site": "Lax", "expires_ms": NOW + 60000}
BLOCK1 = {"class": "RATE_LIMIT", "revision": 9, "attempt": 1, "retry_at_ms": NOW,
          "fallback_used": False,
          "observation": {"status": 429, "network": "ok", "cf_mitigated": False,
                          "challenge_marker": False, "login_marker": False,
                          "redirected_to_login": False, "identity": "not_checked",
                          "retry_after": None, "received_ms": NOW - 30000}}
READY_INPUT = {"state": "ACTIVE", "generation": 1, "fence": 7, "lease_id": L,
               "lease_expires_ms": NOW + 45000, "policy_hash": PH, "now_ms": NOW,
               "dispatched": False, "operation_id": O}
TRUST = {"v": 1, "keys": [{"key_id": K, "device_id": D, "purpose": "receipt",
                          "public_key": pub(SK), "valid_from_ms": NOW, "retired_ms": None}]}

# Example requests referenced by vectors.
Q4 = q(4, "session.get", {"session_id": S})
PROOF_Q4 = proof("POST", "/v1/devices/" + D + "/rpc", Q4, 1)

out = {
    "ids": {"S": S, "T": T, "D": D, "A": A, "R": R, "L": L, "H": H, "O": O,
            "K": K, "E": E, "Z": Z},
    "now": NOW,
    "keys": {
        "sk_seed_b64": b64(bytes(range(32))),
        "sk_pub_b64": pub(SK),
        "relay_seed_b64": b64(bytes(range(32, 64))),
        "relay_pub_b64": pub(RELAY_SK),
        "auth_seed_b64": b64(bytes(range(64, 96))),
        "auth_pub_b64": pub(AUTH_SK),
        "enc_key_b64": b64(bytes(range(32))),
        "snapshot_nonce_b64": b64(NONCE),
    },
    "policy_core": PC,
    "policy": P,
    "policy_hash": PH,
    "receipt_envelope": EH,
    "audit7": AUDIT7,
    "snapshot_plain": SP,
    "cipher_header": CH,
    "cipher_snapshot": CS,
    "vault_head": VH,
    "vg2": VG(2),
    "vg3": VG(3),
    "vg4_tombstone": VG(4, True),
    "vg5": VG(5),
    "lease": LEASE,
    "card": CARD,
    "base_obs": BASE_OBS,
    "good_cookie": GOOD_COOKIE,
    "block1": BLOCK1,
    "ready_input": READY_INPUT,
    "trust_file": TRUST,
    "requests": {"q4": Q4},
    "proof_q4": PROOF_Q4,
    "inbox_card": {"v": 1, "external_id": H, "session_id": S, "owner_id": A,
                   "origin": "https://app.example.test", "reason": "INITIAL_LOGIN",
                   "expires_ms": NOW + 900000, "policy_hash": PH,
                   "allowed_actions": ["notify_local", "cancel"]},
}

dest = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures.json")
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print(f"wrote {dest}")
