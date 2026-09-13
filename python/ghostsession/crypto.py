"""Strict Ed25519, AES-256-GCM, and signed envelopes (spec §3, §3.1).

Same canonicality rules as the TypeScript implementation: signatures are
64 bytes with S < L and a canonical R; public keys are canonical non-small-
order points. The signature equation is evaluated by the `cryptography`
package (OpenSSL), mirroring node:crypto.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import b64_decode, b64_encode, jcs_bytes
from .errors import RpcFailure, StrictJsonError
from .encoding import strict_loads

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# Known small-order / non-canonical Ed25519 encodings (libsodium blocklist).
_SMALL_ORDER_ENC = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227945045b3fea6db724b4032548b1f06741d3fc8c992420b5af12d6c",
    "c7176a703d4dd84fba3c0b760438106f1a0e50c8b8962b2d58aa3d5fe1aee4b4",
))


def _le_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def is_canonical_point_encoding(enc: bytes) -> bool:
    """Canonical point encoding: y < p and x exists on the curve."""
    if len(enc) != 32:
        return False
    sign_bit = (enc[31] & 0x80) != 0
    y = _le_int(bytes([*enc[:31], enc[31] & 0x7F]))
    if y >= _P:
        return False
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x2 = (u * pow(v, _P - 2, _P)) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _SQRT_M1) % _P
        if (x * x - x2) % _P != 0:
            return False
    if (x & 1) != (1 if sign_bit else 0):
        x = _P - x
    return True


def is_valid_public_key(pub: bytes) -> bool:
    return (
        len(pub) == 32
        and is_canonical_point_encoding(pub)
        and pub not in _SMALL_ORDER_ENC
    )


def is_canonical_signature(sig: bytes) -> bool:
    return (
        len(sig) == 64
        and _le_int(sig[32:]) < _L
        and is_canonical_point_encoding(sig[:32])
    )


def ed25519_public_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def ed25519_generate() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _K
    k = _K.generate()
    seed = k.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return seed, k.public_key().public_bytes_raw()


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Strict verify: rejects malformed keys/signatures before OpenSSL."""
    if not is_valid_public_key(public_key) or not is_canonical_signature(signature):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sha256(buf: bytes) -> bytes:
    return hashlib.sha256(buf).digest()


def sha256_hex(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def jcs_hash(value) -> str:
    return sha256_hex(jcs_bytes(value))


DOMAINS = ("policy", "receipt", "vault", "request", "response")


def domain_message(domain: str, core_hash_hex: str) -> bytes:
    return f"GhostSession/{domain}/v1\n".encode() + bytes.fromhex(core_hash_hex)


def sign_envelope(domain: str, core, seed: bytes) -> dict:
    h = jcs_hash(core)
    return {"core": core, "hash": h,
            "signature": b64_encode(ed25519_sign(seed, domain_message(domain, h)))}


def verify_envelope(domain: str, envelope, public_key: bytes) -> bool:
    if not isinstance(envelope, dict):
        return False
    h = envelope.get("hash")
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h):
        return False
    if jcs_hash(envelope.get("core")) != h:
        return False
    try:
        sig = b64_decode(envelope.get("signature"))
    except Exception:
        return False
    return ed25519_verify(public_key, domain_message(domain, h), sig)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def aes256gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes256gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def snapshot_aad(header) -> bytes:
    return b"GhostSession/snapshot/v1\n" + jcs_bytes(header)


def cipher_hash(cipher) -> str:
    return jcs_hash(cipher)


def encrypt_snapshot(plain, header, key: bytes, nonce: bytes) -> dict:
    return {
        "header": header,
        "algorithm": "A256GCM",
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(
            aes256gcm_encrypt(key, nonce, jcs_bytes(plain), snapshot_aad(header))
        ),
    }


def decrypt_snapshot(cipher, key: bytes, checks) -> dict:
    """Mirror of the TS restore path. `checks` keys: session_id, site_id,
    device_id, generation, policy_hash, now_ms, audit_anchor_hash(seq)."""
    h = cipher["header"]
    if (
        h["session_id"] != checks["session_id"]
        or h["site_id"] != checks["site_id"]
        or h["device_id"] != checks["device_id"]
        or h["generation"] != checks["generation"]
        or h["policy_hash"] != checks["policy_hash"]
        or cipher["algorithm"] != "A256GCM"
    ):
        raise RpcFailure("INTEGRITY_FAILED")
    try:
        plain_bytes = aes256gcm_decrypt(
            key, b64_decode(cipher["nonce"]), b64_decode(cipher["ciphertext"]),
            snapshot_aad(h),
        )
        plain = strict_loads(plain_bytes)
    except Exception:
        raise RpcFailure("INTEGRITY_FAILED") from None
    if (
        not isinstance(plain, dict)
        or plain.get("session_id") != checks["session_id"]
        or plain.get("site_id") != checks["site_id"]
        or plain.get("generation") != checks["generation"]
        or plain.get("saved_ms") != h["created_ms"]
        or plain.get("expires_ms") != h["expires_ms"]
    ):
        raise RpcFailure("INTEGRITY_FAILED")
    anchor = checks["audit_anchor_hash"](plain["audit_seq"])
    if anchor is None or anchor != plain["audit_hash"]:
        raise RpcFailure("INTEGRITY_FAILED")
    if checks["now_ms"] >= plain["expires_ms"]:
        raise RpcFailure("SNAPSHOT_EXPIRED")
    return plain


def live_cookies(plain, now_ms: int) -> list:
    """Drop cookies expired at restore time (inclusive expiry)."""
    return [c for c in plain["cookies"]
            if c["expires_ms"] is None or now_ms < c["expires_ms"]]
