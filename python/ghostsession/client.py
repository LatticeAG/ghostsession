"""ghostsession Python client — unix-socket local transport and remote HTTPS
transport with request proofs + response-proof verification.

`client.call(method, params, request_id=...)` returns the typed result —
observationally equivalent to the TypeScript client (spec §10).
"""

from __future__ import annotations

import http.client
import secrets
import socket
import time

from .crypto import domain_message, ed25519_sign, ed25519_verify, jcs_hash, sha256_hex
from .encoding import b64_decode, b64_encode, jcs_bytes, new_id, strict_loads
from .errors import RpcFailure


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _fail(code: str, retryable: bool = False) -> RpcFailure:
    f = RpcFailure(code)
    f.retryable = retryable
    f.retry_at_ms = None
    f.state = None
    return f


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


class UnixSocketTransport:
    def __init__(self, socket_path: str, timeout_ms: int = 30_000):
        self.socket_path = socket_path
        self.timeout_ms = timeout_ms

    def call(self, body: bytes) -> dict:
        conn = _UnixHTTPConnection(self.socket_path, self.timeout_ms / 1000)
        try:
            conn.request("POST", "/v1/rpc", body=body,
                         headers={"content-type": "application/json"})
            res = conn.getresponse()
            return {"status": res.status, "body": res.read(),
                    "response_proof": None}
        except socket.timeout:
            raise _fail("TIMEOUT", retryable=True) from None
        except OSError:
            raise _fail("DEVICE_OFFLINE", retryable=True) from None
        finally:
            conn.close()


class RemoteTransport:
    """HTTPS transport: signs an x-ghost-proof request proof per call and
    verifies the daemon's response proof."""

    def __init__(self, *, base_url: str, device_id: str, actor_id: str,
                 request_key_id: str, request_seed: bytes,
                 device_public_key: bytes, timeout_ms: int = 30_000):
        from urllib.parse import urlparse
        u = urlparse(base_url)
        self.host = u.hostname
        self.port = u.port or 443
        self.device_id = device_id
        self.actor_id = actor_id
        self.request_key_id = request_key_id
        self.request_seed = request_seed
        self.device_public_key = device_public_key
        self.timeout_ms = timeout_ms
        self.last_proof_core = None

    def call(self, body: bytes) -> dict:
        parsed = strict_loads(body)
        now = _now_ms()
        path = f"/v1/devices/{self.device_id}/rpc"
        proof_core = {
            "v": 1, "actor_id": self.actor_id, "device_id": self.device_id,
            "key_id": self.request_key_id, "method": "POST", "path": path,
            "body_hash": sha256_hex(jcs_bytes(parsed)),
            "nonce": b64_encode(secrets.token_bytes(16)),
            "issued_ms": now, "expires_ms": now + 60_000,
            "if_match": None, "if_none_match": None,
        }
        self.last_proof_core = proof_core
        signature = b64_encode(ed25519_sign(
            self.request_seed, domain_message("request", jcs_hash(proof_core))))
        proof_header = jcs_bytes({"core": proof_core, "signature": signature})
        conn = http.client.HTTPSConnection(self.host, self.port,
                                           timeout=self.timeout_ms / 1000)
        try:
            conn.request("POST", path, body=body, headers={
                "content-type": "application/json",
                "x-ghost-proof": b64_encode(proof_header),
            })
            res = conn.getresponse()
            rp = res.getheader("x-ghost-response-proof")
            return {"status": res.status, "body": res.read(),
                    "response_proof": b64_decode(rp) if rp else None}
        except socket.timeout:
            raise _fail("TIMEOUT", retryable=True) from None
        except OSError:
            raise _fail("DEVICE_OFFLINE", retryable=True) from None
        finally:
            conn.close()

    def verify_response(self, request_proof_core, status: int, body: bytes,
                        proof_header: bytes | None) -> None:
        if proof_header is None:
            raise _fail("INTEGRITY_FAILED")
        env = strict_loads(proof_header)
        c = env.get("core")
        ok = (
            isinstance(c, dict)
            and c.get("v") == 1
            and c.get("device_id") == self.device_id
            and c.get("request_hash") == jcs_hash(request_proof_core)
            and c.get("status") == status
            and c.get("body_hash") == sha256_hex(body)
            and ed25519_verify(
                self.device_public_key,
                domain_message("response", jcs_hash(c)),
                b64_decode(env["signature"]))
        )
        if not ok:
            raise _fail("INTEGRITY_FAILED")


class Client:
    def __init__(self, transport, timeout_ms: int = 30_000):
        self.transport = transport
        self.timeout_ms = timeout_ms

    @classmethod
    def local(cls, socket_path: str, timeout_ms: int = 30_000) -> "Client":
        return cls(UnixSocketTransport(socket_path, timeout_ms), timeout_ms)

    def call(self, method: str, params, request_id: str | None = None):
        rid = request_id if request_id is not None else new_id("gq")
        body = jcs_bytes({"v": 1, "id": rid, "method": method, "params": params})
        attempts = 0
        while True:
            attempts += 1
            try:
                res = self.transport.call(body)
            except RpcFailure as e:
                if getattr(e, "retryable", False) and attempts <= 2:
                    continue
                raise
            if isinstance(self.transport, RemoteTransport):
                self.transport.verify_response(
                    self.transport.last_proof_core, res["status"],
                    res["body"], res["response_proof"])
            parsed = strict_loads(res["body"])
            if parsed.get("ok"):
                return parsed.get("result")
            e = parsed["error"]
            failure = RpcFailure(e["code"])
            failure.retryable = e["retryable"]
            failure.retry_at_ms = e["retry_at_ms"]
            failure.state = e["state"]
            if failure.retryable and attempts <= 2:
                continue
            raise failure
