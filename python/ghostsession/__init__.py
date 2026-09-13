"""GhostSession Python SDK — protocol-equivalent client for the local daemon.

The SDK serializes the same wire protocol as the TypeScript client. It does
not run a second vault or implement another browser driver (spec §10).
"""

from . import audit, classify, crypto, delay, encoding, schema
from .client import Client, RemoteTransport, UnixSocketTransport
from .errors import B64Error, JcsError, RpcFailure, StrictJsonError

__all__ = [
    "audit", "classify", "crypto", "delay", "encoding", "schema",
    "Client", "RemoteTransport", "UnixSocketTransport",
    "RpcFailure", "StrictJsonError", "JcsError", "B64Error",
]
__version__ = "1.0.0"
