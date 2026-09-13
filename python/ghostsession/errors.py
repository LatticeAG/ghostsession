"""GhostSession error taxonomy (spec §3/§7)."""


class RpcFailure(Exception):
    """A protocol failure carrying a locked error code."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message if message is not None else code)


class StrictJsonError(Exception):
    pass


class JcsError(Exception):
    pass


class B64Error(Exception):
    pass
