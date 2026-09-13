"""Bounded recovery delay computation (spec §6). Deterministic: no jitter;
inclusive expiry everywhere. Byte-identical to the TypeScript version."""

from __future__ import annotations

import calendar
import re
from datetime import datetime, timezone

CHALLENGE_BASE_MS = 60_000
RATE_BASE_MS = 30_000
NETWORK_BASE_MS = 5_000
MAX_RETRY_DELAY_MS = 900_000
MAX_SERVER_WAIT_MS = 86_400_000
MAX_SAFE_UINT = 9007199254740991

_IMF_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_IMF_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_IMF_RE = re.compile(
    r"^([A-Z][a-z]{2}), (\d{2}) ([A-Z][a-z]{2}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$")


def _base_delay(cls: str, network: str) -> int:
    if cls == "CF_CHALLENGE":
        return CHALLENGE_BASE_MS
    if cls == "RATE_LIMIT":
        return RATE_BASE_MS
    if cls == "NETWORK_ERROR" and network != "tls_error":
        return NETWORK_BASE_MS
    return 0


def parse_retry_after(raw: str | None, received_ms: int) -> dict:
    """Valid inputs: ASCII digits after OWS trim, or an IMF-fixdate with GMT.
    Anything else — other date formats, signs, fractions, non-GMT zones — is
    invalid."""
    if raw is None:
        return {"kind": "none"}
    t = raw.strip()
    if t == "":
        return {"kind": "invalid"}
    if re.fullmatch(r"[0-9]+", t):
        # digit strings may be arbitrarily long — detect overflow safely
        if len(t) > 15:
            return {"kind": "overflow"}
        ms = int(t) * 1000
        if ms > MAX_SAFE_UINT:
            return {"kind": "overflow"}
        return {"kind": "ok", "delay_ms": ms}
    m = _IMF_RE.match(t)
    if not m:
        return {"kind": "invalid"}
    wday, day, mon, year, hh, mm, ss = m.groups()
    if mon not in _IMF_MONTHS:
        return {"kind": "invalid"}
    mon_idx = _IMF_MONTHS.index(mon)
    d, y, H, M, S = int(day), int(year), int(hh), int(mm), int(ss)
    if d < 1 or d > 31 or H > 23 or M > 59 or S > 60:
        return {"kind": "invalid"}
    try:
        dt = datetime(y, mon_idx + 1, d, H, M, min(S, 59), tzinfo=timezone.utc)
    except ValueError:
        return {"kind": "invalid"}
    if S == 60:
        # leap second — datetime caps at 59; field equality below uses 59.
        pass
    if (
        dt.year != y or dt.month != mon_idx + 1 or dt.day != d
        or dt.hour != H or dt.minute != M or dt.second != min(S, 59)
        or _IMF_WEEKDAYS[dt.weekday()] != wday
    ):
        return {"kind": "invalid"}
    date_ms = calendar.timegm(dt.timetuple()) * 1000
    return {"kind": "ok", "delay_ms": max(0, date_ms - received_ms)}


def compute_delay(cls: str, network: str, attempt: int,
                  retry_after: str | None, received_ms: int) -> dict:
    """delay = max(backoff, parsed server delay); retry_at = received + delay.
    A valid server delay above MAX_SERVER_WAIT_MS (or overflow) exhausts
    eligibility — it is never capped down."""
    base = _base_delay(cls, network)
    backoff = min(base * 2 ** (attempt - 1), MAX_RETRY_DELAY_MS)
    parsed = parse_retry_after(retry_after, received_ms)
    if parsed["kind"] == "overflow":
        return {"delay_ms": None, "retry_at_ms": None, "exhausted": True}
    server = parsed["delay_ms"] if parsed["kind"] == "ok" else 0
    if parsed["kind"] == "ok" and server > MAX_SERVER_WAIT_MS:
        return {"delay_ms": None, "retry_at_ms": None, "exhausted": True}
    delay = max(backoff, server)
    retry_at = received_ms + delay
    if retry_at > MAX_SAFE_UINT:
        return {"delay_ms": None, "retry_at_ms": None, "exhausted": True}
    return {"delay_ms": delay, "retry_at_ms": retry_at, "exhausted": False}
