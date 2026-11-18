"""Small in-memory sliding-window rate limiter.
Good for a single process; for multi-worker production use Redis (e.g. Flask-Limiter with a Redis backend)."""
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import g, jsonify, request

_hits = defaultdict(deque)
_lock = threading.Lock()


def client_key():
    uid = getattr(g, "user_id", None)
    # request.remote_addr is only the real client IP behind a trusted proxy when TRUST_PROXY=1 (ProxyFix); never trust raw headers.
    return f"u{uid}" if uid else (request.remote_addr or "?")


def rate_limit(limit_getter, window=60, scope="default"):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            limit = limit_getter() if callable(limit_getter) else limit_getter
            key = (scope, client_key())
            now = time.monotonic()
            with _lock:
                q = _hits[key]
                while q and now - q[0] > window:
                    q.popleft()
                if len(q) >= limit:
                    retry = int(window - (now - q[0])) + 1
                    resp = jsonify({"error": "Too many requests. Please slow down.", "retry_after": retry})
                    resp.status_code = 429
                    resp.headers["Retry-After"] = str(retry)
                    return resp
                q.append(now)
            return fn(*a, **kw)
        return wrapper
    return deco


def reset():
    with _lock:
        _hits.clear()
