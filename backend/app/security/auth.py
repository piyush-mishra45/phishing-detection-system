import threading
import time
import uuid
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from app.database.db import db
from app.models.models import User

_revoked = {}  # jti -> exp   (in-memory; use Redis/DB table for multi-worker deployments)
_rv_lock = threading.Lock()


def hash_password(pw):
    return generate_password_hash(pw)  # werkzeug default: scrypt, salted


def verify_password(pw, h):
    return check_password_hash(h, pw)


def make_token(user):
    cfg = current_app.config
    now = int(time.time())
    payload = {"sub": str(user.id), "role": user.role, "iat": now, "exp": now + cfg["JWT_EXPIRES_HOURS"] * 3600, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, cfg["SECRET_KEY"], algorithm="HS256")


def revoke(payload):
    with _rv_lock:
        now = time.time()
        for k in [k for k, v in _revoked.items() if v < now]:
            _revoked.pop(k, None)
        _revoked[payload["jti"]] = payload["exp"]


def _decode():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        p = jwt.decode(h[7:], current_app.config["SECRET_KEY"], algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})
    except jwt.PyJWTError:
        return None
    with _rv_lock:
        if p["jti"] in _revoked:
            return None
    return p


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        p = _decode()
        if not p:
            return jsonify({"error": "Authentication required"}), 401
        user = db().get(User, int(p["sub"]))
        if not user:
            return jsonify({"error": "Account no longer exists"}), 401
        g.user, g.user_id, g.token_payload = user, user.id, p
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if g.user.role != "admin":  # role is re-read from DB, not trusted from the token
            return jsonify({"error": "Admin access required"}), 403
        return fn(*a, **kw)
    return wrapper
