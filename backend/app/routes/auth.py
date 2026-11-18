from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app.database.db import db
from app.models.models import User
from app.security import auth as sec
from app.security.ratelimit import rate_limit
from app.security.validators import ValidationError, require_str, validate_email_addr, validate_password
from app.security.validators import USERNAME_RE

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
_DUMMY = sec.hash_password("dummy-password-for-timing")
limit = rate_limit(lambda: current_app.config["RATE_LIMIT_AUTH_PER_MIN"], scope="auth")


def _user_json(u):
    return {"id": u.id, "username": u.username, "email": u.email, "role": u.role, "created_at": u.created_at.isoformat()}


@bp.post("/register")
@limit
def register():
    d = request.get_json(silent=True) or {}
    username = require_str(d, "username", 50, min_len=3)
    if not USERNAME_RE.match(username):
        raise ValidationError("Username may only contain letters, digits, . _ -", "username")
    email = validate_email_addr(require_str(d, "email", 254))
    pw = validate_password(d.get("password"))
    s = db()
    if s.query(User).filter(or_(User.username == username, User.email == email)).first():
        return jsonify({"error": "Username or email already registered"}), 409
    admin = bool(current_app.config["ADMIN_EMAIL"]) and email == current_app.config["ADMIN_EMAIL"]
    u = User(username=username, email=email, password_hash=sec.hash_password(pw), role="admin" if admin else "user")
    s.add(u)
    try:
        s.commit()
    except IntegrityError:
        s.rollback()
        return jsonify({"error": "Username or email already registered"}), 409
    return jsonify({"token": sec.make_token(u), "user": _user_json(u)}), 201


@bp.post("/login")
@limit
def login():
    d = request.get_json(silent=True) or {}
    ident = require_str(d, "identifier", 254).lower() if "identifier" in d else require_str(d, "email", 254).lower()
    pw = d.get("password") or ""
    u = db().query(User).filter(or_(User.email == ident, User.username == ident)).first()
    ok = sec.verify_password(pw, u.password_hash if u else _DUMMY)  # same work either way (timing)
    if not u or not ok:
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"token": sec.make_token(u), "user": _user_json(u)})


@bp.post("/logout")
@sec.login_required
def logout():
    sec.revoke(g.token_payload)
    return jsonify({"message": "Logged out"})


@bp.get("/me")
@sec.login_required
def me():
    return jsonify({"user": _user_json(g.user)})


@bp.put("/me")
@sec.login_required
def update_me():
    d = request.get_json(silent=True) or {}
    s, u = db(), g.user
    if "username" in d:
        nu = require_str(d, "username", 50, min_len=3)
        if not USERNAME_RE.match(nu):
            raise ValidationError("Invalid username", "username")
        if s.query(User).filter(User.username == nu, User.id != u.id).first():
            return jsonify({"error": "Username already taken"}), 409
        u.username = nu
    if "email" in d:
        ne = validate_email_addr(require_str(d, "email", 254))
        if s.query(User).filter(User.email == ne, User.id != u.id).first():
            return jsonify({"error": "Email already registered"}), 409
        u.email = ne
    s.merge(u)
    s.commit()
    return jsonify({"user": _user_json(u)})


@bp.post("/change-password")
@sec.login_required
@limit
def change_password():
    d = request.get_json(silent=True) or {}
    if not sec.verify_password(d.get("current_password") or "", g.user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 403
    g.user.password_hash = sec.hash_password(validate_password(d.get("new_password")))
    db().merge(g.user)
    db().commit()
    sec.revoke(g.token_payload)  # force re-login
    return jsonify({"message": "Password changed. Please log in again."})
