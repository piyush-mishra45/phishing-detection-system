from flask import Blueprint, g, jsonify, request
from sqlalchemy import func

from app.database.db import db
from app.models.models import EmailScan, ScanHistory, User, WebsiteScan
from app.routes.dashboard import compute_stats
from app.security.auth import admin_required

bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@bp.get("/users")
@admin_required
def users():
    s = db()
    counts = dict(s.query(ScanHistory.user_id, func.count()).group_by(ScanHistory.user_id).all())
    return jsonify({"users": [{"id": u.id, "username": u.username, "email": u.email, "role": u.role, "created_at": u.created_at.isoformat(), "scans": counts.get(u.id, 0)}
                              for u in s.query(User).order_by(User.id).all()]})


@bp.patch("/users/<int:uid>/role")
@admin_required
def set_role(uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400
    if uid == g.user_id:
        return jsonify({"error": "You cannot change your own role"}), 400
    s = db()
    u = s.get(User, uid)
    if not u:
        return jsonify({"error": "User not found"}), 404
    u.role = role
    s.commit()
    return jsonify({"id": u.id, "role": u.role})


@bp.delete("/users/<int:uid>")
@admin_required
def delete_user(uid):
    if uid == g.user_id:
        return jsonify({"error": "You cannot delete your own account here"}), 400
    s = db()
    u = s.get(User, uid)
    if not u:
        return jsonify({"error": "User not found"}), 404
    s.query(EmailScan).filter_by(user_id=uid).delete()
    s.query(WebsiteScan).filter_by(user_id=uid).delete()
    s.delete(u)  # cascades to scan_history -> scan_features
    s.commit()
    return jsonify({"message": "User deleted"})


@bp.get("/stats")
@admin_required
def stats():
    r = compute_stats(None)
    r.pop("_recent_q")
    r["users"] = db().query(func.count(User.id)).scalar()
    return jsonify(r)
