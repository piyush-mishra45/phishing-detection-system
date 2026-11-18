import csv
import io
import json
from datetime import datetime, timedelta

from flask import Blueprint, Response, g, jsonify, request
from sqlalchemy import and_, func, or_, select

from app.database.db import db
from app.models.models import EmailScan, ScanHistory, WebsiteScan
from app.security.auth import login_required
from app.security.validators import ValidationError, csv_safe
from app.services.risk_engine import level_range, risk_level

bp = Blueprint("history", __name__, url_prefix="/api")
E, W = EmailScan, WebsiteScan
PRED = func.coalesce(E.prediction, W.prediction)
SCORE = func.coalesce(E.risk_score, W.risk_score)
TITLE = func.coalesce(E.subject, W.url)
SUB = func.coalesce(E.sender_email, W.domain)


def _date(v, end=False):
    if not v:
        return None
    try:
        d = datetime.strptime(v, "%Y-%m-%d")
    except ValueError:
        raise ValidationError("Dates must be YYYY-MM-DD")
    return d + timedelta(days=1) if end else d


def build_query(user_id):
    q = (select(ScanHistory.id, ScanHistory.scan_type, ScanHistory.status, ScanHistory.created_at, PRED.label("prediction"), SCORE.label("risk_score"), TITLE.label("title"), SUB.label("subtitle"))
         .select_from(ScanHistory)
         .outerjoin(E, and_(ScanHistory.scan_type == "email", ScanHistory.scan_reference_id == E.id))
         .outerjoin(W, and_(ScanHistory.scan_type == "website", ScanHistory.scan_reference_id == W.id))
         .where(ScanHistory.user_id == user_id))
    a = request.args
    if a.get("q"):
        term = f"%{a['q'][:100].replace('%', '').replace('_', '')}%"
        q = q.where(or_(TITLE.ilike(term), SUB.ilike(term)))
    if a.get("type") in ("email", "website"):
        q = q.where(ScanHistory.scan_type == a["type"])
    if a.get("prediction"):
        q = q.where(PRED == a["prediction"].upper())
    if a.get("category"):
        rng = level_range(a["category"])
        if not rng:
            raise ValidationError("category must be low, medium, high or critical")
        q = q.where(SCORE >= rng[0], SCORE <= rng[1])  # scores are whole numbers (see risk_engine)
    if _date(a.get("date_from")):
        q = q.where(ScanHistory.created_at >= _date(a["date_from"]))
    if _date(a.get("date_to")):
        q = q.where(ScanHistory.created_at < _date(a["date_to"], end=True))
    return q.order_by(ScanHistory.created_at.desc(), ScanHistory.id.desc())


def _row(r):
    return {"id": r.id, "scan_type": r.scan_type, "status": r.status, "created_at": r.created_at.isoformat(), "prediction": r.prediction,
            "risk_score": r.risk_score, "risk_level": risk_level(r.risk_score or 0), "title": r.title, "subtitle": r.subtitle}


@bp.get("/history")
@login_required
def list_history():
    q = build_query(g.user_id)
    s = db()
    page = max(1, request.args.get("page", 1, type=int))
    per = min(100, max(1, request.args.get("per_page", 20, type=int)))
    total = s.execute(select(func.count()).select_from(q.order_by(None).subquery())).scalar_one()
    rows = s.execute(q.limit(per).offset((page - 1) * per)).all()
    return jsonify({"items": [_row(r) for r in rows], "total": total, "page": page, "per_page": per})


@bp.get("/history/<int:hid>")
@login_required
def history_detail(hid):
    s = db()
    h = s.get(ScanHistory, hid)
    if not h or h.user_id != g.user_id:  # ownership check: no cross-user access (IDOR)
        return jsonify({"error": "Scan not found"}), 404
    model = EmailScan if h.scan_type == "email" else WebsiteScan
    row = s.get(model, h.scan_reference_id)
    if not row:
        return jsonify({"error": "Scan data missing"}), 404
    base = {"id": h.id, "scan_type": h.scan_type, "status": h.status, "created_at": h.created_at.isoformat(), "prediction": row.prediction, "risk_score": row.risk_score}
    if h.scan_type == "email":
        base.update({"sender_email": row.sender_email, "subject": row.subject, "content_excerpt": row.email_content})
    else:
        base.update({"url": row.url, "domain": row.domain, "ssl_status": row.ssl_status})
    return jsonify({**base, "report": json.loads(row.report_json or "{}"),
                    "features": [{"name": f.feature_name, "value": f.feature_value, "risk_reason": f.risk_reason} for f in h.features]})


@bp.delete("/history/<int:hid>")
@login_required
def delete_history(hid):
    s = db()
    h = s.get(ScanHistory, hid)
    if not h or h.user_id != g.user_id:
        return jsonify({"error": "Scan not found"}), 404
    model = EmailScan if h.scan_type == "email" else WebsiteScan
    row = s.get(model, h.scan_reference_id)
    if row:
        s.delete(row)
    s.delete(h)
    s.commit()
    return jsonify({"message": "Deleted"})


@bp.get("/reports/export")
@login_required
def export_csv():
    rows = db().execute(build_query(g.user_id).limit(10000)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "type", "date_utc", "title", "sender_or_domain", "prediction", "risk_score", "risk_level", "status"])
    for r in rows:
        w.writerow([r.id, r.scan_type, r.created_at.isoformat(), csv_safe(r.title), csv_safe(r.subtitle), r.prediction, r.risk_score, risk_level(r.risk_score or 0), r.status])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=phishguard_report.csv"})
