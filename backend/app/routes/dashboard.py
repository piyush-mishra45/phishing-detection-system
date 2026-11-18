from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request
from sqlalchemy import case, func, select

from app.database.db import db
from app.models.models import EmailScan, ScanHistory, WebsiteScan
from app.security.auth import login_required
from app.routes.history import _row, build_query

bp = Blueprint("dashboard", __name__, url_prefix="/api")
SAFE = ("LEGITIMATE", "SAFE")


def compute_stats(user_id=None):
    """user_id=None -> all users (admin). Returns the numbers shown on the dashboard."""
    s = db()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    since = (now - timedelta(days=185)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    out = {}
    rows = []
    for kind, M in (("email", EmailScan), ("website", WebsiteScan)):
        q = select(M.created_at, M.prediction, M.risk_score)
        if user_id:
            q = q.where(M.user_id == user_id)
        rows += [(kind, *r) for r in s.execute(q.where(M.created_at >= since)).all()]
        tq = select(M.prediction, func.count(), func.sum(case((M.risk_score > 80, 1), else_=0))).group_by(M.prediction)
        if user_id:
            tq = tq.where(M.user_id == user_id)
        out[kind] = s.execute(tq).all()
    totals = {k: sum(c for _, c, _ in v) for k, v in out.items()}
    pred = {k: {p: c for p, c, _ in v} for k, v in out.items()}
    critical = sum(int(cr or 0) for v in out.values() for _, _, cr in v)
    all_total = totals["email"] + totals["website"]
    phish = pred["email"].get("PHISHING", 0) + pred["website"].get("PHISHING", 0)
    susp = pred["email"].get("SUSPICIOUS", 0) + pred["website"].get("SUSPICIOUS", 0)
    safe = sum(pred[k].get(x, 0) for k in pred for x in SAFE)

    days = [(now - timedelta(days=i)).date() for i in range(6, -1, -1)]
    wk = {d: {"emails": 0, "websites": 0, "threats": 0} for d in days}
    mo = defaultdict(lambda: {"phishing": 0, "suspicious": 0, "safe": 0})
    for kind, created, p, score in rows:
        d = created.date()
        if d in wk:
            wk[d]["emails" if kind == "email" else "websites"] += 1
            wk[d]["threats"] += p in ("PHISHING", "SUSPICIOUS")
        key = created.strftime("%Y-%m")
        mo[key]["phishing" if p == "PHISHING" else "suspicious" if p == "SUSPICIOUS" else "safe" if p in SAFE else "safe"] += 0 if p == "UNKNOWN" else 1
    months = sorted(mo)[-6:]
    recent_q = build_query(user_id).limit(8) if user_id else None
    return {"totals": {"emails_scanned": totals["email"], "websites_scanned": totals["website"], "phishing_emails": pred["email"].get("PHISHING", 0),
                       "malicious_websites": pred["website"].get("PHISHING", 0), "suspicious": susp, "safe_results": safe, "critical_threats": critical,
                       "total_scans": all_total, "phishing_detection_rate": round(100 * phish / all_total, 1) if all_total else 0.0},
            "weekly": [{"date": d.strftime("%a %d"), **v} for d, v in wk.items()],
            "monthly": [{"month": m, **mo[m]} for m in months],
            "distribution": [{"name": "Phishing", "value": phish}, {"name": "Suspicious", "value": susp}, {"name": "Safe", "value": safe},
                             {"name": "Unknown", "value": pred["website"].get("UNKNOWN", 0)}],
            "_recent_q": recent_q}


@bp.get("/dashboard/stats")
@login_required
def stats():
    uid = None if (request.args.get("scope") == "all" and g.user.role == "admin") else g.user_id
    r = compute_stats(uid)
    q = r.pop("_recent_q")
    r["recent_scans"] = [_row(x) for x in db().execute(q).all()] if q is not None else []
    return jsonify(r)
