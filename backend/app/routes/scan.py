import json

from flask import Blueprint, current_app, g, jsonify, request

from app.database.db import db
from app.models.models import EmailScan, ScanFeature, ScanHistory, WebsiteScan
from app.security.auth import login_required
from app.security.ratelimit import rate_limit
from app.security.validators import ValidationError, redact_excerpt, require_str, validate_email_addr
from app.services import email_analyzer, website_analyzer

bp = Blueprint("scan", __name__, url_prefix="/api/scan")
limit = rate_limit(lambda: current_app.config["RATE_LIMIT_SCAN_PER_MIN"], scope="scan")


def _features(history_id, signals, extras=()):
    rows = []
    for s in signals:
        rows.append(ScanFeature(scan_id=history_id, feature_name=str(s["id"])[:100], feature_value=json.dumps(s.get("value"), default=str)[:2000], risk_reason=(s.get("reason") or "")[:500]))
    for name, val in extras:
        rows.append(ScanFeature(scan_id=history_id, feature_name=name, feature_value=json.dumps(val, default=str)[:2000], risk_reason=""))
    return rows


def _persist(scan_type, row, report, extras=()):
    s = db()
    try:
        row.report_json = json.dumps(report, default=str)
        s.add(row)
        s.flush()
        h = ScanHistory(user_id=g.user_id, scan_type=scan_type, scan_reference_id=row.id, status="completed")
        s.add(h)
        s.flush()
        s.add_all(_features(h.id, report.get("signals", []), extras))
        s.commit()
        return h.id
    except Exception:
        s.rollback()
        raise


@bp.post("/email")
@login_required
@limit
def scan_email():
    parsed, body, sender, subject = None, "", "", ""
    if request.files.get("file"):
        f = request.files["file"]
        if not (f.filename or "").lower().endswith(".eml"):
            raise ValidationError("Only .eml files are supported", "file")
        raw = f.read(current_app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(raw) > current_app.config["MAX_CONTENT_LENGTH"]:
            raise ValidationError("File too large (max 2 MB)", "file")
        try:
            parsed = email_analyzer.parse_eml(raw)  # held in memory only; the upload is never written to disk or executed
        except Exception:
            raise ValidationError("Could not parse the .eml file", "file")
        body, sender, subject = parsed["body"], parsed["from"], parsed["subject"]
        # manual fields (if supplied) override the parsed values
        sender = request.form.get("sender_email", "").strip() or sender
        subject = request.form.get("subject", "").strip() or subject
    else:
        d = request.get_json(silent=True) or request.form or {}
        body = require_str(d, "email_content", 100_000, required=True)
        sender = require_str(d, "sender_email", 254, required=False)
        subject = require_str(d, "subject", 500, required=False)
        if sender and "<" not in sender:
            sender = validate_email_addr(sender, "sender_email")
    if len(body.strip()) < 10:
        raise ValidationError("Email content is too short to analyse", "email_content")

    rep = email_analyzer.analyze_email(sender, subject, body, parsed)
    row = EmailScan(user_id=g.user_id, sender_email=sender[:255], subject=subject[:500], email_content=redact_excerpt(body), prediction=rep["prediction"], risk_score=rep["risk_score"])
    extras = [("ml.phishing_probability", rep["phishing_probability"]), ("ml.model_confidence", rep["model_confidence"]), ("risk.score", rep["risk_score"])]
    sid = _persist("email", row, rep, extras)
    return jsonify({"scan_id": sid, "scan_type": "email", "report": rep}), 201


@bp.post("/website")
@login_required
@limit
def scan_website():
    d = request.get_json(silent=True) or {}
    url = require_str(d, "url", 2048)
    try:
        rep = website_analyzer.analyze_website(url, current_app.config)
    except ValueError as e:
        raise ValidationError(str(e), "url")
    row = WebsiteScan(user_id=g.user_id, url=rep["url"][:2048], domain=rep["domain"][:255], prediction=rep["prediction"], risk_score=rep["risk_score"], ssl_status=rep["ssl"]["status"])
    extras = [("ml.phishing_probability", rep["ml_probability"]), ("ml.model_confidence", rep["model_confidence"]), ("risk.score", rep["risk_score"])]
    sid = _persist("website", row, rep, extras)
    return jsonify({"scan_id": sid, "scan_type": "website", "report": rep}), 201
