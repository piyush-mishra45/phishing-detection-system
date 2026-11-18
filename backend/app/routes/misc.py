from flask import Blueprint, jsonify
from sqlalchemy import text

from app.database.db import db
from app.ml import predictor
from app.models.models import ModelMetric
from app.security.auth import login_required

bp = Blueprint("misc", __name__, url_prefix="/api")


@bp.get("/health")
def health():
    try:
        db().execute(text("SELECT 1"))
        dbs = "ok"
    except Exception:
        dbs = "error"
    return jsonify({"status": "ok" if dbs == "ok" else "degraded", "database": dbs, "models": predictor.model_info()})


@bp.get("/model/metrics")
@login_required
def metrics():
    import json
    rows = db().query(ModelMetric).order_by(ModelMetric.trained_at.desc(), ModelMetric.id.desc()).all()
    latest = {}
    for r in rows:  # newest run per model
        latest.setdefault(r.model_name, r)
    return jsonify({"metrics": [{"model_name": r.model_name, "accuracy": r.accuracy, "precision": r.precision, "recall": r.recall, "f1_score": r.f1_score, "roc_auc": r.roc_auc,
                                 "confusion_matrix": json.loads(r.confusion_matrix or "[]"), "trained_at": r.trained_at.isoformat(), "dataset": r.dataset, "is_demo_data": bool(r.is_demo_data)}
                                for r in latest.values()],
                    "warning": "Metrics measure performance on the held-out split of the training dataset only. They are NOT evidence of real-world accuracy." })
