import json
from datetime import datetime
from pathlib import Path

from app.database.db import db
from app.models.models import ModelMetric


def sync_metrics(model_dir):
    """Copy metrics written by the training scripts (models/metrics.json) into the model_metrics table."""
    f = Path(model_dir) / "metrics.json"
    if not f.exists():
        return 0
    s, n = db(), 0
    for m in json.loads(f.read_text()):
        trained = datetime.fromisoformat(m["trained_at"])
        exists = s.query(ModelMetric).filter_by(model_name=m["model_name"], trained_at=trained).first()
        if exists:
            continue
        s.add(ModelMetric(model_name=m["model_name"], accuracy=m["accuracy"], precision=m["precision"], recall=m["recall"], f1_score=m["f1_score"],
                          roc_auc=m.get("roc_auc"), trained_at=trained, confusion_matrix=json.dumps(m.get("confusion_matrix", [])),
                          dataset=m.get("dataset", ""), is_demo_data=int(m.get("is_demo_data", False))))
        n += 1
    s.commit()
    return n
