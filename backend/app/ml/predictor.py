"""Lazy, thread-safe loading of the Joblib models. Models are loaded ONLY from the local MODEL_DIR that
this project's training scripts write to (joblib uses pickle: never load model files from untrusted sources)."""
import logging
import threading
from pathlib import Path

import joblib

from app.services.url_features import FEATURE_NAMES, feature_vector

log = logging.getLogger("phishguard.ml")
_lock = threading.Lock()
_cache = {}
_model_dir = Path(__file__).resolve().parents[3] / "models"


def configure(model_dir):
    global _model_dir
    _model_dir = Path(model_dir)
    _cache.clear()


def _load(filename):
    with _lock:
        if filename in _cache:
            return _cache[filename]
        p = _model_dir / filename
        obj = None
        if p.exists():
            try:
                obj = joblib.load(p)
            except Exception:  # corrupted / incompatible sklearn version
                log.exception("Could not load %s", filename)
        _cache[filename] = obj
        return obj


def email_ready():
    return _load("email_model.pkl") is not None and _load("vectorizer.pkl") is not None


def website_ready():
    return _load("website_model.pkl") is not None


def predict_email_prob(text: str):
    """Calibrated P(phishing) for email text, or None when no model is available."""
    vec, clf = _load("vectorizer.pkl"), _load("email_model.pkl")
    if vec is None or clf is None:
        return None
    return float(clf.predict_proba(vec.transform([text]))[0][1])


def predict_url_prob(url: str):
    bundle = _load("website_model.pkl")
    if bundle is None:
        return None
    if bundle.get("feature_names") != FEATURE_NAMES:
        log.error("website_model.pkl feature set does not match code; retrain with train_website_model.py")
        return None
    return float(bundle["model"].predict_proba([feature_vector(url)])[0][1])


def model_info():
    out = {}
    for key, fn in (("email", "email_model.pkl"), ("website", "website_model.pkl")):
        out[key] = _load(fn) is not None
    return out
