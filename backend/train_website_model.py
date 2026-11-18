"""Train website/URL models (Random Forest, XGBoost [optional], Logistic Regression) on LEXICAL URL features.
Usage:  python train_website_model.py      (run from backend/)
Writes: models/website_model.pkl, models/metrics.json

NOTE: the model sees only the URL string, so it cannot see page content. The web scanner combines it with live
checks (SSL, DNS, domain age, HTML...). Beware dataset bias: if phishing URLs come from PhishTank (full paths) and
legitimate URLs from a top-sites list (bare domains), a model can learn 'has a path' instead of 'is phishing'."""
import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.training_utils import MODELS, evaluate, load_labeled, pick_dataset, save_metrics
from app.services.url_features import FEATURE_NAMES, feature_vector

path, demo = pick_dataset("phishing_urls.csv", "sample_phishing_urls.csv")
df = load_labeled(path, ["url", "urls", "link", "website"])
X = [feature_vector(u) for u in df["text"]]  # feature engineering
y = df["label"]
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

candidates = {
    "Random Forest": (RandomForestClassifier(random_state=42, n_jobs=-1, class_weight="balanced"), {"n_estimators": [200, 400], "max_depth": [None, 20]}),
    "Logistic Regression": (make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced")), {"logisticregression__C": [0.1, 1, 10]}),
}
try:
    from xgboost import XGBClassifier
    candidates["XGBoost"] = (XGBClassifier(eval_metric="logloss", random_state=42, n_jobs=1), {"n_estimators": [200, 400], "max_depth": [3, 6], "learning_rate": [0.05, 0.1]})
except ImportError:
    print("xgboost not installed -> skipping XGBoost (pip install xgboost)")

print("Hyper-parameter tuning (3-fold CV, scoring=F1) and test-set evaluation:")
results, best = [], None
for name, (est, grid) in candidates.items():
    gs = GridSearchCV(est, grid, cv=3, scoring="f1", n_jobs=-1).fit(X_tr, y_tr)
    m = evaluate(f"Website: {name}", y_te, gs.best_estimator_.predict_proba(X_te)[:, 1], path.name, demo)
    m["best_params"] = {k: (v if isinstance(v, (int, float, str, type(None))) else str(v)) for k, v in gs.best_params_.items()}
    results.append(m)
    if best is None or (m["f1_score"], m["roc_auc"]) > (best[1]["f1_score"], best[1]["roc_auc"]):
        best = (gs.best_estimator_, m, name)

final = CalibratedClassifierCV(best[0], method="sigmoid", cv=3).fit(X_tr, y_tr)
print("\nDeployed model (best by F1, probability-calibrated):")
results.append(evaluate(f"Website: DEPLOYED ({best[2]}, calibrated)", y_te, final.predict_proba(X_te)[:, 1], path.name, demo))

MODELS.mkdir(exist_ok=True)
joblib.dump({"model": final, "feature_names": FEATURE_NAMES, "name": best[2]}, MODELS / "website_model.pkl")
save_metrics("Website:", results)
print(f"\nSaved model to {MODELS}")
if demo:
    print("REMINDER: trained on SYNTHETIC demo data; do not trust this model. Train on real data.")
