"""Train phishing-EMAIL models: TF-IDF + Logistic Regression / Naive Bayes / Random Forest.
Usage:  python train_email_model.py      (run from backend/)
Writes: models/email_model.pkl (calibrated), models/vectorizer.pkl, models/metrics.json"""
import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.naive_bayes import MultinomialNB

from app.ml.training_utils import MODELS, evaluate, load_labeled, pick_dataset, save_metrics

path, demo = pick_dataset("phishing_emails.csv", "sample_phishing_emails.csv")
df = load_labeled(path, ["text", "email text", "body", "email_text", "content", "message"])

X_tr, X_te, y_tr, y_te = train_test_split(df["text"], df["label"], test_size=0.2, stratify=df["label"], random_state=42)
vec = TfidfVectorizer(ngram_range=(1, 2), max_features=50_000, sublinear_tf=True, stop_words="english", min_df=2 if len(df) > 500 else 1)
A_tr, A_te = vec.fit_transform(X_tr), vec.transform(X_te)  # vectoriser fitted on TRAIN only (no leakage)

candidates = {
    "TF-IDF + Logistic Regression": (LogisticRegression(max_iter=2000, class_weight="balanced"), {"C": [0.3, 1, 3, 10]}),
    "TF-IDF + Naive Bayes": (MultinomialNB(), {"alpha": [0.05, 0.1, 0.5, 1.0]}),
    "TF-IDF + Random Forest": (RandomForestClassifier(random_state=42, n_jobs=-1, class_weight="balanced"), {"n_estimators": [200, 400], "max_depth": [None, 30]}),
}
print("Hyper-parameter tuning (3-fold CV, scoring=F1) and test-set evaluation:")
results, best = [], None
for name, (est, grid) in candidates.items():
    gs = GridSearchCV(est, grid, cv=3, scoring="f1", n_jobs=-1).fit(A_tr, y_tr)
    m = evaluate(f"Email: {name}", y_te, gs.best_estimator_.predict_proba(A_te)[:, 1], path.name, demo)
    m["best_params"] = gs.best_params_
    results.append(m)
    if best is None or (m["f1_score"], m["roc_auc"]) > (best[1]["f1_score"], best[1]["roc_auc"]):
        best = (gs.best_estimator_, m, name)

# Probability calibration (sigmoid / Platt) so model outputs behave like probabilities
final = CalibratedClassifierCV(best[0], method="sigmoid", cv=3).fit(A_tr, y_tr)
print("\nDeployed model (best by F1, probability-calibrated):")
results.append(evaluate(f"Email: DEPLOYED ({best[2]}, calibrated)", y_te, final.predict_proba(A_te)[:, 1], path.name, demo))

MODELS.mkdir(exist_ok=True)
joblib.dump(final, MODELS / "email_model.pkl")
joblib.dump(vec, MODELS / "vectorizer.pkl")
save_metrics("Email:", results)
print(f"\nSaved models to {MODELS}")
if demo:
    print("REMINDER: trained on SYNTHETIC demo data; do not trust these models. Train on real data.")
