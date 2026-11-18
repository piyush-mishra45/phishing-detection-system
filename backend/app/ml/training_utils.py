import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[3]
DATASETS = ROOT / "datasets"
MODELS = ROOT / "models"
POS = {"1", "phishing", "phishing email", "phish", "bad", "malicious", "spam", "defacement", "malware", "true", "yes"}
NEG = {"0", "legitimate", "safe email", "safe", "good", "benign", "ham", "legit", "false", "no"}


def pick_dataset(real_name, sample_name):
    real, sample = DATASETS / real_name, DATASETS / sample_name
    if real.exists():
        return real, False
    if sample.exists():
        print("\n" + "!" * 78 + f"\n!  {real_name} not found -> using SYNTHETIC DEMO data ({sample_name}).\n"
              "!  Metrics below are NOT meaningful. See datasets/README.md for real datasets.\n" + "!" * 78 + "\n")
        return sample, True
    raise SystemExit(f"No dataset found. Put {real_name} in datasets/ (see datasets/README.md) or run scripts/make_sample_data.py")


def load_labeled(path, text_candidates):
    df = pd.read_csv(path, encoding="utf-8", encoding_errors="replace")
    cols = {c.lower().strip(): c for c in df.columns}
    tcol = next((cols[c] for c in text_candidates if c in cols), None)
    lcol = next((cols[c] for c in ("label", "email type", "type", "class", "status", "result") if c in cols), None)
    if not tcol or not lcol:
        raise SystemExit(f"{path.name}: need a text column {text_candidates} and a label column; found {list(df.columns)}")
    df = df[[tcol, lcol]].rename(columns={tcol: "text", lcol: "label"})
    n0 = len(df)
    df = df.dropna()                                     # missing values
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(POS | NEG)]
    df["label"] = df["label"].isin(POS).astype(int)      # 1 = phishing
    df = df[df["text"].str.len() > 0].drop_duplicates(subset="text")  # duplicates
    print(f"Loaded {n0} rows -> {len(df)} after cleaning (missing/unknown labels/duplicates removed); phishing share = {df['label'].mean():.1%}")
    if df["label"].nunique() < 2 or df["label"].value_counts().min() < 10:
        raise SystemExit("Need at least 10 examples of each class")
    return df.reset_index(drop=True)


def evaluate(name, y_true, proba, dataset, demo):
    pred = (proba >= 0.5).astype(int)
    cm = confusion_matrix(y_true, pred, labels=[0, 1]).tolist()
    m = {"model_name": name, "accuracy": float(accuracy_score(y_true, pred)), "precision": float(precision_score(y_true, pred, zero_division=0)),
         "recall": float(recall_score(y_true, pred, zero_division=0)), "f1_score": float(f1_score(y_true, pred, zero_division=0)),
         "roc_auc": float(roc_auc_score(y_true, proba)), "confusion_matrix": cm, "trained_at": datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0).isoformat(),
         "dataset": dataset, "is_demo_data": demo}
    print(f"  {name:<52} acc={m['accuracy']:.3f} prec={m['precision']:.3f} rec={m['recall']:.3f} f1={m['f1_score']:.3f} auc={m['roc_auc']:.3f}  cm={cm}")
    return m


def save_metrics(prefix, metrics):
    MODELS.mkdir(exist_ok=True)
    f = MODELS / "metrics.json"
    old = json.loads(f.read_text()) if f.exists() else []
    old = [m for m in old if not m["model_name"].startswith(prefix)]
    f.write_text(json.dumps(old + metrics, indent=2))
