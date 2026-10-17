"""Train and evaluate the URL classifier (scikit-learn).

Run from the project root:
    python data/generate_synthetic_data.py      # only needed once
    python -m ai.model_training                  # trains, evaluates, saves model + metrics

Honest-evaluation rules built in:
  * Stratified train/test split with a fixed seed (random_state=42).
  * The model is fitted on the TRAINING part only; all reported metrics use the held-out TEST part.
  * Duplicate URLs are removed first so no identical URL appears on both sides.
  * Results are written to models/metrics.json and shown in the app exactly as measured.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import config
from ai.features import FEATURE_NAMES, extract_features

SEED = 42


def load_dataset(csv_path):
    df = pd.read_csv(csv_path)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Training CSV needs the columns: url,label")
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)
    feats = [extract_features(u) for u in df["url"]]
    keep = [i for i, f in enumerate(feats) if f is not None]
    skipped = len(df) - len(keep)
    X = np.array([feats[i] for i in keep], dtype=float)
    y = df["label"].to_numpy()[keep]
    return X, y, skipped


def train(csv_path=None, model_path=None, metrics_path=None, synthetic=True):
    csv_path = csv_path or config.TRAINING_CSV
    model_path = model_path or config.MODEL_PATH
    metrics_path = metrics_path or config.METRICS_PATH

    X, y, skipped = load_dataset(csv_path)
    if len(set(y)) < 2 or len(y) < 50:
        raise ValueError("Need at least 50 usable rows with both classes (0 and 1) to train.")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)

    pipe = Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)),
    ])
    pipe.fit(X_tr, y_tr)  # training data only

    pred = pipe.predict(X_te)  # held-out data only
    p, r, f1, _ = precision_recall_fscore_support(y_te, pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_te, pred, labels=[0, 1])
    coefs = dict(zip(FEATURE_NAMES, pipe.named_steps["clf"].coef_[0].round(3).tolist()))

    metrics = {
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_file": str(csv_path).split("/")[-1],
        "dataset_sha256": hashlib.sha256(Path(csv_path).read_bytes()).hexdigest()[:16],
        "dataset_is_synthetic": bool(synthetic),
        "rows_used": int(len(y)), "rows_skipped_unparseable": int(skipped),
        "class_distribution": {"benign_0": int((y == 0).sum()), "suspicious_1": int((y == 1).sum())},
        "split": {"train": int(len(y_tr)), "test": int(len(y_te)), "test_size": 0.2, "random_state": SEED},
        "model": "StandardScaler + LogisticRegression(class_weight=balanced)",
        "precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f1), 4),
        "confusion_matrix": {"labels": ["benign(0)", "suspicious(1)"], "matrix": cm.tolist()},
        "feature_coefficients": coefs,
        "sklearn_version": sklearn.__version__,
        "python_version": sys.version.split()[0],
        "note": ("Metrics are measured on a held-out test split of SYNTHETIC template data. They show the "
                 "pipeline works; they do NOT predict real-world accuracy." if synthetic else
                 "Metrics measured on a held-out test split of the supplied dataset."),
    }
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipe, "feature_names": FEATURE_NAMES, "meta": metrics}, model_path)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    return metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=None, help="CSV with columns url,label (default: synthetic demo data)")
    ap.add_argument("--real-data", action="store_true", help="Mark the dataset as NOT synthetic in the metrics")
    a = ap.parse_args()
    m = train(csv_path=a.data, synthetic=not a.real_data)
    print(json.dumps({k: m[k] for k in ("dataset_file", "class_distribution", "split", "precision",
                                         "recall", "f1", "confusion_matrix", "note")}, indent=2))
    print(f"\nSaved model -> {config.MODEL_PATH}\nSaved metrics -> {config.METRICS_PATH}")
