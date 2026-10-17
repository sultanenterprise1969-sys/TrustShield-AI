"""Load the saved model and score URLs. Never raises: problems become {'available': False, ...}.

NOTE: joblib files are pickles. Only load model files that YOU trained.
"""
import joblib

import config
from ai.features import FEATURE_NAMES, extract_features

_cache = {}


def reset_cache():
    _cache.clear()


def load_model(path=None):
    path = str(path or config.MODEL_PATH)
    if path in _cache:
        return _cache[path]
    try:
        bundle = joblib.load(path)
        if bundle.get("feature_names") != FEATURE_NAMES:
            raise ValueError("model was trained with different features; please retrain")
        _cache[path] = (bundle, None)
    except FileNotFoundError:
        _cache[path] = (None, "No trained model found. Run: python -m ai.model_training")
    except Exception as e:  # corrupted file, version mismatch, ...
        _cache[path] = (None, f"Model could not be loaded ({type(e).__name__}). Retrain with: python -m ai.model_training")
    return _cache[path]


def predict_url(url, path=None) -> dict:
    bundle, err = load_model(path)
    if bundle is None:
        return {"available": False, "reason": err}
    feats = extract_features(url)
    if feats is None:
        return {"available": False, "reason": "URL could not be converted into model features."}
    try:
        prob = float(bundle["pipeline"].predict_proba([feats])[0][1])
    except Exception as e:
        return {"available": False, "reason": f"Model prediction failed ({type(e).__name__})."}
    meta = bundle.get("meta", {})
    return {
        "available": True,
        "label": int(prob >= 0.5),
        "label_text": "suspicious-looking" if prob >= 0.5 else "benign-looking",
        "score": round(prob, 3),
        "score_note": "Raw, uncalibrated model score (not a probability of fraud).",
        "trained_on_synthetic": bool(meta.get("dataset_is_synthetic", True)),
        "test_f1": meta.get("f1"),
    }
