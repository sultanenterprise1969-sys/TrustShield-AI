"""Login threat analysis on SYNTHETIC / demo security logs (not connected to any real accounts).

Two parts, both explained in the output:
  1. Documented rules  -> each gives a reason + weight (fed into the shared risk scorer).
  2. IsolationForest   -> an unsupervised anomaly model that adds a small extra weight to
                          events that look statistically unusual compared with the rest of the file.
"""
import io

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

import config
from services.risk_scoring import Indicator, assess

REQUIRED = ["timestamp", "user_id", "failed_attempts", "country", "device_type", "ip_address", "login_success"]
BASELINE_MIN = 3       # successful past logins needed before we trust a user's "normal"
BURST_WINDOW = pd.Timedelta(minutes=10)

RESPONSES = {
    "High Risk": "Lock or force a password reset, require multi-factor authentication and review the session; contact the user via a known-good channel.",
    "Suspicious": "Ask the user to confirm the login, require extra verification and keep monitoring.",
    "Low Risk": "No action needed.",
}


def load_login_csv(source) -> pd.DataFrame:
    """source: path, bytes or file-like. Raises ValueError with a friendly message."""
    try:
        if isinstance(source, (bytes, bytearray)):
            source = io.BytesIO(source)
        df = pd.read_csv(source, nrows=config.MAX_LOGIN_ROWS + 1)
    except Exception as e:
        raise ValueError(f"Could not read the CSV ({type(e).__name__}).")
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
    if len(df) > config.MAX_LOGIN_ROWS:
        raise ValueError(f"CSV has more than {config.MAX_LOGIN_ROWS} rows; please upload a smaller sample.")
    if df.empty:
        raise ValueError("The CSV has no rows.")
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["failed_attempts"] = pd.to_numeric(df["failed_attempts"], errors="coerce")
    df["login_success"] = pd.to_numeric(df["login_success"], errors="coerce")
    df = df.dropna(subset=["timestamp", "failed_attempts", "login_success", "user_id"])
    if df.empty:
        raise ValueError("No valid rows after checking timestamps and numbers.")
    if "hour_of_day" not in df.columns:
        df["hour_of_day"] = df["timestamp"].dt.hour
    df["hour_of_day"] = pd.to_numeric(df["hour_of_day"], errors="coerce").fillna(df["timestamp"].dt.hour).astype(int)
    return df.sort_values("timestamp").reset_index(drop=True)


def analyze_logins(df: pd.DataFrame) -> pd.DataFrame:
    seen_ok = {}      # user -> {"countries": set, "devices": set, "n": int}
    recent = {}       # user -> list of timestamps
    rows, feats = [], []
    for r in df.itertuples(index=False):
        ind = []
        base = seen_ok.setdefault(r.user_id, {"countries": set(), "devices": set(), "n": 0})
        has_base = base["n"] >= BASELINE_MIN

        if r.failed_attempts >= 5:
            ind.append(Indicator("many_failures", "Many failed attempts", 35, "5 or more failed attempts.", [f"{int(r.failed_attempts)} failures"]))
        elif r.failed_attempts >= 3:
            ind.append(Indicator("many_failures", "Repeated failed attempts", 20, "3 or more failed attempts.", [f"{int(r.failed_attempts)} failures"]))
        if r.hour_of_day < 5:
            ind.append(Indicator("odd_hour", "Login at an unusual hour", 15, "Between 00:00 and 04:59.", [f"hour {int(r.hour_of_day)}"]))
        new_country = has_base and r.country not in base["countries"]
        new_device = has_base and r.device_type not in base["devices"]
        if new_country:
            ind.append(Indicator("new_country", "Country not seen before for this user", 25, "Differs from the user's baseline.", [str(r.country)]))
        if new_device:
            ind.append(Indicator("new_device", "Device type not seen before for this user", 10, "Differs from the user's baseline.", [str(r.device_type)]))
        times = [t for t in recent.get(r.user_id, []) if r.timestamp - t <= BURST_WINDOW] + [r.timestamp]
        recent[r.user_id] = times
        burst = len(times)
        if burst >= 4:
            ind.append(Indicator("burst", "Several attempts within 10 minutes", 20, "4 or more events for one user in 10 minutes.", [f"{burst} events"]))
        if r.login_success == 1 and r.failed_attempts >= 3:
            ind.append(Indicator("success_after_failures", "Success after many failures", 20, "Possible password-guessing success.", []))

        if r.login_success == 1:
            base["countries"].add(r.country); base["devices"].add(r.device_type); base["n"] += 1
        feats.append([r.failed_attempts, r.hour_of_day, r.login_success, int(new_country), int(new_device), burst])
        rows.append((r, ind))

    # unsupervised anomaly model (needs enough rows to be meaningful)
    flags = np.zeros(len(rows), dtype=bool)
    if len(rows) >= 50:
        iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        flags = iso.fit_predict(np.array(feats, dtype=float)) == -1

    out = []
    for (r, ind), flagged in zip(rows, flags):
        if flagged:
            ind.append(Indicator("anomaly_model", "IsolationForest flags this event as statistically unusual", 10,
                                 "Compared with the other events in this file only.", []))
        res = assess(ind, limitations=["Demo/synthetic data; not connected to real accounts."])
        out.append({
            "timestamp": r.timestamp, "user_id": r.user_id, "ip_address": getattr(r, "ip_address", ""),
            "country": r.country, "device_type": r.device_type, "failed_attempts": int(r.failed_attempts),
            "login_success": int(r.login_success), "risk_score": res["risk_score"], "risk_category": res["risk_category"],
            "reason": "; ".join(i["label"] for i in res["indicators"] if i["weight"] > 0) or "No suspicious pattern",
            "recommended_response": RESPONSES[res["risk_category"]],
        })
    return pd.DataFrame(out)
