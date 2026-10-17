"""Scan history in SQLite. Stores ONLY: id, time, type, category, score, short summary.

Message bodies, OCR text, uploaded images and full URLs are never stored. All SQL is parameterised.
"""
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

import config

SCHEMA = """CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    risk_category TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    summary TEXT NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 0)"""


def _conn(db_path=None):
    path = db_path or config.DB_PATH
    path_parent = getattr(path, "parent", None)
    if path_parent is not None:
        path_parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(path))
    c.execute(SCHEMA)
    return c


def add_scan(scan_type, risk_category, risk_score, summary, is_demo=False, db_path=None):
    summary = (summary or "")[:200]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with closing(_conn(db_path)) as c, c:
        cur = c.execute("INSERT INTO scans (created_at, scan_type, risk_category, risk_score, summary, is_demo) VALUES (?,?,?,?,?,?)",
                        (now, scan_type, risk_category, int(risk_score), summary, int(is_demo)))
        return cur.lastrowid


def list_scans(limit=100, db_path=None):
    limit = max(1, min(int(limit), 1000))
    with closing(_conn(db_path)) as c:
        cur = c.execute("SELECT id, created_at, scan_type, risk_category, risk_score, summary, is_demo FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def stats(db_path=None):
    with closing(_conn(db_path)) as c:
        total = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_cat = dict(c.execute("SELECT risk_category, COUNT(*) FROM scans GROUP BY risk_category").fetchall())
        by_type = dict(c.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type").fetchall())
        demo = c.execute("SELECT COUNT(*) FROM scans WHERE is_demo=1").fetchone()[0]
    return {"total": total, "high_risk": by_cat.get("High Risk", 0), "suspicious": by_cat.get("Suspicious", 0),
            "low_risk": by_cat.get("Low Risk", 0), "by_category": by_cat, "by_type": by_type, "demo_rows": demo}


def delete_all(db_path=None):
    with closing(_conn(db_path)) as c, c:
        return c.execute("DELETE FROM scans").rowcount


DEMO_ROWS = [("url", "High Risk", 73, "paypal.secure-login.xyz: brand in domain"), ("url", "Low Risk", 8, "example.org: HTTP"),
             ("message", "High Risk", 100, "1 link(s); credential request"), ("message", "Suspicious", 41, "0 link(s); urgency"),
             ("message", "Low Risk", 0, "0 link(s); no indicators"), ("image", "High Risk", 68, "OCR text: prize, gift card"),
             ("image", "Suspicious", 35, "OCR text: org claim, urgency"), ("url", "Suspicious", 43, "bit.ly: URL shortener"),
             ("login", "High Risk", 100, "15 flagged of 377 events"), ("url", "Low Risk", 0, "wikipedia.org: no indicators")]


def load_demo(db_path=None):
    for t, cat, score, summ in DEMO_ROWS:
        add_scan(t, cat, score, "[DEMO] " + summ, is_demo=True, db_path=db_path)
    return len(DEMO_ROWS)
