"""Generate the SYNTHETIC demo datasets used by TrustShield AI.

IMPORTANT: Every row is produced by templates in this script (fixed random seed 42).
The labels describe how the row was *constructed*, not verified real-world threat intelligence.
Metrics measured on this data show that the pipeline works; they are NOT real-world accuracy.

Run from the project root:  python data/generate_synthetic_data.py
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
rng = random.Random(42)

WORDS = ["news", "recipe", "travel", "garden", "python", "science", "music", "health", "sport",
         "review", "guide", "history", "market", "design", "photo", "career", "study", "budget"]
BENIGN_DOMAINS = ["wikipedia.org", "github.com", "bbc.co.uk", "nytimes.com", "python.org", "mozilla.org",
                  "stackoverflow.com", "ibm.com", "medium.com", "readthedocs.io", "khanacademy.org",
                  "coursera.org", "weather.com", "imdb.com", "etsy.com", "ebay.com", "bandcamp.com",
                  "accounts.google.com", "login.microsoftonline.com", "www.paypal.com", "www.amazon.com"]
BRANDS = ["paypal", "amazon", "microsoft", "apple", "netflix", "google", "facebook", "dhl", "maybank", "hsbc"]
BAD_TLDS = ["xyz", "top", "click", "tk", "icu", "buzz", "work", "support", "com", "net", "info"]
KEYS = ["login", "verify", "secure", "update", "account", "confirm", "signin", "billing", "recover"]
SHORT = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd"]


def rs(n, chars="abcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(rng.choice(chars) for _ in range(n))


def benign():
    d = rng.choice(BENIGN_DOMAINS)
    scheme = "https" if rng.random() < 0.93 else "http"
    kind = rng.random()
    if kind < 0.25:
        path = "/"
    elif kind < 0.55:
        path = "/" + "/".join(rng.choice(WORDS) for _ in range(rng.randint(1, 3)))
    elif kind < 0.75:
        path = f"/{rng.choice(WORDS)}/{rng.randint(2015, 2025)}/{'-'.join(rng.sample(WORDS, rng.randint(3, 6)))}"
    elif kind < 0.9:
        path = f"/search?q={rng.choice(WORDS)}&page={rng.randint(1, 30)}&utm_source={rng.choice(WORDS)}"
    else:  # noisy benign: login pages on real sites, long tracking ids
        path = rng.choice(["/signin", "/login?continue=%2Fhome", "/account/settings", f"/p/{rs(24)}?ref={rs(10)}"])
    return f"{scheme}://{d}{path}"


def suspicious():
    kind = rng.random()
    k1, k2 = rng.sample(KEYS, 2)
    brand = rng.choice(BRANDS)
    tld = rng.choice(BAD_TLDS)
    if kind < 0.15:  # IP host
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{k1}/{rs(8)}.php?id={rng.randint(1000, 99999)}"
    if kind < 0.35:  # brand in subdomain of random domain
        return f"http://{brand}.{k1}-{rs(6)}.{tld}/{k2}"
    if kind < 0.5:  # hyphenated brand lookalike
        return f"https://{brand}-{k1}-{k2}.{tld}/{rs(10)}"
    if kind < 0.6:  # shortener
        return f"https://{rng.choice(SHORT)}/{rs(7, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}"
    if kind < 0.7:  # @ trick / redirect param
        return f"http://{rng.choice(BENIGN_DOMAINS)}@{rs(8)}.{tld}/{k1}"
    if kind < 0.8:  # many subdomains + long path
        subs = ".".join(rng.choice(KEYS + BRANDS) for _ in range(4))
        return f"http://{subs}.{rs(7)}.{tld}/{k1}/{rs(30)}"
    if kind < 0.85:  # punycode
        return f"http://xn--{rs(8, 'abcdefghijklmnopqrstuvwxyz')}-{rs(3)}.{tld}/{k1}"
    # noisy: clean-looking short https URL (hard to tell from benign by structure)
    return f"https://{rs(rng.randint(6, 10), 'abcdefghijklmnopqrstuvwxyz')}.{rng.choice(['com', 'net', 'online'])}/{rng.choice([k1, 'offer', 'claim', 'pay'])}"


def write_urls(n_benign=1500, n_susp=900):
    rows, seen = [], set()
    for label, fn, n in ((0, benign, n_benign), (1, suspicious, n_susp)):
        count = 0
        while count < n:
            u = fn()
            if u in seen:  # de-duplicate so train and test never share identical URLs
                continue
            seen.add(u)
            rows.append((u, label))
            count += 1
    rng.shuffle(rows)
    with open(HERE / "urls_synthetic.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"urls_synthetic.csv: {len(rows)} rows (label 1 = constructed to look suspicious)")


def write_logins():
    users = {
        "U001": ("Malaysia", "desktop", "192.0.2.10"), "U002": ("Malaysia", "mobile", "192.0.2.11"),
        "U003": ("Singapore", "desktop", "198.51.100.7"), "U004": ("Malaysia", "mobile", "192.0.2.44"),
        "U005": ("Malaysia", "tablet", "198.51.100.23"), "U006": ("Indonesia", "desktop", "203.0.113.5"),
    }
    start = datetime(2026, 9, 1, 8, 0)
    rows = []
    for day in range(30):
        for uid, (country, device, ip) in users.items():
            for _ in range(rng.randint(1, 3)):
                ts = start + timedelta(days=day, hours=rng.randint(0, 13), minutes=rng.randint(0, 59))
                failed = 0 if rng.random() < 0.85 else 1
                rows.append((ts, uid, failed, country, device, ip, 1))
    # --- injected suspicious patterns (synthetic) ---
    t = datetime(2026, 9, 28, 3, 12)  # U003: burst of failures from a new country at 3am
    for i in range(6):
        rows.append((t + timedelta(minutes=i), "U003", rng.randint(4, 8), "Russia", "mobile", "203.0.113.99", 0))
    rows.append((t + timedelta(minutes=7), "U003", 5, "Russia", "mobile", "203.0.113.99", 1))
    t2 = datetime(2026, 9, 29, 2, 40)  # U005: success after failures, new country + device
    rows.append((t2, "U005", 4, "Brazil", "linux-bot", "198.51.100.200", 0))
    rows.append((t2 + timedelta(minutes=2), "U005", 3, "Brazil", "linux-bot", "198.51.100.200", 1))
    t3 = datetime(2026, 9, 30, 4, 5)  # credential stuffing: one IP, several users
    for i, uid in enumerate(users):
        rows.append((t3 + timedelta(minutes=i), uid, 3, "Netherlands", "script", "203.0.113.250", 0))
    rows.sort(key=lambda r: r[0])
    with open(HERE / "login_events_sample.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "user_id", "failed_attempts", "country", "device_type", "ip_address",
                    "login_success", "hour_of_day"])
        for ts, uid, failed, country, device, ip, ok in rows:
            w.writerow([ts.isoformat(sep=" "), uid, failed, country, device, ip, ok, ts.hour])
    print(f"login_events_sample.csv: {len(rows)} rows (synthetic; IPs from documentation ranges)")


if __name__ == "__main__":
    write_urls()
    write_logins()
