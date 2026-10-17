"""Turn a URL string into numbers for the machine-learning model.

Only the URL text is used. No network access, no page content.
"""
import re

from scanners.knowledge import SHORTENERS, SUSPICIOUS_TLDS, count_keywords
from scanners.url_parts import parse_url, shannon_entropy

FEATURE_NAMES = [
    "url_length", "host_length", "num_dots", "num_subdomains", "num_hyphens_host", "num_digits_host",
    "digit_ratio_url", "has_ip", "is_https", "num_query_params", "num_percent_encodings",
    "has_at_symbol", "path_length", "path_depth", "keyword_count", "has_punycode_or_idn",
    "is_shortener", "suspicious_tld", "num_special_chars", "host_entropy", "nonstandard_port",
]


def extract_features(url):
    """Return a list of floats in FEATURE_NAMES order, or None if the URL is unusable."""
    p = parse_url(url)
    if not p["ok"]:
        return None
    full, host, path = p["normalized"], p["host"], p["path"]
    digits_url = sum(c.isdigit() for c in full)
    return [
        float(len(full)),
        float(len(host)),
        float(host.count(".")),
        float(len(p["subdomain_labels"])),
        float(host.count("-")),
        float(sum(c.isdigit() for c in host)),
        digits_url / max(1, len(full)),
        float(p["is_ip"] or p["is_obfuscated_ip"]),
        float(p["scheme"] == "https"),
        float(len(p["query_params"])),
        float(len(re.findall(r"%[0-9a-fA-F]{2}", full))),
        float(p["has_userinfo"]),
        float(len(path)),
        float(path.strip("/").count("/") + (1 if path.strip("/") else 0)),
        float(len(count_keywords(host + path + p["query"]))),
        float(p["punycode"] or p["non_ascii"]),
        float(p["registered_domain"] in SHORTENERS),
        float(p["suffix"].split(".")[-1] in SUSPICIOUS_TLDS),
        float(sum(full.count(c) for c in "!#$%^&*()+=[]{};',<>~|\\")),
        shannon_entropy(host),
        float(p["port"] not in (None, 80, 443)),
    ]
