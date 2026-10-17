"""Safe URL parsing. Pure string work: nothing here ever opens a network connection."""
import ipaddress
import math
import re
import unicodedata
from urllib.parse import parse_qsl, urlsplit

from config import MAX_URL_CHARS

# Tiny public-suffix substitute (no extra dependency). Documented limitation.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au", "co.nz",
    "co.in", "co.jp", "co.kr", "co.za", "com.br", "com.cn", "com.hk", "com.mx", "com.sg",
    "com.tr", "com.my", "edu.my", "gov.my", "org.my", "net.my", "com.ph", "co.id", "ac.id",
    "com.vn", "co.th", "com.pk", "com.ng",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def split_domain(host: str):
    """Return (subdomain_labels, domain_label, suffix, registered_domain)."""
    labels = host.split(".")
    if len(labels) == 1:
        return [], host, "", host
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        suffix, domain_label, sub = ".".join(labels[-2:]), labels[-3], labels[:-3]
    else:
        suffix, domain_label, sub = labels[-1], labels[-2], labels[:-2]
    return sub, domain_label, suffix, f"{domain_label}.{suffix}"


def _err(msg: str) -> dict:
    return {"ok": False, "error": msg}


def _scripts(text: str) -> set:
    out = set()
    for ch in text:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def parse_url(raw) -> dict:
    """Parse a user-supplied URL. Returns {'ok': False, 'error': ...} for unusable input."""
    if not isinstance(raw, str) or not raw.strip():
        return _err("Please enter a link to analyse.")
    text = raw.strip()
    if len(text) > MAX_URL_CHARS:
        return _err(f"The link is longer than {MAX_URL_CHARS} characters, which is not supported.")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in text):
        return _err("The link contains spaces or control characters. Paste only the link itself.")

    assumed = False
    if "://" in text:
        scheme = text.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return _err("Only http:// and https:// links can be analysed.")
        full = text
    elif re.match(r"^(javascript|data|file|vbscript|mailto|tel|ftp|blob|sms):", text, re.I):
        return _err("Only http:// and https:// links can be analysed.")
    else:
        scheme, full, assumed = "http", "http://" + text, True

    try:
        parts = urlsplit(full)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return _err("The link could not be parsed. Check that it is a valid web address.")
    if not host:
        return _err("No hostname was found in the link.")
    host = host.lower().rstrip(".")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    obfuscated_ip = bool(re.fullmatch(r"\d+|0x[0-9a-f]+", host))
    non_ascii = any(ord(c) > 127 for c in host)

    if not (is_ip or obfuscated_ip):
        if "." not in host:
            return _err("That does not look like a web address (no domain extension such as .com).")
        if any(not l or len(l) > 63 for l in host.split(".")):
            return _err("The hostname is not valid.")
        if not non_ascii and not re.fullmatch(r"[a-z0-9._-]+", host):
            return _err("The hostname contains invalid characters.")

    labels = host.split(".")
    punycode = any(l.startswith("xn--") for l in labels)
    unicode_host = host
    if punycode:
        decoded = []
        for l in labels:
            try:
                decoded.append(l[4:].encode("ascii").decode("punycode") if l.startswith("xn--") else l)
            except Exception:
                decoded.append(l)
        unicode_host = ".".join(decoded)
    scripts = _scripts(unicode_host)
    mixed_script = "LATIN" in scripts and len(scripts) > 1

    if is_ip or obfuscated_ip:
        sub, dlabel, suffix, registered = [], host, "", host
    else:
        sub, dlabel, suffix, registered = split_domain(host)

    try:
        params = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        params = []

    return {
        "ok": True, "original": text, "normalized": full, "scheme": scheme, "scheme_assumed": assumed,
        "host": host, "port": port, "has_userinfo": "@" in parts.netloc,
        "is_ip": is_ip, "is_obfuscated_ip": obfuscated_ip, "non_ascii": non_ascii,
        "punycode": punycode, "unicode_host": unicode_host, "mixed_script": mixed_script,
        "labels": labels, "subdomain_labels": sub, "domain_label": dlabel, "suffix": suffix,
        "registered_domain": registered, "path": parts.path, "query": parts.query,
        "query_params": params,
    }
