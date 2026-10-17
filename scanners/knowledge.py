"""Small, editable lists used by the scanners. These are heuristics, NOT a threat-intelligence feed."""

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "lnkd.in",
}

# Often abused, but plenty of legitimate sites use them too -> low weight.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "loan", "icu", "buzz", "rest", "monster", "cyou",
}

URL_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "password", "wallet", "recover", "recovery",
    "suspend", "unlock", "payment", "invoice", "billing", "urgent", "authenticate",
)

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "redirecturl", "next", "return",
    "returnurl", "return_url", "goto", "dest", "destination", "continue", "target", "link",
}

# brand -> legitimate registered domains (small demo list)
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.com.au"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "goo.gl"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "wa.me"],
    "linkedin": ["linkedin.com", "lnkd.in"],
    "dropbox": ["dropbox.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "hsbc": ["hsbc.com", "hsbc.co.uk"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "citibank": ["citibank.com", "citi.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
}

WELL_KNOWN_DOMAINS = {d for ds in BRANDS.values() for d in ds} | {
    "wikipedia.org", "github.com", "stackoverflow.com", "python.org", "mozilla.org",
    "ibm.com", "anthropic.com", "bbc.co.uk", "nytimes.com",
}

FREE_MAIL = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "live.com", "aol.com", "proton.me", "icloud.com"}


def count_keywords(text: str) -> list:
    """Distinct suspicious keywords found in text (lower-cased match)."""
    t = (text or "").lower()
    return sorted({k for k in URL_KEYWORDS if k in t})


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def deleet(label: str) -> str:
    """paypa1 -> paypal, rnicrosoft -> microsoft (simple look-alike normalisation)."""
    return label.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")
