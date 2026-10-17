"""Link scanner. Analyses the URL TEXT only: never visits it, never follows redirects."""
import re
from urllib.parse import unquote

from scanners.knowledge import (BRANDS, REDIRECT_PARAMS, SHORTENERS, SUSPICIOUS_TLDS, WELL_KNOWN_DOMAINS,
                                count_keywords, deleet, levenshtein)
from scanners.url_parts import parse_url
from services.risk_scoring import Indicator, assess

POSITIVE_BLOCKERS = {"brand_in_host", "lookalike_domain", "at_symbol", "idn_homograph", "ip_host"}


def scan_url(raw, use_model=True, check_reputation=False) -> dict:
    p = parse_url(raw)
    if not p["ok"]:
        return {"ok": False, "scan_type": "url", "error": p["error"]}

    ind = []
    host, reg, full = p["host"], p["registered_domain"], p["normalized"]
    no_domain = p["is_ip"] or p["is_obfuscated_ip"]

    if p["scheme"] == "https":
        ind.append(Indicator("https", "Uses HTTPS", -3,
                             "Encrypted connection. This is only a weak signal: scam sites can use HTTPS too."))
    elif not p["scheme_assumed"]:
        ind.append(Indicator("no_https", "Uses HTTP instead of HTTPS", 8,
                             "The connection is not encrypted. HTTP alone does not prove fraud.", ["http://"]))

    if no_domain:
        ind.append(Indicator("ip_host", "Uses an IP address instead of a domain name", 25,
                             "Legitimate services rarely ask you to log in at a raw IP address.", [host]))

    if p["punycode"] or p["non_ascii"]:
        ind.append(Indicator("idn_homograph", "Internationalised / punycode domain name",
                             25 if p["mixed_script"] else 15,
                             "Look-alike characters from other alphabets can imitate real brands."
                             + (" Mixed alphabets were found." if p["mixed_script"] else ""),
                             [f"{host} (displays as {p['unicode_host']})"]))

    if p["has_userinfo"]:
        ind.append(Indicator("at_symbol", "Contains '@' before the hostname", 20,
                             "Text before '@' is ignored by browsers, so the real destination is what follows it.", ["@"]))

    if p["port"] not in (None, 80, 443):
        ind.append(Indicator("odd_port", "Uses a non-standard port", 6, "Unusual for ordinary websites.", [f":{p['port']}"]))

    n = len(full)
    if n > 150:
        ind.append(Indicator("long_url", "Unusually long URL", 12, "Very long URLs can hide the real destination.", [f"{n} characters"]))
    elif n > 75:
        ind.append(Indicator("long_url", "Long URL", 6, "Long URLs can hide the real destination.", [f"{n} characters"]))

    if len(re.findall(r"%[0-9a-fA-F]{2}", full)) >= 5 or "%25" in full:
        ind.append(Indicator("encoding", "Heavy or double URL encoding", 8, "Encoding can disguise what a link really contains."))

    for k, v in p["query_params"]:
        if k.lower() in REDIRECT_PARAMS and re.match(r"(?i)^(https?://|//)", unquote(v)):
            ind.append(Indicator("redirect_param", "Redirect parameter pointing to another address", 12,
                                 "The link may bounce you to a different site. Redirects were NOT followed.", [f"{k}={v[:60]}"]))
            break

    hits = count_keywords(host + p["path"] + p["query"])
    if hits:
        ind.append(Indicator("keywords", "Sensitive keywords in the link", min(12, 4 * len(hits)),
                             "Words like login/verify/secure are common in phishing links but also on real sites.", hits))

    if not no_domain:
        if reg in SHORTENERS:
            ind.append(Indicator("shortener", "URL shortener", 15,
                                 "The real destination is hidden. It was not resolved (redirects are not followed).", [reg]))
        if len(p["subdomain_labels"]) >= 3:
            ind.append(Indicator("many_subdomains", "Many subdomains", 10 if len(p["subdomain_labels"]) >= 4 else 5,
                                 "Attackers stack subdomains so a trusted name appears at the start.", [host]))
        if host.replace("xn--", "").count("-") >= 3:
            ind.append(Indicator("hyphens", "Many hyphens in the hostname", 8, "Common in made-up look-alike domains.", [host]))
        if p["suffix"].split(".")[-1] in SUSPICIOUS_TLDS:
            ind.append(Indicator("odd_tld", "Domain ending often abused by scammers", 8,
                                 "Many legitimate sites use it too; treat as a weak signal.", [f".{p['suffix'].split('.')[-1]}"]))

        tokens = re.split(r"[.\-_]", host)
        for brand, legit in BRANDS.items():
            b = brand.replace(" ", "")
            hit = (b in tokens) or (len(b) >= 6 and any(b in t for t in tokens))
            if hit and reg not in legit:
                ind.append(Indicator("brand_in_host", "Brand name appears in a domain it does not own", 25,
                                     "The real owner of this domain is not the brand named in it.",
                                     [f"'{brand}' in {host} (registered domain: {reg})"]))
                break
        label = p["domain_label"]
        for brand, legit in BRANDS.items():
            b = brand.replace(" ", "")
            if len(b) >= 6 and reg not in legit and label != b and (deleet(label) == b or levenshtein(label, b) == 1):
                ind.append(Indicator("lookalike_domain", "Domain looks like a misspelling of a known brand", 25,
                                     "One-character differences are a classic typosquatting trick.", [f"{label} ~ {b}"]))
                break

    # --- predictive AI component (optional) ---
    model_info = {"available": False, "reason": "disabled"}
    if use_model:
        from ai.predictor import predict_url  # lazy import keeps the scanner usable without sklearn
        model_info = predict_url(full)
        if model_info.get("available") and model_info["label"] == 1:
            ind.append(Indicator("ml_model", "ML model rates the URL structure as suspicious-looking",
                                 round(model_info["score"] * 20),
                                 "Contribution is capped at 20 points because the score is uncalibrated"
                                 + (" and the model was trained on synthetic data." if model_info.get("trained_on_synthetic") else "."),
                                 [f"model score {model_info['score']}"]))

    if (reg in WELL_KNOWN_DOMAINS and not no_domain and not (POSITIVE_BLOCKERS & {i.id for i in ind})):
        ind.append(Indicator("well_known", "Domain is on a small built-in list of well-known sites", -10,
                             "Only means the domain name matches; it cannot prove this exact page is genuine.", [reg]))

    # --- optional reputation lookup ---
    rep = {"checked": False, "matched": None, "reason": "not requested"}
    limits = ["Page content was not fetched and redirects were not followed."]
    if check_reputation:
        from services.threat_intel import check_url
        rep = check_url(full)
        if rep["checked"] and rep["matched"]:
            ind.append(Indicator("reputation_match", f"Listed by {rep['provider']}", 60,
                                 "An external reputation service lists this URL as unsafe.", [rep["provider"]]))
        elif rep["checked"]:
            limits.append(f"{rep['provider']} did not list this URL at the time of the check. That does not guarantee safety.")
        else:
            limits.append(f"Reputation check requested but unavailable ({rep.get('reason')}). Result is local analysis only.")
    if not rep["checked"]:
        limits.append("Result is based on LOCAL analysis only, not a live global blacklist.")
    if p["scheme_assumed"]:
        limits.append("No http/https was typed, so http:// was assumed for parsing only.")
    if model_info.get("available") and model_info.get("trained_on_synthetic"):
        limits.append("The ML model was trained on synthetic demo data, so its judgement is limited.")
    elif use_model and not model_info.get("available"):
        limits.append("ML model unavailable; heuristic rules only. " + model_info.get("reason", ""))

    positives = [i for i in ind if i.weight > 0]
    result = assess(ind, sufficient=bool(positives),
                    insufficient_reason="No suspicious signs were found in the link's text, but the page itself was not examined, "
                                        "so this says little about whether it is safe.",
                    limitations=limits)
    top = ", ".join([i["label"] for i in result["indicators"] if i["weight"] > 0][:2]) or "no indicators"
    result.update({
        "ok": True, "scan_type": "url", "submitted_url": p["original"],
        "parsed": {k: p[k] for k in ("scheme", "host", "registered_domain", "suffix", "subdomain_labels", "port", "unicode_host")},
        "model": model_info, "reputation": rep, "summary": f"{p['host']}: {top}",
    })
    return result
