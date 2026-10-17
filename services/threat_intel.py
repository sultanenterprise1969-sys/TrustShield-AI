"""OPTIONAL external reputation check (disabled by default).

Uses Google Safe Browsing's Lookup API. Only the URL string is sent to the provider, and only when
THREAT_INTEL_ENABLED=true, an API key is set, AND the user ticks the consent box in the app.
The submitted URL itself is never visited by this server.  (Not tested against the live API in the
original build environment, which had no internet access.)
"""
import json
import urllib.request

import config

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def is_configured() -> bool:
    s = config.threat_intel_settings()
    return bool(s["enabled"] and s["api_key"])


def check_url(url: str, timeout: float = 8.0) -> dict:
    s = config.threat_intel_settings()
    if not (s["enabled"] and s["api_key"]):
        return {"checked": False, "matched": None, "provider": s["provider"], "reason": "not configured"}
    body = {
        "client": {"clientId": "trustshield-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
        },
    }
    try:
        req = urllib.request.Request(f"{ENDPOINT}?key={s['api_key']}", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed https endpoint
            data = json.loads(resp.read().decode())
        return {"checked": True, "matched": bool(data.get("matches")), "provider": s["provider"]}
    except Exception as e:  # never leak the key or the stack trace
        return {"checked": False, "matched": None, "provider": s["provider"], "reason": f"lookup failed ({type(e).__name__})"}
