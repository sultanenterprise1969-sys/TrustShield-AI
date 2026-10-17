"""Generative-AI explanation component (Component B of the hybrid design).

Input : the structured findings produced by the predictive component (scores + indicators).
Output: a plain-language explanation. It EXPLAINS the result; it never changes the score.

  * Default: a deterministic template (always works, no network, no key).
  * Optional: an OpenAI-compatible chat endpoint (LLM_ENABLED=true + LLM_API_URL + LLM_MODEL).
    Only labels/scores are sent (message snippets only if include_snippets=True). The UI asks consent first.
  * Any LLM problem -> automatic fallback to the template.
"""
import json
import re
import urllib.request
from urllib.parse import urlparse

import config

AVOID = ["Do not click links, open attachments or scan QR codes in the message.",
         "Do not share passwords, PINs or one-time codes (OTPs).",
         "Do not send money, gift cards or crypto to someone who contacted you unexpectedly."]

OVERCLAIM = re.compile(r"\b(definitely|certainly|confirmed|guaranteed|100%)\b[^.]{0,40}\b(scam|fraud|phishing|malicious)\b", re.I)


def llm_available() -> bool:
    s = config.llm_settings()
    return bool(s["enabled"] and s["api_url"] and s["model"])


def template_explanation(result: dict) -> dict:
    inc = [i for i in result.get("indicators", []) if i["weight"] > 0]
    dec = [i for i in result.get("indicators", []) if i["weight"] < 0]
    cat, score = result["risk_category"], result["risk_score"]
    kind = {"url": "link", "message": "message", "image": "screenshot", "login": "login event"}.get(result.get("scan_type"), "item")

    if result.get("evidence_level") != "Sufficient":
        summary = (f"This {kind} scored {score}/100 ({cat}), but there is insufficient evidence to be confident. "
                   "A low score here does not mean it is safe.")
    elif cat == "High Risk":
        summary = f"This {kind} scored {score}/100 (High Risk): several warning signs were found. That is not proof of fraud, but caution is strongly advised."
    elif cat == "Suspicious":
        summary = f"This {kind} scored {score}/100 (Suspicious): some warning signs were found. Verify it independently before acting."
    else:
        summary = f"This {kind} scored {score}/100 (Low Risk): few warning signs were found. This does not guarantee it is safe."

    what = [f"{i['label']} \u2014 {i['detail']}" if i["detail"] else i["label"] for i in inc[:5]] or ["No specific warning signs were detected."]
    evidence = []
    for i in inc[:5]:
        for e in i["evidence"][:2]:
            evidence.append(f"{i['label']}: {e}")
    if dec:
        evidence.append("Factors that lowered the score: " + "; ".join(d["label"] for d in dec))

    model = result.get("model") or {}
    model_note = ""
    if model.get("available"):
        model_note = (f"The ML model gave the link structure a raw score of {model['score']} ({model['label_text']}). "
                      "It is an uncalibrated score from a model trained on synthetic data, so it is one clue among several.")
    elif result.get("scan_type") == "url":
        model_note = "The ML model was not available, so this result uses transparent rules only."

    return {"source": "template", "summary": summary, "what_looks_suspicious": what, "evidence": evidence,
            "avoid": AVOID, "safest_next_step": result["next_steps"][0] if result.get("next_steps") else "", "model_note": model_note}


def _safe_payload(result: dict, include_snippets: bool) -> dict:
    return {
        "scan_type": result.get("scan_type"), "risk_score": result["risk_score"], "risk_category": result["risk_category"],
        "evidence_level": result["evidence_level"], "limitations": result["limitations"][:4],
        "model": {k: (result.get("model") or {}).get(k) for k in ("available", "label_text", "score")},
        "external_reputation_checked": bool((result.get("reputation") or {}).get("checked")),
        "indicators": [{"label": i["label"], "weight": i["weight"], "detail": i["detail"],
                        **({"evidence": i["evidence"][:2]} if include_snippets else {})} for i in result["indicators"]],
    }


def _call_llm(payload: dict) -> str:
    s = config.llm_settings()
    u = urlparse(s["api_url"])
    if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError("LLM_API_URL must use https (or be localhost)")
    system = ("You explain scam-risk findings to non-experts in simple, calm language (max 150 words). "
              "Use ONLY the JSON provided. Do not invent evidence. Do not change or restate a different score. "
              "Never say something is confirmed fraud and never claim an external blacklist was checked unless "
              "external_reputation_checked is true. Cover: what looks suspicious, what to avoid, the safest next step.")
    body = {"model": s["model"], "temperature": 0.2, "max_tokens": 400,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": json.dumps(payload)}]}
    headers = {"Content-Type": "application/json"}
    if s["api_key"]:
        headers["Authorization"] = f"Bearer {s['api_key']}"
    req = urllib.request.Request(s["api_url"], data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:  # nosec - endpoint is operator-configured
        data = json.loads(resp.read().decode())
    return data["choices"][0]["message"]["content"].strip()


def explain(result: dict, use_llm: bool = False, include_snippets: bool = False) -> dict:
    """Always returns a usable explanation. `use_llm` must reflect the user's explicit consent."""
    exp = template_explanation(result)
    if use_llm and llm_available():
        try:
            text = _call_llm(_safe_payload(result, include_snippets))
            if text and not OVERCLAIM.search(text):
                exp["llm_text"], exp["source"] = text, "llm"
            else:
                exp["llm_note"] = "The LLM reply was rejected by safety checks; showing the standard explanation."
        except Exception as e:
            exp["llm_note"] = f"LLM unavailable ({type(e).__name__}); showing the standard explanation."
    return exp
