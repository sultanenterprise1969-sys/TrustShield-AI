"""Email / SMS / WhatsApp text scanner.

Finds scam *indicators* with supporting snippets, extracts links and scans each one with the link
scanner. Indicators are evidence, not proof: real messages can also be urgent or contain links.
Nothing is sent to any third party by this module.
"""
import re

from scanners.knowledge import BRANDS, FREE_MAIL
from scanners.url_parts import split_domain
from scanners.url_scanner import scan_url
from services.risk_scoring import Indicator, assess
from utils.validation import validate_text

MAX_URLS = 10

URL_RE = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"'\])]+"""
    r"""|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at|tiny\.cc)/[^\s<>"'\])]+"""
)
EMAIL_RE = re.compile(r"[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

_CRED = r"(?:password|passcode|pin(?: number)?|otp|one[- ]time (?:pass(?:word|code)|code)|cvv|cvc|security code|verification code|login details|card number|banking (?:details|credentials)|internet banking)"
_ASK = r"(?:send|share|provide|enter|reply with|confirm|tell|give|submit|verify|reveal|type|read out|forward)"

# (id, label, weight, explanation, regex, needs_negation_check)
PATTERNS = [
    ("credential_request", "Asks for passwords, PINs, OTPs or banking credentials", 30,
     "Real organisations do not ask you to send these by message.",
     rf"\b{_ASK}\b[^.\n]{{0,40}}\b{_CRED}\b|\b{_CRED}\b[^.\n]{{0,30}}\b(?:required|needed|to (?:verify|confirm|unlock))\b", True),
    ("sensitive_info", "Asks for personal or financial details", 12,
     "Unexpected requests for ID or account details are a common scam step.",
     r"\b(?:social security|ssn|nric|passport (?:number|copy)|ic number|date of birth|mother'?s maiden|bank account (?:number|details)|routing number|iban|confirm your (?:identity|details|information)|update your (?:details|information|billing)|verify your (?:identity|account|information|details))\b", True),
    ("urgency", "Creates urgency or time pressure", 12,
     "Pressure to act fast stops you from checking. Legitimate messages can be urgent too.",
     r"\b(?:urgent(?:ly)?|immediately|right away|asap|within (?:\d+|24|48) (?:hours?|hrs?|minutes?|mins?)|act now|last (?:warning|chance|notice)|final (?:notice|warning)|expires? (?:today|soon|in)|limited time)\b", False),
    ("account_threat", "Threatens account suspension or legal consequences", 15,
     "Threats are used to scare people into acting without thinking.",
     r"\b(?:account (?:has been |will be |is )?(?:suspended|locked|blocked|closed|disabled|deactivated|terminated|limited|compromised)|(?:suspend|lock|block|close|disable|terminate)d? your account|unusual (?:activity|sign[- ]?in|login)|legal action|arrest|penalt(?:y|ies))\b", False),
    ("prize", "Unexpected prize or reward", 18,
     "Unsolicited winnings are a classic advance-fee / data-harvesting lure.",
     r"\b(?:you(?:'ve| have)? (?:won|been selected)|winner|congratulations|lottery|free (?:gift|iphone|money)|claim your|inheritance|unclaimed (?:funds|prize))\b", False),
    ("money_transfer", "Asks you to transfer money or change bank details", 20,
     "Requests to pay a personal account or to 'update' bank details are common payment scams.",
     r"\b(?:transfer|wire|send|deposit|pay)\b[^.\n]{0,40}\b(?:money|funds|payment|fee|amount|usd|dollars|rm ?\d+)\b|\bpersonal account\b|\bnew (?:bank )?account number\b|\bchang(?:ed|e) (?:my |our )?bank (?:details|account)\b", False),
    ("unusual_payment", "Unusual payment method (gift cards, crypto, transfer services)", 15,
     "Scammers favour payment methods that are hard to reverse.",
     r"\b(?:gift ?cards?|itunes card|google play card|bitcoin|btc|crypto(?:currency)?|usdt|western union|moneygram|cash ?app|zelle|wire transfer)\b", False),
    ("org_claim", "Claims to be a bank, government, university IT or delivery service", 10,
     "Impersonation of trusted organisations is common. This only notes the claim; it is not proof.",
     r"\b(?:your bank|bank (?:security|fraud) (?:team|department)|tax (?:authority|refund)|customs|police|immigration|university (?:it|helpdesk|help desk|admin\w*)|it ?help ?desk|parcel|package (?:delivery|could not)|delivery (?:attempt|fee)|courier)\b", False),
    ("click_pressure", "Pushes you to click a link", 6,
     "Links in unexpected messages are the main delivery route for phishing.",
     r"\b(?:click (?:here|the link|below)|tap (?:here|the link)|follow (?:the|this) link|log ?in (?:here|below|now))\b", False),
]
COMPILED = [(i, l, w, e, re.compile(rx, re.I), neg) for i, l, w, e, rx, neg in PATTERNS]
NEGATIONS = ("do not", "don't", "dont", "never", "will not ask", "won't ask", "not share", "no one")


def extract_urls(text: str) -> list:
    seen = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?)\"'")
        if u and u not in seen:
            seen.append(u)
    return seen


def _snippet(text, start, end, pad=35):
    s = " ".join(text[max(0, start - pad): end + pad].split())
    return ("\u2026" if start - pad > 0 else "") + s[:120] + ("\u2026" if end + pad < len(text) else "")


def _negated(text, start):
    before = text[max(0, start - 25): start].lower()
    return any(n in before for n in NEGATIONS)


def _brands_in(text):
    return [b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", text, re.I)]


def parse_sender(sender: str) -> dict:
    m = EMAIL_RE.search(sender or "")
    if not m:
        return {"email_domain": None, "registered_domain": None}
    dom = m.group(1).lower().rstrip(".")
    return {"email_domain": dom, "registered_domain": split_domain(dom)[3]}


def scan_message(body, sender="", subject="", use_model=True, scan_type="message") -> dict:
    text_body, err = validate_text(body, "Message")
    if err and not (subject or "").strip():
        return {"ok": False, "scan_type": scan_type, "error": err}
    text = f"{subject or ''}\n{text_body}".strip()
    if len(text) > 25_000:
        return {"ok": False, "scan_type": scan_type, "error": "Message plus subject is too long."}

    ind = []
    for pid, label, weight, explain, rx, neg in COMPILED:
        snippets = []
        for m in rx.finditer(text):
            if neg and _negated(text, m.start()):
                continue  # e.g. "never share your OTP" is a warning, not a request
            snippets.append(_snippet(text, m.start(), m.end()))
            if len(snippets) == 3:
                break
        if snippets:
            ind.append(Indicator(pid, label, weight, explain, snippets))

    # --- links: scanned locally, never visited ---
    urls = extract_urls(text)[:MAX_URLS]
    url_results = []
    for u in urls:
        r = scan_url(u, use_model=use_model)
        if r["ok"]:
            url_results.append({"url": u, "score": r["risk_score"], "category": r["risk_category"],
                                "host": r["parsed"]["host"], "registered_domain": r["parsed"]["registered_domain"],
                                "reasons": [i["label"] for i in r["indicators"] if i["weight"] > 0][:4]})
    worst = max(url_results, key=lambda r: r["score"], default=None)
    if worst and worst["score"] >= 30:
        ind.append(Indicator("suspicious_link", "Contains a link that looks suspicious", min(30, round(worst["score"] * 0.5)),
                             "One of the links scored as suspicious in the link scanner.",
                             [f"{worst['url'][:80]} (score {worst['score']}: {', '.join(worst['reasons']) or 'see link scan'})"]))

    # --- sender / brand consistency ---
    snd = parse_sender(sender)
    claimed = _brands_in(f"{sender or ''} {subject or ''} {text_body[:400]}")
    link_regs = {r["registered_domain"] for r in url_results}
    if claimed and snd["registered_domain"]:
        if not any(snd["registered_domain"] in BRANDS[b] for b in claimed):
            ind.append(Indicator("sender_brand_mismatch", "Sender address does not match the brand it mentions", 20,
                                 "The message mentions a known brand but was sent from a different domain.",
                                 [f"mentions {', '.join(claimed)}; sender domain is {snd['registered_domain']}"
                                  + (" (free email service)" if snd["registered_domain"] in FREE_MAIL else "")]))
    if claimed and link_regs and not any(r in BRANDS[b] for b in claimed for r in link_regs):
        ind.append(Indicator("brand_link_mismatch", "Mentions a known brand but links elsewhere", 20,
                             "None of the links belong to the brand named in the message.",
                             [f"mentions {', '.join(claimed)}; links go to {', '.join(sorted(link_regs))}"]))
    if snd["registered_domain"] and link_regs and snd["registered_domain"] not in link_regs:
        ind.append(Indicator("sender_link_mismatch", "Links point to a different domain than the sender's", 8,
                             "Common in scams, but mailing services also do this legitimately.",
                             [f"sender {snd['registered_domain']} vs links {', '.join(sorted(link_regs))}"]))

    words = len(text.split())
    short = words < 5
    limits = ["Indicators are evidence, not proof. Real messages can also be urgent, contain links or ask for action.",
              "Text analysis uses keyword/pattern rules in English only; links are analysed locally and never visited.",
              "Nothing you pasted was sent to any third party."]
    result = assess(ind, sufficient=not short and (bool(ind) or words >= 12),
                    insufficient_reason="The text is very short or no recognisable scam patterns were found, so there is little to judge by.",
                    limitations=limits)
    top = ", ".join([i["label"] for i in result["indicators"] if i["weight"] > 0][:2]) or "no indicators"
    result.update({"ok": True, "scan_type": scan_type, "extracted_urls": urls, "url_results": url_results,
                   "sender_info": snd, "summary": f"{len(urls)} link(s); {top}"})
    return result
