"""Shared, transparent risk scoring used by EVERY scanner.

How it works (plain language):
  * Each scanner produces a list of Indicators. Each indicator has an id and a weight
    (positive = raises risk, negative = lowers it).
  * Indicators with the same id are merged, so the same evidence is never counted twice.
  * Score = sum of the unique weights, clamped to 0..100.
  * Categories are demonstration thresholds chosen by us, NOT statistically validated:
      0-29 Low Risk | 30-59 Suspicious | 60-100 High Risk
"""
from dataclasses import dataclass, field

LOW_MAX = 29
SUSPICIOUS_MAX = 59

DISCLAIMER = (
    "This is an automated assessment based on indicators, not a definitive fraud determination. "
    "TrustShield AI cannot catch every scam and cannot guarantee that anything is safe. It is not a "
    "substitute for your bank, law enforcement or a professional security service."
)


@dataclass
class Indicator:
    id: str
    label: str
    weight: int
    detail: str = ""
    evidence: list = field(default_factory=list)


def categorize(score: int) -> str:
    if score <= LOW_MAX:
        return "Low Risk"
    if score <= SUSPICIOUS_MAX:
        return "Suspicious"
    return "High Risk"


NEXT_STEPS = {
    "Low Risk": [
        "Stay cautious anyway: a low score only means few warning signs were found, not that it is safe.",
        "Type the official website address yourself instead of following links you were sent.",
        "Never share passwords, PINs or OTPs with anyone who contacts you.",
    ],
    "Suspicious": [
        "Do not click links or open attachments until you have verified the sender another way.",
        "Verify the sender through an independently obtained official contact (not the details in the message).",
        "Type the official website address yourself rather than following a suspicious link.",
        "Do not share passwords, PINs, or OTPs.",
    ],
    "High Risk": [
        "Do not click, reply, pay, or download anything.",
        "Do not share passwords, PINs, or OTPs. If you already did, change your password and contact the provider now.",
        "If money or banking details are involved, contact your bank using its official number.",
        "Report it to the impersonated organisation or your email/phone provider, then delete it.",
    ],
}


def assess(indicators, sufficient=True, insufficient_reason="", limitations=None, extra_steps=None) -> dict:
    """Merge indicators, compute the score and return a consistent result structure."""
    merged = {}
    for ind in indicators:
        cur = merged.get(ind.id)
        if cur is None:
            merged[ind.id] = Indicator(ind.id, ind.label, int(ind.weight), ind.detail, list(ind.evidence))
        else:
            if abs(ind.weight) > abs(cur.weight):
                cur.weight, cur.label, cur.detail = int(ind.weight), ind.label, ind.detail
            for e in ind.evidence:
                if e not in cur.evidence:
                    cur.evidence.append(e)

    items = sorted(merged.values(), key=lambda i: -abs(i.weight))
    score = max(0, min(100, int(round(sum(i.weight for i in items)))))
    category = categorize(score)

    steps = list(NEXT_STEPS[category])
    for s in extra_steps or []:
        if s not in steps:
            steps.append(s)

    lims = list(limitations or [])
    lims.append("Score thresholds are demonstration values defined by this app, not industry standards.")
    if not sufficient:
        lims.insert(0, insufficient_reason or "There was too little information to judge reliably.")

    return {
        "risk_score": score,
        "risk_category": category,
        "evidence_level": "Sufficient" if sufficient else "Insufficient evidence",
        "display_category": category if sufficient else f"{category} \u2014 Insufficient evidence",
        "indicators": [
            {"id": i.id, "label": i.label, "weight": i.weight,
             "direction": "increases risk" if i.weight > 0 else "decreases risk",
             "detail": i.detail, "evidence": i.evidence}
            for i in items
        ],
        "limitations": lims,
        "next_steps": steps,
        "disclaimer": DISCLAIMER,
    }
