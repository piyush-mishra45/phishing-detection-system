"""Combined risk scoring.

score = 0.5 * (calibrated ML phishing probability x 100) + 0.5 * (heuristic signal score, capped at 100)
If one side is unavailable the other is used alone. Checks that could not be performed are listed as
`unknown` and contribute NOTHING (they are never counted as safe).

`confidence` is deliberately separate from `risk_score`: it describes how decisive the ML model was
(max(p, 1-p)), and is None when no model is loaded."""

LEVELS = [(30, "Low Risk"), (60, "Medium Risk"), (80, "High Risk"), (100, "Critical Risk")]


def risk_level(score: float) -> str:
    for hi, name in LEVELS:
        if score <= hi:
            return name
    return "Critical Risk"


def level_range(name: str):
    return {"low": (0, 30), "medium": (31, 60), "high": (61, 80), "critical": (81, 100)}.get(name.lower().split()[0])


def combine(ml_prob, signals, unknown=None):
    """signals: [{id,label,status,points,reason}] ; ml_prob: float|None."""
    sig_points = sum(s.get("points", 0) for s in signals if s.get("status") == "risk")
    sig_score = min(100.0, float(sig_points))
    if ml_prob is None:
        score = sig_score
    elif not signals:
        score = ml_prob * 100
    else:
        score = 0.5 * ml_prob * 100 + 0.5 * sig_score
    score = int(round(max(0.0, min(100.0, score))))  # whole number so the 0-30/31-60/61-80/81-100 bands are unambiguous
    reasons = [s["reason"] for s in sorted(signals, key=lambda x: -x.get("points", 0)) if s.get("status") == "risk" and s.get("reason")]
    return {
        "risk_score": score, "risk_level": risk_level(score), "heuristic_score": int(round(sig_score)),
        "ml_probability": None if ml_prob is None else round(float(ml_prob), 4),
        "model_confidence": None if ml_prob is None else round(max(ml_prob, 1 - ml_prob), 4),
        "reasons": reasons, "unknown_checks": unknown or [],
    }


ACTIONS = {
    "Low Risk": ["No strong phishing indicators were found, but this is not a guarantee of safety.", "Still avoid entering passwords unless you reached the site by typing the address yourself."],
    "Medium Risk": ["Do not click links or open attachments until you verify the sender through a separate channel.", "Navigate to the organisation's site by typing its address manually.", "Report to your IT/security team if unsure."],
    "High Risk": ["Do not enter credentials or personal data.", "Do not click links or download attachments.", "Report as phishing to your email provider / IT security team.", "If you already interacted, change affected passwords and enable MFA."],
    "Critical Risk": ["Treat as malicious: do not interact and delete or quarantine it.", "Report it to your security team and the impersonated organisation.", "If credentials were entered, change them immediately, enable MFA and check account activity.", "Consider monitoring accounts and reporting to your local cyber-crime portal."],
}


def actions_for(level):
    return ACTIONS.get(level, ACTIONS["Medium Risk"])
