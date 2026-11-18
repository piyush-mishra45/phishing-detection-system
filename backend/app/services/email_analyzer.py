"""Phishing e-mail analysis: parsing, header checks, sender-domain checks, keyword + link analysis, ML."""
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from app.ml import predictor
from app.services import risk_engine
from app.services.url_features import BRANDS, SHORTENERS, SUSPICIOUS_TLDS, brand_mismatch, explain_url, is_ip, split_host

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com"}
KEYWORD_GROUPS = {
    "urgency": ["urgent", "immediately", "within 24 hours", "act now", "final notice", "last warning", "expires today", "action required", "asap", "limited time"],
    "credentials": ["verify your account", "confirm your password", "update your password", "login to your account", "sign in to", "validate your", "security alert", "unusual sign-in", "reset your password", "your credentials"],
    "financial": ["wire transfer", "bank account", "credit card", "payment failed", "invoice attached", "refund", "tax refund", "billing information", "gift card", "bitcoin", "crypto"],
    "threat": ["account suspended", "account will be closed", "account has been locked", "legal action", "unauthorized", "suspicious activity", "deactivated", "terminated"],
    "reward": ["you have won", "congratulations", "claim your prize", "lottery", "free gift", "winner", "inheritance", "selected for"],
    "generic_greeting": ["dear customer", "dear user", "dear account holder", "dear member", "valued customer"],
}
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
MAX_BODY = 100_000


def parse_eml(raw: bytes) -> dict:
    """Parse a .eml safely: attachments are NOT stored or executed, only listed by name/type."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    text, html, attachments = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype, disp = part.get_content_type(), (part.get_content_disposition() or "")
        if disp == "attachment" or part.get_filename():
            attachments.append({"filename": part.get_filename() or "unnamed", "type": ctype})
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain" and not text:
            text = content
        elif ctype == "text/html" and not html:
            html = content
    if not text and html:
        text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    hdr = lambda k: str(msg.get(k, "") or "")
    return {"subject": hdr("Subject"), "from": hdr("From"), "reply_to": hdr("Reply-To"), "return_path": hdr("Return-Path"),
            "to": hdr("To"), "date": hdr("Date"), "message_id": hdr("Message-ID"), "x_mailer": hdr("X-Mailer"),
            "received_count": len(msg.get_all("Received", [])), "auth_results": " ".join(msg.get_all("Authentication-Results", [])),
            "received_spf": hdr("Received-SPF"), "body": text[:MAX_BODY], "html": html[:MAX_BODY * 2], "attachments": attachments}


def _edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_sender(from_header: str, reply_to="", return_path="") -> list:
    name, addr = parseaddr(from_header)
    addr = addr.lower()
    sig = []
    if not addr or "@" not in addr:
        return [{"id": "sender_missing", "label": "Sender address", "value": "missing/invalid", "status": "unknown", "points": 0, "reason": ""}]
    domain = addr.split("@", 1)[1]
    reg, subs, tld = split_host(domain)

    def add(id_, label, value, risky, pts, reason):
        sig.append({"id": id_, "label": label, "value": value, "status": "risk" if risky else "ok", "points": pts if risky else 0, "reason": reason if risky else ""})

    brand = brand_mismatch(domain)
    add("sender_brand", "Sender domain imitates a brand", brand or "no", bool(brand), 30, f"Sender domain '{domain}' contains '{brand}' but is not an official {brand} domain.")
    look = ""
    for b, legit in BRANDS.items():
        for l in legit:
            lbl = l.split(".")[0]
            if reg not in legit and reg.split(".")[0] != lbl and 0 < _edit_distance(reg.split(".")[0], lbl) <= 1 and len(lbl) >= 5:
                look = l
    add("sender_lookalike", "Look-alike of a known domain", look or "no", bool(look), 30, f"'{reg}' is nearly identical to '{look}' (typosquatting).")
    shown_brand = next((b for b in BRANDS if b in name.lower()), "")
    add("display_spoof", "Display name vs. domain", shown_brand or "consistent", bool(shown_brand and reg not in BRANDS[shown_brand]), 25,
        f"Display name mentions '{shown_brand}' but the e-mail comes from '{domain}'.")
    add("free_mail_brand", "Free-mail address posing as organisation", domain if shown_brand else "no", bool(shown_brand and domain in FREE_MAIL), 10, "Organisations rarely use free-mail addresses.")
    add("sender_tld", "Sender TLD", tld, tld in SUSPICIOUS_TLDS, 12, f".{tld} domains are frequently abused.")
    add("sender_punycode", "Punycode in sender domain", "xn--" in domain, "xn--" in domain, 20, "Look-alike (homograph) characters in the sender domain.")
    add("sender_digits", "Digits mixed in sender domain", reg, bool(re.search(r"[a-z]\d+[a-z]|\d[a-z]{2,}\d", reg.split(".")[0])), 6, "Digit/letter substitution (e.g. 'paypa1') is common in spoofed domains.")
    for hname, h in (("reply_to", reply_to), ("return_path", return_path)):
        _, a2 = parseaddr(h)
        if a2 and "@" in a2:
            d2 = split_host(a2.split("@", 1)[1].lower())[0]
            add(f"{hname}_mismatch", f"{hname.replace('_', '-').title()} domain differs from sender", d2, d2 != reg, 15 if hname == "reply_to" else 5,
                f"{hname.replace('_', '-').title()} goes to '{d2}', not the sender's domain '{reg}'.")
    return sig


def analyze_headers(h: dict) -> tuple:
    """Return (signals, unknown_checks). Missing auth headers => unknown, never 'pass'."""
    sig, unknown = [], []
    auth = (h.get("auth_results", "") + " " + h.get("received_spf", "")).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if not m:
            unknown.append(f"{mech.upper()} result (not present in headers)")
            continue
        ok = m.group(1) in ("pass", "bestguesspass")
        sig.append({"id": f"auth_{mech}", "label": f"{mech.upper()} result", "value": m.group(1), "status": "ok" if ok else "risk", "points": 0 if ok else 15,
                    "reason": "" if ok else f"{mech.upper()} check did not pass ({m.group(1)}); the sender may be forged."})
    return sig, unknown


def find_keywords(text: str) -> dict:
    low = text.lower()
    found = {}
    for grp, words in KEYWORD_GROUPS.items():
        hits = [w for w in words if w in low]
        if hits:
            found[grp] = hits
    return found


def analyze_links(body: str, html: str = "") -> list:
    links, seen = [], set()
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href, txt = a["href"].strip(), a.get_text(" ", strip=True)
            if href.lower().startswith(("http://", "https://")) and href not in seen:
                seen.add(href)
                links.append({"url": href, "text": txt})
    for u in URL_RE.findall(body or ""):
        u = u.rstrip(".,;:!?")
        if u not in seen:
            seen.add(u)
            links.append({"url": u, "text": ""})
    out = []
    for l in links[:50]:
        sigs = explain_url(l["url"])
        pts = sum(s["points"] for s in sigs)
        reasons = [s["reason"] for s in sigs if s["status"] == "risk" and s["reason"] and s["id"] != "https"]
        txt = l["text"]
        if txt and re.match(r"(https?://|www\.)", txt, re.I):  # visible text shows one site, href goes elsewhere
            try:
                shown = split_host(urlsplit(txt if "://" in txt else "http://" + txt).hostname or "")[0]
                real = split_host(urlsplit(l["url"]).hostname or "")[0]
                if shown and shown != real:
                    pts += 30
                    reasons.append(f"Link text shows '{shown}' but leads to '{real}'.")
            except ValueError:
                pass
        p = predictor.predict_url_prob(l["url"])
        out.append({"url": l["url"], "text": txt, "heuristic_points": pts, "ml_probability": None if p is None else round(p, 3),
                    "reasons": reasons, "malicious": pts >= 30 or (p is not None and p >= 0.8 and pts >= 10)})
    return out


def analyze_email(sender="", subject="", body="", parsed=None) -> dict:
    parsed = parsed or {}
    html = parsed.get("html", "")
    text = f"{subject}\n{body}"
    signals, unknown = [], []

    kw = find_keywords(text)
    kw_count = sum(len(v) for v in kw.values())
    signals.append({"id": "keywords", "label": "Suspicious keywords", "value": kw_count, "status": "risk" if kw_count >= 2 else "ok",
                    "points": min(30, kw_count * 6) if kw_count >= 2 else 0,
                    "reason": f"Contains {kw_count} phishing-style phrases ({', '.join(kw)})." if kw_count >= 2 else ""})
    if sender:
        signals += analyze_sender(sender, parsed.get("reply_to", ""), parsed.get("return_path", ""))
    else:
        unknown.append("Sender checks (no sender address supplied)")
    if parsed:
        s2, u2 = analyze_headers(parsed)
        signals += s2
        unknown += u2
    else:
        unknown.append("SPF/DKIM/DMARC (upload a .eml file to analyse headers)")

    links = analyze_links(body, html)
    bad = [l for l in links if l["malicious"]]
    if bad:
        signals.append({"id": "bad_links", "label": "Suspicious links", "value": len(bad), "status": "risk", "points": min(40, 20 + 10 * len(bad)),
                        "reason": f"{len(bad)} link(s) show phishing characteristics (see link analysis)."})
    elif links:
        signals.append({"id": "bad_links", "label": "Suspicious links", "value": 0, "status": "ok", "points": 0, "reason": ""})
    risky_att = [a for a in parsed.get("attachments", []) if a["filename"].lower().endswith((".exe", ".scr", ".js", ".vbs", ".bat", ".html", ".htm", ".iso", ".lnk", ".docm", ".xlsm", ".zip", ".jar"))]
    if risky_att:
        signals.append({"id": "attachment", "label": "Risky attachment type", "value": [a["filename"] for a in risky_att], "status": "risk", "points": 20,
                        "reason": "Attachment type commonly used to deliver malware (never opened by this tool)."})

    ml = predictor.predict_email_prob(text)
    if ml is None:
        unknown.append("ML text classifier (model not trained yet; run train_email_model.py)")
    res = risk_engine.combine(ml, signals, unknown)
    score = res["risk_score"]
    prediction = "PHISHING" if score > 60 else "SUSPICIOUS" if score > 30 else "LEGITIMATE"
    res.update({
        "prediction": prediction, "phishing_probability": res["ml_probability"],
        "legitimate_probability": None if ml is None else round(1 - ml, 4),
        "threat_category": "Credential phishing" if "credentials" in kw else "Financial fraud" if "financial" in kw else "Prize/advance-fee scam" if "reward" in kw else "Generic phishing" if prediction != "LEGITIMATE" else "None detected",
        "suspicious_keywords": kw, "links": links, "malicious_links": [l for l in links if l["malicious"]], "signals": signals,
        "headers": {k: parsed.get(k, "") for k in ("from", "reply_to", "return_path", "date", "message_id", "received_count", "x_mailer")} if parsed else {},
        "attachments": parsed.get("attachments", []), "recommended_actions": risk_engine.actions_for(res["risk_level"]),
        "disclaimer": "Automated analysis can be wrong. When in doubt, verify with the sender through another channel.",
    })
    return res
