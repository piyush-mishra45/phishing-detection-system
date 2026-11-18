"""Website analysis. Safe by design: static HTML parsing only, no JavaScript execution, no form submission,
SSRF-guarded fetch with timeouts and size limits. Checks that cannot be performed are reported as 'unknown'."""
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from app.ml import predictor
from app.security import ssrf
from app.services import risk_engine
from app.services.url_features import BRANDS, brand_mismatch, explain_url, extract_features, registrable, split_host

JS_PATTERNS = {
    "eval(": r"\beval\s*\(", "atob/base64 decode": r"\batob\s*\(", "unescape()": r"\bunescape\s*\(", "document.write": r"document\.write\s*\(",
    "String.fromCharCode": r"fromCharCode", "location redirect": r"(window|document|top)\.location(\.href)?\s*=", "right-click disabled": r"contextmenu|oncontextmenu\s*=\s*[\"']?return\s+false",
    "hex-obfuscated strings": r"(\\x[0-9a-f]{2}){6,}", "form keylogging hook": r"addEventListener\(\s*[\"']key(down|up|press)", "popup window.open": r"window\.open\s*\(",
}
U = lambda: {"status": "unknown"}


def _hidden(tag) -> bool:
    st = (tag.get("style") or "").replace(" ", "").lower()
    return (any(x in st for x in ("display:none", "visibility:hidden", "opacity:0")) or tag.get("hidden") is not None
            or str(tag.get("width", "")).strip() in ("0", "0px", "1", "1px") or str(tag.get("height", "")).strip() in ("0", "0px", "1", "1px")
            or "width:0" in st or "height:0" in st)


def analyze_html(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    base_reg = registrable(urlsplit(base_url).hostname or "")
    title = (soup.title.get_text(strip=True) if soup.title else "")[:200]
    meta = {m.get("name") or m.get("property"): (m.get("content") or "")[:300] for m in soup.find_all("meta") if (m.get("name") or m.get("property"))}
    refresh = next((m.get("content", "") for m in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})), "")

    forms, cred_forms = [], 0
    for f in soup.find_all("form"):
        action = urljoin(base_url, f.get("action") or "")
        inputs = f.find_all("input")
        has_pw = any((i.get("type") or "").lower() == "password" for i in inputs)
        ext = bool(action.startswith("http")) and registrable(urlsplit(action).hostname or "") != base_reg
        insecure = action.startswith("http://") and has_pw
        cred_forms += has_pw
        forms.append({"action": action[:300], "method": (f.get("method") or "get").lower(), "has_password_field": has_pw, "posts_to_external_domain": ext, "insecure_http_post": insecure,
                      "input_types": sorted({(i.get("type") or "text").lower() for i in inputs})[:10]})
    iframes = [{"src": (i.get("src") or "")[:300], "hidden": _hidden(i)} for i in soup.find_all(["iframe", "frame"])]
    scripts = soup.find_all("script")
    inline_js = " ".join((s.string or "") for s in scripts if not s.get("src"))[:200_000]
    js_hits = [name for name, rx in JS_PATTERNS.items() if re.search(rx, inline_js, re.I)]  # regex only; never executed
    ext_scripts = [s["src"] for s in scripts if s.get("src", "").startswith(("http://", "https://")) and registrable(urlsplit(s["src"]).hostname or "") != base_reg]
    anchors = [urljoin(base_url, a["href"]) for a in soup.find_all("a", href=True)]
    http_anchors = [a for a in anchors if a.startswith(("http://", "https://"))]
    ext_links = [a for a in http_anchors if registrable(urlsplit(a).hostname or "") != base_reg]
    empty_links = sum(1 for a in soup.find_all("a", href=True) if a["href"].strip() in ("#", "", "javascript:void(0)", "javascript:;"))
    fav = soup.find("link", rel=lambda v: v and "icon" in " ".join(v).lower())
    fav_ext = bool(fav and fav.get("href", "").startswith("http") and registrable(urlsplit(fav["href"]).hostname or "") != base_reg)
    title_brand = next((b for b in ("paypal", "microsoft", "apple", "google", "amazon", "facebook", "netflix", "instagram", "linkedin", "dropbox", "docusign", "chase", "wells fargo", "hdfc", "sbi", "icici", "paytm", "coinbase", "binance")
                        if b in title.lower()), "")
    return {"title": title, "meta_description": meta.get("description", ""), "meta_robots": meta.get("robots", ""), "meta_refresh": refresh,
            "forms": forms[:10], "credential_forms": cred_forms, "iframes": iframes[:20], "hidden_iframes": sum(i["hidden"] for i in iframes),
            "suspicious_js": js_hits, "external_scripts": ext_scripts[:15], "link_count": len(http_anchors), "external_link_count": len(ext_links),
            "external_link_ratio": round(len(ext_links) / len(http_anchors), 2) if http_anchors else 0.0, "empty_link_count": empty_links,
            "top_external_domains": sorted({registrable(urlsplit(a).hostname or "") for a in ext_links})[:10], "favicon_external": fav_ext,
            "title_brand": title_brand}


def dns_info(host: str) -> dict:
    out = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt_count": None, "status": "unknown"}
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.lifetime = 4
        for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns")):
            try:
                out[key] = sorted(str(r).rstrip(".") for r in res.resolve(host, rtype))[:8]
            except Exception:
                pass
        try:
            out["txt_count"] = len(res.resolve(host, "TXT"))
        except Exception:
            out["txt_count"] = 0
        out["status"] = "ok" if (out["a"] or out["aaaa"]) else "no_address"
    except ImportError:  # dnspython missing: fall back to the system resolver (A/AAAA only; MX/NS stay unknown)
        try:
            infos = socket.getaddrinfo(host, None)
            out["a"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
            out["aaaa"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
            out["mx"] = out["ns"] = None
            out["status"] = "partial"
        except socket.gaierror:
            out["status"] = "no_address"
    return out


def domain_age(reg_domain: str) -> dict:
    """RDAP (JSON registration data) via the public rdap.org bootstrap. Returns unknown on any failure."""
    if not re.fullmatch(r"[a-z0-9.\-]{3,253}", reg_domain or ""):
        return {"status": "unknown", "error": "invalid domain"}
    try:
        r = requests.get(f"https://rdap.org/domain/{reg_domain}", timeout=5, headers={"Accept": "application/rdap+json"}, allow_redirects=True)
        if r.status_code != 200:
            return {"status": "unknown", "error": f"RDAP returned {r.status_code}"}
        data = r.json()
        ev = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        reg = ev.get("registration")
        if not reg:
            return {"status": "unknown", "error": "no registration date published"}
        dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
        return {"status": "ok", "registered": dt.date().isoformat(), "age_days": (datetime.now(timezone.utc) - dt).days,
                "registrar": next((e.get("vcardArray", [None, [[0, 0, 0, "?"]]])[1][-1][3] for e in data.get("entities", []) if "registrar" in e.get("roles", [])), "")}
    except Exception as e:
        return {"status": "unknown", "error": f"RDAP lookup failed ({type(e).__name__})"}


def analyze_website(raw_url: str, cfg: dict | None = None, do_domain_age=True) -> dict:
    cfg = cfg or {}
    p = ssrf.parse_url(raw_url)  # ValueError -> 400 in the route
    url, host = p["url"], p["host"]
    reg = registrable(host)
    feats = extract_features(url)
    signals = explain_url(url)
    unknown = []
    report = {"url": url, "domain": host, "registrable_domain": reg, "url_features": feats, "port": p["port"]}

    # --- Fetch (SSRF guarded). Never raises for unsafe targets: the verdict becomes UNKNOWN / flagged.
    fetch = ssrf.safe_fetch(url, timeout=cfg.get("FETCH_TIMEOUT", (3.05, 8)), max_bytes=cfg.get("FETCH_MAX_BYTES", 1_000_000), max_redirects=cfg.get("FETCH_MAX_REDIRECTS", 5))
    ips = fetch.resolved_ips
    blocked = "non-public" in fetch.error or "private" in fetch.error
    report["fetch"] = {"reachable": fetch.ok, "status_code": fetch.status or None, "error": fetch.error, "truncated": fetch.truncated, "content_type": fetch.content_type, "resolved_ips": ips}
    if blocked:
        report["blocked_reason"] = "Target resolves to a private/local address; it was NOT contacted (SSRF protection)."
        signals.append({"id": "private_target", "label": "Resolves to non-public address", "value": True, "status": "risk", "points": 10, "reason": "The domain resolves to a private/local address, which is abnormal for a public website."})

    # --- Redirects
    chain = fetch.chain
    hops = max(0, len(chain) - 1)
    cross = []
    for h in chain[1:]:
        r2 = registrable(urlsplit(h["url"]).hostname or "")
        if r2 and r2 != reg:
            cross.append(r2)
    report["redirects"] = {"status": "ok" if fetch.chain else "unknown", "count": hops, "chain": [{"url": c["url"][:300], "status": c["status"]} for c in chain], "final_url": fetch.final_url or url,
                           "cross_domain": sorted(set(cross)), "blocked_unsafe_redirect": fetch.blocked_redirect}
    if not fetch.chain:
        unknown.append("Redirect analysis (site could not be fetched)")
    signals.append({"id": "redirects", "label": "Redirect hops", "value": hops, "status": "risk" if hops >= 3 else "ok", "points": 10 if hops >= 3 else 0, "reason": f"{hops} redirects before reaching the page."})
    signals.append({"id": "cross_redirect", "label": "Redirects to a different domain", "value": sorted(set(cross)), "status": "risk" if cross else "ok", "points": 15 if cross else 0,
                    "reason": f"Redirects to a different domain ({', '.join(sorted(set(cross)))})."})
    if fetch.blocked_redirect:
        signals.append({"id": "unsafe_redirect", "label": "Redirect to non-public address", "value": True, "status": "risk", "points": 25, "reason": "A redirect pointed at a private/internal address (blocked)."})

    # --- SSL
    ssl_info = {"status": "unknown"}
    if p["scheme"] != "https":
        ssl_info = {"status": "not_https"}
    elif ips and not blocked and p["port"] in ssrf.FETCHABLE_PORTS:
        ssl_info = ssrf.tls_inspect(host, ips[0], p["port"])
    report["ssl"] = ssl_info
    st = ssl_info["status"]
    if st == "not_https":
        pass  # already counted in the 'https' URL signal
    elif st == "invalid":
        signals.append({"id": "ssl", "label": "SSL certificate", "value": "invalid", "status": "risk", "points": 20, "reason": f"Invalid TLS certificate ({ssl_info.get('error', '')})."})
    elif st == "valid":
        young = ssl_info["cert_age_days"] < 14
        signals.append({"id": "ssl", "label": "SSL certificate", "value": f"valid, issued {ssl_info['cert_age_days']}d ago", "status": "risk" if young else "ok", "points": 8 if young else 0,
                        "reason": "Certificate was issued very recently (note: valid HTTPS does NOT mean a site is trustworthy)."})
    else:
        unknown.append("SSL certificate")

    # --- DNS + domain age
    dns = dns_info(host) if not re.fullmatch(r"[\d.:]+", host) else {"status": "n/a (IP host)"}
    report["dns"] = dns
    if dns.get("status") == "no_address":
        signals.append({"id": "dns", "label": "DNS resolution", "value": "no address", "status": "risk", "points": 15, "reason": "Domain has no A/AAAA records."})
    elif dns.get("status") in ("unknown",):
        unknown.append("DNS records")
    if dns.get("status") == "partial":
        unknown.append("MX/NS/TXT records (install dnspython)")
    age = domain_age(reg) if do_domain_age and not re.fullmatch(r"[\d.:]+", host) else {"status": "unknown", "error": "skipped"}
    report["domain_age"] = age
    if age["status"] == "ok":
        d = age["age_days"]
        signals.append({"id": "domain_age", "label": "Domain age", "value": f"{d} days", "status": "risk" if d < 90 else "ok", "points": 25 if d < 30 else 15 if d < 90 else 0,
                        "reason": f"Domain was registered only {d} days ago; most phishing domains are young."})
    else:
        unknown.append("Domain age (registration data unavailable)")

    # --- HTML
    html_report = None
    if fetch.ok and fetch.html:
        html_report = analyze_html(fetch.html, fetch.final_url or url)
        report["html"] = html_report
        h = html_report
        pw_risk = h["credential_forms"] > 0
        signals.append({"id": "cred_form", "label": "Password / credential form", "value": h["credential_forms"], "status": "risk" if pw_risk else "ok", "points": 12 if pw_risk else 0,
                        "reason": "Page asks for a password (not malicious on its own; relevant combined with other signals)."})
        ext_form = any(f["posts_to_external_domain"] and f["has_password_field"] for f in h["forms"])
        signals.append({"id": "form_external", "label": "Credential form posts to another domain", "value": ext_form, "status": "risk" if ext_form else "ok", "points": 30 if ext_form else 0, "reason": "A password form sends data to a different domain than the page itself."})
        insecure = any(f["insecure_http_post"] for f in h["forms"])
        if insecure:
            signals.append({"id": "form_http", "label": "Password form over HTTP", "value": True, "status": "risk", "points": 15, "reason": "A password form submits over unencrypted HTTP."})
        signals.append({"id": "hidden_iframe", "label": "Hidden iframes", "value": h["hidden_iframes"], "status": "risk" if h["hidden_iframes"] else "ok", "points": 20 if h["hidden_iframes"] else 0, "reason": "Invisible iframes are used for clickjacking and silent content loading."})
        js = len(h["suspicious_js"])
        signals.append({"id": "js", "label": "Suspicious JavaScript patterns", "value": h["suspicious_js"], "status": "risk" if js >= 2 else "ok", "points": min(25, js * 7) if js >= 2 else 0, "reason": f"Obfuscation/redirect patterns found in inline scripts: {', '.join(h['suspicious_js'])} (static check only; code was not executed)."})
        ext_r = h["external_link_ratio"] > 0.8 and h["link_count"] >= 5
        signals.append({"id": "ext_links", "label": "External link ratio", "value": h["external_link_ratio"], "status": "risk" if ext_r else "ok", "points": 8 if ext_r else 0, "reason": "Nearly all links lead to other domains."})
        if h["meta_refresh"]:
            signals.append({"id": "meta_refresh", "label": "Meta refresh redirect", "value": h["meta_refresh"][:80], "status": "risk", "points": 8, "reason": "Page redirects automatically via <meta refresh>."})
        tb = h["title_brand"]
        mism = bool(tb and h["credential_forms"] and reg not in BRANDS.get(tb.replace(" ", ""), set()))
        signals.append({"id": "title_brand", "label": "Page title brand vs domain", "value": tb or "none", "status": "risk" if mism else "ok", "points": 20 if mism else 0, "reason": f"Page presents itself as '{tb}' but the domain is '{reg}'."})
        if h["favicon_external"]:
            signals.append({"id": "fav", "label": "Favicon loaded from other domain", "value": True, "status": "risk", "points": 4, "reason": "Favicon hot-linked from another site (typical of cloned pages)."})
    else:
        unknown.append("HTML / form / JavaScript analysis (page content unavailable)")
        report["html"] = None

    ml = predictor.predict_url_prob(url)
    if ml is None:
        unknown.append("ML URL classifier (model not trained yet; run train_website_model.py)")
    res = risk_engine.combine(ml, signals, unknown)
    score = res["risk_score"]
    analysed = bool(html_report)
    if blocked:
        verdict = "UNKNOWN"  # never contacted; cannot judge the page
    elif score > 60:
        verdict = "PHISHING"
    elif score > 30:
        verdict = "SUSPICIOUS"
    elif analysed:
        verdict = "SAFE"  # = "no strong indicators found", never "guaranteed safe"
    else:
        verdict = "UNKNOWN"  # low score but the page itself could not be inspected
    res.update({"prediction": verdict, "signals": signals, "recommended_actions": risk_engine.actions_for(res["risk_level"]),
                "verdict_note": "SAFE means no strong phishing indicators were found among the checks that could be run. It is not a guarantee, and HTTPS alone never proves a site is trustworthy." if verdict == "SAFE"
                else report.get("blocked_reason") or "The page could not be inspected, so the result is based on URL/domain signals only." if verdict == "UNKNOWN" else ""})
    report.update(res)
    return report
