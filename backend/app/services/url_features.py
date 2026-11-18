"""Lexical URL features. The SAME function feeds the ML model (training + inference) and the explainable heuristics,
so training/serving skew cannot happen. Pure stdlib, no network access."""
import ipaddress
import math
import re
from urllib.parse import unquote, urlsplit

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "country", "kim", "work", "loan", "icu", "cyou", "rest", "buzz", "support", "mov"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
KEYWORDS = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm", "banking", "wallet", "password", "credential", "webscr", "authenticate", "suspend", "unlock", "recover", "billing", "invoice", "payment"]
# brand -> legitimate registrable domains (used for brand-impersonation checks)
BRANDS = {"paypal": {"paypal.com"}, "apple": {"apple.com", "icloud.com"}, "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
          "google": {"google.com", "gmail.com", "youtube.com"}, "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
          "facebook": {"facebook.com", "fb.com"}, "netflix": {"netflix.com"}, "instagram": {"instagram.com"}, "linkedin": {"linkedin.com"},
          "dropbox": {"dropbox.com"}, "docusign": {"docusign.com", "docusign.net"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"},
          "chase": {"chase.com"}, "wellsfargo": {"wellsfargo.com"}, "hdfc": {"hdfcbank.com"}, "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "icici": {"icicibank.com"},
          "paytm": {"paytm.com"}, "whatsapp": {"whatsapp.com"}, "coinbase": {"coinbase.com"}, "binance": {"binance.com"}}
TWO_LEVEL_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "net.in", "org.in", "co.jp", "com.br", "co.za", "com.cn", "co.nz", "com.sg", "gov.in", "ac.in"}

_LEET = str.maketrans("0135@$", "oleasS".lower())

FEATURE_NAMES = ["url_length", "host_length", "path_length", "query_length", "num_dots_host", "num_hyphens_host", "num_digits", "digit_ratio",
                 "num_special_chars", "has_at", "has_ip_host", "num_subdomains", "is_https", "nonstandard_port", "has_punycode", "suspicious_tld",
                 "keyword_count", "double_slash_in_path", "host_entropy", "is_shortener", "longest_label", "num_percent_encoded", "path_depth",
                 "brand_in_wrong_domain", "num_params"]


def split_host(host: str):
    """Return (registrable_domain, subdomain_labels, tld)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return host, [], ""
    last2 = ".".join(labels[-2:])
    n = 3 if last2 in TWO_LEVEL_TLDS and len(labels) >= 3 else 2
    return ".".join(labels[-n:]), labels[:-n], labels[-1]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host.lower()))  # decimal/hex IP tricks


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def brand_mismatch(host: str, path: str = "") -> str:
    """Return brand name if the host mentions a brand but isn't that brand's real domain."""
    reg, subs, _ = split_host(host)
    hay = host.lower().replace("-", "").replace(".", "").translate(_LEET)  # 'paypa1' -> 'paypal'
    for brand, legit in BRANDS.items():
        if brand in hay and reg not in legit:
            return brand
    return ""


def extract_features(url: str) -> dict:
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        try:
            port = p.port
        except ValueError:
            port = None
    except ValueError:
        host, port, p = "", None, urlsplit("http://invalid")
    path, query = p.path or "", p.query or ""
    reg, subs, tld = split_host(host)
    low = unquote(u).lower()
    digits = sum(ch.isdigit() for ch in u)
    ip = is_ip(host)
    return {
        "url_length": len(u), "host_length": len(host), "path_length": len(path), "query_length": len(query),
        "num_dots_host": host.count("."), "num_hyphens_host": host.count("-"), "num_digits": digits, "digit_ratio": round(digits / max(1, len(u)), 4),
        "num_special_chars": sum(u.count(c) for c in "@?&=_%~#$!*"), "has_at": int("@" in u.split("?")[0].split("//", 1)[-1].split("/")[0]),
        "has_ip_host": int(ip), "num_subdomains": 0 if ip else len(subs), "is_https": int(p.scheme == "https"),
        "nonstandard_port": int(port is not None and port not in (80, 443)), "has_punycode": int("xn--" in host),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS), "keyword_count": sum(k in low for k in KEYWORDS),
        "double_slash_in_path": int("//" in path), "host_entropy": round(_entropy(host), 4), "is_shortener": int(reg in SHORTENERS),
        "longest_label": max((len(x) for x in host.split(".")), default=0), "num_percent_encoded": u.count("%"),
        "path_depth": len([s for s in path.split("/") if s]), "brand_in_wrong_domain": int(bool(brand_mismatch(host))), "num_params": len([q for q in query.split("&") if q]),
    }


def feature_vector(url: str):
    f = extract_features(url)
    return [f[n] for n in FEATURE_NAMES]


def explain_url(url: str) -> list:
    """Human-readable signals: [{id,label,value,status:'risk'|'ok',points,reason}]. points feed the risk engine."""
    f = extract_features(url)
    u = url if "://" in url else "http://" + url
    host = (urlsplit(u).hostname or "")
    reg, subs, tld = split_host(host)
    S = []

    def add(id_, label, value, risky, points, reason):
        S.append({"id": id_, "label": label, "value": value, "status": "risk" if risky else "ok", "points": points if risky else 0, "reason": reason if risky else ""})

    add("ip_host", "IP address instead of domain", bool(f["has_ip_host"]), f["has_ip_host"], 30, "Legitimate sites rarely use raw IP addresses in links.")
    add("at_symbol", "'@' symbol in URL", bool(f["has_at"]), f["has_at"], 25, "Text before '@' is ignored by browsers and is used to disguise the real destination.")
    add("long_url", "URL length", f["url_length"], f["url_length"] > 90, 8, "Very long URLs are often used to hide the real domain.")
    add("subdomains", "Number of subdomains", f["num_subdomains"], f["num_subdomains"] >= 3, 12, "Many nested subdomains can mimic a trusted brand (e.g. paypal.com.evil.xyz).")
    add("hyphens", "Hyphens in domain", f["num_hyphens_host"], f["num_hyphens_host"] >= 2, 8, "Multiple hyphens are common in look-alike domains.")
    add("special_chars", "Special characters", f["num_special_chars"], f["num_special_chars"] >= 6, 6, "An unusual number of special characters.")
    add("odd_port", "Non-standard port", f["nonstandard_port"], f["nonstandard_port"], 15, "Phishing kits are sometimes hosted on unusual ports.")
    add("punycode", "Punycode / look-alike characters", bool(f["has_punycode"]), f["has_punycode"], 20, "Internationalised domains can visually imitate real brands (homograph attack).")
    add("bad_tld", "Top-level domain", tld or "?", f["suspicious_tld"], 12, f".{tld} is frequently abused for throw-away phishing domains.")
    add("keywords", "Sensitive keywords in URL", f["keyword_count"], f["keyword_count"] >= 2, 10, "Words like login/verify/secure/update in the URL are common lures.")
    add("shortener", "URL shortener", bool(f["is_shortener"]), f["is_shortener"], 15, "Shorteners hide the true destination.")
    b = brand_mismatch(host)
    add("brand", "Brand impersonation", b or "none", bool(b), 30, f"Domain mentions '{b}' but is not an official {b} domain.")
    add("double_slash", "'//' inside path", bool(f["double_slash_in_path"]), f["double_slash_in_path"], 5, "Can indicate an embedded redirect.")
    add("https", "Uses HTTPS", bool(f["is_https"]), not f["is_https"], 8, "No transport encryption. (HTTPS alone does NOT make a site safe.)")
    return S


def registrable(host: str) -> str:
    return split_host(host)[0]
