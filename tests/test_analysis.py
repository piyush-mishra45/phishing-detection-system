"""URL features, risk engine, email analysis, HTML analysis. No network, no database."""
from app.services import email_analyzer, risk_engine
from app.services.url_features import FEATURE_NAMES, brand_mismatch, explain_url, extract_features, feature_vector
from app.services.website_analyzer import analyze_html, analyze_website


def test_feature_vector_shape_and_malformed_urls():
    for u in ["http://", "http://[bad", "////", "http://a:b:c", "x" * 500, "http://user@host:99999999/"]:
        assert len(feature_vector(u)) == len(FEATURE_NAMES)


def test_ip_and_at_symbol_detected():
    f = extract_features("http://192.0.2.5/login")
    assert f["has_ip_host"] == 1
    assert extract_features("http://paypal.com@evil.tk/x")["has_at"] == 1
    assert extract_features("https://www.python.org/")["has_at"] == 0


def test_brand_impersonation():
    assert brand_mismatch("paypa1-secure.tk") == "paypal"
    assert brand_mismatch("www.paypal.com") == ""
    assert brand_mismatch("login.microsoftonline.com") == ""


def test_legit_url_has_few_risk_signals():
    risky = [s for s in explain_url("https://www.python.org/downloads/") if s["status"] == "risk"]
    assert sum(s["points"] for s in risky) < 20


def test_risk_bands():
    assert risk_engine.risk_level(0) == "Low Risk" and risk_engine.risk_level(30) == "Low Risk"
    assert risk_engine.risk_level(31) == "Medium Risk" and risk_engine.risk_level(60) == "Medium Risk"
    assert risk_engine.risk_level(61) == "High Risk" and risk_engine.risk_level(80) == "High Risk"
    assert risk_engine.risk_level(81) == "Critical Risk" and risk_engine.risk_level(100) == "Critical Risk"


def test_unknown_checks_never_count_as_safe_or_risk():
    r = risk_engine.combine(None, [], unknown=["SSL"])
    assert r["risk_score"] == 0 and r["unknown_checks"] == ["SSL"] and r["model_confidence"] is None


def test_confidence_distinct_from_risk():
    r = risk_engine.combine(0.02, [{"id": "x", "status": "risk", "points": 40, "reason": "r"}])
    assert r["model_confidence"] == 0.98 and r["risk_score"] < 50  # confident it's legit by ML, but heuristics add risk


def test_phishing_email_flagged_and_legit_not():
    bad = email_analyzer.analyze_email("PayPal Support <help@paypa1-secure.tk>", "URGENT: verify your account", "Dear customer, your account has been suspended. Verify your account immediately: http://192.0.2.9/login")
    assert bad["prediction"] == "PHISHING" and bad["risk_score"] > 60 and bad["malicious_links"]
    good = email_analyzer.analyze_email("bob@corp.example", "Lunch", "Hi team, are we still on for lunch tomorrow at noon? Thanks, Bob")
    assert good["prediction"] == "LEGITIMATE"


def test_eml_parsing_and_header_auth():
    raw = (b"From: Bank <alerts@bank-secure.tk>\nReply-To: attacker@evil.example\nTo: you@example.com\nSubject: Verify now\n"
           b"Authentication-Results: mx; spf=fail; dkim=none\nContent-Type: text/html\n\n<a href='http://evil.tk/login'>http://bank.com/login</a> verify your account urgent")
    p = email_analyzer.parse_eml(raw)
    r = email_analyzer.analyze_email(p["from"], p["subject"], p["body"], p)
    ids = {s["id"] for s in r["signals"]}
    assert "auth_spf" in ids and "reply_to_mismatch" in ids
    assert any("DMARC" in u for u in r["unknown_checks"])  # missing => unknown, not 'pass'
    assert r["links"] and "leads to" in " ".join(r["links"][0]["reasons"])  # anchor text mismatch


def test_html_analysis_detects_credential_form_iframe_js():
    h = analyze_html("<title>PayPal</title><iframe src='http://x.biz' width=0 height=0></iframe><form action='http://c.tk/p' method=post><input type=password></form>"
                     "<script>eval(atob('x'));document.write('y')</script>", "http://paypal-login.tk/")
    assert h["credential_forms"] == 1 and h["hidden_iframes"] == 1 and "eval(" in h["suspicious_js"] and h["forms"][0]["posts_to_external_domain"]


def test_private_target_is_unknown_not_fetched():
    r = analyze_website("http://127.0.0.1/admin", do_domain_age=False)
    assert r["prediction"] == "UNKNOWN" and r["fetch"]["reachable"] is False


def test_unreachable_site_is_unknown_not_safe():
    r = analyze_website("https://this-domain-does-not-exist-xyz123.invalid/", do_domain_age=False)
    assert r["prediction"] in ("UNKNOWN", "SUSPICIOUS") and r["prediction"] != "SAFE"
    assert any("HTML" in u for u in r["unknown_checks"])
