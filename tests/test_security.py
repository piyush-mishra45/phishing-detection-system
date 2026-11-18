"""SSRF / validation / CSV-injection tests (no database needed)."""
import pytest

from app.security import ssrf
from app.security.validators import ValidationError, csv_safe, redact_excerpt, validate_email_addr, validate_password

BLOCKED = ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.5/",
           "http://[::1]/", "http://0.0.0.0/", "http://2130706433/", "http://0x7f.1/", "http://[::ffff:127.0.0.1]/", "http://100.64.0.1/"]


@pytest.mark.parametrize("url", BLOCKED)
def test_private_targets_blocked(url):
    p = ssrf.parse_url(url)
    with pytest.raises(ssrf.UnsafeURL):
        ssrf.resolve_public(p["host"], p["port"])


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "http://a b.com", "", "http://" + "a" * 3000 + ".com", "gopher://x.com"])
def test_malformed_or_unsafe_scheme_rejected(url):
    with pytest.raises(ValueError):
        ssrf.parse_url(url)


def test_safe_fetch_refuses_localhost_by_default():
    r = ssrf.safe_fetch("http://127.0.0.1:80/")
    assert not r.ok and r.error


def test_unresolvable_domain():
    r = ssrf.safe_fetch("http://this-domain-does-not-exist-xyz123.invalid/")
    assert not r.ok


def test_password_policy():
    for bad in ("short1A", "alllowercase1234", "ALLUPPERCASE1234", "NoDigitsHereAtAll"):
        with pytest.raises(ValidationError):
            validate_password(bad)
    assert validate_password("Str0ngPassw0rd!")


def test_email_validation():
    assert validate_email_addr("A@b.co") == "a@b.co"
    with pytest.raises(ValidationError):
        validate_email_addr("not-an-email")


def test_csv_injection_neutralised():
    assert csv_safe("=HYPERLINK(\"http://evil\")").startswith("'")
    assert csv_safe("+1+1").startswith("'") and csv_safe("@cmd").startswith("'") and csv_safe("normal") == "normal"


def test_pii_redacted_from_stored_excerpt():
    t = redact_excerpt("Contact bob@example.com or +1 (555) 123-4567 now")
    assert "bob@example.com" not in t and "555" not in t
