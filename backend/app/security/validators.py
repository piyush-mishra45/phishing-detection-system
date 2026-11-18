import re

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,50}$")


class ValidationError(Exception):
    def __init__(self, message, field=None):
        super().__init__(message)
        self.message, self.field = message, field


def require_str(data, key, max_len, required=True, min_len=0):
    v = data.get(key, "")
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise ValidationError(f"{key} must be a string", key)
    v = v.strip()
    if required and not v:
        raise ValidationError(f"{key} is required", key)
    if len(v) > max_len:
        raise ValidationError(f"{key} must be at most {max_len} characters", key)
    if v and len(v) < min_len:
        raise ValidationError(f"{key} must be at least {min_len} characters", key)
    return v


def validate_email_addr(v, key="email", required=True):
    if not v and not required:
        return ""
    if len(v) > 254 or not EMAIL_RE.match(v):
        raise ValidationError("Invalid email address", key)
    return v.lower()


def validate_password(pw):
    if not isinstance(pw, str) or len(pw) < 10 or len(pw) > 128:
        raise ValidationError("Password must be 10-128 characters", "password")
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)):
        raise ValidationError("Password needs upper-case, lower-case and a digit", "password")
    return pw


def csv_safe(v):
    """Neutralise CSV/Excel formula injection."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


_EMAIL_PII = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_PII = re.compile(r"\+?\d[\d\s().\-]{8,}\d")


def redact_excerpt(text: str, n: int = 500) -> str:
    """Short excerpt with e-mail addresses and phone numbers removed (privacy-minimising storage)."""
    t = _EMAIL_PII.sub("[email]", text[: n * 2])
    t = _PHONE_PII.sub("[number]", t)
    return t[:n]
