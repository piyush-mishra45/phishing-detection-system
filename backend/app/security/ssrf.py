"""SSRF protection + safe HTTP fetching.

Defences:
  * only http/https, bounded URL length, no control characters
  * hostname is resolved and EVERY resolved address must be globally routable
    (blocks localhost, RFC1918, link-local/cloud-metadata 169.254.x, CGNAT, multicast, reserved, NAT64/6to4)
  * the connection is PINNED to the validated IP (prevents DNS-rebinding between check and use)
  * redirects are followed manually (max N) and every hop is re-validated
  * fetch only ports 80/443/8080/8443; body is size-capped; short timeouts; scripts are never executed
"""
import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

FETCHABLE_PORTS = {80, 443, 8080, 8443}
MAX_URL_LEN = 2048
_BLOCKED_NETS = [ipaddress.ip_network(n) for n in ("2002::/16", "64:ff9b::/96", "100.64.0.0/10", "192.0.0.0/24")]


def _allow_private() -> bool:
    """Test-only escape hatch so unit tests can talk to a localhost server. NEVER set in production."""
    return os.getenv("PHISHGUARD_ALLOW_PRIVATE_TARGETS") == "1"


class UnsafeURL(Exception):
    pass


def ip_is_blocked(ip) -> bool:
    ip = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if ip.version == 6 and ip.ipv4_mapped:
        return ip_is_blocked(ip.ipv4_mapped)
    if not ip.is_global:
        return True
    return any(ip in n for n in _BLOCKED_NETS if n.version == ip.version)


def parse_url(url: str) -> dict:
    """Validate syntax and return normalised parts. Raises UnsafeURL / ValueError."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL is required")
    url = url.strip()
    if len(url) > MAX_URL_LEN:
        raise ValueError("URL is too long (max 2048 characters)")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError("URL contains whitespace or control characters")
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ValueError("Malformed URL (invalid host or port)")
    if not host:
        raise ValueError("URL has no host")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid internationalised domain name")
    if len(ascii_host) > 253:
        raise ValueError("Hostname too long")
    return {"url": url, "scheme": parts.scheme, "host": ascii_host.lower(), "port": port or (443 if parts.scheme == "https" else 80),
            "explicit_port": port, "path": parts.path or "/", "query": parts.query}


def resolve_public(host: str, port: int) -> list:
    """Resolve host and require every address to be public. Returns list of IP strings."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeURL("Domain does not resolve")
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise UnsafeURL("Domain does not resolve")
    if not _allow_private():
        for ip in ips:
            if ip_is_blocked(ip):
                raise UnsafeURL("Target resolves to a private, local or otherwise non-public address")
    return ips


class _PinnedAdapter(HTTPAdapter):
    """Connects to an already-validated IP while keeping TLS SNI / cert checks bound to the real hostname."""

    def __init__(self, hostname, **kw):
        self._hostname = hostname
        super().__init__(**kw)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["server_hostname"] = self._hostname
        pool_kwargs["assert_hostname"] = self._hostname
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


@dataclass
class FetchResult:
    ok: bool = False
    final_url: str = ""
    status: int = 0
    html: str = ""
    truncated: bool = False
    content_type: str = ""
    chain: list = field(default_factory=list)  # [{url,status,ip,location}]
    error: str = ""
    blocked_redirect: bool = False
    resolved_ips: list = field(default_factory=list)


def safe_fetch(url: str, timeout=(3.05, 8), max_bytes=1_000_000, max_redirects=5) -> FetchResult:
    res = FetchResult()
    current = url
    for hop in range(max_redirects + 1):
        try:
            p = parse_url(current)
            if p["port"] not in FETCHABLE_PORTS and not _allow_private():
                res.error = f"Port {p['port']} is not fetched for safety"
                return res
            ips = resolve_public(p["host"], p["port"])
        except (UnsafeURL, ValueError) as e:
            res.error = str(e)
            res.blocked_redirect = hop > 0
            return res
        if hop == 0:
            res.resolved_ips = ips
        ip = ips[0]
        ip_lit = f"[{ip}]" if ":" in ip else ip
        default_port = 443 if p["scheme"] == "https" else 80
        netloc = ip_lit if p["port"] == default_port else f"{ip_lit}:{p['port']}"
        target = f"{p['scheme']}://{netloc}{p['path']}" + (f"?{p['query']}" if p["query"] else "")
        host_hdr = p["host"] if p["port"] == default_port else f"{p['host']}:{p['port']}"
        sess = requests.Session()
        sess.trust_env = False  # ignore proxy env vars
        sess.mount("https://", _PinnedAdapter(p["host"]))
        headers = {"Host": host_hdr, "User-Agent": "PhishGuardScanner/1.0 (+safe-analysis)", "Accept": "text/html,*/*;q=0.5",
                   "Accept-Encoding": "gzip, deflate"}
        try:
            r = sess.get(target, headers=headers, timeout=timeout, allow_redirects=False, stream=True)
        except requests.exceptions.SSLError as e:
            res.error = "TLS/certificate error while connecting"
            res.chain.append({"url": current, "status": 0, "ip": ip, "location": ""})
            return res
        except requests.exceptions.Timeout:
            res.error = "Connection timed out"
            return res
        except requests.exceptions.RequestException as e:
            res.error = f"Connection failed ({type(e).__name__})"
            return res
        loc = r.headers.get("Location", "")
        res.chain.append({"url": current, "status": r.status_code, "ip": ip, "location": loc})
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            r.close()
            current = urljoin(current, loc)
            continue
        ctype = r.headers.get("Content-Type", "")
        res.status, res.final_url, res.content_type = r.status_code, current, ctype
        if "html" in ctype.lower() or "text" in ctype.lower() or not ctype:
            buf, size = [], 0
            try:
                for chunk in r.iter_content(8192):
                    size += len(chunk)
                    if size > max_bytes:
                        res.truncated = True
                        buf.append(chunk[: max(0, len(chunk) - (size - max_bytes))])
                        break
                    buf.append(chunk)
            except requests.exceptions.RequestException:
                res.error = "Connection dropped while reading the page"
            r.close()
            res.html = b"".join(buf).decode(r.encoding or "utf-8", errors="replace")
        else:
            r.close()
        res.ok = True
        return res
    res.error = f"Too many redirects (>{max_redirects})"
    return res


def tls_inspect(host: str, ip: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Read the certificate from an already validated IP. No data is sent beyond the TLS handshake."""
    import ssl
    from datetime import datetime, timezone
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                proto = s.version()
    except ssl.SSLCertVerificationError as e:
        return {"status": "invalid", "error": e.verify_message or "certificate verification failed"}
    except (OSError, ssl.SSLError) as e:
        return {"status": "unknown", "error": f"Could not complete TLS handshake ({type(e).__name__})"}
    d = lambda t: dict(x[0] for x in t)
    nb = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    na = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    now = datetime.now(timezone.utc)
    return {"status": "valid", "issuer": d(cert.get("issuer", ())).get("organizationName") or d(cert.get("issuer", ())).get("commonName", "unknown"),
            "subject": d(cert.get("subject", ())).get("commonName", ""), "protocol": proto,
            "valid_from": nb.date().isoformat(), "valid_to": na.date().isoformat(),
            "days_remaining": (na - now).days, "cert_age_days": (now - nb).days,
            "san_count": len(cert.get("subjectAltName", ()))}
