#!/usr/bin/env python3
"""
appsec_quickcheck.py - fast baseline web security checks (stdlib only).

Checks per URL:
  * HTTP -> HTTPS redirect
  * Security headers (HSTS, CSP, XCTO, clickjacking, Referrer-Policy, Permissions-Policy)
  * Information-leak headers (Server version, X-Powered-By, ...)
  * Cookie flags (Secure, HttpOnly, SameSite)
  * TLS certificate validity / expiry / protocol version

Usage:
  python3 appsec_quickcheck.py https://example.com
  python3 appsec_quickcheck.py -f targets.txt --json report.json --fail-on MEDIUM

Exit code is 1 if any finding >= --fail-on (default HIGH), so it can gate CI.

ONLY scan systems you own or are explicitly authorized to test.
"""
import argparse
import datetime as dt
import http.client
import json
import re
import socket
import ssl
import sys
from urllib.parse import urljoin, urlparse

SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
UA = "appsec-quickcheck/1.0"

# header -> (severity if missing, advice)
REQUIRED_HEADERS = {
    "strict-transport-security": ("HIGH", "Add HSTS, e.g. max-age=31536000; includeSubDomains"),
    "content-security-policy": ("MEDIUM", "Define a CSP to mitigate XSS/injection"),
    "x-content-type-options": ("LOW", "Set to 'nosniff'"),
    "referrer-policy": ("LOW", "Set e.g. 'strict-origin-when-cross-origin'"),
    "permissions-policy": ("LOW", "Restrict powerful browser features"),
}
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def fetch(url, timeout, max_redirects=5, follow=True):
    """GET a URL without auto-redirects; returns (final_url, status, headers[list of tuples])."""
    for _ in range(max_redirects + 1):
        p = urlparse(url)
        conn_cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(p.hostname, p.port, timeout=timeout)
        try:
            path = (p.path or "/") + (f"?{p.query}" if p.query else "")
            conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
            r = conn.getresponse()
            headers = r.getheaders()
            loc = r.getheader("Location")
            if follow and r.status in (301, 302, 303, 307, 308) and loc:
                url = urljoin(url, loc)
                continue
            return url, r.status, headers
        finally:
            conn.close()
    return url, 0, []


def check_redirect(host, port, timeout):
    """Does plain HTTP redirect to HTTPS?"""
    out = []
    try:
        _, status, headers = fetch(f"http://{host}{':' + str(port) if port else ''}/",
                                   timeout, follow=False)
        loc = dict((k.lower(), v) for k, v in headers).get("location", "")
        if not (status in (301, 302, 307, 308) and loc.startswith("https://")):
            out.append(("MEDIUM", "http-redirect", "HTTP does not redirect to HTTPS"))
    except Exception:
        pass  # port 80 closed is fine
    return out


def check_headers(headers):
    out = []
    h = {}
    for k, v in headers:
        h.setdefault(k.lower(), []).append(v)

    for name, (sev, advice) in REQUIRED_HEADERS.items():
        if name not in h:
            out.append((sev, "missing-header", f"{name}: {advice}"))

    # Clickjacking: XFO or CSP frame-ancestors
    csp = " ".join(h.get("content-security-policy", [])).lower()
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(("MEDIUM", "missing-header", "Clickjacking protection: X-Frame-Options or CSP frame-ancestors"))

    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        out.append(("MEDIUM", "weak-csp", "CSP allows 'unsafe-inline' / 'unsafe-eval'"))

    hsts = " ".join(h.get("strict-transport-security", []))
    m = re.search(r"max-age=(\d+)", hsts, re.I)
    if hsts and (not m or int(m.group(1)) < 15552000):
        out.append(("LOW", "weak-hsts", f"HSTS max-age too short (<180 days): {hsts}"))

    for name in LEAKY_HEADERS:
        if name in h:
            val = h[name][0]
            if re.search(r"\d", val) or name != "server":
                out.append(("LOW", "info-leak", f"{name}: {val}"))

    # CORS
    if "*" in h.get("access-control-allow-origin", []) and \
       "true" in [v.lower() for v in h.get("access-control-allow-credentials", [])]:
        out.append(("HIGH", "cors", "ACAO: * combined with Allow-Credentials: true"))

    # Cookies
    for c in h.get("set-cookie", []):
        name = c.split("=", 1)[0]
        low = c.lower()
        problems = []
        if "secure" not in low:
            problems.append("Secure")
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            out.append(("MEDIUM", "cookie", f"Cookie '{name}' missing: {', '.join(problems)}"))
    return out


def check_tls(host, port, timeout):
    out = []
    port = port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                proto = s.version()
                exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days = (exp - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).days
                if days < 0:
                    out.append(("HIGH", "tls-cert", f"Certificate EXPIRED {-days} days ago"))
                elif days < 14:
                    out.append(("HIGH", "tls-cert", f"Certificate expires in {days} days"))
                elif days < 30:
                    out.append(("MEDIUM", "tls-cert", f"Certificate expires in {days} days"))
                else:
                    out.append(("INFO", "tls-cert", f"Certificate valid for {days} more days ({proto})"))
                if proto in ("TLSv1", "TLSv1.1"):
                    out.append(("HIGH", "tls-protocol", f"Deprecated protocol negotiated: {proto}"))
    except ssl.SSLCertVerificationError as e:
        out.append(("HIGH", "tls-cert", f"Certificate verification failed: {e.verify_message}"))
    except Exception as e:
        out.append(("MEDIUM", "tls", f"TLS check failed: {e}"))
    return out


def scan(target, timeout):
    if "://" not in target:
        target = "https://" + target
    p = urlparse(target)
    findings = []
    try:
        final_url, status, headers = fetch(target, timeout)
    except Exception as e:
        return [("HIGH", "connect", f"Request failed: {e}")]

    findings.append(("INFO", "response", f"{status} at {final_url}"))
    findings += check_headers(headers)
    if p.scheme == "https":
        findings += check_tls(p.hostname, p.port, timeout)
        findings += check_redirect(p.hostname, None, timeout)
    else:
        findings.append(("HIGH", "transport", "Target is served over plain HTTP"))
    return findings


def main():
    ap = argparse.ArgumentParser(description="Baseline web security checks.")
    ap.add_argument("urls", nargs="*", help="URLs or hostnames")
    ap.add_argument("-f", "--file", help="File with one target per line")
    ap.add_argument("--json", metavar="PATH", help="Write JSON report to PATH")
    ap.add_argument("--fail-on", default="HIGH", choices=SEVERITY, help="Exit 1 at/above this severity")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    targets = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("no targets given")

    report, worst = {}, 0
    for t in targets:
        results = sorted(scan(t, args.timeout), key=lambda f: -SEVERITY[f[0]])
        report[t] = [{"severity": s, "check": c, "detail": d} for s, c, d in results]
        print(f"\n=== {t} ===")
        for s, c, d in results:
            print(f"  [{s:<6}] {c:<15} {d}")
            worst = max(worst, SEVERITY[s])

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"generated": dt.datetime.now(dt.timezone.utc).isoformat(), "results": report}, fh, indent=2)
        print(f"\nJSON report written to {args.json}")

    sys.exit(1 if worst >= SEVERITY[args.fail_on] else 0)


if __name__ == "__main__":
    main()
