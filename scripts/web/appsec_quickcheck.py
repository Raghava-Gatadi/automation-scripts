#!/usr/bin/env python3
"""Baseline HTTP security checks, using only the Python standard library.

Only scan systems you own or are authorized to test. Exit codes: 0 below the
severity threshold, 1 findings at/above it, 2 invalid input or incomplete scan.
"""
import argparse
import base64
import binascii
from dataclasses import dataclass, field
import datetime as dt
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
from urllib.parse import urljoin, urlsplit, urlunsplit

SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
UA = "appsec-quickcheck/2.0"
REDIRECTS = {301, 302, 303, 307, 308}
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
REFERRER_POLICIES = {"no-referrer", "no-referrer-when-downgrade", "origin",
                     "origin-when-cross-origin", "same-origin", "strict-origin",
                     "strict-origin-when-cross-origin", "unsafe-url"}


def normalize_url(value):
    """Validate before network access; reject userinfo and ambiguous host syntax."""
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("URL must not contain whitespace, control characters, or backslashes")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if ":" in host:
            host = "[" + ipaddress.IPv6Address(host).compressed + "]"
        elif not re.fullmatch(r"[a-z0-9.-]+", host):
            raise ValueError()
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        authority = host + (f":{port}" if port is not None else "")
        # http.client requires an ASCII request target; percent-encode other paths.
        (parsed.path + parsed.query).encode("ascii")
        return urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Use a valid HTTP(S) URL without embedded credentials; percent-encode non-ASCII paths") from exc


def safe_url(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       "[REDACTED]" if parsed.query else "", ""))


def header_map(headers):
    result = {}
    for name, value in headers:
        result.setdefault(name.lower(), []).append(value.strip())
    return result


def check_cookies(headers, https=True):
    findings = []
    for number, cookie in enumerate(header_map(headers).get("set-cookie", []), 1):
        parts = cookie.split(";")
        name, separator, _ = parts[0].strip().partition("=")
        label = f"Cookie #{number}"
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            findings.append(("MEDIUM", "cookie-format", f"{label}: malformed Set-Cookie"))
            continue
        attributes = {}
        duplicate = False
        for part in parts[1:]:
            key, _, value = part.strip().partition("=")
            key = key.lower()
            duplicate |= key in attributes
            if key:
                attributes[key] = value.strip()
        if duplicate:
            findings.append(("LOW", "cookie-attributes", f"{label}: duplicate attributes; review browser interpretation"))
        missing = [key for key in ("secure", "httponly", "samesite") if key not in attributes]
        if missing:
            findings.append(("MEDIUM", "cookie", f"{label}: missing {', '.join(missing)}; assess the cookie's purpose"))
        same_site = attributes.get("samesite", "").lower()
        if "samesite" in attributes and same_site not in {"strict", "lax", "none"}:
            findings.append(("MEDIUM", "cookie-samesite", f"{label}: invalid SameSite value"))
        if same_site == "none" and "secure" not in attributes:
            findings.append(("MEDIUM", "cookie-samesite", f"{label}: SameSite=None requires Secure"))
        if "partitioned" in attributes and "secure" not in attributes:
            findings.append(("MEDIUM", "cookie-partitioned", f"{label}: Partitioned requires Secure"))
        prefixed = name.startswith(("__Secure-", "__Host-", "__Http-"))
        if prefixed and ("secure" not in attributes or not https):
            findings.append(("MEDIUM", "cookie-prefix", f"{label}: prefix requires Secure and an HTTPS origin"))
        if name.startswith("__Host-") and ("domain" in attributes or attributes.get("path") != "/"):
            findings.append(("MEDIUM", "cookie-prefix", f"{label}: __Host- requires Path=/ and no Domain"))
        if name.startswith(("__Http-", "__Host-Http-")) and "httponly" not in attributes:
            findings.append(("MEDIUM", "cookie-prefix", f"{label}: HTTP-only prefix requires HttpOnly"))
    return findings


def parse_policy(value):
    directives = {}
    for part in value.split(";"):
        words = part.split()
        if words:
            directives.setdefault(words[0].lower(), words[1:])
    return directives


def has_nonce_or_hash(sources):
    for source in sources:
        match = re.fullmatch(r"'(nonce|sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})'", source)
        if not match:
            continue
        kind, value = match.groups()
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            continue
        if (kind == "nonce" and decoded) or len(decoded) == {"sha256": 32, "sha384": 48, "sha512": 64}.get(kind):
            return True
    return False


def check_csp(values):
    """Heuristics, not a complete CSP parser or multi-policy intersection evaluator."""
    findings, frame_protected = [], False
    policies = [parse_policy(policy) for value in values for policy in value.split(",") if policy.strip()]
    for number, policy in enumerate(policies, 1):
        ancestors = policy.get("frame-ancestors", [])
        recognized = all(source in {"'none'", "'self'"} or
                         re.fullmatch(r"(?:https?://)?(?:\*\.)?[A-Za-z0-9.-]+(?::[0-9]+)?/?", source)
                         for source in ancestors)
        if ancestors and recognized and not ("'none'" in ancestors and len(ancestors) > 1):
            frame_protected = True
        script = policy.get("script-src", policy.get("default-src"))
        elements = policy.get("script-src-elem", script)
        attrs = policy.get("script-src-attr", script)
        label = f"CSP policy {number}"
        if elements is None or attrs is None:
            findings.append(("MEDIUM", "weak-csp", f"{label}: no effective restriction for some script execution; review combined policies"))
        for sources in (elements, attrs):
            if sources is None:
                continue
            nonce_or_hash = has_nonce_or_hash(sources)
            if "'unsafe-inline'" in sources and not nonce_or_hash:
                findings.append(("MEDIUM", "weak-csp", f"{label}: unsafe-inline without a nonce/hash; review combined policies"))
        if script and "'unsafe-eval'" in script:
            findings.append(("MEDIUM", "weak-csp", f"{label}: unsafe-eval; review combined policies"))
        dynamic = elements and "'strict-dynamic'" in elements and has_nonce_or_hash(elements)
        if elements and not dynamic and any(source in {"*", "http:", "https:", "data:"} for source in elements):
            findings.append(("MEDIUM", "weak-csp", f"{label}: broad script sources; review combined policies"))
    return list(dict.fromkeys(findings)), frame_protected


def check_headers(headers, https=True, document=None, terminal=True):
    findings = check_cookies(headers, https)
    h = header_map(headers)
    if document is None:
        content_type = h.get("content-type", [""])[0].split(";", 1)[0].lower()
        document = not content_type or content_type in {"text/html", "application/xhtml+xml"}
    hsts = h.get("strict-transport-security", [])
    if https:
        if not hsts or not hsts[0]:
            findings.append(("HIGH", "missing-header", "strict-transport-security: configure HSTS after confirming HTTPS coverage"))
        else:
            ages = [part.partition("=")[2].strip() for part in hsts[0].split(";")
                    if part.partition("=")[0].strip().lower() == "max-age"]
            if len(hsts) > 1 or len(ages) != 1 or not re.fullmatch(r'(?:[0-9]+|"[0-9]+")', ages[0]):
                findings.append(("MEDIUM", "invalid-hsts", "HSTS has duplicate or invalid max-age/header values"))
            else:
                digits = ages[0].strip('"').lstrip("0") or "0"
                age = int(digits) if len(digits) < 12 else 31536000
                if age == 0:
                    findings.append(("HIGH", "weak-hsts", "HSTS max-age=0 disables the policy"))
                elif age < 15552000:
                    findings.append(("LOW", "weak-hsts", "HSTS max-age is shorter than 180 days"))
    elif hsts:
        findings.append(("LOW", "hsts-http", "HSTS delivered over HTTP is ignored by browsers"))
    for name in LEAKY_HEADERS:
        if name in h and (name != "server" or any(re.search(r"\d", v) for v in h[name])):
            findings.append(("LOW", "info-leak", f"{name}: implementation information is exposed"))
    origins = h.get("access-control-allow-origin", [])
    credentials = h.get("access-control-allow-credentials", [])
    if origins == ["*"] and credentials == ["true"]:
        findings.append(("MEDIUM", "cors", "Wildcard origin with credentials is rejected by browsers; this alone does not prove data exposure"))
    if len(origins) > 1 or len(credentials) > 1:
        findings.append(("MEDIUM", "cors", "Duplicate CORS response headers may be rejected by browsers"))
    if origins == ["null"] and credentials == ["true"]:
        findings.append(("MEDIUM", "cors", "Credentialed null-origin access: review whether untrusted opaque origins can read sensitive data"))
    if not terminal:
        return findings
    if [value.lower() for value in h.get("x-content-type-options", [])] != ["nosniff"]:
        findings.append(("LOW", "content-type-options", "Set one X-Content-Type-Options header to nosniff"))
    if document:
        policies = h.get("content-security-policy", [])
        if not any(value.strip() for value in policies):
            detail = "Missing enforced Content-Security-Policy"
            if "content-security-policy-report-only" in h:
                detail += "; Report-Only does not enforce restrictions"
            findings.append(("MEDIUM", "missing-header", detail))
        csp_findings, frame_protected = check_csp(policies)
        findings.extend(csp_findings)
        xfo = h.get("x-frame-options", [])
        valid_xfo = len(xfo) == 1 and xfo[0].upper() in {"DENY", "SAMEORIGIN"}
        if xfo and not valid_xfo:
            findings.append(("MEDIUM", "invalid-xfo", "X-Frame-Options must be a single DENY or SAMEORIGIN value"))
        if not frame_protected and not valid_xfo:
            findings.append(("MEDIUM", "clickjacking", "No recognized restrictive frame-ancestors or valid X-Frame-Options"))
        referrers = [item.strip().lower() for value in h.get("referrer-policy", []) for item in value.split(",")]
        valid = [item for item in referrers if item in REFERRER_POLICIES]
        if not valid:
            findings.append(("LOW", "referrer-policy", "Set an explicit valid Referrer-Policy"))
        elif valid[-1] in {"unsafe-url", "no-referrer-when-downgrade"}:
            findings.append(("LOW", "referrer-policy", "Referrer-Policy may disclose path/query information cross-origin"))
        if not any(h.get("permissions-policy", [])):
            findings.append(("LOW", "missing-header", "permissions-policy: restrict browser features according to application needs"))
    return findings


def check_tls(cert, protocol, now=None):
    """Assess metadata from the same verified TLS connection used for the request."""
    findings = []
    now = dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now
    try:
        remaining = (ssl.cert_time_to_seconds(cert["notAfter"]) - now) / 86400
        if remaining <= 0:
            findings.append(("HIGH", "tls-cert", "Certificate has expired"))
        else:
            sev = "HIGH" if remaining < 14 else "MEDIUM" if remaining < 30 else "INFO"
            findings.append((sev, "tls-cert", f"Certificate expires in {remaining:.1f} days"))
        if "notBefore" in cert and ssl.cert_time_to_seconds(cert["notBefore"]) > now:
            findings.append(("HIGH", "tls-cert", "Certificate is not yet valid"))
    except (KeyError, ValueError, OverflowError):
        findings.append(("MEDIUM", "tls-cert", "Certificate validity metadata could not be evaluated"))
    if protocol in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
        findings.append(("HIGH", "tls-protocol", "A deprecated TLS/SSL protocol was negotiated"))
    else:
        findings.append(("INFO", "tls-protocol", f"Negotiated {protocol or 'unknown protocol'}; older protocol support was not tested"))
    return findings


@dataclass
class Response:
    url: str
    status: int
    headers: list
    tls: list = field(default_factory=list)


@dataclass
class FetchResult:
    responses: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    complete: bool = True


def request_once(url, timeout):
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=timeout,
                                            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        conn.connect()
        tls = check_tls(conn.sock.getpeercert(), conn.sock.version()) if parsed.scheme == "https" else []
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*", "Connection": "close"})
        response = conn.getresponse()
        return Response(url, response.status, response.getheaders(), tls)
    finally:
        conn.close()


def fetch(url, timeout, max_redirects=5, allowed_hosts=()):
    result, visited = FetchResult(), set()
    allowed = {urlsplit(url).hostname, *allowed_hosts}
    for hop in range(max_redirects + 1):
        if url in visited:
            result.findings.append(("MEDIUM", "redirect-loop", "Redirect loop detected"))
            result.complete = False
            break
        visited.add(url)
        try:
            response = request_once(url, timeout)
        except ssl.SSLCertVerificationError:
            result.findings.append(("HIGH", "tls-cert", "TLS certificate/hostname verification failed; request stopped"))
            result.complete = False
            break
        except (OSError, http.client.HTTPException, ValueError):
            result.findings.append(("MEDIUM", "connect", "Request failed (network, TLS, timeout, or invalid HTTP response)"))
            result.complete = False
            break
        result.responses.append(response)
        if response.status not in REDIRECTS:
            break
        locations = header_map(response.headers).get("location", [])
        if len(locations) != 1 or not locations[0]:
            result.findings.append(("MEDIUM", "redirect-location", "Redirect has missing, empty, or multiple Location headers"))
            result.complete = False
            break
        try:
            destination = normalize_url(urljoin(url, locations[0]))
        except ValueError:
            result.findings.append(("MEDIUM", "redirect-location", "Redirect destination is not a supported HTTP(S) URL"))
            result.complete = False
            break
        if urlsplit(url).scheme == "https" and urlsplit(destination).scheme == "http":
            result.findings.append(("HIGH", "https-downgrade", "HTTPS redirects to HTTP; downgrade was not followed"))
            result.complete = False
            break
        if urlsplit(destination).hostname not in allowed:
            result.findings.append(("INFO", "redirect-scope", "Redirect leaves allowed hosts; destination was not requested (use --allow-host if authorized)"))
            result.complete = False
            break
        if hop == max_redirects:
            result.findings.append(("MEDIUM", "redirect-limit", "Maximum redirect count reached"))
            result.complete = False
            break
        url = destination
    return result


def check_redirect(url, timeout, port=80):
    """Probe HTTP once; never replay the HTTPS URL's path or query over plaintext."""
    host = urlsplit(url).hostname
    authority = f"[{host}]" if ":" in host else host
    probe = f"http://{authority}:{port}/"
    try:
        response = request_once(probe, timeout)
    except ConnectionRefusedError:
        return [("INFO", "http-redirect", "HTTP connection refused; no redirect response to inspect")], True
    except (OSError, http.client.HTTPException, ValueError):
        return [("MEDIUM", "http-redirect", "HTTP redirect probe failed; redirect behavior is unknown")], False
    findings = check_cookies(response.headers, https=False)
    locations = header_map(response.headers).get("location", [])
    try:
        destination = normalize_url(urljoin(probe, locations[0])) if len(locations) == 1 and locations[0] else None
    except ValueError:
        destination = None
    if response.status in REDIRECTS and destination and urlsplit(destination).scheme == "https":
        findings.append(("INFO", "http-redirect", "HTTP root redirects directly to HTTPS; destination was not probed"))
    else:
        findings.append(("MEDIUM", "http-redirect", "HTTP root does not redirect directly to HTTPS"))
    return findings, True


def scan(target, timeout=8.0, max_redirects=5, allowed_hosts=(), http_probe=True, http_port=80):
    url = normalize_url(target)
    fetched = fetch(url, timeout, max_redirects, allowed_hosts)
    findings = [{"severity": s, "check": c, "detail": d} for s, c, d in fetched.findings]
    for number, response in enumerate(fetched.responses):
        parsed = urlsplit(response.url)
        checks = [("INFO", "response", f"HTTP status {response.status}")]
        if response.status >= 400:
            checks.append(("INFO", "response-scope", "Error response inspected; application pages may use different policies"))
        if parsed.scheme == "http":
            final_http = number == len(fetched.responses) - 1 and response.status not in REDIRECTS
            checks.append(("HIGH" if final_http else "LOW", "transport", "Response received over plaintext HTTP"))
        checks += check_headers(response.headers, https=parsed.scheme == "https",
                                terminal=response.status not in REDIRECTS)
        checks += response.tls
        findings.extend({"severity": s, "check": c, "detail": d, "url": safe_url(response.url)} for s, c, d in checks)
    if http_probe and urlsplit(url).scheme == "https":
        checks, probe_complete = check_redirect(url, timeout, http_port)
        fetched.complete &= probe_complete
        findings.extend({"severity": s, "check": c, "detail": d, "scope": "http-root-probe"} for s, c, d in checks)
    findings.sort(key=lambda f: -SEVERITY[f["severity"]])
    return {"target": safe_url(url), "complete": fetched.complete,
            "responses_checked": len(fetched.responses), "findings": findings}


def write_report(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".appsec-report-", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="*", help="HTTP(S) URLs or hostnames")
    parser.add_argument("-f", "--file", help="UTF-8 file with one target per line")
    parser.add_argument("--json", metavar="PATH", help="Write an atomic JSON report (schema version 2)")
    parser.add_argument("--fail-on", default="HIGH", choices=SEVERITY)
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout per socket operation in seconds")
    parser.add_argument("--max-redirects", type=int, default=5)
    parser.add_argument("--allow-host", action="append", default=[], help="Additional authorized redirect hostname; repeatable")
    parser.add_argument("--no-http-probe", action="store_true", help="Skip the extra HTTP root request for HTTPS targets")
    parser.add_argument("--http-port", type=int, default=80, help="Port for the extra HTTP root probe")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not 0 <= args.max_redirects <= 50 or not 1 <= args.http_port <= 65535:
        parser.error("timeout must be positive and finite, max redirects 0..50, and HTTP port 1..65535")
    try:
        targets = list(args.urls)
        if args.file:
            targets.extend(line.strip() for line in Path(args.file).read_text(encoding="utf-8").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
        if not targets:
            parser.error("no targets given")
        targets = list(dict.fromkeys(normalize_url(target) for target in targets))
        allowed = set()
        for value in args.allow_host:
            parsed = urlsplit(normalize_url(value))
            if parsed.path != "/" or parsed.query or parsed.port or "://" in value:
                raise ValueError("--allow-host requires a hostname only")
            allowed.add(parsed.hostname)
        report_path = Path(args.json).absolute() if args.json else None
        protected = {Path(__file__).resolve()}
        if args.file:
            protected.add(Path(args.file).resolve())
        if report_path and report_path.resolve() in protected:
            raise ValueError("Report must not overwrite the script or targets file")
    except (OSError, UnicodeError, ValueError):
        print("Error: invalid URL, allow-host, input file, or report destination; no targets scanned.", file=sys.stderr)
        return 2
    results = []
    for target in targets:
        result = scan(target, args.timeout, args.max_redirects, allowed, not args.no_http_probe, args.http_port)
        results.append(result)
        print(f'\n=== {json.dumps(result["target"])} ===')
        for finding in result["findings"]:
            location = " (" + json.dumps(finding["url"]) + ")" if "url" in finding else ""
            print(f'[{finding["severity"]}] {finding["check"]}: {finding["detail"]}{location}')
        print("Scan complete." if result["complete"] else "Scan incomplete; inspect findings and redirect scope.")
    if report_path:
        try:
            write_report(report_path, {"schema_version": 2, "generated": dt.datetime.now(dt.timezone.utc).isoformat(), "results": results})
        except OSError:
            print("Error: could not write JSON report.", file=sys.stderr)
            return 2
    if any(not result["complete"] for result in results):
        return 2
    worst = max((SEVERITY[f["severity"]] for result in results for f in result["findings"]), default=-1)
    return 1 if worst >= SEVERITY[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
