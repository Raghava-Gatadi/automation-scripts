#!/usr/bin/env python3
"""First-look exposed Git, environment and backup file checks for your own assets.

GETs a short fixed path list, reads at most 4096 bytes per response, and never
prints file contents. Exit: 0 no candidates, 1 candidates, 2 incomplete/error.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

READ_LIMIT = 4096
PATHS = (("/.git/HEAD", "git-head"), ("/.git/config", "git-config"), ("/.git/", "git-index"),
         ("/.env", "env"), ("/.env.local", "env"), ("/.env.bak", "env"),
         ("/backup.zip", "zip"), ("/backup.tar.gz", "gzip"), ("/backup.sql", "sql"),
         ("/config.php.bak", "php"), ("/.aws/credentials", "aws"), ("/.npmrc", "npm"),
         ("/.htpasswd", "htpasswd"), ("/id_rsa", "private-key"), ("/.ssh/id_rsa", "private-key"),
         ("/.svn/wc.db", "sqlite"), ("/wp-config.php.bak", "php"), ("/wp-config.php~", "php"),
         ("/site.zip", "zip"), ("/dump.sql", "sql"), ("/actuator/env", "actuator"),
         ("/phpinfo.php", "phpinfo"), ("/server-status", "apache"),
         ("/docker-compose.yml", "compose"), ("/.DS_Store", "ds-store"))
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def severity(kind):
    return "LOW" if kind == "ds-store" else "MEDIUM" if kind in {"actuator", "phpinfo", "apache", "compose"} else "HIGH"


def origin(value):
    value = value.strip()
    if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        raise ValueError("Invalid URL")
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or
            parsed.username is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("Use an HTTP(S) origin without credentials, path, query or fragment")
    host = parsed.hostname.encode("idna").decode("ascii").lower().removesuffix(".")
    if ":" in host:
        host = "[" + ipaddress.IPv6Address(host).compressed + "]"
    elif not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host) or any(
            len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")) or len(host) > 253:
        raise ValueError("Invalid hostname")
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return parsed.scheme + "://" + host + (f":{port}" if port is not None else "")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def fetch(opener, url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "sensitive-files-quickcheck/1.0",
        "Range": f"bytes=0-{READ_LIMIT - 1}", "Accept-Encoding": "identity"})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        code = response.code
        if code == 206 and not re.fullmatch(r"bytes 0-[0-9]+/(?:[0-9]+|\*)", response.headers.get("Content-Range", "")):
            raise ValueError("Unexpected partial content range")
        # Only successful response bodies can establish a candidate. Do not read
        # login redirects, denied pages or server diagnostics into the scanner.
        body = response.read(READ_LIMIT) if code in (200, 206) else b""
        return {"code": code, "body": body,
                "type": response.headers.get("Content-Type", "").lower(),
                "encoding": response.headers.get("Content-Encoding", "identity").lower()}


def evidence(kind, body, content_type):
    """Return a fixed explanation, never values or excerpts from the response."""
    text = body.decode("utf-8", errors="replace")
    html = "html" in content_type or bool(re.search(r"<!doctype\s+html|<html\b", text[:512], re.I))
    if kind == "git-index":
        if re.search(r"Index of\s+/\.git/?", text, re.I) and re.search(r"href=[\"'](?:HEAD|config|objects/)", text, re.I):
            return "Git directory listing markers"
        return None
    if kind in {"git-head", "git-config", "env", "sql", "php", "aws", "npm", "htpasswd", "private-key", "compose", "actuator"} and (html or b"\0" in body):
        return None
    if kind == "git-head" and re.fullmatch(r"(?:ref: refs/[^\s]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", text.strip()):
        return "Git HEAD structure"
    if kind == "git-config" and re.search(r"^\s*\[core\]\s*$", text, re.M) and re.search(r"^\s*repositoryformatversion\s*=", text, re.M | re.I):
        return "Git repository configuration structure"
    if kind == "env":
        for line in text.splitlines():
            match = re.fullmatch(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*", line)
            if match and re.search(r"secret|password|passwd|token|api_?key|database_url|private_key", match[1], re.I):
                if match[2].strip() not in {'""', "''"}:
                    return "Environment-style assignment to a sensitive key (value withheld)"
    if kind == "zip" and body.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP signature at a backup filename; review whether publication is intended"
    if kind == "gzip" and body.startswith(b"\x1f\x8b\x08"):
        return "Gzip signature at a backup filename; contents were not extracted"
    if kind == "sql" and re.search(r"^\s*(?:-- (?:MySQL|PostgreSQL) (?:database )?dump|CREATE TABLE\b|INSERT INTO\b)", text, re.M | re.I):
        return "SQL dump statements at a backup filename"
    if kind == "php" and re.search(r"^\s*<\?php\b", text) and re.search(r"(?:\bdefine\s*\(|\$[A-Za-z_][A-Za-z0-9_]*\s*=)", text):
        return "PHP source structure at a backup filename"
    if kind == "aws" and all(re.search(r"^\s*" + key + r"\s*=\s*\S+", text, re.M | re.I)
                             for key in ("aws_access_key_id", "aws_secret_access_key")):
        return "AWS credential configuration structure; values withheld"
    if kind == "npm" and re.search(r"^\s*(?://[^\s]+:)?_authToken\s*=\s*\S+", text, re.M):
        return "npm authentication directive; verify whether the value is a token or substitution"
    if kind == "htpasswd" and re.search(r"^[A-Za-z0-9_.@-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)\S{8,}", text, re.M):
        return "Password-file hash structure; values withheld"
    if kind == "private-key" and re.search(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----", text):
        return "Private-key header; contents withheld"
    if kind == "sqlite" and body.startswith(b"SQLite format 3\0"):
        return "SQLite database signature at a Subversion metadata path"
    if kind == "ds-store" and body.startswith(b"\x00\x00\x00\x01Bud1"):
        return "macOS directory metadata signature"
    if kind == "compose" and re.search(r"^services:\s*(?:#.*)?\n[ \t]+[A-Za-z0-9_.-]+:", text, re.M):
        return "Compose service configuration structure; publication may be intentional"
    if kind == "actuator" and text.lstrip().startswith("{") and re.search(r'"propertySources"\s*:\s*\[', text) and re.search(r'"(?:activeProfiles|defaultProfiles)"\s*:\s*\[', text):
        return "Actuator environment response structure; values may be redacted"
    if kind == "phpinfo" and "PHP Version" in text and "phpinfo()" in text:
        return "PHP diagnostic page markers"
    if kind == "apache" and re.search(r"Apache (?:Server )?Status", text, re.I) and "Server Version:" in text:
        return "Apache status page markers"
    return None


def check(asset, timeout, verify=True):
    result = {"asset": asset, "complete": True, "tls_verification_enabled": verify, "checks": []}
    try:
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
        control = fetch(opener, asset + "/.sensitive-check-" + secrets.token_hex(8), timeout)
        result["control_status"] = control["code"]
        if control["code"] == 429 or control["code"] >= 500:
            raise ValueError("Control request failed")
    except (OSError, ValueError, http.client.HTTPException):
        result.update(complete=False, error="Control request failed (network, TLS or server error); asset checks skipped")
        return result
    def probe(entry):
        path, kind = entry
        item = {"path": path, "status": "NO_MATCH"}
        try:
            response = fetch(opener, asset + path, timeout)
            code = response["code"]
            item["http_status"] = code
            if code in (404, 410):
                item["status"] = "NOT_FOUND"
            elif code in (401, 403):
                item["status"] = "DENIED"
            elif 300 <= code < 400:
                item["status"] = "REDIRECT"
            elif code in (200, 206):
                if response["encoding"] not in {"", "identity"}:
                    raise ValueError("Unexpected content encoding")
                if control["code"] in (200, 206) and response["body"] == control["body"]:
                    item["status"] = "FALLBACK"
                else:
                    reason = evidence(kind, response["body"], response["type"])
                    if reason:
                        item.update(status="CANDIDATE", severity=severity(kind), reason=reason)
            elif code == 429 or code >= 500:
                raise ValueError("Rate limit or server failure")
            else:
                item["status"] = "UNASSESSED"
        except (OSError, ValueError, http.client.HTTPException):
            item.update(status="ERROR", reason="Request failed or response could not be assessed")
        return item
    with ThreadPoolExecutor(max_workers=4) as pool:
        result["checks"] = list(pool.map(probe, PATHS))
    result["complete"] = all(item["status"] not in {"ERROR", "UNASSESSED"} for item in result["checks"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", nargs="*", help="Your HTTP(S) origins, e.g. https://app.example.com")
    parser.add_argument("-f", "--file", help="UTF-8 file with one origin per line; # comments supported")
    parser.add_argument("--json", metavar="PATH", help="Save metadata-only JSON results")
    parser.add_argument("--timeout", type=float, default=8, help="Timeout per socket operation (default: 8 seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show every path status")
    parser.add_argument("-k", "--insecure", action="store_true", help="Explicitly disable TLS verification for this run (e.g. self-signed staging assets)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    try:
        assets = list(args.assets)
        if args.file:
            assets.extend(line.split("#", 1)[0].strip() for line in Path(args.file).read_text(encoding="utf-8-sig").splitlines()
                          if line.split("#", 1)[0].strip())
        if not assets:
            parser.error("provide an asset or --file")
        assets = list(dict.fromkeys(origin(value) for value in assets))
        report_path = Path(args.json).resolve() if args.json else None
        if report_path and report_path in {Path(__file__).resolve(), Path(args.file).resolve() if args.file else None}:
            raise ValueError("Report must not overwrite script or input")
    except (OSError, ValueError, UnicodeError):
        print("Error: invalid asset origin, input file or report path; no requests sent.", file=sys.stderr)
        return 2
    results = []
    if args.insecure:
        print("[INFO] TLS certificate and hostname verification disabled for this run.")
    for asset in assets:
        result = check(asset, args.timeout, verify=not args.insecure)
        results.append(result)
        if result.get("error"):
            print(f'[ERROR] {asset}: {result["error"]}')
        for item in sorted(result["checks"], key=lambda item: (ORDER.get(item.get("severity"), 3), item["path"])):
            if args.verbose or item["status"] in {"CANDIDATE", "ERROR", "UNASSESSED"}:
                label = item.get("severity", item["status"])
                print(f'[{label}] {asset}{item["path"]}: {item.get("reason", "HTTP " + str(item.get("http_status", "unknown")))}')
    candidates = sum(item["status"] == "CANDIDATE" for result in results for item in result["checks"])
    incomplete = sum(not result["complete"] for result in results)
    print(f"{len(results)} asset(s); {candidates} candidate path(s); {incomplete} incomplete asset(s).")
    if report_path:
        try:
            report_path.write_text(json.dumps({"generated": dt.datetime.now(dt.timezone.utc).isoformat(),
                                              "complete": not incomplete, "results": results}, indent=2) + "\n", encoding="utf-8")
        except OSError:
            print("Error: could not write JSON report.", file=sys.stderr)
            return 2
    return 2 if incomplete else 1 if candidates else 0


if __name__ == "__main__":
    sys.exit(main())
