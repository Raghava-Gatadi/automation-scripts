#!/usr/bin/env python3
"""One-pass bulk TLS certificate expiry check with optional Slack/SMTP alerts.

Uses the standard library; no scheduler or saved state. Exit: 0 healthy,
1 expiring/invalid certificates, 2 incomplete checks or alert failure.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
from email.message import EmailMessage
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import smtplib
import socket
import ssl
import sys
import urllib.parse
import urllib.request


def target(value):
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        raise ValueError("Invalid target")
    parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
            parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("Use a hostname[:port] or HTTPS origin")
    host = parsed.hostname.encode("idna").decode("ascii").lower().removesuffix(".")
    if ":" in host:
        ipaddress.IPv6Address(host)
    elif len(host) > 253 or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host) or any(
            len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        raise ValueError("Invalid hostname")
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return host, port


def check(endpoint, days, timeout):
    host, port = endpoint
    label = (f"[{host}]" if ":" in host else host) + f":{port}"
    result = {"target": label, "status": "ERROR", "detail": ""}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=host) as connection:
                cert = connection.getpeercert()
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        remaining = expires - dt.datetime.now(dt.timezone.utc).timestamp()
        result["status"] = ("EXPIRED" if remaining <= 0 else "CRITICAL" if remaining <= 7 * 86400
                            else "WARNING" if remaining <= days * 86400 else "OK")
        expiry = dt.datetime.fromtimestamp(expires, dt.timezone.utc).isoformat()
        result.update(days_left=remaining / 86400, expires_at=expiry)
        result["detail"] = f"expires {expiry}; {remaining / 86400:.1f} days remaining"
    except ssl.SSLCertVerificationError as error:
        # OpenSSL X509_V_ERR_CERT_HAS_EXPIRED is 10. It may refer to an
        # intermediate certificate; do not invent a leaf expiry date.
        if getattr(error, "verify_code", None) == 10:
            result.update(status="EXPIRED", detail="TLS verifier reports an expired certificate in the chain; expiry date unavailable")
        else:
            result.update(status="INVALID_CERT", detail="Certificate/hostname verification failed (untrusted, mismatched or otherwise invalid)")
    except (OSError, ValueError, KeyError, OverflowError):
        result["detail"] = "Connection/TLS failure or unavailable certificate expiry; check incomplete"
    return result


def alert_config(slack, email):
    config = {}
    if slack:
        webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        parsed = urllib.parse.urlsplit(webhook)
        if (parsed.scheme != "https" or parsed.hostname not in {"hooks.slack.com", "hooks.slack-gov.com"} or
                parsed.username is not None or parsed.port not in (None, 443) or
                not re.fullmatch(r"/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", parsed.path) or
                parsed.query or parsed.fragment):
            raise ValueError("Set a valid Slack incoming webhook URL")
        config["slack"] = webhook
    if email:
        host = os.getenv("SMTP_HOST", "").strip()
        mode = os.getenv("SMTP_MODE", "starttls").lower()
        port = int(os.getenv("SMTP_PORT", "465" if mode == "ssl" else "587"))
        sender = os.getenv("SMTP_FROM", "").strip()
        recipients = [item.strip() for item in os.getenv("SMTP_TO", "").split(",") if item.strip()]
        credentials = (os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", ""))
        address = r"[^@\s,<>]+@[^@\s,<>]+"
        if (not host or any(c.isspace() for c in host) or mode not in {"ssl", "starttls"} or
                not 1 <= port <= 65535 or not re.fullmatch(address, sender) or not recipients or
                any(not re.fullmatch(address, item) for item in recipients) or
                bool(credentials[0]) != bool(credentials[1])):
            raise ValueError("Invalid SMTP configuration")
        config["email"] = {"host": host, "port": port, "mode": mode, "sender": sender,
                           "recipients": recipients, "credentials": credentials}
    return config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def send_slack(webhook, text, timeout):
    # Keep a single bounded message; the console always has the full result list.
    if len(text) > 3500:
        text = text[:3400] + "\n... See console for remaining results."
    request = urllib.request.Request(webhook, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200 or response.read(32).strip() != b"ok":
            raise ValueError("Slack did not acknowledge the alert")


def send_email(config, text, timeout):
    message = EmailMessage()
    message["Subject"] = "TLS certificate expiry quick check: attention needed"
    message["From"] = config["sender"]
    message["To"] = ", ".join(config["recipients"])
    message.set_content(text)
    context = ssl.create_default_context()
    if config["mode"] == "ssl":
        server = smtplib.SMTP_SSL(config["host"], config["port"], timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(config["host"], config["port"], timeout=timeout)
    with server:
        if config["mode"] == "starttls":
            server.starttls(context=context)
        if config["credentials"][0]:
            server.login(*config["credentials"])
        refused = server.send_message(message)
        if refused:
            raise ValueError("Some email recipients were refused")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hosts", nargs="*", help="Hosts, HTTPS origins or existing target files (default port 443)")
    parser.add_argument("-f", "--file", help="UTF-8 target file; one target per line, # comments allowed")
    parser.add_argument("--days", type=int, default=30, help="Warning window (default: 30); critical is always <= 7 days")
    parser.add_argument("--timeout", type=float, default=8, help="Timeout per socket operation (default: 8 seconds)")
    parser.add_argument("--slack", action="store_true", help="Send issue summary using SLACK_WEBHOOK_URL")
    parser.add_argument("--email", action="store_true", help="Send issue summary using SMTP_* environment settings")
    args = parser.parse_args(argv)
    if args.days < 0 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("days must be nonnegative and timeout positive and finite")
    try:
        values, files = [], []
        for value in args.hosts:
            if Path(value).is_file():
                files.append(Path(value))
            else:
                values.append(value)
        if args.file:
            files.append(Path(args.file))
        for path in files:
            values.extend(line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
                          if line.split("#", 1)[0].strip())
        if not values:
            parser.error("provide targets or --file")
        targets = list(dict.fromkeys(target(value) for value in values))
        config = alert_config(args.slack, args.email)
    except (OSError, ValueError, UnicodeError):
        print("Error: invalid target, input file or alert configuration; no checks or alerts sent.", file=sys.stderr)
        return 2
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda endpoint: check(endpoint, args.days, args.timeout), targets))
    results.sort(key=lambda item: (item.get("days_left") is not None, item.get("days_left", 0), item["target"]))
    for item in results:
        print(f'[{item["status"]}] {item["target"]}: {item["detail"]}')
    issues = [item for item in results if item["status"] != "OK"]
    print(f"{len(results)} target(s); {len(issues)} need attention (warning: {args.days} days; critical: 7 days).")
    failed = any(item["status"] == "ERROR" for item in results)
    if issues:
        lines = [f'TLS certificate quick check: {len(issues)}/{len(results)} need attention; warning {args.days} days, critical 7 days.']
        lines.extend(f'[{item["status"]}] {item["target"]}: {item["detail"]}' for item in issues)
        text = "\n".join(lines)
        for channel in config:
            try:
                if channel == "slack":
                    send_slack(config[channel], text, args.timeout)
                else:
                    send_email(config[channel], text, args.timeout)
                print(f"{channel.capitalize()} alert submitted.")
            except (OSError, ValueError, smtplib.SMTPException, http.client.HTTPException):
                failed = True
                print(f"Error: {channel} alert failed; check credentials, TLS and connectivity.", file=sys.stderr)
    return 2 if failed else 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
