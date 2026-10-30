#!/usr/bin/env python3
"""First-look CNAME check with optional hosted-service page clues.

Only check domains you own or are authorized to assess. DNS and page clues do
not establish claimability. Exit: 0 no candidates, 1 review, 2 error.
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
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://dns.google/resolve"
MAX_DEPTH = 10
# Context only: these suffixes do not imply that a resource is claimable.
PROVIDERS = {"azurewebsites.net": "Azure App Service", "azurefd.net": "Azure Front Door",
             "azureedge.net": "Azure CDN", "trafficmanager.net": "Azure Traffic Manager"}
# Heuristics supplied with takeover_check.py. A matching error page is a clue,
# not evidence that current provider protections allow the resource to be claimed.
SERVICES = (
    (r"\.github\.io$", "GitHub Pages", "There isn't a GitHub Pages site here"),
    (r"\.(?:herokuapp\.com|herokudns\.com)$", "Heroku", "No such app"),
    (r"\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$", "AWS S3", "NoSuchBucket"),
    (r"\.myshopify\.com$", "Shopify", "Sorry, this shop is currently unavailable"),
    (r"\.fastly\.net$", "Fastly", "Fastly error: unknown domain"),
    (r"\.surge\.sh$", "Surge", "project not found"),
    (r"\.pantheonsite\.io$", "Pantheon", "404 error unknown site"),
    (r"\.zendesk\.com$", "Zendesk", "Help Center Closed"),
    (r"\.bitbucket\.io$", "Bitbucket", "Repository not found"),
    (r"\.ghost\.io$", "Ghost", "Failed to resolve DNS path for this host"),
    (r"\.tumblr\.com$", "Tumblr", "There's nothing here"),
)
BODY_LIMIT = 20000
CANDIDATES = {"DANGLING", "NO_ADDRESS", "SERVICE_CLUE"}


def service_matches(chain):
    return [(label, text) for pattern, label, text in SERVICES
            if any(re.search(pattern, target) for target in chain[1:])]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def probe_services(name, services, timeout):
    """One verified HTTPS GET to the original hostname, without redirect following."""
    try:
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request("https://" + name + "/", headers={
            "User-Agent": "subdomain-quickcheck/2.0", "Accept-Encoding": "identity"})
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error  # Provider error pages commonly return 404/403.
        with response:
            code = response.code
            if 300 <= code < 400:
                return {"status": "REDIRECT", "http_status": code, "services": []}
            body = response.read(BODY_LIMIT).decode("utf-8", errors="replace")
        matches = [label for label, text in services if text in body]
        return {"status": "MATCH" if matches else "NO_MATCH", "http_status": code, "services": matches}
    except (OSError, ValueError, http.client.HTTPException):
        return {"status": "ERROR", "detail": "HTTPS probe failed (including TLS verification); no insecure retry", "services": []}


def hostname(value):
    name = value.strip().removesuffix(".").encode("idna").decode("ascii").lower()
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", name):
        raise ValueError("Expected a DNS hostname")
    if any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in name.split(".")):
        raise ValueError("Invalid DNS label")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("Expected a hostname, not an IP address")


def lookup(name, kind, timeout):
    query = urllib.parse.urlencode({"name": name, "type": kind, "edns_client_subnet": "0.0.0.0/0"})
    request = urllib.request.Request(API + "?" + query, headers={"Accept": "application/dns-json",
                                                              "User-Agent": "subdomain-quickcheck/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.load(response)
    if not isinstance(data, dict) or type(data.get("Status")) is not int:
        raise ValueError("Invalid DNS response")
    if data.get("TC") or data["Status"] not in (0, 3):
        raise ValueError("DNS error or truncated response")
    answers = data.get("Answer", [])
    if not isinstance(answers, list) or any(not isinstance(record, dict) for record in answers):
        raise ValueError("Invalid DNS answers")
    return data["Status"], answers


def cnames(name, answers):
    targets = set()
    for record in answers:
        if record.get("type") == 5 and hostname(record.get("name", "")) == name:
            targets.add(hostname(record.get("data", "")))
    if len(targets) > 1:
        raise ValueError("Multiple CNAME targets for one owner")
    return list(targets)


def check_dns(name, timeout=8):
    result = {"hostname": name, "chain": [name], "status": "ERROR", "detail": "", "providers": []}

    def finish(status, detail):
        result.update(status=status, detail=detail)
        result["providers"] = sorted({label for target in result["chain"][1:]
                                      for suffix, label in PROVIDERS.items()
                                      if target.endswith("." + suffix)})
        return result

    try:
        current = name
        while True:
            code, answers = lookup(current, "CNAME", timeout)
            targets = cnames(current, answers)
            # Recursive NXDOMAIN answers can retain the source CNAME. Follow
            # that link before interpreting the missing downstream hostname.
            if targets:
                target = targets[0]
                if target in result["chain"]:
                    return finish("ERROR", "CNAME loop detected; resolution is inconclusive")
                if len(result["chain"]) - 1 >= MAX_DEPTH:
                    return finish("ERROR", "CNAME depth limit reached; resolution is inconclusive")
                result["chain"].append(target)
                current = target
                continue
            if len(result["chain"]) == 1:
                return finish("NOT_FOUND" if code == 3 else "NO_CNAME",
                              "Input hostname does not exist" if code == 3 else "No CNAME observed; outside this check's scope")
            if code == 3:
                return finish("DANGLING", "CNAME chain ends at NXDOMAIN; review DNS ownership and remove stale records")
            codes, addresses = [], []
            for kind, number in (("A", 1), ("AAAA", 28)):
                address_code, records = lookup(current, kind, timeout)
                codes.append(address_code)
                if cnames(current, records):
                    return finish("ERROR", "DNS chain changed during lookup; retry before drawing conclusions")
                for record in records:
                    if record.get("type") == number and hostname(record.get("name", "")) == current:
                        address = ipaddress.ip_address(record.get("data", ""))
                        if address.version != (4 if number == 1 else 6):
                            raise ValueError("Address family mismatch")
                        addresses.append(str(address))
            if len(set(codes)) != 1 or (3 in codes and addresses):
                return finish("ERROR", "Inconsistent DNS answers; retry before drawing conclusions")
            if codes == [3, 3]:
                return finish("DANGLING", "CNAME target returned NXDOMAIN for both address families; review stale DNS")
            if addresses:
                result["addresses"] = sorted(set(addresses))
                return finish("RESOLVES", "CNAME target has an address; provider ownership was not checked")
            return finish("NO_ADDRESS", "Target exists but has neither A nor AAAA data; review its intended use (not confirmed takeover)")
    except (OSError, ValueError, UnicodeError, TypeError, AttributeError):
        return finish("ERROR", "DNS/API lookup failed or returned invalid data; result is inconclusive")


def check(name, timeout=8, http=False):
    result = check_dns(name, timeout)
    services = service_matches(result["chain"])
    result["providers"] = sorted(set(result["providers"]) | {label for label, _ in services})
    if http and result["status"] == "RESOLVES" and services:
        result["dns_status"] = result["status"]
        result["http"] = probe_services(name, services, timeout)
        if result["http"]["status"] == "MATCH":
            result.update(status="SERVICE_CLUE", detail="Hosted-service error-page clue matched; verify current protections and ownership manually")
        elif result["http"]["status"] in {"ERROR", "REDIRECT"}:
            result.update(status="ERROR", detail="DNS resolves but requested HTTPS check is inconclusive (failed or redirected)")
        else:
            result["detail"] = "DNS resolves; no service clue matched in the inspected body (ownership remains unknown)"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hosts", nargs="*", help="Hostnames or existing target files (no URLs or wildcards)")
    parser.add_argument("-f", "--file", help="UTF-8 file with one hostname per line; # comments supported")
    parser.add_argument("--json", metavar="PATH", help="Also save a JSON report")
    parser.add_argument("--http", action="store_true", help="Also inspect HTTPS error-page clues for recognized resolving service targets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all results; default shows candidates and errors")
    parser.add_argument("--timeout", type=float, default=8, help="Timeout per DNS-over-HTTPS request (default: 8 seconds)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    try:
        hosts, input_files = [], []
        for value in args.hosts:
            if Path(value).is_file():
                input_files.append(Path(value))
            else:
                hosts.append(value)
        if args.file:
            input_files.append(Path(args.file))
        for path in input_files:
            hosts.extend(line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
                         if line.split("#", 1)[0].strip())
        if not hosts:
            parser.error("provide a hostname or --file")
        hosts = list(dict.fromkeys(hostname(value) for value in hosts))
        report_path = Path(args.json).resolve() if args.json else None
        protected = {Path(__file__).resolve()}
        protected.update(path.resolve() for path in input_files)
        if report_path in protected:
            raise ValueError("Report must not overwrite input or script")
    except (OSError, ValueError, UnicodeError):
        print("Error: invalid hostname, input file, or report path; no DNS requests sent.", file=sys.stderr)
        return 2
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda name: check(name, args.timeout, args.http), hosts))
    for result in results:
        if not args.verbose and result["status"] not in CANDIDATES | {"ERROR"}:
            continue
        name = result["hostname"]
        print(f'[{result["status"]}] {name}: {result["detail"]}')
        if len(result["chain"]) > 1:
            print("  " + " -> ".join(result["chain"]))
        if result["providers"]:
            print("  Hosted-service context: " + ", ".join(result["providers"]))
    candidates = sum(result["status"] in CANDIDATES for result in results)
    errors = sum(result["status"] == "ERROR" for result in results)
    print(f"{len(results)} hostname(s); {candidates} candidate(s) to review; {errors} inconclusive.")
    if report_path:
        try:
            report_path.write_text(json.dumps({"generated": dt.datetime.now(dt.timezone.utc).isoformat(),
                                              "resolver": API, "http_requested": args.http,
                                              "complete": not errors, "results": results},
                                             indent=2) + "\n", encoding="utf-8")
        except OSError:
            print("Error: could not write JSON report.", file=sys.stderr)
            return 2
    return 2 if errors else 1 if candidates else 0


if __name__ == "__main__":
    sys.exit(main())
