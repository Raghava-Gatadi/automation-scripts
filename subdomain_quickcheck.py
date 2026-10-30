#!/usr/bin/env python3
"""First-look dangling CNAME check using Google Public DNS over HTTPS.

Only check domains you own or are authorized to assess. This checks DNS, not
whether a provider resource can be claimed. Exit: 0 no candidates, 1 review, 2 error.
"""
import argparse
import datetime as dt
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
import urllib.parse
import urllib.request

API = "https://dns.google/resolve"
MAX_DEPTH = 10
# Context only: these suffixes do not imply that a resource is claimable.
PROVIDERS = {"azurewebsites.net": "Azure App Service", "azurefd.net": "Azure Front Door",
             "azureedge.net": "Azure CDN", "trafficmanager.net": "Azure Traffic Manager"}


def hostname(value):
    name = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
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


def check(name, timeout=8):
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hosts", nargs="*", help="Hostnames only (no URLs or wildcards)")
    parser.add_argument("-f", "--file", help="UTF-8 file with one hostname per line; # comments supported")
    parser.add_argument("--json", metavar="PATH", help="Also save a JSON report")
    parser.add_argument("--timeout", type=float, default=8, help="Timeout per DNS-over-HTTPS request (default: 8 seconds)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    try:
        hosts = list(args.hosts)
        if args.file:
            hosts.extend(line.split("#", 1)[0].strip() for line in Path(args.file).read_text(encoding="utf-8-sig").splitlines()
                         if line.split("#", 1)[0].strip())
        if not hosts:
            parser.error("provide a hostname or --file")
        hosts = list(dict.fromkeys(hostname(value) for value in hosts))
        report_path = Path(args.json).resolve() if args.json else None
        protected = {Path(__file__).resolve()}
        if args.file:
            protected.add(Path(args.file).resolve())
        if report_path in protected:
            raise ValueError("Report must not overwrite input or script")
    except (OSError, ValueError, UnicodeError):
        print("Error: invalid hostname, input file, or report path; no DNS requests sent.", file=sys.stderr)
        return 2
    results = []
    for name in hosts:
        result = check(name, args.timeout)
        results.append(result)
        print(f'[{result["status"]}] {name}: {result["detail"]}')
        if len(result["chain"]) > 1:
            print("  " + " -> ".join(result["chain"]))
        if result["providers"]:
            print("  Hosted-service context: " + ", ".join(result["providers"]))
    candidates = sum(result["status"] in {"DANGLING", "NO_ADDRESS"} for result in results)
    errors = sum(result["status"] == "ERROR" for result in results)
    print(f"{len(results)} hostname(s); {candidates} candidate(s) to review; {errors} inconclusive.")
    if report_path:
        try:
            report_path.write_text(json.dumps({"generated": dt.datetime.now(dt.timezone.utc).isoformat(),
                                              "resolver": API, "complete": not errors, "results": results},
                                             indent=2) + "\n", encoding="utf-8")
        except OSError:
            print("Error: could not write JSON report.", file=sys.stderr)
            return 2
    return 2 if errors else 1 if candidates else 0


if __name__ == "__main__":
    sys.exit(main())
