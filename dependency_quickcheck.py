#!/usr/bin/env python3
"""First-pass OSV checks for exact versions in requirements.txt and package.json.

Uses the standard library. Sends package names, ecosystems and versions to OSV;
does not install packages. Exit: 0 no advisories, 1 advisories, 2 incomplete/error.
"""
import argparse
import datetime as dt
import json
import math
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


API = "https://api.osv.dev/v1/querybatch"
MANIFESTS = ("requirements.txt", "package.json")
PYTHON_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,. -]+\])?\s*==\s*([^\s;]+)")
PYTHON_VERSION = re.compile(
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?", re.I)
NPM_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
NPM_NAME = re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+")


def read_requirements(path, add, skip):
    pending, start = "", 0
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = re.sub(r"\s+#.*$", "", raw).strip()
        if not line or line.startswith("#"):
            continue
        if not pending:
            start = number
        pending += line[:-1] + " " if line.endswith("\\") else line
        if line.endswith("\\"):
            continue
        location = f"{path}:{start}"
        # Hashes describe artifact integrity and are not sent to OSV.
        requirement = re.sub(r"\s+--hash=\S+", "", pending).split(";", 1)[0].strip()
        match = PYTHON_PIN.fullmatch(requirement)
        if match and PYTHON_VERSION.fullmatch(match[2]):
            name = re.sub(r"[-_.]+", "-", match[1]).lower()
            add("PyPI", name, match[2], location)
        else:
            skip(location, "Not a supported exact name==version pin (ranges, URLs, includes and pip directives are not resolved)")
        pending = ""
    if pending:
        skip(f"{path}:{start}", "Unfinished requirement line continuation")


def read_package_json(path, add, skip):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("package.json must contain an object")
    # Optional dependencies override dependencies, as npm does. Preserve dev
    # declarations separately when they specify a different pinned version.
    sections = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        value = data.get(section, {})
        if not isinstance(value, dict):
            raise ValueError("Dependency sections must be objects")
        sections[section] = value
    for section, declarations in sections.items():
        for name, spec in declarations.items():
            if section == "dependencies" and name in sections["optionalDependencies"]:
                continue
            # Do not print unsupported specs: URLs may contain credentials.
            location = f"{path}:{section}:{name}"
            version = spec.strip() if isinstance(spec, str) else ""
            version = version[1:] if version.startswith("=") else version
            version = version[1:] if version.startswith("v") else version
            if NPM_NAME.fullmatch(name) and NPM_VERSION.fullmatch(version):
                add("npm", name, version, location)
            else:
                skip(location, "Not an exact npm version (ranges, tags, aliases, Git and local dependencies are not resolved)")
    if data.get("peerDependencies"):
        skip(f"{path}:peerDependencies", "Peer dependency requirements are not resolved")
    if data.get("workspaces"):
        skip(f"{path}:workspaces", "Workspace manifests are not discovered automatically; pass their files explicitly")


def discover(inputs):
    files = []
    for value in inputs:
        path = Path(value)
        if path.is_dir():
            found = [path / name for name in MANIFESTS if (path / name).is_file()]
            if not found:
                raise ValueError("Directory has no requirements.txt or package.json")
            files.extend(found)
        elif path.is_file() and path.name in MANIFESTS:
            files.append(path)
        else:
            raise ValueError("Input must be a directory, requirements.txt or package.json")
    return list(dict.fromkeys(path.resolve() for path in files))


def query_osv(packages, timeout):
    """Query in small batches, following per-package pagination. Return ID lists."""
    matches = [set() for _ in packages]
    for offset in range(0, len(packages), 100):
        batch = packages[offset:offset + 100]
        pending = [(offset + i, {"package": {"ecosystem": p["ecosystem"], "name": p["name"]},
                                  "version": p["version"]}) for i, p in enumerate(batch)]
        tokens = set()
        while pending:
            payload = json.dumps({"queries": [query for _, query in pending]}).encode()
            request = urllib.request.Request(API, data=payload, headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "User-Agent": "dependency-quickcheck/1.0"}, method="POST")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.load(response)
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                raise ValueError("Unexpected OSV result count")
            following = []
            for (index, query), result in zip(pending, results):
                if not isinstance(result, dict) or "error" in result:
                    raise ValueError("Unexpected OSV package response")
                vulns = result.get("vulns", [])
                if not isinstance(vulns, list):
                    raise ValueError("Unexpected OSV vulnerability list")
                for vuln in vulns:
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"]:
                        raise ValueError("Unexpected OSV advisory")
                    matches[index].add(vuln["id"])
                next_page = result.get("next_page_token")
                if next_page:
                    if not isinstance(next_page, str) or (index, next_page) in tokens:
                        raise ValueError("Invalid or repeated OSV pagination token")
                    tokens.add((index, next_page))
                    next_query = query.copy()
                    next_query["page_token"] = next_page
                    following.append((index, next_query))
            pending = following
    return [sorted(ids) for ids in matches]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Directories or manifest files (default: current directory)")
    parser.add_argument("--json", metavar="PATH", help="Also save a JSON report")
    parser.add_argument("--timeout", type=float, default=30, help="Timeout per OSV request in seconds (default: 30)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    packages, skipped = {}, []

    def add(ecosystem, name, version, location):
        key = (ecosystem, name, version)
        package = packages.setdefault(key, {"ecosystem": ecosystem, "name": name,
                                            "version": version, "sources": []})
        package["sources"].append(location)

    def skip(location, reason):
        skipped.append({"source": location, "reason": reason})

    try:
        files = discover(args.paths or ["."])
        report_path = Path(args.json).resolve() if args.json else None
        if report_path and report_path in {*files, Path(__file__).resolve()}:
            raise ValueError("Report must not overwrite a manifest or the script")
        for path in files:
            reader = read_requirements if path.name == "requirements.txt" else read_package_json
            reader(path, add, skip)
    except (OSError, ValueError, UnicodeError):
        print("Error: missing/invalid manifest or report path. No OSV queries sent.", file=sys.stderr)
        return 2

    packages = list(packages.values())
    report = {"generated": dt.datetime.now(dt.timezone.utc).isoformat(), "complete": False,
              "packages_checked": 0, "results": [], "skipped": skipped}
    error = False
    try:
        advisory_ids = query_osv(packages, args.timeout)
        for package, ids in zip(packages, advisory_ids):
            advisories = [{"id": value, "url": "https://osv.dev/vulnerability/" + urllib.parse.quote(value, safe="")}
                          for value in ids]
            report["results"].append({**package, "advisories": advisories})
            if advisories:
                print(f'{package["ecosystem"]} {package["name"]}@{package["version"]}: {len(advisories)} advisory record(s)')
                for advisory in advisories:
                    print(f'  {json.dumps(advisory["id"])}  {advisory["url"]}')
        report["packages_checked"] = len(packages)
        report["complete"] = not skipped
    except (OSError, ValueError, UnicodeError, urllib.error.URLError):
        error = True
        report["error"] = "OSV query failed; check network access or try again later"
        print("Error: " + report["error"], file=sys.stderr)
    for item in skipped:
        print(f'Skipped {json.dumps(item["source"])}: {item["reason"]}', file=sys.stderr)
    affected = sum(bool(result["advisories"]) for result in report["results"])
    print(f'{report["packages_checked"]} unique package version(s) checked; {affected} with advisories; {len(skipped)} skipped.')
    if not report["complete"]:
        print("Check incomplete; skipped or failed queries are not a clean result.")
    if report_path:
        try:
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        except OSError:
            print("Error: could not write JSON report.", file=sys.stderr)
            return 2
    return 2 if error or skipped else 1 if affected else 0


if __name__ == "__main__":
    sys.exit(main())
