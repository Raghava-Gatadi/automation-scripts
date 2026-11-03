#!/usr/bin/env python3
"""Small Semgrep wrapper with accepted-finding or Git baselines and a summary.

Requires semgrep on PATH (and Git for --baseline). Exit: 0 no findings,
1 findings, 2 scan/configuration/report error. Baseline writes require --update-baseline.
"""
import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

RANK = {"INFO": 1, "WARNING": 2, "ERROR": 3}


def load_baseline(path):
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("tool") != "semgrep_quickcheck" or data.get("version") != 1 or not isinstance(data.get("findings"), list):
        raise ValueError("Unsupported accepted-findings baseline")
    fingerprints = set()
    for item in data["findings"]:
        value = item.get("fingerprint") if isinstance(item, dict) else None
        if not isinstance(value, str):
            raise ValueError("Invalid baseline fingerprint")
        digest, separator, ordinal = value.partition(":")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or not separator or not ordinal.isdigit() or int(ordinal) < 1:
            raise ValueError("Invalid baseline fingerprint")
        fingerprints.add(value)
    return fingerprints


def fingerprint_findings(repo, findings):
    occurrences, sources = Counter(), {}
    for item in sorted(findings, key=lambda item: (item["path"], item["line"], item["rule"])):
        source = (repo / item["path"]).resolve()
        relative = source.relative_to(repo).as_posix()  # Reject paths outside the scan root.
        if source not in sources:
            sources[source] = source.read_text(encoding="utf-8", errors="replace").splitlines()
        lines = sources[source]
        if not 1 <= item["line"] <= item["end_line"] <= len(lines):
            raise ValueError("Finding source range is unavailable")
        # Preserve whitespace inside string literals; do not flatten source text.
        code = "\n".join(lines[item["line"] - 1:item["end_line"]])
        digest = hashlib.sha256(json.dumps([item["rule"], relative, item["severity"], code], ensure_ascii=True).encode()).hexdigest()
        occurrences[digest] += 1
        item["fingerprint"] = f"{digest}:{occurrences[digest]}"


def write_baseline(path, findings):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=".semgrep-baseline-", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump({"tool": "semgrep_quickcheck", "version": 1,
                       "generated": dt.datetime.now(dt.timezone.utc).isoformat(), "findings": findings}, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def finding_counts(findings):
    return {"finding_count": len(findings), "by_severity": dict(Counter(item["severity"] for item in findings)),
            "by_rule": dict(Counter(item["rule"] for item in findings)),
            "files_with_findings": len({item["path"] for item in findings})}


def summarize(data):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Invalid Semgrep JSON")
    findings = []
    for item in data["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("extra"), dict) or not isinstance(item.get("start"), dict):
            raise ValueError("Invalid finding")
        rule, path, line = item.get("check_id"), item.get("path"), item["start"].get("line")
        level = item["extra"].get("severity")
        end = item.get("end", item["start"])
        end_line = end.get("line") if isinstance(end, dict) else None
        if not isinstance(rule, str) or not isinstance(path, str) or type(line) is not int or line < 1 or type(end_line) is not int or end_line < line or not isinstance(level, str) or level not in RANK:
            raise ValueError("Invalid finding location/severity")
        # Rule messages can interpolate source text. Preserve locations and IDs,
        # excluding messages, source snippets, metavariables, fixes and traces.
        findings.append({"rule": rule, "path": path, "line": line, "end_line": end_line, "severity": level})
    errors, skipped = data.get("errors", []), data.get("skipped_rules", [])
    paths = data.get("paths", {})
    if not isinstance(errors, list) or not isinstance(skipped, list) or not isinstance(paths, dict):
        raise ValueError("Invalid scan metadata")
    scanned = paths.get("scanned")
    if scanned is not None and not isinstance(scanned, list):
        raise ValueError("Invalid scanned path list")
    return {"findings": findings, **finding_counts(findings),
            "files_scanned": len(scanned) if scanned is not None else None,
            "error_count": len(errors), "skipped_rule_count": len(skipped),
            "semgrep_version": data.get("version")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", default=".", help="Directory to scan (default: current directory)")
    parser.add_argument("--config", action="append", help="Rules file/directory or registry ruleset; repeatable (default: p/default)")
    baselines = parser.add_mutually_exclusive_group()
    baselines.add_argument("--baseline", help="Local Git commit/ref to compare against, e.g. HEAD~1")
    baselines.add_argument("--baseline-file", help="Accepted-findings file relative to repo (default: .semgrep-baseline.json)")
    parser.add_argument("--update-baseline", action="store_true", help="Accept the current complete scan into the baseline file")
    parser.add_argument("--fail-on", choices=RANK, default="INFO", help="Fail for new findings at/above this severity (default: INFO)")
    parser.add_argument("--json", metavar="PATH", help="Save the summary and finding locations, excluding source text")
    parser.add_argument("--timeout", type=float, default=300, help="Total Semgrep process timeout in seconds (default: 300)")
    args = parser.parse_args(argv)
    args.config = args.config or ["p/default"]
    if args.baseline and args.update_baseline:
        parser.error("--update-baseline cannot be combined with a Git baseline")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    try:
        repo = Path(args.repo).resolve()
        if not repo.is_dir():
            raise ValueError("Scan directory does not exist")
        destination = Path(args.json).resolve() if args.json else None
        protected = {Path(__file__).resolve(), *((repo / value).resolve() for value in args.config)}
        baseline_file = (repo / (args.baseline_file or ".semgrep-baseline.json")).resolve() if not args.baseline else None
        if destination in protected or (baseline_file is not None and (baseline_file in protected or destination == baseline_file)):
            raise ValueError("Output must not overwrite script or rules")
        known = load_baseline(baseline_file) if baseline_file is not None else set()
        if destination and destination.exists():
            existing = json.loads(destination.read_text(encoding="utf-8"))
            if not isinstance(existing, dict) or existing.get("tool") != "semgrep_quickcheck":
                raise ValueError("Output already contains an unrelated file")
        executable = shutil.which("semgrep")
        if not executable:
            print("Error: semgrep is not installed/on PATH; install Semgrep CLI first.", file=sys.stderr)
            return 2
        baseline = None
        if args.baseline:
            resolved = subprocess.run(["git", "rev-parse", "--verify", "--end-of-options", args.baseline + "^{commit}"],
                                      cwd=repo, capture_output=True, text=True, timeout=10)
            baseline = resolved.stdout.strip()
            if resolved.returncode or len(baseline) not in (40, 64) or any(c not in "0123456789abcdef" for c in baseline):
                raise ValueError("Baseline must be a locally available Git commit")
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("Error: invalid repository, rules/output path, or baseline. No Semgrep scan run.", file=sys.stderr)
        return 2
    command = [executable, "scan", "--json", "--error", "--strict", "--oss-only",
               "--metrics=off", "--disable-version-check"]
    for value in args.config:
        command.append("--config=" + value)
    for output_path in (baseline_file, destination):
        if output_path is not None:
            try:
                command.append("--exclude=" + output_path.relative_to(repo).as_posix())
            except ValueError:
                pass
    if baseline:
        command.append("--baseline-commit=" + baseline)
    command.append(".")
    # A baseline inherited from a CI environment must not turn an explicitly
    # full scan into a diff scan. The requested baseline is passed on the CLI.
    environment = dict(os.environ)
    environment.pop("SEMGREP_BASELINE_COMMIT", None)
    report = {"tool": "semgrep_quickcheck", "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
              "mode": "baseline-diff" if baseline else "accepted-baseline", "baseline_commit": baseline, "complete": False}
    try:
        completed = subprocess.run(command, cwd=repo, env=environment, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=args.timeout)
        report["semgrep_exit_code"] = completed.returncode
        report.update(summarize(json.loads(completed.stdout)))
        report["complete"] = (completed.returncode in (0, 1) and not report["error_count"] and
                              not report["skipped_rule_count"] and
                              (completed.returncode != 1 or bool(report["finding_count"])))
        all_findings = report["findings"]
        if baseline_file is not None:
            fingerprint_findings(repo, all_findings)
        current = {item.get("fingerprint") for item in all_findings}
        report["total_findings"] = len(all_findings)
        report["findings"] = [item for item in all_findings if item.get("fingerprint") not in known]
        report.update(finding_counts(report["findings"]))
        report["baselined_count"] = len(all_findings) - report["finding_count"]
        report["stale_baseline_count"] = len(known - current)
        report["blocking_count"] = sum(RANK[item["severity"]] >= RANK[args.fail_on] for item in report["findings"])
        counts = ", ".join(f"{json.dumps(level)}: {count}" for level, count in sorted(report["by_severity"].items())) or "none"
        print(f'Mode: {report["mode"]}' + (f"; baseline {baseline}" if baseline else ""))
        print(f'{report["finding_count"]} new finding(s); {report["baselined_count"]} baselined; '
              f'{report["stale_baseline_count"]} baseline entries absent from this scan scope. Severity counts: {counts}.')
        print(f'Fail threshold: {args.fail_on}; {report["blocking_count"]} blocking new finding(s).')
        print(f'Scanned files: {report["files_scanned"] if report["files_scanned"] is not None else "not reported"}; '
              f'errors: {report["error_count"]}; skipped rules: {report["skipped_rule_count"]}.')
        for rule, count in Counter(report["by_rule"]).most_common(5):
            print(f"  Rule {json.dumps(rule)}: {count}")
        for item in report["findings"][:20]:
            print(f'{json.dumps(item["severity"])} {json.dumps(item["path"])}:{item["line"]} {json.dumps(item["rule"])}')
        if report["finding_count"] > 20:
            print("Showing first 20 locations; --json saves all finding locations.")
        if not report["complete"]:
            print("Scan incomplete: inspect Semgrep's configuration, baseline and parse errors directly.", file=sys.stderr)
    except subprocess.TimeoutExpired:
        report["complete"] = False
        report["error"] = "Semgrep process timed out; scan incomplete"
        print("Error: " + report["error"], file=sys.stderr)
    except (OSError, ValueError, UnicodeError):
        report["complete"] = False
        report["error"] = "Semgrep failed or returned unsupported JSON; run Semgrep directly for diagnostics"
        print("Error: " + report["error"], file=sys.stderr)
    if destination:
        try:
            destination.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        except OSError:
            print("Error: could not write summary JSON.", file=sys.stderr)
            return 2
    if not report["complete"]:
        return 2
    if args.update_baseline:
        try:
            write_baseline(baseline_file, all_findings)
        except OSError:
            print("Error: accepted-findings baseline could not be written.", file=sys.stderr)
            return 2
        print(f"Accepted {len(all_findings)} finding(s). Review the baseline before committing it.")
        return 0
    return 1 if report["blocking_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
