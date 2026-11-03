#!/usr/bin/env python3
"""Small Semgrep scan wrapper with native Git baseline diffing and a summary.

Requires semgrep on PATH (and Git for --baseline). Exit: 0 no findings,
1 findings, 2 scan/configuration/report error. No autofix or baseline writes.
"""
import argparse
from collections import Counter
import datetime as dt
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys


def summarize(data):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Invalid Semgrep JSON")
    findings = []
    for item in data["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("extra"), dict) or not isinstance(item.get("start"), dict):
            raise ValueError("Invalid finding")
        rule, path, line = item.get("check_id"), item.get("path"), item["start"].get("line")
        level = item["extra"].get("severity")
        if not isinstance(rule, str) or not isinstance(path, str) or type(line) is not int or line < 1 or not isinstance(level, str):
            raise ValueError("Invalid finding location/severity")
        # Rule messages can interpolate source text. Preserve locations and IDs,
        # excluding messages, source snippets, metavariables, fixes and traces.
        findings.append({"rule": rule, "path": path, "line": line, "severity": level})
    errors, skipped = data.get("errors", []), data.get("skipped_rules", [])
    paths = data.get("paths", {})
    if not isinstance(errors, list) or not isinstance(skipped, list) or not isinstance(paths, dict):
        raise ValueError("Invalid scan metadata")
    scanned = paths.get("scanned")
    if scanned is not None and not isinstance(scanned, list):
        raise ValueError("Invalid scanned path list")
    return {"findings": findings, "finding_count": len(findings),
            "by_severity": dict(Counter(item["severity"] for item in findings)),
            "by_rule": dict(Counter(item["rule"] for item in findings)),
            "files_with_findings": len({item["path"] for item in findings}),
            "files_scanned": len(scanned) if scanned is not None else None,
            "error_count": len(errors), "skipped_rule_count": len(skipped),
            "semgrep_version": data.get("version")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", default=".", help="Directory to scan (default: current directory)")
    parser.add_argument("--config", action="append", required=True, help="Semgrep rules file/directory or registry ruleset; repeatable")
    parser.add_argument("--baseline", help="Local Git commit/ref to compare against, e.g. HEAD~1")
    parser.add_argument("--json", metavar="PATH", help="Save the summary and finding locations, excluding source text")
    parser.add_argument("--timeout", type=float, default=300, help="Total Semgrep process timeout in seconds (default: 300)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    try:
        repo = Path(args.repo).resolve()
        if not repo.is_dir():
            raise ValueError("Scan directory does not exist")
        destination = Path(args.json).resolve() if args.json else None
        protected = {Path(__file__).resolve(), *((repo / value).resolve() for value in args.config)}
        if destination in protected:
            raise ValueError("Output must not overwrite script or rules")
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
        print("Error: invalid repository, rules/output path, or Git baseline. No Semgrep scan run.", file=sys.stderr)
        return 2
    command = [executable, "scan", "--json", "--error", "--strict", "--oss-only",
               "--metrics=off", "--disable-version-check"]
    for value in args.config:
        command.append("--config=" + value)
    if baseline:
        command.append("--baseline-commit=" + baseline)
    command.append(".")
    # A baseline inherited from a CI environment must not turn an explicitly
    # full scan into a diff scan. The requested baseline is passed on the CLI.
    environment = dict(os.environ)
    environment.pop("SEMGREP_BASELINE_COMMIT", None)
    report = {"tool": "semgrep_quickcheck", "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
              "mode": "baseline-diff" if baseline else "full", "baseline_commit": baseline, "complete": False}
    try:
        completed = subprocess.run(command, cwd=repo, env=environment, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=args.timeout)
        report["semgrep_exit_code"] = completed.returncode
        report.update(summarize(json.loads(completed.stdout)))
        report["complete"] = (completed.returncode in (0, 1) and not report["error_count"] and
                              not report["skipped_rule_count"] and
                              (completed.returncode != 1 or bool(report["finding_count"])))
        counts = ", ".join(f"{json.dumps(level)}: {count}" for level, count in sorted(report["by_severity"].items())) or "none"
        print(f'Mode: {report["mode"]}' + (f"; baseline {baseline}" if baseline else ""))
        print(f'{report["finding_count"]} finding(s) across {report["files_with_findings"]} file(s); severity counts: {counts}.')
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
        report["error"] = "Semgrep process timed out; scan incomplete"
        print("Error: " + report["error"], file=sys.stderr)
    except (OSError, ValueError, UnicodeError):
        report["error"] = "Semgrep failed or returned unsupported JSON; run Semgrep directly for diagnostics"
        print("Error: " + report["error"], file=sys.stderr)
    if destination:
        try:
            destination.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        except OSError:
            print("Error: could not write summary JSON.", file=sys.stderr)
            return 2
    return 2 if not report["complete"] else 1 if report["finding_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
