#!/usr/bin/env python3
"""Run Days 1-6 once and combine their output into one Markdown report.

Use cron/CI for weekly scheduling. Configuration paths and child arguments are
relative to the config directory. Exit: 0 all pass, 1 findings, 2 incomplete/error.
"""
import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = Path(__file__).resolve().parent
TITLE = "# Weekly security quick check"
CHECKS = (
    ("appsec", "Web security", "appsec_quickcheck.py"),
    ("secrets", "Git secrets", "git_secrets_scan.py"),
    ("dependencies", "Dependency vulnerabilities", "dependency_quickcheck.py"),
    ("subdomains", "Dangling CNAMEs", "subdomain_quickcheck.py"),
    ("sensitive_files", "Exposed files", "sensitive_files_quickcheck.py"),
    ("certificates", "Certificate expiry", "cert_expiry_quickcheck.py"),
)


def load_config(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    checks = data.get("checks") if isinstance(data, dict) else None
    if not isinstance(checks, dict) or set(checks) != {key for key, _, _ in CHECKS}:
        raise ValueError("Config must contain all six named checks")
    if any(not isinstance(args, list) or any(not isinstance(arg, str) or "\0" in arg for arg in args)
           for args in checks.values()):
        raise ValueError("Each check must have a list of argument strings")
    return checks


def run_checks(checks, directory, timeout):
    results = []
    for day, (key, name, filename) in enumerate(CHECKS, 1):
        print(f"[{day}/6] {name}...", flush=True)
        started = time.monotonic()
        try:
            completed = subprocess.run([sys.executable, str(SCRIPT_DIR / filename), *checks[key]],
                                       cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace", timeout=timeout)
            code, output = completed.returncode, completed.stdout
            status = "PASS" if code == 0 else "FINDINGS" if code == 1 else "INCOMPLETE/ERROR"
        except subprocess.TimeoutExpired as error:
            partial = error.output or b""
            output = partial.decode("utf-8", errors="replace") if isinstance(partial, bytes) else partial
            output += "\nRunner: step timed out; check incomplete.\n"
            code, status = None, "TIMEOUT"
        except (OSError, ValueError):
            code, status, output = None, "INCOMPLETE/ERROR", "Runner: could not launch this step."
        results.append({"day": day, "name": name, "status": status, "exit_code": code,
                        "seconds": round(time.monotonic() - started, 2), "output": output})
    return results


def report_text(results, generated):
    lines = [TITLE, "", f"Generated: {generated} (UTC)", "",
             "| Day | Check | Result | Exit | Seconds |", "| --- | --- | --- | --- | --- |"]
    for item in results:
        code = item["exit_code"] if item["exit_code"] is not None else "-"
        lines.append(f'| {item["day"]} | {item["name"]} | {item["status"]} | {code} | {item["seconds"]} |')
    lines += ["", "PASS means the selected script completed below its configured finding threshold.",
              "Review all output for skipped files, limited scope and findings below that threshold."]
    for item in results:
        lines += ["", f'## Day {item["day"]}: {item["name"]}', ""]
        # Indented blocks keep captured output from becoming active Markdown.
        lines.extend("    " + line for line in (item["output"].strip() or "(no output)").splitlines())
    return "\n".join(lines) + "\n"


def write_report(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".weekly-report-", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", default="weekly_runner.json", help="JSON config (default: weekly_runner.json)")
    parser.add_argument("--report", default="reports/weekly-report.md", help="Markdown destination, relative to config directory")
    parser.add_argument("--step-timeout", type=float, default=300, help="Seconds allowed per script (default: 300)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.step_timeout) or args.step_timeout <= 0:
        parser.error("step timeout must be positive and finite")
    try:
        config_path = Path(args.config).resolve()
        checks = load_config(config_path)
        destination = (config_path.parent / args.report).resolve()
        protected = {config_path, Path(__file__).resolve(), *(SCRIPT_DIR / filename for _, _, filename in CHECKS)}
        # Protect input files explicitly mentioned in child argument lists.
        for arguments in checks.values():
            for argument in arguments:
                candidate = (config_path.parent / argument).resolve()
                if candidate.is_file():
                    protected.add(candidate)
        if destination in protected:
            raise ValueError("Report must not overwrite a script, config or input file")
        if destination.exists():
            with destination.open(encoding="utf-8") as handle:
                if handle.read(len(TITLE)) != TITLE:
                    raise ValueError("Destination already contains an unrelated file")
    except (OSError, ValueError, UnicodeError):
        print("Error: invalid config or report destination; no checks run.", file=sys.stderr)
        return 2
    generated = dt.datetime.now(dt.timezone.utc).isoformat()
    results = run_checks(checks, config_path.parent, args.step_timeout)
    try:
        write_report(destination, report_text(results, generated))
    except OSError:
        print("Error: report could not be written. Captured results follow:", file=sys.stderr)
        print(report_text(results, generated))
        return 2
    print(f"Report: {destination}")
    for item in results:
        print(f'Day {item["day"]}: {item["status"]}')
    return 2 if any(item["exit_code"] not in (0, 1) for item in results) else 1 if any(item["exit_code"] == 1 for item in results) else 0


if __name__ == "__main__":
    sys.exit(main())
