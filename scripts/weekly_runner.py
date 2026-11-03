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
import urllib.parse

SCRIPT_DIR = Path(__file__).resolve().parent
TITLE = "# Weekly security quick check"
MAX_REPORT_LINES = 300
CHECKS = (
    ("appsec", "Web security", "web/appsec_quickcheck.py"),
    ("secrets", "Git secrets", "repository/git_secrets_scan.py"),
    ("dependencies", "Dependency vulnerabilities", "repository/dependency_quickcheck.py"),
    ("subdomains", "Dangling CNAMEs", "network/subdomain_quickcheck.py"),
    ("sensitive_files", "Exposed files", "web/sensitive_files_quickcheck.py"),
    ("certificates", "Certificate expiry", "network/cert_expiry_quickcheck.py"),
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
        if checks[key] is None:
            results.append({"day": day, "name": name, "status": "SKIPPED", "exit_code": None,
                            "seconds": 0, "output": "No applicable input provided for this check."})
            continue
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


def quick_checks(repo, targets, scratch, notes=None):
    """Build normal CLI arguments from a repo and/or one origin list."""
    checks = {key: None for key, _, _ in CHECKS}
    if repo:
        project = Path(repo).resolve()
        if not project.is_dir():
            raise ValueError("Repository directory missing")
        checks["secrets"] = [str(project)]
        if any((project / name).is_file() for name in ("requirements.txt", "package-lock.json", "package.json")):
            checks["dependencies"] = [str(project)]
    if targets:
        # Reuse the root-origin and DNS-host validators of the bundled scripts.
        if __package__:
            from .web.sensitive_files_quickcheck import origin
            from .network.subdomain_quickcheck import hostname
        else:
            from web.sensitive_files_quickcheck import origin
            from network.subdomain_quickcheck import hostname
        values = Path(targets).read_text(encoding="utf-8-sig").splitlines()
        assets = list(dict.fromkeys(origin(line.split("#", 1)[0].strip()) for line in values
                                   if line.split("#", 1)[0].strip()))
        if not assets:
            raise ValueError("Target list is empty")
        names, certificates, omitted = [], [], 0
        for asset in assets:
            parsed = urllib.parse.urlsplit(asset)
            try:
                names.append(hostname(parsed.hostname))
            except ValueError:
                omitted += 1  # IP/short hostnames do not fit the CNAME check.
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            certificates.append(parsed.netloc if parsed.scheme == "https" else host + ":443")
        for filename, entries in (("assets.txt", assets), ("subdomains.txt", names), ("hosts.txt", certificates)):
            (scratch / filename).write_text("\n".join(dict.fromkeys(entries)) + "\n", encoding="utf-8")
        checks["appsec"] = ["-f", str(scratch / "assets.txt")]
        checks["sensitive_files"] = ["-f", str(scratch / "assets.txt")]
        checks["certificates"] = ["-f", str(scratch / "hosts.txt")]
        if names:
            checks["subdomains"] = ["-f", str(scratch / "subdomains.txt")]
        if omitted and notes is not None:
            notes.append(f"Day 4 omits {omitted} IP/short-hostname target(s); the DNS check requires full hostnames.")
    return checks


def report_text(results, generated, notes=()):
    lines = [TITLE, "", f"Generated: {generated} (UTC)", "",
             "| Day | Check | Result | Exit | Seconds |", "| --- | --- | --- | --- | --- |"]
    for item in results:
        code = item["exit_code"] if item["exit_code"] is not None else "-"
        lines.append(f'| {item["day"]} | {item["name"]} | {item["status"]} | {code} | {item["seconds"]} |')
    lines += ["", "PASS means the selected script completed below its configured finding threshold.",
              "SKIPPED means not assessed; review all output for skipped files, limited scope and findings below that threshold."]
    lines.extend("\n" + note for note in notes)
    for item in results:
        lines += ["", f'## Day {item["day"]}: {item["name"]}', ""]
        # Indented blocks keep captured output from becoming active Markdown.
        output = (item["output"].strip() or "(no output)").splitlines()
        lines.extend("    " + line for line in output[:MAX_REPORT_LINES])
        if len(output) > MAX_REPORT_LINES:
            lines.append(f"    ... {len(output) - MAX_REPORT_LINES} lines omitted; rerun this check directly for full output.")
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
    parser.add_argument("config", nargs="?", help="JSON config (default: weekly_runner.json unless using quick inputs)")
    parser.add_argument("--repo", help="Quick input: repository/project directory for Days 2 and 3")
    parser.add_argument("--targets", help="Quick input: hostname or HTTP(S) origin file for Days 1, 4, 5, 6")
    parser.add_argument("--report", "--out", help="Report path; relative to config directory, or current directory for quick inputs")
    parser.add_argument("--step-timeout", "--timeout", type=float, default=300, help="Seconds allowed per script (default: 300)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.step_timeout) or args.step_timeout <= 0:
        parser.error("step timeout must be positive and finite")
    if args.config and (args.repo or args.targets):
        parser.error("choose JSON config or --repo/--targets quick inputs")
    scratch = tempfile.TemporaryDirectory(prefix="weekly-runner-")
    try:
        config_path = Path(args.config or "weekly_runner.json").resolve()
        quick = bool(args.repo or args.targets)
        directory = Path.cwd() if quick else config_path.parent
        notes = []
        checks = quick_checks(args.repo, args.targets, Path(scratch.name), notes) if quick else load_config(config_path)
        default_report = ("reports/weekly-report-" + dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d") + ".md") if quick else "reports/weekly-report.md"
        destination = (directory / (args.report or default_report)).resolve()
        protected = {config_path, Path(__file__).resolve(), *(SCRIPT_DIR / filename for _, _, filename in CHECKS)}
        if args.targets:
            protected.add(Path(args.targets).resolve())
        # Protect input files explicitly mentioned in child argument lists.
        for arguments in checks.values():
            for argument in arguments or []:
                candidate = (directory / argument).resolve()
                if candidate.is_file():
                    protected.add(candidate)
        if destination in protected:
            raise ValueError("Report must not overwrite a script, config or input file")
        if destination.exists():
            with destination.open(encoding="utf-8") as handle:
                if handle.read(len(TITLE)) != TITLE:
                    raise ValueError("Destination already contains an unrelated file")
    except (OSError, ValueError, UnicodeError, ImportError):
        scratch.cleanup()
        print("Error: invalid config or report destination; no checks run.", file=sys.stderr)
        return 2
    generated = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        results = run_checks(checks, directory, args.step_timeout)
    finally:
        scratch.cleanup()
    try:
        write_report(destination, report_text(results, generated, notes))
    except OSError:
        print("Error: report could not be written. Captured results follow:", file=sys.stderr)
        print(report_text(results, generated, notes))
        return 2
    print(f"Report: {destination}")
    for item in results:
        print(f'Day {item["day"]}: {item["status"]}')
    selected = [item for item in results if item["status"] != "SKIPPED"]
    return 2 if not selected or any(item["exit_code"] not in (0, 1) for item in selected) else 1 if any(item["exit_code"] == 1 for item in selected) else 0


if __name__ == "__main__":
    sys.exit(main())
