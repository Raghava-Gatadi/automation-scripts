#!/usr/bin/env python3
"""Scan Git working-tree or staged files for potential secrets (Python stdlib only)."""

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


VERSION = 1
DEFAULT_BASELINE = ".secrets-baseline.json"
# Keep rule IDs stable: they are part of baseline fingerprints.
RULES = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
    ("credential-url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@", re.I)),
    ("secret-assignment", re.compile(
        r"(?<![\w-])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
        r"client[_-]?secret|[a-z0-9_]*(?:_password|_secret|_token|_api_key))"
        r"[\"']?\s*[:=]\s*[\"']?([^\s\"'`,;#}\]]{8,})", re.I)),
)
CANDIDATE_PATTERN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{20,}={0,2}(?![A-Za-z0-9_+/=-])")
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
    r"[\s\S]*?(?:-----END (?P=kind)-----|\Z)")


class ScanError(Exception):
    pass


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if result.returncode:
        # Git errors can contain file contents or credential-bearing URLs.
        raise ScanError(f"Git command failed: {args[0]}")
    return result.stdout


def entropy(value):
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def fingerprint(path, rule, value):
    payload = json.dumps([path, rule, value], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def detect(path, text, threshold):
    """Return locations and fingerprints only; never return matched secrets."""
    findings = []
    key_lines = set()
    for match in PRIVATE_KEY.finditer(text):
        line_number = text.count("\n", 0, match.start()) + 1
        key_lines.update(range(line_number, line_number + match.group().count("\n") + 1))
        findings.append({"path": path, "line": line_number, "rule": "private-key",
                         "fingerprint": fingerprint(path, "private-key", match.group())})
    for line_number, line in enumerate(text.splitlines(), 1):
        if line_number in key_lines:
            continue
        covered = []
        for rule, pattern in RULES:
            for match in pattern.finditer(line):
                group = 1 if pattern.groups else 0
                start, end = match.span(group)
                if any(start < b and end > a for a, b in covered):
                    continue
                covered.append((start, end))
                findings.append({"path": path, "line": line_number, "rule": rule,
                                 "fingerprint": fingerprint(path, rule, match.group(group))})
        for match in CANDIDATE_PATTERN.finditer(line):
            if any(match.start() < b and match.end() > a for a, b in covered):
                continue
            value = match.group()
            # Require letters and digits to reduce prose and path false positives.
            if not (re.search(r"[A-Za-z]", value) and re.search(r"[0-9]", value)):
                continue
            is_hex = bool(re.fullmatch(r"[A-Fa-f0-9]{32,}", value))
            limit = min(threshold, 3.5) if is_hex else threshold
            score = entropy(value)
            if score >= limit:
                rule = "entropy-hex" if is_hex else "entropy-token"
                findings.append({"path": path, "line": line_number, "rule": rule,
                                 "entropy": round(score, 3),
                                 "fingerprint": fingerprint(path, rule, value)})
    return findings


def load_baseline(path):
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != VERSION:
            raise ValueError()
        entries = data["findings"]
        if not isinstance(entries, list):
            raise ValueError()
        result = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError()
            digest = entry.get("fingerprint")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError()
            result.add(digest)
        return result
    except (OSError, ValueError, KeyError) as exc:
        raise ScanError("Cannot read baseline or unsupported baseline format") from exc


def write_json(path, data):
    """Replace atomically, so an interrupted run does not corrupt a baseline."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".secrets-scan-", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def scan(root, staged, include_untracked, excluded, max_bytes, threshold):
    entries = {}
    for record in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, oid, stage = metadata.split()
        path = os.fsdecode(raw_path)
        if stage != b"0":
            raise ScanError("Resolve Git index conflicts before scanning")
        entries[path] = (mode, oid.decode("ascii"))
    if include_untracked:
        for raw_path in git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
            if raw_path:
                entries[os.fsdecode(raw_path)] = (b"100644", None)
    findings, skipped, scanned = [], [], 0
    for path, (mode, oid) in sorted(entries.items()):
        full_path = root / path
        if full_path in excluded:
            continue
        if mode not in (b"100644", b"100755"):
            skipped.append({"path": path, "reason": "symlink or submodule"})
            continue
        if staged:
            if int(git(root, "cat-file", "-s", oid)) > max_bytes:
                skipped.append({"path": path, "reason": "size limit"})
                continue
            content = git(root, "cat-file", "blob", oid)
        else:
            # Never follow file or parent-directory symlinks outside the checkout.
            if full_path.is_symlink() or full_path.resolve() != full_path:
                skipped.append({"path": path, "reason": "symlink"})
                continue
            try:
                with full_path.open("rb") as handle:
                    content = handle.read(max_bytes + 1)
            except FileNotFoundError:
                skipped.append({"path": path, "reason": "deleted from working tree"})
                continue
            except OSError as exc:
                raise ScanError(f"Cannot read file: {json.dumps(path)}") from exc
            if len(content) > max_bytes:
                skipped.append({"path": path, "reason": "size limit"})
                continue
        if b"\0" in content:
            skipped.append({"path": path, "reason": "binary"})
            continue
        findings.extend(detect(path, content.decode("utf-8", errors="replace"), threshold))
        scanned += 1
    return findings, skipped, scanned


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", default=".", help="Repository path (default: current directory)")
    parser.add_argument("--staged", action="store_true", help="Scan the entire Git index instead of working files")
    parser.add_argument("--include-untracked", action="store_true", help="Include non-ignored untracked files")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE, help="Baseline path, relative to repo root")
    parser.add_argument("--write-baseline", action="store_true", help="Replace baseline with all current findings after review")
    parser.add_argument("--json", metavar="PATH", help="Write a redacted JSON report, relative to repo root")
    parser.add_argument("--entropy-threshold", type=float, default=4.5, help="Token entropy cutoff (default: 4.5 bits/character)")
    parser.add_argument("--max-bytes", type=int, default=1048576, help="Maximum file size (default: 1 MiB)")
    args = parser.parse_args(argv)
    if args.staged and args.include_untracked:
        parser.error("--staged cannot be combined with --include-untracked")
    if not 0 < args.entropy_threshold <= 6 or args.max_bytes < 1:
        parser.error("entropy threshold must be in (0, 6] and max bytes must be positive")
    try:
        root = Path(os.fsdecode(git(args.repo, "rev-parse", "--show-toplevel")).rstrip("\n")).resolve()
        baseline = Path(os.path.abspath(root / args.baseline))
        report_path = Path(os.path.abspath(root / args.json)) if args.json else None
        if report_path and report_path.resolve() == baseline.resolve():
            raise ScanError("JSON report and baseline must have different paths")
        # Do not silently overwrite repository source files with generated output.
        tracked = {root / os.fsdecode(p) for p in git(root, "ls-files", "-z").split(b"\0") if p}
        if report_path in tracked:
            raise ScanError("JSON report must not overwrite a tracked file")
        known = load_baseline(baseline)
        findings, skipped, scanned = scan(root, args.staged, args.include_untracked,
                                           {baseline, report_path}, args.max_bytes,
                                           args.entropy_threshold)
        fresh = [finding for finding in findings if finding["fingerprint"] not in known]
        report = {"version": VERSION, "mode": "staged" if args.staged else "working-tree",
                  "files_scanned": scanned, "new_findings": fresh,
                  "baselined_count": len(findings) - len(fresh), "skipped": skipped}
        if report_path:
            write_json(report_path, report)
        for finding in fresh:
            print(f'{json.dumps(finding["path"])}:{finding["line"]}: {finding["rule"]} [REDACTED]')
        print(f"Scanned {scanned} files; {len(fresh)} new, {len(findings) - len(fresh)} baselined findings; {len(skipped)} skipped.")
        for item in skipped:
            print(f'Skipped {json.dumps(item["path"])}: {item["reason"]}', file=sys.stderr)
        if args.write_baseline:
            unique = {finding["fingerprint"]: finding for finding in findings}
            write_json(baseline, {"version": VERSION, "findings": list(unique.values())})
            print(f"Baseline written with {len(unique)} entries. Review it before committing.")
            return 0
        return 1 if fresh else 0
    except (ScanError, OSError) as exc:
        # Avoid echoing arbitrary OS error strings, which may contain sensitive input.
        message = str(exc) if isinstance(exc, ScanError) else "File or command operation failed"
        print(f"Error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
