# Semgrep quick check

`semgrep_quickcheck.py` runs Semgrep and summarizes new findings by severity,
rule and affected file. It combines accepted-findings files from the supplied
`semgrep_wrap.py` with the original wrapper's native Git comparison and error handling.

```sh
# Install Semgrep CLI separately using its official installation instructions.
python3 scripts/repository/semgrep_quickcheck.py /path/to/repo
python3 scripts/repository/semgrep_quickcheck.py /path/to/repo --update-baseline
python3 scripts/repository/semgrep_quickcheck.py /path/to/repo --fail-on ERROR
python3 scripts/repository/semgrep_quickcheck.py /path/to/repo --config p/default
python3 scripts/repository/semgrep_quickcheck.py /path/to/repo --config p/default --baseline HEAD~1
python3 scripts/repository/semgrep_quickcheck.py /path/to/repo --config .semgrep.yml --baseline origin/main --json reports/semgrep-summary.json
```

- `--config` is repeatable and defaults to `p/default`. Local rule paths are relative to the
  scanned directory; registry configs require network access. Trust the rules
  you select. This uses `semgrep scan` with the OSS engine, metrics off, version
  checks disabled, strict errors and finding exit codes. No autofix is requested.
- By default, compares against `<repo>/.semgrep-baseline.json`. A missing file
  means all findings are new. `--baseline-file PATH` chooses another file relative
  to the repo. `--update-baseline` explicitly accepts all current findings after
  a complete scan, writes atomically and exits 0. It never overwrites the baseline
  after scan errors, skipped rules, missing source, or timeout.
- File fingerprints cover rule ID, repo-relative file, severity and exact matched
  source lines, excluding line numbers. Line moves remain baselined; edits inside
  strings, formatting or severity changes resurface. An occurrence counter detects
  added identical matches. Source files must stay available and stable during
  the scan; unreadable/outside-repo source fails instead of hashing empty content.
  Baselines contain locations and hashes, not source, but hashes of guessable
  content can be guessed. Review baseline changes before committing them.
- Absent baseline entries are called **stale**, not fixed: rules, exclusions or
  scope changes can also explain their absence. Use consistent scope/rules when
  refreshing. The supplied standalone script used a different truncated hash
  format; regenerate into a new baseline path and review it rather than copying
  that baseline directly.
- `--baseline COMMIT_OR_REF` instead selects native Git diff mode. It is mutually
  exclusive with file-baseline selection/update. It resolves the local ref and delegates comparison to
  `--baseline-commit`: only findings absent from that baseline are returned.
  A missing/invalid baseline fails; it never falls back to a full scan.
  Fetch needed refs yourself and use a clean working tree as required by Semgrep.
  This mode is not an inventory of old, resolved or unchanged findings.
- `--fail-on INFO` (default) fails for any new finding. Choose WARNING or ERROR
  to change the gate; below-threshold findings remain visible. The threshold and
  blocking count are printed. Unlike the supplied version, messages that may
  interpolate source values are excluded from console and JSON.
- Prints the top five rules and first twenty finding locations. Optional JSON
  saves all returned locations and summary counts. Source snippets, interpolated
  messages, metavariables, fixes, traces and raw stderr are not printed or saved.
  Rule IDs, file paths and metadata remain visible. Run Semgrep directly when
  you need its detailed error diagnostics. Output paths are relative to your
  invoking directory; the parent directory must exist. Existing wrapper reports
  can be refreshed; unrelated existing files are protected.
- Semgrep's ignore rules, supported languages and normal size/coverage limits
  still apply. Skipped rules or JSON-reported scan errors produce an incomplete
  result. A zero-finding diff (or zero scanned files) is not a full security audit.
  `--timeout` caps the Semgrep process at 300 seconds by default.
- Exit **0**: completed with no new findings at/above the threshold, or a successful
  baseline update; **1**: new findings meet the threshold; **2**:
  missing tools, invalid config/baseline, timeout, partial/error results or output
  failure. This standalone wrapper is not added to the six-step weekly runner.

References: [Semgrep CLI and baseline options](https://docs.semgrep.dev/cli-reference),
[Semgrep JSON fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif).

Offline tests use Semgrep JSON fixtures and send no network traffic:

```sh
python3 -m unittest -v tests.test_semgrep_quickcheck
```
