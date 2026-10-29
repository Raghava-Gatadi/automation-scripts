# Automation scripts

Small Python utilities using only the standard library. Requires Python 3.9+;
the secrets scanner also requires Git on your PATH.

## Git repository secrets scanner

`git_secrets_scan.py` scans tracked working-tree files for private keys, common
provider token formats, credentials in URLs, sensitive variable assignments,
and high-entropy strings. It prints file paths, line numbers, and rule names;
matched values and source lines are never included in console or JSON output.

```sh
# Scan this repository, or pass a path to another checkout.
python3 git_secrets_scan.py
python3 git_secrets_scan.py /path/to/repo

# Scan the entire staged snapshot, including files unchanged by this commit.
python3 git_secrets_scan.py --staged

# Also inspect untracked files that are not excluded by .gitignore.
python3 git_secrets_scan.py --include-untracked

# Save a redacted report (relative paths resolve against the repository root).
python3 git_secrets_scan.py --json /tmp/secrets-report.json
```

Exit codes: **0** means no new findings (or a successful baseline write),
**1** means new potential secrets, and **2** means an input or operational error.

### Baseline workflow

First review the findings. Remove actual secrets from source and rotate exposed
credentials. Use a baseline only for findings you deliberately accept, such as
test fixtures and false positives:

```sh
python3 git_secrets_scan.py --write-baseline
git add .secrets-baseline.json

# Future runs suppress findings recorded in that baseline.
python3 git_secrets_scan.py
```

The default baseline is `.secrets-baseline.json` at the repository root.
`--baseline PATH` selects a different file. `--write-baseline` explicitly replaces
the baseline with all findings in the selected scan scope, removing stale entries;
it reports new findings but exits 0. Normal scans never modify the baseline.
Use consistent scope and thresholds when refreshing a baseline.
This repository's included baseline accepts only the synthetic entropy-test value
in `test_git_secrets_scan.py`.

Each entry contains a SHA-256 fingerprint of the file path, rule ID, and matched
value, plus location metadata. Moving a finding to another line in the same file
keeps it baselined; changing the value or file path flags it again. Private key
fingerprints cover the whole key block. Baselines contain no raw matched values,
but hashes of weak secrets can be guessed: review baselines and their file paths
before publishing them. A malformed baseline fails the scan instead of silently
disabling checks. Protect baseline changes through normal code review.

### Scope and tuning

- `--entropy-threshold 4.5` sets the Shannon entropy cutoff in bits per character.
  Candidates need at least 20 characters and both letters and digits. Hex strings
  need at least 32 characters and use a cutoff capped at 3.5. Hashes, lockfiles,
  and generated identifiers can produce false positives.
- `--max-bytes 1048576` sets the per-file size limit (default 1 MiB).
- Binary files containing NUL bytes, oversized files, symlinks, submodules, and
  tracked files deleted from the working tree are skipped and listed in the
  console and JSON report. Skips alone do not produce a nonzero exit code;
  review them when coverage matters. Submodules require separate scans.
- Tracked files are scanned even when a `.gitignore` rule would match them.
  Untracked and ignored files are excluded by default. Baseline and report files
  are excluded from their own scan.
- This scans the current working tree or Git index, **not commit history**.
  It cannot prove a repository is secret-free, validate credentials, or detect
  every encoded or split secret. No network requests or external dependencies
  are used by the scanner.

Run the disposable-repository tests with:

```sh
python3 -m unittest -v test_git_secrets_scan.py
```

## Web security quick check

`appsec_quickcheck.py` checks HTTPS redirects, security headers, cookie flags,
and TLS certificate validity. Only scan systems you own or are authorized to test.

```sh
python3 appsec_quickcheck.py https://example.com
python3 appsec_quickcheck.py -f targets.txt --json report.json --fail-on MEDIUM
```
