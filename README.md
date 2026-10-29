# Automation scripts

Small Python utilities using only the standard library. Requires Python 3.9+;
the secrets scanner also requires Git on your PATH.

## Git repository secrets scanner

`git_secrets_scan.py` scans tracked working-tree files for private keys, common
provider token formats, credentials in URLs, sensitive variable assignments,
and high-entropy strings. It prints severity, file paths, line numbers, and rule names;
matched values and source lines are never included in console or JSON output.

```sh
# Scan this repository, or pass a path to another checkout.
python3 git_secrets_scan.py
python3 git_secrets_scan.py /path/to/repo

# Scan the entire staged snapshot, including files unchanged by this commit.
python3 git_secrets_scan.py --staged

# Also inspect untracked files that are not excluded by .gitignore.
python3 git_secrets_scan.py --include-untracked

# Also scan history reachable from all local refs and HEAD.
python3 git_secrets_scan.py --history

# Save a redacted report (relative paths resolve against the repository root).
python3 git_secrets_scan.py --json /tmp/secrets-report.json
```

Exit codes: **0** means no new findings (or a successful baseline write),
**1** means new potential secrets, and **2** means an input or operational error.
Every severity causes exit 1 when new: HIGH identifies strong credential patterns,
MEDIUM covers generic assignments and other token formats, and LOW covers entropy
heuristics. Severity is a triage hint, not proof that a credential is valid.

### Combined design

This version combines the original scanner with the supplied `secrets_scanner.py`:

| Area | Selection |
| --- | --- |
| Detection | Keep existing rule IDs; add AWS secret keys, Slack webhooks, JWTs, and PGP private keys from the supplied version. |
| Entropy noise | Use the supplied version's quoted/assigned context and UUID filtering; require a nearby keyword for hex candidates. Keep broad scanning available with `--entropy-mode all`. |
| History | Adopt `--history`, implemented using complete Git blobs and NUL-delimited tree records to handle merge commits, multiline keys, and unusual filenames. |
| Baselines | Keep full SHA-256 fingerprints, validation, and atomic writes; add stale-entry reporting and the `--update-baseline` alias. |
| Output | Add severity and commit locations; keep full redaction rather than revealing secret prefixes. |
| Scan coverage | Keep staged scanning, optional untracked files, symlink protection, and reported skips. No automatic vendor/lockfile or long-line exclusions. |
| Suppression | Add explicit glob exclusions and opt-in inline allowlists; use exact placeholder matches instead of broad substring filtering. |

The scanner requires a Git checkout; it does not silently fall back to directory
walking when Git fails. All functionality uses the Python standard library.

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
`--baseline PATH` selects a different file. `--write-baseline` (also spelled
`--update-baseline`) explicitly replaces
the baseline with all findings in the selected scan scope, removing stale entries;
it reports new findings but exits 0. Normal scans never modify the baseline.
Use consistent scope and thresholds when refreshing a baseline.
Stale counts mean an entry was not found in the selected scope, not necessarily
that the secret disappeared from all history. Use `--history --update-baseline`
when reviewing and accepting historical findings as well. Duplicate findings
share one entry; current files take precedence over historical occurrences.
This repository's included baseline accepts only synthetic test values in
`test_git_secrets_scan.py`.

Each entry contains a SHA-256 fingerprint of the file path, rule ID, and matched
value, plus location metadata. Moving a finding to another line in the same file
keeps it baselined; changing the value or file path flags it again. Private key
fingerprints cover the whole key block. Baselines contain no raw matched values,
but hashes of weak secrets can be guessed: review baselines and their file paths
before publishing them. A malformed baseline fails the scan instead of silently
disabling checks. Protect baseline changes through normal code review.
Existing baselines from earlier versions of `git_secrets_scan.py` remain readable.
The supplied standalone script used a different, truncated fingerprint format;
those baseline files must be regenerated and reviewed, not copied over directly.

### Scope and tuning

- `--entropy-threshold 4.5` sets the Shannon entropy cutoff in bits per character.
  Candidates need at least 20 characters and both letters and digits. Hex strings
  need at least 32 characters and use a cutoff capped at 3.5. The default
  `--entropy-mode contextual` examines quoted/assigned candidates, skips UUIDs,
  and requires a secret-related keyword before hex candidates on the same line.
  `--entropy-mode all` checks all candidate tokens, including bare strings and
  hashes. `--no-entropy` disables entropy checks; regex rules still run.
  Hashes, lockfiles, and generated identifiers can still produce false positives.
- `--exclude 'vendor/*'` explicitly skips matching repo-relative paths in both
  current files and history. Repeat the option for more patterns. Globs match the
  entire path, are case-sensitive, and `*` can cross directory separators. Quote
  globs to prevent shell expansion. Exclusions appear in the skipped list.
- `--honor-allowlist` enables comment markers such as `# pragma: allowlist secret`
  and `// nosecret` on the finding's line. This uses a comment-pattern heuristic,
  not a language parser; review suppressions. Markers are ignored by default.
  Inline-allowlisted findings are counted in the report and omitted from baseline
  writes. A marker on a private-key header accepts that whole key block. A new
  comment does not suppress an unallowlisted occurrence in history.
- `--max-bytes 1048576` sets the per-file size limit (default 1 MiB).
- Binary files containing NUL bytes, oversized files, symlinks, submodules, and
  tracked files deleted from the working tree are skipped and listed in the
  console and JSON report. Skips alone do not produce a nonzero exit code;
  review them when coverage matters. Submodules require separate scans.
- Tracked files are scanned even when a `.gitignore` rule would match them.
  Untracked and ignored files are excluded by default. Baseline and report files
  are excluded from their own scan.
- `--history` adds every unique file version reachable from local refs and HEAD,
  including deleted files, other branches, and merge-only changes. It reports
  a commit containing each finding and its real line number. It never fetches
  remote commits; unreachable objects and reflog-only commits are outside scope.
  Shallow clones produce a warning. Large histories can be expensive because
  each commit tree is enumerated, although unchanged file versions are scanned
  only once per path. Size limits and exclusions also apply to historical files.
- Without `--history`, only current working-tree files or the Git index are scanned.
  No mode can prove a repository is secret-free, validate credentials, or detect
  every encoded or split secret. No network requests are made.

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
