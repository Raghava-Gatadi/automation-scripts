# Automation scripts

Small Python utilities using only the standard library. Requires Python 3.9+;
the secrets scanner also requires Git on your PATH.

## Dangling CNAME quick check (day 4)

`subdomain_quickcheck.py` follows CNAME chains for supplied hostnames and flags
missing targets for manual review. Uses Python's standard library and
[Google Public DNS's JSON API](https://developers.google.com/speed/public-dns/docs/doh/json).

```sh
python3 subdomain_quickcheck.py app.example.com docs.example.com
python3 subdomain_quickcheck.py -f subdomains.txt --json cname-report.json
python3 subdomain_quickcheck.py subdomains.txt --http -v
```

- Accepts hostnames or a file with one per line, deduplicates inputs, and follows
  up to ten CNAME links. Positional filenames and `-f` both work. Four concurrent
  checks keep larger lists quick. Inputs must be hostnames rather than URLs;
  no enumeration is performed. Default output shows candidates and errors;
  `-v` shows all observations. JSON always includes every result.
- `DANGLING`: an observed CNAME chain ends in NXDOMAIN. `NO_ADDRESS`: the target
  exists but has neither A nor AAAA data; check its intended use. Both are review
  candidates, not proof a resource can be claimed.
- `RESOLVES`: an address was found. This does not rule out an unclaimed hosted
  service. `NO_CNAME` and `NOT_FOUND` describe the input hostname, without implying
  a takeover finding. A nonexistent input alone is not a dangling CNAME.
- `ERROR`: timeouts, DNS errors such as SERVFAIL/REFUSED, loops, changing answers,
  invalid API responses, or a depth limit. Requested HTTP probes that fail or
  redirect also produce ERROR. These results are inconclusive.
- `--http` enables one HTTPS GET to the **original input hostname** for a resolving
  CNAME chain matching a supplied service pattern. Checks the first 20,000 body
  bytes, including HTTP error bodies such as 404. TLS verification remains enabled;
  redirects are not followed and there is no plaintext retry. Bodies are not saved.
  DNS-only remains the default. Unknown providers are not HTTP-probed.
- `SERVICE_CLUE`: a known service's error-page text matched, prompting manual
  review. Missing text does **not** mean a resource is claimed. Page wording,
  localization, compression, and the body limit can cause missed matches.
  A redirect or failed probe retains `dns_status` and HTTP metadata in JSON.
- The supplied `takeover_check.py` contributes patterns for GitHub Pages, Heroku,
  S3, Shopify, Fastly, Surge, Pantheon, Zendesk, Bitbucket, Ghost, and Tumblr.
  These are static page clues, not a current list of exploitable providers; confirm
  findings against the [service guidance](https://github.com/EdOverflow/can-i-take-over-xyz).
  Azure suffixes add context without HTTP fingerprint checks. Provider protections
  and resource claimability require separate review; see
  [Microsoft's dangling DNS guidance](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover).
- Queries go to Google Public DNS; only check names you are authorized to assess.
  Internal/split DNS may look different from this public resolver. This is a
  single cached DNS view; confirm findings against authoritative DNS before acting.
  The timeout is per request, not for the whole run. No accounts or resources are
  created, and the script does not attempt to claim targets.
- Exit **0**: no candidates observed in the selected checks; **1**: candidates to review; **2**:
  invalid input, inconclusive lookup, or report error. Exit 2 takes precedence.

The combination keeps this script's dependency-free DNS-over-HTTPS, full CNAME
chain, IPv6 handling, JSON, and distinct DNS error states. From the supplied
version it takes service-page clues, file arguments, concise output and bounded
concurrency. It avoids treating a missing fingerprint as “claimed” or an error
page as a confirmed vulnerability. No `dig` installation is required.

Run the focused tests (mocked DNS and HTTP, no live requests):

```sh
python3 -m unittest -v test_subdomain_quickcheck.py
```

## Dependency quick check (day 3)

`dependency_quickcheck.py` sends exact package versions from `requirements.txt`,
`package.json`, and `package-lock.json` (v2/v3) to the [OSV API](https://google.github.io/osv.dev/post-v1-querybatch/)
and prints advisory IDs with links. It uses only the Python standard library.

```sh
python3 dependency_quickcheck.py                   # manifests in this directory
python3 dependency_quickcheck.py /path/to/project
python3 dependency_quickcheck.py requirements.txt frontend/package.json
python3 dependency_quickcheck.py requirements.txt frontend/package-lock.json
python3 dependency_quickcheck.py /path/to/project --json dependency-report.json
```

- Checks Python `name==version` pins (including extras and hash annotations),
  plus exact npm versions in dependencies, devDependencies and optionalDependencies.
  Python environment markers are not evaluated: every supported declared pin is
  checked, even if its marker would exclude it on the current machine.
- When given a directory, prefers `package-lock.json` over `package.json` and
  prints the selected input files. Explicit file arguments are honored even when
  a sibling lockfile exists. A malformed lockfile fails rather than silently
  falling back to a manifest. Lockfile v1 is unsupported.
- Lockfile scans include pinned direct and transitive registry packages, including
  nested/scoped packages and recorded dev/optional packages. The project root is
  excluded. Recorded real names are used for aliases when available. Git/local
  dependencies, workspace links, and entries without usable names or versions
  are listed as skipped. OS/platform applicability is not evaluated. Lockfiles
  describe a dependency snapshot; the script does not verify freshness against
  package.json or check the actual installed tree.
- Lists unsupported entries as skipped. It does not guess versions for ranges
  such as `>=1.0` or `^1.2.3`, resolve tags/aliases, follow requirements includes,
  or install dependencies. Peer requirements and workspaces are flagged for
  follow-up when scanning package.json; pass each workspace's manifest explicitly.
  Python pins and standalone package.json scans cover declared dependencies only.
- Queries unique ecosystem/name/version combinations in batches and follows OSV
  pagination. Multiple advisory records can describe the same underlying issue.
  Links provide details; the script does not calculate severity or choose upgrades.
- Sends package names and versions to OSV, including private package names if
  declared with supported pins. It does not send entire manifests or index URLs.
- Exit **0**: all supported declarations checked with no matching advisories;
  **1**: advisories found; **2**: skipped entries, invalid input, network/API errors,
  or report-write failure. Exit 2 takes precedence over discovered advisories.
  An empty manifest has zero packages to check; no matching advisory is not proof
  that a dependency is safe.

The combined version keeps lockfile support and the short advisory summary from
the supplied `osv_check.py`, plus exact-version validation, pagination, cross-file
deduplication, skip reporting, and JSON from the first version. It deliberately
does not strip `^` or `~` to treat a range's lower bound as an installed version.
Lockfile handling follows the [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

Run the dependency tests (temporary manifests and mocked OSV, no live API calls):

```sh
python3 -m unittest -v test_dependency_quickcheck.py
```

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
and TLS certificate validity. Version 2 combines the original script's simple
standard-library CLI with stricter parsing, bounded redirects, and explicit
scan-completeness reporting. Only scan systems you own or are authorized to test.

```sh
python3 appsec_quickcheck.py https://example.com
python3 appsec_quickcheck.py -f targets.txt --json report.json --fail-on MEDIUM
python3 appsec_quickcheck.py https://example.com --allow-host www.example.com
python3 appsec_quickcheck.py https://example.com:8443 --http-port 8080
python3 appsec_quickcheck.py https://example.com --no-http-probe --max-redirects 3
```

### What the combined version keeps and improves

| Area | Original behavior | Combined behavior |
| --- | --- | --- |
| CLI and dependencies | Python standard library, target files, JSON, severity threshold | Retained; target inputs are validated and deduplicated before any request. |
| Cookies | Searches the entire Set-Cookie text for flag substrings | Parses individual attributes; checks SameSite, Partitioned, and prefix requirements without printing cookie values. |
| Redirects | Follows arbitrary hosts; returns status 0 after the limit | Detects loops, invalid destinations, and exhausted limits; stops HTTPS downgrades and unapproved host changes. |
| TLS | Opens a separate connection to the initial hostname | Inspects the verified TLS connection used for each response, including followed HTTPS redirects. |
| Headers | Mostly presence and substring checks | Validates HSTS max-age, nosniff, X-Frame-Options, and Referrer-Policy; applies document-specific checks to HTML or missing Content-Type. |
| CSP | Flags unsafe-inline wherever it appears | Inspects script directives and fallback rules, distinguishes report-only policies, and accounts for nonces/hashes. |
| CORS | Calls wildcard origin plus credentials a HIGH finding | Reports a MEDIUM browser-rejected configuration; does not claim credential exposure from that alone. |
| Failure handling | Broad exception suppression for the HTTP probe | Distinguishes refused HTTP connections from an inconclusive probe; network and redirect failures make the scan incomplete. |
| Reports | Raw target URLs and direct JSON writes | Redacts query strings and raw header values; writes JSON atomically and reports completeness per target. |

Side-by-side regression cases against the original script confirmed that the
combined version catches a cookie value that merely contains `secure`, `httponly`,
and `samesite`; upgrades `HSTS max-age=0` from LOW to HIGH; detects invalid
X-Frame-Options; and avoids the old warning for a nonce-based CSP with
`unsafe-inline`. The original file remains available in Git history.

### Scope, requests, and exit codes

- Each target uses unauthenticated GET requests; response bodies are not read,
  cookies are not replayed, and pages are not crawled. There is no CORS reflection
  probe, exploit verification, or authenticated application testing.
- Redirects stay on the starting hostname unless an additional hostname is
  supplied with repeatable `--allow-host`. Ports may change on allowed hosts.
  The default limit is five redirects; `--max-redirects` accepts 0 through 50.
  HTTPS-to-HTTP downgrades are reported and never followed.
- For an initial HTTPS target, a separate HTTP request checks `/` on port 80.
  It sends neither the original path nor query and checks only whether the first
  response redirects directly to HTTPS. `--http-port` changes that port;
  `--no-http-probe` disables this request. Connection refusal is recorded as an
  observation; DNS failures, timeouts, and other probe errors are inconclusive.
- Certificate and hostname validation remain enabled. TLS findings describe
  the negotiated protocol, not every protocol the server supports. The scanner
  does not retry with unverified certificates or attempt obsolete protocols.
- Cookie, HSTS, and information-leak checks include intermediate responses.
  Document-specific CSP, framing, Referrer-Policy, and Permissions-Policy checks
  apply to terminal HTML responses or responses with no Content-Type. Unknown
  HTML context is treated conservatively. Error pages are explicitly identified.
- Header checks are baseline heuristics. Multiple CSP policies can impose
  stricter combined restrictions than an individual-policy warning suggests.
  Permissions-Policy presence is checked, not application-specific correctness.
  Cookie flag recommendations depend on the cookie's purpose. A clean result
  is not a full application security assessment.
- `--timeout` defaults to 8 seconds **per socket operation**, not for the entire
  run. Redirects, DNS resolution, and multiple targets can take longer.
- Exit **0** means all requested checks completed below `--fail-on` (default
  HIGH); **1** means completed checks found an issue at or above that threshold;
  **2** means invalid input, report failure, or an incomplete scan. Exit 2 takes
  precedence over findings, including a failed TLS certificate verification.
  An HTTP error status alone does not make header inspection incomplete.

### JSON compatibility and output privacy

Version 2 retains `--json` but changes the JSON format: `schema_version` is 2
and `results` is a **list**, replacing the original object keyed by raw URLs.
Each result contains `target`, `complete`, `responses_checked`, and `findings`.
Each finding has `severity`, `check`, and `detail`, with a redacted `url` or probe
`scope` where applicable. Update consumers of the original JSON format.

Queries are replaced with `[REDACTED]` and fragments are removed from reports.
Cookie values and raw response headers are not logged. **Hosts and URL paths
remain visible**; avoid embedding secrets in path segments. URLs containing
userinfo are rejected. Query values are still sent to the requested target and
any followed redirect as required by HTTP URL resolution.

Run the offline tests (local HTTP server and mocked TLS, no public targets):

```sh
python3 -m unittest -v test_appsec_quickcheck.py
python3 -m unittest discover -v
```

Behavior references: [MDN cookie attributes and prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie),
[MDN credentialed CORS with wildcard origins](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials),
[MDN CSP script sources](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src),
and [Python TLS documentation](https://docs.python.org/3/library/ssl.html).
