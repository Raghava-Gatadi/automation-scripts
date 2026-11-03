# Web security quick check

`appsec_quickcheck.py` checks HTTPS redirects, security headers, cookie flags,
and TLS certificate validity. Version 2 combines the original script's simple
standard-library CLI with stricter parsing, bounded redirects, and explicit
scan-completeness reporting. Only scan systems you own or are authorized to test.

```sh
python3 scripts/web/appsec_quickcheck.py https://example.com
python3 scripts/web/appsec_quickcheck.py -f targets.txt --json report.json --fail-on MEDIUM
python3 scripts/web/appsec_quickcheck.py https://example.com --allow-host www.example.com
python3 scripts/web/appsec_quickcheck.py https://example.com:8443 --http-port 8080
python3 scripts/web/appsec_quickcheck.py https://example.com --no-http-probe --max-redirects 3
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
python3 -m unittest -v tests.test_appsec_quickcheck
python3 -m unittest discover -v
```

Behavior references: [MDN cookie attributes and prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie),
[MDN credentialed CORS with wildcard origins](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials),
[MDN CSP script sources](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src),
and [Python TLS documentation](https://docs.python.org/3/library/ssl.html).
