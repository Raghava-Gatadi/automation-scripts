# Exposed sensitive files quick check (day 5)

`sensitive_files_quickcheck.py` checks 25 fixed paths on your own assets. It combines
the supplied `exposed_files.py` path signatures, severity labels and concurrency
with fallback-page detection, bounded reads, JSON and explicit failure reporting.

| Category | Paths |
| --- | --- |
| Git and SVN | `/.git/HEAD`, `/.git/config`, `/.git/`, `/.svn/wc.db` |
| Environment and credentials | `/.env`, `/.env.local`, `/.env.bak`, `/.aws/credentials`, `/.npmrc`, `/.htpasswd` |
| Private keys | `/id_rsa`, `/.ssh/id_rsa` |
| Backups | `/backup.zip`, `/site.zip`, `/backup.tar.gz`, `/backup.sql`, `/dump.sql`, `/config.php.bak`, `/wp-config.php.bak`, `/wp-config.php~` |
| Diagnostics and configuration | `/actuator/env`, `/phpinfo.php`, `/server-status`, `/docker-compose.yml`, `/.DS_Store` |

```sh
python3 scripts/web/sensitive_files_quickcheck.py https://app.example.com
python3 scripts/web/sensitive_files_quickcheck.py -f assets.txt --json sensitive-report.json
python3 scripts/web/sensitive_files_quickcheck.py https://app.example.com -v
python3 scripts/web/sensitive_files_quickcheck.py https://staging.example.com -k
```

- Only scan assets you own or are explicitly authorized to assess. Inputs are
  origins (scheme, hostname and optional port); paths, credentials, queries, and
  fragments are rejected. Bare hostnames default to HTTPS.
- Performs one random nonexistent-path control request, followed by 25 fixed
  GETs with up to four concurrent requests. Sends a Range header and reads at most
  4 KiB per successful response, even if the server ignores Range. Certificates
  are verified by default. `-k`/`--insecure` explicitly disables certificate and
  hostname verification for that run; console output and the JSON field
  `tls_verification_enabled` record this choice. There is no automatic insecure
  retry after TLS failure. Redirects are
  recorded but never followed; provide the intended final origin explicitly.
- Flags recognizable Git metadata/listings, environment assignments to sensitive
  keys, credentials/configuration, archive signatures, SQL dumps, PHP source at
  backup paths, and diagnostic-page markers. A 200 alone
  is not a finding. Identical control/path bodies are treated as fallback pages.
  HTML is rejected for text-file checks; custom/dynamic fallback pages can still
  cause false positives. Review every candidate.
- HIGH/MEDIUM/LOW are triage labels, not proof of a secret. HIGH covers credential,
  repository and backup candidates; MEDIUM covers diagnostics and Compose
  configuration; LOW covers directory metadata. Actuator values may be redacted,
  npm configuration may use environment substitution, and published configuration
  or archives may be intentional. HTML exclusion stays in place for text-file
  checks; recognizable HTML diagnostic pages have separate signatures.
- Output and JSON contain paths, HTTP status, and fixed explanations only.
  Response contents, credentials, and header values are never printed or saved.
  Archives are not extracted and repositories are not reconstructed.
- `DENIED`, `REDIRECT`, and `NOT_FOUND` are observations, not exposure findings.
  `NO_MATCH` means the bounded response did not match the expected structure;
  it does not prove that the file is absent or harmless. Compression and malformed
  partial responses are inconclusive. Rate limits and server errors are errors.
- Exit **0**: no recognizable candidates in completed checks; **1**: candidates
  to review; **2**: invalid input, incomplete requests, or report errors. Exit 2
  takes precedence. Default output shows candidates/errors; `-v` shows all paths.
  Timeout is per socket operation, not per asset or entire run.

This is a first pass over common names, not a comprehensive file search. Git
signatures follow the [Git repository layout documentation](https://git-scm.com/docs/gitrepository-layout).
The combined list omits duplicate backup names and less useful legacy diagnostics.
It also omits `/actuator/heapdump`: [requesting it produces a JVM heap dump](https://docs.spring.io/spring-boot/api/rest/actuator/heapdump.html),
which can impose server work even when the client limits its read. Environment
diagnostic structure follows [Spring's env endpoint documentation](https://docs.spring.io/spring-boot/api/rest/actuator/env.html).

Run the focused tests (mocked responses only; no live asset requests):

```sh
python3 -m unittest -v tests.test_sensitive_files_quickcheck
```
