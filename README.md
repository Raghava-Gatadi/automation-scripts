# Security Automation Scripts

Small first-pass security checks to run before investigating a project or your
own assets. Each tool runs independently. Python 3.9+ and the standard library
are enough, except the secrets scanner needs Git and the Semgrep wrapper needs
the Semgrep CLI (plus Git for Git baseline comparisons).

## Repository layout

```text
scripts/
  web/          Web security headers and exposed sensitive files
  repository/   Secrets, dependency vulnerabilities and Semgrep
  network/      Dangling CNAMEs and certificate expiry
  weekly_runner.py
tests/          Offline unit and integration tests
examples/       Sample runner configuration
docs/           Usage, options and limitations for each tool
```

Run commands below from the repository root. Script paths can also be absolute;
target and output paths keep their documented working-directory/config semantics.

## Utility index

| Day | Tool | Guide |
| --- | --- | --- |
| 1 | [Web security check](scripts/web/appsec_quickcheck.py) | [Usage](docs/web-security.md) |
| 2 | [Git secrets scanner](scripts/repository/git_secrets_scan.py) | [Usage](docs/secrets.md) |
| 3 | [Dependency vulnerability check](scripts/repository/dependency_quickcheck.py) | [Usage](docs/dependencies.md) |
| 4 | [Subdomain takeover check](scripts/network/subdomain_quickcheck.py) | [Usage](docs/subdomains.md) |
| 5 | [Exposed sensitive files check](scripts/web/sensitive_files_quickcheck.py) | [Usage](docs/sensitive-files.md) |
| 6 | [Certificate expiry monitor](scripts/network/cert_expiry_quickcheck.py) | [Usage](docs/certificate-expiry.md) |
| — | [Weekly runner, Days 1–6](scripts/weekly_runner.py) | [Usage](docs/weekly-runner.md) |
| — | [Semgrep wrapper](scripts/repository/semgrep_quickcheck.py) | [Usage](docs/semgrep.md) |

```sh
python3 scripts/repository/git_secrets_scan.py /path/to/project
python3 scripts/repository/dependency_quickcheck.py /path/to/project
python3 scripts/web/appsec_quickcheck.py https://example.com
python3 scripts/network/cert_expiry_quickcheck.py example.com
```

Only scan systems you own or are authorized to assess. See each guide for scope,
exit codes and incomplete-result behavior.

The linked guides retain each utility's options, network behavior, baseline semantics and limits.

## Weekly report

```sh
cp examples/weekly_runner.example.json weekly_runner.json
# Edit weekly_runner.json with your repo path and authorized target files.
python3 scripts/weekly_runner.py weekly_runner.json
# Or supply quick inputs:
python3 scripts/weekly_runner.py --repo /path/to/project --targets targets.txt
```

Local configuration and generated `reports/` are ignored by Git. Keep the
configuration beside your input files: relative arguments resolve from the
configuration's directory. See the [runner guide](docs/weekly-runner.md) for
scheduling and options.

## Tests

Run the offline suite from the repository root:

```sh
python3 -m unittest discover -s tests -v
# Run a single tool's tests:
python3 -m unittest -v tests.test_weekly_runner
```

Tests use temporary files and mocked services; they do not scan live targets or
send alerts. Add future scripts to the relevant `scripts/` folder, their tests
to `tests/`, and usage notes to `docs/`.

Existing cron jobs or commands using root-level script paths must be updated to
the paths above. Accepted secrets fixtures remain in `.secrets-baseline.json` at
the repository root.
