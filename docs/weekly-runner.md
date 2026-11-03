# Weekly runner (Days 1–6)

`weekly_runner.py` calls the six scripts in day order and writes **one Markdown
report** with a status table and each script's combined console/error output.
Findings, failures and timeouts do not prevent later steps from running.

```sh
cp examples/weekly_runner.example.json weekly_runner.json
# Edit weekly_runner.json with your repo path and your authorized target files.
python3 scripts/weekly_runner.py weekly_runner.json
# Or use quick inputs without a JSON config:
python3 scripts/weekly_runner.py --repo /path/to/project --targets targets.txt
python3 scripts/weekly_runner.py --repo /path/to/project
python3 scripts/weekly_runner.py --targets targets.txt
```

The example reuses `assets.txt` (HTTP(S) origins) for Days 1 and 5,
`subdomains.txt` (DNS hostnames) for Day 4, and `hosts.txt` (TLS hosts/ports) for
Day 6. Day 2 scans your repository; Day 3 discovers dependency manifests there.
Keep all six check keys. Each value is the normal script's CLI arguments as a
JSON list; no shell expansion is performed. Arguments and target-file paths are
relative to the config's directory. The runner locates scripts in the bundled web, repository and network folders, independently of the current directory.

Quick inputs are taken from the supplied runner, adapted to this repository's
actual script names. `--targets` accepts DNS names or HTTP(S) origins, not URL
paths/queries. It creates temporary per-tool files: web tools receive origins,
the CNAME tool receives full DNS names (IP/short-name omissions are noted), and
the certificate tool receives host/port targets. HTTP origins map to TLS port
443; explicit HTTPS ports are preserved. Missing input groups and absent root
dependency manifests appear as **SKIPPED**, not PASS. `--repo` scans the working
tree; use JSON config to opt into history or additional tool flags. Config-file
and quick-input modes cannot be combined.

- Default output: `reports/weekly-report.md`, relative to the config directory.
  Quick mode defaults to `reports/weekly-report-YYYY-MM-DD.md` (UTC date) relative
  to the current directory. `--out` aliases `--report`; `--timeout` aliases
  `--step-timeout`.
  `--report PATH` selects another destination. Repeated runs replace that report
  atomically; unrelated existing files are protected. The local config and
  `reports/` directory are ignored by Git. Reports can contain internal asset and
  repository names; store them appropriately.
- Each script has a five-minute limit; change it with `--step-timeout SECONDS`.
  The report records partial output from timed-out checks. Each section is capped
  at 300 lines with an explicit omission count; run that tool directly for full
  output. A missing script is an
  error, not a skipped success. Exit **0** means all six returned 0; **1** means
  findings; **2** means at least one incomplete/error/timeout or report failure.
  Exit 2 takes precedence; review the report even when a step passes, because
  individual tools can have below-threshold findings and documented skipped scope.
  In quick mode, exit 0 means selected checks passed; SKIPPED checks were not run.
- The sample enables no alerts, history scan, HTTP takeover probes, baseline writes,
  or insecure TLS. You can explicitly add normal script options to the config;
  treat it as trusted executable configuration. For certificate alerts, add
  `--slack`/`--email` to `certificates` and provide the documented environment
  variables. They notify about certificate issues, not the whole weekly report.

The runner performs one pass. To run it weekly, configure cron or your CI scheduler.
For example, this cron entry runs Mondays at 09:00 in the scheduler's timezone
(replace every path, including the Python executable, with your actual paths):

```cron
0 9 * * 1 /absolute/path/to/python3 "/absolute/path/to/Automation Scripts/scripts/weekly_runner.py" "/absolute/path/to/weekly_runner.json" >> "/absolute/path/to/weekly-runner.log" 2>&1
```

Cron has a limited environment. Use absolute paths, make Git available on PATH,
and supply any alert environment variables through your scheduler's protected
configuration. Scheduling and live target selection are left to your local config.

Offline runner tests use temporary stand-in scripts and send no network traffic:

```sh
python3 -m unittest -v tests.test_weekly_runner
```
