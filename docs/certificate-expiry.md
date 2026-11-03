# Bulk certificate expiry quick check (day 6)

`cert_expiry_quickcheck.py` checks the leaf TLS certificate for each target and
prints its UTC expiry date and remaining days. Standard library only, four workers,
one pass per invocation. No scheduler, saved state or alert deduplication.

```sh
python3 scripts/network/cert_expiry_quickcheck.py example.com api.example.com:8443
python3 scripts/network/cert_expiry_quickcheck.py -f hosts.txt --days 14
python3 scripts/network/cert_expiry_quickcheck.py hosts.txt --days 45
python3 scripts/network/cert_expiry_quickcheck.py -f hosts.txt --slack
python3 scripts/network/cert_expiry_quickcheck.py -f hosts.txt --email
```

- Targets are hostnames, `host:port`, or HTTPS origins; default port is 443.
  Existing filenames work as positional arguments as well as through `-f`.
  IPv6 uses brackets, e.g. `[2001:db8::1]:443`. Target files allow `#` comments.
  Checks direct TLS only; no HTTP requests, STARTTLS service probes, or redirects.
- `WARNING` means expiry within `--days` (default 30); `CRITICAL` means expiry
  within seven days. The critical level applies even if `--days` is below seven.
  Thresholds compare exact remaining time rather than rounding down to whole days.
  `OK` means beyond both windows. The earlier `EXPIRING` label is replaced by
  WARNING/CRITICAL. Results with no expiry date appear first, then soonest expiry.
- Certificate chain and hostname verification remain enabled. `EXPIRED` identifies
  an elapsed expiry or the verifier's expired-certificate error; the latter may
  refer to a certificate anywhere in the chain and has no leaf expiry date.
  Other trust/hostname failures are `INVALID_CERT`. No insecure retry or guessed
  dates are used. Network failures are `ERROR`, not a healthy result.
- Alerts require the explicit `--slack` or `--email` flag (both are allowed).
  One summary is sent per enabled channel only when a target needs attention,
  including certificate validation failures and network errors. All-healthy runs
  stay quiet in Slack/email. Repeated failing runs send repeated alerts.
- For Slack, set `SLACK_WEBHOOK_URL` to an existing incoming webhook. The script
  does not print the URL or follow redirects. Long summaries are truncated with
  a note; full results remain in the console. See [Slack webhook setup](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).
- For email, set `SMTP_HOST`, `SMTP_FROM`, and `SMTP_TO` (comma-separated plain
  addresses). Set `SMTP_USER` and `SMTP_PASSWORD` together when login is required.
  `SMTP_MODE=starttls` and port 587 are defaults; use `SMTP_MODE=ssl` for implicit
  TLS on port 465. `SMTP_PORT` overrides the port. TLS is required and verified;
  there is no plaintext fallback. Keep credentials in your environment, not Git.
- Configured alert destinations receive target names, expiry dates and error
  summaries. No private keys or raw certificate contents are sent. SMTP acceptance
  does not guarantee inbox delivery.
- Exit **0**: all certificates valid and beyond the window; **1**: expiring,
  expired or invalid certificates; **2**: invalid input/configuration, incomplete
  checks or alert failure. Exit 2 takes precedence. Timeout is per socket operation,
  not a total run deadline. A single connection does not inventory every certificate
  behind a load balancer.

The combination takes status levels, filename arguments and expiry ordering from
the supplied `cert_expiry.py`; retains SMTP email, IPv6/URL validation, four-worker
concurrency and alert-delivery checks; and keeps one summary per enabled channel.
Expired verification errors use the [OpenSSL expiry error code](https://docs.openssl.org/1.0.2/man1/verify/)
rather than substring matching the hostname or raw exception text.

Run the focused offline tests (mock certificates, sockets, Slack and SMTP):

```sh
python3 -m unittest -v tests.test_cert_expiry_quickcheck
```
