# Dangling CNAME quick check (day 4)

`subdomain_quickcheck.py` follows CNAME chains for supplied hostnames and flags
missing targets for manual review. Uses Python's standard library and
[Google Public DNS's JSON API](https://developers.google.com/speed/public-dns/docs/doh/json).

```sh
python3 scripts/network/subdomain_quickcheck.py app.example.com docs.example.com
python3 scripts/network/subdomain_quickcheck.py -f subdomains.txt --json cname-report.json
python3 scripts/network/subdomain_quickcheck.py subdomains.txt --http -v
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
python3 -m unittest -v tests.test_subdomain_quickcheck
```
