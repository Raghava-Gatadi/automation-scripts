"""Offline DNS and HTTPS fixtures; no requests to real domains or providers."""
import contextlib
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import subdomain_quickcheck as scanner

HOST, TARGET = "app.example.com", "removed.github.io"


def alias(owner=HOST, target=TARGET):
    return {"name": owner + ".", "type": 5, "data": target + "."}


def resolving():
    return [(0, [alias()]), (0, []), (0, [{"name": TARGET, "type": 1, "data": "192.0.2.1"}]), (0, [])]


class DNSTests(unittest.TestCase):
    def test_dangling_and_recursive_nxdomain_retaining_cname(self):
        for code in (0, 3):
            with self.subTest(code=code), patch.object(scanner, "lookup", side_effect=[(code, [alias()]), (3, [])]):
                result = scanner.check(HOST)
                self.assertEqual(result["status"], "DANGLING")
                self.assertEqual(result["chain"], [HOST, TARGET])
                self.assertIn("GitHub Pages", result["providers"])

    def test_missing_input_and_no_cname_are_not_candidates(self):
        for code, expected in ((0, "NO_CNAME"), (3, "NOT_FOUND")):
            with patch.object(scanner, "lookup", return_value=(code, [])):
                self.assertEqual(scanner.check(HOST)["status"], expected)

    def test_ipv6_only_is_resolving(self):
        answers = [(0, [alias()]), (0, []), (0, []), (0, [{"name": TARGET, "type": 28, "data": "2001:db8::1"}])]
        with patch.object(scanner, "lookup", side_effect=answers):
            result = scanner.check(HOST)
        self.assertEqual(result["status"], "RESOLVES")
        self.assertEqual(result["addresses"], ["2001:db8::1"])

    def test_no_address_is_review_candidate(self):
        with patch.object(scanner, "lookup", side_effect=[(0, [alias()]), (0, []), (0, []), (0, [])]):
            self.assertEqual(scanner.check(HOST)["status"], "NO_ADDRESS")

    def test_loop_and_depth_limit_are_inconclusive(self):
        with patch.object(scanner, "lookup", side_effect=[(0, [alias()]), (0, [alias(TARGET, HOST)])]):
            self.assertEqual(scanner.check(HOST)["status"], "ERROR")
        with patch.object(scanner, "MAX_DEPTH", 1), patch.object(scanner, "lookup", side_effect=[
                (0, [alias()]), (0, [alias(TARGET, "next.example.com")])]):
            self.assertEqual(scanner.check(HOST)["status"], "ERROR")

    def test_inconsistent_or_changing_answers_are_errors(self):
        for answers in ([(0, [alias()]), (0, []), (3, []), (0, [])],
                        [(0, [alias()]), (0, []), (0, [alias(TARGET, "changed.example.com")])]):
            with patch.object(scanner, "lookup", side_effect=answers):
                self.assertEqual(scanner.check(HOST)["status"], "ERROR")

    def test_lookup_rejects_servfail_truncation_and_malformed_responses(self):
        for data in ({"Status": 2}, {"Status": 5}, {"Status": 0, "TC": True},
                     {"Status": False}, {"Status": 0, "Answer": [None]}, {}):
            with self.subTest(data=data), patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(data).encode())), \
                    self.assertRaises(ValueError):
                scanner.lookup(HOST, "CNAME", 1)

    def test_network_failure_is_not_reported_as_no_cname(self):
        with patch.object(scanner, "lookup", side_effect=TimeoutError("private diagnostic")):
            result = scanner.check(HOST)
        self.assertEqual(result["status"], "ERROR")
        self.assertNotIn("private diagnostic", json.dumps(result))

    def test_hostname_validation_and_normalization(self):
        self.assertEqual(scanner.hostname("APP.Example.com."), HOST)
        for name in ("https://example.com", "*.example.com", "127.0.0.1", "bad..example.com", "-bad.example.com", "example.com.."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                scanner.hostname(name)


class HTTPTests(unittest.TestCase):
    def test_service_matching_requires_suffix_boundary(self):
        self.assertTrue(scanner.service_matches([HOST, "bucket.s3.amazonaws.com"]))
        self.assertTrue(scanner.service_matches([HOST, "bucket.s3.us-east-1.amazonaws.com"]))
        self.assertFalse(scanner.service_matches([HOST, "evilgithub.io"]))
        self.assertFalse(scanner.service_matches([HOST, "foo.github.io.attacker.example"]))

    def test_http_is_opt_in_and_dangling_does_not_probe(self):
        with patch.object(scanner, "lookup", side_effect=resolving()), patch.object(scanner, "probe_services") as probe:
            self.assertEqual(scanner.check(HOST)["status"], "RESOLVES")
            probe.assert_not_called()
        with patch.object(scanner, "lookup", side_effect=[(0, [alias()]), (3, [])]), \
                patch.object(scanner, "probe_services") as probe:
            self.assertEqual(scanner.check(HOST, http=True)["status"], "DANGLING")
            probe.assert_not_called()

    def test_match_is_clue_and_nonmatch_never_means_claimed(self):
        for outcome, status in (("MATCH", "SERVICE_CLUE"), ("NO_MATCH", "RESOLVES"), ("ERROR", "ERROR"), ("REDIRECT", "ERROR")):
            with patch.object(scanner, "lookup", side_effect=resolving()), \
                    patch.object(scanner, "probe_services", return_value={"status": outcome}) as probe:
                result = scanner.check(HOST, http=True)
            self.assertEqual(result["status"], status)
            self.assertEqual(result["dns_status"], "RESOLVES")
            probe.assert_called_once_with(HOST, scanner.service_matches([HOST, TARGET]), 8)
            self.assertNotIn("claimed)", result["detail"])

    def test_404_body_clue_is_read_with_verified_tls_and_bounded_size(self):
        body = "There isn't a GitHub Pages site here"
        error = urllib.error.HTTPError("https://" + HOST, 404, "Not found", {}, io.BytesIO(body.encode()))
        opener = MagicMock()
        opener.open.side_effect = error
        with patch.object(scanner.urllib.request, "build_opener", return_value=opener) as build:
            result = scanner.probe_services(HOST, [("GitHub Pages", body)], 2)
        self.assertEqual(result, {"status": "MATCH", "http_status": 404, "services": ["GitHub Pages"]})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://" + HOST + "/")
        context = build.call_args.args[1]._context
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        response = MagicMock()
        response.__enter__.return_value = response
        response.code, response.read.return_value = 200, b"no clue"
        opener.open.side_effect, opener.open.return_value = None, response
        with patch.object(scanner.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(scanner.probe_services(HOST, [("GitHub Pages", body)], 2)["status"], "NO_MATCH")
        response.read.assert_called_once_with(scanner.BODY_LIMIT)

    def test_tls_failure_does_not_retry_over_plaintext(self):
        opener = MagicMock()
        opener.open.side_effect = ssl.SSLCertVerificationError("private diagnostic")
        with patch.object(scanner.urllib.request, "build_opener", return_value=opener):
            result = scanner.probe_services(HOST, [("test", "text")], 1)
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(opener.open.call_count, 1)
        self.assertNotIn("private diagnostic", json.dumps(result))

    def test_redirect_is_not_followed_or_used_as_evidence(self):
        self.assertIsNone(scanner.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example"))
        error = urllib.error.HTTPError("https://" + HOST, 302, "Redirect", {}, io.BytesIO(b"provider error"))
        opener = MagicMock()
        opener.open.side_effect = error
        with patch.object(scanner.urllib.request, "build_opener", return_value=opener):
            result = scanner.probe_services(HOST, [("test", "provider error")], 1)
        self.assertEqual(result["status"], "REDIRECT")
        self.assertEqual(result["services"], [])
        self.assertEqual(opener.open.call_count, 1)


class CLITests(unittest.TestCase):
    def test_file_input_deduplication_quiet_output_and_full_json(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs, report = Path(directory) / "hosts.txt", Path(directory) / "report.json"
            inputs.write_text("  # comment\napp.example.com\napp.example.com\n")
            output = io.StringIO()
            with patch.object(scanner, "check", return_value={"hostname": HOST, "status": "RESOLVES", "chain": [HOST, TARGET],
                                                               "detail": "DNS resolves", "providers": []}) as check, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(scanner.main([str(inputs), "--json", str(report)]), 0)
            self.assertEqual(check.call_count, 1)
            self.assertNotIn("[RESOLVES]", output.getvalue())
            self.assertEqual(len(json.loads(report.read_text())["results"]), 1)

    def test_error_precedes_candidate_exit_code(self):
        results = [{"hostname": HOST, "status": "DANGLING", "detail": "review", "chain": [HOST, TARGET], "providers": []},
                   {"hostname": "other.example.com", "status": "ERROR", "detail": "unknown", "chain": [], "providers": []}]
        with patch.object(scanner, "check", side_effect=results), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([HOST, "other.example.com"]), 2)
        with patch.object(scanner, "check", return_value=results[0]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([HOST]), 1)

    def test_invalid_input_and_report_overwrite_stop_before_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "hosts.txt"
            inputs.write_text(HOST)
            with patch.object(scanner, "check") as check, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scanner.main(["https://example.com"]), 2)
                self.assertEqual(scanner.main([str(inputs), "--json", str(inputs)]), 2)
                check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
