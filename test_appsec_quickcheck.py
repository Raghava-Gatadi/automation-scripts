"""Offline HTTP integration and TLS/header regression tests; no public targets."""
import contextlib
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import appsec_quickcheck as scanner


GOOD_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=()"),
]


def replace_header(name, value):
    return [(k, v) for k, v in GOOD_HEADERS if k.lower() != name.lower()] + [(name, value)]


class HeaderTests(unittest.TestCase):
    def test_good_headers(self):
        self.assertEqual(scanner.check_headers(GOOD_HEADERS), [])
        self.assertEqual(scanner.check_headers(replace_header("X-Content-Type-Options", "NoSniff")), [])

    def test_cookie_value_cannot_fake_attributes(self):
        findings = scanner.check_cookies([("Set-Cookie", "session=secure_httponly_samesite")])
        self.assertEqual(len(findings), 1)
        self.assertIn("missing secure, httponly, samesite", findings[0][2])
        self.assertNotIn("secure_httponly_samesite", repr(findings))

    def test_cookie_flags_case_and_expires(self):
        value = "id=value; SECURE; HttpOnly; SameSite=Lax; Expires=Wed, 21 Oct 2037 07:28:00 GMT"
        self.assertEqual(scanner.check_cookies([("Set-Cookie", value)]), [])

    def test_cookie_samesite_partitioning_and_prefixes(self):
        values = ["id=value; SameSite=None; Partitioned", "__Host-id=value; Secure; HttpOnly; SameSite=Lax; Domain=example.invalid",
                  "__Http-id=value; Secure; SameSite=invalid", "broken-cookie"]
        checks = {f[1] for f in scanner.check_cookies([("Set-Cookie", value) for value in values])}
        self.assertTrue({"cookie", "cookie-samesite", "cookie-partitioned", "cookie-prefix", "cookie-format"} <= checks)
        good = "__Host-Http-id=value; Secure; HttpOnly; SameSite=Lax; Path=/"
        self.assertEqual(scanner.check_cookies([("Set-Cookie", good)]), [])
        self.assertTrue(scanner.check_cookies([("Set-Cookie", good)], https=False))

    def test_cookies_independent_and_duplicate_attributes(self):
        findings = scanner.check_cookies([("Set-Cookie", "a=value; Secure; HttpOnly; SameSite=Lax"),
                                          ("Set-Cookie", "b=value; Path=/; Path=/other")])
        self.assertTrue(all("Cookie #2" in finding[2] for finding in findings))
        self.assertIn("cookie-attributes", [f[1] for f in findings])

    def test_hsts_values_and_duplicates(self):
        for value, check, sev in [("max-age=0", "weak-hsts", "HIGH"), ("max-age=60", "weak-hsts", "LOW"),
                                  ("max-age=no", "invalid-hsts", "MEDIUM"),
                                  ("max-age=1; max-age=99999999", "invalid-hsts", "MEDIUM")]:
            with self.subTest(value=value):
                self.assertTrue(any(f[:2] == (sev, check) for f in scanner.check_headers(replace_header("Strict-Transport-Security", value))))
        self.assertFalse(scanner.check_headers(replace_header("Strict-Transport-Security", 'Max-Age = "31536000"')))
        self.assertFalse(scanner.check_headers(replace_header("Strict-Transport-Security", "max-age=" + "9" * 5000)))
        duplicates = GOOD_HEADERS + [("Strict-Transport-Security", "max-age=1")]
        self.assertIn("invalid-hsts", [f[1] for f in scanner.check_headers(duplicates)])

    def test_http_and_json_do_not_get_html_or_hsts_requirements(self):
        headers = [("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")]
        self.assertEqual(scanner.check_headers(headers, https=False), [])
        self.assertIn("hsts-http", [f[1] for f in scanner.check_headers(GOOD_HEADERS, https=False)])

    def test_report_only_and_invalid_xfo(self):
        headers = [(k.replace("Content-Security-Policy", "Content-Security-Policy-Report-Only"), v) for k, v in GOOD_HEADERS]
        headers.append(("X-Frame-Options", "ALLOW-FROM https://example.invalid"))
        findings = scanner.check_headers(headers)
        self.assertTrue(any("Report-Only" in f[2] for f in findings))
        self.assertTrue({"invalid-xfo", "clickjacking"} <= {f[1] for f in findings})

    def test_csp_nonce_hash_and_script_directive_semantics(self):
        nonce = "'nonce-" + "YWJjZGVmZ2hpamtsbW5vcA==" + "'"
        policy = f"script-src 'unsafe-inline' {nonce}; frame-ancestors 'none'"
        self.assertEqual(scanner.check_csp([policy]), ([], True))
        self.assertEqual(scanner.check_csp([policy + "; img-src 'unsafe-inline'"]), ([], True))
        broad = f"script-src 'unsafe-inline' 'strict-dynamic' https: {nonce}; frame-ancestors 'none'"
        self.assertEqual(scanner.check_csp([broad]), ([], True))
        self.assertTrue(scanner.check_csp(["script-src 'unsafe-inline' 'sha256-a'"])[0])
        self.assertFalse(scanner.check_csp(["default-src 'none'; frame-ancestors *"])[1])
        findings, _ = scanner.check_csp(["script-src 'unsafe-eval' https:; frame-ancestors 'self'"])
        self.assertTrue(any("unsafe-eval" in f[2] for f in findings))
        self.assertTrue(any("broad script" in f[2] for f in findings))

    def test_csp_first_duplicate_directive_wins(self):
        findings, _ = scanner.check_csp(["default-src 'none'; script-src 'unsafe-inline'; script-src 'none'"])
        self.assertTrue(any("unsafe-inline" in f[2] for f in findings))

    def test_cors_does_not_claim_wildcard_credential_exposure(self):
        headers = GOOD_HEADERS + [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
        findings = scanner.check_headers(headers)
        self.assertEqual([f[0] for f in findings if f[1] == "cors"], ["MEDIUM"])
        self.assertIn("rejected by browsers", findings[0][2])

    def test_invalid_nosniff_referrer_and_header_values_redacted(self):
        headers = replace_header("X-Content-Type-Options", "wrong") + [("Server", "private-product-123")]
        findings = scanner.check_headers(headers)
        self.assertIn("content-type-options", [f[1] for f in findings])
        self.assertNotIn("private-product-123", repr(findings))
        self.assertTrue(scanner.check_headers(replace_header("Referrer-Policy", "unsafe-url")))


class TransportTests(unittest.TestCase):
    def test_urls_ipv6_and_invalid_inputs(self):
        self.assertEqual(scanner.normalize_url("EXAMPLE.invalid"), "https://example.invalid/")
        self.assertEqual(scanner.normalize_url("http://[::1]:8080/a#private"), "http://[::1]:8080/a")
        for value in ("ftp://example.invalid", "https://user:" + "value@example.invalid", "https://example.invalid:0",
                      "https://example.invalid:99999", "https://example.invalid/a b", "https://example.invalid\\x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.normalize_url(value)

    def test_redirect_loop_limit_and_relative_locations(self):
        first = scanner.Response("https://example.invalid/", 302, [("Location", "/next")])
        second = scanner.Response("https://example.invalid/next", 200, GOOD_HEADERS)
        with patch.object(scanner, "request_once", side_effect=[first, second]):
            self.assertTrue(scanner.fetch(first.url, 1).complete)
        with patch.object(scanner, "request_once", return_value=first) as request:
            result = scanner.fetch(first.url, 1, max_redirects=0)
            self.assertEqual(request.call_count, 1)
            self.assertEqual(result.findings[0][1], "redirect-limit")
        second.status, second.headers = 302, [("Location", "/")]
        with patch.object(scanner, "request_once", side_effect=[first, second]) as request:
            result = scanner.fetch(first.url, 1)
            self.assertEqual(result.findings[0][1], "redirect-loop")
            self.assertEqual(request.call_count, 2)

    def test_downgrade_cross_host_and_bad_locations_are_not_followed(self):
        cases = [("http://example.invalid/", "https-downgrade"),
                 ("https://other.invalid/", "redirect-scope"), ("file:///tmp/test", "redirect-location")]
        for destination, check in cases:
            response = scanner.Response("https://example.invalid/", 302, [("Location", destination)])
            with self.subTest(destination=destination), patch.object(scanner, "request_once", return_value=response) as request:
                result = scanner.fetch(response.url, 1)
                self.assertFalse(result.complete)
                self.assertEqual(result.findings[0][1], check)
                self.assertEqual(request.call_count, 1)
        for headers in ([], [("Location", "")], [("Location", "/a"), ("Location", "/b")]):
            with patch.object(scanner, "request_once", return_value=scanner.Response("https://example.invalid/", 302, headers)):
                self.assertEqual(scanner.fetch("https://example.invalid/", 1).findings[0][1], "redirect-location")

    def test_allowed_redirect_uses_final_tls_and_keeps_intermediate_cookies(self):
        first = scanner.Response("https://example.invalid/", 302, [("Location", "https://other.invalid/") , ("Set-Cookie", "id=value")],
                                 [("INFO", "tls-cert", "first certificate")])
        last = scanner.Response("https://other.invalid/", 200, GOOD_HEADERS, [("HIGH", "tls-cert", "second certificate")])
        with patch.object(scanner, "request_once", side_effect=[first, last]):
            report = scanner.scan(first.url, allowed_hosts=["other.invalid"], http_probe=False)
        self.assertTrue(report["complete"])
        self.assertEqual(report["responses_checked"], 2)
        self.assertTrue(any(f["check"] == "cookie" and f["url"] == first.url for f in report["findings"]))
        self.assertTrue(any(f["detail"] == "second certificate" and f["url"] == last.url for f in report["findings"]))

    def test_tls_validation_failure_and_timeout_are_incomplete(self):
        for error in (ssl.SSLCertVerificationError("private diagnostic"), TimeoutError("private diagnostic")):
            with patch.object(scanner, "request_once", side_effect=error):
                report = scanner.scan("https://example.invalid", http_probe=False)
            self.assertFalse(report["complete"])
            self.assertNotIn("private diagnostic", json.dumps(report))

    def test_http_probe_does_not_replay_query_and_distinguishes_refused(self):
        response = scanner.Response("http://[::1]:8080/", 303, [("Location", "https://example.invalid/")])
        with patch.object(scanner, "request_once", return_value=response) as request:
            findings, complete = scanner.check_redirect("https://[::1]:8443/private?value=hidden", 1, 8080)
            request.assert_called_once_with("http://[::1]:8080/", 1)
            self.assertTrue(complete)
            self.assertEqual(findings[0][0], "INFO")
        with patch.object(scanner, "request_once", side_effect=ConnectionRefusedError):
            self.assertTrue(scanner.check_redirect("https://example.invalid/", 1)[1])
        with patch.object(scanner, "request_once", side_effect=TimeoutError):
            self.assertFalse(scanner.check_redirect("https://example.invalid/", 1)[1])

    def test_tls_expiration_boundaries_and_deprecated_protocol(self):
        now = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        for days, expected in [(-1, "HIGH"), (0, "HIGH"), (13, "HIGH"), (14, "MEDIUM"), (29, "MEDIUM"), (30, "INFO")]:
            cert = {"notAfter": (now + dt.timedelta(days=days)).strftime("%b %d %H:%M:%S %Y GMT")}
            self.assertEqual(scanner.check_tls(cert, "TLSv1.3", now.timestamp())[0][0], expected)
        findings = scanner.check_tls({}, "TLSv1", now.timestamp())
        self.assertIn(("HIGH", "tls-protocol"), [f[:2] for f in findings])

    def test_request_uses_verified_tls_connection_and_closes_without_body_read(self):
        connection = Mock()
        connection.sock.getpeercert.return_value = {"notAfter": "Jan 01 00:00:00 2099 GMT"}
        connection.sock.version.return_value = "TLSv1.3"
        response = connection.getresponse.return_value
        response.status = 200
        response.getheaders.return_value = GOOD_HEADERS
        with patch.object(scanner.http.client, "HTTPSConnection", return_value=connection) as constructor:
            result = scanner.request_once("https://example.invalid/a?b=c", 1)
        context = constructor.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(result.tls)
        connection.connect.assert_called_once()
        connection.close.assert_called_once()
        response.read.assert_not_called()
        self.assertEqual(connection.request.call_args.args[:2], ("GET", "/a?b=c"))


class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.send_header("Set-Cookie", "id=value")
                elif self.path == "/loop":
                    self.send_response(302)
                    self.send_header("Location", "/loop")
                else:
                    self.send_response(200)
                    for name, value in GOOD_HEADERS:
                        self.send_header(name, value)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_real_redirect_and_plaintext_transport(self):
        report = scanner.scan(self.url + "/redirect")
        self.assertTrue(report["complete"])
        self.assertEqual(report["responses_checked"], 2)
        self.assertTrue(any(f["check"] == "cookie" for f in report["findings"]))
        self.assertTrue(any(f["check"] == "transport" and f["severity"] == "HIGH" for f in report["findings"]))

    def test_cli_json_redaction_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = scanner.main([self.url + "/ok?value=PRIVATEVALUE", "--json", str(report_path)])
            self.assertEqual(code, 1)
            data = json.loads(report_path.read_text())
            self.assertEqual(data["schema_version"], 2)
            self.assertNotIn("PRIVATEVALUE", report_path.read_text() + output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.main([self.url + "/loop"]), 2)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.stack.enter_context(contextlib.redirect_stderr(self.output))

    def test_validate_all_inputs_before_network(self):
        with patch.object(scanner, "request_once") as request:
            self.assertEqual(scanner.main(["https://example.invalid", "ftp://invalid"]), 2)
            request.assert_not_called()

    def test_invalid_numeric_arguments(self):
        for args in (("--timeout", "nan"), ("--timeout", "0"), ("--max-redirects", "-1"), ("--http-port", "0")):
            with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                scanner.main(["https://example.invalid", *args])
            self.assertEqual(error.exception.code, 2)

    def test_comments_deduplication_and_protected_report_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / "targets.txt"
            targets.write_text("  # comment\nhttps://example.invalid\nhttps://example.invalid\n")
            response = scanner.Response("https://example.invalid/", 200, GOOD_HEADERS)
            with patch.object(scanner, "request_once", return_value=response) as request:
                self.assertEqual(scanner.main(["-f", str(targets), "--no-http-probe"]), 0)
                self.assertEqual(request.call_count, 1)
                self.assertEqual(scanner.main(["-f", str(targets), "--json", str(targets)]), 2)
                self.assertEqual(request.call_count, 1)

    def test_fail_on_threshold_and_no_http_probe(self):
        headers = GOOD_HEADERS + [("Server", "server/1.0")]
        with patch.object(scanner, "request_once", return_value=scanner.Response("https://example.invalid/", 200, headers)) as request:
            self.assertEqual(scanner.main(["https://example.invalid", "--no-http-probe"]), 0)
            self.assertEqual(scanner.main(["https://example.invalid", "--no-http-probe", "--fail-on", "LOW"]), 1)
            self.assertEqual(request.call_count, 2)

    def test_atomic_report_failure_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("previous")
            with patch.object(scanner.os, "replace", side_effect=OSError), self.assertRaises(OSError):
                scanner.write_report(path, {"test": True})
            self.assertEqual(path.read_text(), "previous")
            self.assertEqual([p.name for p in path.parent.iterdir()], ["report.json"])


if __name__ == "__main__":
    unittest.main()
