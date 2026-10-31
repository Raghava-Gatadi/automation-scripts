"""Offline file-signature, response, and CLI checks; no real asset requests."""
import contextlib
import http.client
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import sensitive_files_quickcheck as scanner

ASSET = "https://app.example.invalid"
PRIVATE = b"DB_PASSWORD" + b"=private-fixture-value\n"


def response(code=404, body=b"", content_type="text/plain", encoding="identity"):
    return {"code": code, "body": body, "type": content_type, "encoding": encoding}


def fixture_fetch(mapping, control=None):
    def fetch(opener, url, timeout):
        path = url.removeprefix(ASSET)
        if path.startswith("/.sensitive-check-"):
            return control if control is not None else response()
        value = mapping.get(path, response())
        if isinstance(value, Exception):
            raise value
        return value
    return fetch


class SignatureTests(unittest.TestCase):
    def test_all_supported_signature_types(self):
        fixtures = {
            "git-head": b"ref: refs/heads/main\n",
            "git-config": b"[core]\nrepositoryformatversion = 0\n",
            "git-index": b'<title>Index of /.git/</title><a href="HEAD">HEAD</a>',
            "env": PRIVATE,
            "zip": b"PK\x03\x04archive",
            "gzip": b"\x1f\x8b\x08archive",
            "sql": b"-- PostgreSQL database dump\n",
            "php": b'<?php\n$db = "fixture";',
            "aws": b"aws_access_key_id = demo\n" + b"aws_secret_access_key = demo\n",
            "npm": b"//registry.npmjs.org/:_authToken=demo\n",
            "htpasswd": b"user:" + b"$apr1$abcdefgh$synthetic\n",
            "private-key": b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n",
            "sqlite": b"SQLite format 3\0binary",
            "ds-store": b"\0\0\0\1Bud1binary",
            "compose": b"services:\n  app:\n    image: example\n",
            "actuator": b'{"activeProfiles":[],"propertySources":[{"name":"systemProperties"',
            "phpinfo": b"<title>phpinfo()</title><h1>PHP Version 8.0</h1>",
            "apache": b"<title>Apache Server Status</title>Server Version: Apache",
        }
        self.assertEqual({kind for _, kind in scanner.PATHS}, set(fixtures))
        for kind, body in fixtures.items():
            with self.subTest(kind=kind):
                reason = scanner.evidence(kind, body, "application/octet-stream")
                self.assertTrue(reason)
                self.assertNotIn("private-fixture-value", reason)

    def test_html_and_plain_200_are_not_file_evidence(self):
        for kind in ("env", "aws", "npm", "git-head", "php", "actuator"):
            with self.subTest(kind=kind):
                self.assertIsNone(scanner.evidence(kind, b"<html>Welcome</html>", "text/html"))
                self.assertIsNone(scanner.evidence(kind, b"Welcome to our site", "text/plain"))
        self.assertIsNone(scanner.evidence("env", PRIVATE, "text/html"))

    def test_archive_signatures_match_the_expected_type(self):
        self.assertIsNone(scanner.evidence("zip", b"\x1f\x8b\x08", "application/gzip"))
        self.assertIsNone(scanner.evidence("gzip", b"PK\x03\x04", "application/zip"))
        self.assertIsNone(scanner.evidence("git-config", b"[core]\nwelcome=yes", "text/plain"))

    def test_empty_environment_values_do_not_match(self):
        for value in (b"APP_ENV=production", b"SECRET_KEY=", b'SECRET_KEY=""'):
            self.assertIsNone(scanner.evidence("env", value, "text/plain"))

    def test_detached_git_head_and_severities(self):
        self.assertTrue(scanner.evidence("git-head", b"a" * 40, "text/plain"))
        self.assertTrue(scanner.evidence("git-head", b"a" * 64, "text/plain"))
        self.assertEqual(scanner.severity("private-key"), "HIGH")
        self.assertEqual(scanner.severity("actuator"), "MEDIUM")
        self.assertEqual(scanner.severity("ds-store"), "LOW")


class CheckTests(unittest.TestCase):
    def test_candidates_metadata_only_and_fixed_path_list(self):
        mapping = {"/.env": response(200, PRIVATE), "/backup.zip": response(200, b"PK\x03\x04"),
                   "/phpinfo.php": response(200, b"phpinfo() PHP Version 8.0", "text/html")}
        with patch.object(scanner, "fetch", side_effect=fixture_fetch(mapping)) as fetch:
            result = scanner.check(ASSET, 1)
        self.assertEqual(len(result["checks"]), 25)
        self.assertEqual(fetch.call_count, 26)
        self.assertTrue(result["complete"])
        self.assertEqual(sum(item["status"] == "CANDIDATE" for item in result["checks"]), 3)
        self.assertNotIn("private-fixture-value", json.dumps(result))
        self.assertFalse(any(path == "/actuator/heapdump" for path, _ in scanner.PATHS))

    def test_identical_control_body_suppresses_soft_404(self):
        with patch.object(scanner, "fetch", return_value=response(200, PRIVATE)):
            result = scanner.check(ASSET, 1)
        self.assertTrue(all(item["status"] == "FALLBACK" for item in result["checks"]))

    def test_denied_redirect_missing_are_observations(self):
        mapping = {"/.env": response(403), "/.git/HEAD": response(302), "/backup.sql": response(410)}
        with patch.object(scanner, "fetch", side_effect=fixture_fetch(mapping)):
            result = scanner.check(ASSET, 1)
        self.assertTrue(result["complete"])
        statuses = {item["path"]: item["status"] for item in result["checks"]}
        self.assertEqual((statuses["/.env"], statuses["/.git/HEAD"], statuses["/backup.sql"]), ("DENIED", "REDIRECT", "NOT_FOUND"))

    def test_partial_content_can_match(self):
        with patch.object(scanner, "fetch", side_effect=fixture_fetch({"/.env": response(206, PRIVATE)})):
            result = scanner.check(ASSET, 1)
        self.assertEqual(next(item for item in result["checks"] if item["path"] == "/.env")["status"], "CANDIDATE")

    def test_network_rate_limit_encoding_and_unknown_status_are_incomplete(self):
        for value in (TimeoutError("private diagnostic"), response(429), response(503), response(416),
                      response(200, b"compressed", encoding="gzip")):
            with self.subTest(value=value), patch.object(scanner, "fetch", side_effect=fixture_fetch({"/.env": value})):
                result = scanner.check(ASSET, 1)
            self.assertFalse(result["complete"])
            self.assertNotIn("private diagnostic", json.dumps(result))

    def test_failed_control_stops_asset_probes(self):
        for value in (TimeoutError("private diagnostic"), ssl.SSLCertVerificationError("private diagnostic")):
            with patch.object(scanner, "fetch", side_effect=value) as fetch:
                result = scanner.check(ASSET, 1)
            self.assertFalse(result["complete"])
            self.assertEqual(result["checks"], [])
            self.assertEqual(fetch.call_count, 1)
        with patch.object(scanner, "fetch", return_value=response(503)) as fetch:
            self.assertFalse(scanner.check(ASSET, 1)["complete"])
            self.assertEqual(fetch.call_count, 1)

    def test_tls_verification_default_and_explicit_override(self):
        for verify in (True, False):
            with patch.object(scanner, "fetch", return_value=response()), \
                    patch.object(scanner.urllib.request, "build_opener") as build:
                result = scanner.check(ASSET, 1, verify=verify)
            context = build.call_args.args[1]._context
            self.assertEqual(context.check_hostname, verify)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
            self.assertEqual(result["tls_verification_enabled"], verify)


class FetchTests(unittest.TestCase):
    def test_range_bounded_read_and_close(self):
        opener, response = MagicMock(), MagicMock()
        opener.open.return_value = response
        response.__enter__.return_value = response
        response.code, response.headers, response.read.return_value = 200, {}, PRIVATE
        result = scanner.fetch(opener, ASSET + "/.env", 2)
        response.read.assert_called_once_with(scanner.READ_LIMIT)
        response.__exit__.assert_called_once()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Range"), "bytes=0-4095")
        self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertEqual(result["body"], PRIVATE)

    def test_partial_range_must_start_at_zero(self):
        for content_range, valid in (("bytes 0-100/200", True), ("bytes 20-100/200", False), ("", False)):
            opener, response = MagicMock(), MagicMock()
            opener.open.return_value = response
            response.__enter__.return_value = response
            response.code, response.headers = 206, {"Content-Range": content_range}
            response.read.return_value = b"fixture"
            if valid:
                self.assertEqual(scanner.fetch(opener, ASSET, 1)["code"], 206)
            else:
                with self.assertRaises(ValueError):
                    scanner.fetch(opener, ASSET, 1)

    def test_redirects_are_not_followed_or_read(self):
        self.assertIsNone(scanner.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid"))
        error = urllib.error.HTTPError(ASSET, 302, "redirect", {}, io.BytesIO(b"not inspected"))
        opener = MagicMock()
        opener.open.side_effect = error
        result = scanner.fetch(opener, ASSET, 1)
        self.assertEqual((result["code"], result["body"]), (302, b""))
        self.assertEqual(opener.open.call_count, 1)


class CLITests(unittest.TestCase):
    def test_invalid_origins_stop_before_requests(self):
        for value in ("https://user:" + "pass@example.invalid", ASSET + "/path", ASSET + "?key=value", ASSET + "#fragment", "ftp://example.invalid"):
            with patch.object(scanner, "check") as check, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scanner.main([value]), 2)
                check.assert_not_called()
        self.assertEqual(scanner.origin("EXAMPLE.invalid"), "https://example.invalid")
        self.assertEqual(scanner.origin("http://[::1]:8080/"), "http://[::1]:8080")

    def test_json_redaction_and_insecure_option(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            output = io.StringIO()
            with patch.object(scanner, "fetch", side_effect=fixture_fetch({"/.env": response(200, PRIVATE)})), contextlib.redirect_stdout(output):
                self.assertEqual(scanner.main([ASSET, "-k", "--json", str(path)]), 1)
            text = path.read_text() + output.getvalue()
            self.assertNotIn("private-fixture-value", text)
            self.assertFalse(json.loads(path.read_text())["results"][0]["tls_verification_enabled"])
            self.assertIn("disabled for this run", output.getvalue())

    def test_file_comments_deduplication_and_overwrite_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.txt"
            path.write_text("  # comment\n" + ASSET + "\n" + ASSET + "\n")
            clean = {"asset": ASSET, "complete": True, "checks": []}
            with patch.object(scanner, "check", return_value=clean) as check, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.main(["-f", str(path)]), 0)
                self.assertEqual(check.call_count, 1)
            with patch.object(scanner, "check") as check, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scanner.main(["-f", str(path), "--json", str(path)]), 2)
                check.assert_not_called()

    def test_incomplete_precedes_findings_and_clean_is_zero(self):
        result = {"asset": ASSET, "complete": False, "checks": [
            {"path": "/.env", "status": "CANDIDATE", "severity": "HIGH", "reason": "review"}]}
        with patch.object(scanner, "check", return_value=result), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([ASSET]), 2)
        with patch.object(scanner, "fetch", return_value=response()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([ASSET]), 0)


if __name__ == "__main__":
    unittest.main()
