"""Offline certificate and alert checks; no TLS connections or messages sent."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scripts.network import cert_expiry_quickcheck as scanner

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def result(status="OK", host="app.example.invalid:443", days=None):
    item = {"target": host, "status": status, "detail": "fixture result"}
    if days is not None:
        item["days_left"] = days
    return item


class CertificateTests(unittest.TestCase):
    def inspect(self, remaining, warn_days=30):
        context, raw, tls = MagicMock(), MagicMock(), MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = tls
        expiry = NOW + timedelta(seconds=remaining)
        tls.getpeercert.return_value = {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}
        with patch.object(scanner.ssl, "create_default_context", return_value=context), \
                patch.object(scanner.socket, "create_connection", return_value=raw), \
                patch.object(scanner.dt, "datetime", wraps=datetime) as clock:
            clock.now.return_value = NOW
            item = scanner.check(("app.example.invalid", 443), warn_days, 1)
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "app.example.invalid")
        return item

    def test_exact_thresholds_without_flooring_days(self):
        for seconds, status in ((-1, "EXPIRED"), (0, "EXPIRED"), (1, "CRITICAL"), (7 * 86400, "CRITICAL"),
                                (7 * 86400 + 1, "WARNING"), (30 * 86400, "WARNING"), (30 * 86400 + 1, "OK")):
            with self.subTest(seconds=seconds):
                item = self.inspect(seconds)
                self.assertEqual(item["status"], status)
                self.assertEqual(item["days_left"], seconds / 86400)
                self.assertTrue(item["expires_at"].endswith("+00:00"))

    def test_critical_window_is_independent_of_warning(self):
        self.assertEqual(self.inspect(5 * 86400, warn_days=0)["status"], "CRITICAL")
        self.assertEqual(self.inspect(8 * 86400, warn_days=0)["status"], "OK")
        self.assertEqual(self.inspect(40 * 86400, warn_days=45)["status"], "WARNING")

    def test_verification_expiry_and_invalid_reason(self):
        for code, expected in ((10, "EXPIRED"), (18, "INVALID_CERT"), (62, "INVALID_CERT")):
            error = ssl.SSLCertVerificationError("private diagnostic")
            error.verify_code = code
            error.verify_message = "hostname expired.example.invalid does not match"
            with patch.object(scanner.socket, "create_connection", side_effect=error):
                item = scanner.check(("app.example.invalid", 443), 30, 1)
            self.assertEqual(item["status"], expected)
            self.assertNotIn("days_left", item)
            self.assertNotIn("private diagnostic", json.dumps(item))

    def test_connection_failure_and_missing_certificate_metadata(self):
        with patch.object(scanner.socket, "create_connection", side_effect=TimeoutError("private diagnostic")):
            item = scanner.check(("app.example.invalid", 443), 30, 1)
        self.assertEqual(item["status"], "ERROR")
        self.assertNotIn("private diagnostic", json.dumps(item))
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {}
        with patch.object(scanner.ssl, "create_default_context", return_value=context), \
                patch.object(scanner.socket, "create_connection", return_value=MagicMock()):
            self.assertEqual(scanner.check(("app.example.invalid", 443), 30, 1)["status"], "ERROR")

    def test_target_ipv6_ports_and_invalid_input(self):
        self.assertEqual(scanner.target("APP.Example.invalid"), ("app.example.invalid", 443))
        self.assertEqual(scanner.target("https://[::1]:8443/"), ("::1", 8443))
        for value in ("http://example.invalid", "https://example.invalid/path", "https://example.invalid?x=1",
                      "https://example.invalid#fragment", "https://user:" + "pass@example.invalid", "example.invalid:0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.target(value)


class AlertTests(unittest.TestCase):
    def test_disabled_alerts_need_no_environment(self):
        with patch.dict(scanner.os.environ, {}, clear=True):
            self.assertEqual(scanner.alert_config(False, False), {})
            for flags in ((True, False), (False, True)):
                with self.assertRaises(ValueError):
                    scanner.alert_config(*flags)

    def test_slack_webhook_validation(self):
        webhook = "https://hooks.slack.com/" + "services/TEST/TEST/SYNTHETIC"
        with patch.dict(scanner.os.environ, {"SLACK_WEBHOOK_URL": webhook}, clear=True):
            self.assertEqual(scanner.alert_config(True, False), {"slack": webhook})
        for invalid in ("https://other.invalid/services/T/B/key", webhook + "?secret=x", "http://hooks.slack.com/services/T/B/key"):
            with patch.dict(scanner.os.environ, {"SLACK_WEBHOOK_URL": invalid}, clear=True), self.assertRaises(ValueError):
                scanner.alert_config(True, False)

    def test_smtp_configuration_defaults_modes_and_credentials(self):
        settings = {"SMTP_HOST": "smtp.example.invalid", "SMTP_FROM": "from@example.invalid",
                    "SMTP_TO": "one@example.invalid,two@example.invalid"}
        with patch.dict(scanner.os.environ, settings, clear=True):
            config = scanner.alert_config(False, True)["email"]
            self.assertEqual((config["mode"], config["port"], len(config["recipients"])), ("starttls", 587, 2))
        with patch.dict(scanner.os.environ, {**settings, "SMTP_MODE": "ssl"}, clear=True):
            self.assertEqual(scanner.alert_config(False, True)["email"]["port"], 465)
        for override in ({"SMTP_USER": "demo"}, {"SMTP_PORT": "0"}, {"SMTP_MODE": "plain"}, {"SMTP_TO": "bad\naddress"}):
            with patch.dict(scanner.os.environ, {**settings, **override}, clear=True), self.assertRaises(ValueError):
                scanner.alert_config(False, True)

    def test_slack_acknowledgment_truncation_and_no_redirects(self):
        opener, response = MagicMock(), MagicMock()
        opener.open.return_value.__enter__.return_value = response
        response.status, response.read.return_value = 200, b"ok"
        with patch.object(scanner.urllib.request, "build_opener", return_value=opener) as build:
            scanner.send_slack("https://example.invalid/webhook", "x" * 4000, 1)
        payload = json.loads(opener.open.call_args.args[0].data)
        self.assertLess(len(payload["text"]), 3500)
        self.assertIn("See console", payload["text"])
        self.assertIsInstance(build.call_args.args[0], scanner.NoRedirect)
        self.assertIsNone(scanner.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid"))
        for code, body in ((200, b"not_ok"), (500, b"error")):
            response.status, response.read.return_value = code, body
            with patch.object(scanner.urllib.request, "build_opener", return_value=opener), self.assertRaises(ValueError):
                scanner.send_slack("https://example.invalid/webhook", "fixture", 1)

    def test_encrypted_email_modes_and_recipient_refusal(self):
        settings = {"host": "smtp.example.invalid", "port": 587, "sender": "from@example.invalid",
                    "recipients": ["to@example.invalid"], "credentials": ("demo", "fake")}
        for mode in ("starttls", "ssl"):
            server = MagicMock()
            server.send_message.return_value = {}
            with patch.object(scanner.smtplib, "SMTP", return_value=server) as plain, \
                    patch.object(scanner.smtplib, "SMTP_SSL", return_value=server) as secure:
                scanner.send_email({**settings, "mode": mode}, "fixture alert", 1)
            if mode == "starttls":
                plain.assert_called_once()
                secure.assert_not_called()
                context = server.starttls.call_args.kwargs["context"]
            else:
                secure.assert_called_once()
                plain.assert_not_called()
                server.starttls.assert_not_called()
                context = secure.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            server.login.assert_called_once_with("demo", "fake")
            self.assertEqual(server.send_message.call_args.args[0]["To"], "to@example.invalid")
        server.send_message.return_value = {"to@example.invalid": (550, b"refused")}
        with patch.object(scanner.smtplib, "SMTP_SSL", return_value=server), self.assertRaises(ValueError):
            scanner.send_email({**settings, "mode": "ssl"}, "fixture", 1)

    def test_smtp_tls_failure_does_not_login_or_send(self):
        server = MagicMock()
        server.starttls.side_effect = ssl.SSLError("TLS failed")
        settings = {"host": "smtp.example.invalid", "port": 587, "mode": "starttls",
                    "sender": "from@example.invalid", "recipients": ["to@example.invalid"], "credentials": ("demo", "fake")}
        with patch.object(scanner.smtplib, "SMTP", return_value=server), self.assertRaises(ssl.SSLError):
            scanner.send_email(settings, "fixture", 1)
        server.login.assert_not_called()
        server.send_message.assert_not_called()


class CLITests(unittest.TestCase):
    def test_filename_comments_normalization_and_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.txt"
            path.write_text("  # comment\nEXAMPLE.invalid\nhttps://example.invalid/\n")
            with patch.object(scanner, "check", return_value=result()) as check, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.main([str(path)]), 0)
            check.assert_called_once_with(("example.invalid", 443), 30, 8)

    def test_results_order_unknown_first_then_soonest(self):
        items = {"a.example.invalid": result("OK", "a", 60), "b.example.invalid": result("CRITICAL", "b", 3),
                 "c.example.invalid": result("INVALID_CERT", "c")}
        output = io.StringIO()
        with patch.object(scanner, "check", side_effect=lambda endpoint, *_: items[endpoint[0]]), contextlib.redirect_stdout(output):
            self.assertEqual(scanner.main(list(items)), 1)
        self.assertLess(output.getvalue().index("[INVALID_CERT]"), output.getvalue().index("[CRITICAL]"))
        self.assertLess(output.getvalue().index("[CRITICAL]"), output.getvalue().index("[OK]"))

    def test_healthy_never_sends_and_issues_send_once_per_channel(self):
        for status, expected, sends in (("OK", 0, 0), ("WARNING", 1, 1), ("ERROR", 2, 1)):
            with patch.object(scanner, "check", return_value=result(status)), \
                    patch.object(scanner, "alert_config", return_value={"slack": "configured", "email": {}}), \
                    patch.object(scanner, "send_slack") as slack, patch.object(scanner, "send_email") as email, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.main(["app.example.invalid", "--slack", "--email"]), expected)
                self.assertEqual(slack.call_count, sends)
                self.assertEqual(email.call_count, sends)

    def test_alert_failure_still_attempts_other_channel(self):
        with patch.object(scanner, "check", return_value=result("WARNING")), \
                patch.object(scanner, "alert_config", return_value={"slack": "configured", "email": {}}), \
                patch.object(scanner, "send_slack", side_effect=OSError("private diagnostic")), \
                patch.object(scanner, "send_email") as email, contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(scanner.main(["app.example.invalid", "--slack", "--email"]), 2)
            email.assert_called_once()
            self.assertNotIn("private diagnostic", output.getvalue())

    def test_console_only_is_default(self):
        with patch.object(scanner, "check", return_value=result("CRITICAL")), patch.object(scanner, "send_slack") as slack, \
                patch.object(scanner, "send_email") as email, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main(["app.example.invalid"]), 1)
        slack.assert_not_called()
        email.assert_not_called()

    def test_invalid_targets_config_and_numbers_fail_before_checks(self):
        with patch.object(scanner, "check") as check, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(["http://example.invalid"]), 2)
            with patch.dict(scanner.os.environ, {}, clear=True):
                self.assertEqual(scanner.main(["example.invalid", "--slack"]), 2)
            for arguments in (("--days", "-1"), ("--timeout", "nan"), ("--timeout", "0")):
                with self.assertRaises(SystemExit) as error:
                    scanner.main(["example.invalid", *arguments])
                self.assertEqual(error.exception.code, 2)
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
