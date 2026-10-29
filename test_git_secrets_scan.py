"""Integration tests use synthetic values in disposable local Git repositories."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import git_secrets_scan as scanner


SCRIPT = Path(scanner.__file__).resolve()


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git("init", "-q")
        self.git("config", "user.name", "Scanner Test")
        self.git("config", "user.email", "scanner-test@example.invalid")
        self.secret = "ghp_" + "Ab9x" * 9

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              capture_output=True)

    def write(self, name, content, track=True):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        if track:
            self.git("add", "--", name)
        return path

    def run_scan(self, *args, expected=0):
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root), *args],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        return result

    def test_clean_and_regex_redaction(self):
        self.write("clean.py", "print('hello')\n")
        self.run_scan()
        self.write("config.txt", self.secret)
        self.run_scan("--json", "report.json", expected=1)
        report = (self.root / "report.json").read_text()
        self.assertNotIn(self.secret, report)
        self.assertEqual(json.loads(report)["new_findings"][0]["rule"], "github-token")

    def test_baseline_survives_line_move_but_not_secret_rotation(self):
        path = self.write("config.txt", self.secret)
        self.run_scan("--write-baseline")
        baseline = (self.root / scanner.DEFAULT_BASELINE).read_text()
        self.assertNotIn(self.secret, baseline)
        path.write_text("\n\n" + self.secret)
        self.run_scan()
        path.write_text("ghp_" + "Zy8w" * 9)
        self.run_scan(expected=1)

    def test_private_key_baseline_detects_rotation(self):
        header = "-----BEGIN " + "PRIVATE KEY-----\n"
        footer = "\n-----END " + "PRIVATE KEY-----"
        path = self.write("key.txt", header + "first-key-body" + footer)
        self.run_scan("--write-baseline")
        path.write_text(header + "second-key-body" + footer)
        result = self.run_scan(expected=1)
        self.assertIn("private-key", result.stdout)
        self.assertNotIn("second-key-body", result.stdout)

    def test_index_is_independent_of_working_tree(self):
        path = self.write("config.txt", self.secret)
        path.write_text("clean\n")
        self.run_scan()
        self.run_scan("--staged", expected=1)
        self.git("add", "config.txt")
        path.write_text(self.secret)
        self.run_scan("--staged")
        self.run_scan(expected=1)

    def test_untracked_and_gitignore(self):
        self.write(".gitignore", "ignored.txt\n")
        self.write("ignored.txt", self.secret, track=False)
        self.write("new.txt", self.secret, track=False)
        self.run_scan()
        self.run_scan("--include-untracked", "--json", "report.json", expected=1)
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual([f["path"] for f in report["new_findings"]], ["new.txt"])

    def test_binary_large_deleted_and_symlink(self):
        self.write("binary", b"\0" + self.secret.encode())
        self.write("large", "x" * 200)
        self.write("deleted", self.secret).unlink()
        self.write("outside.txt", self.secret, track=False)
        (self.root / "link").symlink_to(self.root / "outside.txt")
        self.git("add", "link")
        self.run_scan("--max-bytes", "100", "--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(len(report["skipped"]), 4)

    def test_odd_filename_and_no_line_leak(self):
        self.write("odd\nname.txt", self.secret)
        result = self.run_scan(expected=1)
        self.assertIn('"odd\\nname.txt":1:', result.stdout)

    def test_malformed_baseline_fails_closed(self):
        path = self.root / scanner.DEFAULT_BASELINE
        for value in ('{}', '{"version":1,"findings":[{}]}', 'not json', '[]'):
            path.write_text(value)
            self.run_scan(expected=2)

    def test_report_cannot_overwrite_tracked_source_or_baseline(self):
        source = self.write("source.py", "print('keep me')")
        self.run_scan("--json", "source.py", expected=2)
        self.assertEqual(source.read_text(), "print('keep me')")
        self.run_scan("--json", scanner.DEFAULT_BASELINE, expected=2)

    def test_staged_size_limit_and_custom_baseline(self):
        self.write("config.txt", self.secret)
        self.run_scan("--staged", "--baseline", "accepted.json", "--write-baseline")
        self.run_scan("--staged", "--baseline", "accepted.json")
        self.run_scan("--staged", "--max-bytes", "10", "--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["skipped"], [{"path": "config.txt", "reason": "size limit"}])

    def test_failure_does_not_replace_baseline(self):
        self.write("config.txt", self.secret)
        self.run_scan("--write-baseline")
        path = self.root / scanner.DEFAULT_BASELINE
        before = path.read_bytes()
        self.run_scan("--write-baseline", "--json", "missing/report.json", expected=2)
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_arguments(self):
        self.run_scan("--staged", "--include-untracked", expected=2)
        self.run_scan("--entropy-threshold", "nan", expected=2)
        self.run_scan("--max-bytes", "0", expected=2)

    def test_entropy_and_assignment_rules(self):
        high = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL"
        low = "a1" * 30
        values = scanner.detect("test", '"' + high + '"\n"' + low + '"', 4.5)
        self.assertEqual([f["rule"] for f in values], ["entropy-token"])
        hex_value = "0123456789abcdef" * 4
        self.assertEqual(scanner.detect("test", 'key material: "' + hex_value + '"', 4.5)[0]["rule"], "entropy-hex")
        assignment = "password" + ' = "' + "ordinary-value" + '"'
        self.assertEqual(scanner.detect("test", assignment, 4.5)[0]["rule"], "secret-assignment")
        self.assertEqual(scanner.entropy("aaaa"), 0)

    def test_provider_rules(self):
        examples = {
            "aws-access-key": "AKIA" + "X" * 16,
            "github-token": self.secret,
            "slack-token": "xoxb" + "-" + "1234567890-abcd",
            "google-api-key": "AIza" + "x" * 35,
            "stripe-live-key": "sk_" + "live_" + "x" * 24,
            "credential-url": "https://alice:" + "example-password" + "@example.invalid",
        }
        for rule, value in examples.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, [f["rule"] for f in scanner.detect("test", value, 4.5)])

    def test_added_rules_and_severities(self):
        examples = {
            "aws-secret-key": "AWS_SECRET_ACCESS_KEY" + ' = "' + "Ab9/" * 10 + '"',
            "slack-webhook": "https://hooks.slack.com/" + "services/T123/B456/abcdef123",
            "jwt": "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
            "private-key": "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\nbody\n-----END PGP " + "PRIVATE KEY BLOCK-----",
        }
        for rule, value in examples.items():
            with self.subTest(rule=rule):
                results = scanner.detect("test", value, 4.5)
                self.assertEqual([f["rule"] for f in results], [rule])
                self.assertIn(results[0]["severity"], scanner.SEVERITY_ORDER)

    def test_contextual_entropy_and_no_entropy(self):
        value = "Ab3De6Gh9Jk2Mn5Pq8St1Vw4Yz7Cf0Il"
        self.assertEqual(scanner.detect("test", value, 4.5), [])
        self.assertEqual(len(scanner.detect("test", value, 4.5, entropy_mode="all")), 1)
        self.assertEqual(len(scanner.detect("test", "VALUE=" + value, 4.5)), 1)
        hex_value = "0123456789abcdef" * 4
        self.assertEqual(scanner.detect("test", 'checksum = "' + hex_value + '"', 4.5), [])
        uuid = "01234567-89ab-cdef-0123-456789abcdef"
        self.assertEqual(scanner.detect("test", 'id = "' + uuid + '"', 1.0), [])
        self.write("data.txt", 'value = "' + value + '"')
        self.run_scan(expected=1)
        self.run_scan("--no-entropy")
        self.write("config.txt", self.secret)
        self.run_scan("--no-entropy", expected=1)

    def test_exact_placeholders_do_not_hide_real_secrets(self):
        prefix = "password" + ' = "'
        for value in ("changeme", "your_password", "${MY_PASSWORD}", "{{MY_PASSWORD}}", "<PASSWORD>"):
            self.assertEqual(scanner.detect("test", prefix + value + '"', 4.5), [])
        for value in ("my-example-real-secret", "your-real-password-123", "StrongPassword123"):
            self.assertTrue(scanner.detect("test", prefix + value + '"', 4.5))
        # Provider patterns are never suppressed by placeholder substrings.
        self.assertTrue(scanner.detect("test", "ghp_" + "example" + "A" * 29, 4.5))

    def test_allowlist_is_opt_in_and_counted(self):
        self.write("config.txt", self.secret + " # pragma: allowlist secret")
        self.run_scan(expected=1)
        self.run_scan("--honor-allowlist", "--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["inline_allowlisted_count"], 1)
        self.assertEqual(report["new_findings"], [])
        self.write("config.txt", self.secret + " nosecret")
        self.run_scan("--honor-allowlist", expected=1)

    def test_long_lines_and_explicit_exclusions(self):
        self.write("vendor/fixture.txt", " " * 3000 + self.secret)
        self.run_scan(expected=1)
        self.run_scan("--exclude", "vendor/*", "--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["skipped"], [{"path": "vendor/fixture.txt", "reason": "excluded"}])

    def test_history_deleted_secret_and_odd_path(self):
        path = self.write("odd\tname\n.txt", "clean\n" + self.secret)
        self.git("commit", "-qm", "Add synthetic fixture")
        commit = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.git("rm", "--", path.name)
        self.git("commit", "-qm", "Remove fixture")
        self.run_scan()
        self.run_scan("--history", "--json", "report.json", expected=1)
        report = json.loads((self.root / "report.json").read_text())
        self.assertNotIn(self.secret, json.dumps(report))
        finding = report["new_findings"][0]
        self.assertEqual((finding["path"], finding["line"], finding["commit"]), (path.name, 2, commit))
        self.assertEqual(finding["where"], "history")
        self.run_scan("--history", "--update-baseline")
        self.run_scan("--history")

    def test_history_unborn_repository(self):
        self.run_scan("--history")

    def test_history_includes_detached_head(self):
        self.write("readme", "hello")
        self.git("commit", "-qm", "Initial")
        self.git("checkout", "--detach")
        path = self.write("config.txt", self.secret)
        self.git("commit", "-qm", "Detached fixture")
        path.write_text("clean")
        self.run_scan("--history", expected=1)

    def test_shallow_history_is_reported(self):
        self.write("readme", "hello")
        self.git("commit", "-qm", "Initial")
        commit = self.git("rev-parse", "HEAD").stdout
        (self.root / ".git" / "shallow").write_bytes(commit)
        result = self.run_scan("--history", "--json", "report.json")
        self.assertIn("shallow clone", result.stderr)
        self.assertTrue(json.loads((self.root / "report.json").read_text())["history_shallow"])

    def test_history_exclusions_and_size_limits_are_reported(self):
        self.write("vendor/config.txt", self.secret)
        self.git("commit", "-qm", "Fixture")
        self.git("rm", "vendor/config.txt")
        self.git("commit", "-qm", "Remove fixture")
        self.run_scan("--history", "--exclude", "vendor/*", "--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["skipped"][0]["reason"], "excluded")
        self.assertIn("commit", report["skipped"][0])
        self.run_scan("--history", "--max-bytes", "10", "--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["skipped"][0]["reason"], "size limit")

    def test_history_deduplicates_versions_and_current_findings(self):
        self.write("config.txt", self.secret)
        self.git("commit", "-qm", "Add fixture")
        self.write("readme", "hello")
        self.git("commit", "-qm", "Keep fixture unchanged")
        self.run_scan("--history", "--json", "report.json", expected=1)
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(len(report["new_findings"]), 1)
        self.assertEqual(report["new_findings"][0]["where"], "working-tree")
        self.assertEqual(report["history_versions_scanned"], 2)

    def test_current_allowlist_does_not_hide_historical_secret(self):
        path = self.write("config.txt", self.secret)
        self.git("commit", "-qm", "Add fixture")
        path.write_text(self.secret + " # nosecret")
        self.run_scan("--honor-allowlist")
        self.run_scan("--history", "--honor-allowlist", "--json", "report.json", expected=1)
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["new_findings"][0]["where"], "history")

    def test_history_captures_merge_only_key_and_other_refs(self):
        self.write("readme", "hello")
        self.git("commit", "-qm", "Initial")
        base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.git("checkout", "-qb", "side")
        self.write("side.txt", "hello side")
        self.git("commit", "-qm", "Side")
        self.git("checkout", "-qb", "main-test", base)
        self.write("main.txt", "hello main")
        self.git("commit", "-qm", "Main")
        self.git("merge", "--no-ff", "--no-commit", "side")
        key = "-----BEGIN " + "PRIVATE KEY-----\nsynthetic-body\n-----END " + "PRIVATE KEY-----"
        self.write("merge-key.txt", key)
        self.git("commit", "-qm", "Merge with fixture")
        self.git("checkout", "--detach", base)
        self.run_scan("--history", "--json", "report.json", expected=1)
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual([f["rule"] for f in report["new_findings"]], ["private-key"])

    def test_stale_baseline_reporting_and_update_alias(self):
        path = self.write("config.txt", self.secret)
        self.run_scan("--update-baseline")
        path.write_text("clean")
        self.run_scan("--json", "report.json")
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["stale_baseline_count"], 1)
        self.run_scan("--update-baseline")
        self.assertEqual(json.loads((self.root / scanner.DEFAULT_BASELINE).read_text())["findings"], [])

    def test_history_git_failure_is_an_error(self):
        from unittest.mock import patch
        with patch.object(scanner, "git", side_effect=scanner.ScanError("Git command failed: rev-list")):
            with self.assertRaises(scanner.ScanError):
                scanner.scan_history(self.root, set(), 1048576, 4.5)


if __name__ == "__main__":
    unittest.main()
