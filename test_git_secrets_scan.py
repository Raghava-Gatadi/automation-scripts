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
        values = scanner.detect("test", high + "\n" + low, 4.5)
        self.assertEqual([f["rule"] for f in values], ["entropy-token"])
        hex_value = "0123456789abcdef" * 4
        self.assertEqual(scanner.detect("test", hex_value, 4.5)[0]["rule"], "entropy-hex")
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


if __name__ == "__main__":
    unittest.main()
