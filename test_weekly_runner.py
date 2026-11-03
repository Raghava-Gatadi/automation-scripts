"""Runner integration tests with disposable scripts, not real scans or alerts."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import weekly_runner as runner


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "config.json"
        self.checks = {key: ["argument with spaces"] for key, _, _ in runner.CHECKS}
        self.config.write_text(json.dumps({"checks": self.checks}))

    def main(self, *arguments):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.main([str(self.config), *arguments])

    def fake_scripts(self, codes):
        for (key, _, filename), code in zip(runner.CHECKS, codes):
            source = ("import sys\nfrom pathlib import Path\n"
                      f"with open('order.txt', 'a') as handle: handle.write({key!r} + '\\n')\n"
                      "print('cwd=' + str(Path.cwd()))\n"
                      "print('arg=' + sys.argv[1])\n"
                      f"print('stderr={key}', file=sys.stderr)\nraise SystemExit({code})\n")
            (self.root / filename).write_text(source)

    def test_six_real_subprocesses_keep_order_and_continue_after_errors(self):
        self.fake_scripts([0, 1, 2, 0, 0, 0])
        with patch.object(runner, "SCRIPT_DIR", self.root):
            self.assertEqual(self.main(), 2)
        report = (self.root / "reports" / "weekly-report.md").read_text()
        self.assertEqual((self.root / "order.txt").read_text().splitlines(), list(self.checks))
        self.assertIn("| 2 | Git secrets | FINDINGS | 1 |", report)
        self.assertIn("| 3 | Dependency vulnerabilities | INCOMPLETE/ERROR | 2 |", report)
        self.assertIn("## Day 6: Certificate expiry", report)
        self.assertIn("arg=argument with spaces", report)
        self.assertIn("cwd=" + str(self.root.resolve()), report)
        self.assertIn("stderr=certificates", report)

    def test_clean_and_findings_exit_codes_and_existing_report_refresh(self):
        for codes, expected in (([0] * 6, 0), ([0, 0, 1, 0, 0, 0], 1)):
            with self.subTest(codes=codes):
                self.fake_scripts(codes)
                with patch.object(runner, "SCRIPT_DIR", self.root):
                    self.assertEqual(self.main("--report", "nested/report.md"), expected)
        self.assertTrue((self.root / "nested" / "report.md").read_text().startswith(runner.TITLE))

    def test_timeout_partial_output_and_launch_failure_continue(self):
        responses = [subprocess.TimeoutExpired(["fixture"], 1, output=b"partial output\xff"),
                     FileNotFoundError(), *[subprocess.CompletedProcess([], 0, "done") for _ in range(4)]]
        with patch.object(runner.subprocess, "run", side_effect=responses) as run, contextlib.redirect_stdout(io.StringIO()):
            results = runner.run_checks(self.checks, self.root, 1)
        self.assertEqual(run.call_count, 6)
        self.assertEqual(results[0]["status"], "TIMEOUT")
        self.assertIn("partial output", results[0]["output"])
        self.assertIn("timed out", results[0]["output"])
        self.assertEqual(results[1]["exit_code"], None)
        self.assertEqual(results[-1]["status"], "PASS")

    def test_missing_child_is_reported_and_later_steps_run(self):
        self.fake_scripts([0] * 6)
        (self.root / runner.CHECKS[0][2]).unlink()
        with patch.object(runner, "SCRIPT_DIR", self.root):
            self.assertEqual(self.main(), 2)
        report = (self.root / "reports" / "weekly-report.md").read_text()
        self.assertIn("| 1 | Web security | INCOMPLETE/ERROR | 2 |", report)
        self.assertEqual(len((self.root / "order.txt").read_text().splitlines()), 5)

    def test_invalid_config_stops_before_any_child(self):
        for value in ({}, {"checks": []}, {"checks": {"appsec": []}},
                      {"checks": {**self.checks, "unknown": []}},
                      {"checks": {**self.checks, "secrets": "not a list"}},
                      {"checks": {**self.checks, "secrets": [None]}}):
            self.config.write_text(json.dumps(value))
            with self.subTest(value=value), patch.object(runner.subprocess, "run") as run:
                self.assertEqual(self.main(), 2)
                run.assert_not_called()

    def test_protects_config_input_and_unrelated_report_file(self):
        unrelated = self.root / "notes.md"
        unrelated.write_text("# Keep these notes\n")
        source = self.root / "input.md"
        source.write_text(runner.TITLE)
        self.checks["appsec"] = ["input.md"]
        self.config.write_text(json.dumps({"checks": self.checks}))
        for destination in (self.config, unrelated, source):
            before = destination.read_bytes()
            with self.subTest(destination=destination), patch.object(runner.subprocess, "run") as run:
                self.assertEqual(self.main("--report", str(destination)), 2)
                run.assert_not_called()
            self.assertEqual(destination.read_bytes(), before)

    def test_report_preserves_output_as_literal_text(self):
        results = [{"day": 1, "name": "Web security", "status": "PASS", "exit_code": 0,
                    "seconds": 1, "output": "## Untrusted heading\n```\n<script>fixture</script>"}]
        text = runner.report_text(results, "fixture time")
        self.assertNotIn("\n## Untrusted heading", text)
        self.assertIn("    ## Untrusted heading", text)
        self.assertIn("    <script>fixture</script>", text)

    def test_example_config_contains_every_check(self):
        example = Path(runner.__file__).with_name("weekly_runner.example.json")
        self.assertEqual(set(runner.load_config(example)), set(self.checks))


if __name__ == "__main__":
    unittest.main()
