"""Semgrep wrapper fixtures; requires no installed Semgrep and scans no real code."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import semgrep_quickcheck as scanner


def finding(line=1, severity="WARNING", path="app.py"):
    return {"check_id": "fixture.rule", "path": path, "start": {"line": line}, "end": {"line": line},
            "extra": {"severity": severity, "message": "PRIVATE_SOURCE", "lines": "PRIVATE_SOURCE",
                      "metavars": {"private": "PRIVATE_SOURCE"}}}


class SemgrepTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name).resolve()
        (self.repo / "app.py").write_text('print("a b")\n')
        self.baseline = self.repo / ".semgrep-baseline.json"
        self.report = self.repo / "summary.json"

    def invoke(self, findings=None, code=0, errors=None, skipped=None, extra_args=(), failure=None):
        payload = {"version": "fixture", "results": findings if findings is not None else [finding()],
                   "errors": errors or [], "skipped_rules": skipped or [], "paths": {"scanned": ["app.py"]}}
        response = subprocess.CompletedProcess([], code, json.dumps(payload), "PRIVATE_STDERR")
        output = io.StringIO()
        with patch.object(scanner.shutil, "which", return_value="/fixture/semgrep"), \
                patch.object(scanner.subprocess, "run", return_value=response, side_effect=failure) as run, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = scanner.main([str(self.repo), "--json", str(self.report), *extra_args])
        data = json.loads(self.report.read_text()) if self.report.exists() else None
        return result, data, output.getvalue(), run

    def test_default_scan_summary_is_source_free_and_uses_safety_flags(self):
        code, data, output, run = self.invoke()
        self.assertEqual(code, 1)
        self.assertEqual(data["finding_count"], 1)
        self.assertEqual(data["by_rule"], {"fixture.rule": 1})
        self.assertNotIn("PRIVATE_SOURCE", json.dumps(data) + output)
        self.assertNotIn("PRIVATE_STDERR", output)
        command = run.call_args.args[0]
        for flag in ("--strict", "--error", "--metrics=off", "--oss-only", "--config=p/default", "--exclude=.semgrep-baseline.json"):
            self.assertIn(flag, command)
        self.assertNotIn("--autofix", command)

    def test_baseline_update_then_line_move_stays_baselined(self):
        self.assertEqual(self.invoke(extra_args=["--update-baseline"])[0], 0)
        baseline = self.baseline.read_text()
        self.assertNotIn('print(', baseline)
        self.assertNotIn("PRIVATE_SOURCE", baseline)
        (self.repo / "app.py").write_text('\nprint("a b")\n')
        code, data, _, _ = self.invoke([finding(2)])
        self.assertEqual(code, 0)
        self.assertEqual((data["finding_count"], data["baselined_count"]), (0, 1))

    def test_literal_whitespace_or_severity_changes_resurface(self):
        self.invoke(extra_args=["--update-baseline"])
        (self.repo / "app.py").write_text('print("a  b")\n')
        self.assertEqual(self.invoke()[0], 1)
        (self.repo / "app.py").write_text('print("a b")\n')
        self.assertEqual(self.invoke([finding(severity="ERROR")])[0], 1)

    def test_identical_occurrence_added_is_new(self):
        self.invoke(extra_args=["--update-baseline"])
        (self.repo / "app.py").write_text('print("a b")\nprint("a b")\n')
        code, data, _, _ = self.invoke([finding(), finding(2)])
        self.assertEqual(code, 1)
        self.assertEqual((data["finding_count"], data["baselined_count"]), (1, 1))

    def test_absent_entries_are_stale_not_claimed_fixed(self):
        self.invoke(extra_args=["--update-baseline"])
        code, data, output, _ = self.invoke([])
        self.assertEqual(code, 0)
        self.assertEqual(data["stale_baseline_count"], 1)
        self.assertIn("absent from this scan scope", output)

    def test_severity_threshold_affects_exit_not_visibility(self):
        code, data, _, _ = self.invoke([finding(severity="INFO")], extra_args=["--fail-on", "ERROR"])
        self.assertEqual(code, 0)
        self.assertEqual((data["finding_count"], data["blocking_count"]), (1, 0))

    def test_errors_and_skipped_rules_do_not_replace_baseline(self):
        self.invoke(extra_args=["--update-baseline"])
        before = self.baseline.read_bytes()
        for kwargs in ({"errors": [{"message": "PRIVATE_ERROR"}]}, {"skipped": ["unsupported"]}, {"code": 5}):
            with self.subTest(kwargs=kwargs):
                code, data, output, _ = self.invoke(extra_args=["--update-baseline"], **kwargs)
                self.assertEqual(code, 2)
                self.assertFalse(data["complete"])
                self.assertNotIn("PRIVATE_ERROR", output)
                self.assertEqual(self.baseline.read_bytes(), before)

    def test_corrupt_baseline_stops_before_scan(self):
        self.baseline.write_text('{"version":1,"findings":[]}')
        code, _, _, run = self.invoke()
        self.assertEqual(code, 2)
        run.assert_not_called()

    def test_missing_or_outside_source_cannot_be_accepted(self):
        for path in ("missing.py", "../outside.py"):
            with self.subTest(path=path):
                code, data, _, _ = self.invoke([finding(path=path)], extra_args=["--update-baseline"])
                self.assertEqual(code, 2)
                self.assertFalse(data["complete"])
                self.assertFalse(self.baseline.exists())

    def test_git_baseline_is_separate_and_resolved_to_a_commit(self):
        sha = "a" * 40
        payload = {"results": [finding(path="not-read.py")], "errors": [], "paths": {"scanned": []}}
        replies = [subprocess.CompletedProcess([], 0, sha + "\n", ""),
                   subprocess.CompletedProcess([], 1, json.dumps(payload), "")]
        with patch.object(scanner.shutil, "which", return_value="/fixture/semgrep"), \
                patch.object(scanner.subprocess, "run", side_effect=replies) as run, \
                patch.dict(scanner.os.environ, {"SEMGREP_BASELINE_COMMIT": "inherited"}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main([str(self.repo), "--baseline", "HEAD~1"]), 1)
        self.assertIn("--baseline-commit=" + sha, run.call_args.args[0])
        self.assertNotIn("SEMGREP_BASELINE_COMMIT", run.call_args.kwargs["env"])
        self.assertFalse(self.baseline.exists())

    def test_timeout_and_malformed_results_are_incomplete(self):
        code, data, _, _ = self.invoke(failure=subprocess.TimeoutExpired([], 1))
        self.assertEqual(code, 2)
        self.assertFalse(data["complete"])
        malformed = finding()
        malformed["end"] = None
        self.assertEqual(self.invoke([malformed])[0], 2)

    def test_baseline_and_summary_cannot_share_output(self):
        with contextlib.redirect_stderr(io.StringIO()), patch.object(scanner.subprocess, "run") as run:
            self.assertEqual(scanner.main([str(self.repo), "--baseline-file", str(self.report), "--json", str(self.report)]), 2)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
