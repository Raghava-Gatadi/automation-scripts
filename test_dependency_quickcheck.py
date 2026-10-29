"""Dependency parser and mocked OSV tests; no public API traffic or installs."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import dependency_quickcheck as checker


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def parse(self, path):
        packages, skipped = [], []
        reader = {"requirements.txt": checker.read_requirements, "package.json": checker.read_package_json,
                  "package-lock.json": checker.read_package_lock}[path.name]
        reader(path, lambda *values: packages.append(values), lambda *values: skipped.append(values))
        return packages, skipped

    def run_cli(self, paths, answers=None, error=None):
        output = io.StringIO()
        report_path = self.root / "report.json"
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), \
                patch.object(checker, "query_osv", return_value=answers or [], side_effect=error) as query:
            code = checker.main([*map(str, paths), "--json", str(report_path)])
        report = json.loads(report_path.read_text()) if report_path.exists() else None
        return code, report, output.getvalue(), query

    def test_requirements_pins_extras_markers_hashes_and_normalization(self):
        path = self.write("requirements.txt", "# comment\nSome_Pkg[extra]==1.2.3; python_version < '3'\n"
                          "requests==2.31.0 \\\n    --hash=sha256:abcd\n")
        packages, skipped = self.parse(path)
        self.assertEqual([p[:3] for p in packages], [("PyPI", "some-pkg", "1.2.3"), ("PyPI", "requests", "2.31.0")])
        self.assertEqual(skipped, [])

    def test_requirements_unknown_versions_and_directives_are_visible(self):
        path = self.write("requirements.txt", "foo>=1\nbar==1.*\nbaz\n-r other.txt\n-e ./local\nunfinished==1 \\\n")
        packages, skipped = self.parse(path)
        self.assertEqual(packages, [])
        self.assertEqual(len(skipped), 6)

    def test_package_ranges_are_not_guessed(self):
        path = self.write("package.json", {"dependencies": {"lodash": "^4.17.20", "foo": "~1.2.3", "bar": ">=1.0.0"}})
        packages, skipped = self.parse(path)
        self.assertEqual(packages, [])
        self.assertEqual(len(skipped), 3)

    def test_package_exact_versions_and_optional_override(self):
        path = self.write("package.json", {"dependencies": {"foo": "1.0.0", "@scope/pkg": "=v2.0.0-beta.1+build"},
                                          "devDependencies": {"test": "3.0.0"}, "optionalDependencies": {"foo": "2.0.0"}})
        packages, skipped = self.parse(path)
        self.assertEqual({p[:3] for p in packages}, {("npm", "foo", "2.0.0"), ("npm", "test", "3.0.0"),
                                                   ("npm", "@scope/pkg", "2.0.0-beta.1+build")})
        self.assertEqual(skipped, [])

    def test_lock_versions_nested_scoped_aliases_and_root(self):
        for lock_version in (2, 3):
            path = self.write("package-lock.json", {"lockfileVersion": lock_version, "packages": {
                "": {"name": "project", "version": "1.0.0"},
                "node_modules/foo": {"version": "1.0.0"},
                "node_modules/foo/node_modules/@scope/bar": {"version": "2.0.0"},
                "node_modules/alias": {"name": "actual", "version": "3.0.0"},
            }})
            packages, skipped = self.parse(path)
            self.assertEqual({p[:3] for p in packages}, {("npm", "foo", "1.0.0"), ("npm", "@scope/bar", "2.0.0"),
                                                       ("npm", "actual", "3.0.0")})
            self.assertEqual(skipped, [])

    def test_lock_local_git_missing_versions_are_skipped(self):
        path = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/local": {"link": True, "resolved": "packages/local"},
            "packages/local": {"version": "1.0.0"},
            "node_modules/git": {"version": "1.0.0", "resolved": "git+https://example.invalid/project#commit"},
            "node_modules/missing": {},
        }})
        packages, skipped = self.parse(path)
        self.assertFalse(packages)
        self.assertEqual(len(skipped), 4)

    def test_invalid_lock_and_manifest_shapes_fail(self):
        for value in ({"lockfileVersion": 1}, {"lockfileVersion": 3}, {"lockfileVersion": 3, "packages": []},
                      {"lockfileVersion": 3, "packages": {"node_modules/x": []}}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse(self.write("package-lock.json", value))
        with self.assertRaises(ValueError):
            self.parse(self.write("package.json", {"dependencies": []}))

    def test_discovery_prefers_lock_but_explicit_manifest_is_respected(self):
        req = self.write("requirements.txt", "")
        manifest = self.write("package.json", {})
        lock = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        self.assertEqual(checker.discover([self.root]), [req, lock])
        self.assertEqual(checker.discover([manifest, lock, lock]), [manifest, lock])
        lock.unlink()
        self.assertEqual(checker.discover([self.root]), [req, manifest])

    def test_deduplication_and_advisory_output(self):
        path = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "node_modules/foo": {"version": "1.0.0"}, "node_modules/bar/node_modules/foo": {"version": "1.0.0"}}})
        code, report, output, query = self.run_cli([path], [["GHSA-demo-id"]])
        self.assertEqual(code, 1)
        self.assertTrue(report["complete"])
        self.assertEqual(report["packages_checked"], 1)
        self.assertEqual(len(query.call_args.args[0]), 1)
        self.assertEqual(len(report["results"][0]["sources"]), 2)
        self.assertIn("https://osv.dev/vulnerability/GHSA-demo-id", output)

    def test_clean_skipped_and_api_error_exit_codes(self):
        path = self.write("requirements.txt", "foo==1.0.0")
        code, report, _, _ = self.run_cli([path], [[]])
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        path.write_text("foo==1.0.0\nbar>=1")
        code, report, _, _ = self.run_cli([path], [["OSV-demo"]])
        self.assertEqual(code, 2)
        self.assertFalse(report["complete"])
        self.assertTrue(report["results"][0]["advisories"])
        code, report, output, _ = self.run_cli([path], error=urllib.error.URLError("private diagnostic"))
        self.assertEqual(code, 2)
        self.assertFalse(report["complete"])
        self.assertNotIn("private diagnostic", output)

    def test_invalid_inputs_make_no_queries(self):
        path = self.write("package.json", "{broken")
        output = io.StringIO()
        with contextlib.redirect_stderr(output), patch.object(checker, "query_osv") as query:
            self.assertEqual(checker.main([str(path)]), 2)
            self.assertEqual(checker.main([str(path), "--json", str(path)]), 2)
            query.assert_not_called()

    def test_report_cannot_overwrite_manifest_hidden_by_lock_preference(self):
        manifest = self.write("package.json", {"dependencies": {"foo": "^1.0.0"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        before = manifest.read_text()
        with contextlib.redirect_stderr(io.StringIO()), patch.object(checker, "query_osv") as query:
            self.assertEqual(checker.main([str(self.root), "--json", str(manifest)]), 2)
            query.assert_not_called()
        self.assertEqual(manifest.read_text(), before)

    def test_specs_containing_credentials_are_not_echoed(self):
        private = "https://user:" + "private-value@example.invalid/repo"
        path = self.write("package.json", {"dependencies": {"foo": private}})
        code, report, output, _ = self.run_cli([path])
        self.assertEqual(code, 2)
        self.assertNotIn(private, output + json.dumps(report))


class OSVTests(unittest.TestCase):
    @staticmethod
    def packages(count=1):
        return [{"ecosystem": "npm", "name": f"pkg-{i}", "version": "1.0.0"} for i in range(count)]

    @staticmethod
    def response(data):
        return io.BytesIO(json.dumps(data).encode())

    def test_batching_and_query_order(self):
        def respond(request, timeout):
            queries = json.loads(request.data)["queries"]
            self.assertEqual(request.full_url, checker.API)
            self.assertEqual(timeout, 5)
            return self.response({"results": [{"vulns": [{"id": q["package"]["name"]}]} for q in queries]})
        with patch.object(checker.urllib.request, "urlopen", side_effect=respond) as urlopen:
            matches = checker.query_osv(self.packages(101), 5)
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(matches, [[f"pkg-{i}"] for i in range(101)])

    def test_per_package_pagination_and_deduplication(self):
        responses = [self.response({"results": [{"vulns": [{"id": "A"}], "next_page_token": "next"}, {}]}),
                     self.response({"results": [{"vulns": [{"id": "A"}, {"id": "B"}]}]})]
        with patch.object(checker.urllib.request, "urlopen", side_effect=responses) as urlopen:
            self.assertEqual(checker.query_osv(self.packages(2), 5), [["A", "B"], []])
        queries = json.loads(urlopen.call_args.args[0].data)["queries"]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0]["page_token"], "next")

    def test_invalid_responses_fail_instead_of_clean_result(self):
        for data in ({}, {"results": []}, {"results": [None]}, {"results": [{"error": "bad"}]},
                     {"results": [{"vulns": {}}]}, {"results": [{"vulns": [{}]}]},
                     {"results": [{"next_page_token": 123}]}):
            with self.subTest(data=data), patch.object(checker.urllib.request, "urlopen", return_value=self.response(data)), \
                    self.assertRaises(ValueError):
                checker.query_osv(self.packages(), 5)

    def test_repeated_pagination_fails(self):
        data = {"results": [{"next_page_token": "same"}]}
        with patch.object(checker.urllib.request, "urlopen", side_effect=[self.response(data), self.response(data)]), \
                self.assertRaises(ValueError):
            checker.query_osv(self.packages(), 5)

    def test_empty_input_makes_no_requests(self):
        with patch.object(checker.urllib.request, "urlopen") as urlopen:
            self.assertEqual(checker.query_osv([], 5), [])
            urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
