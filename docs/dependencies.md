# Dependency quick check (day 3)

`dependency_quickcheck.py` sends exact package versions from `requirements.txt`,
`package.json`, and `package-lock.json` (v2/v3) to the [OSV API](https://google.github.io/osv.dev/post-v1-querybatch/)
and prints advisory IDs with links. It uses only the Python standard library.

```sh
python3 scripts/repository/dependency_quickcheck.py                   # manifests in this directory
python3 scripts/repository/dependency_quickcheck.py /path/to/project
python3 scripts/repository/dependency_quickcheck.py requirements.txt frontend/package.json
python3 scripts/repository/dependency_quickcheck.py requirements.txt frontend/package-lock.json
python3 scripts/repository/dependency_quickcheck.py /path/to/project --json dependency-report.json
```

- Checks Python `name==version` pins (including extras and hash annotations),
  plus exact npm versions in dependencies, devDependencies and optionalDependencies.
  Python environment markers are not evaluated: every supported declared pin is
  checked, even if its marker would exclude it on the current machine.
- When given a directory, prefers `package-lock.json` over `package.json` and
  prints the selected input files. Explicit file arguments are honored even when
  a sibling lockfile exists. A malformed lockfile fails rather than silently
  falling back to a manifest. Lockfile v1 is unsupported.
- Lockfile scans include pinned direct and transitive registry packages, including
  nested/scoped packages and recorded dev/optional packages. The project root is
  excluded. Recorded real names are used for aliases when available. Git/local
  dependencies, workspace links, and entries without usable names or versions
  are listed as skipped. OS/platform applicability is not evaluated. Lockfiles
  describe a dependency snapshot; the script does not verify freshness against
  package.json or check the actual installed tree.
- Lists unsupported entries as skipped. It does not guess versions for ranges
  such as `>=1.0` or `^1.2.3`, resolve tags/aliases, follow requirements includes,
  or install dependencies. Peer requirements and workspaces are flagged for
  follow-up when scanning package.json; pass each workspace's manifest explicitly.
  Python pins and standalone package.json scans cover declared dependencies only.
- Queries unique ecosystem/name/version combinations in batches and follows OSV
  pagination. Multiple advisory records can describe the same underlying issue.
  Links provide details; the script does not calculate severity or choose upgrades.
- Sends package names and versions to OSV, including private package names if
  declared with supported pins. It does not send entire manifests or index URLs.
- Exit **0**: all supported declarations checked with no matching advisories;
  **1**: advisories found; **2**: skipped entries, invalid input, network/API errors,
  or report-write failure. Exit 2 takes precedence over discovered advisories.
  An empty manifest has zero packages to check; no matching advisory is not proof
  that a dependency is safe.

The combined version keeps lockfile support and the short advisory summary from
the supplied `osv_check.py`, plus exact-version validation, pagination, cross-file
deduplication, skip reporting, and JSON from the first version. It deliberately
does not strip `^` or `~` to treat a range's lower bound as an installed version.
Lockfile handling follows the [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

Run the dependency tests (temporary manifests and mocked OSV, no live API calls):

```sh
python3 -m unittest -v tests.test_dependency_quickcheck
```
