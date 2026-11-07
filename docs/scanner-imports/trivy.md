# Import Trivy dependency findings

Use a saved Trivy schema-v2 JSON or gzip report from a repository or filesystem scan. The importer reads language-package vulnerabilities and lists excluded sections, including OS packages, secrets and misconfigurations. The reader works offline without installing Trivy.

## Preview the report

If you need a report,
run `trivy fs --scanners vuln --format json --output /private/path/trivy.json .`
from the checkout root. Use a private output directory outside the checkout.

Set `--trivy-scan-root` to the directory Trivy scanned, relative to the checkout.
Use `.` for the whole checkout or, for example, `apps/web` for a subtree.

```sh
codex-security publish findings /private/path/trivy.json --to local --repository /path/to/checkout \
  --provider trivy --trivy-scan-root . --source-key example/project/main --dry-run --format json
```

Check the repository, manifest paths, versions and exclusions in the preview. Keep the same source key across scans of the same project and branch. Cloud requires a deployment that accepts the `trivy` provider. [Save or publish and verify](README.md#save-or-publish-and-verify).

## Match the report to its checkout

A repository scan can omit `--trivy-scan-root` when its remote target and Git metadata corroborate a whole-checkout scan. A filesystem scan always needs the scan root. A filesystem artifact name is a display label. Trivy's Git metadata is the source of its repository claim. When the report or local checkout has no comparable remote, verify the source independently.

Use credential-free repository URLs. If the importer reports ambiguous or conflicting repository claims, compare `Metadata.RepoURL` with the checkout's Git remotes. Regenerate the report with a verified HTTPS URL or an unambiguous SSH remote, preserving its account, host, port and path. An artifact label cannot restore an SSH account that Trivy omitted. Unknown Git hosts may require the same remote spelling. If a Windows report uses backslashes as directory separators, regenerate it with Trivy v0.36.0 or later to get repository paths that use `/`.

## Read the evidence and repeat an import

- Each finding retains its native vulnerability, exact `FixedVersion` expression and, when available, the matched package and declaration lines. Ambiguous archive paths stay in the raw evidence.
- A package can appear many times in the same lockfile. Cloud projects the first 100 locations per finding. The full list of declaration ranges is in `source_data.package.Locations`.
- Trivy can scan uncommitted files. Its reported commit stays in `source_data.report.Metadata.Commit`. Imported findings start as `not_assessed`, including when Trivy reports an upstream fix.
- Changes to severity, installed version or declaration line update the same occurrence. A different manifest or package path identifies a separate occurrence. Duplicate identities are excluded as a group. Omitted findings stay open.
- With the SDK, use `readTrivyFindings` for a file or `normalizeTrivyFindings` for parsed JSON. When selecting rows from a repository-bound report, retain its native header and each row’s `source_data.report` or `details.repository.url`, and import with provider `trivy`. Empty and fully excluded reports also retain their native header.

If a private-inbox upload is interrupted and the connected repository is renamed, check the existing job before retrying. The new catalog URL can fail the original report’s source check.

When changing CLI versions with a Cloud upload pending, finish the upload with the version that created it. A change to finding IDs or evidence can prevent another version from recognizing the request.
