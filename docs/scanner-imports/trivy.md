# Import Trivy dependency findings

Import an existing Trivy schema-v2 JSON report for one checkout. Use a report saved by CI or produced in an isolated scanner job with only approved inputs and no credentials. Both plain JSON and gzip are supported. The import requires no Trivy installation, vulnerability database, or Aqua account.

## Preview and import

Set `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`. Preview the report against the checkout it describes.

```sh
checkout=/absolute/path/to/project
codex-security publish findings /path/to/reports/trivy.json --to local --repository "$checkout" \
  --provider trivy --trivy-scan-root . --source-key example/project/main --dry-run --format json
```

The importer infers `.` when a remote repository target matches its Git metadata, including literal spaces or Unicode escaped in an HTTP path. Repository and filesystem findings retain the original `ArtifactName` as evidence. A filesystem name is a display label. A repository target with a mixed-case HTTP scheme needs corroborating Git metadata to identify its transport. For other scans without a corroborated remote, set `--trivy-scan-root` to the scanned directory relative to the Git root. Use `.` for the whole checkout or `apps/web` for a subtree on any platform. In this argument, a backslash is a path separator on Windows and a literal filename character on POSIX.

Use repository targets without embedded HTTP credentials, including when omitting the HTTPS scheme. If a relative checkout name looks like an authenticated target, scan from inside the checkout or use its absolute path. For an SCP remote with `@` in its first path component, include the SSH account, for example `git@host:group@version/project`, or use an explicit SSH URL for the same repository.

Trivy can remove the SSH account from `Metadata.RepoURL`, leaving `ssh://host/path`. Even on older reports, an account in `ArtifactName` cannot recover it because a checkout can supply that label through `etc/hostname`. For either an uncorroborated mixed-case HTTP target or a missing SSH account, Cloud and local checkouts with a comparable Git remote require a regenerated report. For a plain directory or a checkout without a network remote, verify the source independently and supply an explicit scan root. Check the remote that supplied `Metadata.RepoURL`. Trivy v0.76.1 checks `upstream` before `origin`. Preserve the effective account, host, port and path when configuring it. In SCP syntax, `user@host:/srv/repo.git` selects an absolute path and `user@host:srv/repo.git` selects a home-relative path. A nondefault port needs a verified SSH configuration or a verified HTTPS remote. Regenerate the report from that checkout.

A saved Git origin such as `r:org/repo.git` can name either a Windows drive-relative path or a one-letter SSH server. Supply the scan root if this is the only origin. For a one-letter SSH server, include the verified SSH account, for example `user@r:org/repo.git`. Trivy preserves this spelling in the report.

Use a stable source key per project and branch across commits and scans. Check the source, destination, package locations, and exclusions in the preview. Repeat without `--dry-run` to confirm. Read the stored evidence with `codex-security findings imported "$checkout" --format json`.

For Cloud, replace `--to local --repository "$checkout"` with `--to cloud --repository URL_OR_ID`. You need access to the destination and a Cloud deployment that accepts the `trivy` provider. The importer compares the report’s Git remote with the destination when both are available. On unknown Git hosts, use the same remote spelling because distinct SSH users or paths can select different repositories. In a local checkout, an Enterprise web URL cannot resolve a custom SSH host alias. The importer rejects conflicting repository URLs. If either side lacks a comparable remote, verify the report’s origin before confirming.

## Evidence and repeat imports

The importer accepts language-package vulnerabilities in repository and filesystem reports. It rejects image, Kubernetes/Operator, and SARIF reports. In mixed reports, it lists unsupported sections such as OS packages, secrets, misconfigurations, and licenses as exclusions.

Empty and fully excluded SDK results retain the native Trivy header in `report`. To assert the source of a normalized batch, supply its native header in `report` and retain the repository in each finding’s `source_data.report` or `details.repository.url`. Select the `trivy` provider when importing those rows, including when supplying a custom finding ID.

Each finding retains the original vulnerability, advisory, package, reported versions and severity. The original `FixedVersion` field preserves the vendor’s exact expression. The ecosystem comes from the package URL when present and otherwise from the Trivy analyzer. The importer preserves the manifest and declaration lines when available. Trivy can report the checkout’s HEAD while scanning uncommitted files. The reported commit stays in `source_data.report.Metadata.Commit`, and `code_revision` remains unknown.

The importer uses Trivy’s v0.36.0 path convention. It treats `/` as a directory separator and preserves backslashes as literal filename characters. If an older Windows report uses backslashes as separators, regenerate it from the same checkout and scan root with Trivy v0.36.0 or later before importing. [Trivy v0.36.0 filesystem walker](https://github.com/aquasecurity/trivy/blob/4813cf5cfdaf22d3caf8ca2a2cc89448a5ef994f/pkg/fanal/walker/fs.go#L32-L37)

Trivy can report the same package path for a JAR inside a WAR file and a JAR inside an unpacked directory named `site.war`. The importer retains the ambiguous path in the original evidence and occurrence identity and omits it from file locations.

With the same source key and identifying paths, a change in version, severity, commit, or declaration line updates the existing occurrence. Replaying identical evidence leaves it unchanged. A different manifest or package path, including a versioned JAR filename, identifies a new occurrence. If several records have the same identity, the importer excludes all of them.

If an earlier development build left a Cloud upload pending, verify its destination and finish it with that build before switching. Earlier builds can produce different finding IDs or evidence from the same file. If either changed, the current build cannot identify the old pending request from that file.

A Trivy status of `fixed` means an upstream fix is available. Imported evidence starts as `not_assessed`. Omitting an occurrence from a later report leaves its earlier record open.
