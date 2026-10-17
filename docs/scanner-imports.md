# Import scanner findings

`codex-security publish findings` can import a selected Snyk Open Source SARIF
2.1.0 report into a configured Cloud repository:

```sh
codex-security publish findings selected.sarif --to cloud \
  --provider snyk --repository <cloud-repository-id> \
  --source-key <organization/project/branch> --dry-run
```

Remove `--dry-run` to review and confirm the upload. The existing `--yes` option
allows noninteractive publication. Defaults and the Wiz/GitHub formats are
unchanged. This command imports saved evidence; it does not run Snyk, fetch links,
or start a Cloud assessment.

Use a stable source key for one Snyk organization, project and branch. Do not
combine different projects that have the same manifest path. Identity uses the
Snyk advisory ID and the literal manifest URI set within that namespace; a moved
manifest is a new identity. Timestamped automation IDs and run indexes are retained
as provenance but never used as identity. All records with a duplicate identity
are excluded, with their positions shown in the preview.

The mapper follows the public [Snyk Open Source SARIF formatter](https://github.com/snyk/cli/blob/main/src/lib/formatters/open-source-sarif-output.ts).
It keeps the original result, rule, dependency paths and report metadata. Severity
comes from Snyk's severity label, preserving critical versus high. Unrecognized
labels remain unknown. Suggested upgrades and synthetic line numbers remain in
the original evidence; they are not presented as verified fixes or source lines.
Absolute paths and traversal paths also stay in the original evidence without
being mapped to repository locations.

Reported version-control repository URLs must match the selected Cloud repository
before a new upload is prepared. Existing immutable requests continue to use their
saved repository IDs when resuming, including after a repository rename.

Snyk Code, Container, IaC, license findings and external SARIF property files are
not supported by this profile. Indexed or base-relative artifact references are
excluded because this formatter profile uses direct manifest URIs. Gzip and UTF-8
BOM input are accepted. The existing
Cloud evidence limits still apply: oversized or invalid records are excluded, not
truncated. Review the preview's exclusions before proceeding.

Tests use synthetic vendor-shaped fixtures, including repeated imports, changed
evidence, duplicate identities, 500 findings and malformed inputs. These tests do
not establish live Snyk tenant or deployed Cloud compatibility.
