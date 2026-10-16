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

Snyk Code, Container, IaC, license findings and external SARIF property files are
not supported by this profile. Gzip and UTF-8 BOM input are accepted. The existing
Cloud evidence limits still apply: oversized or invalid records are excluded, not
truncated. Review the preview's exclusions before proceeding.

Tests use synthetic vendor-shaped fixtures, including repeated imports, changed
evidence, duplicate identities, 500 findings and malformed inputs. These tests do
not establish live Snyk tenant or deployed Cloud compatibility.

## Endor Labs

Use the same command with `--provider endor`. Input may be an Endor Finding object,
an array, an unmasked `ListFindingsResponse` with `list.objects`, or endorctl SARIF
2.1.0. Choose a stable namespace/project/context source key and the matching Cloud
repository. JSON/SARIF detection is automatic; no additional flags or defaults change.

Identity uses the native finding UUID, including SARIF's `properties.finding-uuid`.
The mapper follows the public [Finding model](https://github.com/endorlabs/endorlabs-sdk/blob/8a41756890c2dee3bb089fee881cae4f2adbde03/src/endorlabs/generated/models/finding_service.py)
and [endorctl SARIF sample](https://github.com/endorlabs/endor-azure-pipelines-task/blob/2333a2f4548c2a1012a7e5219fa836627a466e0f/task/scan_results.sarif).
Masked records lacking identity or project fields are excluded.

JSON preserves the finding's severity and update timestamp. SARIF does not reliably
carry Endor's finding severity: diagnostic levels and CVSS remain original evidence,
and displayed severity stays unknown. Recommended versions, reachability, dismissals,
snoozes and other source assertions are retained without becoming Cloud assessments.
Synthetic SARIF line numbers are not promoted to verified code locations.

Imports replace the complete source snapshot for an existing UUID. Preview before
switching between JSON and SARIF, since the two exports contain different evidence.
Synthetic QA covers both formats and 500-record exports; live tenant verification
is separate.

Endor list responses with a continuation cursor or token are rejected. Finish fetching the export or provide an explicitly selected array; a single unfinished page is not a complete import. Fractional timestamps are rounded down to Cloud epoch seconds while their original precision remains in source evidence.
