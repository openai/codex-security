# Import GitHub Dependabot findings

Import Dependabot alerts from one GitHub repository. An alert identifies a
dependency occurrence in a manifest. Its advisory describes the vulnerability.

## Quick start

[Enable external imports](README.md#preview-a-report) and
[export the repository alerts](#export-repository-alerts). From the matching
checkout root, replace the file path, hostname, and repository in this preview.

```sh
codex-security publish findings /private/path/dependabot.jsonl \
  --to local --repository . --provider github \
  --source-key github.com/OWNER/REPO/dependabot --dry-run --format json
```

## Import and verify

The alert repository must match a configured network remote when one is
available. For a checkout with only filesystem remotes or no remote, verify
the export belongs to it. [Save or publish and verify](README.md#save-or-publish-and-verify)
using the same source key for later exports from this repository.

## Reference

### Identity and evidence

The host, repository, and alert number identify an occurrence, so two alerts
for one GHSA keep separate histories. Reimport updates included alerts and
leaves omitted alerts in place.

Each finding records the matched package, ecosystem, manifest path, vulnerable
version range, first patched version when available, and advisory IDs. The
native alert retains GitHub’s state and timestamps. An alert does not establish
the installed version, an affected line, or a Codex assessment. The importer
requires repository-relative manifest paths and rejects conflicts between
alert identities, affected packages, or ranges.

To investigate a local alert, use the
[`$resolve-dependency-alert` skill](../../plugins/codex-security/skills/resolve-dependency-alert/SKILL.md)
with the saved alert and checkout. GitHub [code scanning](github-code-scanning.md)
and [security advisories](github-security-advisories.md) have separate guides.

### Export repository alerts

In Codex, replace the host, repository and private output path in this request:

> Export all native Dependabot alerts for https://HOST/OWNER/REPO to
> /private/path/dependabot.jsonl, across all states and classifications.

Follow the [scoped GitHub read procedure](../../plugins/codex-security/skills/triage-finding/references/github-rest-intake.md#github-finding-retrieval)
for the selected transport and identity. Ask before changing either. A connected
app must return complete native records and confirm it enumerated every matching
page. For HTTPS, use a credential with Dependabot alerts read access to request
`GET /repos/OWNER/REPO/dependabot/alerts?per_page=100` on the selected host's API. Omit `state` and `classification` to export every alert
the deployment exposes. Note any unknown malware coverage. For HTTPS,
reject redirects and rebuild each next page on the same API origin and repository
endpoint with the requested filters. [Dependabot alerts endpoint](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)

Keep every field. Write each successful page as one compact JSON array per line,
including `[]` for an empty page. Write to a private temporary file in the
destination directory outside the checkout, then rename it to the requested
output path only after all pages have been verified and saved.
