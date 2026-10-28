# Import GitHub Dependabot repository alerts

A Dependabot alert identifies a vulnerable dependency in one repository. Its GHSA
describes the affected software. GitHub code scanning and published security
advisories have separate import formats.

## Export one repository

Use a fine-grained token or GitHub App installation with **Dependabot alerts: read**
for the repository. The GitHub CLI reads the alerts. Codex Security imports the
saved file offline. Keep the export outside the checkout.

```bash
set -eu
umask 077
out=$(mktemp -d)
gh api --hostname github.com --method GET --paginate \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  --jq 'if type == "array" then tojson else error("expected an alert page") end' \
  'repos/OWNER/REPO/dependabot/alerts?per_page=100' > "$out/pages.tmp"
test -s "$out/pages.tmp"
mv "$out/pages.tmp" "$out/dependabot.jsonl"
```

Replace the hostname and `OWNER/REPO` in both examples. The command follows every
page and includes open, fixed, dismissed, and auto-dismissed alerts. Each line
contains one page, including `[]` for an empty collection. If a request fails,
check repository access before retrying.

## Preview and import

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/dependabot.jsonl" \
  --to local --repository ./project --provider github \
  --source-key github.com/OWNER/REPO/dependabot --dry-run --format json
```

Review the destination, ready records, and exclusions, then remove `--dry-run`.
Use `--to cloud` with an authorized repository ID or URL for Cloud publication.
For a local checkout, the alert repository must match a configured network
remote when one is available. If the checkout has only filesystem remotes or
no remote, verify the export belongs to it before importing.

Keep the export and reuse its source key for the same repository. The host,
repository, and alert number identify an occurrence. Two alerts for the same
GHSA keep separate histories. A later selection updates the alerts it includes
and leaves omitted alerts in place.

Each finding records the matched package, ecosystem, manifest path, vulnerable
version range, first patched version when available, and advisory IDs. The
native alert retains GitHub’s state and timestamps. An alert identifies a
manifest dependency without establishing the installed version, an affected
line, or a Codex assessment. The importer rejects conflicts between alert
identities, affected packages, or ranges, and requires repository-relative
manifest paths.

Read local evidence with `codex-security findings imported ./project --format json`.
See the [GitHub Dependabot alerts endpoint](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)
and the [GitHub CLI pagination options](https://cli.github.com/manual/gh_api).
