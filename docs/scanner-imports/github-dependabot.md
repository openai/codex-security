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

Authenticate the GitHub CLI with a fine-grained token or GitHub App installation
that has read access to Dependabot alerts for the repository. Replace `github.com`
and `OWNER/REPO` with the alert host and repository.

```bash
out=$(mktemp -d) && (
  set -eu
  umask 077
  gh api --hostname github.com --method GET --paginate \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    --jq 'if type == "array" then tojson else error("expected an alert page") end' \
    'repos/OWNER/REPO/dependabot/alerts?per_page=100' > "$out/pages.tmp" &&
    test -s "$out/pages.tmp" &&
    mv "$out/pages.tmp" "$out/dependabot.jsonl"
)
```

The export contains one JSON array per line, including `[]` for an empty page.
It follows every page and includes open, fixed, dismissed, and auto-dismissed
alerts. The saved file is `$out/dependabot.jsonl`. See the
[Dependabot alerts endpoint](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)
and [GitHub CLI pagination](https://cli.github.com/manual/gh_api).
