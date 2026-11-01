# Import GitHub Dependabot findings

Import Dependabot alerts from one GitHub repository. An alert identifies a
dependency occurrence in a manifest. Its advisory describes the vulnerability.

## Quick start

Authenticate the GitHub CLI with a fine-grained token or GitHub App installation
that has read access to Dependabot alerts for the repository. From the destination
checkout root, replace `github.com` and `OWNER/REPO` in the export and source key.

```bash
out=$(mktemp -d) && (
  set -eu
  umask 077
  gh api --hostname github.com --method GET --paginate \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    --jq 'if type == "array" then tojson else error("expected an alert page") end' \
    'repos/OWNER/REPO/dependabot/alerts?per_page=100' > "$out/pages.tmp"
  test -s "$out/pages.tmp"
  mv "$out/pages.tmp" "$out/dependabot.jsonl"
)
```

After the export succeeds, preview the saved file in the same shell.

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/dependabot.jsonl" \
  --to local --repository . --provider github \
  --source-key github.com/OWNER/REPO/dependabot --dry-run --format json
```

The export contains one JSON array per line, including `[]` for an empty page.
It follows every page and includes open, fixed, dismissed, and auto-dismissed
alerts. The importer reads the saved file offline.

## Import and verify

Check the destination, ready records, and exclusions. The alert repository
must match a configured network remote when one is available. For a checkout
with only filesystem remotes or no remote, verify the export belongs to it.
Rerun only the `publish findings` command without `--dry-run` to import the
reviewed `$out/dependabot.jsonl` file. Then read the local evidence.

```sh
codex-security findings imported . --format json
```

For Cloud, replace `--to local --repository .` with
`--to cloud --repository CLOUD_REPOSITORY_ID` and preview again before confirming.
To investigate a local alert, use the
[`$resolve-dependency-alert` skill](../../plugins/codex-security/skills/resolve-dependency-alert/SKILL.md)
with the saved alert and checkout.

## Reference

Reuse the source key for repeat exports from the same repository. The host,
repository, and alert number identify an occurrence, so two alerts for one GHSA
keep separate histories. Reimport updates included alerts and leaves omitted
alerts in place.

Each finding records the matched package, ecosystem, manifest path, vulnerable
version range, first patched version when available, and advisory IDs. The
native alert retains GitHub’s state and timestamps. An alert does not establish
the installed version, an affected line, or a Codex assessment. The importer
requires repository-relative manifest paths and rejects conflicts between
alert identities, affected packages, or ranges.

GitHub code scanning and published security advisories have separate import
formats. See the [scanner import guide](schema-guide.md), the
[Dependabot alerts endpoint](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository),
and [GitHub CLI pagination](https://cli.github.com/manual/gh_api).
