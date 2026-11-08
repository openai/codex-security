# Import GitHub Dependabot findings

Import native Dependabot alerts from one repository. Each alert identifies a
dependency occurrence. Its advisory describes the vulnerability.

## Quick start

In the matching checkout, choose a private report path outside the repository.
Use the same source key for repeat imports from this host, repository and alert
family.

```sh
report=/private/path/dependabot.jsonl
source_key=github.com/OWNER/REPO/dependabot
```

**Saved report.** If you already have the complete REST alert objects,
[preview the report](#preview-the-report).

<a id="export-repository-alerts"></a>

### Export from GitHub

Use either an existing GitHub connection in Codex or an authorized REST client.
Fetch all selected pages from the same repository and keep full REST alert
objects, including `html_url`, `security_advisory` and `security_vulnerability`.
Save each page as one compact JSON array per line. An empty page is `[]`.
Only use the final file after every page succeeds.

**In Codex**, replace the host, repository and private output path in this request.

> Export the native Dependabot alerts for https://HOST/OWNER/REPO across all
> states and classifications. Follow the scoped GitHub read procedure in the
> Codex Security triage-finding skill. Save each page as one compact JSON
> array per line in a private temporary file beside /private/path/dependabot.jsonl.
> Rename it to that path once you've verified and saved every page.

Check that the connection returned complete REST objects and all selected pages.
[Scoped GitHub read procedure](../../plugins/codex-security/skills/triage-finding/references/github-rest-intake.md#github-finding-retrieval).

**With a REST client**, use a credential with Dependabot alerts read access.
Request `GET /repos/OWNER/REPO/dependabot/alerts?per_page=100` on the selected
host's API. Omit `state` and `classification` for all alerts the deployment
exposes. Note any unknown malware coverage. Reject redirects and rebuild each
page request on the same API origin and repository endpoint with the original
filters. [Dependabot alerts endpoint](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository).

### Preview the report

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider github --source-key "$source_key" --dry-run --format json
```

### Save and verify

Check the alert numbers, packages and manifest paths. The repository must
match a configured network remote when available. If the checkout has only
filesystem remotes or no remote, verify the export belongs to it. Then
[save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

The host, repository and alert number identify a dependency occurrence. Two
alerts for the same GHSA keep separate histories. Repeat imports update the
alerts you include and keep the ones you omit.

Each finding records the matched package, ecosystem, manifest path, affected
version range, advisory IDs and first patched version when available. The URL
opens the repository alert. Severity comes from the matched package vulnerability,
which can differ from the advisory’s overall severity. The native alert retains
GitHub’s state and timestamps. The reader requires
repository-relative manifest paths and rejects conflicting alert identities,
packages or ranges.

Use the saved alert and checkout to check the installed version and trace
whether the vulnerable code is used. An alert alone supplies no affected line
or Codex assessment. [Resolve a dependency alert](../../plugins/codex-security/skills/resolve-dependency-alert/SKILL.md)
