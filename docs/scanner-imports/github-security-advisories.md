# Import GitHub Security Advisories

Use the JSON array from `codex-security import github-advisories` to import
repository disclosures or selected GitHub global advisories. Each advisory
lists the packages and version ranges it affects.

## Quick start

In the destination checkout, set the repository and source key. For GitHub Enterprise, export
`GH_HOST` with your hostname first. For a repeat import, use the exact
advisories key from your previous preview, including case.

```sh
repo=OWNER/REPO
source_key="${GH_HOST:-github.com}/$repo/security-advisories"
```

**Saved report.** Set `report=/private/path/advisories.json` if you already
have the collector's complete JSON array. Continue with [Preview the report](#preview-the-report).

### Export from GitHub

Sign in to the selected host with `gh auth login`.
Choose [repository disclosures](#repository-disclosures) for advisories issued
by this repository or [global advisories](#global-advisories) to investigate
specified GHSA IDs in the checkout. Use a private temporary directory outside
the checkout. Omit output filters, token limits and `--full-output` to keep
the collector's complete array.

#### Repository disclosures

The collector lists published advisories by default. To list another
state, add `--github-state draft`, `triage` or `closed`. To select specific
IDs, repeat `--github-advisory GHSA-xxxx-xxxx-xxxx` and omit `--github-state`.
Private advisories require repository advisory read permission and access to
the disclosures.

```sh
report=
out=$(mktemp -d) &&
  codex-security import github-advisories "$repo" --format json > "$out/advisories.json" &&
  report="$out/advisories.json"
```

#### Global advisories

Supply at least one GHSA ID. The repository argument
names the repository where you'll investigate the advisory.

```sh
report=
out=$(mktemp -d) &&
  codex-security import github-advisories "$repo" --github-advisory-source global \
    --github-advisory GHSA-2345-6789-cfgh --format json > "$out/advisories.json" &&
  report="$out/advisories.json"
```

### Preview the report

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider github --source-key "$source_key" --dry-run --format json
```

### Save and verify

Check the GHSA IDs and whether each advisory came from the repository or the
global database. Repository disclosures must match a comparable local Git
remote when available, or the selected Cloud repository. If the preview
matches, [save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

Repository and global advisories have distinct finding IDs, even when they
share a GHSA ID and source key. The finding URL opens the selected disclosure.
A repository advisory links to that repository’s advisory page. A global advisory
links to the advisory database and has no source repository.
Compare the affected package ranges with the versions installed in your
checkout to decide whether the advisory applies.

If you can access a draft repository advisory, selecting its exact GHSA ID
can return it. A collection failure produces no partial selection.
[GitHub repository advisory permissions](https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories).

## Use the SDK

Collect the advisories with `importGitHubAdvisories()`. For Cloud,
pass `normalizeGitHubAdvisories(advisories, "cloud")` to
`prepareNormalizedExternalPublication()`. For local storage, pass
`normalizeGitHubAdvisories(advisories, "local")` to `prepareNormalizedLocalImport()`.
`importGitHubAdvisories()` defaults to `{ source: "repository", state: "published" }`; use
`{ source: "global", advisoryIds: ["GHSA-2345-6789-cfgh"] }` for selected database
records. Both forms require `repository: "OWNER/REPO"` as source or target context.
When normalized evidence retains a collector record in `source_data`, imports
check a repository disclosure's original repository against the destination.
Supply `githubHost` and `githubToken` to override the GitHub CLI login and host.
