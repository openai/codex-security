# Import GitHub Security Advisories

Use the JSON array from `codex-security import github-advisories` to import
repository disclosures or selected GitHub global advisories. Each advisory
lists the packages and version ranges it affects.

## Quick start

[Enable external imports](README.md#preview-a-report). From the destination
checkout, set the repository and source key. For GitHub Enterprise, export
`GH_HOST` with your hostname first. For a repeat import, use the exact
advisories key from your previous preview, including case.

```sh
repo=OWNER/REPO
source_key="${GH_HOST:-github.com}/$repo/security-advisories"
```

**Saved report.** Set `report=/private/path/advisories.json` if you already
have the collector's complete JSON array.

**Export from GitHub.** Sign in to the selected host with `gh auth login`.
Choose a repository or global export. Use a private temporary directory
outside the checkout. Omit output filters, token limits and `--full-output`
so the reader gets the complete array.

For published repository advisories, run the command below. To list another
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

For global advisories, supply at least one GHSA ID. The repository argument
names the repository where you'll investigate the advisory.

```sh
report=
out=$(mktemp -d) &&
  codex-security import github-advisories "$repo" --github-advisory-source global \
    --github-advisory GHSA-2345-6789-cfgh --format json > "$out/advisories.json" &&
  report="$out/advisories.json"
```

**Preview the report.**

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider github --source-key "$source_key" --dry-run --format json
```

Check the GHSA IDs and whether each advisory came from the repository or the
global database. Repository disclosures must match a comparable local Git
remote when available, or the selected Cloud repository. If the preview
matches, [save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Identity and evidence

Repository and global advisories have distinct finding IDs, even when they
share a GHSA ID and source key. A global advisory has no source repository.
Compare the affected package ranges with the versions installed in your
checkout to decide whether the advisory applies.

To collect with the SDK instead of `gh`, pass `githubHost` and a `githubToken`
for that host. [Advisory SDK examples](../../sdk/typescript/docs/cli.md#import-ghsa-advisories-separately)
