# Import GitHub Security Advisories

Import repository disclosures or selected entries from GitHub's global advisory
database. Use the affected packages and version ranges to investigate whether
a dependency in your checkout is affected.

## Quick start

Sign in with `gh auth login`. For GitHub Enterprise, set `GH_HOST` to the host
you signed in to. From the destination checkout root, set `repo` to its GitHub
repository and `source_key` to your existing advisories key exactly, including
case. For a first import, choose a key for the host, repository and finding
family. Replace `/path/to/private/reports` with an existing private directory
outside the checkout. Collect published advisories as a complete JSON array
without field or token filters or `--full-output`, then preview the saved file.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
repo=OWNER/REPO
source_key=github.com/example/project/security-advisories
out=$(mktemp -d "/path/to/private/reports/github.XXXXXX") &&
  codex-security import github-advisories "$repo" --format json > "$out/advisories.json" &&
  codex-security publish findings "$out/advisories.json" \
    --to local --repository . --provider github \
    --source-key "$source_key" --dry-run --format json
```

## Import and verify

Check the advisory IDs and source in the preview. For repository advisories, the
source must match a comparable local Git remote when available or the selected
Cloud repository. Use a source key separate from code scanning and Dependabot
when you [save or publish and verify](README.md#save-or-publish-and-verify).

## Reference

- **Repository advisories.** Repeat `--github-advisory GHSA-xxxx-xxxx-xxxx` to select exact
  IDs. To list an unpublished state instead, pass `--github-state draft`,
  `triage`, or `closed`. Private advisories require repository advisory read
  permission and access to the disclosures.
- **Global advisories.** Add `--github-advisory-source global` and at least one
  `--github-advisory GHSA-xxxx-xxxx-xxxx` to the collector. The repository argument selects
  the context for investigation. A global record has no source repository.
- An advisory retains the GHSA ID, reported packages and affected version
  ranges. Check the installed versions in your repository separately. For
  programmatic imports, see the [advisory SDK examples](../../sdk/typescript/docs/cli.md#import-ghsa-advisories-separately).

To collect a specific global advisory, use the same shell and replace the
example ID. Preview `"$out/global-advisories.json"` with the same command and
advisories source key. Each finding’s ID already distinguishes global and
repository scope.

```sh
codex-security import github-advisories "$repo" \
  --github-advisory-source global --github-advisory GHSA-2345-6789-cfgh \
  --format json > "$out/global-advisories.json"
```
