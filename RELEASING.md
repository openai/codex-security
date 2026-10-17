# Releasing Codex Security

[GitHub Releases](https://github.com/openai/codex-security/releases) is the
canonical changelog. Under the current process, each new release combines a
short, reviewed summary with a categorized list of merged pull requests.
Historical releases may contain generated notes only. The release tag and npm
package use the same stable version: `npm-vX.Y.Z` and
`@openai/codex-security@X.Y.Z`. Releases whose source includes the GitHub Action
also publish `action-vX.Y.Z`, which installs that exact CLI version. The Action's
manifest and SBOM accompany the npm archive on the same GitHub Release.

## Pull request titles and categories

Pull request titles must follow this form:

```text
<type>[optional scope][!]: <description>
```

Use a lowercase type beginning with a letter and containing only letters,
digits, and hyphens. Use a lowercase scope when present. Start the description
with a non-whitespace character and do not leave trailing whitespace. Examples:

```text
feat(cli): add component scan planning
fix(windows): preserve Unicode paths
docs: explain scan cost limits
feat(sdk)!: remove the legacy result field
```

The title controls the generated release category:

| Title                               | Release category |
| ----------------------------------- | ---------------- |
| Any type with `!`                   | Breaking changes |
| `feat`                              | Features         |
| `fix`                               | Fixes            |
| `docs`                              | Documentation    |
| `chore(release)`, `release`, `test` | Excluded         |
| Any other type                      | Other changes    |

Use `chore(release)` for release preparation and `test` for test-only changes.
The legacy `release` type remains supported. Use these only for changes that
do not affect package users. A maintainer can apply `skip-release-notes` to
exclude another internal change. That manual label takes precedence over the
title category.

## Dependency updates

Dependabot checks npm packages, Python test dependencies, and GitHub Actions
daily, including weekends. OpenAI dependencies have no release cooldown; other
releases must be at least seven days old. Security updates do not wait for the
version-update cooldown.
Updates still require review and passing CI; nothing is merged automatically.

Keep `@openai/codex` and `@openai/codex-sdk` on the same exact version across the
TypeScript SDK, MCP app, and triage evals in `evals/triage-finding`. Dependabot
groups their updates across all three projects, and the SDK tests reject
mismatched pins or multiple locked SDK versions. The evals override Promptfoo's
transitive Codex SDK to the direct SDK dependency so it follows the same update.

Each pnpm project applies the same seven-day age policy to newly resolved
dependencies, including transitive packages, with `openai` and `@openai/*` exempt.
Committed lockfiles remain installable. The existing Socket release checks remain
in place.

The production dependency audit is a blocking step in CI package builds and npm
release validation. `pnpm --dir sdk/typescript run audit:prod` checks the locked
production graph at the existing high-severity threshold. High or critical
advisories and audit service failures stop publication. Resolve dependency
advisories with dependency and lockfile updates; retry service failures once
the audit service is available.

## Version policy before 1.0

While the package is on `0.x`, ordinary changes, including features, use a
patch release. Breaking changes use a minor release and reset the patch to
zero. For example, changes after `0.1.23` propose `0.1.24`, or `0.2.0` if any
included change is breaking. The category of a feature remains **Features**;
the category does not imply a minor version bump.

The release PR updater recognizes breaking changes from a `!` in a
Conventional Commit title, a `BREAKING CHANGE:` or `BREAKING-CHANGE:` footer,
or the `breaking-change` label. `skip-release-notes` affects visibility, not
version impact. All merges and direct commits after the release boundary
count toward the next version, including documentation and internal changes.
Review this policy before enabling automation for `1.x`.

## Rolling release PRs

`node-release-pr` runs after pushes to `main` and can be dispatched manually.
It defaults to a read-only preview. It does not merge, tag, publish, or change
the existing publication gates.

The updater opens one ready-for-review proposal on `release/next-<base-version>`
once a change reaches `main` after the current package version. It recomputes
the proposal's version from all changes since that package version first
reached `main`. Squash-merge release PRs, as required by this
repository's enabled merge method, so the whole proposal lands as one
release boundary commit. Generated PR titles and commit subjects use
`chore(release): X.Y.Z`, matching the proposed package version. Confirm the
squash commit subject uses the current PR title when merging. A later breaking
change updates the version and title on the same PR. Each update incorporates
the latest `main` and appends a commit; the updater never force-pushes.
A concurrent commit causes it to reread and
retry. It requests Codex review when the proposal files change. Updates that
only incorporate `main` keep CI current without repeating the same proposal
review. New suggestions for human-owned notes still appear in a comment.
Before merging the proposal, check CI and request a final Codex review
if the last review targets an older head.

The proposal updates the SDK version and the Action version in
`github-action/package.json` and `github-action/package-lock.json` together.
The Action's runtime dependency and lockfile keep their previously published
CLI version until npm publishes the proposed version. Release packaging then
updates that pin and lockfile to the verified publication. This lets release
PRs run CI while the next npm version is still unavailable; `node-ci` also
tests the Action against the packed CLI candidate before publication.

If a run reports that GitHub has not exposed the updated PR head, manually
rerun the updater with **dry_run** disabled after the PR catches up. This
allows any deferred review request or note suggestions to be posted. Verify
review on the current head before merging the proposal.

When the release version merges, the updater waits for another change to
reach `main` before opening the next proposal. An empty release cycle returns
`action: "unchanged"` without creating a branch or PR. Publication of the
previous version still has to complete and pass the verification steps below.

The updater leaves another open `chore(release):` or legacy `release:` PR
targeting `main`, including a manually prepared release, untouched and does not
open a duplicate. Finish or close that PR before enabling the new flow.
Closing an automated proposal
pauses its cycle; reopen it to resume. Retargeting it away from `main` also
pauses updates; restore its `main` base before resuming. Both ready proposals
and existing drafts receive updates. Existing drafts can be marked ready
without pausing the updater. Review the current head before merging if
`main` has advanced. The updater rechecks pause conditions before advancing
the branch. Changes to other files on the release branch, or to package
fields other than the version, also pause the
updater so those edits cannot be lost. These intentional pauses return
`action: "held"` and leave the workflow successful. Preserve or merge the
additional changes, then rerun the updater to resume.

### Editing the release notes

The committed `.github/release-notes.md` is authoritative. The updater
drafts highlights from merged titles and lists marked breaking changes for
migration review; it does not infer migration instructions from source code.
Review and refine these suggestions before releasing.

- Edit the highlights or upgrade notes on the release PR branch. Keep the
  surrounding `release-section` comments if you want to retain section
  boundaries. The bot refreshes a section only while it matches the last
  generated draft. An edit or deletion makes that section human-owned, and
  later updates preserve it. Custom prose outside the sections is preserved.
- Later suggestions appear in a new bot comment on the same PR. They do not
  replace human-owned notes. The bot updates the version header and PR title
  but never rewrites the PR description. Review version-specific links in
  human-owned prose when the proposed version changes.
- `.github/release-pr-state.json` records the cycle and section ownership.
  To explicitly regenerate a section, add `"reset": true` to that section's
  state entry. The next run consumes the reset and resumes automatic updates.
  Restore any damaged section markers before resetting. Do not delete the
  state file to reset ownership. A section with missing ownership metadata
  is preserved until explicitly reset; missing state does not authorize
  replacing manual notes.
- Deleting the notes file is preserved too. Restore reviewed notes, or
  explicitly reset the sections, before merging; publication requires the
  versioned notes file.

### Preview and enable

With an authenticated `gh` CLI, a local checkout can preview the plan with:

```bash
RELEASE_PR_DRY_RUN=true node sdk/typescript/scripts/release-pr.mjs
```

The preview may fetch missing Git objects locally, but performs no GitHub
writes. Its JSON output includes the proposed files and any reason the
updater would pause. After the workflow is on `main`, use its **Run workflow**
form with **dry_run** enabled to test the hosted read-only path.

To test writes, enable **Allow GitHub Actions to create and approve pull requests**
under the repository's **Settings → Actions → General → Workflow permissions**,
then manually dispatch the workflow with **dry_run** disabled. This permits a
single write run while automatic updates remain disabled. The workflow uses
the repository's `GITHUB_TOKEN` with **Contents: write** and **Pull requests: write**
by default; no separate App credentials are required. Preview runs use a separate
job with read-only permissions for both scopes.

Review the resulting PR and select **Approve workflows to run** in its merge
box to start hosted CI. GitHub requires this approval for PRs created or updated
with `GITHUB_TOKEN`. Check the Codex review on the current head as well, and
request it manually if the automated request has not started a review.

For CI to start without this approval, optionally configure a GitHub App
installed on this repository with **Contents: write** and **Pull requests: write**.
Set the `RELEASE_APP_CLIENT_ID` repository variable and `RELEASE_APP_PRIVATE_KEY`
secret. When the Client ID is configured, write runs request an App token scoped
to this repository; a missing or invalid private key fails the run. Previews
always use `GITHUB_TOKEN`. See [GitHub's token documentation](https://docs.github.com/en/actions/concepts/security/github_token).

After the manual write run is verified, set the `RELEASE_PR_ENABLED`
repository variable to `true` to allow updates after pushes to `main`.
Remove it or set it to `false` to return push-triggered runs to previews.
Manual runs always honor their **dry_run** input, which defaults to a preview;
disabling automatic updates does not prevent an explicit manual write run.
Generated PRs leave the disclosure attestations unchecked for maintainer review.

## Prepare a release

1. Choose the next stable version and update `sdk/typescript/package.json`,
   `github-action/package.json`, and both root version fields in
   `github-action/package-lock.json`. The rolling release PR normally prepares
   these changes. Keep the Action runtime pin on the previously published CLI;
   release packaging updates it after npm publication.
2. Update `.github/release-notes.md`. Its first line must be
   `<!-- release-version: X.Y.Z -->` with the exact package version.
3. Summarize the changes a user will notice. Call out required migration or
   compatibility work, link relevant public documentation, and leave the
   pull-request inventory to the generated section.
4. Open a pull request with a strict Conventional Commit title such as
   `chore(release): 0.2.0`.
5. Run the checks required by the changed files and record the results in the
   pull request. Do not merge until required CI, review, and public disclosure
   checks pass on the current commit.

Review the summary with the same standard as product documentation. Keep it
specific, describe behavior before implementation, and do not include private
repositories, systems, people, findings, links, or issue identifiers.

## Publish

The release starts after the version bump reaches `main` and `node-ci` succeeds
for that exact commit:

1. `node-release-cut` verifies that the version increased, checks the reviewed
   summary, and creates the exact `npm-vX.Y.Z` tag.
2. `node-release` installs the committed dependency graph, tests and packs the
   package, publishes it to npm, and records npm provenance.
3. `node-github-release` verifies the public package, provenance, tag, and
   archive before publishing the GitHub release. It prepends the reviewed
   summary to GitHub's categorized notes.
4. The same workflow runs `published-install-smoke` against the exact published
   version on Linux, macOS, and Windows. It uses the current release automation
   so the checks also work for historical backfills.
5. If the release source contains `action.yml`, the workflow prepares the
   Action from that exact source commit, pins its runtime to the verified npm
   version and integrity, and fetches the locked runtime through Socket Firewall
   with an empty cache before executing it. The lock retains public npm URLs.
   It builds and tests the distribution in a job with read-only repository
   permissions. A fresh publisher checks out the same
   source, downloads only the tested runtime lock by artifact ID, and rebuilds
   and verifies the bundles without executing the CLI. It creates
   `action-vX.Y.Z` and uploads the Action release manifest and SBOM to the
   existing `npm-vX.Y.Z` GitHub Release. A final status job reports publication,
   installation smoke, and Action results.

The Action tag points to a generated distribution commit whose parent is the
CLI release commit. That additional commit contains the runnable Action bundle
and runtime lockfile. Its release manifest records both commits, both tags,
the aligned version, and the npm integrity. Metadata finalization verifies the
bundle hashes against the files being published. Consumers can pin the Action's
distribution commit from that manifest.

Historical releases whose source predates `action.yml` skip Action publication
and still run the exact-version installation checks. The workflow does not add
Action code from a later commit to an older CLI release.

After npm accepts a publication, its registry can take several minutes to expose
the version. GitHub publication waits up to ten minutes for that version to
become available before verifying its archive and signed provenance. Other
registry errors fail immediately.

`node-release` generates the npm plugin payload from the canonical source under
`plugins/codex-security/` during `prepack`. The generated
`sdk/typescript/_bundled_plugin/` directory is not a committed release input;
do not prepare a release by editing or committing files there.

Monitor all three workflows and the final status in `node-github-release`.
A release is complete when npm and GitHub publication, exact-version install
checks, and applicable Action publication have succeeded. The protected npm
publication gates and immutable `npm-vX.Y.Z` tag remain in place.

Container publication currently has its own workflow and approval. It uses
`container-vX.Y.Z` or a manual `container-release` run on `main`, with the version
matching the SDK package. It is not part of the coordinated npm and Action
completion status. See [Container releases](docker/README.md) for its
publication and verification steps.

## Verify

Check the published state before announcing the release:

- `npm-vX.Y.Z` points to the merged release commit.
- `npm view @openai/codex-security@X.Y.Z` reports the expected version and
  commit, and the provenance check passed in `node-release`.
- The GitHub release is stable, has the correct title, and contains one verified
  npm package archive plus the Action manifest and SBOM when applicable.
- The exact-version published installation checks succeeded.
- For releases with the Action, `action-vX.Y.Z` points to the distribution
  commit recorded in its manifest, whose parent is the CLI release commit.
  The manifest and runtime lock identify the same CLI version and npm integrity.
- The newest version is marked Latest. A historical backfill is not.
- For releases created under this process, the reviewed highlights, category
  headings, documentation links, and full comparison link are correct.
  Historical releases may have generated notes only.
- Every merged pull request is included or has an intentional
  `skip-release-notes` label.

The `published-install-smoke` workflow checks each exact version during release
publication. It also checks npm's current `latest` daily and on pull requests
changing its smoke checks. Manual dispatch accepts a **version** (default
`latest`) and an optional **ref** for the source of the smoke checks. It installs
into a temporary consumer, verifies the requested version, checks the npm CLI
shim and public SDK, starts the bundled Codex executable with `--version`,
and initializes the bundled MCP server. Linux covers supported Node majors
22, 24, and 26; macOS and Windows cover Node 24. These checks use temporary
configuration directories and do not run scans or call model APIs.

The smoke test verifies the installed package independently of the version on
`main`, so it can run while the checkout contains unreleased changes. A failure
reports the installed version or failing startup command in the Actions log;
inspect that job before treating it as a release regression. To reproduce
locally, run `node sdk/typescript/scripts/smoke-published-package.mjs X.Y.Z`
from the repository. Omit the version to check `latest`.

## Recover or repair a release

Do not retarget a release tag or publish a second package under the same
version. The workflows are designed to recover from partial publication while
keeping the original tag and package identity.

To retry GitHub publication, run `node-github-release` from `main` with the
existing `npm-vX.Y.Z` tag. Supply the successful `node-release` run ID when
automatic lookup is not enough. The workflow verifies the npm artifact and
provenance again before it creates or updates the release, repeats the
exact-version installation checks, and completes applicable Action publication.
If `action-vX.Y.Z` already exists, recovery checks its package manifests and
lockfiles against the reviewed source and CLI release identity before installing
dependencies or running package scripts. It then reuses that distribution commit.
Do not move that tag or regenerate the release from newer Action source.
A failure after npm publication can leave
the npm package or GitHub Release visible while later checks or Action
publication remain incomplete; use the final workflow status to identify the
remaining work.

To repair categories on an existing release, correct the merged pull request's
title or release label first, then rerun `node-github-release` for the tag. For
a release that predates `.github/release-notes.md`, start the existing release
body with this marker block. Keep a blank line between the end marker and the
generated notes:

```text
<!-- codex-security-release-summary:start -->
Reviewed summary
<!-- codex-security-release-summary:end -->

Generated notes
```

The workflow preserves that marked summary and replaces the generated section.
After any recovery or repair, repeat every verification step above and review
the final public release body.
