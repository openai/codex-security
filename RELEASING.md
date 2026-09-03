# Releasing Codex Security

[GitHub Releases](https://github.com/openai/codex-security/releases) is the
canonical changelog. Under the current process, each new release combines a
short, reviewed summary with a categorized list of merged pull requests.
Historical releases may contain generated notes only. The release tag and npm
package use the same stable version: `npm-vX.Y.Z` and
`@openai/codex-security@X.Y.Z`.

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

| Title             | Release category |
| ----------------- | ---------------- |
| Any type with `!` | Breaking changes |
| `feat`            | Features         |
| `fix`             | Fixes            |
| `docs`            | Documentation    |
| `release`, `test` | Excluded         |
| Any other type    | Other changes    |

Use `release` and `test` only for changes that do not affect package users. A
maintainer can apply `skip-release-notes` to exclude another internal change.
That manual label takes precedence over the title category.

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

The updater keeps one draft proposal on `release/next-<base-version>` and
recomputes its version from all changes since the current package version
first reached `main`. Squash-merge release PRs, as required by this
repository's enabled merge method, so the whole proposal lands as one
release boundary commit. A later breaking change changes the version on the
same PR. Each update incorporates the latest `main` and appends a commit;
the updater never force-pushes. A concurrent commit causes it to reread and
retry. It requests Codex review when the proposal files change. Updates that
only incorporate `main` keep CI current without repeating the same proposal
review. New suggestions for human-owned notes still appear in a comment.
Before marking the proposal ready, check CI and request a final Codex review
if the last review targets an older head.

If a run reports that GitHub has not exposed the updated PR head, manually
rerun the updater with **dry_run** disabled after the PR catches up. This
allows any deferred review request or note suggestions to be posted. Verify
review on the current head before marking the proposal ready.

When the release version merges, the next draft can open immediately, even
while publication is still running. Until another change reaches `main`,
that draft leaves the package version unchanged. Do not mark an empty draft
ready or merge it. Publication of the previous version still has to complete
and pass the verification steps below.

The updater leaves another open `release:` PR targeting `main`, including a
manually prepared release, untouched and does not open a duplicate. Finish
or close that PR before enabling the new flow. Closing an automated proposal
pauses its cycle; reopen it to resume. Retargeting it away from `main` also
pauses updates; restore its `main` base before resuming. Marking the proposal
ready pauses updates, preserving the reviewed version and notes. To resume,
convert it back to a draft and rerun the updater. Do this before merging if
`main` has advanced, then review the updated proposal. The updater rechecks
these conditions before advancing the branch. Changes to other files on the
release branch, or to package fields other than the version, also pause the
updater so those edits cannot be lost. These intentional pauses return
`action: "held"` and leave the workflow successful. Preserve or merge the
additional changes, then rerun the updater to resume.

### Editing the draft notes

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

To test writes, configure a GitHub App installed on this repository
with **Contents: write** and **Pull requests: write**, set the
`RELEASE_APP_CLIENT_ID` repository variable and `RELEASE_APP_PRIVATE_KEY`
secret, then manually dispatch the workflow with **dry_run** disabled.
This permits a single write run while automatic updates remain disabled.
Review the resulting draft, its hosted CI, and the Codex review request.
The workflow requests an App token scoped to this repository so CI on the
bot's PR does not need the approval required for PR events created by
`GITHUB_TOKEN`. See [GitHub's token documentation](https://docs.github.com/en/actions/concepts/security/github_token).

After the manual write run is verified, set the `RELEASE_PR_ENABLED`
repository variable to `true` to allow updates after pushes to `main`.
Remove it or set it to `false` to return push-triggered runs to previews.
Manual runs always honor their **dry_run** input, which defaults to a preview;
disabling automatic updates does not prevent an explicit manual write run.
Generated PRs leave the disclosure attestations unchecked for maintainer review.

## Prepare a release

1. Choose the next stable version and update `sdk/typescript/package.json`.
   Keep the lockfile version in sync when it records the package version.
2. Update `.github/release-notes.md`. Its first line must be
   `<!-- release-version: X.Y.Z -->` with the exact package version.
3. Summarize the changes a user will notice. Call out required migration or
   compatibility work, link relevant public documentation, and leave the
   pull-request inventory to the generated section.
4. Open a pull request with a strict Conventional Commit title such as
   `release: bump Codex Security to 0.2.0`.
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

`node-release` generates the npm plugin payload from the canonical source under
`plugins/codex-security/` during `prepack`. The generated
`sdk/typescript/_bundled_plugin/` directory is not a committed release input;
do not prepare a release by editing or committing files there.

Monitor all three workflows. A version bump is not a completed release until
the npm package and GitHub release both exist and match the tag.

## Verify

Check the published state before announcing the release:

- The tag points to the merged release commit.
- `npm view @openai/codex-security@X.Y.Z` reports the expected version and
  commit, and the provenance check passed in `node-release`.
- The GitHub release is stable, has the correct title, and contains exactly one
  verified package archive.
- The newest version is marked Latest. A historical backfill is not.
- For releases created under this process, the reviewed highlights, category
  headings, documentation links, and full comparison link are correct.
  Historical releases may have generated notes only.
- Every merged pull request is included or has an intentional
  `skip-release-notes` label.

## Recover or repair a release

Do not retarget a release tag or publish a second package under the same
version. The workflows are designed to recover from partial publication while
keeping the original tag and package identity.

To retry GitHub publication, run `node-github-release` from `main` with the
existing `npm-vX.Y.Z` tag. Supply the successful `node-release` run ID when
automatic lookup is not enough. The workflow verifies the npm artifact and
provenance again before it creates or updates the release.

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
