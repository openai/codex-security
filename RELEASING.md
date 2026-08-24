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
