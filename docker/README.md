# Container releases

`container-release` uses one release pipeline for both images:

| Docker target       | GHCR image                               |
| ------------------- | ---------------------------------------- |
| `scanner` (default) | `ghcr.io/openai/codex-security`          |
| `findings-service`  | `ghcr.io/openai/codex-security-findings` |

Both use the SDK package version, native Linux `amd64`/`arm64` builds, BuildKit
SBOMs and maximum-mode provenance, and a GitHub provenance attestation. Native
images are tested before publishing the multiarchitecture manifest. Anonymous
pulls and attestation must succeed before promoting version, `sha-<commit>`, and
`latest` tags. Stable version tags cannot be overwritten.

## GHCR administrator setup

Before the first release, an administrator must prepare each package:

1. Allow organization package creation and bootstrap missing packages with a
   reviewed image and a non-release tag. For the findings image:

   ```bash
   docker build --target findings-service -t ghcr.io/openai/codex-security-findings:bootstrap .
   printf '%s' "$CR_PAT" | docker login ghcr.io --username YOUR_GITHUB_USER --password-stdin
   docker push ghcr.io/openai/codex-security-findings:bootstrap
   docker logout ghcr.io
   ```

   Use a personal access token (classic) with `write:packages`, authorized for SSO
   if required; never commit it or pass it into the build. For the scanner, use
   target `scanner` and image `ghcr.io/openai/codex-security:bootstrap`.

2. In each package's settings, link `openai/codex-security`, set visibility to
   **Public**, and grant the repository **Write** under **Manage Actions access**.
   The workflow uses `GITHUB_TOKEN` and refuses missing, private, or unreadable
   packages. Verify `docker pull` works after logging out of GHCR.
3. Protect the repository's `container` environment with required reviewers and
   deployment rules for protected `main` and approved `container-v*` tags.
   Allow the workflow's pinned actions, package writes, and OIDC attestations.
   Update branch-protection check names if they reference the old release jobs.

See GitHub's [registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and [package access settings](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

## Publishing

After merging to `main`, push `container-v<version>` matching the SDK package
version or run `container-release` manually on `main`. Releases require a commit
on protected `main`; pull requests only build and test.

The images release independently. If one fails, fix the cause and rerun only
failed jobs; do not overwrite an existing stable version. `bootstrap` and
`release-candidate-<commit>` tags are not consumer releases.

See the [findings service guide](../sdk/typescript/README.md#findings-service-preview)
for image selection, source builds, storage, backups, and upgrades.
