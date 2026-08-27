# Container releases

The `container-release` workflow calls the same release pipeline for two images:

| Docker target                  | GHCR image                               |
| ------------------------------ | ---------------------------------------- |
| `scanner` (the default target) | `ghcr.io/openai/codex-security`          |
| `findings-service`             | `ghcr.io/openai/codex-security-findings` |

Both images use the version in `sdk/typescript/package.json`. Each has native
Linux `amd64` and `arm64` builds, BuildKit SBOMs and maximum-mode provenance,
and a GitHub build-provenance attestation for the verified multiarchitecture
digest. Stable version tags are never overwritten. `sha-<commit>` and `latest`
are published alongside the version tag only after verification and attestation.

See the [findings service guide](../sdk/typescript/README.md#findings-service-preview)
for configuration, storage, backups, upgrades, and the source-build option.

## One-time GHCR administrator setup

The workflow deliberately refuses to create a missing package or publish to a
private package. Before the first release, an organization/package administrator
must prepare **both** packages above; configuring the scanner package does not
grant access to the findings package.

1. Allow package creation under the organization policy and bootstrap any missing
   package with a reviewed image from this public repository. Use a non-release
   tag such as `bootstrap`, never a stable version or `latest`. For the findings
   package, from an approved source checkout:

   ```bash
   docker build --target findings-service \
     -t ghcr.io/openai/codex-security-findings:bootstrap .
   printf '%s' "$CR_PAT" | docker login ghcr.io \
     --username YOUR_GITHUB_USER --password-stdin
   docker push ghcr.io/openai/codex-security-findings:bootstrap
   docker logout ghcr.io
   ```

   Replace the username and supply an administrator's personal access token
   (classic) with `write:packages`, authorized for organization SSO if required.
   Do not commit the token or put it in build arguments. For a missing scanner
   package, use target `scanner` and image `ghcr.io/openai/codex-security:bootstrap`.

2. In each package's **Package settings**, link it to `openai/codex-security` and
   set visibility to **Public**. Public repository visibility alone does not
   make an existing container package public. Review the bootstrap contents
   before making them public.
3. In each package's **Manage Actions access**, grant `openai/codex-security`
   **Write** access (or confirm inherited repository access provides it). The
   release workflow uses `GITHUB_TOKEN`, not the administrator's token. Confirm
   organization Actions policy permits the pinned actions, package writes, and
   OIDC/build attestations used by the workflow.
4. Configure the repository's `container` environment with required release
   reviewers and deployment rules allowing protected `main` and approved
   `container-v*` tags. Protect `main` and restrict who can create release tags.
   If branch protection requires named container-release checks, update those
   requirements to the scanner and findings matrix check names.
5. With no registry credentials, verify each bootstrap image can be pulled:

   ```bash
   docker logout ghcr.io
   docker pull ghcr.io/openai/codex-security-findings:bootstrap
   ```

GitHub documents [container authentication and repository linking](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and [package visibility and Actions access](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

## Publish and verify

After merging to `main`, push an approved `container-v<version>` tag whose version
matches the SDK package, or run `container-release` manually on `main`. Manual
runs on other branches, mismatched versions, commits outside `main`, private or
unreadable packages, and already-published versions fail before publication.
Pull requests only build and test; they do not authorize or publish images.

Each image is released independently, with separate build caches and digest
artifacts. A missing findings package does not prevent a scanner release.
If one image succeeds and the other fails, rerun only failed jobs after fixing
the cause; rerunning a completed release is rejected by the immutable-version
check. Do not remove or overwrite a stable tag to work around a failure.

Each native digest and the multiarchitecture candidate must pass anonymous
pulls and runtime tests before attestation and stable-tag promotion. The stable
tag is then checked for anonymous pulls and agreement with the attested digest.
`bootstrap` and `release-candidate-<commit>` tags are not consumer releases.

To verify a published image's provenance, replace `<version>` below:

```bash
gh attestation verify oci://ghcr.io/openai/codex-security-findings:<version> \
  --repo openai/codex-security
```

Use `docker buildx imagetools inspect <image>:<version>` to inspect the published
platforms and digest. Pin that digest in deployments that must not follow tag
updates.
