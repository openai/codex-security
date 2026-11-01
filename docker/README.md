# Container releases

Each scanner release publishes two images to `ghcr.io/openai/codex-security`
from the same verified npm tarball and runtime dependency lock. Both run the
scanner CLI and use the runner's local SQLite database for saved-scan deduplication.

| Tag                                       | Image                             | Platforms             |
| ----------------------------------------- | --------------------------------- | --------------------- |
| `X.Y.Z`, `sha-<scanner-commit>`, `latest` | Debian                            | Linux amd64 and arm64 |
| `X.Y.Z-wolfi-amd64`                       | Wolfi                             | Linux amd64           |
| `X.Y.Z-wolfi-amd64-rN`                    | Wolfi OS update for scanner X.Y.Z | Linux amd64           |

Version tags are immutable. Only the newest stable Debian release gets `latest`.

## Image metadata and verification

Debian release images include OCI metadata in each platform's image labels and in the
final multiarchitecture index: title, description, source, license, vendor,
version, source commit, build timestamp, release notes, and documentation pinned
to that commit. GHCR reads the multiarchitecture description from the index,
not from the Dockerfile labels alone.

The workflow generates metadata once for both architectures, verifies it on the
published candidate, then signs and promotes that exact digest. Metadata changes
require a new digest and a new release; existing stable versions are not updated.
The successful release run's summary includes the digest, supported platforms,
documentation links, and commands to pull and verify the published image.

Replace `VERSION` with an available stable version. Resolve its index digest once
and use that reference for inspection, verification, and deployment:

```bash
image=ghcr.io/openai/codex-security
version=VERSION
digest="$(docker buildx imagetools inspect "$image:$version" --format '{{.Manifest.Digest}}')"
reference="$image@$digest"

docker buildx imagetools inspect "$reference" --raw | jq '.annotations'
gh attestation verify "oci://$reference" --repo openai/codex-security \
  --cert-identity 'https://github.com/openai/codex-security/.github/workflows/container-publish.yml@refs/heads/main' \
  --source-ref refs/heads/main
docker pull "$reference"
```

Older Debian releases were signed by `container-release.yml`. For those releases,
use that filename in the certificate identity. For an older image published from
a `container-vVERSION` tag, use `refs/tags/container-vVERSION` for both refs
and pass `--source-digest` with the release commit.

Set `CODEX_SECURITY_IMAGE` to the verified
`reference` when using Compose. The index selects the native `amd64` or `arm64`
image. Its `unknown/unknown` entries contain the per-platform SBOM and build
provenance; they are not runnable platforms and should not be removed.

All labels, annotations, SBOMs, and provenance are public. Keep private URLs,
scan data, and credentials out of them. BuildKit's maximum-mode provenance
includes build arguments, so pass build credentials through secret mounts rather
than build arguments.

## GHCR administrator setup

Before the first release, an administrator must prepare the package:

Prepare the [universal native payload](../plugins/codex-security/native/README.md#package-inputs) before building an image from source.

1. Allow organization package creation and, if the package is missing, bootstrap
   it with a reviewed image and a non-release tag:

   ```bash
   docker build --target scanner -t ghcr.io/openai/codex-security:bootstrap .
   printf '%s' "$CR_PAT" | docker login ghcr.io --username YOUR_GITHUB_USER --password-stdin
   docker push ghcr.io/openai/codex-security:bootstrap
   docker logout ghcr.io
   ```

   Use a personal access token (classic) with `write:packages`, authorized for SSO
   if required; never commit it or pass it into the build.

2. In the package's settings, link `openai/codex-security`, set visibility to
   **Public**, and grant the repository **Write** under **Manage Actions access**.
   The workflow uses `GITHUB_TOKEN` and refuses missing, private, or unreadable
   packages. Verify `docker pull` works after logging out of GHCR.
3. Configure the protected `npm` environment with release reviewers authorized
   for both npm and GHCR and limit it to `npm-v*` tags. For image backfills
   and standalone Wolfi OS updates, protect the `container` environment with
   required reviewers and deployment rules for `main` and approved `container-v*` tags.
   Allow the workflow's pinned actions, package writes, and OIDC attestations.
   Update branch-protection check names if they reference the old release jobs.

See GitHub's [registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and [package access settings](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

## Publishing

After verifying the published npm tarball and installation, `node-github-release`
publishes the matching Action. Its immutable `action-vX.Y.Z` tag preserves the
runtime lock for future backfills. The workflow passes the verified archive and
lock to `container-publish`. Debian builds on amd64 and arm64 and Wolfi builds
on amd64, both using recipes from the scanner release commit. Approving
**Publish npm and container images** in the `npm` environment authorizes both
images for that release. Publication uses the tested digests, verifies
anonymous pulls, and attests the images before promoting their version tags.
Debian carries BuildKit SBOMs and maximum-mode provenance. Wolfi carries build
provenance and an SPDX inventory of its OS packages, installed npm packages,
and native components.

To backfill a release, dispatch `node-github-release` on protected `main` with
the original `npm-vX.Y.Z` tag. A manual `container-release` run on `main`
requests the coordinated release for the current package version. Pushing a
`container-vX.Y.Z` tag runs the container workflow at the tagged commit.
The release source determines which images are required.
Sources from 0.5.0 onward with a Dockerfile but predating coordinated Wolfi
builds use the original Debian release path. Earlier releases skip image
publication. A default backfill uses the scanner release commit's recipes.
If the Wolfi build needs updated OS pins, dispatch `node-github-release` with
`refresh-wolfi-recipe=true` to use the recipe from protected `main` with the
original scanner tarball and runtime lock. Review and approve the `container`
deployment when publishing with a different recipe commit or recovering
images for a release whose approval covered only npm. A backfill that
verifies all existing tags finishes without a deployment approval.

Promotion updates tags separately. If publication stops partway through, rerun
the failed jobs to reuse the retained artifacts. The publisher verifies existing
version tags and refuses to replace a different digest. The `release status`
summary lists both digests when the coordinated release finishes. For a Wolfi
OS update between scanner releases, see [Wolfi-only OS updates](wolfi/README.md#wolfi-only-os-updates).
The `bootstrap` and `release-candidate-<commit>` tags are for registry setup
and release validation.

## Workflow runner

`compose.runner.yaml` runs the packaged CLI from the **scanner** image. It does
not start a findings service or implement another workflow engine. It passes
commands, output, and exit codes through the existing scanner entrypoint.

Run these commands from the repository root after
[verifying an image](#image-metadata-and-verification). Keep the verified
`reference` in the same shell. Prepare the output and state directories, keep
state private, and choose the host user's UID/GID so the runner can write its
bind mounts:

```bash
mkdir -p results state
chmod 700 state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE="$reference"
docker compose -f compose.runner.yaml pull
docker compose -f compose.runner.yaml run --rm codex-security login --device-auth
```

The `login --device-auth` command above signs the runner in with ChatGPT and
requires device auth to be enabled in your workspace. If device auth is
disabled, skip that command and export `OPENAI_API_KEY` or `CODEX_API_KEY` in
your host shell. Compose passes the key to the runner. Use API keys for
unattended runs too.

Git authentication uses the existing `GH_TOKEN`/`GITHUB_TOKEN` and optional
`CODEX_SECURITY_GIT_HOST` settings. Pass only the credentials the runner needs.
Use a version or digest in `CODEX_SECURITY_IMAGE` for repeatable deployments.
To test an unreleased checkout, build the same scanner target locally instead
of pulling. First prepare the [universal native payload](../plugins/codex-security/native/README.md#package-inputs):

```bash
docker build --target scanner -t codex-security:local .
export CODEX_SECURITY_IMAGE=codex-security:local
```

To build the Linux amd64 Wolfi image locally, see the
[melange and apko recipe](wolfi/README.md).

The existing `CODEX_SECURITY_RESULTS` and `CODEX_SECURITY_STATE` settings select
the host directories (default `./results` and `./state`):

| Container path                             | Durable contents                                              |
| ------------------------------------------ | ------------------------------------------------------------- |
| `/output`                                  | Scan artifacts and any source checkouts stored here           |
| `/output/.codex-security-state`            | CLI scan history and workbench database                       |
| `/output/.codex-security-state/codex-home` | Wrapper sign-in credentials and private runtime configuration |
| `/state`                                   | Ambient Codex configuration and credentials imported at setup |

Keep both host mounts across runner replacements. The results mount also holds
the wrapper's private credential directory. Keep the approved source checkout
available at the same container path for later source reviews. For example,
place a checkout under `results/repository`, then scan it with artifacts outside
the checkout:

```bash
docker compose -f compose.runner.yaml run --rm codex-security \
  scan /output/repository --output-dir /output/scans/run-001 --headless
```

An existing checkout elsewhere can instead be bind-mounted with
`run --volume /absolute/repository:/input/repository`; repeat that mount on each
stage that needs the source. Moving a host scan's files into these directories
does not rewrite absolute paths in its saved state. Run the scan in the runner
or preserve its original paths.

### Deduplication and custom endpoints

Deduplicate a saved scan against the runner's persisted local SQLite database:

```bash
docker compose -f compose.runner.yaml run --rm codex-security \
  dedupe --scan SCAN_ID --json
```

For an independently operated compatible endpoint, pass its reachable base URL
through `--findings-url`. Container loopback addresses refer to the runner, not
the Docker host or another container. See the
[findings guide](../sdk/typescript/docs/findings-service.md) for custom publication,
remote deduplication, and the removed local service's compatibility changes.

Only commands supported by the selected image are available. Workflow resumption,
custom publication, and dedupe write-back require a release containing those
SDK/CLI capabilities; durable mounts alone do not add them. The runner does not
schedule, retry, or skip stages on its own.

### Sandbox and lifecycle

The runner retains the scanner's nonroot user, dropped capabilities,
no-new-privileges, and seccomp profile. It does not override Codex approval or
filesystem settings. On hosts that restrict nested user namespaces, install the
existing [AppArmor profile](../sdk/typescript/README.md#containerized-bulk-scans)
and append `-f compose.apparmor.yaml` to the runner Compose commands. This override
works because both examples use the `codex-security` service name. Codex 0.156.1
requires Bubblewrap for filesystem-restricted execution; the legacy Landlock
fallback is no longer supported. The entrypoint preserves Codex sandbox settings.
Source inspection needs a host that supports Bubblewrap; do not disable sandboxing
to work around host restrictions.

The bundled seccomp profile allows direct Linux socket creation for Unix sockets,
IPv4, IPv6, and the route netlink protocol Bubblewrap uses to configure loopback.
The profile blocks IPv4’s legacy `SOCK_PACKET` type, which opens a packet socket.
Direct socket pairs are limited to Unix sockets. On amd64, 32-bit x86 programs
can use the direct socket syscalls. The legacy i386 `socketcall` multiplexor
returns `ENOSYS`, so programs that depend on it lose those socket operations.
Use a network policy to restrict outbound destinations. The profile also denies
`ptrace`, `process_vm_readv`, and `process_vm_writev`.

`run --rm` removes only the finished runner container. Preserve its host mounts
for later stages and retries; use the same image version and source paths.
Stop active runners before backing up the entire results and state directories,
and keep backups separately. No service ports or Docker socket are exposed by
the runner example.
