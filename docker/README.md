# Container releases

`container-release` publishes `ghcr.io/openai/codex-security` from the default
`scanner` Docker target. The image runs the scanner CLI; saved-scan
deduplication uses the runner's local SQLite database directly.

Releases use the SDK package version, native Linux `amd64`/`arm64` builds,
BuildKit SBOMs and maximum-mode provenance, and a GitHub provenance attestation.
Each native image passes scanner checks before
publishing the multiarchitecture manifest. Anonymous
pulls and attestation must succeed before promoting version, `sha-<commit>`, and
`latest` tags. Stable version tags cannot be overwritten.

## Image metadata and verification

Release images include OCI metadata in each platform's image labels and in the
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
gh attestation verify "oci://$reference" --repo openai/codex-security
docker pull "$reference"
```

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

If a release fails, fix the cause and rerun only failed jobs. Promotion retries
require the existing stable version to reference the verified digest. If a newer
stable version exists, promotion leaves `latest` untouched; otherwise a retry
also requires `latest` to reference that digest. `bootstrap` and
`release-candidate-<commit>` tags are not consumer releases.

## Workflow runner

`compose.runner.yaml` runs the packaged CLI from the **scanner** image. It does
not start a findings service or implement another workflow engine. It passes
commands, output, and exit codes through the existing scanner entrypoint.

Run these commands from the repository root. After the selected scanner release
is available, prepare private directories and choose the host user's UID/GID so
the runner can write its bind mounts:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:latest
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

The existing `CODEX_SECURITY_RESULTS` and `CODEX_SECURITY_STATE` settings select
the host directories (default `./results` and `./state`):

| Container path                  | Durable contents                                    |
| ------------------------------- | --------------------------------------------------- |
| `/output`                       | Scan artifacts and any source checkouts stored here |
| `/output/.codex-security-state` | CLI scan history and workbench database             |
| `/state`                        | Codex sign-in and configuration                     |

Keep all three across runner replacements. Keep the approved source checkout
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

`run --rm` removes only the finished runner container. Preserve its host mounts
for later stages and retries; use the same image version and source paths.
Stop active runners before backing up the entire results and state directories,
and keep backups separately. No service ports or Docker socket are exposed by
the runner example.
