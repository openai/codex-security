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

   To bootstrap a missing findings package through GitHub Actions instead, run:

   ```bash
   gh workflow run container-bootstrap-findings.yml --repo openai/codex-security --ref main
   ```

   This manual workflow uses `GITHUB_TOKEN`, retains the `container` environment's
   approval rules, and pushes only `codex-security-findings:bootstrap` for Linux
   `amd64`. Complete the package settings below before running the release
   workflow; the bootstrap image is not a consumer release.

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

## Workflow runner

`compose.runner.yaml` runs the packaged CLI from the **scanner** image. It does
not start a findings service or implement another workflow engine. It passes
commands, output, and exit codes through the existing scanner entrypoint.
The shared Dockerfile and the two image releases above are unchanged.

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

For unattended use, provide `OPENAI_API_KEY` or `CODEX_API_KEY` instead of login.
Git authentication uses the existing `GH_TOKEN`/`GITHUB_TOKEN` and optional
`CODEX_SECURITY_GIT_HOST` settings. Pass only the credentials the runner needs;
the findings service's embedding credentials are configured separately.
Use a version or digest in `CODEX_SECURITY_IMAGE` for repeatable deployments.
To test an unreleased checkout, build the same scanner target locally instead
of pulling:

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
or preserve its original paths. Never share the runner's workbench database or
Codex home with the findings service's `/state` volume.

### Connecting to the findings service

For an independently hosted service, pass its reachable base URL through the
existing `--findings-url` flag. Container loopback addresses refer to the runner,
not the Docker host or another container. The findings API has no authentication;
use a private network or an authenticated TLS proxy appropriate to the deployment.
Do not expose the unauthenticated API publicly.

For a service on the same Docker engine, start it as a separate Compose project:

```bash
docker compose -p findings -f compose.findings.yaml up -d
```

Save this network-only override as `compose.runner.local.yaml`:

```yaml
networks:
  default:
    external: true
    name: findings_default
```

Then run the runner as a different project on that existing network. The service
is reachable by its Compose DNS name even though its published host port remains
loopback-only:

```bash
docker compose -p runner -f compose.runner.yaml -f compose.runner.local.yaml \
  run --rm codex-security dedupe --scan SCAN_ID \
  --findings-url http://findings:3000 --json
```

Use the scan ID from the completed scan and first import its findings into the
service with the matching repository ID, as described in the
[findings API guide](../sdk/typescript/README.md#findings-service-preview).
For a remote service, omit the network override and supply its URL instead.
Stopping or replacing the runner does not stop the service or remove its volume.

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
works because both examples use the `codex-security` service name. The entrypoint's
bulk-scan-specific Landlock selection remains unchanged; it is not applied to
other commands. Source inspection needs a host that supports the selected Codex
sandbox; do not disable sandboxing to work around host restrictions.

`run --rm` removes only the finished runner container. Preserve its host mounts
for later stages and retries; use the same image version and source paths.
Stop active runners before backing up the entire results and state directories,
and back up the findings service separately. No service ports or Docker socket
are exposed by the runner example.
