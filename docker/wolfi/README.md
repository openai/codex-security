# Wolfi scanner image

Each new scanner release includes a Linux amd64 Wolfi image.
[melange](https://github.com/chainguard-dev/melange) creates the scanner APK.
[apko](https://github.com/chainguard-dev/apko) assembles it
with packages from the [public Wolfi repository](https://github.com/wolfi-dev/os).
The image uses the same entrypoint, UID/GID 10001, and `/input`, `/output`, and
`/state` directories as the [Debian image](../README.md). The local build below
uses the scanner version pinned in [payload/package.json](payload/package.json).

## Build and inspect

Use a Linux amd64 builder with user namespaces and Bubblewrap, apko 1.4.13,
melange 0.61.1, Python 3.9 or later, Node.js with npm 11, OpenSSL,
and Docker for runtime testing. From the repository root:

```sh
docker/wolfi/build.sh /tmp/codex-security-wolfi
docker load --input /tmp/codex-security-wolfi/image.tar
docker run --rm --pull=never --network=none codex-security:wolfi-amd64 --version
```

Use a new output directory for each build. Alongside the Docker archive,
the builder writes the signed scanner APK and index, apko locks, SPDX SBOMs,
a [component inventory](verify-public.py), and a signed `SHA256SUMS`. To verify
the saved files later, use the public key retained from that build:

```sh
cd /tmp/codex-security-wolfi
openssl dgst -sha256 -verify melange.rsa.pub -signature SHA256SUMS.sig SHA256SUMS
sha256sum --check SHA256SUMS
```

Each run generates a local signing key, adds its public half to the APK keyring,
and removes the private key at exit. The key identifies that build; it is not
an upstream release signature. A new key changes the APK and image digests.

To test that the melange guest can be built without access to Wolfi, run a
build with the [offline melange wrapper](tests/offline-melange.sh) on a Linux
builder that permits `unshare --net`:

```sh
MELANGE="$PWD/docker/wolfi/tests/offline-melange.sh" docker/wolfi/build.sh /tmp/codex-security-offline-guest
```

The wrapper disconnects melange before it installs the guest packages. Staging
the inputs and resolving the runtime lock still need the network.

## Run the offline smoke test

On a native Linux amd64 Docker host with AppArmor and user namespaces, load
the built image and run the following from the repository root. If the
`codex-security-container` AppArmor profile is already loaded, omit the setup
and cleanup commands. Otherwise use a disposable test host:

```sh
sudo apparmor_parser --skip-cache --add docker/codex-security.apparmor
docker/wolfi/tests/smoke.sh codex-security:wolfi-amd64
sudo apparmor_parser --skip-cache --remove docker/codex-security.apparmor
```

The test uses the repository's seccomp profile with a read-only root filesystem,
no capabilities, and no external network. It exercises the CLI, the native plugin,
artifact and SARIF output, saved history, and a model turn against a loopback
fixture. It also checks that a sandboxed child can read the test repository but
cannot modify it. A real scan needs a compatible model endpoint; the image
does not include a model.

## Publish the amd64 variant

For a scanner release, `container-publish` supplies the same verified npm tarball
and runtime lock used for Debian. The scanner and Wolfi recipe both come from
`npm-vX.Y.Z`. One `npm` deployment approval authorizes the package and both
container images. The Wolfi publisher verifies an anonymous pull and attests
build provenance and the SPDX inventory before promoting
`ghcr.io/openai/codex-security:X.Y.Z-wolfi-amd64`. To recover a missing image
using refreshed OS pins, follow the [container backfill instructions](../README.md#publishing).

### Wolfi-only OS updates

Choose an existing `X.Y.Z-wolfi-amd64` release. Update the OS pins and increment
`image_revision` in [build-inputs.json](build-inputs.json) in the same PR. After
it merges, run the following on protected `main`, substituting the scanner version
for `X.Y.Z`.

```sh
gh workflow run publish-wolfi.yml --repo openai/codex-security --ref main -f release-version=X.Y.Z
```

The build verifies the original scanner tarball against its signed npm provenance.
It uses the base image's lock and staging recipe to reproduce the scanner payload
and verifies its digest before packaging it with the updated OS pins. Approve the
pending `container` deployment to publish `X.Y.Z-wolfi-amd64-rN` for the reviewed
revision `N`. New scanner versions begin with the unsuffixed tag.

To retry publication, rerun the failed jobs within the seven-day artifact
retention period. A fresh build generates a new APK signing key and a different
image digest.

## Inputs and updates

[builder.yaml](builder.yaml) and [apko.yaml](apko.yaml) list the exact builder
and runtime packages. [build-inputs.json](build-inputs.json) pins their resolved
lock identities and Wolfi's signing key. The build downloads the locked builder
APKs, verifies their bytes, and gives melange only a local, signed index of those
files. For a local build, [the recipe's npm lock](payload/package-lock.json) pins
the scanner and dependencies. Coordinated builds use the release runtime lock.
[stage.py](payload/stage.py) checks the target dependency graph, skips npm
lifecycle scripts, and stages the Linux scanner. [melange.yaml](melange.yaml)
checks the normalized tar hash before installing it. The APK omits the optional
voice runtime and plugin binaries for other platforms; it keeps the matching
Linux addon, Codex, code-mode host, Bubblewrap, ripgrep, and license notices.
In the image, `/usr/share/licenses/codex-security/SOURCES.json` records the
sources and hashes of the native files along with the npm dependency inventory.
The original npm lock is retained, including optional packages for other
platforms; the inventory lists only packages installed in the image.
Components keep their upstream licenses.

If the public Wolfi index moves past a pinned version, refresh the affected
package pins and review the resulting apko locks and component inventory before
updating the lock digests. Review native source and notice pins when scanner
dependencies change. Coordinated builds take the scanner version, source commit,
and integrity from the verified release. Run the native smoke test after
changing either the scanner payload or OS packages.
