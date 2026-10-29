import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";
import { runWorkflowScript } from "./support/workflow-script.js";

type Step = {
  name: string;
  uses?: string;
  run?: string;
  with?: Record<string, string | boolean>;
};
type Job = {
  needs?: string | string[];
  uses?: string;
  if?: string;
  environment?: string;
  permissions?: Record<string, string>;
  with?: Record<string, string>;
  steps?: Step[];
};
function workflow(name: string) {
  return Bun.YAML.parse(
    readFileSync(
      new URL(`../../../.github/workflows/${name}.yml`, import.meta.url),
      "utf8",
    ),
  ) as {
    concurrency?: {
      group: string;
      queue?: string;
    };
    jobs: Record<string, Job>;
  };
}
const release = workflow("container-publish");
const parent = workflow("node-github-release");
const directories = createTemporaryDirectoriesSync();
afterEach(directories.cleanup);

function fixture() {
  const directory = directories.create("container release ");
  const repository = join(directory, "source");
  mkdirSync(join(repository, "sdk/typescript"), { recursive: true });
  const output = join(directory, "output");
  function git(...args: string[]) {
    return execFileSync(
      "git",
      [
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release@example.invalid",
        "-c",
        "commit.gpgsign=false",
        ...args,
      ],
      { cwd: repository, encoding: "utf8", stdio: "pipe" },
    ).trim();
  }
  function commit(version: string) {
    writeFileSync(
      join(repository, "sdk/typescript/package.json"),
      JSON.stringify({ version }),
    );
    git("add", ".");
    git("commit", "-m", `Release ${version}`);
    return git("rev-parse", "HEAD");
  }
  git("init", "-b", "main");
  const source = commit("99.1.2");
  git("tag", "npm-v99.1.2");
  const automation = commit("99.2.0");
  git("remote", "add", "origin", repository);
  function run(env: Record<string, string> = {}, selected = release) {
    writeFileSync(output, "");
    const result = runWorkflowScript(
      repository,
      selected.jobs["source"]!.steps![1]!.run,
      {
        GITHUB_OUTPUT: output.replaceAll("\\", "/"),
        GITHUB_REPOSITORY_OWNER: "Example",
        GITHUB_SHA: automation,
        GITHUB_EVENT_NAME: "workflow_dispatch",
        GITHUB_REF: "refs/heads/main",
        GITHUB_REF_NAME: "main",
        RELEASE_SHA: source,
        RELEASE_VERSION: "99.1.2",
        ...env,
      },
    );
    return { ...result, output: readFileSync(output, "utf8") };
  }
  return { source, automation, git, commit, run, repository };
}

test("backfills the tagged release after main has advanced", () => {
  const { run } = fixture();
  const result = run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.output).toBe("image=ghcr.io/example/codex-security\n");
});

test("rejects a different commit with the same package version", () => {
  const source = fixture();
  const different = source.commit("99.1.2");
  const result = source.run({ RELEASE_SHA: different });
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("immutable npm release tag");
});

test("rejects source outside protected main", () => {
  const source = fixture();
  source.git("checkout", "-b", "unmerged", source.source);
  const unmerged = source.commit("99.3.0");
  source.git("tag", "npm-v99.3.0");
  source.git("checkout", "main");
  const result = source.run({
    RELEASE_SHA: unmerged,
    RELEASE_VERSION: "99.3.0",
  });
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("protected main branch");
});

test("rejects a release tag whose version differs from the package", () => {
  const source = fixture();
  source.git("tag", "npm-v99.3.0", source.source);
  const result = source.run({ RELEASE_VERSION: "99.3.0" });
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("must match the CLI package version");
});

test.each(["refs/heads/feature", "refs/tags/npm-v99.1.2"])(
  "rejects coordinated publication from %s",
  (ref) => {
    const result = fixture().run({ GITHUB_REF: ref });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("must run on main");
  },
);

test("routes new manual and tagged requests through the verified release coordinator", () => {
  const source = fixture();
  const wrapper = workflow("container-release");
  const released = source.commit("99.3.0");
  source.git("tag", "npm-v99.3.0");
  source.git("fetch", "origin", "main");
  const manual = source.run({ GITHUB_SHA: released }, wrapper);
  expect(manual.status, manual.stderr).toBe(0);
  expect(manual.output).toBe("version=99.3.0\n");
  const push = {
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF: "refs/tags/container-v99.3.0",
    GITHUB_SHA: released,
  };
  expect(source.run(push, wrapper).status).toBe(0);
  expect(
    source.run({ ...push, GITHUB_REF: "refs/tags/container-v99.3.1" }, wrapper)
      .status,
  ).not.toBe(0);
});

test("requires both verified artifacts for a scanner release with the Wolfi builder", () => {
  const source = fixture();
  mkdirSync(join(source.repository, ".github/workflows"), { recursive: true });
  writeFileSync(
    join(source.repository, ".github/workflows/wolfi-build.yml"),
    "",
  );
  const sha = source.commit("99.3.0");
  source.git("tag", "npm-v99.3.0");
  const inputs = {
    RELEASE_SHA: sha,
    RELEASE_VERSION: "99.3.0",
    GITHUB_SHA: sha,
    GITHUB_REF_PROTECTED: "true",
    TARBALL: "123",
    RUNTIME_LOCK: "456",
    CLI_INTEGRITY: "sha512-test",
  };
  expect(source.run(inputs).output).toContain("wolfi=true\n");
  for (const artifact of ["TARBALL", "RUNTIME_LOCK"]) {
    expect(source.run({ ...inputs, [artifact]: "" }).status).not.toBe(0);
  }
});

test("approves both tested container candidates in one deployment", () => {
  const container = parent.jobs["container"]!;
  expect(container.uses).toBe("./.github/workflows/container-publish.yml");
  expect(container.needs).toContain("action-verify");
  expect(container.needs).toContain("action");
  expect(container.with).toMatchObject({
    "release-sha": "${{ needs.release.outputs.sha }}",
    "release-version": "${{ needs.release.outputs.version }}",
    "release-integrity": "${{ needs.release.outputs.integrity }}",
    "release-tarball-artifact":
      "${{ needs.release.outputs.release-tarball-artifact }}",
    "runtime-lock-artifact":
      "${{ needs.action-verify.outputs.runtime-lock-artifact }}",
  });
  expect(parent.jobs["complete"]?.needs).toContain("container");

  expect(
    Object.keys(release.jobs).filter(
      (key) => release.jobs[key]!.environment === "container",
    ),
  ).toEqual(["authorize"]);
  for (const candidate of ["debian", "wolfi"]) {
    expect(release.jobs["authorize"]?.needs).toContain(candidate);
  }
  expect(release.jobs["manifest"]?.needs).toContain("authorize");
  const upload = release.jobs["manifest"]!.steps!.find(
    ({ name }) =>
      name === "Upload the approved index and verify its anonymous digest",
  )!.run!;
  expect(upload).toContain(
    "skopeo copy --all --src-no-creds --preserve-digests",
  );
  expect(upload).toContain(
    '"docker://$IMAGE@$DIGEST" "oci:$RUNNER_TEMP/public:scanner"',
  );

  expect(release.jobs["publish-wolfi"]?.needs).toContain("authorize");
  expect(release.jobs["promote"]?.needs).toContain("attest");
  expect(release.jobs["promote"]?.needs).toContain("publish-wolfi");
  expect(release.concurrency).toEqual({
    group: "container-release-publish",
    queue: "max",
  });
});

test("routes a Wolfi-only OS update through its own approval", () => {
  const publisher = workflow("publish-wolfi");
  const update = publisher.jobs["os-update"]!;
  expect(update.uses).toBe("./.github/workflows/wolfi-build.yml");
  expect(update.if).toContain("github.event_name == 'workflow_dispatch'");
  expect(update.if).toContain("github.ref_protected");
  expect(update.with).toMatchObject({
    "release-version": "${{ inputs.release-version }}",
    "os-update": true,
  });
  expect(publisher.jobs["authorize"]).toMatchObject({
    environment: "container",
    needs: "os-update",
  });
  const publish = publisher.jobs["publish"]!;
  expect(publish.if).toContain("needs.authorize.result == 'success'");
  expect(publish.if).toContain(
    "inputs.artifact != '' && github.workflow_ref == 'openai/codex-security/.github/workflows/node-github-release.yml@refs/heads/main'",
  );
});

test("passes the same verified npm tarball and runtime lock to both image builders", () => {
  const debian = release.jobs["validate"]!;
  const wolfi = release.jobs["wolfi"]!;
  for (const key of [
    "release-integrity",
    "release-tarball-artifact",
    "runtime-lock-artifact",
  ]) {
    expect(debian.with?.[key]).toBeTruthy();
    expect(wolfi.with?.[key]).toBe(debian.with?.[key]);
  }
  expect(debian.with?.["ref"]).toBe("${{ needs.source.outputs.sha }}");
  expect(wolfi.with?.["release-sha"]).toBe("${{ needs.source.outputs.sha }}");
});

test("keeps historical native payloads tied to the release checkout", () => {
  expect(release.jobs["native"]?.with?.["ref"]).toBe(
    "${{ needs.source.outputs.sha }}",
  );
  const native = workflow("native-artifacts");
  for (const platform of ["unix", "windows", "musl"]) {
    expect(native.jobs[platform]?.with?.["ref"]).toBe(
      "${{ inputs.ref || github.sha }}",
    );
    const steps = workflow(`native-${platform}`).jobs["primitives"]!.steps!;
    expect(steps[0]?.with?.["ref"]).toBe("${{ inputs.ref || github.sha }}");
    expect(steps.at(-1)?.with?.["name"]).toContain(
      "${{ inputs.ref || github.sha }}",
    );
  }
  expect(
    native.jobs["bundle"]!.steps!.find(
      (step) => step.name === "Download verified platform payloads",
    )?.with?.["pattern"],
  ).toBe("native-platform-*-${{ inputs.ref || github.sha }}");
  expect(
    native.jobs["bundle"]!.steps!.find(
      (step) => step.name === "Upload universal native payload",
    )?.with?.["name"],
  ).toBe("native-universal-${{ inputs.ref || github.sha }}");
});

const digest = `sha256:${"a".repeat(64)}`;
const arm64Digest = `sha256:${"c".repeat(64)}`;
test.each([
  ["historical Debian", false, "", true],
  ["missing Wolfi", true, "", false],
  ["published Wolfi", true, "99.1.2-wolfi-amd64", true],
  ["different Wolfi tag digest", true, "unexpected", false],
] as const)(
  "verifies the public digests before completing publication: %s",
  (_case, required, approvedWolfi, succeeds) => {
    const directory = directories.create("container completion ");
    const image = "ghcr.io/example/scanner";
    const version = "99.1.2";
    const tagDigest = (tag: string) =>
      `sha256:${createHash("sha256").update(`docker://${image}:${tag}`).digest("hex")}`;
    writeFileSync(join(directory, "skopeo"), `#!/bin/sh\nprintf '%s' "$4"\n`, {
      mode: 0o755,
    });
    if (process.platform === "darwin" && !Bun.which("sha256sum")) {
      writeFileSync(
        join(directory, "sha256sum"),
        '#!/bin/sh\nexec shasum -a 256 "$@"\n',
        { mode: 0o755 },
      );
    }
    const result = runWorkflowScript(
      directory,
      release.jobs["complete"]!.steps![0]!.run,
      {
        GITHUB_OUTPUT: join(directory, "output").replaceAll("\\", "/"),
        PATH: `${directory}${delimiter}${process.env["PATH"]}`,
        IMAGE: image,
        VERSION: version,
        SOURCE_OK: "success",
        DEBIAN: tagDigest(version),
        DEBIAN_OK: "true",
        WOLFI: approvedWolfi && tagDigest(approvedWolfi),
        WOLFI_OK: String(Boolean(approvedWolfi)),
        WOLFI_REQUIRED: String(required),
      },
    );
    expect(result.status === 0, result.stderr).toBe(succeeds);
  },
);

function existingFixture() {
  const directory = directories.create("container release ");
  const source = "1".repeat(40);
  const repository = join(directory, "source");
  const bin = join(directory, "bin");
  const events = join(directory, "events");
  const output = join(directory, "reuse-output");
  mkdirSync(bin);
  mkdirSync(join(repository, "docker"), { recursive: true });
  copyFileSync(
    new URL(
      "../../../docker/verify-container-release-version.sh",
      import.meta.url,
    ),
    join(repository, "docker/verify-container-release-version.sh"),
  );
  writeFileSync(
    join(bin, "gh"),
    `#!/bin/sh
case "$1" in
  api) printf '%s\\n' "$MOCK_VERSIONS"; exit "$MOCK_API_STATUS" ;;
  attestation)
    printf '%s\\n' "$*" >> "$EVENTS"
    shift 3
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --repo) [ "$2" = "example/project" ] || exit 1 ;;
        --cert-identity) [ "$2" = "https://github.com/example/project/.github/workflows/$MOCK_SIGNER.yml@$MOCK_SIGNER_REF" ] || exit 1 ;;
        --source-ref) [ "$2" = "$MOCK_SOURCE_REF" ] || exit 1 ;;
        --source-digest) [ "$2" = "$MOCK_SOURCE_SHA" ] || exit 1 ;;
        *) exit 99 ;;
      esac
      shift 2
    done
    exit "$MOCK_ATTESTATION_STATUS" ;;
  *) exit 99 ;;
esac
`,
    { mode: 0o755 },
  );
  writeFileSync(
    join(bin, "docker"),
    `#!/bin/sh
printf '%s\\n' "$*" >> "$EVENTS"
case "$1" in
  buildx) printf '%s\\n' "$MOCK_MANIFEST" ;;
  logout) exit 0 ;;
  pull)
    if [ "$3" = linux/arm64 ] && [ "$MOCK_ARM64_PULL_STATUS" != 0 ]; then exit "$MOCK_ARM64_PULL_STATUS"; fi
    exit "$MOCK_DOCKER_STATUS" ;;
  run) printf '%s\\n' "$MOCK_CLI_VERSION"; exit "$MOCK_DOCKER_STATUS" ;;
  *) exit 99 ;;
esac
`,
    { mode: 0o755 },
  );
  const manifest = {
    annotations: {
      "org.opencontainers.image.version": "99.1.2",
      "org.opencontainers.image.revision": source,
    },
    manifests: [
      {
        digest: `sha256:${"d".repeat(64)}`,
        platform: { os: "linux", architecture: "amd64" },
      },
      { digest: arm64Digest, platform: { os: "linux", architecture: "arm64" } },
    ],
  };
  const script = release.jobs["source"]!.steps!.find(
    (step) => step.name === "Verify an existing immutable container release",
  )!.run;
  function run(env: Record<string, string> = {}, command = script) {
    writeFileSync(events, "");
    writeFileSync(output, "");
    const result = runWorkflowScript(repository, command, {
      PATH: `${bin}${delimiter}${process.env["PATH"]}`,
      EVENTS: events.replaceAll("\\", "/"),
      GITHUB_OUTPUT: output.replaceAll("\\", "/"),
      GITHUB_REPOSITORY: "example/project",
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY_OWNER: "Example",
      IMAGE: "ghcr.io/example/codex-security",
      VERSION: "99.1.2",
      RELEASE_SHA: source,
      DIGEST: digest,
      HAS_WOLFI: "true",
      MOCK_SIGNER: "container-publish",
      MOCK_SIGNER_REF: "refs/heads/main",
      MOCK_SOURCE_REF: "refs/heads/main",
      MOCK_SOURCE_SHA: source,
      RUNNER_TEMP: directory.replaceAll("\\", "/"),
      MOCK_VERSIONS: JSON.stringify([
        {
          name: digest,
          metadata: {
            container: { tags: ["99.1.2", "latest", `sha-${source}`] },
          },
        },
      ]),
      MOCK_MANIFEST: JSON.stringify(manifest),
      MOCK_API_STATUS: "0",
      MOCK_ATTESTATION_STATUS: "0",
      MOCK_DOCKER_STATUS: "0",
      MOCK_ARM64_PULL_STATUS: "0",
      MOCK_CLI_VERSION: "99.1.2",
      ...env,
    });
    return {
      ...result,
      output: readFileSync(output, "utf8"),
      events: readFileSync(events, "utf8"),
    };
  }
  return { run, manifest, source };
}

test("verifies and reuses the published source without a registry write", () => {
  const { run } = existingFixture();
  const result = run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.output).toContain(`digest=${digest}\n`);
  expect(result.output).toContain("complete=true\n");
  expect(result.events.trim().split("\n")).toEqual([
    `buildx imagetools inspect ghcr.io/example/codex-security@${digest} --raw`,
    `attestation verify oci://ghcr.io/example/codex-security@${digest} --repo example/project --cert-identity https://github.com/example/project/.github/workflows/container-publish.yml@refs/heads/main --source-ref refs/heads/main`,
    "logout ghcr.io",
    `pull --platform linux/arm64 ghcr.io/example/codex-security@${arm64Digest}`,
    `pull --platform linux/amd64 ghcr.io/example/codex-security@${digest}`,
    `run --rm --platform linux/amd64 ghcr.io/example/codex-security@${digest} --version`,
  ]);
});

const historicalTag = "refs/tags/container-v99.1.2";
const historicalSigner = {
  HAS_WOLFI: "false",
  MOCK_SIGNER: "container-release",
};
const historicalTagSigner = {
  ...historicalSigner,
  MOCK_SIGNER_REF: historicalTag,
  MOCK_SOURCE_REF: historicalTag,
};
const signerCases: [string, Record<string, string>, boolean][] = [
  ["historical main", historicalSigner, true],
  ["historical release tag", historicalTagSigner, true],
  [
    "wrong historical source commit",
    { ...historicalTagSigner, MOCK_SOURCE_SHA: "2".repeat(40) },
    false,
  ],
  [
    "historical signer on a coordinated release",
    { ...historicalSigner, HAS_WOLFI: "true" },
    false,
  ],
  ["another repository workflow", { MOCK_SIGNER: "container-ci" }, false],
  [
    "unprotected signing branch",
    { MOCK_SIGNER_REF: "refs/heads/feature" },
    false,
  ],
  [
    "unprotected caller branch",
    { MOCK_SOURCE_REF: "refs/heads/feature" },
    false,
  ],
];

test.each(signerCases)(
  "checks recovered image attestation: %s",
  (_name, claims, allowed) => {
    const result = existingFixture().run(claims);
    expect(result.status === 0, result.stderr).toBe(allowed);
    expect(result.output.includes(`digest=${digest}`)).toBe(allowed);
  },
);

test("verifies newly signed images with the protected publisher", () => {
  const script = release.jobs["attest"]!.steps!.find(
    ({ name }) => name === "Verify the published provenance",
  )!.run!;
  const { run } = existingFixture();
  expect(run({}, script).status).toBe(0);
  const untrusted: Record<string, string>[] = [
    historicalSigner,
    { MOCK_SIGNER_REF: "refs/heads/feature" },
    { MOCK_SOURCE_REF: "refs/heads/feature" },
  ];
  for (const claims of untrusted) {
    expect(run(claims, script).status).not.toBe(0);
  }
});

test("stops recovery when the existing arm64 image cannot be pulled anonymously", () => {
  const result = existingFixture().run({ MOCK_ARM64_PULL_STATUS: "1" });
  expect(result.status).not.toBe(0);
  expect(result.output).toBe("");
  expect(result.events.trim().split("\n").at(-1)).toBe(
    `pull --platform linux/arm64 ghcr.io/example/codex-security@${arm64Digest}`,
  );
});

test("rejects an existing index when the scanner version differs from its label", () => {
  const result = existingFixture().run({ MOCK_CLI_VERSION: "99.1.1" });
  expect(result.status).not.toBe(0);
  expect(result.output).not.toContain("digest=");
});

test("leaves an unpublished version on the build and approval path", () => {
  const result = existingFixture().run({ MOCK_VERSIONS: "[]" });
  expect(result.status, result.stderr).toBe(0);
  expect(result.output).toBe("");
  expect(result.events).toBe("");
});

test.each(["MOCK_API_STATUS", "MOCK_ATTESTATION_STATUS", "MOCK_DOCKER_STATUS"])(
  "does not reuse an image when %s fails",
  (variable) => {
    const result = existingFixture().run({ [variable]: "1" });
    expect(result.status).not.toBe(0);
    expect(result.output).not.toContain("digest=");
  },
);

test.each(["source", "version", "architecture"] as const)(
  "rejects published container %s mismatches",
  (field) => {
    const { run, manifest } = existingFixture();
    if (field === "source")
      manifest.annotations["org.opencontainers.image.revision"] = "b".repeat(
        40,
      );
    if (field === "version")
      manifest.annotations["org.opencontainers.image.version"] = "99.1.1";
    if (field === "architecture") manifest.manifests.pop();
    const result = run({ MOCK_MANIFEST: JSON.stringify(manifest) });
    expect(result.status).not.toBe(0);
    expect(result.output).toBe("");
  },
);

test.each(["latest", "sha", "version", "version and sha"] as const)(
  "resumes an attested index with a missing %s tag",
  (missing) => {
    const { run, source } = existingFixture();
    const tags = { latest: "latest", sha: `sha-${source}`, version: "99.1.2" };
    const result = run({
      MOCK_VERSIONS: JSON.stringify([
        {
          name: digest,
          metadata: {
            container: {
              tags:
                missing === "version and sha"
                  ? [tags.latest]
                  : Object.values(tags).filter((tag) => tag !== tags[missing]),
            },
          },
        },
      ]),
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.output).toContain(`digest=${digest}\n`);
    expect(result.output).toContain("complete=false\n");
    expect(result.events).toContain(
      `attestation verify oci://ghcr.io/example/codex-security@${digest}`,
    );
  },
);

test.each(["version", "revision"] as const)(
  "checks the %s of a latest-only index",
  (different) => {
    const { run, manifest } = existingFixture();
    if (different === "version")
      manifest.annotations["org.opencontainers.image.version"] = "99.1.1";
    manifest.annotations["org.opencontainers.image.revision"] = "b".repeat(40);
    const result = run({
      MOCK_VERSIONS: JSON.stringify([
        { name: digest, metadata: { container: { tags: ["latest"] } } },
      ]),
      MOCK_MANIFEST: JSON.stringify(manifest),
    });
    expect(result.status, result.stderr).toBe(different === "version" ? 0 : 1);
    expect(result.output).toBe("");
  },
);

test("refuses to replace a source tag pointing at another index", () => {
  const { run, source } = existingFixture();
  const result = run({
    MOCK_VERSIONS: JSON.stringify([
      { name: digest, metadata: { container: { tags: ["99.1.2", "latest"] } } },
      {
        name: `sha256:${"b".repeat(64)}`,
        metadata: { container: { tags: [`sha-${source}`] } },
      },
    ]),
  });
  expect(result.status).not.toBe(0);
  expect(result.output).not.toContain("digest=");
});
