import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
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
const release = workflow("container-release");
const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "container release "));
  directories.push(directory);
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
  function run(env: Record<string, string> = {}) {
    writeFileSync(output, "");
    const result = runWorkflowScript(
      repository,
      release.jobs["source"]!.steps![1]!.run,
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
  return { directory, repository, source, automation, git, commit, run };
}

test("backfills the tagged release after main has advanced", () => {
  const { run, source } = fixture();
  const result = run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.output).toContain(`sha=${source}\n`);
  expect(result.output).toContain("version=99.1.2\n");
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

test("preserves standalone manual and container tag source selection", () => {
  const source = fixture();
  const manual = source.run({ RELEASE_SHA: "", RELEASE_VERSION: "" });
  expect(manual.status, manual.stderr).toBe(0);
  expect(manual.output).toContain(`sha=${source.automation}\n`);
  expect(manual.output).toContain("version=99.2.0\n");
  const tagged = source.run({
    RELEASE_SHA: "",
    RELEASE_VERSION: "",
    GITHUB_SHA: source.source,
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF: "refs/tags/container-v99.1.2",
    GITHUB_REF_NAME: "container-v99.1.2",
  });
  expect(tagged.status, tagged.stderr).toBe(0);
  expect(tagged.output).toContain(`sha=${source.source}\n`);
});

test("coordinates publication, approval, and completion with the verified npm source", () => {
  const parent = workflow("node-github-release");
  expect(parent.jobs["container"]).toMatchObject({
    needs: ["release", "installed"],
    if: "needs.release.outputs.has-container == 'true'",
    uses: "./.github/workflows/container-release.yml",
    with: {
      "release-sha": "${{ needs.release.outputs.sha }}",
      "release-version": "${{ needs.release.outputs.version }}",
    },
    permissions: {
      contents: "read",
      packages: "write",
      attestations: "write",
      "artifact-metadata": "write",
      "id-token": "write",
    },
  });
  expect(parent.jobs["complete"]?.needs).toContain("container");
  expect(release.jobs["authorize"]).toMatchObject({
    needs: ["source", "validate"],
    environment: "container",
    permissions: { contents: "read", packages: "read" },
  });
  expect(release.jobs["publish-platform"]?.needs).toBe("authorize");
  expect(release.jobs["promote"]?.needs).toContain("attest");
  expect(release.jobs["attest"]?.permissions?.["artifact-metadata"]).toBe(
    "write",
  );
  expect(release.concurrency).toEqual({
    group: "container-release-publish",
    queue: "max",
  });
});

test("builds and downloads native payloads from the same source as the image", () => {
  expect(release.jobs["native"]?.with?.["ref"]).toBe(
    "${{ needs.source.outputs.sha }}",
  );
  expect(release.jobs["validate"]?.with?.["ref"]).toBe(
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
  for (const job of ["publish-platform", "manifest"]) {
    expect(release.jobs[job]!.steps![0]?.with?.["ref"]).toBe(
      "${{ needs.authorize.outputs.sha }}",
    );
  }
  for (const job of ["authorize", "promote"]) {
    expect(release.jobs[job]!.steps![0]?.with?.["ref"]).toBe(
      "${{ github.sha }}",
    );
  }
  const buildSteps = release.jobs["publish-platform"]!.steps!;
  expect(
    buildSteps.find((step) => step.name === "Prepare native runtime")?.with?.[
      "name"
    ],
  ).toBe("native-universal-${{ needs.authorize.outputs.sha }}");
  const validation = workflow("container-validate").jobs["validate"]!.steps!;
  expect(validation[0]?.with?.["ref"]).toBe("${{ inputs.ref || github.sha }}");
  expect(validation[1]?.with?.["name"]).toBe(
    "native-universal-${{ inputs.ref || github.sha }}",
  );
});

const digest = `sha256:${"a".repeat(64)}`;
function existingFixture() {
  const source = fixture();
  const bin = join(source.directory, "bin");
  const events = join(source.directory, "events");
  const output = join(source.directory, "reuse-output");
  mkdirSync(bin);
  mkdirSync(join(source.repository, "docker"));
  copyFileSync(
    new URL(
      "../../../docker/verify-container-release-version.sh",
      import.meta.url,
    ),
    join(source.repository, "docker/verify-container-release-version.sh"),
  );
  writeFileSync(
    join(bin, "gh"),
    `#!/bin/sh
case "$1" in
  api) printf '%s\\n' "$MOCK_VERSIONS"; exit "$MOCK_API_STATUS" ;;
  attestation) printf '%s\\n' "$*" >> "$EVENTS"; exit "$MOCK_ATTESTATION_STATUS" ;;
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
  pull|run) exit "$MOCK_DOCKER_STATUS" ;;
  *) exit 99 ;;
esac
`,
    { mode: 0o755 },
  );
  const manifest = {
    annotations: {
      "org.opencontainers.image.version": "99.1.2",
      "org.opencontainers.image.revision": source.source,
    },
    manifests: ["amd64", "arm64"].map((architecture) => ({
      platform: { os: "linux", architecture },
    })),
  };
  const script = release.jobs["source"]!.steps!.find(
    (step) => step.name === "Verify an existing immutable container release",
  )!.run;
  function run(env: Record<string, string> = {}) {
    writeFileSync(events, "");
    writeFileSync(output, "");
    const result = runWorkflowScript(source.repository, script, {
      PATH: `${bin}${delimiter}${process.env["PATH"]}`,
      EVENTS: events.replaceAll("\\", "/"),
      GITHUB_OUTPUT: output.replaceAll("\\", "/"),
      GITHUB_REPOSITORY: "example/project",
      GITHUB_REPOSITORY_OWNER: "Example",
      IMAGE: "ghcr.io/example/codex-security",
      VERSION: "99.1.2",
      RELEASE_SHA: source.source,
      MOCK_VERSIONS: JSON.stringify([
        {
          name: digest,
          metadata: {
            container: { tags: ["99.1.2", "latest", `sha-${source.source}`] },
          },
        },
      ]),
      MOCK_MANIFEST: JSON.stringify(manifest),
      MOCK_API_STATUS: "0",
      MOCK_ATTESTATION_STATUS: "0",
      MOCK_DOCKER_STATUS: "0",
      ...env,
    });
    return {
      ...result,
      output: readFileSync(output, "utf8"),
      events: readFileSync(events, "utf8"),
    };
  }
  return { run, manifest, source: source.source };
}

test("verifies and reuses the published source without a registry write", () => {
  const { run } = existingFixture();
  const result = run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.output).toContain(`digest=${digest}\n`);
  expect(result.events.trim().split("\n")).toEqual([
    `buildx imagetools inspect ghcr.io/example/codex-security@${digest} --raw`,
    `attestation verify oci://ghcr.io/example/codex-security@${digest} --repo example/project`,
    `pull ghcr.io/example/codex-security@${digest}`,
    `run --rm ghcr.io/example/codex-security@${digest} --version`,
  ]);
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

test("does not reuse a version whose latest tag is incomplete", () => {
  const { run, source } = existingFixture();
  const result = run({
    MOCK_VERSIONS: JSON.stringify([
      {
        name: digest,
        metadata: { container: { tags: ["99.1.2", `sha-${source}`] } },
      },
    ]),
  });
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("matching latest tag");
  expect(result.output).not.toContain("digest=");
});

test("does not reuse a version missing its source commit tag", () => {
  const result = existingFixture().run({
    MOCK_VERSIONS: JSON.stringify([
      { name: digest, metadata: { container: { tags: ["99.1.2", "latest"] } } },
    ]),
  });
  expect(result.status).not.toBe(0);
  expect(result.output).toBe("");
});
