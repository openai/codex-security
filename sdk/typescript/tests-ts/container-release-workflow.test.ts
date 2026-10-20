import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  ) as { jobs: Record<string, Job> };
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
  return { source, automation, git, commit, run };
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
  expect(native.jobs["bundle"]!.steps![0]?.with?.["pattern"]).toBe(
    "native-platform-*-${{ inputs.ref || github.sha }}",
  );
  expect(native.jobs["bundle"]!.steps![1]?.with?.["name"]).toBe(
    "native-universal-${{ inputs.ref || github.sha }}",
  );
  for (const job of ["publish-platform", "manifest", "promote"]) {
    expect(release.jobs[job]!.steps![0]?.with?.["ref"]).toBe(
      "${{ needs.authorize.outputs.sha }}",
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
