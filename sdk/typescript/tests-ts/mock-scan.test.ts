import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { DiffTarget } from "../src/targets.js";
import { runWorkbench } from "../src/runtime.js";
import { loadContract } from "../src/contract.js";
import { ScanInterruptedError } from "../src/errors.js";
import { TestClient } from "./support/api-client.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(await realpath(tmpdir()), "mock-scan-test-"));
  roots.push(root);
  const repository = join(root, "repository");
  await mkdir(repository);
  await writeFile(
    join(repository, "example.ts"),
    "export const example = 1;\n",
  );
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: join(root, "codex-home"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const client = new TestClient(
    { pythonPath: python! },
    {
      environment,
      runWorkbench,
      prepareRuntime: async () => {
        throw new Error("Mock scan initialized Codex");
      },
      matchFindings: async () => {
        throw new Error("Mock scan called model matching");
      },
    },
  );
  return { root, repository, client, environment, python: python! };
}

test("mock scans seal real artifacts and index shared and unique findings without Codex", async () => {
  const { repository, client, environment, python } = await fixture();
  const callbacks: string[] = [];
  try {
    const first = await client.run(repository, {
      mock: true,
      auth: "api-key",
      maxCostUsd: 0.01,
      onAuthentication: () => callbacks.push("authentication"),
      onScanStarted: () => callbacks.push("started"),
    });
    const second = await client.run(repository, { mock: true });
    expect(callbacks).toEqual(["started"]);
    expect(first.findings.findings).toHaveLength(12);
    expect(first.coverage.completeness).toBe("complete");
    expect(first.manifest.scan.status).toBe("completed");
    expect(first.manifest.scan.sealedAt).toBeTruthy();
    expect(first.turnResult["mock"]).toBe(true);
    expect(first.threadId).toBe("");
    expect(first.cost?.estimatedUsd).toBe(0);
    expect(first.cost?.inputTokens).toBe(0);
    expect(first.cost?.outputTokens).toBe(0);
    expect(await readFile(first.reportPath, "utf8")).toContain(
      "Synthetic mock scan",
    );
    expect(
      await loadContract(first.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).toEqual({
      manifest: first.manifest,
      findings: first.findings,
      coverage: first.coverage,
    });
    const previousIds = new Set(
      first.findings.findings.map((finding) => finding.findingId),
    );
    const recurring = second.findings.findings.filter((finding) =>
      previousIds.has(finding.findingId),
    );
    expect(recurring).toHaveLength(8);
    expect(
      new Set([
        ...previousIds,
        ...second.findings.findings.map((finding) => finding.findingId),
      ]).size,
    ).toBe(16);
    expect(
      new Set(first.findings.findings.map((finding) => finding.severity.level))
        .size,
    ).toBe(5);
    for (const id of ["command-injection", "path-traversal"]) {
      const pair = first.findings.findings.filter(
        (finding) => finding.extensions?.["mockGroup"] === id,
      );
      expect(pair).toHaveLength(2);
      expect(pair[0]!.findingId).not.toBe(pair[1]!.findingId);
      expect(pair[0]!.locations).toEqual(pair[1]!.locations);
    }
    expect(second.repositoryFindings).toHaveLength(16);
    expect(
      second.repositoryFindings?.filter(
        (finding) => finding.knownScanIds?.length === 2,
      ),
    ).toHaveLength(8);
    expect(await readdir(repository)).toEqual(["example.ts"]);
    expect(await readFile(join(repository, "example.ts"), "utf8")).toBe(
      "export const example = 1;\n",
    );
    const history = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["list-scans", "--repository", repository],
    );
    expect(history["scans"]).toHaveLength(2);
    const recipe = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["get-scan-recipe", "--scan-id", first.manifest.scan.id],
    );
    let rerunMock: boolean | undefined;
    expect(
      await main(
        ["scans", "rerun", first.manifest.scan.id],
        capture().stream,
        capture().stream,
        dependencies({
          currentDirectory: repository,
          onWorkbench: async () => recipe,
          onTurn: (_repository, options) => {
            rerunMock = (options as { mock?: boolean }).mock;
          },
        }),
      ),
    ).toBe(0);
    expect(rerunMock).toBe(true);
  } finally {
    await client.close();
  }
});

test("mock scans preserve output protection and archive existing completed results", async () => {
  const { root, repository, client } = await fixture();
  try {
    await expect(
      client.run(repository, {
        mock: true,
        outputDir: join(repository, "results"),
      }),
    ).rejects.toThrow();
    const outputDir = join(root, "results");
    const first = await client.run(repository, {
      mock: true,
      outputDir,
      target: ["example.ts"],
    });
    const original = await readFile(first.manifestPath, "utf8");
    await expect(
      client.run(repository, { mock: true, outputDir }),
    ).rejects.toThrow();
    expect(await readFile(first.manifestPath, "utf8")).toBe(original);
    let archive = "";
    const second = await client.run(repository, {
      mock: true,
      outputDir,
      archiveExisting: true,
      onOutputArchived: (path) => {
        archive = path;
      },
    });
    expect(await readFile(join(archive, "scan-manifest.json"), "utf8")).toBe(
      original,
    );
    expect(second.manifest.scan.id).not.toBe(first.manifest.scan.id);
    expect(first.coverage.mode).toBe("scoped_path");
    expect(first.coverage.includePaths).toEqual(["example.ts"]);
  } finally {
    await client.close();
  }
});

test("mock scan CLI forwards the flag and never offers authentication or patching", async () => {
  const stdout = capture();
  const stderr = capture(true);
  let mock: boolean | undefined;
  const code = await main(
    ["scan", ".", "--mock", "--fail-on-severity", "high", "--auth", "api-key"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({
        result: fakeResult(["high"]),
        onTurn: (_repository, options) => {
          mock = (options as { mock?: boolean }).mock;
        },
      }),
      confirmPatchReview: async () => {
        throw new Error("Unexpected patch prompt");
      },
    },
  );
  expect(code).toBe(1);
  expect(mock).toBe(true);
  expect(stderr.text()).toContain("Mock scan");
});

test("mock scans bind clean Git, committed diff, and working-tree snapshots", async () => {
  const { root, repository, client } = await fixture();
  const git = async (...args: string[]) => {
    const result = await runCommand(
      "git",
      [
        "-C",
        repository,
        "-c",
        `core.hooksPath=${join(root, "hooks")}`,
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Example",
        "-c",
        "user.email=example@example.test",
        ...args,
      ],
      { timeout: 10000 },
    );
    expect(result.status).toBe(0);
  };
  try {
    await git("init");
    await git("add", ".");
    await git("commit", "-m", "Initial synthetic fixture");
    const clean = await client.run(repository, { mock: true });
    expect(clean.manifest.scan.target.kind).toBe("git_revision");
    await writeFile(
      join(repository, "example.ts"),
      "export const example = 2;\n",
    );
    await git("commit", "-am", "Update synthetic fixture");
    const diff = await client.run(repository, {
      mock: true,
      target: DiffTarget.refs({ base: "HEAD~1" }),
    });
    expect(diff.manifest.scan.target.kind).toBe("git_diff");
    expect(diff.coverage.completeness).toBe("complete");
    expect(diff.coverage.mode).toBe("branch_diff");
    await writeFile(
      join(repository, "example.ts"),
      "export const example = 3;\n",
    );
    const workingTree = await client.run(repository, {
      mock: true,
      target: DiffTarget.workingTree({}),
    });
    expect(workingTree.manifest.scan.target.kind).toBe("git_diff");
    expect(workingTree.coverage.completeness).toBe("complete");
    expect(workingTree.coverage.mode).toBe("working_tree");
  } finally {
    await client.close();
  }
});

test("aborting mock generation leaves a terminal scan record", async () => {
  const { client, repository, environment, python } = await fixture();
  const controller = new AbortController();
  try {
    await expect(
      client.run(repository, {
        mock: true,
        signal: controller.signal,
        onScanStarted: () => controller.abort(),
      }),
    ).rejects.toThrow(ScanInterruptedError);
    const history = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["list-scans", "--repository", repository],
    );
    expect(history["scans"]).toMatchObject([
      { progress: { status: "failed" } },
    ]);
  } finally {
    await client.close();
  }
});

test.each(["--dry-run", "--patch"])(
  "mock scan CLI rejects %s",
  async (flag) => {
    const stderr = capture();
    const code = await main(
      ["scan", "--mock", flag],
      capture().stream,
      stderr.stream,
      dependencies({
        onRun: () => {
          throw new Error("Unexpected scan");
        },
      }),
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("--mock cannot be combined");
  },
);

test.each([
  { mode: "deep" as const },
  { validationPrompt: "Validate" },
  { postScanPrompt: "Follow up" },
])("mock scans reject model-dependent workflows: %j", async (options) => {
  const { client, repository } = await fixture();
  try {
    await expect(
      client.run(repository, { mock: true, ...options }),
    ).rejects.toThrow("require model calls");
  } finally {
    await client.close();
  }
});
