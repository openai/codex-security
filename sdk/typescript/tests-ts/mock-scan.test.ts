import type { JsonObject, ScanOptions } from "../src/index.js";
import { BUNDLED_PLUGIN_VERSION, VERSION } from "../src/version.js";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  test,
  mock,
} from "bun:test";
import { main } from "../src/cli.js";
import { DiffTarget } from "../src/targets.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { loadContract } from "../src/contract.js";
import { ScanInterruptedError } from "../src/errors.js";
import { TestClient } from "./support/api-client.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";

const { temporaryDirectories: roots, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function fixture(workbench: typeof runWorkbench = runWorkbench) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "mock-scan-test-"));
  roots.track(root);
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
  const python = await resolvePluginPython({
    environment,
    protectedRoot: repository,
  });
  const client = new TestClient(
    { pythonPath: python },
    {
      environment,
      runWorkbench: workbench,
      resolvePluginPython: async () => python,
      prepareRuntime: rejecting("Mock scan initialized Codex"),
      matchFindings: rejecting("Mock scan called model matching"),
    },
  );
  return { root, repository, client, environment, python };
}

test("mock scans seal real artifacts and index shared and unique findings without Codex", async () => {
  const { repository, client, environment, python } = await fixture();
  const callbacks: string[] = [];
  const registrations: Array<
    Parameters<NonNullable<ScanOptions["onScanRegistered"]>>[0]
  > = [];
  const onLifecycle = mock<NonNullable<ScanOptions["onLifecycle"]>>();
  onLifecycle.mockImplementationOnce(rejecting("observer unavailable"));
  const onObserverError = mock<NonNullable<ScanOptions["onObserverError"]>>();
  try {
    const first = await client.run(repository, {
      mock: true,
      auth: "api-key",
      maxCostUsd: 0.01,
      failureSeverity: "informational",
      onAuthentication: () => callbacks.push("authentication"),
      onLifecycle,
      onObserverError,
      onScanRegistered: (scan) => {
        callbacks.push("registered");
        registrations.push(scan);
      },
      onScanStarted: () => callbacks.push("started"),
    });
    const second = await client.run(repository, { mock: true });
    expect(callbacks).toEqual(["registered", "started"]);
    const launch = {
      scanId: first.manifest.scan.id,
      mode: "standard",
      startedAt: first.manifest.scan.startedAt,
      status: "running",
      finishedAt: null,
      hasReportableFindings: null,
      surface: "sdk",
      packageVersion: VERSION,
      pluginVersion: BUNDLED_PLUGIN_VERSION,
      mock: true,
    } as const;
    expect(onLifecycle.mock.calls).toEqual([
      [launch],
      [
        {
          ...launch,
          status: "completed",
          finishedAt: first.manifest.scan.completedAt,
          hasReportableFindings: true,
        },
      ],
    ]);
    expect(onObserverError).toHaveBeenCalledWith(
      "onLifecycle",
      expect.any(Error),
    );
    expect(registrations).toEqual([
      {
        scanId: first.manifest.scan.id,
        scanDir: first.scanDir,
      },
    ]);
    expect(first.findings.findings).toHaveLength(12);
    expect(first.review).not.toHaveProperty("status");
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
      review: first.review,
      mode: first.mode,
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
    expect(second.repositoryFindings).toEqual(
      expect.arrayContaining(
        second.findings.findings.map((finding) =>
          expect.objectContaining({ findingId: finding.findingId }),
        ),
      ),
    );
    const currentIds = new Set(
      second.findings.findings.map((finding) => finding.findingId),
    );
    const priorOnly = first.findings.findings.filter(
      (finding) => !currentIds.has(finding.findingId),
    );
    expect(priorOnly).toHaveLength(4);
    expect(second.repositoryFindings).toEqual(
      expect.arrayContaining(
        priorOnly.map((finding) =>
          expect.objectContaining({
            findingId: finding.findingId,
            status: "open",
            confirmedInLatestScan: false,
          }),
        ),
      ),
    );
    expect(
      second.repositoryFindings?.filter(
        (finding) => finding.knownScanIds?.length === 2,
      ),
    ).toHaveLength(8);
    const allHistory = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      [
        "list-global-findings",
        "--repository",
        repository,
        "--include-resolved",
      ],
    );
    expect(allHistory["findings"]).toHaveLength(16);
    expect(allHistory["findings"]).toEqual(
      expect.arrayContaining(
        [...first.findings.findings, ...second.findings.findings].map(
          (finding) =>
            expect.objectContaining({ findingId: finding.findingId }),
        ),
      ),
    );
    expect(await readdir(repository)).toEqual(["example.ts"]);
    expect(await readFile(join(repository, "example.ts"), "utf8")).toBe(
      "export const example = 1;\n",
    );
    const history = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["list-scans", "--repository", repository],
    );
    expect(history["scans"]).toHaveLength(2);
    const saved = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["get-scan", "--scan-id", first.manifest.scan.id],
    );
    const savedScan = saved["scan"] as JsonObject;
    expect(typeof savedScan["updatedAt"]).toBe("string");
    const showOutput = capture(true);
    const showDiagnostics = capture();
    expect(
      await main(
        ["scans", "show", first.manifest.scan.id],
        showOutput.stream,
        showDiagnostics.stream,
        dependencies({ onWorkbench: async () => saved }),
      ),
    ).toBe(0);
    expect(showDiagnostics.text()).toContain(
      `updated ${savedScan["updatedAt"]}`,
    );
    expect(showOutput.text()).toContain("UPDATED");
    expect(showOutput.text()).toContain(savedScan["updatedAt"] as string);
    const recipe = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["get-scan-recipe", "--scan-id", first.manifest.scan.id],
    );
    const onTurn = mock((_repository: string, { mock }: ScanOptions) => mock);
    expect(
      await main(
        ["scans", "rerun", first.manifest.scan.id],
        capture().stream,
        capture().stream,
        dependencies({
          currentDirectory: repository,
          onWorkbench: async () => recipe,
          onTurn,
        }),
      ),
    ).toBe(0);
    expect(onTurn.mock.results.at(-1)?.value).toBe(true);
    expect(onTurn.mock.lastCall?.[1].failureSeverity).toBe("informational");
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
    const firstOptions = {
      mock: true,
      outputDir,
      target: ["example.ts"],
      workflowId: "synthetic-archived-workflow",
    };
    const first = await client.run(repository, firstOptions);
    const original = await readFile(first.manifestPath, "utf8");
    await expect(
      client.run(repository, { mock: true, outputDir }),
    ).rejects.toThrow();
    expect(await readFile(first.manifestPath, "utf8")).toBe(original);
    const onOutputArchived = mock((_path: string) => {});
    const second = await client.run(repository, {
      mock: true,
      outputDir,
      archiveExisting: true,
      onOutputArchived,
    });
    const archive = onOutputArchived.mock.lastCall?.[0] ?? "";
    expect(await readFile(join(archive, "scan-manifest.json"), "utf8")).toBe(
      original,
    );
    expect(second.manifest.scan.id).not.toBe(first.manifest.scan.id);
    expect(first.manifest.scan.mode).toBe("scoped_path");
    expect(first.manifest.scan.scope.includePaths).toEqual(["example.ts"]);
    const resumed = await client.run(repository, firstOptions);
    expect(resumed.manifest).toEqual(first.manifest);
    expect(resumed.scanDir).toBe(archive);
    expect(resumed.sarifPath).toBe(join(archive, "exports", "results.sarif"));
  } finally {
    await client.close();
  }
});

test("mock scan CLI forwards the flag and never offers authentication or patching", async () => {
  const stdout = capture();
  const stderr = capture(true);
  const onTurn = mock((_repository: string, { mock }: ScanOptions) => mock);
  const code = await main(
    ["scan", ".", "--mock", "--fail-on-severity", "high", "--auth", "api-key"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({
        result: fakeResult(["high"]),
        onTurn,
      }),
      confirmPatchReview: rejecting("Unexpected patch prompt"),
    },
  );
  expect(code).toBe(1);
  expect(onTurn.mock.results.at(-1)?.value).toBe(true);
  expect(stderr.text()).toContain("Mock scan");
});

test("mock scans bind clean Git, committed diff, and working-tree snapshots", async () => {
  const { root, repository, client } = await fixture();
  const git = async (...args: string[]) => {
    const result = await runCommand("git", [
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
    ]);
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
    const onLifecycle = mock<NonNullable<ScanOptions["onLifecycle"]>>();
    const diff = await client.run(repository, {
      mock: true,
      target: DiffTarget.refs({ base: "HEAD~1" }),
      onLifecycle,
    });
    expect(
      onLifecycle.mock.calls.map(([{ mode, status }]) => [mode, status]),
    ).toEqual([
      ["diff", "running"],
      ["diff", "completed"],
    ]);
    expect(diff.manifest.scan.target.kind).toBe("git_diff");
    expect(diff.manifest.scan.mode).toBe("branch_diff");
    await writeFile(
      join(repository, "example.ts"),
      "export const example = 3;\n",
    );
    const workingTree = await client.run(repository, {
      mock: true,
      target: DiffTarget.workingTree({}),
    });
    expect(workingTree.manifest.scan.target.kind).toBe("git_diff");
    expect(workingTree.manifest.scan.mode).toBe("working_tree");
  } finally {
    await client.close();
  }
});

test.each(["abort", "close", "timeout"] as const)(
  "stopping mock generation via %s records its terminal outcome",
  async (stop) => {
    const { client, repository, environment, python } = await fixture();
    const controller = new AbortController();
    const onLifecycle = mock<NonNullable<ScanOptions["onLifecycle"]>>();
    try {
      await expect(
        client.run(repository, {
          mock: true,
          signal: controller.signal,
          onLifecycle,
          onScanStarted: () => {
            if (stop === "close") void client.close();
            else if (stop === "timeout")
              controller.abort(new DOMException("deadline", "TimeoutError"));
            else controller.abort();
          },
        }),
      ).rejects.toThrow(
        stop === "close" ? "CodexSecurity is closed" : ScanInterruptedError,
      );
      const terminal = stop === "timeout" ? "failed" : "canceled";
      const history = await runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        ["list-scans", "--repository", repository],
      );
      expect(history["scans"]).toMatchObject([
        { progress: { status: terminal } },
      ]);
      const [saved] = history["scans"] as JsonObject[];
      expect(
        onLifecycle.mock.calls.map(([snapshot]) => snapshot.status),
      ).toEqual(["running", terminal]);
      expect(saved?.["lifecycle"]).toEqual(onLifecycle.mock.lastCall?.[0]);
    } finally {
      await client.close();
    }
  },
);

test("reports committed completion after the workbench response is lost", async () => {
  const { client, repository } = await fixture(async (options, args, input) => {
    if (args[0] === "get-scan")
      throw new Error("Full scan details unavailable");
    const saved = await runWorkbench(options, args, input);
    if (args[0] === "complete-scan") throw new Error("completion reply lost");
    return saved;
  });
  const onLifecycle = mock<NonNullable<ScanOptions["onLifecycle"]>>();
  try {
    await expect(
      client.run(repository, { mock: true, onLifecycle }),
    ).rejects.toThrow("completion reply lost");
    expect(onLifecycle.mock.calls.map(([snapshot]) => snapshot.status)).toEqual(
      ["running", "completed"],
    );
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
        onRun: throwing("Unexpected scan"),
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

describe("interrupted workbench registration", () => {
  let registeredId: string | undefined;
  let saved: { id: string; status: string } | undefined;

  afterAll(cleanup);

  beforeAll(async () => {
    const controller = new AbortController();
    const { client, repository, environment, python } = await fixture(
      async (options, args, input) => {
        const reply = await runWorkbench(options, args, input);
        if (args[0] === "register-cli-scan") {
          if (typeof reply["scanId"] !== "string")
            throw new Error("Missing registered scan ID");
          registeredId = reply["scanId"];
          controller.abort();
          throw new DOMException(
            "Synthetic registration reply lost",
            "AbortError",
          );
        }
        return reply;
      },
    );
    const workbench = { environment, python, pluginRoot: PLUGIN_ROOT };
    try {
      await expect(
        client.run(repository, { mock: true, signal: controller.signal }),
      ).rejects.toThrow(ScanInterruptedError);
      if (registeredId === undefined)
        throw new Error("Registration did not commit");
      const { scan } = await runWorkbench(workbench, [
        "get-scan",
        "--scan-id",
        registeredId,
      ]);
      const row = scan as { scanId: string; lifecycle: { status: string } };
      saved = { id: row.scanId, status: row.lifecycle.status };
    } finally {
      await client.close();
    }
  }, 60_000);

  test("finds the exact saved scan after interruption", () => {
    expect(registeredId).toEqual(expect.any(String));
    expect(saved?.id).toBe(registeredId);
    expect(saved?.status).toEqual(expect.any(String));
  });

  test.todo("marks that saved scan canceled when its reply was lost", () => {
    expect(saved?.status).toBe("canceled");
  });
});
