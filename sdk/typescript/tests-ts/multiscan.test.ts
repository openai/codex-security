import { gitText } from "./support/shell.js";
import { createCliTest, captureCli } from "./support/cli-run.js";
import { execFileSync } from "node:child_process";
import {
  access,
  appendFile,
  chmod,
  cp,
  lstat,
  link,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { build } from "esbuild";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contract from "../src/contract.js";
import { PYTHON } from "./support/security-policy.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanResult } from "../src/result.js";
import { runMultiscan } from "../src/multiscan.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { DiffTarget, normalizeTarget } from "../src/targets.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import * as runtime from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { rejecting, throwing } from "./support/errors.js";

import {
  type MultiscanOptions,
  type SecurityClient,
  createMultiscanFixtures,
  git,
  repository,
  client,
  results,
} from "./support/multiscan.js";

const {
  cleanup,
  fixture,
  repositoryFixture,
  completedScan,
  completeRun,
  reseal,
  options,
  fixtureRequests,
} = createMultiscanFixtures();

const testPosix = process.platform === "win32" ? test.skip : test;
afterEach(cleanup);

describe("multiscan", () => {
  test("prepares shared prompt files once while missing sources remain row failures", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "prompt-source");
    const prompt = join(paths.root, "shared-prompt.md");
    await writeFile(prompt, "Review synthetic boundaries.");
    await writeFile(
      paths.input,
      `id,repository,revision\nmissing,${join(paths.root, "absent")},${source.revision}\nfirst,${source.path},${source.revision}\nsecond,${source.path},${source.revision}\n`,
    );
    let scans = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_checkout, scanOptions = {}) => {
          expect(scanOptions.scanPrompt).toBe("Review synthetic boundaries.");
          expect(scanOptions.scanPromptFile).toBeUndefined();
          if (scans++ === 0) await rm(prompt);
          return await completedScan(scanOptions.outputDir!);
        }),
        { maxAttempts: 1, scanPromptFile: prompt },
      ),
    );
    expect(scans).toBe(2);
    expect(summary).toMatchObject({ total: 3, completed: 2, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "missing", status: "failed" },
      { id: "first", status: "completed" },
      { id: "second", status: "completed" },
    ]);
  });

  test.each([DiffTarget.refs({ base: "HEAD~1" }), DiffTarget.workingTree()])(
    "rejects unsupported bulk diff scopes before preparing a campaign: %j",
    async (target) => {
      const { paths } = await repositoryFixture("configured-scope", "example");
      const createSecurity = mock(() => {
        return security;
      });
      const security = client(
        rejecting("The unsupported target must not reach a scan."),
      );
      await expect(
        runMultiscan(
          options(paths, security, {
            scanOptionsByMode: { standard: { target } },
            createSecurity,
          }),
        ),
      ).rejects.toThrow(
        "Bulk scans do not support diff or working-tree scopes",
      );
      expect(createSecurity).not.toHaveBeenCalled();
      await expect(access(paths.output)).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  test("parses quoted CSV fields, embedded delimiters, and Windows line endings", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "comma, quoted");
    await writeFile(
      paths.input,
      `\uFEFF" id "," repository "," revision ","scope","mode","prompt","notes"\r\n"payments","${source.path}","${source.revision}","src","deep","Focus on authentication, authorization.","contains ""quotes"""\r\n\r\n`,
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (repository, scanOptions = {}) => {
          expect(scanOptions.target).toEqual([join(repository, "src")]);
          expect(scanOptions.mode).toBe("deep");
          expect(scanOptions.scanPrompt).toBe(
            "Review boundaries.\n\nFocus on authentication, authorization.",
          );
          expect(scanOptions.postScanPrompt).toBe("Draft confirmed fixes.");
          expect(scanOptions.maxCostUsd).toBe(12.5);
          return await completedScan(scanOptions.outputDir!);
        }),
        {
          scanPrompt: "Review boundaries.",
          postScanPrompt: "Draft confirmed fixes.",
          maxCostUsd: 12.5,
          scanOptionsByMode: {
            deep: { target: DiffTarget.workingTree() },
          },
        },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "payments", repository: source.path },
    ]);
    expect(
      JSON.parse(await readFile(join(paths.output, "manifest.json"), "utf8")),
    ).toMatchObject({
      scanPrompt: "Review boundaries.",
      postScanPrompt: "Draft confirmed fixes.",
      maxCostUsd: 12.5,
      tasks: [
        { id: "payments", prompt: "Focus on authentication, authorization." },
      ],
    });
  });

  test("records each completed scan's cost in the resumable ledger", async () => {
    const { paths } = await repositoryFixture("priced");
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
    };

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          Object.assign(await completedScan(scanOptions.outputDir!), { cost }),
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "priced", status: "completed", cost },
    ]);
  });

  test.each([false, true])(
    "retains usage for failed or canceled bulk attempts: canceled=%p",
    async (cancel) => {
      const { paths } = await repositoryFixture("synthetic-usage");
      const controller = new AbortController();
      const measurement = {
        coverage: "partial" as const,
        cost: null,
        observedAt: "2026-10-01T00:00:00.000Z",
        threadCount: 1,
        missingThreadCount: 1,
        usage: {
          input_tokens: 100,
          cached_input_tokens: 0,
          cache_write_input_tokens: 0,
          output_tokens: 5,
          reasoning_output_tokens: 0,
          total_tokens: 105,
        },
      };
      const run = runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            scanOptions.onMeasurement?.(measurement);
            if (cancel) controller.abort(new Error("Synthetic cancellation"));
            throw new Error("Synthetic execution failure");
          }),
          { maxAttempts: 1, signal: controller.signal },
        ),
      );
      if (cancel) await expect(run).rejects.toThrow("Synthetic cancellation");
      else expect(await run).toMatchObject({ completed: 0, failed: 1 });
      expect(await results(join(paths.output, "results.jsonl"))).toMatchObject([
        {
          status: "failed",
          outcome: cancel ? "canceled" : "failed",
          measurement,
        },
      ]);
    },
  );

  test("records an exhausted repository budget without retrying the scan", async () => {
    const { paths } = await repositoryFixture("over-budget");
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 25.25,
    };
    const attempts = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        throw new ScanCostLimitExceededError(25, cost, scanOptions.outputDir!);
      },
    );

    const summary = await runMultiscan(
      options(paths, client(attempts), { maxAttempts: 3, maxCostUsd: 25 }),
    );

    expect(attempts.mock.calls.length).toBe(1);
    expect(summary).toMatchObject({ completed: 0, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "over-budget", status: "failed", attempt: 1, cost },
    ]);
  });

  test("forwards a bulk CLI cost limit and rejects zero", async () => {
    const { paths } = await repositoryFixture("sample");
    const { runCli } = createCliTest(main);

    let scanOptions: unknown;

    expect(
      await runCli(
        [
          "bulk-scan",
          "repositories.csv",
          "--output-dir",
          "results",
          "--max-cost",
          "12.5",
          "--json",
        ],
        dependencies({
          currentDirectory: paths.root,
          onTurn: (_repository, options) => (scanOptions = options),
        }),
      ),
    ).toBe(0);
    expect(scanOptions).toMatchObject({ maxCostUsd: 12.5 });

    const invalid = captureCli(main, "stderr");
    expect(
      await invalid.run(
        ["bulk-scan", "--max-cost=0"],
        dependencies({ currentDirectory: paths.root }),
      ),
    ).toBe(2);
    expect(invalid.text()).toContain("expected number to be >0");
  });

  test("surfaces optional post-scan warnings without failing completed scans", async () => {
    const { paths } = await repositoryFixture("follow-up-warning");
    const progress: Parameters<
      NonNullable<MultiscanOptions["onProgress"]>
    >[0][] = [];

    const warnings = [
      "Could not run post-scan instructions.",
      "Repository changed during the scan.",
    ];
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          for (const warning of warnings) scanOptions.onWarning?.(warning);
          return await completedScan(scanOptions.outputDir!);
        }),
        { onProgress: (event) => progress.push(event) },
      ),
    );

    expect(summary).toMatchObject({
      completed: 1,
      failed: 0,
      warnings: [
        {
          repository: "follow-up-warning",
          warnings,
        },
      ],
    });
    expect(progress).toContainEqual({
      repository: "follow-up-warning",
      attempt: 1,
      status: "started",
      warning: "Could not run post-scan instructions.",
    });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "follow-up-warning",
        status: "completed",
        warnings,
      },
    ]);

    const resumedProgress: typeof progress = [];
    const resumed = await runMultiscan(
      options(
        paths,
        client(async () => Promise.reject(new Error("must not rerun"))),
        {
          onProgress: (event) => resumedProgress.push(event),
        },
      ),
    );

    expect(resumed).toEqual({ ...summary, skipped: 1 });
    for (const warning of warnings) {
      expect(resumedProgress).toContainEqual({
        repository: "follow-up-warning",
        attempt: 1,
        status: "completed",
        warning,
      });
    }
  });

  test.each([false, true])(
    "continues scanning when a progress observer fails %p",
    async (asynchronous) => {
      const { paths } = await repositoryFixture("observer-failure");
      const attempts = mock<SecurityClient["run"]>(
        async (_repository, scanOptions = {}) => {
          scanOptions.onWarning?.("Optional post-scan warning.");
          return await completedScan(scanOptions.outputDir!);
        },
      );
      const progress: string[] = [];

      const summary = await runMultiscan(
        options(paths, client(attempts), {
          onProgress: (event) => {
            progress.push(event.warning ?? event.status);
            const error = new Error("Optional progress observer failed.");
            if (asynchronous) return Promise.reject(error);
            throw error;
          },
        }),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      expect(attempts.mock.calls.length).toBe(1);
      expect(progress).toEqual([
        "started",
        "Optional post-scan warning.",
        "completed",
      ]);
      expect(await results(summary.resultsPath)).toMatchObject([
        { id: "observer-failure", status: "completed", attempt: 1 },
      ]);
    },
  );

  test("rejects malformed CSV and duplicate headers before starting scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "csv");
    const invalid = [
      `id,repository,revision\npayments,"${source.path},${source.revision}\n`,
      `id,repository,revision,id\npayments,${source.path},${source.revision},again\n`,
      `id,repository,revision\npayments,${source.path}\n`,
    ];
    const scans = mock(completeRun);

    for (const input of invalid) {
      await writeFile(paths.input, input);
      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        /CSV/,
      );
    }

    expect(scans.mock.calls.length).toBe(0);
  });

  test("rejects task IDs that collide with Windows path names", async () => {
    const paths = await fixture();
    const scans = mock(completeRun);
    for (const id of [
      "CON",
      "con.txt",
      "NUL",
      "AUX.txt",
      "PRN",
      "COM1",
      "com9.log",
      "LPT1",
      "lpt9.txt",
      "report.",
    ]) {
      await writeFile(
        paths.input,
        `id,repository,revision\n${id},./repository,${"0".repeat(40)}\n`,
      );

      await expect(
        runMultiscan(options(paths, client(scans))),
        id,
      ).rejects.toThrow("safe, unique path names");
    }

    expect(scans.mock.calls.length).toBe(0);
  });

  test("knowledge failures do not hide a later real scan failure behind an older completed result", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "later-failure");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const document = join(paths.root, "context.md");
    await writeFile(document, "Original context.");
    let calls = 0;
    const configured = options(
      paths,
      client(async (_repo, scan = {}) => {
        calls++;
        if (calls === 2) {
          await mkdir(scan.outputDir!, { recursive: true, mode: 0o700 });
          await writeFile(join(scan.outputDir!, "checkpoint"), "keep");
          throw new Error("Actual scan failed");
        }
        return completedScan(scan.outputDir!);
      }),
      { knowledgeBasePaths: [document], maxAttempts: 1 },
    );
    await runMultiscan(configured);
    const oldCoverage = join(
      paths.output,
      "artifacts",
      "repo",
      "attempt-1",
      "coverage.json",
    );
    const originalCoverage = await readFile(oldCoverage);
    await rm(oldCoverage);
    expect(await runMultiscan(configured)).toMatchObject({ failed: 1 });
    await writeFile(oldCoverage, originalCoverage);
    await rm(document);
    expect(await runMultiscan(configured)).toMatchObject({ failed: 1 });
    await writeFile(document, "Original context.");
    const repaired = await runMultiscan(configured);
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(3);
    expect((await results(repaired.resultsPath)).at(-1)).toMatchObject({
      status: "completed",
      attempt: 4,
    });
  });

  test.each(["partial write", "rename"])(
    "preserves the campaign manifest after a knowledge repair %s failure",
    async (failure) => {
      const testName = `preserves the campaign manifest after a knowledge repair ${failure} failure`;
      if (runTestInSubprocess(import.meta.path, testName)) return;
      const paths = await fixture();
      const source = await repository(paths.root, "manifest-repair");
      await writeFile(
        paths.input,
        `id,repository,revision,mode\nfailed,${source.path},${source.revision},deep\ngood,${source.path},${source.revision},standard\n`,
      );
      const document = join(paths.root, "missing.md");
      const scans: string[] = [];
      const configured = options(
        paths,
        client(async (_repo, scan = {}) => {
          scans.push(scan.mode!);
          return completedScan(scan.outputDir!);
        }),
        {
          maxAttempts: 1,
          scanOptionsByMode: { deep: { knowledgeBasePaths: [document] } },
        },
      );
      const initial = await runMultiscan(configured);
      expect(initial).toMatchObject({ completed: 1, failed: 1 });
      const manifestPath = join(paths.output, "manifest.json");
      const originalManifest = await readFile(manifestPath, "utf8");
      const originalReceipts = await readFile(initial.resultsPath, "utf8");
      await writeFile(document, "Repaired context.");
      const originalWrite = filesystem.writeFile;
      const originalRename = filesystem.rename;
      const write = spyOn(filesystem, "writeFile").mockImplementation(
        async (file, data, opts) => {
          if (
            failure === "partial write" &&
            ((String(file) === manifestPath &&
              (typeof opts !== "object" || opts?.flag !== "wx")) ||
              String(file).startsWith(`${manifestPath}.`))
          ) {
            await originalWrite(file, "{", opts);
            throw Object.assign(new Error("Synthetic manifest I/O failure"), {
              code: "EIO",
            });
          }
          return originalWrite(file, data, opts);
        },
      );
      const move = spyOn(filesystem, "rename").mockImplementation(
        async (from, to) => {
          if (failure === "rename" && String(to) === manifestPath)
            throw Object.assign(new Error("Synthetic manifest I/O failure"), {
              code: "EIO",
            });
          return originalRename(from, to);
        },
      );
      try {
        await expect(runMultiscan(configured)).rejects.toThrow(
          "Synthetic manifest I/O failure",
        );
      } finally {
        write.mockRestore();
        move.mockRestore();
      }
      expect(await readFile(manifestPath, "utf8")).toBe(originalManifest);
      expect(await readFile(initial.resultsPath, "utf8")).toBe(
        originalReceipts,
      );
      expect(scans).toEqual(["standard"]);
      expect(await readdir(paths.output)).not.toContainEqual(
        expect.stringMatching(/^manifest\.json\..*\.tmp$/),
      );
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 2,
        failed: 0,
        skipped: 1,
      });
      expect(scans).toEqual(["standard", "deep"]);
      expect(await runMultiscan(configured)).toMatchObject({ skipped: 2 });
    },
  );

  test("rejects legacy campaigns when unrecorded inputs are omitted", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-inputs");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const document = join(paths.root, "architecture.md");
    await writeFile(document, "Original context.");
    let calls = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      calls++;
      return completedScan(scanOptions.outputDir!);
    });
    const initial = options(paths, security, {
      knowledgeBasePaths: [document],
      config: { codexOverrides: { model: "synthetic-model" } },
    });
    await runMultiscan(initial);
    expect(await runMultiscan(initial)).toMatchObject({ skipped: 1 });

    const manifestPath = join(paths.output, "manifest.json");
    const { tasks } = JSON.parse(await readFile(manifestPath, "utf8"));
    await writeFile(
      manifestPath,
      JSON.stringify({ version: 1, tasks }, null, 2) + "\n",
    );
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(calls).toBe(1);
  });

  test.each([false, true])(
    "campaign resume binds extracted knowledge from mode settings=%p",
    async (perMode) => {
      const paths = await fixture();
      const source = await repository(paths.root, "knowledge");
      await writeFile(
        paths.input,
        `id,repository,revision\nknowledge,${source.path},${source.revision}\n`,
      );
      const knowledge = join(paths.root, "knowledge-base");
      const nested = join(knowledge, "nested");
      await mkdir(nested, { recursive: true });
      const document = join(knowledge, "architecture.md");
      const deployment = join(nested, "deployment.md");
      const priorities = join(nested, "priorities.md");
      await writeFile(document, "Original context.");
      await writeFile(deployment, "Deployment context.");
      await writeFile(priorities, "Review priorities.");
      let calls = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        calls++;
        return completedScan(scanOptions.outputDir!);
      });
      const run = (
        knowledgeBasePaths: string[],
        overrides: Partial<MultiscanOptions> = {},
      ) =>
        runMultiscan(
          options(paths, security, {
            ...(perMode
              ? { scanOptionsByMode: { standard: { knowledgeBasePaths } } }
              : { knowledgeBasePaths }),
            ...overrides,
          }),
        );
      const recover = { recoverScan: async () => undefined };
      const manifestPath = join(paths.output, "manifest.json");
      let reverseListing = false;
      const originalReaddir = filesystem.readdir;
      const listingSpy = spyOn(filesystem, "readdir").mockImplementation(
        async (...args) => {
          const entries = await Reflect.apply(
            originalReaddir,
            filesystem,
            args,
          );
          if (args[0] === knowledge || args[0] === nested) {
            entries.sort((left: { name: string }, right: { name: string }) =>
              left.name.localeCompare(right.name),
            );
            if (reverseListing) entries.reverse();
          }
          return entries;
        },
      );
      try {
        let attempts = 0;
        for (const failure of [
          "missing",
          ...(process.platform === "win32" ? [] : ["unreadable"]),
          "invalid",
        ]) {
          const moved = `${knowledge}-moved`;
          if (failure === "missing") await rename(knowledge, moved);
          else if (failure === "unreadable") await chmod(document, 0);
          else await writeFile(document, Buffer.from([0xff]));
          try {
            const failed = await run([knowledge], attempts > 0 ? recover : {});
            attempts += 2;
            expect(failed).toMatchObject({
              completed: 0,
              failed: 1,
              skipped: 0,
            });
            const receipts = await results(failed.resultsPath);
            expect(receipts).toHaveLength(attempts);
            expect(receipts.at(-1)).toMatchObject({
              id: "knowledge",
              status: "failed",
              attempt: attempts,
            });
            expect(calls).toBe(0);
            expect(
              JSON.parse(await readFile(manifestPath, "utf8"))
                .knowledgeBaseDigests,
            ).toEqual({ standard: null });
            await expect(run([])).rejects.toThrow("manifest does not match");
            expect(calls).toBe(0);
          } finally {
            if (failure === "missing") await rename(moved, knowledge);
            else if (failure === "unreadable") await chmod(document, 0o600);
            else await writeFile(document, "Original context.");
          }
        }
        await run([knowledge], perMode ? recover : {});
        reverseListing = true;
        expect(await run([knowledge])).toMatchObject({ skipped: 1 });
      } finally {
        listingSpy.mockRestore();
      }
      const boundManifest = await readFile(manifestPath, "utf8");
      const completedReceipt = (
        await results(join(paths.output, "results.jsonl"))
      ).at(-1)!;
      const completedReport = await readFile(
        join(completedReceipt["outputDir"] as string, "report.md"),
        "utf8",
      );
      await writeFile(document, Buffer.from([0xff]));
      await expect(
        run([knowledge], { scanPrompt: "Changed review scope." }),
      ).rejects.toThrow("manifest does not match");
      expect(await run([knowledge], perMode ? recover : {})).toMatchObject({
        completed: 0,
        failed: 1,
        skipped: 0,
      });
      expect(calls).toBe(1);
      expect(await readFile(manifestPath, "utf8")).toBe(boundManifest);
      expect(
        await readFile(
          join(completedReceipt["outputDir"] as string, "report.md"),
          "utf8",
        ),
      ).toBe(completedReport);
      await writeFile(document, "Original context.");
      expect(await run([knowledge], perMode ? recover : {})).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(
        await run(
          perMode ? [knowledge] : [document, deployment, priorities, document],
        ),
      ).toMatchObject({ skipped: 1 });
      if (!perMode) {
        await expect(run([deployment, document, priorities])).rejects.toThrow(
          "manifest does not match",
        );
      }
      await writeFile(document, "Revised context.");
      await expect(run([knowledge])).rejects.toThrow("manifest does not match");
      await writeFile(document, "Original context.");
      const additional = join(knowledge, "constraints.txt");
      await writeFile(additional, "Additional context.");
      await expect(run([knowledge])).rejects.toThrow("manifest does not match");
      await rm(additional);
      expect(await run([knowledge])).toMatchObject({ skipped: 1 });
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      delete manifest.knowledgeBaseDigests;
      await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
      await expect(run([knowledge])).rejects.toThrow("manifest does not match");
      expect(calls).toBe(1);
    },
  );

  test.each([
    ["standard", true],
    ["deep", true],
    ["deep", false],
  ] as const)(
    "knowledge failure in %s preserves other modes with knowledge=%p",
    async (failedMode, goodKnowledge) => {
      const paths = await fixture();
      const source = await repository(paths.root, "mixed-knowledge");
      const goodMode = failedMode === "standard" ? "deep" : "standard";
      await writeFile(
        paths.input,
        `id,repository,revision,mode\nfailed,${source.path},${source.revision},${failedMode}\ngood,${source.path},${source.revision},${goodMode}\n`,
      );
      const missing = join(paths.root, "missing.md");
      const good = join(paths.root, "good.md");
      await writeFile(good, "Original context.");
      const scans: string[] = [];
      const configured = options(
        paths,
        client(async (_repo, scan = {}) => {
          scans.push(scan.mode!);
          return completedScan(scan.outputDir!);
        }),
        {
          maxAttempts: 1,
          scanOptionsByMode: {
            [failedMode]: { knowledgeBasePaths: [missing] },
            ...(goodKnowledge
              ? { [goodMode]: { knowledgeBasePaths: [good] } }
              : {}),
          },
        },
      );
      const initial = await runMultiscan(configured);
      expect(initial).toMatchObject({ completed: 1, failed: 1, skipped: 0 });
      expect(scans).toEqual([goodMode]);
      expect(await results(initial.resultsPath)).toMatchObject([
        { id: "failed", status: "failed", attempt: 1 },
        { id: "good", status: "completed", attempt: 1 },
      ]);
      const manifestPath = join(paths.output, "manifest.json");
      const partialManifest = await readFile(manifestPath, "utf8");
      expect(JSON.parse(partialManifest).knowledgeBaseDigests).toEqual({
        [failedMode]: null,
        ...(goodKnowledge
          ? {
              [goodMode]: workflowDigest({
                "0-good.md.txt": "Original context.",
              }),
            }
          : {}),
      });
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 1,
        skipped: 1,
      });
      expect(scans).toEqual([goodMode]);
      for (const repaired of [false, true]) {
        if (repaired) await writeFile(missing, "Repaired context.");
        if (goodKnowledge) {
          await writeFile(good, "Changed context.");
          await expect(runMultiscan(configured)).rejects.toThrow(
            "manifest does not match",
          );
        }
        expect(await readFile(manifestPath, "utf8")).toBe(partialManifest);
      }
      await writeFile(good, "Original context.");
      expect(
        await runMultiscan({
          ...configured,
          recoverScan: async () => {
            throw new Error("An extraction failure has no scan to recover.");
          },
        }),
      ).toMatchObject({ completed: 2, failed: 0, skipped: 1 });
      expect(scans).toEqual([goodMode, failedMode]);
      expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
        id: "failed",
        status: "completed",
        attempt: 3,
      });
      if (!goodKnowledge) return;
      const boundManifest = await readFile(manifestPath, "utf8");
      await rm(good);
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 1,
        skipped: 1,
      });
      expect(await readFile(manifestPath, "utf8")).toBe(boundManifest);
      await writeFile(good, "Changed context.");
      await expect(runMultiscan(configured)).rejects.toThrow(
        "manifest does not match",
      );
      expect(scans).toEqual([goodMode, failedMode]);
    },
  );

  test("a mode-specific knowledge failure preserves other interrupted scans for recovery", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "mixed-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision,mode\nstandard,${source.path},${source.revision},standard\ndeep,${source.path},${source.revision},deep\n`,
    );
    const document = join(paths.root, "standard.md");
    await writeFile(document, "Original context.");
    let runs = 0;
    const configured = options(
      paths,
      client(async (_repo, scan = {}) => {
        runs++;
        await mkdir(scan.outputDir!, { recursive: true, mode: 0o700 });
        await writeFile(join(scan.outputDir!, "checkpoint"), "keep");
        throw new Error("Interrupted scan");
      }),
      {
        maxAttempts: 1,
        scanOptionsByMode: { standard: { knowledgeBasePaths: [document] } },
      },
    );
    await runMultiscan(configured);
    const resumed: string[] = [];
    const recover = {
      ...configured,
      recoverScan: async (dir: string) => {
        resumed.push(dir);
        return completedScan(dir);
      },
    };
    const standard = join(paths.output, "artifacts", "standard", "attempt-1");
    const deep = join(paths.output, "artifacts", "deep", "attempt-1");
    await rm(document);
    expect(await runMultiscan(recover)).toMatchObject({
      completed: 1,
      failed: 1,
      skipped: 0,
    });
    expect(resumed).toEqual([deep]);
    expect(
      (await results(join(paths.output, "results.jsonl"))).slice(-2),
    ).toMatchObject([
      { id: "standard", status: "failed", attempt: 1, outputDir: standard },
      { id: "deep", status: "completed", attempt: 1, outputDir: deep },
    ]);
    await writeFile(document, "Original context.");
    expect(await runMultiscan(recover)).toMatchObject({
      completed: 2,
      failed: 0,
      skipped: 1,
    });
    expect(resumed).toEqual([deep, standard]);
    expect(runs).toBe(2);
    expect(await readFile(join(standard, "checkpoint"), "utf8")).toBe("keep");
    expect(await readFile(join(deep, "checkpoint"), "utf8")).toBe("keep");
  });

  test("shared knowledge failures affect all modes before mode-specific inputs", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "shared-knowledge");
    await writeFile(
      paths.input,
      `id,repository,revision,mode\nstandard,${source.path},${source.revision},standard\ndeep,${source.path},${source.revision},deep\n`,
    );
    const shared = join(paths.root, "shared.md");
    const perMode = join(paths.root, "per-mode.md");
    await writeFile(perMode, "Mode-specific context.");
    const scans: string[] = [];
    const configured = options(
      paths,
      client(async (_repo, scan = {}) => {
        scans.push(scan.mode!);
        expect(scan.knowledgeBaseSnapshot?.documents).toEqual({
          "0-shared.md.txt": "Shared context.",
        });
        return completedScan(scan.outputDir!);
      }),
      {
        maxAttempts: 1,
        knowledgeBasePaths: [shared],
        scanOptionsByMode: {
          standard: { knowledgeBasePaths: [perMode] },
          deep: { knowledgeBasePaths: [perMode] },
        },
      },
    );
    expect(await runMultiscan(configured)).toMatchObject({
      completed: 0,
      failed: 2,
    });
    expect(scans).toEqual([]);
    await writeFile(shared, "Shared context.");
    await rm(perMode);
    expect(await runMultiscan(configured)).toMatchObject({
      completed: 2,
      failed: 0,
    });
    expect(scans).toEqual(["standard", "deep"]);
  });

  test.each([false, true])(
    "campaign workers stage the fingerprinted snapshot with mode settings=%p",
    async (perMode) => {
      const paths = await fixture();
      const source = await repository(paths.root, "snapshot");
      const modes = ["standard", "deep", "standard", "deep"] as const;
      await writeFile(
        paths.input,
        "id,repository,revision,mode\n" +
          modes
            .map(
              (mode, index) =>
                `repo-${index},${source.path},${source.revision},${mode}`,
            )
            .join("\n") +
          "\n",
      );
      const standard = join(paths.root, "architecture.md");
      const deep = join(paths.root, "threat-model.txt");
      await writeFile(standard, "Original architecture.");
      await writeFile(deep, "Original threat model.");
      const homes = [join(paths.root, "home-1"), join(paths.root, "home-2")];
      await Promise.all(homes.map((home) => mkdir(home)));
      let created = 0;
      let calls = 0;
      const staged: Record<string, string>[] = [];
      const recipes: Record<string, unknown>[] = [];
      const summary = await runMultiscan(
        options(
          paths,
          client(async () => {
            throw new Error("Unexpected client");
          }),
          {
            workers: 2,
            maxAttempts: 1,
            ...(perMode ? {} : { knowledgeBasePaths: [standard] }),
            scanOptionsByMode: {
              standard: { knowledgeBasePaths: [standard] },
              deep: { knowledgeBasePaths: [deep] },
            },
            createSecurity: (config) => {
              const home = homes[created++]!;
              return new TestClient(config, {
                environment: {},
                prepareRuntime: async () => preparedRuntime(home),
                resolvePluginPython: async () => "/managed/python",
                repositoryRevision: async () => source.revision,
                runWorkbench: async (_options, args, input) => {
                  if (args[0] === "register-cli-scan")
                    recipes.push(JSON.parse(input!).recipe);
                  return mockWorkbench(args, input);
                },
                createCodex: (codex) => ({
                  startThread: () => ({
                    id: null,
                    async runStreamed() {
                      const first = calls++ === 0;
                      if (first) {
                        await writeFile(
                          standard,
                          "Changed after the manifest was saved.",
                        );
                        await rm(deep);
                      }
                      const directory =
                        codex.env!["CODEX_SECURITY_KNOWLEDGE_BASE"]!;
                      staged.push(
                        Object.fromEntries(
                          await Promise.all(
                            (await readdir(directory)).map(async (name) => [
                              name,
                              await readFile(join(directory, name), "utf8"),
                            ]),
                          ),
                        ),
                      );
                      throw new Error(
                        "Synthetic model stop after reading staged knowledge.",
                      );
                    },
                  }),
                }),
              });
            },
          },
        ),
      );
      expect(created).toBe(2);
      expect(calls).toBe(4);
      expect(summary).toMatchObject({ total: 4, failed: 4 });
      expect(
        (await results(summary.resultsPath)).every((row) =>
          String(row["error"]).includes("Synthetic model stop"),
        ),
      ).toBe(true);
      const standardDocuments = {
        "0-architecture.md.txt": "Original architecture.",
      };
      const deepDocuments = perMode
        ? { "0-threat-model.txt.txt": "Original threat model." }
        : standardDocuments;
      expect(
        staged.filter(
          (documents) =>
            JSON.stringify(documents) === JSON.stringify(standardDocuments),
        ),
      ).toHaveLength(perMode ? 2 : 4);
      if (perMode)
        expect(
          staged.filter(
            (documents) =>
              JSON.stringify(documents) === JSON.stringify(deepDocuments),
          ),
        ).toHaveLength(2);
      for (const recipe of recipes) {
        expect(recipe["knowledgeBasePaths"]).toEqual([
          perMode && recipe["mode"] === "deep" ? deep : standard,
        ]);
        expect(recipe["knowledgeBaseSnapshot"]).toBeUndefined();
      }
      const manifestText = await readFile(
        join(paths.output, "manifest.json"),
        "utf8",
      );
      expect(JSON.parse(manifestText).knowledgeBaseDigests).toEqual({
        standard: workflowDigest(standardDocuments),
        deep: workflowDigest(deepDocuments),
      });
      expect(manifestText).not.toContain("Original architecture.");
      expect(manifestText).not.toContain("Original threat model.");
    },
  );

  test("renaming a top-level knowledge document invalidates saved results", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "renamed-knowledge");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const document = join(paths.root, "architecture.md");
    const renamed = join(paths.root, "deployment.md");
    await writeFile(document, "Unchanged text.");
    const security = client(async (_repository, scan = {}) =>
      completedScan(scan.outputDir!),
    );
    await runMultiscan(
      options(paths, security, { knowledgeBasePaths: [document] }),
    );
    await rename(document, renamed);
    await expect(
      runMultiscan(options(paths, security, { knowledgeBasePaths: [renamed] })),
    ).rejects.toThrow("manifest does not match");
  });

  test.each([
    ["pluginPath", false],
    ["pluginPath", true],
    ["pythonPath", false],
    ["pythonPath", true],
  ] as const)(
    "campaign binds explicit %s before client creation and recovery=%p",
    async (field, recovery) => {
      const paths = await fixture();
      const source = await repository(paths.root, "runtime-selection");
      await writeFile(
        paths.input,
        `id,repository,revision\ndone,${source.path},${source.revision}\npending,${source.path},${source.revision}\n`,
      );
      const pending = join(paths.output, "artifacts", "pending", "attempt-1");
      const run = mock(
        async (
          _repository: string,
          scan: Parameters<SecurityClient["run"]>[1] = {},
        ) => {
          if (scan.outputDir === pending) {
            await mkdir(pending, { recursive: true });
            await writeFile(
              join(pending, "checkpoint"),
              "Preserve this attempt.",
            );
            throw new Error("Synthetic interruption before completion.");
          }
          return completedScan(scan.outputDir!);
        },
      );
      const security = client(run);
      const createSecurity = mock(
        (_config: MultiscanOptions["config"]) => security,
      );
      const recoverScan = mock(async (scanDir: string) =>
        completedScan(scanDir),
      );
      const config: MultiscanOptions["config"] = {
        [field]: field === "pythonPath" ? PYTHON : PLUGIN_ROOT,
      };
      const configured = options(paths, security, {
        config,
        createSecurity,
        maxAttempts: 1,
      });
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 1,
      });
      const manifest = await readFile(
        join(paths.output, "manifest.json"),
        "utf8",
      );
      const receipts = await readFile(
        join(paths.output, "results.jsonl"),
        "utf8",
      );
      const continuation = {
        ...configured,
        workers: 3,
        maxAttempts: 4,
        ...(recovery ? { recoverScan } : {}),
      };
      for (const changed of [
        { [field]: join(paths.root, "other-runtime") },
        {},
      ]) {
        await expect(
          runMultiscan({ ...continuation, config: changed }),
        ).rejects.toThrow("manifest does not match");
        expect(createSecurity).toHaveBeenCalledTimes(1);
        expect(run).toHaveBeenCalledTimes(2);
        expect(recoverScan).not.toHaveBeenCalled();
        expect(
          await readFile(join(paths.output, "manifest.json"), "utf8"),
        ).toBe(manifest);
        expect(
          await readFile(join(paths.output, "results.jsonl"), "utf8"),
        ).toBe(receipts);
      }
      expect(await runMultiscan(continuation)).toMatchObject({
        completed: 2,
        failed: 0,
        skipped: 1,
      });
      expect(createSecurity).toHaveBeenLastCalledWith(config);
      expect(recoverScan).toHaveBeenCalledTimes(recovery ? 1 : 0);
      expect(run).toHaveBeenCalledTimes(recovery ? 2 : 3);
      expect(await readFile(join(pending, "checkpoint"), "utf8")).toBe(
        "Preserve this attempt.",
      );
      expect(await readFile(join(paths.output, "manifest.json"), "utf8")).toBe(
        manifest,
      );
    },
  );

  test("campaign preserves absent runtime selections and rejects adding one", async () => {
    const { paths } = await repositoryFixture("default-runtime");
    const security = client(completeRun);
    const createSecurity = mock(() => security);
    const configured = options(paths, security, { createSecurity });
    await runMultiscan(configured);
    const manifest = await readFile(
      join(paths.output, "manifest.json"),
      "utf8",
    );
    expect(JSON.parse(manifest).configurationDigest).toBeUndefined();
    for (const field of ["pluginPath", "pythonPath"] as const) {
      await expect(
        runMultiscan({
          ...configured,
          config: { [field]: join(paths.root, "selected-runtime") },
        }),
      ).rejects.toThrow("manifest does not match");
    }
    expect(
      await runMultiscan({
        ...configured,
        workers: 3,
        maxAttempts: 4,
        config: { pluginPath: undefined, pythonPath: undefined },
      }),
    ).toMatchObject({ skipped: 1 });
    expect(createSecurity).toHaveBeenCalledTimes(1);
    expect(await readFile(join(paths.output, "manifest.json"), "utf8")).toBe(
      manifest,
    );
  });

  test.each([false, true])(
    "campaign resume binds overrides with configured modes=%p",
    async (configuredModes) => {
      const paths = await fixture();
      const source = await repository(paths.root, "configuration");
      await writeFile(
        paths.input,
        `id,repository,revision\nconfiguration,${source.path},${source.revision}\n`,
      );
      let calls = 0;
      const security = client(async (repository, scanOptions = {}) => {
        calls++;
        return configuredModes
          ? completedConfiguredPaths(repository, scanOptions)
          : completedScan(scanOptions.outputDir!);
      });
      const initial = options(paths, security, {
        ...(configuredModes
          ? { scanOptionsByMode: { standard: { target: ["src"] } } }
          : {}),
        config: {
          codexOverrides: {
            model: "synthetic-model",
            features: { example: true },
          },
        },
      });
      await runMultiscan(initial);
      expect(
        await runMultiscan({
          ...initial,
          workers: 3,
          maxAttempts: 4,
          config: {
            codexOverrides: {
              features: { example: true },
              model: "synthetic-model",
            },
          },
        }),
      ).toMatchObject({ skipped: 1 });
      await expect(
        runMultiscan({
          ...initial,
          config: {
            codexOverrides: {
              model: "changed-model",
              features: { example: true },
            },
          },
        }),
      ).rejects.toThrow("manifest does not match");
      const manifestPath = join(paths.output, "manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      delete manifest.configurationDigest;
      await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
      await expect(runMultiscan(initial)).rejects.toThrow(
        "manifest does not match",
      );
      expect(calls).toBe(1);
    },
  );

  test("rejects unsafe input without starting scans or exposing URL credentials", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "safe");
    const secret = "MULTISCAN_CREDENTIAL_SHOULD_NOT_APPEAR";
    const invalid = [
      {
        name: "task-id",
        row: `../escape,${source.path},${source.revision},.`,
      },
      {
        name: "windows-alias",
        row: `report,${source.path},${source.revision},.\nreport.,${source.path},${source.revision},.`,
      },
      {
        name: "scope",
        row: `safe,${source.path},${source.revision},../outside`,
      },
      ...(process.platform === "win32"
        ? [
            {
              name: "windows-qualified-scope",
              row: `safe,${source.path},${source.revision},src:stream`,
            },
          ]
        : []),
      {
        name: "revision",
        row: `safe,${source.path},HEAD,.`,
      },
      {
        name: "duplicate-id",
        row: `safe,${source.path},${source.revision},.\nsafe,${source.path},${source.revision},.`,
      },
      {
        name: "credentials",
        row: `safe,https://user:${secret}@example.test/private.git,${source.revision},.`,
      },
    ];
    const security = client(mock(completeRun));

    for (const entry of invalid) {
      await writeFile(
        paths.input,
        `id,repository,revision,scope\n${entry.row}\n`,
      );
      const output = join(paths.root, entry.name);
      const error = await runMultiscan(
        options(paths, security, { outputDir: output }),
      ).then(
        () => null,
        (reason: unknown) => reason,
      );
      expect(error, entry.name).toBeInstanceOf(Error);
      if (entry.name === "credentials")
        expect(String(error)).not.toContain(secret);
    }

    expect(security.run.mock.calls.length).toBe(0);
  });
});

type ScanSettings = NonNullable<Parameters<SecurityClient["run"]>[1]>;
type CampaignPaths = Awaited<ReturnType<typeof fixture>>;
type CampaignSource = Awaited<ReturnType<typeof repository>>;

function writeRecoveryTask(
  paths: CampaignPaths,
  source: CampaignSource,
  scope?: string,
  revision = source.revision,
) {
  const columns = scope
    ? "id,repository,revision,scope"
    : "id,repository,revision";
  const row = ["repo", source.path, revision];
  if (scope) row.push(scope);
  return writeFile(paths.input, `${columns}\n${row.join(",")}\n`);
}

async function scopedRepository(name: string) {
  const paths = await fixture();
  const source = await repository(paths.root, name);
  await writeRecoveryTask(paths, source, "src");
  return { paths, source };
}

function commitFixture(repo: string, message: string) {
  git(
    repo,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.test",
    "commit",
    "-qm",
    message,
  );
}

function savedCampaign(
  paths: CampaignPaths,
  overrides: Partial<MultiscanOptions> = {},
) {
  const runs = mock(completeRun);
  return { runs, campaign: options(paths, client(runs), overrides) };
}

async function cloneWithoutScope(paths: CampaignPaths, source: CampaignSource) {
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  return checkout;
}

function interruptCampaign(paths: CampaignPaths) {
  return runMultiscan(
    options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
  );
}

async function completedRetry(
  paths: CampaignPaths,
  overrides: Partial<MultiscanOptions> = {},
  run: SecurityClient["run"] = completeRun,
) {
  await runMultiscan(
    options(paths, client(rejecting("Interrupted")), {
      ...overrides,
      maxAttempts: 1,
    }),
  );
  const runs = mock(run);
  const campaign = options(paths, client(runs), {
    ...overrides,
    recoverScan: async () => undefined,
  });
  const initial = await expectScanned(campaign);
  return { campaign, runs, initial };
}

function recoveryCheckout(paths: CampaignPaths) {
  return join(paths.output, "recovery-checkouts", "repo", "attempt-2");
}

async function expectScanned(campaign: MultiscanOptions) {
  const summary = await runMultiscan(campaign);
  expect(summary).toMatchObject({ completed: 1, skipped: 0 });
  return summary;
}

async function expectReused(campaign: MultiscanOptions) {
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
}

test("qualified campaign reuses a completed recovery checkout", async () => {
  const { paths, source } = await repositoryFixture("recovery-source", "repo");
  await interruptCampaign(paths);
  const originalCheckout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, originalCheckout);
  const originalIdentity = await lstat(originalCheckout);
  const { runs, campaign } = savedCampaign(paths, {
    recoverScan: async () => undefined,
  });
  await expectScanned(campaign);
  await expectReused(campaign);
  expect(runs).toHaveBeenCalledTimes(1);
  const retainedIdentity = await lstat(originalCheckout);
  expect([retainedIdentity.dev, retainedIdentity.ino]).toEqual([
    originalIdentity.dev,
    originalIdentity.ino,
  ]);
});

for (const target of [["src"], ["src", "src/app.ts"]]) {
  test(`qualified campaign retains configured scopes ${target.join(",")}`, async () => {
    const { paths } = await repositoryFixture("configured-source", "repo");
    const runs = mock(completedConfiguredPaths);
    const campaign = options(paths, client(runs), {
      scanOptionsByMode: { standard: { target } },
    });
    await runMultiscan(campaign);
    expect(runs.mock.calls[0]![1]!.target).toEqual(target);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const orphaned of [false, true]) {
  testPosix(
    `qualified campaign retains resolved scope after ${orphaned ? "orphaned" : "recorded"} recovery`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "resolved-source");
      await symlink("src", join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      commitFixture(source.path, "Add directory alias");
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nRepo,${source.path},${revision},alias\n`,
      );
      const interrupted = client(async (checkout: string, settings = {}) => {
        await completedScan(settings.outputDir!, "partial", checkout);
        throw new Error("Interrupted after saved progress");
      });
      const initial = await runMultiscan(
        options(paths, interrupted, { maxAttempts: 1 }),
      );
      if (orphaned) await writeFile(initial.resultsPath, "");
      const recoverScan = mock(async (dir: string) => {
        const result = await completedScan(dir);
        result.manifest.scan.scope.includePaths = ["src"];
        await writeFile(
          join(dir, "scan-manifest.json"),
          JSON.stringify(result.manifest),
        );
        const coveragePath = join(dir, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        coverage.includePaths = ["src"];
        await writeFile(coveragePath, JSON.stringify(coverage));
        await reseal(dir);
        return {
          manifest: result.manifest,
          cost: null,
          findings: (await loadContract(dir, { pluginRoot: PLUGIN_ROOT }))
            .findings,
        };
      });
      const runs = mock(completeRun);
      const recovered = await runMultiscan(
        options(paths, client(runs), { recoverScan }),
      );
      expect((await results(recovered.resultsPath)).at(-1)).toMatchObject({
        status: "completed",
        resolvedScope: "src",
      });
      expect(await runMultiscan(options(paths, client(runs)))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(0);
    },
  );
}

test("qualified campaign keeps a recorded checkout while rejecting a failed sealed attempt", async () => {
  const { paths, source } = await scopedRepository("retained-checkout-source");
  let checkout = "";
  await runMultiscan(
    options(
      paths,
      client(async (root, settings = {}) => {
        checkout = root;
        await completedScan(settings.outputDir!, "complete", root);
        throw new Error("Synthetic interruption after saved artifacts");
      }),
      { maxAttempts: 1 },
    ),
  );
  // Restore the owned fixture checkout that an interrupted process would retain.
  git(paths.root, "clone", "--quiet", source.path, checkout);
  const before = await lstat(checkout);
  let preserved = false;
  const runs = mock(completeRun);
  const recoverScan = mock(async (dir: string) => {
    const current = await lstat(checkout).catch(() => undefined);
    preserved = current?.dev === before.dev && current?.ino === before.ino;
    return completedScan(dir, "complete", checkout);
  });
  expect(
    await runMultiscan(options(paths, client(runs), { recoverScan })),
  ).toMatchObject({ completed: 1, failed: 0 });
  expect(preserved).toBe(true);
  expect(runs).toHaveBeenCalledTimes(0);
  expect(recoverScan).toHaveBeenCalledTimes(1);
});

test.each(["checkouts", "recovery-checkouts"] as const)(
  "completed reuse preserves the retained %s checkout when its source is unavailable",
  async (layout) => {
    const { paths, source } = await scopedRepository("retained-reuse-source");
    const campaign = options(paths, client(rejecting("Interrupted scan")), {
      maxAttempts: 1,
    });
    await runMultiscan(campaign);
    const dir = join(paths.output, "artifacts", "repo", "attempt-1");
    await mkdir(dir, { recursive: true });
    const checkout = join(
      paths.output,
      layout,
      "repo",
      ...(layout === "recovery-checkouts" ? ["attempt-1"] : []),
    );
    await mkdir(dirname(checkout), { recursive: true });
    git(paths.root, "clone", "--quiet", source.path, checkout);
    const marker = join(checkout, "retained.txt");
    await writeFile(marker, "Preserved interrupted checkout data.\n");
    const identity = await lstat(checkout);
    const recoverScan = mock((scanDir: string) =>
      completedScan(scanDir, "complete", checkout),
    );
    const runs = mock(completeRun);
    expect(
      await runMultiscan({
        ...campaign,
        createSecurity: () => client(runs),
        recoverScan,
      }),
    ).toMatchObject({ completed: 1, failed: 0 });
    await rename(
      source.path,
      join(paths.root, "temporarily-unavailable-source"),
    );
    for (let attempt = 0; attempt < 2; attempt += 1) {
      expect(
        await runMultiscan({ ...campaign, createSecurity: () => client(runs) }),
      ).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
      const retained = await lstat(checkout);
      expect([retained.dev, retained.ino]).toEqual([
        identity.dev,
        identity.ino,
      ]);
      expect(await readFile(marker, "utf8")).toBe(
        "Preserved interrupted checkout data.\n",
      );
    }
    expect(runs).toHaveBeenCalledTimes(0);
    expect(recoverScan).toHaveBeenCalledTimes(1);
  },
);

test("qualified campaign replays warnings only from accepted saved attempts", async () => {
  const { paths } = await repositoryFixture("saved-warning-source", "repo");
  const warning = "Synthetic saved-attempt warning";
  let attempts = 0;
  const security = client(async (_root, settings = {}) => {
    attempts += 1;
    if (attempts === 1) settings.onWarning?.(warning);
    return completedScan(settings.outputDir!);
  });
  const campaign = options(paths, security);
  const first = await runMultiscan(campaign);
  expect(first.warnings).toEqual([{ repository: "repo", warnings: [warning] }]);
  const acceptedProgress: string[] = [];
  expect(
    await runMultiscan({
      ...campaign,
      onProgress: (event) => {
        if (event.warning) acceptedProgress.push(event.warning);
      },
    }),
  ).toMatchObject({
    skipped: 1,
    warnings: [{ repository: "repo", warnings: [warning] }],
  });
  expect(acceptedProgress).toEqual([warning]);
  const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
  await appendFile(join(dir, "findings.json"), " ");
  const freshProgress: string[] = [];
  const fresh = await runMultiscan({
    ...campaign,
    onProgress: (event) => {
      if (event.warning) freshProgress.push(event.warning);
    },
  });
  expect(fresh).toMatchObject({ completed: 1, skipped: 0 });
  expect(fresh).not.toHaveProperty("warnings");
  expect(freshProgress).toEqual([]);
  expect(attempts).toBe(2);
});

test("failed repair preserves the retained checkout and completed receipt", async () => {
  const { paths, source } = await scopedRepository("unavailable-scoped-source");
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs), { maxAttempts: 1 });
  const initial = await runMultiscan(campaign);
  const ledger = await readFile(initial.resultsPath, "utf8");
  const checkout = join(paths.output, "checkouts", "repo");
  await mkdir(checkout);
  const marker = join(checkout, "notes.txt");
  await writeFile(marker, "Retained edits.");
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  await expect(runMultiscan(campaign)).rejects.toThrow();
  expect(await readFile(initial.resultsPath, "utf8")).toBe(ledger);
  expect(await readFile(marker, "utf8")).toBe("Retained edits.");
  expect(runs).toHaveBeenCalledTimes(1);
});

for (const spelling of [
  "absolute",
  "home",
  "parent alias",
  "ancestor relative",
] as const) {
  const platformTest = spelling === "absolute" ? test : testPosix;
  platformTest(
    `resumes a configured scope with ${spelling} spelling`,
    async () => {
      const { paths } = await repositoryFixture("configured-scope", "repo");
      const original = join(paths.output, "checkouts", "repo", "src");
      let requested = original;
      if (spelling === "home")
        requested = `~/${relative(homedir(), original).split(sep).join("/")}`;
      if (spelling === "ancestor relative")
        requested = "../../checkouts/repo/src";
      if (spelling === "parent alias") {
        const alias = join(paths.root, "campaign-alias");
        await symlink(paths.output, alias, "dir");
        requested = join(alias, "checkouts", "repo", "src");
      }
      const runs = mock(
        async (checkout: string, settings: ScanSettings = {}) => {
          const result = await completedConfiguredPaths(checkout, settings);
          expect(result.manifest.scan.scope.includePaths).toEqual(["src"]);
          return result;
        },
      );
      const campaign = options(paths, client(runs), {
        scanOptionsByMode: { standard: { target: [requested] } },
      });
      await expectScanned(campaign);
      await expectReused(campaign);
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

test("qualified campaign recovers its report from an unrelated Python invocation directory", async () => {
  const invocation = await fixture();
  if (
    await runTestInSubprocess(
      fileURLToPath(import.meta.url),
      "qualified campaign recovers its report from an unrelated Python invocation directory",
      {},
      invocation.root,
    )
  )
    return;
  const { paths } = await repositoryFixture("python-invocation-source", "repo");
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs), {
    config: { pythonPath: PYTHON },
  });
  const initial = await runMultiscan(campaign);
  const ledger = await readFile(initial.resultsPath, "utf8");
  await expectReused(campaign);
  expect(await readFile(initial.resultsPath, "utf8")).toBe(ledger);
  expect(runs).toHaveBeenCalledTimes(1);
});

testPosix(
  "resume compatibility retains a tracked scope alias anchored to its checkout basename",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "scope-layout-source");
    await symlink("../repo/src", join(source.path, "alias"), "dir");
    git(source.path, "add", "alias");
    commitFixture(source.path, "add checkout-relative scope alias");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "alias", revision);
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

testPosix(
  "resume compatibility preserves a recovery checkout reached through a directory link",
  async () => {
    const { paths, source } = await repositoryFixture(
      "linked-recovery-source",
      "repo",
    );
    await interruptCampaign(paths);
    const { runs, campaign } = savedCampaign(paths, {
      recoverScan: async () => undefined,
    });
    await expectScanned(campaign);
    const taskRoot = join(paths.output, "recovery-checkouts", "repo");
    // Recreate the owned checkout retained by interruption after receipt publication.
    git(
      paths.root,
      "clone",
      "--quiet",
      source.path,
      join(taskRoot, "attempt-2"),
    );
    const retained = join(paths.root, "retained-recovery");
    await rename(taskRoot, retained);
    await symlink(retained, taskRoot, "dir");
    const marker = join(retained, "attempt-2", "retained.txt");
    await writeFile(marker, "retained recovery checkout\n");
    await expectReused(campaign);
    expect(await readFile(marker, "utf8")).toBe("retained recovery checkout\n");
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("resume compatibility recovers a failed completed bundle without fetching its unavailable source", async () => {
  const { paths, source } = await scopedRepository("failed-completed-source");
  await runMultiscan(
    options(
      paths,
      client(async (checkout, settings = {}) => {
        await completedScan(settings.outputDir!, "complete", checkout);
        throw new Error("Synthetic failure after saved completion");
      }),
      { maxAttempts: 1 },
    ),
  );
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  const runs = mock(completeRun);
  const recoverScan = mock(async (dir: string) => {
    const saved = await loadContract(dir, { pluginRoot: PLUGIN_ROOT });
    return { ...saved, cost: null };
  });
  expect(
    await runMultiscan(options(paths, client(runs), { recoverScan })),
  ).toMatchObject({ completed: 1, failed: 0 });
  expect(recoverScan).toHaveBeenCalledTimes(1);
  expect(runs).toHaveBeenCalledTimes(0);
});

for (const section of ["rootCause", "validation", "attackPath"] as const) {
  const catalogs =
    section === "rootCause"
      ? ["present", "absent", "matched", "duplicate"]
      : ["present", "absent"];
  for (const catalog of catalogs) {
    test(`reuses legacy ${section} references with ${catalog} evidence catalog`, async () => {
      const { paths } = await repositoryFixture("legacy-reference", "repo");
      const { runs, campaign } = savedCampaign(paths);
      const first = await expectScanned(campaign);
      const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
      const path = join(dir, "findings.json");
      const saved = JSON.parse(
        await readFile(path, "utf8"),
      ) as ScanResult["findings"];
      const finding = saved.findings[0]!;
      if (catalog !== "absent") {
        const evidence = { id: "saved-evidence", code: "extract()" };
        finding.code_evidence =
          catalog === "duplicate" ? [evidence, evidence] : [evidence];
      }
      finding[section] = {
        summary: "Existing saved source evidence",
        evidenceRefs:
          catalog === "matched" || catalog === "duplicate"
            ? ["saved-evidence"]
            : ["saved-evidence", "obsolete-evidence"],
      };
      await writeFile(path, JSON.stringify(saved));
      await reseal(dir);
      const loaded = (await loadContract(dir, { pluginRoot: PLUGIN_ROOT }))
        .findings.findings[0]!;
      expect(loaded[section]).toEqual(finding[section]);
      expect(loaded.code_evidence).toEqual(finding.code_evidence);
      const bytes = await readFile(path);
      await expectReused(campaign);
      expect(runs).toHaveBeenCalledTimes(1);
      expect(await readFile(path)).toEqual(bytes);
    });
  }
}

for (const spelling of [
  "plain",
  "ancestor relative",
  "absolute link",
] as const) {
  testPosix(
    `original coordinates preserve tracked scope with ${spelling} spelling`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "coordinate-source");
      const destination =
        spelling === "absolute link"
          ? join(paths.output, "checkouts", "repo", "src")
          : spelling === "ancestor relative"
            ? "../../checkouts/repo/src"
            : "src";
      await symlink(destination, join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      commitFixture(source.path, "add supported scope link");
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source, "alias", revision);
      const { runs, campaign } = savedCampaign(paths);
      await expectScanned(campaign);
      await expectReused(campaign);
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

test("original coordinates reuse an existing pinned scope checkout without refetching", async () => {
  const { paths, source } = await scopedRepository(
    "retained-coordinate-source",
  );
  const { runs, campaign } = savedCampaign(paths);
  await expectScanned(campaign);
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  await expectReused(campaign);
  expect(runs).toHaveBeenCalledTimes(1);
});

(process.platform === "win32" ? test : test.skip)(
  "original coordinates retain canonical Windows checkout parent spelling",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "windows-coordinate-source");
    await mkdir(join(paths.output, "CHECKOUTS"), {
      recursive: true,
      mode: 0o700,
    });
    await writeRecoveryTask(paths, source, "src");
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

(process.platform === "win32" ? test : test.skip)(
  "original coordinates retain canonical Windows recovery parent spelling",
  async () => {
    const paths = await fixture();
    const source = await repository(
      paths.root,
      "windows-recovery-coordinate-source",
    );
    await mkdir(join(paths.output, "RECOVERY-CHECKOUTS"), {
      recursive: true,
      mode: 0o700,
    });
    await writeRecoveryTask(paths, source, "src");
    await interruptCampaign(paths);
    const { runs, campaign } = savedCampaign(paths, {
      recoverScan: async () => undefined,
    });
    await expectScanned(campaign);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const recovery of [false, true]) {
  for (const partial of ["empty", "missing subtree"] as const) {
    test(`retained preparation completes ${recovery ? "recovery" : "normal"} checkout with ${partial}`, async () => {
      const { paths, source } = await scopedRepository(
        "partial-checkout-source",
      );
      if (recovery) await interruptCampaign(paths);
      const runs = mock(completeRun);
      const campaign = options(
        paths,
        client(runs),
        recovery ? { recoverScan: async () => undefined } : {},
      );
      await expectScanned(campaign);
      const checkout = recovery
        ? recoveryCheckout(paths)
        : join(paths.output, "checkouts", "repo");
      if (partial === "empty")
        await mkdir(checkout, { recursive: true, mode: 0o700 });
      else {
        git(paths.root, "clone", "--quiet", source.path, checkout);
        await rm(join(checkout, "src"), { recursive: true });
      }
      const retained = join(checkout, "retained.txt");
      await writeFile(retained, "Preserved interrupted checkout data.\n");
      await expectReused(campaign);
      expect(runs).toHaveBeenCalledTimes(1);
      if (recovery)
        expect(await readFile(retained, "utf8")).toBe(
          "Preserved interrupted checkout data.\n",
        );
    });
  }
}

testPosix.each(["source", "campaign"] as const)(
  "reuses an explicitly configured %s-local Python interpreter",
  async (location) => {
    const paths = await fixture();
    const source = await repository(paths.root, "source-local-python");
    const interpreter =
      location === "source"
        ? join(source.path, ".venv", "bin", "python")
        : join(paths.output, "tools", "bin", "python");
    await mkdir(dirname(interpreter), { recursive: true });
    await writeFile(
      interpreter,
      `#!/usr/bin/env node\nconst {spawnSync} = require("node:child_process");\nconst result = spawnSync(${JSON.stringify(PYTHON)}, process.argv.slice(2), {stdio: "inherit"});\nif (result.error) throw result.error;\nprocess.exit(result.status ?? 1);\n`,
      { mode: 0o700 },
    );
    expect((await lstat(interpreter)).isFile()).toBe(true);
    await writeRecoveryTask(paths, source);
    const runs = mock(async (checkout: string, settings: ScanSettings = {}) => {
      const selected = await runtime.resolvePluginPythonCommand({
        configuredPath: interpreter,
        protectedRoot: checkout,
        environment: runtime.pluginHelperEnvironment(process.env),
      });
      expect(selected.executable).toBe(interpreter);
      return completedScan(settings.outputDir!, "complete", checkout);
    });
    const campaign = options(paths, client(runs), {
      config: { pythonPath: interpreter },
    });
    await expectScanned(campaign);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const binding of ["gitfile", "worktree", "common", "objects"] as const) {
  test(`retained Git bindings keep ${binding} writes inside the campaign checkout`, async () => {
    const { paths, source } = await scopedRepository("retained-binding-source");
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    const outside = await repository(paths.root, "other-owned-repository");
    await writeFile(
      join(outside.path, "retained-marker.txt"),
      "Preserve the other repository.\n",
    );
    git(outside.path, "add", ".");
    commitFixture(outside.path, "Other repository state");
    const originalHead = git(outside.path, "rev-parse", "HEAD");
    const originalFiles = await readFile(
      join(outside.path, "retained-marker.txt"),
      "utf8",
    );
    const checkout = await cloneWithoutScope(paths, source);
    if (binding === "gitfile") {
      await rm(join(checkout, ".git"), { recursive: true, force: true });
      await writeFile(
        join(checkout, ".git"),
        `gitdir: ${join(outside.path, ".git")}\n`,
      );
    } else if (binding === "worktree") {
      git(checkout, "config", "core.worktree", outside.path);
    } else if (binding === "common") {
      await writeFile(
        join(checkout, ".git", "commondir"),
        `${join(outside.path, ".git")}\n`,
      );
    } else {
      await rm(join(checkout, ".git", "objects"), {
        recursive: true,
        force: true,
      });
      await symlink(
        join(outside.path, ".git", "objects"),
        join(checkout, ".git", "objects"),
        "junction",
      );
    }
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(git(outside.path, "rev-parse", "HEAD")).toBe(originalHead);
    expect(
      await readFile(join(outside.path, "retained-marker.txt"), "utf8"),
    ).toBe(originalFiles);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

(process.platform === "win32" ? test : test.skip)(
  "retained Git bindings reject a Windows recovery parent junction before checkout writes",
  async () => {
    const { paths, source } = await scopedRepository("junction-source");
    await interruptCampaign(paths);
    const externalParent = join(paths.root, "other-recovery-parent");
    await mkdir(externalParent);
    const externalCheckout = join(externalParent, "attempt-2");
    git(paths.root, "clone", "--quiet", source.path, externalCheckout);
    const runs = mock(async (_checkout: string, settings: ScanSettings = {}) =>
      completedScan(settings.outputDir!, "complete", externalCheckout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    await expectScanned(campaign);
    await rename(externalCheckout, join(externalParent, "retained-attempt"));
    const lexicalParent = join(paths.output, "recovery-checkouts", "repo");
    await rm(lexicalParent, { recursive: true, force: true });
    await symlink(externalParent, lexicalParent, "junction");
    await expect(runMultiscan(campaign)).rejects.toThrow();
    await expect(lstat(externalCheckout)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const entry of ["config", "FETCH_HEAD", "logs/HEAD", "logs"] as const) {
  test(`recovery refuses a linked Git ${entry} before external bytes change`, async () => {
    const { paths, source } = await scopedRepository("metadata-source");
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    const checkout = await cloneWithoutScope(paths, source);
    const outside = await repository(paths.root, "other-metadata-repository");
    git(outside.path, "config", "core.filemode", "false");
    const target = join(outside.path, ".git", entry);
    if (entry === "FETCH_HEAD")
      await writeFile(target, "Preserve external metadata.\n");
    const sentinel = entry === "logs" ? join(target, "HEAD") : target;
    const bytes = await readFile(sentinel);
    const local = join(checkout, ".git", entry);
    await rm(local, { recursive: true, force: true });
    await symlink(target, local, entry === "logs" ? "junction" : undefined);
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(await readFile(sentinel)).toEqual(bytes);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const partial of [false, true, "refs", "blob", "tree", "umask"] as const) {
  test(`metadata recovery restores an interrupted repository with removed metadata=${partial}`, async () => {
    const { paths, source } = await scopedRepository("partial-metadata-source");
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    const checkout = join(paths.output, "checkouts", "repo");
    const previousUmask = process.umask();
    if (partial === "umask") process.umask(0o002);
    try {
      git(paths.root, "clone", "--quiet", source.path, checkout);
      if (partial === "umask") await chmod(checkout, 0o700);
      if (partial === "blob" || partial === "tree") {
        const object = git(
          checkout,
          "rev-parse",
          partial === "blob" ? "HEAD:src/app.ts" : "HEAD^{tree}",
        );
        await rm(
          join(
            checkout,
            ".git",
            "objects",
            object.slice(0, 2),
            object.slice(2),
          ),
        );
      }
      await rm(join(checkout, "src"), { recursive: true });
      if (partial === true) await rm(join(checkout, ".git", "HEAD"));
      if (partial === "refs")
        await rm(join(checkout, ".git", "refs"), { recursive: true });
      await writeFile(
        join(checkout, "retained.txt"),
        "Preserve interrupted data.\n",
      );
      await expectReused(campaign);
      expect(runs).toHaveBeenCalledTimes(1);
    } finally {
      process.umask(previousUmask);
    }
  });
}

for (const modified of [
  false,
  true,
  "deleted",
  "deleted-missing-index",
] as const) {
  test(`preserved recovery data retains unrelated tracked modifications=${modified}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "preserved-tracked-source");
    await writeFile(
      join(source.path, "README.md"),
      "Original tracked notes.\n",
    );
    git(source.path, "add", ".");
    commitFixture(source.path, "Tracked notes");
    source.revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "src");
    const { runs, campaign } = await completedRetry(paths);
    const checkout = recoveryCheckout(paths);
    git(paths.root, "clone", "--quiet", source.path, checkout);
    const expectedApp = await readFile(join(checkout, "src", "app.ts"));
    await rm(join(checkout, "src"), { recursive: true });
    const notes = modified
      ? "Preserve interrupted tracked notes.\n"
      : await readFile(join(checkout, "README.md"), "utf8");
    if (modified === "deleted" || modified === "deleted-missing-index")
      await rm(join(checkout, "README.md"));
    else if (modified) await writeFile(join(checkout, "README.md"), notes);
    if (modified === "deleted-missing-index")
      await rm(join(checkout, ".git", "index"));
    await writeFile(
      join(checkout, "retained.txt"),
      "Preserve untracked recovery data.\n",
    );
    await expectReused(campaign);
    if (modified === "deleted" || modified === "deleted-missing-index")
      await expect(lstat(join(checkout, "README.md"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    else
      expect(await readFile(join(checkout, "README.md"), "utf8")).toBe(notes);
    expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
      "Preserve untracked recovery data.\n",
    );
    expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
      expectedApp,
    );
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const nested of [false, true, "chain"] as const) {
  testPosix(
    `scope alias recovery restores tracked link nested=${nested}`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "preserved-tracked-source");
      await writeFile(
        join(source.path, "README.md"),
        "Original tracked notes.\n",
      );
      await symlink(
        nested === "chain" ? "middle" : "src",
        join(source.path, "alias"),
        "dir",
      );
      if (nested === "chain")
        await symlink("src", join(source.path, "middle"), "dir");
      await symlink("src", join(source.path, "unrelated-alias"), "dir");
      git(source.path, "add", ".");
      commitFixture(source.path, "Tracked notes");
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source, nested ? "alias/app.ts" : "alias");
      const { runs, campaign } = await completedRetry(paths);
      const checkout = recoveryCheckout(paths);
      git(paths.root, "clone", "--quiet", source.path, checkout);
      await rm(join(checkout, "alias"));
      if (nested === "chain") await rm(join(checkout, "middle"));
      await rm(join(checkout, "unrelated-alias"));
      await rm(join(checkout, "README.md"));
      await writeFile(
        join(checkout, "retained.txt"),
        "Preserve untracked recovery data.\n",
      );
      await expectReused(campaign);
      await expect(lstat(join(checkout, "README.md"))).rejects.toMatchObject({
        code: "ENOENT",
      });
      expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
        "Preserve untracked recovery data.\n",
      );
      expect(await readFile(join(checkout, "src", "app.ts"), "utf8")).toBe(
        await readFile(join(source.path, "src", "app.ts"), "utf8"),
      );
      expect(await readFile(join(checkout, "alias", "app.ts"), "utf8")).toBe(
        await readFile(join(source.path, "src", "app.ts"), "utf8"),
      );
      await expect(
        lstat(join(checkout, "unrelated-alias")),
      ).rejects.toMatchObject({ code: "ENOENT" });
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

test("followup recovery restores deleted paths above the default subprocess buffer", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "large-path-list-source");
  const names = Array.from(
    { length: 10000 },
    (_, i) => `src/file_${i}_${"b".repeat(100)}.ts`,
  );
  expect(names.join("\0").length).toBeGreaterThan(1024 * 1024);
  const blob = git(source.path, "hash-object", "-w", "src/app.ts");
  gitText(["-C", source.path, "update-index", "--index-info"], {
    input: names.map((name) => `100644 ${blob}\t${name}\n`).join(""),
  });
  commitFixture(source.path, "Add realistic long tracked paths");
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeRecoveryTask(paths, source, "src", revision);
  const { runs, campaign } = savedCampaign(paths);
  await expectScanned(campaign);
  await cloneWithoutScope(paths, source);
  await expectReused(campaign);

  expect(runs).toHaveBeenCalledTimes(1);
});

for (const entry of ["index", "shallow"] as const) {
  test(`followup recovery refuses a linked ${entry} write destination`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "index-binding-source");
    const interruptedRevision = source.revision;
    await appendFile(
      join(source.path, "src", "app.ts"),
      "export const pinned = true;\n",
    );
    git(source.path, "add", ".");
    commitFixture(source.path, "Advance pinned state");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "src", revision);
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    const checkout = join(paths.output, "checkouts", "repo");
    const outside = join(paths.root, "other-index-checkout");
    git(paths.root, "clone", "--quiet", source.path, outside);
    git(outside, "checkout", "--quiet", "--detach", interruptedRevision);
    const destination = join(outside, ".git", entry);
    if (entry === "shallow")
      await writeFile(destination, interruptedRevision + "\n");
    const bytes = await readFile(destination);
    git(paths.root, "clone", "--quiet", source.path, checkout);
    git(checkout, "checkout", "--quiet", "--detach", interruptedRevision);
    await rm(join(checkout, "src"), { recursive: true });
    await rm(join(checkout, ".git", entry), { force: true });
    await symlink(destination, join(checkout, ".git", entry));
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(await readFile(destination)).toEqual(bytes);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

test("final native recovery restores a locally pinned commit with an unavailable source", async () => {
  const { paths, source } = await scopedRepository("local-pinned-source");
  const { runs, campaign } = savedCampaign(paths);
  const initial = await runMultiscan(campaign);
  const before = await readFile(initial.resultsPath);
  await cloneWithoutScope(paths, source);
  await rename(source.path, join(paths.root, "moved-pinned-source"));
  await expectReused(campaign);
  expect(runs).toHaveBeenCalledTimes(1);
  expect(await readFile(initial.resultsPath)).toEqual(before);
});

(process.platform === "darwin" ? test.skip : testPosix)(
  "final native recovery forwards non-UTF-8 deleted filenames as raw bytes",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "byte-path-source");
    const suffix = Buffer.from([
      0x62, 0x79, 0x74, 0x65, 0x2d, 0xff, 0x2e, 0x74, 0x78, 0x74,
    ]);
    const bytePath = (root: string) =>
      Buffer.concat([Buffer.from(join(root, "src") + sep), suffix]);
    await writeFile(bytePath(source.path), "Synthetic bytes.\n");
    git(source.path, "add", ".");
    commitFixture(source.path, "Byte-valued tracked path");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "src", revision);
    const { runs, campaign } = savedCampaign(paths);
    await runMultiscan(campaign);
    await cloneWithoutScope(paths, source);

    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

testPosix(
  "final native recovery retains a tracked interpreter alias through report recovery",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "tracked-python-source");
    const python = await realpath(PYTHON);
    await symlink(python, join(source.path, "python-alias"));
    git(source.path, "add", ".");
    commitFixture(source.path, "Tracked interpreter alias");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "src", revision);
    const alias = join(paths.output, "checkouts", "repo", "python-alias");
    const runs = mock(async (checkout: string, settings: ScanSettings = {}) => {
      const selected = await runtime.resolvePluginPythonCommand({
        configuredPath: alias,
        protectedRoot: checkout,
        environment: runtime.pluginHelperEnvironment(process.env),
      });
      expect(selected.executable).toBe(python);
      return completedScan(settings.outputDir!, "complete", checkout);
    });
    const campaign = options(paths, client(runs), {
      config: { pythonPath: alias },
    });
    await expectScanned(campaign);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test.each(["FETCH_HEAD", "logs/HEAD"])(
  "recovery refuses a hardlinked %s before external bytes change",
  async (entry) => {
    const { paths, source } = await scopedRepository("hardlinked-fetch-source");
    const { runs, campaign } = savedCampaign(paths);
    await runMultiscan(campaign);
    const outside = join(paths.root, "external-fetch-head");
    await writeFile(outside, "Preserve synthetic metadata.\n");
    const before = await readFile(outside);
    const checkout = await cloneWithoutScope(paths, source);
    await rm(join(checkout, ".git", entry), { force: true });
    await link(outside, join(checkout, ".git", entry));
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(await readFile(outside)).toEqual(before);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("final native recovery refuses a linked pack directory before fetching missing objects", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "linked-pack-source");
  const interrupted = join(paths.root, "interrupted-checkout");
  git(paths.root, "clone", "--quiet", source.path, interrupted);
  for (let i = 0; i < 120; i++)
    await writeFile(
      join(source.path, "src", `object-${i}.ts`),
      `export const object${i} = ${i};\n`,
    );
  git(source.path, "add", ".");
  commitFixture(source.path, "Pinned packed objects");
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeRecoveryTask(paths, source, "src", revision);
  const { runs, campaign } = savedCampaign(paths);
  await runMultiscan(campaign);
  const outside = join(paths.root, "external-packs");
  await mkdir(outside);
  const checkout = join(paths.output, "checkouts", "repo");
  await rename(interrupted, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  await rm(join(checkout, ".git", "objects", "pack"), {
    recursive: true,
    force: true,
  });
  await symlink(outside, join(checkout, ".git", "objects", "pack"), "junction");
  await expect(runMultiscan(campaign)).rejects.toThrow();
  expect(await readdir(outside)).toEqual([]);
  expect(runs).toHaveBeenCalledTimes(1);
});

for (const selection of [
  "configured",
  "inherited",
  "parent",
  "chain",
  "external",
  "external-parent",
  "path",
] as const) {
  const inherited = selection === "inherited";
  testPosix(
    `current native recovery retains an unscoped tracked interpreter alias selection=${selection}`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "tracked-python-source");
      const python = await realpath(PYTHON);
      if (selection === "chain")
        await symlink(python, join(source.path, "middle"));
      await symlink(
        selection === "chain" ? "middle" : python,
        join(source.path, "python-alias"),
      );
      git(source.path, "add", ".");
      commitFixture(source.path, "Tracked interpreter alias");
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source, undefined, revision);
      const parentAlias = join(paths.root, "output-parent-link");
      if (selection === "parent")
        await symlink(paths.output, parentAlias, "junction");
      const checkoutAlias = join(
        selection === "parent" ? parentAlias : paths.output,
        "checkouts",
        "repo",
        "python-alias",
      );
      const externalDirectory = join(paths.root, "external-python-directory");
      const tools = join(paths.root, "trusted-python-tools");
      const alias =
        selection === "external"
          ? join(paths.root, "external-python")
          : selection === "external-parent"
            ? join(externalDirectory, "python-alias")
            : selection === "path"
              ? join(tools, "scan-python")
              : checkoutAlias;
      if (selection === "external-parent") {
        await symlink(dirname(checkoutAlias), externalDirectory);
      } else if (selection === "external" || selection === "path") {
        if (selection === "path") await mkdir(tools);
        await symlink(checkoutAlias, alias);
      }
      const requestedPython = selection === "path" ? "scan-python" : alias;
      const runs = mock(
        async (checkout: string, settings: ScanSettings = {}) => {
          const selected = await runtime.resolvePluginPythonCommand({
            configuredPath: inherited ? undefined : requestedPython,
            protectedRoot: checkout,
            environment: runtime.pluginHelperEnvironment(process.env),
          });
          expect(selected.executable).toBe(
            ["external", "path"].includes(selection) ? alias : python,
          );
          return completedScan(settings.outputDir!, "complete", checkout);
        },
      );
      const campaign = options(paths, client(runs), {
        config: inherited ? {} : { pythonPath: requestedPython },
      });
      const previousPython = process.env["PYTHON"];
      const previousPath = process.env["PATH"];
      if (inherited) process.env["PYTHON"] = alias;
      if (selection === "path")
        process.env["PATH"] = `${tools}${delimiter}${previousPath ?? ""}`;
      try {
        const initialSummary = await runMultiscan(campaign);
        expect(initialSummary).toMatchObject({
          completed: 1,
          skipped: 0,
        });
        if (selection === "chain") {
          const checkout = join(paths.output, "checkouts", "repo");
          git(paths.root, "clone", "--quiet", source.path, checkout);
          await rm(join(checkout, "middle"));
          await writeFile(
            join(checkout, "retained.txt"),
            "Preserve interrupted data.\n",
          );
        }
        await expectReused(campaign);
        expect(runs).toHaveBeenCalledTimes(1);
      } finally {
        if (previousPython === undefined) delete process.env["PYTHON"];
        else process.env["PYTHON"] = previousPython;
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
      }
    },
  );
}

for (const [entry, removeHead] of [
  ["info", true],
  ["loose-object", false],
  ["hooks", true],
  ["refs", true],
  ["refs", false],
] as const) {
  test(`current native recovery preserves external ${entry} initialization and fetch destinations (HEAD removed: ${removeHead})`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "linked-native-source");
    const interrupted = join(paths.root, "interrupted-checkout");
    git(paths.root, "clone", "--quiet", source.path, interrupted);
    await writeFile(
      join(source.path, "src", "later.ts"),
      "Synthetic later revision.\n",
    );
    git(source.path, "add", ".");
    commitFixture(source.path, "Later pinned revision");
    const revision = git(source.path, "rev-parse", "HEAD");
    const object = git(source.path, "rev-parse", "HEAD:src/later.ts");
    await writeRecoveryTask(paths, source, "src", revision);
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    const checkout = join(paths.output, "checkouts", "repo");
    await rename(interrupted, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    const outside = join(paths.root, "external-native-directory");
    await mkdir(outside);
    const destination =
      entry !== "loose-object"
        ? join(checkout, ".git", entry)
        : join(checkout, ".git", "objects", object.slice(0, 2));
    await rm(destination, { recursive: true, force: true });
    await symlink(outside, destination, "junction");
    if (removeHead) await rm(join(checkout, ".git", "HEAD"));
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(await readdir(outside)).toEqual([]);
    expect(failed).toBe(entry === "refs" || entry === "loose-object");
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

test("retained scope recovery rejects mismatched artifacts without resurrecting unrelated files", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "scope-binding-source");
  await writeFile(
    join(source.path, "README.md"),
    "Synthetic retained notes.\n",
  );
  git(source.path, "add", ".");
  commitFixture(source.path, "Tracked notes");
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeRecoveryTask(paths, source, "src", revision);
  const { runs, campaign, initial: first } = await completedRetry(paths);
  const receipt = (await results(first.resultsPath)).find(
    (entry) => entry["status"] === "completed",
  );
  const outputDir = receipt!["outputDir"] as string;
  for (const filename of ["scan-manifest.json", "coverage.json"]) {
    const path = join(outputDir, filename);
    const document = JSON.parse(await readFile(path, "utf8"));
    if (filename === "scan-manifest.json")
      document.scan.scope.includePaths = ["."];
    else document.includePaths = ["."];
    await writeFile(path, JSON.stringify(document));
  }
  await reseal(outputDir);
  const checkout = recoveryCheckout(paths);
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  await rm(join(checkout, "README.md"));
  await expectScanned(campaign);
  await expect(lstat(join(checkout, "README.md"))).rejects.toMatchObject({
    code: "ENOENT",
  });
  expect(runs).toHaveBeenCalledTimes(2);
});

async function completedConfiguredPaths(
  checkout: string,
  settings: ScanSettings = {},
) {
  const target = await normalizeTarget(checkout, settings.target!);
  const result = await completedScan(settings.outputDir!, "complete", checkout);
  result.manifest.scan.scope.includePaths = [...target.paths];
  await writeFile(
    join(settings.outputDir!, "scan-manifest.json"),
    JSON.stringify(result.manifest),
  );
  const file = join(settings.outputDir!, "coverage.json");
  const coverage = JSON.parse(await readFile(file, "utf8"));
  Object.assign(coverage, {
    mode: "scoped_path",
    includePaths: target.paths,
    inventoryStrategy: "scoped_path",
  });
  await writeFile(file, JSON.stringify(coverage));
  await reseal(settings.outputDir!);
  return result;
}
for (const selection of ["root", "parent alias"] as const) {
  test(`final snapshot recovery restores accepted configured paths through ${selection}`, async () => {
    const { paths, source } = await repositoryFixture(
      "configured-snapshot-source",
      "repo",
    );
    const parentAlias = join(paths.root, "campaign-parent");
    if (selection === "parent alias") {
      await mkdir(paths.output, { mode: 0o700 });
      await symlink(paths.output, parentAlias, "junction");
    }
    const target =
      selection === "root"
        ? [".", "src/app.ts"]
        : [join(parentAlias, "checkouts", "repo", "src", "app.ts")];
    const runs = mock(completedConfiguredPaths);
    const campaign = options(paths, client(runs), {
      scanOptionsByMode: { standard: { target } },
    });
    const initial = await expectScanned(campaign);
    const ledger = await readFile(initial.resultsPath);
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src", "app.ts"));
    await expectReused(campaign);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
for (const missingAncestor of [false, true]) {
  test(`final snapshot recovery stays offline with missing ancestor objects=${missingAncestor}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "offline-snapshot-source");
    const ancestorBlob = git(source.path, "rev-parse", "HEAD:src/app.ts");
    await writeFile(
      join(source.path, "src", "app.ts"),
      "Current pinned content.\n",
    );
    git(source.path, "add", ".");
    commitFixture(source.path, "Current pinned snapshot");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "src", revision);
    const { runs, campaign } = savedCampaign(paths);
    const initial = await expectScanned(campaign);
    const ledger = await readFile(initial.resultsPath);
    const checkout = await cloneWithoutScope(paths, source);
    if (missingAncestor)
      await rm(
        join(
          checkout,
          ".git",
          "objects",
          ancestorBlob.slice(0, 2),
          ancestorBlob.slice(2),
        ),
      );
    await rename(source.path, join(paths.root, "unavailable-source"));
    await expectReused(campaign);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
test("final snapshot recovery skips a sealed report's unavailable interpreter ancestor", async () => {
  const { paths } = await repositoryFixture("sealed-python-source", "repo");
  const parent = join(paths.root, "python-parent");
  await mkdir(parent);
  const interpreter = join(parent, "bin", "python");
  const runs = mock(async (checkout: string, settings: ScanSettings = {}) => {
    const result = await completedScan(
      settings.outputDir!,
      "complete",
      checkout,
    );
    result.manifest.scan.artifacts.push({
      path: "report.md",
      sha256: "0".repeat(64),
      mediaType: "text/markdown",
    });
    await writeFile(
      join(settings.outputDir!, "scan-manifest.json"),
      JSON.stringify(result.manifest),
    );
    await reseal(settings.outputDir!);
    expect(
      await contract.hasSealedReport(settings.outputDir!, result.manifest),
    ).toBe(true);
    return result;
  });
  const campaign = options(paths, client(runs), {
    config: { pythonPath: interpreter },
  });
  const initial = await expectScanned(campaign);
  const ledger = await readFile(initial.resultsPath);
  await rm(parent, { recursive: true });
  await writeFile(parent, "Ancestor is now an ordinary file.\n");
  await expectReused(campaign);
  expect(await readFile(initial.resultsPath)).toEqual(ledger);
  expect(runs).toHaveBeenCalledTimes(1);
});

for (const linked of [false, true]) {
  test(`final snapshot recovery fetches without maintaining linked server info=${linked}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "maintenance-snapshot-source");
    for (let i = 0; i < 3; i++) {
      await writeFile(
        join(source.path, "src", "app.ts"),
        `Synthetic version ${i}.\n`,
      );
      git(source.path, "add", ".");
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        `Synthetic revision ${i}`,
      );
    }
    const interrupted = join(paths.root, "interrupted");
    git(paths.root, "clone", "--quiet", source.path, interrupted);
    await writeFile(
      join(source.path, "src", "later.ts"),
      "Pinned later source.\n",
    );
    git(source.path, "add", ".");
    commitFixture(source.path, "Pinned later revision");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "src", revision);
    const { runs, campaign } = savedCampaign(paths);
    const initial = await expectScanned(campaign);
    const ledger = await readFile(initial.resultsPath);
    const checkout = join(paths.output, "checkouts", "repo");
    await rename(interrupted, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    const objects = git(checkout, "rev-list", "--objects", "HEAD").split("\n");
    for (let i = 0; i < 3; i++)
      gitText(
        [
          "-C",
          checkout,
          "pack-objects",
          join(checkout, ".git", "objects", "pack", `pack-${i}`),
        ],
        { input: objects[i]!.split(" ")[0] + "\n" },
      );
    git(checkout, "config", "gc.auto", "1");
    git(checkout, "config", "gc.autoPackLimit", "1");
    git(checkout, "config", "gc.autoDetach", "false");
    const destinations = [
      join(paths.root, "outside-info"),
      join(paths.root, "outside-objects-info"),
    ];
    if (linked) {
      for (const [i, name] of ["info", "objects/info"].entries()) {
        await mkdir(destinations[i]!);
        const target = join(checkout, ".git", name);
        await rm(target, { recursive: true });
        await symlink(destinations[i]!, target, "junction");
      }
    }
    await expectReused(campaign);
    if (linked)
      for (const destination of destinations)
        expect(await readdir(destination)).toEqual([]);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const mode of ["many scopes", "early restore exit"] as const) {
  const selectedTest = mode === "early restore exit" ? testPosix : test;
  selectedTest(
    `final snapshot recovery handles ${mode} through actual Git stdin`,
    async () => {
      const name = `final snapshot recovery handles ${mode} through actual Git stdin`;
      if (runTestInSubprocess(import.meta.path, name)) return;
      const paths = await fixture();
      const source = await repository(paths.root, "stdin-snapshot-source");
      const names = Array.from(
        { length: mode === "many scopes" ? 800 : 5500 },
        (_, i) =>
          `src/file_${i}_${"b".repeat(mode === "many scopes" ? 70 : 230)}.ts`,
      );
      const blob = git(source.path, "hash-object", "-w", "src/app.ts");
      gitText(["-C", source.path, "update-index", "--index-info"], {
        input: names.map((name) => `100644 ${blob}\t${name}\n`).join(""),
      });
      commitFixture(source.path, "Tracked restoration paths");
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision${mode === "many scopes" ? "" : ",scope"}\nrepo,${source.path},${revision}${mode === "many scopes" ? "" : ",src"}\n`,
      );
      const runs = mock(
        mode === "many scopes" ? completedConfiguredPaths : completeRun,
      );
      const campaign = options(
        paths,
        client(runs),
        mode === "many scopes"
          ? { scanOptionsByMode: { standard: { target: names } } }
          : {},
      );
      const initial = await expectScanned(campaign);
      const ledger = await readFile(initial.resultsPath);
      await cloneWithoutScope(paths, source);
      const previousPath = process.env["PATH"];
      const tools = join(paths.root, "synthetic-tools");
      if (process.platform !== "win32") {
        const original = await resolveTrustedExecutable(
          "git",
          process.env,
          process.cwd(),
        );
        expect(original).not.toBeNull();
        await mkdir(tools);
        // Exercise Windows's process-argument ceiling on Unix; Windows uses its real ceiling.
        const script = `#!/usr/bin/env node\nconst {spawnSync}=require("node:child_process");const args=process.argv.slice(2);if(args.includes("ls-files")&&args.join(" ").length>32767)process.exit(72);if(${JSON.stringify(mode)}==="early restore exit"&&args.includes("restore"))process.exit(73);const result=spawnSync(${JSON.stringify(original!.executable)},args,{stdio:"inherit"});if(result.error)throw result.error;process.exit(result.status??1);\n`;
        await writeFile(join(tools, "git"), script, { mode: 0o700 });
        process.env["PATH"] = tools + delimiter + (previousPath ?? "");
      }
      try {
        if (mode === "early restore exit") {
          const node = "node";
          const bundle = join(paths.root, "multiscan-runtime.mjs");
          const modules = join(paths.root, "node_modules");
          await symlink(
            join(dirname(import.meta.path), "..", "node_modules"),
            modules,
            "junction",
          );
          await symlink(
            PLUGIN_ROOT,
            join(paths.root, "_bundled_plugin"),
            "junction",
          );
          execFileSync(process.execPath, [
            "build",
            join(dirname(import.meta.path), "..", "src", "multiscan.ts"),
            "--target=node",
            "--packages=external",
            `--outfile=${bundle}`,
          ]);
          const entry = join(paths.root, "node-recovery.mjs");
          await writeFile(
            entry,
            `import {runMultiscan} from ${JSON.stringify(bundle)};\nconst options=JSON.parse(process.argv[2]);options.createSecurity=()=>({run:async()=>{throw new Error("Existing receipt must be reused");},close:async()=>{}});try{await runMultiscan(options);process.exitCode=1;}catch(error){console.log("Child failure returned to SDK host",error.code);}console.log("SDK host remained alive");\n`,
          );
          const output = execFileSync(
            node,
            [
              entry,
              JSON.stringify({
                inputPath: paths.input,
                outputDir: paths.output,
                workers: 1,
                mode: "standard",
                maxAttempts: 2,
                config: {},
              }),
            ],
            { encoding: "utf8", env: process.env },
          );
          expect(output).toContain("Child failure returned to SDK host 73");
          expect(output).toContain("SDK host remained alive");
        } else await expectReused(campaign);
        expect(await readFile(initial.resultsPath)).toEqual(ledger);
        expect(runs).toHaveBeenCalledTimes(1);
      } finally {
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
      }
    },
  );
}

for (const staged of [false, true]) {
  test(`retained edge recovery restores staged selected deletion=${staged} and preserves replacement data`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "staged-selected-source");
    await writeFile(
      join(source.path, "README.md"),
      "Synthetic retained readme.\n",
    );
    git(source.path, "add", ".");
    commitFixture(source.path, "Selected fixture readme");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, undefined, revision);
    const { runs, campaign, initial } = await completedRetry(
      paths,
      {
        scanOptionsByMode: {
          standard: { target: ["src/app.ts", "README.md"] },
        },
      },
      completedConfiguredPaths,
    );
    const ledger = await readFile(initial.resultsPath);
    const checkout = recoveryCheckout(paths);
    git(paths.root, "clone", "--quiet", source.path, checkout);
    const expectedApp = await readFile(join(checkout, "src", "app.ts"));
    if (staged) git(checkout, "rm", "--quiet", "src/app.ts");
    else await rm(join(checkout, "src", "app.ts"));
    git(checkout, "rm", "--quiet", "README.md");
    await writeFile(
      join(checkout, "README.md"),
      "Preserve staged replacement content.\n",
    );
    const stagedBefore = git(checkout, "diff", "--cached", "--name-only");
    await expectReused(campaign);
    expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
      expectedApp,
    );
    expect(await readFile(join(checkout, "README.md"), "utf8")).toBe(
      "Preserve staged replacement content.\n",
    );
    expect(git(checkout, "diff", "--cached", "--name-only")).toBe(stagedBefore);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
for (const linked of [false, true]) {
  test(`retained edge recovery avoids bundle commit-graph writes through linked info=${linked}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "bundle-graph-source");
    for (let i = 0; i < 3; i++) {
      await writeFile(
        join(source.path, "src", "app.ts"),
        `Synthetic pinned version ${i}.\n`,
      );
      git(source.path, "add", ".");
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        `Pinned fixture revision ${i}`,
      );
    }
    const revision = git(source.path, "rev-parse", "HEAD");
    const blob = git(source.path, "rev-parse", "HEAD:src/app.ts");
    const bundle = join(paths.root, "source.bundle");
    git(source.path, "bundle", "create", bundle, "--all");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${bundle},${revision},src\n`,
    );
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    const checkout = await cloneWithoutScope(paths, source);
    await rm(
      join(checkout, ".git", "objects", blob.slice(0, 2), blob.slice(2)),
    );
    git(checkout, "config", "fetch.writeCommitGraph", "true");
    const outside = join(paths.root, "outside-object-info");
    await mkdir(outside, { mode: 0o700 });
    if (linked) {
      await rm(join(checkout, ".git", "objects", "info"), { recursive: true });
      await symlink(
        outside,
        join(checkout, ".git", "objects", "info"),
        "junction",
      );
    }
    await expectReused(campaign);
    expect(await readdir(outside)).toEqual([]);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
(process.platform === "win32" ? test : test.skip)(
  "retained edge recovery restores a missing Windows scope with accepted different casing",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "case-scope-source");
    await writeRecoveryTask(paths, source, "SRC");
    const { runs, campaign } = savedCampaign(paths);
    await expectScanned(campaign);
    await cloneWithoutScope(paths, source);
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);
(process.platform === "win32" ? test : test.skip)(
  "retained edge recovery rejects an unscoped interpreter repair through a Windows parent junction",
  async () => {
    const { paths, source } = await repositoryFixture(
      "unscoped-junction-source",
      "repo",
    );
    const outsideParent = join(paths.root, "outside-recovery-parent");
    const outsideCheckout = join(outsideParent, "attempt-2");
    const config = { pythonPath: join(outsideCheckout, "missing-python.exe") };
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), {
        maxAttempts: 1,
        config,
      }),
    );
    await mkdir(outsideParent, { mode: 0o700 });
    git(paths.root, "clone", "--quiet", source.path, outsideCheckout);
    const runs = mock(async (_checkout: string, settings: ScanSettings = {}) =>
      completedScan(settings.outputDir!, "complete", outsideCheckout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
      config,
    });
    await expectScanned(campaign);
    await rename(outsideCheckout, join(outsideParent, "retained-attempt"));
    const lexicalParent = join(paths.output, "recovery-checkouts", "repo");
    await rm(lexicalParent, { recursive: true, force: true });
    await symlink(outsideParent, lexicalParent, "junction");
    await expect(runMultiscan(campaign)).rejects.toThrow();
    await expect(lstat(outsideCheckout)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const configured of [false, true]) {
  test(`retained spelling recovery keeps a bare PATH interpreter configured=${configured}`, async () => {
    const { paths, source } = await repositoryFixture(
      "bare-interpreter-source",
      "repo",
    );
    const runs = mock(completeRun);
    const python = basename(PYTHON);
    const initial = await runMultiscan(
      options(paths, client(runs), {
        config: configured ? { pythonPath: python } : {},
      }),
    );
    const receipt = (await results(initial.resultsPath)).find(
      (row) => row["status"] === "completed",
    )!;
    const output = receipt["outputDir"] as string;
    await appendFile(
      join(output, "report.md"),
      "Refresh this synthetic report.\n",
    );
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, ".git"), { recursive: true });
    await rm(source.path, { recursive: true });
    const code = `import {runMultiscan} from ${JSON.stringify(join(dirname(import.meta.path), "..", "src", "multiscan.ts"))};
      const options=${JSON.stringify({ inputPath: paths.input, outputDir: paths.output, workers: 1, mode: "standard", maxAttempts: 2, config: configured ? { pythonPath: python } : {} })};
      options.createSecurity=()=>({run:async()=>{throw new Error("Completed receipt must be reused");},close:async()=>{}});
      options.recoverScan=async()=>undefined;
      console.log(JSON.stringify(await runMultiscan(options)));`;
    const summary = JSON.parse(
      execFileSync(process.execPath, ["-e", code], {
        cwd: checkout,
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: dirname(PYTHON) + delimiter + (process.env["PATH"] ?? ""),
          PYTHON: configured ? undefined : python,
        },
      }),
    );
    expect(summary).toMatchObject({ completed: 1, skipped: 1 });
    expect(runs).toHaveBeenCalledTimes(1);
    expect(
      await lstat(join(checkout, ".git")).catch(() => undefined),
    ).toBeUndefined();
  });
}

for (const nested of [false, true]) {
  const name = `retained spelling recovery preserves accepted alias casing nested=${nested}`;
  test(name, async () => {
    if (process.platform === "win32") {
      const count = Number(process.env["GIT_CONFIG_COUNT"] ?? "0");
      if (
        runTestInSubprocess(import.meta.path, name, {
          ...process.env,
          GIT_CONFIG_COUNT: String(count + 1),
          [`GIT_CONFIG_KEY_${count}`]: "core.symlinks",
          [`GIT_CONFIG_VALUE_${count}`]: "true",
        })
      )
        return;
    }
    const paths = await fixture();
    const source = await repository(paths.root, "case-alias-source");
    await symlink("src", join(source.path, "alias"), "dir");
    git(source.path, "add", ".");
    commitFixture(source.path, "Tracked scope alias");
    const revision = git(source.path, "rev-parse", "HEAD");
    const caseInsensitive = await realpath(join(source.path, "ALIAS")).then(
      () => true,
      () => false,
    );
    const requested =
      (caseInsensitive ? "ALIAS" : "alias") + (nested ? "/APP.TS" : "");
    const scope = !caseInsensitive && nested ? "alias/app.ts" : requested;
    await writeRecoveryTask(paths, source, scope, revision);
    const { runs, campaign, initial } = await completedRetry(paths);
    expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
      status: "completed",
      attempt: 2,
    });
    const checkout = recoveryCheckout(paths);
    git(
      paths.root,
      "clone",
      "--quiet",
      "-c",
      "core.symlinks=true",
      source.path,
      checkout,
    );
    const aliasFile = join(checkout, "alias", "app.ts");
    const originalBytes = await readFile(aliasFile);
    await unlink(join(checkout, "alias"));
    await rm(join(checkout, "src"), { recursive: true });
    await writeFile(
      join(checkout, "retained.txt"),
      "Keep unrelated recovery bytes.\n",
    );
    await expectReused(campaign);
    expect(runs).toHaveBeenCalledTimes(1);
    expect(await readFile(aliasFile)).toEqual(originalBytes);
    expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
      "Keep unrelated recovery bytes.\n",
    );
  });
}

test("retained spelling recovery restores a tracked interpreter selection", async () => {
  const count = Number(process.env["GIT_CONFIG_COUNT"] ?? "0");
  if (
    runTestInSubprocess(
      fileURLToPath(import.meta.url),
      "retained spelling recovery restores a tracked interpreter selection",
      {
        ...process.env,
        GIT_CONFIG_COUNT: String(count + 1),
        [`GIT_CONFIG_KEY_${count}`]: "core.symlinks",
        [`GIT_CONFIG_VALUE_${count}`]: "true",
      },
    )
  )
    return;
  const paths = await fixture();
  const source = await repository(paths.root, "extensionless-python-source");
  await symlink(await realpath(PYTHON), join(source.path, "python.exe"));
  git(source.path, "add", ".");
  commitFixture(source.path, "Tracked interpreter link");
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeRecoveryTask(paths, source, undefined, revision);
  const checkout = recoveryCheckout(paths);
  const alias = join(
    checkout,
    process.platform === "win32" ? "python" : "python.exe",
  );
  await runMultiscan(
    options(paths, client(rejecting("Interrupted")), {
      maxAttempts: 1,
      config: { pythonPath: alias },
    }),
  );
  const runs = mock(async (root: string, settings: ScanSettings = {}) => {
    expect(root).toBe(checkout);
    const selected = await runtime.resolvePluginPythonCommand({
      configuredPath: alias,
      protectedRoot: root,
      environment: runtime.pluginHelperEnvironment(process.env),
    });
    expect(await realpath(selected.executable)).toBe(await realpath(PYTHON));
    return completedScan(settings.outputDir!, "complete", root);
  });
  const campaign = options(paths, client(runs), {
    config: { pythonPath: alias },
    recoverScan: async () => undefined,
  });
  const initial = await runMultiscan(campaign);
  expect(await results(initial.resultsPath)).toEqual(
    expect.arrayContaining([expect.objectContaining({ status: "completed" })]),
  );
  expect(initial).toMatchObject({ completed: 1, skipped: 0 });
  const receipt = (await results(initial.resultsPath)).find(
    (row) => row["status"] === "completed",
  )!;
  expect(receipt["attempt"]).toBe(2);
  git(
    paths.root,
    "clone",
    "--quiet",
    "-c",
    "core.symlinks=true",
    source.path,
    checkout,
  );
  const marker = join(checkout, "retained.txt");
  await writeFile(marker, "Keep this retained checkout.\n");
  const originalMarker = await lstat(marker);
  await appendFile(
    join(receipt["outputDir"] as string, "report.md"),
    "Refresh this synthetic report.\n",
  );

  await rm(join(checkout, "python.exe"));
  await expectReused(campaign);
  expect(await realpath(join(checkout, "python.exe"))).toBe(
    await realpath(PYTHON),
  );
  expect(runs).toHaveBeenCalledTimes(1);
  expect(await readFile(marker, "utf8")).toBe("Keep this retained checkout.\n");
  const retainedMarker = await lstat(marker);
  expect([retainedMarker.dev, retainedMarker.ino]).toEqual([
    originalMarker.dev,
    originalMarker.ino,
  ]);
});

for (const tracked of [false, true]) {
  for (const allMetadata of [false, true]) {
    test(`retained ignored data keeps unrelated bytes with removed metadata tracked=${tracked} all=${allMetadata}`, async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "ignored-retained-source");
      if (tracked) {
        await writeFile(
          join(source.path, "notes.log"),
          "Pinned synthetic note.\n",
        );
        git(source.path, "add", ".");
        commitFixture(source.path, "Pinned synthetic note");
      }
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source, "src", revision);
      const { runs, campaign, initial } = await completedRetry(paths);

      const ledger = await readFile(initial.resultsPath);
      const checkout = recoveryCheckout(paths);
      await rm(checkout, { recursive: true, force: true });
      git(paths.root, "clone", "--quiet", source.path, checkout);
      const expectedApp = await readFile(join(checkout, "src", "app.ts"));
      await rm(join(checkout, "src"), { recursive: true });
      const retained = "Keep unrelated retained note bytes.\n";
      await writeFile(join(checkout, "notes.log"), retained);
      await appendFile(
        join(checkout, ".git", "info", "exclude"),
        "notes.log\n",
      );
      await rm(
        allMetadata ? join(checkout, ".git") : join(checkout, ".git", "index"),
        { recursive: true },
      );
      if (!allMetadata) await rm(source.path, { recursive: true });
      let failure: unknown;
      let summary: unknown;
      try {
        summary = await runMultiscan(campaign);
      } catch (error) {
        failure = error;
      }
      expect(await readFile(join(checkout, "notes.log"), "utf8")).toBe(
        retained,
      );
      expect(runs).toHaveBeenCalledTimes(1);
      expect(failure).toBeUndefined();
      expect(summary).toMatchObject({ completed: 1, skipped: 1 });
      expect(await readFile(initial.resultsPath)).toEqual(ledger);
      expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
        expectedApp,
      );
      if (tracked) {
        expect(git(checkout, "show", ":notes.log")).toBe(
          "Pinned synthetic note.",
        );
        expect(git(checkout, "diff", "--name-only")).toContain("notes.log");
      }
    });
  }
}

for (const missingCode of ["native", "ENOENT"]) {
  for (const obstructed of [false, true]) {
    test(`retained requested-file recovery preserves a regular-file ancestor=${obstructed} missing-code=${missingCode}`, async () => {
      const { paths, source } = await repositoryFixture(
        "retained-ancestor-source",
        "repo",
      );
      const selected = { standard: { target: ["src/app.ts"] } };
      const { runs, campaign, initial } = await completedRetry(
        paths,
        { scanOptionsByMode: selected },
        completedConfiguredPaths,
      );
      const ledger = await readFile(initial.resultsPath);
      const checkout = recoveryCheckout(paths);
      git(paths.root, "clone", "--quiet", source.path, checkout);
      const expectedApp = await readFile(join(checkout, "src", "app.ts"));
      await rm(join(checkout, "src"), { recursive: true });
      if (obstructed)
        await writeFile(
          join(checkout, "src"),
          "Preserve retained ancestor contents.\n",
        );
      const originalLstat = filesystem.lstat;
      const inspect =
        missingCode === "ENOENT"
          ? spyOn(filesystem, "lstat").mockImplementation((async (
              ...args: Parameters<typeof filesystem.lstat>
            ) => {
              try {
                return await originalLstat(...args);
              } catch (error) {
                if (
                  String(args[0]) === join(checkout, "src", "app.ts") &&
                  (error as NodeJS.ErrnoException).code === "ENOTDIR"
                )
                  (error as NodeJS.ErrnoException).code = "ENOENT";
                throw error;
              }
            }) as typeof filesystem.lstat)
          : undefined;
      let outcome: unknown;
      try {
        outcome = await runMultiscan(campaign).catch((error: unknown) => error);
      } finally {
        inspect?.mockRestore();
      }
      if (obstructed) {
        expect(await readFile(join(checkout, "src"), "utf8")).toBe(
          "Preserve retained ancestor contents.\n",
        );
        expect(outcome).toBeInstanceOf(Error);
      } else {
        expect(outcome).toMatchObject({ completed: 1, skipped: 1 });
        expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
          expectedApp,
        );
      }
      expect(await readFile(initial.resultsPath)).toEqual(ledger);
      expect(runs).toHaveBeenCalledTimes(1);
    });
  }
}

for (const { parentThroughLink, missing } of [
  { parentThroughLink: false, missing: "alias" },
  { parentThroughLink: true, missing: "alias" },
  { parentThroughLink: true, missing: "jump" },
  { parentThroughLink: true, missing: "both" },
  { parentThroughLink: false, missing: "nested" },
  { parentThroughLink: true, missing: "nested" },
]) {
  testPosix(
    `retained requested-file recovery follows physical alias parent=${parentThroughLink} missing=${missing}`,
    async () => {
      const paths = await fixture();
      const source = await repository(
        paths.root,
        "retained-physical-alias-source",
      );
      await mkdir(join(source.path, "nested", "deep"), { recursive: true });
      await mkdir(join(source.path, "nested", "src"));
      await writeFile(
        join(source.path, "nested", "deep", "keep.ts"),
        "export const keep = true;\n",
      );
      await writeFile(
        join(source.path, "nested", "src", "app.ts"),
        "export const nested = true;\n",
      );
      await symlink("nested/deep", join(source.path, "jump"), "dir");
      await symlink(
        parentThroughLink ? "jump/../src" : "nested/src",
        join(source.path, "alias"),
        "dir",
      );
      git(source.path, "add", ".");
      commitFixture(source.path, "Physical scope alias fixture");
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source, "alias/app.ts");
      const config = { pythonPath: PYTHON };
      const { runs, initial } = await completedRetry(paths, {
        config,
      });
      const ledger = await readFile(initial.resultsPath);
      const checkout = recoveryCheckout(paths);
      git(paths.root, "clone", "--quiet", source.path, checkout);
      if (missing !== "jump") await rm(join(checkout, "alias"));
      if (missing !== "alias") await rm(join(checkout, "jump"));
      if (missing === "nested")
        await rm(join(checkout, "nested"), { recursive: true });
      else await rm(join(checkout, "nested", "src", "app.ts"));
      await writeFile(
        join(checkout, "retained.txt"),
        "Preserve retained recovery data.\n",
      );
      const sourceModule = new URL("../src/multiscan.ts", import.meta.url);
      const nodeModule = join(paths.root, "multiscan.cjs");
      await build({
        entryPoints: [fileURLToPath(sourceModule)],
        outfile: nodeModule,
        bundle: true,
        platform: "node",
        format: "cjs",
        define: { "import.meta.url": JSON.stringify(sourceModule.href) },
      });
      const code = `const {runMultiscan} = require(process.argv[1]);
      const options=${JSON.stringify({ inputPath: paths.input, outputDir: paths.output, workers: 1, mode: "standard", maxAttempts: 2, config })};
      options.createSecurity=()=>({run:async()=>{throw new Error("Completed receipt must be reused");},close:async()=>{}});
      options.recoverScan=async()=>undefined;
      runMultiscan(options).then((result)=>console.log(JSON.stringify(result)),(error)=>{console.error(error);process.exitCode=1});`;
      const summary = JSON.parse(
        execFileSync("node", ["--eval", code, nodeModule], {
          encoding: "utf8",
          env: process.env,
        }),
      );
      expect(summary).toMatchObject({ completed: 1, skipped: 1 });
      expect(await readFile(join(checkout, "alias", "app.ts"), "utf8")).toBe(
        "export const nested = true;\n",
      );
      expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
        await readFile(join(source.path, "src", "app.ts")),
      );
      expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
        "Preserve retained recovery data.\n",
      );
      expect(await readFile(initial.resultsPath)).toEqual(ledger);
      if (missing === "nested")
        expect(
          await lstat(join(checkout, "nested", "deep", "keep.ts")).catch(
            () => undefined,
          ),
        ).toBeUndefined();
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

for (const linked of [false, true]) {
  testPosix(
    `retained requested-file recovery preserves directory-link ancestor=${linked}`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "retained-directory-source");
      await mkdir(join(source.path, "src", "nested", "inside"), {
        recursive: true,
      });
      await writeFile(
        join(source.path, "src", "nested", "inside", "keep.ts"),
        "export const keep = true;\n",
      );
      git(source.path, "add", ".");
      commitFixture(source.path, "Nested retained source");
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source);
      const selected = { standard: { target: ["src", "src/app.ts"] } };
      const { runs, campaign, initial } = await completedRetry(
        paths,
        { scanOptionsByMode: selected },
        completedConfiguredPaths,
      );
      const ledger = await readFile(initial.resultsPath);
      const checkout = recoveryCheckout(paths);
      git(paths.root, "clone", "--quiet", source.path, checkout);
      await rm(join(checkout, "src", "app.ts"));
      await rm(join(checkout, "src", "nested", "inside", "keep.ts"));
      const nested = join(checkout, "src", "nested");
      const destination = join(checkout, "retained-directory");
      if (linked) {
        await rm(nested, { recursive: true });
        await mkdir(join(destination, "inside"), { recursive: true });
        await writeFile(
          join(destination, "inside", "retained.txt"),
          "Preserve directory-link data.\n",
        );
        await symlink("../retained-directory", nested, "dir");
      }
      await expectReused(campaign);
      expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
        await readFile(join(source.path, "src", "app.ts")),
      );
      if (linked) {
        expect((await lstat(nested)).isSymbolicLink()).toBe(true);
        expect(
          await readFile(join(destination, "inside", "retained.txt"), "utf8"),
        ).toBe("Preserve directory-link data.\n");
        await expect(
          lstat(join(destination, "inside", "keep.ts")),
        ).rejects.toMatchObject({ code: "ENOENT" });
      } else {
        expect(await readFile(join(nested, "inside", "keep.ts"))).toEqual(
          await readFile(
            join(source.path, "src", "nested", "inside", "keep.ts"),
          ),
        );
      }
      expect(await readFile(initial.resultsPath)).toEqual(ledger);
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

for (const automatic of [false, true]) {
  testPosix(
    `whole recovery preserves automatically selected tracked Python automatic=${automatic}`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "automatic-python-source");
      const python = await realpath(PYTHON);
      await symlink(python, join(source.path, "python-alias"));
      git(source.path, "add", ".");
      commitFixture(source.path, "Tracked automatic interpreter alias");
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source);
      const alias = join(paths.output, "checkouts", "repo", "python-alias");
      const bin = join(paths.root, "tools");
      await mkdir(bin);
      await symlink(alias, join(bin, "python3"));
      const selectedGit = await resolveTrustedExecutable(
        "git",
        process.env,
        paths.root,
      );
      expect(selectedGit).not.toBeNull();
      await symlink(selectedGit!.executable, join(bin, "git"));
      const runs = mock(
        async (checkout: string, settings: ScanSettings = {}) => {
          const selected = await runtime.resolvePluginPythonCommand({
            environment: { ...process.env, PATH: bin, PYTHON: undefined },
            protectedRoot: checkout,
            homeDirectory: paths.root,
            managedRuntimeRoots: [],
          });
          expect(await realpath(selected.executable)).toBe(python);
          return completedScan(settings.outputDir!, "complete", checkout);
        },
      );
      const initial = await runMultiscan(
        options(paths, client(runs), {
          config: automatic ? {} : { pythonPath: "python3" },
        }),
      );
      const rows = await results(initial.resultsPath);
      expect(initial).toMatchObject({ completed: 1, skipped: 0 });
      const receipt = rows.find((row) => row["status"] === "completed")!;
      await appendFile(
        join(receipt["outputDir"] as string, "report.md"),
        "Refresh this synthetic report.\n",
      );
      const ledger = await readFile(initial.resultsPath);
      const code = `import {runMultiscan} from ${JSON.stringify(join(dirname(import.meta.path), "..", "src", "multiscan.ts"))};
        const options=${JSON.stringify({ inputPath: paths.input, outputDir: paths.output, workers: 1, mode: "standard", maxAttempts: 2, config: automatic ? {} : { pythonPath: "python3" } })};
        options.createSecurity=()=>({run:async()=>{throw new Error("Completed receipt must be reused");},close:async()=>{}});
        options.recoverScan=async()=>undefined;
        console.log(JSON.stringify(await runMultiscan(options)));`;
      const summary = JSON.parse(
        execFileSync(process.execPath, ["-e", code], {
          encoding: "utf8",
          env: {
            ...process.env,
            PATH: bin,
            PYTHON: undefined,
            HOME: paths.root,
            USERPROFILE: paths.root,
          },
        }),
      );
      expect(summary).toMatchObject({ completed: 1, skipped: 1 });
      expect(runs).toHaveBeenCalledTimes(1);
      expect(await readFile(initial.resultsPath)).toEqual(ledger);
    },
  );
}

for (const imported of [false, true]) {
  testPosix(
    `retained recovery preserves selected Git across repository import=${imported}`,
    async () => {
      const name = `retained recovery preserves selected Git across repository import=${imported}`;
      if (runTestInSubprocess(import.meta.path, name)) return;
      const paths = await fixture();
      const source = await repository(paths.root, "selected-git-source");
      const original = await resolveTrustedExecutable(
        "git",
        process.env,
        process.cwd(),
      );
      expect(original).not.toBeNull();
      const marker = join(paths.root, "selected-git-marker.txt");
      const script = `#!${process.execPath}\nconst {appendFileSync}=require("node:fs");const {spawnSync}=require("node:child_process");appendFileSync(${JSON.stringify(marker)},"git invoked\\n");const result=spawnSync(${JSON.stringify(original!.executable)},process.argv.slice(2),{stdio:"inherit"});if(result.error)throw result.error;process.exit(result.status??1);\n`;
      if (imported) {
        await mkdir(join(source.path, "bin"));
        await writeFile(join(source.path, "bin", "git"), script, {
          mode: 0o700,
        });
        git(source.path, "add", ".");
        commitFixture(source.path, "Synthetic imported tool");
      }
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeRecoveryTask(paths, source, "src", revision);
      await interruptCampaign(paths);
      const checkout = recoveryCheckout(paths);
      const tools = imported
        ? join(checkout, "bin")
        : join(paths.root, "user-tools");
      if (!imported) {
        await mkdir(tools);
        await writeFile(join(tools, "git"), script, { mode: 0o700 });
      }
      const previousPath = process.env["PATH"];
      process.env["PATH"] = `${tools}${delimiter}${previousPath ?? ""}`;
      try {
        const { runs, campaign } = savedCampaign(paths, {
          recoverScan: async () => undefined,
        });
        const initial = await runMultiscan(campaign);
        expect(initial).toMatchObject({ completed: 1, skipped: 0 });
        const ledger = await readFile(initial.resultsPath);
        execFileSync(original!.executable, [
          "clone",
          "--quiet",
          source.path,
          checkout,
        ]);
        await rm(marker, { force: true });
        await rm(join(checkout, "src"), { recursive: true });
        await expectReused(campaign);
        const invoked = await readFile(marker, "utf8").catch(
          (error: NodeJS.ErrnoException) => {
            if (error.code === "ENOENT") return "";
            throw error;
          },
        );
        expect(invoked.length > 0).toBe(!imported);
        expect(runs).toHaveBeenCalledTimes(1);
        expect(await readFile(initial.resultsPath)).toEqual(ledger);
        expect(
          await readFile(join(checkout, "src", "app.ts"), "utf8"),
        ).toContain("selected-git-source");
      } finally {
        if (previousPath === undefined) delete process.env["PATH"];
        else process.env["PATH"] = previousPath;
      }
    },
  );
}

for (const ignoreCase of [false, true]) {
  test(`retained selected restoration respects explicit core.ignorecase=${ignoreCase}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "case-sensitive-source");
    git(source.path, "mv", "src", "selected-case");
    git(source.path, "mv", "selected-case", "SRC");
    await writeFile(
      join(paths.root, "other.ts"),
      "Keep unrelated case-distinct path absent.\n",
    );
    const blob = git(
      source.path,
      "hash-object",
      "-w",
      join(paths.root, "other.ts"),
    );
    git(
      source.path,
      "update-index",
      "--add",
      "--cacheinfo",
      `100644,${blob},src/other.ts`,
    );
    commitFixture(source.path, "Synthetic case-distinct path");
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeRecoveryTask(paths, source, "SRC", revision);
    const { runs, campaign, initial } = await completedRetry(paths);

    expect(await results(initial.resultsPath)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ status: "completed", resolvedScope: "SRC" }),
      ]),
    );
    const ledger = await readFile(initial.resultsPath);
    const checkout = recoveryCheckout(paths);
    git(paths.root, "clone", "--quiet", source.path, checkout);
    git(checkout, "config", "core.ignorecase", String(ignoreCase));
    await rm(join(checkout, "src"), { recursive: true, force: true });
    await rm(join(checkout, "SRC"), { recursive: true, force: true });
    await expectReused(campaign);
    expect(await readFile(join(checkout, "SRC", "app.ts"), "utf8")).toContain(
      "case-sensitive-source",
    );
    expect(
      await lstat(join(checkout, "src", "other.ts"))
        .then(() => true)
        .catch((error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return false;
          throw error;
        }),
    ).toBe(ignoreCase);
    expect(runs).toHaveBeenCalledTimes(1);
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
  });
}

for (const scenario of [
  "policy-edited",
  "foreign-scan",
  "registered-scan",
  "foreign-scan-ordinary",
  "registered-scan-ordinary",
] as const)
  test(`missing report uses registered campaign and severity ${scenario}`, async () => {
    const { paths, source } = await repositoryFixture(
      `report-${scenario}`,
      "repo",
    );
    const environment = {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: join(paths.root, "state"),
    };
    const python = await runtime.resolvePluginPython({ environment });
    const call = (args: readonly string[], input?: string) =>
      runtime.runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const writeActualScan = async (
      checkout: string,
      outputDir: string,
      userContext: string,
    ) => {
      await mkdir(outputDir, { recursive: true, mode: 0o700 });
      const registered = (await call(
        [
          "register-cli-scan",
          "--repository",
          checkout,
          "--scan-dir",
          outputDir,
          "--registration-json-stdin",
        ],
        JSON.stringify({
          recipe: {
            repository: checkout,
            repositoryRevision: source.revision,
            scanRequestDigest: fixtureRequests.get(outputDir)?.digest,
            mode: "standard",
            target: { kind: "repository", paths: [] },
            config: {},
          },
          userContext,
        }),
      )) as unknown as {
        scanId: string;
        targetId: string;
        targetRevision: string;
        contract: { target: { allowedKinds: string[] } };
      };
      await completedScan(outputDir, "complete", checkout);
      for (const name of [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
      ]) {
        const p = join(outputDir, name),
          document = JSON.parse(await readFile(p, "utf8"));
        if (name === "scan-manifest.json") {
          document.scan.id = registered.scanId;
          document.scan.target.kind =
            registered.contract.target.allowedKinds[0];
          document.scan.target.targetId = registered.targetId;
          document.scan.target.revision = registered.targetRevision;
          delete document.scan.target.snapshotDigest;
          delete document.scan.sealedAt;
          delete document.scan.artifacts;
        } else document.scanId = registered.scanId;
        await writeFile(p, JSON.stringify(document));
      }
      await call(["complete-scan", "--scan-id", String(registered.scanId)]);
      return {
        ...(await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT })),
        scanDir: outputDir,
        cost: null,
      } as ScanResult;
    };
    const initial = client(async (checkout, scan) =>
      writeActualScan(
        checkout,
        scan!.outputDir!,
        "Requested campaign instructions.",
      ),
    );
    const configured = options(paths, initial, {
      maxAttempts: 1,
      scanPrompt: "Requested campaign instructions.",
      scanOptionsByMode: { standard: { failureSeverity: "high" } },
    });
    const first = await runMultiscan(configured);
    expect(first.failed).toBe(0);
    expect(first.policyFailed).toBe(true);
    const [receipt] = await results(first.resultsPath);
    expect(receipt!["policyFailed"]).toBe(true);
    const scanDir = String(receipt!["outputDir"]);
    if (scenario.startsWith("foreign-scan")) {
      const checkout = join(paths.output, "checkouts", "repo");
      git(paths.root, "clone", "-q", source.path, checkout);
      const replacement = join(paths.root, "replacement-scan");
      await writeActualScan(
        checkout,
        replacement,
        "Different supplied instructions.",
      );
      await rm(scanDir, { recursive: true });
      await cp(replacement, scanDir, { recursive: true });
      await chmod(scanDir, 0o700);
    }
    if (scenario === "policy-edited") {
      receipt!["policyFailed"] = false;
      await writeFile(first.resultsPath, JSON.stringify(receipt) + "\n");
    }
    await rm(join(scanDir, "report.md"));
    const recoverScan = async (path: string) => {
      const history = await call(["list-scans", "--scan-root", path]);
      const scan = (
        history["scans"] as Array<{ scanId: string; scanDir: string }>
      ).find((row) => row.scanDir === path);
      if (!scan) return undefined;
      const saved = await loadContract(path, {
        pluginRoot: PLUGIN_ROOT,
        expectedScanId: scan.scanId,
      });
      return { manifest: saved.manifest, findings: saved.findings, cost: null };
    };
    const resumed = () =>
      runMultiscan({
        ...configured,
        createSecurity: () =>
          client(throwing("Unexpected replacement analysis")),
        ...(scenario.endsWith("-ordinary") ? {} : { recoverScan }),
      });
    if (scenario === "foreign-scan")
      await expect(resumed()).rejects.toThrow(
        /Scan artifacts do not match selected scan/,
      );
    else if (scenario === "foreign-scan-ordinary")
      expect(await resumed()).toMatchObject({
        completed: 0,
        skipped: 0,
        failed: 1,
      });
    else {
      const value = await resumed();
      expect(value).toMatchObject({
        completed: 1,
        skipped: 1,
        failed: 0,
        policyFailed: true,
      });
      if (scenario === "policy-edited")
        expect(await resumed()).toMatchObject({
          completed: 1,
          skipped: 1,
          failed: 0,
          policyFailed: true,
        });
    }
  });

test.each([
  "missing-cache-write",
  "valid",
  "absent",
  "invalid-authority",
] as const)(
  "validates receipt authority independently of optional cost metadata %s",
  async (variation) => {
    const { paths } = await repositoryFixture("optional-receipt-cost");
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 20,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 5,
      estimatedUsd: 0.01,
    };
    let scans = 0;
    const security = client(async (_target, settings = {}) => {
      scans += 1;
      return Object.assign(await completedScan(settings.outputDir!), { cost });
    });
    const first = await runMultiscan(options(paths, security));
    const [receipt] = await results(first.resultsPath);
    if (variation === "missing-cache-write") {
      delete (receipt!["cost"] as Record<string, unknown>)[
        "cacheWriteInputTokens"
      ];
    } else if (variation === "absent") {
      delete receipt!["cost"];
    } else if (variation === "invalid-authority") {
      receipt!["status"] = "unsupported";
    }
    const bytes = JSON.stringify(receipt) + "\n";
    await writeFile(first.resultsPath, bytes);
    if (variation === "invalid-authority") {
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        "Multiscan recovery is required",
      );
    } else {
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(scans).toBe(1);
      expect(await readFile(first.resultsPath, "utf8")).toBe(bytes);
    }
  },
);
