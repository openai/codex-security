import { createCliTest, captureCli } from "./support/cli-run.js";
import {
  access,
  appendFile,
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import { PYTHON } from "./support/security-policy.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanResult } from "../src/result.js";
import { runMultiscan } from "../src/multiscan.js";
import { DiffTarget, normalizeTarget } from "../src/targets.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { rejecting } from "./support/errors.js";

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
} = createMultiscanFixtures();

afterEach(cleanup);

const testPosix = test.skipIf(process.platform === "win32");

describe("multiscan", () => {
  test("divides an invocation budget across pending repositories and retries", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "source");
    await writeFile(
      paths.input,
      `id,repository,revision
first,${source.path},${source.revision}
second,${source.path},${source.revision}
`,
    );
    const limits: number[] = [];
    const bothStarted = Promise.withResolvers<void>();
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_checkout, scan = {}) => {
          limits.push(scan.maxCostUsd!);
          expect(scan.skipFindingMatching).toBe(true);
          expect(scan.ownerSuggestions).toBe(false);
          if (scan.outputDir!.endsWith("attempt-1")) {
            if (limits.length === 2) bothStarted.resolve();
            await bothStarted.promise;
            throw new Error("Retry this repository");
          }
          return completedScan(scan.outputDir!);
        }),
        {
          maxCostUsd: 12,
          maxTotalCostUsd: 8,
          workers: 2,
          maxAttempts: 2,
          scanOptionsByMode: { standard: { ownerSuggestions: true } },
        },
      ),
    );
    expect(summary).toMatchObject({ completed: 2, failed: 0 });
    expect(limits).toEqual([2, 2, 2, 2]);
  });

  test("charges observed overruns before dispatching queued repository attempts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "source");
    const rows = ["first", "second", "third"].map(
      (id) => `${id},${source.path},${source.revision}`,
    );
    await writeFile(
      paths.input,
      ["id,repository,revision", ...rows].join("\n"),
    );
    const limits: number[] = [];
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repo, scan = {}) => {
          limits.push(scan.maxCostUsd!);
          const estimatedUsd = limits.length === 1 ? 5 : 2;
          throw new ScanCostLimitExceededError(
            scan.maxCostUsd!,
            {
              model: "gpt-5.6-sol",
              inputTokens: 10,
              cachedInputTokens: 0,
              cacheWriteInputTokens: 0,
              outputTokens: 10,
              estimatedUsd,
            },
            scan.outputDir!,
          );
        }),
        { workers: 1, maxAttempts: 1, maxTotalCostUsd: 6 },
      ),
    );
    expect(limits).toEqual([2, 1]);
    expect(summary).toMatchObject({ failed: 3 });
    expect((await results(summary.resultsPath)).at(-1)?.["error"]).toContain(
      "invocation cost limit is exhausted",
    );
  });

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

  const linkedPromptGit =
    "excludes every selected repository from Git lookup for linked bulk prompts";
  test(linkedPromptGit, async () => {
    if (runTestInSubprocess(import.meta.path, linkedPromptGit)) return;
    const { paths, source } = await repositoryFixture("first");
    const second = await repository(paths.root, "second");
    await writeFile(
      paths.input,
      `id,repository,revision\nfirst,${source.path},${source.revision}\nsecond,${second.path},${second.revision}\n`,
    );
    await writeFile(join(paths.root, "prompt.md"), "External prompt.");
    const docs = join(source.path, "docs");
    await symlink(paths.root, docs, "junction");
    const marker = join(paths.root, "untrusted-git-ran");
    const hostGit = Bun.which("git")!;
    const shim = join(
      second.path,
      process.platform === "win32" ? "git.exe" : "git",
    );
    await writeFile(
      shim,
      '#!/bin/sh\necho called > "$SHIM_MARKER"\nexec "$HOST_GIT" "$@"\n',
      { mode: 0o700 },
    );
    process.env["SHIM_MARKER"] = marker;
    process.env["HOST_GIT"] = hostGit;
    process.env["PATH"] = [second.path, process.env["PATH"]].join(delimiter);
    await expect(
      runMultiscan(
        options(paths, client(completeRun), {
          scanPromptFile: join(docs, "prompt.md"),
        }),
      ),
    ).rejects.toThrow("repository directory links");
    expect(await Bun.file(marker).exists()).toBe(false);
    const internal = join(source.path, "internal");
    await mkdir(internal);
    await writeFile(join(internal, "prompt.md"), "Internal prompt.");
    const alias = join(source.path, "alias");
    await symlink(internal, alias, "junction");
    const security = client(async (_checkout, scan = {}) => {
      expect(scan.scanPrompt).toBe("Internal prompt.");
      return await completedScan(scan.outputDir!);
    });
    const result = await runMultiscan(
      options(paths, security, { scanPromptFile: join(alias, "prompt.md") }),
    );
    expect(result).toMatchObject({ completed: 2, failed: 0 });
  });

  test("checks linked bulk documents against the selected Git layout", async () => {
    const { paths, source } = await repositoryFixture("source");
    const settings = options(paths, client(completeRun), { maxAttempts: 1 });
    const direct = join(await filesystem.realpath(paths.root), "policy.md");
    await writeFile(direct, "External document.");
    const docs = join(source.path, "docs");
    await filesystem.symlink(paths.root, docs, "junction");
    const linked = join(docs, "policy.md");

    const { resultsPath } = await runMultiscan({
      ...settings,
      knowledgeBasePaths: [linked],
    });
    expect(await results(resultsPath)).toMatchObject([
      {
        status: "failed",
        error: expect.stringContaining("repository directory links"),
      },
    ]);

    const requireCanonical = async (repository: string) => {
      await writeFile(
        paths.input,
        `id,repository,revision\nrow,${repository},${source.revision}\n`,
      );
      await expect(
        runMultiscan({ ...settings, scanPromptFile: linked }),
      ).rejects.toThrow("canonical path");
    };

    const gitfile = join(source.path, "target.ref");
    await writeFile(
      gitfile,
      `gitdir: ${git(source.path, "rev-parse", "--absolute-git-dir")}\n`,
    );
    await requireCanonical(gitfile);
    const directRun = await runMultiscan({
      ...settings,
      outputDir: join(paths.root, "direct-run"),
      knowledgeBasePaths: [direct],
    });
    expect(directRun.completed).toBe(1);

    const archive = join(paths.root, "archive");
    git(paths.root, "clone", "--bare", source.path, archive + ".git");
    await requireCanonical(archive);
    git(source.path, "config", "core.worktree", paths.root);
    await requireCanonical(source.path);
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

  testPosix.each(["repository", "inventory"])(
    "clones the physical repository through a %s symlink parent traversal",
    async (selection) => {
      const paths = await fixture();
      const source = await repository(paths.root, "physical/repository");
      await repository(paths.root, "entry/repository");
      await mkdir(join(paths.root, "physical", "child"));
      await symlink(
        join(paths.root, "physical", "child"),
        join(paths.root, "entry", "link"),
      );
      const input =
        selection === "inventory"
          ? `${paths.root}/entry/link/../repositories.csv`
          : paths.input;
      await writeFile(
        selection === "inventory"
          ? join(paths.root, "physical", "repositories.csv")
          : input,
        `id,repository,revision\nphysical,${selection === "inventory" ? "repository" : "entry/link/../repository"},${source.revision}\n`,
      );
      let scanned = false;
      const summary = await runMultiscan(
        options(
          { ...paths, input },
          client(async (checkout, scanOptions = {}) => {
            expect(
              await readFile(join(checkout, "src", "app.ts"), "utf8"),
            ).toBe(await readFile(join(source.path, "src", "app.ts"), "utf8"));
            scanned = true;
            return completedScan(scanOptions.outputDir!);
          }),
        ),
      );
      expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
      expect(scanned).toBe(true);
    },
  );

  testPosix.each([
    ["repository", "../source"],
    ["repository ancestor", "../source/src/.."],
    ["terminal alias", "../alias"],
    ["ancestor alias", "../alias/src/.."],
  ])(
    "resumes the recorded %s source without changing traversal spelling",
    async (selection, relativePath) => {
      const paths = await fixture();
      const source = await repository(paths.root, "source");
      const alias = join(paths.root, "alias");
      await symlink(source.path, alias);
      const input = join(paths.root, "inventory", "repositories.csv");
      await mkdir(dirname(input));
      const original = selection.startsWith("repository") ? source.path : alias;
      const inventory = (path: string) =>
        `id,repository,revision\nresume,${path},${source.revision}\n`;
      await writeFile(input, inventory(original));
      const security = client(mock(completeRun));
      const settings = options({ ...paths, input }, security);
      expect(await runMultiscan(settings)).toMatchObject({
        completed: 1,
        failed: 0,
      });
      const manifestPath = join(paths.output, "manifest.json");
      const manifest = await readFile(manifestPath, "utf8");
      expect(JSON.parse(manifest).tasks[0].repository).toBe(original);

      await writeFile(input, inventory(relativePath));
      await expect(runMultiscan(settings)).rejects.toThrow(
        "Multiscan manifest does not match existing output directory.",
      );
      expect(await readFile(manifestPath, "utf8")).toBe(manifest);
      await writeFile(input, inventory(original));
      expect(await runMultiscan(settings)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      await rm(source.path, { recursive: true });
      expect(await runMultiscan(settings)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(await readFile(manifestPath, "utf8")).toBe(manifest);
      expect(security.run).toHaveBeenCalledTimes(1);
    },
  );

  testPosix.each([
    ["traversal", "entry/first/../repository", "entry/second/../repository"],
    ["recorded path", "entry/repository", "entry/first/../repository"],
  ])(
    "rejects changing a %s source at the same revision",
    async (_selection, original, changed) => {
      const paths = await fixture();
      const source = await repository(paths.root, "first/repository");
      await mkdir(join(paths.root, "first", "child"));
      await mkdir(join(paths.root, "second", "child"), { recursive: true });
      await mkdir(join(paths.root, "entry"));
      for (const destination of ["second/repository", "entry/repository"]) {
        git(paths.root, "clone", "--quiet", "--", source.path, destination);
        expect(git(join(paths.root, destination), "rev-parse", "HEAD")).toBe(
          source.revision,
        );
      }
      for (const name of ["first", "second"]) {
        await symlink(
          join(paths.root, name, "child"),
          join(paths.root, "entry", name),
        );
      }
      const inventory = (path: string) =>
        `id,repository,revision\nresume,${path},${source.revision}\n`;
      await writeFile(paths.input, inventory(original));
      const security = client(mock(completeRun));
      const settings = options(paths, security);
      expect(await runMultiscan(settings)).toMatchObject({
        completed: 1,
        failed: 0,
      });
      const manifestPath = join(paths.output, "manifest.json");
      const manifest = await readFile(manifestPath, "utf8");
      await writeFile(paths.input, inventory(changed));
      await expect(runMultiscan(settings)).rejects.toThrow(
        "Multiscan manifest does not match existing output directory.",
      );
      expect(await readFile(manifestPath, "utf8")).toBe(manifest);
      expect(security.run).toHaveBeenCalledTimes(1);

      await rm(
        original === "entry/repository"
          ? join(paths.root, "entry", "repository")
          : source.path,
        { recursive: true },
      );
      expect(
        await runMultiscan({
          ...settings,
          outputDir: join(paths.root, "new-results"),
        }),
      ).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
      expect(security.run).toHaveBeenCalledTimes(2);
    },
  );

  testPosix.each(["link", "target"])(
    "resumes a completed campaign after its traversal %s disappears",
    async (removed) => {
      const paths = await fixture();
      const source = await repository(paths.root, "physical/repository");
      const target = join(paths.root, "physical", "child");
      const link = join(paths.root, "entry", "link");
      await mkdir(target);
      await mkdir(dirname(link));
      await symlink(target, link);
      await writeFile(
        paths.input,
        `id,repository,revision\nresume,entry/link/../repository,${source.revision}\n`,
      );
      const security = client(mock(completeRun));
      const settings = options(paths, security);
      expect(await runMultiscan(settings)).toMatchObject({
        completed: 1,
        failed: 0,
      });
      const manifestPath = join(paths.output, "manifest.json");
      const manifest = await readFile(manifestPath, "utf8");
      await rm(removed === "link" ? link : target, { recursive: true });
      expect(await runMultiscan(settings)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(await readFile(manifestPath, "utf8")).toBe(manifest);
      expect(security.run).toHaveBeenCalledTimes(1);
    },
  );

  testPosix.each(["missing", "file", "file-link"])(
    "does not collapse a %s parent component into another repository",
    async (component) => {
      const paths = await fixture();
      const source = await repository(paths.root, "entry/repository");
      const file = join(paths.root, "entry", "file");
      await writeFile(file, "Synthetic file.\n");
      await symlink(file, join(paths.root, "entry", "file-link"));
      await writeFile(
        paths.input,
        `id,repository,revision\ninvalid,entry/${component}/../repository,${source.revision}\n`,
      );
      const security = client(mock(completeRun));
      expect(
        await runMultiscan(options(paths, security, { maxAttempts: 1 })),
      ).toMatchObject({ completed: 0, failed: 1 });
      expect(security.run).not.toHaveBeenCalled();
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

function interruptCampaign(paths: CampaignPaths) {
  return runMultiscan(
    options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
  );
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
