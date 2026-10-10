import { createCliTest, captureCli } from "./support/cli-run.js";
import { gitText } from "./support/shell.js";
import { parseJsonLines, readJsonLines } from "./support/json.js";
import { resolving } from "./support/promises.js";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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
  utimes,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { hostname, homedir } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  join,
  posix,
  relative,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { zipSync } from "fflate";
import Papa from "papaparse";
import { build } from "esbuild";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contract from "../src/contract.js";
import { writeThreatModel } from "../src/artifact-export.js";
import { PYTHON } from "./support/security-policy.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanResult } from "../src/result.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { normalizeTarget } from "../src/targets.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { DiffTarget } from "../src/targets.js";
import { prepareOutputDir } from "../src/runtime.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import * as runtime from "../src/runtime.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-multiscan-",
);
const testPosix = process.platform === "win32" ? test.skip : test;

const fixtureRoots = new Set<string>();
afterEach(async () => {
  await cleanup();
  fixtureRoots.clear();
});

async function fixture(): Promise<{
  root: string;
  input: string;
  output: string;
}> {
  const root = await temporaryDirectory();
  fixtureRoots.add(root);
  return {
    root,
    input: join(root, "repositories.csv"),
    output: join(root, "results"),
  };
}

function git(repository: string, ...args: string[]): string {
  return gitText(["-C", repository, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

async function repository(
  root: string,
  name: string,
  objectFormat = "sha1",
): Promise<{ path: string; revision: string }> {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q", `--object-format=${objectFormat}`);
  await writeFile(join(path, ".gitattributes"), "* text eol=lf\n");
  git(path, "add", ".");
  git(
    path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "initial",
  );
  return { path, revision: git(path, "rev-parse", "HEAD") };
}

async function repositoryFixture(name: string, id = name) {
  const paths = await fixture();
  const source = await repository(paths.root, name);
  await writeFile(
    paths.input,
    `id,repository,revision\n${id},${source.path},${source.revision}\n`,
  );
  return { paths, source };
}

async function completedScan(
  outputDir: string,
  completeness: "complete" | "partial" | "unknown" = "complete",
  targetRoot?: string,
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  await chmod(outputDir, 0o700);
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), outputDir, {
    recursive: true,
  });
  await writeFile(join(outputDir, "report.md"), "# Scan report\n");
  const manifestPath = join(outputDir, "scan-manifest.json");
  const findingsPath = join(outputDir, "findings.json");
  const coveragePath = join(outputDir, "coverage.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ScanResult["manifest"];
  const findings = JSON.parse(
    await readFile(findingsPath, "utf8"),
  ) as ScanResult["findings"];
  const coverage = JSON.parse(
    await readFile(coveragePath, "utf8"),
  ) as ScanResult["coverage"];
  const id = basename(dirname(outputDir));
  const campaignRoot = dirname(dirname(dirname(outputDir)));
  const fixtureRoot = [...fixtureRoots].find((root) =>
    outputDir.startsWith(root + sep),
  );
  const inventory =
    fixtureRoot === undefined
      ? undefined
      : await readFile(join(fixtureRoot, "repositories.csv"), "utf8").catch(
          () => undefined,
        );
  if (inventory !== undefined) {
    const task = Papa.parse<Record<string, string>>(inventory, {
      header: true,
      skipEmptyLines: true,
    }).data.find((entry) => entry["id"] === id);
    if (task !== undefined) {
      manifest.scan.target.kind = "git_revision";
      manifest.scan.target.targetId = `target_sha256_${createHash("sha256")
        .update(
          `local-workspace\0${targetRoot ?? join(campaignRoot, "checkouts", id)}`,
        )
        .digest("hex")}`;
      manifest.scan.target.displayName = basename(
        targetRoot ?? join(campaignRoot, "checkouts", id),
      );
      manifest.scan.target.revision = task["revision"]!;
      delete manifest.scan.target.snapshotDigest;
      const scope = task["scope"]?.trim();
      let normalizedScope = scope ? posix.normalize(scope) : ".";
      if (scope) {
        const checkout = targetRoot ?? join(campaignRoot, "checkouts", id);
        const canonicalScope = await realpath(join(checkout, scope)).catch(
          () => undefined,
        );
        if (canonicalScope !== undefined) {
          normalizedScope =
            relative(await realpath(checkout), canonicalScope)
              .split(sep)
              .join("/") || ".";
        }
      }
      const includePaths = [normalizedScope];
      manifest.scan.scope.includePaths = includePaths;
      coverage.includePaths = includePaths;
      coverage.mode = scope
        ? "scoped_path"
        : task["mode"]?.trim() === "deep"
          ? "deep_repository"
          : "repository";
      coverage.inventoryStrategy = scope ? "scoped_path" : "repository";
    }
  }
  for (const finding of findings.findings) {
    const fingerprint = `codex-security/v1:sha256:${createHash("sha256")
      .update(
        [
          "codex-security/v1",
          manifest.scan.target.targetId,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? "",
        ].join("\0"),
      )
      .digest("hex")}`;
    finding.fingerprints.primary = fingerprint;
    finding.findingId = `csf_${createHash("sha256")
      .update(fingerprint)
      .digest("hex")
      .slice(0, 24)}`;
    finding.occurrenceId = `occ_${createHash("sha256")
      .update([manifest.scan.id, fingerprint].join("\0"))
      .digest("hex")
      .slice(0, 24)}`;
  }
  coverage.completeness = completeness;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
  await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
  await reseal(outputDir);
  return { manifest, coverage: { completeness } } as ScanResult;
}

async function reseal(outputDir: string): Promise<void> {
  const path = join(outputDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(path, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(outputDir, artifact.path)))
      .digest("hex");
  }
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

const completeRun: SecurityClient["run"] = async (
  _repository,
  scanOptions = {},
) => {
  return await completedScan(scanOptions.outputDir!);
};

const completeRunWithoutAwait: SecurityClient["run"] = async (
  _repository,
  scanOptions = {},
) => {
  return completedScan(scanOptions.outputDir!);
};

function client<Run extends SecurityClient["run"]>(
  run: Run,
  close: SecurityClient["close"] = async () => {},
): SecurityClient & { run: Run } {
  return { run, close };
}

function options(
  paths: { input: string; output: string },
  security: SecurityClient,
  overrides: Partial<MultiscanOptions> = {},
): MultiscanOptions {
  return {
    inputPath: paths.input,
    outputDir: paths.output,
    workers: 1,
    mode: "standard",
    maxAttempts: 2,
    config: {},
    createSecurity: () => security,
    ...overrides,
  };
}

const results = readJsonLines<Record<string, unknown>>;

describe("multiscan", () => {
  test.each([false, true])(
    "only links current models from failed child runs with recovery=%p",
    async (recovery) => {
      const paths = await fixture();
      const source = await repository(paths.root, "model-source");
      await writeFile(
        paths.input,
        `id,repository,revision\ncurrent,${source.path},${source.revision}\nstale,${source.path},${source.revision}\n`,
      );
      if (recovery)
        await runMultiscan(
          options(
            paths,
            client(async () => {
              throw new Error("Synthetic interruption before checkpoint");
            }),
            { maxAttempts: 1, config: { pythonPath: PYTHON } },
          ),
        );
      const checkouts: string[] = [];
      const python = spyOn(runtime, "resolvePluginPython");
      let summary;
      try {
        summary = await runMultiscan(
          options(
            paths,
            client(async (checkout, scanOptions = {}) => {
              checkouts.push(checkout);
              const directory = scanOptions.outputDir!;
              await mkdir(directory, { recursive: true });
              const manifest = {
                documentType: "codex-security.policy-draft",
                status: "threat_model_ready",
                threatModel: {
                  format: "markdown",
                  content: "# Earlier model\n",
                },
              };
              await writeFile(
                join(directory, "policy-draft.json"),
                JSON.stringify(manifest),
              );
              await writeThreatModel(directory, { pythonPath: PYTHON });
              if (directory.includes("stale")) {
                manifest.threatModel.content = "# Updated model\n";
                await writeFile(
                  join(directory, "policy-draft.json"),
                  JSON.stringify(manifest),
                );
              }
              throw new Error("Synthetic child failure after checkpoint");
            }),
            {
              maxAttempts: 1,
              config: { pythonPath: PYTHON },
              ...(recovery ? { recoverScan: async () => undefined } : {}),
            },
          ),
        );
        expect(checkouts).toHaveLength(2);
        for (const checkout of checkouts) {
          expect(python).toHaveBeenCalledWith(
            expect.objectContaining({
              configuredPath: PYTHON,
              protectedRoot: checkout,
            }),
          );
          if (recovery)
            expect((await lstat(checkout)).isDirectory()).toBe(true);
          else await expect(lstat(checkout)).rejects.toThrow();
        }
      } finally {
        python.mockRestore();
      }
      const rows = (await results(summary.resultsPath)).reverse();
      expect(
        rows.find((row) => row["id"] === "current")?.["threatModelPath"],
      ).toBeString();
      expect(
        rows.find((row) => row["id"] === "stale")?.["threatModelPath"],
      ).toBeUndefined();
    },
  );

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

  test("canceled recovery retains the new checkout and attempt without appending a failure receipt", async () => {
    const { paths } = await repositoryFixture("cancel-recovery", "repo");
    await runMultiscan(
      options(paths, client(rejecting("Stopped")), { maxAttempts: 1 }),
    );
    const before = await readFile(join(paths.output, "results.jsonl"), "utf8");
    const controller = new AbortController();
    let retained = "";
    await expect(
      runMultiscan(
        options(
          paths,
          client(async (checkout, scan = {}) => {
            retained = checkout;
            await writeFile(join(scan.outputDir!, "checkpoint"), "keep");
            controller.abort(new Error("Interrupted recovery"));
            controller.signal.throwIfAborted();
            throw new Error("Unreachable");
          }),
          { recoverScan: async () => undefined, signal: controller.signal },
        ),
      ),
    ).rejects.toThrow("Interrupted recovery");
    expect(await readFile(join(retained, "src", "app.ts"), "utf8")).toContain(
      "cancel-recovery",
    );
    expect(
      await readFile(
        join(paths.output, "artifacts", "repo", "attempt-2", "checkpoint"),
        "utf8",
      ),
    ).toBe("keep");
    expect(await readFile(join(paths.output, "results.jsonl"), "utf8")).toBe(
      before,
    );
  });

  test.each([false, true])(
    "occupied bulk attempts preserve the checkout with missing knowledge=%p",
    async (missingKnowledge) => {
      const { paths } = await repositoryFixture("occupied", "repo");
      const document = join(paths.root, "context.md");
      await writeFile(document, "Original context.");
      const scanDir = join(paths.output, "artifacts", "repo", "attempt-1");
      const checkout = join(paths.output, "checkouts", "repo");
      const arguments_ = [
        "bulk-scan",
        paths.input,
        "--output-dir",
        paths.output,
        "--knowledge-base",
        document,
        "--json",
      ];
      const deps = dependencies();
      let initializing = true;
      let scans = 0;
      const configured: typeof deps = {
        ...deps,
        createSecurity: (config) => ({
          ...deps.createSecurity(config),
          run: async (repo, scan = {}) => {
            if (initializing) throw new Error("Synthetic interrupted setup");
            scans++;
            expect(repo).not.toBe(checkout);
            await prepareOutputDir(scan.outputDir, "repo");
            return completedScan(scan.outputDir!);
          },
        }),
      };
      await main(arguments_, capture().stream, capture().stream, configured);
      initializing = false;
      await rm(join(paths.output, "results.jsonl"));
      await mkdir(scanDir, { recursive: true, mode: 0o700 });
      await mkdir(checkout, { recursive: true });
      await writeFile(join(scanDir, "checkpoint"), "keep");
      await writeFile(join(checkout, "source"), "keep checkout");
      if (missingKnowledge) await rm(document);
      const error = capture();
      const output = capture();
      const code = await main(
        [...arguments_, "--max-attempts", "3"],
        output.stream,
        error.stream,
        configured,
      );
      expect(code).toBe(2);
      expect(error.text()).toContain("--recover");
      expect(error.text()).not.toContain("--archive-existing");
      expect(scans).toBe(0);
      const receipts = await results(JSON.parse(output.text()).resultsPath);
      expect(receipts).toHaveLength(1);
      expect(receipts[0]).toMatchObject({
        status: "failed",
        attempt: 1,
        error: expect.stringContaining("--recover"),
      });
      expect(receipts[0]!["knowledgeBaseFailure"]).toBeUndefined();
      expect(await readFile(join(checkout, "source"), "utf8")).toBe(
        "keep checkout",
      );
      expect(await readFile(join(scanDir, "checkpoint"), "utf8")).toBe("keep");
      await expect(prepareOutputDir(scanDir, "repo")).rejects.toThrow(
        "--archive-existing",
      );
      await writeFile(document, "Original context.");
      const recovered = capture();
      expect(
        await main(
          [...arguments_, "--recover"],
          recovered.stream,
          capture().stream,
          configured,
        ),
      ).toBe(0);
      expect(JSON.parse(recovered.text())).toMatchObject({
        completed: 1,
        failed: 0,
      });
      expect(scans).toBe(1);
      expect(
        (await results(JSON.parse(recovered.text()).resultsPath)).at(-1),
      ).toMatchObject({
        status: "completed",
        attempt: 2,
      });
      expect(await readFile(join(checkout, "source"), "utf8")).toBe(
        "keep checkout",
      );
      expect(await readFile(join(scanDir, "checkpoint"), "utf8")).toBe("keep");
    },
  );

  test("CLI escapes bulk failure controls while preserving the saved receipt", async () => {
    const { paths } = await repositoryFixture("failure", "repo");
    const failure = "Bulk failed: token=SYNTHETIC_VALUE\u001b[2J\ncontinued";
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    expect(
      await runCli(
        [
          "bulk-scan",
          paths.input,
          "--output-dir",
          paths.output,
          "--max-attempts",
          "1",
          "--json",
        ],
        {
          ...deps,
          createSecurity: (config) => ({
            ...deps.createSecurity(config),
            run: rejecting(failure),
          }),
        },
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "Bulk failed: token=SYNTHETIC_VALUE [2J continued\n",
    );
    expect(stderr.text()).not.toContain("\u001b");
    expect(await results(JSON.parse(stdout.text()).resultsPath)).toMatchObject([
      { status: "failed", error: failure },
    ]);
  });

  test("recovery skips untouched rows and saves an interrupted ledger tail before appending", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "tail");
    const tasks = ["failed", "untouched"].map((id) => ({
      id,
      repository: source.path,
      revision: source.revision,
      mode: "standard",
    }));
    await writeFile(
      paths.input,
      `id,repository,revision\n${tasks.map((task) => `${task.id},${task.repository},${task.revision}`).join("\n")}\n`,
    );
    await mkdir(paths.output);
    await writeFile(
      join(paths.output, "manifest.json"),
      JSON.stringify({ version: 2, tasks }, null, 2) + "\n",
    );
    const tail = '{"id":"failed","status":';
    const original =
      JSON.stringify({
        ...tasks[0],
        status: "failed",
        attempt: 1,
        outputDir: join(paths.output, "artifacts", "failed", "attempt-1"),
      }) + "\n";
    await writeFile(join(paths.output, "results.jsonl"), original + tail);
    const runs = mock(completeRunWithoutAwait);
    const result = await runMultiscan(
      options(paths, client(runs), { recoverScan: async () => undefined }),
    );
    expect(result).toMatchObject({
      total: 2,
      completed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(runs.mock.calls.length).toBe(1);
    expect(
      (await readFile(result.resultsPath, "utf8")).startsWith(original),
    ).toBe(true);
    const backup = (await readdir(paths.output)).find((name) =>
      name.startsWith("results.jsonl.interrupted-"),
    );
    expect(backup).toBeDefined();
    expect(await readFile(join(paths.output, backup!), "utf8")).toBe(tail);
  });

  test("recovery preserves occupied attempts and checkouts while retrying only failed repositories", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "recovery");
    await writeFile(
      paths.input,
      `id,repository,revision,mode\nfailed,${source.path},${source.revision},deep\ndone,${source.path},${source.revision},deep\n`,
    );
    const failedDir = join(paths.output, "artifacts", "failed", "attempt-1");
    const first = await runMultiscan(
      options(
        paths,
        client(async (_repo, scan = {}) => {
          if (scan.outputDir === failedDir) throw new Error("Interrupted scan");
          return completedScan(scan.outputDir!, "partial");
        }),
        { maxAttempts: 1 },
      ),
    );
    const before = await readFile(first.resultsPath, "utf8");
    const orphan = join(paths.output, "artifacts", "failed", "attempt-5");
    const checkout = join(paths.output, "checkouts", "failed");
    await mkdir(orphan, { recursive: true });
    await mkdir(checkout, { recursive: true });
    await writeFile(join(orphan, "checkpoint"), "keep checkpoint");
    await writeFile(join(checkout, "source"), "keep checkout");
    const inode = (await lstat(checkout)).ino;
    const resumed = mock(resolving<undefined, [string]>(undefined));
    const runs = mock<SecurityClient["run"]>(async (repo, scan = {}) => {
      expect(repo).not.toBe(checkout);
      expect(git(repo, "rev-parse", "HEAD")).toBe(source.revision);
      expect(scan.mode).toBe("deep");
      expect(scan.outputDir).toBe(
        join(paths.output, "artifacts", "failed", "attempt-6"),
      );
      return completedScan(scan.outputDir!);
    });
    const result = await runMultiscan(
      options(paths, client(runs), {
        maxAttempts: 1,
        recoverScan: resumed,
      }),
    );
    expect(result).toMatchObject({
      completed: 1,
      incomplete: 1,
      failed: 0,
      skipped: 1,
    });
    expect(runs.mock.calls.length).toBe(1);
    expect(resumed.mock.calls.map(([value]) => value)).toEqual([orphan]);
    expect((await lstat(checkout)).ino).toBe(inode);
    expect(await readFile(join(checkout, "source"), "utf8")).toBe(
      "keep checkout",
    );
    expect(await readFile(join(orphan, "checkpoint"), "utf8")).toBe(
      "keep checkpoint",
    );
    expect(
      (await readFile(result.resultsPath, "utf8")).startsWith(before),
    ).toBe(true);
    expect((await results(result.resultsPath)).at(-1)).toMatchObject({
      id: "failed",
      attempt: 6,
      status: "completed",
    });
  });

  test.each([false, true])(
    "recovery records the original attempt and preserves it after resume failure=%p",
    async (failure) => {
      const paths = await fixture();
      const source = await repository(paths.root, "retained");
      await writeFile(
        paths.input,
        `id,repository,revision\nretained,${source.path},${source.revision}\n`,
      );
      const document = join(paths.root, "context.md");
      await writeFile(document, "Synthetic context.");
      const knowledgeBasePaths = [document];
      await runMultiscan(
        options(
          paths,
          client(async () => {
            throw new Error("Stopped");
          }),
          { maxAttempts: 1, knowledgeBasePaths },
        ),
      );
      const dir = join(paths.output, "artifacts", "retained", "attempt-1");
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "checkpoint"), "keep");
      let resumed = 0;
      let runs = 0;
      const configured = options(
        paths,
        client(async (_repo, scan = {}) => {
          runs++;
          return completedScan(scan.outputDir!);
        }),
        {
          maxAttempts: 3,
          knowledgeBasePaths,
          recoverScan: async (scanDir) => {
            resumed++;
            expect(scanDir).toBe(dir);
            if (failure) throw new Error("Resume transport failed");
            return completedScan(scanDir);
          },
        },
      );
      await rm(document);
      expect(
        await runMultiscan({
          ...configured,
          recoverScan: undefined,
          maxAttempts: 2,
        }),
      ).toMatchObject({ completed: 0, failed: 1 });
      expect(
        (await results(join(paths.output, "results.jsonl"))).at(-1),
      ).toMatchObject({ status: "failed", attempt: 3 });
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 0,
        failed: 1,
      });
      expect(resumed).toBe(0);
      expect(
        (await results(join(paths.output, "results.jsonl"))).at(-1),
      ).toMatchObject({
        status: "failed",
        attempt: 1,
      });
      await writeFile(document, "Synthetic context.");
      const summary = await runMultiscan(configured);
      expect(runs).toBe(0);
      expect(resumed).toBe(1);
      expect(summary.failed).toBe(failure ? 1 : 0);
      expect(summary.completed).toBe(failure ? 0 : 1);
      expect((await results(summary.resultsPath)).at(-1)).toMatchObject({
        attempt: 1,
        outputDir: dir,
        status: failure ? "failed" : "completed",
      });
      expect(await readFile(join(dir, "checkpoint"), "utf8")).toBe("keep");
      if (failure) {
        const retried = await runMultiscan({
          ...configured,
          recoverScan: undefined,
          maxAttempts: 1,
        });
        expect(retried).toMatchObject({ completed: 1, failed: 0 });
        expect((await results(retried.resultsPath)).at(-1)).toMatchObject({
          status: "completed",
          attempt: 4,
        });
      }
    },
  );

  test.each([
    [false, "checkouts"],
    [true, "checkouts"],
    [false, "recovery-checkouts"],
    [true, "recovery-checkouts"],
  ] as const)(
    "recovery records the original attempt with failure=%p and retained %s",
    async (failure, layout) => {
      const { paths } = await repositoryFixture("retained");
      await runMultiscan(
        options(paths, client(rejecting("Stopped")), {
          maxAttempts: 1,
          config: { pythonPath: PYTHON },
        }),
      );
      const dir = join(paths.output, "artifacts", "retained", "attempt-1");
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "checkpoint"), "keep");
      const checkout = join(
        paths.output,
        layout,
        "retained",
        ...(layout === "recovery-checkouts" ? ["attempt-1"] : []),
      );
      await mkdir(checkout, { recursive: true });
      await writeFile(join(checkout, "source"), "keep checkout");
      const recoverScan = mock(async (scanDir: string) => {
        expect(scanDir).toBe(dir);
        if (failure) throw new Error("Resume transport failed");
        return completedScan(scanDir, "complete", checkout);
      });
      const runs = mock(completeRunWithoutAwait);
      const python = spyOn(runtime, "resolvePluginPython");
      let summary;
      try {
        summary = await runMultiscan(
          options(paths, client(runs), {
            maxAttempts: 3,
            config: { pythonPath: PYTHON },
            recoverScan,
          }),
        );
        expect(python).toHaveBeenCalledWith(
          expect.objectContaining({
            configuredPath: PYTHON,
            protectedRoot: checkout,
          }),
        );
      } finally {
        python.mockRestore();
      }
      expect(await readFile(join(checkout, "source"), "utf8")).toBe(
        "keep checkout",
      );
      expect(runs.mock.calls.length).toBe(0);
      expect(recoverScan).toHaveBeenCalledTimes(1);
      expect(summary.failed).toBe(failure ? 1 : 0);
      expect(summary.completed).toBe(failure ? 0 : 1);
      expect((await results(summary.resultsPath)).at(-1)).toMatchObject({
        attempt: 1,
        outputDir: dir,
        status: failure ? "failed" : "completed",
      });
      expect(await readFile(join(dir, "checkpoint"), "utf8")).toBe("keep");
      if (!failure) {
        expect(
          await runMultiscan(
            options(paths, client(runs), { config: { pythonPath: PYTHON } }),
          ),
        ).toMatchObject({
          completed: 1,
          skipped: 1,
          failed: 0,
        });
        expect(runs).toHaveBeenCalledTimes(0);
        expect(recoverScan).toHaveBeenCalledTimes(1);
      }
    },
  );

  test.each(["high", "low"] as const)(
    "recovery applies the campaign severity policy to %s findings and retains the outcome",
    async (severity) => {
      const { paths } = await repositoryFixture("policy-recovery", "repo");
      const configured = options(paths, client(rejecting("Interrupted scan")), {
        maxAttempts: 1,
        scanPrompt: "Shared scan instructions.",
        scanOptionsByMode: { standard: { failureSeverity: "high" } },
      });
      await runMultiscan(configured);
      await mkdir(join(paths.output, "artifacts", "repo", "attempt-1"), {
        recursive: true,
      });
      const result = await runMultiscan({
        ...configured,
        recoverScan: async (scanDir, prompts) => {
          expect(prompts.scanPrompt).toBe("Shared scan instructions.");
          await completedScan(scanDir);
          const findingsPath = join(scanDir, "findings.json");
          const saved = JSON.parse(
            await readFile(findingsPath, "utf8"),
          ) as ScanResult["findings"];
          for (const finding of saved.findings)
            finding.severity.level = severity;
          await writeFile(findingsPath, JSON.stringify(saved));
          await reseal(scanDir);
          const recovered = fakeResult([severity]);
          return {
            coverage: recovered.coverage,
            cost: recovered.cost,
            findings: recovered.findings,
          };
        },
      });
      expect(result).toMatchObject({
        completed: 1,
        failed: 0,
        policyFailed: severity === "high",
      });
      expect((await results(result.resultsPath)).at(-1)).toMatchObject({
        attempt: 1,
        policyFailed: severity === "high",
      });
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        skipped: 1,
        policyFailed: severity === "high",
      });
    },
  );

  test("bulk recovery requires an existing campaign and a CSV", async () => {
    const { paths } = await repositoryFixture("missing-campaign", "repo");
    for (const args of [
      ["--recover"],
      [paths.input, "--output-dir", paths.output, "--recover"],
    ]) {
      const error = captureCli(main, "stderr");
      const code = await error.run(["bulk-scan", ...args], dependencies());
      expect(code).toBe(2);
      expect(error.text()).toMatch(/recovery requires/i);
    }
  });

  test("scopes GitHub CLI credentials to the discovered GitHub host", () => {
    expect(buildGitHubCredentialArgs(undefined)).toEqual([]);
    expect(buildGitHubCredentialArgs("github.com")).toEqual([
      "-c",
      "credential.https://github.com.helper=",
      "-c",
      "credential.https://github.com.helper=!gh auth git-credential",
    ]);
    expect(buildGitHubCredentialArgs("github.acme.example")).toEqual([
      "-c",
      "credential.https://github.acme.example.helper=",
      "-c",
      "credential.https://github.acme.example.helper=!gh auth git-credential",
    ]);
    for (const host of [
      "github.com/another-owner",
      "user@github.com",
      "github.com?token=secret",
      "github.com#fragment",
    ]) {
      expect(() => buildGitHubCredentialArgs(host)).toThrow(
        "GitHub credential host is invalid",
      );
    }
  });

  test("uses GitHub credentials for discovered checkouts without changing global Git configuration", async () => {
    const { paths } = await repositoryFixture("github-credentials", "private");
    const configured = gitText(
      [
        ...buildGitHubCredentialArgs("github.acme.example"),
        "config",
        "--get-all",
        "credential.https://github.acme.example.helper",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    expect(configured.trim()).toBe("!gh auth git-credential");

    const summary = await runMultiscan(
      options(paths, client(completeRun), {
        githubHost: "github.acme.example",
      }),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
  });

  test("parses quoted CSV fields, embedded delimiters, and Windows line endings", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "comma, quoted");
    await writeFile(
      paths.input,
      `\uFEFF"id","repository","revision","scope","mode","prompt","notes"\r\n"payments","${source.path}","${source.revision}","src","deep","Focus on authentication, authorization.","contains ""quotes"""\r\n\r\n`,
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.target).toEqual(["src"]);
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

    expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "priced", status: "completed", coverage: "complete", cost },
    ]);
  });

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
      incomplete: 0,
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

      expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
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

  test.each(["partial", "unknown"] as const)(
    "retains sealed %s coverage without retries or multiplied costs",
    async (completeness) => {
      const { paths } = await repositoryFixture(completeness, "sealed");
      const document = join(paths.root, "context.md");
      await writeFile(document, "Original context.");
      const knowledgeBasePaths = [document];
      const cost = {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 12.5,
      };
      const progress: Parameters<
        NonNullable<MultiscanOptions["onProgress"]>
      >[0][] = [];
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return Object.assign(
          await completedScan(scanOptions.outputDir!, completeness),
          { cost },
        );
      });

      const summary = await runMultiscan(
        options(paths, security, {
          maxAttempts: 3,
          knowledgeBasePaths,
          onProgress: (event) => progress.push(event),
        }),
      );

      expect(attempts).toBe(1);
      expect(summary).toMatchObject({
        total: 1,
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 0,
      });
      const outputDir = join(paths.output, "artifacts", "sealed", "attempt-1");
      const warning = `Scan coverage is ${completeness}; results may be incomplete.`;
      const receipts = await results(summary.resultsPath);
      expect(receipts).toMatchObject([
        {
          id: "sealed",
          status: "completed_with_incomplete_coverage",
          attempt: 1,
          outputDir,
          coverage: completeness,
          cost,
          warning,
        },
      ]);
      expect(
        receipts.reduce(
          (total, receipt) =>
            total + (receipt["cost"] as typeof cost).estimatedUsd,
          0,
        ),
      ).toBe(cost.estimatedUsd);
      await Promise.all(
        [
          "scan-manifest.json",
          "findings.json",
          "coverage.json",
          "report.md",
        ].map((name) => access(join(outputDir, name))),
      );
      expect(progress).toMatchObject([
        { repository: "sealed", status: "started", attempt: 1 },
        {
          repository: "sealed",
          status: "completed_with_incomplete_coverage",
          attempt: 1,
          warning,
        },
      ]);

      const resumed = await runMultiscan(
        options(paths, security, {
          maxAttempts: 3,
          knowledgeBasePaths,
          onProgress: throwing("Optional progress observer failed."),
        }),
      );
      expect(resumed).toMatchObject({
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 1,
      });
      expect(attempts).toBe(1);
      expect(await results(resumed.resultsPath)).toHaveLength(1);
      await rm(document);
      expect(
        await runMultiscan(options(paths, security, { knowledgeBasePaths })),
      ).toMatchObject({ completed: 0, incomplete: 0, failed: 1 });
      await writeFile(document, "Original context.");
      expect(
        await runMultiscan(options(paths, security, { knowledgeBasePaths })),
      ).toMatchObject({ incomplete: 1, failed: 0, skipped: 1 });
      expect(attempts).toBe(1);
      const afterRepair = await results(resumed.resultsPath);
      expect(afterRepair).toHaveLength(3);
      expect(
        afterRepair.reduce(
          (total, receipt) =>
            total +
            ((receipt["cost"] as typeof cost | undefined)?.estimatedUsd ?? 0),
          0,
        ),
      ).toBe(cost.estimatedUsd);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "resumes legacy sealed %s coverage without rerunning or duplicating cost",
    async (completeness) => {
      const { paths, source } = await repositoryFixture(
        `legacy-${completeness}`,
        "legacy",
      );
      const outputDir = join(paths.output, "artifacts", "legacy", "attempt-1");
      await completedScan(outputDir, completeness);
      const cost = {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 231.73,
      };
      const receipt = {
        id: "legacy",
        repository: source.path,
        revision: source.revision,
        mode: "standard",
        status: "failed",
        attempt: 1,
        outputDir,
        cost,
        error: "Multiscan repository coverage is incomplete.",
      };
      await writeFile(
        join(paths.output, "results.jsonl"),
        `${JSON.stringify(receipt)}\n`,
      );
      const progress: Parameters<
        NonNullable<MultiscanOptions["onProgress"]>
      >[0][] = [];
      const security = client(mock(completeRun));

      const summary = await runMultiscan(
        options(paths, security, {
          maxAttempts: 3,
          onProgress: (event) => progress.push(event),
        }),
      );

      expect(summary).toMatchObject({
        total: 1,
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 1,
      });
      expect(security.run.mock.calls.length).toBe(0);
      expect(progress).toEqual([
        {
          repository: "legacy",
          status: "completed_with_incomplete_coverage",
          attempt: 1,
          warning: `Scan coverage is ${completeness}; results may be incomplete.`,
        },
      ]);
      expect(await results(summary.resultsPath)).toEqual([receipt]);

      await runMultiscan(options(paths, security, { maxAttempts: 3 }));
      expect(security.run.mock.calls.length).toBe(0);
      expect(await results(summary.resultsPath)).toEqual([receipt]);
    },
  );

  test.each([
    ["operational failures", "partial", "Worker exited unexpectedly.", false],
    [
      "complete coverage",
      "complete",
      "Multiscan repository coverage is incomplete.",
      false,
    ],
    [
      "malformed coverage",
      "malformed",
      "Multiscan repository coverage is incomplete.",
      false,
    ],
    [
      "missing artifacts",
      "partial",
      "Multiscan repository coverage is incomplete.",
      true,
    ],
  ] as const)(
    "continues retrying legacy %s",
    async (_scenario, completeness, error, missingArtifact) => {
      const { paths, source } = await repositoryFixture(
        "legacy-retry",
        "legacy",
      );
      const outputDir = join(paths.output, "artifacts", "legacy", "attempt-1");
      await completedScan(outputDir);
      await writeFile(
        join(outputDir, "coverage.json"),
        completeness === "malformed"
          ? "{\n"
          : `${JSON.stringify({ completeness })}\n`,
      );
      if (missingArtifact) await rm(join(outputDir, "report.md"));
      await writeFile(
        join(paths.output, "results.jsonl"),
        `${JSON.stringify({
          id: "legacy",
          repository: source.path,
          revision: source.revision,
          mode: "standard",
          status: "failed",
          attempt: 1,
          outputDir,
          error,
        })}\n`,
      );
      const attempts = mock(completeRun);

      const summary = await runMultiscan(options(paths, client(attempts)));

      expect(summary).toMatchObject({
        completed: 1,
        incomplete: 0,
        failed: 0,
        skipped: 0,
      });
      expect(attempts.mock.calls.length).toBe(1);
      expect(await results(summary.resultsPath)).toMatchObject([
        { status: "failed", attempt: 1, error },
        { status: "completed", attempt: 2, coverage: "complete" },
      ]);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "keeps sealed %s-coverage CLI runs fail-closed without retrying",
    async (completeness) => {
      const { paths } = await repositoryFixture("sample");
      const outputDir = join(paths.output, "artifacts", "sample", "attempt-1");
      const result = fakeResult([], completeness);
      const { stdout, stderr, runCli } = createCliTest(main);

      const onRun = mock();
      const arguments_ = [
        "bulk-scan",
        "repositories.csv",
        "--output-dir",
        "results",
        "--max-attempts",
        "3",
        "--json",
      ];
      const clientDependencies = dependencies({
        currentDirectory: paths.root,
        result,
        onRun,
      });
      const createSecurity = clientDependencies.createSecurity;
      clientDependencies.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          run: async (repository, scan = {}) => {
            const completed = await completedScan(
              scan.outputDir!,
              completeness,
            );
            result.manifest.scan.target = completed.manifest.scan.target;
            return security.run(repository, scan);
          },
        };
      };

      expect(await runCli(arguments_, clientDependencies)).toBe(2);
      expect(onRun).toHaveBeenCalledTimes(1);
      expect(JSON.parse(stdout.text())).toMatchObject({
        total: 1,
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 0,
      });
      const warning = `Scan coverage is ${completeness}; results may be incomplete.`;
      expect(stderr.text()).toContain(
        "sample completed_with_incomplete_coverage (attempt 1)",
      );
      expect(stderr.text()).toContain(warning);
      expect(stderr.text()).not.toContain("attempt 2");
      expect(await results(join(paths.output, "results.jsonl"))).toMatchObject([
        {
          status: "completed_with_incomplete_coverage",
          coverage: completeness,
          outputDir,
        },
      ]);

      const resumedOutput = capture();
      const resumedError = capture();
      expect(
        await main(
          arguments_,
          resumedOutput.stream,
          resumedError.stream,
          clientDependencies,
        ),
      ).toBe(2);
      expect(JSON.parse(resumedOutput.text())).toMatchObject({
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 1,
      });
      expect(resumedError.text()).toContain(warning);
      expect(onRun).toHaveBeenCalledTimes(1);
    },
  );

  test("retries incomplete scans that are missing required artifacts", async () => {
    const { paths } = await repositoryFixture("missing-artifact", "missing");

    const attempts = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        const result = await completedScan(
          scanOptions.outputDir!,
          attempts.mock.calls.length === 1 ? "partial" : "complete",
        );
        if (attempts.mock.calls.length === 1) {
          await rm(join(scanOptions.outputDir!, "report.md"));
        }
        return result;
      },
    );
    const summary = await runMultiscan(options(paths, client(attempts)));

    expect(attempts.mock.calls.length).toBe(2);
    expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "missing",
        status: "failed",
        attempt: 1,
        coverage: "partial",
        error: "Multiscan scan output is missing required artifacts.",
      },
      { id: "missing", status: "completed", attempt: 2, coverage: "complete" },
    ]);
  });

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
    for (const id of ["task.", "CON", "nul.txt", "COM1", "LPT9.log"]) {
      await writeFile(
        paths.input,
        `id,repository,revision\n${id},./repository,${"0".repeat(40)}\n`,
      );

      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        "safe, unique path names",
      );
    }

    expect(scans.mock.calls.length).toBe(0);
  });

  test("materializes the pinned commit, applies row options, and removes its checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "payments");
    await writeFile(
      join(source.path, "src", "app.ts"),
      "export const changed = true;\n",
    );
    git(source.path, "add", ".");
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "later",
    );
    await writeFile(
      paths.input,
      `id,repository,revision,scope,mode\npayments,${source.path},${source.revision},src,deep\n`,
    );

    const run = mock<SecurityClient["run"]>(async (path, scanOptions = {}) => {
      expect(git(path, "rev-parse", "HEAD")).toBe(source.revision);
      expect(await readFile(join(path, "src", "app.ts"), "utf8")).toContain(
        'name = "payments"',
      );
      expect(scanOptions.target).toEqual(["src"]);
      expect(scanOptions.mode).toBe("deep");
      expect(scanOptions.outputDir).toBe(
        join(paths.output, "artifacts", "payments", "attempt-1"),
      );
      return await completedScan(scanOptions.outputDir!);
    });
    const observeClosed = mock(async () => {});
    const summary = await runMultiscan(
      options(paths, client(run, observeClosed)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(observeClosed).toHaveBeenCalledTimes(1);
    await expect(access(run.mock.lastCall?.[0] ?? "")).rejects.toThrow();
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "payments",
        repository: source.path,
        revision: source.revision,
        scope: "src",
        mode: "deep",
        status: "completed",
        attempt: 1,
      },
    ]);
  });

  test("limits simultaneous checkouts to the requested worker count", async () => {
    const paths = await fixture();
    const knowledgeBasePaths = [
      join(paths.root, "architecture.md"),
      join(paths.root, "threat-model.md"),
    ];
    await Promise.all(
      knowledgeBasePaths.map((path) => writeFile(path, "Synthetic context.")),
    );
    const sources = await Promise.all(
      ["one", "two", "three"].map((name) => repository(paths.root, name)),
    );
    await writeFile(
      paths.input,
      `id,repository,revision\n${sources
        .map(
          (source, index) => `${index + 1},${source.path},${source.revision}`,
        )
        .join("\n")}\n`,
    );

    let active = 0;
    let maximum = 0;
    const createSecurity = mock(() => {
      let running = false;
      return client(async (repository, scanOptions) => {
        if (running) {
          throw new Error("A scan is already running for this client.");
        }
        running = true;
        try {
          return await security.run(repository, scanOptions);
        } finally {
          running = false;
        }
      }, close);
    });
    const close = mock(async () => {});
    const simultaneous = Promise.withResolvers<void>();
    const security = client(async (_repository, scanOptions = {}) => {
      expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
      active += 1;
      maximum = Math.max(maximum, active);
      if (active === 2) simultaneous.resolve();
      await simultaneous.promise;
      active -= 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const summary = await runMultiscan(
      options(paths, security, {
        workers: 2,
        knowledgeBasePaths,
        createSecurity,
      }),
    );

    expect(maximum).toBe(2);
    expect(createSecurity).toHaveBeenCalledTimes(2);
    expect(close).toHaveBeenCalledTimes(2);
    expect(summary).toMatchObject({ total: 3, completed: 3, failed: 0 });
    expect(await results(summary.resultsPath)).toHaveLength(3);
  });

  test("rejects another supervisor and recovers a crashed owner's checkout", async () => {
    const { paths, source } = await repositoryFixture("exclusive");
    const running = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    const security = client(async (_repository, scanOptions = {}) => {
      running.resolve();
      await finish.promise;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = runMultiscan(options(paths, security));
    await running.promise;
    try {
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      expect(JSON.parse(await readFile(ownerPath, "utf8"))).toMatchObject({
        pid: process.pid,
        ownerId: expect.any(String),
        hostname: hostname(),
        processStartedAt: expect.any(Number),
      });
      if (process.platform !== "win32") {
        expect((await lstat(lock)).mode & 0o777).toBe(0o700);
        expect((await lstat(ownerPath)).mode & 0o777).toBe(0o600);
      }
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        /running|locked|supervisor/iu,
      );
    } finally {
      finish.resolve();
      await first;
    }

    const [receipt] = await results(join(paths.output, "results.jsonl"));
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    const lock = join(paths.output, ".lock");
    await mkdir(lock);
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
    );
    const checkout = join(paths.output, "checkouts", "exclusive");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    const marker = join(checkout, "retained.txt");
    await writeFile(marker, "Preserved crashed-owner checkout data.\n");
    const identity = await lstat(checkout);

    const recovered = await runMultiscan(options(paths, security));
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(await results(recovered.resultsPath)).toEqual([receipt!]);
    await access(join(receipt!["outputDir"] as string, "report.md"));
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([
      "exclusive",
    ]);
    const retained = await lstat(checkout);
    expect([retained.dev, retained.ino]).toEqual([identity.dev, identity.ino]);
    expect(await readFile(marker, "utf8")).toBe(
      "Preserved crashed-owner checkout data.\n",
    );
    await expect(access(lock)).rejects.toThrow();
  });

  test("recovers a legacy supervisor lock when this live PID was reused", async () => {
    const { paths } = await repositoryFixture("legacy-pid-reuse", "legacy");
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(ownerPath, JSON.stringify({ pid: process.pid }), {
      mode: 0o600,
    });
    const beforeProcessStarted = new Date(performance.timeOrigin - 60_000);
    await utimes(ownerPath, beforeProcessStarted, beforeProcessStarted);

    const summary = await runMultiscan(
      options(paths, client(completeRunWithoutAwait)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
    expect(
      (await readdir(paths.output)).some((name) =>
        name.startsWith(".lock.stale-"),
      ),
    ).toBe(false);
  });

  test("preserves an active legacy supervisor lock", async () => {
    const { paths } = await repositoryFixture("legacy-owner", "legacy");
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(ownerPath, JSON.stringify({ pid: process.pid }), {
      mode: 0o600,
    });

    await expect(
      runMultiscan(options(paths, client(completeRunWithoutAwait))),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect(JSON.parse(await readFile(ownerPath, "utf8"))).toEqual({
      pid: process.pid,
    });
  });

  for (const previousHostname of [hostname(), "previous-container"]) {
    test(`recovers an expired supervisor lease from ${previousHostname === hostname() ? "a reused live PID" : "a replacement container"}`, async () => {
      const { paths } = await repositoryFixture(
        "expired-supervisor",
        "expired",
      );
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      await mkdir(lock, { recursive: true, mode: 0o700 });
      await writeFile(
        ownerPath,
        JSON.stringify({
          pid: process.pid,
          ownerId: "previous-supervisor",
          hostname: previousHostname,
          processStartedAt: performance.timeOrigin - 60_000,
        }),
        { mode: 0o600 },
      );
      const expired = new Date(Date.now() - 120_000);
      await utimes(ownerPath, expired, expired);

      const summary = await runMultiscan(
        options(paths, client(completeRunWithoutAwait)),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(lock)).rejects.toThrow();
    });
  }

  test("does not reclaim a live supervisor in another container", async () => {
    const { paths } = await repositoryFixture("remote-supervisor", "remote");
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      ownerPath,
      JSON.stringify({
        pid: 999_999_999,
        ownerId: "live-remote-supervisor",
        hostname: "another-container",
        processStartedAt: performance.timeOrigin,
      }),
      { mode: 0o600 },
    );

    await expect(
      runMultiscan(options(paths, client(completeRunWithoutAwait))),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect(JSON.parse(await readFile(ownerPath, "utf8"))).toMatchObject({
      ownerId: "live-remote-supervisor",
    });
  });

  test("recovers interrupted lock creation without an owner record", async () => {
    const { paths } = await repositoryFixture(
      "interrupted-owner",
      "interrupted",
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    const expired = new Date(Date.now() - 120_000);
    await utimes(lock, expired, expired);

    const summary = await runMultiscan(
      options(paths, client(completeRunWithoutAwait)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
  });

  test("preserves a supervisor lock while its owner record is being created", async () => {
    const { paths } = await repositoryFixture(
      "initializing-owner",
      "initializing",
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });

    await expect(
      runMultiscan(options(paths, client(completeRunWithoutAwait))),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect((await lstat(lock)).isDirectory()).toBe(true);
  });

  test("recovers an interrupted stale-lock recovery claim", async () => {
    const { paths } = await repositoryFixture(
      "interrupted-recovery",
      "interrupted",
    );
    const lock = join(paths.output, ".lock");
    const recoveryPath = join(lock, ".recovering");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
      {
        mode: 0o600,
      },
    );
    await writeFile(recoveryPath, "", { mode: 0o600 });
    const expired = new Date(Date.now() - 120_000);
    await utimes(recoveryPath, expired, expired);

    const summary = await runMultiscan(
      options(paths, client(completeRunWithoutAwait)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
  });

  test("allows only one supervisor to recover an abandoned lock", async () => {
    const { paths } = await repositoryFixture("recovery-race", "race");
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
      {
        mode: 0o600,
      },
    );
    const running = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    let active = 0;
    let maximum = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      active += 1;
      maximum = Math.max(maximum, active);
      running.resolve();
      await finish.promise;
      active -= 1;
      return completedScan(scanOptions.outputDir!);
    });
    const contenders = Promise.allSettled([
      runMultiscan(options(paths, security)),
      runMultiscan(options(paths, security)),
    ]);

    await running.promise;
    finish.resolve();
    const outcomes = await contenders;

    expect(maximum).toBe(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "rejected"),
    ).toHaveLength(1);
  });

  test("never removes a replacement owner's lock during interrupted cleanup", async () => {
    const { paths } = await repositoryFixture(
      "replacement-owner",
      "replacement",
    );
    const running = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    const first = runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          running.resolve();
          await finish.promise;
          return completedScan(scanOptions.outputDir!);
        }),
      ),
    );
    await running.promise;
    const lock = join(paths.output, ".lock");
    const abandoned = join(paths.output, ".lock.stale-interrupted");
    await rename(lock, abandoned);
    await mkdir(lock, { mode: 0o700 });
    const replacement = {
      pid: process.pid,
      ownerId: "replacement-supervisor",
      hostname: hostname(),
      processStartedAt: performance.timeOrigin,
    };
    await writeFile(join(lock, "owner.json"), JSON.stringify(replacement), {
      mode: 0o600,
    });

    finish.resolve();
    await first;

    expect(
      JSON.parse(await readFile(join(lock, "owner.json"), "utf8")),
    ).toEqual(replacement);
  });

  test("removes an empty supervisor lock when owner creation fails", async () => {
    const { paths } = await repositoryFixture(
      "owner-creation-failure",
      "failure",
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    const originalWriteFile = filesystem.writeFile;
    const writeOwner = spyOn(filesystem, "writeFile").mockImplementation(
      async (path, data, options) => {
        if (String(path) !== ownerPath) {
          return await originalWriteFile(path, data, options);
        }
        writeOwner.mockRestore();
        throw Object.assign(new Error("could not publish lock owner"), {
          code: "EACCES",
        });
      },
    );
    const security = client(completeRunWithoutAwait);

    try {
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        "could not publish lock owner",
      );
      await expect(access(lock)).rejects.toThrow();
      await expect(
        runMultiscan(options(paths, security)),
      ).resolves.toMatchObject({ completed: 1 });
    } finally {
      writeOwner.mockRestore();
    }
  });

  test.each([false, true])(
    "never removes a replacement lock when owner creation fails (owner published: %p)",
    async (ownerPublished) => {
      if (
        runTestInSubprocess(
          import.meta.path,
          `never removes a replacement lock when owner creation fails (owner published: ${ownerPublished})`,
        )
      ) {
        return;
      }
      const { paths } = await repositoryFixture("owner-creation-race", "race");
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      const replacement = JSON.stringify({
        pid: process.pid,
        ownerId: "replacement-supervisor",
        hostname: hostname(),
        processStartedAt: performance.timeOrigin,
      });
      const createdInode = 2n ** 60n;
      const replacementInode = createdInode + 1n;
      expect(Number(createdInode)).toBe(Number(replacementInode));
      let replaced = false;
      const originalLstat = filesystem.lstat;
      const originalWriteFile = filesystem.writeFile;
      const readLock = spyOn(filesystem, "lstat").mockImplementation((async (
        ...args: Parameters<typeof filesystem.lstat>
      ) => {
        const metadata = await originalLstat(...args);
        if (String(args[0]) === lock) {
          const inode = replaced ? replacementInode : createdInode;
          metadata.ino =
            typeof metadata.ino === "bigint" ? inode : Number(inode);
        }
        return metadata;
      }) as typeof filesystem.lstat);
      const writeOwner = spyOn(filesystem, "writeFile").mockImplementation(
        async (path, data, options) => {
          if (String(path) !== ownerPath) {
            return await originalWriteFile(path, data, options);
          }
          writeOwner.mockRestore();
          await rename(lock, join(paths.output, ".lock.stale-owner-creation"));
          await mkdir(lock, { mode: 0o700 });
          replaced = true;
          if (ownerPublished) {
            await originalWriteFile(ownerPath, replacement, { mode: 0o600 });
          }
          throw Object.assign(new Error("replacement already owns the lock"), {
            code: "EEXIST",
          });
        },
      );

      try {
        await expect(
          runMultiscan(options(paths, client(completeRunWithoutAwait))),
        ).rejects.toThrow("replacement already owns the lock");
        await access(lock);
        if (ownerPublished) {
          expect(await readFile(ownerPath, "utf8")).toBe(replacement);
        }
      } finally {
        writeOwner.mockRestore();
        readLock.mockRestore();
      }
    },
  );

  test("retries a failed attempt and records both durable receipts", async () => {
    const { paths } = await repositoryFixture("retry");
    const failure = "temporary failure: token=SYNTHETIC_MULTISCAN_TOKEN";
    const document = join(paths.root, "architecture.md");
    await writeFile(document, "Synthetic architecture.");
    const knowledgeBasePaths = [document];

    let attempts = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
          attempts += 1;
          if (attempts === 1) {
            scanOptions.onWarning?.("Warning from the failed attempt.");
            throw new Error(failure);
          }
          return await completedScan(scanOptions.outputDir!);
        }),
        { knowledgeBasePaths },
      ),
    );

    expect(attempts).toBe(2);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(summary).not.toHaveProperty("warnings");
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "retry",
        status: "failed",
        attempt: 1,
        error: failure,
        warnings: ["Warning from the failed attempt."],
      },
      { id: "retry", status: "completed", attempt: 2 },
    ]);
  });

  test("rescans corrupt, modified, and mismatched sealed repository artifacts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume-integrity");
    await writeFile(
      paths.input,
      `id,repository,revision\nresume-integrity,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = await runMultiscan(options(paths, security));
    const foreignPaths = await fixture();
    await writeFile(
      foreignPaths.input,
      `id,repository,revision\nresume-integrity,${source.path},${source.revision}\n`,
    );
    const foreign = await runMultiscan(
      options(
        foreignPaths,
        client(async (_repository, scanOptions = {}) =>
          completedScan(scanOptions.outputDir!),
        ),
      ),
    );
    const [foreignReceipt] = await results(foreign.resultsPath);
    const [firstReceipt] = await results(first.resultsPath);
    expect(foreignReceipt!["targetId"]).not.toBe(firstReceipt!["targetId"]);

    const modify = async (
      outputDir: string,
      name: string,
      update: (
        document: Record<string, unknown> & {
          scan?: ScanResult["manifest"]["scan"];
        },
      ) => void,
    ): Promise<void> => {
      const path = join(outputDir, name);
      const document = JSON.parse(await readFile(path, "utf8")) as Record<
        string,
        unknown
      > & { scan?: ScanResult["manifest"]["scan"] };
      update(document);
      await writeFile(path, `${JSON.stringify(document, null, 2)}\n`);
      await reseal(outputDir);
    };
    await modify(
      firstReceipt!["outputDir"] as string,
      "scan-manifest.json",
      (manifest) => {
        manifest.scan!.producer.version = "0.0.1";
      },
    );
    expect(await runMultiscan(options(paths, security))).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    const corruptions: Array<(outputDir: string) => Promise<void>> = [
      ...(["failed", "canceled", "interrupted"] as const).map(
        (status) => async (outputDir: string) => {
          await modify(outputDir, "scan-manifest.json", (manifest) => {
            manifest.scan!.status = status;
          });
          await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
        },
      ),
      async (outputDir) => {
        await writeFile(
          join(outputDir, "scan-manifest.json"),
          "{broken json\n",
        );
      },
      async (outputDir) => {
        await writeFile(join(outputDir, "findings.json"), "{}\n");
        await reseal(outputDir);
      },
      async (outputDir) => {
        await appendFile(join(outputDir, "coverage.json"), "\n");
      },
      (outputDir) =>
        modify(outputDir, "coverage.json", (coverage) => {
          coverage["completeness"] = "partial";
        }),
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.revision = "0".repeat(40);
        }),
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.displayName = "another-repository";
        }),
      async (outputDir) => {
        await cp(foreignReceipt!["outputDir"] as string, outputDir, {
          recursive: true,
          force: true,
        });
        const contract = await loadContract(outputDir, {
          pluginRoot: PLUGIN_ROOT,
        });
        expect(contract.manifest.scan.target.targetId).toBe(
          foreignReceipt!["targetId"] as string,
        );
      },
      async (outputDir) => {
        const receipts = await results(first.resultsPath);
        receipts.at(-1)!["targetId"] = foreignReceipt!["targetId"];
        await writeFile(
          first.resultsPath,
          `${receipts.map((receipt) => JSON.stringify(receipt)).join("\n")}\n`,
        );
        await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
      },
      async (outputDir) => {
        await modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.producer.name = "another-security-plugin";
        });
        await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
      },
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.kind = "directory_snapshot";
          manifest.scan!.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
        }),
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
        }),
      (outputDir) =>
        modify(outputDir, "coverage.json", (coverage) => {
          coverage["mode"] = "deep_repository";
        }),
      async (outputDir) => {
        await modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.scope.includePaths = ["another-scope"];
        });
        await modify(outputDir, "coverage.json", (coverage) => {
          coverage["includePaths"] = ["another-scope"];
        });
      },
      async (outputDir) => {
        await modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.scope.excludePaths = ["src"];
        });
        await modify(outputDir, "coverage.json", (coverage) => {
          coverage["excludePaths"] = ["src"];
        });
        await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
      },
    ];

    for (const corrupt of corruptions) {
      const previous = join(
        paths.output,
        "artifacts",
        "resume-integrity",
        `attempt-${attempts}`,
      );
      await corrupt(previous);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      await access(previous);
    }

    expect(attempts).toBe(corruptions.length + 1);
    expect(await results(join(paths.output, "results.jsonl"))).toHaveLength(
      corruptions.length + 1,
    );
  });

  test.each([
    "forged campaign target identity",
    "forged resolved repository scope",
    "forged lexical symlink scope",
    "forged worktree snapshot digest",
    "deferred complete coverage",
    "follow-up complete coverage",
    "unsealed canonical findings",
    "unsealed canonical coverage",
    "duplicate coverage surface identities",
    "duplicate finding identities",
    "reversed finding line range",
    "duplicate evidence identifiers",
    "dangling root-cause evidence",
    "dangling validation evidence",
    "dangling attack-path evidence",
  ] as const)("checks sealed artifacts with %s", async (corruption) => {
    if (corruption === "forged lexical symlink scope") {
      const count = Number(process.env["GIT_CONFIG_COUNT"] ?? "0");
      if (
        runTestInSubprocess(
          fileURLToPath(import.meta.url),
          `checks sealed artifacts with ${corruption}`,
          {
            ...process.env,
            GIT_CONFIG_COUNT: String(count + 1),
            [`GIT_CONFIG_KEY_${count}`]: "core.symlinks",
            [`GIT_CONFIG_VALUE_${count}`]: "true",
          },
        )
      )
        return;
    }
    const paths = await fixture();
    const source = await repository(paths.root, "sealed-resume-integrity");
    let revision = source.revision;
    if (corruption === "forged lexical symlink scope") {
      await symlink("src", join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add scoped directory alias",
      );
      revision = git(source.path, "rev-parse", "HEAD");
    }
    const inventory =
      corruption === "forged resolved repository scope"
        ? `id,repository,revision,scope\nsealed-resume,${source.path},${revision},src\n`
        : corruption === "forged lexical symlink scope"
          ? `id,repository,revision,scope\nsealed-resume,${source.path},${revision},alias\n`
          : `id,repository,revision\nsealed-resume,${source.path},${revision}\n`;
    await writeFile(paths.input, inventory);
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    let pluginRoot = PLUGIN_ROOT;
    if (
      corruption === "deferred complete coverage" ||
      corruption === "follow-up complete coverage" ||
      corruption === "unsealed canonical findings" ||
      corruption === "unsealed canonical coverage"
    ) {
      pluginRoot = join(paths.root, "custom-plugin");
      await mkdir(pluginRoot);
      await cp(
        join(PLUGIN_ROOT, ".codex-plugin"),
        join(pluginRoot, ".codex-plugin"),
        { recursive: true },
      );
      await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
        recursive: true,
      });
      const coverageSchema =
        corruption === "deferred complete coverage" ||
        corruption === "follow-up complete coverage";
      const schemaPath = join(
        pluginRoot,
        "schemas",
        coverageSchema ? "coverage.schema.json" : "scan-manifest.schema.json",
      );
      const schema = JSON.parse(await readFile(schemaPath, "utf8")) as {
        allOf?: unknown;
        properties?: { scan?: { allOf?: unknown } };
      };
      if (coverageSchema) delete schema.allOf;
      else delete schema.properties?.scan?.allOf;
      await writeFile(schemaPath, `${JSON.stringify(schema, null, 2)}\n`);
    }
    const campaign = options(
      paths,
      security,
      pluginRoot === PLUGIN_ROOT ? {} : { config: { pluginPath: pluginRoot } },
    );
    const first = await runMultiscan(campaign);
    const [receipt] = await results(first.resultsPath);
    const outputDir = receipt!["outputDir"] as string;

    if (corruption === "forged campaign target identity") {
      const foreignPaths = await fixture();
      await writeFile(foreignPaths.input, inventory);
      const foreign = await runMultiscan(
        options(
          foreignPaths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      );
      const [foreignReceipt] = await results(foreign.resultsPath);
      await cp(foreignReceipt!["outputDir"] as string, outputDir, {
        recursive: true,
        force: true,
      });
      receipt!["targetId"] = foreignReceipt!["targetId"];
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
    } else if (
      corruption === "forged resolved repository scope" ||
      corruption === "forged lexical symlink scope"
    ) {
      const manifestPath = join(outputDir, "scan-manifest.json");
      const manifest = JSON.parse(
        await readFile(manifestPath, "utf8"),
      ) as ScanResult["manifest"];
      const forgedScope =
        corruption === "forged lexical symlink scope" ? "alias" : ".";
      manifest.scan.scope.includePaths = [forgedScope];
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      const coveragePath = join(outputDir, "coverage.json");
      const coverage = JSON.parse(
        await readFile(coveragePath, "utf8"),
      ) as ScanResult["coverage"];
      coverage.includePaths = [forgedScope];
      await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
      receipt!["resolvedScope"] = forgedScope;
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
    } else if (corruption === "forged worktree snapshot digest") {
      const manifestPath = join(outputDir, "scan-manifest.json");
      const manifest = JSON.parse(
        await readFile(manifestPath, "utf8"),
      ) as ScanResult["manifest"];
      const forgedDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
      manifest.scan.target.kind = "git_worktree";
      manifest.scan.target.snapshotDigest = forgedDigest;
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      receipt!["snapshotDigest"] = forgedDigest;
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
    } else if (
      corruption === "duplicate finding identities" ||
      corruption === "reversed finding line range" ||
      corruption === "duplicate evidence identifiers" ||
      corruption === "dangling root-cause evidence" ||
      corruption === "dangling validation evidence" ||
      corruption === "dangling attack-path evidence"
    ) {
      const findingsPath = join(outputDir, "findings.json");
      const findings = JSON.parse(
        await readFile(findingsPath, "utf8"),
      ) as ScanResult["findings"];
      const finding = findings.findings[0]!;
      if (corruption === "duplicate finding identities") {
        findings.findings.push(structuredClone(finding));
      } else if (corruption === "reversed finding line range") {
        finding.locations[0]!.endLine = finding.locations[0]!.startLine - 1;
      } else if (corruption === "duplicate evidence identifiers") {
        const evidence = {
          id: "source-evidence",
          label: "Source evidence",
          path: "src/extract.py",
          startLine: 41,
          endLine: 44,
          code: "extract()",
          explanation: "Source evidence",
        };
        finding.codeEvidence = [evidence, structuredClone(evidence)];
      } else if (corruption === "dangling root-cause evidence") {
        finding.rootCause = {
          summary: "Missing source evidence.",
          evidenceRefs: ["missing-evidence"],
        };
      } else if (corruption === "dangling validation evidence") {
        finding.validation = { evidenceRefs: ["missing-evidence"] };
      } else {
        finding.attackPath = { evidenceRefs: ["missing-evidence"] };
      }
      await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
    } else if (
      corruption === "deferred complete coverage" ||
      corruption === "follow-up complete coverage" ||
      corruption === "duplicate coverage surface identities"
    ) {
      const coveragePath = join(outputDir, "coverage.json");
      const coverage = JSON.parse(
        await readFile(coveragePath, "utf8"),
      ) as ScanResult["coverage"];
      if (corruption === "deferred complete coverage") {
        coverage.deferred.push({
          id: "unreviewed-surface",
          reason: "Review remains incomplete.",
        });
      } else if (corruption === "follow-up complete coverage") {
        coverage.surfaces[0]!.disposition = "needs_follow_up";
      } else {
        coverage.surfaces.push(structuredClone(coverage.surfaces[0]!));
      }
      await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
    }

    const manifestPath = join(outputDir, "scan-manifest.json");
    const manifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as ScanResult["manifest"];
    if (corruption === "unsealed canonical findings") {
      manifest.scan.artifacts = manifest.scan.artifacts.filter(
        (artifact) => artifact.path !== "findings.json",
      );
    } else if (corruption === "unsealed canonical coverage") {
      manifest.scan.artifacts = manifest.scan.artifacts.filter(
        (artifact) => artifact.path !== "coverage.json",
      );
    }
    manifest.scan.artifacts.push({
      path: "report.md",
      sha256: "0".repeat(64),
      mediaType: "text/markdown",
    });
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await reseal(outputDir);
    const sealedManifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as ScanResult["manifest"];
    expect(
      await contract.hasSealedReport(outputDir, sealedManifest),
    ).toBeTrue();

    const compatibleLegacyReference =
      corruption === "dangling root-cause evidence" ||
      corruption === "dangling validation evidence" ||
      corruption === "dangling attack-path evidence";
    if (compatibleLegacyReference)
      await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: compatibleLegacyReference ? 1 : 0,
    });
    expect(attempts).toBe(compatibleLegacyReference ? 1 : 2);
  });

  test.each([
    ["scoped", "src", "standard"],
    ["trailing-scope", "src/", "standard"],
    ["root-scope", "./", "standard"],
    ["deep", "", "deep"],
  ] as const)(
    "resumes current and legacy sealed %s scans matching the requested mode and scope",
    async (id, scope, mode) => {
      const paths = await fixture();
      const source = await repository(paths.root, id);
      await writeFile(
        paths.input,
        `id,repository,revision,scope,mode\n${id},${source.path},${source.revision},${scope},${mode}\n`,
      );
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return await completedScan(scanOptions.outputDir!);
      });

      const first = await runMultiscan(options(paths, security));
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });

      const [legacy] = await results(first.resultsPath);
      delete legacy!["targetId"];
      delete legacy!["resolvedScope"];
      const ledger = `${JSON.stringify(legacy)}\n`;
      await writeFile(first.resultsPath, ledger);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
      expect(attempts).toBe(1);
    },
  );

  testPosix(
    "resumes a sealed scope reached through an in-repository symlink",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "symlink-scope");
      await symlink("src", join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add scoped directory alias",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nsymlink-scope,${source.path},${revision},alias\n`,
      );
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return await completedScan(scanOptions.outputDir!);
      });

      const first = await runMultiscan(options(paths, security));
      expect(await results(first.resultsPath)).toMatchObject([
        { status: "completed", scope: "alias", resolvedScope: "src" },
      ]);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(attempts).toBe(1);

      const [legacy] = await results(first.resultsPath);
      delete legacy!["resolvedScope"];
      await writeFile(first.resultsPath, `${JSON.stringify(legacy)}\n`);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(attempts).toBe(2);
    },
  );

  test("validates resumed artifacts with a configured plugin archive", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "custom-plugin");
    await writeFile(
      paths.input,
      `id,repository,revision\ncustom,${source.path},${source.revision}\n`,
    );
    const pluginPath = join(paths.root, "plugin.zip");
    const entries: Record<string, Uint8Array> = {};
    for (const path of [
      ".codex-plugin/plugin.json",
      "schemas/scan-manifest.schema.json",
      "schemas/findings.schema.json",
      "schemas/coverage.schema.json",
    ]) {
      entries[`release/${path}`] = await readFile(join(PLUGIN_ROOT, path));
    }
    await writeFile(pluginPath, zipSync(entries));
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const campaign = options(paths, security, { config: { pluginPath } });

    await runMultiscan(campaign);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(attempts).toBe(1);
    expect(
      (await readdir(paths.output)).some((name) =>
        name.startsWith(".resume-plugin-"),
      ),
    ).toBe(false);
  });

  test("resumes complete bundles, repairs missing reports, and rejects manifest drift", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume");
    const csv = `id,repository,revision\nresume,${source.path},${source.revision}\n`;
    await writeFile(paths.input, csv);
    const security = client(mock(completeRun));

    const initial = await runMultiscan(options(paths, security));
    await appendFile(initial.resultsPath, '{"id":"interrupted"');
    const resumed = await runMultiscan(options(paths, security));
    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(security.run.mock.calls.length).toBe(1);
    for (const prompts of [
      { scanPrompt: "Review different boundaries." },
      { postScanPrompt: "Draft confirmed fixes." },
      { maxCostUsd: 12.5 },
      { config: { codexOverrides: { model: "synthetic-model" } } },
    ]) {
      await expect(
        runMultiscan(options(paths, security, prompts)),
      ).rejects.toThrow("manifest does not match");
    }
    expect(security.run.mock.calls.length).toBe(1);

    const [receipt] = await results(initial.resultsPath);
    const outputDir = receipt!["outputDir"] as string;
    const reportPath = join(outputDir, "report.md");
    const report = await readFile(reportPath);
    const canonicalPaths = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
    ].map((name) => join(outputDir, name));
    const canonical = await Promise.all(
      canonicalPaths.map((path) => readFile(path)),
    );
    const ledger = await readFile(initial.resultsPath, "utf8");
    await rm(reportPath);
    const repaired = await runMultiscan(options(paths, security));
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(security.run.mock.calls.length).toBe(1);
    expect(await readFile(reportPath)).toEqual(report);
    expect(
      await Promise.all(canonicalPaths.map((path) => readFile(path))),
    ).toEqual(canonical);
    expect(await readFile(repaired.resultsPath, "utf8")).toBe(ledger);

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(security.run.mock.calls.length).toBe(1);
  });

  test("skips sealed report recovery and preserves earned receipts on recovery failure", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "report-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nreport-recovery,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = await runMultiscan(options(paths, security));
    const ledger = await readFile(first.resultsPath, "utf8");
    const resolvePython = spyOn(
      runtime,
      "resolvePluginPythonCommand",
    ).mockRejectedValue(
      new Error("Python unavailable: sk-proj-SYNTHETIC_REPORT_RECOVERY_123"),
    );
    try {
      const reportSealed = spyOn(contract, "hasSealedReport").mockResolvedValue(
        true,
      );
      try {
        await expect(
          runMultiscan(options(paths, security)),
        ).resolves.toMatchObject({ completed: 1, failed: 0, skipped: 1 });
        expect(reportSealed).toHaveBeenCalledTimes(1);
        expect(resolvePython).not.toHaveBeenCalled();
        expect(attempts).toBe(1);
        expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
      } finally {
        reportSealed.mockRestore();
      }
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        "Multiscan report recovery is required: Python unavailable: sk-proj-SYNTHETIC_REPORT_RECOVERY_123",
      );
      expect(resolvePython).toHaveBeenCalledWith(
        expect.objectContaining({
          protectedRoot: join(paths.output, "checkouts", "report-recovery"),

          environment: runtime.pluginHelperEnvironment(process.env),
        }),
      );
      expect(attempts).toBe(1);
      expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
    } finally {
      resolvePython.mockRestore();
    }
  });

  test("preserves cancellation during report recovery", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "cancel-report-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nreport-recovery,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = await runMultiscan(options(paths, security));
    const ledger = await readFile(first.resultsPath, "utf8");
    const controller = new AbortController();
    const reason = new Error("Report recovery cancelled.");
    const resolvePython = spyOn(
      runtime,
      "resolvePluginPythonCommand",
    ).mockImplementation(async () => {
      controller.abort(reason);
      throw reason;
    });
    try {
      await expect(
        runMultiscan(options(paths, security, { signal: controller.signal })),
      ).rejects.toBe(reason);
      expect(attempts).toBe(1);
      expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
    } finally {
      resolvePython.mockRestore();
    }
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

  test.skipIf(process.platform !== "win32")(
    "resumes campaigns across Windows repository path aliases",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "resume-alias");
      const inventory = (repositoryPath: string) =>
        `id,repository,revision\nresume,${repositoryPath},${source.revision}\n`;
      const security = client(mock(completeRun));

      await writeFile(paths.input, inventory(source.path));
      await runMultiscan(options(paths, security));
      await writeFile(paths.input, inventory(source.path.toUpperCase()));

      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(security.run.mock.calls.length).toBe(1);
    },
  );

  test("ignores repository-local Git shims while preserving credential configuration", async () => {
    if (
      runTestInSubprocess(
        fileURLToPath(import.meta.url),
        "ignores repository-local Git shims while preserving credential configuration",
      )
    )
      return;
    const { paths } = await repositoryFixture("private");
    const shimDirectory = join(paths.root, "node_modules", ".bin");
    const leakedCredential = join(paths.root, "leaked-credential");
    await mkdir(shimDirectory, { recursive: true });
    await writeFile(
      join(shimDirectory, "git"),
      `#!/bin/sh\nprintf '%s' "$GIT_CONFIG_VALUE_0" > "${leakedCredential}"\nexit 1\n`,
      { mode: 0o700 },
    );
    const previousDirectory = process.cwd();
    const environment = new Map(
      [
        "PATH",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
      ].map((name) => [name, process.env[name]] as const),
    );

    try {
      process.chdir(paths.root);
      process.env["PATH"] =
        `${shimDirectory}${process.platform === "win32" ? ";" : ":"}${environment.get("PATH") ?? ""}`;
      process.env["GIT_CONFIG_COUNT"] = "1";
      process.env["GIT_CONFIG_KEY_0"] = "multiscan.credential";
      process.env["GIT_CONFIG_VALUE_0"] = "SYNTHETIC_GIT_CREDENTIAL";

      const summary = await runMultiscan(
        options(
          paths,
          client(async (checkout, scanOptions = {}) => {
            const trustedGit = await resolveTrustedExecutable(
              "git",
              { ...process.env, PATH: environment.get("PATH") ?? "" },
              paths.root,
            );
            if (trustedGit === null) {
              throw new Error("Git is not available on a trusted PATH.");
            }
            const credential = execFileSync(
              trustedGit.executable,
              ["-C", checkout, "config", "--get", "multiscan.credential"],
              {
                encoding: "utf8",
                env: trustedGit.environment,
                stdio: ["ignore", "pipe", "pipe"],
              },
            ).trim();
            expect(credential).toBe("SYNTHETIC_GIT_CREDENTIAL");
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(leakedCredential)).rejects.toThrow();
    } finally {
      process.chdir(previousDirectory);
      for (const [name, value] of environment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("removes mixed-case repository Git variables before cloning", async () => {
    if (
      runTestInSubprocess(
        "./tests-ts/multiscan.test.ts",
        "removes mixed-case repository Git variables before cloning",
      )
    )
      return;
    const { paths } = await repositoryFixture("isolated");
    const trace = join(paths.root, "git-events.jsonl");

    const repositoryVariables = [
      "GIT_DIR",
      "GIT_COMMON_DIR",
      "gIt_Replace_Ref_Base",
      "Git_Dir",
      "gIt_Work_Tree",
      "Git_Index_File",
      "gIt_Object_Directory",
      "Git_Alternate_Object_Directories",
    ];
    const previous = new Map(
      [...repositoryVariables, "GIT_TRACE2_EVENT", "GIT_TRACE2_ENV_VARS"].map(
        (name) => [name, process.env[name]] as const,
      ),
    );

    try {
      for (const name of repositoryVariables) {
        process.env[name] = join(paths.root, `missing-${name}`);
      }
      process.env["GIT_TRACE2_EVENT"] = trace;
      process.env["GIT_TRACE2_ENV_VARS"] = repositoryVariables.join(",");
      const inherited = repositoryVariables.map((name) => process.env[name]);

      const summary = await runMultiscan(
        options(paths, client(completeRunWithoutAwait)),
      );
      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      const resumed = await runMultiscan(
        options(paths, client(completeRunWithoutAwait)),
      );
      expect(resumed).toMatchObject({ completed: 1, skipped: 1, failed: 0 });
      expect(repositoryVariables.map((name) => process.env[name])).toEqual(
        inherited,
      );

      const leakedVariables = parseJsonLines<{
        event: string;
        param?: string;
        value?: string;
      }>(await readFile(trace, "utf8")).filter(
        (event) =>
          event.event === "def_param" &&
          repositoryVariables.includes(event.param ?? "") &&
          event.value === join(paths.root, `missing-${event.param}`),
      );
      expect(leakedVariables).toEqual([]);
    } finally {
      for (const [name, value] of previous) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("rejects output-directory symlinks before deleting external checkouts", async () => {
    for (const directory of ["", "checkouts", "artifacts"]) {
      const { paths } = await repositoryFixture("victim");
      const external = join(paths.root, "external");
      const preserved = join(external, "victim", "keep.txt");
      await mkdir(join(external, "victim"), { recursive: true });
      await writeFile(preserved, "preserved\n");
      if (directory) await mkdir(paths.output, { mode: 0o700 });
      await symlink(
        external,
        directory ? join(paths.output, directory) : paths.output,
      );

      const scans = mock(completeRun);
      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        "symbolic links",
      );
      expect(scans.mock.calls.length).toBe(0);
      expect(await readFile(preserved, "utf8")).toBe("preserved\n");
    }
  });

  test("rejects linked task artifact directories without touching external files", async () => {
    const { paths } = await repositoryFixture("victim");
    const external = join(paths.root, "external");
    await mkdir(external);
    await writeFile(join(external, "preserved.txt"), "preserved\n");
    await mkdir(join(paths.output, "artifacts"), {
      recursive: true,
      mode: 0o700,
    });
    await symlink(
      external,
      join(paths.output, "artifacts", "victim"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const scans = mock(completeRun);
    const summary = await runMultiscan(
      options(paths, client(scans), { maxAttempts: 1 }),
    );

    expect(summary).toMatchObject({ total: 1, completed: 0, failed: 1 });
    expect(scans.mock.calls.length).toBe(0);
    expect((await results(summary.resultsPath))[0]?.["error"]).toContain(
      "symbolic links",
    );
    expect(await readdir(external)).toEqual(["preserved.txt"]);
    expect(await readFile(join(external, "preserved.txt"), "utf8")).toBe(
      "preserved\n",
    );
  });

  test("rejects linked task artifacts before accepting completed receipts", async () => {
    const { paths, source } = await repositoryFixture("victim");
    const external = join(paths.root, "external");
    await completedScan(join(external, "attempt-1"));
    await mkdir(join(paths.output, "artifacts"), {
      recursive: true,
      mode: 0o700,
    });
    await symlink(
      external,
      join(paths.output, "artifacts", "victim"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await writeFile(
      join(paths.output, "results.jsonl"),
      `${JSON.stringify({
        id: "victim",
        repository: source.path,
        revision: source.revision,
        mode: "standard",
        status: "completed",
        attempt: 1,
        outputDir: join(paths.output, "artifacts", "victim", "attempt-1"),
      })}\n`,
    );

    const scans = mock(completeRun);
    await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
      "symbolic links",
    );
    expect(scans.mock.calls.length).toBe(0);
    expect(await readdir(external)).toEqual(["attempt-1"]);
  });

  test("rejects an output directory replaced during preparation when numeric identities collide", async () => {
    const { paths } = await repositoryFixture("output-identity-race", "race");
    await mkdir(paths.output, { mode: 0o700 });
    const originalLstat = filesystem.lstat;
    const canonicalOutput = await realpath(paths.output);
    const firstExactIdentity = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    let outputInspections = 0;
    const inspectOutput = spyOn(filesystem, "lstat").mockImplementation(
      async (path, options) => {
        const stats = await originalLstat(path, options as never);
        if (String(path) !== paths.output && String(path) !== canonicalOutput) {
          return stats as never;
        }
        const exactIdentity =
          firstExactIdentity + (outputInspections++ === 0 ? 0n : 1n);
        return Object.assign(
          Object.create(Object.getPrototypeOf(stats)),
          stats,
          {
            ino:
              typeof stats.ino === "bigint"
                ? exactIdentity
                : Number(exactIdentity),
          },
        ) as never;
      },
    );
    const scans = mock(completeRun);

    try {
      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        "changed during preparation",
      );
      expect(scans.mock.calls.length).toBe(0);
    } finally {
      inspectOutput.mockRestore();
    }
  });

  testPosix(
    "rejects other-user-writable campaigns while preserving readable existing campaigns",
    async () => {
      const { paths } = await repositoryFixture("sample");
      await mkdir(paths.output, { mode: 0o755 });
      const security = client(mock(completeRun));

      for (const mode of [0o770, 0o777]) {
        await chmod(paths.output, mode);
        await expect(runMultiscan(options(paths, security))).rejects.toThrow(
          "must not be group- or world-writable",
        );
        expect(security.run.mock.calls.length).toBe(0);
      }

      await chmod(paths.output, 0o755);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        total: 1,
        completed: 1,
        failed: 0,
      });
      expect(security.run.mock.calls.length).toBe(1);
    },
  );

  testPosix("rejects campaigns beneath an unsafe shared parent", async () => {
    const { paths } = await repositoryFixture("sample");
    const parent = join(paths.root, "shared");
    await mkdir(parent, { mode: 0o777 });
    await chmod(parent, 0o777);
    const scans = mock(completeRun);

    await expect(
      runMultiscan(
        options(paths, client(scans), { outputDir: join(parent, "results") }),
      ),
    ).rejects.toThrow(
      "must not be group- or world-writable without the sticky bit",
    );
    expect(scans.mock.calls.length).toBe(0);
  });

  test("preserves trusted user-selected campaign parent aliases", async () => {
    const { paths } = await repositoryFixture("sample");
    const canonicalParent = join(paths.root, "campaigns");
    const linkedParent = join(paths.root, "linked-campaigns");
    await mkdir(canonicalParent, { mode: 0o700 });
    await symlink(
      canonicalParent,
      linkedParent,
      process.platform === "win32" ? "junction" : "dir",
    );
    const output = join(linkedParent, "results");
    const security = client(mock(completeRun));

    const summary = await runMultiscan(
      options(paths, security, { outputDir: output }),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(summary.resultsPath).toBe(join(output, "results.jsonl"));
    const [receipt] = await results(summary.resultsPath);
    expect(receipt?.["outputDir"]).toBe(
      join(canonicalParent, "results", "artifacts", "sample", "attempt-1"),
    );
    await writeFile(
      summary.resultsPath,
      `${JSON.stringify({
        ...receipt,
        outputDir: join(output, "artifacts", "sample", "attempt-1"),
      })}\n`,
    );
    expect(
      await runMultiscan(options(paths, security, { outputDir: output })),
    ).toMatchObject({ completed: 1, skipped: 1 });
    expect(security.run.mock.calls.length).toBe(1);
    expect(await readdir(join(canonicalParent, "results"))).toContain(
      "results.jsonl",
    );
  });

  test("keeps campaign operations on their validated canonical directory", async () => {
    const { paths } = await repositoryFixture("sample");
    const canonicalParent = join(paths.root, "campaigns");
    const redirectedParent = join(paths.root, "redirected");
    const linkedParent = join(paths.root, "linked-campaigns");
    await mkdir(canonicalParent, { mode: 0o700 });
    await mkdir(join(redirectedParent, "results"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(
      join(redirectedParent, "results", "preserved.txt"),
      "preserved\n",
    );
    await symlink(
      canonicalParent,
      linkedParent,
      process.platform === "win32" ? "junction" : "dir",
    );
    const output = join(linkedParent, "results");

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          await rename(linkedParent, join(paths.root, "previous-alias"));
          await symlink(
            redirectedParent,
            linkedParent,
            process.platform === "win32" ? "junction" : "dir",
          );
          return await completedScan(scanOptions.outputDir!);
        }),
        { outputDir: output },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(summary.resultsPath).toBe(
      join(canonicalParent, "results", "results.jsonl"),
    );
    expect(await readdir(join(redirectedParent, "results"))).toEqual([
      "preserved.txt",
    ]);
  });

  test("rejects unsafe input without starting scans or exposing URL credentials", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "safe");
    const secret = "MULTISCAN_CREDENTIAL_SHOULD_NOT_APPEAR";
    const invalid = [
      {
        name: "task-id",
        row: `../escape,${source.path},${source.revision},.`,
      },
      ...[
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
      ].map((id) => ({
        name: `task-id-${id}`,
        row: `${id},${source.path},${source.revision},.`,
      })),
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
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toContain(secret);
    }

    expect(security.run.mock.calls.length).toBe(0);
  });

  test("records incomplete coverage separately and still finishes other repositories", async () => {
    const paths = await fixture();
    const incomplete = await repository(paths.root, "incomplete");
    const complete = await repository(paths.root, "complete");
    await writeFile(
      paths.input,
      [
        "id,repository,revision",
        `incomplete,${incomplete.path},${incomplete.revision}`,
        `complete,${complete.path},${complete.revision}`,
        "",
      ].join("\n"),
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (checkout, scanOptions = {}) =>
          completedScan(
            scanOptions.outputDir!,
            (await readFile(join(checkout, "src", "app.ts"), "utf8")).includes(
              'name = "incomplete"',
            )
              ? "partial"
              : "complete",
          ),
        ),
        { maxAttempts: 3 },
      ),
    );

    expect(summary).toMatchObject({
      total: 2,
      completed: 1,
      incomplete: 1,
      failed: 0,
    });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "incomplete",
        status: "completed_with_incomplete_coverage",
        attempt: 1,
        coverage: "partial",
      },
      { id: "complete", status: "completed", attempt: 1, coverage: "complete" },
    ]);
  });
});

test("qualified campaign reuses a completed recovery checkout", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "recovery-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  await runMultiscan(
    options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
  );
  const originalCheckout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, originalCheckout);
  const originalIdentity = await lstat(originalCheckout);
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => completedScan(settings.outputDir!, "complete", checkout),
  );
  const campaign = options(paths, client(runs), {
    recoverScan: async () => undefined,
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(runs).toHaveBeenCalledTimes(1);
  const retainedIdentity = await lstat(originalCheckout);
  expect([retainedIdentity.dev, retainedIdentity.ino]).toEqual([
    originalIdentity.dev,
    originalIdentity.ino,
  ]);
});

for (const count of [1, 2]) {
  test(`qualified campaign accepts ${count} referenced legacy evidence entries`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const first = await runMultiscan(campaign);
    const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
    const path = join(dir, "findings.json");
    const saved = JSON.parse(
      await readFile(path, "utf8"),
    ) as ScanResult["findings"];
    saved.findings[0]!.code_evidence = Array.from({ length: count }, () => ({
      id: "saved-evidence",
      code: "extract()",
    }));
    saved.findings[0]!.rootCause = {
      summary: "Existing source evidence",
      evidenceRefs: ["saved-evidence"],
    };
    await writeFile(path, JSON.stringify(saved));
    await reseal(dir);
    expect(
      (await loadContract(dir, { pluginRoot: PLUGIN_ROOT })).findings
        .findings[0]!.code_evidence,
    ).toEqual(saved.findings[0]!.code_evidence);
    const bytes = await readFile(path);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
    expect(await readFile(path)).toEqual(bytes);
  });
}

for (const target of [["src"], ["src", "src/app.ts"]]) {
  test(`qualified campaign retains configured scopes ${target.join(",")}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "configured-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        expect(settings.target).toEqual(target);
        const result = await completedScan(
          settings.outputDir!,
          "complete",
          checkout,
        );
        result.manifest.scan.scope.includePaths = target;
        const coveragePath = join(settings.outputDir!, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        coverage.includePaths = target;
        coverage.mode = "scoped_path";
        coverage.inventoryStrategy = "scoped_path";
        await writeFile(coveragePath, JSON.stringify(coverage));
        await writeFile(
          join(settings.outputDir!, "scan-manifest.json"),
          JSON.stringify(result.manifest),
        );
        await reseal(settings.outputDir!);
        return result;
      },
    );
    const campaign = options(paths, client(runs), {
      scanOptionsByMode: { standard: { target } },
    });
    await runMultiscan(campaign);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
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
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "Add directory alias",
      );
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
          coverage: result.coverage,
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
  const paths = await fixture();
  const source = await repository(paths.root, "retained-checkout-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
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
    const paths = await fixture();
    const source = await repository(paths.root, "retained-reuse-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope
repo,${source.path},${source.revision},src
`,
    );
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
  const paths = await fixture();
  const source = await repository(paths.root, "saved-warning-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
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

test("qualified campaign preserves a completed receipt when scope checkout fails", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "unavailable-scoped-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs), { maxAttempts: 1 });
  const initial = await runMultiscan(campaign);
  const ledger = await readFile(initial.resultsPath, "utf8");
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  await expect(runMultiscan(campaign)).rejects.toThrow();
  expect(await readFile(initial.resultsPath, "utf8")).toBe(ledger);
  expect(runs).toHaveBeenCalledTimes(1);
});

test("qualified campaign resumes an absolute configured scope inside its checkout", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "absolute-scope-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  const requested = join(paths.output, "checkouts", "repo", "src");
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => {
      expect((await normalizeTarget(checkout, settings.target!)).paths).toEqual(
        ["src"],
      );
      const result = await completedScan(
        settings.outputDir!,
        "complete",
        checkout,
      );
      const manifestPath = join(settings.outputDir!, "scan-manifest.json");
      result.manifest.scan.scope.includePaths = ["src"];
      await writeFile(manifestPath, JSON.stringify(result.manifest));
      const coveragePath = join(settings.outputDir!, "coverage.json");
      const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
      coverage.mode = "scoped_path";
      coverage.includePaths = ["src"];
      coverage.inventoryStrategy = "scoped_path";
      await writeFile(coveragePath, JSON.stringify(coverage));
      await reseal(settings.outputDir!);
      return result;
    },
  );
  const campaign = options(paths, client(runs), {
    scanOptionsByMode: { standard: { target: [requested] } },
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(runs).toHaveBeenCalledTimes(1);
});

test("qualified campaign recovers its report from an unrelated Python invocation directory", async () => {
  if (
    await runTestInSubprocess(
      fileURLToPath(import.meta.url),
      "qualified campaign recovers its report from an unrelated Python invocation directory",
    )
  )
    return;
  const paths = await fixture();
  const source = await repository(paths.root, "python-invocation-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs), {
    config: { pythonPath: PYTHON },
  });
  const initial = await runMultiscan(campaign);
  const ledger = await readFile(initial.resultsPath, "utf8");
  const invocationDirectory = join(paths.root, "python-invocation");
  await mkdir(invocationDirectory);
  const originalDirectory = process.cwd();
  try {
    process.chdir(invocationDirectory);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
  } finally {
    process.chdir(originalDirectory);
  }
  expect(await readFile(initial.resultsPath, "utf8")).toBe(ledger);
  expect(runs).toHaveBeenCalledTimes(1);
});

for (const spelling of ["absolute", "home", "parent alias"] as const) {
  testPosix(
    `resume compatibility retains configured scope with ${spelling} spelling`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "scope-spelling-source");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
      const original = join(paths.output, "checkouts", "repo", "src");
      let requested = original;
      if (spelling === "home")
        requested = `~/${relative(homedir(), original).split(sep).join("/")}`;
      if (spelling === "parent alias") {
        const alias = join(paths.root, "campaign-alias");
        await symlink(paths.output, alias, "dir");
        requested = join(alias, "checkouts", "repo", "src");
      }
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => {
          const target = await normalizeTarget(checkout, settings.target!);
          expect(target.paths).toEqual(["src"]);
          const result = await completedScan(
            settings.outputDir!,
            "complete",
            checkout,
          );
          result.manifest.scan.scope.includePaths = [...target.paths];
          await writeFile(
            join(settings.outputDir!, "scan-manifest.json"),
            JSON.stringify(result.manifest),
          );
          const coveragePath = join(settings.outputDir!, "coverage.json");
          const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
          Object.assign(coverage, {
            mode: "scoped_path",
            includePaths: target.paths,
            inventoryStrategy: "scoped_path",
          });
          await writeFile(coveragePath, JSON.stringify(coverage));
          await reseal(settings.outputDir!);
          return result;
        },
      );
      const campaign = options(paths, client(runs), {
        scanOptionsByMode: { standard: { target: [requested] } },
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

testPosix(
  "resume compatibility retains a tracked scope alias anchored to its checkout basename",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "scope-layout-source");
    await symlink("../repo/src", join(source.path, "alias"), "dir");
    git(source.path, "add", "alias");
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "add checkout-relative scope alias",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},alias\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

testPosix(
  "resume compatibility preserves a recovery checkout reached through a directory link",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "linked-recovery-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
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
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await readFile(marker, "utf8")).toBe("retained recovery checkout\n");
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("resume compatibility recovers a failed completed bundle without fetching its unavailable source", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "failed-completed-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
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
    return {
      ...saved,
      coverage: { completeness: saved.coverage.completeness },
    } as ScanResult;
  });
  expect(
    await runMultiscan(options(paths, client(runs), { recoverScan })),
  ).toMatchObject({ completed: 1, failed: 0 });
  expect(recoverScan).toHaveBeenCalledTimes(1);
  expect(runs).toHaveBeenCalledTimes(0);
});

for (const section of ["rootCause", "validation", "attackPath"] as const) {
  for (const evidenceCatalog of ["present", "absent"] as const) {
    test(`resume compatibility reuses sealed legacy ${section} references with ${evidenceCatalog} evidence catalog`, async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "legacy-reference-source");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
      const runs = mock(completeRun);
      const campaign = options(paths, client(runs));
      const first = await runMultiscan(campaign);
      const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
      const path = join(dir, "findings.json");
      const saved = JSON.parse(
        await readFile(path, "utf8"),
      ) as ScanResult["findings"];
      const finding = saved.findings[0]!;
      if (evidenceCatalog === "present")
        finding.code_evidence = [{ id: "saved-evidence", code: "extract()" }];
      finding[section] = {
        summary: "Existing saved source evidence",
        evidenceRefs: ["saved-evidence", "obsolete-evidence"],
      };
      await writeFile(path, JSON.stringify(saved));
      await reseal(dir);
      expect(
        (await loadContract(dir, { pluginRoot: PLUGIN_ROOT })).findings
          .findings[0]![section],
      ).toEqual(finding[section]);
      const bytes = await readFile(path);
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
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
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add supported scope link",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${revision},alias\n`,
      );
      const runs = mock(completeRun);
      const campaign = options(paths, client(runs));
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

testPosix(
  "original coordinates retain ancestor-relative configured scope",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "configured-coordinate-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const target = await normalizeTarget(checkout, settings.target!);
        expect(target.paths).toEqual(["src"]);
        const result = await completedScan(
          settings.outputDir!,
          "complete",
          checkout,
        );
        result.manifest.scan.scope.includePaths = [...target.paths];
        await writeFile(
          join(settings.outputDir!, "scan-manifest.json"),
          JSON.stringify(result.manifest),
        );
        const coveragePath = join(settings.outputDir!, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        Object.assign(coverage, {
          mode: "scoped_path",
          includePaths: target.paths,
          inventoryStrategy: "scoped_path",
        });
        await writeFile(coveragePath, JSON.stringify(coverage));
        await reseal(settings.outputDir!);
        return result;
      },
    );
    const campaign = options(paths, client(runs), {
      scanOptionsByMode: { standard: { target: ["../../checkouts/repo/src"] } },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("original coordinates reuse an existing pinned scope checkout without refetching", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "retained-coordinate-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
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
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
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
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const recovery of [false, true]) {
  for (const partial of ["empty", "missing subtree"] as const) {
    test(`retained preparation completes ${recovery ? "recovery" : "normal"} checkout with ${partial}`, async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "partial-checkout-source");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
      );
      if (recovery)
        await runMultiscan(
          options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
        );
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => completedScan(settings.outputDir!, "complete", checkout),
      );
      const campaign = options(
        paths,
        client(runs),
        recovery ? { recoverScan: async () => undefined } : {},
      );
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      const checkout = recovery
        ? join(paths.output, "recovery-checkouts", "repo", "attempt-2")
        : join(paths.output, "checkouts", "repo");
      if (partial === "empty")
        await mkdir(checkout, { recursive: true, mode: 0o700 });
      else {
        git(paths.root, "clone", "--quiet", source.path, checkout);
        await rm(join(checkout, "src"), { recursive: true });
      }
      const retained = join(checkout, "retained.txt");
      await writeFile(retained, "Preserved interrupted checkout data.\n");
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
      if (recovery)
        expect(await readFile(retained, "utf8")).toBe(
          "Preserved interrupted checkout data.\n",
        );
    });
  }
}

testPosix(
  "retained preparation preserves a configured source-local Python interpreter",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "source-local-python");
    const interpreter = join(source.path, ".venv", "bin", "python");
    await mkdir(dirname(interpreter), { recursive: true });
    await writeFile(
      interpreter,
      `#!/usr/bin/env node\nconst {spawnSync} = require("node:child_process");\nconst result = spawnSync(${JSON.stringify(PYTHON)}, process.argv.slice(2), {stdio: "inherit"});\nif (result.error) throw result.error;\nprocess.exit(result.status ?? 1);\n`,
      { mode: 0o700 },
    );
    expect((await lstat(interpreter)).isFile()).toBe(true);
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const selected = await runtime.resolvePluginPythonCommand({
          configuredPath: interpreter,
          protectedRoot: checkout,
          environment: runtime.pluginHelperEnvironment(process.env),
        });
        expect(selected.executable).toBe(interpreter);
        return completedScan(settings.outputDir!, "complete", checkout);
      },
    );
    const campaign = options(paths, client(runs), {
      config: { pythonPath: interpreter },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const binding of ["gitfile", "worktree", "common", "objects"] as const) {
  test(`retained Git bindings keep ${binding} writes inside the campaign checkout`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "retained-binding-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const outside = await repository(paths.root, "other-owned-repository");
    await writeFile(
      join(outside.path, "retained-marker.txt"),
      "Preserve the other repository.\n",
    );
    git(outside.path, "add", ".");
    git(
      outside.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "--quiet",
      "-m",
      "Other repository state",
    );
    const originalHead = git(outside.path, "rev-parse", "HEAD");
    const originalFiles = await readFile(
      join(outside.path, "retained-marker.txt"),
      "utf8",
    );
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
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
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(git(outside.path, "rev-parse", "HEAD")).toBe(originalHead);
    expect(
      await readFile(join(outside.path, "retained-marker.txt"), "utf8"),
    ).toBe(originalFiles);
    expect(failed).toBe(true);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

(process.platform === "win32" ? test : test.skip)(
  "retained Git bindings reject a Windows recovery parent junction before checkout writes",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "junction-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const externalParent = join(paths.root, "other-recovery-parent");
    await mkdir(externalParent);
    const externalCheckout = join(externalParent, "attempt-2");
    git(paths.root, "clone", "--quiet", source.path, externalCheckout);
    const runs = mock(
      async (
        _checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", externalCheckout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    await rename(externalCheckout, join(externalParent, "retained-attempt"));
    const lexicalParent = join(paths.output, "recovery-checkouts", "repo");
    await rm(lexicalParent, { recursive: true, force: true });
    await symlink(externalParent, lexicalParent, "junction");
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(
      await lstat(externalCheckout).then(
        () => true,
        () => false,
      ),
    ).toBe(false);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const entry of ["config", "FETCH_HEAD"] as const) {
  test(`metadata recovery refuses external ${entry} write destinations`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "metadata-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const outside = await repository(paths.root, "other-metadata-repository");
    git(outside.path, "config", "core.filemode", "false");
    const destination = join(outside.path, ".git", entry);
    if (entry === "FETCH_HEAD")
      await writeFile(destination, "Preserve this other owned metadata.\n");
    const bytes = await readFile(destination);
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    await rm(join(checkout, ".git", entry), { force: true });
    await symlink(destination, join(checkout, ".git", entry));
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(await readFile(destination)).toEqual(bytes);
    expect(failed).toBe(true);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const partial of [false, true, "refs", "blob", "tree", "umask"] as const) {
  test(`metadata recovery restores an interrupted repository with removed metadata=${partial}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "partial-metadata-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
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
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
    } finally {
      process.umask(previousUmask);
    }
  });
}

testPosix(
  "metadata recovery preserves explicitly configured campaign-local Python",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "campaign-local-python-source");
    const interpreter = join(paths.output, "tools", "bin", "python");
    await mkdir(dirname(interpreter), { recursive: true });
    await writeFile(
      interpreter,
      `#!/usr/bin/env node\nconst {spawnSync} = require("node:child_process");\nconst result = spawnSync(${JSON.stringify(PYTHON)}, process.argv.slice(2), {stdio: "inherit"});\nif (result.error) throw result.error;\nprocess.exit(result.status ?? 1);\n`,
      { mode: 0o700 },
    );
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const selected = await runtime.resolvePluginPythonCommand({
          configuredPath: interpreter,
          protectedRoot: checkout,
          environment: runtime.pluginHelperEnvironment(process.env),
        });
        expect(selected.executable).toBe(interpreter);
        return completedScan(settings.outputDir!, "complete", checkout);
      },
    );
    const campaign = options(paths, client(runs), {
      config: { pythonPath: interpreter },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Tracked notes",
    );
    source.revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "repo",
      "attempt-2",
    );
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    const notes = modified
      ? "Preserve interrupted tracked notes.\n"
      : "Original tracked notes.\n";
    if (modified === "deleted" || modified === "deleted-missing-index")
      await rm(join(checkout, "README.md"));
    else if (modified) await writeFile(join(checkout, "README.md"), notes);
    if (modified === "deleted-missing-index")
      await rm(join(checkout, ".git", "index"));
    await writeFile(
      join(checkout, "retained.txt"),
      "Preserve untracked recovery data.\n",
    );
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    if (modified === "deleted" || modified === "deleted-missing-index")
      expect(
        await lstat(join(checkout, "README.md")).then(
          () => true,
          () => false,
        ),
      ).toBe(false);
    else
      expect(await readFile(join(checkout, "README.md"), "utf8")).toBe(notes);
    expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
      "Preserve untracked recovery data.\n",
    );
    expect(await readFile(join(checkout, "src", "app.ts"), "utf8")).toBe(
      await readFile(join(source.path, "src", "app.ts"), "utf8"),
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
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "Tracked notes",
      );
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${source.revision},${nested ? "alias/app.ts" : "alias"}\n`,
      );
      await runMultiscan(
        options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
      );
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => completedScan(settings.outputDir!, "complete", checkout),
      );
      const campaign = options(paths, client(runs), {
        recoverScan: async () => undefined,
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      const checkout = join(
        paths.output,
        "recovery-checkouts",
        "repo",
        "attempt-2",
      );
      git(paths.root, "clone", "--quiet", source.path, checkout);
      await rm(join(checkout, "alias"));
      if (nested === "chain") await rm(join(checkout, "middle"));
      await rm(join(checkout, "unrelated-alias"));
      await rm(join(checkout, "README.md"));
      await writeFile(
        join(checkout, "retained.txt"),
        "Preserve untracked recovery data.\n",
      );
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(
        await lstat(join(checkout, "README.md")).then(
          () => true,
          () => false,
        ),
      ).toBe(false);
      expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
        "Preserve untracked recovery data.\n",
      );
      expect(await readFile(join(checkout, "src", "app.ts"), "utf8")).toBe(
        await readFile(join(source.path, "src", "app.ts"), "utf8"),
      );
      expect(await readFile(join(checkout, "alias", "app.ts"), "utf8")).toBe(
        await readFile(join(source.path, "src", "app.ts"), "utf8"),
      );
      expect(
        await lstat(join(checkout, "unrelated-alias")).then(
          () => true,
          () => false,
        ),
      ).toBe(false);
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

for (const entry of ["logs/HEAD", "logs"] as const) {
  test(`followup recovery refuses linked ${entry} write destinations`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "reflog-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    const outside = await repository(paths.root, "other-reflog-repository");
    const destination = join(outside.path, ".git", "logs", "HEAD");
    const bytes = await readFile(destination);
    await rm(join(checkout, ".git", entry), { recursive: true, force: true });
    await symlink(
      join(outside.path, ".git", entry),
      join(checkout, ".git", entry),
      entry === "logs" ? "junction" : undefined,
    );
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(await readFile(destination)).toEqual(bytes);
    expect(failed).toBe(true);
    expect(runs).toHaveBeenCalledTimes(1);
  });
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
  git(
    source.path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "Add realistic long tracked paths",
  );
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
  );
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => completedScan(settings.outputDir!, "complete", checkout),
  );
  const campaign = options(paths, client(runs));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });

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
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "Advance pinned state",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
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
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(await readFile(destination)).toEqual(bytes);
    expect(failed).toBe(true);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

test("final native recovery restores a locally pinned commit with an unavailable source", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "local-pinned-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs));
  const initial = await runMultiscan(campaign);
  const before = await readFile(initial.resultsPath);
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  await rename(source.path, join(paths.root, "moved-pinned-source"));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Byte-valued tracked path",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    await runMultiscan(campaign);
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });

    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Tracked interpreter alias",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
    );
    const alias = join(paths.output, "checkouts", "repo", "python-alias");
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const selected = await runtime.resolvePluginPythonCommand({
          configuredPath: alias,
          protectedRoot: checkout,
          environment: runtime.pluginHelperEnvironment(process.env),
        });
        expect(selected.executable).toBe(python);
        return completedScan(settings.outputDir!, "complete", checkout);
      },
    );
    const campaign = options(paths, client(runs), {
      config: { pythonPath: alias },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("final native recovery refuses hardlinked FETCH_HEAD before external bytes change", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "hardlinked-fetch-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs));
  await runMultiscan(campaign);
  const outside = join(paths.root, "external-fetch-head");
  await writeFile(outside, "Preserve synthetic metadata.\n");
  const before = await readFile(outside);
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  await rm(join(checkout, ".git", "FETCH_HEAD"), { force: true });
  await link(outside, join(checkout, ".git", "FETCH_HEAD"));
  let failed = false;
  try {
    await runMultiscan(campaign);
  } catch {
    failed = true;
  }
  expect(await readFile(outside)).toEqual(before);
  expect(failed).toBe(true);
  expect(runs).toHaveBeenCalledTimes(1);
});

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
  git(
    source.path,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.test",
    "commit",
    "-qm",
    "Pinned packed objects",
  );
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs));
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
  let failed = false;
  try {
    await runMultiscan(campaign);
  } catch {
    failed = true;
  }
  expect(await readdir(outside)).toEqual([]);
  expect(failed).toBe(true);
  expect(runs).toHaveBeenCalledTimes(1);
});
test("current native recovery refuses hardlinked HEAD reflog before external bytes change", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "hardlinked-fetch-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs));
  await runMultiscan(campaign);
  const outside = join(paths.root, "external-fetch-head");
  await writeFile(outside, "Preserve synthetic metadata.\n");
  const before = await readFile(outside);
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  await rm(join(checkout, ".git", "logs", "HEAD"), { force: true });
  await link(outside, join(checkout, ".git", "logs", "HEAD"));
  let failed = false;
  try {
    await runMultiscan(campaign);
  } catch {
    failed = true;
  }
  expect(await readFile(outside)).toEqual(before);
  expect(failed).toBe(true);
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
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "Tracked interpreter alias",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${revision}\n`,
      );
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
      if (["external", "external-parent", "path"].includes(selection)) {
        git(
          paths.root,
          "clone",
          "--quiet",
          source.path,
          dirname(checkoutAlias),
        );
        if (selection === "external-parent")
          await symlink(dirname(checkoutAlias), externalDirectory);
        else {
          if (selection === "path") await mkdir(tools);
          await symlink(checkoutAlias, alias);
        }
      }
      const requestedPython = selection === "path" ? "scan-python" : alias;
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => {
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
        expect(await runMultiscan(campaign)).toMatchObject({
          completed: 1,
          skipped: 1,
        });
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

for (const entry of ["info", "loose-object", "hooks", "refs"] as const) {
  test(`current native recovery preserves external ${entry} initialization and fetch destinations`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "linked-native-source");
    const interrupted = join(paths.root, "interrupted-checkout");
    git(paths.root, "clone", "--quiet", source.path, interrupted);
    await writeFile(
      join(source.path, "src", "later.ts"),
      "Synthetic later revision.\n",
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
      "Later pinned revision",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    const object = git(source.path, "rev-parse", "HEAD:src/later.ts");
    await writeFile(
      paths.input,
      `id,repository,revision,scope
repo,${source.path},${revision},src
`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
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
    if (entry !== "loose-object") await rm(join(checkout, ".git", "HEAD"));
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
  git(
    source.path,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.test",
    "commit",
    "-qm",
    "Tracked notes",
  );
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
  );
  await runMultiscan(
    options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
  );
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => completedScan(settings.outputDir!, "complete", checkout),
  );
  const campaign = options(paths, client(runs), {
    recoverScan: async () => undefined,
  });
  const first = await runMultiscan(campaign);
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
  const checkout = join(
    paths.output,
    "recovery-checkouts",
    "repo",
    "attempt-2",
  );
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rm(join(checkout, "src"), { recursive: true });
  await rm(join(checkout, "README.md"));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  expect(
    await lstat(join(checkout, "README.md")).then(
      () => true,
      () => false,
    ),
  ).toBe(false);
  expect(runs).toHaveBeenCalledTimes(2);
});

async function completedConfiguredPaths(
  checkout: string,
  settings: Parameters<SecurityClient["run"]>[1] = {},
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
    const paths = await fixture();
    const source = await repository(paths.root, "configured-snapshot-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
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
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
    const ledger = await readFile(initial.resultsPath);
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src", "app.ts"));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Current pinned snapshot",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
    const ledger = await readFile(initial.resultsPath);
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
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
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await readFile(initial.resultsPath)).toEqual(ledger);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
test("final snapshot recovery skips a sealed report's unavailable interpreter ancestor", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "sealed-python-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  const parent = join(paths.root, "python-parent");
  await mkdir(parent);
  const interpreter = join(parent, "bin", "python");
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => {
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
    },
  );
  const campaign = options(paths, client(runs), {
    config: { pythonPath: interpreter },
  });
  const initial = await runMultiscan(campaign);
  expect(initial).toMatchObject({ completed: 1, skipped: 0 });
  const ledger = await readFile(initial.resultsPath);
  await rm(parent, { recursive: true });
  await writeFile(parent, "Ancestor is now an ordinary file.\n");
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Pinned later revision",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
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
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
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
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "Tracked restoration paths",
      );
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
      const initial = await runMultiscan(campaign);
      expect(initial).toMatchObject({ completed: 1, skipped: 0 });
      const ledger = await readFile(initial.resultsPath);
      const checkout = join(paths.output, "checkouts", "repo");
      git(paths.root, "clone", "--quiet", source.path, checkout);
      await rm(join(checkout, "src"), { recursive: true });
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
        } else
          expect(await runMultiscan(campaign)).toMatchObject({
            completed: 1,
            skipped: 1,
          });
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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Selected fixture readme",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${revision}\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), {
        maxAttempts: 1,
        scanOptionsByMode: {
          standard: { target: ["src/app.ts", "README.md"] },
        },
      }),
    );
    const runs = mock(completedConfiguredPaths);
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
      scanOptionsByMode: { standard: { target: ["src/app.ts", "README.md"] } },
    });
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
    const ledger = await readFile(initial.resultsPath);
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "repo",
      "attempt-2",
    );
    git(paths.root, "clone", "--quiet", source.path, checkout);
    if (staged) git(checkout, "rm", "--quiet", "src/app.ts");
    else await rm(join(checkout, "src", "app.ts"));
    git(checkout, "rm", "--quiet", "README.md");
    await writeFile(
      join(checkout, "README.md"),
      "Preserve staged replacement content.\n",
    );
    const stagedBefore = git(checkout, "diff", "--cached", "--name-only");
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
      await readFile(join(source.path, "src", "app.ts")),
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
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
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
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await readdir(outside)).toEqual([]);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
(process.platform === "win32" ? test : test.skip)(
  "retained edge recovery restores a missing Windows scope with accepted different casing",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "case-scope-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},SRC\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);
(process.platform === "win32" ? test : test.skip)(
  "retained edge recovery rejects an unscoped interpreter repair through a Windows parent junction",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "unscoped-junction-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
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
    const runs = mock(
      async (
        _checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", outsideCheckout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
      config,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    await rename(outsideCheckout, join(outsideParent, "retained-attempt"));
    const lexicalParent = join(paths.output, "recovery-checkouts", "repo");
    await rm(lexicalParent, { recursive: true, force: true });
    await symlink(outsideParent, lexicalParent, "junction");
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(
      await lstat(outsideCheckout).then(
        () => true,
        () => false,
      ),
    ).toBe(false);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const configured of [false, true]) {
  test(`retained spelling recovery keeps a bare PATH interpreter configured=${configured}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "bare-interpreter-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
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
  test(`retained spelling recovery preserves accepted alias casing nested=${nested}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "case-alias-source");
    await symlink("src", join(source.path, "alias"), "dir");
    git(source.path, "add", ".");
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Tracked scope alias",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    const caseInsensitive = await realpath(join(source.path, "ALIAS")).then(
      () => true,
      () => false,
    );
    const requested =
      (caseInsensitive ? "ALIAS" : "alias") + (nested ? "/APP.TS" : "");
    const scope = !caseInsensitive && nested ? "alias/app.ts" : requested;
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},${scope}\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "repo",
      "attempt-2",
    );
    git(
      paths.root,
      "clone",
      "--quiet",
      "-c",
      "core.symlinks=true",
      source.path,
      checkout,
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });

    await unlink(join(checkout, "alias"));
    await rm(join(checkout, "src"), { recursive: true });
    await writeFile(
      join(checkout, "retained.txt"),
      "Keep unrelated recovery bytes.\n",
    );
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
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
  git(
    source.path,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.test",
    "commit",
    "-qm",
    "Tracked interpreter link",
  );
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${revision}\n`,
  );
  const checkout = join(
    paths.output,
    "recovery-checkouts",
    "repo",
    "attempt-2",
  );
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
  const runs = mock(
    async (
      root: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => {
      expect(root).toBe(checkout);
      const selected = await runtime.resolvePluginPythonCommand({
        configuredPath: alias,
        protectedRoot: root,
        environment: runtime.pluginHelperEnvironment(process.env),
      });
      expect(await realpath(selected.executable)).toBe(await realpath(PYTHON));
      return completedScan(settings.outputDir!, "complete", root);
    },
  );
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
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
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
        git(
          source.path,
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.test",
          "commit",
          "-qm",
          "Pinned synthetic note",
        );
      }
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
      );
      const expectedApp = await readFile(join(source.path, "src", "app.ts"));
      await runMultiscan(
        options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
      );
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => completedScan(settings.outputDir!, "complete", checkout),
      );
      const campaign = options(paths, client(runs), {
        recoverScan: async () => undefined,
      });
      const initial = await runMultiscan(campaign);
      expect(initial).toMatchObject({ completed: 1, skipped: 0 });
      const ledger = await readFile(initial.resultsPath);
      const checkout = join(
        paths.output,
        "recovery-checkouts",
        "repo",
        "attempt-2",
      );
      await rm(checkout, { recursive: true, force: true });
      git(paths.root, "clone", "--quiet", source.path, checkout);
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
      const paths = await fixture();
      const source = await repository(paths.root, "retained-ancestor-source");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
      const selected = { standard: { target: ["src/app.ts"] } };
      await runMultiscan(
        options(paths, client(rejecting("Interrupted")), {
          maxAttempts: 1,
          scanOptionsByMode: selected,
        }),
      );
      const runs = mock(completedConfiguredPaths);
      const campaign = options(paths, client(runs), {
        recoverScan: async () => undefined,
        scanOptionsByMode: selected,
      });
      const initial = await runMultiscan(campaign);
      expect(initial).toMatchObject({ completed: 1, skipped: 0 });
      const ledger = await readFile(initial.resultsPath);
      const checkout = join(
        paths.output,
        "recovery-checkouts",
        "repo",
        "attempt-2",
      );
      git(paths.root, "clone", "--quiet", source.path, checkout);
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
          await readFile(join(source.path, "src", "app.ts")),
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
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "Physical scope alias fixture",
      );
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${source.revision},alias/app.ts\n`,
      );
      const config = { pythonPath: PYTHON };
      await runMultiscan(
        options(paths, client(rejecting("Interrupted")), {
          maxAttempts: 1,
          config,
        }),
      );
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => completedScan(settings.outputDir!, "complete", checkout),
      );
      const campaign = options(paths, client(runs), {
        recoverScan: async () => undefined,
        config,
      });
      const initial = await runMultiscan(campaign);
      expect(initial).toMatchObject({ completed: 1, skipped: 0 });
      const ledger = await readFile(initial.resultsPath);
      const checkout = join(
        paths.output,
        "recovery-checkouts",
        "repo",
        "attempt-2",
      );
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
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "Nested retained source",
      );
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
      const selected = { standard: { target: ["src", "src/app.ts"] } };
      await runMultiscan(
        options(paths, client(rejecting("Interrupted")), {
          maxAttempts: 1,
          scanOptionsByMode: selected,
        }),
      );
      const runs = mock(completedConfiguredPaths);
      const campaign = options(paths, client(runs), {
        recoverScan: async () => undefined,
        scanOptionsByMode: selected,
      });
      const initial = await runMultiscan(campaign);
      expect(initial).toMatchObject({ completed: 1, skipped: 0 });
      const ledger = await readFile(initial.resultsPath);
      const checkout = join(
        paths.output,
        "recovery-checkouts",
        "repo",
        "attempt-2",
      );
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
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(await readFile(join(checkout, "src", "app.ts"))).toEqual(
        await readFile(join(source.path, "src", "app.ts")),
      );
      if (linked) {
        expect((await lstat(nested)).isSymbolicLink()).toBe(true);
        expect(
          await readFile(join(destination, "inside", "retained.txt"), "utf8"),
        ).toBe("Preserve directory-link data.\n");
        expect(
          await lstat(join(destination, "inside", "keep.ts")).then(
            () => true,
            () => false,
          ),
        ).toBe(false);
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
      git(
        source.path,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-qm",
        "Tracked automatic interpreter alias",
      );
      source.revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
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
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => {
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
        git(
          source.path,
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.test",
          "commit",
          "-qm",
          "Synthetic imported tool",
        );
      }
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${revision},src\n`,
      );
      await runMultiscan(
        options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
      );
      const checkout = join(
        paths.output,
        "recovery-checkouts",
        "repo",
        "attempt-2",
      );
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
        const runs = mock(
          async (
            root: string,
            settings: Parameters<SecurityClient["run"]>[1] = {},
          ) => completedScan(settings.outputDir!, "complete", root),
        );
        const campaign = options(paths, client(runs), {
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
        expect(await runMultiscan(campaign)).toMatchObject({
          completed: 1,
          skipped: 1,
        });
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
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Synthetic case-distinct path",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},SRC\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        root: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", root),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    const initial = await runMultiscan(campaign);
    expect(initial).toMatchObject({ completed: 1, skipped: 0 });
    expect(await results(initial.resultsPath)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ status: "completed", resolvedScope: "SRC" }),
      ]),
    );
    const ledger = await readFile(initial.resultsPath);
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "repo",
      "attempt-2",
    );
    git(paths.root, "clone", "--quiet", source.path, checkout);
    git(checkout, "config", "core.ignorecase", String(ignoreCase));
    await rm(join(checkout, "src"), { recursive: true, force: true });
    await rm(join(checkout, "SRC"), { recursive: true, force: true });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
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
      return { coverage: saved.coverage, findings: saved.findings, cost: null };
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

test.each(["sha1", "sha256"])(
  "bulk checkout preserves %s object format despite Git defaults",
  async (objectFormat) => {
    const name = `bulk checkout preserves ${objectFormat} object format despite Git defaults`;
    if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
    const paths = await fixture();
    const repo = await repository(paths.root, "source", objectFormat);
    await writeFile(
      paths.input,
      `id,repository,revision\nfixture,${repo.path},${repo.revision}\n`,
    );
    const run = mock(async (checkout: string, scanOptions = {}) => {
      expect(git(checkout, "rev-parse", "--show-object-format")).toBe(
        objectFormat,
      );
      return completeRun(checkout, scanOptions);
    });
    const previous = process.env["GIT_DEFAULT_HASH"];
    process.env["GIT_DEFAULT_HASH"] =
      objectFormat === "sha1" ? "sha256" : "sha1";
    try {
      const result = await runMultiscan(options(paths, client(run)));
      expect(result.failed).toBe(0);
      expect(run).toHaveBeenCalledTimes(1);
      expect(process.env["GIT_DEFAULT_HASH"]).toBe(
        objectFormat === "sha1" ? "sha256" : "sha1",
      );
    } finally {
      if (previous === undefined) delete process.env["GIT_DEFAULT_HASH"];
      else process.env["GIT_DEFAULT_HASH"] = previous;
    }
  },
);
