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
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { hostname } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { zipSync } from "fflate";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contracts from "../src/contract.js";
import { writeThreatModel } from "../src/artifact-export.js";
import { PYTHON } from "./support/security-policy.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanResult } from "../src/result.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { DiffTarget, normalizeTarget } from "../src/targets.js";
import { prepareOutputDir } from "../src/runtime.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import * as runtime from "../src/runtime.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-multiscan-",
);
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(cleanup);

test("keeps literal CSV scopes at the checked out repository", async () => {
  const name = "keeps literal CSV scopes at the checked out repository";
  if (runTestInSubprocess(import.meta.path, name)) return;
  const { paths, source } = await repositoryFixture("literal-scopes");
  const os = { ...(await import("node:os")) };
  mock.module("node:os", () => ({ ...os, homedir: () => source.path }));
  const literals = ["~/src", "$HOME/src", "%HOME%/src", "space name"];
  for (const path of literals) {
    await mkdir(join(source.path, path), { recursive: true });
    await writeFile(join(source.path, path, "app.ts"), "export {};\n");
  }
  git(source.path, "add", ".");
  git(
    source.path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "literal scopes",
  );
  const revision = git(source.path, "rev-parse", "HEAD");
  await writeFile(
    paths.input,
    [
      "id,repository,revision,scope",
      ...literals.map(
        (scope, index) => `scope-${index},${source.path},${revision},${scope}`,
      ),
      `configured,${source.path},${revision},`,
    ].join("\n"),
  );
  const observed: string[] = [];
  const summary = await runMultiscan(
    options(
      paths,
      client(async (repository, scanOptions = {}) => {
        const target = await normalizeTarget(repository, scanOptions.target!);
        observed.push(...target.paths);
        expect(scanOptions.target).toEqual(
          target.paths[0] === "src"
            ? ["src"]
            : target.paths.map((path) => join(repository, path)),
        );
        return await completedScan(scanOptions.outputDir!);
      }),
      { scanOptionsByMode: { standard: { target: ["src"] } } },
    ),
  );
  expect(summary).toMatchObject({ completed: literals.length + 1, failed: 0 });
  expect(observed.sort()).toEqual([...literals, "src"].sort());
});

async function fixture() {
  const root = await temporaryDirectory();
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

async function repository(root: string, name: string, objectFormat = "sha1") {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q", `--object-format=${objectFormat}`);
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
  completeness?: "complete" | "partial" | "unknown",
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  await chmod(outputDir, 0o700);
  await copyCompletedScanFixture(outputDir);
  await writeFile(join(outputDir, "report.md"), "{}\n");
  if (completeness !== undefined) {
    const coveragePath = join(outputDir, "coverage.json");
    const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
    coverage.completeness = completeness;
    await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
    await reseal(outputDir);
  }
  const result = fakeResult([], completeness);
  return { manifest: result.manifest, coverage: result.coverage } as ScanResult;
}

async function reseal(scanDir: string): Promise<void> {
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(scanDir, artifact.path)))
      .digest("hex");
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function customPlugin(
  root: string,
  format: "directory" | "zip",
): Promise<string> {
  const files: Record<string, Uint8Array> = {};
  for (const name of [
    ".codex-plugin/plugin.json",
    "schemas/scan-manifest.schema.json",
    "schemas/findings.schema.json",
    "schemas/coverage.schema.json",
  ]) {
    files[name] = await readFile(join(PLUGIN_ROOT, name));
  }
  const coverage = JSON.parse(
    Buffer.from(files["schemas/coverage.schema.json"]!).toString("utf8"),
  );
  coverage.properties.schemaVersion = { enum: ["1.0", "custom-test"] };
  files["schemas/coverage.schema.json"] = Buffer.from(JSON.stringify(coverage));
  const path = join(root, format === "zip" ? "plugin.zip" : "plugin");
  if (format === "zip") {
    await writeFile(path, zipSync(files));
  } else {
    await mkdir(join(path, ".codex-plugin"), { recursive: true });
    await mkdir(join(path, "schemas"));
    for (const [name, bytes] of Object.entries(files)) {
      await writeFile(join(path, name), bytes);
    }
  }
  return path;
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

function receiptCost(onSerialized: () => void) {
  const cost = {
    model: "synthetic-model",
    inputTokens: 1,
    cachedInputTokens: 0,
    cacheWriteInputTokens: 0,
    outputTokens: 1,
    estimatedUsd: 0,
  };
  return {
    ...cost,
    toJSON() {
      onSerialized();
      return cost;
    },
  };
}

describe("multiscan", () => {
  test("serializes receipt writes through close and drains workers before unlocking", async () => {
    const { paths, source } = await repositoryFixture("receipt-order", "first");
    await appendFile(paths.input, `second,${source.path},${source.revision}\n`);
    const pause = () => {
      const entered = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      return {
        entered: entered.promise,
        release: release.resolve,
        async wait() {
          entered.resolve();
          await release.promise;
        },
      };
    };
    const firstWrite = pause();
    const firstSync = pause();
    const firstClose = pause();
    const secondClose = pause();
    const secondSerialized = Promise.withResolvers<void>();
    const firstCompleted = Promise.withResolvers<void>();
    const clientsClosing = Promise.withResolvers<void>();
    const releaseClients = Promise.withResolvers<void>();
    const ledger = join(paths.output, "results.jsonl");
    const originalOpen = filesystem.open;
    let opens = 0;
    let closes = 0;
    let settled = false;
    const openSpy = spyOn(filesystem, "open").mockImplementation(
      async (...args: Parameters<typeof originalOpen>) => {
        const ordinal = String(args[0]) === ledger ? ++opens : 0;
        const file = await Reflect.apply(originalOpen, filesystem, args);
        if (ordinal === 0) return file;
        const write = file.writeFile.bind(file);
        const sync = file.sync.bind(file);
        const close = file.close.bind(file);
        file.writeFile = async (...writeArgs) => {
          if (ordinal === 1) await firstWrite.wait();
          await write(...writeArgs);
        };
        file.sync = async () => {
          if (ordinal === 1) await firstSync.wait();
          await sync();
        };
        file.close = async () => {
          await (ordinal === 1 ? firstClose : secondClose).wait();
          await close();
        };
        return file;
      },
    );
    const configured = options(
      paths,
      client(
        async (_repository, scanOptions = {}) => {
          const second = basename(dirname(scanOptions.outputDir!)) === "second";
          if (second) await firstWrite.entered;
          return Object.assign(await completedScan(scanOptions.outputDir!), {
            threatModelPath: null,
            cost: second ? receiptCost(secondSerialized.resolve) : null,
          });
        },
        async () => {
          if (++closes === 2) clientsClosing.resolve();
          await releaseClients.promise;
        },
      ),
      {
        workers: 2,
        onProgress: (event) => {
          if (event.repository === "first" && event.status === "completed") {
            firstCompleted.resolve();
          }
        },
      },
    );
    const operation = runMultiscan(configured);
    void operation.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    try {
      // Serialization is the final synchronous step before enqueueing the row.
      await secondSerialized.promise;
      for (const stage of [firstWrite, firstSync, firstClose]) {
        await stage.entered;
        expect(opens).toBe(1);
        stage.release();
      }
      await secondClose.entered;
      await firstCompleted.promise;
      expect(opens).toBe(2);
      expect(settled).toBe(false);
      await expect(runMultiscan(configured)).rejects.toThrow(
        "A multiscan supervisor is already running.",
      );
      secondClose.release();
      await clientsClosing.promise;
      expect(settled).toBe(false);
      expect((await lstat(join(paths.output, ".lock"))).isDirectory()).toBe(
        true,
      );
      releaseClients.resolve();
      expect(await operation).toMatchObject({ completed: 2, failed: 0 });
      expect(await results(ledger)).toMatchObject([
        { id: "first", status: "completed" },
        { id: "second", status: "completed" },
      ]);
      await expect(lstat(join(paths.output, ".lock"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      for (const stage of [firstWrite, firstSync, firstClose, secondClose]) {
        stage.release();
      }
      releaseClients.resolve();
      await operation.catch(() => {});
      openSpy.mockRestore();
    }
  });

  test.each(["open", "write", "sync", "close"])(
    "stops queued receipt appends after a receipt %s failure",
    async (failure) => {
      const { paths, source } = await repositoryFixture(
        "receipt-failure",
        "first",
      );
      await appendFile(
        paths.input,
        `second,${source.path},${source.revision}\n`,
      );
      const failing = Promise.withResolvers<void>();
      const secondSerialized = Promise.withResolvers<void>();
      const injected = new Error(`Synthetic receipt ${failure} failure`);
      const rejectAppend = async () => {
        failing.resolve();
        await secondSerialized.promise;
        throw injected;
      };
      const ledger = join(paths.output, "results.jsonl");
      const originalOpen = filesystem.open;
      let opens = 0;
      const openSpy = spyOn(filesystem, "open").mockImplementation(
        async (...args: Parameters<typeof originalOpen>) => {
          const ordinal = String(args[0]) === ledger ? ++opens : 0;
          if (ordinal === 1 && failure === "open") await rejectAppend();
          const file = await Reflect.apply(originalOpen, filesystem, args);
          if (ordinal !== 1) return file;
          const write = file.writeFile.bind(file);
          const sync = file.sync.bind(file);
          const close = file.close.bind(file);
          file.writeFile = async (...writeArgs) => {
            if (failure === "write") await rejectAppend();
            await write(...writeArgs);
          };
          file.sync = async () => {
            if (failure === "sync") await rejectAppend();
            await sync();
          };
          file.close = async () => {
            await close();
            if (failure === "close") await rejectAppend();
          };
          return file;
        },
      );
      const close = mock(async () => {});
      const security = client(async (_repository, scanOptions = {}) => {
        const second = basename(dirname(scanOptions.outputDir!)) === "second";
        if (second) await failing.promise;
        return Object.assign(await completedScan(scanOptions.outputDir!), {
          threatModelPath: null,
          cost: second ? receiptCost(secondSerialized.resolve) : null,
        });
      }, close);
      try {
        await expect(
          runMultiscan(options(paths, security, { workers: 2 })),
        ).rejects.toBe(injected);
        expect(opens).toBe(1);
        expect(close).toHaveBeenCalledTimes(2);
        await expect(lstat(join(paths.output, ".lock"))).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        openSpy.mockRestore();
      }
    },
  );

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

  const interruptedUtf8Cases: [string, number, boolean][] = [
    ["é", 1, false],
    ["中", 1, false],
    ["中", 2, false],
    ["🧪", 1, false],
    ["🧪", 2, false],
    ["🧪", 3, false],
    ["malformed prefix", 0, true],
  ];
  test.each(interruptedUtf8Cases)(
    "recovery preserves interrupted %s after %d UTF-8 bytes (malformed prefix=%p)",
    async (character, length, malformedPrefix) => {
      const paths = await fixture();
      const task = {
        id: "complete",
        repository: join(paths.root, "unused-source"),
        revision: "a".repeat(40),
        mode: "standard",
      };
      const outputDir = join(paths.output, "artifacts", task.id, "attempt-1");
      await completedScan(outputDir);
      const artifacts = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ].map((name) => join(outputDir, name));
      const before = await Promise.all(artifacts.map((path) => readFile(path)));
      await writeFile(
        paths.input,
        `id,repository,revision\n${task.id},${task.repository},${task.revision}\n`,
      );
      await writeFile(
        join(paths.output, "manifest.json"),
        JSON.stringify({ version: 2, tasks: [task] }, null, 2) + "\n",
      );
      let prefix = Buffer.from(
        JSON.stringify({
          ...task,
          status: "completed",
          attempt: 1,
          outputDir,
          error: "prefix marker é中🧪",
        }) + "\n",
      );
      if (malformedPrefix) {
        const offset = prefix.indexOf("prefix marker");
        expect(offset).toBeGreaterThan(-1);
        prefix = Buffer.concat([
          prefix.subarray(0, offset),
          Buffer.from([0xff, 0xfe]),
          prefix.subarray(offset + "prefix marker".length),
        ]);
      }
      const receipt = Buffer.from(
        JSON.stringify({
          ...task,
          status: "failed",
          attempt: 2,
          error: character,
        }) + "\n",
      );
      // The malformed prefix made the old offset retain this byte and add NULs.
      const tail = malformedPrefix
        ? Buffer.from([0xf0])
        : receipt.subarray(
            0,
            receipt.lastIndexOf(Buffer.from(character)) + length,
          );
      const ledger = join(paths.output, "results.jsonl");
      await writeFile(ledger, Buffer.concat([prefix, tail]));
      const createSecurity = mock(
        throwing("Completed task must not start a client"),
      );
      const recoverScan = mock(rejecting("Completed task must not be resumed"));
      for (const _ of [1, 2]) {
        expect(
          await runMultiscan({
            inputPath: paths.input,
            outputDir: paths.output,
            mode: "standard",
            workers: 1,
            maxAttempts: 1,
            config: {},
            createSecurity,
            recoverScan,
          }),
        ).toEqual({
          total: 1,
          completed: 1,
          failed: 0,
          skipped: 1,
          resultsPath: ledger,
        });
        expect(createSecurity).not.toHaveBeenCalled();
        expect(recoverScan).not.toHaveBeenCalled();
        expect(await readFile(ledger)).toEqual(prefix);
        const backups = (await readdir(paths.output)).filter((name) =>
          name.startsWith("results.jsonl.interrupted-"),
        );
        expect(backups).toHaveLength(1);
        expect(await readFile(join(paths.output, backups[0]!))).toEqual(tail);
        expect(
          await Promise.all(artifacts.map((path) => readFile(path))),
        ).toEqual(before);
      }
    },
  );

  test.each(["backup", "truncate"] as const)(
    "recovery preserves interrupted receipt bytes when %s fails",
    async (operation) => {
      const { paths } = await repositoryFixture("interrupted-receipt");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      const initial = await runMultiscan(configured);
      const original = await readFile(initial.resultsPath);
      const tail = Buffer.concat([
        Buffer.from('{"error":"'),
        Buffer.from([0xc3]),
      ]);
      const damaged = Buffer.concat([original, tail]);
      await writeFile(initial.resultsPath, damaged);
      const failure = new Error(`Synthetic receipt ${operation} failure`);
      const recoverScan = mock(async () => undefined);
      const originalWriteFile = filesystem.writeFile;
      const originalTruncate = filesystem.truncate;
      const backupSpy = spyOn(filesystem, "writeFile").mockImplementation(
        async (...args) => {
          if (
            operation === "backup" &&
            String(args[0]).startsWith(`${initial.resultsPath}.interrupted-`)
          )
            throw failure;
          return await originalWriteFile(...args);
        },
      );
      const truncateSpy = spyOn(filesystem, "truncate").mockImplementation(
        async (path, length) => {
          if (path === initial.resultsPath && operation === "truncate")
            throw failure;
          return await originalTruncate(path, length);
        },
      );
      try {
        await expect(runMultiscan({ ...configured, recoverScan })).rejects.toBe(
          failure,
        );
        expect(await readFile(initial.resultsPath)).toEqual(damaged);
        expect(run).toHaveBeenCalledTimes(1);
        expect(recoverScan).not.toHaveBeenCalled();
        const names = await readdir(paths.output);
        expect(names).not.toContain(".lock");
        const backups = names.filter((name) =>
          name.startsWith("results.jsonl.interrupted-"),
        );
        if (operation === "backup") {
          expect(backups).toHaveLength(0);
          expect(truncateSpy).not.toHaveBeenCalled();
        } else {
          expect(backups).toHaveLength(1);
          expect(await readFile(join(paths.output, backups[0]!))).toEqual(tail);
          expect(truncateSpy).toHaveBeenCalledWith(
            initial.resultsPath,
            original.length,
          );
        }
      } finally {
        backupSpy.mockRestore();
        truncateSpy.mockRestore();
      }
    },
  );

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
    const configured = options(paths, client(runs), {
      maxAttempts: 1,
      recoverScan: resumed,
    });
    const result = await runMultiscan(configured);
    expect(result).toMatchObject({
      completed: 2,
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
    expect(await runMultiscan(configured)).toMatchObject({
      completed: 2,
      failed: 0,
      skipped: 2,
    });
    expect(runs).toHaveBeenCalledTimes(1);
    expect(resumed).toHaveBeenCalledTimes(1);
    expect((await lstat(checkout)).ino).toBe(inode);
    expect(await readFile(join(checkout, "source"), "utf8")).toBe(
      "keep checkout",
    );
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
        return completedScan(scanDir);
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
            options(paths, client(runs), {
              maxAttempts: 3,
              config: { pythonPath: PYTHON },
              recoverScan,
            }),
          ),
        ).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
        expect(recoverScan).toHaveBeenCalledTimes(1);
        expect(runs).not.toHaveBeenCalled();
        expect(await readFile(join(checkout, "source"), "utf8")).toBe(
          "keep checkout",
        );
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
          const recovered = fakeResult([severity]);
          return {
            manifest: recovered.manifest,
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
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      const outputDir = join(paths.output, "artifacts", "sealed", "attempt-1");
      const receipts = await results(summary.resultsPath);
      expect(receipts).toMatchObject([
        {
          id: "sealed",
          status: "completed",
          attempt: 1,
          outputDir,
          cost,
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
          status: "completed",
          attempt: 1,
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
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(attempts).toBe(1);
      expect(await results(resumed.resultsPath)).toHaveLength(1);
      await rm(document);
      expect(
        await runMultiscan(options(paths, security, { knowledgeBasePaths })),
      ).toMatchObject({ completed: 0, failed: 1 });
      await writeFile(document, "Original context.");
      expect(
        await runMultiscan(options(paths, security, { knowledgeBasePaths })),
      ).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
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

  test.each([
    ["partial", "failed"],
    ["unknown", "completed_with_incomplete_coverage"],
  ] as const)(
    "resumes legacy sealed %s coverage (%s receipt) without rerunning or duplicating cost",
    async (completeness, status) => {
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
        status,
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
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(security.run.mock.calls.length).toBe(0);
      expect(progress).toEqual([]);
      expect(await results(summary.resultsPath)).toEqual([receipt]);

      await runMultiscan(options(paths, security, { maxAttempts: 3 }));
      expect(security.run.mock.calls.length).toBe(0);
      expect(await results(summary.resultsPath)).toEqual([receipt]);
    },
  );

  test.each([
    ["operational failures", "completed", "Worker exited unexpectedly.", false],
    [
      "failed manifest",
      "failed",
      "Multiscan repository coverage is incomplete.",
      false,
    ],
    [
      "malformed manifest",
      "malformed",
      "Multiscan repository coverage is incomplete.",
      false,
    ],
    [
      "missing artifacts",
      "completed",
      "Multiscan repository coverage is incomplete.",
      true,
    ],
  ] as const)(
    "continues retrying legacy %s",
    async (_scenario, status, error, missingArtifact) => {
      const { paths, source } = await repositoryFixture(
        "legacy-retry",
        "legacy",
      );
      const outputDir = join(paths.output, "artifacts", "legacy", "attempt-1");
      await completedScan(outputDir);
      await writeFile(
        join(outputDir, "scan-manifest.json"),
        status === "malformed" ? "{\n" : JSON.stringify({ scan: { status } }),
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
        failed: 0,
        skipped: 0,
      });
      expect(attempts.mock.calls.length).toBe(1);
      expect(await results(summary.resultsPath)).toMatchObject([
        { status: "failed", attempt: 1, error },
        { status: "completed", attempt: 2 },
      ]);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "accepts sealed legacy %s coverage without retrying",
    async (completeness) => {
      const { paths } = await repositoryFixture("sample");
      const outputDir = join(paths.output, "artifacts", "sample", "attempt-1");
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
        result: fakeResult([], completeness),
        onRun,
      });
      const createSecurity = clientDependencies.createSecurity;
      clientDependencies.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          run: async (repository, scan = {}) => {
            await completedScan(scan.outputDir!, completeness);
            return security.run(repository, scan);
          },
        };
      };

      expect(await runCli(arguments_, clientDependencies)).toBe(0);
      expect(onRun).toHaveBeenCalledTimes(1);
      expect(JSON.parse(stdout.text())).toMatchObject({
        total: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      expect(stderr.text()).toContain("sample completed (attempt 1)");
      expect(stderr.text()).not.toContain("attempt 2");
      expect(await results(join(paths.output, "results.jsonl"))).toMatchObject([
        {
          status: "completed",
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
      ).toBe(0);
      expect(JSON.parse(resumedOutput.text())).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(onRun).toHaveBeenCalledTimes(1);
    },
  );

  test("retries actual failed manifests while retaining completed reports", async () => {
    const { paths } = await repositoryFixture("missing-artifact", "missing");

    const attempts = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        const result = await completedScan(
          scanOptions.outputDir!,
          attempts.mock.calls.length === 1 ? "partial" : "complete",
        );
        if (attempts.mock.calls.length === 1) {
          result.manifest.scan.status = "failed";
        }
        return result;
      },
    );
    const summary = await runMultiscan(options(paths, client(attempts)));

    expect(attempts.mock.calls.length).toBe(2);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "missing",
        status: "failed",
        attempt: 1,
        error: "Multiscan scan failed.",
      },
      { id: "missing", status: "completed", attempt: 2 },
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
      expect(scanOptions.target).toEqual([join(path, "src")]);
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

  test.each(["completed", "failed"] as const)(
    "records a %s scan outcome when checkout cleanup fails",
    async (outcome) => {
      const { paths } = await repositoryFixture(
        `cleanup-${outcome}`,
        "stubborn",
      );
      const checkout = join(paths.output, "checkouts", "stubborn");
      const originalRm = filesystem.rm;
      let scanned = false;
      let rejectedCleanup = false;
      const removeSpy = spyOn(filesystem, "rm").mockImplementation(
        async (...args: Parameters<typeof originalRm>) => {
          if (scanned && !rejectedCleanup && String(args[0]) === checkout) {
            rejectedCleanup = true;
            throw Object.assign(
              new Error(`EACCES: permission denied, rm '${checkout}'`),
              { code: "EACCES" },
            );
          }
          return await Reflect.apply(originalRm, filesystem, args);
        },
      );
      const run = mock<SecurityClient["run"]>(
        async (_repository, scanOptions = {}) => {
          if (outcome === "failed") {
            scanned = true;
            throw new Error("ORIGINAL_SCAN_FAILURE");
          }
          const result = await completedScan(scanOptions.outputDir!);
          scanned = true;
          return result;
        },
      );
      const configured = options(paths, client(run), { maxAttempts: 1 });

      try {
        const summary = await runMultiscan(configured);
        expect(summary).toMatchObject(
          outcome === "completed"
            ? { completed: 1, failed: 0 }
            : { completed: 0, failed: 1 },
        );
        const receipts = await results(summary.resultsPath);
        expect(receipts).toHaveLength(1);
        expect(receipts[0]).toMatchObject({ status: outcome });
        expect(receipts[0]?.["cleanupPending"]).toBe(
          outcome === "completed" ? "checkout" : undefined,
        );
        const error = String(receipts[0]?.["error"]);
        expect(error).toContain("Multiscan checkout cleanup failed");
        if (outcome === "failed") {
          expect(error).toContain("ORIGINAL_SCAN_FAILURE");
        } else {
          expect((await lstat(checkout)).isDirectory()).toBe(true);
          expect(await runMultiscan(configured)).toMatchObject({ skipped: 1 });
          expect(run).toHaveBeenCalledTimes(1);
          await expect(lstat(checkout)).rejects.toMatchObject({
            code: "ENOENT",
          });
        }
      } finally {
        removeSpy.mockRestore();
      }
    },
  );

  test("keeps recovery receipts readable and continues after checkout cleanup fails", async () => {
    const { paths, source } = await repositoryFixture(
      "recovery-cleanup",
      "stubborn",
    );
    await appendFile(paths.input, `next,${source.path},${source.revision}\n`);
    await runMultiscan(
      options(paths, client(rejecting("Interrupted scan")), { maxAttempts: 1 }),
    );
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "stubborn",
      "attempt-2",
    );
    const originalRm = filesystem.rm;
    const originalOpen = filesystem.open;
    let diagnosticWrites = 0;
    const openSpy = spyOn(filesystem, "open").mockImplementation(
      async (...args: Parameters<typeof originalOpen>) => {
        const file = await Reflect.apply(originalOpen, filesystem, args);
        if (String(args[0]) === join(paths.output, "results.jsonl")) {
          const write = file.writeFile.bind(file);
          file.writeFile = async (data, options) => {
            const text = String(data);
            if (
              JSON.parse(text).error?.includes(
                "Multiscan checkout cleanup failed",
              )
            ) {
              diagnosticWrites += 1;
              await write(text.slice(0, 24), options);
              throw new Error("EIO: synthetic partial diagnostic write");
            }
            return await write(data, options);
          };
        }
        return file;
      },
    );
    let scanned = false;
    let rejectedCleanup = false;
    const removeSpy = spyOn(filesystem, "rm").mockImplementation(
      async (...args: Parameters<typeof originalRm>) => {
        if (scanned && !rejectedCleanup && String(args[0]) === checkout) {
          rejectedCleanup = true;
          throw Object.assign(
            new Error(`EBUSY: resource busy, rm '${checkout}'`),
            { code: "EBUSY" },
          );
        }
        return await Reflect.apply(originalRm, filesystem, args);
      },
    );
    const run = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        const result = await completedScan(scanOptions.outputDir!);
        scanned = true;
        return result;
      },
    );
    const progress: Array<
      Parameters<NonNullable<MultiscanOptions["onProgress"]>>[0]
    > = [];
    const configured = options(paths, client(run), {
      maxAttempts: 1,
      recoverScan: async () => undefined,
      onProgress: (event) => progress.push(event),
    });

    try {
      const summary = await runMultiscan(configured);
      expect(summary).toMatchObject({ completed: 2, failed: 0, skipped: 0 });
      expect(
        progress.find(
          (event) =>
            event.repository === "stubborn" && event.status === "completed",
        ),
      ).toMatchObject({
        repository: "stubborn",
        attempt: 2,
        status: "completed",
        error: expect.stringContaining("Multiscan checkout cleanup failed"),
      });
      const receipts = await results(summary.resultsPath);
      const recovered = receipts.find(
        (receipt) =>
          receipt["id"] === "stubborn" && receipt["status"] === "completed",
      );
      expect(recovered).toMatchObject({
        status: "completed",
        attempt: 2,
        cleanupPending: "recovery-checkout",
      });
      expect(recovered).not.toHaveProperty("error");
      expect(receipts.at(-1)).toMatchObject({
        id: "next",
        status: "completed",
      });
      expect(diagnosticWrites).toBe(0);
      expect((await lstat(checkout)).isDirectory()).toBe(true);

      expect(await runMultiscan(options(paths, client(run)))).toMatchObject({
        completed: 2,
        failed: 0,
        skipped: 2,
      });
      expect(run).toHaveBeenCalledTimes(2);
      await expect(lstat(checkout)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      removeSpy.mockRestore();
      openSpy.mockRestore();
    }
  });

  test("reuses recovered completion saved before checkout removal", async () => {
    const { paths } = await repositoryFixture("cleanup-interruption", "done");
    await runMultiscan(
      options(paths, client(rejecting("Interrupted scan")), { maxAttempts: 1 }),
    );
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "done",
      "attempt-2",
    );
    const ledger = join(paths.output, "results.jsonl");
    const originalRm = filesystem.rm;
    let persistedBeforeRemoval: string | undefined;
    const removeSpy = spyOn(filesystem, "rm").mockImplementation(
      async (...args: Parameters<typeof originalRm>) => {
        if (String(args[0]) === checkout) {
          persistedBeforeRemoval = await readFile(ledger, "utf8");
        }
        return await Reflect.apply(originalRm, filesystem, args);
      },
    );
    const run = mock(completeRun);
    try {
      await runMultiscan(
        options(paths, client(run), { recoverScan: async () => undefined }),
      );
    } finally {
      removeSpy.mockRestore();
    }

    expect(persistedBeforeRemoval).toBeDefined();
    await writeFile(ledger, persistedBeforeRemoval!);
    expect((await results(ledger)).at(-1)).toMatchObject({
      status: "completed",
      attempt: 2,
      cleanupPending: "recovery-checkout",
    });
    expect(await runMultiscan(options(paths, client(run)))).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(run).toHaveBeenCalledTimes(1);
  });

  test("retries failed scans and continues later tasks when checkout cleanup fails", async () => {
    const { paths, source } = await repositoryFixture("cleanup-retry", "retry");
    await appendFile(paths.input, `next,${source.path},${source.revision}\n`);
    const checkout = join(paths.output, "checkouts", "retry");
    const originalRm = filesystem.rm;
    let attempted = false;
    let rejectedCleanup = false;
    const removeSpy = spyOn(filesystem, "rm").mockImplementation(
      async (...args: Parameters<typeof originalRm>) => {
        if (attempted && !rejectedCleanup && String(args[0]) === checkout) {
          rejectedCleanup = true;
          throw new Error("EACCES: synthetic cleanup failure");
        }
        return await Reflect.apply(originalRm, filesystem, args);
      },
    );
    const run = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        if (!attempted) {
          attempted = true;
          throw new Error("ORIGINAL_SCAN_FAILURE");
        }
        return await completedScan(scanOptions.outputDir!);
      },
    );

    try {
      const summary = await runMultiscan(options(paths, client(run)));

      expect(summary).toMatchObject({ total: 2, completed: 2, failed: 0 });
      expect(run).toHaveBeenCalledTimes(3);
      expect(await results(summary.resultsPath)).toMatchObject([
        {
          id: "retry",
          status: "failed",
          attempt: 1,
          error:
            "ORIGINAL_SCAN_FAILURE; Multiscan checkout cleanup failed: EACCES: synthetic cleanup failure",
        },
        { id: "retry", status: "completed", attempt: 2 },
        { id: "next", status: "completed", attempt: 1 },
      ]);
    } finally {
      removeSpy.mockRestore();
    }
  });

  test.each(["root", "task"] as const)(
    "preserves completed scans and external files when the recovery checkout %s is linked",
    async (parent) => {
      const { paths } = await repositoryFixture("linked-cleanup", "done");
      const scans = mock(completeRun);
      const configured = options(paths, client(scans));
      await runMultiscan(configured);
      const ledger = join(paths.output, "results.jsonl");
      const [receipt] = await results(ledger);
      await writeFile(
        ledger,
        `${JSON.stringify({ ...receipt, cleanupPending: "recovery-checkout" })}\n`,
      );
      const recoveryRoot = join(paths.output, "recovery-checkouts");
      const external = await temporaryDirectory();
      const preserved = join(
        external,
        ...(parent === "root" ? ["done"] : []),
        "attempt-1",
        "keep.txt",
      );
      await mkdir(dirname(preserved), { recursive: true });
      await writeFile(preserved, "preserved\n");
      if (parent === "task") await mkdir(recoveryRoot, { mode: 0o700 });
      await symlink(
        external,
        parent === "root" ? recoveryRoot : join(recoveryRoot, "done"),
        process.platform === "win32" ? "junction" : "dir",
      );

      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(scans).toHaveBeenCalledTimes(1);
      expect(await readFile(preserved, "utf8")).toBe("preserved\n");
    },
  );

  test("preserves sibling artifacts when a cleanup receipt has a traversal attempt", async () => {
    const { paths } = await repositoryFixture("cleanup-traversal", "done");
    const scans = mock(completeRun);
    const configured = options(paths, client(scans));
    await runMultiscan(configured);
    const external = join(paths.root, "other-scan");
    await completedScan(external);
    const preserved = join(external, "keep.txt");
    await writeFile(preserved, "preserved\n");
    await mkdir(join(paths.output, "recovery-checkouts", "done"), {
      recursive: true,
      mode: 0o700,
    });
    const ledger = join(paths.output, "results.jsonl");
    const [receipt] = await results(ledger);
    await writeFile(
      ledger,
      `${JSON.stringify({
        ...receipt,
        attempt: "1/../../../../other-scan",
        outputDir: external,
        cleanupPending: "recovery-checkout",
      })}\n`,
    );

    expect(await runMultiscan(configured)).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(scans).toHaveBeenCalledTimes(1);
    expect(await readFile(preserved, "utf8")).toBe("preserved\n");
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
    const { paths } = await repositoryFixture("exclusive");
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
    await mkdir(checkout);

    const recovered = await runMultiscan(options(paths, security));
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
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

  test("resumes complete bundles, repairs missing output, and rejects manifest drift", async () => {
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
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    const repaired = await runMultiscan(options(paths, security));
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(security.run.mock.calls.length).toBe(2);
    expect((await results(repaired.resultsPath)).at(-1)?.["outputDir"]).toBe(
      join(paths.output, "artifacts", "resume", "attempt-2"),
    );

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(security.run.mock.calls.length).toBe(2);
  });

  test.each([
    "malformed manifest",
    "schema-invalid manifest",
    "changed findings",
    "failed",
    "canceled",
    "interrupted",
  ] as const)(
    "rescans a completed receipt with %s artifacts",
    async (problem) => {
      const { paths } = await repositoryFixture("resume-integrity");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      await runMultiscan(configured);
      const [receipt] = await results(join(paths.output, "results.jsonl"));
      const scanDir = receipt!["outputDir"] as string;
      const manifestPath = join(scanDir, "scan-manifest.json");
      if (problem === "malformed manifest")
        await writeFile(manifestPath, "{broken json");
      else if (problem === "schema-invalid manifest")
        await writeFile(manifestPath, "{}");
      else if (problem === "changed findings")
        await appendFile(join(scanDir, "findings.json"), "\n");
      else {
        const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        manifest.scan.status = problem;
        await writeFile(manifestPath, JSON.stringify(manifest));
        expect(
          (await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT })).manifest
            .scan.status,
        ).toBe(problem);
      }
      const savedArtifacts = () =>
        Promise.all(
          [
            "scan-manifest.json",
            "findings.json",
            "coverage.json",
            "report.md",
          ].map((name) => readFile(join(scanDir, name))),
        );
      const before = await savedArtifacts();
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      expect(run).toHaveBeenCalledTimes(2);
      expect(await savedArtifacts()).toEqual(before);
      expect(
        (await results(join(paths.output, "results.jsonl"))).at(-1),
      ).toMatchObject({
        status: "completed",
        attempt: 2,
        outputDir: join(
          paths.output,
          "artifacts",
          "resume-integrity",
          "attempt-2",
        ),
      });
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(run).toHaveBeenCalledTimes(2);
    },
  );

  test.each(["completed_with_incomplete_coverage", "failed"])(
    "validates artifacts before reusing a legacy %s receipt",
    async (status) => {
      const { paths } = await repositoryFixture("legacy-integrity");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      await runMultiscan(configured);
      const ledger = join(paths.output, "results.jsonl");
      const [receipt] = await results(ledger);
      await writeFile(
        ledger,
        JSON.stringify({
          ...receipt,
          status,
          error: "Multiscan repository coverage is incomplete.",
        }) + "\n",
      );
      await appendFile(
        join(receipt!["outputDir"] as string, "findings.json"),
        "\n",
      );
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      expect(run).toHaveBeenCalledTimes(2);
    },
  );

  test.each(["directory", "zip"] as const)(
    "uses configured %s schemas for resume and removes temporary plugin files",
    async (format) => {
      const { paths } = await repositoryFixture(`custom-${format}`);
      const pluginPath = await customPlugin(paths.root, format);
      const run = mock(completeRun);
      const configured = options(paths, client(run), {
        config: { pluginPath },
      });
      await runMultiscan(configured);
      const [receipt] = await results(join(paths.output, "results.jsonl"));
      const scanDir = receipt!["outputDir"] as string;
      const coveragePath = join(scanDir, "coverage.json");
      const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
      coverage.schemaVersion = "custom-test";
      await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
      await reseal(scanDir);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow();
      expect(await runMultiscan(configured)).toMatchObject({ skipped: 1 });
      expect(run).toHaveBeenCalledTimes(1);
      const clean = async () =>
        expect(
          (await readdir(paths.output)).filter(
            (name) => name === ".lock" || name.startsWith(".resume-plugin-"),
          ),
        ).toEqual([]);
      await clean();

      await rm(pluginPath, { recursive: true, force: true });
      await expect(runMultiscan(configured)).rejects.toThrow(
        "Plugin path must be a directory or ZIP",
      );
      expect(run).toHaveBeenCalledTimes(1);
      await clean();
    },
  );

  test.each(["plugin resolution", "contract validation"] as const)(
    "preserves cancellation during %s without rescanning or retaining plugin files",
    async (phase) => {
      const { paths } = await repositoryFixture("cancel-validation");
      const pluginPath = await customPlugin(paths.root, "zip");
      const run = mock(completeRun);
      const configured = options(paths, client(run), {
        config: { pluginPath },
      });
      await runMultiscan(configured);
      const before = await readFile(
        join(paths.output, "results.jsonl"),
        "utf8",
      );
      const controller = new AbortController();
      const reason = new Error("Synthetic resume cancellation");
      const resolvePlugin = runtime.resolvePluginPath;
      const load = contracts.loadContract;
      const resolveSpy = spyOn(runtime, "resolvePluginPath").mockImplementation(
        async (...args) => {
          if (phase === "plugin resolution") controller.abort(reason);
          return await resolvePlugin(...args);
        },
      );
      const loadSpy = spyOn(contracts, "loadContract").mockImplementation(
        async (...args) => {
          if (phase === "contract validation") controller.abort(reason);
          return await load(...args);
        },
      );
      try {
        await expect(
          runMultiscan({ ...configured, signal: controller.signal }),
        ).rejects.toBe(reason);
        expect(resolveSpy).toHaveBeenCalledWith(
          pluginPath,
          expect.any(String),
          controller.signal,
        );
        if (phase === "contract validation")
          expect(loadSpy).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({ signal: controller.signal }),
          );
        expect(run).toHaveBeenCalledTimes(1);
        expect(
          await readFile(join(paths.output, "results.jsonl"), "utf8"),
        ).toBe(before);
        expect(
          (await readdir(paths.output)).filter(
            (name) => name === ".lock" || name.startsWith(".resume-plugin-"),
          ),
        ).toEqual([]);
      } finally {
        resolveSpy.mockRestore();
        loadSpy.mockRestore();
      }
    },
  );

  test("does not resolve a validation plugin before a new scan", async () => {
    const { paths } = await repositoryFixture("lazy-validation");
    const run = mock(completeRun);
    const configured = options(paths, client(run), {
      config: { pluginPath: join(paths.root, "unused-plugin.zip") },
    });
    const resolveSpy = spyOn(runtime, "resolvePluginPath");
    try {
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      expect(resolveSpy).not.toHaveBeenCalled();
      expect(run).toHaveBeenCalledTimes(1);
    } finally {
      resolveSpy.mockRestore();
    }
  });

  test.each([
    ["missing", "valid", false],
    ["invalid JSON", "valid", false],
    ["invalid schema", "valid", false],
    ["missing", "malformed", false],
    ["missing", "malformed", true],
    ["invalid JSON", "schema-invalid", false],
    ["invalid JSON", "schema-invalid", true],
    ["invalid schema", "missing", false],
    ["invalid schema", "missing", true],
    ["async", "malformed", false],
  ] as const)(
    "keeps completed artifacts when the plugin schema is %s and output is %s with recovery=%p",
    async (problem, output, recovery) => {
      const { paths } = await repositoryFixture("schema-error");
      const pluginPath = await customPlugin(paths.root, "directory");
      const run = mock(completeRun);
      const createSecurity = mock(() => client(run));
      const configured = options(paths, client(run), {
        config: { pluginPath },
        createSecurity,
      });
      await runMultiscan(configured);
      const ledger = join(paths.output, "results.jsonl");
      const before = await readFile(ledger, "utf8");
      const [receipt] = await results(ledger);
      const scanDir = receipt!["outputDir"] as string;
      if (output === "malformed")
        await writeFile(join(scanDir, "findings.json"), "");
      else if (output === "schema-invalid")
        await writeFile(join(scanDir, "scan-manifest.json"), "{}");
      else if (output === "missing") await rm(join(scanDir, "findings.json"));
      const artifactBytes = async () =>
        Promise.all(
          [
            "scan-manifest.json",
            "findings.json",
            "coverage.json",
            "report.md",
          ].map(async (name) =>
            readFile(join(scanDir, name)).catch(
              (error: NodeJS.ErrnoException) => {
                if (error.code === "ENOENT") return null;
                throw error;
              },
            ),
          ),
        );
      const savedArtifacts = await artifactBytes();
      const schema = join(pluginPath, "schemas", "coverage.schema.json");
      if (problem === "missing") await rm(schema);
      else
        await writeFile(
          schema,
          problem === "invalid JSON"
            ? "{"
            : problem === "async"
              ? '{"$async":true,"type":"object"}'
              : '{"type":"not-a-schema-type"}',
        );
      const recoverScan = mock(async () => undefined);
      const resumed = runMultiscan({
        ...configured,
        ...(recovery ? { recoverScan } : {}),
      });
      await expect(resumed).rejects.toBeInstanceOf(
        contracts.ContractSchemaError,
      );
      await expect(resumed).rejects.toThrow("coverage.schema.json");
      expect(createSecurity).toHaveBeenCalledTimes(1);
      expect(run).toHaveBeenCalledTimes(1);
      expect(recoverScan).not.toHaveBeenCalled();
      expect(await readFile(ledger, "utf8")).toBe(before);
      expect(await artifactBytes()).toEqual(savedArtifacts);
      expect(
        await readdir(join(paths.output, "artifacts", "schema-error")),
      ).toEqual(["attempt-1"]);
      expect(
        (await readdir(paths.output)).filter(
          (name) => name === ".lock" || name.startsWith(".resume-plugin-"),
        ),
      ).toEqual([]);
    },
  );

  test.each([
    ["missing", false],
    ["unsealed", false],
    ["failed", false],
    ["unsealed", true],
  ] as const)(
    "recovery handles rejected %s output with a newer attempt=%p",
    async (integrity, newerAttempt) => {
      const { paths } = await repositoryFixture("invalid-recovery");
      const run = mock(completeRun);
      const configured = options(paths, client(run), { maxAttempts: 3 });
      await runMultiscan(configured);
      const [receipt] = await results(join(paths.output, "results.jsonl"));
      const scanDir = receipt!["outputDir"] as string;
      const coveragePath = join(scanDir, "coverage.json");
      if (integrity === "missing") await rm(join(scanDir, "findings.json"));
      else if (integrity === "unsealed") await appendFile(coveragePath, "\n");
      else {
        const manifestPath = join(scanDir, "scan-manifest.json");
        const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
        manifest.scan.status = "failed";
        await writeFile(manifestPath, JSON.stringify(manifest));
      }
      const before = await readFile(coveragePath, "utf8");
      const checkout = join(paths.output, "checkouts", "invalid-recovery");
      await mkdir(checkout, { recursive: true, mode: 0o700 });
      await writeFile(join(checkout, "retained.txt"), "Original checkout.");
      const nextOutput = join(
        paths.output,
        "artifacts",
        "invalid-recovery",
        "attempt-2",
      );
      if (newerAttempt) await completedScan(nextOutput);
      const recoverScan = mock(async (path: string) => ({
        ...(await loadContract(path, { pluginRoot: PLUGIN_ROOT })),
        cost: null,
      }));
      const summary = await runMultiscan({ ...configured, recoverScan });
      expect(summary).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
      expect(recoverScan).toHaveBeenCalledTimes(newerAttempt ? 1 : 0);
      if (newerAttempt)
        expect(recoverScan).toHaveBeenCalledWith(
          nextOutput,
          expect.any(Object),
        );
      expect(run).toHaveBeenCalledTimes(newerAttempt ? 1 : 2);
      expect(await readFile(coveragePath, "utf8")).toBe(before);
      if (integrity === "missing")
        await expect(
          lstat(join(scanDir, "findings.json")),
        ).rejects.toMatchObject({
          code: "ENOENT",
        });
      expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
        "Original checkout.",
      );
      expect((await results(summary.resultsPath)).at(-1)).toMatchObject({
        status: "completed",
        attempt: 2,
      });
    },
  );

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
    const oldReport = join(
      paths.output,
      "artifacts",
      "repo",
      "attempt-1",
      "report.md",
    );
    await rm(oldReport);
    expect(await runMultiscan(configured)).toMatchObject({ failed: 1 });
    await writeFile(oldReport, "{}\n");
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
      ).toBe("{}\n");
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
        [field]:
          field === "pluginPath"
            ? await customPlugin(paths.root, "directory")
            : join(paths.root, "selected-runtime"),
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
      const security = client(async (_repository, scanOptions = {}) => {
        calls++;
        return completedScan(scanOptions.outputDir!);
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

  test("accepts legacy coverage notes and still finishes other repositories", async () => {
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
      completed: 2,
      failed: 0,
    });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "incomplete",
        status: "completed",
        attempt: 1,
      },
      { id: "complete", status: "completed", attempt: 1 },
    ]);
  });
});

test.each([
  ["sha1", "sha1"],
  ["sha1", "sha256"],
  ["sha256", "sha1"],
  ["sha256", "sha256"],
])(
  "bulk checkout preserves %s object format with a %s default",
  async (objectFormat, defaultFormat) => {
    if (
      runTestInSubprocess(
        fileURLToPath(import.meta.url),
        `bulk checkout preserves ${objectFormat} object format with a ${defaultFormat} default`,
      )
    )
      return;
    const paths = await fixture();
    const repo = await repository(paths.root, "source", objectFormat);
    await writeFile(
      paths.input,
      `id,repository,revision\nfixture,${repo.path},${repo.revision}\n`,
    );
    const run = mock(async (checkout: string, scanOptions = {}) => {
      expect(process.env["GIT_DEFAULT_HASH"]).toBe(defaultFormat);
      expect(git(checkout, "rev-parse", "--show-object-format")).toBe(
        objectFormat,
      );
      expect(git(checkout, "rev-parse", "HEAD")).toBe(repo.revision);
      return completeRun(checkout, scanOptions);
    });
    const previous = process.env["GIT_DEFAULT_HASH"];
    process.env["GIT_DEFAULT_HASH"] = defaultFormat;
    try {
      const result = await runMultiscan(options(paths, client(run)));
      expect(result.failed).toBe(0);
      expect(run).toHaveBeenCalledTimes(1);
      expect(process.env["GIT_DEFAULT_HASH"]).toBe(defaultFormat);
    } finally {
      if (previous === undefined) delete process.env["GIT_DEFAULT_HASH"];
      else process.env["GIT_DEFAULT_HASH"] = previous;
    }
  },
);

testPosix(
  "bulk SHA-1 checkout works without Git object-format options",
  async () => {
    if (
      runTestInSubprocess(
        fileURLToPath(import.meta.url),
        "bulk SHA-1 checkout works without Git object-format options",
      )
    )
      return;
    const paths = await fixture();
    const source = await repository(paths.root, "source");
    await writeFile(
      paths.input,
      `id,repository,revision\nfixture,${source.path},${source.revision}\n`,
    );
    const command = await resolveTrustedExecutable(
      "git",
      process.env,
      process.cwd(),
    );
    expect(command).not.toBeNull();
    const bin = await temporaryDirectory();
    await writeFile(
      join(bin, "git"),
      `#!/bin/sh
for argument do
  case "$argument" in
    --object-format=*) echo 'error: unknown option object-format' >&2; exit 129 ;;
  esac
done
exec '${command!.executable.replaceAll("'", "'\\''")}' "$@"
`,
      { mode: 0o700 },
    );
    const previousPath = process.env["PATH"];
    process.env["PATH"] = `${bin}:${previousPath ?? ""}`;
    try {
      const run = mock(async (checkout: string, scanOptions = {}) => {
        expect(git(checkout, "rev-parse", "HEAD")).toBe(source.revision);
        return completeRun(checkout, scanOptions);
      });
      const result = await runMultiscan(options(paths, client(run)));
      expect(result.failed).toBe(0);
      expect(run).toHaveBeenCalledTimes(1);
    } finally {
      if (previousPath === undefined) delete process.env["PATH"];
      else process.env["PATH"] = previousPath;
    }
  },
);
