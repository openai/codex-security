import { createCliTest, captureCli } from "./support/cli-run.js";
import { resolving } from "./support/promises.js";
import {
  access,
  appendFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contracts from "../src/contract.js";
import { writeThreatModel } from "../src/artifact-export.js";
import { PYTHON } from "./support/security-policy.js";
import { runMultiscan } from "../src/multiscan.js";
import { prepareOutputDir } from "../src/runtime.js";
import * as runtime from "../src/runtime.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { rejecting, throwing } from "./support/errors.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  type SecurityClient,
  type MultiscanOptions,
  createMultiscanFixtures,
  git,
  repository,
  completedScan,
  reseal,
  customPlugin,
  completeRun,
  client,
  options,
  results,
} from "./support/multiscan.js";

const { fixture, repositoryFixture, cleanup } = createMultiscanFixtures();

afterEach(cleanup);

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

  test("starts a fresh attempt when a damaged completed receipt points to invalid sealed artifacts", async () => {
    const { paths } = await repositoryFixture("damaged-completion");
    const run = mock(completeRun);
    const configured = options(paths, client(run));
    const initial = await runMultiscan(configured);
    const [receipt] = await results(initial.resultsPath);
    const scanDir = receipt!["outputDir"] as string;
    await appendFile(join(scanDir, "findings.json"), "\n");
    const damagedArtifact = await readFile(join(scanDir, "findings.json"));
    await writeFile(
      initial.resultsPath,
      `${JSON.stringify({ ...receipt, warnings: {} })}\n`,
    );
    const recoverScan = mock(async () => {
      throw new Error("Invalid completed artifacts must not be resumed");
    });
    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 0,
    });
    expect(run).toHaveBeenCalledTimes(2);
    expect(recoverScan).not.toHaveBeenCalled();
    expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
      attempt: 2,
      status: "completed",
    });
    expect(await readFile(join(scanDir, "findings.json"))).toEqual(
      damagedArtifact,
    );
    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(run).toHaveBeenCalledTimes(2);
    expect(recoverScan).not.toHaveBeenCalled();
  });

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
    const runs = mock(completeRun);
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
      const runs = mock(completeRun);
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
            review: recovered.review,
            mode: recovered.mode,
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
  test.each([
    ["malformed JSON", "{broken}"],
    ["null", "null"],
    ["array", "[]"],
    ["missing ID", "{}"],
    ["non-string ID", { id: 42 }],
    ["invalid attempt", { attempt: 0 }],
    ["invalid status", { status: "running" }],
    ["invalid output path", { outputDir: 42 }],
    ["invalid warnings", { warnings: {} }],
  ])(
    "requires explicit recovery for a committed receipt with %s",
    async (_name, corruption) => {
      const { paths } = await repositoryFixture("damaged-receipt");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      const initial = await runMultiscan(configured);
      const original = await readFile(initial.resultsPath);
      const [receipt] = await results(initial.resultsPath);
      const bad =
        typeof corruption === "string"
          ? corruption
          : JSON.stringify({ ...receipt, ...corruption });
      const damaged = Buffer.concat([
        original,
        Buffer.from(`${bad}\n{"unfinished":"`),
        Buffer.from([0xc3]),
      ]);
      await writeFile(initial.resultsPath, damaged);
      await expect(runMultiscan(configured)).rejects.toThrow(
        "results.jsonl:2: invalid campaign receipt:",
      );
      await expect(runMultiscan(configured)).rejects.toThrow("--recover");
      expect(await readFile(initial.resultsPath)).toEqual(damaged);
      expect(run).toHaveBeenCalledTimes(1);

      const recoverScan = mock(async () => undefined);
      const identifiable =
        typeof corruption !== "string" &&
        !["non-string ID", "invalid attempt"].includes(_name);
      if (!identifiable) {
        await expect(
          runMultiscan({ ...configured, recoverScan }),
        ).rejects.toThrow("Repair the ledger manually");
        expect(await readFile(initial.resultsPath)).toEqual(damaged);
        expect(run).toHaveBeenCalledTimes(1);
        expect(recoverScan).not.toHaveBeenCalled();
        const backups = (await readdir(paths.output)).filter((name) =>
          name.startsWith("results.corrupt-"),
        );
        expect(backups).toHaveLength(1);
        expect(await readFile(join(paths.output, backups[0]!))).toEqual(
          damaged,
        );
        return;
      }
      const recovered = await runMultiscan({ ...configured, recoverScan });
      expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
      expect(run).toHaveBeenCalledTimes(1);
      expect(recoverScan).not.toHaveBeenCalled();
      expect(await readFile(initial.resultsPath)).toEqual(original);
      const backups = (await readdir(paths.output)).filter((name) =>
        name.startsWith("results.corrupt-"),
      );
      expect(backups).toHaveLength(1);
      expect(await readFile(join(paths.output, backups[0]!))).toEqual(damaged);
      expect(
        (await readdir(paths.output)).filter((name) =>
          name.startsWith(".results.repair-"),
        ),
      ).toEqual([]);
    },
  );

  test.each([
    ["invalid output path", { outputDir: 42 }],
    ["invalid warnings", { warnings: {} }],
    ["invalid JSON", undefined],
  ] as const)(
    "refuses repair when discarded checkout-failure history has no saved attempt (%s)",
    async (_name, corruption) => {
      const paths = await fixture();
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${join(paths.root, "absent-repository")},${"a".repeat(40)}\n`,
      );
      const run = mock(rejecting("Unexpected model scan"));
      const configured = options(paths, client(run), { maxAttempts: 1 });
      const initial = await runMultiscan(configured);
      expect(initial).toMatchObject({ failed: 1, skipped: 0 });
      const artifactRoot = join(paths.output, "artifacts", "repo");
      expect(await readdir(artifactRoot)).toEqual([]);
      const [receipt] = await results(initial.resultsPath);
      const damaged = Buffer.from(
        corruption === undefined
          ? "{broken}\n"
          : `${JSON.stringify({ ...receipt, ...corruption })}\n`,
      );
      await writeFile(initial.resultsPath, damaged);
      await expect(runMultiscan(configured)).rejects.toThrow(
        "invalid campaign receipt",
      );
      expect(await readFile(initial.resultsPath)).toEqual(damaged);
      const recoverScan = mock(async () => undefined);
      for (let repeat = 0; repeat < 2; repeat++) {
        await expect(
          runMultiscan({ ...configured, recoverScan }),
        ).rejects.toThrow("Repair the ledger manually");
        expect(await readFile(initial.resultsPath)).toEqual(damaged);
        expect(await readdir(artifactRoot)).toEqual([]);
      }
      expect(run).not.toHaveBeenCalled();
      expect(recoverScan).not.toHaveBeenCalled();
      const names = await readdir(paths.output);
      const backups = names.filter((name) =>
        name.startsWith("results.corrupt-"),
      );
      expect(backups).toHaveLength(2);
      for (const backup of backups)
        expect(await readFile(join(paths.output, backup))).toEqual(damaged);
      expect(
        names.filter(
          (name) => name === ".lock" || name.startsWith(".results.repair-"),
        ),
      ).toEqual([]);
    },
  );

  test.each([
    "warnings",
    "missing attempt",
    "string attempt",
    "malformed JSON",
  ] as const)(
    "refuses repair when a damaged newer attempt would expose an older completion (%s)",
    async (corruption) => {
      const { paths } = await repositoryFixture("unresolved-newer-attempt");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      const initial = await runMultiscan(configured);
      const original = await readFile(initial.resultsPath);
      const [receipt] = await results(initial.resultsPath);
      const scanDir = receipt!["outputDir"] as string;
      const report = await readFile(join(scanDir, "report.md"));
      const newer: Record<string, unknown> = {
        ...receipt,
        attempt: 2,
        status: "failed",
        outputDir: join(
          paths.output,
          "artifacts",
          "unresolved-newer-attempt",
          "attempt-2",
        ),
        error: "Synthetic checkout failure",
      };
      if (corruption === "warnings") newer["warnings"] = {};
      if (corruption === "missing attempt") delete newer["attempt"];
      if (corruption === "string attempt") newer["attempt"] = "2";
      const damaged = Buffer.concat([
        original,
        Buffer.from(
          `${corruption === "malformed JSON" ? "{broken}" : JSON.stringify(newer)}\n`,
        ),
      ]);
      await writeFile(initial.resultsPath, damaged);
      const recoverScan = mock(async () => undefined);
      for (let repeat = 0; repeat < 2; repeat++) {
        await expect(
          runMultiscan({ ...configured, recoverScan }),
        ).rejects.toThrow("unresolved attempted history");
        expect(await readFile(initial.resultsPath)).toEqual(damaged);
        expect(await readFile(join(scanDir, "report.md"))).toEqual(report);
      }
      expect(run).toHaveBeenCalledTimes(1);
      expect(recoverScan).not.toHaveBeenCalled();
    },
  );

  test("keeps unidentified history unresolved even when older scan artifacts remain on disk", async () => {
    const { paths } = await repositoryFixture(
      "recoverable-unidentified-history",
    );
    const saved = fakeResult();
    const run = mock<SecurityClient["run"]>(async (_repository, scan = {}) => {
      await completedScan(scan.outputDir!);
      return saved;
    });
    const configured = options(paths, client(run));
    const initial = await runMultiscan(configured);
    const [receipt] = await results(initial.resultsPath);
    const scanDir = receipt!["outputDir"] as string;
    const report = await readFile(join(scanDir, "report.md"));
    const damaged = Buffer.from("{broken}\n");
    await writeFile(initial.resultsPath, damaged);
    const recoverScan = mock(async (path: string) => {
      expect(path).toBe(scanDir);
      return saved;
    });
    await expect(runMultiscan({ ...configured, recoverScan })).rejects.toThrow(
      "Repair the ledger manually",
    );
    expect(await readFile(initial.resultsPath)).toEqual(damaged);
    expect(recoverScan).not.toHaveBeenCalled();
    expect(run).toHaveBeenCalledTimes(1);
    expect(await readFile(join(scanDir, "report.md"))).toEqual(report);
    const backups = (await readdir(paths.output)).filter((name) =>
      name.startsWith("results.corrupt-"),
    );
    expect(backups).toHaveLength(1);
    expect(await readFile(join(paths.output, backups[0]!))).toEqual(damaged);
  });

  test.each([false, true])(
    "recovery finds newer attempts beside unaffected completions with ledger repair=%p",
    async (repair) => {
      const paths = await fixture();
      const source = await repository(paths.root, "damaged-history");
      await writeFile(
        paths.input,
        `id,repository,revision\nnewer,${source.path},${source.revision}\nuntouched,${source.path},${source.revision}\n`,
      );
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      const initial = await runMultiscan(configured);
      const original = await readFile(initial.resultsPath);
      const oldReceipts = await results(initial.resultsPath);
      const untouched = oldReceipts.find(
        (receipt) => receipt["id"] === "untouched",
      )!;
      const oldReport = join(
        paths.output,
        "artifacts",
        "newer",
        "attempt-1",
        "report.md",
      );
      const oldReportBytes = await readFile(oldReport);
      const newerPath = join(paths.output, "artifacts", "newer", "attempt-2");
      const saved = await completedScan(newerPath);
      const damaged = repair
        ? Buffer.concat([
            original,
            Buffer.from(
              `${JSON.stringify({ ...oldReceipts.find((receipt) => receipt["id"] === "newer"), attempt: 2, outputDir: newerPath, warnings: {} })}\n`,
            ),
          ])
        : original;
      await writeFile(initial.resultsPath, damaged);
      if (!repair) {
        expect(await runMultiscan(configured)).toMatchObject({
          completed: 2,
          skipped: 2,
          failed: 0,
        });
        expect(await readFile(initial.resultsPath)).toEqual(original);
      }
      const recoverScan = mock(async (path: string) => {
        expect(path).toBe(newerPath);
        return saved;
      });
      const result = await runMultiscan({ ...configured, recoverScan });
      expect(result).toMatchObject({ completed: 2, skipped: 1, failed: 0 });
      expect(run).toHaveBeenCalledTimes(2);
      expect(recoverScan).toHaveBeenCalledTimes(1);
      const receipts = await results(result.resultsPath);
      expect(
        receipts.filter((receipt) => receipt["id"] === "untouched"),
      ).toEqual([untouched]);
      expect(receipts.at(-1)).toMatchObject({
        id: "newer",
        attempt: 2,
        status: "completed",
      });
      expect(
        (await readFile(result.resultsPath)).subarray(0, original.length),
      ).toEqual(original);
      expect(await readFile(oldReport)).toEqual(oldReportBytes);
    },
  );

  test.each(["resume", "fresh", "missing scan", "mixed saved scan"] as const)(
    "receipt repair distinguishes discarded extraction attempts from scan work (%s)",
    async (scenario) => {
      const { paths, source } = await repositoryFixture(
        "mixed-attempt-history",
      );
      const knowledgePath = join(paths.root, "context.md");
      const knowledge = "Synthetic knowledge for recovery.\n";
      await writeFile(knowledgePath, knowledge);
      let runCalls = 0;
      const saved = fakeResult();
      const run = mock<SecurityClient["run"]>(
        async (_repository, scan = {}) => {
          runCalls++;
          if (
            runCalls === 1 ||
            (scenario === "mixed saved scan" && runCalls === 2)
          ) {
            await mkdir(scan.outputDir!, { recursive: true, mode: 0o700 });
            await writeFile(
              join(scan.outputDir!, "checkpoint"),
              "Synthetic interrupted scan.\n",
            );
            throw new Error("Synthetic interrupted scan");
          }
          expect(scan.outputDir).toBe(
            join(
              paths.output,
              "artifacts",
              "mixed-attempt-history",
              "attempt-4",
            ),
          );
          await completedScan(scan.outputDir!);
          return saved;
        },
      );
      const configured = options(paths, client(run), {
        maxAttempts: 1,
        knowledgeBasePaths: [knowledgePath],
      });
      const initial = await runMultiscan(configured);
      expect(initial.failed).toBe(1);
      if (scenario === "missing scan") {
        const movedSource = join(paths.root, "temporarily-moved-source");
        await rename(source.path, movedSource);
        expect((await runMultiscan(configured)).failed).toBe(1);
        await rename(movedSource, source.path);
      } else if (scenario === "mixed saved scan") {
        expect((await runMultiscan(configured)).failed).toBe(1);
      } else {
        await rm(knowledgePath);
        expect((await runMultiscan(configured)).failed).toBe(1);
      }
      await rm(knowledgePath, { force: true });
      expect((await runMultiscan(configured)).failed).toBe(1);
      if (scenario === "missing scan" || scenario === "mixed saved scan")
        expect((await runMultiscan(configured)).failed).toBe(1);
      const lines = (await readFile(initial.resultsPath, "utf8"))
        .trimEnd()
        .split("\n");
      const rows = lines.map(
        (line) => JSON.parse(line) as Record<string, unknown>,
      );
      expect(
        rows.map((row) => ({
          attempt: row["attempt"],
          knowledge: row["knowledgeBaseFailure"] === true,
        })),
      ).toEqual([
        { attempt: 1, knowledge: false },
        {
          attempt: 2,
          knowledge: scenario === "resume" || scenario === "fresh",
        },
        { attempt: 3, knowledge: true },
        ...(scenario === "missing scan" || scenario === "mixed saved scan"
          ? [{ attempt: 4, knowledge: true }]
          : []),
      ]);
      const artifactRoot = join(
        paths.output,
        "artifacts",
        "mixed-attempt-history",
      );
      expect((await readdir(artifactRoot)).sort()).toEqual(
        scenario === "mixed saved scan"
          ? ["attempt-1", "attempt-2"]
          : ["attempt-1"],
      );
      const scanDir = join(
        artifactRoot,
        scenario === "mixed saved scan" ? "attempt-2" : "attempt-1",
      );
      const checkpoint = await readFile(join(scanDir, "checkpoint"));
      const rejected =
        scenario === "missing scan" || scenario === "mixed saved scan"
          ? [1, 2]
          : [1];
      for (const index of rejected)
        rows[index]!["warnings"] = "Synthetic malformed warnings";
      const damaged = Buffer.from(
        rows.map((row) => JSON.stringify(row)).join("\n") + "\n",
      );
      await writeFile(initial.resultsPath, damaged);
      await writeFile(knowledgePath, knowledge);
      const recoverScan = mock(async (path: string) => {
        expect(path).toBe(scanDir);
        if (scenario === "fresh") return undefined;
        await completedScan(path);
        return saved;
      });
      if (scenario === "missing scan") {
        for (let repeat = 0; repeat < 2; repeat++) {
          await expect(
            runMultiscan({ ...configured, recoverScan }),
          ).rejects.toThrow("unresolved attempted history");
          expect(await readFile(initial.resultsPath)).toEqual(damaged);
        }
        expect(recoverScan).not.toHaveBeenCalled();
        expect(run).toHaveBeenCalledTimes(1);
      } else {
        expect(
          await runMultiscan({ ...configured, recoverScan }),
        ).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
        expect(recoverScan).toHaveBeenCalledTimes(1);
        expect(run).toHaveBeenCalledTimes(
          scenario === "fresh" || scenario === "mixed saved scan" ? 2 : 1,
        );
        const retained = Buffer.from(
          lines.filter((_line, index) => !rejected.includes(index)).join("\n") +
            "\n",
        );
        expect(
          (await readFile(initial.resultsPath)).subarray(0, retained.length),
        ).toEqual(retained);
        expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
          attempt:
            scenario === "fresh" ? 4 : scenario === "mixed saved scan" ? 2 : 1,
          status: "completed",
        });
        expect(
          await runMultiscan({ ...configured, recoverScan }),
        ).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
        expect(recoverScan).toHaveBeenCalledTimes(1);
      }
      expect(await readFile(join(scanDir, "checkpoint"))).toEqual(checkpoint);
      const backups = (await readdir(paths.output)).filter((name) =>
        name.startsWith("results.corrupt-"),
      );
      expect(backups).toHaveLength(scenario === "missing scan" ? 2 : 1);
      for (const backup of backups)
        expect(await readFile(join(paths.output, backup))).toEqual(damaged);
    },
  );

  test("receipt repair leaves knowledge-only history unchanged beside unidentified corruption", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "knowledge-retry-source");
    const knowledgePath = join(paths.root, "knowledge.md");
    await writeFile(
      paths.input,
      `id,repository,revision,mode\nscan,${source.path},${source.revision},standard\nknowledge,${source.path},${source.revision},deep\n`,
    );
    const saved = fakeResult();
    const run = mock<SecurityClient["run"]>(async (_repository, scan = {}) => {
      await completedScan(scan.outputDir!);
      return saved;
    });
    const configured = options(paths, client(run), {
      maxAttempts: 1,
      scanOptionsByMode: { deep: { knowledgeBasePaths: [knowledgePath] } },
    });
    const initial = await runMultiscan(configured);
    expect(initial).toMatchObject({ completed: 1, failed: 1 });
    const lines = (await readFile(initial.resultsPath, "utf8"))
      .trimEnd()
      .split("\n");
    const retainedLine = lines.find(
      (line) => JSON.parse(line).id === "knowledge",
    )!;
    expect(JSON.parse(retainedLine)).toMatchObject({
      attempt: 1,
      knowledgeBaseFailure: true,
      status: "failed",
    });
    expect(await readdir(join(paths.output, "artifacts", "knowledge"))).toEqual(
      [],
    );
    const scanDir = join(paths.output, "artifacts", "scan", "attempt-1");
    const report = await readFile(join(scanDir, "report.md"));
    await writeFile(knowledgePath, "Synthetic restored knowledge.\n");
    const retained = Buffer.from(`${retainedLine}\n`);
    const damaged = Buffer.concat([Buffer.from("{broken}\n"), retained]);
    await writeFile(initial.resultsPath, damaged);
    const recoverScan = mock(async (path: string) => {
      expect(path).toBe(scanDir);
      return saved;
    });
    await expect(runMultiscan({ ...configured, recoverScan })).rejects.toThrow(
      "Repair the ledger manually",
    );
    expect(run).toHaveBeenCalledTimes(1);
    expect(recoverScan).not.toHaveBeenCalled();
    expect(await readFile(initial.resultsPath)).toEqual(damaged);
    expect(await readFile(join(scanDir, "report.md"))).toEqual(report);
    const backups = (await readdir(paths.output)).filter((name) =>
      name.startsWith("results.corrupt-"),
    );
    expect(backups).toHaveLength(1);
    expect(await readFile(join(paths.output, backups[0]!))).toEqual(damaged);
  });

  test("receipt repair retains legacy coverage notes and knowledge-failure history", async () => {
    const { paths } = await repositoryFixture("retained-history");
    const run = mock<SecurityClient["run"]>(async (_repository, scan = {}) => {
      scan.onWarning?.("Synthetic warning with token=unchanged.");
      return await completedScan(scan.outputDir!, "partial");
    });
    const configured = options(paths, client(run));
    const initial = await runMultiscan(configured);
    const original = await readFile(initial.resultsPath);
    const [receipt] = await results(initial.resultsPath);
    const knowledgeFailure = `${JSON.stringify({ ...receipt, status: "failed", attempt: 2, knowledgeBaseFailure: true, error: "Synthetic knowledge failure", extra: { retained: true } })}\n`;
    const retained = Buffer.concat([original, Buffer.from(knowledgeFailure)]);
    await writeFile(
      initial.resultsPath,
      Buffer.concat([
        retained,
        Buffer.from(`${JSON.stringify({ ...receipt, warnings: {} })}\n`),
      ]),
    );
    const recoverScan = mock(async () => undefined);
    const result = await runMultiscan({ ...configured, recoverScan });
    expect(result).toMatchObject({ completed: 1, skipped: 1, failed: 0 });
    expect(result.warnings).toEqual([
      {
        repository: "retained-history",
        warnings: ["Synthetic warning with token=unchanged."],
      },
    ]);
    expect(await readFile(result.resultsPath)).toEqual(retained);
    expect(run).toHaveBeenCalledTimes(1);
    expect(recoverScan).not.toHaveBeenCalled();
  });

  test.each(["publication failure", "cancellation"] as const)(
    "receipt repair preserves original evidence after %s",
    async (problem) => {
      const { paths } = await repositoryFixture("repair-failure");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      const initial = await runMultiscan(configured);
      const [receipt] = await results(initial.resultsPath);
      const original = Buffer.concat([
        await readFile(initial.resultsPath),
        Buffer.from(`${JSON.stringify({ ...receipt, warnings: {} })}\n`),
      ]);
      await writeFile(initial.resultsPath, original);
      const controller = new AbortController();
      const failure = new Error(`Synthetic repair ${problem}`);
      const originalRename = filesystem.rename;
      const originalOpen = filesystem.open;
      const renameSpy = spyOn(filesystem, "rename").mockImplementation(
        async (from, to) => {
          if (
            problem === "publication failure" &&
            String(from).includes(".results.repair-")
          )
            throw failure;
          return await originalRename(from, to);
        },
      );
      const openSpy = spyOn(filesystem, "open").mockImplementation(
        async (...args) => {
          const file = await originalOpen(...args);
          if (
            problem === "cancellation" &&
            String(args[0]).includes(".results.repair-")
          )
            controller.abort(failure);
          return file;
        },
      );
      try {
        await expect(
          runMultiscan({
            ...configured,
            recoverScan: async () => undefined,
            signal: controller.signal,
          }),
        ).rejects.toBe(failure);
        expect(await readFile(initial.resultsPath)).toEqual(original);
        expect(run).toHaveBeenCalledTimes(1);
        const names = await readdir(paths.output);
        const backups = names.filter((name) =>
          name.startsWith("results.corrupt-"),
        );
        expect(backups).toHaveLength(1);
        expect(await readFile(join(paths.output, backups[0]!))).toEqual(
          original,
        );
        expect(
          names.filter(
            (name) => name === ".lock" || name.startsWith(".results.repair-"),
          ),
        ).toEqual([]);
      } finally {
        renameSpy.mockRestore();
        openSpy.mockRestore();
      }
    },
  );

  test("repairs malformed receipt policy state without losing the requested severity outcome", async () => {
    const { paths } = await repositoryFixture("receipt-policy");
    const saved = fakeResult(["high"]);
    const run = mock<SecurityClient["run"]>(async (_repository, scan = {}) => {
      await completedScan(scan.outputDir!);
      return saved;
    });
    const configured = options(paths, client(run), {
      scanOptionsByMode: { standard: { failureSeverity: "high" } },
    });
    const initial = await runMultiscan(configured);
    expect(initial.policyFailed).toBe(true);
    const [receipt] = await results(initial.resultsPath);
    const scanDir = receipt!["outputDir"] as string;
    const report = await readFile(join(scanDir, "report.md"));
    const recoverScan = mock(async (path: string) => {
      expect(path).toBe(scanDir);
      return saved;
    });

    const { policyFailed: _policy, ...legacy } = receipt!;
    await writeFile(initial.resultsPath, `${JSON.stringify(legacy)}\n`);
    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      skipped: 1,
      policyFailed: false,
    });
    expect(recoverScan).not.toHaveBeenCalled();

    const damaged = Buffer.from(
      `${JSON.stringify({ ...receipt, policyFailed: "true" })}\n`,
    );
    await writeFile(initial.resultsPath, damaged);
    await expect(runMultiscan(configured)).rejects.toThrow(
      "invalid campaign receipt",
    );
    expect(await readFile(initial.resultsPath)).toEqual(damaged);
    expect(run).toHaveBeenCalledTimes(1);

    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      skipped: 0,
      failed: 0,
      policyFailed: true,
    });
    expect(recoverScan).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledTimes(1);
    expect(await readFile(join(scanDir, "report.md"))).toEqual(report);
    const backups = (await readdir(paths.output)).filter((name) =>
      name.startsWith("results.corrupt-"),
    );
    expect(backups).toHaveLength(1);
    expect(await readFile(join(paths.output, backups[0]!))).toEqual(damaged);
    expect((await results(initial.resultsPath)).at(-1)?.["policyFailed"]).toBe(
      true,
    );
    expect(await runMultiscan(configured)).toMatchObject({
      completed: 1,
      skipped: 1,
      policyFailed: true,
    });
  });
});
