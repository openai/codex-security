import { Database } from "bun:sqlite";
import type { CoverageDocument } from "../src/models.js";
import { createCliTest, captureCli } from "./support/cli-run.js";
import { resolving } from "./support/promises.js";
import {
  access,
  appendFile,
  cp,
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
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { zipSync } from "fflate";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contract from "../src/contract.js";
import * as artifactExport from "../src/artifact-export.js";
import { PYTHON } from "./support/security-policy.js";
import type { ScanResult } from "../src/result.js";
import { runMultiscan } from "../src/multiscan.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { prepareOutputDir } from "../src/runtime.js";
import * as runtime from "../src/runtime.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { rejecting, throwing } from "./support/errors.js";

import {
  type MultiscanOptions,
  type SecurityClient,
  createMultiscanFixtures,
  git,
  repository,
  customPlugin,
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
  recordFixtureRequest,
  recordFixtureAuthority,
  fixtureRequests,
} = createMultiscanFixtures();

const testPosix = process.platform === "win32" ? test.skip : test;
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
              await artifactExport.writeThreatModel(directory, {
                pythonPath: PYTHON,
              });
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
      expect(receipts[0]!["checkoutOccupied"]).toBeUndefined();
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

  test.each([
    ["malformed middle record", "{", true],
    ["malformed final record", "{", false],
    ["non-object", "null", false],
    ["missing ID", "{}", false],
    ["non-string ID", '{"id":42}', false],
    ["missing attempt", '{"id":"receipt"}', false],
    ["string attempt", '{"id":"receipt","attempt":"1"}', false],
    ["zero attempt", '{"id":"receipt","attempt":0}', false],
    ["fractional attempt", '{"id":"receipt","attempt":1.5}', true],
    ["incomplete task identity", '{"id":"receipt","attempt":1}', true],
    ["non-string operation ID", { operationId: { id: "other" } }, false],
  ] as const)(
    "CLI identifies the %s and preserves committed history",
    async (_name, bad, middle) => {
      const { paths } = await repositoryFixture("receipt");
      const args = [
        "bulk-scan",
        paths.input,
        "--output-dir",
        paths.output,
        "--json",
      ];
      const deps = dependencies();
      const run = mock(completeRun);
      const configured: Parameters<typeof main>[3] = {
        ...deps,
        createSecurity: (config) => ({ ...deps.createSecurity(config), run }),
      };
      expect(await createCliTest(main).runCli(args, configured)).toBe(0);
      const ledger = join(paths.output, "results.jsonl");
      const valid = await readFile(ledger, "utf8");
      const invalid =
        typeof bad === "string"
          ? bad
          : JSON.stringify({ ...JSON.parse(valid), ...bad });
      const damaged = Buffer.concat([
        Buffer.from(`${valid}\n${invalid}\n`),
        ...(middle ? [Buffer.from(valid), Buffer.from([0xe2, 0x82])] : []),
      ]);
      await writeFile(ledger, damaged);
      for (const flags of [[], ["--recover"]]) {
        const cli = createCliTest(main);
        expect(await cli.runCli([...args, ...flags], configured)).toBe(2);
        expect(cli.stderr.text()).toContain(`${ledger}:3:`);
        expect(cli.stderr.text()).toContain("Restore a complete");
        expect(cli.stderr.text()).toContain("new --output-dir");
        expect(await readFile(ledger)).toEqual(damaged);
        expect(
          (await readdir(paths.output)).filter((name) =>
            name.startsWith("results.jsonl.interrupted-"),
          ),
        ).toEqual([]);
      }
      expect(run).toHaveBeenCalledTimes(1);
    },
  );

  test.each([false, true])(
    "reuses a registered request across telemetry changes (legacy digest=%p)",
    async (legacy) => {
      const { paths } = await repositoryFixture("receipt-digest", "repo");
      const run = mock(completeRun);
      const configured = options(paths, client(run));
      const first = await runMultiscan(configured);
      const receipt = (await results(first.resultsPath))[0]!;
      const outputDir = receipt["outputDir"] as string;
      const operationId = receipt["operationId"];
      expect(operationId).toBeString();
      const inputs = { target: "repository", mode: "standard", outputDir };
      const registered = fixtureRequests.get(outputDir)!;
      expect(registered.digest).toBe(
        workflowDigest({ config: {}, options: inputs }),
      );
      if (legacy) {
        registered.digest = workflowDigest({
          config: {},
          options: { ...inputs, telemetryContext: { operationId } },
        });
        await recordFixtureAuthority(outputDir);
      }

      expect(await runMultiscan(configured)).toMatchObject({ skipped: 1 });
      delete receipt["operationId"];
      delete receipt["scanId"];
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        skipped: legacy ? 0 : 1,
      });
      expect(run).toHaveBeenCalledTimes(legacy ? 2 : 1);
      expect((await results(first.resultsPath)).at(-1)!["attempt"]).toBe(
        legacy ? 2 : 1,
      );
    },
  );

  test("a receipt for a different repository reserves its attempt without sharing its operation", async () => {
    const { paths } = await repositoryFixture("receipt-identity", "repo");
    const first = await runMultiscan(options(paths, client(completeRun)));
    const [receipt] = await results(first.resultsPath);
    const foreign = {
      ...receipt,
      repository: "other-repository",
      operationId: "other-operation",
    };
    const prior = `${JSON.stringify(foreign)}\n`;
    await writeFile(first.resultsPath, prior);
    const manifest = join(
      paths.output,
      "artifacts",
      "repo",
      "attempt-1",
      "scan-manifest.json",
    );
    const original = await readFile(manifest);
    const recoverScan = mock(resolving<undefined, [string]>(undefined));
    const recovered = await runMultiscan(
      options(paths, client(completeRun), { recoverScan }),
    );
    expect(recoverScan).not.toHaveBeenCalled();
    expect(recovered).toMatchObject({ completed: 1, skipped: 0 });
    const latest = (await results(recovered.resultsPath)).at(-1);
    expect(latest).toMatchObject({
      id: "repo",
      attempt: 2,
      status: "completed",
    });
    expect(latest?.["operationId"]).toBeString();
    expect(latest?.["operationId"]).not.toBe(foreign.operationId);
    expect((await readFile(first.resultsPath, "utf8")).startsWith(prior)).toBe(
      true,
    );
    expect(await readFile(manifest)).toEqual(original);
  });

  test.each(["rerun", "recover receipt", "recover directory"])(
    "preserves exhausted attempt numbers on %s",
    async (mode) => {
      const { paths } = await repositoryFixture("repo");
      const setup = options(paths, client(rejecting("Initial failure")), {
        maxAttempts: 1,
      });
      const { resultsPath: ledger } = await runMultiscan(setup);
      const root = join(paths.output, "artifacts", "repo");
      const last = join(root, `attempt-${Number.MAX_SAFE_INTEGER}`);
      if (mode === "recover directory") {
        await mkdir(last);
      } else {
        const [receipt] = await results(ledger);
        await writeFile(
          ledger,
          JSON.stringify({
            ...receipt,
            attempt: Number.MAX_SAFE_INTEGER,
            outputDir: last,
          }) + "\n",
        );
      }
      const saved = await readFile(ledger, "utf8");
      const directories = await readdir(root);
      const run = mock(completeRun);
      const configured = options(paths, client(run), {
        ...(mode === "rerun" ? {} : { recoverScan: async () => undefined }),
      });
      await expect(runMultiscan(configured)).rejects.toThrow("attempt numbers");
      expect(run).not.toHaveBeenCalled();
      expect(await readFile(ledger, "utf8")).toBe(saved);
      expect(await readdir(root)).toEqual(directories);
    },
  );

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
      const { paths, source } = await repositoryFixture(
        "utf8-source",
        "complete",
      );
      const task = {
        id: "complete",
        repository: source.path,
        revision: source.revision,
        mode: "standard",
      };
      const outputDir = join(paths.output, "artifacts", task.id, "attempt-1");
      // Complete the producer flow so recovery has private registration and a seal.
      expect(
        await runMultiscan(
          options(
            paths,
            client(async (_repository, settings = {}) => {
              const result = await completedScan(settings.outputDir!);
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
              return result;
            }),
          ),
        ),
      ).toMatchObject({ completed: 1, failed: 0 });
      const artifacts = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ].map((name) => join(outputDir, name));
      const before = await Promise.all(artifacts.map((path) => readFile(path)));
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
    await recordFixtureRequest(
      checkout,
      { outputDir: orphan, mode: "deep" },
      {},
      source.revision,
    );
    await recordFixtureAuthority(orphan);
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
      // The interrupted scan was registered at this checkout before the crash.
      await recordFixtureRequest(
        checkout,
        { outputDir: dir, mode: "standard" },
        { pythonPath: PYTHON },
      );
      await recordFixtureAuthority(dir);
      const recoverScan = mock(async (scanDir: string) => {
        expect(scanDir).toBe(dir);
        if (failure) throw new Error("Resume transport failed");
        return completedScan(scanDir, "complete", checkout);
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
      const initial = await runMultiscan(configured);
      const [receipt] = await results(initial.resultsPath);
      const operationId = receipt?.["operationId"];
      expect(operationId).toBeString();
      const measurement = {
        coverage: "partial" as const,
        cost: null,
        observedAt: "2026-10-01T00:00:00.000Z",
        threadCount: 1,
        missingThreadCount: 1,
        usage: {
          input_tokens: 17,
          cached_input_tokens: 0,
          cache_write_input_tokens: 0,
          output_tokens: 2,
          reasoning_output_tokens: 0,
          total_tokens: 19,
        },
      };
      await mkdir(join(paths.output, "artifacts", "repo", "attempt-1"), {
        recursive: true,
      });
      const result = await runMultiscan({
        ...configured,
        recoverScan: async (scanDir, prompts) => {
          expect(prompts.scanPrompt).toBe("Shared scan instructions.");
          expect(operationId).toBe(prompts.telemetryContext?.operationId);
          prompts.onMeasurement?.(measurement);
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
            manifest: recovered.manifest,
            review: recovered.review,
            mode: recovered.mode,
            cost: recovered.cost,
            usage: measurement.usage,
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
        operationId,
        measurement,
        usage: measurement.usage,
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
      await recordFixtureRequest(
        join(paths.output, "checkouts", "legacy"),
        {
          outputDir,
          mode: "standard",
        },
        {},
        source.revision,
      );
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
        environment: {
          CODEX_SECURITY_STATE_DIR: process.env["CODEX_SECURITY_STATE_DIR"],
          PYTHON,
        },
        result,
        onRun,
      });
      const createSecurity = clientDependencies.createSecurity;
      clientDependencies.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          run: async (repository, scan = {}) => {
            await recordFixtureRequest(repository, scan, config);
            const completed = await completedScan(
              scan.outputDir!,
              completeness,
            );
            result.manifest.scan.id = completed.manifest.scan.id;
            result.manifest.scan.target = completed.manifest.scan.target;
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
        resumedError.text(),
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
    const operationIds: string[] = [];
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
          expect(scanOptions.telemetryContext?.operationId).toBeString();
          operationIds.push(scanOptions.telemetryContext!.operationId);
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
    expect(new Set(operationIds).size).toBe(1);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(summary).not.toHaveProperty("warnings");
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "retry",
        status: "failed",
        attempt: 1,
        operationId: operationIds[0],
        error: failure,
        warnings: ["Warning from the failed attempt."],
      },
      {
        id: "retry",
        status: "completed",
        attempt: 2,
        operationId: operationIds[0],
      },
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

  test("recovers the saved attempt after an ordinary retry stops before starting", async () => {
    const { paths } = await repositoryFixture("blocked-recovery");
    const run = mock(completeRun).mockImplementationOnce(async (...args) => {
      await completeRun(...args);
      throw new Error("Transport stopped after saving the scan.");
    });
    const campaign = options(paths, client(run), { maxAttempts: 1 });
    const { resultsPath } = await runMultiscan(campaign);
    const [saved] = await results(resultsPath);
    const scanDir = saved!["outputDir"] as string;
    await mkdir(join(paths.output, "checkouts", "blocked-recovery"));
    expect(await runMultiscan(campaign)).toMatchObject({ failed: 1 });
    const [original, blocked] = await results(resultsPath);
    expect(original).toMatchObject({ status: "failed", attempt: 1 });
    expect(blocked).toMatchObject({
      status: "failed",
      attempt: 2,
      checkoutOccupied: true,
    });
    await expect(lstat(blocked!["outputDir"] as string)).rejects.toMatchObject({
      code: "ENOENT",
    });

    const recoverScan = mock(async (path: string) => ({
      ...(await loadContract(path, { pluginRoot: PLUGIN_ROOT })),
      cost: null,
    }));
    expect(await runMultiscan({ ...campaign, recoverScan })).toMatchObject({
      completed: 1,
      failed: 0,
    });
    expect(recoverScan).toHaveBeenCalledTimes(1);
    expect(recoverScan).toHaveBeenCalledWith(scanDir, expect.any(Object));
    expect(run).toHaveBeenCalledTimes(1);
    expect((await results(resultsPath)).at(-1)).toMatchObject({
      status: "completed",
      attempt: 1,
      outputDir: scanDir,
    });
  });

  test("an occupied checkout blocks a fresh retry until its owner moves it", async () => {
    const { paths } = await repositoryFixture("occupied-retry");
    const run = mock(completeRun);
    const campaign = options(paths, client(run));
    const { resultsPath } = await runMultiscan(campaign);
    const [original] = await results(resultsPath);
    const findings = join(original!["outputDir"] as string, "findings.json");
    await appendFile(findings, "\n");
    const checkout = join(paths.output, "checkouts", "occupied-retry");
    await mkdir(checkout);
    await writeFile(join(checkout, "retained.txt"), "User edits before retry.");

    const exported = spyOn(
      artifactExport,
      "readThreatModelPath",
    ).mockImplementation(
      throwing("Unexpected helper invocation for a blocked checkout."),
    );
    try {
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 0,
        failed: 1,
      });
      expect(exported).not.toHaveBeenCalled();
    } finally {
      exported.mockRestore();
    }
    expect(run).toHaveBeenCalledTimes(1);
    expect(await results(resultsPath)).toMatchObject([
      original,
      {
        status: "failed",
        attempt: 2,
        error: `Bulk checkout is already occupied: ${checkout}. Inspect and move the retained checkout before retrying.`,
      },
    ]);
    const moved = join(paths.root, "retained-checkout");
    await rename(checkout, moved);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      failed: 0,
    });
    expect(await readFile(join(moved, "retained.txt"), "utf8")).toBe(
      "User edits before retry.",
    );
    expect(run).toHaveBeenCalledTimes(2);
  });

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
      const load = contract.loadContractWithScanDirectory;
      const resolveSpy = spyOn(runtime, "resolvePluginPath").mockImplementation(
        async (...args) => {
          if (phase === "plugin resolution") controller.abort(reason);
          return await resolvePlugin(...args);
        },
      );
      const loadSpy = spyOn(
        contract,
        "loadContractWithScanDirectory",
      ).mockImplementation(async (...args) => {
        if (phase === "contract validation") controller.abort(reason);
        return await load(...args);
      });
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
        contract.ContractSchemaError,
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
      const nextAttempt = newerAttempt ? Number.MAX_SAFE_INTEGER : 2;
      const nextOutput = join(
        paths.output,
        "artifacts",
        "invalid-recovery",
        `attempt-${nextAttempt}`,
      );
      if (newerAttempt) {
        await recordFixtureRequest(
          checkout,
          { outputDir: nextOutput, mode: "standard" },
          configured.config,
        );
        await completedScan(nextOutput);
      }
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
        attempt: nextAttempt,
      });
    },
  );

  test.each([
    ["recorded", false, 2],
    ["orphan", false, 2],
    ["orphan", true, 1],
  ] as const)(
    "recovers %s output with a missing report when the callback writes it=%p (attempt %i)",
    async (history, writesReport, attempt) => {
      const { paths } = await repositoryFixture("missing-report");
      const run = mock(completeRun);
      const campaign = options(paths, client(run));
      const { resultsPath } = await runMultiscan(campaign);
      const [receipt] = await results(resultsPath);
      const report = join(receipt!["outputDir"] as string, "report.md");
      await rm(report);
      if (history === "orphan") await writeFile(resultsPath, "");
      const recoverScan = mock(async (scanDir: string) => {
        if (writesReport) await writeFile(report, "# Recovered report\n");
        return {
          ...(await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT })),
          cost: null,
        };
      });
      const resume = () => runMultiscan({ ...campaign, recoverScan });

      expect(await resume()).toMatchObject({ completed: 1, failed: 0 });
      const receipts = await results(resultsPath);
      const last = receipts.at(-1)!;
      expect(last).toMatchObject({ status: "completed", attempt });
      expect(receipts).toHaveLength(history === "orphan" ? 1 : attempt);
      expect(
        (await lstat(join(last["outputDir"] as string, "report.md"))).isFile(),
      ).toBe(true);
      expect(await resume()).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 1,
      });
      expect(await results(resultsPath)).toEqual(receipts);
      expect(recoverScan).toHaveBeenCalledTimes(1);
      expect(run).toHaveBeenCalledTimes(attempt);
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
      const schemaPath = join(
        pluginRoot,
        "schemas",
        "scan-manifest.schema.json",
      );
      const schema = JSON.parse(await readFile(schemaPath, "utf8")) as {
        properties?: { scan?: { allOf?: unknown } };
      };
      delete schema.properties?.scan?.allOf;
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
      ) as CoverageDocument;
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
    } else if (corruption === "duplicate coverage surface identities") {
      const coveragePath = join(outputDir, "coverage.json");
      const coverage = JSON.parse(
        await readFile(coveragePath, "utf8"),
      ) as CoverageDocument;
      coverage.surfaces.push(structuredClone(coverage.surfaces[0]!));
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
      const checkout = join(paths.output, "checkouts", "symlink-scope");
      await expect(lstat(checkout)).rejects.toMatchObject({ code: "ENOENT" });
      const offline = join(paths.root, "offline-origin");
      await rename(source.path, offline);
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
        skipped: 1,
      });

      await rename(offline, source.path);
      const database = new Database(
        join(paths.root, "state", "workbench.sqlite3"),
      );
      try {
        database.run(
          "UPDATE scans SET recipe_json = json_remove(recipe_json, '$.target') WHERE scan_dir = ?",
          [legacy!["outputDir"] as string],
        );
      } finally {
        database.close();
      }
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
});
