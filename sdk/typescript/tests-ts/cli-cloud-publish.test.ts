import { resolving } from "./support/promises.js";
import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/index.js";
import {
  dependencies,
  FakeSignals,
  SYNTHETIC_CREDENTIALS,
  mustNotInitializeCodex,
} from "./cli-fixtures.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";

import {
  createCliTest,
  captureCli,
  runCapturedCli,
} from "./support/cli-run.js";

const receipt = {
  scanId: "scan-1",
  findingIds: ["finding-1"],
  findingCount: 1,
};

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "cloud-saved-scans-",
  false,
);
afterEach(cleanup);

async function savedScansFixture() {
  const root = await temporaryDirectory();
  const scans = await Promise.all(
    [1, 2, 3].map(async (index) => {
      const scanDir = join(root, `scan ${index}`);
      await mkdir(scanDir);
      return {
        scanId: `${String(index).repeat(8)}-1111-4111-8111-111111111111`,
        scanDir,
        targetSummary: `example/repo-${index}`,
        progress: { status: "complete" },
        findingCount: index,
      };
    }),
  );
  const workbenchCalls: string[][] = [];
  const deps = dependencies({
    onWorkbench: (args): JsonObject => {
      workbenchCalls.push([...args]);
      if (args[0] === "list-scans") return { scans };
      expect(args.slice(0, 2)).toEqual(["get-scan", "--scan-id"]);
      const scan = scans.find(({ scanId }) => scanId.startsWith(args[2]!));
      if (!scan) throw new Error("Codex Security scan not found.");
      return { scan };
    },
  });
  return { scans, deps, workbenchCalls };
}

describe("publish scan to Cloud", () => {
  test("documents the findings CSV option", async () => {
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(["publish", "scan", "--help"], dependencies()),
    ).toBe(0);
    expect(stdout.text()).toContain("--csv <file>");
    expect(stdout.text()).toContain("Findings CSV");
  });

  test("passes --dry-run through when publishing a findings CSV", async () => {
    const deps = dependencies({
      currentDirectory: "/workspace/repository",
      onWorkbench: throwing("unexpected scan lookup"),
    });
    let publishedPath = "";
    deps.publishFindingsCsvToCloud = async (path, options) => {
      publishedPath = path;
      expect(options?.dryRun).toBe(true);
      expect(options?.signal).toBeInstanceOf(AbortSignal);
      return { ...receipt, dryRun: true };
    };
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "publish",
          "scan",
          "--to",
          "cloud",
          "--csv",
          "inputs/findings.csv",
          "--dry-run",
          "--json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(publishedPath).toBe(
      resolve("/workspace/repository", "inputs/findings.csv"),
    );
    expect(JSON.parse(stdout.text())).toMatchObject({
      scanId: "scan-1",
      findingCount: 1,
      dryRun: true,
    });
    expect(stderr.text()).toBe("");
  });

  test.each([
    [
      "a saved scan",
      ["--scan", "11111111", "--to", "cloud", "--csv", "findings.csv"],
      "Use --csv or scan directory and ID inputs",
    ],
    [
      "a scan directory",
      ["scan", "--to", "cloud", "--csv", "findings.csv"],
      "Use --csv or scan directory and ID inputs",
    ],
    [
      "Linear",
      ["--to", "linear", "--linear-team", "team", "--csv", "findings.csv"],
      "--csv is only supported with --to cloud",
    ],
  ])("rejects combining --csv with %s", async (_name, args, message) => {
    const deps = dependencies();
    const publishFindingsCsvToCloud = mock(resolving(receipt));
    deps.publishFindingsCsvToCloud = publishFindingsCsvToCloud;
    const stderr = captureCli(main, "stderr");
    expect(await stderr.run(["publish", "scan", ...args], deps)).toBe(2);
    expect(publishFindingsCsvToCloud).toHaveBeenCalledTimes(0);
    expect(stderr.text()).toContain(message);
  });

  test("resolves IDs, prefixes, and latest before publishing and deduplicates aliases", async () => {
    const { scans, deps, workbenchCalls } = await savedScansFixture();
    const [first, second] = scans;
    const calls: string[] = [];
    deps.publishScanToCloud = async (directory, options) => {
      expect(workbenchCalls).toHaveLength(4);
      const scan = scans[calls.length]!;
      expect(directory).toBe(await realpath(scan.scanDir));
      expect(options?.expectedScanId).toBe(scan.scanId);
      expect(options?.dryRun).toBe(true);
      calls.push(scan.scanId);
      return { ...receipt, scanId: scan.scanId, dryRun: true };
    };
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "publish",
          "scan",
          "--scan",
          first!.scanId,
          `--scan=${second!.scanId.slice(0, 8)}`,
          "--scan",
          "latest",
          "--to",
          "cloud",
          "--dry-run",
          "--json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(workbenchCalls).toContainEqual([
      "list-scans",
      "--repository",
      resolve(deps.currentDirectory()),
      "--status",
      "complete",
    ]);
    expect(calls).toEqual([first!.scanId, second!.scanId]);
    expect(JSON.parse(stdout.text()).results).toHaveLength(2);
    expect(stderr.text()).toBe("");
  });

  test.each(["missing", "incomplete", "unavailable"])(
    "rejects a %s saved scan before uploading any selected scan",
    async (failure) => {
      const { scans, deps } = await savedScansFixture();
      const [first, second] = scans;
      let requestedId = second!.scanId;
      if (failure === "missing") requestedId = "99999999";
      if (failure === "incomplete") second!.progress.status = "running";
      if (failure === "unavailable")
        await rm(second!.scanDir, { recursive: true });
      const publishScanToCloud = mock(resolving(receipt));
      deps.publishScanToCloud = publishScanToCloud;
      const stderr = captureCli(main, "stderr");
      expect(
        await stderr.run(
          [
            "publish",
            "scan",
            "--scan",
            first!.scanId,
            "--scan",
            requestedId,
            "--to",
            "cloud",
          ],
          deps,
        ),
      ).toBe(2);
      expect(publishScanToCloud).toHaveBeenCalledTimes(0);
      expect(stderr.text()).toMatch(
        /not found|not complete|artifacts or run a new scan/,
      );
      if (failure !== "missing")
        expect(stderr.text()).toContain(second!.scanId);
    },
  );

  test("rejects mixed ID and directory selectors before reading history", async () => {
    const deps = dependencies({
      onWorkbench: throwing("unexpected lookup"),
    });
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        [
          "publish",
          "scan",
          "--scan",
          "11111111",
          "--scan-dir",
          "external-scan",
          "--to",
          "cloud",
        ],
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Use --scan or scan directory inputs");
  });

  test("publishes checked scans in display order from one multi-select prompt", async () => {
    const { scans, deps } = await savedScansFixture();
    const picks = scans.slice(0, 2).map(({ scanId }) => scanId);
    let selections = 0;
    deps.publishPrompt = {
      isInteractive: () => true,
      select: unexpectedSingleSelect,
      checkbox: async <Value extends string>(
        _question: string,
        choices: readonly { label: string; value: Value }[],
        presentation?: { header?: string; required?: boolean },
        signal?: AbortSignal,
      ): Promise<Value[]> => {
        selections++;
        expect(signal).toBeInstanceOf(AbortSignal);
        expect(presentation?.header).toContain("SCAN ID");
        expect(presentation?.required).toBe(true);
        expect(choices.some(({ value }) => value === "")).toBe(false);
        expect(
          choices.some(({ label }) => label.includes(scans[0]!.scanDir)),
        ).toBe(false);
        expect(choices.map(({ value }) => String(value))).toEqual(
          scans.map(({ scanId }) => scanId),
        );
        return choices.slice(0, 2).map(({ value }) => value);
      },
    };
    const calls: string[] = [];
    deps.publishScanToCloud = async (_directory, options) => {
      expect(selections).toBe(1);
      calls.push(options!.expectedScanId!);
      return { ...receipt, scanId: options!.expectedScanId! };
    };
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(["publish", "scan", "--to", "cloud", "--json"], deps),
    ).toBe(0);
    expect(calls).toEqual(picks);
    expect(
      JSON.parse(stdout.text()).results.map(
        (result: { scanId: string }) => result.scanId,
      ),
    ).toEqual(calls);
  });

  test("cancels in the picker without uploading already selected scans", async () => {
    const { deps } = await savedScansFixture();
    const signals = new FakeSignals();
    deps.addSignalListener = (signal, listener) =>
      signals.add(signal, listener);
    deps.removeSignalListener = (signal, listener) =>
      signals.remove(signal, listener);
    deps.publishPrompt = {
      isInteractive: () => true,
      select: unexpectedSingleSelect,
      checkbox: async (_question, _choices, _presentation, signal) => {
        signals.emit("SIGINT");
        signal!.throwIfAborted();
        return [];
      },
    };
    const publishScanToCloud = mock(resolving(receipt));
    deps.publishScanToCloud = publishScanToCloud;
    expect(
      await runCapturedCli(main, ["publish", "scan", "--to", "cloud"], deps),
    ).toBe(130);
    expect(publishScanToCloud).toHaveBeenCalledTimes(0);
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
  });

  test("identifies failed and unattempted saved scans by ID on cancellation", async () => {
    const { scans, deps } = await savedScansFixture();
    const signals = new FakeSignals();
    deps.addSignalListener = (signal, listener) =>
      signals.add(signal, listener);
    deps.removeSignalListener = (signal, listener) =>
      signals.remove(signal, listener);
    deps.publishScanToCloud = async (_directory, options) => {
      if (options!.expectedScanId === scans[1]!.scanId) {
        signals.emit("SIGTERM");
        throw new Error("Publication was not confirmed.");
      }
      return { ...receipt, scanId: options!.expectedScanId! };
    };
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        [
          "publish",
          "scan",
          ...scans.flatMap(({ scanId }) => ["--scan", scanId]),
          "--to",
          "cloud",
          "--json",
        ],
        deps,
      ),
    ).toBe(143);
    expect(JSON.parse(stdout.text())).toMatchObject({
      results: [{ scanId: scans[0]!.scanId }],
      failed: [
        { scanId: scans[1]!.scanId, error: "Publication was not confirmed." },
      ],
      notAttempted: [scans[2]!.scanId],
    });
  });

  test("preserves a fully confirmed batch when cancellation follows the final response", async () => {
    const { scans, deps } = await savedScansFixture();
    const signals = new FakeSignals();
    deps.addSignalListener = (signal, listener) =>
      signals.add(signal, listener);
    deps.removeSignalListener = (signal, listener) =>
      signals.remove(signal, listener);
    let uploads = 0;
    deps.publishScanToCloud = async (_directory, options) => {
      uploads++;
      if (uploads === scans.length) signals.emit("SIGINT");
      return { ...receipt, scanId: options!.expectedScanId! };
    };
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "publish",
          "scan",
          ...scans.flatMap(({ scanId }) => ["--scan", scanId]),
          "--to",
          "cloud",
          "--json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(uploads).toBe(scans.length);
    expect(JSON.parse(stdout.text())).toMatchObject({
      results: scans.map(({ scanId }) => ({ scanId })),
      failed: [],
      notAttempted: [],
    });
    expect(stderr.text()).toBe("");
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
  });

  test("publishes multiple explicit scans in order and deduplicates resolved paths", async () => {
    for (const dryRun of [false, true]) {
      const deps = dependencies({
        onWorkbench: unexpectedScanHistory,
      });
      deps.createSecurity = mustNotInitializeCodex;
      deps.publishScan = rejecting("must not publish to Linear");
      const directories = ["scan one", "scan-two"].map((path) =>
        resolve(deps.currentDirectory(), path),
      );
      const calls: string[] = [];
      let publishing = false;
      const results = directories.map((scanDir, index) => ({
        scanDir,
        scanId: `scan-${index + 1}`,
        findingIds: dryRun ? [] : [`finding-${index + 1}`],
        findingCount: 1,
        ...(dryRun ? { dryRun: true as const, findings: [] } : {}),
      }));
      deps.publishScanToCloud = async (directory, options) => {
        expect(publishing).toBe(false);
        publishing = true;
        expect(directory).toBe(directories[calls.length]!);
        expect(options).toEqual({
          environment: deps.environment,
          dryRun,
          signal: expect.any(AbortSignal),
        });
        const { scanDir: _, ...result } = results[calls.length]!;
        calls.push(directory);
        await Promise.resolve();
        publishing = false;
        return result;
      };
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "publish",
            "scan",
            "--scan-dir",
            "scan one",
            "--to=cloud",
            "--scan-dir=scan-two",
            "--scan-dir",
            "./scan one",
            "--json",
            ...(dryRun ? ["--dry-run"] : []),
          ],
          deps,
        ),
      ).toBe(0);
      expect(calls).toEqual(directories);
      expect(JSON.parse(stdout.text())).toEqual({
        results,
        failed: [],
        notAttempted: [],
      });
      expect(stderr.text()).toBe("");
    }
  });

  test("keeps receipts and continues after a failed scan without retrying", async () => {
    const failure = `Cloud failed: ${SYNTHETIC_CREDENTIALS}\u001b[2J\ncontinued`;
    const deps = dependencies();
    const directories = ["scan-one", "scan-two", "scan-three"].map((path) =>
      resolve(deps.currentDirectory(), path),
    );
    const calls: string[] = [];
    deps.publishScanToCloud = async (directory) => {
      calls.push(directory);
      if (directory === directories[1]) {
        throw new Error(failure);
      }
      return {
        ...receipt,
        scanId: directory === directories[0] ? "scan-1" : "scan-3",
      };
    };
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "publish",
          "scan",
          ...directories.flatMap((directory) => ["--scan-dir", directory]),
          "--to",
          "cloud",
          "--json",
        ],
        deps,
      ),
    ).toBe(2);
    expect(calls).toEqual(directories);
    expect(JSON.parse(stdout.text())).toEqual({
      results: [
        { scanDir: directories[0], ...receipt },
        { scanDir: directories[2], ...receipt, scanId: "scan-3" },
      ],
      failed: [
        {
          scanDir: directories[1],
          error: failure,
        },
      ],
      notAttempted: [],
    });
    expect(stderr.text()).toContain(
      `Cloud failed: ${SYNTHETIC_CREDENTIALS} [2J continued\n`,
    );
    expect(stderr.text()).not.toContain("\u001b");
  });

  test.each([false, true])(
    "preserves batch receipts on cancellation with a confirmed response: %j",
    async (confirmed) => {
      for (const [signal, code] of [
        ["SIGINT", 130],
        ["SIGTERM", 143],
      ] as const) {
        const signals = new FakeSignals();
        const deps = dependencies({ signals });
        const directories = ["scan-one", "scan-two", "scan-three"].map((path) =>
          resolve(deps.currentDirectory(), path),
        );
        const calls: string[] = [];
        deps.publishScanToCloud = async (directory, options) => {
          calls.push(directory);
          if (directory === directories[1]) {
            signals.emit(signal);
            expect(options?.signal?.aborted).toBe(true);
            if (confirmed) return { ...receipt, scanId: "scan-2" };
            throw new Error(
              "Cloud publication was not confirmed. Check acceptance before resubmitting.",
            );
          }
          return receipt;
        };
        const { stdout, stderr, runCli } = createCliTest(main);

        expect(
          await runCli(
            [
              "publish",
              "scan",
              ...directories.flatMap((directory) => ["--scan-dir", directory]),
              "--to",
              "cloud",
              "--json",
            ],
            deps,
          ),
        ).toBe(code);
        expect(calls).toEqual(directories.slice(0, 2));
        expect(JSON.parse(stdout.text())).toEqual({
          results: [
            { scanDir: directories[0], ...receipt },
            ...(confirmed
              ? [{ scanDir: directories[1], ...receipt, scanId: "scan-2" }]
              : []),
          ],
          failed: confirmed
            ? []
            : [
                {
                  scanDir: directories[1],
                  error:
                    "Cloud publication was not confirmed. Check acceptance before resubmitting.",
                },
              ],
          notAttempted: [directories[2]],
        });
        expect(stderr.text()).toContain(
          signal === "SIGINT" ? "canceled" : "terminated",
        );
        expect(
          [...signals.listeners.values()].every(
            (listeners) => listeners.size === 0,
          ),
        ).toBe(true);
      }
    },
  );

  test("rejects multiple scans for Linear before publishing any findings", async () => {
    const deps = dependencies();
    const publishScan = mock(rejecting("unexpected publication"));
    deps.publishScan = publishScan;
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "publish",
          "scan",
          "scan-one",
          "--scan-dir",
          "scan-two",
          "--to",
          "linear",
          "--linear-team",
          "synthetic-team",
          "--json",
        ],
        deps,
      ),
    ).toBe(2);
    expect(publishScan).toHaveBeenCalledTimes(0);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Multiple scan directories");
  });

  test.each(["positional", "flag"])(
    "routes an explicit %s scan to Cloud without initializing Codex or Linear",
    async (syntax) => {
      for (const destination of [["--to=cloud"], ["--to", "cloud"]]) {
        for (const dryRun of [false, true]) {
          const currentDirectory = join(tmpdir(), "cloud-publish-current");
          const deps = dependencies({
            currentDirectory,
            environment: { CODEX_SECURITY_LINEAR_API_KEY: " " },
            onWorkbench: unexpectedScanHistory,
          });
          deps.createSecurity = mustNotInitializeCodex;
          deps.publishScan = rejecting("must not publish to Linear");
          let calls = 0;
          const result = dryRun
            ? {
                ...receipt,
                findingIds: [],
                dryRun: true as const,
                findings: [],
              }
            : receipt;
          deps.publishScanToCloud = async (directory, options) => {
            calls++;
            expect(directory).toBe(join(currentDirectory, "completed-scan"));
            expect(options).toEqual({
              environment: deps.environment,
              dryRun,
              signal: expect.any(AbortSignal),
            });
            return result;
          };
          const { stdout, stderr, runCli } = createCliTest(main);

          expect(
            await runCli(
              [
                "publish",
                "scan",
                ...(syntax === "flag"
                  ? ["--scan-dir", "completed-scan"]
                  : ["completed-scan"]),
                ...destination,
                "--json",
                ...(dryRun ? ["--dry-run"] : []),
              ],
              deps,
            ),
          ).toBe(0);
          expect(calls).toBe(1);
          expect(JSON.parse(stdout.text())).toEqual(result);
          expect(stderr.text()).toBe("");
        }
      }
    },
  );

  test("expands home-relative scan inputs and deduplicates mixed positional and flag paths", async () => {
    const first = join(homedir(), "scan-one");
    const second = join(homedir(), "scan-two");
    for (const { inputs, expected } of [
      { inputs: ["~/scan-one"], expected: [first] },
      {
        inputs: ["--scan-dir", "~/scan-one", "--scan-dir", first],
        expected: [first],
      },
      {
        inputs: ["~/scan-one", "--scan-dir", first, "--scan-dir", "~/scan-two"],
        expected: [first, second],
      },
    ]) {
      const deps = dependencies({
        onWorkbench: unexpectedScanHistory,
      });
      const calls = mock(resolving<typeof receipt, [string]>(receipt));
      deps.publishScanToCloud = calls;
      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(
          ["publish", "scan", ...inputs, "--to", "cloud", "--json"],
          deps,
        ),
      ).toBe(0);
      expect(calls.mock.calls.map(([value]) => value)).toEqual(expected);
      expect(JSON.parse(stdout.text())).toEqual(
        expected.length === 1
          ? receipt
          : {
              results: expected.map((scanDir) => ({ scanDir, ...receipt })),
              failed: [],
              notAttempted: [],
            },
      );
    }
  });

  test("publishes a scan once through canonical and directory-linked paths", async () => {
    const root = await temporaryDirectory("cloud-publish-links-");
    const scans = join(root, "scans");
    const scanDir = join(scans, "completed-scan");
    const linkedScans = join(root, "linked-scans");
    await mkdir(scanDir, { recursive: true });
    await symlink(
      scans,
      linkedScans,
      process.platform === "win32" ? "junction" : "dir",
    );
    const canonicalScan = await realpath(scanDir);
    const calls = mock(resolving<typeof receipt, [string]>(receipt));
    const deps = dependencies({
      onWorkbench: unexpectedScanHistory,
    });
    deps.publishScanToCloud = calls;
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        [
          "publish",
          "scan",
          "--scan-dir",
          scanDir,
          "--scan-dir",
          join(linkedScans, "completed-scan"),
          "--to",
          "cloud",
          "--json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(calls.mock.calls.map(([value]) => value)).toEqual([canonicalScan]);
    expect(JSON.parse(stdout.text())).toEqual(receipt);
  });

  test("rejects missing or empty scan flags and extra positionals before publishing", async () => {
    for (const inputs of [
      ["--scan"],
      ["--scan="],
      ["--scan", "--json"],
      ["--scan-dir"],
      ["--scan-dir="],
      ["--scan-dir", "--json"],
      ["scan-one", "scan-two"],
    ]) {
      const deps = dependencies();
      const publishScanToCloud = mock(resolving(receipt));
      deps.publishScanToCloud = publishScanToCloud;
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(["publish", "scan", ...inputs, "--to", "cloud"], deps),
      ).toBe(2);
      expect(publishScanToCloud).toHaveBeenCalledTimes(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).not.toBe("");
    }
  });

  test("reuses the completed-scan picker when no directory is supplied", async () => {
    const root = await mkdtemp(join(tmpdir(), "cloud-publish-picker-"));
    const scanDir = join(root, "completed-scan");
    try {
      await mkdir(scanDir);
      const deps = dependencies({
        onWorkbench: (args) => {
          expect(args).toEqual(["list-scans", "--status", "complete"]);
          return {
            scans: [
              {
                scanId: "scan-1",
                scanDir,
                progress: { status: "complete" },
                findingCount: 1,
              },
            ],
          };
        },
      });
      let selections = 0;
      deps.publishPrompt = {
        isInteractive: () => true,
        select: unexpectedSingleSelect,
        checkbox: async (_question, choices, presentation) => {
          selections++;
          const directories: string[] = choices.map(({ value }) => value);
          expect(directories).toEqual(["scan-1"]);
          expect(presentation?.required).toBe(true);
          return [choices[0]!.value];
        },
      };
      deps.publishScanToCloud = async (directory, options) => {
        expect(directory).toBe(await realpath(scanDir));
        expect(options?.expectedScanId).toBe("scan-1");
        return receipt;
      };
      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(["publish", "scan", "--to", "cloud", "--json"], deps),
      ).toBe(0);
      expect(selections).toBe(1);
      expect(JSON.parse(stdout.text())).toEqual(receipt);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("requests an explicit scan outside a terminal without suggesting Linear options", async () => {
    const deps = dependencies();
    deps.publishPrompt = {
      isInteractive: () => false,
      select: rejecting("unexpected picker"),
    };
    deps.publishScanToCloud = rejecting("unexpected publication");
    const stderr = captureCli(main, "stderr");
    expect(await stderr.run(["publish", "scan", "--to", "cloud"], deps)).toBe(
      2,
    );
    expect(stderr.text()).toContain("--scan SCAN_ID --to cloud");
    expect(stderr.text()).not.toContain("--linear-team");
  });

  test("rejects Linear-specific options before uploading to Cloud", async () => {
    for (const linearOptions of [
      ["--linear-team", "synthetic-value"],
      ["--linear-project", "synthetic-value"],
      ["--project", "synthetic-value"],
      ["--linear-assignee", "synthetic-value"],
      ["--linear-api-key", "synthetic-value"],
      ["--skip-existing"],
    ]) {
      const deps = dependencies();
      const publishScanToCloud = mock(resolving(receipt));
      deps.publishScanToCloud = publishScanToCloud;
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "publish",
            "scan",
            "completed-scan",
            "--to",
            "cloud",
            ...linearOptions,
          ],
          deps,
        ),
      ).toBe(2);
      expect(publishScanToCloud).toHaveBeenCalledTimes(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("cannot be combined with Linear options");
    }
  });

  test("keeps the internal Cloud destination out of help and discovery", async () => {
    for (const flag of ["--help", "--schema", "--llms", "--llms-full"]) {
      const stdout = captureCli(main, "stdout");
      const deps = dependencies();
      deps.publishScanToCloud = rejecting("unexpected publication");
      expect(await stdout.run(["publish", "scan", flag], deps)).toBe(0);
      expect(stdout.text().toLowerCase()).not.toContain("cloud");
    }
  });

  test("reports original publication failures without claiming success", async () => {
    const deps = dependencies();
    deps.publishScanToCloud = rejecting(
      `Cloud failed: ${SYNTHETIC_CREDENTIALS}\u001b[2J\ncontinued`,
    );
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["publish", "scan", "completed-scan", "--to", "cloud"],
        deps,
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe(
      `codex-security: Cloud failed: ${SYNTHETIC_CREDENTIALS} [2J continued\n`,
    );
  });

  test("preserves a confirmed single-scan receipt when cancellation follows the response", async () => {
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.publishScanToCloud = async () => {
      signals.emit("SIGINT");
      return receipt;
    };
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["publish", "scan", "completed-scan", "--to", "cloud", "--json"],
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(receipt);
    expect(stderr.text()).toBe("");
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
  });

  test("aborts Cloud publication without activating Linear recovery signal handling", async () => {
    for (const [signal, code] of [
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      const signals = new FakeSignals();
      const deps = dependencies({
        signals,
        environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-linear-key" },
      });
      let now = 0;
      const forceExit = mock();
      deps.now = () => now;
      deps.forceExit = forceExit;
      deps.publishScanToCloud = async (_directory, options) => {
        signals.emit(signal);
        expect(options?.signal?.aborted).toBe(true);
        now = 500;
        signals.emit(signal);
        options?.signal?.throwIfAborted();
        return receipt;
      };
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["publish", "scan", "completed-scan", "--to", "cloud"],
          deps,
        ),
      ).toBe(code);
      expect(forceExit).not.toHaveBeenCalled();
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        signal === "SIGINT" ? "canceled" : "terminated",
      );
      expect(stderr.text()).not.toContain("reconcile retained Linear");
      expect(
        [...signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
    }
  });
});

const unexpectedSingleSelect = rejecting("unexpected single-select prompt");

const unexpectedScanHistory = throwing("must not inspect scan history");
