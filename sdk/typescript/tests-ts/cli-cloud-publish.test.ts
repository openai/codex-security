import { mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/index.js";
import {
  capture,
  dependencies,
  FakeSignals,
  SYNTHETIC_CREDENTIALS,
} from "./cli-fixtures.js";

const receipt = {
  scanId: "scan-1",
  findingIds: ["finding-1"],
  findingCount: 1,
};

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function savedScansFixture() {
  const root = await mkdtemp(join(tmpdir(), "cloud-saved-scans-"));
  temporaryDirectories.push(root);
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
    const stdout = capture();
    expect(
      await main(
        ["publish", "scan", "--help"],
        stdout.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("--csv <string>");
    expect(stdout.text()).toContain("Findings CSV");
  });

  test("passes --dry-run through when publishing a findings CSV", async () => {
    const deps = dependencies({
      currentDirectory: "/workspace/repository",
      onWorkbench: () => {
        throw new Error("unexpected scan lookup");
      },
    });
    let publishedPath = "";
    deps.publishFindingsCsvToCloud = async (path, options) => {
      publishedPath = path;
      expect(options?.dryRun).toBe(true);
      expect(options?.signal).toBeInstanceOf(AbortSignal);
      return { ...receipt, dryRun: true };
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
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
        stdout.stream,
        stderr.stream,
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
    let publications = 0;
    deps.publishFindingsCsvToCloud = async () => {
      publications++;
      return receipt;
    };
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", ...args],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(publications).toBe(0);
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
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
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
        stdout.stream,
        stderr.stream,
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
      let uploads = 0;
      deps.publishScanToCloud = async () => {
        uploads++;
        return receipt;
      };
      const stderr = capture();
      expect(
        await main(
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
          capture().stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(uploads).toBe(0);
      expect(stderr.text()).toMatch(
        /not found|not complete|artifacts or run a new scan/,
      );
      if (failure !== "missing")
        expect(stderr.text()).toContain(second!.scanId);
    },
  );

  test("rejects mixed ID and directory selectors before reading history", async () => {
    const deps = dependencies({
      onWorkbench: () => {
        throw new Error("unexpected lookup");
      },
    });
    const stderr = capture();
    expect(
      await main(
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
        capture().stream,
        stderr.stream,
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
      select: async () => {
        throw new Error("unexpected single-select prompt");
      },
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
    const stdout = capture();
    expect(
      await main(
        ["publish", "scan", "--to", "cloud", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
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
      select: async () => {
        throw new Error("unexpected single-select prompt");
      },
      checkbox: async (_question, _choices, _presentation, signal) => {
        signals.emit("SIGINT");
        signal!.throwIfAborted();
        return [];
      },
    };
    let uploads = 0;
    deps.publishScanToCloud = async () => {
      uploads++;
      return receipt;
    };
    expect(
      await main(
        ["publish", "scan", "--to", "cloud"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(130);
    expect(uploads).toBe(0);
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
    const stdout = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          ...scans.flatMap(({ scanId }) => ["--scan", scanId]),
          "--to",
          "cloud",
          "--json",
        ],
        stdout.stream,
        capture().stream,
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
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          ...scans.flatMap(({ scanId }) => ["--scan", scanId]),
          "--to",
          "cloud",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
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
        onWorkbench: () => {
          throw new Error("must not inspect scan history");
        },
      });
      deps.createSecurity = () => {
        throw new Error("must not initialize Codex");
      };
      deps.publishScan = async () => {
        throw new Error("must not publish to Linear");
      };
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
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
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
          stdout.stream,
          stderr.stream,
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
    const deps = dependencies();
    const directories = ["scan-one", "scan-two", "scan-three"].map((path) =>
      resolve(deps.currentDirectory(), path),
    );
    const calls: string[] = [];
    deps.publishScanToCloud = async (directory) => {
      calls.push(directory);
      if (directory === directories[1]) {
        throw new Error(`Cloud failed: ${SYNTHETIC_CREDENTIALS}`);
      }
      return {
        ...receipt,
        scanId: directory === directories[0] ? "scan-1" : "scan-3",
      };
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          ...directories.flatMap((directory) => ["--scan-dir", directory]),
          "--to",
          "cloud",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(calls).toEqual(directories);
    expect(JSON.parse(stdout.text())).toEqual({
      results: [
        { scanDir: directories[0], ...receipt },
        { scanDir: directories[2], ...receipt, scanId: "scan-3" },
      ],
      failed: [{ scanDir: directories[1], error: "[redacted]" }],
      notAttempted: [],
    });
    expect(stderr.text()).toContain("[redacted]");
    expect(stderr.text()).not.toContain(SYNTHETIC_CREDENTIALS);
  });

  test.each([false, true])(
    "preserves batch receipts on cancellation with a confirmed response: %s",
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
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            [
              "publish",
              "scan",
              ...directories.flatMap((directory) => ["--scan-dir", directory]),
              "--to",
              "cloud",
              "--json",
            ],
            stdout.stream,
            stderr.stream,
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
    let calls = 0;
    deps.publishScan = async () => {
      calls++;
      throw new Error("unexpected publication");
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
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
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(calls).toBe(0);
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
            onWorkbench: () => {
              throw new Error("must not inspect scan history");
            },
          });
          deps.createSecurity = () => {
            throw new Error("must not initialize Codex");
          };
          deps.publishScan = async () => {
            throw new Error("must not publish to Linear");
          };
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
          const stdout = capture();
          const stderr = capture();
          expect(
            await main(
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
              stdout.stream,
              stderr.stream,
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
        onWorkbench: () => {
          throw new Error("must not inspect scan history");
        },
      });
      const calls: string[] = [];
      deps.publishScanToCloud = async (directory) => {
        calls.push(directory);
        return receipt;
      };
      const stdout = capture();
      expect(
        await main(
          ["publish", "scan", ...inputs, "--to", "cloud", "--json"],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toEqual(expected);
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
    const root = await mkdtemp(join(tmpdir(), "cloud-publish-links-"));
    temporaryDirectories.push(root);
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
    const calls: string[] = [];
    const deps = dependencies({
      onWorkbench: () => {
        throw new Error("must not inspect scan history");
      },
    });
    deps.publishScanToCloud = async (directory) => {
      calls.push(directory);
      return receipt;
    };
    const stdout = capture();
    expect(
      await main(
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
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls).toEqual([canonicalScan]);
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
      let calls = 0;
      deps.publishScanToCloud = async () => {
        calls++;
        return receipt;
      };
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["publish", "scan", ...inputs, "--to", "cloud"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(calls).toBe(0);
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
        select: async () => {
          throw new Error("unexpected single-select prompt");
        },
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
      const stdout = capture();
      expect(
        await main(
          ["publish", "scan", "--to", "cloud", "--json"],
          stdout.stream,
          capture().stream,
          deps,
        ),
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
      select: async () => {
        throw new Error("unexpected picker");
      },
    };
    deps.publishScanToCloud = async () => {
      throw new Error("unexpected publication");
    };
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "--to", "cloud"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
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
      let calls = 0;
      deps.publishScanToCloud = async () => {
        calls++;
        return receipt;
      };
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            "--to",
            "cloud",
            ...linearOptions,
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(calls).toBe(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("cannot be combined with Linear options");
    }
  });

  test("keeps the internal Cloud destination out of help and discovery", async () => {
    for (const flag of ["--help", "--schema", "--llms", "--llms-full"]) {
      const stdout = capture();
      const deps = dependencies();
      deps.publishScanToCloud = async () => {
        throw new Error("unexpected publication");
      };
      expect(
        await main(
          ["publish", "scan", flag],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(stdout.text().toLowerCase()).not.toContain("cloud");
    }
  });

  test("reports publication failures without leaking credentials or claiming success", async () => {
    const deps = dependencies();
    deps.publishScanToCloud = async () => {
      throw new Error(`Cloud failed: ${SYNTHETIC_CREDENTIALS}`);
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "completed-scan", "--to", "cloud"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe("codex-security: [redacted]\n");
  });

  test("preserves a confirmed single-scan receipt when cancellation follows the response", async () => {
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.publishScanToCloud = async () => {
      signals.emit("SIGINT");
      return receipt;
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "completed-scan", "--to", "cloud", "--json"],
        stdout.stream,
        stderr.stream,
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
      let forced = false;
      deps.now = () => now;
      deps.forceExit = () => {
        forced = true;
      };
      deps.publishScanToCloud = async (_directory, options) => {
        signals.emit(signal);
        expect(options?.signal?.aborted).toBe(true);
        now = 500;
        signals.emit(signal);
        options?.signal?.throwIfAborted();
        return receipt;
      };
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["publish", "scan", "completed-scan", "--to", "cloud"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(code);
      expect(forced).toBe(false);
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
