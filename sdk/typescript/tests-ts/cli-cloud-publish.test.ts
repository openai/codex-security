import { createHash } from "node:crypto";
import { resolving } from "./support/promises.js";
import {
  chmod,
  cp,
  readFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { publishScanToCloud } from "../src/cloud-publish.js";
import type { ImportedScanReceipt } from "../src/cloud-import-models.js";
import {
  nativeCloudServer,
  nativeCloudDestination as cloudDestination,
} from "./support/cloud-import.js";
import type { JsonObject } from "../src/index.js";
import {
  capture,
  dependencies,
  FakeSignals,
  SYNTHETIC_CREDENTIALS,
  mustNotInitializeCodex,
} from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";

import { createCliTest, captureCli } from "./support/cli-run.js";

async function populateScan(scanDir: string) {
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);
  const path = join(scanDir, "scan-manifest.json"),
    manifest = JSON.parse(await readFile(path, "utf8"));
  manifest.scan.target.repositoryPath = ".";
  manifest.scan.target.revision = "a".repeat(40);
  await writeFile(path, JSON.stringify(manifest));
}

const nativeReceipt: ImportedScanReceipt = {
  protocol_version: 1,
  imported_scan_id: "import-1",
  source: "cli",
  source_scan_id: "scan-1",
  environment_id: "env-1",
  repository_id: "repo-1",
  repository_full_name: "example/repo",
  repository_remote: "https://github.com/example/repo",
  connector_id: "connector-1",
  target_kind: "git_revision",
  base_commit: "a".repeat(40),
  snapshot_digest: null,
  upload_status: "finalizing",
  materialization_status: "pending",
  dedupe_status: "pending",
  artifacts: [],
  created_at: "2026-06-01T00:00:00Z",
  scan_started_at: "2026-06-01T00:00:00Z",
  scan_completed_at: "2026-06-01T00:01:00Z",
  finalized_at: null,
  finalization_started_at: "2026-06-01T00:02:00Z",
  materialization_completed_at: null,
  finding_count: null,
  failure_code: null,
  status_url: "/api/aardvark/imported-scans/v1/import-1",
};
const receipt = {
  scanId: "scan-1",
  findingIds: [],
  findingCount: 1,
  publication: nativeReceipt,
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
      await populateScan(scanDir);
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
  deps.listCloudDestinations = async () => [cloudDestination];
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

  test("rejects legacy CSV publication before invoking a publisher", async () => {
    const deps = dependencies({
      onWorkbench: throwing("unexpected scan lookup"),
    });
    deps.publishScanToCloud = rejecting("unexpected publisher");
    deps.listCloudDestinations = rejecting("unexpected discovery");
    const { stderr, runCli } = createCliTest(main);
    expect(
      await runCli(
        [
          "publish",
          "scan",
          "--to",
          "cloud",
          "--csv",
          "findings.csv",
          "--dry-run",
        ],
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("CSV imports are unsupported");
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
    const publish = mock(resolving(receipt));
    deps.publishScanToCloud = publish;
    const stderr = captureCli(main, "stderr");
    expect(await stderr.run(["publish", "scan", ...args], deps)).toBe(2);
    expect(publish).toHaveBeenCalledTimes(0);
    expect(stderr.text()).toContain(message);
  });

  test.each([
    [
      "positional with spaced option",
      ["scan output", "--cloud-environment", "env-1"],
    ],
    [
      "option before positional",
      ["--cloud-environment", "env-1", "scan output"],
    ],
    [
      "positional with equals option",
      ["scan output", "--cloud-environment=env-1"],
    ],
    [
      "directory option",
      ["--scan-dir", "scan output", "--cloud-environment", "env-1"],
    ],
  ])("forwards the Cloud environment with %s", async (_name, selection) => {
    const deps = dependencies({ currentDirectory: "/workspace/repository" });
    let published = false;
    deps.publishScanToCloud = async (directory, options) => {
      expect(directory).toBe(resolve("/workspace/repository", "scan output"));
      expect(options?.cloudEnvironment).toBe("env-1");
      published = true;
      return receipt;
    };
    const { runCli, stdout, stderr } = createCliTest(main);
    expect(
      await runCli(
        ["publish", "scan", ...selection, "--to", "cloud", "--json"],
        deps,
      ),
    ).toBe(0);
    expect(published).toBe(true);
    expect(JSON.parse(stdout.text())).toEqual(receipt);
    expect(stderr.text()).not.toContain("Unexpected positional");
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

  test("selects the Cloud environment before listing matching local scans", async () => {
    const { scans, deps, workbenchCalls } = await savedScansFixture();
    const unrelated = join(scans[1]!.scanDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(unrelated, "utf8"));
    manifest.scan.target.remote = "https://github.com/example/other";
    await writeFile(unrelated, JSON.stringify(manifest));
    let environmentSelected = false;
    deps.listCloudDestinations = async () => [
      {
        ...cloudDestination,
        environment_name: "Example\u001b[2J\u001b[H\u009b2J",
      },
      { ...cloudDestination, environment_id: "env-2" },
    ];
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async (_question, choices) => {
        expect(workbenchCalls).toHaveLength(0);
        expect(choices[0]!.label).not.toMatch(/[\u001b\u009b]/u);
        expect(choices[0]!.label).toContain("Example");
        expect(String(choices[0]!.value)).toBe("env-1");
        environmentSelected = true;
        return choices[1]!.value;
      },
      checkbox: async (_question, choices) => {
        expect(environmentSelected).toBe(true);
        expect(choices.map((item) => String(item.value))).toEqual([
          scans[0]!.scanId,
          scans[2]!.scanId,
        ]);
        return [choices[0]!.value];
      },
    };
    deps.publishScanToCloud = async (_directory, options) => {
      expect(options?.cloudEnvironment).toBe("env-2");
      return receipt;
    };
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "--to", "cloud", "--json"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(stderr.text()).toBe("");
  });

  test("one environment with multiple repositories shows large matching scans", async () => {
    const { scans, deps } = await savedScansFixture();
    const path = join(scans[1]!.scanDir, "scan-manifest.json"),
      manifest = JSON.parse(await readFile(path, "utf8"));
    manifest.scan.target.remote = "https://github.com/example/second";
    await writeFile(path, JSON.stringify(manifest));
    for (const scan of scans) {
      const findingsPath = join(scan.scanDir, "findings.json");
      const findings = JSON.parse(await readFile(findingsPath, "utf8"));
      findings.findings[0].summary = "Large artifact-backed evidence. ".repeat(
        12000,
      );
      const bytes = JSON.stringify(findings);
      expect(Buffer.byteLength(bytes)).toBeGreaterThan(256 * 1024);
      await writeFile(findingsPath, bytes);
      const manifestPath = join(scan.scanDir, "scan-manifest.json");
      const saved = JSON.parse(await readFile(manifestPath, "utf8"));
      saved.scan.artifacts.find(
        (artifact: { path: string }) => artifact.path === "findings.json",
      ).sha256 = createHash("sha256").update(bytes).digest("hex");
      await writeFile(manifestPath, JSON.stringify(saved));
    }
    deps.listCloudDestinations = async () => [
      cloudDestination,
      {
        ...cloudDestination,
        repository_id: "repo-2",
        repository_remote: manifest.scan.target.remote,
      },
    ];
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async () => {
        throw new Error("One environment must auto-select");
      },
      checkbox: async (_question, choices) => {
        expect(choices.map((item) => String(item.value))).toEqual(
          scans.map((item) => item.scanId),
        );
        return choices.map((item) => item.value);
      },
    };
    deps.publishScanToCloud = async (_directory, options) => {
      expect(options?.cloudEnvironment).toBe("env-1");
      return receipt;
    };
    expect(
      await main(
        ["publish", "scan", "--to", "cloud", "--json"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
  });

  test("cancels environment selection before reading scan history", async () => {
    const { deps, workbenchCalls } = await savedScansFixture();
    const signals = new FakeSignals();
    deps.addSignalListener = (signal, listener) =>
      signals.add(signal, listener);
    deps.removeSignalListener = (signal, listener) =>
      signals.remove(signal, listener);
    deps.listCloudDestinations = async () => [
      cloudDestination,
      { ...cloudDestination, environment_id: "env-2" },
    ];
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async (_question, _choices, _presentation, signal) => {
        expect(signal).toBeInstanceOf(AbortSignal);
        signals.emit("SIGTERM");
        signal!.throwIfAborted();
        throw new Error("unreachable");
      },
    };
    deps.publishScanToCloud = async () => {
      throw new Error("unexpected upload");
    };
    expect(
      await main(
        ["publish", "scan", "--to", "cloud"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(143);
    expect(workbenchCalls).toHaveLength(0);
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
  });

  test("passes explicit environment selection with a saved ID from another directory", async () => {
    const { scans, deps, workbenchCalls } = await savedScansFixture();
    deps.currentDirectory = () => "/unrelated/repository";
    deps.publishScanToCloud = async (_directory, options) => {
      expect(options?.cloudEnvironment).toBe("env-1");
      expect(options?.expectedScanId).toBe(scans[0]!.scanId);
      return receipt;
    };
    expect(
      await main(
        [
          "publish",
          "scan",
          "--to",
          "cloud",
          "--scan",
          scans[0]!.scanId,
          "--cloud-environment",
          "env-1",
        ],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(workbenchCalls).toEqual([
      ["get-scan", "--scan-id", scans[0]!.scanId],
    ]);
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
    const { stderr, runCli } = createCliTest(main);
    expect(await runCli(["publish", "scan", "--to", "cloud"], deps)).toBe(130);
    expect(publishScanToCloud).toHaveBeenCalledTimes(0);
    expect(stderr.text()).toContain("Publication canceled");
    expect(stderr.text()).not.toMatch(/accepted|retry/i);
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
          fetch: expect.any(Function),
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

  test.each([
    ["single preflight", "preflight", false],
    ["single request", "request", false],
    ["single receipt", "receipt", false],
    ["batch preflight", "preflight", true],
    ["batch request", "request", true],
    ["batch receipt", "receipt", true],
  ] as const)(
    "handles cancellation from the real Cloud publisher: %s",
    async (_scenario, stage, batch) => {
      for (const [signal, code] of [
        ["SIGINT", 130],
        ["SIGTERM", 143],
      ] as const) {
        const root = await realpath(await temporaryDirectory());
        const credentialHome = join(root, "credentials");
        await mkdir(credentialHome, { mode: 0o700 });
        await writeFile(
          join(credentialHome, "auth.json"),
          JSON.stringify({
            auth_mode: "chatgpt",
            tokens: {
              access_token: "synthetic-access-token",
              account_id: "synthetic-account",
            },
          }),
          { mode: 0o600 },
        );
        await writeFile(
          join(credentialHome, "config.toml"),
          'cli_auth_credentials_store = "file"\n',
        );
        const scanDirectories = await Promise.all(
          ["scan-one", "scan-two"].map(async (name) => {
            const directory = join(root, name);
            await populateScan(directory);
            return directory;
          }),
        );
        const directories = batch
          ? [...scanDirectories, join(root, "not-attempted")]
          : [scanDirectories[0]!];
        const signals = new FakeSignals();
        const deps = dependencies({
          signals,
          currentDirectory: root,
          environment: {
            CODEX_HOME: credentialHome,
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
          },
        });
        let requests = 0;
        let publications = 0;
        const cloud = nativeCloudServer();
        deps.cloudFetch = async (url, request) => {
          requests++;
          if ((batch && publications === 1) || request.method === "GET")
            return cloud.fetch(url, request);
          expect(request.signal).toBeInstanceOf(AbortSignal);
          if (stage === "request") {
            signals.emit(signal);
            throw request.signal!.reason;
          }
          return new Response(
            new ReadableStream({
              pull(body) {
                signals.emit(signal);
                body.error(request.signal!.reason);
              },
            }),
            { status: 201 },
          );
        };
        deps.publishScanToCloud = (directory, options) => {
          publications++;
          const result = publishScanToCloud(directory, options);
          if (stage === "preflight" && publications === (batch ? 2 : 1))
            signals.emit(signal);
          return result;
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
        expect(requests).toBe(
          (batch ? 7 : 0) + (stage === "preflight" ? 0 : 2),
        );
        if (batch) {
          expect(JSON.parse(stdout.text())).toEqual({
            results: [
              expect.objectContaining({
                scanDir: directories[0],
                findingIds: [],
                publication: expect.objectContaining({
                  upload_status: "accepted",
                }),
              }),
            ],
            failed: [
              {
                scanDir: directories[1],
                error:
                  stage === "preflight"
                    ? signal
                    : expect.stringMatching(/not confirmed|resume/i),
              },
            ],
            notAttempted: [directories[2]],
          });
        } else {
          expect(stdout.text()).toBe("");
        }
        if (stage === "preflight") {
          expect(stderr.text()).not.toMatch(/accepted|retry/i);
        } else {
          expect(stderr.text()).toMatch(/not confirmed|resume/i);
        }
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
              fetch: expect.any(Function),
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
      await populateScan(scanDir);
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
      deps.listCloudDestinations = async () => [cloudDestination];
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

  test.each([false, true])(
    "requests an explicit scan outside a terminal before discovery (dryRun=%s)",
    async (dryRun) => {
      const deps = dependencies();
      deps.listCloudDestinations = async () => {
        throw new Error("unexpected discovery");
      };
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
          [
            "publish",
            "scan",
            "--to",
            "cloud",
            ...(dryRun ? ["--dry-run"] : []),
          ],
          capture().stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain("--scan SCAN_ID --to cloud");
      expect(stderr.text()).not.toContain("--linear-team");
    },
  );

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

  test("documents native Cloud selection in help and discovery", async () => {
    for (const flag of ["--help", "--schema", "--llms", "--llms-full"]) {
      const stdout = captureCli(main, "stdout");
      const deps = dependencies();
      deps.publishScanToCloud = rejecting("unexpected publication");
      expect(await stdout.run(["publish", "scan", flag], deps)).toBe(0);
      expect(stdout.text().toLowerCase()).toContain("cloud");
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

  test("does not suggest retrying an upload when a Cloud dry run is canceled", async () => {
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.publishScanToCloud = async (_directory, options) => {
      signals.emit("SIGINT");
      throw options!.signal!.reason;
    };
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["publish", "scan", "completed-scan", "--to", "cloud", "--dry-run"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(130);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).not.toMatch(/accepted|retry/i);
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
