import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { workbenchCommand } from "./support/workbench-command.js";
import { runNodePython } from "./support/python-probe.js";
import {
  copyCompletedScanFixture,
  PLUGIN_ROOT,
  readCompletedFindingsFixture,
} from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { readJson } from "./support/json.js";
import { main } from "../src/cli.js";
import { ScanInterruptedError } from "../src/errors.js";
import { dependencies, fakeSecurity } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

type FindingsDocument = {
  findings: Array<{
    identity: { anchor: string };
    summary: string;
    writeup?: { reportPath: string };
  }>;
};

type CoverageSurface = Record<string, unknown> & {
  id: string;
  label: string;
  disposition: string;
  receiptRefs: unknown[];
};

type CoverageDocument = Record<string, unknown> & {
  scanId: string;
  inventoryStrategy: string;
  surfaces: CoverageSurface[] | Record<string, unknown>;
  explicitExclusions: unknown;
  deferred: unknown;
};

type ScanSummary = {
  findingCount: number;
  progress: { status: string };
  warnings: string[];
};

type ScanFixture = Awaited<ReturnType<typeof startDraftScan>>;

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-scan-recovery-",
);

afterEach(cleanup);

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function workbench(
  fixture: ScanFixture,
  args: readonly string[],
  input?: string,
) {
  return workbenchCommand(fixture.python, fixture.stateDir)(args, input);
}

async function startDraftScan(
  repositoryKind: "directory" | "clean" | "dirty" | "nested" = "directory",
  recipeFromStdin = false,
) {
  const root = await temporaryDirectory();
  const python =
    process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();

  const target = join(
    root,
    recipeFromStdin ? "répository-日本語" : "repository",
  );
  const scanDir = join(root, "scan");
  await mkdir(join(target, "src"), { recursive: true });
  await writeFile(join(target, "src", "extract.py"), "# fixture\n");
  await mkdir(scanDir, { mode: 0o700 });

  if (repositoryKind !== "directory") {
    for (const args of [
      ["init", "--quiet", target],
      ["-C", target, "add", "--", "src/extract.py"],
      [
        "-C",
        target,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
      ],
    ]) {
      const result = spawnSync("git", args, { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
    }
    if (repositoryKind === "dirty") {
      await writeFile(join(target, "src", "extract.py"), "# changed fixture\n");
    }
    if (repositoryKind === "nested") {
      const nested = join(target, "nested");
      await mkdir(nested);
      await writeFile(join(nested, "source.py"), "# nested fixture\n");
      const initialized = spawnSync("git", ["init", "--quiet", nested], {
        encoding: "utf8",
      });
      expect(initialized.status, initialized.stderr).toBe(0);
    }
  }

  const fixture = {
    python: python!,
    repository: target,
    stateDir: join(root, "state"),
    scanDir,
    scanId: "",
    registration: {} as Record<string, unknown>,
  };
  const recipe = JSON.stringify({
    config: {},
    mode: "standard",
    repository: target,
    target: { kind: "repository", paths: [] },
  });
  const registration = await workbench(
    fixture,
    [
      "register-cli-scan",
      "--repository",
      target,
      "--scan-dir",
      scanDir,
      ...(recipeFromStdin
        ? ["--recipe-json-stdin"]
        : ["--recipe-json", recipe]),
    ],
    recipeFromStdin ? recipe : undefined,
  );
  fixture.scanId = String(registration["scanId"]);
  fixture.registration = registration;

  await copyCompletedScanFixture(scanDir);
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = await readJson<{
    scan: {
      id: string;
      target: { kind: string };
      sealedAt?: string;
      artifacts?: unknown[];
    };
  }>(manifestPath);
  manifest.scan.id = fixture.scanId;
  manifest.scan.target.kind =
    repositoryKind === "directory"
      ? "directory_snapshot"
      : repositoryKind === "clean"
        ? "git_revision"
        : "git_worktree";
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  await writeJson(manifestPath, manifest);

  for (const name of ["findings.json", "coverage.json"] as const) {
    const path = join(scanDir, name);
    const document =
      name === "findings.json"
        ? await readCompletedFindingsFixture()
        : await readJson<{ scanId: string }>(path);
    document.scanId = fixture.scanId;
    await writeJson(path, document);
  }
  await writeFile(join(scanDir, "report.md"), "# Draft report\n");
  return fixture;
}

async function completeScan(fixture: ScanFixture): Promise<ScanSummary> {
  const result = await workbench(fixture, [
    "complete-scan",
    "--scan-id",
    fixture.scanId,
  ]);
  return result["scan"] as unknown as ScanSummary;
}

describe("scan publication and artifact recovery", () => {
  test.each(["scan", "rerun", "resume"] as const)(
    "%s full-output includes sealed findings after execution throws",
    async (command) => {
      const fixture = await startDraftScan();
      const message = "Synthetic execution failure after finding discovery.";
      const recipe = {
        repository: fixture.repository,
        target: { kind: "repository", paths: [] },
        mode: command === "resume" ? "deep" : "standard",
        config: {},
      };
      const deps = dependencies({
        currentDirectory: fixture.repository,
        onWorkbench: () => ({
          scanId: fixture.scanId,
          scanDir: fixture.scanDir,
          recipe,
        }),
      });
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onScanRegistered?.(fixture);
          await workbench(fixture, [
            "fail-scan",
            "--scan-id",
            fixture.scanId,
            "--message",
            message,
          ]);
          throw command === "resume"
            ? new ScanInterruptedError(message, fixture.scanDir)
            : new Error(message);
        });
      const args =
        command === "scan" ? ["scan"] : ["scans", command, fixture.scanId];
      const expectedError = { code: "SCAN_FAILED", message };
      for (const output of ["full", "filtered", "ordinary"] as const) {
        if (command === "scan" && output === "filtered") continue;
        const cli = createCliTest(main);
        expect(
          await cli.runCli(
            [
              ...args,
              "--format",
              command === "resume" ? "jsonl" : "json",
              ...(output === "ordinary" ? [] : ["--full-output"]),
              ...(output === "filtered"
                ? ["--filter-output", "findings.findings"]
                : []),
            ],
            deps,
          ),
        ).toBe(2);
        const envelope = JSON.parse(cli.stdout.text());
        if (output === "ordinary") {
          expect(envelope).toEqual({ status: "failed", ...expectedError });
        } else {
          expect(envelope).toMatchObject({ ok: false, error: expectedError });
          if (output === "filtered") {
            expect(Object.keys(envelope.data)).toEqual(["findings"]);
            expect(envelope.data.findings.findings).toHaveLength(1);
            expect(envelope.data.findings.findings[0].summary).toBeTruthy();
          } else {
            expect(envelope.data).toMatchObject({
              manifest: { scan: { id: fixture.scanId, status: "failed" } },
              scanDir: fixture.scanDir,
              reportPath: join(fixture.scanDir, "report.md"),
            });
            expect(envelope.data.findings.findings).toHaveLength(1);
            expect(envelope.data.review).toEqual({ excludedPaths: [] });
            expect(envelope.data).not.toHaveProperty("turn");
          }
        }
        expect(cli.stderr.text()).toContain(message);
      }
    },
  );

  test.each(["unregistered", "unsealed", "malformed", "different-scan"])(
    "full-output preserves the execution error with %s saved artifacts",
    async (artifactState) => {
      const fixture = await startDraftScan();
      const message = "Synthetic scanner failure.";
      if (artifactState !== "unsealed") {
        await workbench(fixture, [
          "fail-scan",
          "--scan-id",
          fixture.scanId,
          "--message",
          message,
        ]);
      }
      if (artifactState === "malformed")
        await writeFile(join(fixture.scanDir, "findings.json"), "invalid");
      const deps = dependencies({ currentDirectory: fixture.repository });
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onOutputDirReady?.(fixture.scanDir);
          if (artifactState !== "unregistered")
            options?.onScanRegistered?.({
              ...fixture,
              scanId:
                artifactState === "different-scan"
                  ? "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                  : fixture.scanId,
            });
          throw new Error(message);
        });
      const cli = createCliTest(main);
      expect(await cli.runCli(["scan", "--json", "--full-output"], deps)).toBe(
        2,
      );
      expect(JSON.parse(cli.stdout.text())).toMatchObject({
        ok: false,
        error: { code: "SCAN_FAILED", message },
      });
      expect(JSON.parse(cli.stdout.text())).not.toHaveProperty("data");
      expect(cli.stderr.text()).toContain(message);
    },
  );

  test("registers a Unicode stdin recipe with the authoritative directory contract", async () => {
    const fixture = await startDraftScan("directory", true);
    expect(fixture.registration).toMatchObject({
      scanDir: fixture.scanDir,
      targetRevision: "unversioned",
      contract: {
        target: {
          allowedKinds: ["directory_snapshot"],
          displayName: "répository-日本語",
          targetId: fixture.registration["targetId"],
          requiredSnapshotDigest: expect.stringMatching(
            /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
          ),
        },
      },
    });
    const saved = await workbench(fixture, [
      "get-scan-recipe",
      "--scan-id",
      fixture.scanId,
    ]);
    expect(saved["recipe"]).toMatchObject({ repository: fixture.repository });
  });

  test("rejoins a headless scan after its stdin context is cleared", async () => {
    const fixture = await startDraftScan();
    const threadId = "context-rejoin-regression";
    const originalContext = "original security focus".repeat(3_000);
    const startArguments = [
      "start-headless-standard-scan",
      "--thread-id",
      threadId,
      "--target-path",
      fixture.repository,
      "--scope",
      ".",
      "--user-context-stdin",
    ];
    const created = await workbench(fixture, startArguments, originalContext);
    const scan = created["scan"] as {
      scanId: string;
      handoffClaimToken: string;
      userContext: string;
    };

    expect(scan.userContext).toBe(originalContext);

    const updated = await workbench(
      fixture,
      [
        "update-scan-context",
        "--scan-id",
        scan.scanId,
        "--user-context-stdin",
        "--thread-id",
        threadId,
        "--claim-token",
        scan.handoffClaimToken,
      ],
      "",
    );
    expect(updated["scan"]).toMatchObject({
      scanId: scan.scanId,
      userContext: null,
    });
    expect(updated["workspace"]).toMatchObject({
      userContext: null,
    });

    const retried = await workbench(fixture, startArguments, originalContext);
    expect(retried["startDisposition"]).toBe("joined");
    expect(retried["scan"]).toMatchObject({
      scanId: scan.scanId,
      userContext: null,
    });
  }, 30_000);

  test("builds each ordinary scan context once without losing selected findings", async () => {
    const fixture = await startDraftScan();
    const findingsPath = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(findingsPath);
    const original = document.findings[0]!;
    document.findings = Array.from({ length: 21 }, (_, index) => {
      const finding = structuredClone(original);
      finding.identity.anchor = `scan-context-finding-${index}`;
      return finding;
    });
    await writeJson(findingsPath, document);
    await completeScan(fixture);

    const page = await workbench(fixture, [
      "list-findings",
      "--scan-id",
      fixture.scanId,
      "--offset",
      "20",
      "--limit",
      "1",
    ]);
    const occurrenceId = (
      page["findingsPage"] as {
        findings: Array<{ occurrenceId: string }>;
      }
    ).findings[0]!.occurrenceId;
    const probe = runNodePython(
      fixture.python,
      [
        "-c",
        [
          "import json, sys",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_db as workbench",
          "calls = []",
          "original = workbench.scan_result",
          "def count_result(connection, scan, **kwargs):",
          "    calls.append(kwargs.get('occurrence_id'))",
          "    return original(connection, scan, **kwargs)",
          "workbench.scan_result = count_result",
          "with workbench.connect() as connection:",
          "    ordinary = workbench.scan_context(connection, sys.argv[2])",
          "    ordinary_calls = len(calls)",
          "    calls.clear()",
          "    selected = workbench.scan_context(connection, sys.argv[2], sys.argv[3])",
          "print(json.dumps({'ordinaryCalls': ordinary_calls, 'selectedCalls': len(calls), 'ordinaryCount': len(ordinary['scan']['findings']), 'selectedCount': len(selected['scan']['findings']), 'workspaceCount': len(selected['workspace']['results']['findings']), 'selectedIncluded': any(finding['occurrenceId'] == sys.argv[3] for finding in selected['scan']['findings'])}))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.scanId,
        occurrenceId,
      ],
      {
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(probe.status, probe.stderr).toBe(0);
    expect(JSON.parse(probe.stdout)).toEqual({
      ordinaryCalls: 1,
      selectedCalls: 2,
      ordinaryCount: 20,
      selectedCount: 21,
      workspaceCount: 20,
      selectedIncluded: true,
    });
  }, 30_000);

  test("returns authoritative clean, dirty, and nested Git target contracts", async () => {
    for (const kind of ["clean", "dirty", "nested"] as const) {
      const fixture = await startDraftScan(kind);
      const registration = fixture.registration;
      const contract = registration["contract"] as {
        target: {
          allowedKinds: string[];
          targetId: string;
          requiredSnapshotDigest?: string;
        };
      };
      const revision = spawnSync(
        "git",
        ["-C", fixture.repository, "rev-parse", "HEAD"],
        { encoding: "utf8" },
      );

      expect(revision.status, revision.stderr).toBe(0);
      expect(registration["targetRevision"]).toBe(revision.stdout.trim());
      expect(registration["targetId"]).toBe(contract.target.targetId);
      expect(contract.target.allowedKinds).toEqual([
        kind === "clean" ? "git_revision" : "git_worktree",
      ]);
      if (kind === "clean") {
        expect(contract.target).not.toHaveProperty("requiredSnapshotDigest");
      } else {
        expect(contract.target.requiredSnapshotDigest).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
        );
      }
      if (kind === "nested") {
        const copied = runNodePython(fixture.python, [
          "-c",
          [
            "import sys",
            "from pathlib import Path",
            "sys.path.insert(0, sys.argv[1])",
            "import workbench_target as target",
            "source = Path(sys.argv[2])",
            "checkout, _ = target.copy_git_worktree_files(source, Path(sys.argv[3]), ())",
            "git_dir = Path(target.git_output(source, 'rev-parse', '--absolute-git-dir'))",
            "assert target.worktree_content_digest_for_context(checkout, '.', git_dir=git_dir, work_tree=checkout) == target.worktree_content_digest(source)",
          ].join("\n"),
          join(PLUGIN_ROOT, "scripts"),
          fixture.repository,
          join(fixture.stateDir, "checkout"),
        ]);
        expect(copied.status, copied.stderr).toBe(0);
      }
    }
  });

  test.each([
    ["unavailable", undefined],
    [
      "worker-inclusive",
      {
        coverage: "complete",
        source: "codex_rollout",
        threadCount: 3,
        inputTokens: 5_000,
        cachedInputTokens: 400,
        cacheWriteInputTokens: 0,
        outputTokens: 120,
        reasoningOutputTokens: 20,
        totalTokens: 5_120,
      },
    ],
  ] as const)(
    "reconciles authoritative scan cost without replacing %s usage or sealed artifacts",
    async (_scenario, measuredUsage) => {
      const fixture = await startDraftScan();
      const firstCompletion = await workbench(fixture, [
        "complete-scan",
        "--scan-id",
        fixture.scanId,
        ...(measuredUsage === undefined
          ? []
          : ["--cost-json", JSON.stringify({ usage: measuredUsage })]),
      ]);
      const initiallyCompleted = firstCompletion["scan"] as ScanSummary & {
        usage: Record<string, unknown>;
        cost?: unknown;
      };
      expect(initiallyCompleted.progress.status).toBe("complete");
      expect(initiallyCompleted.usage).toBeDefined();
      if (measuredUsage !== undefined) {
        expect(initiallyCompleted.usage).toEqual(measuredUsage);
      }
      expect(initiallyCompleted.cost).toBeUndefined();

      const artifactNames = [
        "scan-manifest.json",
        "findings.json",
        "report.md",
      ];
      const sealedArtifacts = await Promise.all(
        artifactNames.map((name) => readFile(join(fixture.scanDir, name))),
      );
      const cost = {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 0.00625,
      };

      const reconciled = await workbench(fixture, [
        "complete-scan",
        "--scan-id",
        fixture.scanId,
        "--cost-json",
        JSON.stringify(cost),
      ]);
      expect(reconciled["scan"]).toMatchObject({
        progress: { status: "complete" },
        usage: initiallyCompleted.usage,
        cost,
      });

      const persisted = await workbench(fixture, [
        "get-scan",
        "--scan-id",
        fixture.scanId,
      ]);
      expect(persisted["scan"]).toMatchObject({
        progress: { status: "complete" },
        usage: initiallyCompleted.usage,
        cost,
      });
      expect(
        await Promise.all(
          artifactNames.map((name) => readFile(join(fixture.scanDir, name))),
        ),
      ).toEqual(sealedArtifacts);
    },
  );

  test("preserves target-drift classification from prepared completion", async () => {
    const fixture = await startDraftScan();
    const source = join(fixture.repository, "src", "extract.py");
    const original = await readFile(source, "utf8");
    await writeFile(source, "# target changed during scan\n");

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    const warning =
      "Directory contents changed while the scan was running; results were saved for the original snapshot.";
    expect(prepared["targetWarnings"]).toEqual([warning]);

    await writeFile(source, original);
    const completed = await workbench(fixture, [
      "complete-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((completed["scan"] as ScanSummary).warnings).toContain(warning);
    expect(completed["targetWarnings"]).toEqual([]);
  });

  test("marks rejected prepared scans as failed without publishing completion", async () => {
    const fixture = await startDraftScan();
    await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    await writeFile(join(fixture.scanDir, "findings.json"), "corrupted\n");

    const failed = await workbench(fixture, [
      "fail-scan",
      "--scan-id",
      fixture.scanId,
      "--message",
      "Sealed scan could not be accepted.",
    ]);

    expect((failed["scan"] as ScanSummary).progress.status).toBe("failed");
    const stored = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((stored["scan"] as ScanSummary).progress.status).toBe("failed");
  });

  test("keeps explicit scan cancellation distinct from failure", async () => {
    const fixture = await startDraftScan();

    await workbench(fixture, ["cancel-scan", "--scan-id", fixture.scanId]);
    const stored = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);

    expect(stored["scan"]).toMatchObject({
      canceledAt: expect.any(String),
      failureMessage: null,
      progress: { status: "canceled" },
    });
  });

  test("keeps a prepared scan running and preserves its missing-writeup warning on completion", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.writeup = {
      reportPath: "findings/missing/missing.md",
    };
    await writeJson(path, document);

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    const preparedScan = prepared["scan"] as ScanSummary;
    expect(preparedScan.progress.status).toBe("running");
    expect(preparedScan.warnings).toHaveLength(1);
    const warning = preparedScan.warnings[0]!;
    expect(warning).toStartWith("Skipped missing writeup for finding 1:");
    const preparedFindings = (await readJson<FindingsDocument>(path)).findings;
    expect(preparedFindings).toHaveLength(1);
    expect(preparedFindings[0]).not.toHaveProperty("writeup");
    const manifest = await readJson<{
      scan: { sealedAt: string; completedAt: string };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.sealedAt).toBeTruthy();
    expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
    const running = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((running["scan"] as ScanSummary).progress.status).toBe("running");
    const completion = await workbench(fixture, [
      "complete-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    const completed = completion["scan"] as ScanSummary;
    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toEqual([warning]);
    expect(completion["targetWarnings"]).toEqual([]);
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as ScanSummary).warnings).toEqual([warning]);
  });

  test("rejects malformed findings without changing the draft and accepts a corrected retry", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = structuredClone(document);
    document.findings[0]!.summary = "";
    await writeJson(path, document);
    const artifactPaths = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
    ].map((name) => join(fixture.scanDir, name));
    const original = await Promise.all(
      artifactPaths.map((name) => readFile(name)),
    );

    await expect(completeScan(fixture)).rejects.toThrow("invalid findings");

    expect(
      await Promise.all(artifactPaths.map((name) => readFile(name))),
    ).toEqual(original);
    const pending = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((pending["scan"] as ScanSummary).progress.status).toBe("running");
    await writeJson(path, valid);
    expect((await completeScan(fixture)).findingCount).toBe(1);
  });

  test("seals verified receipts and discards unsafe references without losing findings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    const receipt = "artifacts/02_discovery/work_ledger.jsonl";
    await mkdir(join(fixture.scanDir, "artifacts", "02_discovery"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, receipt), '{"status":"reviewed"}\n');
    const surface = (document.surfaces as CoverageSurface[])[0]!;
    surface.receiptRefs = [
      receipt,
      "report.md",
      "../outside.json",
      "artifacts/02_discovery/missing.jsonl",
      null,
    ];
    await writeJson(path, document);
    const manifestPath = join(fixture.scanDir, "scan-manifest.json");
    const draft = await readJson<{ scan: { hardening?: unknown } }>(
      manifestPath,
    );
    draft.scan.hardening = { portfolioPath: "../outside.md" };
    await writeJson(manifestPath, draft);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toHaveLength(5);
    expect(
      completed.warnings.filter((warning) =>
        warning.startsWith("Skipped malformed coverage receipt"),
      ),
    ).toHaveLength(4);
    expect(
      completed.warnings.some((warning) =>
        warning.startsWith("Skipped malformed hardening portfolio:"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside");
    const manifest = await readJson<{
      scan: { artifacts: Array<{ path: string }> };
    }>(manifestPath);
    expect(manifest.scan).not.toHaveProperty("hardening");
    expect(manifest.scan.artifacts.map((artifact) => artifact.path)).toContain(
      receipt,
    );
  });

  test.each([
    ["invalid object", "not an object"],
    ["missing file", { portfolioPath: "hardening/hardening.md" }],
  ] as const)(
    "recovers malformed coverage collections and omits a hardening portfolio (%s)",
    async (_case, hardening) => {
      const fixture = await startDraftScan();
      const coveragePath = join(fixture.scanDir, "coverage.json");
      const manifestPath = join(fixture.scanDir, "scan-manifest.json");
      const findingsPath = join(fixture.scanDir, "findings.json");
      const { findings } = await readJson<FindingsDocument>(findingsPath);
      const coverage = await readJson<CoverageDocument>(coveragePath);
      coverage.surfaces = { id: "not-an-array" };
      coverage.explicitExclusions = null;
      coverage.deferred = "later";
      await writeJson(coveragePath, coverage);
      const manifest = await readJson<{
        scan: { hardening?: unknown; sealedAt?: string };
      }>(manifestPath);
      manifest.scan.hardening = hardening;
      await writeJson(manifestPath, manifest);

      const completed = await completeScan(fixture);

      expect(completed).toMatchObject({
        findingCount: 1,
        progress: { status: "complete" },
      });
      expect(completed.warnings).toHaveLength(4);
      expect(
        completed.warnings.filter((warning) =>
          warning.endsWith("expected an array."),
        ),
      ).toHaveLength(3);
      expect(completed.warnings).toContainEqual(
        expect.stringMatching(/^Skipped malformed hardening portfolio:/),
      );
      expect(await readJson<FindingsDocument>(findingsPath)).toMatchObject({
        findings: [{ summary: findings[0]!.summary }],
      });
      const sealed = await readJson<typeof manifest>(manifestPath);
      expect(sealed.scan.sealedAt).toBeTruthy();
      expect(sealed.scan).toMatchObject({ review: { excludedPaths: [] } });
      expect(sealed.scan).not.toHaveProperty("coverageRef");
      expect(sealed.scan).not.toHaveProperty("reviewState");
      expect(sealed.scan).not.toHaveProperty("hardening");
    },
  );

  test.each(["complete-scan", "prepare-scan-completion"] as const)(
    "keeps a repairable %s contract failure resumable",
    async (command) => {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "coverage.json");
      const document = await readJson<CoverageDocument>(path);
      const validInventoryStrategy = document.inventoryStrategy;
      document.inventoryStrategy = "";
      await writeJson(path, document);
      const original = await readFile(path);

      await expect(
        workbench(fixture, [command, "--scan-id", fixture.scanId]),
      ).rejects.toThrow("inventoryStrategy");
      expect(await readFile(path)).toEqual(original);
      const pending = await workbench(fixture, [
        "get-scan",
        "--scan-id",
        fixture.scanId,
      ]);
      expect((pending["scan"] as ScanSummary).progress.status).toBe("running");

      document.inventoryStrategy = validInventoryStrategy;
      await writeJson(path, document);
      expect((await completeScan(fixture)).findingCount).toBe(1);
    },
  );
});
