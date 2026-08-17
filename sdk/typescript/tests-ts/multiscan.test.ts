import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  appendFile,
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
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
import { hostname, tmpdir } from "node:os";
import { basename, dirname, join, posix, relative, sep } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { zipSync } from "fflate";
import Papa from "papaparse";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contract from "../src/contract.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanResult } from "../src/result.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import * as runtime from "../src/runtime.js";
import { outermostGitMarkerRoot } from "../src/targets.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture(): Promise<{
  root: string;
  input: string;
  output: string;
}> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-multiscan-")),
  );
  temporaryDirectories.push(root);
  return {
    root,
    input: join(root, "repositories.csv"),
    output: join(root, "results"),
  };
}

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

async function repository(
  root: string,
  name: string,
): Promise<{ path: string; revision: string }> {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q");
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

async function completedScan(
  outputDir: string,
  completeness: "complete" | "partial" | "unknown" = "complete",
  targetKind: "git_revision" | "git_worktree" = "git_revision",
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
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
  const fixtureRoot = temporaryDirectories.find((root) =>
    outputDir.startsWith(`${root}${sep}`),
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
      manifest.scan.target.kind = targetKind;
      manifest.scan.target.targetId = `target_sha256_${createHash("sha256")
        .update(`local-workspace\0${join(campaignRoot, "checkouts", id)}`)
        .digest("hex")}`;
      manifest.scan.target.displayName = id;
      manifest.scan.target.revision = task["revision"]!;
      if (targetKind === "git_worktree") {
        const checkout = join(campaignRoot, "checkouts", id);
        const contents = await readFile(join(checkout, "src", "app.ts"));
        manifest.scan.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${createHash(
          "sha256",
        )
          .update(task["revision"]!)
          .update("\0")
          .update(contents)
          .digest("hex")}`;
      } else {
        delete manifest.scan.target.snapshotDigest;
      }
      const scope = task["scope"]?.trim();
      let normalizedScope = scope ? posix.normalize(scope) : ".";
      if (scope) {
        const checkout = join(campaignRoot, "checkouts", id);
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

function client(
  run: SecurityClient["run"],
  close: SecurityClient["close"] = async () => {},
): SecurityClient {
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

async function results(path: string): Promise<Record<string, unknown>[]> {
  return (await readFile(path, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("multiscan", () => {
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
    const paths = await fixture();
    const source = await repository(paths.root, "github-credentials");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const configured = execFileSync(
      "git",
      [
        ...buildGitHubCredentialArgs("github.acme.example"),
        "config",
        "--get-all",
        "credential.https://github.acme.example.helper",
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    expect(configured.trim()).toBe("!gh auth git-credential");

    const summary = await runMultiscan(
      options(
        paths,
        client(
          async (_checkout, scanOptions = {}) =>
            await completedScan(scanOptions.outputDir!),
        ),
        { githubHost: "github.acme.example" },
      ),
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
    const paths = await fixture();
    const source = await repository(paths.root, "priced");
    await writeFile(
      paths.input,
      `id,repository,revision\npriced,${source.path},${source.revision}\n`,
    );
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
    const paths = await fixture();
    const source = await repository(paths.root, "over-budget");
    await writeFile(
      paths.input,
      `id,repository,revision\nover-budget,${source.path},${source.revision}\n`,
    );
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 25.25,
    };
    let attempts = 0;

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          attempts += 1;
          throw new ScanCostLimitExceededError(
            25,
            cost,
            scanOptions.outputDir!,
          );
        }),
        { maxAttempts: 3, maxCostUsd: 25 },
      ),
    );

    expect(attempts).toBe(1);
    expect(summary).toMatchObject({ completed: 0, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "over-budget", status: "failed", attempt: 1, cost },
    ]);
  });

  test("forwards a bulk CLI cost limit and rejects zero", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const stdout = capture();
    const stderr = capture();
    let scanOptions: unknown;

    expect(
      await main(
        [
          "bulk-scan",
          "repositories.csv",
          "--output-dir",
          "results",
          "--max-cost",
          "12.5",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        dependencies({
          currentDirectory: paths.root,
          onTurn: (_repository, options) => (scanOptions = options),
        }),
      ),
    ).toBe(0);
    expect(scanOptions).toMatchObject({ maxCostUsd: 12.5 });

    const invalid = capture();
    expect(
      await main(
        ["bulk-scan", "--max-cost=0"],
        capture().stream,
        invalid.stream,
        dependencies({ currentDirectory: paths.root }),
      ),
    ).toBe(2);
    expect(invalid.text()).toContain("expected number to be >0");
  });

  test("persists redacted scan warnings without failing completed scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "follow-up-warning");
    const quiet = await repository(paths.root, "quiet");
    const secret = "sk-proj-SYNTHETIC_MULTISCAN_WARNING_123";
    await writeFile(
      paths.input,
      [
        "id,repository,revision",
        `follow-up-warning,${source.path},${source.revision}`,
        `quiet,${quiet.path},${quiet.revision}`,
        "",
      ].join("\n"),
    );
    const progress: Parameters<
      NonNullable<MultiscanOptions["onProgress"]>
    >[0][] = [];
    let scans = 0;
    const security = client(async (checkout, scanOptions = {}) => {
      scans += 1;
      if (basename(checkout) === "follow-up-warning") {
        scanOptions.onWarning?.("Could not run post-scan instructions.");
        scanOptions.onWarning?.(`Scan target changed after ${secret}.`);
      }
      return await completedScan(scanOptions.outputDir!);
    });
    const summary = await runMultiscan(
      options(paths, security, { onProgress: (event) => progress.push(event) }),
    );

    expect(summary).toMatchObject({
      completed: 2,
      incomplete: 0,
      failed: 0,
      warned: 1,
    });
    expect(progress).toContainEqual({
      repository: "follow-up-warning",
      attempt: 1,
      status: "started",
      warning: "Could not run post-scan instructions.",
    });
    const receipts = await results(summary.resultsPath);
    expect(receipts).toMatchObject([
      {
        id: "follow-up-warning",
        status: "completed",
        warnings: ["Could not run post-scan instructions.", "[redacted]"],
      },
      { id: "quiet", status: "completed" },
    ]);
    expect(receipts[1]).not.toHaveProperty("warnings");
    expect(await readFile(summary.resultsPath, "utf8")).not.toContain(secret);

    const ledger = await readFile(summary.resultsPath, "utf8");
    const unrelatedWarning = {
      id: "OUTSIDE-CAMPAIGN",
      warnings: ["Unrelated historical warning."],
    };
    await appendFile(
      summary.resultsPath,
      `${JSON.stringify(unrelatedWarning)}\n`,
    );
    const malformedLedger = await readFile(summary.resultsPath, "utf8");
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "Multiscan recovery is required",
    );
    expect(scans).toBe(2);
    expect(await readFile(summary.resultsPath, "utf8")).toBe(malformedLedger);
    await writeFile(summary.resultsPath, ledger);
    await appendFile(
      summary.resultsPath,
      `${JSON.stringify({
        ...receipts[0],
        ...unrelatedWarning,
      })}\n`,
    );
    for (const identity of [{ id: "QUIET" }, { repository: source.path }]) {
      const previous = (await results(summary.resultsPath)).findLast(
        (receipt) => receipt["id"] === "quiet",
      );
      await appendFile(
        summary.resultsPath,
        `${JSON.stringify({
          ...previous,
          ...identity,
          warnings: ["Warning from another scan identity."],
        })}\n`,
      );
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 2,
        warned: 1,
        skipped: 1,
      });
    }
  });

  test("keeps warnings from failed attempts across retries and resumes", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "warned-retry");
    await writeFile(
      paths.input,
      `id,repository,revision\nwarned-retry,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      if (attempts === 1) {
        scanOptions.onWarning?.("Scan target changed while it was running.");
        throw new Error("temporary failure");
      }
      return await completedScan(scanOptions.outputDir!);
    });

    const first = await runMultiscan(
      options(paths, security, { maxAttempts: 1 }),
    );
    expect(first).toMatchObject({ completed: 0, failed: 1, warned: 1 });

    const retried = await runMultiscan(
      options(paths, security, { maxAttempts: 1 }),
    );
    expect(retried).toMatchObject({
      completed: 1,
      failed: 0,
      warned: 1,
      skipped: 0,
    });
    expect(await results(retried.resultsPath)).toMatchObject([
      {
        status: "failed",
        attempt: 1,
        warnings: ["Scan target changed while it was running."],
      },
      { status: "completed", attempt: 2 },
    ]);

    const resumed = await runMultiscan(options(paths, security));
    expect(resumed).toMatchObject({
      completed: 1,
      failed: 0,
      warned: 1,
      skipped: 1,
    });
    expect(attempts).toBe(2);
  });

  test.each([false, true])(
    "continues scanning when a progress observer fails %s",
    async (asynchronous) => {
      const paths = await fixture();
      const source = await repository(paths.root, "observer-failure");
      await writeFile(
        paths.input,
        `id,repository,revision\nobserver-failure,${source.path},${source.revision}\n`,
      );
      let attempts = 0;
      const progress: string[] = [];

      const summary = await runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            attempts += 1;
            scanOptions.onWarning?.("Optional post-scan warning.");
            return await completedScan(scanOptions.outputDir!);
          }),
          {
            onProgress: (event) => {
              progress.push(event.warning ?? event.status);
              const error = new Error("Optional progress observer failed.");
              if (asynchronous) return Promise.reject(error);
              throw error;
            },
          },
        ),
      );

      expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
      expect(attempts).toBe(1);
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
      const paths = await fixture();
      const source = await repository(paths.root, completeness);
      await writeFile(
        paths.input,
        `id,repository,revision\nsealed,${source.path},${source.revision}\n`,
      );
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
          onProgress: () => {
            throw new Error("Optional progress observer failed.");
          },
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
    },
  );

  test.each(["partial", "unknown"] as const)(
    "resumes legacy sealed %s coverage without rerunning or duplicating cost",
    async (completeness) => {
      const paths = await fixture();
      const source = await repository(paths.root, `legacy-${completeness}`);
      await writeFile(
        paths.input,
        `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
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
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return await completedScan(scanOptions.outputDir!);
      });

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
      expect(attempts).toBe(0);
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
      expect(attempts).toBe(0);
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
      const paths = await fixture();
      const source = await repository(paths.root, "legacy-retry");
      await writeFile(
        paths.input,
        `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
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
      let attempts = 0;

      const summary = await runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            attempts += 1;
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      );

      expect(summary).toMatchObject({
        completed: 1,
        incomplete: 0,
        failed: 0,
        skipped: 0,
      });
      expect(attempts).toBe(1);
      expect(await results(summary.resultsPath)).toMatchObject([
        { status: "failed", attempt: 1, error },
        { status: "completed", attempt: 2, coverage: "complete" },
      ]);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "keeps sealed %s-coverage CLI runs fail-closed without retrying",
    async (completeness) => {
      const paths = await fixture();
      const source = await repository(paths.root, "sample");
      await writeFile(
        paths.input,
        `id,repository,revision\nsample,${source.path},${source.revision}\n`,
      );
      const outputDir = join(paths.output, "artifacts", "sample", "attempt-1");
      const completed = await completedScan(outputDir, completeness);
      const result = fakeResult([], completeness);
      result.manifest.scan.target.targetId =
        completed.manifest.scan.target.targetId;
      const stdout = capture();
      const stderr = capture();
      let attempts = 0;
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
        onRun: () => {
          attempts += 1;
        },
      });

      expect(
        await main(
          arguments_,
          stdout.stream,
          stderr.stream,
          clientDependencies,
        ),
      ).toBe(2);
      expect(attempts).toBe(1);
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
      expect(attempts).toBe(1);
    },
  );

  test("retries incomplete scans that are missing required artifacts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "missing-artifact");
    await writeFile(
      paths.input,
      `id,repository,revision\nmissing,${source.path},${source.revision}\n`,
    );

    let attempts = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          attempts += 1;
          const result = await completedScan(
            scanOptions.outputDir!,
            attempts === 1 ? "partial" : "complete",
          );
          if (attempts === 1) {
            await rm(join(scanOptions.outputDir!, "report.md"));
          }
          return result;
        }),
      ),
    );

    expect(attempts).toBe(2);
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
    let scans = 0;

    for (const input of invalid) {
      await writeFile(paths.input, input);
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow(/CSV/);
    }

    expect(scans).toBe(0);
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

    let checkout = "";
    let closed = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(
          async (path, scanOptions = {}) => {
            checkout = path;
            expect(git(path, "rev-parse", "HEAD")).toBe(source.revision);
            expect(
              await readFile(join(path, "src", "app.ts"), "utf8"),
            ).toContain('name = "payments"');
            expect(scanOptions.target).toEqual(["src"]);
            expect(scanOptions.mode).toBe("deep");
            expect(scanOptions.outputDir).toBe(
              join(paths.output, "artifacts", "payments", "attempt-1"),
            );
            return await completedScan(scanOptions.outputDir!);
          },
          async () => {
            closed += 1;
          },
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(closed).toBe(1);
    await expect(access(checkout)).rejects.toThrow();
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
      "shared/threat-model.md",
    ];
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
    let created = 0;
    let closed = 0;
    let release!: () => void;
    const simultaneous = new Promise<void>((resolve) => {
      release = resolve;
    });
    const security = client(async (_repository, scanOptions = {}) => {
      expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
      active += 1;
      maximum = Math.max(maximum, active);
      if (active === 2) release();
      await simultaneous;
      active -= 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const summary = await runMultiscan(
      options(paths, security, {
        workers: 2,
        knowledgeBasePaths,
        createSecurity: () => {
          created += 1;
          let running = false;
          return client(
            async (repository, scanOptions) => {
              if (running) {
                throw new Error("A scan is already running for this client.");
              }
              running = true;
              try {
                return await security.run(repository, scanOptions);
              } finally {
                running = false;
              }
            },
            async () => {
              closed += 1;
            },
          );
        },
      }),
    );

    expect(maximum).toBe(2);
    expect(created).toBe(2);
    expect(closed).toBe(2);
    expect(summary).toMatchObject({ total: 3, completed: 3, failed: 0 });
    expect(await results(summary.resultsPath)).toHaveLength(3);
  });

  test("rejects another supervisor and recovers a crashed owner's checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "exclusive");
    await writeFile(
      paths.input,
      `id,repository,revision\nexclusive,${source.path},${source.revision}\n`,
    );
    let started!: () => void;
    let release!: () => void;
    const running = new Promise<void>((resolve) => {
      started = resolve;
    });
    const finish = new Promise<void>((resolve) => {
      release = resolve;
    });
    const security = client(async (_repository, scanOptions = {}) => {
      started();
      await finish;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = runMultiscan(options(paths, security));
    await running;
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
      release();
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
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(await results(recovered.resultsPath)).toEqual([receipt!]);
    await access(join(receipt!["outputDir"] as string, "report.md"));
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    await expect(access(lock)).rejects.toThrow();
  });

  test("recovers a legacy supervisor lock when this live PID was reused", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-pid-reuse");
    await writeFile(
      paths.input,
      `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(ownerPath, JSON.stringify({ pid: process.pid }), {
      mode: 0o600,
    });
    const beforeProcessStarted = new Date(performance.timeOrigin - 60_000);
    await utimes(ownerPath, beforeProcessStarted, beforeProcessStarted);

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          completedScan(scanOptions.outputDir!),
        ),
      ),
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
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(ownerPath, JSON.stringify({ pid: process.pid }), {
      mode: 0o600,
    });

    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      ),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect(JSON.parse(await readFile(ownerPath, "utf8"))).toEqual({
      pid: process.pid,
    });
  });

  for (const previousHostname of [hostname(), "previous-container"]) {
    test(`recovers an expired supervisor lease from ${previousHostname === hostname() ? "a reused live PID" : "a replacement container"}`, async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "expired-supervisor");
      await writeFile(
        paths.input,
        `id,repository,revision\nexpired,${source.path},${source.revision}\n`,
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
        options(
          paths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(lock)).rejects.toThrow();
    });
  }

  test("does not reclaim a live supervisor in another container", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "remote-supervisor");
    await writeFile(
      paths.input,
      `id,repository,revision\nremote,${source.path},${source.revision}\n`,
    );
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
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      ),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect(JSON.parse(await readFile(ownerPath, "utf8"))).toMatchObject({
      ownerId: "live-remote-supervisor",
    });
  });

  test("recovers interrupted lock creation without an owner record", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "interrupted-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\ninterrupted,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    const expired = new Date(Date.now() - 120_000);
    await utimes(lock, expired, expired);

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          completedScan(scanOptions.outputDir!),
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
  });

  test("preserves a supervisor lock while its owner record is being created", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "initializing-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\ninitializing,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });

    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      ),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect((await lstat(lock)).isDirectory()).toBe(true);
  });

  test("recovers an interrupted stale-lock recovery claim", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "interrupted-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\ninterrupted,${source.path},${source.revision}\n`,
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
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          completedScan(scanOptions.outputDir!),
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
  });

  test("allows only one supervisor to recover an abandoned lock", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "recovery-race");
    await writeFile(
      paths.input,
      `id,repository,revision\nrace,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
      {
        mode: 0o600,
      },
    );
    let started!: () => void;
    let release!: () => void;
    const running = new Promise<void>((resolve) => {
      started = resolve;
    });
    const finish = new Promise<void>((resolve) => {
      release = resolve;
    });
    let active = 0;
    let maximum = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      active += 1;
      maximum = Math.max(maximum, active);
      started();
      await finish;
      active -= 1;
      return completedScan(scanOptions.outputDir!);
    });
    const contenders = Promise.allSettled([
      runMultiscan(options(paths, security)),
      runMultiscan(options(paths, security)),
    ]);

    await running;
    release();
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
    const paths = await fixture();
    const source = await repository(paths.root, "replacement-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\nreplacement,${source.path},${source.revision}\n`,
    );
    let started!: () => void;
    let release!: () => void;
    const running = new Promise<void>((resolve) => {
      started = resolve;
    });
    const finish = new Promise<void>((resolve) => {
      release = resolve;
    });
    const first = runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          started();
          await finish;
          return completedScan(scanOptions.outputDir!);
        }),
      ),
    );
    await running;
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

    release();
    await first;

    expect(
      JSON.parse(await readFile(join(lock, "owner.json"), "utf8")),
    ).toEqual(replacement);
  });

  test("removes an empty supervisor lock when owner creation fails", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "owner-creation-failure");
    await writeFile(
      paths.input,
      `id,repository,revision\nfailure,${source.path},${source.revision}\n`,
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
    const security = client(async (_repository, scanOptions = {}) =>
      completedScan(scanOptions.outputDir!),
    );

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
    "never removes a replacement lock when owner creation fails (owner published: %s)",
    async (ownerPublished) => {
      const paths = await fixture();
      const source = await repository(paths.root, "owner-creation-race");
      await writeFile(
        paths.input,
        `id,repository,revision\nrace,${source.path},${source.revision}\n`,
      );
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      const replacement = JSON.stringify({
        pid: process.pid,
        ownerId: "replacement-supervisor",
        hostname: hostname(),
        processStartedAt: performance.timeOrigin,
      });
      const originalWriteFile = filesystem.writeFile;
      const writeOwner = spyOn(filesystem, "writeFile").mockImplementation(
        async (path, data, options) => {
          if (String(path) !== ownerPath) {
            return await originalWriteFile(path, data, options);
          }
          writeOwner.mockRestore();
          await rename(lock, join(paths.output, ".lock.stale-owner-creation"));
          await mkdir(lock, { mode: 0o700 });
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
          runMultiscan(
            options(
              paths,
              client(async (_repository, scanOptions = {}) =>
                completedScan(scanOptions.outputDir!),
              ),
            ),
          ),
        ).rejects.toThrow("replacement already owns the lock");
        await access(lock);
        if (ownerPublished) {
          expect(await readFile(ownerPath, "utf8")).toBe(replacement);
        }
      } finally {
        writeOwner.mockRestore();
      }
    },
  );

  test("retries a failed attempt and records both durable receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "retry");
    const secret = "sk-proj-SYNTHETIC_MULTISCAN_SECRET_123";
    const knowledgeBasePaths = ["architecture.md"];
    const proxyUrl =
      "https://SYNTHETIC_USER:SYNTHETIC_MULTISCAN_PASSWORD@proxy.test/v1/responses";
    const queryUrl =
      "https://proxy.test/v1/responses?api_key=SYNTHETIC_MULTISCAN_QUERY_123&safe=1";
    const shortAuthorization = "Bearer abc123";
    const suffixedSecret = "SYNTHETIC_SUFFIXED_CLIENT_SECRET_123";
    const suffixedToken = "SYNTHETIC_SUFFIXED_ACCESS_TOKEN_123";
    const suffixedQuery = "SYNTHETIC_SUFFIXED_QUERY_SECRET_123";
    const quotedSecret = "SYNTHETIC correct horse battery staple";
    const opaqueAuthorization = "SYNTHETIC opaque authorization secret";
    const npmAuthorization = "SYNTHETIC_NPM_AUTH_VALUE_123";
    const customAuthorization = "SYNTHETIC_CUSTOM_AUTHORIZATION_123";
    const suffixedAuthorization = "SYNTHETIC_SUFFIXED_AUTHORIZATION_123";
    const paddedAuthorization = "SYNTHETIC_PADDED_AUTHORIZATION_TOKEN==";
    const keyedAuthorization = "SYNTHETIC_KEYED_AUTHORIZATION_SECRET_123";
    const camelCaseSecret = "SYNTHETIC_CAMEL_CASE_CLIENT_SECRET_123";
    await writeFile(
      paths.input,
      `id,repository,revision\nretry,${source.path},${source.revision}\n`,
    );

    let attempts = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
          attempts += 1;
          if (attempts === 1) {
            throw new Error(
              `temporary failure ${secret} ${shortAuthorization} client_secret_value=${suffixedSecret} access_token_value=${suffixedToken} ${JSON.stringify({ client_secret_value: quotedSecret })} authorization="${opaqueAuthorization}" _auth=${npmAuthorization} Authorization: ApiKey ${customAuthorization} client_authorization_value=ApiKey ${suffixedAuthorization} auth=ApiKey ${paddedAuthorization} Authorization: Custom key=${keyedAuthorization} clientSecretValue=${camelCaseSecret} sending request for url (${proxyUrl}) and ${queryUrl}&client_secret_value=${suffixedQuery}`,
            );
          }
          return await completedScan(scanOptions.outputDir!);
        }),
        { knowledgeBasePaths },
      ),
    );

    expect(attempts).toBe(2);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "retry", status: "failed", attempt: 1 },
      { id: "retry", status: "completed", attempt: 2 },
    ]);
    const ledger = await readFile(summary.resultsPath, "utf8");
    expect(ledger).toContain('"error":"[redacted]"');
    expect(ledger).not.toContain("SYNTHETIC");
  });

  test.each(["complete", "partial", "failed"] as const)(
    "preserves the %s scan outcome when checkout cleanup fails",
    async (outcome) => {
      const failed = outcome === "failed";
      const expected = {
        completed: outcome === "complete" ? 1 : 0,
        incomplete: outcome === "partial" ? 1 : 0,
        failed: failed ? 1 : 0,
        warned: 1,
      };
      const paths = await fixture();
      const source = await repository(paths.root, "cleanup-failure");
      await writeFile(
        paths.input,
        `id,repository,revision\ncleanup,${source.path},${source.revision}\n`,
      );
      const checkout = join(paths.output, "checkouts", "cleanup");
      const originalRm = filesystem.rm;
      let scanned = false;
      const remove = spyOn(filesystem, "rm").mockImplementation(
        async (...args: Parameters<typeof originalRm>) => {
          if (scanned && String(args[0]) === checkout) {
            throw Object.assign(new Error("EACCES: checkout is in use"), {
              code: "EACCES",
            });
          }
          return await originalRm(...args);
        },
      );

      try {
        const summary = await runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scanned = true;
              if (outcome === "failed") {
                throw new Error("Original scan failure.");
              }
              return await completedScan(scanOptions.outputDir!, outcome);
            }),
            { maxAttempts: 1 },
          ),
        );

        expect(summary).toMatchObject(expected);
        expect(await results(summary.resultsPath)).toMatchObject([
          {
            status: failed
              ? "failed"
              : outcome === "complete"
                ? "completed"
                : "completed_with_incomplete_coverage",
            attempt: 1,
            ...(failed ? { error: "Original scan failure." } : {}),
            warnings: [
              "Multiscan checkout cleanup failed: EACCES: checkout is in use",
            ],
          },
        ]);
      } finally {
        remove.mockRestore();
      }

      if (!failed) {
        const ledgerPath = join(paths.output, "results.jsonl");
        const ledger = await readFile(ledgerPath, "utf8");
        const resumed = await runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) =>
              completedScan(scanOptions.outputDir!),
            ),
          ),
        );
        expect(resumed).toMatchObject({
          ...expected,
          skipped: 1,
        });
        expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
        expect(await readFile(ledgerPath, "utf8")).toBe(ledger);
      }
    },
  );

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

  test.each(["complete", "partial"] as const)(
    "binds sealed %s worktree snapshots to their validated attempt receipts",
    async (completeness) => {
      const paths = await fixture();
      const source = await repository(paths.root, "worktree-snapshot");
      await writeFile(
        paths.input,
        `id,repository,revision\nworktree,${source.path},${source.revision}\n`,
      );
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return await completedScan(
          scanOptions.outputDir!,
          completeness,
          "git_worktree",
        );
      });
      const outcome =
        completeness === "complete"
          ? { completed: 1, incomplete: 0 }
          : { completed: 0, incomplete: 1 };

      const first = await runMultiscan(options(paths, security));
      const [originalReceipt] = await results(first.resultsPath);
      const originalDigest = originalReceipt!["snapshotDigest"];
      const originalTargetId = originalReceipt!["targetId"];
      expect(originalDigest).toMatch(
        /^codex-security-snapshot\/v1:sha256:[a-f\d]{64}$/,
      );
      expect(originalTargetId).toMatch(/^target_sha256_[a-f\d]{64}$/);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        ...outcome,
        skipped: 1,
      });
      expect(attempts).toBe(1);

      delete originalReceipt!["targetId"];
      await writeFile(
        first.resultsPath,
        `${JSON.stringify(originalReceipt)}\n`,
      );
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        ...outcome,
        skipped: 1,
      });
      expect(attempts).toBe(1);

      const manifestPath = join(
        originalReceipt!["outputDir"] as string,
        "scan-manifest.json",
      );
      const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
        scan: { target: { snapshotDigest: string } };
      };
      manifest.scan.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      await reseal(originalReceipt!["outputDir"] as string);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        ...outcome,
        skipped: 0,
      });
      expect(attempts).toBe(2);

      const receipts = await results(first.resultsPath);
      delete receipts.at(-1)!["snapshotDigest"];
      await writeFile(
        first.resultsPath,
        `${receipts.map((receipt) => JSON.stringify(receipt)).join("\n")}\n`,
      );
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        ...outcome,
        skipped: 0,
      });
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        ...outcome,
        skipped: 1,
      });
      expect(attempts).toBe(3);
      expect((await results(first.resultsPath)).at(-1)).toMatchObject({
        status:
          completeness === "complete"
            ? "completed"
            : "completed_with_incomplete_coverage",
        targetId: originalTargetId,
        snapshotDigest: originalDigest,
      });
    },
  );

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
        warned: 0,
        skipped: 1,
      });

      const [legacy] = await results(first.resultsPath);
      delete legacy!["targetId"];
      delete legacy!["resolvedScope"];
      const ledger = `${JSON.stringify(legacy)}\n`;
      await writeFile(first.resultsPath, ledger);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        warned: 0,
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
      warned: 0,
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
    let calls = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      calls += 1;
      return await completedScan(scanOptions.outputDir!);
    });

    const initial = await runMultiscan(options(paths, security));
    await appendFile(initial.resultsPath, '{"id":"interrupted"');
    const resumed = await runMultiscan(options(paths, security));
    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(calls).toBe(1);
    for (const prompts of [
      { scanPrompt: "Review different boundaries." },
      { postScanPrompt: "Draft confirmed fixes." },
      { maxCostUsd: 12.5 },
    ]) {
      await expect(
        runMultiscan(options(paths, security, prompts)),
      ).rejects.toThrow("manifest does not match");
    }
    expect(calls).toBe(1);

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
    expect(calls).toBe(1);
    expect(await readFile(reportPath)).toEqual(report);
    expect(
      await Promise.all(canonicalPaths.map((path) => readFile(path))),
    ).toEqual(canonical);
    expect(await readFile(repaired.resultsPath, "utf8")).toBe(ledger);

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(calls).toBe(1);
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
        "Multiscan report recovery is required: [redacted]",
      );
      expect(resolvePython).toHaveBeenCalledWith(
        expect.objectContaining({
          additionalProtectedRoots: expect.arrayContaining([
            paths.output,
            source.path,
            await outermostGitMarkerRoot(await realpath(process.cwd())),
          ]),
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

  test("ignores repository-local Git shims while preserving credential configuration", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "private");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
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
    const paths = await fixture();
    const source = await repository(paths.root, "isolated");
    const trace = join(paths.root, "git-events.jsonl");
    await writeFile(
      paths.input,
      `id,repository,revision\nisolated,${source.path},${source.revision}\n`,
    );
    const repositoryVariables = [
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

      const summary = await runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      );
      expect(summary).toMatchObject({ completed: 1, failed: 0 });

      const leakedVariables = (await readFile(trace, "utf8"))
        .trim()
        .split("\n")
        .map(
          (line) =>
            JSON.parse(line) as {
              event: string;
              param?: string;
              value?: string;
            },
        )
        .filter(
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
      const paths = await fixture();
      const source = await repository(paths.root, "victim");
      await writeFile(
        paths.input,
        `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
      );
      const external = join(paths.root, "external");
      const preserved = join(external, "victim", "keep.txt");
      await mkdir(join(external, "victim"), { recursive: true });
      await writeFile(preserved, "preserved\n");
      if (directory) await mkdir(paths.output);
      await symlink(
        external,
        directory ? join(paths.output, directory) : paths.output,
      );

      let scans = 0;
      await expect(
        runMultiscan(
          options(
            paths,
            client(async (_repository, scanOptions = {}) => {
              scans += 1;
              return await completedScan(scanOptions.outputDir!);
            }),
          ),
        ),
      ).rejects.toThrow("symbolic links");
      expect(scans).toBe(0);
      expect(await readFile(preserved, "utf8")).toBe("preserved\n");
    }
  });

  test("rejects linked task artifact directories without touching external files", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "victim");
    await writeFile(
      paths.input,
      `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
    );
    const external = join(paths.root, "external");
    await mkdir(external);
    await writeFile(join(external, "preserved.txt"), "preserved\n");
    await mkdir(join(paths.output, "artifacts"), { recursive: true });
    await symlink(
      external,
      join(paths.output, "artifacts", "victim"),
      process.platform === "win32" ? "junction" : "dir",
    );

    let scans = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          scans += 1;
          return await completedScan(scanOptions.outputDir!);
        }),
        { maxAttempts: 1 },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 0, failed: 1 });
    expect(scans).toBe(0);
    expect((await results(summary.resultsPath))[0]?.["error"]).toContain(
      "symbolic links",
    );
    expect(await readdir(external)).toEqual(["preserved.txt"]);
    expect(await readFile(join(external, "preserved.txt"), "utf8")).toBe(
      "preserved\n",
    );
  });

  test("rejects linked task artifacts before accepting completed receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "victim");
    await writeFile(
      paths.input,
      `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
    );
    const external = join(paths.root, "external");
    await completedScan(join(external, "attempt-1"));
    await mkdir(join(paths.output, "artifacts"), { recursive: true });
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

    let scans = 0;
    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            scans += 1;
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      ),
    ).rejects.toThrow("symbolic links");
    expect(scans).toBe(0);
    expect(await readdir(external)).toEqual(["attempt-1"]);
  });

  testPosix(
    "rejects other-user-writable campaigns while preserving readable existing campaigns",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "sample");
      await writeFile(
        paths.input,
        `id,repository,revision\nsample,${source.path},${source.revision}\n`,
      );
      await mkdir(paths.output, { mode: 0o755 });
      let scans = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        scans += 1;
        return await completedScan(scanOptions.outputDir!);
      });

      for (const mode of [0o770, 0o777]) {
        await chmod(paths.output, mode);
        await expect(runMultiscan(options(paths, security))).rejects.toThrow(
          "must not be group- or world-writable",
        );
        expect(scans).toBe(0);
      }

      await chmod(paths.output, 0o755);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        total: 1,
        completed: 1,
        failed: 0,
      });
      expect(scans).toBe(1);
    },
  );

  testPosix("rejects campaigns beneath an unsafe shared parent", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const parent = join(paths.root, "shared");
    await mkdir(parent, { mode: 0o777 });
    await chmod(parent, 0o777);
    let scans = 0;

    await expect(
      runMultiscan(
        options(
          paths,
          client(async (_repository, scanOptions = {}) => {
            scans += 1;
            return await completedScan(scanOptions.outputDir!);
          }),
          { outputDir: join(parent, "results") },
        ),
      ),
    ).rejects.toThrow(
      "must not be group- or world-writable without the sticky bit",
    );
    expect(scans).toBe(0);
  });

  test("preserves trusted user-selected campaign parent aliases", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const canonicalParent = join(paths.root, "campaigns");
    const linkedParent = join(paths.root, "linked-campaigns");
    await mkdir(canonicalParent);
    await symlink(
      canonicalParent,
      linkedParent,
      process.platform === "win32" ? "junction" : "dir",
    );
    const output = join(linkedParent, "results");
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });

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
    expect(scans).toBe(1);
    expect(await readdir(join(canonicalParent, "results"))).toContain(
      "results.jsonl",
    );
  });

  test("keeps campaign operations on their validated canonical directory", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const canonicalParent = join(paths.root, "campaigns");
    const redirectedParent = join(paths.root, "redirected");
    const linkedParent = join(paths.root, "linked-campaigns");
    await mkdir(canonicalParent);
    await mkdir(join(redirectedParent, "results"), { recursive: true });
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
    let scans = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      scans += 1;
      return await completedScan(scanOptions.outputDir!);
    });

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

    expect(scans).toBe(0);
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
