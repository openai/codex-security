import { execFileSync } from "node:child_process";
import {
  access,
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { main } from "../src/cli.js";
import type { ScanResult } from "../src/result.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const temporaryDirectories: string[] = [];

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
  const root = await mkdtemp(join(tmpdir(), "codex-security-multiscan-"));
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
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true });
  await Promise.all(
    ["scan-manifest.json", "findings.json", "coverage.json", "report.md"].map(
      (name) => writeFile(join(outputDir, name), "{}\n"),
    ),
  );
  return { coverage: { completeness } } as ScanResult;
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
          return await completedScan(scanOptions.outputDir!);
        }),
        {
          scanPrompt: "Review boundaries.",
          postScanPrompt: "Draft confirmed fixes.",
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
        options(paths, security, { maxAttempts: 3 }),
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
      await writeFile(
        join(outputDir, "coverage.json"),
        `${JSON.stringify({ completeness })}\n`,
      );
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
      await completedScan(outputDir, completeness);
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
        result: fakeResult([], completeness),
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
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
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

  test("resumes complete bundles, repairs missing output, and rejects manifest drift", async () => {
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
    ]) {
      await expect(
        runMultiscan(options(paths, security, prompts)),
      ).rejects.toThrow("manifest does not match");
    }
    expect(calls).toBe(1);

    const [receipt] = await results(initial.resultsPath);
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    const repaired = await runMultiscan(options(paths, security));
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(calls).toBe(2);
    expect((await results(repaired.resultsPath)).at(-1)?.["outputDir"]).toBe(
      join(paths.output, "artifacts", "resume", "attempt-2"),
    );

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(calls).toBe(2);
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
