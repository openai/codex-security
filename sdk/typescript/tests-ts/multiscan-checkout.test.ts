import { gitText } from "./support/shell.js";
import { parseJsonLines } from "./support/json.js";
import { execFileSync } from "node:child_process";
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
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { normalizeTarget } from "../src/targets.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { rejecting } from "./support/errors.js";
import {
  type SecurityClient,
  type MultiscanOptions,
  createMultiscanFixtures,
  git,
  repository,
  completedScan,
  completeRun,
  client,
  options,
  results,
} from "./support/multiscan.js";

const { temporaryDirectory, fixture, repositoryFixture, cleanup } =
  createMultiscanFixtures();
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

    const damaged = await readFile(ledger);
    await expect(runMultiscan(configured)).rejects.toThrow(
      "invalid campaign receipt",
    );
    expect(await readFile(ledger)).toEqual(damaged);
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

    const summary = await runMultiscan(options(paths, client(completeRun)));

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
      runMultiscan(options(paths, client(completeRun))),
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

      const summary = await runMultiscan(options(paths, client(completeRun)));

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
      runMultiscan(options(paths, client(completeRun))),
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

    const summary = await runMultiscan(options(paths, client(completeRun)));

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
      runMultiscan(options(paths, client(completeRun))),
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

    const summary = await runMultiscan(options(paths, client(completeRun)));

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
    const security = client(completeRun);

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
          runMultiscan(options(paths, client(completeRun))),
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
        import.meta.path,
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

      const summary = await runMultiscan(options(paths, client(completeRun)));
      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      const resumed = await runMultiscan(options(paths, client(completeRun)));
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
