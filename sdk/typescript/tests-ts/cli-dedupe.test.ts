import { expect, test } from "bun:test";
import { CodexSecurityError } from "../src/errors.js";
import { main } from "../src/cli.js";
import { deduplicateScanDirectoryInternal } from "../src/deduplication/scan.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { workflowFixture } from "./support/workflow-fixture.js";

const args = [
  "dedupe",
  "--scan",
  "latest",
  "--findings-url",
  "http://127.0.0.1:3000",
  "--json",
];

test("dedupe resolves a workflow's pinned scan and passes the workflow ID to the SDK", async () => {
  const deps = dependencies();
  deps.runWorkbench = async (args, input) => {
    expect(args).toEqual(["finding-workflow"]);
    expect(JSON.parse(input!)).toEqual({
      id: "workflow-example",
      action: "get",
    });
    return {
      workflow: {
        id: "workflow-example",
        scanId: "exact-scan",
        scanDir: "/synthetic/artifacts",
      },
    };
  };
  deps.deduplicateScan = async (scanId, options) => {
    expect(scanId).toBe("exact-scan");
    expect(options.workflowId).toBe("workflow-example");
    return {
      scanId,
      uniqueFindingIds: [],
      duplicateGroups: [],
      deduplicationStatus: "completed",
    };
  };
  const stdout = capture();
  expect(
    await main(
      [
        "dedupe",
        "--workflow-id",
        "workflow-example",
        "--findings-url",
        "http://localhost:3000",
        "--json",
      ],
      stdout.stream,
      capture().stream,
      deps,
    ),
  ).toBe(0);
  expect(JSON.parse(stdout.text())).toEqual({
    scanId: "exact-scan",
    uniqueFindingIds: [],
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
});

test.each([false, true])(
  "dedupe exposes the accepted publication receipt and warning (json=%j)",
  async (json) => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    const result = {
      scanId: "scan-example",
      uniqueFindingIds: ["finding-example"],
      duplicateGroups: [],
      deduplicationStatus: "completed" as const,
      publication: {
        scanId: "scan-example",
        repositoryId: "repository-example",
        findingIds: ["finding-example"],
        findingCount: 1,
        warnings: [
          "The server accepted the upload; keep this receipt because its checkpoint failed.",
        ],
      },
    };
    deps.deduplicateScan = async () => result;
    expect(
      await main(
        args.filter((arg) => json || arg !== "--json"),
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    if (json) expect(JSON.parse(stdout.text())).toEqual(result);
    else {
      expect(stdout.text()).toContain("publication:");
      expect(stdout.text()).toContain("repository-example");
      expect(stdout.text()).toContain("finding-example");
    }
    expect(stderr.text()).toContain(result.publication.warnings[0]!);
  },
);

test.each([false, true])(
  "dedupe returns a failed receipt envelope without hiding the review error (json=%j)",
  async (json) => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    const failure = new CodexSecurityError("Review disconnected");
    failure.publication = {
      scanId: "scan-example",
      repositoryId: "repository-example",
      findingIds: ["finding-example"],
      findingCount: 1,
      warnings: ["The server accepted the upload; its checkpoint failed."],
    };
    deps.deduplicateScan = async () => {
      throw failure;
    };
    expect(
      await main(
        args.filter((arg) => json || arg !== "--json"),
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    if (json)
      expect(JSON.parse(stdout.text())).toEqual({
        scanId: "scan-example",
        deduplicationStatus: "failed",
        publication: failure.publication,
      });
    else {
      expect(stdout.text()).toContain("failed");
      expect(stdout.text()).toContain("repository-example");
      expect(stdout.text()).toContain("finding-example");
    }
    expect(stderr.text()).toContain("Review disconnected");
    expect(stderr.text()).toContain(failure.publication.warnings![0]!);
  },
);

test("dedupe retains the accepted receipt with a primitive SIGINT reason", async () => {
  const signals = new FakeSignals();
  const deps = dependencies();
  deps.addSignalListener = (name, listener) => signals.add(name, listener);
  deps.removeSignalListener = (name, listener) =>
    signals.remove(name, listener);
  const publication = {
    scanId: "scan-example",
    repositoryId: "repository-example",
    findingIds: ["finding-example"],
    findingCount: 1,
    warnings: ["The server accepted the upload; its checkpoint failed."],
  };
  deps.deduplicateScan = async (_scanId, options, dependencies) => {
    await dependencies?.onPublication?.(publication);
    signals.emit("SIGINT");
    options.signal!.throwIfAborted();
    throw new Error("Cancellation must throw");
  };
  const stdout = capture();
  const stderr = capture();
  expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(130);
  expect(JSON.parse(stdout.text())).toEqual({
    scanId: "scan-example",
    deduplicationStatus: "failed",
    publication,
  });
  expect(stderr.text()).toContain("Deduplication canceled");
  expect(stderr.text()).toContain(publication.warnings[0]!);
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
});

test.each([
  ["SIGINT", 130, true],
  ["SIGTERM", 143, false],
] as const)(
  "cached dedupe retains the accepted receipt and cancellation after %s",
  async (signal, expectedCode, json) => {
    await using fixture = await workflowFixture();
    const { scanDir, repository, environment, document } = fixture;
    const workflowId = "cached-publication-cancellation";
    const findingIds = document.findings.map((finding) => finding.findingId);
    const signals = new FakeSignals();
    let failCompletion = true;
    let cancelCompletion = false;
    let searches = 0;
    const keys: (string | null)[] = [];
    const execute = async (args: string[], input?: string) => {
      const request = JSON.parse(input!);
      if (
        failCompletion &&
        request.action === "complete" &&
        request.stage === "publish"
      ) {
        if (cancelCompletion) signals.emit(signal);
        throw new Error("publication checkpoint unavailable");
      }
      return runWorkbench(
        {
          environment,
          pluginRoot: PLUGIN_ROOT,
          python: Bun.which("python3") ?? Bun.which("python")!,
        },
        args,
        input,
      );
    };
    const sdkDependencies = {
      environment,
      runWorkbench: execute,
      fetch: async (url: URL, init: RequestInit) => {
        if (url.pathname === "/v1/bulk/findings") {
          keys.push(new Headers(init.headers).get("Idempotency-Key"));
          return Response.json(findingIds, { status: 201 });
        }
        expect(url.pathname).toEndWith("/potential-duplicates");
        searches++;
        return Response.json({
          finding: document.findings[0],
          potentialDuplicates: [],
        });
      },
    };
    const options = {
      workflowId,
      findingsUrl: "http://synthetic.test",
      repository,
    };
    const { publication, ...completed } =
      await deduplicateScanDirectoryInternal(scanDir, options, sdkDependencies);
    expect(publication?.warnings).toEqual([
      expect.stringContaining("publication checkpoint unavailable"),
    ]);
    expect(completed.deduplicationStatus).toBe("completed");
    expect(searches).toBe(findingIds.length);

    const deps = dependencies({ environment });
    deps.runWorkbench = execute;
    deps.addSignalListener = (name, listener) => signals.add(name, listener);
    deps.removeSignalListener = (name, listener) =>
      signals.remove(name, listener);
    let caught: unknown;
    deps.deduplicateScan = async (_scanId, options, internal) => {
      try {
        return await deduplicateScanDirectoryInternal(
          scanDir,
          { ...options, repository },
          { ...internal, ...sdkDependencies },
        );
      } catch (error) {
        caught = error;
        throw error;
      }
    };
    const command = [
      "dedupe",
      "--scan",
      document.scanId,
      "--workflow-id",
      workflowId,
      "--findings-url",
      options.findingsUrl,
      ...(json ? ["--json"] : []),
    ];
    const stdout = capture();
    const stderr = capture();
    cancelCompletion = true;
    expect(await main(command, stdout.stream, stderr.stream, deps)).toBe(
      expectedCode,
    );
    expect(caught).toBe(signal);
    if (json) {
      expect(JSON.parse(stdout.text())).toEqual({
        scanId: document.scanId,
        deduplicationStatus: "failed",
        publication,
      });
    } else {
      expect(stdout.text()).toContain("failed");
      expect(stdout.text()).toContain(publication!.repositoryId);
      for (const id of findingIds) expect(stdout.text()).toContain(id);
    }
    expect(stderr.text()).toContain("Deduplication canceled");
    expect(stderr.text()).toContain("publication checkpoint unavailable");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    const workflow = new FindingWorkflow(workflowId, environment);
    expect((await workflow.get())!.stages.dedupe).toMatchObject({
      status: "completed",
      result: completed,
    });
    expect(searches).toBe(findingIds.length);

    failCompletion = false;
    const retried = capture();
    const retryErrors = capture();
    expect(
      await main(
        [...command.filter((arg) => arg !== "--json"), "--json"],
        retried.stream,
        retryErrors.stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(retried.text())).toEqual(completed);
    expect(retryErrors.text()).toBe("");
    expect((await workflow.get())!.stages.publish.status).toBe("completed");
    expect(searches).toBe(findingIds.length);
    expect(keys).toHaveLength(3);
    expect(new Set(keys).size).toBe(1);
  },
);

test.each([false, true])(
  "dedupe passes the scan selector, URL, and all-repository scope %j to the SDK",
  async (allRepositories) => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    const result = {
      scanId: "scan-example",
      uniqueFindingIds: ["finding-example"],
      duplicateGroups: [],
      deduplicationStatus: "completed" as const,
    };
    deps.deduplicateScan = async (scanId, options, dependencies) => {
      expect(scanId).toBe("latest");
      expect(options).toEqual({
        findingsUrl: "http://127.0.0.1:3000",
        allRepositories,
        signal: expect.any(AbortSignal),
      });
      expect(dependencies?.runWorkbench).toBe(deps.runWorkbench);
      return result;
    };
    expect(
      await main(
        [...args, ...(allRepositories ? ["--all-repositories"] : [])],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toBe("");
  },
);

test("dedupe requires both explicit inputs and reports SDK failures", async () => {
  const deps = dependencies();
  let called = false;
  deps.deduplicateScan = async () => {
    called = true;
    throw new Error("Finding has not been indexed");
  };
  for (const flags of [
    [],
    ["--scan", "latest"],
    ["--findings-url", "http://127.0.0.1:3000"],
  ]) {
    expect(
      await main(
        ["dedupe", ...flags],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).not.toBe(0);
  }
  expect(called).toBe(false);
  const stdout = capture();
  const stderr = capture();
  expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(2);
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain("Finding has not been indexed");
});

test("dedupe forwards cancellation and removes signal handlers", async () => {
  for (const [signal, expectedCode] of [
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const) {
    const signals = new FakeSignals();
    const deps = dependencies();
    deps.addSignalListener = (name, listener) => signals.add(name, listener);
    deps.removeSignalListener = (name, listener) =>
      signals.remove(name, listener);
    deps.deduplicateScan = async (_scanId, options, internal) => {
      signals.emit(signal);
      await internal?.onRecovery?.({
        scanId: "saved-scan",
        operationId: "dedupe-canceled",
        findingsUrl: "http://127.0.0.1:3000/",
        allRepositories: false,
        phase: "screening",
        findingIds: [],
        candidateCount: 1,
        reviewCount: 2,
        findingCount: 1,
        pendingWrite: false,
      });
      options.signal!.throwIfAborted();
      throw new Error("Cancellation must throw");
    };
    const stdout = capture();
    const stderr = capture();
    expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(
      expectedCode,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Deduplication canceled");
    expect(stderr.text()).toContain(
      "Saved 2 validated reviews and 1/1 candidate neighborhoods",
    );
    expect(stderr.text()).toContain("--workflow-id dedupe-canceled");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  }
});

test.each(["--help", "--json"])(
  "dedupe recovery commands replay the accepted workflow ID %s",
  async (workflowId) => {
    const deps = dependencies();
    let calls = 0;
    deps.deduplicateScan = async (scanId, options) => {
      calls++;
      expect(scanId).toBe("saved-scan");
      expect(options.workflowId).toBe(workflowId);
      if (calls === 1) {
        const failure = new CodexSecurityError("Synthetic review failure");
        failure.deduplicationRecovery = {
          scanId,
          operationId: workflowId,
          findingsUrl: options.findingsUrl,
          allRepositories: false,
          phase: "screening",
          findingIds: [],
          findingCount: 1,
          pendingWrite: false,
        };
        throw failure;
      }
      return {
        scanId,
        uniqueFindingIds: [],
        duplicateGroups: [],
        deduplicationStatus: "completed",
      };
    };
    const stderr = capture();
    expect(
      await main(
        [
          "dedupe",
          "--scan",
          "saved-scan",
          `--workflow-id=${workflowId}`,
          "--findings-url",
          "http://127.0.0.1:3000/",
        ],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    const retry = stderr
      .text()
      .match(/^Resume(?: \(PowerShell\))?: (.+)$/mu)![1]!;
    expect(
      await main(
        retry.split(" ").slice(1),
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls).toBe(2);
  },
);

test.skipIf(process.platform === "win32" || Bun.which("zsh") === null)(
  "dedupe recovery preserves a leading equals sign through zsh",
  async () => {
    const deps = dependencies();
    const failure = new CodexSecurityError("Synthetic review failure");
    failure.deduplicationRecovery = {
      scanId: "saved-scan",
      operationId: "=ls",
      findingsUrl: "http://127.0.0.1:3000/",
      allRepositories: false,
      phase: "screening",
      findingIds: [],
      findingCount: 1,
      pendingWrite: false,
    };
    deps.deduplicateScan = async () => {
      throw failure;
    };
    const stderr = capture();
    expect(await main(args, capture().stream, stderr.stream, deps)).toBe(2);
    const retry = stderr.text().match(/^Resume: (.+)$/mu)![1]!;
    const parsed = Bun.spawnSync([
      Bun.which("zsh")!,
      "-f",
      "-c",
      `set -- ${retry}\nprintf '%s\\0' "$@"`,
    ]);
    expect(parsed.exitCode, parsed.stderr.toString()).toBe(0);
    const recoveredArgs = parsed.stdout.toString().split("\0").slice(1, -1);
    deps.deduplicateScan = async (scanId, options) => {
      expect(scanId).toBe("saved-scan");
      expect(options.workflowId).toBe("=ls");
      return {
        scanId,
        uniqueFindingIds: [],
        duplicateGroups: [],
        deduplicationStatus: "completed",
      };
    };
    expect(
      await main(recoveredArgs, capture().stream, capture().stream, deps),
    ).toBe(0);
  },
);

test("dedupe reports committed work and a pinned retry without implicitly publishing", async () => {
  const deps = dependencies();
  const failure = new CodexSecurityError("Synthetic lost acknowledgement");
  failure.deduplicationRecovery = {
    scanId: "saved-scan",
    operationId: "dedupe-example",
    findingsUrl: "http://127.0.0.1:3000/",
    allRepositories: true,
    phase: "groups",
    findingIds: [],
    candidateCount: 4,
    reviewCount: 6,
    findingCount: 4,
    pendingWrite: true,
    diagnosticsPath: "/synthetic/review.json",
  };
  deps.deduplicateScan = async () => {
    throw failure;
  };
  const stdout = capture();
  const stderr = capture();
  expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(2);
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain(
    "Saved 6 validated reviews and 4/4 candidate neighborhoods",
  );
  expect(stderr.text()).toContain("acknowledgement is not confirmed");
  expect(stderr.text()).toContain("/synthetic/review.json");
  expect(stderr.text()).toContain(
    "codex-security dedupe --scan saved-scan --workflow-id dedupe-example --findings-url http://127.0.0.1:3000/ --all-repositories",
  );
});

test("dedupe quotes a leading at sign in PowerShell recovery arguments", async () => {
  const deps = dependencies();
  const failure = new CodexSecurityError("Synthetic review failure");
  failure.deduplicationRecovery = {
    scanId: "saved-scan",
    operationId: "@review",
    findingsUrl: "http://127.0.0.1:3000/",
    allRepositories: false,
    phase: "screening",
    findingIds: [],
    findingCount: 1,
    pendingWrite: false,
  };
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  deps.deduplicateScan = async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    throw failure;
  };
  const stderr = capture();
  try {
    expect(await main(args, capture().stream, stderr.stream, deps)).toBe(2);
    expect(stderr.text()).toContain(
      "Resume (PowerShell): codex-security dedupe --scan saved-scan --workflow-id '@review' --findings-url http://127.0.0.1:3000/",
    );
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
});

const powershell = Bun.which("pwsh") ?? Bun.which("powershell");
for (const quote of ["'", "\u2018", "\u2019", "\u201a", "\u201b"]) {
  test.skipIf(powershell === null)(
    `dedupe recovery preserves PowerShell quote U+${quote.codePointAt(0)!.toString(16)}`,
    async () => {
      const workflowId = `@review${quote}checkpoint`;
      const deps = dependencies();
      const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
      let calls = 0;
      deps.deduplicateScan = async (scanId, options) => {
        calls++;
        expect(scanId).toBe("saved-scan");
        expect(options.workflowId).toBe(workflowId);
        if (calls === 1) {
          const failure = new CodexSecurityError("Synthetic review failure");
          failure.deduplicationRecovery = {
            scanId,
            operationId: workflowId,
            findingsUrl: options.findingsUrl,
            allRepositories: false,
            phase: "screening",
            findingIds: [],
            findingCount: 1,
            pendingWrite: false,
          };
          Object.defineProperty(process, "platform", { value: "win32" });
          throw failure;
        }
        return {
          scanId,
          uniqueFindingIds: [],
          duplicateGroups: [],
          deduplicationStatus: "completed",
        };
      };
      const stderr = capture();
      try {
        expect(
          await main(
            [
              "dedupe",
              "--scan",
              "saved-scan",
              "--workflow-id",
              workflowId,
              "--findings-url",
              "http://127.0.0.1:3000/",
            ],
            capture().stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
      } finally {
        Object.defineProperty(process, "platform", platform);
      }
      const retry = stderr.text().match(/^Resume \(PowerShell\): (.+)$/mu)![1]!;
      const parsed = Bun.spawnSync([
        powershell!,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); function codex-security { ConvertTo-Json -InputObject @($args) -Compress }; ${retry}`,
      ]);
      expect(parsed.exitCode, parsed.stderr.toString()).toBe(0);
      const recoveredArgs = JSON.parse(parsed.stdout.toString());
      expect(recoveredArgs).toEqual([
        "dedupe",
        "--scan",
        "saved-scan",
        "--workflow-id",
        workflowId,
        "--findings-url",
        "http://127.0.0.1:3000/",
      ]);
      expect(
        await main(recoveredArgs, capture().stream, capture().stream, deps),
      ).toBe(0);
      expect(calls).toBe(2);
    },
  );
}
