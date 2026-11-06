import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runHostedScan, type HostedScanInput } from "../src/hosted-scan.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "../src/deep-scan-defaults.js";
import type { DeepScanOptions } from "../src/scan-settings.js";
import type {
  DeepScanExecutionRequest,
  HostedScanExecutor,
} from "../src/scan-executor.js";
import { git } from "./git-fixture.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures("hosted-deep-");
afterEach(cleanup);

async function fixture(scoped = false): Promise<
  Extract<HostedScanInput, { version: 3 }> & {
    deepScan: Required<DeepScanOptions>;
  }
> {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(join(repository, "service"), { recursive: true });
  await writeFile(
    join(repository, "service", "index.ts"),
    "export const value = 1;\n",
  );
  git(repository, "init", "-q");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "fixture");
  return {
    version: 3,
    mode: "deep",
    repository,
    revision: git(repository, "rev-parse", "HEAD"),
    ...(scoped ? { scope: { paths: ["service"] } } : {}),
    outputDirectory: join(root, "output"),
    stateDirectory: join(root, "state"),
    model: "fixture-model",
    reasoningEffort: "high",
    identity: { runId: "run", attemptId: "attempt", buildId: "fixture" },
    deepScan: {
      ...DEFAULT_DEEP_SCAN_SETTINGS,
      workers: 2,
      maxDiscoveryRuns: 2,
      stopAfterNoNew: 2,
      maxTimeHours: 0.1,
    },
  };
}

function discovery(
  request: Parameters<HostedScanExecutor["run"]>[0],
): DeepScanExecutionRequest {
  expect(request.version).toBe(3);
  if (request.version !== 3 || request.kind !== "discovery")
    throw new Error("Expected hosted discovery");
  expect(request.artifactContext?.layout).toBe("worker");
  return request;
}

async function writeDraft(
  request: DeepScanExecutionRequest,
  findingTitle?: string,
) {
  await writeFile(
    join(request.artifactContext!.root, "result.json"),
    JSON.stringify({
      scanId: request.scanId,
      complete: true,
      findings:
        findingTitle === undefined
          ? []
          : [
              {
                ruleId: "synthetic.query",
                title: findingTitle,
                summary: "Synthetic input reaches a query operation.",
                severity: { level: "high" },
                confidence: {
                  level: "high",
                  rationale: "Synthetic source fixture.",
                },
                taxonomy: { category: "sql-injection", cwe: ["CWE-89"] },
                locations: [
                  { path: "service/index.ts", startLine: 1, endLine: 1 },
                ],
                remediation: "Use a parameterized query.",
                provenance: {
                  source: "local_plugin",
                  workerId: request.workerId,
                },
              },
            ],
      reviewState: {
        surfaces: [
          { label: "Synthetic source review", disposition: "no_issue_found" },
        ],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
}

test.each([false, true])(
  "hosted Deep runs parallel workers and seals normal artifacts (scoped=%p)",
  async (scoped) => {
    const input = await fixture(scoped);
    const dispatched: DeepScanExecutionRequest[] = [];
    const publicEvents: string[] = [];
    const active = new Set<string>();
    const ready = Promise.withResolvers<void>();
    const result = await runHostedScan(input, {
      onEvent(event) {
        publicEvents.push(event.type);
      },
      executor: {
        async run(value, options) {
          const request = discovery(value);
          dispatched.push(request);
          const sessionId = `session-${dispatched.length}`;
          active.add(sessionId);
          options.onEvent?.({ type: "session.started", sessionId });
          if (dispatched.length === 2) ready.resolve();
          await ready.promise;
          await writeDraft(request);
          return {
            requestId: request.requestId,
            status: "completed",
            sessionId,
            usage: { input_tokens: 10, output_tokens: 2 },
          };
        },
        async release(sessionId) {
          expect(active.delete(sessionId)).toBe(true);
        },
      },
    });
    expect(result).toMatchObject({ status: "completed" });
    expect(publicEvents).not.toContain("session.started");
    expect(result.coordinatorStatus).toBe("succeeded");
    expect(result.execution).toBeUndefined();
    expect(active.size).toBe(0);
    expect(result.executions?.map((receipt) => receipt.requestId)).toEqual(
      dispatched.map((request) => request.requestId),
    );
    expect(new Set(dispatched.map((request) => request.scanId)).size).toBe(1);
    expect(dispatched.every((request) => request.subagents === 3)).toBe(true);
    const manifest = JSON.parse(
      await readFile(
        join(result.outputDirectory, "scan-manifest.json"),
        "utf8",
      ),
    );
    expect(manifest.scan.mode).toBe(scoped ? "scoped_path" : "deep_repository");
    expect(manifest.scan.scope.includePaths).toEqual(
      scoped ? ["service"] : ["."],
    );
    expect(
      result.artifacts.some((artifact) => artifact.path === "findings.json"),
    ).toBe(true);
  },
);

test("hosted Deep delegates structured comparisons and publishes findings", async () => {
  const input = await fixture();
  const kinds: string[] = [];
  const active = new Set<string>();
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        if (request.version !== 3) throw new Error("Expected Deep execution");
        kinds.push(request.kind);
        const sessionId = `session-${kinds.length}`;
        active.add(sessionId);
        if (request.kind === "discovery") {
          await writeDraft(request, `Synthetic query issue ${kinds.length}`);
        } else {
          expect(request.subagents).toBe(0);
          expect(request.artifactContext).toBeUndefined();
          expect(request.outputSchema).toBeDefined();
        }
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId,
          ...(request.kind === "comparison"
            ? {
                finalResponse: JSON.stringify({
                  defects: [],
                  uncertain: [0, 1],
                }),
              }
            : {}),
        };
      },
      async release(sessionId) {
        expect(active.delete(sessionId)).toBe(true);
      },
    },
  });
  expect(result).toMatchObject({ status: "completed" });
  expect(kinds).toEqual(["discovery", "discovery", "comparison"]);
  expect(active.size).toBe(0);
  const findings = JSON.parse(
    await readFile(join(result.outputDirectory, "findings.json"), "utf8"),
  );
  expect(findings.findings).toHaveLength(2);
  expect(result.executions).toHaveLength(3);
});

test("hosted Deep never replaces execution whose acceptance is unknown", async () => {
  const input = await fixture();
  input.deepScan.workers = 1;
  let calls = 0;
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        calls += 1;
        return { requestId: request.requestId, status: "acceptance_unknown" };
      },
      async release() {},
    },
  });
  expect(result).toMatchObject({ status: "acceptance_unknown" });
  expect(calls).toBe(1);
  expect(result.executions).toHaveLength(1);
  expect(result.artifacts).toEqual([]);
});

test("hosted Deep resumes the same session to finish missing artifacts before release", async () => {
  const input = await fixture();
  input.deepScan.workers = 1;
  input.deepScan.maxDiscoveryRuns = 1;
  const requests: DeepScanExecutionRequest[] = [];
  const released: string[] = [];
  const result = await runHostedScan(input, {
    executor: {
      async run(value) {
        const request = discovery(value);
        requests.push(request);
        if (requests.length === 1)
          expect(request.resumeSessionId).toBeUndefined();
        else {
          expect(request.resumeSessionId).toBe("retained-session");
          expect(released).toEqual([]);
          await writeDraft(request);
        }
        // Receipt attribution must work even when optional progress is absent.
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "retained-session",
        };
      },
      async release(sessionId) {
        released.push(sessionId);
      },
    },
  });
  expect(result).toMatchObject({ status: "completed" });
  expect(requests).toHaveLength(2);
  expect(new Set(requests.map((request) => request.workerId)).size).toBe(1);
  expect(released).toEqual(["retained-session"]);
  expect(result.executions).toHaveLength(2);
}, 120_000);

test("hosted Deep does not dispatch queued work after owner cancellation", async () => {
  const input = await fixture();
  const controller = new AbortController();
  let calls = 0;
  const result = await runHostedScan(input, {
    signal: controller.signal,
    executor: {
      async run(request, options) {
        options.signal.throwIfAborted();
        calls += 1;
        controller.abort();
        return { requestId: request.requestId, status: "canceled" };
      },
      async release() {},
    },
  });
  expect(result).toMatchObject({ status: "canceled" });
  expect(calls).toBe(1);
  expect(result.executions).toHaveLength(1);
});

test("hosted Deep cancellation retains every worker receipt and releases sessions", async () => {
  const input = await fixture();
  const controller = new AbortController();
  const active = new Set<string>();
  let calls = 0;
  const result = await runHostedScan(input, {
    signal: controller.signal,
    executor: {
      async run(request, options) {
        const sessionId = `session-${++calls}`;
        active.add(sessionId);
        options.onEvent?.({ type: "session.started", sessionId });
        if (calls === 2) controller.abort();
        if (!options.signal.aborted)
          await new Promise<void>((resolve) =>
            options.signal.addEventListener("abort", () => resolve(), {
              once: true,
            }),
          );
        return {
          requestId: request.requestId,
          status: "canceled",
          sessionId,
          usage: { input_tokens: 10, output_tokens: 2 },
        };
      },
      async release(sessionId) {
        expect(active.delete(sessionId)).toBe(true);
      },
    },
  });
  expect(result).toMatchObject({ status: "canceled" });
  expect(calls).toBe(2);
  expect(active.size).toBe(0);
  expect(result.executions).toHaveLength(2);
  expect(
    result.executions?.every(
      (receipt) => receipt.status === "canceled" && receipt.usage !== undefined,
    ),
  ).toBe(true);
});
