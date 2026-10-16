import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { PassThrough } from "node:stream";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, mock, test } from "bun:test";
import {
  runHostedRemediation,
  runHostedRemediationProtocol,
  type HostedRemediationInput,
  type RemediationExecutionRequest,
  type RemediationExecutionResult,
  type RemediationExecutor,
  type FindingVerification,
  type FindingVerificationCheck,
} from "../src/index.js";
import { parseFindingVerifications } from "../src/remediation.js";
import { capture } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSource } from "./support/shell.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "hosted-remediation-",
);
afterEach(cleanup);

const passedChecks: FindingVerificationCheck[] = [
  {
    name: "Authorization regression tests",
    status: "passed",
    command: "bun test tests/authorization.test.ts",
    evidence:
      "The original unauthorized request is rejected and the legitimate request succeeds.",
  },
  {
    name: "Static assessment of equivalent authorization paths",
    status: "passed",
    evidence: "All handlers in guard.ts use the shared authorization check.",
  },
];

async function fixture(
  operation: HostedRemediationInput["operation"] = "patch",
): Promise<HostedRemediationInput> {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  writeSource(repository, "guard.ts", "export const allowed = false;\n");
  git(repository, "init", "-q");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "fixture");
  return {
    version: 1,
    operation,
    repository,
    revision: git(repository, "rev-parse", "HEAD"),
    finding: {
      id: "finding-1",
      context:
        "Original authorization boundary and legitimate request evidence.",
    },
    instructions: "Preserve the shared authorization helper.",
    validationInstructions: "Run the focused authorization checks.",
    model: "fixture-model",
    reasoningEffort: "high",
    identity: { runId: "run-1", attemptId: "attempt-1", buildId: "fixture" },
  };
}

function receipt(
  request: Pick<
    RemediationExecutionRequest,
    "requestId" | "operation" | "findingId"
  >,
  overrides: Partial<RemediationExecutionResult> = {},
): RemediationExecutionResult {
  return {
    requestId: request.requestId,
    status: "completed",
    sessionId: "host-session",
    usage: { input_tokens: 100, output_tokens: 25 },
    finalResponse: JSON.stringify(
      request.operation === "patch"
        ? {
            patches: [
              {
                occurrenceId: request.findingId,
                status: "verified",
                files: ["guard.ts"],
                verification:
                  "Original request rejected; legitimate control passed.",
              },
            ],
          }
        : {
            results: [
              {
                id: request.findingId,
                status: "fixed",
                evidence:
                  "Original request rejected; legitimate control passed.",
                checks: passedChecks,
              },
            ],
          },
    ),
    ...overrides,
  };
}

test.each(["patch", "verify"] as const)(
  "%s reuses skill context, explicit instructions, and the requested sandbox",
  async (operation) => {
    const input = await fixture(operation);
    const run = mock<RemediationExecutor["run"]>(async (request, options) => {
      expect(request).toMatchObject({
        operation,
        repository: input.repository,
        revision: input.revision,
        identity: input.identity,
        findingId: input.finding.id,
        model: input.model,
        reasoningEffort: input.reasoningEffort,
        sandbox: operation === "verify" ? "read-only" : "workspace-write",
      });
      expect(request.prompt).toContain(input.finding.context);
      expect(request.prompt).toContain(input.instructions!);
      expect(request.prompt).toContain(input.validationInstructions!);
      expect(request.prompt).toContain(
        operation === "patch"
          ? "$codex-security:fix-finding"
          : "standalone verification-only mode",
      );
      if (operation === "verify") {
        expect(request.prompt).toContain("without modifying repository files");
        expect(request.prompt).toContain('"checks" array');
        expect(request.prompt).toContain('"passed|failed|not_run"');
        expect(request.prompt).toContain(
          "Distinguish static source assessment",
        );
      }
      options.onEvent?.({ type: "activity", description: "Checking guard" });
      return receipt(request);
    });
    const result = await runHostedRemediation(input, {
      executor: { run },
      onEvent() {
        throw new Error("Optional observer failed");
      },
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(result.status).toBe("completed");
    expect(result.execution?.sessionId).toBe("host-session");
    expect(result.execution?.usage).toEqual({
      input_tokens: 100,
      output_tokens: 25,
    });
    expect(result.provenance.buildId).toBe(input.identity.buildId);
    expect(
      operation === "patch"
        ? result.patch?.status
        : result.verification?.status,
    ).toBe(operation === "patch" ? "verified" : "fixed");
    if (operation === "verify")
      expect(result.verification?.checks).toEqual(passedChecks);
  },
);

test.each(["verified", "no_change", "blocked", "failed"] as const)(
  "a completed generation retains its distinct %s outcome",
  async (status) => {
    const input = await fixture();
    const patch = {
      occurrenceId: input.finding.id,
      status,
      files: status === "verified" ? ["guard.ts"] : [],
      verification: "Current source and legitimate behavior checked.",
      reason: "Relevant test tooling is unavailable.",
    };
    const result = await runHostedRemediation(input, {
      executor: {
        run: async (request) =>
          receipt(request, {
            finalResponse: JSON.stringify({ patches: [patch] }),
          }),
      },
    });
    expect(result.status).toBe("completed");
    expect(result.patch).toEqual(patch);
    expect(result.verification).toBeUndefined();
  },
);

test.each(["fixed", "still_vulnerable", "inconclusive"] as const)(
  "a completed verification preserves the %s verdict",
  async (status) => {
    const input = await fixture("verify");
    const verification: FindingVerification = {
      id: input.finding.id,
      status,
      evidence: "Specific source, test, or missing-check evidence.",
      checks:
        status === "fixed"
          ? passedChecks
          : [
              {
                name: "Original authorization reproducer",
                status: status === "still_vulnerable" ? "failed" : "not_run",
                evidence:
                  status === "still_vulnerable"
                    ? "The original unauthorized request still succeeds."
                    : "The required fixture needs repository writes, which verification does not allow.",
              },
            ],
    };
    const result = await runHostedRemediation(input, {
      executor: {
        run: async (request) =>
          receipt(request, {
            finalResponse: JSON.stringify({ results: [verification] }),
          }),
      },
    });
    expect(result.status).toBe("completed");
    expect(result.verification).toEqual(verification);
    expect(result.patch).toBeUndefined();
  },
);

test("static evidence remains distinct from commands when no runtime check is required", async () => {
  const input = await fixture("verify");
  const verification: FindingVerification = {
    id: input.finding.id,
    status: "fixed",
    evidence:
      "The constant deny rule rejects every unauthorized call while the existing authorized branch remains unchanged.",
    checks: [passedChecks[1]!],
  };
  const result = await runHostedRemediation(
    { ...input, validationInstructions: undefined },
    {
      executor: {
        run: async (request) =>
          receipt(request, {
            finalResponse: JSON.stringify({ results: [verification] }),
          }),
      },
    },
  );
  expect(result.status).toBe("completed");
  expect(result.verification).toEqual(verification);
  expect(result.verification?.checks?.[0]).not.toHaveProperty("command");
});

test.each([undefined, passedChecks, [{ result: "legacy summary" }]])(
  "local verification keeps the legacy output with extra checks=%p",
  (checks) => {
    const verification: FindingVerification = {
      id: "finding-1",
      status: "fixed",
      evidence: "Original request rejected; legitimate control passed.",
    };
    expect(
      parseFindingVerifications(
        JSON.stringify({ results: [{ ...verification, checks }] }),
        [verification.id],
      ),
    ).toEqual([verification]);
  },
);

test.each([
  "not JSON",
  JSON.stringify({ results: [] }),
  JSON.stringify({
    results: [{ id: "other", status: "fixed", evidence: "Checked" }],
  }),
  JSON.stringify({
    results: [{ id: "finding-1", status: "fixed", evidence: " " }],
  }),
  ...[
    undefined,
    [],
    [{ name: "Authorization check", status: "passed", evidence: " " }],
    [{ name: " ", status: "passed", evidence: "Original request rejected." }],
    [
      {
        name: "Authorization regression tests",
        status: "failed",
        evidence: "The original unauthorized request still succeeds.",
      },
    ],
    [
      {
        name: "Legitimate request control",
        status: "not_run",
        evidence: "Required fixture is unavailable.",
      },
    ],
  ].map((checks) =>
    JSON.stringify({
      results: [
        { id: "finding-1", status: "fixed", evidence: "Checked", checks },
      ],
    }),
  ),
])(
  "invalid verification preserves the execution receipt: %s",
  async (finalResponse) => {
    const input = await fixture("verify");
    const result = await runHostedRemediation(input, {
      executor: { run: async (request) => receipt(request, { finalResponse }) },
    });
    expect(result.status).toBe("failed");
    expect(result.error?.code).toBe("INVALID_RESULT");
    expect(result.verification).toBeUndefined();
    expect(result.execution).toMatchObject({
      sessionId: "host-session",
      finalResponse,
    });
  },
);

test.each([
  { status: "verified", verification: undefined },
  { status: "no_change", verification: " " },
  { status: "blocked", reason: undefined },
  { status: "failed", reason: " " },
  {
    status: "verified",
    occurrenceId: "another-finding",
    verification: "Checked",
  },
])("invalid patch outcome %p retains the execution receipt", async (patch) => {
  const input = await fixture();
  const result = await runHostedRemediation(input, {
    executor: {
      run: async (request) =>
        receipt(request, {
          finalResponse: JSON.stringify({
            patches: [{ occurrenceId: input.finding.id, files: [], ...patch }],
          }),
        }),
    },
  });
  expect(result.status).toBe("failed");
  expect(result.error?.code).toBe("INVALID_RESULT");
  expect(result.patch).toBeUndefined();
  expect(result.execution?.sessionId).toBe("host-session");
});

test("a changed HEAD fails before execution, and cannot be accepted afterward", async () => {
  const input = await fixture();
  const never = mock<RemediationExecutor["run"]>(async () => {
    throw new Error("Must not execute");
  });
  await expect(
    runHostedRemediation(
      { ...input, revision: "0".repeat(40) },
      {
        executor: { run: never },
      },
    ),
  ).rejects.toMatchObject({ reason: "revision_mismatch" });
  expect(never).not.toHaveBeenCalled();
  const result = await runHostedRemediation(input, {
    executor: {
      run: async (request) => {
        git(input.repository, "commit", "--allow-empty", "-qm", "changed");
        return receipt(request);
      },
    },
  });
  expect(result.status).toBe("failed");
  expect(result.error?.message).toContain("frozen revision");
  expect(result.execution?.sessionId).toBe("host-session");
});

test.each(["failed", "canceled", "acceptance_unknown"] as const)(
  "execution %s remains distinct and is never resubmitted",
  async (status) => {
    const run = mock<RemediationExecutor["run"]>(async (request) =>
      receipt(request, { status, finalResponse: undefined }),
    );
    const result = await runHostedRemediation(await fixture(), {
      executor: { run },
    });
    expect(result.status).toBe(status);
    expect(result.execution?.usage).toEqual({
      input_tokens: 100,
      output_tokens: 25,
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(result.patch).toBeUndefined();
  },
);

test("a mismatched execution receipt is retained but never accepted", async () => {
  const result = await runHostedRemediation(await fixture(), {
    executor: {
      run: async (request) => receipt(request, { requestId: "other" }),
    },
  });
  expect(result.status).toBe("failed");
  expect(result.execution?.sessionId).toBe("host-session");
  expect(result.error?.message).toContain("does not match");
});

test("malformed protocol input returns one error without dispatch", async () => {
  const input = new PassThrough();
  const output = capture();
  const completed = runHostedRemediationProtocol(input, output.stream);
  input.write(
    JSON.stringify({ jsonrpc: "2.0", id: "run", method: "run", params: {} }) +
      "\n",
  );
  expect(await completed).toBe(2);
  const messages = output
    .text()
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(messages).toHaveLength(1);
  expect(messages[0].error.code).toBe(-32602);
  input.destroy();
});

test.each([
  ["patch", false],
  ["verify", false],
  ["verify", true],
] as const)(
  "SDK protocol pipes execute %s with cancellation=%p",
  async (operation, cancel) => {
    const input = await fixture(operation);
    const entrypoint = pathToFileURL(
      join(import.meta.dirname, "../src/index.ts"),
    ).href;
    const child = spawn(
      process.execPath,
      [
        "-e",
        `import(${JSON.stringify(entrypoint)}).then(async ({runHostedRemediationProtocol}) => { process.exitCode = await runHostedRemediationProtocol(process.stdin, process.stdout); });`,
      ],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    const closed = new Promise<number | null>((resolve, reject) => {
      child.on("exit", resolve);
      child.on("error", reject);
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    const send = (value: object) =>
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...value }) + "\n");
    let execution: RemediationExecutionRequest | undefined;
    const messages: any[] = [];
    try {
      send({ id: "run", method: "run", params: input });
      for await (const line of createInterface({ input: child.stdout })) {
        const message = JSON.parse(line);
        messages.push(message);
        if (message.method === "execution.run") {
          expect(execution).toBeUndefined();
          execution = message.params;
          send({
            method: "execution.progress",
            params: {
              requestId: execution!.requestId,
              event: { type: "activity", description: "Check" },
            },
          });
          if (cancel) send({ method: "cancel", params: { id: "run" } });
          else send({ id: message.id, result: receipt(execution!) });
        } else if (message.method === "execution.cancel") {
          expect(message.params.requestId).toBe(execution?.requestId);
          send({
            id: execution!.requestId,
            result: receipt(execution!, { status: "canceled" }),
          });
        }
      }
      expect(await closed, stderr).toBe(cancel ? 1 : 0);
      expect(messages.at(-1)).toMatchObject({
        id: "run",
        result: {
          status: cancel ? "canceled" : "completed",
          execution: {
            sessionId: "host-session",
            usage: { input_tokens: 100, output_tokens: 25 },
          },
        },
      });
      expect(
        messages.some((message) => message.method === "remediation.progress"),
      ).toBe(true);
    } finally {
      child.kill();
    }
  },
);
