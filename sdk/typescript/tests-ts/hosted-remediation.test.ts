import { PassThrough } from "node:stream";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, mock, test } from "bun:test";
import {
  runHostedRemediation,
  runHostedRemediationProtocol,
  type HostedRemediationInput,
  type RemediationExecutor,
} from "../src/index.js";
import {
  parseFindingPatch,
  parseFindingVerifications,
} from "../src/remediation.js";
import { capture } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSource } from "./support/shell.js";
import { parseJsonLines } from "./support/json.js";
import { rejecting } from "./support/errors.js";
import {
  exerciseRemediationProtocol,
  passedChecks,
  remediationInput,
  remediationReceipt as receipt,
  verificationResult,
} from "./support/hosted-remediation.mjs";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "hosted-remediation-",
);
afterEach(cleanup);

async function fixture(
  operation: HostedRemediationInput["operation"] = "patch",
): Promise<HostedRemediationInput> {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  writeSource(repository, "guard.ts", "export const allowed = false;\n");
  git(repository, "init", "-q");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "fixture");
  return remediationInput(
    { repository, revision: git(repository, "rev-parse", "HEAD") },
    operation,
  );
}

test.each(["patch", "verify"] as const)(
  "%s reuses skill context, explicit instructions, and the requested sandbox",
  async (operation) => {
    const input = {
      ...(await fixture(operation)),
      reasoningEffort: "provider-specific-effort",
    };
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
          : "$codex-security:verify-fix",
      );
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

test.each([
  ["still_vulnerable", "failed"],
  ["inconclusive", "not_run"],
] as const)(
  "verification preserves %s with a %s check",
  (status, checkStatus) => {
    const verification = {
      ...verificationResult,
      status,
      checks: [{ ...passedChecks[0]!, status: checkStatus }],
    };
    expect(
      parseFindingVerifications(
        JSON.stringify({ results: [verification] }),
        [verification.id],
        {
          requireChecks: true,
        },
      ),
    ).toEqual([verification]);
  },
);

test("local verification ignores extra hosted checks", () => {
  const { checks: _, ...verification } = verificationResult;
  expect(
    parseFindingVerifications(
      JSON.stringify({
        results: [{ ...verification, checks: [{ result: "legacy summary" }] }],
      }),
      [verification.id],
    ),
  ).toEqual([verification]);
});

test.each([
  ["missing", undefined],
  ["empty", []],
  ["missing evidence", [{ ...passedChecks[0], evidence: " " }]],
  ["missing name", [{ ...passedChecks[0], name: " " }]],
  ["failed", [{ ...passedChecks[0], status: "failed" }]],
  ["not run", [{ ...passedChecks[0], status: "not_run" }]],
])(
  "hosted verification rejects fixed results with %s checks",
  (_name, checks) => {
    expect(() =>
      parseFindingVerifications(
        JSON.stringify({ results: [{ ...verificationResult, checks }] }),
        [verificationResult.id],
        { requireChecks: true },
      ),
    ).toThrow();
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
])("patch parsing rejects invalid outcome %p", (patch) => {
  expect(() =>
    parseFindingPatch(
      JSON.stringify({
        patches: [{ occurrenceId: "finding-1", files: [], ...patch }],
      }),
      "finding-1",
    ),
  ).toThrow();
});

test.each(["patch", "verify"] as const)(
  "invalid %s results preserve the execution receipt",
  async (operation) => {
    const finalResponse = "invalid JSON";
    const result = await runHostedRemediation(await fixture(operation), {
      executor: { run: async (request) => receipt(request, { finalResponse }) },
    });
    expect(result.status).toBe("failed");
    expect(result.error?.code).toBe("INVALID_RESULT");
    expect(result.patch).toBeUndefined();
    expect(result.verification).toBeUndefined();
    expect(result.execution).toMatchObject({
      sessionId: "host-session",
      finalResponse,
    });
  },
);

test("a changed HEAD fails before execution, and cannot be accepted afterward", async () => {
  const input = await fixture();
  const never = mock(rejecting("Must not execute"));
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
  const messages = parseJsonLines(output.text());
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
    await exerciseRemediationProtocol(process.execPath, entrypoint, input, {
      cancel,
    });
  },
);
