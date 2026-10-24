import { PassThrough } from "node:stream";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import {
  runHostedRemediation,
  runHostedRemediationProtocol,
  type HostedRemediationInput,
  type RemediationExecutor,
} from "../src/index.js";
import { parseFindingPatch } from "../src/remediation.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSource } from "./support/shell.js";
import { parseJsonLines } from "./support/json.js";
import { rejecting } from "./support/errors.js";
import {
  exerciseRemediationProtocol,
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
  git(repository, "config", "--local", "core.autocrlf", "false");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "fixture");
  return remediationInput(
    { repository, revision: git(repository, "rev-parse", "HEAD") },
    operation,
  );
}

test.each([
  ["patch", "standard"],
  ["verify", "standard"],
  ["patch", "static"],
  ["verify", "static"],
] as const)(
  "%s preserves skill context, instructions, and permissions in %s mode",
  async (operation, mode) => {
    const staticVerification = mode === "static";
    const input = {
      ...(await fixture(operation)),
      reasoningEffort: "provider-specific-effort",
      verificationMode: staticVerification ? mode : undefined,
      validationInstructions: "Install dependencies and run regression tests.",
    };
    const evidence =
      "guard.ts rejects unauthorized requests before dispatch and preserves authorized callers. Runtime checks were not performed.";
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
      expect(request.prompt).toContain(input.validationInstructions);
      expect(request.prompt).toContain(
        operation === "patch"
          ? "$codex-security:fix-finding"
          : "$codex-security:verify-fix",
      );
      options.onEvent?.({ type: "activity", description: "Checking guard" });
      if (!staticVerification) return receipt(request);
      expect(request.prompt).toContain("Verification mode: static");
      expect(request.prompt).toContain("without executing requested setup");
      expect(request.prompt).not.toContain(
        "instructions for dynamic validation",
      );
      expect(request.prompt).not.toContain(
        "only after the original issue no longer reproduces",
      );
      return receipt(request, {
        finalResponse: JSON.stringify(
          operation === "patch"
            ? {
                patches: [
                  {
                    occurrenceId: input.finding.id,
                    status: "verified",
                    files: ["guard.ts"],
                    verification: evidence,
                  },
                ],
              }
            : {
                results: [{ ...verificationResult, evidence }],
              },
        ),
      });
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
    expect(result.patch?.verification ?? result.verification?.evidence).toBe(
      staticVerification ? evidence : verificationResult.evidence,
    );
    if (!staticVerification) {
      await runHostedRemediation(
        { ...input, verificationMode: "standard" },
        { executor: { run } },
      );
      expect(run.mock.calls[1]![0].prompt).toBe(run.mock.calls[0]![0].prompt);
    }
  },
);

test.each([
  [
    "fixed",
    "The guard blocks the original call and preserves authorized callers.",
  ],
  [
    "still_vulnerable",
    "The alternate route still reaches the unguarded handler.",
  ],
  [
    "inconclusive",
    "The source does not establish whether authorized callers still work.",
  ],
] as const)(
  "hosted static verification completes with the CLI verdict %s",
  async (status, evidence) => {
    const input = {
      ...(await fixture("verify")),
      verificationMode: "static" as const,
    };
    const verdict = { id: input.finding.id, status, evidence };
    const result = await runHostedRemediation(input, {
      executor: {
        run: async (request) =>
          receipt(request, {
            finalResponse: JSON.stringify({ results: [verdict] }),
          }),
      },
    });
    expect(result.status).toBe("completed");
    expect(result.verification).toEqual(verdict);
  },
);

test("hosted verification ignores extra fields like the local CLI", async () => {
  const input = await fixture("verify");
  const result = await runHostedRemediation(input, {
    executor: {
      run: async (request) =>
        receipt(request, {
          finalResponse: JSON.stringify({
            results: [
              {
                ...verificationResult,
                checks: [{ status: "not_run" }],
              },
            ],
          }),
        }),
    },
  });
  expect(result.status).toBe("completed");
  expect(result.verification).toEqual(verificationResult);
});

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
  "CLI protocol pipes execute %s with cancellation=%p",
  async (operation, cancel) => {
    await exerciseRemediationProtocol(
      process.execPath,
      join(import.meta.dirname, "../src/cli.ts"),
      await fixture(operation),
      { cancel },
    );
  },
);

test.each(["patch", "verify-fix"])(
  "%s --host rejects a mismatched operation without execution",
  async (command) => {
    const input = new PassThrough();
    const stdout = capture();
    const stderr = capture();
    const completed = main([command, "--host"], stdout.stream, stderr.stream, {
      ...dependencies(),
      recordsInput: input,
    });
    input.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: "run",
        method: "run",
        params: await fixture(command === "patch" ? "verify" : "patch"),
      }) + "\n",
    );
    expect(await completed).toBe(2);
    expect(stderr.text()).toBe("");
    const messages = parseJsonLines(stdout.text());
    expect(messages).toHaveLength(1);
    expect(messages[0].error.code).toBe(-32602);
    expect(messages[0].error.message).toContain("requires operation");
    input.destroy();
  },
);

test.each([
  { args: ["patch", "--host=true"] },
  { args: ["patch", "--host", "--create-pr"] },
  { args: ["verify-fix", "finding.md", "--host"] },
])("hosted remediation rejects mixed arguments $args", async ({ args }) => {
  const stdout = capture();
  const stderr = capture();
  expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
    2,
  );
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain("--host must be used alone");
});
