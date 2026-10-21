import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

/** @type {import("../../src/remediation.js").FindingVerificationCheck[]} */
export const passedChecks = [
  {
    name: "Authorization regression tests",
    status: "passed",
    command: "bun test tests/authorization.test.ts",
    evidence: "Original request rejected; legitimate control passed.",
  },
  {
    name: "Static assessment of equivalent authorization paths",
    status: "passed",
    evidence: "All handlers in guard.ts use the shared authorization check.",
  },
];

/** @type {import("../../src/remediation.js").FindingVerification} */
export const verificationResult = {
  id: "finding-1",
  status: "fixed",
  evidence: "Original request rejected; legitimate control passed.",
  checks: passedChecks,
};

/**
 * @param {{repository: string, revision: string}} checkout
 * @param {"patch" | "verify"} operation
 * @returns {import("../../src/hosted-remediation.js").HostedRemediationInput}
 */
export function remediationInput(checkout, operation = "patch") {
  return {
    version: 1,
    operation,
    ...checkout,
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

/**
 * @param {{requestId: string, operation: "patch" | "verify", findingId: string}} request
 * @param {Partial<import("../../src/hosted-remediation.js").RemediationExecutionResult>} overrides
 * @returns {import("../../src/hosted-remediation.js").RemediationExecutionResult}
 */
export function remediationReceipt(request, overrides = {}) {
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
                verification: verificationResult.evidence,
              },
            ],
          }
        : {
            results: [{ ...verificationResult, id: request.findingId }],
          },
    ),
    ...overrides,
  };
}

/**
 * Exercise the same pipe contract against source and installed CLI entrypoints.
 * @param {string} node
 * @param {string} entrypoint
 * @param {import("../../src/hosted-remediation.js").HostedRemediationInput} input
 * @param {{cancel?: boolean, onExecution?: (request: import("../../src/hosted-remediation.js").RemediationExecutionRequest) => Promise<void>}} options
 */
export async function exerciseRemediationProtocol(
  node,
  entrypoint,
  input,
  { cancel = false, onExecution } = {},
) {
  const child = spawn(
    node,
    [
      entrypoint,
      input.operation === "patch" ? "patch" : "verify-fix",
      "--host",
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const closed = new Promise((resolve, reject) => {
    child.on("exit", resolve);
    child.on("error", reject);
  });
  const send = (value) =>
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...value }) + "\n");
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  const messages = [];
  let execution;
  try {
    send({ id: "run", method: "run", params: input });
    for await (const line of createInterface({ input: child.stdout })) {
      const message = JSON.parse(line);
      messages.push(message);
      if (message.method === "execution.run") {
        assert.equal(
          execution,
          undefined,
          "Only one execution may be submitted",
        );
        execution = message.params;
        assert.equal(execution.operation, input.operation);
        assert.equal(
          execution.sandbox,
          input.operation === "patch" ? "workspace-write" : "read-only",
        );
        assert.equal(execution.revision, input.revision);
        await onExecution?.(execution);
        send({
          method: "execution.progress",
          params: {
            requestId: execution.requestId,
            event: { type: "activity", description: "Check" },
          },
        });
        if (cancel) send({ method: "cancel", params: { id: "run" } });
        else send({ id: message.id, result: remediationReceipt(execution) });
      } else if (message.method === "execution.cancel") {
        assert.ok(cancel);
        assert.equal(message.params.requestId, execution?.requestId);
        send({
          id: execution.requestId,
          result: remediationReceipt(execution, { status: "canceled" }),
        });
      }
    }
    assert.equal(await closed, cancel ? 1 : 0, stderr);
    assert.ok(execution);
    const terminal = messages.at(-1);
    assert.equal(terminal.error, undefined, JSON.stringify(terminal.error));
    assert.equal(terminal.id, "run");
    const result = terminal.result;
    assert.equal(result.status, cancel ? "canceled" : "completed");
    assert.deepEqual(
      result.execution,
      remediationReceipt(execution, { status: result.status }),
    );
    assert.ok(
      messages.some((message) => message.method === "remediation.progress"),
    );
    if (!cancel) {
      if (input.operation === "patch")
        assert.equal(result.patch.status, "verified");
      else {
        assert.equal(result.verification.status, "fixed");
        assert.deepEqual(result.verification.checks, passedChecks);
      }
    }
    return result;
  } finally {
    child.kill();
  }
}
