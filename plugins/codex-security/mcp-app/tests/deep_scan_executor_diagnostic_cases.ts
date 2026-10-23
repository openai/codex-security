import assert from "node:assert/strict";
import type { CodexWorkerDiagnostic } from "../src/deep-scan/types.js";

export const trustedParentSandbox = Object.freeze({
  filesystemDenies: [],
});
export const trustedParentSandboxWithDenials = Object.freeze({
  filesystemDenies: [
    "/repo/.env",
    "/repo/**/.secret",
    "/repo/**/*.pem",
    "/repo/temp[1]",
    "/repo/secret[1]",
    "/repo/.env",
  ],
  literalFilesystemDenies: ["/repo/temp[1]", "/repo/secret[1]"],
  globScanMaxDepth: 3,
});
export const emptyWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: { ":root": "read" },
  network: { enabled: false },
};

export const deniedWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: {
    ":root": "read",
    "/repo/.env": "deny",
    "/repo/**/.secret": "deny",
    "/repo/**/*.pem": "deny",
    "/repo/temp[1]": { ".": "deny" },
    "/repo/secret[1]": { ".": "deny" },
    "/": { "repo/temp[1]": "deny", "repo/secret[1]": "deny" },
    glob_scan_max_depth: 3,
  },
  network: { enabled: false },
};

export function testCodeModeFrameDiagnosticBoundaries(
  appendItemDiagnostic: (
    diagnostics: CodexWorkerDiagnostic[],
    item: unknown,
  ) => void,
  ipcFrameError: string,
) {
  const failedArtifactTool = {
    type: "mcp_tool_call",
    server: "cs_artifacts",
    tool: "get_codex_security_deep_reducer_inputs",
    status: "failed",
  };
  const resultWithText = (text: string) => ({
    content: [{ type: "text", text }],
  });
  for (const item of [
    { type: "error", message: ipcFrameError },
    { ...failedArtifactTool, error: { message: ipcFrameError } },
    {
      ...failedArtifactTool,
      server: "foreign_server",
      error: { message: ipcFrameError },
    },
    { ...failedArtifactTool, result: resultWithText(ipcFrameError) },
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendItemDiagnostic(diagnostics, failedArtifactTool);
    appendItemDiagnostic(diagnostics, item);
    appendItemDiagnostic(diagnostics, failedArtifactTool);
    assert.deepEqual(diagnostics, [
      {
        code: "artifact_tool_failed",
        message:
          "Codex worker artifact tool get_codex_security_deep_reducer_inputs failed.",
      },
      { code: "artifact_tool_failed", message: ipcFrameError },
    ]);
  }
  for (const message of [
    `private source: ${ipcFrameError}`,
    `${ipcFrameError} private output`,
    `${ipcFrameError}\n`,
    JSON.stringify({ error: ipcFrameError }),
    ipcFrameError.replace("76008279", "unknown"),
    "private path /customer/repo: IPC frame limit exceeded",
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendItemDiagnostic(diagnostics, { type: "error", message });
    appendItemDiagnostic(diagnostics, {
      ...failedArtifactTool,
      result: resultWithText(message),
    });
    assert.deepEqual(diagnostics, [
      { code: "worker_error", message },
      { code: "artifact_tool_failed", message },
    ]);
  }
  for (const item of [
    {
      ...failedArtifactTool,
      server: "foreign_server",
      result: resultWithText(ipcFrameError),
    },
    {
      ...failedArtifactTool,
      server: "foreign_server",
      error: { message: "Synthetic unrelated transport failure" },
    },
    {
      type: "command_execution",
      status: "failed",
      aggregated_output: ipcFrameError,
    },
    { type: "agent_message", text: ipcFrameError },
    { type: "unknown", status: "failed", error: { message: ipcFrameError } },
  ]) {
    const diagnostics: CodexWorkerDiagnostic[] = [];
    appendItemDiagnostic(diagnostics, item);
    assert.deepEqual(diagnostics, []);
  }
}

export function workerPermissionProfileOverride(args: readonly string[]) {
  assert.deepEqual(
    args.filter((arg: string) => arg.startsWith("default_permissions=")),
    ['default_permissions="codex_security_deep_scan_worker"'],
  );
  const overrides = args.filter((arg: string) =>
    arg.startsWith("permissions.codex_security_deep_scan_worker="),
  );
  assert.equal(overrides.length, 1);
  return overrides[0];
}

export function testWorkerErrorClassificationPreservesExplicitFailures({
  classifyCodexWorkerError,
  DeepScanNonRetryableError,
  isCodexCybersecurityPolicyRefusal,
}: Pick<
  typeof import("../src/deep-scan/errors.js"),
  | "classifyCodexWorkerError"
  | "DeepScanNonRetryableError"
  | "isCodexCybersecurityPolicyRefusal"
>) {
  const explicit = new DeepScanNonRetryableError(
    "Explicitly rejected worker permission profile.",
  );
  assert.equal(classifyCodexWorkerError(explicit), explicit);

  const refusalMessages = [
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
  ];
  for (const message of refusalMessages) {
    const original = new Error(message);
    const classified = classifyCodexWorkerError(original);
    assert.equal(classified, original);
    assert.equal(classified.name, "Error");
    assert.equal(isCodexCybersecurityPolicyRefusal(classified), true);

    const explicitRefusal = new DeepScanNonRetryableError(message);
    assert.equal(classifyCodexWorkerError(explicitRefusal), explicitRefusal);

    for (const unrecognized of [
      `Source fixture: ${message}`,
      `${message} Source fixture.`,
      JSON.stringify({ message }),
      `Codex Exec exited with code 1: ${message}`,
      `429 Too Many Requests: ${message}`,
      ` ${message}`,
      `${message}\n`,
      message.toLowerCase(),
    ]) {
      const unrelated = new Error(unrecognized);
      assert.equal(classifyCodexWorkerError(unrelated), unrelated);
      assert.equal(isCodexCybersecurityPolicyRefusal(unrelated), false);
    }
  }

  for (const message of [
    "config parser handles unknown keys",
    "failed to load configuration: invalid value",
    "agents.max_threads cannot be set when features.multi_agent_v2 is enabled",
    "authentication required",
    "not logged in",
    "missing API key",
    "Codex Exec exited with code 2: failed to load configuration: invalid value",
    "chatgpt authentication required for remote plugin catalog; api key auth is not supported",
    "chatgpt authentication required to sync remote plugins; api key auth is not supported",
  ]) {
    const original = new Error(message);
    assert.equal(classifyCodexWorkerError(original), original);
  }
  for (const code of ["ECONNRESET", "EPIPE", "ETIMEDOUT", "cyber_policy"]) {
    const original = Object.assign(new Error("Unrecognized worker failure"), {
      code,
    });
    assert.equal(classifyCodexWorkerError(original), original);
  }
}
