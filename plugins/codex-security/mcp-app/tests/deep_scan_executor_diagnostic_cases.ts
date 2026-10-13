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
