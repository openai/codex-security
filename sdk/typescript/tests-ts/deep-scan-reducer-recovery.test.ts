import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

function bundledFunction(runtime: string, name: string): string {
  const source = new RegExp(
    `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
    "u",
  ).exec(runtime)?.[0];
  if (!source) throw new Error(`Missing bundled runtime function: ${name}.`);
  return source;
}

test("keeps every advertised Deep worker tool within Codex's name limit", async () => {
  const runtime = await loadBundledRuntime();
  const method = /  compactArtifactServer\(request\) \{[\s\S]*?\n  \}/u.exec(
    runtime,
  )?.[0];
  expect(method).toBeDefined();
  const pathImport = /\(0, (import_node_path\d+)\.join\)/u.exec(method!)?.[1];
  expect(pathImport).toBeDefined();
  const compactArtifactServer = new Function(
    pathImport!,
    `return ({${method}}).compactArtifactServer;`,
  )({ join }) as (
    this: { modelSettings: { artifactContext: Record<string, string> } },
    request: Record<string, unknown>,
  ) => Record<string, { args: string[]; env: NodeJS.ProcessEnv }>;

  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const root = mkdtempSync(join(tmpdir(), "codex-security-deep-tools-"));
  const repoRoot = join(root, "repository");
  const scanRoot = join(root, "scan");
  mkdirSync(repoRoot);
  mkdirSync(scanRoot);

  try {
    for (const layout of ["worker", "reducer"] as const) {
      const artifactRoot = join(scanRoot, layout);
      mkdirSync(artifactRoot);
      const servers = compactArtifactServer.call(
        {
          modelSettings: {
            artifactContext: {
              pluginRoot: PLUGIN_ROOT,
              scanRoot,
              repoRoot,
              scanId: "test-scan",
            },
          },
        },
        {
          kind: layout === "reducer" ? "dedup" : "discovery",
          artifactContext: {
            root: artifactRoot,
            layout,
            ...(layout === "reducer"
              ? { deepReducer: { scanRoot, claimedWorkers: [] } }
              : {}),
          },
        },
      );
      expect(Object.keys(servers)).toEqual(["cs_artifacts"]);
      const server = servers["cs_artifacts"]!;
      const result = spawnSync(node!, server.args, {
        encoding: "utf8",
        env: { ...process.env, ...server.env },
        input: [
          '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex-security-test","version":"1.0.0"}}}',
          '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
          '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
          "",
        ].join("\n"),
        timeout: 30_000,
      });
      expect(result.status, result.stderr).toBe(0);
      const response = result.stdout
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { id?: number; result?: unknown })
        .find((message) => message.id === 2)?.result as
        | { tools: Array<{ name: string }> }
        | undefined;
      expect(response).toBeDefined();
      expect(response!.tools.length).toBeGreaterThan(0);
      for (const tool of response!.tools) {
        expect(`mcp__cs_artifacts__${tool.name}`.length).toBeLessThanOrEqual(
          64,
        );
      }
      if (layout === "reducer") {
        expect(response!.tools.map((tool) => tool.name)).toContain(
          "record_codex_security_deep_reduction",
        );
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("classifies owned worker tool failures without exposing their contents", async () => {
  const runtime = await loadBundledRuntime();
  const diagnosticSource = bundledFunction(runtime, "appendSafeItemDiagnostic");
  const recordHelper = /\b(isRecord\d*)\(item\)/u.exec(diagnosticSource)?.[1];
  expect(recordHelper).toBeDefined();
  const appendDiagnostic = new Function(
    [
      bundledFunction(runtime, recordHelper!),
      bundledFunction(runtime, "isSandboxNamespaceExhaustion"),
      bundledFunction(runtime, "appendUniqueDiagnostic"),
      diagnosticSource,
      "return appendSafeItemDiagnostic;",
    ].join("\n"),
  )() as (
    diagnostics: Array<{ code: string; message: string }>,
    event: Record<string, unknown>,
  ) => void;

  const secret = "synthetic-secret-never-log";
  for (const fixture of [
    {
      server: "cs_artifacts",
      tool: "record_codex_security_deep_reduction",
      result: { isError: true, content: [{ text: secret }] },
      error: null,
      reason: "returned an error",
    },
    {
      server: "cs_artifacts",
      tool: "additional_codex_security_worker_tool",
      result: null,
      error: { message: secret },
      reason: "transport failed",
    },
    {
      server: "codex_security_artifacts",
      tool: "record_codex_security_discovery_candidates",
      result: null,
      error: null,
      reason: "failed",
    },
  ]) {
    const diagnostics: Array<{ code: string; message: string }> = [];
    appendDiagnostic(diagnostics, {
      type: "mcp_tool_call",
      status: "failed",
      arguments: { token: secret },
      ...fixture,
    });
    expect(diagnostics).toEqual([
      {
        code: "artifact_tool_failed",
        message: `Codex worker artifact tool ${fixture.tool} ${fixture.reason}.`,
      },
    ]);
    expect(JSON.stringify(diagnostics)).not.toContain(secret);
  }

  const unrelatedDiagnostics: Array<{ code: string; message: string }> = [];
  appendDiagnostic(unrelatedDiagnostics, {
    type: "mcp_tool_call",
    status: "failed",
    server: "unrelated_server",
    tool: "record_codex_security_deep_reduction",
    result: { isError: true },
    error: null,
  });
  expect(unrelatedDiagnostics).toEqual([]);
});

test("resumes only when the exact Standard worker or reducer result is missing", async () => {
  const runtime = await loadBundledRuntime();
  const source = bundledFunction(runtime, "isMissingWorkerResult");
  const pathImport = /\(0, (import_node_path\d+)\.join\)/u.exec(source)?.[1];
  expect(pathImport).toBeDefined();
  const isMissingWorkerResult = new Function(
    pathImport!,
    `${source}\nreturn isMissingWorkerResult;`,
  )({ join }) as (error: Error, artifactDirectory: string) => boolean;
  const artifactDirectory = join(tmpdir(), "codex-security-reducer-artifacts");
  const missingResult = Object.assign(new Error("result missing"), {
    code: "ENOENT",
    path: join(artifactDirectory, "result.json"),
  });
  const diagnosedMissingResult = Object.assign(
    new Error("artifact tool failed", { cause: missingResult }),
    { code: "artifact_tool_failed" },
  );

  expect(isMissingWorkerResult(missingResult, artifactDirectory)).toBe(true);
  expect(isMissingWorkerResult(diagnosedMissingResult, artifactDirectory)).toBe(
    true,
  );
  expect(
    isMissingWorkerResult(
      Object.assign(new Error("different artifact missing"), {
        code: "ENOENT",
        path: join(artifactDirectory, "candidates.jsonl"),
      }),
      artifactDirectory,
    ),
  ).toBe(false);
  expect(
    isMissingWorkerResult(
      Object.assign(new Error("result cannot be read"), {
        code: "EACCES",
        path: join(artifactDirectory, "result.json"),
      }),
      artifactDirectory,
    ),
  ).toBe(false);

  const standardContinuation = new Function(
    `${bundledFunction(runtime, "standardScanCompletionContinuation")}\nreturn standardScanCompletionContinuation;`,
  )() as (attempt: number) => string;
  expect(standardContinuation(1)).toContain("record_codex_security_scan_draft");
  expect(standardContinuation(1)).toMatch(/retry.*until it succeeds/iu);

  const continuation = new Function(
    `${bundledFunction(runtime, "reducerCompletionContinuation")}\nreturn reducerCompletionContinuation;`,
  )() as (attempt: number) => string;
  expect(continuation(1)).toContain("record_codex_security_deep_reduction");
  expect(continuation(1)).toMatch(/retry.*until it succeeds/iu);
});
