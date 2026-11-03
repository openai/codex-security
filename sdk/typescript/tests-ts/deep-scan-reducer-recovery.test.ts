import { mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { importModule } from "../../../plugins/codex-security/mcp-app/tests/import-module.ts";
import { startRpc } from "../scripts/fixtures/package-rpc.mjs";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories = createTemporaryDirectories(true);
afterEach(directories.cleanup);

test.each(["worker", "reducer"])(
  "advertises the packaged %s tool contract",
  async (layout) => {
    const root = await directories.create("codex-security-deep-tools-");
    const artifacts = join(root, layout);
    await mkdir(artifacts);
    const client = await startRpc(
      Bun.which("node")!,
      [join(PLUGIN_ROOT, "mcp", "server.mjs"), "--artifact-writer", "--stdio"],
      {
        env: {
          ...process.env,
          CODEX_SECURITY_PLUGIN_ROOT: PLUGIN_ROOT,
          CODEX_SECURITY_SCAN_ID: "test-scan",
          CODEX_SECURITY_REPO_ROOT: root,
          CODEX_SECURITY_ARTIFACT_ROOT: artifacts,
          CODEX_SECURITY_ARTIFACT_LAYOUT: layout,
          ...(layout === "reducer"
            ? {
                CODEX_SECURITY_REDUCER_CONTEXT_JSON: JSON.stringify({
                  scanRoot: root,
                  claimedWorkers: [],
                }),
              }
            : {}),
        },
      },
    );
    try {
      const { tools } = (await client.request("tools/list")) as {
        tools: Array<{
          name: string;
          inputSchema: { properties: Record<string, unknown> };
        }>;
      };
      expect(tools.map((tool) => tool.name).sort()).toEqual(
        layout === "worker"
          ? ["record_codex_security_scan_draft"]
          : [
              "get_codex_security_deep_reducer_inputs",
              "record_codex_security_deep_reduction",
            ],
      );
      for (const tool of tools)
        expect(`mcp__cs_artifacts__${tool.name}`.length).toBeLessThanOrEqual(
          64,
        );
      const record = tools.find(
        (tool) =>
          tool.name ===
          (layout === "reducer"
            ? "record_codex_security_deep_reduction"
            : "record_codex_security_scan_draft"),
      );
      expect(record?.inputSchema.properties).toHaveProperty("findings");
      expect(record?.inputSchema.properties).toHaveProperty("scope");
      expect(Object.hasOwn(record!.inputSchema.properties, "reviewState")).toBe(
        layout === "worker",
      );
    } finally {
      await client.close();
    }
    expect(client.child.exitCode).toBe(0);
  },
);

test("resumes only when the exact Standard worker or reducer result is missing", async () => {
  const runner = new URL(
    "../../../plugins/codex-security/mcp-app/src/deep-scan/worker-runner.ts",
    import.meta.url,
  );
  const {
    isMissingWorkerResult,
    standardScanCompletionContinuation,
    reducerCompletionContinuation,
  } = await importModule({
    stdin: {
      contents: `${await readFile(runner, "utf8")}
export { isMissingWorkerResult, standardScanCompletionContinuation, reducerCompletionContinuation };`,
      resolveDir: dirname(fileURLToPath(runner)),
      loader: "ts",
    },
    loader: { ".md": "text" },
  });
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

  expect(standardScanCompletionContinuation(1)).toContain(
    "record_codex_security_scan_draft",
  );
  expect(standardScanCompletionContinuation(1)).toMatch(
    /retry.*until it succeeds/iu,
  );
  expect(reducerCompletionContinuation(1)).toContain(
    "record_codex_security_deep_reduction",
  );
  expect(reducerCompletionContinuation(1)).toMatch(
    /retry.*until it succeeds/iu,
  );
});
