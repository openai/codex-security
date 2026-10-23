import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { privateDirectory } from "./helpers/source.mjs";

const applicationRoot = path.resolve(import.meta.dirname, "..");
const pluginRoot =
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
  path.resolve(applicationRoot, "../../../sdk/typescript/_bundled_plugin");
const artifacts = [
  "scan-manifest.json",
  "findings.json",
  "coverage.json",
  "report.md",
];
type FixtureState =
  "completed" | "sealed-running" | "fresh" | "unsealed" | "post-scan";
type SandboxMetadata = "missing" | "unsupported" | "valid";
type Scan = {
  scanId: string;
  scanDir: string;
  handoffClaimToken: string;
  progress: { status: string };
};
type ToolArguments = NonNullable<
  Parameters<Client["callTool"]>[0]["arguments"]
>;

async function fixture(state: FixtureState) {
  const root = await privateDirectory("native-saved-recovery-");
  const repository = path.join(root, "repository");
  const owner = "synthetic-recovery-owner";
  const environment = {
    ...process.env,
    CODEX_SECURITY_PLUGIN_ROOT: pluginRoot,
    CODEX_SECURITY_SCAN_ROOT: path.join(root, "scans"),
    CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
    CODEX_HOME: path.join(root, "home"),
    CODEX_SECURITY_CONFIG_PATH: "",
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: "",
    CODEX_SECURITY_KNOWLEDGE_BASE: "",
    // Saved publication needs no executable; execution controls stop before lookup.
    CODEX_CLI_PATH: path.join(root, "missing-codex"),
    CODEX_API_KEY: "",
    OPENAI_API_KEY: "",
  };
  const workbench = (
    args: string[],
    input?: Record<string, unknown>,
  ): { scan: Scan } =>
    JSON.parse(
      execFileSync(
        process.env.PYTHON ?? "python3",
        [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
        {
          env: environment,
          encoding: "utf8",
          ...(input === undefined ? {} : { input: JSON.stringify(input) }),
        },
      ),
    );
  const client = new Client({ name: "native-recovery-test", version: "1.0.0" });
  const call = (
    name: string,
    args: ToolArguments,
    metadata: SandboxMetadata = "valid",
    threadId = owner,
  ) =>
    client.callTool({
      name,
      arguments: args,
      _meta: {
        "openai/threadId": threadId,
        ...(metadata === "missing"
          ? {}
          : {
              "codex/sandbox-state-meta":
                metadata === "unsupported"
                  ? { permissionProfile: { type: "unsupported" } }
                  : {
                      permissionProfile: {
                        type: "managed",
                        file_system: {
                          type: "restricted",
                          entries: [
                            {
                              path: {
                                type: "special",
                                value: { kind: "root" },
                              },
                              access: "read",
                            },
                          ],
                        },
                        network: "restricted",
                      },
                      sandboxCwd: pathToFileURL(repository).href,
                    },
            }),
      },
    });
  try {
    await Promise.all([
      mkdir(repository),
      mkdir(environment.CODEX_SECURITY_SCAN_ROOT, { mode: 0o700 }),
      mkdir(environment.CODEX_HOME, { mode: 0o700 }),
    ]);
    await writeFile(
      path.join(repository, "app.py"),
      "print('synthetic fixture')\n",
    );
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [path.join(pluginRoot, "mcp/server.mjs"), "--stdio"],
        cwd: applicationRoot,
        env: environment,
      }),
    );
    let scan: Scan | undefined;
    if (state !== "fresh") {
      scan = workbench([
        "begin-deep-scan",
        "--target-path",
        repository,
        "--thread-id",
        owner,
        "--scan-root",
        environment.CODEX_SECURITY_SCAN_ROOT,
      ]).scan;
      const { scanId, scanDir, handoffClaimToken } = scan;
      workbench(
        [
          "register-cli-scan",
          "--repository",
          repository,
          "--scan-dir",
          scanDir,
          "--registration-json-stdin",
        ],
        {
          scanId,
          threadId: owner,
          claimToken: handoffClaimToken,
          recipe: {
            repository,
            mode: "deep",
            target: { kind: "repository", paths: [] },
            config: {},
            ...(state === "post-scan"
              ? { postScanPrompt: "Review the synthetic result." }
              : {}),
          },
        },
      );
      if (state !== "unsealed") {
        workbench([
          "set-scan-thread",
          "--scan-id",
          scanId,
          "--claim-token",
          handoffClaimToken,
          "--thread-id",
          "synthetic-merge",
        ]);
        workbench(
          [
            "save-scan-artifact",
            "--scan-id",
            scanId,
            "--claim-token",
            handoffClaimToken,
            "--artifact-path",
            "artifacts/deep-scan/checkpoint.json",
          ],
          {
            version: 3,
            startedAt: new Date().toISOString(),
            passes: [],
            mergedScanIds: [],
            noNewStreak: 0,
            consecutiveErrors: 0,
            terminalReason: "capped",
          },
        );
        const draft = await call("record_codex_security_scan_draft", {
          scanId,
          handoffClaimToken,
          findings: [],
          coverage: {
            completeness: "complete",
            surfaces: [{ label: "Synthetic fixture", disposition: "rejected" }],
            explicitExclusions: [],
            deferred: [],
          },
        });
        assert.notEqual(draft.isError, true, JSON.stringify(draft.content));
        workbench([
          "prepare-scan-completion",
          "--scan-id",
          scanId,
          "--claim-token",
          handoffClaimToken,
        ]);
      }
      if (state === "completed") {
        const completed = await call("start_codex_security_deep_scan", {
          scanId,
          handoffClaimToken,
        });
        assert.notEqual(
          completed.isError,
          true,
          JSON.stringify(completed.content),
        );
      }
      assert.equal(
        workbench(["get-scan", "--scan-id", scanId]).scan.progress.status,
        state === "completed" ? "complete" : "running",
      );
    }
    return {
      root,
      repository,
      scan,
      call,
      workbench,
      async close() {
        await client.close();
        await rm(root, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await client.close();
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

for (const state of ["completed", "sealed-running"] as const) {
  for (const metadata of ["missing", "unsupported", "valid"] as const) {
    test(`native saved recovery: ${state} with ${metadata} sandbox metadata`, async () => {
      const context = await fixture(state);
      try {
        const scan = context.scan!;
        const before = await Promise.all(
          artifacts.map((name) => readFile(path.join(scan.scanDir, name))),
        );
        const response = await context.call(
          "start_codex_security_deep_scan",
          {
            scanId: scan.scanId,
            handoffClaimToken: scan.handoffClaimToken,
          },
          metadata,
        );
        assert.notEqual(
          response.isError,
          true,
          JSON.stringify(response.content),
        );
        assert.equal(
          (response.structuredContent as Record<string, unknown> | undefined)
            ?.scanId,
          scan.scanId,
        );
        assert.equal(
          context.workbench(["get-scan", "--scan-id", scan.scanId]).scan
            .progress.status,
          "complete",
        );
        assert.deepEqual(
          await Promise.all(
            artifacts.map((name) => readFile(path.join(scan.scanDir, name))),
          ),
          before,
        );
      } finally {
        await context.close();
      }
    });
  }
}

for (const state of ["fresh", "unsealed", "post-scan"] as const) {
  for (const metadata of ["missing", "unsupported"] as const) {
    test(`native execution requires sandbox metadata: ${state} with ${metadata}`, async () => {
      const context = await fixture(state);
      try {
        const scan = context.scan;
        const response = await context.call(
          "start_codex_security_deep_scan",
          scan
            ? { scanId: scan.scanId, handoffClaimToken: scan.handoffClaimToken }
            : { targetPath: context.repository },
          metadata,
        );
        assert.equal(response.isError, true);
        assert.match(
          JSON.stringify(response.content),
          /cannot preserve the parent sandbox/,
        );
        if (scan)
          assert.equal(
            context.workbench(["get-scan", "--scan-id", scan.scanId]).scan
              .progress.status,
            "running",
          );
      } finally {
        await context.close();
      }
    });
  }
}

for (const invalid of ["owner", "claim", "seal"] as const) {
  test(`native saved recovery retains ${invalid} validation`, async () => {
    const context = await fixture("sealed-running");
    try {
      const scan = context.scan!;
      if (invalid === "seal")
        await writeFile(path.join(scan.scanDir, "findings.json"), "{}\n");
      const response = await context.call(
        "start_codex_security_deep_scan",
        {
          scanId: scan.scanId,
          handoffClaimToken:
            invalid === "claim"
              ? "00000000-0000-4000-8000-000000000000"
              : scan.handoffClaimToken,
        },
        "valid",
        invalid === "owner" ? "synthetic-other-owner" : undefined,
      );
      assert.equal(response.isError, true);
      assert.match(
        JSON.stringify(response.content),
        invalid === "owner"
          ? /owning Codex thread/
          : invalid === "claim"
            ? /another continuation/
            : /artifact|seal|findings\.json/,
      );
      assert.equal(
        context.workbench(["get-scan", "--scan-id", scan.scanId]).scan.progress
          .status,
        "running",
      );
    } finally {
      await context.close();
    }
  });
}
