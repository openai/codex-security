import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { CodexSecurity } from "../src/api.js";
import { runWorkbench } from "../src/runtime.js";
import type { ScanLogSource } from "../src/scan-logs.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import {
  checkSavedProjection,
  savedLogTurn,
} from "./support/scan-log-lifecycle.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

for (const outcome of ["completed", "failed"] as const) {
  for (const followUp of ["prompt", "file", "none"] as const) {
    test(`saved logs retain ${outcome} scan with ${followUp} follow-up`, async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      const home = join(root, "state", "codex-home");
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      };
      await mkdir(repository);
      await writeFile(join(repository, "source.py"), "# Synthetic input\n");
      await mkdir(home, { recursive: true });
      const python = Bun.which("python3") ?? Bun.which("python");
      if (python === null) throw new Error("Python required");
      const runtime = preparedRuntime(home);
      runtime.environment = environment as Record<string, string>;
      runtime.plugin.version = JSON.parse(
        await readFile(
          join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
          "utf8",
        ),
      ).version;
      let scanId = "";
      let turns = 0;
      const threadId = randomUUID();
      const warnings: string[] = [];
      const names = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ];
      let beforeFollowUp: Buffer<ArrayBuffer>[] | undefined;
      let beforeFollowUpCost: ScanLogSource["cost"] | undefined;
      await using client = new CodexSecurity(
        {},
        {
          environment,
          prepareRuntime: async () => runtime,
          resolvePluginPython: async () => python,
          createCodex: (options) => ({
            startThread: () => ({
              id: threadId,
              async runStreamed() {
                scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
                turns++;
                if (turns === 2) {
                  const saved = await runWorkbench(
                    { python, pluginRoot: PLUGIN_ROOT, environment },
                    ["get-scan", "--scan-id", scanId],
                  );
                  beforeFollowUpCost = (saved["scan"] as ScanLogSource)["cost"];
                  if (outcome === "completed")
                    beforeFollowUp = await Promise.all(
                      names.map((name) => readFile(join(scanDir, name))),
                    );
                }
                return savedLogTurn({
                  environment: options.env!,
                  threadId,
                  turnId: turns === 1 ? "main" : "follow-up",
                  outcome: turns === 1 ? outcome : "failed",
                  draft: turns === 1 && outcome === "completed",
                });
              },
            }),
          }),
        },
        { surface: "sdk" },
      );
      const promptFile = join(root, "post-scan.md");
      await writeFile(promptFile, "Explain the saved results.");
      const run = client.run(repository, {
        outputDir: scanDir,
        ...(followUp === "prompt"
          ? { postScanPrompt: "Explain the saved results." }
          : followUp === "file"
            ? { postScanPromptFile: promptFile }
            : {}),
        onWarning: (warning) => warnings.push(warning),
      });
      if (outcome === "failed")
        await expect(run).rejects.toThrow("main failed");
      else await run;
      const command = (args: string[]) =>
        runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args);
      const scan = (await command(["get-scan", "--scan-id", scanId]))[
        "scan"
      ] as ScanLogSource;
      expect(scan.progress?.status).toBe(
        outcome === "completed" ? "complete" : "failed",
      );
      expect(turns).toBe(followUp === "none" ? 1 : 2);
      if (followUp !== "none")
        expect(warnings.join("\n")).toContain("follow-up failed");
      const saved = JSON.stringify(scan);
      const artifacts =
        outcome === "completed"
          ? await Promise.all(
              names.map((name) => readFile(join(scanDir, name))),
            )
          : [];
      if (beforeFollowUp !== undefined)
        expect(artifacts).toEqual(beforeFollowUp);
      if (followUp !== "none") expect(scan["cost"]).toEqual(beforeFollowUpCost);
      await checkSavedProjection(
        scan,
        environment,
        root,
        threadId,
        followUp === "none" ? ["main"] : ["main", "follow-up"],
      );
      expect(
        JSON.stringify(
          (await command(["get-scan", "--scan-id", scanId]))["scan"],
        ),
      ).toBe(saved);
      if (outcome === "completed")
        expect(
          await Promise.all(
            [
              "scan-manifest.json",
              "findings.json",
              "coverage.json",
              "report.md",
            ].map((name) => readFile(join(scanDir, name))),
          ),
        ).toEqual(artifacts);
    });
  }
}
