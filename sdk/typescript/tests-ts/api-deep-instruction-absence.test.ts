import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDeepApiFixtures, pluginRoot } from "./support/deep-api.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { loadDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import type { JsonObject } from "../src/config.js";
import { CodexSecurity } from "../src/api.js";
import type { SavedScanRecipe } from "../src/scan-registration.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { DeepScanRecoveryError } from "../src/deep-scan.js";
import { captureEnvironment } from "../tests-support/process-environment.mjs";

const { fixture, cleanup } = createDeepApiFixtures();
afterEach(cleanup);
for (const role of ["discovery", "reducer"] as const) {
  for (const scenario of ["introduced", "unchanged", "legacy"] as const) {
    const changed = scenario !== "unchanged";
    test(`native Deep known instruction absence ${role} ${scenario}`, async () => {
      // The MCP package has its own TypeScript configuration.
      const { NativeScanHost, prepareNativeScan } = await import(
        new URL(
          "../../../plugins/codex-security/mcp-app/src/native-scan.ts",
          import.meta.url,
        ).href
      );
      const h = await fixture(undefined, true);
      const python = await resolvePluginPython({
        environment: h.environment,
        protectedRoot: h.repository,
      });
      const selectedPath = join(h.root, "selected.toml");
      const deepPath = join(h.root, "deep.toml");
      const instructionPath = join(h.root, "introduced.md");
      await writeFile(selectedPath, 'model = "gpt-6-astra"\n');
      await writeFile(
        deepPath,
        `[deep_scan]\nworkers = ${role === "reducer" ? 2 : 1}\nsubagents = 3\nmax_discovery_runs = 2\nmax_time_hours = 1\nstop_after_no_new = 3\nstop_after_consecutive_errors = 2\n`,
      );
      await writeFile(
        instructionPath,
        "Synthetic instructions introduced after interruption.\n",
      );
      const nativeEnvironment = {
        CODEX_HOME: h.home,
        CODEX_CLI_PATH: process.execPath,
        CODEX_API_KEY: undefined,
        OPENAI_API_KEY: "synthetic-test-key",
        CODEX_SECURITY_CONFIG_PATH: selectedPath,
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: deepPath,
        CODEX_SECURITY_KNOWLEDGE_BASE: undefined,
        CODEX_SECURITY_STATE_DIR: h.environment["CODEX_SECURITY_STATE_DIR"],
      };
      const observations: Array<{
        mode: string;
        scanId: string;
        file: string | null;
        text: string | null;
      }> = [];
      h.observeLaunch(async (launch) => {
        const scanId = launch.options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const effective = launch.options.config!;
        const observed = JSON.parse(
          execFileSync(
            "node",
            [
              "-e",
              'const fs=require("node:fs");const c=JSON.parse(process.argv[1]);const file=typeof c.model_instructions_file==="string"?c.model_instructions_file:null;process.stdout.write(JSON.stringify({file,text:file===null?null:fs.readFileSync(file,"utf8")}));',
              JSON.stringify(effective),
            ],
            { cwd: launch.threadOptions.workingDirectory, encoding: "utf8" },
          ),
        );
        observations.push({
          mode: h.records.get(scanId)!.mode,
          scanId,
          ...observed,
        });
      });
      const command = (args: readonly string[]) =>
        runWorkbench(
          {
            python,
            pluginRoot,
            environment: h.environment,
          },
          args,
        );
      const scanId = h.options.registeredScan!.scanId;
      const readSaved = async () =>
        await command(["get-scan", "--scan-id", scanId]);
      const prepare = async (input: { recipe?: SavedScanRecipe }) => {
        const restore = captureEnvironment(Object.keys(nativeEnvironment));
        try {
          for (const [key, value] of Object.entries(nativeEnvironment)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
          }
          const prepared = await prepareNativeScan(input);
          if (input.recipe === undefined)
            expect(prepared.options.resumeScanId).toBeUndefined();
          else expect(prepared.options.resumeScanId).toBe(scanId);
          const configuration = (prepared.client as CodexSecurity).config
            .codexOverrides;
          await prepared.client.close();
          // Keep native configuration and resume options, then use the SDK fixture
          // dependencies for model events, runtime preparation and workbench observation.
          return { ...prepared, client: h.makeClient(configuration) };
        } finally {
          restore();
        }
      };
      const host = new NativeScanHost(prepare);
      const input = async () => {
        const saved = await readSaved();
        return {
          scan: saved["scan"],
          ...(saved["recipe"] !== null &&
          typeof saved["recipe"] === "object" &&
          !Array.isArray(saved["recipe"])
            ? { recipe: saved["recipe"] as unknown as SavedScanRecipe }
            : {}),
          threadId: "native-owner",
          pluginRoot,
          pythonPath: python,
          stateDirectory: h.environment["CODEX_SECURITY_STATE_DIR"],
          parentSandbox: {
            workspaceAccess: "write" as const,
            filesystemDenies: [],
          },
        };
      };
      if (role === "discovery") h.stopAfterSealing("standard");
      else h.failChildProjection(true);
      try {
        await expect(host.run(await input())).rejects.toBeInstanceOf(
          role === "discovery"
            ? ScanTransportClosedError
            : DeepScanRecoveryError,
        );
        const firstSaved = await readSaved();
        const recipe = firstSaved["recipe"] as JsonObject;
        if (scenario === "legacy") {
          const legacy = structuredClone(recipe);
          delete (legacy["scanInputs"] as JsonObject)[
            "modelInstructionsFileSha256"
          ];
          execFileSync(python, [
            "-c",
            "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE scans SET recipe_json=? WHERE id=?',(sys.argv[2],sys.argv[3])); c.commit()",
            join(
              h.environment["CODEX_SECURITY_STATE_DIR"]!,
              "workbench.sqlite3",
            ),
            JSON.stringify(legacy),
            scanId,
          ]);
        }
        const scanInputs = ((await readSaved())["recipe"] as JsonObject)[
          "scanInputs"
        ] as JsonObject;
        const before = observations.length;
        expect(before).toBeGreaterThan(0);
        expect(
          observations.every((row) => row.file === null && row.text === null),
        ).toBe(true);
        const checkpoint = await loadDeepScanCheckpoint(h.outputDir);
        const accepted: string[] = [];
        for (const [childId, child] of h.records) {
          if (child.mode !== "standard") continue;
          const childSaved = await command(["get-scan", "--scan-id", childId]);
          if (
            ((childSaved["scan"] as JsonObject)["progress"] as JsonObject)[
              "status"
            ] === "complete"
          )
            accepted.push(childId);
        }
        const reservedIds = checkpoint!.passes
          .map((pass) => pass.scanId)
          .filter(Boolean);
        if (role === "reducer") expect(accepted).toHaveLength(2);
        if (changed)
          await writeFile(
            selectedPath,
            `model = "gpt-6-astra"\nmodel_instructions_file = ${JSON.stringify(instructionPath)}\n`,
          );
        h.failChildProjection(false);
        let blockedIds: Array<string | undefined> | undefined;
        if (scenario === "introduced") {
          const beforeCommands = h.commands.length;
          await expect(host.run(await input())).rejects.toBeInstanceOf(
            DeepScanRecoveryError,
          );
          expect(observations).toHaveLength(before);
          expect(h.commands.slice(beforeCommands)).not.toContain("fail-scan");
          expect(h.commands.slice(beforeCommands)).not.toContain("cancel-scan");
          expect(scanInputs["modelInstructionsFileSha256"]).toBeNull();
          const blocked = await loadDeepScanCheckpoint(h.outputDir);
          expect(blocked?.terminalReason).not.toBe("failed");
          expect(blocked?.terminalReason).not.toBe("canceled");
          blockedIds = blocked!.passes.map((pass) => pass.scanId);
          await expect(host.run(await input())).rejects.toBeInstanceOf(
            DeepScanRecoveryError,
          );
          expect(observations).toHaveLength(before);
          expect(
            (await loadDeepScanCheckpoint(h.outputDir))!.passes.map(
              (pass) => pass.scanId,
            ),
          ).toEqual(blockedIds);
          await writeFile(selectedPath, 'model = "gpt-6-astra"\n');
        }
        const result = await host.run(await input());
        expect(result.manifest.scan.id).toBe(scanId);
        const resumed = observations.slice(before);
        expect(resumed.length).toBeGreaterThan(0);
        expect(new Set(resumed.map((row) => row.mode))).toEqual(
          new Set(role === "discovery" ? ["standard", "deep"] : ["deep"]),
        );
        expect(
          resumed.every(
            (row) =>
              row.file === (scenario === "legacy" ? instructionPath : null),
          ),
        ).toBe(true);
        expect(
          resumed.every(
            (row) =>
              row.text ===
              (scenario === "legacy"
                ? "Synthetic instructions introduced after interruption.\n"
                : null),
          ),
        ).toBe(true);
        const finalSaved = await readSaved();
        expect((finalSaved["recipe"] as JsonObject)["scanInputs"]).toEqual(
          scanInputs,
        );
        const completed = await loadDeepScanCheckpoint(h.outputDir);
        expect(completed!.mergedScanIds).toEqual(
          expect.arrayContaining(accepted),
        );
        expect(completed!.passes.map((pass) => pass.scanId)).toEqual(
          expect.arrayContaining(reservedIds),
        );
        if (blockedIds !== undefined)
          expect(completed!.passes.map((pass) => pass.scanId)).toEqual(
            blockedIds,
          );
        if (scenario === "legacy")
          expect(Object.hasOwn(scanInputs, "modelInstructionsFileSha256")).toBe(
            false,
          );
        else expect(scanInputs["modelInstructionsFileSha256"]).toBeNull();
      } finally {
        await host.close();
      }
    }, 120_000);
  }
}
