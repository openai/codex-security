import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { loadSourceModule, privateDirectory } from "./helpers/source.mjs";

const applicationRoot = path.resolve(import.meta.dirname, "..");
const sdkRoot = path.resolve(applicationRoot, "../../../sdk/typescript");
const pluginRoot =
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
  path.join(sdkRoot, "_bundled_plugin");
const { readKnowledgeBaseSnapshot } = await loadSourceModule<
  typeof import("../../../../sdk/typescript/src/knowledge-base.js")
>(new URL("../../../../sdk/typescript/src/knowledge-base.ts", import.meta.url));
const { scanInputIdentity, saveScanKnowledge } = await loadSourceModule<
  typeof import("../../../../sdk/typescript/src/scan-inputs.js")
>(new URL("../../../../sdk/typescript/src/scan-inputs.ts", import.meta.url));
const { resolveDeepScanConfig } = await loadSourceModule<
  typeof import("../../../../sdk/typescript/src/deep-config.js")
>(new URL("../../../../sdk/typescript/src/deep-config.ts", import.meta.url));
const { nativeScanConfiguration } = await loadSourceModule<
  typeof import("../../../../sdk/typescript/src/execution-preparation.js")
>(
  new URL(
    "../../../../sdk/typescript/src/execution-preparation.ts",
    import.meta.url,
  ),
);
const { createProviderProfile, restoreProviderProfile } =
  await loadSourceModule<
    typeof import("../../../../sdk/typescript/src/provider-profile.js")
  >(
    new URL(
      "../../../../sdk/typescript/src/provider-profile.ts",
      import.meta.url,
    ),
  );

type Scan = {
  scanId: string;
  scanDir: string;
  handoffClaimToken: string;
  progress: { status: string };
};
type ToolArguments = NonNullable<
  Parameters<Client["callTool"]>[0]["arguments"]
>;
type ToolResponse = Awaited<ReturnType<Client["callTool"]>>;
const model = "synthetic-original-model";
const reasoningEffort = "medium";
const userContext = "  Inspect synthetic authentication.  ";
const deepConfiguration = "[deep_scan]\nworkers = 2\nsubagents = 1\n";
const selectedConfiguration = `model = "${model}"\nmodel_reasoning_effort = "${reasoningEffort}"\n`;

for (const scenario of [
  "unchanged",
  "equivalent config",
  "knowledge",
  "added knowledge",
  "missing knowledge",
  "whitespace knowledge",
  "padded knowledge path",
  "plain knowledge path",
  "deep config",
  "model",
  "reasoning effort",
  "selected config",
  "turn metadata precedence",
  "legacy recipe",
  "instructions unchanged",
  "instructions changed",
  "instructions removed",
  "instructions absent",
  "instructions added",
  "instruction file unchanged",
  "instruction file content changed",
  "instruction file legacy",
  "instruction file empty",
  "instruction file missing",
  "instruction file changed",
  "instruction file removed",
  "instruction file explicit",
  "instruction file running",
  "compact prompt file unchanged",
  "compact prompt file content changed",
  "compact prompt file legacy",
  "compact prompt file empty",
  "compact prompt file missing",
  "compact prompt file changed",
  "compact prompt file removed",
  "compact prompt file explicit",
  "compact prompt file running",
  "running scan ID",
  "running target",
]) {
  const change = scenario.replace(/^compact prompt file /, "instruction file ");
  const promptFile = scenario.startsWith("compact prompt file ")
    ? "experimental_compact_prompt_file"
    : "model_instructions_file";
  const promptFileDigestKey = scenario.startsWith("compact prompt file ")
    ? "compactPromptFileSha256"
    : "modelInstructionsFileSha256";
  test(`native target reuse after MCP restart: ${scenario}`, async () => {
    const root = await privateDirectory("native-completed-reuse-");
    const repository = path.join(root, "repository");
    const knowledgePath = path.join(
      root,
      change === "padded knowledge path" || change === "plain knowledge path"
        ? "knowledge guidance.md"
        : "knowledge.md",
    );
    const deepConfigPath = path.join(root, "deep.toml");
    const selectedConfigPath = path.join(root, "selected.toml");
    const originalInstructionFile = path.join(root, "instructions-a.md");
    const changedInstructionFile = path.join(root, "instructions-b.md");
    const environment = {
      ...process.env,
      CODEX_SECURITY_SCAN_ROOT: path.join(root, "scans"),
      CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      CODEX_HOME: path.join(root, "home"),
      CODEX_SECURITY_KNOWLEDGE_BASE:
        change === "added knowledge" ||
        change === "legacy recipe" ||
        change === "whitespace knowledge"
          ? ""
          : knowledgePath,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: deepConfigPath,
      CODEX_SECURITY_CONFIG_PATH: selectedConfigPath,
      // A fresh scan must reach preparation; no model service is used.
      CODEX_CLI_PATH: path.join(root, "missing-codex"),
      CODEX_API_KEY: "",
      OPENAI_API_KEY: "",
    };
    const owner = "synthetic-reuse-owner";
    const instructionFileCase = change.startsWith("instruction file ");
    const running =
      change === "running scan ID" ||
      change === "running target" ||
      change === "instruction file running";
    const instructionCase =
      change.startsWith("instructions ") || instructionFileCase || running;
    const originalInstructions =
      instructionCase &&
      change !== "instructions absent" &&
      change !== "instructions added"
        ? "Inspect synthetic authentication boundaries."
        : undefined;
    const selectedConfig = (
      instructions: string | undefined,
      instructionFile?: string,
    ) =>
      selectedConfiguration +
      (instructions === undefined
        ? ""
        : `developer_instructions = ${JSON.stringify(instructions)}\n`) +
      (instructionFile === undefined
        ? ""
        : `${promptFile} = ${JSON.stringify(path.basename(instructionFile))}\n`);
    let client: Client | undefined;
    const workbench = (
      args: string[],
      input?: Record<string, unknown>,
    ): { scan: Scan; scans: Scan[] } =>
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
    const connect = async () => {
      const next = new Client({ name: "native-reuse-test", version: "1.0.0" });
      await next.connect(
        new StdioClientTransport({
          command: process.execPath,
          args: [path.join(pluginRoot, "mcp/server.mjs"), "--stdio"],
          cwd: applicationRoot,
          env: environment,
        }),
      );
      return next;
    };
    const call = (
      name: string,
      args: ToolArguments,
      turn: Record<string, string> = {
        model,
        reasoning_effort: reasoningEffort,
      },
    ) => {
      assert.ok(client);
      return client.callTool({
        name,
        arguments: args,
        _meta: {
          "openai/threadId": owner,
          "x-codex-turn-metadata": turn,
          "codex/sandbox-state-meta": {
            permissionProfile: {
              type: "managed",
              file_system: {
                type: "restricted",
                entries: [
                  {
                    path: { type: "special", value: { kind: "root" } },
                    access: "read",
                  },
                ],
              },
              network: "restricted",
            },
            sandboxCwd: pathToFileURL(repository).href,
          },
        },
      });
    };
    const successful = (response: ToolResponse): Record<string, unknown> => {
      assert.notEqual(response.isError, true, JSON.stringify(response.content));
      assert.ok(response.structuredContent);
      return response.structuredContent as Record<string, unknown>;
    };
    try {
      await Promise.all([
        mkdir(repository),
        mkdir(environment.CODEX_SECURITY_SCAN_ROOT, { mode: 0o700 }),
        mkdir(environment.CODEX_HOME, { mode: 0o700 }),
      ]);
      await writeFile(path.join(repository, "app.py"), "print('fixture')\n");
      await writeFile(knowledgePath, "Original synthetic guidance.\n");
      await writeFile(deepConfigPath, deepConfiguration);
      await writeFile(
        selectedConfigPath,
        selectedConfig(
          originalInstructions,
          instructionFileCase ? originalInstructionFile : undefined,
        ),
      );
      if (instructionFileCase) {
        await writeFile(
          originalInstructionFile,
          change === "instruction file empty"
            ? ""
            : "Original synthetic model instructions.\n",
        );
        await writeFile(
          changedInstructionFile,
          "Different synthetic model instructions.\n",
        );
      }
      const nativeConfig = instructionFileCase
        ? await nativeScanConfiguration(
            environment,
            { model, reasoningEffort },
            1,
          )
        : undefined;
      if (nativeConfig)
        assert.equal(nativeConfig[promptFile], originalInstructionFile);
      const profile = instructionCase
        ? await createProviderProfile(environment.CODEX_HOME, {
            analytics: { enabled: false },
            ...(nativeConfig ??
              (originalInstructions === undefined
                ? {}
                : { developer_instructions: originalInstructions })),
          })
        : undefined;
      const originalProfile = profile
        ? await readFile(profile.path)
        : undefined;
      const knowledge = environment.CODEX_SECURITY_KNOWLEDGE_BASE
        ? await readKnowledgeBaseSnapshot([knowledgePath])
        : undefined;
      const deep = (await resolveDeepScanConfig({}, deepConfigPath)).settings;
      const begun = workbench([
        "begin-deep-scan",
        "--target-path",
        repository,
        "--thread-id",
        owner,
        "--user-context",
        userContext,
        "--model",
        model,
        "--reasoning-effort",
        reasoningEffort,
      ]);
      const { scanId, scanDir, handoffClaimToken } = begun.scan;
      const recipe = {
        repository,
        mode: "deep",
        target: { kind: "repository", paths: [] },
        config: { model, model_reasoning_effort: reasoningEffort },
        ...(profile
          ? { providerProfile: { name: profile.name, home: "ambient" } }
          : {}),
        ...(knowledge ? { knowledgeBasePaths: [knowledgePath] } : {}),
        ...(change === "legacy recipe"
          ? {}
          : {
              scanInputs: {
                ...scanInputIdentity(userContext.trim(), knowledge),
                ...(instructionFileCase && change !== "instruction file legacy"
                  ? {
                      [promptFileDigestKey]: createHash("sha256")
                        .update(await readFile(originalInstructionFile))
                        .digest("hex"),
                    }
                  : {}),
              },
              deepScan: deep,
            }),
      };
      if (profile) {
        const saved = await restoreProviderProfile(
          recipe.config,
          recipe.providerProfile,
          environment,
        );
        assert.equal(saved.developer_instructions, originalInstructions);
        if (instructionFileCase)
          assert.equal(saved[promptFile], originalInstructionFile);
      }
      if (knowledge) await saveScanKnowledge(scanDir, knowledge);
      workbench(
        [
          "register-cli-scan",
          "--repository",
          repository,
          "--scan-dir",
          scanDir,
          "--registration-json-stdin",
        ],
        { scanId, threadId: owner, claimToken: handoffClaimToken, recipe },
      );
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
      client = await connect();
      successful(
        await call("record_codex_security_scan_draft", {
          scanId,
          handoffClaimToken,
          findings: [],
          coverage: {
            completeness: "complete",
            surfaces: [{ label: "Synthetic fixture", disposition: "rejected" }],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      workbench([
        "prepare-scan-completion",
        "--scan-id",
        scanId,
        "--claim-token",
        handoffClaimToken,
      ]);
      const artifacts = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ];
      const original = await Promise.all(
        artifacts.map((name) => readFile(path.join(scanDir, name))),
      );
      if (!running)
        successful(
          await call("start_codex_security_deep_scan", {
            scanId,
            handoffClaimToken,
          }),
        );
      assert.equal(
        workbench(["get-scan", "--scan-id", scanId]).scan.progress.status,
        running ? "running" : "complete",
      );
      await client.close();
      client = undefined;
      if (change === "equivalent config") {
        await writeFile(
          deepConfigPath,
          "# Same effective settings\n[deep_scan]\nsubagents = 1\nworkers = 2\n",
        );
        await writeFile(
          selectedConfigPath,
          `# Same effective settings\nmodel_reasoning_effort = "${reasoningEffort}"\nmodel = "${model}"\n`,
        );
      }
      if (change === "knowledge")
        await writeFile(knowledgePath, "Changed synthetic guidance.\n");
      if (change === "deep config")
        await writeFile(
          deepConfigPath,
          "[deep_scan]\nworkers = 3\nsubagents = 1\n",
        );
      if (change === "added knowledge")
        environment.CODEX_SECURITY_KNOWLEDGE_BASE = knowledgePath;
      if (change === "whitespace knowledge")
        environment.CODEX_SECURITY_KNOWLEDGE_BASE = " \t ";
      if (change === "padded knowledge path")
        environment.CODEX_SECURITY_KNOWLEDGE_BASE = `  ${knowledgePath}  `;
      if (
        change === "instructions changed" ||
        change === "instructions added" ||
        (running && !instructionFileCase)
      )
        await writeFile(
          selectedConfigPath,
          selectedConfig("Inspect synthetic storage boundaries."),
        );
      if (change === "instructions removed")
        await writeFile(selectedConfigPath, selectedConfig(undefined));
      if (change === "instruction file content changed")
        await writeFile(
          originalInstructionFile,
          "Changed instructions at the same path.\n",
        );
      if (
        [
          "instruction file missing",
          "instruction file explicit",
          "instruction file running",
        ].includes(change)
      ) {
        await rm(originalInstructionFile);
        await rm(changedInstructionFile);
      }
      if (instructionFileCase) {
        const currentFile = [
          "instruction file unchanged",
          "instruction file content changed",
          "instruction file legacy",
          "instruction file empty",
          "instruction file missing",
        ].includes(change)
          ? originalInstructionFile
          : change === "instruction file removed"
            ? undefined
            : changedInstructionFile;
        await writeFile(
          selectedConfigPath,
          selectedConfig(originalInstructions, currentFile),
        );
        const current = await nativeScanConfiguration(
          environment,
          { model, reasoningEffort },
          1,
        );
        assert.equal(current[promptFile], currentFile);
        assert.equal(current.developer_instructions, originalInstructions);
      }
      if (change === "missing knowledge" || (running && !instructionFileCase))
        await rm(knowledgePath);
      if (running && !instructionFileCase)
        await writeFile(deepConfigPath, "invalid TOML [");
      if (change === "selected config" || change === "turn metadata precedence")
        await writeFile(
          selectedConfigPath,
          'model = "synthetic-selected-model"\nmodel_reasoning_effort = "synthetic-selected-effort"\n',
        );
      const turn: Record<string, string> =
        change === "selected config"
          ? {}
          : {
              model: change === "model" ? "synthetic-changed-model" : model,
              reasoning_effort:
                change === "reasoning effort"
                  ? "synthetic-future-effort"
                  : reasoningEffort,
            };
      client = await connect();
      if (!running && change !== "instruction file explicit")
        assert.equal(
          successful(
            await call("start_codex_security_deep_scan", {
              scanId,
              handoffClaimToken,
            }),
          ).scanId,
          scanId,
          "Explicit identity preserves the saved result despite ambient changes.",
        );
      const response = await call(
        "start_codex_security_deep_scan",
        change === "running scan ID" || change === "instruction file explicit"
          ? { scanId, handoffClaimToken }
          : { targetPath: repository, userContext },
        turn,
      );
      if (
        running ||
        change === "unchanged" ||
        change === "equivalent config" ||
        change === "turn metadata precedence" ||
        change === "instructions unchanged" ||
        change === "instructions absent" ||
        change === "instruction file unchanged" ||
        change === "instruction file empty" ||
        change === "instruction file explicit" ||
        change === "whitespace knowledge" ||
        change === "padded knowledge path" ||
        change === "plain knowledge path"
      ) {
        assert.equal(successful(response).scanId, scanId);
        assert.equal(workbench(["list-scans"]).scans.length, 1);
      } else if (
        change === "missing knowledge" ||
        change === "instruction file missing"
      ) {
        assert.equal(response.isError, true);
        assert.match(JSON.stringify(response.content), /knowledge|ENOENT/i);
        assert.equal(workbench(["list-scans"]).scans.length, 1);
      } else {
        assert.equal(response.isError, true);
        assert.match(JSON.stringify(response.content), /Codex executable/i);
        const scans = workbench(["list-scans"]).scans;
        assert.equal(scans.length, 2, "Changed inputs register a fresh scan.");
        assert.ok(scans.some((scan) => scan.scanId !== scanId));
      }
      assert.equal(
        workbench(["get-scan", "--scan-id", scanId]).scan.progress.status,
        "complete",
      );
      assert.deepEqual(
        await Promise.all(
          artifacts.map((name) => readFile(path.join(scanDir, name))),
        ),
        original,
      );
      if (profile)
        assert.deepEqual(await readFile(profile.path), originalProfile);
    } finally {
      await client?.close();
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const [promptFile, scenario] of [
  "model_instructions_file",
  "experimental_compact_prompt_file",
].flatMap((promptFile) =>
  [
    "instruction-repository-PATH",
    "saved-instruction-repository-PATH",
    "running-instruction-repository-PATH",
    "target-repository-PATH",
    "explicit-external",
  ].map((scenario) => [promptFile, scenario] as const),
)) {
  test(
    `public MCP prompt executable boundary: ${promptFile}, ${scenario}`,
    {
      skip:
        process.platform === "win32"
          ? "Synthetic executable uses a POSIX shebang."
          : false,
    },
    async () => {
      const root = await privateDirectory("external-instructions-exec-");
      const target = path.join(root, "target");
      const guidance = path.join(root, "guidance");
      const trusted = path.join(root, "trusted");
      const home = path.join(root, "home");
      const helpers = path.join(root, "helpers");
      const tools = JSON.parse(
        execFileSync(
          process.env.PYTHON ?? "python3",
          [
            "-c",
            'import json, shutil, sys; print(json.dumps({"python": sys.executable, "git": shutil.which("git")}))',
          ],
          { encoding: "utf8" },
        ),
      ) as { python: string; git: string };
      const marker = path.join(root, "executed.json");
      const configPath = path.join(root, "selected.toml");
      const executableRoot =
        scenario === "target-repository-PATH"
          ? target
          : scenario === "explicit-external"
            ? trusted
            : guidance;
      const executable = path.join(executableRoot, "codex");
      let client: Client | undefined;
      try {
        for (const directory of [target, guidance, trusted, home, helpers])
          await mkdir(directory);
        assert.ok(tools.git);
        await symlink(process.execPath, path.join(helpers, "node"));
        await symlink(tools.git, path.join(helpers, "git"));
        await mkdir(path.join(guidance, ".git"));
        await mkdir(path.join(target, ".git"));
        await writeFile(
          path.join(target, "app.py"),
          "print('synthetic fixture')\n",
        );
        await writeFile(
          path.join(guidance, "instructions.md"),
          "Synthetic security guidance.\n",
        );
        await writeFile(
          executable,
          `#!${process.execPath}\nconst fs = require('node:fs'); fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify({argv:process.argv.slice(2), syntheticProvider:process.env.SYNTHETIC_PROVIDER_KEY === 'synthetic-provider-proof-value'})); process.stderr.write('synthetic Codex fixture stopped after marker\\n'); process.exit(42);\n`,
        );
        await chmod(executable, 0o700);
        await writeFile(
          configPath,
          `model = "synthetic-proof-model"\nmodel_provider = "synthetic"\n${promptFile} = ${JSON.stringify(path.join(guidance, "instructions.md"))}\n[model_providers.synthetic]\nname = "Synthetic"\nbase_url = "https://provider.example.test/v1"\nenv_key = "SYNTHETIC_PROVIDER_KEY"\nrequires_openai_auth = false\nwire_api = "responses"\n`,
        );
        const environment: Record<string, string> = Object.fromEntries(
          Object.entries(process.env).filter(
            (entry): entry is [string, string] => entry[1] !== undefined,
          ),
        );
        Object.assign(environment, {
          CODEX_HOME: home,
          CODEX_SECURITY_SCAN_ROOT: path.join(root, "scans"),
          CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
          CODEX_SECURITY_CONFIG_PATH: configPath,
          CODEX_API_KEY: "",
          OPENAI_API_KEY: "",
          SYNTHETIC_PROVIDER_KEY: "synthetic-provider-proof-value",
          PYTHON: tools.python,
          PATH: [executableRoot, helpers].join(path.delimiter),
        });
        delete environment.CODEX_CLI_PATH;
        delete environment.CODEX_SECURITY_KNOWLEDGE_BASE;
        delete environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
        if (scenario === "explicit-external")
          environment.CODEX_CLI_PATH = executable;
        let savedScanId: string | undefined;
        let savedClaimToken: string | undefined;
        if (
          scenario === "saved-instruction-repository-PATH" ||
          scenario === "running-instruction-repository-PATH"
        ) {
          const workbench = (args: string[], input?: Record<string, unknown>) =>
            JSON.parse(
              execFileSync(
                tools.python,
                [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
                {
                  env: environment,
                  encoding: "utf8",
                  ...(input === undefined
                    ? {}
                    : { input: JSON.stringify(input) }),
                },
              ),
            );
          const begun = workbench([
            "begin-deep-scan",
            "--target-path",
            target,
            "--thread-id",
            "synthetic-executable-proof-owner",
          ]);
          const { scanId, scanDir, handoffClaimToken } = begun.scan;
          savedScanId = scanId;
          savedClaimToken = handoffClaimToken;
          workbench(
            [
              "register-cli-scan",
              "--repository",
              target,
              "--scan-dir",
              scanDir,
              "--registration-json-stdin",
            ],
            {
              scanId,
              threadId: "synthetic-executable-proof-owner",
              claimToken: handoffClaimToken,
              recipe: {
                repository: target,
                mode: "deep",
                target: { kind: "repository", paths: [] },
                config: {
                  model: "synthetic-proof-model",
                  [promptFile]: path.join(guidance, "instructions.md"),
                },
              },
            },
          );
          // Saved instructions take precedence over a changed ambient selection.
          await writeFile(
            configPath,
            `${promptFile} = ${JSON.stringify(path.join(trusted, "ignored.md"))}\n`,
          );
        }
        client = new Client({
          name: "synthetic-executable-boundary-proof",
          version: "1.0.0",
        });
        await client.connect(
          new StdioClientTransport({
            command: process.execPath,
            args: [path.join(pluginRoot, "mcp/server.mjs"), "--stdio"],
            cwd: target,
            env: environment,
          }),
        );
        const response = await client.callTool(
          {
            name: "start_codex_security_deep_scan",
            arguments:
              savedScanId === undefined ||
              scenario === "running-instruction-repository-PATH"
                ? { targetPath: target }
                : { scanId: savedScanId, handoffClaimToken: savedClaimToken },
            _meta: {
              "openai/threadId": "synthetic-executable-proof-owner",
              "x-codex-turn-metadata": {
                model: "synthetic-proof-model",
                reasoning_effort: "medium",
              },
              "codex/sandbox-state-meta": {
                permissionProfile: {
                  type: "managed",
                  file_system: {
                    type: "restricted",
                    entries: [
                      {
                        path: { type: "special", value: { kind: "root" } },
                        access: "read",
                      },
                    ],
                  },
                  network: "restricted",
                },
                sandboxCwd: pathToFileURL(target).href,
              },
            },
          },
          undefined,
          { timeout: 30000 },
        );
        const observed = await readFile(marker, "utf8").then(
          (text) => JSON.parse(text),
          (error) => (error.code === "ENOENT" ? null : Promise.reject(error)),
        );
        if (scenario !== "explicit-external") {
          assert.equal(observed, null);
          assert.equal(response.isError, true);
          assert.match(
            JSON.stringify(response.content),
            /outside the scan target/,
          );
        } else {
          assert.ok(observed);
          assert.equal(observed.syntheticProvider, true);
        }
      } finally {
        await client?.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}
