import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { captureEnvironment } from "../../../../../sdk/typescript/tests-support/process-environment.mjs";

export async function nativeSemanticWorkers({
  pluginVersion,
  syntheticPermissionAppServer,
  readNativeScanSemanticInputs,
  readKnowledgeBaseSnapshot,
  saveScanKnowledge,
  createProviderProfile,
  scanInputIdentity,
  input,
  prepareNativeExecution,
  mergedCodexConfig,
  prepareAmbientRuntime,
  prepareKnowledgeBase,
  prepareExecutionSource,
  scanRuntimeCodexConfig,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  createExecutionCodex,
  collectNativeEvents,
}) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-semantic-workers-")),
  );
  const executable = join(root, "codex");
  const pluginRoot = join(root, "plugin");
  const restore = captureEnvironment([
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "CODEX_SECURITY_STATE_DIR",
    "NATIVE_PROFILE_CAPTURE",
    "NATIVE_PROFILE_MARKER",
  ]);
  const cases = [
    {
      id: "first",
      workers: 2,
      subagents: 1,
      effort: "high",
      summary: "detailed",
      selectedInstructions: "Synthetic first selected instructions.",
    },
    {
      id: "second",
      workers: 3,
      subagents: 2,
      effort: "ultra",
      summary: "none",
    },
    {
      id: "saved",
      workers: 5,
      subagents: 4,
      effort: "medium",
      summary: "detailed",
    },
    {
      id: "absent",
      workers: 4,
      subagents: 2,
      effort: "medium",
      summary: "none",
    },
  ].map((fixture) => ({
    ...fixture,
    model: `synthetic-${fixture.id}-model`,
    ambientInstructions: `Synthetic ${fixture.id} ambient instructions.`,
    documentText: `Synthetic ${fixture.id} architecture.\n`,
    home: join(root, fixture.id, "home"),
    repository: join(root, fixture.id, "repository"),
    scanDir: join(root, fixture.id, "scan"),
    document: join(root, fixture.id, "architecture.md"),
    selectedConfig: join(root, fixture.id, "selected.toml"),
    ambientInstructionFile: join(root, fixture.id, "home", "ambient.md"),
    selectedInstructionFile: join(root, fixture.id, "selected.md"),
    savedInstructionFile: join(root, fixture.id, "saved.md"),
    laterInstructionFile: join(root, fixture.id, "later.md"),
    ambientCompactFile: join(root, fixture.id, "home", "ambient-compact.md"),
    selectedCompactFile: join(root, fixture.id, "selected-compact.md"),
    savedCompactFile: join(root, fixture.id, "saved-compact.md"),
    laterCompactFile: join(root, fixture.id, "later-compact.md"),
    deepConfig: join(root, fixture.id, "deep.toml"),
    capture: join(root, `${fixture.id}.jsonl`),
  }));
  const selectEnvironment = (fixture) =>
    Object.assign(process.env, {
      CODEX_HOME: fixture.home,
      CODEX_CLI_PATH: executable,
      CODEX_SECURITY_CONFIG_PATH: fixture.selectedConfig,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: fixture.deepConfig,
      CODEX_SECURITY_KNOWLEDGE_BASE: fixture.document,
      CODEX_SECURITY_STATE_DIR: join(root, fixture.id, "state"),
      OPENAI_API_KEY: `synthetic-key-${fixture.id}`,
    });
  try {
    await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
    await writeFile(
      join(pluginRoot, ".codex-plugin/plugin.json"),
      JSON.stringify({ name: "codex-security", version: pluginVersion }),
    );
    await writeFile(
      executable,
      `#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) servePermissionProfiles();
else if (process.argv.includes("login")) console.error("Logged in using an API key");
else {
const knowledge = process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
  const { parse } = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
  const config = parse(fs.readFileSync(path.join(process.env.CODEX_HOME, "config.toml"), "utf8"));
  for (let i = 0; i < process.argv.length; i++)
    if (["-c", "--config"].includes(process.argv[i])) Object.assign(config, parse(process.argv[++i]));
  const instructionFile = config.model_instructions_file;
  const compactFile = config.experimental_compact_prompt_file;
fs.appendFileSync(process.env.NATIVE_PROFILE_CAPTURE, JSON.stringify({
  kind: "exec", argv: process.argv.slice(2), marker: process.env.NATIVE_PROFILE_MARKER,
    instructionFile, instructionText: instructionFile && fs.readFileSync(instructionFile, "utf8"),
    compactFile, compactText: compactFile && fs.readFileSync(compactFile, "utf8"),
  knowledgePath: knowledge,
  documents: knowledge ? Object.fromEntries(fs.readdirSync(knowledge).map(name => [name, fs.readFileSync(path.join(knowledge, name), "utf8")])) : {},
}) + "\\n");
console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-semantic-worker" }));
console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
      { mode: 0o700 },
    );
    delete process.env.CODEX_API_KEY;
    delete process.env.NATIVE_PROFILE_CAPTURE;
    delete process.env.NATIVE_PROFILE_MARKER;
    for (const fixture of cases) {
      await mkdir(fixture.home, { recursive: true });
      await mkdir(fixture.repository);
      await mkdir(fixture.scanDir, { mode: 0o700 });
      for (const kind of ["ambient", "selected", "saved", "later"]) {
        await writeFile(
          fixture[`${kind}InstructionFile`],
          `Synthetic ${fixture.id} ${kind} model instructions.\n`,
        );
        await writeFile(
          fixture[`${kind}CompactFile`],
          `Synthetic ${fixture.id} ${kind} compact prompt.\n`,
        );
      }
      await writeFile(
        join(fixture.home, "config.toml"),
        stringifyToml({
          model: "synthetic-ambient-model",
          developer_instructions: fixture.ambientInstructions,
          ...(fixture.id === "absent"
            ? {}
            : {
                model_instructions_file: basename(
                  fixture.ambientInstructionFile,
                ),
                experimental_compact_prompt_file: basename(
                  fixture.ambientCompactFile,
                ),
              }),
        }),
      );
      await writeFile(fixture.document, fixture.documentText);
      await writeFile(
        fixture.selectedConfig,
        stringifyToml({
          model_reasoning_summary: fixture.summary,
          ...(fixture.selectedInstructions === undefined
            ? {}
            : {
                developer_instructions: fixture.selectedInstructions,
                model_instructions_file: basename(
                  fixture.selectedInstructionFile,
                ),
                experimental_compact_prompt_file: basename(
                  fixture.selectedCompactFile,
                ),
              }),
        }),
      );
      await writeFile(
        fixture.deepConfig,
        stringifyToml({
          deep_scan: {
            workers: fixture.workers,
            subagents: fixture.subagents,
          },
        }),
      );
      selectEnvironment(fixture);
      if (fixture.id === "first")
        process.env.CODEX_SECURITY_KNOWLEDGE_BASE = `  ${fixture.document}  `;
      else if (fixture.id === "absent")
        process.env.CODEX_SECURITY_KNOWLEDGE_BASE = "   ";
      fixture.semanticInputs = await readNativeScanSemanticInputs({
        model: fixture.model,
        reasoningEffort: fixture.effort,
      });
      assert.deepEqual(
        fixture.semanticInputs.knowledgeBaseSnapshot?.documents,
        fixture.id === "absent"
          ? undefined
          : { "0-architecture.md.txt": fixture.documentText },
      );
      if (fixture.id === "saved") {
        const savedDocument = join(root, fixture.id, "saved-architecture.md");
        await writeFile(
          savedDocument,
          "Synthetic saved recipe architecture.\n",
        );
        fixture.savedSnapshot = await readKnowledgeBaseSnapshot([
          savedDocument,
        ]);
        await saveScanKnowledge(fixture.scanDir, fixture.savedSnapshot);
        const profile = await createProviderProfile(fixture.home, {
          developer_instructions: "Synthetic saved recipe instructions.",
          model_instructions_file: fixture.savedInstructionFile,
          experimental_compact_prompt_file: fixture.savedCompactFile,
        });
        fixture.recipe = {
          auth: "api-key",
          providerProfile: { name: profile.name, home: "ambient" },
          config: {
            model: "synthetic-recipe-model",
            model_reasoning_effort: "low",
            model_reasoning_summary: "none",
          },
          deepScan: {
            ...fixture.semanticInputs.deepScanSettings,
            workers: 7,
            subagents: 3,
          },
          knowledgeBasePaths: [savedDocument],
          scanInputs: scanInputIdentity(
            input().scan.userContext,
            fixture.savedSnapshot,
          ),
        };
        await writeFile(
          savedDocument,
          "Changed saved document after capture.\n",
        );
      }
      await writeFile(fixture.document, "Changed document after capture.\n");
      await writeFile(
        join(fixture.home, "config.toml"),
        stringifyToml({
          model: "synthetic-later-ambient",
          developer_instructions: "Synthetic later ambient instructions.",
          ...(fixture.id === "absent"
            ? {}
            : {
                model_instructions_file: fixture.laterInstructionFile,
                experimental_compact_prompt_file: fixture.laterCompactFile,
              }),
        }),
      );
      await writeFile(
        fixture.selectedConfig,
        stringifyToml({
          model: "synthetic-later-selected",
          model_reasoning_effort: "minimal",
          model_reasoning_summary: "auto",
          developer_instructions: "Synthetic later selected instructions.",
          model_instructions_file: fixture.laterInstructionFile,
          experimental_compact_prompt_file: fixture.laterCompactFile,
        }),
      );
      await writeFile(
        fixture.deepConfig,
        "[deep_scan]\nworkers = 1\nsubagents = 0\n",
      );
    }
    const preparation = await Promise.allSettled(
      cases.map((fixture) => {
        selectEnvironment(fixture);
        return prepareNativeExecution({
          ...input(fixture.id),
          pluginRoot,
          model: "synthetic-later-request",
          reasoningEffort: "minimal",
          semanticInputs: fixture.semanticInputs,
          recipe: fixture.recipe,
          scan: {
            ...input(fixture.id).scan,
            targetPath: fixture.repository,
            scanDir: fixture.scanDir,
          },
        });
      }),
    );
    const prepared = preparation.map((result) => {
      if (result.status === "rejected") throw result.reason;
      return result.value;
    });
    const results = await Promise.allSettled(
      cases.map(async (fixture, index) => {
        const native = prepared[index];
        const saved = fixture.recipe !== undefined;
        assert.equal(native.options.workers, saved ? 7 : fixture.workers);
        assert.equal(native.options.subagents, saved ? 3 : fixture.subagents);
        const snapshot = saved
          ? fixture.savedSnapshot
          : fixture.semanticInputs.knowledgeBaseSnapshot;
        assert.deepEqual(native.options.knowledgeBaseSnapshot, snapshot);
        assert.deepEqual(
          native.options.knowledgeBasePaths,
          saved
            ? fixture.recipe.knowledgeBasePaths
            : fixture.id === "absent"
              ? undefined
              : [fixture.document],
        );
        const ambient = native.client.dependencies.ambientExecution;
        assert.equal(
          ambient.environment.CODEX_SECURITY_KNOWLEDGE_BASE,
          undefined,
        );
        await mergedCodexConfig({
          ...native.client.config,
          codexOverrides: ambient.configuration,
        });
        const runtime = await prepareAmbientRuntime(ambient);
        const knowledge = snapshot
          ? await prepareKnowledgeBase(snapshot)
          : undefined;
        try {
          const source = prepareExecutionSource(ambient);
          const session = {
            policy: "ordinary",
            source,
            runtime,
            runtimeHome: runtime.codexHome,
            effectiveConfig: ambient.configuration,
            preflightConfig: {},
            sessionConfig: scanRuntimeCodexConfig(
              native.client.config.codexOverrides,
              fixture.repository,
              native.options.inheritedPermissions,
            ),
            inheritedPermissions: native.options.inheritedPermissions,
            authentication: source.authentication,
            approvalPolicy: "never",
            python: process.execPath,
            releaseCredentialHome: null,
          };
          for (const role of ["discovery", "merge"]) {
            const worker =
              role === "discovery"
                ? prepareDiscoveryExecution(session)
                : prepareMergeExecution(session, native.options.subagents);
            const { codex } = await createExecutionCodex(
              { surface: "sdk", command: "scan" },
              worker,
              {
                NATIVE_PROFILE_CAPTURE: fixture.capture,
                NATIVE_PROFILE_MARKER: fixture.id,
                ...(knowledge === undefined
                  ? {}
                  : { CODEX_SECURITY_KNOWLEDGE_BASE: knowledge.path }),
              },
            );
            for (const resumed of [false, true]) {
              const options = {
                workingDirectory: fixture.repository,
                skipGitRepoCheck: true,
                approvalPolicy: "never",
              };
              const thread = resumed
                ? codex.resumeThread("synthetic-semantic-worker", options)
                : codex.startThread(options);
              const events = await collectNativeEvents(
                thread,
                "Synthetic captured input boundary check.",
                {},
              );
              assert.equal(events.at(-1).type, "turn.completed");
            }
          }
          const observations = (await readFile(fixture.capture, "utf8"))
            .trim()
            .split("\n")
            .map(JSON.parse)
            .filter((row) => row.kind === "exec");
          assert.equal(observations.length, 4);
          assert.deepEqual(
            observations.map((row) => row.argv.includes("resume")),
            [false, true, false, true],
          );
          for (const observed of observations) {
            const instructionKind = saved
              ? "saved"
              : fixture.id === "first"
                ? "selected"
                : fixture.id === "absent"
                  ? undefined
                  : "ambient";
            assert.equal(
              observed.instructionFile,
              instructionKind && fixture[`${instructionKind}InstructionFile`],
            );
            assert.equal(
              observed.instructionText,
              instructionKind &&
                `Synthetic ${fixture.id} ${instructionKind} model instructions.\n`,
            );
            assert.equal(
              observed.compactFile,
              instructionKind && fixture[`${instructionKind}CompactFile`],
            );
            assert.equal(
              observed.compactText,
              instructionKind &&
                `Synthetic ${fixture.id} ${instructionKind} compact prompt.\n`,
            );
            const fragments = [];
            for (let i = 0; i < observed.argv.length; i++)
              if (["-c", "--config"].includes(observed.argv[i]))
                fragments.push(parseToml(observed.argv[++i]));
            const config = Object.assign({}, ...fragments);
            assert.equal(
              config.model,
              saved ? "synthetic-recipe-model" : fixture.model,
            );
            assert.equal(
              config.model_reasoning_effort,
              saved ? "low" : fixture.effort,
            );
            assert.equal(
              config.model_reasoning_summary,
              saved ? "none" : fixture.summary,
            );
            assert.equal(
              config.developer_instructions,
              saved
                ? "Synthetic saved recipe instructions."
                : (fixture.selectedInstructions ?? fixture.ambientInstructions),
            );
            assert.equal(
              config.features.multi_agent_v2.max_concurrent_threads_per_session,
              native.options.subagents + 1,
            );
            assert.equal(observed.marker, fixture.id);
            assert.equal(observed.knowledgePath, knowledge?.path);
            assert.deepEqual(observed.documents, snapshot?.documents ?? {});
          }
        } finally {
          await knowledge?.cleanup();
          await rm(runtime.bootstrapWorkspace, {
            recursive: true,
            force: true,
          });
        }
      }),
    );
    for (const result of results)
      if (result.status === "rejected") throw result.reason;
    assert.equal(process.env.CODEX_HOME, cases.at(-1).home);
    assert.equal(
      process.env.CODEX_SECURITY_KNOWLEDGE_BASE,
      cases.at(-1).document,
    );
  } finally {
    restore();
    await rm(root, { recursive: true, force: true });
  }
}
