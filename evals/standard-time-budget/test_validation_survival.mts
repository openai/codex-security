import assert from "node:assert/strict";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { importModule } from "../../plugins/codex-security/mcp-app/tests/import-module.ts";
import { temporaryDirectory } from "../../plugins/codex-security/mcp-app/tests/support/temporary-directories.ts";
import type { ThreadEvent } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import * as sdk from "../../sdk/typescript/dist/api.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "../../sdk/typescript/src/models.js";
import {
  bundledPluginRoot,
  resolvePluginPython,
  runWorkbench,
} from "../../sdk/typescript/dist/runtime.js";
import { prepareStandardEval } from "./fixtures.mts";
import { gradeResult } from "./grade.mts";
import { createStandardRunner } from "./production.mts";

const { CodexSecurity } =
  sdk as unknown as typeof import("../../sdk/typescript/src/api.js");
const { createScanArtifactContext, recordCodexSecurityScanDraftViaWorkbench } =
  await importModule({
    stdin: {
      contents:
        'export { createScanArtifactContext } from "./artifact-context.ts"; export { recordCodexSecurityScanDraftViaWorkbench } from "./artifact-scan-draft.ts";',
      resolveDir: fileURLToPath(
        new URL("../../plugins/codex-security/mcp-app/src/", import.meta.url),
      ),
    },
  });

for (const deferred of [false, true]) {
  test(`production completion grades retained findings, not deferred candidates: deferred=${deferred}`, async (context) => {
    const root = await temporaryDirectory("eval-validation-survival-", true);
    context.after(() => rm(root, { recursive: true, force: true }));
    const pluginRoot = await bundledPluginRoot();
    const prepared = await prepareStandardEval(root, pluginRoot);
    const python = await resolvePluginPython();
    const codexHome = join(root, "home");
    await mkdir(codexHome);
    const plugin = JSON.parse(
      await readFile(join(pluginRoot, ".codex-plugin/plugin.json"), "utf8"),
    );
    const findings = prepared.fixture.positives.map((expected, index) => ({
      ruleId: expected.id,
      identity: { anchor: expected.id },
      title: `Synthetic ${expected.id}`,
      summary: "A synthetic finding grounded in the benchmark source.",
      severity: { level: "high" },
      confidence: { level: "high", rationale: "Synthetic validation result." },
      taxonomy: { category: expected.id, cwe: [expected.cwes[0]] },
      locations: [
        { path: expected.path, startLine: expected.line, role: "sink" },
      ],
      validation: {
        disposition: "reportable",
        method: "Synthetic static review",
        summary: "Synthetic validation accepted this finding.",
        limitations: ["No model-driven validation was performed."],
      },
      codeEvidence: [
        {
          id: `evidence-${index}`,
          label: "Source evidence",
          path: expected.path,
          startLine: expected.line,
          code: prepared.fixture.files[expected.path].split("\n")[
            expected.line - 1
          ],
          explanation: "The cited source line is unchanged by publication.",
        },
      ],
      remediation: "Apply the corresponding safe control in the fixture.",
      provenance: { source: "local_plugin" },
    }));
    assert.equal(gradeResult({ findings }, prepared.fixture).passed, true);
    const withheld = prepared.fixture.positives.at(-1)!;
    const accepted = deferred ? findings.slice(0, -1) : findings;
    const deferredWork: CoverageDocument["deferred"] = deferred
      ? [
          {
            id: withheld.id,
            reason: `Unverified candidate: ${withheld.id}`,
            paths: [withheld.path],
          },
        ]
      : [];
    const commands: string[] = [];
    let stateDirectory = "";
    let scanId = "";
    const workbench = (args: string[]) =>
      runWorkbench(
        {
          python,
          pluginRoot,
          environment: {
            PATH: process.env.PATH,
            CODEX_SECURITY_STATE_DIR: stateDirectory,
          },
        },
        args,
      );
    const run = createStandardRunner({
      stateRoot: join(root, "states"),
      outputRoot: join(root, "results"),
      environment: { PATH: process.env.PATH },
      createClient: (config, dependencies) => {
        stateDirectory = dependencies.environment["CODEX_SECURITY_STATE_DIR"]!;
        return new CodexSecurity(
          config,
          {
            ...dependencies,
            prepareRuntime: async () => ({
              codexHome,
              deepScanConfigPath: join(codexHome, "deep-scan.toml"),
              plugin: {
                pluginRoot,
                installedRoot: pluginRoot,
                marketplaceRoot: pluginRoot,
                marketplaceName: "codex-security-sdk",
                name: "codex-security",
                version: plugin.version,
              },
              environment: {},
              credentialsAvailable: true,
            }),
            resolvePluginPython: async () => python,
            runWorkbench: async (options, args, input) => {
              commands.push(args[0]!);
              const result = await runWorkbench(options, args, input);
              if (args[0] === "register-cli-scan")
                scanId = String(result["scanId"]);
              return result;
            },
          },
          { surface: "sdk" },
        );
      },
      createCodex: async () => ({
        startThread: () => ({
          id: "synthetic-eval-thread",
          runStreamed: async (prompt) => {
            for (const expected of prepared.fixture.positives)
              assert.equal(prompt.includes(expected.id), false);
            async function* events(): AsyncGenerator<ThreadEvent> {
              yield {
                type: "thread.started",
                thread_id: "synthetic-eval-thread",
              };
              yield { type: "turn.started" };
              // A discovered candidate is not yet a validated final finding.
              yield {
                type: "item.completed",
                item: {
                  id: "discovery",
                  type: "agent_message",
                  text: JSON.stringify({ findings }),
                },
              };
              const artifactContext = await createScanArtifactContext(
                scanId,
                workbench,
                {
                  requireRunning: true,
                  pluginRoot,
                },
              );
              const draft = {
                scanId,
                threatModel: {
                  summary: "Synthetic authenticated account portal.",
                },
                findings: accepted,
                reviewState: {
                  surfaces: [],
                  explicitExclusions: [],
                  deferred: deferredWork,
                },
              };
              await recordCodexSecurityScanDraftViaWorkbench(
                artifactContext,
                { ...draft, complete: false },
                workbench,
              );
              // The final checkpoint must retain the already accepted findings.
              await recordCodexSecurityScanDraftViaWorkbench(
                artifactContext,
                { ...draft, complete: true, findings: [] },
                workbench,
              );
              yield {
                type: "turn.completed",
                usage: {
                  input_tokens: 0,
                  cached_input_tokens: 0,
                  cache_write_input_tokens: 0,
                  output_tokens: 0,
                  reasoning_output_tokens: 0,
                },
              };
            }
            return { events: events() };
          },
        }),
      }),
    });
    const result = await run(prepared, {
      model: "synthetic-model",
      pair: 1,
      variant: "baseline",
      observation: {},
    });
    assert.ok(commands.includes("prepare-scan-completion"));
    assert.ok(commands.includes("complete-scan"));
    assert.equal(result.report.scanId, scanId);
    assert.equal(result.report.foundCount, accepted.length);
    assert.equal(result.report.passed, !deferred);
    assert.deepEqual(
      result.report.cases.filter((entry) => !entry.found),
      deferred ? [{ id: withheld.id, found: false }] : [],
    );
    const archived: FindingsDocument = JSON.parse(
      await readFile(join(result.report.scanDir!, "findings.json"), "utf8"),
    );
    assert.deepEqual(result.semanticResult.findings, archived.findings);
    assert.equal(archived.findings.length, accepted.length);
    for (const expected of accepted) {
      const retained = archived.findings.find(
        (finding) => finding.ruleId === expected.ruleId,
      );
      assert.ok(retained);
      for (const field of [
        "identity",
        "locations",
        "validation",
        "codeEvidence",
      ] as const)
        assert.deepEqual(retained[field], expected[field]);
    }
    const manifest: ScanManifest = JSON.parse(
      await readFile(
        join(result.report.scanDir!, "scan-manifest.json"),
        "utf8",
      ),
    );
    assert.equal(manifest.scan.status, "completed");
    assert.ok(manifest.scan.sealedAt);
    const head: { checkpoint: string } = JSON.parse(
      await readFile(
        join(result.report.scanDir!, "checkpoint-head.json"),
        "utf8",
      ),
    );
    const checkpoint: { reviewState: Pick<CoverageDocument, "deferred"> } =
      JSON.parse(
        await readFile(
          join(result.report.scanDir!, "checkpoints", head.checkpoint),
          "utf8",
        ),
      );
    assert.deepEqual(checkpoint.reviewState.deferred, deferredWork);
    const report = await readFile(result.report.reportPath!, "utf8");
    for (const finding of accepted) assert.ok(report.includes(finding.title));
    if (deferred) assert.equal(report.includes(findings.at(-1)!.title), false);
    assert.equal(result.report.safeControlFindings, 0);
    assert.deepEqual(result.report.evidenceErrors, []);
  });
}
