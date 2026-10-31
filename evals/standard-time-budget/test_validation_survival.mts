import assert from "node:assert/strict";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { readJson } from "../../plugins/codex-security/mcp-app/tests/support/json.ts";
import { startMcpClient } from "../../plugins/codex-security/mcp-app/tests/support/mcp-client.ts";
import { temporaryDirectory } from "../../plugins/codex-security/mcp-app/tests/support/temporary-directories.ts";
import type { ThreadEvent } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import * as sdk from "../../sdk/typescript/dist/api.js";
import {
  bundledPluginRoot,
  pluginMetadata,
} from "../../sdk/typescript/dist/runtime.js";
import type { FindingsDocument } from "../../sdk/typescript/src/models.js";
import { prepareStandardEval } from "./fixtures.mts";
import { createStandardRunner } from "./production.mts";

const { CodexSecurity } =
  sdk as unknown as typeof import("../../sdk/typescript/src/api.js");

const threadId = "synthetic-eval-thread";

for (const deferLast of [false, true]) {
  test(`completion retains checkpoint findings and grades ${deferLast ? "only validated" : "all five"} cases`, async (t) => {
    const root = await temporaryDirectory("eval-validation-survival-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const pluginRoot = await bundledPluginRoot();
    const prepared = await prepareStandardEval(root, pluginRoot);
    const { positives, files } = prepared.fixture;
    const candidates = positives.map(({ id, path, line, cwes }) => ({
      ruleId: id,
      identity: { anchor: id },
      title: `Synthetic ${id}`,
      summary: "Synthetic benchmark finding.",
      severity: { level: "high" },
      confidence: { level: "high", rationale: "Source review." },
      taxonomy: { category: id, cwe: [cwes[0]] },
      locations: [{ path, startLine: line, role: "sink" }],
      codeEvidence: [
        {
          id,
          label: "Sink",
          path,
          startLine: line,
          code: files[path].split("\n")[line - 1],
          explanation: "The cited sink.",
        },
      ],
      remediation: "Use the corresponding safe control.",
    }));
    const accepted = (deferLast ? candidates.slice(0, -1) : candidates).map(
      (candidate) => ({
        ...candidate,
        validation: {
          disposition: "reportable",
          method: "Static review",
          summary: `Verified ${candidate.ruleId} against its cited sink.`,
          limitations: ["Synthetic review."],
        },
        provenance: { source: "local_plugin", candidateId: candidate.ruleId },
      }),
    );
    const withheld = candidates.at(-1)!;
    const deferred = deferLast
      ? [
          {
            id: withheld.ruleId,
            candidateId: withheld.ruleId,
            candidate: withheld,
            reason: "Awaiting verification.",
            paths: [withheld.locations[0]!.path],
          },
        ]
      : [];

    async function* scanEvents(
      env: Record<string, string>,
    ): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: threadId };
      yield { type: "turn.started" };
      // Discovery mentions all five candidates, including any deferred case.
      yield {
        type: "item.completed",
        item: {
          type: "agent_message",
          id: "discovery",
          text: JSON.stringify({ findings: candidates }),
        },
      };
      const client = await startMcpClient(
        {
          command: process.execPath,
          args: [join(pluginRoot, "mcp", "server.mjs"), "--stdio"],
          env,
        },
        "validation-survival",
      );
      try {
        for (const complete of [false, true]) {
          const result = await client.request("tools/call", {
            name: "record_codex_security_scan_draft",
            arguments: {
              scanId: env.CODEX_SECURITY_SCAN_ID,
              complete,
              threatModel: { summary: "Synthetic account portal." },
              findings: complete ? [] : accepted,
              reviewState: {
                surfaces: [],
                explicitExclusions: [],
                deferred: complete ? [] : deferred,
              },
            },
            _meta: { "openai/threadId": threadId },
          });
          assert.notEqual(result.isError, true, JSON.stringify(result.content));
        }
      } finally {
        await client.close();
      }
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

    const codexHome = join(root, "home");
    await mkdir(codexHome);
    const run = createStandardRunner({
      stateRoot: join(root, "states"),
      outputRoot: join(root, "results"),
      environment: {
        PATH: process.env.PATH,
        PYTHON: process.env.PYTHON,
        SystemRoot: process.env.SystemRoot,
        HOME: root,
        USERPROFILE: root,
        CODEX_HOME: codexHome,
      },
      createClient: (config, dependencies) =>
        new CodexSecurity(
          config,
          {
            ...dependencies,
            prepareRuntime: async () => ({
              codexHome,
              plugin: {
                pluginRoot,
                installedRoot: pluginRoot,
                marketplaceRoot: pluginRoot,
                marketplaceName: "codex-security-sdk",
                ...(await pluginMetadata(pluginRoot)),
              },
              environment: Object.fromEntries(
                Object.entries(dependencies.environment).filter(
                  (entry): entry is [string, string] => entry[1] !== undefined,
                ),
              ),
              credentialsAvailable: true,
            }),
          },
          { surface: "sdk" },
        ),
      createCodex: async ({ env }) => ({
        startThread: () => ({
          id: threadId,
          runStreamed: async (prompt) => {
            for (const { id } of positives) assert.ok(!prompt.includes(id), id);
            return { events: scanEvents(env!) };
          },
        }),
      }),
    });
    const { report, semanticResult } = await run(prepared, {
      model: "synthetic-model",
      pair: 1,
      variant: "baseline",
      observation: {},
    });
    assert.equal(report.passed, !deferLast);
    assert.equal(report.foundCount, accepted.length);
    assert.equal(report.safeControlFindings, 0);
    assert.deepEqual(report.evidenceErrors, []);
    assert.deepEqual(
      report.cases,
      positives.map(({ id }, index) => ({
        id,
        found: index < accepted.length,
      })),
    );
    const scanDir = report.scanDir!;
    const archived: FindingsDocument = await readJson(scanDir, "findings.json");
    assert.deepEqual(semanticResult.findings, archived.findings);
    assert.equal(archived.findings.length, accepted.length);
    const markdown = await readFile(report.reportPath!, "utf8");
    for (const expected of accepted) {
      const retained = archived.findings.find(
        ({ ruleId }) => ruleId === expected.ruleId,
      );
      assert.ok(retained, expected.ruleId);
      assert.equal(
        retained.provenance.candidateId,
        expected.provenance.candidateId,
      );
      for (const field of [
        "identity",
        "locations",
        "validation",
        "codeEvidence",
      ] as const)
        assert.deepEqual(retained[field], expected[field]);
      assert.ok(markdown.includes(expected.title), expected.title);
    }
    if (deferLast) assert.ok(!markdown.includes(withheld.title));
    const { scan } = await readJson(scanDir, "scan-manifest.json");
    assert.equal(scan.id, report.scanId);
    assert.equal(scan.status, "completed");
    assert.ok(scan.sealedAt);
    const { checkpoint } = await readJson(scanDir, "checkpoint-head.json");
    const terminal = await readJson(scanDir, "checkpoints", checkpoint);
    assert.notEqual(terminal.complete, false);
    assert.deepEqual(terminal.reviewState.deferred, deferred);
  });
}
