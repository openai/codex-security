import { fixturePython } from "./support/python.ts";
import { readJson, snapshotScanDraft, writeJson } from "./support/json.ts";
import { workerDraft, finding } from "./scan-draft-fixture.ts";
import { gitText } from "../scripts/git.mjs";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type { TextContent, Tool } from "@modelcontextprotocol/sdk/types.js";
type CompletedResult = {
  scanId: string;
  manifest: {
    scan: {
      status: string;
      sealedAt: string;
      mode: string;
      scope: { includePaths: string[]; excludePaths: string[] };
      artifacts: unknown[];
      target: Record<string, unknown> & { snapshotDigest: string };
    };
  };
  findings: {
    findings: (Record<string, unknown> & {
      extensions: Record<string, unknown>;
      fingerprints: { primary: string };
    })[];
  };
  review: { excludedPaths: string[] };
};
type ToolResponse = Awaited<ReturnType<Client["callTool"]>>;
type WorkspaceResult = {
  workspace: { id: string; results: { scanId: string; scanDir: string } };
};
type ScanResult = {
  scan: {
    progress: Record<string, unknown>;
    reportAvailable: boolean;
    continuationThreadId?: string;
    handoffClaimToken?: string;
  };
};
import { readOnlyParentSandboxState } from "./sandbox-state.ts";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { applicationRoot, buildServer } from "./build-server.ts";

const pluginRoot = path.resolve(applicationRoot, "..");
const bundledPluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : path.resolve(applicationRoot, "../../../sdk/typescript/_bundled_plugin");
const temporaryRoot = await temporaryDirectory("codex-security-artifact-mcp-");

try {
  const runtimeBundle = path.join(temporaryRoot, "server.cjs");
  await buildServer(runtimeBundle, {
    define: {
      __dirname: JSON.stringify(path.join(bundledPluginRoot, "mcp")),
      "import.meta.url": JSON.stringify(
        pathToFileURL(path.join(bundledPluginRoot, "mcp", "server.mjs")).href,
      ),
    },
    logOverride: { "empty-import-meta": "silent" },
    target: "node20",
  });

  const shipped = path.join(bundledPluginRoot, "mcp", "server.mjs");
  for (const [bundle, label] of [
    [runtimeBundle, "source"],
    [shipped, "shipped"],
  ]) {
    await test(`${label}: parent tool registration`, () =>
      testParentToolList(bundle));
  }
  await test("shipped: private recipes stay in host storage", () =>
    testPromptDrivenPrivateRecipe(shipped));
  for (const metadata of ["valid", "missing", "unsupported"])
    await test(`shipped: native terminal results with ${metadata} sandbox metadata`, () =>
      testNativeDeepTerminalResults(shipped, metadata));
  await test("shipped: claimed parent operations", () =>
    testClaimedParentArtifactOperations(shipped, "shipped"));
  await test("shipped: semantic scan draft completion", () =>
    testSemanticScanDraftCompletion(shipped, "shipped"));
  await test("shipped: large parent draft checkpoints", () =>
    testLargeScanDraftCheckpoints(shipped, "shipped"));
  await test("shipped: compact diff scan completion", () =>
    testCompactDiffScanCompletion(shipped, "shipped"));
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function createScanFixture(label: string) {
  const fixtureRoot = path.join(temporaryRoot, label);
  const repoRoot = path.join(fixtureRoot, "repository");
  const environment = {
    CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "scans"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
  };
  await mkdir(path.join(repoRoot, "src"), { recursive: true });
  return { repoRoot, environment };
}

async function testLargeScanDraftCheckpoints(
  bundle: string,
  runtimeLabel: string,
) {
  const label = `large-draft-${runtimeLabel}-parent`;
  const { repoRoot, environment } = await createScanFixture(label);
  await writeFile(path.join(repoRoot, "src", "fixture.py"), "value = 1\n");
  const client = await startClient(bundle, environment);
  const ownerThread = `${label}-owner`;
  const call = toolCaller(client, ownerThread);

  try {
    const { scanId, scanDir, handoffClaimToken } = await startScan(
      call,
      ownerThread,
      { targetPath: repoRoot, scope: ".", mode: "standard" },
      {
        workspace: `${label}: open workspace`,
        setup: `${label}: submit setup`,
        scan: `${label}: start scan`,
        claim: `${label}: claim scan`,
        owner: `${label}: attach owner`,
      },
    );

    const mib = 1024 * 1024;
    // Exercise both one large excerpt and a request with smaller excerpts
    // that together exceed the SDK's default 10 MiB stdio buffer.
    for (const [step, sizes] of [
      [9 * mib],
      [11 * mib],
      [6 * mib, 6 * mib],
      [32],
    ].entries()) {
      const findings = sizes.map((size, index) => ({
        ...finding(`checkpoint-${step}-${index}`, "src/fixture.py"),
        evidenceExcerpt: `checkpoint-${step}-${index}:`.padEnd(size, "e"),
      }));
      const result = requireSuccessfulTool(
        await call("record_codex_security_scan_draft", {
          ...workerDraft(findings),
          scanId,
          ...(handoffClaimToken === undefined ? {} : { handoffClaimToken }),
          complete: false,
        }),
        `${label}: save checkpoint ${step}`,
      );
      assert.equal(result.status, "draft_written");
      const saved = await readJson(scanDir, "findings.json");
      assert.equal(result.findingCount, saved.findings.length);
      const head = await readJson(scanDir, "checkpoint-head.json");
      const checkpoint = await readJson(
        scanDir,
        "checkpoints",
        head.checkpoint,
      );
      assert.equal(checkpoint.complete, false);
      for (const document of [saved, checkpoint]) {
        assert.equal(document.scanId, scanId);
        for (const expected of findings) {
          const actual = document.findings.find(
            (entry: { ruleId: string }) => entry.ruleId === expected.ruleId,
          );
          assert.equal(
            actual?.evidenceExcerpt,
            expected.evidenceExcerpt,
            `${label}: checkpoint ${step} must retain every evidence byte`,
          );
        }
      }
      assert.deepEqual(await client.ping(), {});
    }
  } finally {
    await client.close();
  }
}

async function testCompactDiffScanCompletion(
  bundle: string,
  runtimeLabel: string,
) {
  const { repoRoot, environment } = await createScanFixture(
    `compact-diff-${runtimeLabel}`,
  );
  const git = (...arguments_: string[]) =>
    gitText(
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.com",
        ...arguments_,
      ],
      { cwd: repoRoot },
    ).trim();
  git("init", "-q");
  await writeFile(path.join(repoRoot, "src", "guard.py"), "allowed = True\n");
  await writeFile(path.join(repoRoot, "src", "handler.py"), "value = 1\n");
  git("add", ".");
  git("commit", "-qm", "base");
  const baseRevision = git("rev-parse", "HEAD");
  await rm(path.join(repoRoot, "src", "guard.py"));
  await writeFile(path.join(repoRoot, "src", "handler.py"), "value = 2\n");
  git("add", ".");
  git("commit", "-qm", "selected changes");
  const headRevision = git("rev-parse", "HEAD");

  const client = await startClient(bundle, environment);
  const ownerThread = `compact-diff-owner-${runtimeLabel}`;
  const call = toolCaller(client, ownerThread);

  try {
    const selection = {
      targetPath: repoRoot,
      scope: ".",
      mode: "diff",
      diffTarget: { kind: "range", baseRevision, headRevision },
    };
    const { scanId, scanDir, handoffClaimToken } = await startScan(
      call,
      ownerThread,
      selection,
      {
        workspace: `${runtimeLabel}: open compact diff workspace`,
        setup: `${runtimeLabel}: submit compact diff setup`,
        scan: `${runtimeLabel}: start compact diff scan`,
        claim: `${runtimeLabel}: claim compact diff scan`,
        owner: `${runtimeLabel}: attach compact diff owner`,
      },
    );
    requireSuccessfulTool<ScanResult>(
      await call("get_codex_security_scan_context", {
        scanId,
        handoffClaimToken,
      }),
      `${runtimeLabel}: authenticate compact diff owner`,
    );

    for (const name of [
      "list_codex_security_review_items",
      "list_codex_security_candidates",
    ]) {
      for (const page of [
        { cursor: "-1" },
        { cursor: "01" },
        { limit: 0 },
        { limit: 1001 },
      ]) {
        requireToolError(
          await call(name, { scanId, ...page }),
          /Input validation error/,
          `${runtimeLabel}: reject invalid ${name} paging`,
        );
      }
    }

    for (const reserved of [
      "artifacts/02_discovery/candidate_ledger.jsonl",
      "artifacts/02_discovery/in_scope_files.txt",
      "artifacts/01_context/false_positive_feedback.json",
    ]) {
      const rejected = await call("save_codex_security_artifact", {
        scanId,
        handoffClaimToken,
        storage: "persistent",
        path: `${reserved}/note.txt`,
        content: "must not block typed writers",
      });
      assert.equal(
        rejected.isError,
        true,
        `${runtimeLabel}: reject a canonical file used as a directory`,
      );
    }

    const inventory = requireSuccessfulTool(
      await call("prepare_codex_security_review_items", {
        scanId,
        handoffClaimToken,
      }),
      `${runtimeLabel}: prepare exact compact diff inventory`,
    );
    assert.equal(inventory.reviewItemsTotal, 2);
    const reviewItems = requireSuccessfulTool(
      await call("list_codex_security_review_items", {
        scanId,
        handoffClaimToken,
      }),
      `${runtimeLabel}: list compact diff inventory`,
    );
    assert.deepEqual(reviewItems.items, [
      { path: "src/guard.py" },
      { path: "src/handler.py" },
    ]);

    const candidateInput = {
      cwe_ids: [],
      locations: [
        { path: "src/handler.py", start_line: 1, role: "root_control" },
      ],
      summary: "The changed handler may rely on the removed guard.",
      evidence: "The selected change removes a neighboring guard.",
    };
    requireSuccessfulTool(
      await call("record_codex_security_discovery_candidates", {
        scanId,
        candidates: [candidateInput],
      }),
      `${runtimeLabel}: record a diff candidate alongside a deleted file`,
    );
    const ledger = path.join(
      scanDir,
      "artifacts/02_discovery/candidate_ledger.jsonl",
    );
    const before = await readFile(ledger, "utf8");
    requireToolError(
      await call("record_codex_security_discovery_candidates", {
        scanId,
        candidates: [candidateInput, { ...candidateInput, evidence: "  " }],
      }),
      /Input validation error/,
      `${runtimeLabel}: reject a malformed mixed discovery batch`,
    );
    assert.equal(await readFile(ledger, "utf8"), before);
    const candidates = requireSuccessfulTool<{
      rows: { candidate_id: string }[];
    }>(
      await call("list_codex_security_candidates", { scanId }),
      `${runtimeLabel}: read compact diff candidates`,
    );
    requireSuccessfulTool(
      await call("record_codex_security_candidate_validations", {
        scanId,
        validations: [
          {
            candidateId: candidates.rows[0].candidate_id,
            validation: {
              disposition: "suppressed",
              method: "Static review of the changed handler.",
              confidence: "high",
              confidence_rationale:
                "The changed handler has no security-sensitive operation.",
              rubric: [
                "The changed assignment does not cross a trust boundary.",
              ],
              evidence: ["value = 2"],
              counterevidence_or_proof_gap:
                "No attacker-controlled operation is present.",
              remaining_uncertainty: "",
            },
          },
        ],
      }),
      `${runtimeLabel}: record the compact diff validation`,
    );
    requireSuccessfulTool(
      await call("record_candidate_attack_paths", {
        scanId,
        attackPaths: [],
      }),
      `${runtimeLabel}: close the empty compact diff attack-path phase`,
    );
    requireSuccessfulTool(
      await call("record_codex_security_scan_draft", {
        scanId,
        handoffClaimToken,
        findings: [],
        reviewState: {
          surfaces: [
            {
              label: "Changed handler and removed guard",
              disposition: "rejected",
            },
          ],
          explicitExclusions: [],
          deferred: [],
        },
      }),
      `${runtimeLabel}: record compact diff canonical semantics`,
    );
    const note = {
      scanId,
      handoffClaimToken,
      storage: "persistent",
      path: "artifacts/review-note.md",
    };
    const content = "Saved with the scan.\n";
    requireSuccessfulTool(
      await call("save_codex_security_artifact", { ...note, content }),
      `${runtimeLabel}: save supplemental note`,
    );
    requireSuccessfulTool<ScanResult>(
      await call("complete_codex_security_scan", { scanId, handoffClaimToken }),
      `${runtimeLabel}: complete compact diff scan`,
    );
    await rename(repoRoot, repoRoot + "-moved");
    const saved = requireSuccessfulTool<{ content: string }>(
      await call("read_codex_security_artifact", note),
      `${runtimeLabel}: read supplemental note after moving its checkout`,
    );
    assert.equal(saved.content, content);
    const completed = requireSuccessfulTool<CompletedResult>(
      await call("get_codex_security_completed_scan", {
        scanId,
        handoffClaimToken,
      }),
      `${runtimeLabel}: read completed compact diff scan`,
    );
    assert.equal(completed.manifest.scan.target.baseRevision, baseRevision);
    assert.equal(completed.manifest.scan.target.headRevision, headRevision);
    assert.match(
      completed.manifest.scan.target.snapshotDigest,
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
    assert.equal(completed.manifest.scan.mode, "branch_diff");
    assert.equal(completed.findings.findings.length, 0);
  } finally {
    await client.close();
  }
}

async function testSemanticScanDraftCompletion(
  bundle: string,
  runtimeLabel: string,
) {
  const { repoRoot, environment } = await createScanFixture(
    `semantic-draft-${runtimeLabel}`,
  );
  const sourceLine = "    return connection.execute(query)";
  await writeFile(
    path.join(repoRoot, "src", "fixture.py"),
    `def execute(query):\n${sourceLine}\n`,
  );

  const client = await startClient(bundle, environment);
  const ownerThread = `semantic-draft-owner-${runtimeLabel}`;
  const call = toolCaller(client, ownerThread);

  try {
    const {
      scanId,
      scanDir: scanDirectory,
      handoffClaimToken,
    } = await startScan(
      call,
      ownerThread,
      { targetPath: repoRoot, scope: ".", mode: "standard" },
      {
        workspace: `${runtimeLabel}: open semantic-draft workspace`,
        setup: `${runtimeLabel}: submit semantic-draft setup`,
        scan: `${runtimeLabel}: start semantic-draft scan`,
        claim: `${runtimeLabel}: claim semantic-draft scan`,
        owner: `${runtimeLabel}: attach semantic-draft owner`,
      },
    );
    requireSuccessfulTool<ScanResult>(
      await call("get_codex_security_scan_context", {
        scanId,
        handoffClaimToken,
      }),
      `${runtimeLabel}: authenticate semantic-draft owner`,
    );

    for (const [name, arguments_] of [
      ["list_codex_security_review_items", { scanId, handoffClaimToken }],
      ["list_codex_security_candidates", { scanId }],
      [
        "record_codex_security_candidate_validations",
        {
          scanId,
          validations: [],
        },
      ],
      [
        "record_candidate_attack_paths",
        {
          scanId,
          attackPaths: [],
        },
      ],
    ] as const) {
      requireToolError(
        await call(name, arguments_),
        /only available for Deep or diff scans/,
        `${runtimeLabel}: ${name} must reject a Standard scan`,
      );
    }

    const candidate = {
      candidate_id: "candidate-0123456789abcdef",
      cwe_ids: ["CWE-89"],
    };
    for (const name of ["in_scope_files.txt", "candidate_ledger.jsonl"])
      await assert.rejects(
        readFile(path.join(scanDirectory, "artifacts", "02_discovery", name)),
        { code: "ENOENT" },
      );

    const codeEvidence = {
      id: "fixture-sql-sink",
      label: "SQL execution sink",
      path: "src/fixture.py",
      startLine: 2,
      code: sourceLine,
      explanation:
        "The reviewed query argument is passed directly to SQL execution.",
    };
    const finding = {
      ruleId: "sql-injection.query-execution",
      title: "Untrusted query text reaches SQL execution",
      summary:
        "The execution helper passes a query argument directly to its SQL sink.",
      severity: { level: "high" },
      confidence: {
        level: "high",
        rationale:
          "The vulnerable sink is directly visible in the reviewed source.",
      },
      taxonomy: { category: "sql-injection", cwe: candidate.cwe_ids },
      locations: [{ path: "src/fixture.py", startLine: 2, endLine: 2 }],
      codeEvidence: [codeEvidence],
      rootCause: {
        summary: "The query is not parameterized before SQL execution.",
        evidenceRefs: [codeEvidence.id],
      },
      remediation: "Use a parameterized SQL statement.",
      remediationTests: [
        "Verify an attacker-controlled query remains a bound parameter.",
      ],
      preventiveControls: ["Require the shared parameterized-query helper."],
      provenance: {
        source: "local_plugin",
        candidateId: candidate.candidate_id,
      },
      extensions: { candidateId: candidate.candidate_id },
    };
    const reasonOnlyDeferred = {
      reason: "A neighboring SQL adapter could not be exercised.",
      paths: ["src/fixture.py"],
      surfaceIds: ["surface_sql-execution"],
      source: "preserve-reason-only-metadata",
    };
    const explicitCollisionDeferred = {
      reason: "An unavailable adapter requires explicit follow-up ownership.",
    };
    const candidateCollisionDeferred = {
      reason: "An unavailable adapter belongs to an existing candidate.",
    };
    const explicitCollisionDeferredId = "explicit-adapter-review";
    const candidateCollisionDeferredId = "candidate-adapter-review";
    const reviewState = {
      surfaces: [
        {
          id: "surface_sql-execution",
          label: "SQL execution",
          disposition: "reported",
          notes:
            "Reviewed the execution helper and its unparameterized SQL sink.",
        },
      ],
      explicitExclusions: [],
      deferred: [
        {
          candidateId: "candidate-deferred-query",
          reason: "A neighboring SQL execution mode remains unavailable.",
          paths: ["src/fixture.py"],
          source: "preserve-candidate-metadata",
        },
        {
          candidateId: "candidate-reserved-query",
          reason: "A neighboring query sink needs a follow-up trace.",
        },
        {
          id: "candidate-reserved-query",
          candidateId: "candidate-explicit-query",
          reason: "Retain the explicitly supplied deferred identity.",
          surfaceIds: ["surface_sql-execution"],
        },
        {
          candidateId: "candidate-deferred-query",
          reason: "Another query sink requires a unique deferred identity.",
        },
        {
          candidateId: "candidate-reserved-query",
          reason: "Use the next available identity for the reserved query.",
        },
        reasonOnlyDeferred,
        { ...reasonOnlyDeferred },
        explicitCollisionDeferred,
        candidateCollisionDeferred,
        {
          id: explicitCollisionDeferredId,
          candidateId: "candidate-explicit-reason-only-query",
          reason: "The later explicit identity must retain its owned base.",
        },
        {
          candidateId: candidateCollisionDeferredId,
          reason: "The later candidate identity must retain its owned base.",
        },
      ],
      openQuestions: [
        "  Can a neighboring query API bypass parameterization?  ",
        {
          question: "Does authorization restrict the query endpoint?",
          followUpPrompt: "Trace the endpoint authorization boundary.",
          source: "preserve-question-metadata",
        },
      ],
    };

    const originalDraft = await snapshotScanDraft(scanDirectory);
    const malformed = {
      scanId,
      handoffClaimToken,
      scope: { includePaths: ["."] },
      findings: [
        {
          ...finding,
          ruleId: "CWE-89",
          taxonomy: { category: "sql-injection", cweIds: candidate.cwe_ids },
          provenance: { candidateId: candidate.candidate_id },
          codeEvidence: [{ ...codeEvidence, code: "" }],
        },
      ],
      reviewState: {
        ...reviewState,
        mode: "repository",
        inventoryStrategy: "repository",
        includePaths: ["."],
        excludePaths: [],
        receiptRefs: [],
        surfaces: [{ surface: "SQL execution", outcome: "reported" }],
      },
    };

    let rejected;
    try {
      rejected = await call("record_codex_security_scan_draft", malformed);
    } catch (error) {
      assert.equal(
        (error as { code: number }).code,
        -32602,
        `${runtimeLabel}: malformed draft must fail before handler execution`,
      );
    }
    if (rejected !== undefined) {
      assert.equal(
        rejected.isError,
        true,
        `${runtimeLabel}: a malformed draft must not be accepted`,
      );
    }
    assert.deepEqual(
      await snapshotScanDraft(scanDirectory),
      originalDraft,
      `${runtimeLabel}: input rejection must not write any canonical artifact`,
    );

    for (const [description, invalidCoverage] of [
      [
        "a whitespace-only deferred candidate identity",
        {
          ...reviewState,
          deferred: [{ candidateId: "  ", reason: "An identity is required." }],
        },
      ],
      [
        "a whitespace-only open question",
        { ...reviewState, openQuestions: ["  \t  "] },
      ],
      [
        "an open-question object without its question",
        {
          ...reviewState,
          openQuestions: [{ followUpPrompt: "Trace the SQL entrypoint." }],
        },
      ],
      ...[
        ["a path-traversal candidate identity", ".."],
        ["a forward-slash candidate identity", "candidate/nested"],
        ["a backslash candidate identity", "candidate\\nested"],
        ["a control-character candidate identity", "candidate\u0001nested"],
        ["an oversized candidate identity", "a".repeat(513)],
      ].flatMap(([description, candidateId]) => [
        [
          description,
          {
            ...reviewState,
            deferred: [
              {
                candidateId,
                reason: "The candidate identity must remain safe.",
              },
            ],
          },
        ],
        [
          `${description} alongside an explicit deferred identity`,
          {
            ...reviewState,
            deferred: [
              {
                id: "explicit-safe-deferred",
                candidateId,
                reason:
                  "An explicit identity must not bypass candidate validation.",
              },
            ],
          },
        ],
      ]),
    ] as const) {
      let invalid;
      try {
        invalid = await call("record_codex_security_scan_draft", {
          scanId,
          handoffClaimToken,
          findings: [finding],
          reviewState: invalidCoverage,
        });
      } catch (error) {
        assert.equal(
          (error as { code: number }).code,
          -32602,
          `${runtimeLabel}: ${description} must fail input validation`,
        );
      }
      if (invalid !== undefined) {
        assert.equal(
          invalid.isError,
          true,
          `${runtimeLabel}: ${description} must not be accepted`,
        );
      }
      assert.deepEqual(
        await snapshotScanDraft(scanDirectory),
        originalDraft,
        `${runtimeLabel}: rejecting ${description} must not write canonical artifacts`,
      );
    }

    const progress = async () =>
      requireSuccessfulTool<ScanResult>(
        await call("get_codex_security_scan_context", {
          scanId,
          handoffClaimToken,
        }),
      ).scan.progress;
    assert.equal((await progress()).phase, "preflight");
    requireSuccessfulTool(
      await call("update_codex_security_scan_progress", {
        scanId,
        handoffClaimToken,
        phaseItemsTotal: 1,
        phaseItemsCompleted: 1,
        phaseProgressUnit: "checks",
      }),
    );
    const checkpoint = {
      scanId,
      handoffClaimToken,
      complete: false,
      findings: [finding],
      reviewState: { ...reviewState },
    };
    const threatModel = {
      summary: "Legacy structured model.",
      format: "markdown",
      content: "# Saved model\r\n\r\n    Preserve  spacing.\r\n",
      origin: false,
      scope: { includePaths: ["src/[api]"] },
    };
    const firstDraft = requireSuccessfulTool(
      await call("record_codex_security_scan_draft", {
        ...checkpoint,
        threatModel,
      }),
    );
    assert.equal(firstDraft.warnings, undefined);
    const documentPath = path.join(scanDirectory, "threatmodel.md");
    const savedDocument = await readFile(documentPath, "utf8");
    assert.ok(savedDocument.startsWith(threatModel.content));
    assert.match(savedDocument, /Model origin: not recorded\n/);
    assert.match(savedDocument, /Model scope: src\/\\\[api\\\]\n/);
    assert.match(savedDocument, /provisional/);
    const checkpointDeferred = (
      await readJson(scanDirectory, "scan-manifest.json")
    ).scan.reviewState.deferred;
    const generatedIds = checkpointDeferred
      .slice(5, 9)
      .map(({ id }: { id: string }) => id);
    assert.ok(generatedIds.every((id: string) => typeof id === "string"));
    assert.equal(new Set(generatedIds).size, generatedIds.length);
    const discovery = await progress();
    assert.equal(discovery.status, "running");
    assert.equal(discovery.phase, "discovery");
    assert.deepEqual(discovery.phaseProgress, {
      completed: 0,
      total: 0,
      unit: null,
    });

    requireSuccessfulTool(
      await call("update_codex_security_scan_progress", {
        scanId,
        handoffClaimToken,
        phase: "validation",
        phaseItemsTotal: 2,
        phaseItemsCompleted: 1,
        phaseProgressUnit: "candidate_findings",
      }),
    );
    requireSuccessfulTool(
      await call("record_codex_security_scan_draft", checkpoint),
    );
    assert.equal(await readFile(documentPath, "utf8"), savedDocument);
    assert.deepEqual(
      (await readJson(scanDirectory, "scan-manifest.json")).scan.threatModel,
      threatModel,
    );
    const validation = await progress();
    assert.equal(validation.phase, "validation");
    assert.deepEqual(validation.phaseProgress, {
      completed: 1,
      total: 2,
      unit: "candidate_findings",
    });

    const drafted = requireSuccessfulTool(
      await call("record_codex_security_scan_draft", {
        scanId,
        handoffClaimToken,
        findings: [finding],
        reviewState,
      }),
      `${runtimeLabel}: correct the same scan and accept exactly one draft`,
    );
    const savedManifest = await readJson(scanDirectory, "scan-manifest.json");
    const savedCoverage = {
      ...savedManifest.scan.reviewState,
      mode: savedManifest.scan.mode,
      inventoryStrategy: "directory",
      openQuestions: [
        { question: "Can a neighboring query API bypass parameterization?" },
        reviewState.openQuestions[1],
      ],
      includePaths: savedManifest.scan.scope.includePaths,
      excludePaths: savedManifest.scan.scope.excludePaths,
    };
    assert.equal(savedManifest.scan.id, scanId);
    assert.deepEqual(drafted, {
      scanId,
      findingCount: 1,
      surfaceCount: 1,
      reviewState: savedCoverage,
      operation: "replace",
      status: "draft_written",
    });
    const reporting = await progress();
    assert.equal(reporting.phase, "reporting");
    assert.equal(reporting.status, "running");
    assert.deepEqual(reporting.phaseProgress, {
      completed: 0,
      total: 0,
      unit: null,
    });

    const completed = requireSuccessfulTool<ScanResult>(
      await call("complete_codex_security_scan", { scanId, handoffClaimToken }),
      `${runtimeLabel}: finalize the accepted draft exactly once`,
    );
    assert.equal(completed.scan.progress.status, "complete");
    assert.equal(completed.scan.reportAvailable, true);

    const results = requireSuccessfulTool<CompletedResult>(
      await call("get_codex_security_completed_scan", {
        scanId,
        handoffClaimToken,
      }),
      `${runtimeLabel}: read the actually sealed completed scan`,
    );
    assert.equal(results.scanId, scanId);
    assert.equal(results.manifest.scan.status, "completed");
    assert.ok(results.manifest.scan.sealedAt);
    assert.ok(results.manifest.scan.artifacts.length > 0);
    assert.equal(results.findings.findings.length, 1);
    const savedFinding = results.findings.findings[0];
    assert.equal(savedFinding.ruleId, finding.ruleId);
    assert.equal(savedFinding.remediation, finding.remediation);
    for (const field of [
      "taxonomy",
      "provenance",
      "remediationTests",
      "preventiveControls",
    ] as const)
      assert.deepEqual(savedFinding[field], finding[field]);
    assert.equal(savedFinding.extensions.candidateId, candidate.candidate_id);
    assert.ok(savedFinding.findingId);
    assert.ok(savedFinding.occurrenceId);
    assert.ok(savedFinding.fingerprints.primary);
    assert.equal(results.manifest.scan.target.kind, "directory_snapshot");
    assert.equal(results.manifest.scan.mode, "repository");
    assert.deepEqual(results.manifest.scan.scope.includePaths, ["."]);
    assert.deepEqual(results.manifest.scan.scope.excludePaths, []);
    assert.deepEqual(results.review, { excludedPaths: [] });
    const head = await readJson(scanDirectory, "checkpoint-head.json");
    const retained = (
      await readJson(scanDirectory, "checkpoints", head.checkpoint)
    ).reviewState;
    assert.equal(retained.surfaces[0].disposition, "reported");
    const withId = (row: Record<string, unknown>, id: string) => ({
      ...row,
      id,
    });
    assert.deepEqual(retained.deferred, [
      withId(reviewState.deferred[0], "candidate-deferred-query"),
      withId(reviewState.deferred[1], "candidate-reserved-query-2"),
      reviewState.deferred[2],
      withId(reviewState.deferred[3], "candidate-deferred-query-2"),
      withId(reviewState.deferred[4], "candidate-reserved-query-3"),
      withId(reasonOnlyDeferred, generatedIds[0]),
      withId(reasonOnlyDeferred, generatedIds[1]),
      withId(explicitCollisionDeferred, generatedIds[2]),
      withId(candidateCollisionDeferred, generatedIds[3]),
      reviewState.deferred[9],
      withId(reviewState.deferred[10], candidateCollisionDeferredId),
    ]);
    assert.deepEqual(retained.openQuestions, savedCoverage.openQuestions);
    assert.ok(
      (await readFile(path.join(scanDirectory, "report.md"), "utf8")).length >
        0,
    );
  } finally {
    await client.close();
  }
}

async function testClaimedParentArtifactOperations(
  bundle: string,
  runtimeLabel: string,
) {
  const { repoRoot, environment } = await createScanFixture(
    `claimed-parent-${runtimeLabel}`,
  );
  await writeFile(
    path.join(repoRoot, "src", "fixture.py"),
    "print('fixture')\n",
  );

  const client = await startClient(bundle, environment);
  const ownerThread = `compact-artifact-owner-${runtimeLabel}`;
  const otherThread = `compact-artifact-other-${runtimeLabel}`;
  const call = toolCaller(client, ownerThread);

  try {
    const {
      scanId,
      scanDir: scanDirectory,
      handoffClaimToken: claimToken,
    } = await startScan(
      call,
      ownerThread,
      { targetPath: repoRoot, scope: ".", mode: "deep" },
      {
        workspace: "open claimed parent workspace",
        setup: "submit claimed parent setup",
        scan: "start claimed parent scan",
        claim: "claim parent scan handoff",
        owner: "attach parent scan owner",
      },
    );
    const inventoryPath = path.join(
      scanDirectory,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt",
    );
    const ledgerPath = path.join(
      scanDirectory,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl",
    );
    const phaseCalls: [string, Record<string, unknown>][] = [
      ["list_codex_security_review_items", { scanId }],
      ["list_codex_security_candidates", { scanId }],
      [
        "record_codex_security_candidate_validations",
        { scanId, validations: [] },
      ],
      ["record_candidate_attack_paths", { scanId, attackPaths: [] }],
    ];
    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_),
        /requires its current continuation claim/,
        `${name} before authenticated scan context`,
      );
    }

    const delivered = requireSuccessfulTool<ScanResult>(
      await call("get_codex_security_scan_context", {
        scanId,
        handoffClaimToken: claimToken,
      }),
      "authenticate parent scan owner",
    );
    assert.equal(delivered.scan.continuationThreadId, ownerThread);
    assert.equal(delivered.scan.handoffClaimToken, undefined);

    for (const [name, arguments_] of [
      ["prepare_codex_security_review_items", { scanId }],
      [
        "record_codex_security_discovery_candidates",
        { scanId, candidates: [] },
      ],
    ] as const) {
      requireToolError(
        await call(name, arguments_),
        /only available for diff scans/,
        `${name} must not replace Deep discovery artifacts`,
      );
    }

    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_, null),
        /requires its current continuation claim/,
        `${name} without continuation-thread metadata`,
      );
      requireToolError(
        await call(name, arguments_, otherThread),
        /requires its current continuation claim/,
        `${name} from a different continuation thread before discovery artifacts exist`,
      );
    }
    await assert.rejects(readFile(inventoryPath, "utf8"), { code: "ENOENT" });
    await assert.rejects(readFile(ledgerPath, "utf8"), { code: "ENOENT" });

    await mkdir(path.dirname(inventoryPath), { recursive: true });
    await writeFile(inventoryPath, "./src/fixture.py\n");
    const seededCandidate = {
      candidate_id: "candidate-0123456789abcdef",
      cwe_ids: ["CWE-89"],
      locations: [
        {
          path: "src/fixture.py",
          start_line: 1,
          end_line: 1,
          role: "sink",
        },
      ],
      summary: "The fixture provides a reachable SQL sink.",
      evidence: "The first source line contains the reviewed sink.",
    };
    await writeFile(ledgerPath, `${JSON.stringify(seededCandidate)}\n`);

    const reviewItems = requireSuccessfulTool(
      await call("list_codex_security_review_items", { scanId }),
      "read claimed parent inventory without a model-visible claim",
    );
    assert.deepEqual(reviewItems.items, [{ path: "./src/fixture.py" }]);

    const explicitlyListed = requireSuccessfulTool(
      await call("list_codex_security_review_items", {
        scanId,
        handoffClaimToken: claimToken,
      }),
      "read claimed parent inventory with an explicit continuation claim",
    );
    assert.deepEqual(explicitlyListed.items, [{ path: "./src/fixture.py" }]);

    const originalInventory = await readFile(inventoryPath, "utf8");
    const listed = requireSuccessfulTool<{ rows: { candidate_id: string }[] }>(
      await call("list_codex_security_candidates", {
        scanId,
      }),
      "read Deep discovery candidates without a model-visible claim",
    );
    assert.equal(listed.rows.length, 1);
    const candidateId = listed.rows[0].candidate_id;

    const validated = requireSuccessfulTool(
      await call("record_codex_security_candidate_validations", {
        scanId,
        validations: [
          {
            candidateId,
            validation: {
              disposition: "reportable",
              method: "Static source-to-sink trace.",
              confidence: "high",
              confidence_rationale:
                "The vulnerable code path is directly visible.",
              rubric: ["The source is attacker-controlled."],
              evidence: ["The source line directly reaches the sink."],
              counterevidence_or_proof_gap: "No effective control was found.",
              remaining_uncertainty: "",
            },
          },
        ],
      }),
      "validate claimed parent candidates without a model-visible claim",
    );
    assert.deepEqual(validated, {
      kind: "candidate_validations",
      operation: "replace",
      rowsWritten: 1,
    });

    const attacked = requireSuccessfulTool(
      await call("record_candidate_attack_paths", {
        scanId,
        attackPaths: [
          {
            candidateId,
            attackPath: {
              decision: "reportable",
              dataflow: "Request input reaches the SQL sink.",
              reachability: "The handler is reachable.",
              counterevidence: "No effective control was found.",
              impact: "high",
              likelihood: "medium",
              severity: "high",
              severity_rationale: "The sink accepts attacker-controlled input.",
              change_conditions: "Parameterized queries remove the issue.",
            },
          },
        ],
      }),
      "record claimed parent attack paths without a model-visible claim",
    );
    assert.deepEqual(attacked, {
      kind: "candidate_attack_paths",
      operation: "replace",
      rowsWritten: 1,
    });

    const originalLedger = await readFile(ledgerPath, "utf8");
    const { validation, attack_path: attackPath } = JSON.parse(originalLedger);
    const validationLedger = `${originalLedger}${JSON.stringify({
      ...seededCandidate,
      candidate_id: "candidate-valid",
    })}\n`;
    await writeFile(ledgerPath, validationLedger);
    requireToolError(
      await call("record_codex_security_candidate_validations", {
        scanId,
        validations: [
          { candidateId, validation: { ...validation, confidence: "certain" } },
          { candidateId: "candidate-valid", validation },
        ],
      }),
      /confidence/,
      `${runtimeLabel}: reject invalid validation confidence`,
    );
    assert.equal(await readFile(ledgerPath, "utf8"), validationLedger);
    await writeFile(ledgerPath, originalLedger);
    for (const invalid of [
      { severity: "moderate" },
      { decision: "ignore" },
      { decision: "deferred" },
      { severity_rationale: "  " },
    ]) {
      requireToolError(
        await call("record_candidate_attack_paths", {
          scanId,
          attackPaths: [
            { candidateId, attackPath: { ...attackPath, ...invalid } },
          ],
        }),
        /Input validation error/,
        `${runtimeLabel}: reject invalid attack-path judgment`,
      );
      assert.equal(await readFile(ledgerPath, "utf8"), originalLedger);
    }
    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_, otherThread),
        /requires its current continuation claim/,
        `${name} from a different continuation thread`,
      );
      assert.equal(await readFile(ledgerPath, "utf8"), originalLedger);
      assert.equal(await readFile(inventoryPath, "utf8"), originalInventory);
    }

    execFileSync(fixturePython, [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); " +
        "c.execute('UPDATE scans SET handoff_claim_token = ? WHERE id = ?', " +
        "(sys.argv[2],sys.argv[3])); c.commit(); c.close()",
      path.join(environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      randomUUID(),
      scanId,
    ]);
    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_),
        /owned by a different continuation/,
        `${name} after continuation claim rotation`,
      );
      assert.equal(await readFile(ledgerPath, "utf8"), originalLedger);
      assert.equal(await readFile(inventoryPath, "utf8"), originalInventory);
    }
  } finally {
    await client.close();
  }
}

function requireSuccessfulTool<Result = Record<string, unknown>>(
  result: ToolResponse,
  label?: string,
): Result {
  assert.notEqual(
    result.isError,
    true,
    `${label}: ${(result.content as TextContent[] | undefined)?.[0]?.text ?? "tool failed"}`,
  );
  assert.ok(result.structuredContent, `${label}: missing structured result`);
  return result.structuredContent as Result;
}

function requireToolError(
  result: ToolResponse,
  expected: RegExp,
  label: string,
) {
  assert.equal(result.isError, true, `${label}: unexpectedly succeeded`);
  assert.match(
    (result.content as TextContent[] | undefined)?.[0]?.text ?? "",
    expected,
    label,
  );
}

async function testPromptDrivenPrivateRecipe(bundle: string) {
  for (const kind of ["prompt-only", "headless"]) {
    const fixtureRoot = path.join(temporaryRoot, `private-recipe-${kind}`);
    const repoRoot = path.join(fixtureRoot, "repository");
    const environment = {
      CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "scans"),
      CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
    };
    await mkdir(repoRoot, { recursive: true });
    await mkdir(environment.CODEX_SECURITY_SCAN_ROOT, { mode: 0o700 });
    await writeFile(path.join(repoRoot, "fixture.py"), "print('fixture')\n");
    const client = await startClient(bundle, environment);
    const ownerThread = `private-recipe-${kind}`;
    const toolName =
      kind === "prompt-only"
        ? "start_codex_security_prompt_only_scan"
        : "start_codex_security_standard_scan";
    const callStart = () =>
      client.callTool({
        name: toolName,
        arguments: {
          targetPath: repoRoot,
          scope: ".",
          ...(kind === "prompt-only" ? { mode: "standard" } : {}),
        },
        _meta: { "openai/threadId": ownerThread },
      });

    try {
      const startedResult = await callStart();
      const started = requireSuccessfulTool(
        startedResult,
        `start ${kind} scan`,
      );
      const { scanId, scanDir } = started.scan;
      const claimToken = started.handoffClaimToken;
      const recipe = privateScanRecipe(repoRoot, "standard");
      runWorkbenchFixture(
        environment,
        [
          "register-cli-scan",
          "--repository",
          repoRoot,
          "--scan-dir",
          scanDir,
          "--registration-json-stdin",
        ],
        {
          recipe,
          scanId,
          threadId: ownerThread,
          ...(claimToken ? { claimToken } : {}),
        },
      );
      if (claimToken) {
        runWorkbenchFixture(environment, [
          "set-scan-thread",
          "--scan-id",
          scanId,
          "--claim-token",
          claimToken,
          "--thread-id",
          ownerThread,
        ]);
      }
      const joinedResult = await callStart();
      const joined = requireSuccessfulTool(joinedResult, `rejoin ${kind} scan`);
      assert.equal(joined.startDisposition, "joined");
      assert.equal(joined.scan.scanId, scanId);
      if (kind === "prompt-only") {
        for (const result of [startedResult, joinedResult]) {
          const instructions = result.content
            .filter((content) => content.type === "text")
            .map((content) => content.text)
            .join("\n");
          assert.ok(instructions.includes("complete_codex_security_scan"));
          assert.equal(
            instructions.includes("get_codex_security_completed_scan"),
            false,
          );
        }
      }
      assertPrivateRecipeOmitted(joinedResult, recipe, `${kind} rejoin`);
      assert.deepEqual(
        runWorkbenchFixture(environment, [
          "get-scan-recipe",
          "--scan-id",
          scanId,
        ]).recipe,
        recipe,
        `${kind} rejoin preserves the complete host recipe`,
      );
    } finally {
      await client.close();
    }
  }
}

async function testNativeDeepTerminalResults(
  bundle: string,
  sandboxMetadata: string,
) {
  const fixtureRoot = path.join(
    temporaryRoot,
    `completed-native-${sandboxMetadata}`,
  );
  const repoRoot = path.join(fixtureRoot, "repository");
  const invocationPath = path.join(fixtureRoot, "unexpected-codex-invocation");
  const environment = {
    CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "scans"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
    CODEX_HOME: path.join(fixtureRoot, "codex-home"),
    CODEX_CLI_PATH: path.join(fixtureRoot, "codex-stub"),
    CODEX_API_KEY: "",
    OPENAI_API_KEY: "",
  };
  await mkdir(repoRoot, { recursive: true });
  await mkdir(environment.CODEX_SECURITY_SCAN_ROOT, { mode: 0o700 });
  await mkdir(environment.CODEX_HOME, { mode: 0o700 });
  await writeFile(path.join(repoRoot, "fixture.py"), "print('fixture')\n");
  await writeFile(
    environment.CODEX_CLI_PATH,
    `#!${process.execPath}
require("node:fs").writeFileSync(${JSON.stringify(invocationPath)}, "unexpected launch");
process.exit(1);
`,
    { mode: 0o700 },
  );

  const ownerThread = "completed-native-owner";
  const begun = runWorkbenchFixture(environment, [
    "begin-deep-scan",
    "--target-path",
    repoRoot,
    "--scope",
    ".",
    "--thread-id",
    ownerThread,
  ]);
  const { scanId, scanDir, handoffClaimToken } = begun.scan;
  runWorkbenchFixture(
    environment,
    [
      "register-cli-scan",
      "--repository",
      repoRoot,
      "--scan-dir",
      scanDir,
      "--registration-json-stdin",
    ],
    {
      scanId,
      threadId: ownerThread,
      claimToken: handoffClaimToken,
      recipe: {
        repository: repoRoot,
        mode: "deep",
        target: { kind: "repository", paths: [] },
        config: {},
      },
    },
  );
  runWorkbenchFixture(environment, [
    "set-scan-thread",
    "--scan-id",
    scanId,
    "--claim-token",
    handoffClaimToken,
    "--thread-id",
    "completed-native-merge",
  ]);
  runWorkbenchFixture(
    environment,
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
      version: 2,
      passes: [],
      mergedScanIds: [],
      aggregate: null,
      terminalReason: "capped",
    },
  );

  const client = await startClient(bundle, environment);
  const call = (name, arguments_) =>
    client.callTool({
      name,
      arguments: arguments_,
      _meta: {
        "openai/threadId": ownerThread,
        ...(sandboxMetadata === "missing"
          ? {}
          : {
              "codex/sandbox-state-meta": {
                permissionProfile: {
                  type:
                    sandboxMetadata === "unsupported"
                      ? "synthetic-unsupported-profile"
                      : "managed",
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
                sandboxCwd: pathToFileURL(repoRoot).href,
              },
            }),
      },
    });
  const rejoin = () =>
    call("start_codex_security_deep_scan", { scanId, handoffClaimToken });
  const expectedResult = {
    scanId,
    scanDir,
    manifestPath: path.join(scanDir, "scan-manifest.json"),
    reportPath: path.join(scanDir, "report.md"),
  };
  const assertCompleted = (response, label) => {
    const result = requireSuccessfulTool(response, label);
    const { instructions, usage, warnings, cost, ...paths } = result;
    assert.match(instructions, /is complete/);
    assert.match(
      instructions,
      /Do not call complete_codex_security_scan or start another scan/,
    );
    assert.deepEqual(paths, expectedResult);
    assert.equal(usage.coverage, "unavailable");
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /selected checkout is no longer accessible/);
    assert.equal(cost, undefined);
    assert.deepEqual(response.content, [{ type: "text", text: instructions }]);
  };

  try {
    if (sandboxMetadata !== "valid") {
      const rejected = await rejoin();
      assert.equal(rejected.isError, true);
      assert.match(
        rejected.content[0].text,
        /cannot preserve the parent sandbox/,
      );
      assert.equal(rejected.structuredContent, undefined);
      assert.equal(
        runWorkbenchFixture(environment, ["get-scan", "--scan-id", scanId]).scan
          .progress.status,
        "running",
      );
      await assert.rejects(readFile(invocationPath), { code: "ENOENT" });
    }
    requireSuccessfulTool(
      await call("record_codex_security_scan_draft", {
        scanId,
        handoffClaimToken,
        findings: [],
        reviewState: {
          completeness: "complete",
          surfaces: [{ label: "Synthetic fixture", disposition: "rejected" }],
          explicitExclusions: [],
          deferred: [],
        },
      }),
      "write native parent aggregate",
    );
    const head = await readJson(scanDir, "checkpoint-head.json");
    const admitted = await readJson(
      scanDir,
      "checkpoints",
      head.inputCheckpoint,
    );
    assert.deepEqual(admitted.publication, {
      previousCheckpoint: null,
      previousInputCheckpoint: null,
    });
    runWorkbenchFixture(environment, [
      "prepare-scan-completion",
      "--scan-id",
      scanId,
      "--claim-token",
      handoffClaimToken,
    ]);
    const originalDraft = await snapshotScanDraft(scanDir);
    assert.equal(
      runWorkbenchFixture(environment, ["get-scan", "--scan-id", scanId]).scan
        .progress.status,
      "running",
    );
    const movedRepo = path.join(fixtureRoot, "moved-repository");
    await rename(repoRoot, movedRepo);
    try {
      assertCompleted(
        await rejoin(),
        "publish sealed running native parent after checkout moves",
      );
      assert.equal(
        runWorkbenchFixture(environment, ["get-scan", "--scan-id", scanId]).scan
          .progress.status,
        "complete",
      );
      assert.deepEqual(await snapshotScanDraft(scanDir), originalDraft);
      await assert.rejects(readFile(invocationPath), { code: "ENOENT" });
    } finally {
      await rename(movedRepo, repoRoot);
    }

    for (let repeat = 0; repeat < 2; repeat += 1) {
      assertCompleted(await rejoin(), "rejoin intact completed native parent");
    }
    await rm(expectedResult.reportPath);
    assertCompleted(
      await rejoin(),
      "regenerate missing report before native success",
    );
    assert.ok((await readFile(expectedResult.reportPath, "utf8")).length > 0);
    assert.deepEqual(await snapshotScanDraft(scanDir), originalDraft);

    for (const artifact of ["scan-manifest.json", "findings.json"]) {
      const artifactPath = path.join(scanDir, artifact);
      const original = await readFile(artifactPath);
      for (const change of ["modified", "missing"]) {
        try {
          if (change === "modified")
            await writeFile(
              artifactPath,
              Buffer.concat([original, Buffer.from("\n")]),
            );
          else await rm(artifactPath);
          const rejected = await rejoin();
          assert.equal(
            rejected.isError,
            true,
            `reject ${change} completed ${artifact}`,
          );
          assert.equal(rejected.structuredContent, undefined);
          assert.equal(
            runWorkbenchFixture(environment, ["get-scan", "--scan-id", scanId])
              .scan.progress.status,
            "complete",
          );
        } finally {
          await writeFile(artifactPath, original);
        }
      }
    }
    assert.deepEqual(await snapshotScanDraft(scanDir), originalDraft);
    await assert.rejects(readFile(invocationPath), { code: "ENOENT" });
    assert.equal(
      runWorkbenchFixture(environment, ["list-scans"]).scans.length,
      1,
    );

    const canceledRepo = path.join(fixtureRoot, "canceled-repository");
    await mkdir(canceledRepo);
    await writeFile(
      path.join(canceledRepo, "fixture.py"),
      "print('fixture')\n",
    );
    const { scan: canceledScan } = runWorkbenchFixture(environment, [
      "begin-deep-scan",
      "--target-path",
      canceledRepo,
      "--scope",
      ".",
      "--thread-id",
      ownerThread,
    ]);
    const childRelativeDirectory = "artifacts/deep-scan/passes/pass-1";
    const childDirectory = path.join(
      canceledScan.scanDir,
      childRelativeDirectory,
    );
    await mkdir(childDirectory, { recursive: true, mode: 0o700 });
    const child = runWorkbenchFixture(
      environment,
      [
        "register-cli-scan",
        "--repository",
        canceledRepo,
        "--scan-dir",
        childDirectory,
        "--parent-scan-id",
        canceledScan.scanId,
        "--registration-json-stdin",
      ],
      {
        recipe: privateScanRecipe(canceledRepo, "standard"),
        parentScanRole: "deep_pass",
      },
    );
    runWorkbenchFixture(
      environment,
      [
        "save-scan-artifact",
        "--scan-id",
        canceledScan.scanId,
        "--claim-token",
        canceledScan.handoffClaimToken,
        "--artifact-path",
        "artifacts/deep-scan/checkpoint.json",
      ],
      {
        version: 2,
        passes: [{ directory: childRelativeDirectory, scanId: child.scanId }],
        mergedScanIds: [],
        aggregate: null,
      },
    );
    runWorkbenchFixture(environment, [
      "cancel-scan",
      "--scan-id",
      canceledScan.scanId,
      "--thread-id",
      ownerThread,
      "--defer-publication",
    ]);
    const canceledResponse = await call("start_codex_security_deep_scan", {
      scanId: canceledScan.scanId,
      handoffClaimToken: canceledScan.handoffClaimToken,
    });
    const canceledResult = requireSuccessfulTool(
      canceledResponse,
      "rejoin canceled scan",
    );
    const { instructions, usage, cost, warnings, ...retained } = canceledResult;
    assert.match(instructions, /was canceled/);
    assert.match(
      instructions,
      /Do not start additional scan work or claim complete coverage/,
    );
    assert.deepEqual(retained, {
      status: "canceled",
      scanId: canceledScan.scanId,
      scanDir: canceledScan.scanDir,
    });
    assert.equal(usage, undefined);
    assert.deepEqual(warnings, []);
    assert.equal(cost, undefined);
    assert.deepEqual(canceledResponse.content, [
      { type: "text", text: instructions },
    ]);
    assert.equal(
      runWorkbenchFixture(environment, [
        "get-scan",
        "--scan-id",
        canceledScan.scanId,
      ]).scan.progress.status,
      "canceled",
    );
    assert.equal(
      runWorkbenchFixture(environment, ["get-scan", "--scan-id", child.scanId])
        .scan.progress.status,
      "failed",
      "terminal rejoin finishes the deferred child stop",
    );
    const failedRepo = path.join(fixtureRoot, "failed-repository");
    await mkdir(failedRepo);
    await writeFile(path.join(failedRepo, "fixture.py"), "print('fixture')\n");
    const { scan: failedScan } = runWorkbenchFixture(environment, [
      "begin-deep-scan",
      "--target-path",
      failedRepo,
      "--scope",
      ".",
      "--thread-id",
      ownerThread,
    ]);
    runWorkbenchFixture(environment, [
      "fail-scan",
      "--scan-id",
      failedScan.scanId,
      "--claim-token",
      failedScan.handoffClaimToken,
      "--message",
      "Synthetic retained failure.",
      "--defer-publication",
    ]);
    const failedResponse = await call("start_codex_security_deep_scan", {
      scanId: failedScan.scanId,
      handoffClaimToken: failedScan.handoffClaimToken,
    });
    assert.equal(failedResponse.isError, true);
    assert.equal(failedResponse.structuredContent?.scanId, failedScan.scanId);
    assert.equal(failedResponse.structuredContent?.status, "failed");
    assert.equal(failedResponse.content[0].text, "Synthetic retained failure.");
    assert.equal(
      runWorkbenchFixture(environment, [
        "get-scan",
        "--scan-id",
        failedScan.scanId,
      ]).scan.progress.status,
      "failed",
    );
    await assert.rejects(readFile(invocationPath), { code: "ENOENT" });
  } finally {
    await client.close();
  }
}

function privateScanRecipe(repository, mode) {
  return {
    repository,
    mode,
    target: { kind: "repository", paths: [] },
    config: {
      model_provider: "fixture",
      model_providers: {
        fixture: {
          http_headers: {
            Authorization: "Bearer synthetic-private-header-marker",
          },
          auth: {
            type: "command",
            command: "synthetic-private-auth-command-marker",
          },
        },
      },
    },
  };
}

function assertPrivateRecipeOmitted(result, recipe, label) {
  assert.equal(
    Object.hasOwn(result.structuredContent, "recipe"),
    false,
    `${label}: omit host recipe`,
  );
  const serialized = JSON.stringify(result);
  const provider = recipe.config.model_providers.fixture;
  for (const marker of [
    provider.http_headers.Authorization,
    provider.auth.command,
  ]) {
    assert.equal(
      serialized.includes(marker),
      false,
      `${label}: omit private provider settings`,
    );
  }
}

function runWorkbenchFixture(environment, arguments_, input) {
  return JSON.parse(
    execFileSync(
      process.env.PYTHON ?? "python3",
      [
        path.join(bundledPluginRoot, "scripts", "workbench_db.py"),
        ...arguments_,
      ],
      {
        env: { ...process.env, ...environment },
        encoding: "utf8",
        ...(input === undefined ? {} : { input: JSON.stringify(input) }),
      },
    ),
  );
}

async function listSandboxAwareTools(client: Client, role: string) {
  assert.deepEqual(
    client.getServerCapabilities()?.experimental?.["codex/sandbox-state-meta"],
    {},
    `The ${role} MCP must advertise actual parent sandbox-state metadata.`,
  );
  return (await client.listTools()).tools;
}

async function testParentToolList(bundle: string) {
  const client = await startClient(bundle, {
    CODEX_SECURITY_STATE_DIR: path.join(temporaryRoot, randomUUID()),
  });
  try {
    const tools = await listSandboxAwareTools(client, "parent");
    for (const tool of tools) {
      if (
        (
          tool._meta?.ui as { visibility?: string[] } | undefined
        )?.visibility?.includes("model") === false
      )
        continue;
      const projectedName = `mcp__codex_security__${tool.name}`;
      assert.ok(
        projectedName.length <= 64,
        `Model-visible MCP tool ${projectedName} exceeds Codex's 64-character limit.`,
      );
    }
    const names = new Set(tools.map((tool) => tool.name));
    assert.equal(
      names.has("record_codex_security_worker_threat_model"),
      false,
      "The parent MCP must not expose a bound discovery worker's threat-model tool.",
    );
    const scanTools = [
      "prepare_codex_security_review_items",
      "list_codex_security_review_items",
      "record_codex_security_discovery_candidates",
      "list_codex_security_candidates",
      "record_codex_security_candidate_validations",
      "record_candidate_attack_paths",
      "record_codex_security_scan_draft",
      "get_codex_security_completed_scan",
    ];
    for (const name of [
      ...scanTools,
      "get_codex_security_finding_issues",
      "record_codex_security_finding_issues",
      "complete_codex_security_scan",
    ]) {
      assert.equal(names.has(name), true, `Missing parent MCP tool ${name}.`);
    }

    for (const name of [
      "get_codex_security_deep_reducer_inputs",
      "record_codex_security_deep_reduction",
      "post_deep_scan_peer_note",
      "read_deep_scan_peer_notes",
    ]) {
      assert.equal(
        names.has(name),
        false,
        `Parent MCP must not expose ${name}.`,
      );
    }

    for (const tool of tools.filter((entry) =>
      scanTools.includes(entry.name),
    )) {
      assert.equal(
        tool.inputSchema.required?.includes("scanId"),
        true,
        `${tool.name} must require the authoritative workbench scan identity.`,
      );
      assertNoArtifactDestination(tool);
      if (tool.name === "record_codex_security_scan_draft")
        assertSemanticInputProperties(tool.inputSchema);
    }

    const deepScanTool = tools.find(
      (tool) => tool.name === "start_codex_security_deep_scan",
    );
    assert.ok(
      deepScanTool,
      "The parent MCP must expose Deep Scan initialization.",
    );
    const contextSchema = deepScanTool.inputSchema.properties!.userContext as {
      minLength?: number;
      maxLength?: number;
    };
    assert.equal(contextSchema.minLength, undefined);
    assert.equal(contextSchema.maxLength, undefined);

    const sandboxState = readOnlyParentSandboxState(pluginRoot);
    for (const userContext of ["", "   "]) {
      requireToolError(
        await client.callTool({
          name: deepScanTool.name,
          arguments: { targetPath: pluginRoot, userContext },
        }),
        /owning Codex thread context/,
        "Empty optional Deep Scan context must not fail schema validation.",
      );
      requireToolError(
        await client.callTool({
          name: deepScanTool.name,
          arguments: { scanId: randomUUID(), userContext },
          _meta: {
            "openai/threadId": "fixture-thread",
            "codex/sandbox-state-meta": sandboxState,
          },
        }),
        /Codex Security scan not found/,
        "Empty optional Deep Scan context must not override persisted scan authority.",
      );
    }
    requireToolError(
      await client.callTool({
        name: deepScanTool.name,
        arguments: {
          scanId: randomUUID(),
          userContext: "replace persisted context",
        },
        _meta: { "openai/threadId": "fixture-thread" },
      }),
      /persisted scan is authoritative/,
      "Nonempty user context must not override an existing Deep Scan.",
    );
  } finally {
    await client.close();
  }
}

function assertNoArtifactDestination(tool: Tool) {
  for (const forbidden of [
    "path",
    "artifactPath",
    "outputPath",
    "root",
    "operation",
  ]) {
    assert.equal(
      Object.hasOwn(tool.inputSchema.properties ?? {}, forbidden),
      false,
      `${tool.name} must not accept a model-selected artifact destination (${forbidden}).`,
    );
  }
}

function assertSemanticInputProperties(schema: Record<string, unknown>) {
  const properties = schema.properties as Record<
    string,
    Record<string, unknown>
  >;
  const findingSchema = properties.findings.items as Record<string, unknown>;
  if (properties.reviewState) {
    assert.equal(
      Object.hasOwn(
        properties.reviewState.properties as object,
        "completeness",
      ),
      false,
    );
    assert.equal(
      (properties.reviewState.required as string[]).includes("completeness"),
      false,
    );
  }
  const groups: [Record<string, unknown>, string[]][] = [
    [properties.scope, ["includePaths", "excludePaths"]],
    [findingSchema, ["findingId", "occurrenceId", "fingerprints"]],
  ];
  if (properties.reviewState)
    groups.push([
      properties.reviewState,
      [
        "documentType",
        "schemaVersion",
        "scanId",
        "mode",
        "inventoryStrategy",
        "includePaths",
        "excludePaths",
        "receiptRefs",
      ],
    ]);
  for (const [object, forbidden] of groups) {
    const names = object.propertyNames as { not: { enum: string[] } };
    for (const key of forbidden) {
      assert.equal(
        Object.hasOwn(object.properties as object, key),
        false,
        `${key} must not be advertised as an optional unknown input`,
      );
      assert.ok(
        names.not.enum.includes(key),
        `${key} remains forbidden in tools/list`,
      );
    }
  }
}

async function startScan(
  call: ReturnType<typeof toolCaller>,
  ownerThread: string,
  selection: Record<string, unknown>,
  labels: {
    workspace: string;
    setup: string;
    scan: string;
    claim: string;
    owner: string;
  },
) {
  const opened = requireSuccessfulTool<WorkspaceResult>(
    await call("open_codex_security_workspace", selection),
    labels.workspace,
  );
  const sessionId = opened.workspace.id;
  requireSuccessfulTool(
    await call("submit_codex_security_setup", { ...selection, sessionId }),
    labels.setup,
  );
  const started = requireSuccessfulTool<WorkspaceResult>(
    await call("start_codex_security_scan", { sessionId }),
    labels.scan,
  );
  const { scanId } = started.workspace.results;
  const handoffClaimToken = randomUUID();
  requireSuccessfulTool(
    await call("claim_codex_security_scan_handoff_delivery", {
      scanId,
      claimToken: handoffClaimToken,
    }),
    labels.claim,
  );
  requireSuccessfulTool(
    await call("attach_codex_security_scan_continuation_thread", {
      scanId,
      claimToken: handoffClaimToken,
      threadId: ownerThread,
    }),
    labels.owner,
  );
  return { ...started.workspace.results, handoffClaimToken };
}

async function startClient(
  bundle: string,
  environment: Record<string, string>,
) {
  const client = new Client({
    name: "codex-security-compact-artifact-test",
    version: "1.0.0",
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [bundle, "--stdio"],
    cwd: applicationRoot,
    env: {
      ...process.env,
      ...environment,
    } as Record<string, string>,
  });
  await client.connect(transport);
  return client;
}

function toolCaller(client: Client, ownerThread: string) {
  return (
    name: string,
    arguments_: Record<string, unknown>,
    threadId: string | null = ownerThread,
  ) =>
    client.callTool({
      name,
      arguments: arguments_,
      ...(threadId == null ? {} : { _meta: { "openai/threadId": threadId } }),
    });
}
