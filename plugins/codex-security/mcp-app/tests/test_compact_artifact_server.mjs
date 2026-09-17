import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const applicationRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const pluginRoot = path.resolve(applicationRoot, "..");
const bundledPluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : path.resolve(applicationRoot, "../../../sdk/typescript/_bundled_plugin");
const temporaryRoot = await mkdtemp(path.join(tmpdir(), "codex-security-artifact-mcp-"));

try {
  const runtimeBundle = path.join(temporaryRoot, "server.cjs");
  await bundleEntrypoint("main.ts", runtimeBundle);

  await testParentToolList(runtimeBundle);
  await testClaimedParentArtifactOperations(runtimeBundle, "source");
  await testPromptDrivenPrivateRecipe(runtimeBundle, "source");
  await testCompletedNativeDeepRejoin(runtimeBundle, "source");
  await testSemanticScanDraftCompletion(runtimeBundle, "source");
  await testCompactDiffScanCompletion(runtimeBundle, "source");

  const shippedRuntime = path.join(bundledPluginRoot, "mcp", "server.mjs");
  await testParentToolList(shippedRuntime);
  await testClaimedParentArtifactOperations(shippedRuntime, "shipped");
  await testPromptDrivenPrivateRecipe(shippedRuntime, "shipped");
  await testCompletedNativeDeepRejoin(shippedRuntime, "shipped");
  await testSemanticScanDraftCompletion(shippedRuntime, "shipped");
  await testCompactDiffScanCompletion(shippedRuntime, "shipped");
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function testCompactDiffScanCompletion(bundle, runtimeLabel) {
  const fixtureRoot = path.join(temporaryRoot, `compact-diff-${runtimeLabel}`);
  const repoRoot = path.join(fixtureRoot, "repository");
  const stateRoot = path.join(fixtureRoot, "state");
  const scanRoot = path.join(fixtureRoot, "scans");
  await mkdir(fixtureRoot, { mode: 0o700 });
  await Promise.all([
    mkdir(path.join(repoRoot, "src"), { recursive: true }),
    mkdir(stateRoot, { recursive: true }),
    mkdir(scanRoot, { recursive: true, mode: 0o700 })
  ]);
  const git = (...arguments_) => execFileSync(
    "git",
    ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", ...arguments_],
    { cwd: repoRoot, encoding: "utf8" }
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

  const client = await startClient(bundle, {
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
    CODEX_SECURITY_STATE_DIR: stateRoot
  });
  const ownerThread = `compact-diff-owner-${runtimeLabel}`;
  const call = (name, arguments_) => client.callTool({
    name,
    arguments: arguments_,
    _meta: { "openai/threadId": ownerThread }
  });

  try {
    const selection = {
      targetPath: repoRoot,
      scope: ".",
      mode: "diff",
      diffTarget: { kind: "range", baseRevision, headRevision }
    };
    const opened = requireSuccessfulTool(
      await call("open_codex_security_workspace", selection),
      `${runtimeLabel}: open compact diff workspace`
    );
    const sessionId = opened.workspace.id;
    requireSuccessfulTool(
      await call("submit_codex_security_setup", { ...selection, sessionId }),
      `${runtimeLabel}: submit compact diff setup`
    );
    const started = requireSuccessfulTool(
      await call("start_codex_security_scan", { sessionId }),
      `${runtimeLabel}: start compact diff scan`
    );
    const scanId = started.workspace.results.scanId;
    const handoffClaimToken = randomUUID();
    requireSuccessfulTool(
      await call("claim_codex_security_scan_handoff_delivery", {
        scanId,
        claimToken: handoffClaimToken
      }),
      `${runtimeLabel}: claim compact diff scan`
    );
    requireSuccessfulTool(
      await call("attach_codex_security_scan_continuation_thread", {
        scanId,
        claimToken: handoffClaimToken,
        threadId: ownerThread
      }),
      `${runtimeLabel}: attach compact diff owner`
    );
    requireSuccessfulTool(
      await call("get_codex_security_scan_context", { scanId, handoffClaimToken }),
      `${runtimeLabel}: authenticate compact diff owner`
    );

    for (const reserved of [
      "artifacts/02_discovery/candidate_ledger.jsonl",
      "artifacts/02_discovery/in_scope_files.txt",
      "artifacts/01_context/false_positive_feedback.json"
    ]) {
      const rejected = await call("save_codex_security_artifact", {
        scanId, handoffClaimToken, storage: "persistent",
        path: `${reserved}/note.txt`, content: "must not block typed writers"
      });
      assert.equal(rejected.isError, true, `${runtimeLabel}: reject a canonical file used as a directory`);
    }

    const inventory = requireSuccessfulTool(
      await call("prepare_codex_security_review_items", { scanId, handoffClaimToken }),
      `${runtimeLabel}: prepare exact compact diff inventory`
    );
    assert.equal(inventory.reviewItemsTotal, 2);
    const reviewItems = requireSuccessfulTool(
      await call("list_codex_security_review_items", { scanId, handoffClaimToken }),
      `${runtimeLabel}: list compact diff inventory`
    );
    assert.deepEqual(reviewItems.items, [
      { path: "src/guard.py" },
      { path: "src/handler.py" }
    ]);

    requireSuccessfulTool(
      await call("record_codex_security_discovery_candidates", {
        scanId,
        candidates: [{
          cwe_ids: [],
          locations: [{ path: "src/handler.py", start_line: 1, role: "root_control" }],
          summary: "The changed handler may rely on the removed guard.",
          evidence: "The selected change removes a neighboring guard."
        }]
      }),
      `${runtimeLabel}: record a diff candidate alongside a deleted file`
    );
    const candidates = requireSuccessfulTool(
      await call("list_codex_security_candidates", { scanId }),
      `${runtimeLabel}: read compact diff candidates`
    );
    requireSuccessfulTool(
      await call("record_codex_security_candidate_validations", {
        scanId,
        validations: [{
          candidateId: candidates.rows[0].candidate_id,
          validation: {
            disposition: "suppressed",
            method: "Static review of the changed handler.",
            confidence: "high",
            confidence_rationale: "The changed handler has no security-sensitive operation.",
            rubric: ["The changed assignment does not cross a trust boundary."],
            evidence: ["value = 2"],
            counterevidence_or_proof_gap: "No attacker-controlled operation is present.",
            remaining_uncertainty: ""
          }
        }]
      }),
      `${runtimeLabel}: record the compact diff validation`
    );
    requireSuccessfulTool(
      await call("record_candidate_attack_paths", {
        scanId,
        attackPaths: []
      }),
      `${runtimeLabel}: close the empty compact diff attack-path phase`
    );
    requireSuccessfulTool(
      await call("record_codex_security_scan_draft", {
        scanId,
        handoffClaimToken,
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [{ label: "Changed handler and removed guard", disposition: "rejected" }],
          explicitExclusions: [],
          deferred: []
        }
      }),
      `${runtimeLabel}: record compact diff canonical semantics`
    );
    requireSuccessfulTool(
      await call("complete_codex_security_scan", { scanId, handoffClaimToken }),
      `${runtimeLabel}: complete compact diff scan`
    );
    const completed = requireSuccessfulTool(
      await call("get_codex_security_completed_scan", { scanId, handoffClaimToken }),
      `${runtimeLabel}: read completed compact diff scan`
    );
    assert.equal(completed.manifest.scan.target.baseRevision, baseRevision);
    assert.equal(completed.manifest.scan.target.headRevision, headRevision);
    assert.match(
      completed.manifest.scan.target.snapshotDigest,
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u
    );
    assert.equal(completed.coverage.inventoryStrategy, "diff");
    assert.equal(completed.findings.findings.length, 0);
  } finally {
    await client.close();
  }
}

async function testSemanticScanDraftCompletion(bundle, runtimeLabel) {
  const fixtureRoot = path.join(temporaryRoot, `semantic-draft-${runtimeLabel}`);
  const repoRoot = path.join(fixtureRoot, "repository");
  const stateRoot = path.join(fixtureRoot, "state");
  const scanRoot = path.join(fixtureRoot, "scans");
  await mkdir(fixtureRoot, { mode: 0o700 });
  await Promise.all([
    mkdir(path.join(repoRoot, "src"), { recursive: true }),
    mkdir(stateRoot, { recursive: true }),
    mkdir(scanRoot, { recursive: true, mode: 0o700 })
  ]);
  const sourceLine = "    return connection.execute(query)";
  await writeFile(
    path.join(repoRoot, "src", "fixture.py"),
    `def execute(query):\n${sourceLine}\n`
  );

  const client = await startClient(bundle, {
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
    CODEX_SECURITY_STATE_DIR: stateRoot
  });
  const ownerThread = `semantic-draft-owner-${runtimeLabel}`;
  const call = (name, arguments_) => client.callTool({
    name,
    arguments: arguments_,
    _meta: { "openai/threadId": ownerThread }
  });

  try {
    const opened = requireSuccessfulTool(await call("open_codex_security_workspace", {
      targetPath: repoRoot,
      scope: ".",
      mode: "standard"
    }), `${runtimeLabel}: open semantic-draft workspace`);
    const sessionId = opened.workspace.id;

    requireSuccessfulTool(await call("submit_codex_security_setup", {
      sessionId,
      targetPath: repoRoot,
      scope: ".",
      mode: "standard"
    }), `${runtimeLabel}: submit semantic-draft setup`);

    const started = requireSuccessfulTool(await call("start_codex_security_scan", {
      sessionId
    }), `${runtimeLabel}: start semantic-draft scan`);
    const scanId = started.workspace.results.scanId;
    const scanDirectory = started.workspace.results.scanDir;
    const handoffClaimToken = randomUUID();

    requireSuccessfulTool(await call("claim_codex_security_scan_handoff_delivery", {
      scanId,
      claimToken: handoffClaimToken
    }), `${runtimeLabel}: claim semantic-draft scan`);
    requireSuccessfulTool(await call("attach_codex_security_scan_continuation_thread", {
      scanId,
      claimToken: handoffClaimToken,
      threadId: ownerThread
    }), `${runtimeLabel}: attach semantic-draft owner`);
    requireSuccessfulTool(await call("get_codex_security_scan_context", {
      scanId,
      handoffClaimToken
    }), `${runtimeLabel}: authenticate semantic-draft owner`);

    for (const [name, arguments_] of [
      ["list_codex_security_review_items", { scanId, handoffClaimToken }],
      ["list_codex_security_candidates", { scanId }],
      ["record_codex_security_candidate_validations", {
        scanId,
        validations: []
      }],
      ["record_candidate_attack_paths", {
        scanId,
        attackPaths: []
      }]
    ]) {
      requireToolError(
        await call(name, arguments_),
        /only available for Deep or diff scans/,
        `${runtimeLabel}: ${name} must reject a Standard scan`
      );
    }

    const candidate = {
      candidate_id: "candidate-0123456789abcdef",
      cwe_ids: ["CWE-89"]
    };
    await assert.rejects(
      readFile(path.join(scanDirectory, "artifacts", "02_discovery", "in_scope_files.txt")),
      { code: "ENOENT" }
    );
    await assert.rejects(
      readFile(path.join(scanDirectory, "artifacts", "02_discovery", "candidate_ledger.jsonl")),
      { code: "ENOENT" }
    );

    const codeEvidence = {
      id: "fixture-sql-sink",
      label: "SQL execution sink",
      path: "src/fixture.py",
      startLine: 2,
      code: sourceLine,
      explanation: "The reviewed query argument is passed directly to SQL execution."
    };
    const finding = {
      ruleId: "sql-injection.query-execution",
      title: "Untrusted query text reaches SQL execution",
      summary: "The execution helper passes a query argument directly to its SQL sink.",
      severity: { level: "high" },
      confidence: {
        level: "high",
        rationale: "The vulnerable sink is directly visible in the reviewed source."
      },
      taxonomy: { category: "sql-injection", cwe: candidate.cwe_ids },
      locations: [{ path: "src/fixture.py", startLine: 2, endLine: 2 }],
      codeEvidence: [codeEvidence],
      rootCause: {
        summary: "The query is not parameterized before SQL execution.",
        evidenceRefs: [codeEvidence.id]
      },
      remediation: "Use a parameterized SQL statement.",
      remediationTests: ["Verify an attacker-controlled query remains a bound parameter."],
      preventiveControls: ["Require the shared parameterized-query helper."],
      provenance: {
        source: "local_plugin",
        candidateId: candidate.candidate_id
      },
      extensions: { candidateId: candidate.candidate_id }
    };
    const reasonOnlyDeferred = {
      reason: "A neighboring SQL adapter could not be exercised.",
      paths: ["src/fixture.py"],
      surfaceIds: ["surface_sql-execution"],
      source: "preserve-reason-only-metadata"
    };
    const explicitCollisionDeferred = {
      reason: "An unavailable adapter requires explicit follow-up ownership."
    };
    const candidateCollisionDeferred = {
      reason: "An unavailable adapter belongs to an existing candidate."
    };
    const deferredIdentity = ({ reason, paths, surfaceIds }) => {
      const digest = createHash("sha256")
        .update(JSON.stringify([reason, paths ?? [], surfaceIds ?? []]))
        .digest("hex")
        .slice(0, 16);
      return `deferred-${digest}`;
    };
    const reasonOnlyDeferredId = deferredIdentity(reasonOnlyDeferred);
    const explicitCollisionDeferredId = deferredIdentity(explicitCollisionDeferred);
    const candidateCollisionDeferredId = deferredIdentity(candidateCollisionDeferred);
    const coverage = {
      completeness: "partial",
      surfaces: [{
        label: "SQL execution",
        disposition: "reported",
        notes: "Reviewed the execution helper and its unparameterized SQL sink."
      }],
      explicitExclusions: [],
      deferred: [
        {
          candidateId: "candidate-deferred-query",
          reason: "A neighboring SQL execution mode remains unavailable.",
          paths: ["src/fixture.py"],
          source: "preserve-candidate-metadata"
        },
        {
          candidateId: "candidate-reserved-query",
          reason: "A neighboring query sink needs a follow-up trace."
        },
        {
          id: "candidate-reserved-query",
          candidateId: "candidate-explicit-query",
          reason: "Retain the explicitly supplied deferred identity.",
          surfaceIds: ["surface_sql-execution"]
        },
        {
          candidateId: "candidate-deferred-query",
          reason: "Another query sink requires a unique deferred identity."
        },
        {
          candidateId: "candidate-reserved-query",
          reason: "Use the next available identity for the reserved query."
        },
        reasonOnlyDeferred,
        { ...reasonOnlyDeferred },
        explicitCollisionDeferred,
        candidateCollisionDeferred,
        {
          id: explicitCollisionDeferredId,
          candidateId: "candidate-explicit-reason-only-query",
          reason: "The later explicit identity must retain its owned base."
        },
        {
          candidateId: candidateCollisionDeferredId,
          reason: "The later candidate identity must retain its owned base."
        }
      ],
      openQuestions: [
        "  Can a neighboring query API bypass parameterization?  ",
        {
          question: "Does authorization restrict the query endpoint?",
          followUpPrompt: "Trace the endpoint authorization boundary.",
          source: "preserve-question-metadata"
        }
      ]
    };

    const originalDraft = await snapshotScanDraft(scanDirectory);
    const malformed = {
      scanId,
      handoffClaimToken,
      scope: { includePaths: ["."] },
      findings: [{
        ...finding,
        ruleId: "CWE-89",
        taxonomy: { category: "sql-injection", cweIds: candidate.cwe_ids },
        provenance: { candidateId: candidate.candidate_id },
        codeEvidence: [{ ...codeEvidence, code: "" }]
      }],
      coverage: {
        ...coverage,
        mode: "repository",
        inventoryStrategy: "repository",
        includePaths: ["."],
        excludePaths: [],
        receiptRefs: [],
        surfaces: [{ surface: "SQL execution", outcome: "reported" }]
      }
    };

    let rejected;
    try {
      rejected = await call("record_codex_security_scan_draft", malformed);
    } catch (error) {
      assert.equal(
        error.code,
        -32602,
        `${runtimeLabel}: malformed draft must fail before handler execution`
      );
    }
    if (rejected !== undefined) {
      assert.equal(
        rejected.isError,
        true,
        `${runtimeLabel}: a malformed draft must not be accepted`
      );
    }
    assert.deepEqual(
      await snapshotScanDraft(scanDirectory),
      originalDraft,
      `${runtimeLabel}: input rejection must not write any canonical artifact`
    );

    for (const [description, invalidCoverage] of [
      [
        "a whitespace-only deferred candidate identity",
        { ...coverage, deferred: [{ candidateId: "  ", reason: "An identity is required." }] }
      ],
      [
        "a whitespace-only open question",
        { ...coverage, openQuestions: ["  \t  "] }
      ],
      [
        "an open-question object without its question",
        { ...coverage, openQuestions: [{ followUpPrompt: "Trace the SQL entrypoint." }] }
      ],
      ...[
        ["a path-traversal candidate identity", ".."],
        ["a forward-slash candidate identity", "candidate/nested"],
        ["a backslash candidate identity", "candidate\\nested"],
        ["a control-character candidate identity", "candidate\u0001nested"],
        ["an oversized candidate identity", "a".repeat(513)]
      ].flatMap(([description, candidateId]) => [
        [
          description,
          {
            ...coverage,
            deferred: [{ candidateId, reason: "The candidate identity must remain safe." }]
          }
        ],
        [
          `${description} alongside an explicit deferred identity`,
          {
            ...coverage,
            deferred: [{
              id: "explicit-safe-deferred",
              candidateId,
              reason: "An explicit identity must not bypass candidate validation."
            }]
          }
        ]
      ])
    ]) {
      let invalid;
      try {
        invalid = await call("record_codex_security_scan_draft", {
          scanId,
          handoffClaimToken,
          findings: [finding],
          coverage: invalidCoverage
        });
      } catch (error) {
        assert.equal(error.code, -32602, `${runtimeLabel}: ${description} must fail input validation`);
      }
      if (invalid !== undefined) {
        assert.equal(invalid.isError, true, `${runtimeLabel}: ${description} must not be accepted`);
      }
      assert.deepEqual(
        await snapshotScanDraft(scanDirectory),
        originalDraft,
        `${runtimeLabel}: rejecting ${description} must not write canonical artifacts`
      );
    }

    const progress = async () => requireSuccessfulTool(await call(
      "get_codex_security_scan_context", { scanId, handoffClaimToken }
    )).scan.progress;
    assert.equal((await progress()).phase, "preflight");
    requireSuccessfulTool(await call("update_codex_security_scan_progress", {
      scanId, handoffClaimToken, phaseItemsTotal: 1, phaseItemsCompleted: 1,
      phaseProgressUnit: "checks"
    }));
    const checkpoint = {
      scanId,
      handoffClaimToken,
      complete: false,
      findings: [finding],
      coverage: { ...coverage, completeness: "partial" }
    };
    requireSuccessfulTool(await call("record_codex_security_scan_draft", checkpoint));
    const discovery = await progress();
    assert.equal(discovery.status, "running");
    assert.equal(discovery.phase, "discovery");
    assert.deepEqual(discovery.phaseProgress, { completed: 0, total: 0, unit: null });

    requireSuccessfulTool(await call("update_codex_security_scan_progress", {
      scanId, handoffClaimToken, phase: "validation", phaseItemsTotal: 2,
      phaseItemsCompleted: 1, phaseProgressUnit: "candidate_findings"
    }));
    requireSuccessfulTool(await call("record_codex_security_scan_draft", checkpoint));
    const validation = await progress();
    assert.equal(validation.phase, "validation");
    assert.deepEqual(validation.phaseProgress, {
      completed: 1, total: 2, unit: "candidate_findings"
    });

    const drafted = requireSuccessfulTool(await call(
      "record_codex_security_scan_draft",
      {
        scanId,
        handoffClaimToken,
        findings: [finding],
        coverage
      }
    ), `${runtimeLabel}: correct the same scan and accept exactly one draft`);
    assert.deepEqual(drafted, {
      scanId,
      findingCount: 1,
      surfaceCount: 1,
      operation: "replace",
      status: "draft_written"
    });
    const reporting = await progress();
    assert.equal(reporting.phase, "reporting");
    assert.equal(reporting.status, "running");
    assert.deepEqual(reporting.phaseProgress, { completed: 0, total: 0, unit: null });

    const completed = requireSuccessfulTool(await call(
      "complete_codex_security_scan",
      { scanId, handoffClaimToken }
    ), `${runtimeLabel}: finalize the accepted draft exactly once`);
    assert.equal(completed.scan.progress.status, "complete");
    assert.equal(completed.scan.reportAvailable, true);

    const results = requireSuccessfulTool(await call(
      "get_codex_security_completed_scan",
      { scanId, handoffClaimToken }
    ), `${runtimeLabel}: read the actually sealed completed scan`);
    assert.equal(results.scanId, scanId);
    assert.equal(results.manifest.scan.status, "completed");
    assert.ok(results.manifest.scan.sealedAt);
    assert.ok(results.manifest.scan.artifacts.length > 0);
    assert.equal(results.findings.findings.length, 1);
    assert.equal(results.findings.findings[0].ruleId, finding.ruleId);
    assert.deepEqual(results.findings.findings[0].taxonomy, finding.taxonomy);
    assert.deepEqual(results.findings.findings[0].provenance, finding.provenance);
    assert.equal(results.findings.findings[0].remediation, finding.remediation);
    assert.deepEqual(results.findings.findings[0].remediationTests, finding.remediationTests);
    assert.deepEqual(results.findings.findings[0].preventiveControls, finding.preventiveControls);
    assert.equal(
      results.findings.findings[0].extensions.candidateId,
      candidate.candidate_id
    );
    assert.ok(results.findings.findings[0].findingId);
    assert.ok(results.findings.findings[0].occurrenceId);
    assert.ok(results.findings.findings[0].fingerprints.primary);
    assert.equal(results.manifest.scan.target.kind, "directory_snapshot");
    assert.equal(results.coverage.inventoryStrategy, "directory");
    assert.equal(results.coverage.completeness, "partial");
    assert.deepEqual(results.coverage.includePaths, ["."]);
    assert.deepEqual(results.coverage.excludePaths, []);
    assert.equal(results.coverage.surfaces[0].disposition, "reported");
    assert.deepEqual(results.coverage.deferred, [
      {
        ...coverage.deferred[0],
        id: "candidate-deferred-query"
      },
      {
        ...coverage.deferred[1],
        id: "candidate-reserved-query-2"
      },
      coverage.deferred[2],
      {
        ...coverage.deferred[3],
        id: "candidate-deferred-query-2"
      },
      {
        ...coverage.deferred[4],
        id: "candidate-reserved-query-3"
      },
      {
        ...reasonOnlyDeferred,
        id: reasonOnlyDeferredId
      },
      {
        ...reasonOnlyDeferred,
        id: `${reasonOnlyDeferredId}-2`
      },
      {
        ...explicitCollisionDeferred,
        id: `${explicitCollisionDeferredId}-2`
      },
      {
        ...candidateCollisionDeferred,
        id: `${candidateCollisionDeferredId}-2`
      },
      coverage.deferred[9],
      {
        ...coverage.deferred[10],
        id: candidateCollisionDeferredId
      }
    ]);
    assert.deepEqual(results.coverage.openQuestions, [
      { question: "Can a neighboring query API bypass parameterization?" },
      coverage.openQuestions[1]
    ]);
    assert.ok((await readFile(path.join(scanDirectory, "report.md"), "utf8")).length > 0);
  } finally {
    await client.close();
  }
}

async function snapshotScanDraft(scanDirectory) {
  return Promise.all(["scan-manifest.json", "findings.json", "coverage.json"].map(
    async (artifact) => {
      try {
        return await readFile(path.join(scanDirectory, artifact), "utf8");
      } catch (error) {
        if (error.code === "ENOENT") return null;
        throw error;
      }
    }
  ));
}

async function testClaimedParentArtifactOperations(bundle, runtimeLabel) {
  const repoRoot = path.join(temporaryRoot, `claimed-parent-${runtimeLabel}-repository`);
  const stateRoot = path.join(temporaryRoot, `claimed-parent-${runtimeLabel}-state`);
  const scanRoot = path.join(temporaryRoot, `claimed-parent-${runtimeLabel}-scans`);
  await Promise.all([
    mkdir(path.join(repoRoot, "src"), { recursive: true }),
    mkdir(stateRoot, { recursive: true }),
    mkdir(scanRoot, { recursive: true, mode: 0o700 })
  ]);
  await writeFile(path.join(repoRoot, "src", "fixture.py"), "print('fixture')\n");

  const environment = {
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
    CODEX_SECURITY_STATE_DIR: stateRoot
  };
  let client = await startClient(bundle, environment);
  const ownerThread = `compact-artifact-owner-${runtimeLabel}`;
  const otherThread = `compact-artifact-other-${runtimeLabel}`;
  const executionThread = `compact-artifact-sdk-merge-${runtimeLabel}`;
  const call = (name, arguments_, threadId = ownerThread) => client.callTool({
    name,
    arguments: arguments_,
    ...(threadId == null ? {} : { _meta: { "openai/threadId": threadId } })
  });

  try {
    const opened = requireSuccessfulTool(await call("open_codex_security_workspace", {
      targetPath: repoRoot,
      scope: ".",
      mode: "deep"
    }), "open claimed parent workspace");
    const sessionId = opened.workspace.id;

    requireSuccessfulTool(await call("submit_codex_security_setup", {
      sessionId,
      targetPath: repoRoot,
      scope: ".",
      mode: "deep"
    }), "submit claimed parent setup");

    const started = requireSuccessfulTool(await call("start_codex_security_scan", {
      sessionId
    }), "start claimed parent scan");
    const scanId = started.workspace.results.scanId;
    const scanDirectory = started.workspace.results.scanDir;
    const inventoryPath = path.join(
      scanDirectory,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt"
    );
    const ledgerPath = path.join(
      scanDirectory,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl"
    );
    const claimToken = randomUUID();

    requireSuccessfulTool(await call("claim_codex_security_scan_handoff_delivery", {
      scanId,
      claimToken
    }), "claim parent scan handoff");
    requireSuccessfulTool(await call("attach_codex_security_scan_continuation_thread", {
      scanId,
      claimToken,
      threadId: ownerThread
    }), "attach parent scan owner");

    const phaseCalls = [
      ["list_codex_security_review_items", { scanId }],
      ["list_codex_security_candidates", { scanId }],
      ["record_codex_security_candidate_validations", { scanId, validations: [] }],
      ["record_candidate_attack_paths", { scanId, attackPaths: [] }]
    ];
    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_),
        /requires its current continuation claim/,
        `${name} before authenticated scan context`
      );
    }

    const delivered = requireSuccessfulTool(await call("get_codex_security_scan_context", {
      scanId,
      handoffClaimToken: claimToken
    }), "authenticate parent scan owner");
    assert.equal(delivered.scan.continuationThreadId, ownerThread);
    assert.equal(delivered.scan.handoffClaimToken, undefined);

    const recipe = privateScanRecipe(repoRoot, "deep");
    runWorkbenchFixture(runtimeLabel, environment, [
      "register-cli-scan", "--repository", repoRoot, "--scan-dir", scanDirectory,
      "--registration-json-stdin"
    ], { recipe, scanId, threadId: ownerThread, claimToken });
    runWorkbenchFixture(runtimeLabel, environment, [
      "set-scan-thread", "--scan-id", scanId, "--claim-token", claimToken,
      "--thread-id", executionThread
    ]);

    await client.close();
    client = await startClient(bundle, environment);
    for (const threadId of [otherThread, executionThread]) {
      requireToolError(
        await call("get_codex_security_scan_context", {
          scanId, handoffClaimToken: claimToken
        }, threadId),
        /owning Codex thread/,
        `${runtimeLabel}: reject context reload from a different native owner`
      );
    }
    requireToolError(
      await call("get_codex_security_scan_context", {
        scanId, handoffClaimToken: randomUUID()
      }),
      /owned by another continuation/,
      `${runtimeLabel}: reject context reload with a different claim`
    );
    const reloadedResult = await call("get_codex_security_scan_context", {
      scanId, handoffClaimToken: claimToken
    });
    const reloaded = requireSuccessfulTool(reloadedResult, "reload original native owner after SDK execution");
    assert.equal(reloaded.scan.continuationThreadId, executionThread);
    assertPrivateRecipeOmitted(reloadedResult, recipe, `${runtimeLabel}: reloaded context`);
    const progressResult = await call("update_codex_security_scan_progress", {
      scanId, handoffClaimToken: claimToken, preflightChecks: []
    });
    requireSuccessfulTool(progressResult, "update native owner progress after SDK execution");
    assertPrivateRecipeOmitted(progressResult, recipe, `${runtimeLabel}: progress response`);
    assert.deepEqual(runWorkbenchFixture(runtimeLabel, environment, [
      "get-scan-recipe", "--scan-id", scanId
    ]).recipe, recipe, `${runtimeLabel}: model responses preserve the complete host recipe`);

    for (const [name, arguments_] of [
      ["prepare_codex_security_review_items", { scanId }],
      ["record_codex_security_discovery_candidates", { scanId, candidates: [] }]
    ]) {
      requireToolError(
        await call(name, arguments_),
        /only available for diff scans/,
        `${name} must not replace Deep discovery artifacts`
      );
    }

    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_, null),
        /requires its current continuation claim/,
        `${name} without continuation-thread metadata`
      );
      requireToolError(
        await call(name, arguments_, otherThread),
        /requires its current continuation claim/,
        `${name} from a different continuation thread before discovery artifacts exist`
      );
    }
    await assert.rejects(readFile(inventoryPath, "utf8"), { code: "ENOENT" });
    await assert.rejects(readFile(ledgerPath, "utf8"), { code: "ENOENT" });

    await mkdir(path.dirname(inventoryPath), { recursive: true });
    await writeFile(inventoryPath, "./src/fixture.py\n");
    const seededCandidate = {
      candidate_id: "candidate-0123456789abcdef",
      cwe_ids: ["CWE-89"],
      locations: [{
        path: "src/fixture.py",
        start_line: 1,
        end_line: 1,
        role: "sink"
      }],
      summary: "The fixture provides a reachable SQL sink.",
      evidence: "The first source line contains the reviewed sink."
    };
    await writeFile(ledgerPath, `${JSON.stringify(seededCandidate)}\n`);

    const reviewItems = requireSuccessfulTool(await call(
      "list_codex_security_review_items",
      { scanId }
    ), "read claimed parent inventory without a model-visible claim");
    assert.deepEqual(reviewItems.items, [{ path: "./src/fixture.py" }]);

    const explicitlyListed = requireSuccessfulTool(await call(
      "list_codex_security_review_items",
      { scanId, handoffClaimToken: claimToken }
    ), "read claimed parent inventory with an explicit continuation claim");
    assert.deepEqual(explicitlyListed.items, [{ path: "./src/fixture.py" }]);

    const originalInventory = await readFile(inventoryPath, "utf8");
    const listed = requireSuccessfulTool(await call("list_codex_security_candidates", {
      scanId
    }), "read Deep discovery candidates without a model-visible claim");
    assert.equal(listed.rows.length, 1);
    const candidateId = listed.rows[0].candidate_id;

    const validated = requireSuccessfulTool(await call(
      "record_codex_security_candidate_validations",
      {
        scanId,
        validations: [{
          candidateId,
          validation: {
            disposition: "reportable",
            method: "Static source-to-sink trace.",
            confidence: "high",
            confidence_rationale: "The vulnerable code path is directly visible.",
            rubric: ["The source is attacker-controlled."],
            evidence: ["The source line directly reaches the sink."],
            counterevidence_or_proof_gap: "No effective control was found.",
            remaining_uncertainty: ""
          }
        }]
      }
    ), "validate claimed parent candidates without a model-visible claim");
    assert.deepEqual(validated, {
      kind: "candidate_validations",
      operation: "replace",
      rowsWritten: 1
    });

    const attacked = requireSuccessfulTool(await call(
      "record_candidate_attack_paths",
      {
        scanId,
        attackPaths: [{
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
            change_conditions: "Parameterized queries remove the issue."
          }
        }]
      }
    ), "record claimed parent attack paths without a model-visible claim");
    assert.deepEqual(attacked, {
      kind: "candidate_attack_paths",
      operation: "replace",
      rowsWritten: 1
    });

    const originalLedger = await readFile(ledgerPath, "utf8");
    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_, otherThread),
        /requires its current continuation claim/,
        `${name} from a different continuation thread`
      );
      assert.equal(await readFile(ledgerPath, "utf8"), originalLedger);
      assert.equal(await readFile(inventoryPath, "utf8"), originalInventory);
    }

    execFileSync(process.env.PYTHON ?? "python3", [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
        + "c.execute('UPDATE scans SET handoff_claim_token = ? WHERE id = ?', "
        + "(sys.argv[2],sys.argv[3])); c.commit(); c.close()",
      path.join(stateRoot, "workbench.sqlite3"),
      randomUUID(),
      scanId
    ]);
    for (const [name, arguments_] of phaseCalls) {
      requireToolError(
        await call(name, arguments_),
        /owned by a different continuation/,
        `${name} after continuation claim rotation`
      );
      assert.equal(await readFile(ledgerPath, "utf8"), originalLedger);
      assert.equal(await readFile(inventoryPath, "utf8"), originalInventory);
    }
  } finally {
    await client.close();
  }
}

async function testPromptDrivenPrivateRecipe(bundle, runtimeLabel) {
  for (const kind of ["prompt-only", "headless"]) {
    const fixtureRoot = path.join(temporaryRoot, `private-recipe-${kind}-${runtimeLabel}`);
    const repoRoot = path.join(fixtureRoot, "repository");
    const environment = {
      CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "scans"),
      CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state")
    };
    await mkdir(repoRoot, { recursive: true });
    await mkdir(environment.CODEX_SECURITY_SCAN_ROOT, { mode: 0o700 });
    await writeFile(path.join(repoRoot, "fixture.py"), "print('fixture')\n");
    const client = await startClient(bundle, environment);
    const ownerThread = `private-recipe-${kind}-${runtimeLabel}`;
    const toolName = kind === "prompt-only"
      ? "start_codex_security_prompt_only_scan"
      : "start_codex_security_standard_scan";
    const callStart = () => client.callTool({
      name: toolName,
      arguments: {
        targetPath: repoRoot,
        scope: ".",
        ...(kind === "prompt-only" ? { mode: "standard" } : {})
      },
      _meta: { "openai/threadId": ownerThread }
    });

    try {
      const startedResult = await callStart();
      const started = requireSuccessfulTool(startedResult, `${runtimeLabel}: start ${kind} scan`);
      const { scanId, scanDir } = started.scan;
      const claimToken = started.handoffClaimToken;
      const recipe = privateScanRecipe(repoRoot, "standard");
      runWorkbenchFixture(runtimeLabel, environment, [
        "register-cli-scan", "--repository", repoRoot, "--scan-dir", scanDir,
        "--registration-json-stdin"
      ], { recipe, scanId, threadId: ownerThread, ...(claimToken ? { claimToken } : {}) });
      if (claimToken) {
        runWorkbenchFixture(runtimeLabel, environment, [
          "set-scan-thread", "--scan-id", scanId, "--claim-token", claimToken,
          "--thread-id", ownerThread
        ]);
      }
      const joinedResult = await callStart();
      const joined = requireSuccessfulTool(joinedResult, `${runtimeLabel}: rejoin ${kind} scan`);
      assert.equal(joined.startDisposition, "joined");
      assert.equal(joined.scan.scanId, scanId);
      if (kind === "prompt-only") {
        for (const result of [startedResult, joinedResult]) {
          const instructions = result.content
            .filter((content) => content.type === "text")
            .map((content) => content.text)
            .join("\n");
          assert.ok(instructions.includes("complete_codex_security_scan"));
          assert.equal(instructions.includes("get_codex_security_completed_scan"), false);
        }
      }
      assertPrivateRecipeOmitted(joinedResult, recipe, `${runtimeLabel}: ${kind} rejoin`);
      assert.deepEqual(runWorkbenchFixture(runtimeLabel, environment, [
        "get-scan-recipe", "--scan-id", scanId
      ]).recipe, recipe, `${runtimeLabel}: ${kind} rejoin preserves the complete host recipe`);
    } finally {
      await client.close();
    }
  }
}

async function testCompletedNativeDeepRejoin(bundle, runtimeLabel) {
  const fixtureRoot = path.join(temporaryRoot, `completed-native-${runtimeLabel}`);
  const repoRoot = path.join(fixtureRoot, "repository");
  const invocationPath = path.join(fixtureRoot, "unexpected-codex-invocation");
  const environment = {
    CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "scans"),
    CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "state"),
    CODEX_HOME: path.join(fixtureRoot, "codex-home"),
    CODEX_CLI_PATH: path.join(fixtureRoot, "codex-stub"),
    CODEX_API_KEY: "",
    OPENAI_API_KEY: ""
  };
  await mkdir(repoRoot, { recursive: true });
  await mkdir(environment.CODEX_SECURITY_SCAN_ROOT, { mode: 0o700 });
  await mkdir(environment.CODEX_HOME, { mode: 0o700 });
  await writeFile(path.join(repoRoot, "fixture.py"), "print('fixture')\n");
  await writeFile(environment.CODEX_CLI_PATH, `#!${process.execPath}
require("node:fs").writeFileSync(${JSON.stringify(invocationPath)}, "unexpected launch");
process.exit(1);
`, { mode: 0o700 });

  const ownerThread = `completed-native-owner-${runtimeLabel}`;
  const begun = runWorkbenchFixture(runtimeLabel, environment, [
    "begin-deep-scan", "--target-path", repoRoot, "--scope", ".", "--thread-id", ownerThread
  ]);
  const { scanId, scanDir, handoffClaimToken } = begun.scan;
  runWorkbenchFixture(runtimeLabel, environment, [
    "register-cli-scan", "--repository", repoRoot, "--scan-dir", scanDir,
    "--registration-json-stdin"
  ], {
    scanId, threadId: ownerThread, claimToken: handoffClaimToken,
    recipe: { repository: repoRoot, mode: "deep", target: { kind: "repository", paths: [] }, config: {} }
  });
  runWorkbenchFixture(runtimeLabel, environment, [
    "set-scan-thread", "--scan-id", scanId, "--claim-token", handoffClaimToken,
    "--thread-id", `completed-native-merge-${runtimeLabel}`
  ]);
  runWorkbenchFixture(runtimeLabel, environment, [
    "save-scan-artifact", "--scan-id", scanId, "--claim-token", handoffClaimToken,
    "--artifact-path", "artifacts/deep-scan/checkpoint.json"
  ], { version: 2, passes: [], mergedScanIds: [], aggregate: null, terminalReason: "capped" });

  const client = await startClient(bundle, environment);
  const call = (name, arguments_) => client.callTool({
    name,
    arguments: arguments_,
    _meta: {
      "openai/threadId": ownerThread,
      "codex/sandbox-state-meta": {
        permissionProfile: {
          type: "managed",
          file_system: {
            type: "restricted",
            entries: [{ path: { type: "special", value: { kind: "root" } }, access: "read" }]
          },
          network: "restricted"
        },
        sandboxCwd: pathToFileURL(repoRoot).href
      }
    }
  });
  const rejoin = () => call("start_codex_security_deep_scan", { scanId, handoffClaimToken });
  const expectedResult = {
    scanId,
    manifestPath: path.join(scanDir, "scan-manifest.json"),
    reportPath: path.join(scanDir, "report.md")
  };

  try {
    requireSuccessfulTool(await call("record_codex_security_scan_draft", {
      scanId,
      handoffClaimToken,
      findings: [],
      coverage: {
        completeness: "complete",
        surfaces: [{ label: "Synthetic fixture", disposition: "rejected" }],
        explicitExclusions: [],
        deferred: []
      }
    }), `${runtimeLabel}: write native parent aggregate`);
    const completed = runWorkbenchFixture(runtimeLabel, environment, [
      "complete-scan", "--scan-id", scanId, "--claim-token", handoffClaimToken
    ]);
    assert.equal(completed.scan.progress.status, "complete");
    const originalDraft = await snapshotScanDraft(scanDir);

    for (let repeat = 0; repeat < 2; repeat += 1) {
      assert.deepEqual(
        requireSuccessfulTool(await rejoin(), `${runtimeLabel}: rejoin intact completed native parent`),
        expectedResult
      );
    }
    await rm(expectedResult.reportPath);
    assert.deepEqual(
      requireSuccessfulTool(await rejoin(), `${runtimeLabel}: regenerate missing report before native success`),
      expectedResult
    );
    assert.ok((await readFile(expectedResult.reportPath, "utf8")).length > 0);
    assert.deepEqual(await snapshotScanDraft(scanDir), originalDraft);

    for (const artifact of ["scan-manifest.json", "findings.json", "coverage.json"]) {
      const artifactPath = path.join(scanDir, artifact);
      const original = await readFile(artifactPath);
      for (const change of ["modified", "missing"]) {
        try {
          if (change === "modified") await writeFile(artifactPath, Buffer.concat([original, Buffer.from("\n")]));
          else await rm(artifactPath);
          const rejected = await rejoin();
          assert.equal(rejected.isError, true, `${runtimeLabel}: reject ${change} completed ${artifact}`);
          assert.equal(rejected.structuredContent, undefined);
          assert.equal(runWorkbenchFixture(runtimeLabel, environment, [
            "get-scan", "--scan-id", scanId
          ]).scan.progress.status, "complete");
        } finally {
          await writeFile(artifactPath, original);
        }
      }
    }
    assert.deepEqual(await snapshotScanDraft(scanDir), originalDraft);
    await assert.rejects(readFile(invocationPath), { code: "ENOENT" });
    assert.equal(runWorkbenchFixture(runtimeLabel, environment, ["list-scans"]).scans.length, 1);
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
          http_headers: { Authorization: "Bearer synthetic-private-header-marker" },
          auth: { type: "command", command: "synthetic-private-auth-command-marker" }
        }
      }
    }
  };
}

function assertPrivateRecipeOmitted(result, recipe, label) {
  assert.equal(Object.hasOwn(result.structuredContent, "recipe"), false, `${label}: omit host recipe`);
  const serialized = JSON.stringify(result);
  const provider = recipe.config.model_providers.fixture;
  for (const marker of [provider.http_headers.Authorization, provider.auth.command]) {
    assert.equal(serialized.includes(marker), false, `${label}: omit private provider settings`);
  }
}

function runWorkbenchFixture(runtimeLabel, environment, arguments_, input) {
  return JSON.parse(execFileSync(process.env.PYTHON ?? "python3", [
    path.join(runtimeLabel === "shipped" ? bundledPluginRoot : pluginRoot, "scripts", "workbench_db.py"),
    ...arguments_
  ], {
    env: { ...process.env, ...environment },
    encoding: "utf8",
    ...(input === undefined ? {} : { input: JSON.stringify(input) })
  }));
}

function requireSuccessfulTool(result, label) {
  assert.notEqual(result.isError, true, `${label}: ${result.content?.[0]?.text ?? "tool failed"}`);
  assert.ok(result.structuredContent, `${label}: missing structured result`);
  return result.structuredContent;
}

function requireToolError(result, expected, label) {
  assert.equal(result.isError, true, `${label}: unexpectedly succeeded`);
  assert.match(result.content?.[0]?.text ?? "", expected, label);
}

async function testParentToolList(bundle) {
  const stateRoot = await mkdtemp(path.join(temporaryRoot, "parent-tool-state-"));
  const client = await startClient(bundle, { CODEX_SECURITY_STATE_DIR: stateRoot });
  try {
    assert.deepEqual(
      client.getServerCapabilities()?.experimental?.["codex/sandbox-state-meta"],
      {},
      "The parent MCP must advertise actual parent sandbox-state metadata."
    );
    const tools = (await client.listTools()).tools;
    for (const tool of tools) {
      if (tool._meta?.ui?.visibility?.includes("model") === false) continue;
      const projectedName = `mcp__codex_security__${tool.name}`;
      assert.ok(
        projectedName.length <= 64,
        `Model-visible MCP tool ${projectedName} exceeds Codex's 64-character limit.`
      );
    }
    const names = new Set(tools.map((tool) => tool.name));
    assert.equal(
      names.has("record_codex_security_worker_threat_model"),
      false,
      "The parent MCP must not expose a bound discovery worker's threat-model tool."
    );
    for (const name of [
      "prepare_codex_security_review_items",
      "list_codex_security_review_items",
      "record_codex_security_discovery_candidates",
      "list_codex_security_candidates",
      "record_codex_security_candidate_validations",
      "record_candidate_attack_paths",
      "record_codex_security_scan_draft",
      "get_codex_security_completed_scan",
      "complete_codex_security_scan"
    ]) {
      assert.equal(names.has(name), true, `Missing parent MCP tool ${name}.`);
    }

    for (const name of [
      "get_codex_security_deep_reducer_inputs",
      "record_codex_security_deep_reduction"
    ]) {
      assert.equal(names.has(name), false, `Parent MCP must not expose ${name}.`);
    }

    for (const tool of tools.filter((entry) => names.has(entry.name) && [
      "prepare_codex_security_review_items",
      "list_codex_security_review_items",
      "record_codex_security_discovery_candidates",
      "list_codex_security_candidates",
      "record_codex_security_candidate_validations",
      "record_candidate_attack_paths",
      "record_codex_security_scan_draft",
      "get_codex_security_completed_scan"
    ].includes(entry.name))) {
      assert.equal(
        tool.inputSchema.required?.includes("scanId"),
        true,
        `${tool.name} must require the authoritative workbench scan identity.`
      );
      for (const forbidden of ["path", "artifactPath", "outputPath", "root", "operation"]) {
        assert.equal(
          Object.hasOwn(tool.inputSchema.properties ?? {}, forbidden),
          false,
          `${tool.name} must not accept a model-selected artifact destination.`
        );
      }
    }

    const deepScanTool = tools.find((tool) => tool.name === "start_codex_security_deep_scan");
    assert.ok(deepScanTool, "The parent MCP must expose Deep Scan initialization.");
    assert.equal(deepScanTool.inputSchema.properties.userContext.minLength, undefined);
    assert.equal(deepScanTool.inputSchema.properties.userContext.maxLength, undefined);

    const sandboxState = {
      permissionProfile: {
        type: "managed",
        file_system: {
          type: "restricted",
          entries: [{
            path: { type: "special", value: { kind: "root" } },
            access: "read"
          }]
        },
        network: "restricted"
      },
      sandboxCwd: pathToFileURL(pluginRoot).href
    };
    for (const userContext of ["", "   "]) {
      requireToolError(
        await client.callTool({
          name: deepScanTool.name,
          arguments: { targetPath: pluginRoot, userContext }
        }),
        /owning Codex thread context/,
        "Empty optional Deep Scan context must not fail schema validation."
      );
      requireToolError(
        await client.callTool({
          name: deepScanTool.name,
          arguments: { scanId: randomUUID(), userContext },
          _meta: {
            "openai/threadId": "fixture-thread",
            "codex/sandbox-state-meta": sandboxState
          }
        }),
        /Codex Security scan not found/,
        "Empty optional Deep Scan context must not override persisted scan authority."
      );
    }
    requireToolError(
      await client.callTool({
        name: deepScanTool.name,
        arguments: { scanId: randomUUID(), userContext: "replace persisted context" },
        _meta: { "openai/threadId": "fixture-thread" }
      }),
      /persisted scan is authoritative/,
      "Nonempty user context must not override an existing Deep Scan."
    );
  } finally {
    await client.close();
  }
}

async function bundleEntrypoint(entrypoint, outfile) {
  await build({
    bundle: true,
    banner: { js: "const __codexSecurityModuleUrl = require('node:url').pathToFileURL(__filename).href;" },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": "__codexSecurityModuleUrl"
    },
    entryPoints: [path.join(applicationRoot, entrypoint)],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    logOverride: { "empty-import-meta": "silent" },
    outfile,
    platform: "node",
    target: "node20"
  });
}

async function startClient(bundle, environment) {
  const client = new Client({
    name: "codex-security-compact-artifact-test",
    version: "1.0.0"
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [bundle, "--stdio"],
    cwd: applicationRoot,
    env: {
      ...process.env,
      ...environment
    }
  });
  await client.connect(transport);
  return client;
}
