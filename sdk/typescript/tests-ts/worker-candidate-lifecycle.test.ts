import { importDiscoverySource } from "../../../plugins/codex-security/mcp-app/tests/support/discovery.ts";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile, unlink } from "node:fs/promises";
import { join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import { ScanResult } from "../src/result.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
type Row = Record<string, any>;

async function fixture(diff = false) {
  const directory = await temporaryDirectory("worker-candidate-lifecycle-");
  const load = (name: string) =>
    import(pathToFileURL(join(sourcePlugin, "mcp-app/src", `${name}.ts`)).href);
  const api = {
    context: await load("artifact-context"),
    draft: await load("artifact-scan-draft"),
    reducer: await load("artifact-deep-reducer"),
    validation: await load("deep-scan/artifact-validation"),
    artifacts: await load("deep-scan/artifacts"),
    discovery: await importDiscoverySource(join(directory, "discovery.mjs")),
    validate: await load("artifact-candidate-ledger"),
  };
  const repoRoot = join(directory, "repository"),
    home = join(directory, "home");
  await mkdir(repoRoot);
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(repoRoot, "app.py"), "value = 1\n");
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      [
        "-C",
        repoRoot,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        ...args,
      ],
      { encoding: "utf8" },
    ).trim();
  if (diff) {
    git("init", "-q");
    git("add", "app.py");
    git("commit", "-qm", "Synthetic fixture");
  }
  const workbench = async (args: string[]) =>
    JSON.parse(
      execFileSync(
        process.env["PYTHON"]?.trim() || "python3",
        [join(PLUGIN_ROOT, "scripts/workbench_db.py"), ...args],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CODEX_HOME: home,
            CODEX_SECURITY_STATE_DIR: join(directory, "state"),
          },
        },
      ),
    );
  const { scan } = await workbench([
    diff ? "start-prompt-only-scan" : "start-headless-standard-scan",
    "--thread-id",
    "synthetic-worker-lifecycle",
    "--target-path",
    repoRoot,
    "--scope",
    ".",
    "--scan-root",
    join(directory, "scans"),
    ...(diff
      ? [
          "--mode",
          "diff",
          "--diff-target-kind",
          "commit",
          "--diff-head-revision",
          git("rev-parse", "HEAD"),
        ]
      : []),
  ]);
  const parent = await api.context.createScanArtifactContext(
    scan.scanId,
    workbench,
    { requireRunning: true, pluginRoot: PLUGIN_ROOT },
  );
  const draft = (
    coverage: Row = {},
    findings: Row[] = [],
    complete = true,
  ) => ({
    scanId: scan.scanId,
    complete,
    findings,
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      ...coverage,
    },
  });
  const checkpointBytes = new Map<string, Buffer>();
  const remember = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const file = join(directory, entry.name);
      if (entry.isDirectory()) await remember(file);
      else if (
        file.split(sep).includes("checkpoints") ||
        entry.name === "result.json"
      )
        checkpointBytes.set(file, await readFile(file));
    }
  };
  const unchanged = async () => {
    for (const [file, bytes] of checkpointBytes)
      expect((await readFile(file)).equals(bytes)).toBe(true);
  };
  const json = async (file: string) => JSON.parse(await readFile(file, "utf8"));
  const publish = (input: Row) =>
    api.draft.recordCodexSecurityScanDraftViaWorkbench(
      parent,
      { ...input, handoffClaimToken: parent.handoffClaimToken },
      workbench,
    );
  const complete = async () => {
    await workbench([
      "complete-scan",
      "--scan-id",
      scan.scanId,
      ...(parent.handoffClaimToken
        ? ["--claim-token", parent.handoffClaimToken]
        : []),
    ]);
    const contract = await loadContract(parent.root, {
      pluginRoot: PLUGIN_ROOT,
      expectedScanId: scan.scanId,
    });
    return new ScanResult({
      ...contract,
      scanDir: parent.root,
      threadId: "synthetic-worker-lifecycle",
      turnResult: {},
    });
  };
  return {
    api,
    directory,
    repoRoot,
    scanId: scan.scanId,
    parent,
    draft,
    workbench,
    remember,
    unchanged,
    json,
    publish,
    complete,
  };
}

const finding = () => ({
  ruleId: "synthetic-review",
  title: "Synthetic finding",
  summary: "Original synthetic evidence",
  taxonomy: { category: "synthetic", cwe: [] },
  severity: { level: "low" },
  confidence: { level: "high", rationale: "Synthetic evidence" },
  locations: [{ path: "app.py", startLine: 1 }],
  remediation: "Apply synthetic fix",
  provenance: { source: "local_plugin", candidateId: "candidate-one" },
});

for (const scenario of [
  "confirmation-inherited",
  "confirmation-fresh",
  "confirmation-pending",
  "archive-missing",
  "archive-valid",
  "archive-missing-no-finding",
  "archive-confirmed",
  "archive-confirmed-repeat",
  "archive-confirmed-no-prior-repeat",
  "archive-confirmed-rearchived-repeat",
  "archive-missing-repeat",
  "archive-confirmed-reopened-repeat",
  "archive-rejected-repeat",
]) {
  test(`public worker state reaches reducer and SDK: ${scenario}`, async () => {
    const f = await fixture();
    const workerRoot = join(
      f.parent.root,
      "artifacts/deep_discovery/workers/worker-one/output",
    );
    await mkdir(workerRoot, { recursive: true });
    const context = {
      root: workerRoot,
      repoRoot: f.repoRoot,
      scanId: f.scanId,
      layout: "worker",
      scope: ".",
    };
    const write = (input: Row) =>
      f.api.draft.recordCodexSecurityWorkerScanDraft(context, input);
    if (scenario.startsWith("confirmation")) {
      await write(f.draft({ completeness: "complete" }, [finding()]));
      const pending = {
        id: "reopened-gap",
        candidateId: "candidate-one",
        reason: "Additional validation required.",
      };
      await write(f.draft({ deferred: [pending] }));
      const saved = (await f.json(join(workerRoot, "result.json"))).findings[0];
      expect(saved.provenance.candidateReopened).toBe(true);
      if (scenario === "confirmation-fresh")
        delete saved.provenance.candidateReopened;
      saved.summary = "Confirmed with additional synthetic evidence.";
      await write(
        f.draft(
          {
            completeness:
              scenario === "confirmation-pending" ? "partial" : "complete",
            deferred: scenario === "confirmation-pending" ? [pending] : [],
          },
          [saved],
        ),
      );
    } else {
      if (
        scenario !== "archive-missing-no-finding" &&
        !scenario.includes("no-prior")
      )
        await write(f.draft({}, [finding()], false));
      await mkdir(join(workerRoot, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(workerRoot, "artifacts/proof/decision.txt"),
        "Synthetic decision evidence.\n",
      );
      await write(
        f.draft(
          {
            surfaces: [
              {
                id: "decision",
                candidateId: "candidate-one",
                label: "Reviewed candidate",
                disposition: "rejected",
                receiptRefs: ["artifacts/proof/decision.txt"],
              },
            ],
          },
          [],
          false,
        ),
      );
      const archive = join(workerRoot, "../attempts/attempt-01");
      await f.api.artifacts.archiveDirectory(workerRoot, archive);
      if (scenario !== "archive-valid")
        await unlink(join(archive, "artifacts/proof/decision.txt"));
      await f.remember(archive);
      await write(
        f.draft(
          { completeness: "complete" },
          scenario.startsWith("archive-confirmed")
            ? [
                {
                  ...finding(),
                  summary: "Newly confirmed after resumed review.",
                },
              ]
            : [],
        ),
      );
    }
    if (scenario === "archive-confirmed-reopened-repeat")
      await write(
        f.draft({
          deferred: [
            {
              id: "new-gap",
              candidateId: "candidate-one",
              reason: "A newer explicit proof gap.",
            },
          ],
        }),
      );
    if (scenario === "archive-rejected-repeat") {
      await mkdir(join(workerRoot, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(workerRoot, "artifacts/proof/replacement.txt"),
        "New reviewed decision.\n",
      );
      await write(
        f.draft({
          completeness: "complete",
          surfaces: [
            {
              id: "new-decision",
              candidateId: "candidate-one",
              label: "New reviewed decision",
              disposition: "rejected",
              receiptRefs: ["artifacts/proof/replacement.txt"],
            },
          ],
        }),
      );
    }
    if (scenario === "archive-confirmed-rearchived-repeat") {
      const archive = join(workerRoot, "../attempts/attempt-02");
      await f.api.artifacts.archiveDirectory(workerRoot, archive);
      await f.remember(archive);
    }
    if (scenario.endsWith("repeat")) {
      await write(f.draft({ completeness: "complete" }));
      await write(f.draft({ completeness: "complete" }));
    }
    await f.remember(workerRoot);
    const validated = await f.api.validation.validateDiscoveryArtifacts(
      { workersRoot: workerRoot },
      join(workerRoot, "result.json"),
      f.scanId,
    );
    expect(validated).toBeDefined();
    const reducerRoot = join(
      f.parent.root,
      "artifacts/deep_discovery/dedup/reducer/output",
    );
    await mkdir(reducerRoot, { recursive: true });
    const contextReducer = {
      root: reducerRoot,
      repoRoot: f.repoRoot,
      scanId: f.scanId,
      layout: "reducer",
      deepReducer: {
        scanRoot: f.parent.root,
        claimedWorkers: [
          { id: "worker-one", resultPath: join(workerRoot, "result.json") },
        ],
      },
    };
    const input =
      await f.api.reducer.getCodexSecurityDeepReducerInputs(contextReducer);
    const expectedPending =
      scenario === "confirmation-pending" ||
      scenario === "archive-missing" ||
      scenario === "archive-missing-repeat" ||
      scenario === "archive-confirmed-reopened-repeat" ||
      scenario === "archive-missing-no-finding";
    const expectedFindings =
      scenario.startsWith("confirmation") ||
      scenario.startsWith("archive-confirmed")
        ? 1
        : 0;
    for (let attempt = 0; attempt < 2; attempt++) {
      await f.api.reducer.recordCodexSecurityDeepReduction(contextReducer, {
        scanId: f.scanId,
        findings: input.discoveries[0].result.findings,
      });
      const result = await f.json(join(reducerRoot, "result.json"));
      expect(result.findings.length).toBe(expectedFindings);
      expect((result.unresolvedCandidates ?? []).length).toBe(
        Number(expectedPending),
      );
    }
    const result = await f.json(join(reducerRoot, "result.json"));
    await f.publish(f.api.validation.deepReductionScanDraft(result));
    await f.workbench([
      "prepare-scan-completion",
      "--scan-id",
      f.scanId,
      "--claim-token",
      f.parent.handoffClaimToken,
    ]);
    const sdk = await f.complete();
    expect(sdk.findings.findings.length).toBe(expectedFindings);
    expect(sdk.unresolvedCandidates.length).toBe(Number(expectedPending));
    if (scenario.startsWith("archive-confirmed"))
      expect(sdk.findings.findings[0]!.summary).toBe(
        "Newly confirmed after resumed review.",
      );
    if (scenario === "archive-missing")
      expect(JSON.stringify(sdk.unresolvedCandidates)).toContain(
        "Original synthetic evidence",
      );
    if (scenario === "confirmation-inherited")
      expect(
        sdk.findings.findings[0]!.provenance["candidateReopened"],
      ).not.toBe(true);
    await f.unchanged();
  });
}

for (const decision of ["pending", "suppressed", "not_applicable"]) {
  for (const resolution of ["none", "receipt", "validation"]) {
    const replacement = resolution === "receipt";
    test(`public draft after prepared receipt recovery retains current decision: ${decision}, resolution=${resolution}`, async () => {
      const f = await fixture(true);
      const discovery = join(f.parent.root, "artifacts/02_discovery");
      await mkdir(discovery, { recursive: true });
      await writeFile(join(discovery, "in_scope_files.txt"), "app.py\n");
      await f.api.discovery.recordCodexSecurityDiscoveryCandidates(
        {
          candidates: [
            {
              cwe_ids: [],
              locations: [
                {
                  path: "app.py",
                  start_line: 1,
                  end_line: 1,
                  role: "evidence",
                },
              ],
              summary: "Synthetic review candidate",
              evidence: "Synthetic evidence",
            },
          ],
        },
        f.parent,
      );
      const candidateId = (
        await f.api.discovery.listCodexSecurityCandidates({}, f.parent)
      ).rows[0].candidate_id;
      await f.publish(
        f.draft(
          {
            deferred: [
              {
                id: "authored-gap",
                candidateId,
                reason: "Original authored proof gap.",
              },
            ],
          },
          [],
          false,
        ),
      );
      if (decision !== "pending")
        await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
          validations: [
            {
              candidateId,
              validation: {
                disposition: decision,
                method: "Static inspection",
                confidence: "high",
                confidence_rationale: "Synthetic evidence",
                rubric: "Synthetic criterion",
                evidence: "Candidate dismissed.",
                counterevidence_or_proof_gap:
                  "Independent terminal validation.",
                remaining_uncertainty: "",
              },
            },
          ],
        });
      const ref = "artifacts/proof/decision.txt";
      await mkdir(join(f.parent.root, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(f.parent.root, ref),
        "Synthetic decision evidence.\n",
      );
      const surface = {
        id: "authored-decision",
        candidateId,
        label: "Authored candidate review",
        disposition: "rejected",
        notes: "Authored decision with receipt.",
        receiptRefs: [ref],
      };
      await f.publish(
        f.draft({ completeness: "complete", surfaces: [surface] }),
      );
      await unlink(join(f.parent.root, ref));
      await f.remember(join(f.parent.root, "checkpoints"));
      await f.workbench(["prepare-scan-completion", "--scan-id", f.scanId]);
      expect(
        (await f.json(join(f.parent.root, "coverage.json"))).deferred.length,
      ).toBeGreaterThan(0);
      if (resolution === "validation")
        await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
          validations: [
            {
              candidateId,
              validation: {
                disposition: decision === "pending" ? "suppressed" : decision,
                method: "Static inspection",
                confidence: "high",
                confidence_rationale: "New synthetic evidence",
                rubric: "Synthetic criterion",
                evidence: "New independent validation dismissed the candidate.",
                counterevidence_or_proof_gap: "Newly verified proof.",
                remaining_uncertainty: "",
              },
            },
          ],
        });
      const replaced = "artifacts/proof/replacement.txt";
      if (replacement)
        await writeFile(
          join(f.parent.root, replaced),
          "New validation evidence.\n",
        );
      await f.publish(
        f.draft({
          completeness: "complete",
          surfaces: replacement
            ? [{ ...surface, receiptRefs: [replaced] }]
            : [],
        }),
      );
      const sdk = await f.complete();
      expect(sdk.unresolvedCandidates.length).toBe(
        Number(resolution === "none"),
      );
      expect(
        sdk.coverage.surfaces.some(
          (row) => row.disposition === "needs_follow_up",
        ),
      ).toBe(resolution === "none");
      await f.unchanged();
    });
  }
}

for (const candidateId of ["", "   ", "candidate-one"]) {
  for (const missing of [false, true]) {
    test(`archived worker surface metadata remains readable: ${JSON.stringify(candidateId)}, missing=${missing}`, async () => {
      const f = await fixture();
      const workerRoot = join(
        f.parent.root,
        "artifacts/deep_discovery/workers/worker-one/output",
      );
      await mkdir(workerRoot, { recursive: true });
      const context = {
        root: workerRoot,
        repoRoot: f.repoRoot,
        scanId: f.scanId,
        layout: "worker",
        scope: ".",
      };
      const write = (input: Row) =>
        f.api.draft.recordCodexSecurityWorkerScanDraft(context, input);
      await mkdir(join(workerRoot, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(workerRoot, "artifacts/proof/decision.txt"),
        "Synthetic decision evidence.\n",
      );
      await write(
        f.draft(
          {
            surfaces: [
              {
                id: "decision",
                candidateId,
                label: "Reviewed surface",
                disposition: "rejected",
                receiptRefs: ["artifacts/proof/decision.txt"],
              },
            ],
          },
          [],
          false,
        ),
      );
      const archive = join(workerRoot, "../attempts/attempt-01");
      await f.api.artifacts.archiveDirectory(workerRoot, archive);
      if (missing) await unlink(join(archive, "artifacts/proof/decision.txt"));
      await f.remember(archive);
      for (let attempt = 0; attempt < 2; attempt++) {
        await write(f.draft({ completeness: "complete" }));
        const output = await f.json(join(workerRoot, "result.json"));
        expect(
          output.coverage.surfaces.some(
            (surface: Row) => surface["candidateId"] === candidateId,
          ),
        ).toBe(true);
        expect(
          output.coverage.surfaces.some(
            (surface: Row) => surface["disposition"] === "needs_follow_up",
          ),
        ).toBe(missing);
        await f.api.validation.validateDiscoveryArtifacts(
          { workersRoot: workerRoot },
          join(workerRoot, "result.json"),
          f.scanId,
        );
        const reducerRoot = join(
          f.parent.root,
          "artifacts/deep_discovery/dedup/reducer/output",
        );
        await mkdir(reducerRoot, { recursive: true });
        const inputs = await f.api.reducer.getCodexSecurityDeepReducerInputs({
          root: reducerRoot,
          repoRoot: f.repoRoot,
          scanId: f.scanId,
          layout: "reducer",
          deepReducer: {
            scanRoot: f.parent.root,
            claimedWorkers: [
              { id: "worker-one", resultPath: join(workerRoot, "result.json") },
            ],
          },
        });
        expect(inputs.discoveries).toHaveLength(1);
      }
      await f.unchanged();
    });
  }
}

for (const decision of ["suppressed", "not_applicable"]) {
  for (const [termination, resolution] of [
    ["fail-scan", "none"],
    ["cancel-scan", "none"],
    ["complete-scan", "none"],
    ["fail-scan", "receipt"],
    ["fail-scan", "validation"],
  ]) {
    test(`explicit Diff reopening survives ${termination}: ${decision}, resolution=${resolution}`, async () => {
      const f = await fixture(true);
      const discovery = join(f.parent.root, "artifacts/02_discovery");
      await mkdir(discovery, { recursive: true });
      await writeFile(join(discovery, "in_scope_files.txt"), "app.py\n");
      await f.api.discovery.recordCodexSecurityDiscoveryCandidates(
        {
          candidates: [
            {
              cwe_ids: [],
              locations: [
                {
                  path: "app.py",
                  start_line: 1,
                  end_line: 1,
                  role: "evidence",
                },
              ],
              summary: "Synthetic review candidate",
              evidence: "Synthetic evidence",
            },
          ],
        },
        f.parent,
      );
      const candidateId = (
        await f.api.discovery.listCodexSecurityCandidates({}, f.parent)
      ).rows[0].candidate_id;
      await f.publish(
        f.draft(
          {
            deferred: [
              {
                id: "original-gap",
                candidateId,
                reason: "Original review gap.",
              },
            ],
          },
          [],
          false,
        ),
      );
      const validation = {
        disposition: decision,
        method: "Static inspection",
        confidence: "high",
        confidence_rationale: "Synthetic evidence",
        rubric: "Synthetic criterion",
        evidence: "Candidate dismissed.",
        counterevidence_or_proof_gap: "Independent terminal validation.",
        remaining_uncertainty: "",
      };
      await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
        validations: [{ candidateId, validation }],
      });
      const ref = "artifacts/proof/decision.txt";
      await mkdir(join(f.parent.root, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(f.parent.root, ref),
        "Synthetic terminal evidence.\n",
      );
      const surface = {
        id: "decision",
        candidateId,
        label: "Reviewed candidate",
        disposition: decision === "suppressed" ? "rejected" : "not_applicable",
        receiptRefs: [ref],
      };
      await f.publish(
        f.draft({ completeness: "complete", surfaces: [surface] }),
      );
      const candidate = JSON.parse(
        (await readFile(join(discovery, "candidate_ledger.jsonl"), "utf8"))
          .trim()
          .split("\n")[0]!,
      );
      await f.publish(
        f.draft({
          deferred: [
            {
              id: "explicit-proof-gap",
              candidateId,
              candidate,
              reason: "Additional evidence is needed after earlier rejection.",
            },
          ],
        }),
      );
      expect(
        (await f.json(join(f.parent.root, "coverage.json"))).deferred.some(
          (row: Row) => row["candidateId"] === candidateId,
        ),
      ).toBe(true);
      if (resolution === "receipt")
        await f.publish(
          f.draft({
            completeness: "complete",
            surfaces: [
              { ...surface, notes: "New independent authored decision." },
            ],
          }),
        );
      if (resolution === "validation") {
        await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
          validations: [
            {
              candidateId,
              validation: {
                ...validation,
                evidence: "New independent terminal evidence.",
              },
            },
          ],
        });
      }
      await f.remember(join(f.parent.root, "checkpoints"));
      if (termination === "complete-scan") {
        await f.workbench(["prepare-scan-completion", "--scan-id", f.scanId]);
        await f.complete();
      } else {
        await f.workbench([
          termination!,
          "--scan-id",
          f.scanId,
          ...(termination === "fail-scan"
            ? ["--message", "Synthetic interruption."]
            : []),
        ]);
        await f.workbench(["preserve-scan-results", "--scan-id", f.scanId]);
        await f.workbench(["preserve-scan-results", "--scan-id", f.scanId]);
      }
      const contract = await loadContract(f.parent.root, {
        pluginRoot: PLUGIN_ROOT,
        expectedScanId: f.scanId,
      });
      const sdk = new ScanResult({
        ...contract,
        scanDir: f.parent.root,
        threadId: "synthetic-worker-lifecycle",
        turnResult: {},
      });
      expect(sdk.unresolvedCandidates.length).toBe(
        Number(resolution === "none"),
      );
      if (resolution === "none")
        expect(JSON.stringify(sdk.unresolvedCandidates)).toContain(
          "Additional evidence is needed after earlier rejection.",
        );
      await f.unchanged();
    });
  }
}

for (const publication of ["writer", "file-authored"]) {
  for (const reference of [
    "shared",
    "cross-owner",
    "other-owner",
    "unlinked",
  ]) {
    test(`stopped Diff retains shared terminal evidence: ${publication}, ${reference}`, async () => {
      const f = await fixture(true);
      const inventory = await import(
        pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-inventory.ts"))
          .href
      );
      await inventory.prepareCodexSecurityReviewItems(f.parent);
      await f.api.discovery.recordCodexSecurityDiscoveryCandidates(
        {
          candidates: [
            {
              cwe_ids: [],
              locations: [
                {
                  path: "app.py",
                  start_line: 1,
                  end_line: 1,
                  role: "evidence",
                },
              ],
              summary: "Synthetic candidate requiring review",
              evidence: "Synthetic shared source evidence",
            },
          ],
        },
        f.parent,
      );
      const candidateId = (
        await f.api.discovery.listCodexSecurityCandidates({}, f.parent)
      ).rows[0].candidate_id;
      await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
        validations: [
          {
            candidateId,
            validation: {
              disposition: "suppressed",
              method: "Source review",
              confidence: "high",
              confidence_rationale: "Synthetic trace",
              rubric: "Synthetic review",
              evidence: "Synthetic evidence",
              counterevidence_or_proof_gap: "Saved decision evidence",
              remaining_uncertainty: "",
            },
          },
        ],
      });
      await f.publish(
        f.draft(
          {},
          [
            {
              ...finding(),
              provenance: { ...finding().provenance, candidateId },
            },
          ],
          false,
        ),
      );
      const candidate = (
        await f.api.discovery.listCodexSecurityCandidates({}, f.parent)
      ).rows[0];
      const surface = {
        id: "shared",
        candidateId,
        label: candidate.summary,
        disposition: "rejected",
        notes: candidate.validation.counterevidence_or_proof_gap,
        receiptRefs: [],
        candidate,
      };
      const pending = {
        id: "pending-b",
        candidateId: "candidate-b",
        reason: "Independent shared review",
        surfaceIds: reference === "unlinked" ? [] : ["shared"],
        ...(["cross-owner", "other-owner"].includes(reference)
          ? { sourceWorkerId: "other-worker" }
          : {}),
      };
      const surfaces = [
        surface,
        ...(reference === "other-owner"
          ? [
              {
                ...surface,
                candidateId: "other-candidate",
                sourceWorkerId: "other-worker",
                notes: "Other owner's retained evidence",
              },
            ]
          : []),
      ];
      const next = f.draft({ surfaces, deferred: [pending] }, [], false);
      if (publication === "writer") await f.publish(next);
      else {
        const coverage = await f.json(join(f.parent.root, "coverage.json"));
        const findings = await f.json(join(f.parent.root, "findings.json"));
        Object.assign(coverage, next.coverage);
        findings.findings = [];
        await writeFile(
          join(f.parent.root, "coverage.json"),
          JSON.stringify(coverage),
        );
        await writeFile(
          join(f.parent.root, "findings.json"),
          JSON.stringify(findings),
        );
      }
      await f.remember(f.parent.root);
      const ledger = join(
        f.parent.root,
        "artifacts/02_discovery/candidate_ledger.jsonl",
      );
      const originalLedger = await readFile(ledger);
      await f.workbench([
        "fail-scan",
        "--scan-id",
        f.scanId,
        "--message",
        "Synthetic interrupted review",
      ]);
      for (let attempt = 0; attempt < 2; attempt++) {
        const scan = (await f.workbench(["get-scan", "--scan-id", f.scanId]))
          .scan;
        const contract = await loadContract(f.parent.root, {
          pluginRoot: PLUGIN_ROOT,
          expectedScanId: f.scanId,
        });
        const result = new ScanResult({
          ...contract,
          scanDir: f.parent.root,
          threadId: "synthetic-shared-review",
          turnResult: {},
        });
        expect(result.unresolvedCandidateCount).toBe(1);
        expect(scan.progress.candidates.unresolved).toBe(1);
        const retained = (result.coverage.deferred as Row[]).find(
          (row) => row["candidateId"] === "candidate-b",
        )!;
        expect(retained["reason"]).toBe(pending.reason);
        expect(retained["sourceWorkerId"]).toEqual(pending.sourceWorkerId);
        for (const id of retained["surfaceIds"]) {
          const linked = (result.coverage.surfaces as Row[]).find(
            (row) => row["id"] === id,
          )!;
          expect(linked).toBeDefined();
          expect(linked["notes"]).toBe(
            reference === "other-owner"
              ? "Other owner's retained evidence"
              : surface.notes,
          );
          expect(linked["candidate"]).toEqual(candidate);
          if (reference === "other-owner")
            expect(linked["sourceWorkerId"]).toBe("other-worker");
        }
        if (publication === "file-authored") {
          expect(result.findings.findings.length).toBe(1);
          const first = (result.coverage.surfaces as Row[]).find(
            (row) => row["candidateId"] === candidateId,
          );
          expect(Boolean(first)).toBe(
            reference === "shared" || reference === "cross-owner",
          );
          if (first) expect(first["disposition"]).toBe("reported");
        }
        await f.unchanged();
        expect((await readFile(ledger)).equals(originalLedger)).toBe(true);
        if (attempt === 0)
          await f.workbench(["recover-scan-results", "--scan-id", f.scanId]);
      }
    });
  }
}

for (const mode of ["standard", "diff"] as const) {
  for (const submission of [
    "terminal",
    "implicit-terminal",
    "incomplete",
    "matching-gap",
    "matching-owner-gap",
    "other-owner-gap",
    "history-only",
  ]) {
    test(`parent reconfirmation preserves current intent: ${mode}, ${submission}`, async () => {
      const f = await fixture(mode === "diff");
      const owner = submission.includes("owner") ? "worker-a" : undefined;
      const initial = {
        ...finding(),
        provenance: {
          ...finding().provenance,
          ...(owner === undefined ? {} : { sourceWorkerId: owner }),
        },
      };
      const pending = {
        id: "reopened-proof-gap",
        candidateId: initial.provenance.candidateId,
        reason: "Synthetic reachability needs another check.",
        ...(owner === undefined ? {} : { sourceWorkerId: owner }),
      };
      await f.publish(f.draft({ completeness: "complete" }, [initial]));
      await f.publish(f.draft({ deferred: [pending] }));
      const reopened = (await f.json(join(f.parent.root, "findings.json")))
        .findings[0];
      expect(reopened.provenance.candidateReopened).toBe(true);
      await f.remember(f.parent.root);
      const confirmed = structuredClone(reopened);
      confirmed.summary = "New synthetic evidence confirms reachability.";
      const matchingGap =
        submission === "matching-gap" || submission === "matching-owner-gap";
      const currentGap =
        submission === "other-owner-gap"
          ? { ...pending, id: "other-owner-gap", sourceWorkerId: "worker-b" }
          : pending;
      const explicitPending = matchingGap || submission === "other-owner-gap";
      const update: Row = f.draft(
        {
          completeness: explicitPending ? "partial" : "complete",
          deferred: explicitPending ? [currentGap] : [],
        },
        submission === "history-only" ? [] : [confirmed],
        submission !== "incomplete",
      );
      if (submission === "implicit-terminal") delete update["complete"];
      const stillReopened =
        matchingGap ||
        submission === "incomplete" ||
        submission === "history-only";
      const expectedPending = stillReopened || submission === "other-owner-gap";
      for (let repeat = 0; repeat < 2; repeat++) {
        await f.publish(update);
        const coverage = await f.json(join(f.parent.root, "coverage.json"));
        const current = (await f.json(join(f.parent.root, "findings.json")))
          .findings;
        expect(current).toHaveLength(1);
        if (submission === "incomplete") {
          const checkpoints = await Promise.all(
            (await readdir(join(f.parent.root, "checkpoints"))).map((name) =>
              f.json(join(f.parent.root, "checkpoints", name)),
            ),
          );
          expect(checkpoints).toContainEqual(
            expect.objectContaining({
              complete: false,
              findings: [confirmed],
            }),
          );
          expect(current[0].summary).toBe(reopened.summary);
        } else if (submission !== "history-only") {
          expect(current[0].summary).toBe(confirmed.summary);
        }
        expect(current[0].provenance.candidateReopened === true).toBe(
          stillReopened,
        );
        expect(coverage.deferred).toEqual(expectedPending ? [currentGap] : []);
        expect(coverage.completeness).toBe(
          expectedPending ? "partial" : "complete",
        );
        expect(confirmed.provenance.candidateReopened).toBe(true);
        await f.unchanged();
      }
      let result: ScanResult;
      if (submission === "incomplete") {
        await expect(f.complete()).rejects.toThrow(/incomplete/);
        await f.workbench([
          "fail-scan",
          "--scan-id",
          f.scanId,
          "--message",
          "Synthetic interruption of an incomplete review.",
          ...(f.parent.handoffClaimToken
            ? ["--claim-token", f.parent.handoffClaimToken]
            : []),
        ]);
        const contract = await loadContract(f.parent.root, {
          pluginRoot: PLUGIN_ROOT,
          expectedScanId: f.scanId,
        });
        result = new ScanResult({
          ...contract,
          scanDir: f.parent.root,
          threadId: "synthetic-reconfirmation",
          turnResult: {},
        });
      } else {
        result = await f.complete();
      }
      const scan = (await f.workbench(["get-scan", "--scan-id", f.scanId]))
        .scan;
      expect(result.unresolvedCandidateCount).toBe(Number(expectedPending));
      expect(scan.progress.candidates.unresolved).toBe(Number(expectedPending));
      expect(result.coverage.completeness).toBe(
        expectedPending ? "partial" : "complete",
      );
      if (submission === "incomplete") {
        expect(result.unresolvedCandidates[0]).toMatchObject({
          candidateId: pending.candidateId,
          reason: pending.reason,
        });
      } else {
        expect(
          result.findings.findings[0]!.provenance["candidateReopened"] === true,
        ).toBe(stillReopened);
        if (submission !== "history-only")
          expect(result.findings.findings[0]!.summary).toBe(confirmed.summary);
      }
      await f.unchanged();
    });
  }
}
