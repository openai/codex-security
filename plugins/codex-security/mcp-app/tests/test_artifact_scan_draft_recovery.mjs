import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { loadSourceModule, privateDirectory } from "./helpers/source.mjs";

const { recordCodexSecurityScanDraftViaWorkbench } = await loadSourceModule(
  new URL("../src/artifact-scan-draft.ts", import.meta.url),
);
const { createScanArtifactContext } = await loadSourceModule(
  new URL("../src/artifact-context.ts", import.meta.url),
);
const { semanticFinding, semanticCoverage } = await loadSourceModule(
  new URL(
    "../../../../sdk/typescript/tests-ts/helpers/semantic-scan.ts",
    import.meta.url,
  ),
);
const exec = promisify(execFile);
const script = fileURLToPath(
  new URL("../../scripts/workbench_db.py", import.meta.url),
);

for (const scenario of [
  "interrupted then new draft",
  "interrupted then empty draft",
  "retry",
]) {
  test(
    `concurrent draft identities survive ${scenario} and completion`,
    { timeout: 30000 },
    async (t) => {
      const root = await privateDirectory("codex-security-draft-recovery-");
      t.after(() => rm(root, { recursive: true, force: true }));
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      await mkdir(repository);
      await mkdir(scanDir, { mode: 0o700 });
      for (const path of ["earlier.js", "later.js", "new.js", "shared.js"])
        await writeFile(join(repository, path), "export const value = 1;\n");
      const workbench = async (args, input) => {
        const execution = exec(
          process.env.PYTHON || "python3",
          [script, ...args],
          {
            env: {
              ...process.env,
              CODEX_SECURITY_STATE_DIR: join(root, "state"),
            },
          },
        );
        execution.child.stdin.on("error", () => {});
        execution.child.stdin.end(input);
        return JSON.parse((await execution).stdout);
      };
      const { scanId } = await workbench(
        [
          "register-cli-scan",
          "--repository",
          repository,
          "--scan-dir",
          scanDir,
          "--registration-json-stdin",
        ],
        JSON.stringify({
          recipe: {
            repository,
            target: { kind: "repository", paths: [] },
            mode: "standard",
            config: {},
          },
        }),
      );
      const context = await createScanArtifactContext(scanId, workbench);
      const input = (path) => ({
        scanId,
        complete: false,
        findings: path
          ? [
              semanticFinding({
                locations: [{ path, startLine: 1 }],
                provenance: { source: "local_plugin", candidateId: path },
              }),
            ]
          : [],
        coverage: semanticCoverage({
          completeness: "partial",
          surfaces: path
            ? [
                {
                  label: "Output review",
                  disposition: "needs_follow_up",
                  paths: [path],
                },
              ]
            : [],
          deferred: path
            ? [
                {
                  reason: "Review shared output",
                  paths: ["shared.js"],
                  candidate: { summary: path },
                },
              ]
            : [],
        }),
      });
      const save = (draft, publish = workbench, signal) =>
        recordCodexSecurityScanDraftViaWorkbench(
          context,
          draft,
          publish,
          signal,
        );
      await save(input());
      let prepared, release;
      const ready = new Promise((resolve) => {
        prepared = resolve;
      });
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      const abort = new AbortController();
      const submitted = [];
      const laterInput = input("later.js");
      const later = save(
        laterInput,
        async (args, encoded) => {
          const checkpoint = JSON.parse(
            await readFile(args[args.indexOf("--checkpoint-path") + 1], "utf8"),
          );
          submitted.push({
            finding: checkpoint.findings.find(
              (row) => row.locations[0].path === "later.js",
            ).identity,
            surface: checkpoint.coverage.surfaces.find(
              (row) => row.paths[0] === "later.js",
            ).id,
            deferred: checkpoint.coverage.deferred.find(
              (row) => row.candidate.summary === "later.js",
            ).id,
          });
          if (submitted.length === 1) {
            prepared();
            await gate;
          }
          try {
            return await workbench(args, encoded);
          } catch (error) {
            assert.match(String(error), /scan_draft_conflict/);
            if (scenario !== "retry")
              abort.abort(new Error("Synthetic interruption"));
            throw error;
          }
        },
        abort.signal,
      ).then(
        () => assert.equal(scenario, "retry"),
        (error) => {
          assert.notEqual(scenario, "retry");
          assert.equal(error.message, "Synthetic interruption");
        },
      );
      await ready;
      await save(input("earlier.js"));
      release();
      await later;
      assert.equal(laterInput.findings[0].identity, undefined);
      assert.equal(submitted.length, scenario === "retry" ? 2 : 1);
      if (scenario === "retry") assert.deepEqual(submitted[1], submitted[0]);
      await save({
        ...input(
          scenario === "interrupted then new draft" ? "new.js" : undefined,
        ),
        complete: true,
      });
      const snapshotPath = join(scanDir, "artifacts/scan-draft.json");
      const saved = JSON.parse(await readFile(snapshotPath, "utf8"));
      const expected =
        scenario === "interrupted then new draft"
          ? ["earlier.js", "later.js", "new.js"]
          : ["earlier.js", "later.js"];
      assert.deepEqual(
        saved.findings.findings.map((row) => row.locations[0].path).sort(),
        expected,
      );
      assert.deepEqual(
        saved.coverage.surfaces.map((row) => row.paths[0]).sort(),
        expected,
      );
      assert.deepEqual(
        saved.coverage.deferred.map((row) => row.candidate.summary).sort(),
        expected,
      );
      assert.deepEqual(
        saved.findings.findings.map((row) => row.provenance.candidateId).sort(),
        expected,
      );
      const revision = saved.findings.findings[0];
      const identity = structuredClone(revision.identity);
      revision.remediation = "Revised repair.";
      await save({
        scanId,
        findings: [revision],
        coverage: semanticCoverage({
          completeness: saved.coverage.completeness,
          surfaces: saved.coverage.surfaces,
          explicitExclusions: saved.coverage.explicitExclusions,
          deferred: saved.coverage.deferred,
        }),
      });
      const revised = JSON.parse(await readFile(snapshotPath, "utf8"));
      assert.equal(revised.findings.findings.length, expected.length);
      assert.deepEqual(revised.findings.findings[0].identity, identity);
      assert.equal(revised.findings.findings[0].remediation, "Revised repair.");
      assert.deepEqual(revised.coverage, saved.coverage);
      await workbench(["prepare-scan-completion", "--scan-id", scanId]);
      const findings = JSON.parse(
        await readFile(join(scanDir, "findings.json"), "utf8"),
      ).findings;
      assert.deepEqual(
        findings.map((row) => row.locations[0].path).sort(),
        expected,
      );
      assert.ok(
        JSON.parse(await readFile(join(scanDir, "scan-manifest.json"), "utf8"))
          .scan.sealedAt,
      );
    },
  );
}

async function publicationFixture(t) {
  const root = await privateDirectory("codex-security-publication-recovery-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(join(repository, "src"), { recursive: true });
  await writeFile(
    join(repository, "src/render.js"),
    "export const value = 1;\n",
  );
  await mkdir(scanDir, { mode: 0o700 });
  const workbench = async (args, input, interruptedAt) => {
    const injected = [
      "import runpy, sys",
      "from pathlib import Path",
      "script, interrupted = sys.argv[1:3]",
      "sys.path.insert(0, str(Path(script).parent))",
      "import workbench_saved_results as saved",
      "original = saved.write_scan_local_bytes",
      "def write(root, relative, contents, **kwargs):",
      "    if relative == interrupted: raise OSError('Synthetic publication interruption')",
      "    return original(root, relative, contents, **kwargs)",
      "saved.write_scan_local_bytes = write",
      "sys.argv = [script, *sys.argv[3:]]",
      "runpy.run_path(script, run_name='__main__')",
    ].join("\n");
    const execution = exec(
      process.env.PYTHON || "python3",
      interruptedAt
        ? ["-c", injected, script, interruptedAt, ...args]
        : [script, ...args],
      {
        env: { ...process.env, CODEX_SECURITY_STATE_DIR: join(root, "state") },
      },
    );
    execution.child.stdin.on("error", () => {});
    execution.child.stdin.end(input);
    return JSON.parse((await execution).stdout);
  };
  const { scanId } = await workbench(
    [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--registration-json-stdin",
    ],
    JSON.stringify({
      recipe: {
        repository,
        target: { kind: "repository", paths: [] },
        mode: "standard",
        config: {},
      },
    }),
  );
  const context = await createScanArtifactContext(scanId, workbench);
  const save = (input, interruptedAt) =>
    recordCodexSecurityScanDraftViaWorkbench(
      context,
      { scanId, findings: [], coverage: semanticCoverage(), ...input },
      (args, stdin) => workbench(args, stdin, interruptedAt),
    );
  const read = async (name) =>
    JSON.parse(await readFile(join(scanDir, name), "utf8"));
  const finding = (id) =>
    semanticFinding({
      identity: { anchor: id },
      provenance: { source: "local_plugin", candidateId: id },
    });
  const rejection = {
    id: "reviewed-surface",
    label: "Reviewed candidate",
    disposition: "rejected",
    candidateId: "candidate",
    rationale: "Synthetic candidate rejected.",
  };
  return {
    root,
    scanDir,
    scanId,
    context,
    save,
    read,
    finding,
    rejection,
    workbench,
  };
}

for (const timestamp of ["unchanged", "changed", "omitted"]) {
  test(`MCP drafts preserve later canonical findings and coverage with ${timestamp} timestamp`, async (t) => {
    const f = await publicationFixture(t);
    await f.save({ complete: false, findings: [f.finding("initial")] });
    const manifest = await f.read("scan-manifest.json");
    const findings = await f.read("findings.json");
    const coverage = await f.read("coverage.json");
    findings.findings.push(f.finding("later-canonical"));
    coverage.completeness = "partial";
    coverage.deferred.push({
      id: "later-work",
      reason: "Retain later observed work.",
    });
    if (timestamp === "changed")
      manifest.scan.completedAt = "2030-01-01T00:00:00Z";
    if (timestamp === "omitted") delete manifest.scan.completedAt;
    for (const [name, document] of [
      ["scan-manifest.json", manifest],
      ["findings.json", findings],
      ["coverage.json", coverage],
    ])
      await writeFile(join(f.scanDir, name), JSON.stringify(document));
    await f.save({ complete: false });
    assert.deepEqual(
      (await f.read("findings.json")).findings
        .map((row) => row.identity.anchor)
        .sort(),
      ["initial", "later-canonical"],
    );
    assert.deepEqual(
      (await f.read("coverage.json")).deferred,
      coverage.deferred,
    );
    await f.save({ complete: false });
    assert.equal((await f.read("findings.json")).findings.length, 2);
  });
}

for (const interruptedAt of [
  "findings.json",
  "coverage.json",
  "scan-manifest.json",
]) {
  test(`MCP drafts retain committed rejection after export interrupts at ${interruptedAt}`, async (t) => {
    const f = await publicationFixture(t);
    const original = f.finding("candidate");
    await f.save({
      findings: [original],
      complete: false,
      coverage: semanticCoverage({
        completeness: "partial",
        deferred: [{ id: "generic-work", reason: "Review a boundary." }],
      }),
    });
    await assert.rejects(
      f.save(
        {
          coverage: semanticCoverage({
            surfaces: [f.rejection],
            resolvedDeferred: [
              { id: "generic-work", reason: "Boundary reviewed." },
            ],
          }),
        },
        interruptedAt,
      ),
      /Synthetic publication interruption/,
    );
    await f.save({ complete: false });
    assert.deepEqual((await f.read("findings.json")).findings, []);
    const coverage = await f.read("coverage.json");
    assert.equal(coverage.surfaces[0].disposition, "rejected");
    assert.deepEqual(coverage.surfaces[0].finding, original);
    assert.deepEqual(coverage.deferred, []);
    assert.deepEqual(coverage.resolvedDeferred, [
      { id: "generic-work", reason: "Boundary reviewed." },
    ]);
  });
}

for (const pendingNewer of [true, false]) {
  test(`MCP reconciliation keeps the ${pendingNewer ? "pending" : "committed"} terminal decision by recency`, async (t) => {
    const f = await publicationFixture(t);
    const original = f.finding("candidate");
    await f.save({ findings: [original] });
    await assert.rejects(
      f.save(
        { coverage: semanticCoverage({ surfaces: [f.rejection] }) },
        "artifacts/scan-draft.json",
      ),
      /Synthetic publication interruption/,
    );
    const pendingDir = join(f.scanDir, "checkpoints/pending");
    const pending = await readdir(pendingDir);
    assert.equal(pending.length, 1);
    await utimes(
      join(f.scanDir, "artifacts/scan-draft.json"),
      1700000010,
      1700000010,
    );
    for (const name of pending) {
      const timestamp = pendingNewer ? 1700000020 : 1700000000;
      for (const relative of [
        join("checkpoints", name),
        join("checkpoints/pending", name),
      ])
        await utimes(join(f.scanDir, relative), timestamp, timestamp);
    }
    await f.save({ complete: false });
    const findings = (await f.read("findings.json")).findings;
    assert.equal(findings.length, pendingNewer ? 0 : 1);
    if (pendingNewer) {
      const surface = (await f.read("coverage.json")).surfaces.find(
        (row) => row.candidateId === "candidate",
      );
      assert.equal(surface.disposition, "rejected");
      assert.deepEqual(surface.finding, original);
    }
    const acknowledged = (await f.read("artifacts/scan-draft.json"))
      .reconciledCheckpointIds;
    assert.ok(pending.every((name) => acknowledged.includes(name)));
    assert.deepEqual(await readdir(pendingDir), []);
    const evidence = await f.read(join("checkpoints", pending[0]));
    assert.equal(evidence.coverage.surfaces[0].disposition, "rejected");
  });
}

test("MCP rejection and re-report preserve every finding for one candidate", async (t) => {
  const f = await publicationFixture(t);
  const original = ["first", "second"].map((id) => ({
    ...f.finding("candidate"),
    identity: { anchor: id },
    title: `Synthetic ${id} finding`,
    remediation: `Preserve ${id} repair.`,
  }));
  await f.save({ findings: original });
  await f.save({ coverage: semanticCoverage({ surfaces: [f.rejection] }) });
  assert.deepEqual((await f.read("findings.json")).findings, []);
  await f.save({
    findings: [
      { ...f.finding("candidate"), identity: { anchor: "reported-again" } },
    ],
  });
  const retained = (await f.read("findings.json")).findings[0].provenance
    .previousFindings;
  assert.deepEqual(
    new Set(retained.map((row) => row.identity.anchor)),
    new Set(["first", "second"]),
  );
  for (const finding of original)
    assert.deepEqual(
      retained.find((row) => row.identity.anchor === finding.identity.anchor),
      finding,
    );
});

test("MCP surface resolution keeps earlier receipts in the final seal", async (t) => {
  const f = await publicationFixture(t);
  const refs = [
    "artifacts/receipts/earlier.txt",
    "artifacts/receipts/final.txt",
  ];
  await mkdir(join(f.scanDir, "artifacts/receipts"), { recursive: true });
  for (const ref of refs)
    await writeFile(join(f.scanDir, ref), `Synthetic evidence: ${ref}\n`);
  const surface = {
    id: "surface",
    label: "Reviewed handler",
    disposition: "needs_follow_up",
    receiptRefs: [refs[0]],
  };
  await f.save({
    complete: false,
    coverage: semanticCoverage({
      completeness: "partial",
      surfaces: [surface],
      deferred: [
        {
          id: "task",
          reason: "Review retained evidence.",
          surfaceIds: [surface.id],
        },
      ],
    }),
  });
  await f.save({
    coverage: semanticCoverage({
      surfaces: [
        { ...surface, disposition: "no_issue_found", receiptRefs: [refs[1]] },
      ],
      resolvedDeferred: [{ id: "task", reason: "Review complete." }],
    }),
  });
  const coverage = await f.read("coverage.json");
  assert.deepEqual(new Set(coverage.surfaces[0].receiptRefs), new Set(refs));
  assert.deepEqual(coverage.deferred, []);
  await f.workbench(["prepare-scan-completion", "--scan-id", f.scanId]);
  const artifacts = (await f.read("scan-manifest.json")).scan.artifacts;
  for (const ref of refs) assert.ok(artifacts.some((row) => row.path === ref));
});

for (const complete of [false, true]) {
  for (const changed of [
    "findings.json",
    "coverage.json",
    "scan-manifest.json",
  ]) {
    test(`MCP retries concurrent canonical ${changed} edits (complete: ${complete})`, async (t) => {
      const f = await publicationFixture(t);
      await f.save({ complete: false, findings: [f.finding("initial")] });
      const committed = await readFile(
        join(f.scanDir, "artifacts/scan-draft.json"),
      );
      let attempts = 0,
        conflicts = 0,
        concurrent;
      await recordCodexSecurityScanDraftViaWorkbench(
        f.context,
        {
          scanId: f.scanId,
          complete,
          findings: [],
          coverage: semanticCoverage(),
        },
        async (args, input) => {
          attempts++;
          if (attempts === 1) {
            const document = await f.read(changed);
            if (changed === "findings.json")
              document.findings.push(f.finding("concurrent"));
            else if (changed === "coverage.json") {
              document.completeness = "partial";
              document.deferred.push({
                id: "concurrent-work",
                reason: "Retain concurrent evidence.",
              });
            } else
              document.scan.threatModel = {
                format: "markdown",
                content: "# Concurrent model\n",
              };
            concurrent = JSON.stringify(document);
            await writeFile(join(f.scanDir, changed), concurrent);
          }
          try {
            return await f.workbench(args, input);
          } catch (error) {
            assert.match(String(error), /scan_draft_conflict/);
            conflicts++;
            assert.equal(
              await readFile(join(f.scanDir, changed), "utf8"),
              concurrent,
            );
            assert.deepEqual(
              await readFile(join(f.scanDir, "artifacts/scan-draft.json")),
              committed,
            );
            throw error;
          }
        },
      );
      assert.equal(conflicts, 1);
      assert.equal(attempts, 2);
      if (changed === "findings.json")
        assert.deepEqual(
          (await f.read(changed)).findings
            .map((row) => row.identity.anchor)
            .sort(),
          ["concurrent", "initial"],
        );
      else if (changed === "coverage.json")
        assert.equal((await f.read(changed)).deferred[0].id, "concurrent-work");
      else
        assert.equal(
          (await f.read(changed)).scan.threatModel.content,
          "# Concurrent model\n",
        );
    });
  }
}
