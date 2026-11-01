import { readJson } from "./support/json.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  readFile,
  writeFile,
  mkdir,
  utimes,
  readdir,
  rm,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  draftFixture,
  fixture,
  interruptDraftWrite,
} from "./scan-draft-recovery-fixture.ts";

import {
  type FixtureFinding,
  type RecoveredFinding,
  type DraftFixture,
  finding,
  recoveryPair,
  savedWorker,
  recoverAndFinalize,
  dateDraftFiles,
} from "./scan-identity-recovery-fixture.ts";

const execFileAsync = promisify(execFile);

function withWorkerId(rows: FixtureFinding[], workerId: string) {
  return rows.map((row) => ({
    ...row,
    provenance: { ...row.provenance, workerId },
  }));
}

const checkpointName = (input: unknown) =>
  createHash("sha256").update(JSON.stringify(input)).digest("hex") + ".json";

async function saveCheckpointAt(
  writer: DraftFixture,
  draft: ReturnType<DraftFixture["draft"]>,
  time: number,
) {
  await writer.checkpoint(draft);
  const { handoffClaimToken: _claim, ...snapshot } = draft;
  await utimes(
    path.join(writer.root, "checkpoints", checkpointName(snapshot)),
    time,
    time,
  );
}

const variants = {
  provenance: [
    finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    }),
  ],
  extension: [
    finding("Synthetic review", { extensions: { candidateId: "candidate-1" } }),
  ],
  unicode: [
    finding("Café review", {
      provenance: { source: "local_plugin", candidateId: "Évidence /réview._" },
    }),
  ],
  title: [finding("Café /réview._")],
  siblings: ["First review", "Second review"].map((title) =>
    finding(title, {
      provenance: { source: "local_plugin", candidateId: "shared-candidate" },
    }),
  ),
  report: [
    finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { reportId: "Synthetic Report" },
    }),
  ],
  ledger: [
    finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { ledgerRowId: "Synthetic Ledger" },
    }),
  ],
  "no candidate siblings": [finding("First review"), finding("Second review")],
  "shared ledger": ["First review", "Second review"].map((title) =>
    finding(title, { extensions: { ledgerRowId: "shared-ledger" } }),
  ),
};

for (const variant of [
  "primary location",
  "primary range",
  "additional locations",
] as const) {
  for (const reversed of [false, true]) {
    test(`worker ${variant} identity survives recovery (reversed=${reversed})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const workerRoot = path.join(normal.root, "worker");
      const interruptedRoot = path.join(recovered.root, "worker");
      await Promise.all([mkdir(workerRoot), mkdir(interruptedRoot)]);
      const worker = draftFixture(workerRoot, "worker");
      const interrupted = draftFixture(interruptedRoot, "worker");
      const locations = [
        { path: "src/first.py", startLine: 1 },
        { path: "src/second.py", startLine: 2 },
        { path: "src/third.py", startLine: 3 },
      ];
      const rows = [
        finding("First synthetic review", {
          summary: "First synthetic evidence.",
          locations,
        }),
        finding("Second synthetic review", {
          summary: "Second synthetic evidence.",
          locations:
            variant === "primary location"
              ? [locations[1], locations[0], locations[2]]
              : variant === "primary range"
                ? [{ ...locations[0], endLine: 1 }, ...locations.slice(1)]
                : [locations[0], locations[2], locations[1]],
        }),
      ];
      if (reversed) rows.reverse();
      for (const target of [worker, interrupted]) {
        await target.writeFindings([rows[0]]);
        await dateDraftFiles(target.root, 100);
      }
      await worker.writeFindings([rows[1]]);
      await interrupted.checkpoint(interrupted.findingsDraft([rows[1]]));
      const saved = await readJson(workerRoot, "result.json");
      await normal.writeFindings(withWorkerId(saved.findings, "worker"));
      const result = await recover({
        workers: [savedWorker(interruptedRoot, "worker", "succeeded")],
        details: true,
        replay: true,
        provenanceDetails: true,
      });
      const expectedCount = variant === "additional locations" ? 1 : 2;
      assert.equal(result.normal.length, expectedCount);
      assert.equal(result.recovered.length, expectedCount);
      const reports = (findings: RecoveredFinding[]) =>
        new Map(
          findings.map((row) => [
            row.summary,
            {
              identity: row.identity,
              findingId: row.findingId,
              occurrenceId: row.occurrenceId,
              locations: row.locations,
              history: (
                row.evidenceProvenance as { previousFindings: FixtureFinding[] }
              ).previousFindings.map((previous) => ({
                title: previous.title,
                summary: previous.summary,
                locations: previous.locations,
              })),
            },
          ]),
        );
      const published = reports(result.normal);
      for (const report of published.values()) {
        assert.deepEqual(
          report.history,
          variant === "additional locations"
            ? [
                {
                  title: rows[0]!.title,
                  summary: rows[0]!.summary,
                  locations: rows[0]!.locations,
                },
              ]
            : [],
        );
      }
      assert.deepEqual(reports(result.recovered), published);
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const kind of ["object", "array", "string"] as const) {
  test(`unchanged worker drafts preserve ${kind} owner metadata`, async (t) => {
    const worker = await fixture(t, "worker");
    const findings = ["first", "second"].map((id) =>
      finding("Synthetic review", {
        provenance: {
          source: "local_plugin",
          candidateId: "shared-candidate",
          workerId: kind === "object" ? { id } : kind === "array" ? [id] : id,
        },
      }),
    );
    for (let replay = 0; replay < 3; replay++) {
      await worker.writeFindings(findings);
      const saved = await readJson(worker.root, "result.json");
      assert.deepEqual(saved.findings, findings);
    }
  });
}

for (const observations of [
  [1, true],
  [true, 1],
  [0, false],
  [false, 0],
  [1, 2],
  [0, 2],
]) {
  test(`worker checkpoints preserve reordered JSON identities ${observations.join("/")}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const workerRoot = path.join(normal.root, "worker");
    const interruptedRoot = path.join(recovered.root, "worker");
    await Promise.all([mkdir(workerRoot), mkdir(interruptedRoot)]);
    const worker = draftFixture(workerRoot, "worker");
    const interrupted = draftFixture(interruptedRoot, "worker");
    const findings = observations.map((value) =>
      finding("Synthetic review", {
        extensions: { observations: [{ value }] },
      }),
    );
    for (const [index, rows] of [findings, [...findings].reverse()].entries()) {
      const snapshot = worker.findingsDraft(rows);
      await worker.write(snapshot);
      if (
        index === 1 &&
        observations.every((value) => typeof value === "number")
      ) {
        const contents = (JSON.stringify(snapshot, null, 2) + "\n").replace(
          /"value": (\d+)/g,
          (_, value: string) =>
            `"value": ${value === "0" ? "-0.0" : `${value}.0`}`,
        );
        const name =
          createHash("sha256").update(contents).digest("hex") + ".json";
        await writeFile(
          path.join(interruptedRoot, "checkpoints", name),
          contents,
        );
      } else {
        await interrupted.checkpoint(snapshot);
      }
      if (index === 0) {
        await dateDraftFiles(workerRoot, 100);
        await dateDraftFiles(interruptedRoot, 100);
      }
    }
    const saved = await readJson(workerRoot, "result.json");
    await normal.writeFindings(withWorkerId(saved.findings, "worker"));
    const result = await recover({
      workers: [savedWorker(interruptedRoot, "worker")],
      details: true,
      replay: true,
    });
    const identitiesByEvidence = (rows: RecoveredFinding[]) =>
      new Map(
        rows.map((row) => [
          JSON.stringify(
            (row.candidateMetadata as { extensions: unknown }).extensions,
          ),
          {
            identity: row.identity,
            findingId: row.findingId,
            occurrenceId: row.occurrenceId,
          },
        ]),
      );
    assert.equal(result.normal.length, 2);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(
      identitiesByEvidence(result.recovered),
      identitiesByEvidence(result.normal),
    );
    assert.deepEqual(result.warnings, []);
  });
}

for (const [label, metadata, count] of [
  ["absent", {}, 2],
  ["ASCII blank", { provenance: { candidateId: " \t" } }, 2],
  ["BOM provenance", { provenance: { candidateId: "\ufeff" } }, 2],
  ["BOM extension", { extensions: { candidateId: "\ufeff" } }, 2],
  ["BOM report", { extensions: { reportId: "\ufeff" } }, 2],
  ["BOM ledger", { extensions: { ledgerRowId: "\ufeff" } }, 2],
  ["candidate", { provenance: { candidateId: "candidate-1" } }, 1],
  ["next line", { provenance: { candidateId: "\u0085" } }, 1],
  ["separator", { provenance: { candidateId: "\u001c" } }, 1],
  [
    "extension fallback",
    {
      provenance: { candidateId: "\ufeff" },
      extensions: { candidateId: "candidate-1" },
    },
    1,
  ],
  [
    "report fallback",
    { extensions: { candidateId: "\ufeff", reportId: "report-1" } },
    1,
  ],
  [
    "ledger fallback",
    { extensions: { reportId: "\ufeff", ledgerRowId: "ledger-1" } },
    1,
  ],
] as const) {
  test(`candidate selection retains moved evidence for ${label}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "standard");
    for (const [index, location] of [
      "src/first.py",
      "src/second.py",
    ].entries()) {
      const row = finding("Synthetic review", {
        ...metadata,
        summary: `Synthetic evidence at ${location}`,
        locations: [{ path: location, startLine: 1 }],
        provenance: {
          source: "local_plugin",
          ...("provenance" in metadata ? metadata.provenance : {}),
        },
      });
      await normal.writeFindings([row]);
      await recovered.checkpoint(recovered.findingsDraft([row]));
      if (index === 0) await dateDraftFiles(recovered.root, 100);
    }
    const result = await recover({ details: true, replay: true });
    const byLocation = (rows: RecoveredFinding[]) =>
      new Map(rows.map((row) => [row.locations[0]!.path, row]));
    assert.equal(result.normal.length, count);
    assert.equal(result.recovered.length, count);
    assert.deepEqual(byLocation(result.recovered), byLocation(result.normal));
    assert.deepEqual(result.warnings, []);
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: Unicode whitespace candidate IDs match recovered identities`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    const candidates = {
      bom: "\ufeff",
      "next-line": "\u0085",
      "control-separators": "\u001c\u001f",
      spaces: " \u00a0\u2003\u3000",
    };
    const findings = Object.entries(candidates).map(([label, candidateId]) =>
      finding(label, {
        ruleId: `fixture.${label}`,
        provenance: { source: "local_plugin", candidateId },
      }),
    );
    await normal.writeFindings(findings);
    await recovered.checkpoint(recovered.findingsDraft(findings));
    const result = await recover({ details: true, replay: true });
    assert.deepEqual(
      result.normal.map((row) => row.title).sort(),
      Object.keys(candidates).sort(),
    );
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const observations of [
    [true, 1],
    [false, 0],
    [1, 2],
    [0, 2],
  ]) {
    test(`${layout}: reordered JSON evidence ${observations.join("/")} keeps published identities`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const initial = observations.map((value) =>
        finding("Synthetic review", {
          extensions: { observation: { value } },
        }),
      );
      for (const target of [normal, recovered]) {
        await target.writeFindings(initial);
        await dateDraftFiles(target.root, 100);
      }
      const findings = [...initial].reverse();
      await normal.writeFindings(findings);
      const snapshot = recovered.findingsDraft(findings);
      if (typeof observations[0] === "boolean") {
        await recovered.checkpoint(snapshot);
      } else {
        // Imported JSON can spell the same numbers differently than JSON.stringify.
        const contents = (JSON.stringify(snapshot, null, 2) + "\n").replace(
          /"value": (\d+)/g,
          (_, value: string) =>
            `"value": ${value === "0" ? "-0.0" : `${value}.0`}`,
        );
        const name =
          createHash("sha256").update(contents).digest("hex") + ".json";
        await writeFile(
          path.join(recovered.root, "checkpoints", name),
          contents,
        );
      }
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, 2);
      const byId = (left: RecoveredFinding, right: RecoveredFinding) =>
        left.findingId.localeCompare(right.findingId);
      assert.deepEqual(result.recovered.sort(byId), result.normal.sort(byId));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const [variant, findings] of Object.entries(variants)) {
    test(`${layout}: first checkpoint publication preserves ${variant} identities`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      await normal.writeFindings(findings);
      await recovered.checkpoint(recovered.findingsDraft(findings));
      const result = await recover();
      assert.equal(result.normal.length, findings.length);
      assert.equal(result.recovered.length, findings.length);
      assert.deepEqual(result.warnings, []);
      assert.deepEqual(result.recovered, result.normal);
    });
  }
}

const terminalDraftCases: Array<{
  variant: string;
  expectedCount: number;
  observation?: [unknown, unknown];
}> = [
  { variant: "candidate", expectedCount: 1 },
  { variant: "report", expectedCount: 1 },
  { variant: "ledger", expectedCount: 1 },
  { variant: "metadata", expectedCount: 1 },
  { variant: "moved", expectedCount: 2 },
  { variant: "true-to-number", expectedCount: 2, observation: [true, 1] },
  { variant: "false-to-number", expectedCount: 2, observation: [false, 0] },
  { variant: "number-to-true", expectedCount: 2, observation: [1, true] },
  { variant: "same-boolean", expectedCount: 1, observation: [true, true] },
  { variant: "same-number", expectedCount: 1, observation: [1, 1.0] },
  {
    variant: "different-string",
    expectedCount: 2,
    observation: ["old", "new"],
  },
];
for (const { variant, expectedCount, observation } of terminalDraftCases) {
  test(`worker: a newer terminal draft reconciles ${variant} observations`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const workerRoot = path.join(normal.root, "worker");
    const interruptedRoot = path.join(recovered.root, "worker");
    await Promise.all([mkdir(workerRoot), mkdir(interruptedRoot)]);
    const worker = draftFixture(workerRoot, "worker");
    const interrupted = draftFixture(interruptedRoot, "worker");
    const plain = finding(
      "Synthetic review",
      observation
        ? { extensions: { observation: { value: observation[0] } } }
        : {},
    );
    const enriched = finding("Synthetic review", {
      ...(variant === "candidate" || variant === "metadata"
        ? { provenance: { source: "local_plugin", candidateId: "candidate-1" } }
        : {}),
      ...(variant === "candidate"
        ? {}
        : {
            extensions: {
              [variant === "ledger" ? "ledgerRowId" : "reportId"]: "report-1",
              ...(observation
                ? {
                    observation: {
                      value: observation[1],
                      note: "Additional synthetic observation.",
                    },
                  }
                : {}),
            },
          }),
    });
    const initial =
      variant === "metadata" || variant === "moved" || observation
        ? [enriched, plain]
        : [enriched, enriched];
    const latest =
      variant === "moved"
        ? [
            { ...plain, locations: [{ path: "src/example.py", startLine: 2 }] },
            enriched,
          ]
        : [enriched];
    for (const target of [worker, interrupted]) {
      await target.writeFindings(initial, { complete: true });
      await dateDraftFiles(target.root, 100);
    }
    await worker.writeFindings(latest, { complete: true });
    await interrupted.checkpoint(
      interrupted.findingsDraft(latest, { complete: true }),
    );
    const published = await readJson(worker.root, "result.json");
    await normal.writeFindings(withWorkerId(published.findings, "worker"), {
      complete: true,
    });
    const sourceBytes = new Map(
      await Promise.all(
        (await readdir(interrupted.root, { recursive: true }))
          .filter((name) => name.endsWith(".json"))
          .map(
            async (name) =>
              [
                name,
                await readFile(path.join(interrupted.root, name)),
              ] as const,
          ),
      ),
    );
    const finalized = await recover({
      workers: [savedWorker(interrupted.root, "worker")],
      details: true,
      replay: true,
    });
    assert.equal(finalized.normal.length, expectedCount);
    assert.equal(finalized.recovered.length, expectedCount);
    const byId = (left: RecoveredFinding, right: RecoveredFinding) =>
      left.findingId.localeCompare(right.findingId);
    assert.deepEqual(
      finalized.recovered.sort(byId),
      finalized.normal.sort(byId),
    );
    assert.deepEqual(finalized.warnings, []);
    for (const [name, bytes] of sourceBytes) {
      assert.deepEqual(
        await readFile(path.join(interrupted.root, name)),
        bytes,
      );
    }
  });
}

for (const layout of ["standard", "diff", "worker"] as const) {
  test(`${layout}: adding candidate metadata preserves a report-backed finding`, async (t) => {
    const f = await fixture(t, layout);
    const initial = finding("Synthetic report", {
      extensions: { reportId: "report-1" },
    });
    await f.writeFindings([initial]);
    await f.writeFindings([
      {
        ...initial,
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
      },
    ]);
    const saved = await readJson(
      f.root,
      layout === "worker" ? "result.json" : "findings.json",
    );
    assert.equal(saved.findings.length, 1);
    assert.equal(saved.findings[0].provenance.candidateId, "candidate-1");
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: canonical rows without identities use their sibling context`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    for (const f of [normal, recovered])
      await f.writeFindings(variants.siblings);
    const destination = path.join(recovered.root, "findings.json");
    const document = await readJson(destination);
    for (const row of document.findings) delete row.identity;
    await writeFile(destination, JSON.stringify(document));
    const result = await recover();
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}
for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: a new sibling survives a published singleton`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    for (const f of [normal, recovered])
      await f.writeFindings(variants.siblings.slice(0, 1));
    await normal.writeFindings(variants.siblings);
    await interruptDraftWrite(path.join(recovered.root, "findings.json"), () =>
      recovered.writeFindings(variants.siblings),
    );
    const result = await recover();
    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
  for (const metadata of ["provenance", "extensions"] as const) {
    for (const reported of [false, true]) {
      for (const cut of ["raw", "reconciled"]) {
        test(`${layout}: ${metadata} enrichment (report=${reported}) retains identities after two ${cut} interruptions`, async (t) => {
          const { normal, recovered, recover } = await recoveryPair(t, layout);
          const first = finding(
            "Synthetic report",
            reported
              ? {
                  extensions: { reportId: "report-1" },
                }
              : {},
          );
          const second = {
            ...first,
            [metadata]: { ...first[metadata], candidateId: "candidate-1" },
          };
          for (const value of [first, second]) {
            await normal.writeFindings([value]);
            const input = recovered.findingsDraft([value]);
            if (cut === "raw") await recovered.checkpoint(input);
            else
              await interruptDraftWrite(
                path.join(recovered.root, "findings.json"),
                () => recovered.write(input),
              );
          }
          const result = await recover({ details: true });
          assert.equal(result.normal.length, 1);
          assert.deepEqual(result.recovered, result.normal);
          assert.deepEqual(result.warnings, []);
        });
      }
    }
  }
}

for (const variant of [
  "different titles",
  "same title",
  "normalized aliases",
  "authored anchor",
  "rejected sibling",
]) {
  test(`deep: worker-local candidates match combined publication (${variant})`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const workers = [];
    const findings = [];
    for (const [index, id] of ["reviewer-a", "reviewer-b"].entries()) {
      const root = path.join(recovered.root, id);
      await mkdir(root);
      const worker = draftFixture(root, "worker");
      const value = finding(
        variant === "same title" || index === 0
          ? "First review"
          : "Second review",
        {
          provenance: {
            source: "local_plugin",
            candidateId:
              variant === "normalized aliases"
                ? index === 0
                  ? "Case"
                  : "Caſe"
                : "candidate-1",
          },
        },
      );
      if (variant === "authored anchor" && index === 0)
        value.identity = { anchor: "established-review" };
      await worker.writeFindings([value]);
      const result = await readJson(root, "result.json");
      if (variant === "rejected sibling" && index === 1) {
        await worker.writeReviewState(
          {
            surfaces: [
              {
                id: "review-completed",
                label: "Review completed",
                candidateId: "candidate-1",
                disposition: "rejected",
              },
            ],
          },
          true,
        );
      } else {
        findings.push(...withWorkerId(result.findings, id));
      }
      workers.push(savedWorker(root, id));
    }
    await normal.writeFindings(findings);
    const result = await recover({ workers });
    assert.equal(result.normal.length, variant === "rejected sibling" ? 1 : 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

for (const [kind, metadata, identifier] of [
  ["candidate aliases", "provenance"],
  ["report enrichment", "extensions", "reportId"],
  ["report enrichment", "extensions", "ledgerRowId"],
  ...[undefined, "reportId", "ledgerRowId"].flatMap((identifier) =>
    ["provenance", "extensions"].map((metadata) => [
      "candidate enrichment",
      metadata,
      identifier,
    ]),
  ),
]) {
  test(`deep: ${kind} via ${metadata}/${identifier ?? "plain"} matches published worker identities`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const normalRoot = path.join(normal.root, "reviewer");
    const recoveryRoot = path.join(recovered.root, "reviewer");
    await mkdir(normalRoot);
    await mkdir(recoveryRoot);
    const publishedWorker = draftFixture(normalRoot, "worker");
    const interruptedWorker = draftFixture(recoveryRoot, "worker");
    const first = finding("First review", {
      ...(kind === "candidate enrichment"
        ? {}
        : {
            provenance: {
              source: "local_plugin",
              candidateId:
                kind === "candidate aliases" ? "CASE" : "candidate-1",
            },
          }),
      ...(kind === "candidate enrichment" && identifier
        ? { extensions: { [identifier!]: "report-1" } }
        : {}),
    });
    const second = structuredClone(first);
    if (kind === "candidate aliases") {
      second.title = "Second review";
      second.provenance.candidateId = "case";
    } else if (kind === "report enrichment") {
      second.extensions = { [identifier!]: "report-1" };
    } else {
      second[metadata!] = {
        ...(second[metadata!] as Record<string, unknown>),
        candidateId: "candidate-1",
      };
    }
    for (const worker of [publishedWorker, interruptedWorker])
      await worker.writeFindings([first]);
    await publishedWorker.writeFindings([second]);
    await interruptedWorker.checkpoint(
      interruptedWorker.findingsDraft([second]),
    );
    const result = await readJson(normalRoot, "result.json");
    await normal.writeFindings(withWorkerId(result.findings, "reviewer"));
    const comparison = await recover({ workers: [savedWorker(recoveryRoot)] });
    assert.equal(
      comparison.normal.length,
      kind === "candidate aliases" ? 2 : 1,
    );
    const byTitle = (left: FixtureFinding, right: FixtureFinding) =>
      left.title.localeCompare(right.title);
    assert.deepEqual(
      comparison.recovered.sort(byTitle),
      comparison.normal.sort(byTitle),
    );
    assert.deepEqual(comparison.warnings, []);
  });
}

for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: growing raw cross-location siblings retain published identities`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "shared-candidate" },
    });
    const second = {
      ...first,
      title: "Second review",
      locations: [{ path: "src/example.py", startLine: 2 }],
    };
    for (const findings of [[first], [first, second]]) {
      await normal.writeFindings(findings);
      await recovered.checkpoint(recovered.findingsDraft(findings));
    }
    const result = await recover();
    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

for (const variant of [
  "unchanged",
  "candidate-collision",
  "no-candidate-enrichment",
  "no-sibling",
] as const) {
  for (const reversed of [false, true]) {
    test(`deep: explicit worker identity survives ${variant} revision (reverse=${reversed})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const nwroot = path.join(normal.root, "reviewer"),
        rwroot = path.join(recovered.root, "reviewer");
      await mkdir(nwroot);
      await mkdir(rwroot);
      const nw = draftFixture(nwroot, "worker"),
        rw = draftFixture(rwroot, "worker");
      const first = finding("First review", {
        identity: { anchor: "authored-review" },
      });
      const sibling = finding("Second review", {
        provenance: { source: "local_plugin", candidateId: "shared-review" },
        locations: [{ path: "src/other.py", startLine: 2 }],
      });
      const withSibling = variant !== "unchanged" && variant !== "no-sibling";
      const ordered = (current: FixtureFinding) => {
        const rows = withSibling ? [current, sibling] : [current];
        return reversed ? rows.toReversed() : rows;
      };
      const second = {
        ...first,
        ...(variant === "unchanged"
          ? {}
          : { title: "Revised first review", summary: "Revised evidence." }),
        provenance: {
          ...first.provenance,
          ...(variant === "no-candidate-enrichment"
            ? {}
            : { candidateId: "shared-review" }),
        },
      };
      await nw.writeFindings(ordered(first));
      await rw.writeFindings(ordered(first));
      await nw.writeFindings(ordered(second));
      await rw.checkpoint(rw.findingsDraft(ordered(second)));
      const result = await readJson(nwroot, "result.json");
      await normal.writeFindings(withWorkerId(result.findings, "reviewer"));
      const comparison = await recover({ workers: [savedWorker(rwroot)] });
      assert.equal(comparison.normal.length, withSibling ? 2 : 1);
      assert.deepEqual(comparison.recovered, comparison.normal);
      assert.deepEqual(comparison.warnings, []);
      assert.deepEqual(
        comparison.normal.map((row) => row.title).sort(),
        ordered(second)
          .map((row) => row.title)
          .sort(),
      );
      const revised = result.findings.find(
        (row: FixtureFinding) => row.title === second.title,
      );
      assert.deepEqual(revised.identity, first.identity);
      if (variant !== "unchanged") {
        assert.deepEqual(revised.provenance.previousFindings, [first]);
      }
      if (withSibling) {
        assert.deepEqual(
          result.findings.find(
            (row: FixtureFinding) => row.title === sibling.title,
          ),
          sibling,
        );
      }
    });
  }
}

for (const layout of ["standard", "diff", "worker"] as const) {
  for (const variant of [
    "reportId",
    "ledgerRowId",
    "metadata enrichment",
    "authored identity",
    "retained sibling",
  ]) {
    test(`${layout}: checkpoint reconciliation preserves ${variant}`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(
        t,
        layout === "worker" ? "deep" : layout,
      );
      let normalSource = normal,
        recoveredSource = recovered;
      const workers = [];
      if (layout === "worker") {
        for (const f of [normal, recovered])
          await mkdir(path.join(f.root, "reviewer"));
        normalSource = draftFixture(
          path.join(normal.root, "reviewer"),
          "worker",
        );
        recoveredSource = draftFixture(
          path.join(recovered.root, "reviewer"),
          "worker",
        );
        workers.push(savedWorker(recoveredSource.root));
      }
      const first = finding("First review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
      });
      let second = structuredClone(first);
      if (["reportId", "ledgerRowId", "authored identity"].includes(variant)) {
        const field = variant === "authored identity" ? "reportId" : variant;
        first.extensions = { [field]: "report-1" };
        second.extensions = { [field]: "report-2" };
      }
      if (variant === "metadata enrichment")
        second.extensions = { reportId: "report-1" };
      if (variant === "authored identity") {
        first.identity = { anchor: "authored-review" };
        second.identity = { anchor: "authored-review" };
      }
      if (variant === "retained sibling") second.title = "Second review";
      const initial =
        variant === "retained sibling" ? [first, second] : [first];
      for (const f of [normalSource, recoveredSource])
        await f.writeFindings(initial);
      await normalSource.writeFindings([second], { complete: true });
      await recoveredSource.checkpoint(
        recoveredSource.findingsDraft([second], { complete: true }),
      );
      if (layout === "worker") {
        const saved = await readJson(normalSource.root, "result.json");
        await normal.writeFindings(withWorkerId(saved.findings, "reviewer"));
      }
      const result = await recover({
        workers,
        details: variant === "metadata enrichment",
      });
      const count = ["metadata enrichment", "authored identity"].includes(
        variant,
      )
        ? 1
        : 2;
      assert.equal(result.normal.length, count);
      assert.equal(result.recovered.length, count);
      if (variant === "retained sibling")
        assert.deepEqual(result.normal.map((row) => row.title).sort(), [
          "First review",
          "Second review",
        ]);
      const ordered = (rows: RecoveredFinding[]) =>
        rows.sort((left, right) =>
          left.findingId.localeCompare(right.findingId),
        );
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const)
  for (const metadata of ["provenance", "extensions"] as const) {
    test(`${layout}: candidate-backed canonical duplicate without identity (${metadata})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const input = finding("Synthetic review", {
        [metadata]: {
          ...(metadata === "provenance" ? { source: "local_plugin" } : {}),
          candidateId: "candidate-1",
        },
      });
      for (const f of [normal, recovered]) await f.writeFindings([input]);
      const dest = path.join(recovered.root, "findings.json");
      const doc = await readJson(dest);
      const duplicate = structuredClone(doc.findings[0]);
      delete duplicate.identity;
      doc.findings.push(duplicate);
      await writeFile(dest, JSON.stringify(doc));
      const result = await recover();
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
    });
  }

for (const layout of ["standard", "diff", "deep"] as const)
  for (const metadata of ["provenance", "extensions"] as const) {
    test(`${layout}: raw candidate identity remains distinct when content matches (${metadata})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const one = finding("Synthetic review", {
        [metadata]: {
          ...(metadata === "provenance" ? { source: "local_plugin" } : {}),
          candidateId: "candidate-1",
        },
      });
      const two = {
        ...one,
        [metadata]: { ...one[metadata], candidateId: "candidate-2" },
      };
      await normal.writeFindings([one, two]);
      await recovered.writeFindings([one]);
      const dest = path.join(recovered.root, "findings.json");
      const doc = await readJson(dest);
      const second = structuredClone(doc.findings[0]);
      delete second.identity;
      second[metadata].candidateId = "candidate-2";
      doc.findings.push(second);
      await writeFile(dest, JSON.stringify(doc));
      const result = await recover();
      assert.equal(result.normal.length, 2);
      assert.deepEqual(result.recovered, result.normal);
    });
  }

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: cumulative distinct owners retain publication identity`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    const first = finding("Synthetic ownership review", {
      provenance: {
        source: "local_plugin",
        candidateId: "candidate-1",
        workerId: "worker-a",
      },
    });
    const second = {
      ...structuredClone(first),
      identity: { anchor: "authored-worker-b" },
      provenance: { ...first.provenance, workerId: "worker-b" },
    };
    for (const findings of [[first], [first, second]]) {
      await normal.writeFindings(findings);
      await recovered.checkpoint(recovered.findingsDraft(findings));
    }
    const result = await recover();
    assert.equal(result.normal.length, 2);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.recovered, result.normal);
  });
  for (const [field, blank] of [
    ["reportId", " "],
    ["ledgerRowId", "\t"],
  ]) {
    test(`${layout}: blank ${field} enrichment retains publication identity`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("Synthetic metadata review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        extensions: { [field]: blank },
      });
      const second = { ...first, extensions: { [field]: "report-1" } };
      for (const value of [first, second]) {
        await normal.writeFindings([value]);
        await recovered.checkpoint(recovered.findingsDraft([value]));
      }
      const result = await recover();
      assert.equal(result.normal.length, 1);
      assert.equal(result.recovered.length, 1);
      assert.deepEqual(result.warnings, []);
      assert.deepEqual(result.recovered, result.normal);
    });
  }
}
for (const field of ["reportId", "ledgerRowId"]) {
  test(`deep: worker blank ${field} enrichment retains publication identity`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const normalRoot = path.join(normal.root, "reviewer");
    const recoveredRoot = path.join(recovered.root, "reviewer");
    await mkdir(normalRoot);
    await mkdir(recoveredRoot);
    const normalWorker = draftFixture(normalRoot, "worker");
    const recoveredWorker = draftFixture(recoveredRoot, "worker");
    const first = finding("Synthetic worker review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { [field]: " \t " },
    });
    const second = { ...first, extensions: { [field]: "report-1" } };
    for (const value of [first, second]) {
      await normalWorker.writeFindings([value]);
      await recoveredWorker.checkpoint(recoveredWorker.findingsDraft([value]));
    }
    const saved = await readJson(normalRoot, "result.json");
    await normal.writeFindings(withWorkerId(saved.findings, "reviewer"));
    const result = await recover({ workers: [savedWorker(recoveredRoot)] });
    assert.equal(result.normal.length, 1);
    assert.equal(result.recovered.length, 1);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.recovered, result.normal);
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: later authored identity survives raw checkpoint recovery`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    const first = finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    });
    const second = { ...first, identity: { anchor: "authored-review" } };
    for (const value of [first, second]) {
      await normal.writeFindings([value]);
      await recovered.checkpoint(recovered.findingsDraft([value]));
    }
    const result = await recover();
    assert.equal(result.normal.length, 2);
    assert.deepEqual(
      [...result.recovered].sort((a, b) =>
        a.identity.anchor.localeCompare(b.identity.anchor),
      ),
      [...result.normal].sort((a, b) =>
        a.identity.anchor.localeCompare(b.identity.anchor),
      ),
    );
  });
  for (const metadata of [
    { id: "synthetic-worker" },
    ["synthetic-worker"],
  ] as const) {
    test(`${layout}: arbitrary worker provenance survives recovery (${Array.isArray(metadata) ? "array" : "object"})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const value = finding("Synthetic review", {
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          workerId: metadata,
        },
      });
      for (const f of [normal, recovered]) await f.writeFindings([value]);
      const result = await recover();
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.recovered[0].workerMetadata, metadata);
    });
  }
}
for (const layout of ["standard", "diff", "deep"] as const) {
  for (const shape of ["summary revision", "shared ledger"]) {
    test(`${layout}: report reconciliation ${shape}`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("First review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        ...(shape === "shared ledger"
          ? { extensions: { ledgerRowId: "ledger-1" } }
          : {}),
      });
      const second = { ...structuredClone(first), title: "Second review" };
      const snapshots =
        shape === "summary revision"
          ? [
              [first, second],
              [{ ...first, summary: "Revised evidence." }, second],
            ]
          : [[first, second]];
      for (const findings of snapshots) {
        await normal.writeFindings(findings);
        await recovered.checkpoint(recovered.findingsDraft(findings));
      }
      const result = await recover({ details: true });

      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, result.normal.length);
      assert.deepEqual(result.warnings, []);
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
    });
  }
}

test("deep: refined candidate retains independent cross-location report", async (t) => {
  const { normal, recovered, recover } = await recoveryPair(t, "deep");
  const normalRoot = path.join(normal.root, "reviewer");
  const recoveredRoot = path.join(recovered.root, "reviewer");
  await mkdir(normalRoot);
  await mkdir(recoveredRoot);
  const normalWorker = draftFixture(normalRoot, "worker");
  const recoveredWorker = draftFixture(recoveredRoot, "worker");
  const first = finding("First review", {
    severity: { level: "high" },
    provenance: { source: "local_plugin", candidateId: "candidate-1" },
  });
  const refined = {
    ...first,
    locations: [{ path: "src/example.py", startLine: 2 }],
  };
  const second = {
    ...structuredClone(first),
    title: "Second review",
    summary: "Independent evidence.",
    severity: { level: "low" },
  };
  for (const findings of [[first], [refined, second]]) {
    await normalWorker.writeFindings(findings);
    await recoveredWorker.checkpoint(recoveredWorker.findingsDraft(findings));
  }
  const saved = await readJson(normalRoot, "result.json");
  await normal.writeFindings(withWorkerId(saved.findings, "reviewer"));
  const result = await recover({
    workers: [savedWorker(recoveredRoot)],
    details: true,
  });

  assert.ok(result.recovered.some((row) => row.title === "Second review"));
  assert.equal(result.normal.length, 3);
  assert.equal(result.recovered.length, 3);
  assert.deepEqual(result.warnings, []);
  const ordered = (rows: RecoveredFinding[]) =>
    [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
  assert.deepEqual(ordered(result.recovered), ordered(result.normal));
});
for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: revised sibling publication completes with unique identities`, async (t) => {
    const f = await fixture(t, layout);
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    });
    const second = { ...structuredClone(first), title: "Second review" };
    await f.writeFindings([first, second]);
    await f.writeFindings(
      [{ ...first, summary: "Revised evidence." }, second],
      { complete: true },
    );
    const { stdout } = await execFileAsync(
      process.env.PYTHON?.trim() || "python3",
      [
        "-c",
        `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from finalize_scan_contract import _prepare_scan_finalization
root=Path(sys.argv[2])
documents=tuple(json.loads((root/name).read_text()) for name in ('scan-manifest.json','findings.json','coverage.json'))
documents[0]['scan'].update(id=sys.argv[3],status='completed',producer={'name':'test','version':'1'},startedAt='2026-05-31T18:00:00Z',completedAt='2026-05-31T18:09:00Z')
for document in documents[1:]: document['scanId']=sys.argv[3]
prepared=_prepare_scan_finalization(root,draft_documents=documents)
print(len(prepared.findings['findings']))`,
        fileURLToPath(new URL("../../scripts", import.meta.url)),
        f.root,
        f.context.scanId!,
      ],
    );
    assert.equal(stdout.trim(), "2");
  });
}
for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: repeated shared-ledger publication preserves allocated identities`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { ledgerRowId: "ledger-1" },
    });
    const second = { ...structuredClone(first), title: "Second review" };
    for (let index = 0; index < 2; index++) {
      for (const f of [normal, recovered])
        await f.writeFindings([first, second]);
    }
    const result = await recover({ details: true });
    assert.equal(result.normal.length, 2);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.recovered, result.normal);
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const cut of ["canonical", "raw"]) {
    test(`${layout}: ownership enrichment preserves publication identity (${cut})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("Synthetic ownership review", {
        identity: { anchor: "authored-review" },
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
      });
      const second = {
        ...first,
        provenance: { ...first.provenance, workerId: "worker-a" },
      };
      for (const row of [first, second]) {
        await normal.writeFindings([row]);
        if (cut === "canonical") await recovered.writeFindings([row]);
        else await recovered.checkpoint(recovered.findingsDraft([row]));
      }
      const result = await recover();

      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: ownership enrichment keeps a newly known independent owner`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, layout);
    const first = finding("Synthetic ownership review", {
      identity: { anchor: "authored-first" },
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    });
    const owned = {
      ...first,
      provenance: { ...first.provenance, workerId: "worker-a" },
    };
    const independent = {
      ...first,
      identity: { anchor: "authored-second" },
      provenance: { ...first.provenance, workerId: "worker-b" },
    };
    for (const findings of [[first], [owned, independent]]) {
      await normal.writeFindings(findings);
      await recovered.checkpoint(recovered.findingsDraft(findings));
    }
    const result = await recover();

    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
  });
}
for (const authored of [false, true]) {
  test(`deep: ownership enrichment cannot bridge bound workers authored=${authored}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const workers = [],
      findings = [];
    for (const id of ["worker-a", "worker-b"]) {
      const workerRoot = path.join(recovered.root, id);
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const value = finding("Synthetic bound owner review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        ...(authored ? { identity: { anchor: "authored-review" } } : {}),
      });
      for (const row of [
        value,
        { ...value, provenance: { ...value.provenance, workerId: id } },
      ]) {
        await worker.checkpoint(worker.findingsDraft([row]));
      }
      findings.push({
        ...value,
        provenance: { ...value.provenance, workerId: id },
      });
      workers.push(savedWorker(workerRoot, id));
    }
    await normal.writeFindings(findings);
    const result = await recover({ workers });

    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
  });
}

for (const order of ["earlier-first", "later-first"]) {
  for (const metadata of ["extensions", "provenance"] as const) {
    for (const initialLevel of ["low", "high"]) {
      test(`worker revised raw checkpoint retains ${metadata} enrichment (${order}, ${initialLevel} to low)`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, "deep");
        const normalRoot = path.join(normal.root, "reviewer"),
          recoveredRoot = path.join(recovered.root, "reviewer");
        for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
        const worker = draftFixture(normalRoot, "worker"),
          recoveryWorker = draftFixture(recoveredRoot, "worker");
        const initial = {
          ...finding("Synthetic review"),
          summary: "Initial assessment.",
          severity: { level: initialLevel },
        };
        const revised = {
          ...initial,
          summary: "Corrected assessment.",
          severity: { level: "low" },
          [metadata]: { ...initial[metadata], candidateId: "candidate-1" },
        };
        const oldDraft = worker.findingsDraft([initial]);
        let newDraft,
          suffix = 0;
        do {
          newDraft = {
            ...worker.draft(),
            findings: [revised],
            threatModel: { summary: `Synthetic checkpoint ${suffix++}.` },
          };
        } while (
          checkpointName(oldDraft) < checkpointName(newDraft) !==
          (order === "earlier-first")
        );
        for (const [index, draft] of [oldDraft, newDraft].entries()) {
          await worker.write(draft);
          await saveCheckpointAt(recoveryWorker, draft, 100 + index * 100);
        }
        const saved = await readJson(normalRoot, "result.json");
        assert.equal(saved.findings.length, 1);
        assert.equal(saved.findings[0].summary, revised.summary);
        assert.equal(saved.findings[0].severity.level, "low");
        assert.equal(saved.findings[0][metadata].candidateId, "candidate-1");
        await normal.writeFindings(withWorkerId(saved.findings, "reviewer"));
        const result = await recover({
          workers: [savedWorker(recoveredRoot)],
          details: true,
        });
        assert.deepEqual(result.warnings, []);
        assert.equal(result.recovered.length, 1);
        assert.deepEqual(result.recovered, result.normal);
      });
    }
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const [field, value] of Object.entries({
    description: "Synthetic annotation",
    source: "authored",
    version: 1,
  })) {
    for (const authoredFirst of [true, false]) {
      test(`${layout}: semantic identity reserves ${field} metadata (authored first=${authoredFirst})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, layout);
        const authored = finding("First review", {
          identity: {
            anchor: "candidate-1",
            instance: "second-review",
            [field]: value,
          },
          extensions: { candidateId: "candidate-1" },
        });
        const generated = finding("Second review", {
          locations: [{ path: "src/example.py", startLine: 2 }],
          extensions: { candidateId: "candidate-1" },
        });
        const reserved = finding("Reserved review", {
          identity: {
            anchor: "candidate-1",
            instance: "second-review-2",
            [field]: value,
          },
          locations: [{ path: "src/example.py", startLine: 3 }],
          extensions: { candidateId: "candidate-1" },
        });
        const findings = authoredFirst
          ? [authored, generated, reserved]
          : [generated, reserved, authored];
        await normal.writeFindings(findings);
        await recovered.checkpoint(recovered.findingsDraft(findings));
        const result = await recover({ details: true });
        assert.equal(result.normal.length, 3);
        assert.equal(result.recovered.length, 3);
        assert.deepEqual(result.warnings, []);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(
          result.recovered.find((row) => row.title === "First review")!
            .identity,
          authored.identity,
        );
        assert.equal(
          result.recovered.find((row) => row.title === "Second review")!
            .identity.instance,
          "second-review-3",
        );
      });
    }
  }
}

for (const sameTitle of [false, true]) {
  test(`bound owner overrides shared metadata sameTitle=${sameTitle}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const workers = [],
      findings = [];
    for (const [index, id] of ["worker-a", "worker-b"].entries()) {
      const workerRoot = path.join(recovered.root, id);
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const value = finding(
        sameTitle
          ? "Synthetic shared review"
          : `${index === 0 ? "First" : "Second"} review`,
        {
          provenance: {
            source: "local_plugin",
            candidateId: "candidate-1",
            workerId: "discovery",
          },
        },
      );
      await worker.writeFindings([value]);
      const saved = await readJson(workerRoot, "result.json");
      findings.push(...saved.findings);
      workers.push(savedWorker(workerRoot, id));
    }
    await normal.writeFindings(findings);
    const result = await recover({ workers });
    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}
for (const authored of [false, true]) {
  test(`bound owner keeps same worker metadata revision authored=${authored}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const workerRoot = path.join(recovered.root, "worker-a"),
      normalWorkerRoot = path.join(normal.root, "worker-a");
    await mkdir(workerRoot);
    await mkdir(normalWorkerRoot);
    const worker = draftFixture(workerRoot, "worker"),
      normalWorker = draftFixture(normalWorkerRoot, "worker");
    for (const alias of ["discovery", "refined"]) {
      const value = finding("Synthetic shared review", {
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          workerId: alias,
        },
        ...(authored ? { identity: { anchor: "authored-review" } } : {}),
      });
      await normalWorker.writeFindings([value]);
      await worker.checkpoint(worker.findingsDraft([value]));
    }
    const saved = await readJson(normalWorkerRoot, "result.json");
    await normal.writeFindings(saved.findings);
    const result = await recover({
      workers: [savedWorker(workerRoot, "worker-a")],
    });
    assert.equal(result.normal.length, 1);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

for (const metadata of ["provenance", "extensions"] as const) {
  for (const shape of ["shared siblings", "reportId", "ledgerRowId"]) {
    test(`raw group authority preserves ${shape} with ${metadata} candidates`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const normalRoot = path.join(normal.root, "reviewer"),
        recoveredRoot = path.join(recovered.root, "reviewer");
      for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
      const writer = draftFixture(normalRoot, "worker"),
        interrupted = draftFixture(recoveredRoot, "worker");
      const first = finding("First review");
      first[metadata] = { ...first[metadata], candidateId: "candidate-1" };
      if (shape === "shared siblings")
        first.extensions = { ...first.extensions, ledgerRowId: "ledger-1" };
      const second = { ...structuredClone(first), title: "Second review" };
      const initial = shape === "shared siblings" ? [first, second] : [first];
      const revised = {
        ...(shape === "shared siblings" ? second : first),
        summary: "Revised evidence.",
        severity: { level: "high" },
        ...(shape === "shared siblings"
          ? {}
          : {
              locations: [{ path: "src/example.py", startLine: 1, endLine: 2 }],
              extensions: { ...first.extensions, [shape]: "report-1" },
            }),
      };
      for (const worker of [writer, interrupted])
        await worker.writeFindings(initial);
      await dateDraftFiles(recoveredRoot, 100);
      const update = writer.findingsDraft([revised]);
      await writer.write(update);
      await interrupted.checkpoint(update);
      await utimes(
        path.join(recoveredRoot, "checkpoints", checkpointName(update)),
        200,
        200,
      );
      const saved = await readJson(normalRoot, "result.json");
      assert.equal(saved.findings.length, initial.length);
      await normal.writeFindings(withWorkerId(saved.findings, "reviewer"));
      const result = await recover({
        workers: [savedWorker(recoveredRoot)],
        details: true,
        replay: true,
      });
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
      assert.equal(result.normal.length, initial.length);
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const authored of [false, true]) {
    test(`${layout}: canonical group retains ownership enrichment (authored=${authored})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const initial = finding("Synthetic ownership", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        ...(authored ? { identity: { anchor: "authored-review" } } : {}),
      });
      for (const writer of [normal, recovered])
        await writer.writeFindings([initial]);
      await dateDraftFiles(recovered.root, 100);
      const revised = {
        ...initial,
        provenance: { ...initial.provenance, workerId: "reviewer" },
      };
      const update = normal.findingsDraft([revised]);
      await normal.write(update);
      await saveCheckpointAt(recovered, update, 200);
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const metadata of ["provenance", "extensions"] as const) {
    test(`${layout}: reciprocal containment preserves ${metadata} sibling identities`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("Synthetic review");
      first[metadata] = { ...first[metadata], candidateId: "candidate-1" };
      const second = {
        ...structuredClone(first),
        extensions: { ...first.extensions, reportId: "report-1" },
      };
      for (const writer of [normal, recovered])
        await writer.writeFindings([first, second]);
      const before = await readJson(normal.root, "findings.json");
      await dateDraftFiles(recovered.root, 100);
      const update = normal.findingsDraft([
        { ...first, summary: "Revised evidence." },
        second,
      ]);
      await normal.write(update);
      const saved = await readJson(normal.root, "findings.json");
      assert.equal(saved.findings.length, 2);
      assert.deepEqual(
        saved.findings.map((row: FixtureFinding) => row.identity),
        before.findings.map((row: FixtureFinding) => row.identity),
      );
      await saveCheckpointAt(recovered, update, 200);
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 2);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}
const revisionFinding = (level: string, summary: string) =>
  finding("Synthetic review", {
    identity: { anchor: "candidate-1" },
    severity: { level },
    summary,
    provenance: {
      source: "local_plugin",
      candidateId: "candidate-1",
      workerId: "reviewer",
    },
  });
for (const source of ["selected checkpoint", "published result"]) {
  test(`finding precedence retains ${source} at tied timestamps`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const output = path.join(recovered.root, "reviewer");
    await mkdir(output);
    const worker = draftFixture(output, "worker");
    const initial = worker.findingsDraft(
      [revisionFinding("low", "Initial evidence.")],
      { complete: true },
    );
    const latest = worker.findingsDraft(
      [revisionFinding("high", "Completed evidence.")],
      { complete: true },
    );
    await worker.write(initial);
    await worker.write(latest);
    const saved = await readJson(output, "result.json");
    await normal.writeFindings(saved.findings, { complete: true });
    // Valid JSON whitespace controls filename order without changing the evidence.
    const names = await readdir(path.join(output, "checkpoints"));
    let contents = JSON.stringify(initial),
      name = "";
    do {
      contents += "\n";
      name = createHash("sha256").update(contents).digest("hex") + ".json";
    } while (names.some((existing) => existing > name));
    await writeFile(path.join(output, "checkpoints", name), contents);
    if (source === "published result") {
      const { rm } = await import("node:fs/promises");
      await rm(path.join(output, "checkpoint-head.json"));
    }
    await dateDraftFiles(output, 100);
    const result = await recover({
      workers: [savedWorker(output)],
      details: true,
      replay: true,
    });
    assert.equal(result.normal[0].severity.level, "high");
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}
for (const layout of ["standard", "diff", "worker"] as const) {
  test(`${layout}: finding precedence retains terminal evidence over later progress`, async (t) => {
    const parentLayout = layout === "worker" ? "deep" : layout;
    const { normal, recovered, recover } = await recoveryPair(t, parentLayout);
    const normalRoot =
      layout === "worker" ? path.join(normal.root, "reviewer") : normal.root;
    const recoveredRoot =
      layout === "worker"
        ? path.join(recovered.root, "reviewer")
        : recovered.root;
    if (layout === "worker")
      for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
    const writer =
      layout === "worker" ? draftFixture(normalRoot, "worker") : normal;
    const interrupted =
      layout === "worker" ? draftFixture(recoveredRoot, "worker") : recovered;
    const terminal = writer.findingsDraft(
      [revisionFinding("high", "Completed evidence.")],
      { complete: true },
    );
    const progress = writer.findingsDraft([
      revisionFinding("low", "Incomplete progress."),
    ]);
    for (const f of [writer, interrupted]) await f.write(terminal);
    await dateDraftFiles(recoveredRoot, 100);
    await writer.write(progress);
    await saveCheckpointAt(interrupted, progress, 200);
    if (layout === "worker") {
      const saved = await readJson(normalRoot, "result.json");
      assert.equal(saved.findings[0].severity.level, "high");
      await normal.writeFindings(saved.findings, { complete: true });
    }
    const result = await recover({
      workers: layout === "worker" ? [savedWorker(recoveredRoot)] : [],
      details: true,
      replay: true,
    });
    assert.equal(result.normal[0].severity.level, "high");
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
    assert.ok(result.historySummaries.includes("Incomplete progress."));
  });
}
test("finding precedence compares parent and worker observation times", async (t) => {
  const { normal, recovered, recover } = await recoveryPair(t, "deep");
  const workerRoot = path.join(recovered.root, "reviewer");
  await mkdir(workerRoot);
  const worker = draftFixture(workerRoot, "worker");
  await worker.writeFindings(
    [revisionFinding("low", "Earlier worker evidence.")],
    { complete: true },
  );
  const latest = normal.findingsDraft(
    [revisionFinding("high", "Newer parent evidence.")],
    { complete: true },
  );
  for (const f of [normal, recovered]) await f.write(latest);
  await dateDraftFiles(recovered.root, 200);
  await dateDraftFiles(workerRoot, 100);
  const result = await recover({
    workers: [savedWorker(workerRoot)],
    details: true,
    replay: true,
  });
  assert.deepEqual(result.recovered, result.normal);
  assert.deepEqual(result.warnings, []);
});
for (const revised of [false, true]) {
  test(`finding revision retains the published collision identity (revised=${revised})`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    const findings = [1, 2].map((line) =>
      finding(`Synthetic report ${line}`, {
        identity: { anchor: "shared" },
        locations: [{ path: "src/example.py", startLine: line }],
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          workerId: "reviewer",
        },
      }),
    );
    const workerRoot = path.join(recovered.root, "reviewer");
    await mkdir(workerRoot);
    const worker = draftFixture(workerRoot, "worker");
    await worker.writeFindings(findings, { complete: true });
    for (const f of [normal, recovered])
      await f.writeFindings(findings, { complete: true });
    await dateDraftFiles(recovered.root, 100);
    const latest = findings.map((row) => ({
      ...row,
      summary: revised ? "Updated evidence." : row.summary,
    }));
    await worker.write({
      ...worker.draft({}, true),
      findings: latest,
      threatModel: { summary: "New context." },
    });
    if (revised) await normal.writeFindings(latest, { complete: true });
    const result = await recover({
      workers: [savedWorker(workerRoot)],
      details: true,
      replay: true,
    });
    assert.equal(result.normal[1].identity.instance, "saved-2");
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

test("finding precedence keeps a resumed worker revision despite newer archive timestamps", async (t) => {
  const { normal, recovered, recover } = await recoveryPair(t, "deep");
  const output = path.join(recovered.root, "reviewer"),
    archive = path.join(output, "attempts", "attempt-1");
  await mkdir(archive, { recursive: true });
  const oldWorker = draftFixture(archive, "worker"),
    currentWorker = draftFixture(output, "worker");
  await oldWorker.writeFindings(
    [revisionFinding("high", "Archived assessment.")],
    { complete: true },
  );
  const latest = currentWorker.findingsDraft(
    [revisionFinding("low", "Corrected resumed assessment.")],
    { complete: true },
  );
  await currentWorker.write(latest);
  await normal.writeFindings(latest.findings, { complete: true });
  await dateDraftFiles(output, 100);
  await dateDraftFiles(archive, 200);
  const result = await recover({
    workers: [{ ...savedWorker(output), attempt: 2 }],
    details: true,
    replay: true,
  });
  assert.deepEqual(result.recovered, result.normal);
  assert.deepEqual(result.warnings, []);
});

test("finding precedence excludes archived attempts before comparing a parent revision", async (t) => {
  const { normal, recovered, recover } = await recoveryPair(t, "deep");
  const output = path.join(recovered.root, "reviewer"),
    archive = path.join(output, "attempts", "attempt-1");
  await mkdir(archive, { recursive: true });
  const oldWorker = draftFixture(archive, "worker"),
    currentWorker = draftFixture(output, "worker");
  await oldWorker.writeFindings(
    [revisionFinding("low", "Archived assessment.")],
    { complete: true },
  );
  await currentWorker.writeFindings(
    [revisionFinding("low", "Current worker assessment.")],
    { complete: true },
  );
  const latest = normal.findingsDraft(
    [revisionFinding("high", "Newer parent assessment.")],
    { complete: true },
  );
  for (const f of [normal, recovered]) await f.write(latest);
  await dateDraftFiles(recovered.root, 150);
  await dateDraftFiles(output, 100);
  await dateDraftFiles(archive, 200);
  const result = await recover({
    workers: [{ ...savedWorker(output), attempt: 2 }],
    details: true,
    replay: true,
  });
  assert.deepEqual(result.recovered, result.normal);
  assert.deepEqual(result.warnings, []);
});

for (const reverse of [false, true]) {
  test(`worker raw checkpoint retains ambiguous candidate siblings (reverse=${reverse})`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "deep");
    for (const f of [normal, recovered])
      await mkdir(path.join(f.root, "reviewer"));
    const writer = draftFixture(path.join(normal.root, "reviewer"), "worker"),
      recoveryWriter = draftFixture(
        path.join(recovered.root, "reviewer"),
        "worker",
      );
    const first = finding("First independent review", {
      provenance: { source: "local_plugin", candidateId: "shared-candidate" },
    });
    const second = { ...first, title: "Second independent review" };
    const revised = {
      ...first,
      title: "New review",
      summary: "New synthetic evidence.",
    };
    const ordered = (rows: FixtureFinding[]) =>
      reverse ? [...rows].reverse() : rows;
    for (const f of [writer, recoveryWriter])
      await f.writeFindings(ordered([first, second]));
    await dateDraftFiles(recoveryWriter.root, 100);
    await writer.writeFindings(ordered([revised, second]));
    const published = await readJson(writer.root, "result.json");
    assert.equal(published.findings.length, 3);
    await interruptDraftWrite(
      path.join(recoveryWriter.root, "checkpoints", checkpointName(published)),
      () => recoveryWriter.writeFindings(ordered([revised, second])),
    );
    const files = [
      "result.json",
      "checkpoint-head.json",
      ...(await readdir(path.join(recoveryWriter.root, "checkpoints"))).map(
        (name) => path.join("checkpoints", name),
      ),
    ];
    const originals = await Promise.all(
      files.map((name) => readFile(path.join(recoveryWriter.root, name))),
    );
    await normal.writeFindings(withWorkerId(published.findings, "reviewer"));
    const result = await recover({
      workers: [savedWorker(recoveryWriter.root)],
      details: true,
      replay: true,
    });
    assert.equal(result.normal.length, 3);
    assert.equal(result.recovered.length, 3);
    const byTitle = (rows: RecoveredFinding[]) =>
      [...rows].sort((a, b) => a.title.localeCompare(b.title));
    assert.deepEqual(byTitle(result.recovered), byTitle(result.normal));
    assert.deepEqual(result.warnings, []);
    for (const [index, name] of files.entries())
      assert.deepEqual(
        await readFile(path.join(recoveryWriter.root, name)),
        originals[index],
      );
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const reverse of [false, true]) {
    for (const published of [false, true]) {
      test(`one-to-one ${layout} unreported revision (published=${published}, reverse=${reverse})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, layout);
        const first = finding("First review");
        const revised = {
          ...first,
          summary: "Revised synthetic evidence.",
          severity: { level: "high" },
        };
        const second = finding("Independent review", {
          extensions: { reportId: "report-2" },
        });
        const initial = normal.findingsDraft([first]);
        await normal.write(initial);
        if (published) await recovered.writeFindings([first]);
        else await recovered.checkpoint(recovered.findingsDraft([first]));
        await dateDraftFiles(recovered.root, 100);
        const rows = reverse ? [second, revised] : [revised, second];
        await normal.writeFindings(rows);
        const update = recovered.findingsDraft(rows);
        await saveCheckpointAt(recovered, update, 200);
        const result = await recover({ details: true, replay: true });
        assert.equal(result.normal.length, 2);
        assert.equal(result.recovered.length, 2);
        const ordered = (values: RecoveredFinding[]) =>
          [...values].sort((a, b) => a.title.localeCompare(b.title));
        assert.deepEqual(ordered(result.recovered), ordered(result.normal));
        assert.deepEqual(result.warnings, []);
      });
    }
    test(`one-to-one ${layout} historical siblings (reverse=${reverse})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("Synthetic review", {
        extensions: { candidateId: "candidate-1" },
      });
      const second = {
        ...structuredClone(first),
        locations: [{ path: "src/example.py", startLine: 2 }],
      };
      const finalRows = reverse ? [second, first] : [first, second];
      for (const [index, rows] of [[first], [second], finalRows].entries()) {
        await normal.writeFindings(rows);
        const update = recovered.findingsDraft(rows);
        await saveCheckpointAt(recovered, update, (index + 1) * 100);
      }
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, 2);
      const ordered = (values: RecoveredFinding[]) =>
        [...values].sort(
          (a, b) => a.locations[0]!.startLine - b.locations[0]!.startLine,
        );
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const [field, value] of Object.entries({
  description: "Synthetic annotation",
  source: "authored",
  version: 1,
})) {
  for (const reservedFirst of [false, true]) {
    test(`worker collision reserves semantic ${field} identity (reserved first=${reservedFirst})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const workers = [],
        findings = [];
      for (const index of reservedFirst ? [2, 0, 1] : [0, 1, 2]) {
        const id = `worker-${index}`;
        const workerRoot = path.join(recovered.root, id);
        await mkdir(workerRoot);
        const worker = draftFixture(workerRoot, "worker");
        const row = finding(`Review ${index}`, {
          identity: {
            anchor: "shared",
            ...(index === 2 ? { instance: "saved-2", [field]: value } : {}),
          },
          locations: [{ path: "src/example.py", startLine: index + 1 }],
          provenance: {
            source: "local_plugin",
            candidateId: "candidate-1",
            workerId: id,
          },
        });
        await worker.writeFindings([row]);
        findings.push(row);
        workers.push(savedWorker(workerRoot, id));
      }
      await normal.writeFindings(findings);
      const result = await recover({ workers, details: true, replay: true });
      assert.equal(result.normal.length, 3);
      assert.equal(result.recovered.length, 3);
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.title.localeCompare(b.title));
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(
        result.recovered.find((row) => row.title === "Review 2")!.identity,
        { anchor: "shared", instance: "saved-2", [field]: value },
      );
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const metadata of ["extensions", "provenance"] as const) {
    for (const reversed of [false, true]) {
      test(`${layout}: unchanged report precedes ${metadata} enrichment matching (reversed=${reversed})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, layout);
        const first = finding("Synthetic review");
        const sibling = {
          ...structuredClone(first),
          [metadata]: { ...first[metadata], candidateId: "candidate-1" },
        };
        await normal.writeFindings([first]);
        await recovered.checkpoint(recovered.findingsDraft([first]));
        await dateDraftFiles(recovered.root, 100);
        const rows = reversed ? [sibling, first] : [first, sibling];
        await normal.writeFindings(rows);
        const update = recovered.findingsDraft(rows);
        await saveCheckpointAt(recovered, update, 200);
        const result = await recover({ details: true, replay: true });
        assert.equal(result.normal.length, 2);
        assert.equal(result.recovered.length, 2);
        const ordered = (rows: RecoveredFinding[]) =>
          [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
        assert.deepEqual(ordered(result.recovered), ordered(result.normal));
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const candidate of [false, true]) {
    for (const reversed of [false, true]) {
      test(`${layout}: ambiguous unmatched sibling survives exact batch assignment (reversed=${reversed}, candidate=${candidate})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, layout);
        const first = finding("First review"),
          second = finding("Second review"),
          added = finding(
            "Added review",
            candidate
              ? {
                  provenance: {
                    source: "local_plugin",
                    candidateId: "new-candidate",
                  },
                }
              : {},
          );
        for (const f of [normal, recovered]) {
          await f.writeFindings([first, second]);
          await dateDraftFiles(f.root, 100);
        }
        const rows = reversed ? [added, second] : [second, added];
        await normal.writeFindings(rows);
        const update = recovered.findingsDraft(rows);
        await saveCheckpointAt(recovered, update, 200);
        const result = await recover({ details: true, replay: true });
        assert.equal(result.normal.length, 3);
        assert.equal(result.recovered.length, 3);
        const ordered = (rows: RecoveredFinding[]) =>
          [...rows].sort((a, b) => a.title.localeCompare(b.title));
        assert.deepEqual(ordered(result.recovered), ordered(result.normal));
        assert.deepEqual(result.warnings, []);
      });
    }
  }
  for (const field of ["reportId", "ledgerRowId"]) {
    test(`${layout}: compatible ${field} enrichment identifies its existing sibling`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("First review"),
        second = finding("Second review");
      for (const f of [normal, recovered]) {
        await f.writeFindings([first, second]);
        await dateDraftFiles(f.root, 100);
      }
      const refined = { ...first, extensions: { [field]: "report-1" } };
      await normal.writeFindings([refined]);
      const update = recovered.findingsDraft([refined]);
      await saveCheckpointAt(recovered, update, 200);
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, 2);
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.title.localeCompare(b.title));
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}
for (const field of ["description", "source", "version"]) {
  for (const candidate of [false, true]) {
    test(`worker identity ${field} annotation revision keeps one report (candidate=${candidate})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const workerRoot = path.join(recovered.root, "reviewer");
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const first = finding("Synthetic review", {
        identity: {
          anchor: "authored",
          instance: "report-1",
          [field]: "initial",
        },
        provenance: {
          source: "local_plugin",
          workerId: "reviewer",
          ...(candidate ? { candidateId: "candidate-1" } : {}),
        },
      });
      await worker.writeFindings([first]);
      await dateDraftFiles(workerRoot, 100);
      const revised = {
        ...first,
        identity: { ...first.identity, [field]: "revised" },
      };
      await worker.writeFindings([revised]);
      const saved = await readJson(workerRoot, "result.json");
      await normal.writeFindings(saved.findings);
      const workers = [savedWorker(workerRoot)];
      const result = await recover({ workers, details: true, replay: true });
      assert.equal(result.normal.length, 1);
      assert.equal(result.recovered.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.equal(result.recovered[0]!.identity[field], "revised");
      assert.deepEqual(result.warnings, []);
    });
  }
}
for (const metadata of ["extensions", "provenance"] as const) {
  for (const malformedFirst of [false, true]) {
    test(`discarded ${metadata} sibling cannot change a valid identity (malformed first=${malformedFirst})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const workerRoot = path.join(recovered.root, "reviewer");
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const row = finding("Synthetic review");
      row[metadata] = { ...row[metadata], candidateId: "candidate-1" };
      row.provenance = { ...row.provenance, workerId: "reviewer" };
      await worker.writeFindings([row]);
      await dateDraftFiles(workerRoot, 100);
      await normal.writeFindings([row]);
      const { summary: _summary, ...malformed } = {
        ...structuredClone(row),
        locations: [{ path: "src/example.py", startLine: 2 }],
      };
      const resultFile = path.join(workerRoot, "result.json");
      const saved = await readJson(resultFile);
      saved.findings = malformedFirst ? [malformed, row] : [row, malformed];
      await writeFile(resultFile, JSON.stringify(saved));
      await utimes(resultFile, 200, 200);
      const workers = [savedWorker(workerRoot)];
      const result = await recover({ workers, details: true, replay: true });
      assert.equal(result.normal.length, 1);
      assert.equal(result.recovered.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.ok(result.warnings.length > 0);
    });
  }
}

for (const field of ["description", "source", "version"]) {
  for (const candidate of [false, true]) {
    for (const order of ["earlier-first", "later-first"]) {
      test(`worker identity ${field} annotation revision survives checkpoint order (${order}, candidate=${candidate})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, "deep");
        const normalRoot = path.join(normal.root, "reviewer"),
          recoveredRoot = path.join(recovered.root, "reviewer");
        for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
        const worker = draftFixture(normalRoot, "worker"),
          recoveryWorker = draftFixture(recoveredRoot, "worker");
        const first = finding("Synthetic review", {
          identity: {
            anchor: "authored",
            instance: "report-1",
            [field]: "initial",
          },
          provenance: {
            source: "local_plugin",
            workerId: "reviewer",
            ...(candidate ? { candidateId: "candidate-1" } : {}),
          },
        });
        const revised = {
          ...first,
          summary: "Revised synthetic assessment.",
          severity: { level: "high" },
          identity: { ...first.identity, [field]: "revised" },
        };
        const oldDraft = worker.findingsDraft([first]);
        let newDraft,
          suffix = 0;
        do {
          newDraft = {
            ...worker.draft(),
            findings: [revised],
            threatModel: { summary: `Synthetic checkpoint ${suffix++}.` },
          };
        } while (
          checkpointName(oldDraft) < checkpointName(newDraft) !==
          (order === "earlier-first")
        );
        for (const [index, draft] of [oldDraft, newDraft].entries()) {
          await worker.write(draft);
          await saveCheckpointAt(recoveryWorker, draft, 100 + index * 100);
        }
        const saved = await readJson(normalRoot, "result.json");
        assert.equal(saved.findings.length, 1);
        assert.equal(saved.findings[0].identity[field], "revised");
        await normal.writeFindings(saved.findings);
        const workers = [savedWorker(recoveredRoot)];
        const result = await recover({ workers, details: true, replay: true });
        assert.equal(result.normal.length, 1);
        assert.equal(result.recovered.length, 1);
        assert.deepEqual(result.recovered, result.normal);
        assert.equal(result.recovered[0]!.identity[field], "revised");
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}
for (const layout of ["standard", "diff", "deep"] as const) {
  for (const metadata of ["extensions", "provenance"] as const) {
    test(`${layout}: malformed canonical ${metadata} sibling cannot alter valid identity or frozen replay`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const valid = finding("Synthetic review");
      valid[metadata] = { ...valid[metadata], candidateId: "candidate-1" };
      for (const f of [normal, recovered]) await f.writeFindings([valid]);
      const destination = path.join(recovered.root, "findings.json");
      const document = await readJson(destination);
      const { summary: _summary, ...invalid } = {
        ...valid,
        locations: [{ path: "src/example.py", startLine: 2 }],
      };
      document.findings = [valid, invalid];
      await writeFile(destination, JSON.stringify(document));
      await rm(path.join(recovered.root, "checkpoints"), {
        recursive: true,
        force: true,
      });
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.equal(result.warnings.length, 1);
      assert.match(String(result.warnings[0]), /summary/);
    });
  }
}
for (const sameLocation of [false, true]) {
  for (const level of ["low", "high"]) {
    test(`absorbed worker report keeps independent candidate sibling (same location=${sameLocation}, ${level})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const workerRoot = path.join(recovered.root, "reviewer");
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const first = finding("First review", {
        summary: "Original first assessment.",
        severity: { level: "medium" },
        provenance: {
          source: "local_plugin",
          workerId: "reviewer",
          candidateId: "shared-candidate",
        },
      });
      const second = {
        ...first,
        title: "Independent second review",
        summary: "Independent second assessment.",
        severity: { level },
        locations: [
          { path: "src/example.py", startLine: sameLocation ? 1 : 20 },
        ],
      };
      const parent = {
        ...first,
        identity: { anchor: "shared-candidate" },
        summary: "Consolidated first assessment.",
        provenance: {
          ...first.provenance,
          sourceFindingIds: ["reviewer:0"],
          sourceFindings: [{ id: "reviewer:0", finding: first }],
        },
      };
      await worker.writeFindings([first], { complete: true });
      await dateDraftFiles(workerRoot, 100);
      for (const f of [normal, recovered])
        await f.writeFindings([parent], { complete: true });
      await dateDraftFiles(recovered.root, 200);
      await dateDraftFiles(workerRoot, 100);
      const checkpoint = worker.findingsDraft([first, second]);
      await saveCheckpointAt(worker, checkpoint, 300);
      await normal.writeFindings([parent, second], { complete: true });
      const result = await recover({
        workers: [savedWorker(workerRoot)],
        details: true,
        replay: true,
      });
      assert.equal(result.normal.length, 2);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}
for (const layout of ["standard", "diff", "deep", "worker"] as const) {
  for (const update of ["omitted", "partial"] as const) {
    test(`${layout}: accepted provenance arrays survive ${update} checkpoint details`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(
        t,
        layout === "worker" ? "deep" : layout,
      );
      let normalWriter = normal,
        recoveredWriter = recovered;
      const workers: Record<string, unknown>[] = [];
      if (layout === "worker") {
        const normalRoot = path.join(normal.root, "reviewer"),
          recoveredRoot = path.join(recovered.root, "reviewer");
        for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
        normalWriter = draftFixture(normalRoot, "worker");
        recoveredWriter = draftFixture(recoveredRoot, "worker");
        workers.push(savedWorker(recoveredRoot));
      }
      const raw = finding("Synthetic finding", {
        identity: { anchor: "stable" },
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          ...(layout === "worker" ? { workerId: "reviewer" } : {}),
        },
      });
      const source = { ...raw, summary: "Original source evidence." };
      const history = { ...raw, summary: "Previously accepted assessment." };
      const first = {
        ...raw,
        provenance: {
          ...raw.provenance,
          sourceFindingIds: ["origin:0", "origin:1"],
          sourceFindings: [
            { id: "origin:0", finding: source },
            {
              id: "origin:1",
              finding: { ...source, summary: "Additional source evidence." },
            },
          ],
          originalCandidates: [
            { id: "candidate-1", summary: "Original candidate evidence." },
          ],
          previousFindings: [history],
        },
      };
      const revised =
        update === "omitted"
          ? raw
          : {
              ...raw,
              provenance: {
                ...raw.provenance,
                sourceFindingIds: ["origin:2", "origin:0"],
                sourceFindings: [
                  {
                    id: "origin:2",
                    finding: { ...source, summary: "New source evidence." },
                  },
                  first.provenance.sourceFindings[0],
                ],
                originalCandidates: [
                  { id: "candidate-1", summary: "Updated candidate evidence." },
                  ...first.provenance.originalCandidates,
                ],
                previousFindings: [
                  { ...history, summary: "New historical assessment." },
                  history,
                ],
              },
            };
      for (const writer of [normalWriter, recoveredWriter])
        await writer.writeFindings([first]);
      await dateDraftFiles(recoveredWriter.root, 100);
      await normalWriter.writeFindings([revised]);
      const checkpoint = recoveredWriter.findingsDraft([revised]);
      await saveCheckpointAt(recoveredWriter, checkpoint, 200);
      if (layout === "worker") {
        const accepted = await readJson(normalWriter.root, "result.json");
        await normal.writeFindings(accepted.findings);
      }
      const result = await recover({
        workers,
        details: true,
        replay: true,
        provenanceDetails: true,
      });
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}
for (const layout of ["standard", "diff", "deep", "worker"] as const) {
  for (const field of ["reportId", "ledgerRowId"] as const) {
    test(`${layout}: revised sibling keeps identity through ${field} enrichment`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(
        t,
        layout === "worker" ? "deep" : layout,
      );
      let normalWriter = normal,
        recoveredWriter = recovered;
      const workers: Record<string, unknown>[] = [];
      if (layout === "worker") {
        const normalRoot = path.join(normal.root, "reviewer"),
          recoveredRoot = path.join(recovered.root, "reviewer");
        for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
        normalWriter = draftFixture(normalRoot, "worker");
        recoveredWriter = draftFixture(recoveredRoot, "worker");
        workers.push(savedWorker(recoveredRoot));
      }
      const first = finding(
        "First review",
        layout === "worker"
          ? { provenance: { source: "local_plugin", workerId: "reviewer" } }
          : {},
      );
      const second = { ...first, title: "Second review" };
      for (const writer of [normalWriter, recoveredWriter])
        await writer.writeFindings([first, second]);
      await dateDraftFiles(recoveredWriter.root, 100);
      const revised = {
        ...first,
        summary: "Revised assessment.",
        severity: { level: "high" },
        extensions: { [field]: "report-1" },
      };
      await normalWriter.writeFindings([revised]);
      const checkpoint = recoveredWriter.findingsDraft([revised]);
      await saveCheckpointAt(recoveredWriter, checkpoint, 200);
      if (layout === "worker") {
        const accepted = await readJson(normalWriter.root, "result.json");
        await normal.writeFindings(accepted.findings);
      }
      const result = await recover({ workers, details: true, replay: true });
      assert.equal(result.normal.length, 2);
      const sorted = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.title.localeCompare(b.title));
      assert.deepEqual(sorted(result.recovered), sorted(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const field of ["reportId", "ledgerRowId"]) {
    test(`${layout}: historical ${field} change does not resurrect raw checkpoint`, async (t) => {
      const f = await fixture(t, layout);
      const first = finding("Synthetic review", {
        extensions: { [field]: "old-report" },
      });
      await f.writeFindings([first]);
      const initial: FixtureFinding = (await readJson(f.root, "findings.json"))
        .findings[0];
      assert.ok(initial.identity);
      const revised = { ...initial, extensions: { [field]: "new-report" } };
      for (const input of [f.findingsDraft([revised]), f.draft()]) {
        await f.write(input);
        const saved: { findings: FixtureFinding[] } = await readJson(
          f.root,
          "findings.json",
        );
        assert.equal(saved.findings.length, 1);
        const retained = saved.findings[0]!;
        assert.deepEqual(retained.identity, initial.identity);
        assert.equal(retained.extensions?.[field], "new-report");
        const history = retained.provenance
          .previousFindings as FixtureFinding[];
        assert.ok(
          history.some((row) => row.extensions?.[field] === "old-report"),
        );
      }
    });
  }
}

for (const layout of ["standard", "diff", "worker"] as const) {
  for (const separateIdentity of [false, true]) {
    test(`${layout}: represented historical findings retain nested ancestry (separateIdentity=${separateIdentity})`, async (t) => {
      const f = await fixture(t, layout);
      const original = finding("Synthetic ancestry review", {
        identity: { anchor: "saved-report" },
        summary: "Original evidence.",
      });
      const ancestor = { ...original, summary: "Earlier source evidence." };
      await f.writeFindings([
        {
          ...original,
          provenance: {
            ...original.provenance,
            previousFindings: [ancestor],
          },
        },
      ]);
      const revised = {
        ...original,
        ...(separateIdentity ? { identity: { anchor: "revised-report" } } : {}),
        summary: "Revised evidence.",
        provenance: { ...original.provenance, previousFindings: [original] },
      };
      const containsAncestor = (value: unknown): boolean => {
        if (Array.isArray(value)) return value.some(containsAncestor);
        if (typeof value !== "object" || value === null) return false;
        const row = value as Record<string, unknown>;
        return (
          row.summary === ancestor.summary ||
          Object.values(row).some(containsAncestor)
        );
      };
      let saved: { findings: FixtureFinding[] };
      for (let replay = 0; replay < 2; replay++) {
        await f.writeFindings([revised]);
        saved = await readJson(
          f.root,
          layout === "worker" ? "result.json" : "findings.json",
        );
        assert.ok(
          containsAncestor(saved.findings),
          "Saved ancestry must survive the published revision and replay.",
        );
        const current = saved.findings.find(
          (row) => row.summary === revised.summary,
        )!;
        assert.deepEqual(current.identity, revised.identity);
      }
      const parent = layout === "worker" ? await fixture(t, "deep") : f;
      if (layout === "worker")
        await parent.writeFindings(saved!.findings, { complete: true });
      const finalized = await recoverAndFinalize(parent, parent, {
        details: true,
        replay: true,
        provenanceDetails: true,
      });
      assert.ok(containsAncestor(finalized.normal));
      assert.ok(containsAncestor(finalized.recovered));
      assert.deepEqual(finalized.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: sibling revisions preserve independent worker identities`, async (t) => {
    const f = await fixture(t, layout);
    const initial = ["First review", "Second review"].map((title, index) =>
      finding(title, {
        identity: { anchor: `saved-${index}` },
        provenance: {
          source: "local_plugin",
          candidateId: "shared-review",
          workerId: `worker-${index}`,
        },
      }),
    );
    await f.writeFindings(initial);
    const revised = initial.map(({ identity: _identity, ...row }, index) => ({
      ...row,
      title: index === 0 ? "Second review" : "Third review",
      summary: "Revised evidence.",
    }));
    for (let replay = 0; replay < 2; replay++) {
      await f.writeFindings(revised);
      const saved: { findings: FixtureFinding[] } = await readJson(
        f.root,
        "findings.json",
      );
      for (const previous of initial) {
        const retained = saved.findings.filter(
          (row) => row.identity?.anchor === previous.identity!.anchor,
        );
        assert.equal(retained.length, 1);
        assert.equal(
          retained[0]!.provenance.workerId,
          previous.provenance.workerId,
        );
      }
      for (const row of saved.findings) {
        for (const previous of (row.provenance.previousFindings ??
          []) as FixtureFinding[]) {
          assert.equal(previous.provenance.workerId, row.provenance.workerId);
        }
      }
    }
    const finalized = await recoverAndFinalize(f, f, {
      details: true,
      replay: true,
    });
    for (const rows of [finalized.normal, finalized.recovered]) {
      for (const previous of initial) {
        const retained = rows.filter(
          (row) => row.identity.anchor === previous.identity!.anchor,
        );
        assert.equal(retained.length, 1);
        assert.equal(retained[0]!.workerMetadata, previous.provenance.workerId);
      }
    }
    assert.deepEqual(finalized.warnings, []);
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const cut of ["raw", "published"]) {
    for (const reversed of [false, true]) {
      test(`${layout}: unchanged ownership selects its saved sibling (${cut}, reversed=${reversed})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, layout);
        const initial = finding("Synthetic ownership review", {
          provenance: { source: "local_plugin", candidateId: "candidate-1" },
        });
        const owned = {
          ...initial,
          provenance: { ...initial.provenance, workerId: "worker-a" },
        };
        await normal.writeFindings([initial]);
        const published = await readJson(normal.root, "findings.json");
        if (cut === "published") {
          await recovered.writeFindings([initial]);
        } else {
          await recovered.checkpoint(recovered.findingsDraft([initial]));
        }
        const findings = reversed ? [owned, initial] : [initial, owned];
        await normal.writeFindings(findings);
        if (cut === "published") {
          await interruptDraftWrite(
            path.join(recovered.root, "findings.json"),
            () => recovered.writeFindings(findings),
          );
        } else {
          await recovered.checkpoint(recovered.findingsDraft(findings));
        }
        const result = await recover({ details: true, replay: true });
        assert.equal(result.normal.length, 2);
        assert.equal(result.recovered.length, 2);
        const contents = (rows: RecoveredFinding[]) =>
          rows
            .map(
              ({
                identity: _identity,
                fingerprints: _fingerprints,
                findingId: _findingId,
                occurrenceId: _occurrenceId,
                ...row
              }) => row,
            )
            .sort((left, right) =>
              String(left.workerMetadata).localeCompare(
                String(right.workerMetadata),
              ),
            );
        assert.deepEqual(contents(result.recovered), contents(result.normal));
        assert.equal(
          new Set(result.recovered.map((row) => row.occurrenceId)).size,
          2,
        );
        assert.deepEqual(
          result.recovered.find((row) => row.workerMetadata === null)?.identity,
          published.findings[0].identity,
        );
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const layout of ["standard", "diff", "deep", "worker"] as const) {
  for (const candidate of [false, true]) {
    test(`${layout}: live revisions inherit the published identity from retained history (candidate=${candidate})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(
        t,
        layout === "worker" ? "deep" : layout,
      );
      let normalWriter = normal,
        recoveredWriter = recovered;
      const workers: Record<string, unknown>[] = [];
      if (layout === "worker") {
        const normalRoot = path.join(normal.root, "reviewer"),
          recoveredRoot = path.join(recovered.root, "reviewer");
        for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
        normalWriter = draftFixture(normalRoot, "worker");
        recoveredWriter = draftFixture(recoveredRoot, "worker");
        workers.push(savedWorker(recoveredRoot));
      }
      const original = finding("Synthetic historical revision", {
        identity: { anchor: "stable-report" },
        summary: "Original evidence.",
        provenance: {
          source: "local_plugin",
          ...(candidate ? { candidateId: "candidate-1" } : {}),
          ...(layout === "worker" ? { workerId: "reviewer" } : {}),
        },
      });
      const { identity: _identity, ...revised } = structuredClone(original);
      revised.summary = "Revised evidence.";
      revised.provenance.previousFindings = [original];
      for (const writer of [normalWriter, recoveredWriter])
        await writer.writeFindings([original]);
      for (let replay = 0; replay < 2; replay++) {
        await normalWriter.writeFindings([revised]);
        await interruptDraftWrite(
          path.join(
            recoveredWriter.root,
            layout === "worker" ? "result.json" : "findings.json",
          ),
          () => recoveredWriter.writeFindings([revised]),
        );
        if (layout === "worker") {
          const saved = await readJson(normalWriter.root, "result.json");
          await normal.writeFindings(saved.findings);
        }
        const result = await recover({ workers, details: true, replay: true });
        assert.equal(result.normal.length, 1);
        assert.deepEqual(result.normal[0]!.identity, original.identity);
        assert.equal(result.normal[0]!.summary, revised.summary);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(result.warnings, []);
      }
    });
  }
}

for (const layout of ["standard", "diff", "deep", "worker"] as const) {
  for (const history of [false, true]) {
    for (const reversed of [false, true]) {
      test(`${layout}: assigned siblings survive ambiguous matches (history=${history}, reversed=${reversed})`, async (t) => {
        const f = await fixture(t, layout);
        const original = finding("Synthetic shared review", {
          provenance: { source: "local_plugin", candidateId: "candidate-1" },
        });
        const first = {
          ...structuredClone(original),
          identity: { anchor: "shared-review", instance: "first" },
        };
        const sibling = history
          ? {
              ...structuredClone(original),
              identity: { anchor: "shared-review", instance: "second" },
            }
          : {
              ...structuredClone(original),
              title: "Independent shared-candidate review",
              summary: "Independent evidence remains active.",
            };
        await f.writeFindings(reversed ? [sibling, first] : [first, sibling]);
        const revised = {
          ...first,
          summary: "Revised evidence.",
          provenance: {
            ...first.provenance,
            ...(history ? { previousFindings: [original] } : {}),
          },
        };
        let previous: unknown;
        for (let replay = 0; replay < 2; replay++) {
          await f.writeFindings([revised]);
          const saved = await readJson(
            f.root,
            layout === "worker" ? "result.json" : "findings.json",
          );
          assert.equal(
            saved.findings.length,
            2,
            `Active findings after replay ${replay}`,
          );
          assert.equal(saved.findings[0].summary, revised.summary);
          const retained = saved.findings.find((row: FixtureFinding) =>
            history
              ? row.identity?.instance === "second"
              : row.summary === sibling.summary,
          );
          assert.ok(retained, "Independent evidence remains an active finding");
          if (previous) assert.deepEqual(saved.findings, previous);
          previous = saved.findings;
        }
      });
    }
  }
}

for (const evidence of ["identical", "distinct", "reordered"] as const) {
  for (const includeResult of [false, true]) {
    test(`unchanged worker batch retains ${evidence} provenance (result=${includeResult})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, "deep");
      const workerRoot = path.join(recovered.root, "reviewer");
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const findings = ["first", "second"].map((id) =>
        finding("Synthetic saved review", {
          provenance: {
            source: "local_plugin",
            candidateId: "candidate-1",
            originalCandidates: [
              { id: evidence === "identical" ? "same" : id },
            ],
          },
        }),
      );
      await worker.writeFindings(findings, { complete: true });
      if (evidence === "reordered")
        await worker.writeFindings([...findings].reverse(), { complete: true });
      const saved = await readJson(workerRoot, "result.json");
      assert.equal(saved.findings.length, 2);
      await normal.writeFindings(withWorkerId(saved.findings, "reviewer"), {
        complete: true,
      });
      if (!includeResult) await rm(path.join(workerRoot, "result.json"));
      const result = await recover({
        workers: [savedWorker(workerRoot)],
        details: true,
        replay: true,
        provenanceDetails: true,
      });
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, 2);
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "worker"] as const) {
  for (const cut of ["raw", "result"]) {
    for (const [metadata, preservedIdentity] of Object.entries({
      note: "Synthetic annotation",
      incomplete: { description: "Synthetic annotation" },
      valid: {
        anchor: "authored",
        description: "Synthetic identity annotation",
      },
    })) {
      test(`${layout}: preserved identity metadata ${metadata} survives ${cut} interruption`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(
          t,
          layout === "worker" ? "deep" : layout,
        );
        let writer: DraftFixture = normal,
          recoveryWriter: DraftFixture = recovered;
        if (layout === "worker") {
          for (const f of [normal, recovered])
            await mkdir(path.join(f.root, "reviewer"));
          writer = draftFixture(path.join(normal.root, "reviewer"), "worker");
          recoveryWriter = draftFixture(
            path.join(recovered.root, "reviewer"),
            "worker",
          );
        }
        const initial = finding("Synthetic preserved identity review", {
          identity:
            metadata === "valid" ? preservedIdentity : { anchor: "authored" },
          provenance: {
            source: "local_plugin",
            candidateId: "candidate-1",
            preservedIdentity,
            ...(layout === "worker" ? { workerId: "reviewer" } : {}),
          },
        });
        for (const f of [writer, recoveryWriter])
          await f.writeFindings([initial]);
        await dateDraftFiles(recoveryWriter.root, 100);
        const revised = {
          ...initial,
          summary: "Revised synthetic assessment.",
          severity: { level: "high" },
        };
        delete revised.identity;
        await writer.writeFindings([revised]);
        const filename = layout === "worker" ? "result.json" : "findings.json";
        if (cut === "raw")
          await recoveryWriter.checkpoint(
            recoveryWriter.findingsDraft([revised]),
          );
        else
          await interruptDraftWrite(
            path.join(recoveryWriter.root, filename),
            () => recoveryWriter.writeFindings([revised]),
          );
        const saved = await readJson(writer.root, filename);
        assert.equal(saved.findings.length, 1);
        assert.equal(saved.findings[0].severity.level, "high");
        assert.deepEqual(
          saved.findings[0].provenance.preservedIdentity,
          preservedIdentity,
        );
        if (layout === "worker") await normal.writeFindings(saved.findings);
        const result = await recover({
          workers:
            layout === "worker" ? [savedWorker(recoveryWriter.root)] : [],
          details: true,
          replay: true,
        });
        assert.deepEqual(result.preservedIdentities, [
          [preservedIdentity],
          [preservedIdentity],
        ]);
        assert.equal(result.normal.length, 1);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(result.warnings, []);
      });
    }
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const variant of [
    "legacy missing",
    "explicit same",
    "explicit changed",
  ] as const) {
    test(`${layout}: preserves canonical finding identity after revision (${variant})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const initial = finding("Synthetic review", {
        identity: {
          anchor: "stable-authored",
          instance: "report-1",
          description: "Saved annotation",
        },
      });
      for (const f of [normal, recovered]) await f.writeFindings([initial]);
      const revised = {
        ...structuredClone(initial),
        summary: "Revised synthetic evidence.",
      };
      if (variant === "legacy missing") delete revised.identity;
      if (variant === "explicit changed")
        revised.identity = {
          anchor: "new-authored",
          instance: "report-2",
          description: "Revised annotation",
        };
      await normal.writeFindings([revised]);
      const dest = path.join(recovered.root, "findings.json");
      const doc = await readJson(dest);
      doc.findings[0].summary = revised.summary;
      if (variant === "legacy missing") delete doc.findings[0].identity;
      else doc.findings[0].identity = revised.identity;
      await writeFile(dest, JSON.stringify(doc));
      // Canonical legacy documents accept an omitted identity; no newer raw checkpoint exists.
      const result = await recover({ details: true });
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
      const replay = await recover({ details: true, replay: true });
      assert.deepEqual(replay.recovered, result.recovered);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const)
  for (const reversed of [false, true]) {
    for (const historical of [false, true])
      test(`${layout}: explicit sibling assignment preserves revised identity (reverse=${reversed}, history=${historical})`, async (t) => {
        const { normal, recovered, recover } = await recoveryPair(t, layout);
        const first = finding("First review", {
          identity: { anchor: "saved-a" },
          provenance: {
            source: "local_plugin",
            candidateId: "shared-candidate",
          },
        });
        const second = {
          ...structuredClone(first),
          identity: { anchor: "saved-b" },
          title: "Second review",
        };
        const ordered = (rows: FixtureFinding[]) =>
          reversed ? rows.toReversed() : rows;
        for (const f of [normal, recovered])
          await f.writeFindings(ordered([first, second]));
        const revised = {
          ...structuredClone(first),
          title: "Revised first review",
          summary: "Updated first evidence.",
        };
        if (historical)
          revised.provenance.previousFindings = [structuredClone(first)];
        await normal.writeFindings(ordered([revised, second]));
        delete revised.identity;
        await recovered.writeFindings(ordered([revised, second]));
        const rows = (await readJson(recovered.root, "findings.json")).findings;
        assert.equal(rows.length, 2);
        assert.deepEqual(
          rows.find((row: FixtureFinding) => row.title === revised.title)
            .identity,
          first.identity,
        );
        assert.deepEqual(
          rows.find((row: FixtureFinding) => row.title === second.title)
            .identity,
          second.identity,
        );
        const result = await recover({ details: true, source: "published" });
        assert.equal(result.normal.length, 2);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(result.warnings, []);
      });
    test(`${layout}: truly ambiguous revised siblings retain independent reports (reverse=${reversed})`, async (t) => {
      const { normal, recovered, recover } = await recoveryPair(t, layout);
      const first = finding("First review", {
        identity: { anchor: "saved-a" },
        provenance: { source: "local_plugin", candidateId: "shared-candidate" },
      });
      const second = {
        ...structuredClone(first),
        identity: { anchor: "saved-b" },
        title: "Second review",
      };
      const revised = [
        {
          ...structuredClone(first),
          title: "New first review",
          summary: "New first evidence.",
        },
        {
          ...structuredClone(second),
          title: "New second review",
          summary: "New second evidence.",
        },
      ];
      for (const row of revised) delete row.identity;
      for (const f of [normal, recovered]) {
        await f.writeFindings(reversed ? [second, first] : [first, second]);
        await f.writeFindings(reversed ? revised.toReversed() : revised);
      }
      const rows = (await readJson(normal.root, "findings.json")).findings;
      assert.equal(rows.length, 4);
      assert.deepEqual(
        rows.find((row: FixtureFinding) => row.title === first.title).identity,
        first.identity,
      );
      assert.deepEqual(
        rows.find((row: FixtureFinding) => row.title === second.title).identity,
        second.identity,
      );
      const result = await recover({ details: true, replay: true });
      assert.equal(result.normal.length, 4);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }

for (const reversed of [false, true]) {
  test(`an explicit revision cannot absorb an unidentified worker sibling (reverse=${reversed})`, async (t) => {
    const f = await fixture(t, "worker");
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "shared-candidate" },
    });
    const second = {
      ...structuredClone(first),
      title: "Second review",
      summary: "Second evidence.",
    };
    await f.writeFindings(reversed ? [second, first] : [first, second]);
    const revised = {
      ...structuredClone(first),
      identity: { anchor: "saved-a" },
      summary: "Revised first evidence.",
    };
    await f.writeFindings([revised]);
    const { findings } = await readJson(f.root, "result.json");
    assert.equal(findings.length, 2);
    assert.deepEqual(
      findings.find((row: FixtureFinding) => row.title === first.title),
      {
        ...revised,
        provenance: { ...revised.provenance, previousFindings: [first] },
      },
    );
    assert.deepEqual(
      findings.find((row: FixtureFinding) => row.title === second.title),
      second,
    );
  });
}

for (const missing of [false, true]) {
  test(`standard: restored parent absorbs worker with missing identity=${missing}`, async (t) => {
    const { normal, recovered, recover } = await recoveryPair(t, "standard");
    const source = finding("Synthetic worker review", {
      provenance: { source: "local_plugin", candidateId: "worker-candidate" },
    });
    const parent = finding("Consolidated review", {
      identity: { anchor: "consolidated-review" },
      provenance: {
        source: "local_plugin",
        candidateId: "parent-candidate",
        sourceFindingIds: ["reviewer:0"],
        sourceFindings: [{ id: "reviewer:0", finding: source }],
      },
    });
    for (const f of [normal, recovered])
      await f.writeFindings([parent], { complete: true });
    if (missing) {
      const file = path.join(recovered.root, "findings.json");
      const saved = await readJson(file);
      delete saved.findings[0].identity;
      await writeFile(file, JSON.stringify(saved));
    }
    const workerRoot = path.join(recovered.root, "reviewer");
    await mkdir(workerRoot);
    const worker = draftFixture(workerRoot, "worker");
    await worker.writeFindings([source], { complete: true });
    for (const name of ["scan-manifest.json", "findings.json", "coverage.json"])
      await utimes(path.join(recovered.root, name), 2, 2);
    for (const name of await readdir(path.join(recovered.root, "checkpoints")))
      await utimes(path.join(recovered.root, "checkpoints", name), 1.5, 1.5);
    await utimes(path.join(workerRoot, "result.json"), 1, 1);
    const result = await recover({ workers: [savedWorker(workerRoot)] });
    assert.equal(result.normal.length, 1);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

for (const reversed of [false, true]) {
  for (const retained of [0, 1, 2]) {
    test(`worker: colliding authored identities retain independent findings (reversed=${reversed}, retained=${retained})`, async (t) => {
      const f = await fixture(t, "worker");
      const rows = [1, 2].map((line) =>
        finding("Synthetic shared review", {
          identity: { anchor: "shared-review" },
          locations: [{ path: "src/example.py", startLine: line }],
          provenance: { source: "local_plugin", candidateId: "candidate-1" },
        }),
      );
      await f.writeFindings(reversed ? rows.toReversed() : rows);
      for (let replay = 0; replay < 2; replay++) {
        await f.writeFindings(retained === 0 ? [] : [rows[retained - 1]!], {
          complete: true,
        });
        const saved = await readJson(f.root, "result.json");
        assert.equal(saved.findings.length, 2);
        assert.deepEqual(
          saved.findings
            .map((row: FixtureFinding) => row.locations[0]!.startLine)
            .sort(),
          [1, 2],
        );
      }
    });
  }
  for (const layout of ["standard", "diff", "worker"] as const) {
    for (const enriched of [false, true]) {
      test(`${layout}: content-only replay retains ambiguous saved identities (reversed=${reversed}, enriched=${enriched})`, async (t) => {
        const f = await fixture(t, layout);
        const raw = finding("Synthetic shared review", {
          provenance: { source: "local_plugin", candidateId: "candidate-1" },
        });
        const rows = ["first", "second"].map((instance) => ({
          ...structuredClone(raw),
          identity: { anchor: "shared-review", instance },
        }));
        await f.writeFindings(reversed ? rows.toReversed() : rows);
        for (let replay = 0; replay < 2; replay++) {
          const update = enriched
            ? { ...raw, extensions: { reportId: "report-1" } }
            : raw;
          await f.writeFindings([update], { complete: true });
          const saved = await readJson(
            f.root,
            layout === "worker" ? "result.json" : "findings.json",
          );
          assert.equal(saved.findings.length, 2);
          assert.deepEqual(
            saved.findings
              .map((row: FixtureFinding) => row.identity?.instance)
              .sort(),
            ["first", "second"],
          );
          if (enriched) {
            assert.ok(
              saved.findings.some(
                (row: FixtureFinding) =>
                  row.extensions?.reportId === "report-1",
              ),
            );
          }
        }
      });
    }
  }
}
