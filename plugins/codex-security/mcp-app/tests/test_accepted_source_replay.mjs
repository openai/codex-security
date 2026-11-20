import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { importSource } from "./import-module.ts";
import { readJson, writeJson } from "./support/json.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { mergeBatch } = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/iteration.ts"),
);
const directories = createTemporaryDirectories(true);
after(directories.cleanup);

// Synthetic accepted artifacts. Expected fixes are independent of display identities.
const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

const fixes = {
  owner: "Check document ownership before returning document contents.",
  path: "Resolve archive paths and reject entries outside the extraction directory.",
  sql: "Bind the search term as a SQL parameter.",
  html: "HTML-encode the search term before rendering the response.",
};

function finding(id, remediation, extra = {}) {
  return {
    ruleId: "synthetic." + id,
    identity: { anchor: id },
    title: "Request boundary " + id,
    summary: "A request-controlled value crosses an unchecked boundary.",
    severity: { level: "high" },
    confidence: {
      level: "high",
      rationale: "A synthetic local test reaches the sink.",
    },
    taxonomy: { category: "input-validation", cwe: ["CWE-20"] },
    locations: [{ path: "src/routes.py", startLine: 12, endLine: 14 }],
    remediation,
    provenance: { source: "local_plugin" },
    ...extra,
  };
}

function coverage(completeness = "complete", deferred = []) {
  return { completeness, surfaces: [], explicitExclusions: [], deferred };
}

function worker(id, findings, scanCoverage = coverage()) {
  return {
    id,
    result: { scanId, complete: true, findings, reviewState: scanCoverage },
  };
}

const workers = [
  worker(
    "worker-owner",
    [
      finding("owner", fixes.owner, {
        summary:
          "An authenticated user can read another user's document by changing its ID.",
        validation: {
          summary: "The ownership check is absent; authentication is required.",
        },
      }),
    ],
    coverage("partial", [
      {
        candidateId: "candidate-1",
        reason: "Check the alternate document handler.",
        paths: ["src/alternate.py"],
      },
    ]),
  ),
  worker(
    "worker-path",
    [finding("path", fixes.path)],
    coverage("partial", [
      {
        candidateId: "candidate-1",
        reason: "Check symlink extraction separately.",
        paths: ["src/archive.py"],
      },
    ]),
  ),
  worker("worker-owner-duplicate", [
    finding("owner-copy", fixes.owner, {
      summary: "Document contents may be reachable without authentication.",
      severity: { level: "critical" },
      confidence: {
        level: "low",
        rationale: "Authentication middleware was not examined.",
      },
      validation: {
        summary:
          "The unauthenticated claim is untested; ownership check is absent.",
      },
    }),
  ]),
  worker("worker-bundled", [
    finding("search-bundle", fixes.sql + " " + fixes.html, {
      summary:
        "The search route interpolates the query into SQL and separately into HTML.",
      locations: [{ path: "src/search.py", startLine: 5, endLine: 9 }],
    }),
  ]),
];

const originals = new Map(
  workers.flatMap(({ id, result }) =>
    result.findings.map((finding, index) => [`${id}:${index}`, finding]),
  ),
);

function permutations(items) {
  if (!items.length) return [[]];
  return items.flatMap((item, index) =>
    permutations(items.filter((_, i) => i !== index)).map((rest) => [
      item,
      ...rest,
    ]),
  );
}

function partitions(items) {
  if (!items.length) return [[]];
  return items.flatMap((_, index) =>
    partitions(items.slice(index + 1)).map((rest) => [
      items.slice(0, index + 1),
      ...rest,
    ]),
  );
}

async function compare(prompt, schema) {
  const rows = JSON.parse(prompt.split("\n").at(-1));
  if (schema.properties.reviews) return JSON.stringify({ reviews: [] });
  const groups = new Map();
  for (const { id, fix, locations } of rows) {
    const group = groups.get(fix) ?? {
      operation: fix,
      failure: fix,
      path: locations[0][0],
      reports: [],
    };
    group.reports.push({ id, evidence: 0 });
    groups.set(fix, group);
  }
  return JSON.stringify({ defects: [...groups.values()], uncertain: [] });
}

async function replay(root, batches) {
  const file = (id) =>
    path.join(
      root,
      "artifacts/deep_discovery/workers",
      id,
      "output/result.json",
    );
  for (const { id, result } of workers) {
    await mkdir(path.dirname(file(id)), { recursive: true });
    await writeJson(file(id), result);
  }
  let result = { scanId, findings: [] };
  for (const [index, batch] of batches.entries()) {
    const inputs = await Promise.all(
      batch.map(async ({ id }) => {
        const resultPath = file(id);
        return {
          id,
          resultPath,
          artifactDir: path.dirname(resultPath),
          result: await readJson(resultPath),
        };
      }),
    );
    await mergeBatch(result, inputs, root, compare, (error) => {
      throw error;
    });
    const checkpoint = path.join(root, `iteration-${index}.json`);
    await writeJson(checkpoint, result);
    result = await readJson(checkpoint);
  }
  for (const worker of workers)
    assert.deepEqual(await readJson(file(worker.id)), worker.result);
  return result;
}

test("accepted sources survive completion orders and eligible batch partitions", async () => {
  const root = await directories.create("accepted-source-replay-");
  let count = 0;
  for (const order of permutations(workers)) {
    for (const batches of partitions(order)) {
      // Ordinary rolling runs require two successes for the first merge.
      if (batches[0].length < 2) continue;
      const result = await replay(path.join(root, String(count++)), batches);
      assert.equal(result.findings.length, 3);
      const refs = result.findings.flatMap(
        (finding) => finding.provenance.sourceFindingIds,
      );
      assert.deepEqual(refs.toSorted(), [...originals.keys()].toSorted());
      for (const finding of result.findings) {
        for (const source of finding.provenance.sourceFindings) {
          assert.ok(originals.has(source.id));
          assert.deepEqual(source.finding, originals.get(source.id));
        }
      }
    }
  }
  assert.equal(count, 96);
});
