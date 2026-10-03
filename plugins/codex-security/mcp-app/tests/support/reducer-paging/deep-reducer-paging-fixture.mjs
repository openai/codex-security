import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";

// This is the existing code-mode transport ceiling, used only to size the eval.
const IPC_FRAME_LIMIT_BYTES = 64 * 1024 * 1024;
const SCAN_ID = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

/** Generate one reducer assignment; no repository scan or external service runs. */
export async function createReducerPagingFixture(root) {
  await mkdir(root, { recursive: true });
  const fixtureRoot = await realpath(root);
  const scanRoot = path.join(fixtureRoot, "scan");
  const deepRoot = path.join(scanRoot, "artifacts", "deep_discovery");
  const workerRoot = path.join(deepRoot, "workers", "discovery-0001", "output");
  const previousRoot = path.join(deepRoot, "dedup", "dedup-0001", "output");
  const outputRoot = path.join(deepRoot, "dedup", "dedup-0002", "output");
  await Promise.all(
    [workerRoot, previousRoot, outputRoot].map((directory) =>
      mkdir(directory, { recursive: true }),
    ),
  );

  const freshHtml = finding("reflected-html", {
    title: "Request text reaches an HTML response without encoding",
    summary: paddedSummary(IPC_FRAME_LIMIT_BYTES / 2),
    remediation: "HTML-encode request text at the response rendering boundary.",
  });
  const freshArchive = finding("archive-path", {
    title: "Archive entry paths escape the extraction directory",
    summary:
      "An independently reachable archive importer joins an untrusted entry path to the extraction directory without checking containment. This is unrelated to HTML rendering or database queries.",
    remediation:
      "Resolve each archive entry against the extraction directory and enforce containment before writing it.",
  });
  const previousOriginal = finding("query-injection", {
    title: "Account lookup interpolates request text into a database query",
    summary:
      "The account lookup builds a query by concatenating request-controlled text. Parameter binding is absent on this path.",
    remediation: "Use parameter binding for account lookup query values.",
  });
  const synthesizedHistory = finding("query-injection", {
    ...previousOriginal,
    summary:
      "Earlier synthesis also established that the transactional account lookup calls the same unsafe query builder. Both paths need the shared parameter-binding fix.",
  });
  const previousSourceId = "previous-worker:0";
  const previousCanonical = {
    ...previousOriginal,
    summary:
      "Account lookup and transactional lookup share a query builder that interpolates request text. A shared parameter-binding fix covers both reachable paths.",
    provenance: {
      ...previousOriginal.provenance,
      sourceFindingIds: [previousSourceId],
      sourceFindings: [{ id: previousSourceId, finding: previousOriginal }],
      previousFindings: [synthesizedHistory],
    },
  };
  const workerId = "current-worker";
  const currentFindings = [freshHtml, freshArchive];
  const expectedSources = new Map([
    ...currentFindings.map((value, index) => [`${workerId}:${index}`, value]),
    [previousSourceId, previousOriginal],
  ]);
  const sourceSha256ById = Object.fromEntries(
    [...expectedSources].map(([id, value]) => [id, canonicalSha256(value)]),
  );
  const result = {
    scanId: SCAN_ID,
    findings: currentFindings,
    scope: {
      summary: "Three independent synthetic request-processing issues.",
    },
  };
  const previous = {
    scanId: SCAN_ID,
    findings: [previousCanonical],
    threatModel: {
      summary:
        "Untrusted request inputs cross distinct output, filesystem, and query boundaries.",
    },
  };
  const workerPath = path.join(workerRoot, "result.json");
  const previousPath = path.join(previousRoot, "result.json");
  await writeFile(
    workerPath,
    JSON.stringify({
      ...result,
      coverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
  await writeFile(previousPath, JSON.stringify(previous));

  const logicalInputs = {
    discoveries: [
      {
        workerId,
        result: {
          ...result,
          findings: currentFindings.map((value, index) => ({
            ...value,
            provenance: {
              ...value.provenance,
              sourceFindingIds: [`${workerId}:${index}`],
            },
          })),
        },
      },
    ],
    previous,
  };
  const { bytes, stringEscapes } = jsonMetrics(logicalInputs);
  // The old response included JSON.stringify(inputs) as text and inputs again
  // as structuredContent. Count its exact bytes without allocating both copies.
  const envelopeBytes =
    Buffer.byteLength(
      JSON.stringify({
        content: [{ type: "text", text: "" }],
        structuredContent: null,
      }),
    ) - Buffer.byteLength("null");
  const legacyResponseBytes = envelopeBytes + bytes * 2 + stringEscapes;
  assert.ok(legacyResponseBytes > IPC_FRAME_LIMIT_BYTES);
  return {
    context: {
      root: outputRoot,
      repoRoot: fixtureRoot,
      scanId: SCAN_ID,
      layout: "reducer",
      deepReducer: {
        scanRoot,
        claimedWorkers: [{ id: workerId, resultPath: workerPath }],
        previousReducerResultPath: previousPath,
      },
    },
    resultPath: path.join(outputRoot, "result.json"),
    expected: {
      sourceSha256ById,
      sourceIdentityById: Object.fromEntries(
        [...expectedSources].map(([id, value]) => [id, value.identity]),
      ),
      previousSourceId,
      previousIdentity: previousOriginal.identity,
      historySha256: canonicalSha256(synthesizedHistory),
    },
    measurements: {
      ipcFrameLimitBytes: IPC_FRAME_LIMIT_BYTES,
      largeSemanticFieldBytes: Buffer.byteLength(freshHtml.summary),
      logicalInputBytes: bytes,
      legacyResponseBytes,
    },
  };
}

/** Fail on lost, duplicated, substituted, or de-identified reducer evidence. */
export async function gradeReducerPagingResult(fixture) {
  const result = JSON.parse(await readFile(fixture.resultPath, "utf8"));
  assert.equal(result.scanId, fixture.context.scanId);
  assert.notEqual(result.complete, false);
  assert.ok(Array.isArray(result.findings));
  const expectedIds = Object.keys(fixture.expected.sourceSha256ById).sort();
  assert.equal(
    result.findings.length,
    expectedIds.length,
    "the three independent issues must remain separate output findings",
  );
  const refs = [];
  const retainedIds = [];
  for (const finding of result.findings) {
    const provenance = finding.provenance;
    assert.ok(Array.isArray(provenance?.sourceFindingIds));
    assert.equal(
      provenance.sourceFindingIds.length,
      1,
      "each independent output finding must reference only its own source",
    );
    const [sourceId] = provenance.sourceFindingIds;
    assert.deepEqual(
      finding.identity,
      fixture.expected.sourceIdentityById[sourceId],
      `output identity must match its source ${sourceId}`,
    );
    assert.ok(Array.isArray(provenance?.sourceFindings));
    refs.push(...provenance.sourceFindingIds);
    assert.deepEqual(
      provenance.sourceFindings.map((source) => source.id).sort(),
      [...provenance.sourceFindingIds].sort(),
      "each output finding must retain exactly its attributed originals",
    );
    for (const source of provenance.sourceFindings) {
      assert.equal(
        canonicalSha256(source.finding),
        fixture.expected.sourceSha256ById[source.id],
        `original evidence changed for ${source.id}`,
      );
      retainedIds.push(source.id);
    }
  }
  assert.deepEqual(
    refs.sort(),
    expectedIds,
    "each assigned reference must occur exactly once",
  );
  assert.deepEqual(
    retainedIds.sort(),
    expectedIds,
    "each original must be retained exactly once",
  );
  const previous = result.findings.find((finding) =>
    finding.provenance.sourceFindingIds.includes(
      fixture.expected.previousSourceId,
    ),
  );
  assert.deepEqual(previous.identity, fixture.expected.previousIdentity);
  assert.ok(
    previous.provenance.previousFindings?.some(
      (history) => canonicalSha256(history) === fixture.expected.historySha256,
    ),
    "the prior synthesized history must survive losslessly",
  );
  return {
    findingCount: result.findings.length,
    accountedSourceCount: refs.length,
    preservedOriginalCount: retainedIds.length,
    previousIdentityPreserved: true,
    synthesizedHistoryPreserved: true,
  };
}

function finding(id, extra = {}) {
  return {
    ruleId: "synthetic." + id,
    identity: { anchor: id },
    title: "Synthetic finding " + id,
    summary: "An untrusted input reaches a sensitive operation.",
    severity: { level: "high" },
    confidence: { level: "high", rationale: "Synthetic validated fixture." },
    taxonomy: {
      category: id,
      cwe: [
        {
          "reflected-html": "CWE-79",
          "archive-path": "CWE-22",
          "query-injection": "CWE-89",
        }[id],
      ],
    },
    locations: [{ path: `src/${id}.ts`, startLine: 1, endLine: 2 }],
    remediation: "Apply the issue-specific boundary check.",
    provenance: { source: "local_plugin" },
    ...extra,
  };
}

function paddedSummary(bytes) {
  const beginning =
    "BEGIN ISSUE: Request text reaches an HTML response without encoding. The following repeated text is synthetic padding to exercise byte-aware paging, not additional evidence.\n";
  const ending =
    "\nEND ISSUE: The remedy is HTML encoding at the response boundary. Archive extraction and query interpolation are distinct issues requiring independent fixes.";
  const available =
    bytes - Buffer.byteLength(beginning) - Buffer.byteLength(ending);
  const unit = '"\\\n😀';
  const repeats = Math.floor(available / Buffer.byteLength(unit));
  return (
    beginning +
    unit.repeat(repeats) +
    "x".repeat(available % Buffer.byteLength(unit)) +
    ending
  );
}

function canonicalSha256(value) {
  const hash = createHash("sha256");
  visitJson(value, (chunk) => hash.update(chunk), true);
  return hash.digest("hex");
}

function jsonMetrics(value) {
  let bytes = 0;
  let stringEscapes = 0;
  visitJson(value, (chunk) => {
    bytes += Buffer.byteLength(chunk);
    for (let index = 0; index < chunk.length; index += 1) {
      if (chunk[index] === '"' || chunk[index] === "\\") stringEscapes += 1;
    }
  });
  return { bytes, stringEscapes };
}

// Hash and measure one scalar at a time instead of retaining another complete
// copy of the oversized document. Fixture values contain only JSON types.
function visitJson(value, emit, sorted = false) {
  if (Array.isArray(value)) {
    emit("[");
    value.forEach((item, index) => {
      if (index > 0) emit(",");
      visitJson(item, emit, sorted);
    });
    emit("]");
  } else if (value !== null && typeof value === "object") {
    emit("{");
    const keys = Object.keys(value);
    if (sorted) keys.sort();
    keys.forEach((key, index) => {
      if (index > 0) emit(",");
      emit(JSON.stringify(key));
      emit(":");
      visitJson(value[key], emit, sorted);
    });
    emit("}");
  } else {
    emit(JSON.stringify(value));
  }
}
