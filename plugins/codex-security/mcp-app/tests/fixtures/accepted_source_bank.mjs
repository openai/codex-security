// Synthetic accepted artifacts. Expected fixes are independent of display identities.
export const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
export const bankVersion = "accepted-source-bank/v1";

export const fixes = {
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
    result: { scanId, complete: true, findings, coverage: scanCoverage },
  };
}

export const workers = [
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

export const sourceGroups = {
  "worker-owner:0": "owner",
  "worker-path:0": "path",
  "worker-owner-duplicate:0": "owner",
  "worker-bundled:0": "search-bundle",
};

export const sourceFixes = {
  "worker-owner:0": ["owner"],
  "worker-path:0": ["path"],
  "worker-owner-duplicate:0": ["owner"],
  "worker-bundled:0": ["sql", "html"],
};

// This history is distinct from the immutable accepted terminal bank above.
// A newer rejection is authoritative for this logical worker's final result.
export const rejectionHistory = {
  workerId: "worker-rejected",
  earlier: worker("worker-rejected", [finding("safe-query", fixes.sql)]).result,
  latest: worker("worker-rejected", [], {
    ...coverage(),
    surfaces: [
      {
        label: "Search SQL",
        disposition: "rejected",
        notes:
          "The driver binds parameters; the earlier interpolation claim was disproved.",
      },
    ],
  }).result,
};

export function permutations(items) {
  if (!items.length) return [[]];
  return items.flatMap((item, index) =>
    permutations(items.filter((_, i) => i !== index)).map((rest) => [
      item,
      ...rest,
    ]),
  );
}

export function partitions(items) {
  if (!items.length) return [[]];
  return items.flatMap((_, index) =>
    partitions(items.slice(index + 1)).map((rest) => [
      items.slice(0, index + 1),
      ...rest,
    ]),
  );
}

export function originals(inputs) {
  const sources = new Map();
  for (const current of inputs.previous?.findings ?? []) {
    for (const source of current.provenance.sourceFindings ?? [])
      sources.set(source.id, source.finding);
  }
  for (const discovery of inputs.discoveries) {
    discovery.result.findings.forEach((value, i) =>
      sources.set(`${discovery.workerId}:${i}`, value),
    );
  }
  return sources;
}

// Scripted proposals isolate host reconciliation from model variability.
export function proposal(inputs, groupFor = (id) => sourceGroups[id]) {
  const grouped = new Map();
  for (const [id, value] of originals(inputs)) {
    const group = groupFor(id);
    if (!grouped.has(group)) grouped.set(group, { value, refs: [] });
    grouped.get(group).refs.push(id);
  }
  return {
    scanId,
    complete: true,
    findings: [...grouped].map(([group, { value, refs }]) => ({
      ...structuredClone(value),
      ruleId: "synthetic." + group,
      identity: { anchor: group },
      provenance: { source: "local_plugin", sourceFindingIds: refs },
    })),
  };
}
