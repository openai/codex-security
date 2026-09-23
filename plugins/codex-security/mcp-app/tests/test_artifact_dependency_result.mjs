import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const compiled = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/artifact-dependency-result.ts", import.meta.url).pathname,
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const {
  dependencyArtifactResultInputSchema,
  recordCodexSecurityDependencyArtifactResult,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(compiled.outputFiles[0].contents).toString("base64")
);
const registrations = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/server/compact-artifact-tools.ts", import.meta.url)
      .pathname,
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { registerCompactArtifactTools } = await import(
  "data:text/javascript;base64," +
    Buffer.from(registrations.outputFiles[0].contents).toString("base64")
);

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const schema = JSON.parse(
  await readFile(
    new URL(
      "../../schemas/tools/dependency-artifact-result.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const scanId = randomUUID();
const sourceLine = "export const install = () => readEnvironment();";
const finding = {
  ruleId: "supply-chain.unsafe-install-hook",
  identity: { anchor: "environment-install-hook", instance: "postinstall" },
  title: "Installation hook reads the environment",
  summary: "The published installation hook reads environment variables.",
  severity: {
    level: "high",
    rationale: "Installation runs with application credentials.",
  },
  confidence: {
    level: "high",
    rationale: "The published hook contains the source.",
  },
  taxonomy: { category: "Unsafe installation hook", cwe: ["CWE-200"] },
  locations: [{ path: "dist/install.js", startLine: 2, role: "sink" }],
  codeEvidence: [
    {
      id: "published-hook",
      label: "Published installation hook",
      path: "dist/install.js",
      startLine: 2,
      code: sourceLine,
      explanation: "The published hook reads environment variables.",
    },
  ],
  remediation: "Remove the installation hook.",
};
const priorFindingAssessment = {
  upstreamFindingId: "dep_existing",
  status: "present",
  reason: "The previously identified installation hook remains present.",
  evidence: [finding.codeEvidence[0]],
};

assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
assert.deepEqual(schema.required, ["scanId", "findings"]);
assert.equal(schema.additionalProperties, false);
assert.equal(
  Object.hasOwn(schema.$defs.finding.properties, "introductionProbe"),
  false,
);
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({ scanId, findings: [] })
    .success,
  true,
);
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({ scanId, findings: [finding] })
    .success,
  true,
);
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({
    scanId,
    findings: [{ ...finding, codeEvidence: [] }],
  }).success,
  true,
  "Canonical findings may contain an explicitly empty code-evidence array.",
);
for (const status of ["present", "fixed", "unknown"]) {
  assert.equal(
    dependencyArtifactResultInputSchema.safeParse({
      scanId,
      findings: [],
      priorFindingAssessments: [{ ...priorFindingAssessment, status }],
    }).success,
    true,
    `The package scan must accept the existing assessment status ${status}.`,
  );
}
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({
    scanId,
    findings: [],
    priorFindingAssessments: [
      { ...priorFindingAssessment, status: "not_checked" },
    ],
  }).success,
  false,
  "Package scans must not expose the removed not_checked assessment status.",
);
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({
    scanId,
    findings: [],
    priorFindingAssessments: [
      { ...priorFindingAssessment, artifactDigest: "sha256:model-supplied" },
    ],
  }).success,
  false,
  "Prior finding assessments must not accept model-owned artifact identities.",
);
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({
    scanId,
    findings: [],
    priorFindingAssessments: [
      {
        ...priorFindingAssessment,
        evidence: [
          {
            ...priorFindingAssessment.evidence[0],
            artifactDigest: "sha256:model-supplied",
          },
        ],
      },
    ],
  }).success,
  false,
  "Prior assessment evidence must not accept model-owned artifact identities.",
);
assert.equal(
  dependencyArtifactResultInputSchema.safeParse({
    scanId,
    findings: [
      {
        ...finding,
        introductionProbe: {
          path: "dist/install.js",
          vulnerableCode: sourceLine,
        },
      },
    ],
  }).success,
  false,
  "Historical-version analysis must not require or accept a model-authored introduction probe.",
);

for (const forbidden of [
  "package",
  "registry",
  "ecosystem",
  "artifactDigest",
  "oldVersion",
  "newVersion",
  "targetId",
  "outputPath",
  "accountId",
]) {
  assert.equal(
    dependencyArtifactResultInputSchema.safeParse({
      scanId,
      findings: [finding],
      [forbidden]: "model-supplied",
    }).success,
    false,
    `The model must not supply ${forbidden}.`,
  );
}

for (const forbidden of [
  "findingId",
  "occurrenceId",
  "fingerprints",
  "extensions",
  "provenance",
  "artifactDigest",
  "package",
  "introducedIn",
]) {
  assert.equal(
    dependencyArtifactResultInputSchema.safeParse({
      scanId,
      findings: [{ ...finding, [forbidden]: "model-supplied" }],
    }).success,
    false,
    `A model finding must not supply ${forbidden}.`,
  );
}

const canonicalEvidence = [
  { label: "more-than-8192-bytes", code: "x".repeat(8193) },
  {
    label: "more-than-12-lines",
    code: Array(14).fill("source line").join("\n"),
  },
  { label: "trailing-newline", code: `${sourceLine}\n` },
  { label: "unicode", code: "const published = 'emoji 😀 and café';" },
];

for (const { label, code } of canonicalEvidence) {
  assert.equal(
    dependencyArtifactResultInputSchema.safeParse({
      scanId,
      findings: [
        {
          ...finding,
          codeEvidence: [{ ...finding.codeEvidence[0], code }],
        },
      ],
    }).success,
    true,
    `Canonical published evidence was rejected: ${label}`,
  );
}

for (const code of ["\0bad"]) {
  assert.equal(
    dependencyArtifactResultInputSchema.safeParse({
      scanId,
      findings: [
        {
          ...finding,
          codeEvidence: [{ ...finding.codeEvidence[0], code }],
        },
      ],
    }).success,
    false,
    `Unsafe source evidence was accepted: ${JSON.stringify(code).slice(0, 120)}`,
  );
}

const previousMode = process.env.CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN;
const previousKnowledgeBase = process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
const root = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-security-package-result-")),
);
try {
  process.env.CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN = "1";
  delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
  const dependencyTools = registeredTools();
  assert.equal(
    dependencyTools.has("record_codex_security_dependency_artifact_result"),
    true,
    "The isolated package scanner must expose its semantic result operation.",
  );
  assert.equal(
    dependencyTools.has("record_codex_security_scan_draft"),
    false,
    "The isolated package scanner must not expose legacy model-authored scan drafts.",
  );

  const withFinding = await createContext("with-finding");
  assert.deepEqual(
    await recordCodexSecurityDependencyArtifactResult(withFinding.context, {
      scanId,
      findings: [finding],
    }),
    {
      scanId,
      findingsRecorded: 1,
      operation: "replace",
      status: "recorded",
    },
  );
  const rows = await readLedger(withFinding.ledgerPath);
  assert.equal(rows.length, 1);
  assert.match(rows[0].candidate_id, /^candidate-[a-f0-9]{16}$/u);
  assert.deepEqual(rows[0].cwe_ids, ["CWE-200"]);
  assert.equal(rows[0].validation.disposition, "reportable");
  assert.equal(rows[0].attack_path.decision, "reportable");
  assert.deepEqual(rows[0].validation.dependencyFinding, finding);
  assert.equal(
    "introductionProbe" in rows[0].validation.dependencyFinding,
    false,
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        path.join(
          withFinding.context.root,
          "dependency-prior-finding-assessments.json",
        ),
        "utf8",
      ),
    ),
    { priorFindingAssessments: [] },
  );
  await assert.rejects(
    access(path.join(withFinding.context.root, "findings.json")),
  );
  await assert.rejects(
    access(path.join(withFinding.context.root, "scan-manifest.json")),
  );
  await assert.rejects(
    access(path.join(withFinding.context.root, "coverage.json")),
  );

  for (const { label, code } of canonicalEvidence) {
    const compatible = await createContext(`canonical-${label}`, code);
    const compatibleFinding = {
      ...finding,
      codeEvidence: [{ ...finding.codeEvidence[0], code }],
    };
    await recordCodexSecurityDependencyArtifactResult(compatible.context, {
      scanId,
      findings: [compatibleFinding],
    });
    const [recorded] = await readLedger(compatible.ledgerPath);
    assert.equal(
      recorded.validation.dependencyFinding.codeEvidence[0].code,
      code,
    );
  }

  const emptyEvidence = await createContext("empty-evidence");
  await recordCodexSecurityDependencyArtifactResult(emptyEvidence.context, {
    scanId,
    findings: [{ ...finding, codeEvidence: [] }],
  });
  const [withoutEvidence] = await readLedger(emptyEvidence.ledgerPath);
  assert.deepEqual(
    withoutEvidence.validation.dependencyFinding.codeEvidence,
    [],
  );
  assert.deepEqual(withoutEvidence.validation.evidence, [finding.summary]);

  const noPriors = await createContext("unseeded-without-priors");
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(noPriors.context, {
      scanId,
      findings: [],
      priorFindingAssessments: [priorFindingAssessment],
    }),
    /unseeded|prior finding/iu,
  );
  await assertNoRecordedArtifacts(noPriors);

  const trustedKnowledgeBase = await createTrustedKnowledgeBase(
    "trusted-priors",
    ["dep_existing", "dep_second"],
  );
  process.env.CODEX_SECURITY_KNOWLEDGE_BASE = trustedKnowledgeBase;

  const secondAssessment = {
    ...priorFindingAssessment,
    upstreamFindingId: "dep_second",
    status: "unknown",
    reason: "The published artifact cannot establish this previous finding.",
  };
  for (const { label, priorFindingAssessments, error } of [
    {
      label: "omitted-assessments",
      priorFindingAssessments: undefined,
      error: /missing|seeded|assessment/iu,
    },
    {
      label: "empty-assessments",
      priorFindingAssessments: [],
      error: /missing|seeded|assessment/iu,
    },
    {
      label: "partial-assessments",
      priorFindingAssessments: [priorFindingAssessment],
      error: /missing|seeded|assessment/iu,
    },
    {
      label: "duplicate-assessments",
      priorFindingAssessments: [priorFindingAssessment, priorFindingAssessment],
      error: /duplicate|repeat/iu,
    },
    {
      label: "unseeded-assessment",
      priorFindingAssessments: [
        priorFindingAssessment,
        { ...secondAssessment, upstreamFindingId: "dep_unseeded" },
      ],
      error: /unseeded|trusted|prior finding/iu,
    },
  ]) {
    const incomplete = await createContext(label);
    await assert.rejects(
      recordCodexSecurityDependencyArtifactResult(incomplete.context, {
        scanId,
        findings: [],
        ...(priorFindingAssessments === undefined
          ? {}
          : { priorFindingAssessments }),
      }),
      error,
      `The semantic tool accepted ${label}.`,
    );
    await assertNoRecordedArtifacts(incomplete);
  }

  const withAssessment = await createContext("prior-assessment");
  assert.deepEqual(
    await recordCodexSecurityDependencyArtifactResult(withAssessment.context, {
      scanId,
      findings: [finding],
      priorFindingAssessments: [priorFindingAssessment, secondAssessment],
    }),
    {
      scanId,
      findingsRecorded: 1,
      operation: "replace",
      status: "recorded",
    },
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        path.join(
          withAssessment.context.root,
          "dependency-prior-finding-assessments.json",
        ),
        "utf8",
      ),
    ),
    { priorFindingAssessments: [priorFindingAssessment, secondAssessment] },
  );

  delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
  const clean = await createContext("clean");
  assert.deepEqual(
    await recordCodexSecurityDependencyArtifactResult(clean.context, {
      scanId,
      findings: [],
    }),
    {
      scanId,
      findingsRecorded: 0,
      operation: "replace",
      status: "recorded",
    },
  );
  assert.deepEqual(await readLedger(clean.ledgerPath), []);
  assert.match(
    await readFile(clean.inventoryPath, "utf8"),
    /dist\/install\.js/u,
  );

  const invalidEvidence = await createContext("invalid-evidence");
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(invalidEvidence.context, {
      scanId,
      findings: [
        {
          ...finding,
          codeEvidence: [
            { ...finding.codeEvidence[0], code: "invented package source" },
          ],
        },
      ],
    }),
    /published artifact|source|evidence/iu,
  );
  await assert.rejects(access(invalidEvidence.ledgerPath));

  process.env.CODEX_SECURITY_KNOWLEDGE_BASE = await createTrustedKnowledgeBase(
    "invalid-assessment-prior",
    ["dep_existing"],
  );
  const invalidAssessment = await createContext("invalid-assessment");
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(invalidAssessment.context, {
      scanId,
      findings: [],
      priorFindingAssessments: [
        {
          ...priorFindingAssessment,
          evidence: [
            {
              ...priorFindingAssessment.evidence[0],
              code: "invented package source",
            },
          ],
        },
      ],
    }),
    /published artifact|source|evidence/iu,
  );
  await assert.rejects(
    access(
      path.join(
        invalidAssessment.context.root,
        "dependency-prior-finding-assessments.json",
      ),
    ),
  );

  const missingKnowledgeBase = path.join(root, "missing-trusted-priors");
  await mkdir(missingKnowledgeBase);
  process.env.CODEX_SECURITY_KNOWLEDGE_BASE = missingKnowledgeBase;
  const missingTrustedDocument = await createContext(
    "missing-trusted-document",
  );
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(
      missingTrustedDocument.context,
      {
        scanId,
        findings: [],
      },
    ),
    /trusted|prior|knowledge/iu,
  );
  await assertNoRecordedArtifacts(missingTrustedDocument);

  const malformedKnowledgeBase = path.join(root, "malformed-trusted-priors");
  await mkdir(malformedKnowledgeBase);
  await writeFile(
    path.join(malformedKnowledgeBase, "0-prior-findings.md.txt"),
    "# Trusted dependency finding assessment context\n\n```json\nnot-json\n```\n",
  );
  process.env.CODEX_SECURITY_KNOWLEDGE_BASE = malformedKnowledgeBase;
  const malformedTrustedDocument = await createContext(
    "malformed-trusted-document",
  );
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(
      malformedTrustedDocument.context,
      { scanId, findings: [] },
    ),
    /trusted|prior|knowledge/iu,
  );
  await assertNoRecordedArtifacts(malformedTrustedDocument);

  const linkedKnowledgeBase = path.join(root, "linked-trusted-priors");
  await mkdir(linkedKnowledgeBase);
  await symlink(
    path.join(trustedKnowledgeBase, "0-prior-findings.md.txt"),
    path.join(linkedKnowledgeBase, "0-prior-findings.md.txt"),
  );
  process.env.CODEX_SECURITY_KNOWLEDGE_BASE = linkedKnowledgeBase;
  const linkedTrustedDocument = await createContext("linked-trusted-document");
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(linkedTrustedDocument.context, {
      scanId,
      findings: [],
    }),
    /trusted|prior|knowledge|regular/iu,
  );
  await assertNoRecordedArtifacts(linkedTrustedDocument);

  process.env.CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN = "0";
  const ordinaryTools = registeredTools();
  assert.equal(
    ordinaryTools.has("record_codex_security_dependency_artifact_result"),
    false,
    "Ordinary first-party scans must not expose the package-only submission operation.",
  );
  assert.equal(
    ordinaryTools.has("record_codex_security_scan_draft"),
    true,
    "Existing first-party scan behavior must remain unchanged.",
  );
  await assert.rejects(
    recordCodexSecurityDependencyArtifactResult(clean.context, {
      scanId,
      findings: [],
    }),
    /dependency artifact/iu,
  );
} finally {
  if (previousMode === undefined) {
    delete process.env.CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN;
  } else {
    process.env.CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN = previousMode;
  }
  if (previousKnowledgeBase === undefined) {
    delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
  } else {
    process.env.CODEX_SECURITY_KNOWLEDGE_BASE = previousKnowledgeBase;
  }
  await rm(root, { recursive: true, force: true });
}

console.log("Codex Security dependency artifact result tests passed");

function registeredTools() {
  const names = new Set();
  registerCompactArtifactTools(
    {
      registerTool(name) {
        names.add(name);
      },
    },
    {
      runWorkbench: async () => ({}),
      pluginRoot,
    },
  );
  return names;
}

async function createContext(name, publishedSource = sourceLine) {
  const repoRoot = path.join(root, name, "repository");
  const scanRoot = path.join(root, name, "scan");
  await mkdir(path.join(repoRoot, "dist"), { recursive: true });
  await mkdir(scanRoot, { recursive: true });
  await writeFile(path.join(repoRoot, ".gitignore"), "dist/\n");
  await writeFile(
    path.join(repoRoot, "dist", "install.js"),
    `// published package\n${publishedSource}\n`,
  );
  const discoveryRoot = path.join(scanRoot, "artifacts", "02_discovery");
  return {
    context: {
      root: await realpath(scanRoot),
      repoRoot: await realpath(repoRoot),
      layout: "scan",
      scanId,
      scope: ".",
      pluginRoot,
      pythonCommand: "python3",
      status: "running",
      mode: "diff",
    },
    inventoryPath: path.join(discoveryRoot, "in_scope_files.txt"),
    ledgerPath: path.join(discoveryRoot, "candidate_ledger.jsonl"),
  };
}

async function createTrustedKnowledgeBase(name, findingIds) {
  const directory = path.join(root, name);
  await mkdir(directory, { recursive: true });
  const findings = Object.fromEntries(
    findingIds.map((findingId) => [findingId, { ruleId: finding.ruleId }]),
  );
  await writeFile(
    path.join(directory, "0-prior-findings.md.txt"),
    "# Trusted dependency finding assessment context\n\n```json\n" +
      JSON.stringify({ findings }, null, 2) +
      "\n```\n",
  );
  return directory;
}

async function assertNoRecordedArtifacts(context) {
  await assert.rejects(access(context.inventoryPath));
  await assert.rejects(access(context.ledgerPath));
  await assert.rejects(
    access(
      path.join(
        context.context.root,
        "dependency-prior-finding-assessments.json",
      ),
    ),
  );
}

async function readLedger(ledgerPath) {
  const rows = await readFile(ledgerPath, "utf8");
  return rows.trim() ? rows.trim().split("\n").map(JSON.parse) : [];
}
