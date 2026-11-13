import { expect, test } from "bun:test";
import { normalizeBlackDuckFindings } from "../src/blackduck-findings.js";
import { normalizeContinuumFindings } from "../src/continuum-findings.js";
import type { ExternalImportTarget } from "../src/external-import-contract.js";
import type { ExternalFindings } from "../src/external-findings.js";
import { normalizeInspectorFindings } from "../src/inspector-findings.js";
import { projectStoredFinding } from "../src/stored-finding-projection.js";
import {
  blackDuckBomReport,
  blackDuckBomRow,
} from "./support/blackduck-import-fixtures.js";
import {
  continuumDetail,
  continuumRepository,
} from "./support/continuum-import-fixtures.js";
import {
  inspectorCodeFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

const blackDuck = {
  ...blackDuckBomRow(),
  packageUrl: `pkg:github/example/${"x".repeat(513)}@1.2.3`,
};
const continuum = {
  ...continuumDetail(),
  affectedPackages: [
    { name: "界".repeat(200) },
    ...Array.from({ length: 101 }, (_, i) => ({ name: `package-${i}` })),
  ],
};
const inspector = inspectorCodeFinding();
inspector.codeVulnerabilityDetails.detectorId = "x".repeat(513);

const cases: [string, (target: ExternalImportTarget) => ExternalFindings][] = [
  [
    "blackduck",
    (target) =>
      normalizeBlackDuckFindings(
        blackDuckBomReport([blackDuck]),
        continuumRepository,
        target,
      ),
  ],
  [
    "continuum",
    (target) =>
      normalizeContinuumFindings(continuum, continuumRepository, target),
  ],
  [
    "inspector",
    (target) =>
      normalizeInspectorFindings(
        { findings: [inspector] },
        inspectorRepositoryUrl,
        target,
      ),
  ],
];

test.each(cases)(
  "stored %s enrichment uses the native Cloud projection only for matching reviewed evidence",
  (provider, read) => {
    const local = read("local").findings[0]!;
    const cloud = read("cloud");
    expect(cloud.findings).toHaveLength(1);
    expect(local.evidence).not.toEqual(cloud.findings[0]!.evidence);
    const row = {
      provider,
      sourceFindingId: local.source_finding_id,
      evidence: local.evidence,
    };
    expect(projectStoredFinding(row, []).findings).toEqual(cloud.findings);
    const edited = {
      ...row,
      evidence: {
        ...row.evidence,
        description: "Operator reviewed and edited this finding.",
      },
    };
    const selection = projectStoredFinding(edited, []);
    expect(selection.findings).toEqual([]);
    expect(selection.excluded).toHaveLength(1);
  },
);
