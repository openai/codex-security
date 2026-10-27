import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { readExternalFindings } from "../src/external-findings-read.js";
import type { Provider } from "../src/external-import-models.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";
import { importedAdvisory } from "./support/github-import-fixtures.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { snykJson } from "./support/snyk-import-fixtures.js";
import {
  removeTemporaryDirectory,
  temporaryDirectory,
} from "./support/temporary-directories.js";

const repositoryUrl = "https://github.com/example/project";
const semgrepId =
  "semgrep:100bac96b3041ed3ef5c1b45291e7c123ab8ef615eed54af962d675f6194dd76";

const cases = [
  {
    provider: "wiz",
    report: {
      data: {
        vulnerabilityFindings: {
          nodes: [
            {
              id: "finding-example-1",
              name: "CVE-2026-0001",
              detailedName: "example-package",
              version: "1.1.0",
              vendorSeverity: "HIGH",
              severity: "LOW",
              vulnerableAsset: { id: "synthetic-asset" },
            },
          ],
        },
      },
    },
    sourceFindingId: "finding-example-1",
    evidence: {
      severity: "high",
      advisory_ids: ["CVE-2026-0001"],
      packages: [{ name: "example-package", installed_version: "1.1.0" }],
      source_data: {
        severity: "LOW",
        vulnerableAsset: { id: "synthetic-asset" },
      },
    },
  },
  {
    provider: "endor",
    report: { list: { objects: [endorFinding()] } },
    sourceFindingId: "finding-example-1",
    evidence: {
      severity: "critical",
      advisory_ids: ["CVE-2099-0001", "GHSA-2222-3333-4444"],
      locations: [{ path: "package.json" }, { path: "package-lock.json" }],
      source_data: { spec: { proposed_version: "2.0.0" } },
    },
  },
  {
    provider: "snyk",
    report: snykJson(),
    sourceFindingId:
      "snyk-json:1c8768bda0ae02bec7076a5062619f38a0d67d080ec78dddfb473804515a7113",
    evidence: {
      advisory_ids: ["SNYK-EXAMPLE-1", "CVE-2099-0001"],
      packages: [{ fixed_versions: ["1.0.1"], manifest_path: null }],
      locations: [],
      source_data: {
        vulnerability: { from: ["example@1.0.0", "@example/package@1.0.0"] },
      },
    },
  },
  {
    provider: "semgrep",
    report: semgrepJson(),
    sourceFindingId: semgrepId,
    evidence: {
      severity: "critical",
      locations: [{ path: "src/example.ts", line: 3 }],
      details: { kind: "sast", source_status: "ignored" },
      source_data: {
        result: { extra: { fingerprint: "synthetic-fingerprint" } },
      },
    },
  },
  {
    provider: "github",
    report: [importedAdvisory("global")],
    sourceFindingId: "github.com/global/security-advisory/GHSA-2345-6789-CFGH",
    evidence: {
      advisory_ids: ["GHSA-2345-6789-cfgh", "CVE-2026-0001"],
      packages: [
        {
          vulnerable_version_range: ">= 1.0.0, < 1.2.3",
          installed_version: null,
        },
      ],
      locations: [],
      details: { kind: "advisory", advisory: { source: "global" } },
      source_data: { advisory: { state: "published" } },
    },
  },
] as const;

function readerOptions(provider: Provider) {
  return provider === "semgrep"
    ? { provider, sourceRepositoryUrl: repositoryUrl }
    : { provider };
}

test.each(cases)(
  "$provider maps a saved report for Cloud without publishing it",
  async ({ provider, report, sourceFindingId, evidence }) => {
    const root = await temporaryDirectory("scanner-import-contract-");
    try {
      const path = join(root, "report.json");
      await writeFile(path, JSON.stringify(report));
      const parsed = await readExternalFindings(
        path,
        readerOptions(provider),
        "cloud",
      );
      expect(parsed.findings).toMatchObject({
        read: 1,
        excluded: [],
        findings: [{ source_finding_id: sourceFindingId, evidence }],
      });
    } finally {
      await removeTemporaryDirectory(root);
    }
  },
);

test("overlapping vendor IDs and advisories stay distinct on SQLite replay", async () => {
  const fixture = await localFindingsFixture({ remote: repositoryUrl });
  try {
    const { repository, environment } = fixture;
    const sourceKey = "example/project/main";
    const ingest = async (provider: Provider, report: unknown) => {
      const path = join(fixture.root, `${provider}.json`);
      await writeFile(path, JSON.stringify(report));
      const prepared = await prepareLocalExternalImport(
        path,
        { repository, sourceKey, ...readerOptions(provider) },
        { environment },
      );
      expect(prepared.preview.excluded).toEqual([]);
      return (await prepared.import()).counts;
    };
    const read = () =>
      listLocalExternalFindings({ repository }, { environment });
    for (const { provider, report } of cases)
      expect(await ingest(provider, report)).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });

    const stored = await read();
    expect(stored).toHaveLength(cases.length);
    for (const { provider, sourceFindingId, evidence, report } of cases) {
      expect(
        stored.find((record) => record.provider === provider),
      ).toMatchObject({
        sourceKey,
        sourceFindingId,
        version: 1,
        assessment: { state: "not_assessed" },
        evidence,
      });
      expect(await ingest(provider, report)).toEqual({
        created: 0,
        updated: 0,
        unchanged: 1,
      });
    }
    expect(await read()).toEqual(stored);

    const sarif = semgrepSarif();
    const region =
      sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region;
    region.startLine = region.endLine = 27;
    expect(await ingest("semgrep", sarif)).toEqual({
      created: 0,
      updated: 1,
      unchanged: 0,
    });
    const after = await read();
    expect(after).toHaveLength(stored.length);
    const changed = after.find((record) => record.provider === "semgrep");
    expect(changed).toMatchObject({
      id: stored.find((record) => record.provider === "semgrep")!.id,
      sourceFindingId: semgrepId,
      version: 2,
      assessment: { state: "not_assessed" },
      evidence: {
        severity: "high",
        locations: [{ path: "src/example.ts", line: 27 }],
        details: { kind: "sast", source_status: "suppressed" },
        source_data: {
          result: { codeFlows: [{ message: { text: "Synthetic dataflow" } }] },
        },
      },
    });
    expect(changed!.evidence.source_data?.["result"]).not.toHaveProperty(
      "extra",
    );
    expect(after.filter((record) => record.provider !== "semgrep")).toEqual(
      stored.filter((record) => record.provider !== "semgrep"),
    );

    expect(await ingest("endor", endorSarif())).toEqual({
      created: 0,
      updated: 1,
      unchanged: 0,
    });
    const overlapping = (await read()).filter(
      (record) => record.sourceFindingId === "finding-example-1",
    );
    expect(overlapping).toHaveLength(2);
    expect(
      overlapping.find((record) => record.provider === "endor"),
    ).toMatchObject({
      id: stored.find((record) => record.provider === "endor")!.id,
      version: 2,
      evidence: {
        severity: "unknown",
        packages: [],
        source_data: { result: { properties: { "cvss-score": 9.8 } } },
      },
    });
    expect(overlapping.find((record) => record.provider === "wiz")).toEqual(
      stored.find((record) => record.provider === "wiz"),
    );
  } finally {
    await fixture.dispose();
  }
});
