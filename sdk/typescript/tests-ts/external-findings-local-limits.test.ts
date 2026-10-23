import { expect, mock, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { readExternalFindings } from "../src/external-findings-read.js";
import { validateExternalEvidence } from "../src/external-import-contract.js";
import type {
  ExternalFindingEvidence,
  Provider,
} from "../src/external-import-models.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";
import {
  importedAdvisory,
  importedAlert,
} from "./support/github-import-fixtures.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import {
  snykJson,
  snykPluginExport,
  snykSarif,
} from "./support/snyk-import-fixtures.js";

const repositoryUrl = "https://github.com/example/project";
const retainedEvidence = `begin-${"x".repeat(300 * 1024)}-end`;

function jsonWithEvidence(input: unknown, record: object): string {
  Object.assign(record, { retainedEvidence });
  return JSON.stringify(input);
}

function normalized() {
  return {
    source_finding_id: "synthetic-finding",
    evidence: { title: "Synthetic finding", severity: "high" as const },
  };
}

const formats: [string, Provider, () => string][] = [
  [
    "Semgrep JSON",
    "semgrep",
    () => {
      const input = semgrepJson();
      return jsonWithEvidence(input, input.results[0]!.extra.metadata);
    },
  ],
  [
    "Semgrep SARIF",
    "semgrep",
    () => {
      const input = semgrepSarif();
      return jsonWithEvidence(input, input.runs[0]!.results[0]!);
    },
  ],
  [
    "Snyk JSON",
    "snyk",
    () => {
      const input = snykJson();
      return jsonWithEvidence(input, input.vulnerabilities[0]!);
    },
  ],
  [
    "Snyk SARIF",
    "snyk",
    () => {
      const input = snykSarif();
      return jsonWithEvidence(input, input.runs[0]!.results[0]!);
    },
  ],
  [
    "Snyk plugin export",
    "snyk",
    () => {
      const input = snykPluginExport();
      return jsonWithEvidence(input, input.findings[0]!);
    },
  ],
  [
    "Endor JSON",
    "endor",
    () => {
      const input = endorFinding();
      return jsonWithEvidence(input, input);
    },
  ],
  [
    "Endor SARIF",
    "endor",
    () => {
      const input = endorSarif();
      return jsonWithEvidence(input, input.runs[0]!.results[0]!);
    },
  ],
  [
    "GitHub code scanning",
    "github",
    () => {
      const input = importedAlert();
      return jsonWithEvidence(input, input.alert);
    },
  ],
  ...(["repository", "global"] as const).map(
    (selection): [string, Provider, () => string] => [
      `GitHub ${selection} advisory`,
      "github",
      () => {
        const input = importedAdvisory(selection);
        return jsonWithEvidence(input, input.advisory);
      },
    ],
  ),
  [
    "Wiz package JSON",
    "wiz",
    () => {
      const input = {
        id: "synthetic-finding",
        name: "CVE-2099-0001",
        detailedName: "example-package",
        severity: "HIGH",
        vulnerableAsset: { id: "synthetic-asset" },
      };
      return jsonWithEvidence(input, input);
    },
  ],
  [
    "Wiz SAST JSON",
    "wiz",
    () => {
      const finding = {
        id: "synthetic-finding",
        name: "Synthetic finding",
        severity: "HIGH",
        repository: {
          id: "synthetic-repository",
          name: "example/project",
          url: repositoryUrl,
        },
      };
      return jsonWithEvidence({ sastFindings: { nodes: [finding] } }, finding);
    },
  ],
  [
    "Wiz CSV",
    "wiz",
    () => {
      const row = {
        ID: "synthetic-finding",
        Name: "CVE-2099-0001",
        DetailedName: "example-package",
        AssetID: "synthetic-asset",
        WizURL: "https://vendor.example.test/findings/synthetic-finding",
        CloudPlatform: "GitHub",
        CloudProviderURL: `${repositoryUrl}/tree/main`,
        Severity: "HIGH",
        retainedEvidence,
      };
      return [Object.keys(row), Object.values(row)]
        .map((cells) =>
          cells.map((value) => `"${value.replaceAll('"', '""')}"`).join(","),
        )
        .join("\r\n");
    },
  ],
  [
    "normalized JSONL",
    "wiz",
    () =>
      JSON.stringify({
        ...normalized(),
        evidence: {
          ...normalized().evidence,
          source_data: { retainedEvidence },
        },
      }),
  ],
];

test.each(formats)(
  "%s persists large local evidence while Cloud retains its size limit",
  async (_name, provider, contents) => {
    const fixture = await localFindingsFixture({ remote: repositoryUrl });
    try {
      const file = join(fixture.root, "scanner-report");
      await writeFile(file, contents());
      const options = {
        provider,
        repository: fixture.repository,
        sourceKey: "synthetic-project",
        sourceRepositoryUrl: repositoryUrl,
      };
      const dependencies = { environment: fixture.environment };
      const cloud = await readExternalFindings(file, options);
      expect(cloud.findings.findings).toEqual([]);
      expect(cloud.findings.excluded).toHaveLength(1);
      expect(cloud.findings.excluded[0]!.reason).toContain("256 KiB");

      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.excluded).toEqual([]);
      expect(prepared.preview.findings).toHaveLength(1);
      expect(
        JSON.stringify(prepared.preview.findings[0]!.evidence.source_data),
      ).toContain(retainedEvidence);
      expect((await prepared.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });
      const stored = await listLocalExternalFindings(options, dependencies);
      expect(stored).toHaveLength(1);
      expect(stored[0]!.evidence).toEqual(
        prepared.preview.findings[0]!.evidence,
      );
    } finally {
      await fixture.dispose();
    }
  },
);

let nested: Record<string, unknown> = { leaf: "retained" };
for (let index = 0; index < 24; index++) nested = { child: nested };

const evidenceLimits: [string, Partial<ExternalFindingEvidence>][] = [
  ["UTF-8 field bytes", { title: "é".repeat(257) }],
  ["description length", { description: "x".repeat(65537) }],
  [
    "nested detail length",
    {
      details: {
        kind: "sast",
        repository: { url: repositoryUrl },
        code: { snippet: "x".repeat(65537) },
      },
    },
  ],
  [
    "location count",
    {
      locations: Array.from({ length: 101 }, (_, index) => ({
        path: `src/file-${index}.ts`,
      })),
    },
  ],
  ["JSON depth", { source_data: nested }],
];

test.each(evidenceLimits)(
  "local imports retain %s above Cloud's contract",
  async (_name, fields) => {
    const fixture = await localFindingsFixture({ remote: repositoryUrl });
    try {
      const input = {
        ...normalized(),
        evidence: { ...normalized().evidence, ...fields },
      };
      const file = join(fixture.root, "normalized.jsonl");
      await writeFile(file, JSON.stringify(input));
      const options = {
        provider: "wiz" as const,
        repository: fixture.repository,
        sourceKey: "synthetic-project",
      };
      const dependencies = { environment: fixture.environment };
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.excluded).toEqual([]);
      const imported = await prepared.import();
      expect(imported.counts.created).toBe(1);
      const stored = await listLocalExternalFindings(options, dependencies);
      expect(stored[0]!.evidence).toEqual(
        prepared.preview.findings[0]!.evidence,
      );
      expect(stored[0]!.evidence).toMatchObject(fields);
      expect(() =>
        validateExternalEvidence(structuredClone(input.evidence)),
      ).toThrow();
      const cloud = await readExternalFindings(file, options);
      expect(cloud.findings.findings).toEqual([]);
      expect(cloud.findings.excluded).toHaveLength(1);
      const credentials = mock(async () => {
        throw new Error("Unexpected credential access");
      });
      await expect(
        prepareNormalizedExternalPublication(
          { read: 1, findings: [input], excluded: [] },
          options,
          { credentials },
        ),
      ).rejects.toThrow();
      expect(credentials).not.toHaveBeenCalled();
    } finally {
      await fixture.dispose();
    }
  },
);

test.each(["wiz", "endor"] as const)(
  "%s local imports preserve source identities longer than Cloud accepts",
  async (provider) => {
    const fixture = await localFindingsFixture();
    try {
      const identity = "x".repeat(513);
      const input =
        provider === "wiz"
          ? { ...normalized(), source_finding_id: identity }
          : { ...endorFinding(), uuid: identity };
      const file = join(fixture.root, "normalized.jsonl");
      await writeFile(file, JSON.stringify(input));
      const options = {
        provider,
        repository: fixture.repository,
        sourceKey: "synthetic-project",
      };
      const dependencies = { environment: fixture.environment };
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.excluded).toEqual([]);
      expect((await prepared.import()).counts.created).toBe(1);
      const stored = await listLocalExternalFindings(options, dependencies);
      expect(stored[0]!.sourceFindingId).toBe(identity);
      const cloud = await readExternalFindings(file, options);
      expect(cloud.findings.excluded[0]!.reason).toContain("512");
      const credentials = mock(async () => {
        throw new Error("Unexpected credential access");
      });
      await expect(
        prepareNormalizedExternalPublication(
          { read: 1, findings: prepared.preview.findings, excluded: [] },
          options,
          { credentials },
        ),
      ).rejects.toThrow("512");
      expect(credentials).not.toHaveBeenCalled();
    } finally {
      await fixture.dispose();
    }
  },
);

test("local evidence validation keeps structure, paths, links and numeric integrity", () => {
  const circular: Record<string, unknown> = {};
  circular["self"] = circular;
  expect(() =>
    validateExternalEvidence(
      { ...normalized().evidence, source_data: circular },
      "local",
    ),
  ).toThrow();
  const invalid: [unknown, string][] = [
    [{ ...normalized().evidence, severity: "not-a-severity" }, "severity"],
    [
      { ...normalized().evidence, locations: [{ path: "../outside.ts" }] },
      "repository-relative",
    ],
    [
      { ...normalized().evidence, url: "https://user@example.test/finding" },
      "without credentials",
    ],
    [{ ...normalized().evidence, source_data: { value: Infinity } }, "finite"],
    [
      {
        ...normalized().evidence,
        source_data: { value: Number.MAX_SAFE_INTEGER + 1 },
      },
      "safe integer",
    ],
  ];
  for (const [evidence, message] of invalid)
    expect(() => validateExternalEvidence(evidence, "local")).toThrow(message);
});

test("large local records still require distinct identities and matching repository provenance", async () => {
  const fixture = await localFindingsFixture({ remote: repositoryUrl });
  try {
    const input = {
      ...normalized(),
      evidence: { ...normalized().evidence, source_data: { retainedEvidence } },
    };
    const file = join(fixture.root, "normalized.jsonl");
    const options = {
      provider: "wiz" as const,
      repository: fixture.repository,
      sourceKey: "synthetic-project",
    };
    const dependencies = { environment: fixture.environment };
    await writeFile(
      file,
      [input, input].map((finding) => JSON.stringify(finding)).join("\n"),
    );
    await expect(
      prepareLocalExternalImport(file, options, dependencies),
    ).rejects.toThrow("Duplicate source");
    await writeFile(
      file,
      JSON.stringify({
        ...input,
        evidence: {
          ...input.evidence,
          details: {
            kind: "sast",
            repository: { url: "https://github.com/example/other" },
          },
        },
      }),
    );
    await expect(
      prepareLocalExternalImport(file, options, dependencies),
    ).rejects.toThrow("does not match");
    expect(await listLocalExternalFindings(options, dependencies)).toEqual([]);
  } finally {
    await fixture.dispose();
  }
});
