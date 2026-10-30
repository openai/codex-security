import { access, readFile, rm, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import {
  normalizeSemgrepSarif,
  readSemgrepFindings,
} from "../src/semgrep-findings.js";
import {
  localFindingsFixture,
  localReportFixture,
} from "./external-findings-local-helpers.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const repositoryUrl = "https://github.com/example/project";
const formats = ["JSON", "SARIF"] as const;

function report(
  format: (typeof formats)[number],
  {
    line = 3,
    fingerprint = "synthetic-fingerprint",
    message = "Synthetic finding",
    sparse = false,
  } = {},
) {
  if (format === "JSON") {
    const input = semgrepJson();
    const result = input.results[0]!;
    result.start.line = line;
    result.end.line = line;
    result.extra.fingerprint = fingerprint;
    result.extra.message = message;
    if (sparse) {
      result.path = "../outside.ts";
      result.extra.severity = "EXPERIMENT";
      result.extra.lines = "requires login";
    }
    return input;
  }
  const input = semgrepSarif();
  const run = input.runs[0]!;
  const result = run.results[0]!;
  const region = result.locations[0]!.physicalLocation.region;
  region.startLine = line;
  region.endLine = line;
  result.fingerprints["matchBasedId/v1"] = fingerprint;
  result.message.text = message;
  if (sparse) {
    result.locations[0]!.physicalLocation.artifactLocation.uri =
      "../outside.ts";
    run.tool.driver.rules[0]!.defaultConfiguration.level = "none";
  }
  return input;
}

test("Semgrep file reader rejects malformed SARIF repository provenance", async () => {
  const directory = await temporaryDirectory("semgrep-reader-");
  try {
    const file = join(directory, "semgrep.sarif");
    const input = sarifWithRepositories(['http://""?\nX']);
    await writeFile(file, JSON.stringify(input));
    await expect(
      readSemgrepFindings(file, { sourceRepositoryUrl: repositoryUrl }),
    ).rejects.toThrow(
      "SARIF source repository does not match the declared source repository URL.",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

for (const suppliedFingerprint of [true, false]) {
  test.each(formats)(
    `Semgrep %s movement ${suppliedFingerprint ? "updates the supplied fingerprint" : "retains both fallback records"} in SQLite`,
    async (format) => {
      await using fixture = await localReportFixture(
        "semgrep.json",
        {
          provider: "semgrep",
          sourceKey: "example-project:main",
          sourceRepositoryUrl: repositoryUrl,
        },
        { remote: repositoryUrl },
      );
      const fingerprint = suppliedFingerprint
        ? "synthetic-fingerprint"
        : "requires login";
      async function prepareLine(line: number, message?: string) {
        await fixture.writeJson(report(format, { line, fingerprint, message }));
        return fixture.prepare();
      }

      const prepared = await prepareLine(3);
      expect(prepared.preview.findings).toHaveLength(1);
      expect(prepared.preview.excluded).toEqual([]);
      expect(prepared.preview.source).toEqual({
        provider: "semgrep",
        source_key: fixture.sourceKey,
      });
      expect((await prepared.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });
      const [original] = await fixture.read();
      expect(original).toMatchObject({
        provider: "semgrep",
        sourceKey: fixture.sourceKey,
        sourceFindingId: prepared.preview.findings[0]!.source_finding_id,
        assessment: { state: "not_assessed" },
        version: 1,
      });
      expect(original!.evidence).toEqual(
        prepared.preview.findings[0]!.evidence,
      );
      expect(original!.evidence).not.toHaveProperty("confidence");
      expect(original!.evidence.locations).toEqual([
        { path: "src/example.ts", line: 3 },
      ]);

      const next = await prepareLine(9);
      expect((await next.import()).counts).toEqual(
        suppliedFingerprint
          ? { created: 0, updated: 1, unchanged: 0 }
          : { created: 1, updated: 0, unchanged: 0 },
      );
      const records = await fixture.read();
      const moved = records.find(
        (record) => record.evidence.locations?.[0]?.line === 9,
      );
      expect(moved).toBeDefined();
      expect(moved!.evidence.locations).toEqual([
        { path: "src/example.ts", line: 9 },
      ]);
      expect(moved!.evidence.source_data?.["result"]).toMatchObject(
        format === "JSON"
          ? { extra: { fingerprint } }
          : { fingerprints: { "matchBasedId/v1": fingerprint } },
      );
      expect(moved!.assessment).toEqual({ state: "not_assessed" });
      if (suppliedFingerprint) {
        expect(records).toHaveLength(1);
        expect(moved).toMatchObject({
          id: original!.id,
          sourceFindingId: original!.sourceFindingId,
          createdAt: original!.createdAt,
          version: 2,
        });
      } else {
        expect(records).toHaveLength(2);
        expect(records.find((record) => record.id === original!.id)).toEqual(
          original,
        );
        expect(moved!.sourceFindingId).not.toBe(original!.sourceFindingId);
        expect(moved!.version).toBe(1);
      }
      const repeated = await fixture.prepare();
      expect((await repeated.import()).counts).toEqual({
        created: 0,
        updated: 0,
        unchanged: 1,
      });
      expect(await fixture.read()).toEqual(records);

      if (suppliedFingerprint) {
        const edited = await prepareLine(9, "Updated scanner evidence");
        expect((await edited.import()).counts).toEqual({
          created: 0,
          updated: 1,
          unchanged: 0,
        });
        const updated = await fixture.read();
        expect(updated).toHaveLength(1);
        expect(updated[0]).toMatchObject({
          id: original!.id,
          sourceFindingId: original!.sourceFindingId,
          createdAt: original!.createdAt,
          assessment: { state: "not_assessed" },
          version: 3,
        });
        expect(updated[0]!.evidence).toEqual(
          edited.preview.findings[0]!.evidence,
        );
        expect(updated[0]!.evidence.description).toBe(
          "Updated scanner evidence",
        );
      }
    },
  );
}

test.each(formats)(
  "Semgrep %s preserves sparse evidence without inventing a repository location or assessment",
  async (format) => {
    await using fixture = await localReportFixture(
      "semgrep.json",
      {
        provider: "semgrep",
        sourceKey: "example-project:main",
        sourceRepositoryUrl: repositoryUrl,
      },
      { remote: repositoryUrl },
    );
    await fixture.writeJson(report(format, { message: "", sparse: true }));
    const prepared = await fixture.prepare();
    expect((await prepared.import()).counts.created).toBe(1);
    const [stored] = await fixture.read();
    expect(stored!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
    expect(stored!.evidence).toMatchObject({
      description: null,
      severity: "unknown",
      locations: [],
      code_revision: null,
      details: { code: { end_line: null, snippet: null } },
    });
    expect(stored!.evidence.source_data).toHaveProperty("result");
    expect(stored!.evidence).not.toHaveProperty("confidence");
    expect(stored!.evidence).not.toHaveProperty("remediation");
    expect(stored!.assessment).toEqual({ state: "not_assessed" });
  },
);

test.each(formats)(
  "Semgrep %s rejects a source repository that conflicts with the selected checkout",
  async (format) => {
    await using fixture = await localReportFixture(
      "semgrep.json",
      {
        provider: "semgrep",
        sourceKey: "example-project:main",
        sourceRepositoryUrl: "https://github.com/other/project",
      },
      { remote: repositoryUrl },
    );
    await fixture.writeJson(report(format));
    await expect(fixture.prepare()).rejects.toThrow("does not match");
    expect(await fixture.read()).toEqual([]);
  },
);

function sarifWithRepositories(urls: string[]) {
  const input = semgrepSarif();
  return {
    ...input,
    runs: [
      {
        ...input.runs[0]!,
        versionControlProvenance: urls.map((repositoryUri) => ({
          repositoryUri,
        })),
      },
    ],
  };
}

test.each([
  ["unknown host", "git.example.test", "with remote"],
  ["GitHub", "github.com", "with remote"],
  ["known GitHub custom host", "git.example.test", "with remote"],
  ["GitHub", "github.com", "with uppercase remote"],
  ["known GitHub custom host", "git.example.test", "with uppercase remote"],
  ["unknown host", "git.example.test", "without remote"],
  ["GitHub", "github.com", "without remote"],
  ["known GitHub custom host", "git.example.test", "without remote"],
])(
  "Semgrep SARIF preserves original repository references on %s (%s, %s)",
  async (platform, host, checkout) => {
    const sourceRepositoryUrl = `https://${host}/team/project`;
    const originalUrl = `https://${host}/Team/Project`;
    await using fixture = await localFindingsFixture(
      checkout === "without remote"
        ? {}
        : {
            remote: `git@${host}:${checkout === "with uppercase remote" ? "Team/Project" : "team/project"}.git`,
          },
    );
    const file = join(fixture.root, "semgrep-report");
    const options = {
      repository: fixture.repository,
      provider: "semgrep" as const,
      sourceKey: "example-project:main",
      sourceRepositoryUrl,
    };
    const dependencies = {
      environment: fixture.environment,
      ...(platform === "known GitHub custom host"
        ? {
            sourceRepositories: [
              { url: originalUrl, platform: "github" as const },
            ],
          }
        : {}),
    };
    const database = join(fixture.stateDirectory, "workbench.sqlite3");
    async function writeReport(url: string, compressed = false) {
      // Keep both refs: checking only the first would miss the case-distinct one.
      const contents = JSON.stringify(
        sarifWithRepositories([sourceRepositoryUrl, url]),
      );
      await writeFile(file, compressed ? gzipSync(contents) : contents);
    }
    await writeReport(originalUrl, true);
    if (platform === "unknown host") {
      await expect(
        prepareLocalExternalImport(file, options, dependencies),
      ).rejects.toThrow("does not match");
      const empty = sarifWithRepositories([sourceRepositoryUrl, originalUrl]);
      empty.runs[0]!.results.length = 0;
      await writeFile(file, JSON.stringify(empty));
      await expect(
        prepareLocalExternalImport(file, options, dependencies),
      ).rejects.toThrow("does not match");
      await expect(access(database)).rejects.toThrow();
      await writeReport(sourceRepositoryUrl);
    }
    const parsed = await readSemgrepFindings(file, { sourceRepositoryUrl });
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(parsed.findings);
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await listLocalExternalFindings(options, dependencies);
    expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
    expect(stored[0]!.evidence.details?.repository?.url).toBe(
      sourceRepositoryUrl,
    );
    expect(stored[0]!.evidence.source_data?.["runContext"]).toMatchObject({
      versionControlProvenance: [
        { repositoryUri: sourceRepositoryUrl },
        {
          repositoryUri:
            platform === "unknown host" ? sourceRepositoryUrl : originalUrl,
        },
      ],
    });
    expect(
      (
        await (
          await prepareLocalExternalImport(file, options, dependencies)
        ).import()
      ).counts,
    ).toEqual({ created: 0, updated: 0, unchanged: 1 });
    const before = await readFile(database);
    await writeReport(
      platform === "unknown host"
        ? originalUrl
        : `https://${host}/other/project`,
    );
    await expect(
      prepareLocalExternalImport(file, options, dependencies),
    ).rejects.toThrow("does not match");
    expect(await readFile(database)).toEqual(before);
    expect(await listLocalExternalFindings(options, dependencies)).toEqual(
      stored,
    );
  },
);

test("normalized Semgrep SDK imports retain original SARIF repository metadata through the explicit dependency", async () => {
  const sourceRepositoryUrl = "https://git.example.test/team/project";
  const originalUrl = "https://git.example.test/Team/Project";
  await using fixture = await localFindingsFixture({
    remote: sourceRepositoryUrl,
  });
  const options = {
    repository: fixture.repository,
    provider: "semgrep" as const,
    sourceKey: "example-project:main",
  };
  const parsed = normalizeSemgrepSarif(sarifWithRepositories([originalUrl]), {
    sourceRepositoryUrl,
  });
  const saved = JSON.parse(JSON.stringify(parsed));
  await expect(
    prepareNormalizedLocalImport(saved, options, {
      environment: fixture.environment,
      sourceRepositories: [{ url: originalUrl }],
    }),
  ).rejects.toThrow("does not match");
  await expect(
    access(join(fixture.stateDirectory, "workbench.sqlite3")),
  ).rejects.toThrow();
  const dependencies = {
    environment: fixture.environment,
    sourceRepositories: [{ url: originalUrl, platform: "github" as const }],
  };
  const prepared = await prepareNormalizedLocalImport(
    saved,
    options,
    dependencies,
  );
  expect((await prepared.import()).counts.created).toBe(1);
  expect(
    (await listLocalExternalFindings(options, dependencies))[0]!.evidence,
  ).toEqual(parsed.findings[0]!.evidence);
});

test("Semgrep gzipped JSON uses the caller source URL without treating rule metadata as repository provenance", async () => {
  const sourceRepositoryUrl = "https://git.example.test/Team/Project";
  await using fixture = await localReportFixture(
    "semgrep-report",
    {
      provider: "semgrep",
      sourceKey: "example-project:main",
      sourceRepositoryUrl,
    },
    {
      remote: "git@git.example.test:Team/Project.git",
    },
  );
  const input = semgrepJson();
  const first = input.results[0]!;
  const report = {
    ...input,
    results: [
      {
        ...first,
        extra: {
          ...first.extra,
          metadata: {
            ...first.extra.metadata,
            source: "https://rules.example.test/Other/Repository",
          },
        },
      },
    ],
  };
  await writeFile(fixture.file, gzipSync(JSON.stringify(report)));
  const parsed = await readSemgrepFindings(fixture.file, {
    sourceRepositoryUrl,
  });
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts.created).toBe(1);
  const stored = await fixture.read();
  expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
  await expect(
    fixture.prepare({
      sourceRepositoryUrl: "https://git.example.test/team/project",
    }),
  ).rejects.toThrow("does not match");
  expect(await fixture.read()).toEqual(stored);
});
