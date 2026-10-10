import { expect, test } from "bun:test";
import { normalizeOsvOutput } from "../src/sca-osv.js";
import { dependencyScanResult } from "../src/sca.js";
import {
  compareScaResults,
  createScaUpdateHandoff,
  renderScaReport,
} from "../src/sca-report.js";
import type { ScaInput } from "../src/sca-types.js";

const cases = [
  {
    ecosystem: "PyPI",
    format: "uv",
    path: "uv.lock",
    name: "synthetic-lib",
    version: "1!2.0.post1",
    fixed: "1!2.0.post2",
  },
  {
    ecosystem: "Go",
    format: "go",
    path: "go.mod",
    name: "example.invalid/synthetic/lib",
    version: "0.0.0-20260901000000-123456789abc",
    fixed: "1.2.0",
  },
  {
    ecosystem: "crates.io",
    format: "cargo",
    path: "Cargo.lock",
    name: "synthetic-lib",
    version: "1.2.0+synthetic",
    fixed: "1.3.0",
  },
  {
    ecosystem: "Maven",
    format: "gradle",
    path: "gradle.lockfile",
    name: "invalid.example:synthetic-lib",
    version: "1.2.Final",
    fixed: "1.3.Final",
  },
  {
    ecosystem: "RubyGems",
    format: "bundler",
    path: "Gemfile.lock",
    name: "synthetic-lib",
    version: "1.2.0.pre.1",
    fixed: "1.3.0",
  },
  {
    ecosystem: "Packagist",
    format: "composer",
    path: "composer.lock",
    name: "synthetic/lib",
    version: "1.2.0.0",
    fixed: "1.3.0.0",
  },
  {
    ecosystem: "NuGet",
    format: "nuget",
    path: "packages.lock.json",
    name: "Synthetic.Lib",
    version: "1.2.0.4",
    fixed: "1.3.0.0",
  },
] as const;

function facts(
  item: (typeof cases)[number],
  affectedName: string = item.name,
  reportedName: string = item.name,
) {
  const input: ScaInput = {
    path: item.path,
    format: item.format,
    status: "scanned",
    sha256: "synthetic-hash",
    reason: null,
  };
  const normalized = normalizeOsvOutput(
    {
      results: [
        {
          source: { path: item.path },
          packages: [
            {
              package: {
                name: reportedName,
                ecosystem: item.ecosystem,
                version: item.version,
              },
              vulnerabilities: [
                {
                  id: "SYNTHETIC-MULTILANGUAGE-1",
                  affected: [
                    {
                      package: {
                        name: affectedName,
                        ecosystem: item.ecosystem,
                      },
                      ranges: [
                        {
                          type: "ECOSYSTEM",
                          events: [{ introduced: "0" }, { fixed: item.fixed }],
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
    { repositoryPath: "/synthetic/repository", inputs: [input] },
  );
  return { input, normalized };
}

function scanResult({ input, normalized }: ReturnType<typeof facts>) {
  return dependencyScanResult(
    {
      status: "completed",
      diagnostics: [],
      components: normalized.components,
      matches: normalized.matches,
      coverage: {
        status: "complete",
        inputs: [input],
        configFiles: [],
        limitations: [],
        unresolvedPackages: 0,
      },
      scanner: {
        name: "osv-scanner",
        version: "2.6.0",
        argv: [],
        startedAt: "2026-01-01T00:00:00Z",
        completedAt: "2026-01-01T00:00:01Z",
        exitCode: 1,
        rawOutputPath: "/synthetic/output/osv.json",
        stderrPath: "/synthetic/output/osv.log",
        advisoryMode: "offline",
        advisorySnapshotId: "synthetic-snapshot",
      },
    },
    {
      path: "/synthetic/repository",
      revision: "synthetic-revision",
      dirty: false,
    },
    "/synthetic/output",
  );
}

test.each([...cases])(
  "preserves $ecosystem version semantics through reports, comparison, and update handoff",
  (item) => {
    const { input, normalized } = facts(item);
    expect(normalized.unresolvedPackages).toBe(0);
    expect(normalized.diagnostics).toEqual([]);
    expect(normalized.components[0]).toMatchObject({
      name: item.name,
      version: item.version,
      ecosystem: item.ecosystem,
      sourcePath: item.path,
    });
    expect(normalized.matches[0]?.fixedVersions).toEqual([item.fixed]);
    const result = scanResult({ input, normalized });
    const report = renderScaReport(result);
    expect(report).toContain(item.ecosystem);
    expect(report).toContain(item.version);
    const handoff = createScaUpdateHandoff(result, [result.matches[0]!.id]);
    expect(handoff.candidates[0]).toMatchObject({
      ecosystem: item.ecosystem,
      package: item.name,
      currentVersion: item.version,
      sourcePath: item.path,
      fixedVersions: [item.fixed],
    });
    const comparison = compareScaResults(result, structuredClone(result));
    expect(comparison.introduced).toEqual([]);
    expect(comparison.noLongerObserved).toEqual([]);
  },
);

test.each([
  { item: cases[0], affectedName: "Synthetic_Lib" },
  { item: cases[6], affectedName: "synthetic.lib" },
])(
  "matches advisory package-name normalization for $item.ecosystem",
  ({ item, affectedName }) => {
    expect(
      facts(item, affectedName).normalized.matches[0]?.fixedVersions,
    ).toEqual([item.fixed]);
  },
);

test("does not confuse package identities across ecosystems in a mixed repository", () => {
  const py = facts(cases[0]);
  const ruby = facts(cases[4]);
  expect(py.normalized.components[0]?.name).toBe(
    ruby.normalized.components[0]?.name,
  );
  expect(py.normalized.components[0]?.id).not.toBe(
    ruby.normalized.components[0]?.id,
  );
  expect(py.normalized.matches[0]?.id).not.toBe(ruby.normalized.matches[0]?.id);
});

test.each([
  { item: cases[0], reportedName: "Synthetic_Lib" },
  { item: cases[6], reportedName: "synthetic.lib" },
])(
  "keeps $item.ecosystem matches persisting after an equivalent package spelling change",
  ({ item, reportedName }) => {
    const base = scanResult(facts(item));
    const head = scanResult(facts(item, item.name, reportedName));
    const comparison = compareScaResults(base, head);
    expect(comparison.comparable).toBe(true);
    expect(base.matches[0]!.id).not.toBe(head.matches[0]!.id);
    expect(comparison.persisting).toEqual([
      {
        baseMatchIds: [base.matches[0]!.id],
        headMatchIds: [head.matches[0]!.id],
      },
    ]);
    expect(comparison.noLongerObserved).toEqual([]);
    expect(comparison.introduced).toEqual([]);
    expect(head.components[0]!.name).toBe(reportedName);
  },
);
