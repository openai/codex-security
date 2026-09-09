import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type {
  FindingsDocument,
  JsonObject,
  ScanManifest,
} from "../src/index.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import {
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
  type ScanMatchingBatch,
} from "../src/scan-comparison.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const empty = { matches: [], uncertain: [] } satisfies ScanComparisonResult;

function confirmed(
  before: { occurrenceId: string },
  after: { occurrenceId: string },
): ScanComparisonResult {
  return {
    matches: [
      {
        beforeOccurrenceIds: [before.occurrenceId],
        afterOccurrenceIds: [after.occurrenceId],
        confidence: "high",
        reason: "The same synthetic root control.",
      },
    ],
    uncertain: [],
  };
}

test("matches sealed scan history end to end without merging related findings", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-matching-")),
  );
  try {
    const python = await resolvePluginPython();
    const repository = join(root, "repository");
    const state = join(root, "state");
    await mkdir(join(repository, "src"), { recursive: true });
    await writeFile(
      join(repository, "src", "extract.py"),
      "# Synthetic fixture\n",
    );
    const environment = {
      PATH: process.env["PATH"],
      CODEX_SECURITY_STATE_DIR: state,
    };
    const workbench = (
      args: readonly string[],
      input?: string,
      signal?: AbortSignal,
    ) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment, signal },
        args,
        input,
      );
    const readJson = async <T>(path: string): Promise<T> =>
      JSON.parse(await readFile(path, "utf8")) as T;
    const writeJson = async (path: string, value: unknown) =>
      writeFile(path, JSON.stringify(value));
    const artifacts: string[] = [];

    async function scan(names: string[]) {
      const scanDir = join(root, `scan-${names[0]}`);
      await mkdir(scanDir, { mode: 0o700 });
      const registered = await workbench([
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository,
          target: { kind: "repository", paths: [] },
        }),
      ]);
      const scanId = String(registered["scanId"]);
      await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
        recursive: true,
      });
      const manifest = await readJson<ScanManifest>(
        join(scanDir, "scan-manifest.json"),
      );
      manifest.scan.id = scanId;
      manifest.scan.target.kind = "directory_snapshot";
      const draftScan: Partial<ScanManifest["scan"]> = manifest.scan;
      delete draftScan.sealedAt;
      delete draftScan.artifacts;
      await writeJson(join(scanDir, "scan-manifest.json"), manifest);
      const document = await readJson<FindingsDocument>(
        join(scanDir, "findings.json"),
      );
      const example = document.findings[0]!;
      document.scanId = scanId;
      document.findings = names.map((name) => ({
        ...example,
        identity: { anchor: `synthetic-${name}` },
        title: `Synthetic control ${name}`,
        summary:
          name === "d"
            ? "A distinct archive-reader control."
            : "The shared archive-writer control.",
        rootCause:
          name === "d"
            ? "The reader checks a different boundary."
            : "The writer omits containment.",
        remediation:
          name === "d"
            ? "Validate the reader boundary."
            : "Validate the shared writer boundary.",
        locations: [
          {
            path: "src/extract.py",
            startLine: 1,
            endLine: 1,
            role: "root_control",
          },
        ],
        codeEvidence: [
          {
            id: `evidence-${name}`,
            label: "Synthetic evidence",
            path: "src/extract.py",
            startLine: 1,
            code: `SYNTHETIC_DETAIL_${name}`,
            explanation: "Fixture evidence only.",
          },
        ],
      }));
      await writeJson(join(scanDir, "findings.json"), document);
      const coverage = await readJson<JsonObject>(
        join(scanDir, "coverage.json"),
      );
      coverage["scanId"] = scanId;
      await writeJson(join(scanDir, "coverage.json"), coverage);
      await writeFile(join(scanDir, "report.md"), "# Synthetic scan\n");
      const completed = await workbench(["complete-scan", "--scan-id", scanId]);
      expect(completed["scan"]).toMatchObject({
        progress: { status: "complete" },
        findingCount: names.length,
      });
      artifacts.push(
        ...[
          "scan-manifest.json",
          "findings.json",
          "coverage.json",
          "report.md",
        ].map((name) => join(scanDir, name)),
      );
      const sealed = await readJson<FindingsDocument>(
        join(scanDir, "findings.json"),
      );
      return { scanId, findings: sealed.findings };
    }

    const first = await scan(["a"]);
    const second = await scan(["b"]);
    const third = await scan(["c", "d"]);
    const fourth = await scan(["e"]);
    const [a, b, c, d, e] = [
      first.findings[0]!,
      second.findings[0]!,
      third.findings[0]!,
      third.findings[1]!,
      fourth.findings[0]!,
    ];
    const digest = async () =>
      Promise.all(
        artifacts.map(async (path) =>
          createHash("sha256")
            .update(await readFile(path))
            .digest("hex"),
        ),
      );
    const originalArtifacts = await digest();
    const save = (
      before: string,
      after: string,
      result: ScanComparisonResult,
    ) =>
      workbench(
        [
          "save-scan-comparison",
          "--before-scan-id",
          before,
          "--after-scan-id",
          after,
          "--matches-json-stdin",
        ],
        JSON.stringify(result),
      );
    await save(first.scanId, second.scanId, confirmed(a, b));
    await save(second.scanId, fourth.scanId, confirmed(b, e));

    const historical = await workbench([
      "compare-scans",
      "--before-scan-id",
      first.scanId,
      "--after-scan-id",
      third.scanId,
      "--include-matching-inputs",
    ]);
    expect(
      (historical["matchingInputs"] as unknown as ScanComparisonInput)
        .knownFindingGroups,
    ).toEqual([[a.findingId, b.findingId].sort()]);
    const plan = await workbench([
      "list-unmatched-scan-pairs",
      "--repository",
      repository,
    ]);
    const batches = plan["batches"] as unknown as ScanMatchingBatch[];
    expect(
      batches.find(({ afterScanId }) => afterScanId === third.scanId)
        ?.knownFindingGroups,
    ).toEqual([[a.findingId, b.findingId].sort()]);
    expect(
      batches.find(({ afterScanId }) => afterScanId === fourth.scanId)
        ?.knownFindingGroups,
    ).toEqual([[a.findingId, b.findingId, e.findingId].sort()]);
    const resumedPair = await workbench([
      "compare-scans",
      "--before-scan-id",
      first.scanId,
      "--after-scan-id",
      fourth.scanId,
      "--include-matching-inputs",
    ]);
    const reused = await matchScanFindings(
      resumedPair["matchingInputs"] as unknown as ScanComparisonInput,
      {
        codex: {
          startThread() {
            throw new Error("An already-confirmed alias must not need Codex.");
          },
        },
      },
    );
    expect(reused.matches).toEqual([
      expect.objectContaining({
        beforeOccurrenceIds: [a.occurrenceId],
        afterOccurrenceIds: [e.occurrenceId],
      }),
    ]);
    const recomputedPair = await workbench([
      "compare-scans",
      "--before-scan-id",
      first.scanId,
      "--after-scan-id",
      second.scanId,
      "--include-matching-inputs",
    ]);
    expect(
      (recomputedPair["matchingInputs"] as unknown as ScanComparisonInput)
        .knownFindingGroups,
    ).toBeUndefined();
    const forced = await workbench([
      "list-unmatched-scan-pairs",
      "--repository",
      repository,
      "--force",
    ]);
    expect(
      (forced["batches"] as unknown as ScanMatchingBatch[]).every(
        (batch) => batch.knownFindingGroups === undefined,
      ),
    ).toBe(true);

    let modelCalls = 0;
    const issueCounts: number[] = [];
    const onMatch = async (
      input: ScanComparisonInput,
      options?: ScanComparisonOptions,
    ) => {
      const current = input.after.find(
        ({ occurrenceId }) => occurrenceId !== d.occurrenceId,
      )!;
      const representative =
        current.occurrenceId === b.occurrenceId
          ? a
          : current.occurrenceId === c.occurrenceId
            ? b
            : c;
      const result = confirmed(representative, current);
      if (current.occurrenceId === c.occurrenceId) {
        result.related = [
          {
            beforeOccurrenceId: b.occurrenceId,
            afterOccurrenceId: d.occurrenceId,
            reason: "Separate reader and writer controls.",
          },
        ];
      } else if (current.occurrenceId === e.occurrenceId) {
        result.related = [
          {
            beforeOccurrenceId: d.occurrenceId,
            afterOccurrenceId: e.occurrenceId,
            reason: "Separate reader and writer controls.",
          },
        ];
      }
      let turns = 0;
      return await matchScanFindings(input, {
        ...options,
        codex: {
          startThread() {
            modelCalls += 1;
            return {
              async run(prompt) {
                const payload = JSON.parse(
                  prompt.slice(prompt.lastIndexOf("\n") + 1),
                ) as { findings?: ScanComparisonInput; content?: string };
                if (turns++ === 0) {
                  issueCounts.push(payload.findings!.before.length);
                  expect(prompt).not.toContain("SYNTHETIC_DETAIL_");
                  if (current.occurrenceId === c.occurrenceId)
                    return {
                      finalResponse: JSON.stringify({
                        ...empty,
                        request: {
                          kind: "evidence",
                          beforeOccurrenceIds: [b.occurrenceId],
                          afterOccurrenceIds: [c.occurrenceId],
                          offset: 0,
                        },
                      }),
                    };
                } else {
                  const evidence = JSON.parse(
                    payload.content!,
                  ) as ScanComparisonInput;
                  expect(
                    evidence.before.map(({ occurrenceId }) => occurrenceId),
                  ).toEqual([a.occurrenceId, b.occurrenceId]);
                  expect(
                    evidence.after.map(({ occurrenceId }) => occurrenceId),
                  ).toEqual([c.occurrenceId]);
                }
                return { finalResponse: JSON.stringify(result) };
              },
            };
          },
        },
      });
    };
    const cli = async (args: string[], matcher = onMatch) => {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          [...args, "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({
            currentDirectory: repository,
            environment,
            onWorkbench: workbench,
            onMatch: matcher,
          }),
        ),
        stderr.text(),
      ).toBe(0);
      return JSON.parse(stdout.text()) as JsonObject;
    };

    for (const [before, after] of [
      [first.scanId, third.scanId],
      [second.scanId, third.scanId],
      [third.scanId, fourth.scanId],
    ] as const) {
      await save(before, after, empty);
    }
    expect(
      await cli(["scans", "match", "--all"], async (input, options) =>
        matchScanFindings(input, {
          ...options,
          codex: {
            startThread() {
              throw new Error("Cached transitive links must not need Codex.");
            },
          },
        }),
      ),
    ).toMatchObject({ matchedPairs: 1, skippedPairs: 5, findingMatches: 1 });
    expect(modelCalls).toBe(0);

    expect(await cli(["scans", "match", "--all", "--force"])).toMatchObject({
      scanCount: 4,
      matchedPairs: 6,
      findingMatches: 6,
      relatedPairs: 3,
      uncertainPairs: 0,
    });
    expect(modelCalls).toBe(3);
    expect(issueCounts).toEqual([1, 1, 2]);
    const compared = await cli([
      "scans",
      "compare",
      first.scanId,
      third.scanId,
    ]);
    expect(compared).toMatchObject({
      summary: { new: 1, persisting: 1, resolved: 0 },
      related: [
        {
          beforeOccurrenceId: a.occurrenceId,
          afterOccurrenceId: d.occurrenceId,
          beforeTitle: a.title,
          afterTitle: d.title,
        },
      ],
    });
    const findings = await cli(["findings", "list"]);
    expect(findings["findings"]).toHaveLength(2);
    expect(findings["findings"]).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ findingId: e.findingId, occurrenceCount: 4 }),
        expect.objectContaining({ findingId: d.findingId, occurrenceCount: 1 }),
      ]),
    );
    const detail = await workbench([
      "get-scan",
      "--scan-id",
      third.scanId,
      "--occurrence-id",
      d.occurrenceId,
    ]);
    expect(detail["scan"]).toMatchObject({
      findings: expect.arrayContaining([
        expect.objectContaining({
          occurrenceId: d.occurrenceId,
          related: expect.arrayContaining([
            expect.objectContaining({ occurrenceId: e.occurrenceId }),
          ]),
        }),
      ]),
    });
    expect(await cli(["scans", "match", "--all"])).toMatchObject({
      matchedPairs: 0,
      skippedPairs: 6,
    });
    expect(modelCalls).toBe(3);

    const combinedReason =
      "Later synthetic evidence confirms a combined control.";
    const combined = await save(third.scanId, fourth.scanId, {
      matches: [
        {
          beforeOccurrenceIds: [c.occurrenceId, d.occurrenceId],
          afterOccurrenceIds: [e.occurrenceId],
          confidence: "high",
          reason: combinedReason,
        },
      ],
      uncertain: [],
    });
    expect((combined["findings"] as JsonObject[])[0]?.["matchReason"]).toBe(
      combinedReason,
    );
    const linkedComparison = await cli([
      "scans",
      "compare",
      first.scanId,
      third.scanId,
    ]);
    expect(linkedComparison).toMatchObject({
      summary: { new: 0, persisting: 1, resolved: 0, unknown: 0 },
      findings: [
        {
          beforeOccurrenceId: a.occurrenceId,
          afterOccurrenceIds: [c.occurrenceId, d.occurrenceId],
          matchReason: "The same synthetic root control.",
          status: "persisting",
        },
      ],
    });
    expect(linkedComparison["related"]).toBeUndefined();
    const linkedDetail = await workbench([
      "get-scan",
      "--scan-id",
      third.scanId,
      "--occurrence-id",
      d.occurrenceId,
    ]);
    const linkedFinding = (
      (linkedDetail["scan"] as JsonObject)["findings"] as JsonObject[]
    ).find((finding) => finding["occurrenceId"] === d.occurrenceId);
    expect(linkedFinding).toBeDefined();
    expect(linkedFinding?.["related"]).toBeUndefined();
    expect(await digest()).toEqual(originalArtifacts);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
