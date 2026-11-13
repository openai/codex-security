import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  SCAN_DIFF_IDENTITY_FIELD,
  SCAN_DIFF_IDENTITY_RULE,
  diffScanFindings,
  findingIdentityKey,
  parseSavedScanFindings,
  tryLoadScanDiffFromPath,
} from "../src/scan-diff.js";
import { CodexSecurityError } from "../src/errors.js";

const fixtureRoot = join(import.meta.dir, "fixtures", "scan-diff");
const scanAPath = join(fixtureRoot, "scan-a");
const scanBPath = join(fixtureRoot, "scan-b");

async function loadFixture(name: "scan-a" | "scan-b") {
  return parseSavedScanFindings(
    await readFile(join(fixtureRoot, name, "findings.json"), "utf8"),
    join(fixtureRoot, name, "findings.json"),
  );
}

describe("scan finding identity", () => {
  test("uses findingId and ignores blank values", () => {
    expect(
      findingIdentityKey({ findingId: "csf_852f90d6e1177502ff113d4a" }),
    ).toBe("csf_852f90d6e1177502ff113d4a");
    expect(findingIdentityKey({ findingId: "  csf_1  " })).toBe("csf_1");
    expect(findingIdentityKey({ findingId: "   " })).toBeUndefined();
    expect(findingIdentityKey({ title: "No identity" })).toBeUndefined();
  });
});

describe("diffScanFindings", () => {
  test("classifies new, resolved, and unchanged findings from saved scan fixtures", async () => {
    const before = await loadFixture("scan-a");
    const after = await loadFixture("scan-b");
    const diff = diffScanFindings(before, after);

    expect(diff.beforeScanId).toBe("scan_diff_fixture_a");
    expect(diff.afterScanId).toBe("scan_diff_fixture_b");
    expect(diff.identity).toEqual({
      field: SCAN_DIFF_IDENTITY_FIELD,
      rule: SCAN_DIFF_IDENTITY_RULE,
    });
    expect(diff.summary).toEqual({ new: 1, resolved: 1, unchanged: 1 });
    expect(
      diff.findings.map(({ status, findingId }) => [status, findingId]),
    ).toEqual([
      ["new", "csf_222222222222222222222222"],
      ["resolved", "csf_111111111111111111111111"],
      ["unchanged", "csf_852f90d6e1177502ff113d4a"],
    ]);

    const unchanged = diff.findings.find(
      (finding) => finding.status === "unchanged",
    )!;
    expect(unchanged.title).toBe(
      "Archive extraction writes outside the output directory",
    );
    expect(unchanged.beforeOccurrenceId).toBe("occ_aaaaaaaaaaaaaaaaaaaaaaaa");
    expect(unchanged.afterOccurrenceId).toBe("occ_cccccccccccccccccccccccc");
  });

  test("does not treat a rewritten title as a new finding", () => {
    const diff = diffScanFindings(
      {
        scanId: "before",
        findings: [
          {
            findingId: "csf_aaaaaaaaaaaaaaaaaaaaaaaa",
            occurrenceId: "occ_before",
            title: "Original title",
            severity: { level: "high" },
            locations: [{ path: "src/a.ts", startLine: 1 }],
          },
        ],
      },
      {
        scanId: "after",
        findings: [
          {
            findingId: "csf_aaaaaaaaaaaaaaaaaaaaaaaa",
            occurrenceId: "occ_after",
            title: "Completely rewritten title",
            severity: { level: "high" },
            locations: [{ path: "src/a.ts", startLine: 4 }],
          },
        ],
      },
    );
    expect(diff.summary).toEqual({ new: 0, resolved: 0, unchanged: 1 });
    expect(diff.findings).toEqual([
      {
        status: "unchanged",
        findingId: "csf_aaaaaaaaaaaaaaaaaaaaaaaa",
        title: "Completely rewritten title",
        severity: "high",
        path: "src/a.ts",
        beforeOccurrenceId: "occ_before",
        afterOccurrenceId: "occ_after",
      },
    ]);
  });

  test("groups multiple occurrences that share a findingId", () => {
    const diff = diffScanFindings(
      {
        scanId: "before",
        findings: [
          { findingId: "csf_1", occurrenceId: "occ_a1", title: "One" },
          { findingId: "csf_1", occurrenceId: "occ_a2", title: "One" },
        ],
      },
      {
        scanId: "after",
        findings: [
          { findingId: "csf_1", occurrenceId: "occ_b1", title: "One" },
        ],
      },
    );
    expect(diff.summary.unchanged).toBe(1);
    expect(diff.findings[0]).toMatchObject({
      status: "unchanged",
      beforeOccurrenceIds: ["occ_a1", "occ_a2"],
      afterOccurrenceId: "occ_b1",
    });
  });

  test("rejects a diff of the same scan", () => {
    expect(() =>
      diffScanFindings(
        { scanId: "scan_same", findings: [] },
        { scanId: "scan_same", findings: [] },
      ),
    ).toThrow(CodexSecurityError);
  });

  test("treats findings without findingId as unmatched", () => {
    const diff = diffScanFindings(
      {
        scanId: "before",
        findings: [{ occurrenceId: "occ_only_before", title: "Orphan" }],
      },
      {
        scanId: "after",
        findings: [{ occurrenceId: "occ_only_after", title: "Orphan" }],
      },
    );
    expect(diff.summary).toEqual({ new: 1, resolved: 1, unchanged: 0 });
  });
});

describe("saved scan fixtures", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(
      tempDirs.splice(0).map((directory) => rm(directory, { recursive: true })),
    );
  });

  test("loads findings.json from a scan directory or file", async () => {
    const fromDirectory = await tryLoadScanDiffFromPath(scanAPath, fixtureRoot);
    const fromFile = await tryLoadScanDiffFromPath(
      join(scanBPath, "findings.json"),
      fixtureRoot,
    );
    expect(fromDirectory?.scanId).toBe("scan_diff_fixture_a");
    expect(fromDirectory?.findings).toHaveLength(2);
    expect(fromFile?.scanId).toBe("scan_diff_fixture_b");
    expect(fromFile?.findings.map(findingIdentityKey)).toEqual([
      "csf_852f90d6e1177502ff113d4a",
      "csf_222222222222222222222222",
    ]);
  });

  test("leaves scan identifiers to the workbench", async () => {
    expect(
      await tryLoadScanDiffFromPath("scan_diff_fixture_a", fixtureRoot),
    ).toBeUndefined();
  });

  test("rejects a missing filesystem scan", async () => {
    await expect(
      tryLoadScanDiffFromPath("./missing-scan", fixtureRoot),
    ).rejects.toThrow(/was not found/);
  });

  test("rejects a directory without findings.json", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-scan-diff-"),
    );
    tempDirs.push(directory);
    await mkdir(join(directory, "empty"), { recursive: true });
    await expect(
      tryLoadScanDiffFromPath(join(directory, "empty"), directory),
    ).rejects.toThrow(/does not contain findings.json/);
  });

  test("rejects invalid findings JSON", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-scan-diff-"),
    );
    tempDirs.push(directory);
    const path = join(directory, "findings.json");
    await writeFile(path, "{");
    await expect(tryLoadScanDiffFromPath(path, directory)).rejects.toThrow(
      /Could not parse findings/,
    );
    await writeFile(path, JSON.stringify({ findings: ["nope"] }));
    await expect(tryLoadScanDiffFromPath(path, directory)).rejects.toThrow(
      /invalid finding/,
    );
  });
});
