import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  classifyScanDirectorySeverity,
  classifyScanSeverityInternal,
} from "../src/classify-scan-severity.js";
import {
  classifySeverity,
  type ClassifySeverityOptions,
} from "../src/classify-severity.js";
import { loadContract } from "../src/contract.js";
import type { JsonObject } from "../src/config.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import { prepareScanPublication } from "../src/publication.js";
import { publishScanInternal } from "../src/publish.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
const destination = { destination: "linear", teamId: "team-example" } as const;
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "classify-scan-"));
  directories.push(root);
  const scanDirectory = join(root, "scan");
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDirectory, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scanDirectory, 0o700);
  const manifest = JSON.parse(
    await readFile(join(scanDirectory, "scan-manifest.json"), "utf8"),
  ) as ScanManifest;
  const document = JSON.parse(
    await readFile(join(scanDirectory, "findings.json"), "utf8"),
  ) as FindingsDocument;
  const other = structuredClone(document.findings[0]!);
  other.identity.instance = "second-instance";
  const sha256 = (input: string | Buffer) =>
    createHash("sha256").update(input).digest("hex");
  const fingerprint = `codex-security/v1:sha256:${sha256(
    [
      "codex-security/v1",
      manifest.scan.target.targetId,
      other.ruleId,
      other.identity.anchor,
      other.identity.instance,
    ].join("\0"),
  )}`;
  other.fingerprints.primary = fingerprint;
  other.findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
  other.occurrenceId = `occ_${sha256([manifest.scan.id, fingerprint].join("\0")).slice(0, 24)}`;
  document.findings.push(other);
  await writeFile(
    join(scanDirectory, "findings.json"),
    JSON.stringify(document),
  );
  for (const artifact of manifest.scan.artifacts)
    artifact.sha256 = sha256(
      await readFile(join(scanDirectory, artifact.path)),
    );
  await writeFile(
    join(scanDirectory, "scan-manifest.json"),
    JSON.stringify(manifest),
  );
  const rubricPath = join(root, "policy.md");
  await writeFile(
    rubricPath,
    "Assign Medium to bounded harm. Exclude administrative records.",
  );
  return {
    root,
    scanDirectory,
    rubricPath,
    findings: document.findings,
    scanId: manifest.scan.id,
  };
}

function classifier(
  finding: Finding,
  excluded = false,
): NonNullable<ClassifySeverityOptions["codex"]> {
  return {
    startThread: () => ({
      run: async () => ({
        finalResponse: JSON.stringify({
          findingId: finding.findingId,
          decision: excluded ? "excluded" : "assessed",
          level: excluded ? null : "medium",
          rubricLabel: excluded ? null : "MEDIUM",
          rationale: excluded
            ? "Administrative record"
            : "Only bounded impact is established.",
          confidence: "high",
          reviewTrigger: null,
        }),
      }),
    }),
  };
}

test("a classified dedupe selection drives Linear priority and preserves sealed evidence", async () => {
  const { scanDirectory, rubricPath, findings, scanId } = await fixture();
  const before = await loadContract(scanDirectory, { pluginRoot: PLUGIN_ROOT });
  const classification = await classifyScanDirectorySeverity(scanDirectory, {
    findingIds: [findings[1]!.findingId],
    rubricPath,
    codex: classifier(findings[1]!),
  });
  expect(classification.scanId).toBe(scanId);
  expect(classification.assessments).toHaveLength(1);
  const result = await publishScanInternal(scanDirectory, {
    ...destination,
    dryRun: true,
  });
  expect(result.issues).toHaveLength(1);
  expect(result.issues![0]).toMatchObject({
    findingId: findings[1]!.findingId,
    priority: 3,
  });
  expect(result.issues![0]!.title).toContain("[MEDIUM]");
  expect(result.issues![0]!.description).toContain("**Severity:** HIGH");
  expect(result.issues![0]!.description).toContain(
    "Only bounded impact is established.",
  );
  expect(
    await loadContract(scanDirectory, { pluginRoot: PLUGIN_ROOT }),
  ).toEqual(before);
  await expect(
    prepareScanPublication(scanDirectory, {
      ...destination,
      findingIds: [findings[0]!.findingId],
    }),
  ).rejects.toThrow("missing from");
});

test("publication accepts in-memory assessments and exact ID selections", async () => {
  const { scanDirectory, rubricPath, findings } = await fixture();
  const classification = await classifySeverity([findings[0]!], {
    rubricPath,
    codex: classifier(findings[0]!),
  });
  const prepared = await prepareScanPublication(scanDirectory, {
    ...destination,
    classification,
  });
  expect(prepared.issues).toHaveLength(1);
  expect(prepared.issues[0]!.priority).toBe(3);
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        findingIds: [findings[1]!.findingId],
      })
    ).issues[0]!.priority,
  ).toBe(2);
  expect(
    (await prepareScanPublication(scanDirectory, destination)).issues,
  ).toHaveLength(2);
  await expect(
    prepareScanPublication(scanDirectory, {
      ...destination,
      findingIds: ["not-in-scan"],
    }),
  ).rejects.toThrow("belong");
});

test("exclusions and empty dedupe selections do not create tickets", async () => {
  const { scanDirectory, rubricPath, findings } = await fixture();
  await classifyScanDirectorySeverity(scanDirectory, {
    findingIds: [findings[0]!.findingId],
    rubricPath,
    codex: classifier(findings[0]!, true),
  });
  expect(
    (await prepareScanPublication(scanDirectory, destination)).issues,
  ).toEqual([]);
  await classifyScanDirectorySeverity(scanDirectory, { findingIds: [] });
  expect(
    (await prepareScanPublication(scanDirectory, destination)).issues,
  ).toEqual([]);
});

test("failed or canceled reassessment leaves the last successful assessment intact", async () => {
  const { scanDirectory, rubricPath, findings } = await fixture();
  await classifyScanDirectorySeverity(scanDirectory);
  const path = join(scanDirectory, "severity-classification.json");
  const before = await readFile(path);
  await expect(
    classifyScanDirectorySeverity(scanDirectory, {
      rubricPath,
      codex: classifier({ ...findings[0]!, findingId: "wrong" }),
    }),
  ).rejects.toThrow("invalid assessment");
  expect(await readFile(path)).toEqual(before);
  const controller = new AbortController();
  const codex: NonNullable<ClassifySeverityOptions["codex"]> = {
    startThread: () => ({
      run: async () => {
        controller.abort(new Error("stop"));
        return { finalResponse: "{}" };
      },
    }),
  };
  await expect(
    classifyScanDirectorySeverity(scanDirectory, {
      rubricPath,
      codex,
      signal: controller.signal,
    }),
  ).rejects.toThrow();
  expect(await readFile(path)).toEqual(before);
});

test("rejects assessments from another scan, changed evidence, and symlinked sidecars", async () => {
  const { root, scanDirectory, findings } = await fixture();
  const result = await classifyScanDirectorySeverity(scanDirectory);
  const path = join(scanDirectory, "severity-classification.json");
  await writeFile(path, JSON.stringify({ ...result, scanId: "other-scan" }));
  await expect(
    prepareScanPublication(scanDirectory, destination),
  ).rejects.toThrow("different scan");
  const stale = await classifySeverity([
    { ...findings[0]!, summary: "Different report" },
  ]);
  await expect(
    prepareScanPublication(scanDirectory, {
      ...destination,
      classification: stale,
    }),
  ).rejects.toThrow("does not match");
  await rm(path);
  const external = join(root, "outside.json");
  await writeFile(external, JSON.stringify(result));
  await symlink(external, path);
  await expect(
    prepareScanPublication(scanDirectory, destination),
  ).rejects.toThrow();
  await classifyScanDirectorySeverity(scanDirectory);
  expect(await readFile(external, "utf8")).toBe(JSON.stringify(result));
});

test.each(["latest", "scan_prefix"])(
  "resolves %s using existing saved-scan history",
  async (selector) => {
    const { scanDirectory, scanId } = await fixture();
    const seen: string[][] = [];
    const result = await classifyScanSeverityInternal(
      selector,
      {},
      {
        currentDirectory: () => scanDirectory,
        runWorkbench: async (args): Promise<JsonObject> => {
          seen.push([...args]);
          return args[0] === "list-scans"
            ? { scans: [{ scanId }] }
            : {
                scan: {
                  scanId,
                  scanDir: scanDirectory,
                  progress: { status: "complete" },
                },
              };
        },
      },
    );
    expect(result.scanId).toBe(scanId);
    expect(seen.at(-1)).toEqual([
      "get-scan",
      "--scan-id",
      selector === "latest" ? scanId : selector,
    ]);
    await expect(
      classifyScanDirectorySeverity(scanDirectory, {
        expectedScanId: "other-scan",
      }),
    ).rejects.toThrow("do not match");
  },
);
