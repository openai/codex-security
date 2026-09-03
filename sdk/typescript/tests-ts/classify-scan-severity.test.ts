import { spawnSync } from "node:child_process";
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
  readScanSeverityClassification,
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
import { resolvePluginPython } from "../src/runtime.js";
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
    environment: {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
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

async function query(environment: NodeJS.ProcessEnv, sql: string) {
  const result = spawnSync(
    await resolvePluginPython({ environment }),
    [
      "-c",
      "import json,sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.row_factory=sqlite3.Row; print(json.dumps([dict(r) for r in c.execute(sys.argv[2]) ])); c.commit()",
      join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
      sql,
    ],
    { encoding: "utf8", env: environment },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Record<string, unknown>[];
}

function recordingClassifier() {
  const calls: string[] = [];
  const control = { failOn: "", excluded: false };
  const codex: NonNullable<ClassifySeverityOptions["codex"]> = {
    startThread: (thread) => ({
      run: async (prompt, turn) => {
        const { finding } = JSON.parse(prompt.split("\n\n").at(-1)!) as {
          finding: Finding;
        };
        calls.push(finding.findingId);
        if (finding.findingId === control.failOn)
          throw new Error("Interrupted model call");
        return classifier(finding, control.excluded)
          .startThread(thread)
          .run(prompt, turn);
      },
    }),
  };
  return { codex, calls, control };
}

test("checkpoints each finding, resumes missing work, and reprocesses only the selection", async () => {
  const { environment, scanDirectory, rubricPath, findings } = await fixture();
  const { codex, calls, control } = recordingClassifier();
  const options = { environment, rubricPath, codex };
  control.failOn = findings[1]!.findingId;
  await expect(
    classifyScanDirectorySeverity(scanDirectory, options),
  ).rejects.toThrow("Interrupted model call");
  expect(
    (
      await query(
        environment,
        "SELECT finding_id FROM finding_severity_assessments",
      )
    ).map((row) => row["finding_id"]),
  ).toEqual([findings[0]!.findingId]);
  await expect(
    prepareScanPublication(scanDirectory, { ...destination, environment }),
  ).rejects.toThrow("incomplete");
  control.failOn = "";
  calls.length = 0;
  const complete = await classifyScanDirectorySeverity(scanDirectory, options);
  expect(calls).toEqual([findings[1]!.findingId]);
  expect(complete.assessments).toHaveLength(2);
  const { scanId: _scanId, ...assessment } = complete;
  expect(
    await readScanSeverityClassification(
      scanDirectory,
      complete.scanId,
      findings,
      undefined,
      environment,
    ),
  ).toEqual(assessment);
  const rows = await query(
    environment,
    "SELECT * FROM finding_severity_assessments ORDER BY finding_id",
  );
  calls.length = 0;
  expect(
    (await classifyScanDirectorySeverity(scanDirectory, options)).assessments,
  ).toEqual(complete.assessments);
  expect(calls).toEqual([]);
  expect(
    await query(
      environment,
      "SELECT * FROM finding_severity_assessments ORDER BY finding_id",
    ),
  ).toEqual(rows);

  control.excluded = true;
  const selected = {
    ...options,
    findingIds: [findings[0]!.findingId],
    reprocess: true,
  };
  const revised = await classifyScanDirectorySeverity(scanDirectory, selected);
  expect(calls).toEqual([findings[0]!.findingId]);
  expect(revised.assessments[0]!.decision).toBe("excluded");
  const revisedRows = await query(
    environment,
    "SELECT * FROM finding_severity_assessments ORDER BY finding_id",
  );
  expect(revisedRows).toHaveLength(2);
  expect(
    revisedRows.find((row) => row["finding_id"] === findings[1]!.findingId),
  ).toEqual(rows.find((row) => row["finding_id"] === findings[1]!.findingId));
  calls.length = 0;
  expect(
    (await classifyScanDirectorySeverity(scanDirectory, options))
      .assessments[0]!.decision,
  ).toBe("excluded");
  expect(calls).toEqual([]);
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toHaveLength(1);

  control.failOn = findings[0]!.findingId;
  await expect(
    classifyScanDirectorySeverity(scanDirectory, selected),
  ).rejects.toThrow("Interrupted model call");
  expect(
    await query(
      environment,
      "SELECT * FROM finding_severity_assessments ORDER BY finding_id",
    ),
  ).toEqual(revisedRows);
});

test("changed rubric, context, or evidence invalidates matching checkpoints", async () => {
  const { environment, root, scanDirectory, rubricPath, findings } =
    await fixture();
  const { codex, calls } = recordingClassifier();
  const options = { environment, rubricPath, codex };
  await classifyScanDirectorySeverity(scanDirectory, options);
  const originalFindings = await query(
    environment,
    "SELECT * FROM findings ORDER BY id",
  );
  calls.length = 0;
  await writeFile(rubricPath, "Assign Medium to bounded metadata reads.");
  await classifyScanDirectorySeverity(scanDirectory, options);
  expect(calls).toHaveLength(2);
  const context = join(root, "context.md");
  await writeFile(context, "The system contains operational counters.");
  calls.length = 0;
  const withContext = { ...options, knowledgeBasePaths: [context] };
  await classifyScanDirectorySeverity(scanDirectory, withContext);
  expect(calls).toHaveLength(2);
  calls.length = 0;
  await writeFile(context, "The counters include protected metadata.");
  await classifyScanDirectorySeverity(scanDirectory, withContext);
  expect(calls).toHaveLength(2);

  const findingPath = join(scanDirectory, "findings.json");
  const document = JSON.parse(
    await readFile(findingPath, "utf8"),
  ) as FindingsDocument;
  document.findings[0]!.summary = "Additional evidence about the same finding.";
  await writeFile(findingPath, JSON.stringify(document));
  const manifestPath = join(scanDirectory, "scan-manifest.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ScanManifest;
  for (const artifact of manifest.scan.artifacts)
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(scanDirectory, artifact.path)))
      .digest("hex");
  await writeFile(manifestPath, JSON.stringify(manifest));
  await expect(
    prepareScanPublication(scanDirectory, { ...destination, environment }),
  ).rejects.toThrow("does not match");
  calls.length = 0;
  await classifyScanDirectorySeverity(scanDirectory, withContext);
  expect(calls).toEqual([findings[0]!.findingId]);
  expect(
    await query(environment, "SELECT * FROM findings ORDER BY id"),
  ).toEqual(originalFindings);
});

test("classification refuses to store workflow state inside sealed scan artifacts", async () => {
  const { environment, scanDirectory } = await fixture();
  await expect(
    classifyScanDirectorySeverity(scanDirectory, {
      environment: {
        ...environment,
        CODEX_SECURITY_STATE_DIR: join(scanDirectory, "state"),
      },
    }),
  ).rejects.toThrow("outside");
});

test("a classified dedupe selection drives Linear priority and preserves sealed evidence", async () => {
  const { environment, scanDirectory, rubricPath, findings, scanId } =
    await fixture();
  const before = await loadContract(scanDirectory, { pluginRoot: PLUGIN_ROOT });
  const classification = await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    findingIds: [findings[1]!.findingId],
    rubricPath,
    codex: classifier(findings[1]!),
  });
  expect(classification.scanId).toBe(scanId);
  expect(classification.assessments).toHaveLength(1);
  const result = await publishScanInternal(
    scanDirectory,
    {
      ...destination,
      dryRun: true,
    },
    { environment },
  );
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
      environment,
      ...destination,
      findingIds: [findings[0]!.findingId],
    }),
  ).rejects.toThrow("missing from");
});

test("publication accepts in-memory assessments and exact ID selections", async () => {
  const { environment, scanDirectory, rubricPath, findings } = await fixture();
  const classification = await classifySeverity([findings[0]!], {
    rubricPath,
    codex: classifier(findings[0]!),
  });
  const prepared = await prepareScanPublication(scanDirectory, {
    environment,
    ...destination,
    classification,
  });
  expect(prepared.issues).toHaveLength(1);
  expect(prepared.issues[0]!.priority).toBe(3);
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        environment,
        ...destination,
        findingIds: [findings[1]!.findingId],
      })
    ).issues[0]!.priority,
  ).toBe(2);
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toHaveLength(2);
  await expect(
    prepareScanPublication(scanDirectory, {
      environment,
      ...destination,
      findingIds: ["not-in-scan"],
    }),
  ).rejects.toThrow("belong");
});

test("exclusions and empty dedupe selections do not create tickets", async () => {
  const { environment, scanDirectory, rubricPath, findings } = await fixture();
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    findingIds: [findings[0]!.findingId],
    rubricPath,
    codex: classifier(findings[0]!, true),
  });
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toEqual([]);
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    findingIds: [],
  });
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toEqual([]);
});

test("failed or canceled reassessment leaves the last successful assessment intact", async () => {
  const { environment, scanDirectory, rubricPath, findings } = await fixture();
  await classifyScanDirectorySeverity(scanDirectory, { environment });
  const path = join(scanDirectory, "severity-classification.json");
  const before = await readFile(path);
  await expect(
    classifyScanDirectorySeverity(scanDirectory, {
      environment,
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
      environment,
      rubricPath,
      codex,
      signal: controller.signal,
    }),
  ).rejects.toThrow();
  expect(await readFile(path)).toEqual(before);
});

test("publication reads SQLite even when the JSON export is modified or symlinked", async () => {
  const { environment, root, scanDirectory, findings } = await fixture();
  const result = await classifyScanDirectorySeverity(scanDirectory, {
    environment,
  });
  const path = join(scanDirectory, "severity-classification.json");
  await writeFile(path, JSON.stringify({ ...result, scanId: "other-scan" }));
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toHaveLength(findings.length);
  const stale = await classifySeverity([
    { ...findings[0]!, summary: "Different report" },
  ]);
  await expect(
    prepareScanPublication(scanDirectory, {
      environment,
      ...destination,
      classification: stale,
    }),
  ).rejects.toThrow("does not match");
  await rm(path);
  const external = join(root, "outside.json");
  await writeFile(external, JSON.stringify(result));
  await symlink(external, path);
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toHaveLength(findings.length);
  await classifyScanDirectorySeverity(scanDirectory, { environment });
  expect(await readFile(external, "utf8")).toBe(JSON.stringify(result));
});

test.each(["latest", "scan_prefix"])(
  "resolves %s using existing saved-scan history",
  async (selector) => {
    const { environment, scanDirectory, scanId } = await fixture();
    const seen: string[][] = [];
    const result = await classifyScanSeverityInternal(
      selector,
      { environment },
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
        environment,
        expectedScanId: "other-scan",
      }),
    ).rejects.toThrow("do not match");
  },
);

test("migrates existing databases without changing findings and reads older state without writes", async () => {
  const { environment, scanDirectory } = await fixture();
  await classifyScanDirectorySeverity(scanDirectory, { environment });
  const original = await query(
    environment,
    "SELECT * FROM findings ORDER BY id",
  );
  await query(environment, "DROP TABLE finding_severity_assessments");
  await query(environment, "DROP TABLE scan_severity_classifications");
  await query(environment, "DELETE FROM schema_migrations WHERE version = 41");
  expect(
    (
      await prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
      })
    ).issues,
  ).toHaveLength(2);
  expect(
    await query(
      environment,
      "SELECT version FROM schema_migrations WHERE version = 41",
    ),
  ).toEqual([]);
  await classifyScanDirectorySeverity(scanDirectory, { environment });
  expect(
    await query(
      environment,
      "SELECT version FROM schema_migrations WHERE version = 41",
    ),
  ).toEqual([{ version: 41 }]);
  expect(
    await query(environment, "SELECT * FROM findings ORDER BY id"),
  ).toEqual(original);
});
