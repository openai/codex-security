import { codexWithRun, jsonCodex } from "./support/codex.js";
import { setFindingIdentity, sha256 } from "./support/finding-identity.js";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  classifyScanDirectorySeverity,
  type ClassifyScanSeverityOptions,
  classifyScanSeverityInternal,
  readScanSeverityClassification,
} from "../src/classify-scan-severity.js";
import {
  classifySeverity,
  type ClassifySeverityOptions,
} from "../src/classify-severity.js";
import { Database } from "bun:sqlite";
import { loadContract } from "../src/contract.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { defaultSeverityRubric } from "../src/default-severity-rubric.js";
import type { JsonObject } from "../src/config.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import {
  prepareScanPublication,
  type PrepareScanPublicationOptions,
} from "../src/publication.js";
import { publishScanInternal } from "../src/publish.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { scanRegistrationArguments } from "./support/workbench-command.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "classify-scan-",
  false,
);
const destination = { destination: "linear", teamId: "team-example" } as const;
afterEach(cleanup);

async function writeScanArtifacts(root: string, scanId?: string) {
  const scanDirectory = join(root, "scan");
  await copyCompletedScanFixture(scanDirectory);
  if (process.platform !== "win32") await chmod(scanDirectory, 0o700);
  const manifest = JSON.parse(
    await readFile(join(scanDirectory, "scan-manifest.json"), "utf8"),
  ) as ScanManifest;
  const document = JSON.parse(
    await readFile(join(scanDirectory, "findings.json"), "utf8"),
  ) as FindingsDocument;
  const other = structuredClone(document.findings[0]!);
  other.identity.instance = "second-instance";
  setFindingIdentity(manifest.scan, other);
  document.findings.push(other);
  if (scanId) {
    manifest.scan.id = scanId;
    document.scanId = scanId;
    for (const finding of document.findings)
      setFindingIdentity(manifest.scan, finding);
    const coveragePath = join(scanDirectory, "coverage.json");
    const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
    coverage.scanId = scanId;
    await writeFile(coveragePath, JSON.stringify(coverage));
  }
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

async function fixture(scanId?: string, sharedEnvironment?: NodeJS.ProcessEnv) {
  const root = await temporaryDirectory();
  const artifacts = await writeScanArtifacts(root, scanId);
  const { scanDirectory, findings } = artifacts;
  const environment: NodeJS.ProcessEnv = sharedEnvironment ?? {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  return {
    ...artifacts,
    environment,
    query(sql: string) {
      using database = new Database(
        join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
      );
      database.run("PRAGMA foreign_keys = ON");
      return database.query<Record<string, unknown>, []>(sql).all();
    },
    classify: (options: ClassifyScanSeverityOptions) =>
      classifyScanDirectorySeverity(scanDirectory, { environment, ...options }),
    preparePublication: (
      options: Pick<
        PrepareScanPublicationOptions,
        "findingIds" | "classification"
      > = {},
    ) =>
      prepareScanPublication(scanDirectory, {
        ...destination,
        environment,
        ...options,
      }),
    readClassification: (id: string, env = environment) =>
      readScanSeverityClassification(
        scanDirectory,
        id,
        findings,
        undefined,
        env,
      ),
  };
}

async function savedFixture() {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const caller = join(root, "caller");
  const scanDirectory = join(root, "scan");
  for (const directory of [repository, caller, scanDirectory])
    await mkdir(directory, { mode: 0o700 });
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    HOME: root,
    USERPROFILE: root,
    CODEX_HOME: join(root, "codex"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    CODEX_SECURITY_NO_UPDATE_NOTICE: "1",
  };
  const python = await resolvePluginPython({ environment });
  const workbench = { environment, python, pluginRoot: PLUGIN_ROOT };
  const registered = await runWorkbench(
    workbench,
    scanRegistrationArguments(repository, scanDirectory),
  );
  const scanId = registered["scanId"] as string;
  const artifacts = await writeScanArtifacts(root, scanId);
  const path = join(scanDirectory, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(path, "utf8"));
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  manifest.scan.target.kind = "directory_snapshot";
  delete manifest.scan.target.revision;
  await writeFile(path, JSON.stringify(manifest));
  await runWorkbench(workbench, ["complete-scan", "--scan-id", scanId]);
  return { ...artifacts, environment, repository, caller, python };
}

function classifier(finding: Finding, excluded = false) {
  return jsonCodex(() => ({
    findingId: finding.findingId,
    decision: excluded ? "excluded" : "assessed",
    level: excluded ? null : "medium",
    rubricLabel: excluded ? null : "MEDIUM",
    rationale: excluded
      ? "Administrative record"
      : "Only bounded impact is established.",
    confidence: "high",
    reviewTrigger: null,
  }));
}

test("classifies and reads a saved scan with an embedded NUL in its ID without Python", async () => {
  const { environment, root, scanId, classify, readClassification } =
    await fixture("imported\0scan");
  const withoutPython = {
    ...environment,
    PATH: dirname(Bun.which("node")!),
    PYTHON: join(root, "missing-python"),
  };
  const { scanId: classifiedScanId, ...classification } = await classify({
    environment: withoutPython,
    codex: recordingClassifier().codex,
  });
  expect(classifiedScanId).toBe(scanId);
  expect(await readClassification(scanId, withoutPython)).toEqual(
    classification,
  );
});

test("saved scan artifacts cannot redirect knowledge-base reads", async () => {
  const { scanDirectory, root, rubricPath, classify } = await fixture();
  const alias = join(scanDirectory, "documents");
  await symlink(root, alias, "junction");
  await expect(
    classify({
      findingIds: [],
      rubricPath,
      knowledgeBasePaths: [join(alias, "policy.md")],
    }),
  ).rejects.toThrow(/symbolic link|directory link/i);
});

test("classifying a saved scan ID checks document links in its source directory", async () => {
  const { environment, repository, root, scanId } = await savedFixture();
  await symlink(root, join(repository, "documents"), "junction");
  const classify = (directory: string) =>
    classifyScanSeverityInternal(scanId, {
      environment,
      findingIds: [],
      rubricPath: join(directory, "documents", "policy.md"),
    });
  await expect(classify(repository)).rejects.toThrow(
    /symbolic link|directory link/i,
  );
  const moved = join(root, "moved");
  await rename(repository, moved);
  await expect(classify(moved)).rejects.toThrow("canonical path");
  await mkdir(repository);
  await expect(classify(moved)).rejects.toThrow("canonical path");
});

test("severity helpers skip Node executables in the caller's enclosing checkout", async () => {
  const { root, environment, scanDirectory } = await fixture();
  const repository = join(root, "repository");
  const bin = join(repository, "bin");
  const cwd = join(repository, "nested");
  await mkdir(bin, { recursive: true });
  await mkdir(cwd);
  await mkdir(join(repository, ".git"));
  const marker = join(root, "untrusted-node-ran");
  const node = join(bin, process.platform === "win32" ? "node.exe" : "node");
  await writeFile(
    node,
    process.platform === "win32"
      ? "synthetic invalid executable"
      : '#!/bin/sh\nprintf called > "$NODE_MARKER"\nexit 91\n',
    { mode: 0o700 },
  );
  const entryPoint = new URL(
    "../src/classify-scan-severity.ts",
    import.meta.url,
  );
  const result = spawnSync(
    process.execPath,
    [
      "--eval",
      `import { classifyScanDirectorySeverity } from ${JSON.stringify(entryPoint.href)};
await classifyScanDirectorySeverity(${JSON.stringify(scanDirectory)}, { environment: process.env, findingIds: [] });`,
    ],
    {
      cwd,
      encoding: "utf8",
      env: {
        ...environment,
        PATH: [bin, dirname(Bun.which("node")!)].join(delimiter),
        NODE_MARKER: marker,
      },
    },
  );
  expect(result.status, result.stderr).toBe(0);
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
});

for (const surface of ["SDK", "CLI"]) {
  test.skipIf(process.platform === "win32")(
    `saved severity ${surface} lookup rejects target Python before probing`,
    async () => {
      const f = await savedFixture();
      const marker = join(f.root, "python-probed");
      const executable = join(f.repository, "python3");
      await writeFile(
        executable,
        `#!/bin/sh\nprintf probed > '${marker.replaceAll("'", "'\\''")}'\nprintf "codex-security-python-ok\\n"\n`,
        { mode: 0o700 },
      );
      const python =
        surface === "CLI" ? join(f.root, "linked-python") : executable;
      if (surface === "CLI") await symlink(executable, python);
      const environment = {
        ...f.environment,
        PYTHON: python,
      };
      if (surface === "SDK") {
        const failure = await classifyScanSeverityInternal(
          f.scanId,
          { environment },
          { currentDirectory: () => f.caller },
        ).catch((error: unknown) => error);
        await expect(readFile(marker)).rejects.toMatchObject({
          code: "ENOENT",
        });
        expect(failure).toMatchObject({
          message: expect.stringContaining(
            "PYTHON interpreter is unavailable or unusable",
          ),
        });
      } else {
        const cli = new URL("../src/cli.ts", import.meta.url);
        const result = spawnSync(
          process.execPath,
          [
            "--eval",
            `const { main } = await import(${JSON.stringify(cli.href)});
process.exitCode = await main(["classify-severity", "--scan", ${JSON.stringify(f.scanId.slice(0, 8))}, "--json"]);`,
          ],
          { cwd: f.caller, encoding: "utf8", env: environment },
        );
        await expect(readFile(marker)).rejects.toMatchObject({
          code: "ENOENT",
        });
        expect(result.status, result.stderr).toBe(2);
        expect(result.stderr).toContain(
          "PYTHON interpreter is unavailable or unusable",
        );
      }
      await expect(
        readFile(join(f.scanDirectory, "severity-classification.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    },
  );
}

test.each(["id", "prefix", "latest", "missing target"])(
  "saved severity supports %s without modifying sealed inputs or the environment",
  async (selection) => {
    const f = await savedFixture();
    const environment = Object.freeze({ ...f.environment, PYTHON: f.python });
    const before = await readFile(join(f.scanDirectory, "scan-manifest.json"));
    if (selection === "missing target")
      await rm(f.repository, { recursive: true });
    const result = await classifyScanSeverityInternal(
      selection === "latest"
        ? "latest"
        : selection === "prefix"
          ? f.scanId.slice(0, 8)
          : f.scanId,
      {
        environment,
        expectedScanId: f.scanId,
        rubricPath: await realpath(f.rubricPath),
        codex: recordingClassifier().codex,
      },
      {
        currentDirectory: () =>
          selection === "latest" ? f.repository : f.caller,
      },
    );
    expect(result.scanId).toBe(f.scanId);
    expect(result.assessments).toHaveLength(f.findings.length);
    expect(await readFile(join(f.scanDirectory, "scan-manifest.json"))).toEqual(
      before,
    );
    expect(environment).toEqual({ ...f.environment, PYTHON: f.python });
  },
);

test("saved severity protects repository and caller tools across concurrent lookups", async () => {
  const results = await Promise.allSettled(
    (["repository", "caller"] as const).map(async (location) => {
      const f = await savedFixture();
      const marker = join(f.root, "node-probed");
      await writeFile(
        join(f[location], process.platform === "win32" ? "node.exe" : "node"),
        process.platform === "win32"
          ? "synthetic invalid executable"
          : '#!/bin/sh\nprintf probed > "$NODE_MARKER"\nexit 91\n',
        { mode: 0o700 },
      );
      const result = await classifyScanSeverityInternal(
        f.scanId,
        {
          codex: recordingClassifier().codex,
          environment: {
            ...f.environment,
            PYTHON: f.python,
            PATH: [f[location], dirname(Bun.which("node")!)].join(delimiter),
            NODE_MARKER: marker,
          },
        },
        { currentDirectory: () => f.caller },
      );
      expect(result.scanId).toBe(f.scanId);
      expect(result.assessments).toHaveLength(f.findings.length);
      await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
    }),
  );
  for (const result of results)
    if (result.status === "rejected") throw result.reason;
});

function recordingClassifier() {
  const calls: string[] = [];
  const control = { failOn: "", failOnRun: 1, excluded: false };
  const codex = codexWithRun(async (prompt: string) => {
    const { finding } = JSON.parse(prompt.split("\n\n").at(-1)!) as {
      finding: Finding;
    };
    calls.push(finding.findingId);
    if (
      finding.findingId === control.failOn &&
      calls.filter((id) => id === finding.findingId).length ===
        control.failOnRun
    )
      throw new Error("Interrupted model call");
    return classifier(finding, control.excluded).startThread().run();
  });
  return { codex, calls, control };
}

test("checkpoints each finding, resumes missing work, and reprocesses only the selection", async () => {
  const { findings, classify, preparePublication, readClassification, query } =
    await fixture();
  const { codex, calls, control } = recordingClassifier();
  const options = { codex };
  control.failOn = findings[1]!.findingId;
  control.failOnRun = 3;
  await expect(classify(options)).rejects.toThrow("Interrupted model call");
  expect(
    query("SELECT finding_id FROM scan_severity_assessments").map(
      (row) => row["finding_id"],
    ),
  ).toEqual([findings[0]!.findingId]);
  await expect(preparePublication()).rejects.toThrow("incomplete");
  control.failOn = "";
  calls.length = 0;
  const complete = await classify(options);
  expect(calls).toEqual(Array(3).fill(findings[1]!.findingId));
  expect(complete.assessments).toHaveLength(2);
  const { scanId: _scanId, ...assessment } = complete;
  expect(await readClassification(complete.scanId)).toEqual(assessment);
  const assessmentRows = () =>
    query("SELECT * FROM scan_severity_assessments ORDER BY finding_id");
  const rows = assessmentRows();
  calls.length = 0;
  expect((await classify(options)).assessments).toEqual(complete.assessments);
  expect(calls).toEqual([]);
  expect(assessmentRows()).toEqual(rows);

  control.excluded = true;
  const selected = {
    ...options,
    findingIds: [findings[0]!.findingId],
    reprocess: true,
  };
  const revised = await classify(selected);
  expect(calls).toEqual(Array(3).fill(findings[0]!.findingId));
  expect(revised.assessments[0]!.decision).toBe("excluded");
  const revisedRows = assessmentRows();
  expect(revisedRows).toHaveLength(2);
  expect(
    revisedRows.find((row) => row["finding_id"] === findings[1]!.findingId),
  ).toEqual(rows.find((row) => row["finding_id"] === findings[1]!.findingId));
  calls.length = 0;
  expect((await classify(options)).assessments[0]!.decision).toBe("excluded");
  expect(calls).toEqual([]);
  expect((await preparePublication()).issues).toHaveLength(1);

  control.failOn = findings[0]!.findingId;
  control.failOnRun = 2;
  await expect(classify(selected)).rejects.toThrow("Interrupted model call");
  expect(assessmentRows()).toEqual(revisedRows);
});

test.each(["same", "different"])(
  "preserves concurrent scan assessments with %s rubrics",
  async (rubric) => {
    const first = await fixture();
    const second = await fixture("scan_example_002", first.environment);
    if (rubric === "different")
      await writeFile(second.rubricPath, "Exclude administrative findings.");
    const firstModel = recordingClassifier();
    const secondModel = recordingClassifier();
    secondModel.control.excluded = true;
    const [firstResult, secondResult] = await Promise.all([
      first.classify({
        rubricPath: first.rubricPath,
        codex: firstModel.codex,
      }),
      second.classify({
        rubricPath: second.rubricPath,
        codex: secondModel.codex,
      }),
    ]);
    for (const [scan, result] of [
      [first, firstResult],
      [second, secondResult],
    ] as const) {
      const { scanId, ...classification } = result;
      expect(await scan.readClassification(scanId, first.environment)).toEqual(
        classification,
      );
    }
    expect(
      (await first.preparePublication()).issues.map((issue) => issue.priority),
    ).toEqual([3, 3]);
    expect((await second.preparePublication()).issues).toEqual([]);
    firstModel.calls.length = 0;
    expect(
      (
        await first.classify({
          rubricPath: first.rubricPath,
          codex: firstModel.codex,
        })
      ).assessments,
    ).toEqual(firstResult.assessments);
    expect(firstModel.calls).toEqual([]);
  },
);

test("migration leaves unindexed legacy assessments incomplete until reclassified", async () => {
  const first = await fixture();
  const second = await fixture("scan_example_002", first.environment);
  const { query } = first;
  const { scanId, ...classification } = await first.classify({
    codex: recordingClassifier().codex,
  });
  query("DROP TABLE scan_severity_assessments");
  query(
    "ALTER TABLE scan_severity_classifications DROP COLUMN rubric_binding_json",
  );
  for (const table of [
    "finding_severity_assessments",
    "scan_severity_classifications",
  ]) {
    query(`ALTER TABLE ${table} DROP COLUMN classification_runs`);
  }
  query("DELETE FROM schema_migrations WHERE version IN (43, 52, 60)");
  expect(await first.readClassification(scanId)).toEqual({
    ...classification,
    classificationRuns: undefined,
    rubricRevision: undefined,
    rubricSha256: workflowDigest([defaultSeverityRubric]),
  });
  expect(
    query("SELECT version FROM schema_migrations WHERE version = 43"),
  ).toEqual([]);
  await second.classify({
    codex: recordingClassifier().codex,
  });
  await expect(first.readClassification(scanId)).rejects.toThrow("incomplete");
  expect(
    (
      await first.classify({
        codex: recordingClassifier().codex,
      })
    ).assessments,
  ).toEqual(classification.assessments);
  expect(
    query("SELECT version FROM schema_migrations WHERE version = 43"),
  ).toEqual([{ version: 43 }]);
});

test("changed rubric, context, or evidence invalidates matching checkpoints", async () => {
  const {
    root,
    scanDirectory,
    rubricPath,
    findings,
    classify,
    preparePublication,
    query,
  } = await fixture();
  const { codex, calls } = recordingClassifier();
  const options = { rubricPath, codex };
  await classify(options);
  const originalFindings = query("SELECT * FROM findings ORDER BY id");
  calls.length = 0;
  await writeFile(rubricPath, "Assign Medium to bounded metadata reads.");
  await classify(options);
  expect(calls).toHaveLength(6);
  const context = join(root, "context.md");
  await writeFile(context, "The system contains operational counters.");
  calls.length = 0;
  const withContext = { ...options, knowledgeBasePaths: [context] };
  await classify(withContext);
  expect(calls).toHaveLength(6);
  calls.length = 0;
  await writeFile(context, "The counters include protected metadata.");
  await classify(withContext);
  expect(calls).toHaveLength(6);

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
    artifact.sha256 = sha256(
      await readFile(join(scanDirectory, artifact.path)),
    );
  await writeFile(manifestPath, JSON.stringify(manifest));
  await expect(preparePublication()).rejects.toThrow("does not match");
  calls.length = 0;
  await classify(withContext);
  expect(calls).toEqual(Array(3).fill(findings[0]!.findingId));
  expect(query("SELECT * FROM findings ORDER BY id")).toEqual(originalFindings);
});

test("classification refuses to store workflow state inside sealed scan artifacts", async () => {
  const { environment, scanDirectory, classify } = await fixture();
  await expect(
    classify({
      environment: {
        ...environment,
        CODEX_SECURITY_STATE_DIR: join(scanDirectory, "state"),
      },
    }),
  ).rejects.toThrow("outside");
});

test("a classified dedupe selection drives Linear priority and preserves sealed evidence", async () => {
  const {
    environment,
    scanDirectory,
    rubricPath,
    findings,
    scanId,
    classify,
    preparePublication,
  } = await fixture();
  const before = await loadContract(scanDirectory, { pluginRoot: PLUGIN_ROOT });
  const classification = await classify({
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
    preparePublication({ findingIds: [findings[0]!.findingId] }),
  ).rejects.toThrow("missing from");
});

test("publication accepts in-memory assessments and exact ID selections", async () => {
  const { rubricPath, findings, preparePublication } = await fixture();
  const classification = await classifySeverity([findings[0]!], {
    rubricPath,
    codex: classifier(findings[0]!),
  });
  const prepared = await preparePublication({ classification });
  expect(prepared.issues).toHaveLength(1);
  expect(prepared.issues[0]!.priority).toBe(3);
  expect(
    (await preparePublication({ findingIds: [findings[1]!.findingId] }))
      .issues[0]!.priority,
  ).toBe(2);
  expect((await preparePublication()).issues).toHaveLength(2);
  await expect(
    preparePublication({ findingIds: ["not-in-scan"] }),
  ).rejects.toThrow("belong");
});

test("exclusions and empty dedupe selections do not create tickets", async () => {
  const { rubricPath, findings, classify, preparePublication } =
    await fixture();
  await classify({
    findingIds: [findings[0]!.findingId],
    rubricPath,
    codex: classifier(findings[0]!, true),
  });
  expect((await preparePublication()).issues).toEqual([]);
  await classify({
    findingIds: [],
  });
  expect((await preparePublication()).issues).toEqual([]);
});

test("failed or canceled reassessment leaves the last successful assessment intact", async () => {
  const { scanDirectory, rubricPath, findings, classify } = await fixture();
  await classify({
    codex: recordingClassifier().codex,
  });
  const path = join(scanDirectory, "severity-classification.json");
  const before = await readFile(path);
  await expect(
    classify({
      rubricPath,
      codex: classifier({ ...findings[0]!, findingId: "wrong" }),
    }),
  ).rejects.toThrow("invalid assessment");
  expect(await readFile(path)).toEqual(before);
  const controller = new AbortController();
  const codex: NonNullable<ClassifySeverityOptions["codex"]> = codexWithRun(
    async () => {
      controller.abort(new Error("stop"));
      return { finalResponse: "{}" };
    },
  );
  await expect(
    classify({
      rubricPath,
      codex,
      signal: controller.signal,
    }),
  ).rejects.toThrow();
  expect(await readFile(path)).toEqual(before);
});

test("publication reads SQLite even when the JSON export is modified or symlinked", async () => {
  const { root, scanDirectory, findings, classify, preparePublication } =
    await fixture();
  const result = await classify({
    codex: recordingClassifier().codex,
  });
  const path = join(scanDirectory, "severity-classification.json");
  await writeFile(path, JSON.stringify({ ...result, scanId: "other-scan" }));
  expect((await preparePublication()).issues).toHaveLength(findings.length);
  const stale = await classifySeverity(
    [{ ...findings[0]!, summary: "Different report" }],
    { codex: classifier(findings[0]!) },
  );
  await expect(preparePublication({ classification: stale })).rejects.toThrow(
    "does not match",
  );
  await rm(path);
  const external = join(root, "outside.json");
  await writeFile(external, JSON.stringify(result));
  await symlink(external, path);
  expect((await preparePublication()).issues).toHaveLength(findings.length);
  await classify({
    codex: recordingClassifier().codex,
  });
  expect(await readFile(external, "utf8")).toBe(JSON.stringify(result));
});

test.each(["saved scan", "latest listing", "latest scan"])(
  "cancels a pending %s history request and preserves its cleanup and error",
  async (boundary) => {
    const controller = new AbortController();
    const reason = new Error("Classification canceled");
    const abortError = Object.assign(new Error("History request aborted"), {
      name: "AbortError",
      cause: reason,
    });
    const entered = Promise.withResolvers<void>();
    const response = Promise.withResolvers<JsonObject>();
    const calls: string[] = [];
    const events: string[] = [];
    let receivedSignal: AbortSignal | undefined;
    const operation = classifyScanSeverityInternal(
      boundary === "saved scan" ? "scan-example" : "latest",
      { signal: controller.signal },
      {
        currentDirectory: () => process.cwd(),
        runWorkbench: async (args, _input, signal) => {
          calls.push(args[0]!);
          if (boundary === "latest scan" && args[0] === "list-scans")
            return { scans: [{ scanId: "scan-example" }] };
          receivedSignal = signal;
          const abort = () => {
            events.push("aborted");
            response.reject(abortError);
          };
          signal?.addEventListener("abort", abort, { once: true });
          events.push("entered");
          entered.resolve();
          try {
            return await response.promise;
          } finally {
            signal?.removeEventListener("abort", abort);
            events.push("cleaned up");
          }
        },
      },
    );
    const pending = operation.catch((error: unknown) => error);
    try {
      await Promise.race([
        entered.promise,
        pending.then((error) => {
          throw error;
        }),
      ]);
      controller.abort(reason);
      response.reject(new Error("History lookup did not observe cancellation"));
      expect(await pending).toBe(abortError);
      expect(receivedSignal).toBe(controller.signal);
      expect(events).toEqual(["entered", "aborted", "cleaned up"]);
      expect(calls).toEqual(
        boundary === "saved scan"
          ? ["get-scan"]
          : boundary === "latest listing"
            ? ["list-scans"]
            : ["list-scans", "get-scan"],
      );
    } finally {
      response.resolve({});
      await pending;
    }
  },
);

test.each(["latest", "scan_prefix"])(
  "resolves %s using existing saved-scan history",
  async (selector) => {
    const { environment, scanDirectory, scanId, classify } = await fixture();
    const seen: string[][] = [];
    const result = await classifyScanSeverityInternal(
      selector,
      { environment, codex: recordingClassifier().codex },
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
      classify({
        expectedScanId: "other-scan",
      }),
    ).rejects.toThrow("do not match");
  },
);

test("migrates existing databases without changing findings and reads older state without writes", async () => {
  const { classify, preparePublication, query } = await fixture();
  await classify({
    codex: recordingClassifier().codex,
  });
  const original = query("SELECT * FROM findings ORDER BY id");
  query("DROP TABLE scan_severity_assessments");
  query("DROP TABLE finding_severity_assessments");
  query("DROP TABLE scan_severity_classifications");
  query("DELETE FROM schema_migrations WHERE version IN (41, 43, 52, 60)");
  expect((await preparePublication()).issues).toHaveLength(2);
  expect(
    query("SELECT version FROM schema_migrations WHERE version = 41"),
  ).toEqual([]);
  await classify({
    codex: recordingClassifier().codex,
  });
  expect(
    query("SELECT version FROM schema_migrations WHERE version = 41"),
  ).toEqual([{ version: 41 }]);
  expect(query("SELECT * FROM findings ORDER BY id")).toEqual(original);
});

test("classifying another scan preserves both recurring-finding assessments", async () => {
  const first = await fixture();
  const second = await fixture("scan_example_002", first.environment);
  const { codex, calls } = recordingClassifier();
  const options = {
    rubricPath: first.rubricPath,
    codex,
  };
  await first.classify(options);
  const { scanId, ...classification } = await second.classify(options);
  expect(await second.readClassification(scanId, first.environment)).toEqual(
    classification,
  );
  expect(calls).toHaveLength(12);
  calls.length = 0;
  for (const scan of [first, second, first, second]) {
    expect((await scan.preparePublication()).issues).toHaveLength(2);
    await scan.classify(options);
  }
  expect(calls).toEqual([]);
});

test("default rubric replaces legacy inherited assessments and respects custom policy changes", async () => {
  const { rubricPath, scanId, classify, readClassification, query } =
    await fixture();
  const { codex, calls } = recordingClassifier();
  const options = { codex };
  await classify(options);
  // Recreate the provenance emitted by the former no-rubric inheritance path.
  for (const table of [
    "scan_severity_assessments",
    "finding_severity_assessments",
  ]) {
    query(
      `UPDATE ${table} SET rubric_sha256 = NULL, source = 'existing-severity', level = 'high', rubric_label = NULL, confidence = NULL`,
    );
  }
  query(
    "UPDATE scan_severity_classifications SET rubric_sha256 = NULL, rubric_binding_json = NULL",
  );
  const legacy = await readClassification(scanId);
  expect(
    legacy?.assessments.every((a) => a.source === "existing-severity"),
  ).toBe(true);
  calls.length = 0;
  const result = await classify(options);
  expect(calls).toHaveLength(6);
  expect(result.rubricSha256).toBe(sha256(defaultSeverityRubric));
  expect(result.rubricRevision).toBe(1);
  expect(
    result.assessments.every(
      (a) => a.source === "rubric" && a.level === "medium",
    ),
  ).toBe(true);
  expect(await readClassification(scanId)).toMatchObject({
    rubricSha256: result.rubricSha256,
    rubricRevision: result.rubricRevision,
  });
  calls.length = 0;
  query("UPDATE scan_severity_classifications SET rubric_binding_json = NULL");
  expect((await classify(options)).assessments).toEqual(result.assessments);
  expect(calls).toHaveLength(0);
  const custom = await classify({
    ...options,
    rubricPath,
  });
  expect(calls).toHaveLength(6);
  expect(custom.rubricSha256).not.toBe(result.rubricSha256);
  calls.length = 0;
  expect((await classify(options)).rubricSha256).toBe(result.rubricSha256);
  expect(calls).toHaveLength(6);
});

test("saved assessments bind their run count and invalidate changed or unrecorded counts", async () => {
  const { scanId, findings, classify, readClassification, query } =
    await fixture();
  const { codex, calls, control } = recordingClassifier();
  for (const [classificationRuns, expectedCalls] of [
    [3, 6],
    [3, 0],
    [1, 2],
    [1, 0],
    [10, 20],
    [3, 6],
  ]) {
    calls.length = 0;
    const result = await classify({
      codex,
      classificationRuns,
    });
    expect(calls).toHaveLength(expectedCalls!);
    expect(result.classificationRuns).toBe(classificationRuns);
    const saved = await readClassification(scanId);
    expect(saved?.classificationRuns).toBe(classificationRuns);
  }
  for (const table of [
    "scan_severity_classifications",
    "scan_severity_assessments",
    "finding_severity_assessments",
  ]) {
    query(`UPDATE ${table} SET classification_runs = NULL`);
  }
  expect(
    (await readClassification(scanId))?.classificationRuns,
  ).toBeUndefined();
  calls.length = 0;
  await classify({ codex });
  expect(calls).toHaveLength(6);
  expect(
    query(
      `SELECT classification_runs FROM scan_severity_classifications WHERE scan_id = '${scanId}'`,
    ),
  ).toEqual([{ classification_runs: 3 }]);
  calls.length = 0;
  control.failOn = findings[1]!.findingId;
  await expect(
    classify({
      codex,
      classificationRuns: 1,
    }),
  ).rejects.toThrow("Interrupted model call");
  await expect(readClassification(scanId)).rejects.toThrow("incomplete");
  calls.length = 0;
  control.failOn = "";
  await classify({
    codex,
    classificationRuns: 1,
  });
  expect(calls).toEqual([findings[1]!.findingId]);
});
