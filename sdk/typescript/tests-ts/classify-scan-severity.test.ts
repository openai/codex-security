import { codexWithRun, jsonCodex } from "./support/codex.js";
import { setFindingIdentity, sha256 } from "./support/finding-identity.js";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
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
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "classify-scan-",
  false,
);
const destination = { destination: "linear", teamId: "team-example" } as const;
afterEach(cleanup);

async function fixture(scanId?: string, savedRoot?: string) {
  const root = savedRoot ?? (await temporaryDirectory());
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
  const registered = await runWorkbench(workbench, [
    "register-cli-scan",
    "--repository",
    repository,
    "--scan-dir",
    scanDirectory,
    "--recipe-json",
    JSON.stringify({
      config: {},
      mode: "standard",
      repository,
      target: { kind: "repository", paths: [] },
    }),
  ]);
  const scanId = registered["scanId"] as string;
  const artifacts = await fixture(scanId, root);
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

async function query(environment: NodeJS.ProcessEnv, sql: string) {
  const result = spawnSync(
    Bun.which("node")!,
    [
      "--input-type=module",
      "--eval",
      `import { DatabaseSync } from "node:sqlite";
const database = new DatabaseSync(process.argv[1]);
try { console.log(JSON.stringify(database.prepare(process.argv[2]).all())); }
finally { database.close(); }`,
      join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
      sql,
    ],
    { encoding: "utf8", env: environment },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Record<string, unknown>[];
}

test("classification and saved assessments run with Node and no Python", async () => {
  const { environment, root, scanDirectory, scanId, findings } =
    await fixture();
  const withoutPython = {
    ...environment,
    PATH: dirname(Bun.which("node")!),
    PYTHON: join(root, "missing-python"),
  };
  const { scanId: _scanId, ...classification } =
    await classifyScanDirectorySeverity(scanDirectory, {
      environment: withoutPython,
      codex: recordingClassifier().codex,
    });
  expect(
    await readScanSeverityClassification(
      scanDirectory,
      scanId,
      findings,
      undefined,
      withoutPython,
    ),
  ).toEqual(classification);
});

test("saved assessments retain embedded NULs in imported scan IDs", async () => {
  const { environment, scanDirectory, scanId, findings } =
    await fixture("imported\0scan");
  const { scanId: classifiedScanId, ...classification } =
    await classifyScanDirectorySeverity(scanDirectory, {
      environment,
      codex: recordingClassifier().codex,
    });
  expect(classifiedScanId).toBe(scanId);
  expect(
    await readScanSeverityClassification(
      scanDirectory,
      scanId,
      findings,
      undefined,
      environment,
    ),
  ).toEqual(classification);
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
  const { environment, scanDirectory, findings } = await fixture();
  const { codex, calls, control } = recordingClassifier();
  const options = { environment, codex };
  control.failOn = findings[1]!.findingId;
  control.failOnRun = 3;
  await expect(
    classifyScanDirectorySeverity(scanDirectory, options),
  ).rejects.toThrow("Interrupted model call");
  expect(
    (
      await query(
        environment,
        "SELECT finding_id FROM scan_severity_assessments",
      )
    ).map((row) => row["finding_id"]),
  ).toEqual([findings[0]!.findingId]);
  await expect(
    prepareScanPublication(scanDirectory, { ...destination, environment }),
  ).rejects.toThrow("incomplete");
  control.failOn = "";
  calls.length = 0;
  const complete = await classifyScanDirectorySeverity(scanDirectory, options);
  expect(calls).toEqual(Array(3).fill(findings[1]!.findingId));
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
    "SELECT * FROM scan_severity_assessments ORDER BY finding_id",
  );
  calls.length = 0;
  expect(
    (await classifyScanDirectorySeverity(scanDirectory, options)).assessments,
  ).toEqual(complete.assessments);
  expect(calls).toEqual([]);
  expect(
    await query(
      environment,
      "SELECT * FROM scan_severity_assessments ORDER BY finding_id",
    ),
  ).toEqual(rows);

  control.excluded = true;
  const selected = {
    ...options,
    findingIds: [findings[0]!.findingId],
    reprocess: true,
  };
  const revised = await classifyScanDirectorySeverity(scanDirectory, selected);
  expect(calls).toEqual(Array(3).fill(findings[0]!.findingId));
  expect(revised.assessments[0]!.decision).toBe("excluded");
  const revisedRows = await query(
    environment,
    "SELECT * FROM scan_severity_assessments ORDER BY finding_id",
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
  control.failOnRun = 2;
  await expect(
    classifyScanDirectorySeverity(scanDirectory, selected),
  ).rejects.toThrow("Interrupted model call");
  expect(
    await query(
      environment,
      "SELECT * FROM scan_severity_assessments ORDER BY finding_id",
    ),
  ).toEqual(revisedRows);
});

test.each(["same", "different"])(
  "preserves concurrent scan assessments with %s rubrics",
  async (rubric) => {
    const first = await fixture();
    const second = await fixture("scan_example_002");
    const environment = first.environment;
    if (rubric === "different")
      await writeFile(second.rubricPath, "Exclude administrative findings.");
    const firstModel = recordingClassifier();
    const secondModel = recordingClassifier();
    secondModel.control.excluded = true;
    const [firstResult, secondResult] = await Promise.all([
      classifyScanDirectorySeverity(first.scanDirectory, {
        environment,
        rubricPath: first.rubricPath,
        codex: firstModel.codex,
      }),
      classifyScanDirectorySeverity(second.scanDirectory, {
        environment,
        rubricPath: second.rubricPath,
        codex: secondModel.codex,
      }),
    ]);
    for (const [scan, result] of [
      [first, firstResult],
      [second, secondResult],
    ] as const) {
      const { scanId, ...classification } = result;
      expect(
        await readScanSeverityClassification(
          scan.scanDirectory,
          scanId,
          scan.findings,
          undefined,
          environment,
        ),
      ).toEqual(classification);
    }
    expect(
      (
        await prepareScanPublication(first.scanDirectory, {
          ...destination,
          environment,
        })
      ).issues.map((issue) => issue.priority),
    ).toEqual([3, 3]);
    expect(
      (
        await prepareScanPublication(second.scanDirectory, {
          ...destination,
          environment,
        })
      ).issues,
    ).toEqual([]);
    firstModel.calls.length = 0;
    expect(
      (
        await classifyScanDirectorySeverity(first.scanDirectory, {
          environment,
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
  const second = await fixture("scan_example_002");
  const environment = first.environment;
  const { scanId, ...classification } = await classifyScanDirectorySeverity(
    first.scanDirectory,
    { environment, codex: recordingClassifier().codex },
  );
  await query(environment, "DROP TABLE scan_severity_assessments");
  for (const table of [
    "finding_severity_assessments",
    "scan_severity_classifications",
  ]) {
    await query(
      environment,
      `ALTER TABLE ${table} DROP COLUMN classification_runs`,
    );
  }
  await query(
    environment,
    "DELETE FROM schema_migrations WHERE version IN (43, 52)",
  );
  expect(
    await readScanSeverityClassification(
      first.scanDirectory,
      scanId,
      first.findings,
      undefined,
      environment,
    ),
  ).toEqual({ ...classification, classificationRuns: undefined });
  expect(
    await query(
      environment,
      "SELECT version FROM schema_migrations WHERE version = 43",
    ),
  ).toEqual([]);
  await classifyScanDirectorySeverity(second.scanDirectory, {
    environment,
    codex: recordingClassifier().codex,
  });
  await expect(
    readScanSeverityClassification(
      first.scanDirectory,
      scanId,
      first.findings,
      undefined,
      environment,
    ),
  ).rejects.toThrow("incomplete");
  expect(
    (
      await classifyScanDirectorySeverity(first.scanDirectory, {
        environment,
        codex: recordingClassifier().codex,
      })
    ).assessments,
  ).toEqual(classification.assessments);
  expect(
    await query(
      environment,
      "SELECT version FROM schema_migrations WHERE version = 43",
    ),
  ).toEqual([{ version: 43 }]);
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
  expect(calls).toHaveLength(6);
  const context = join(root, "context.md");
  await writeFile(context, "The system contains operational counters.");
  calls.length = 0;
  const withContext = { ...options, knowledgeBasePaths: [context] };
  await classifyScanDirectorySeverity(scanDirectory, withContext);
  expect(calls).toHaveLength(6);
  calls.length = 0;
  await writeFile(context, "The counters include protected metadata.");
  await classifyScanDirectorySeverity(scanDirectory, withContext);
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
  await expect(
    prepareScanPublication(scanDirectory, { ...destination, environment }),
  ).rejects.toThrow("does not match");
  calls.length = 0;
  await classifyScanDirectorySeverity(scanDirectory, withContext);
  expect(calls).toEqual(Array(3).fill(findings[0]!.findingId));
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
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    codex: recordingClassifier().codex,
  });
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
  const codex: NonNullable<ClassifySeverityOptions["codex"]> = codexWithRun(
    async () => {
      controller.abort(new Error("stop"));
      return { finalResponse: "{}" };
    },
  );
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
    codex: recordingClassifier().codex,
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
  const stale = await classifySeverity(
    [{ ...findings[0]!, summary: "Different report" }],
    { codex: classifier(findings[0]!) },
  );
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
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
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
    const { environment, scanDirectory, scanId } = await fixture();
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
      classifyScanDirectorySeverity(scanDirectory, {
        environment,
        expectedScanId: "other-scan",
      }),
    ).rejects.toThrow("do not match");
  },
);

test("migrates existing databases without changing findings and reads older state without writes", async () => {
  const { environment, scanDirectory } = await fixture();
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    codex: recordingClassifier().codex,
  });
  const original = await query(
    environment,
    "SELECT * FROM findings ORDER BY id",
  );
  await query(environment, "DROP TABLE scan_severity_assessments");
  await query(environment, "DROP TABLE finding_severity_assessments");
  await query(environment, "DROP TABLE scan_severity_classifications");
  await query(
    environment,
    "DELETE FROM schema_migrations WHERE version IN (41, 43, 52)",
  );
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
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    codex: recordingClassifier().codex,
  });
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

test("classifying another scan preserves both recurring-finding assessments", async () => {
  const first = await fixture();
  const second = await fixture("scan_example_002");
  const { codex, calls } = recordingClassifier();
  const options = {
    environment: first.environment,
    rubricPath: first.rubricPath,
    codex,
  };
  await classifyScanDirectorySeverity(first.scanDirectory, options);
  await classifyScanDirectorySeverity(second.scanDirectory, options);
  expect(calls).toHaveLength(12);
  calls.length = 0;
  for (const scan of [first, second, first, second]) {
    expect(
      (
        await prepareScanPublication(scan.scanDirectory, {
          ...destination,
          environment: first.environment,
        })
      ).issues,
    ).toHaveLength(2);
    await classifyScanDirectorySeverity(scan.scanDirectory, options);
  }
  expect(calls).toEqual([]);
});

test("default rubric replaces legacy inherited assessments and respects custom policy changes", async () => {
  const { environment, scanDirectory, rubricPath, findings, scanId } =
    await fixture();
  const { codex, calls } = recordingClassifier();
  const options = { environment, codex };
  await classifyScanDirectorySeverity(scanDirectory, options);
  // Recreate the provenance emitted by the former no-rubric inheritance path.
  for (const table of [
    "scan_severity_assessments",
    "finding_severity_assessments",
  ]) {
    await query(
      environment,
      `UPDATE ${table} SET rubric_sha256 = NULL, source = 'existing-severity', level = 'high', rubric_label = NULL, confidence = NULL`,
    );
  }
  await query(
    environment,
    "UPDATE scan_severity_classifications SET rubric_sha256 = NULL",
  );
  const legacy = await readScanSeverityClassification(
    scanDirectory,
    scanId,
    findings,
    undefined,
    environment,
  );
  expect(
    legacy?.assessments.every((a) => a.source === "existing-severity"),
  ).toBe(true);
  calls.length = 0;
  const result = await classifyScanDirectorySeverity(scanDirectory, options);
  expect(calls).toHaveLength(6);
  expect(result.rubricSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(
    result.assessments.every(
      (a) => a.source === "rubric" && a.level === "medium",
    ),
  ).toBe(true);
  calls.length = 0;
  expect(
    (await classifyScanDirectorySeverity(scanDirectory, options)).assessments,
  ).toEqual(result.assessments);
  expect(calls).toHaveLength(0);
  const custom = await classifyScanDirectorySeverity(scanDirectory, {
    ...options,
    rubricPath,
  });
  expect(calls).toHaveLength(6);
  expect(custom.rubricSha256).not.toBe(result.rubricSha256);
  calls.length = 0;
  expect(
    (await classifyScanDirectorySeverity(scanDirectory, options)).rubricSha256,
  ).toBe(result.rubricSha256);
  expect(calls).toHaveLength(6);
});

test("saved assessments bind their run count and invalidate changed or unrecorded counts", async () => {
  const { environment, scanDirectory, scanId, findings } = await fixture();
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
    const result = await classifyScanDirectorySeverity(scanDirectory, {
      environment,
      codex,
      classificationRuns,
    });
    expect(calls).toHaveLength(expectedCalls!);
    expect(result.classificationRuns).toBe(classificationRuns);
    const saved = await readScanSeverityClassification(
      scanDirectory,
      scanId,
      findings,
      undefined,
      environment,
    );
    expect(saved?.classificationRuns).toBe(classificationRuns);
  }
  for (const table of [
    "scan_severity_classifications",
    "scan_severity_assessments",
    "finding_severity_assessments",
  ]) {
    await query(environment, `UPDATE ${table} SET classification_runs = NULL`);
  }
  expect(
    (
      await readScanSeverityClassification(
        scanDirectory,
        scanId,
        findings,
        undefined,
        environment,
      )
    )?.classificationRuns,
  ).toBeUndefined();
  calls.length = 0;
  await classifyScanDirectorySeverity(scanDirectory, { environment, codex });
  expect(calls).toHaveLength(6);
  expect(
    await query(
      environment,
      `SELECT classification_runs FROM scan_severity_classifications WHERE scan_id = '${scanId}'`,
    ),
  ).toEqual([{ classification_runs: 3 }]);
  calls.length = 0;
  control.failOn = findings[1]!.findingId;
  await expect(
    classifyScanDirectorySeverity(scanDirectory, {
      environment,
      codex,
      classificationRuns: 1,
    }),
  ).rejects.toThrow("Interrupted model call");
  await expect(
    readScanSeverityClassification(
      scanDirectory,
      scanId,
      findings,
      undefined,
      environment,
    ),
  ).rejects.toThrow("incomplete");
  calls.length = 0;
  control.failOn = "";
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    codex,
    classificationRuns: 1,
  });
  expect(calls).toEqual([findings[1]!.findingId]);
});
