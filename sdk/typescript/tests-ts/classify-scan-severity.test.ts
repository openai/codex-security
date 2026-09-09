import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdtemp,
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import {
  classifyScanDirectorySeverity,
  classifyScanDirectorySeverityInternal,
  classifyScanSeverityInternal,
  readScanSeverityClassification,
} from "../src/classify-scan-severity.js";
import {
  classifySeverity,
  SeverityClassificationError,
  severityRetryCommand,
  type ClassifySeverityOptions,
  type SeverityClassificationProgress,
} from "../src/classify-severity.js";
import { loadContract } from "../src/contract.js";
import type { JsonObject } from "../src/config.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import { prepareScanPublication } from "../src/publication.js";
import { publishScanInternal } from "../src/publish.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { SeverityStore } from "../src/severity-store.js";

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

test("retains the failed finding, model thread, cause and committed counts for inspection", async () => {
  const { environment, scanDirectory, rubricPath, findings } = await fixture();
  const updates: SeverityClassificationProgress[] = [];
  let calls = 0;
  const codex: NonNullable<ClassifySeverityOptions["codex"]> = {
    startThread: (thread) => ({
      id: "synthetic-severity-thread",
      run: async (prompt, turn) => {
        if (calls++ === 1)
          throw new Error("Model turn failed", {
            cause: new Error("Connection reset"),
          });
        return classifier(findings[0]!).startThread(thread).run(prompt, turn);
      },
    }),
  };
  let failure: unknown;
  try {
    await classifyScanDirectorySeverityInternal(
      scanDirectory,
      {
        environment,
        rubricPath,
        codex,
        onProgress: (progress) => updates.push(progress),
      },
      "cli",
    );
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(SeverityClassificationError);
  const progress = (failure as SeverityClassificationError).progress;
  expect(progress).toMatchObject({
    status: "failed",
    phase: "classification",
    completed: 1,
    reused: 0,
    remaining: 1,
    findingId: findings[1]!.findingId,
    threadId: "synthetic-severity-thread",
    failure: {
      stage: "model",
      message: "Model turn failed",
      cause: "Connection reset",
    },
    retryArguments: [
      "classify-severity",
      "--scan-dir",
      scanDirectory,
      "--rubric",
      rubricPath,
    ],
  });
  expect(updates.at(-1)).toEqual(progress);
  const rows = await query(
    environment,
    "SELECT progress_json FROM severity_classification_runs",
  );
  expect(rows).toHaveLength(1);
  expect(JSON.parse(rows[0]!["progress_json"] as string)).toEqual(progress);
  const { codex: resumed, calls: resumedCalls } = recordingClassifier();
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    rubricPath,
    codex: resumed,
  });
  expect(resumedCalls).toEqual([findings[1]!.findingId]);
  expect(
    await query(environment, "SELECT id FROM severity_classification_runs"),
  ).toHaveLength(2);
});

async function registeredFixture() {
  const { root, environment, scanDirectory, rubricPath } = await fixture();
  const repository = join(root, "repository");
  await mkdir(repository);
  const template = join(root, "template");
  await rename(scanDirectory, template);
  await mkdir(scanDirectory, { mode: 0o700 });
  const python = await resolvePluginPython({ environment });
  const workbench = (args: readonly string[], input?: string) =>
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
  async function completeRegisteredScan(
    extra: string[] = [],
    completion = "complete-scan",
  ) {
    const registration = await workbench([
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
      ...extra,
    ]);
    const scanId = String(registration["scanId"]);
    await cp(template, scanDirectory, { recursive: true });
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const manifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as ScanManifest;
    manifest.scan.id = scanId;
    manifest.scan.target.kind = "directory_snapshot";
    const draft: Partial<ScanManifest["scan"]> = manifest.scan;
    delete draft.sealedAt;
    delete draft.artifacts;
    await writeFile(manifestPath, JSON.stringify(manifest));
    for (const filename of ["findings.json", "coverage.json"]) {
      const path = join(scanDirectory, filename);
      const document = JSON.parse(await readFile(path, "utf8"));
      document.scanId = scanId;
      await writeFile(path, JSON.stringify(document));
    }
    await workbench([completion, "--scan-id", scanId]);
    return scanId;
  }
  return {
    root,
    environment,
    scanDirectory,
    rubricPath,
    workbench,
    completeRegisteredScan,
  };
}

test.each([
  "saved scan",
  "registered directory",
  "explicit copy",
  "SDK saved scan",
  "SDK explicit copy",
])(
  "terminal and history retries preserve the selected %s",
  async (selection) => {
    const {
      root,
      environment,
      scanDirectory,
      rubricPath,
      workbench,
      completeRegisteredScan,
    } = await registeredFixture();
    const originalId = await completeRegisteredScan();
    const original = await loadContract(scanDirectory, {
      pluginRoot: PLUGIN_ROOT,
    });
    const { codex, control, calls } = recordingClassifier();
    const copyDirectory = join(root, "explicit copy");
    const explicitCopy = selection.endsWith("copy");
    const sdk = selection.startsWith("SDK");
    if (explicitCopy) {
      await cp(scanDirectory, copyDirectory, { recursive: true });
      if (process.platform !== "win32") await chmod(copyDirectory, 0o700);
    }
    const initialArguments = [
      "classify-severity",
      ...(selection === "saved scan" || selection === "SDK saved scan"
        ? ["--scan", originalId]
        : ["--scan-dir", explicitCopy ? copyDirectory : scanDirectory]),
      "--rubric",
      rubricPath,
    ];
    const expectedRetryArguments =
      selection === "registered directory"
        ? ["classify-severity", "--scan", originalId, "--rubric", rubricPath]
        : initialArguments;
    const cliDependencies: NonNullable<Parameters<typeof main>[3]> = {
      ...dependencies(),
      environment,
      currentDirectory: () => root,
      runWorkbench: workbench,
      classifyScanSeverity: (id, options, _history, surface) =>
        classifyScanSeverityInternal(
          id,
          { ...options, codex },
          { runWorkbench: workbench },
          surface,
        ),
      classifyScanDirectorySeverity: (directory, options, surface) =>
        classifyScanDirectorySeverityInternal(
          directory,
          { ...options, codex },
          surface,
        ),
    };
    const classifyWithSdk = () =>
      explicitCopy
        ? classifyScanDirectorySeverityInternal(copyDirectory, {
            environment,
            rubricPath,
            codex,
            expectedScanId: originalId,
          })
        : classifyScanSeverityInternal(
            originalId,
            { environment, rubricPath, codex },
            { runWorkbench: workbench },
          );
    control.failOn = original.findings.findings[1]!.findingId;
    const errorOutput = capture();
    if (sdk) {
      await expect(classifyWithSdk()).rejects.toBeInstanceOf(
        SeverityClassificationError,
      );
    } else {
      expect(
        await main(
          initialArguments,
          capture().stream,
          errorOutput.stream,
          cliDependencies,
        ),
      ).toBe(2);
      expect(errorOutput.text()).toContain("Interrupted model call");
      expect(errorOutput.text()).toContain(
        severityRetryCommand(expectedRetryArguments),
      );
    }
    const archived = `${scanDirectory}.previous-synthetic`;
    await rename(scanDirectory, archived);
    await mkdir(scanDirectory, { mode: 0o700 });
    const replacementId = await completeRegisteredScan([
      "--archive-existing",
      "--archived-scan-dir",
      archived,
    ]);
    expect(replacementId).not.toBe(originalId);
    const context = await workbench(["get-scan", "--scan-id", originalId]);
    const progress = (context["scan"] as JsonObject)[
      "severityClassification"
    ] as JsonObject;
    expect(progress["retryArguments"]).toEqual(
      sdk ? undefined : expectedRetryArguments,
    );
    expect(progress["registeredScan"]).toBeUndefined();
    const expectedDirectory = explicitCopy ? copyDirectory : archived;
    expect(progress["scanDirectory"]).toBe(expectedDirectory);
    const history = capture(true);
    expect(
      await main(
        ["scans", "show", originalId],
        history.stream,
        capture().stream,
        cliDependencies,
      ),
    ).toBe(0);
    if (!sdk) {
      expect(history.text()).toContain(
        severityRetryCommand(expectedRetryArguments),
      );
    }
    control.failOn = "";
    calls.length = 0;
    const output = capture();
    if (sdk) {
      expect((await classifyWithSdk()).scanId).toBe(originalId);
    } else {
      expect(
        await main(
          [...expectedRetryArguments, "--json"],
          output.stream,
          capture().stream,
          cliDependencies,
        ),
      ).toBe(0);
      expect(JSON.parse(output.text()).scanId).toBe(originalId);
    }
    expect(calls).toEqual([original.findings.findings[1]!.findingId]);
    expect(
      JSON.parse(
        await readFile(
          join(expectedDirectory, "severity-classification.json"),
          "utf8",
        ),
      ).scanId,
    ).toBe(originalId);
    await expect(
      readFile(join(scanDirectory, "severity-classification.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    if (explicitCopy) {
      await expect(
        readFile(join(archived, "severity-classification.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    }
  },
);

test.each(["running", "failed"])(
  "directory retries resume sealed findings when completion history is %s",
  async (status) => {
    const {
      root,
      environment,
      scanDirectory,
      rubricPath,
      workbench,
      completeRegisteredScan,
    } = await registeredFixture();
    const scanId = await completeRegisteredScan([], "prepare-scan-completion");
    if (status === "failed")
      await workbench([
        "fail-scan",
        "--scan-id",
        scanId,
        "--message",
        "Completion interrupted",
      ]);
    const scan = (await workbench(["get-scan", "--scan-id", scanId]))[
      "scan"
    ] as JsonObject;
    expect((scan["progress"] as JsonObject)["status"]).toBe(status);
    const contract = await loadContract(scanDirectory, {
      pluginRoot: PLUGIN_ROOT,
    });
    expect(contract.manifest.scan.sealedAt).toBeDefined();
    const { codex, control, calls } = recordingClassifier();
    control.failOn = contract.findings.findings[1]!.findingId;
    const cliDependencies: NonNullable<Parameters<typeof main>[3]> = {
      ...dependencies(),
      environment,
      currentDirectory: () => root,
      runWorkbench: workbench,
      classifyScanSeverity: (id, options, _history, surface) =>
        classifyScanSeverityInternal(
          id,
          { ...options, codex },
          { runWorkbench: workbench },
          surface,
        ),
      classifyScanDirectorySeverity: (directory, options, surface) =>
        classifyScanDirectorySeverityInternal(
          directory,
          { ...options, codex },
          surface,
        ),
    };
    const savedError = capture();
    expect(
      await main(
        ["classify-severity", "--scan", scanId, "--rubric", rubricPath],
        capture().stream,
        savedError.stream,
        cliDependencies,
      ),
    ).toBe(2);
    expect(savedError.text()).toContain(`Scan ${scanId} is not complete.`);
    expect(calls).toEqual([]);
    const args = [
      "classify-severity",
      "--scan-dir",
      scanDirectory,
      "--rubric",
      rubricPath,
    ];
    const failure = capture();
    expect(
      await main(args, capture().stream, failure.stream, cliDependencies),
    ).toBe(2);
    expect(failure.text()).toContain("Interrupted model call");
    expect(failure.text()).toContain(severityRetryCommand(args));
    const context = await workbench(["get-scan", "--scan-id", scanId]);
    const progress = (context["scan"] as JsonObject)[
      "severityClassification"
    ] as JsonObject;
    expect(progress["retryArguments"]).toEqual(args);
    control.failOn = "";
    calls.length = 0;
    const output = capture();
    expect(
      await main(
        [...(progress["retryArguments"] as string[]), "--json"],
        output.stream,
        capture().stream,
        cliDependencies,
      ),
    ).toBe(0);
    expect(JSON.parse(output.text()).scanId).toBe(scanId);
    expect(calls).toEqual([contract.findings.findings[1]!.findingId]);
  },
);

test.each([false, true])(
  "commits a completed model response when cancellation arrives before its checkpoint (final finding: %s)",
  async (finalFinding) => {
    const { environment, scanDirectory, rubricPath, findings } =
      await fixture();
    const controller = new AbortController();
    const codex: NonNullable<ClassifySeverityOptions["codex"]> = {
      startThread: (thread) => ({
        run: async (prompt, turn) => {
          const response = await classifier(findings[0]!)
            .startThread(thread)
            .run(prompt, turn);
          controller.abort("SIGINT");
          return response;
        },
      }),
    };
    const findingIds = finalFinding ? [findings[0]!.findingId] : undefined;
    let failure: unknown;
    try {
      await classifyScanDirectorySeverityInternal(
        scanDirectory,
        {
          environment,
          rubricPath,
          codex,
          findingIds,
          reprocess: true,
          signal: controller.signal,
        },
        "cli",
      );
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(SeverityClassificationError);
    expect((failure as SeverityClassificationError).message).toBe("SIGINT");
    expect(
      (
        failure as SeverityClassificationError
      ).progress.retryArguments?.includes("--reprocess"),
    ).toBe(!finalFinding);
    const { codex: resumed, calls } = recordingClassifier();
    await classifyScanDirectorySeverity(scanDirectory, {
      environment,
      rubricPath,
      codex: resumed,
      findingIds,
    });
    expect(calls).toEqual(finalFinding ? [] : [findings[1]!.findingId]);
  },
);

test("export failure retains all assessments and its retry omits reprocess", async () => {
  const { environment, scanDirectory, rubricPath } = await fixture();
  const exportPath = join(scanDirectory, "severity-classification.json");
  await mkdir(exportPath);
  const { codex, calls } = recordingClassifier();
  let failure: unknown;
  try {
    await classifyScanDirectorySeverityInternal(
      scanDirectory,
      { environment, rubricPath, codex, reprocess: true },
      "cli",
    );
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(SeverityClassificationError);
  expect((failure as SeverityClassificationError).progress).toMatchObject({
    completed: 2,
    remaining: 0,
    failure: { stage: "export" },
  });
  expect(
    (failure as SeverityClassificationError).progress.retryArguments,
  ).not.toContain("--reprocess");
  await rm(exportPath, { recursive: true });
  calls.length = 0;
  const updates: SeverityClassificationProgress[] = [];
  await classifyScanDirectorySeverity(scanDirectory, {
    environment,
    rubricPath,
    codex,
    onProgress: (progress) => updates.push(progress),
  });
  expect(calls).toEqual([]);
  expect(updates.at(-1)).toMatchObject({
    status: "completed",
    completed: 2,
    reused: 2,
    remaining: 0,
  });
});

test.each([false, true])(
  "optional progress observers cannot stop classification or its checkpoints (async=%s)",
  async (asynchronous) => {
    const { environment, scanDirectory } = await fixture();
    const result = await classifyScanDirectorySeverity(scanDirectory, {
      environment,
      onProgress: () => {
        if (asynchronous)
          return Promise.reject(new Error("Broken progress output"));
        throw new Error("Broken progress output");
      },
    });
    expect(result.assessments).toHaveLength(2);
  },
);

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

test.each([0, 1, 2])(
  "no-rubric classification coalesces saved progress with %i cached findings",
  async (cached) => {
    const { environment, scanDirectory, scanId, findings } = await fixture();
    await new SeverityStore(environment, scanDirectory).isRegisteredScan(
      scanId,
    );
    if (cached > 0)
      await classifyScanDirectorySeverity(scanDirectory, {
        environment,
        findingIds: findings
          .slice(0, cached)
          .map((finding) => finding.findingId),
      });
    await query(
      environment,
      "CREATE TABLE saved_progress (progress_json TEXT)",
    );
    for (const action of ["INSERT", "UPDATE"])
      await query(
        environment,
        `CREATE TRIGGER capture_progress_${action.toLowerCase()}
      AFTER ${action} ON severity_classification_runs
      BEGIN INSERT INTO saved_progress VALUES (NEW.progress_json); END`,
      );
    const updates: SeverityClassificationProgress[] = [];
    const persist = spyOn(SeverityStore.prototype, "progress");
    try {
      const saved = await classifyScanDirectorySeverity(scanDirectory, {
        environment,
        onProgress: (progress) => updates.push(progress),
      });
      expect(saved.assessments).toHaveLength(2);
      expect(
        updates
          .filter((progress) => progress.phase === "classification")
          .map((progress) => progress.completed),
      ).toEqual(
        cached === 2
          ? [0, 1, 2]
          : cached === 1
            ? [0, 1, 1, 2]
            : [0, 0, 1, 1, 2],
      );
      expect(
        persist.mock.calls.map(([, progress]) => [
          progress.status,
          progress.phase,
          progress.reused,
        ]),
      ).toEqual([
        ["running", "classification", 0],
        ["running", "export", cached],
        ["completed", "export", cached],
      ]);
      const durable = (
        await query(environment, "SELECT progress_json FROM saved_progress")
      )
        .map(
          (row) =>
            JSON.parse(
              row["progress_json"] as string,
            ) as SeverityClassificationProgress,
        )
        .filter((update) => update.phase === "classification");
      expect(
        durable.map(({ completed, reused }) => [completed, reused]),
      ).toEqual([
        [0, 0],
        ...findings
          .slice(cached)
          .map((_, index) => [cached + index + 1, cached]),
      ]);
    } finally {
      persist.mockRestore();
    }
  },
);

test("optional progress persistence failure does not discard assessments", async () => {
  const { environment, scanDirectory, scanId } = await fixture();
  await new SeverityStore(environment, scanDirectory).isRegisteredScan(scanId);
  await query(
    environment,
    `CREATE TRIGGER fail_progress BEFORE INSERT ON severity_classification_runs
    BEGIN SELECT RAISE(FAIL, 'Progress storage unavailable'); END`,
  );
  const result = await classifyScanDirectorySeverity(scanDirectory, {
    environment,
  });
  expect(result.assessments).toHaveLength(2);
  expect(
    await query(
      environment,
      "SELECT COUNT(*) AS count FROM finding_severity_assessments",
    ),
  ).toEqual([{ count: 2 }]);
});
