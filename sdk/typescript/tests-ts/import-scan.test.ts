import { execFileSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, spyOn, test, mock } from "bun:test";
import { loadContract } from "../src/contract.js";
import { ScanInterruptedError } from "../src/errors.js";
import { importScan, type ImportScanOptions } from "../src/import-scan.js";
import type { FindingsDocument } from "../src/models.js";
import { ScanResult } from "../src/result.js";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting } from "./support/errors.js";

const { temporaryDirectories: roots, cleanup } = createApiTestFixtures();
afterEach(cleanup);

const description =
  'An imported report with a comma, a "quoted value", and Unicode: café.\n\n' +
  "The full second paragraph must survive importing and indexing.\n" +
  "A final line describes the reported impact.";
const sourceOccurrenceIds = [
  "occ_000000000000000000000001",
  "occ_000000000000000000000002",
];
const csvColumns = [
  "occurrence_id",
  "finding_id",
  "title",
  "summary",
  "severity",
  "confidence",
  "status",
  "close_reason",
  "note",
  "remediation",
  "path",
  "start_line",
  "end_line",
];

function csvSource(): string {
  const rows = sourceOccurrenceIds.map((occurrenceId, index) => [
    occurrenceId,
    `csf_00000000000000000000000${index + 1}`,
    "Reported archive extraction issue",
    description,
    "high",
    "high",
    "open",
    "",
    "",
    "Validate archive entry destinations.",
    "src/extract.ts",
    "41",
    "44",
  ]);
  return (
    [csvColumns, ...rows]
      .map((row) =>
        row.map((value) => `"${value.replaceAll('"', '""')}"`).join(","),
      )
      .join("\r\n") + "\r\n"
  );
}

async function fixture(format: "csv" | "json" = "csv") {
  const root = await mkdtemp(
    join(await realpath(tmpdir()), "import-scan-test-"),
  );
  roots.track(root);
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const stateDirectory = join(root, "state");
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: join(root, "codex-home"),
    CODEX_SECURITY_STATE_DIR: stateDirectory,
  };
  let source = csvSource();
  if (format === "json") {
    const example = JSON.parse(
      await readFile(
        join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
        "utf8",
      ),
    ) as FindingsDocument;
    const finding = example.findings[0]!;
    source = JSON.stringify({
      ...example,
      findings: sourceOccurrenceIds.map((occurrenceId) => ({
        ...finding,
        occurrenceId,
        summary: description,
      })),
    });
  }
  const sourcePath = join(root, `findings.${format}`);
  await writeFile(sourcePath, source);
  const options: ImportScanOptions = {
    sourcePath,
    format,
    config: { pluginPath: PLUGIN_ROOT, pythonPath: python! },
  };
  return {
    root,
    stateDirectory,
    dependencies: {
      environment,
      // Import persistence uses real Python; runtime tests cover interpreter discovery.
      resolvePluginPython: async () => python!,
    },
    python: python!,
    source,
    options,
    workbenchOptions: { python: python!, pluginRoot: PLUGIN_ROOT, environment },
  };
}

async function legacyArchivePlugin(
  context: Awaited<ReturnType<typeof fixture>>,
) {
  const plugin = join(context.root, "legacy-plugin");
  await cp(PLUGIN_ROOT, plugin, { recursive: true });
  await writeFile(
    join(plugin, "scripts", "workbench_db.py"),
    [
      "import runpy, sys",
      "from pathlib import Path",
      "args = sys.argv[1:]",
      'if args[:2] == ["register-cli-scan", "--help"]:',
      '    print("--archive-existing --archived-scan-dir")',
      "    raise SystemExit(0)",
      'if args and args[0] == "register-cli-scan":',
      '    scan_dir = Path(args[args.index("--scan-dir") + 1])',
      "    if next(scan_dir.iterdir(), None) is not None:",
      '        raise SystemExit("The scan artifact directory must be empty before the scan starts.")',
      `runpy.run_path(${JSON.stringify(join(PLUGIN_ROOT, "scripts", "workbench_db.py"))}, run_name="__main__")`,
    ].join("\n"),
  );
  return plugin;
}

function completed(result: Awaited<ReturnType<typeof importScan>>): ScanResult {
  expect(result).toBeInstanceOf(ScanResult);
  if (!(result instanceof ScanResult)) throw new Error("Expected a saved scan");
  return result;
}

async function storedScans(context: Awaited<ReturnType<typeof fixture>>) {
  const result = await runCommand(
    context.python,
    [
      "-c",
      [
        "import json, sqlite3, sys",
        "connection = sqlite3.connect(sys.argv[1])",
        "connection.row_factory = sqlite3.Row",
        'rows = connection.execute("SELECT id, status, target_path, scan_dir, (SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = scans.id) AS occurrence_count FROM scans ORDER BY created_at, id")',
        'print(json.dumps([dict(row, summaries=[summary for (summary,) in connection.execute("SELECT summary FROM finding_occurrences WHERE scan_id = ?", (row["id"],))]) for row in rows]))',
      ].join("\n"),
      join(context.stateDirectory, "workbench.sqlite3"),
    ],
    { timeout: 30_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Array<{
    id: string;
    status: string;
    target_path: string;
    scan_dir: string;
    occurrence_count: number;
    summaries: string[];
  }>;
}

test("a rejected import registration keeps existing output in place", async () => {
  const context = await fixture();
  const outputDir = join(context.root, "scan");
  await mkdir(outputDir, { mode: 0o700 });
  await writeFile(join(outputDir, "previous.txt"), "previous scan\n");
  await expect(
    importScan(
      { ...context.options, outputDir, archiveExisting: true },
      {
        ...context.dependencies,
        runWorkbench: async () => {
          throw new Error("fixture registration rejected");
        },
      },
    ),
  ).rejects.toThrow("fixture registration rejected");
  expect(await readFile(join(outputDir, "previous.txt"), "utf8")).toBe(
    "previous scan\n",
  );
});

test.each(["csv", "json"] as const)(
  "%s import seals every source occurrence and indexes a separate dataset scan",
  async (format) => {
    const context = await fixture(format);
    const result = completed(
      await importScan(context.options, context.dependencies),
    );
    expect(result.findings.findings).toHaveLength(2);
    expect(
      new Set(result.findings.findings.map((finding) => finding.findingId))
        .size,
    ).toBe(2);
    expect(
      new Set(result.findings.findings.map((finding) => finding.occurrenceId))
        .size,
    ).toBe(2);
    for (const finding of result.findings.findings) {
      expect(finding.summary).toBe(description);
      expect(finding.locations[0]).toMatchObject({
        startLine: 41,
        endLine: 44,
      });
      expect(finding.extensions?.["import"]).toMatchObject({ format });
    }
    const expectedFindingIds =
      format === "csv"
        ? ["csf_000000000000000000000001", "csf_000000000000000000000002"]
        : (JSON.parse(context.source) as FindingsDocument).findings.map(
            (finding) => finding.findingId,
          );
    expect(
      result.findings.findings
        .map(
          (finding) =>
            (finding.extensions?.["import"] as { sourceFindingId: string })
              .sourceFindingId,
        )
        .sort(),
    ).toEqual(expectedFindingIds.sort());
    expect(
      result.findings.findings
        .map(
          (finding) =>
            (finding.extensions?.["import"] as { sourceOccurrenceId: string })
              .sourceOccurrenceId,
        )
        .sort(),
    ).toEqual(sourceOccurrenceIds);
    expect(result.findings.findings[0]!.locations).toEqual(
      result.findings.findings[1]!.locations,
    );
    expect(result.manifest.scan.status).toBe("completed");
    expect(result.manifest.scan.sealedAt).toBeTruthy();
    expect(result.manifest.scan.target.kind).toBe("directory_snapshot");
    expect(result.manifest.scan.scope.runtimeStatus).toBe("imported");
    expect(result.coverage.completeness).toBe("unknown");
    expect(result.turnResult["imported"]).toBe(true);
    expect(result.threadId).toBe("");
    expect(await readFile(result.reportPath, "utf8")).toContain(
      "no security analysis was performed",
    );
    expect(
      await loadContract(result.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).toEqual({
      manifest: result.manifest,
      findings: result.findings,
      coverage: result.coverage,
    });
    const sourceRef = `artifacts/import/source.${format}`;
    expect(result.manifest.scan["extensions"]).toMatchObject({
      import: { format, sourceRef, findingCount: 2 },
    });
    expect(
      result.manifest.scan.artifacts.some(
        (artifact) => artifact.path === sourceRef,
      ),
    ).toBe(true);
    expect(await readFile(join(result.scanDir, sourceRef), "utf8")).toBe(
      context.source,
    );
    expect(await readFile(context.options.sourcePath, "utf8")).toBe(
      context.source,
    );
    const [stored] = await storedScans(context);
    expect(stored).toMatchObject({
      id: result.manifest.scan.id,
      status: "complete",
      occurrence_count: 2,
      summaries: [description, description],
    });
    expect(stored!.target_path).not.toBe(process.cwd());
    expect(stored!.target_path).not.toBe(context.root);
    const recipe = await runWorkbench(context.workbenchOptions, [
      "get-scan-recipe",
      "--scan-id",
      result.manifest.scan.id,
    ]);
    const imported = (
      recipe["recipe"] as { import: { format: string; sourcePath: string } }
    ).import;
    expect(imported.format).toBe(format);
    expect(imported.sourcePath).not.toBe(context.options.sourcePath);
    expect(await readFile(imported.sourcePath, "utf8")).toBe(context.source);
  },
);

test.each(["csv", "json"] as const)(
  "%s import rejects a symlinked source before persistence",
  async (format) => {
    const context = await fixture(format);
    const linked = join(context.root, `linked.${format}`);
    await symlink(context.options.sourcePath, linked, "file");
    for (const dryRun of [false, true]) {
      await expect(
        importScan(
          { ...context.options, sourcePath: linked, dryRun },
          context.dependencies,
        ),
      ).rejects.toThrow("Import source must be a regular file");
      await expect(stat(context.stateDirectory)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  },
);

test.each(["csv", "json"] as const)(
  "%s import rejects directory links before persistence",
  async (format) => {
    const context = await fixture(format);
    const repository = join(context.root, "repository");
    await mkdir(repository);
    const linked = join(repository, "reports");
    await symlink(
      context.root,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );
    for (const dryRun of [false, true]) {
      await expect(
        importScan(
          {
            ...context.options,
            sourcePath: join(linked, `findings.${format}`),
            dryRun,
          },
          context.dependencies,
        ),
      ).rejects.toThrow("Import source must not traverse directory links");
      await expect(stat(context.stateDirectory)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  },
);

test.each(process.platform === "win32" ? ["directory"] : ["directory", "FIFO"])(
  "import rejects a %s source before persistence",
  async (kind) => {
    const context = await fixture();
    await rm(context.options.sourcePath);
    if (kind === "directory") await mkdir(context.options.sourcePath);
    else execFileSync("mkfifo", [context.options.sourcePath]);
    await expect(
      importScan(context.options, context.dependencies),
    ).rejects.toThrow("Import source must be a regular file");
    await expect(stat(context.stateDirectory)).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

test.each(["regular file", "symbolic link"])(
  "import rejects a source replaced with a %s before reading",
  async (replacement) => {
    if (
      runTestInSubprocess(
        import.meta.path,
        `import rejects a source replaced with a ${replacement} before reading`,
      )
    )
      return;
    const context = await fixture("json");
    const originalOpen = filesystem.open;
    let replaced = false;
    const observeRead = mock(rejecting("Read a replaced source"));
    let restoreRead: (() => void) | undefined;
    const opening = spyOn(filesystem, "open").mockImplementation(
      async (...args: Parameters<typeof filesystem.open>) => {
        if (String(args[0]) !== context.options.sourcePath) {
          return await originalOpen(...args);
        }
        opening.mockRestore();
        const previous = join(context.root, "previous.json");
        await rename(context.options.sourcePath, previous);
        if (replacement === "symbolic link") {
          await symlink(previous, context.options.sourcePath, "file");
        } else {
          await writeFile(context.options.sourcePath, context.source);
        }
        replaced = true;
        const file = await originalOpen(...args);
        const reading = spyOn(file, "readFile").mockImplementation(observeRead);
        restoreRead = () => reading.mockRestore();
        return file;
      },
    );
    try {
      await expect(
        importScan(context.options, context.dependencies),
      ).rejects.toThrow();
      expect(replaced).toBe(true);
      expect(observeRead).not.toHaveBeenCalled();
      await expect(stat(context.stateDirectory)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      restoreRead?.();
      opening.mockRestore();
    }
  },
);

test("reimporting the retained source preserves finding identities with new scan occurrences", async () => {
  const context = await fixture();
  const first = completed(
    await importScan(context.options, context.dependencies),
  );
  const recipe = await runWorkbench(context.workbenchOptions, [
    "get-scan-recipe",
    "--scan-id",
    first.manifest.scan.id,
  ]);
  const imported = (recipe["recipe"] as { import: { sourcePath: string } })
    .import;
  await rm(context.options.sourcePath);
  const second = completed(
    await importScan(
      {
        ...context.options,
        sourcePath: imported.sourcePath,
        parentScanId: first.manifest.scan.id,
      },
      context.dependencies,
    ),
  );
  expect(second.manifest.scan.id).not.toBe(first.manifest.scan.id);
  expect(second.manifest.scan.target.targetId).toBe(
    first.manifest.scan.target.targetId,
  );
  expect(second.findings.findings.map((finding) => finding.findingId)).toEqual(
    first.findings.findings.map((finding) => finding.findingId),
  );
  const previousOccurrences = new Set(
    first.findings.findings.map((finding) => finding.occurrenceId),
  );
  expect(
    second.findings.findings.every(
      (finding) => !previousOccurrences.has(finding.occurrenceId),
    ),
  ).toBe(true);
  expect(
    (await storedScans(context)).map((scan) => scan.occurrence_count),
  ).toEqual([2, 2]);
});

test("dry run validates source rows without creating database state or invoking the workbench", async () => {
  const context = await fixture();
  const unexpected = rejecting("Dry run invoked scan persistence");
  const result = await importScan(
    { ...context.options, dryRun: true },
    {
      ...context.dependencies,
      runWorkbench: unexpected,
      resolvePluginPython: unexpected,
    },
  );
  expect(result).toEqual({
    dryRun: true,
    inputPath: context.options.sourcePath,
    format: "csv",
    findingCount: 2,
  });
  await expect(stat(context.stateDirectory)).rejects.toMatchObject({
    code: "ENOENT",
  });
  await writeFile(context.options.sourcePath, "not,a,findings,header\n");
  await expect(
    importScan(
      { ...context.options, dryRun: true },
      {
        ...context.dependencies,
        runWorkbench: unexpected,
      },
    ),
  ).rejects.toThrow();
  await expect(stat(context.stateDirectory)).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test.each(["bundled", "legacy"])(
  "imports with %s helpers archive prior output without replacing its saved findings",
  async (helper) => {
    const context = await fixture();
    const options = {
      ...context.options,
      ...(helper === "legacy"
        ? {
            config: {
              ...context.options.config,
              pluginPath: await legacyArchivePlugin(context),
            },
          }
        : {}),
      outputDir: join(context.root, "results"),
    };
    const first = completed(await importScan(options, context.dependencies));
    const originalManifest = await readFile(first.manifestPath, "utf8");
    await expect(importScan(options, context.dependencies)).rejects.toThrow();
    expect(await readFile(first.manifestPath, "utf8")).toBe(originalManifest);
    const second = completed(
      await importScan(
        { ...options, archiveExisting: true },
        context.dependencies,
      ),
    );
    const scans = await storedScans(context);
    expect(scans).toHaveLength(2);
    const archived = scans.find((scan) => scan.id === first.manifest.scan.id)!;
    expect(archived.scan_dir).not.toBe(second.scanDir);
    expect(archived.occurrence_count).toBe(2);
    expect(
      await readFile(join(archived.scan_dir, "scan-manifest.json"), "utf8"),
    ).toBe(originalManifest);
    expect(
      (await loadContract(archived.scan_dir, { pluginRoot: PLUGIN_ROOT }))
        .findings.findings,
    ).toHaveLength(2);
  },
);

test.each(["active scan", "missing parent"])(
  "legacy registration restores output after rejecting %s",
  async (reason) => {
    const context = await fixture();
    const options = {
      ...context.options,
      config: {
        ...context.options.config,
        pluginPath: await legacyArchivePlugin(context),
      },
      outputDir: join(context.root, "results"),
    };
    const first = completed(await importScan(options, context.dependencies));
    const manifest = await readFile(first.manifestPath, "utf8");
    if (reason === "active scan") {
      const update = await runCommand(
        context.python,
        [
          "-c",
          "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE scans SET status='running'\"); c.commit()",
          join(context.stateDirectory, "workbench.sqlite3"),
        ],
        { timeout: 30_000 },
      );
      expect(update.status, update.stderr).toBe(0);
    }
    await expect(
      importScan(
        {
          ...options,
          archiveExisting: true,
          ...(reason === "missing parent"
            ? { parentScanId: "00000000-0000-4000-8000-000000000001" }
            : {}),
        },
        context.dependencies,
      ),
    ).rejects.toThrow(
      reason === "active scan" ? "running scan" : "scan not found",
    );
    expect(await readFile(first.manifestPath, "utf8")).toBe(manifest);
    expect(await storedScans(context)).toHaveLength(1);
    expect((await storedScans(context))[0]?.scan_dir).toBe(first.scanDir);
  },
);

test.each(["response lost", "state unreadable"])(
  "legacy registration preserves its archive when %s after commit",
  async (failure) => {
    const context = await fixture();
    const pluginPath = await legacyArchivePlugin(context);
    const options = {
      ...context.options,
      config: { ...context.options.config, pluginPath },
      outputDir: join(context.root, "results"),
    };
    const first = completed(await importScan(options, context.dependencies));
    const manifest = await readFile(first.manifestPath, "utf8");
    const helper = join(pluginPath, "scripts", "workbench_db.py");
    const original = await readFile(helper, "utf8");
    await writeFile(
      helper,
      original
        .replace(
          "import runpy, sys",
          [
            "import contextlib, io, runpy, sys",
            "from pathlib import Path",
            "args = sys.argv[1:]",
            ...(failure === "state unreadable"
              ? [
                  'if args and args[0] == "list-scans" and Path(__file__).with_suffix(".committed").exists():',
                  '    raise SystemExit("Synthetic state read failure")',
                ]
              : []),
          ].join("\n"),
        )
        .replace(
          "runpy.run_path(",
          'lost_response = args and args[0] == "register-cli-scan"\nwith contextlib.redirect_stdout(io.StringIO()) if lost_response else contextlib.nullcontext():\n    runpy.run_path(',
        ) +
        '\nif lost_response:\n    Path(__file__).with_suffix(".committed").touch()\n    raise SystemExit("Synthetic response lost after commit")\n',
    );
    await expect(
      importScan({ ...options, archiveExisting: true }, context.dependencies),
    ).rejects.toThrow("Synthetic response lost after commit");
    const scans = await storedScans(context);
    expect(scans).toHaveLength(2);
    const archived = scans.find((scan) => scan.id === first.manifest.scan.id)!;
    expect(archived.scan_dir).not.toBe(first.scanDir);
    expect(
      await readFile(join(archived.scan_dir, "scan-manifest.json"), "utf8"),
    ).toBe(manifest);
    expect(
      await stat(join(first.scanDir, "scan-manifest.json")).catch(() => null),
    ).toBeNull();
  },
);

test.each(["failure", "abort"] as const)(
  "an import %s after registration leaves a terminal saved scan",
  async (mode) => {
    const context = await fixture();
    const controller = new AbortController();
    const run: typeof runWorkbench = async (options, args, input) => {
      if (args[0] === "prepare-scan-completion" && mode === "failure") {
        throw new Error("Synthetic import completion failure");
      }
      const result = await runWorkbench(options, args, input);
      if (args[0] === "register-cli-scan" && mode === "abort")
        controller.abort();
      return result;
    };
    const operation = importScan(
      { ...context.options, signal: controller.signal },
      {
        ...context.dependencies,
        runWorkbench: run,
      },
    );
    if (mode === "abort")
      await expect(operation).rejects.toBeInstanceOf(ScanInterruptedError);
    else
      await expect(operation).rejects.toThrow(
        "Synthetic import completion failure",
      );
    const scans = await storedScans(context);
    expect(scans).toHaveLength(1);
    expect(scans[0]!.status).toBe("failed");
  },
);
