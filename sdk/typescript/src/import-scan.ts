import { workbenchArgs } from "./workbench-arguments.js";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { CodexSecurityConfig } from "./config.js";
import { loadContract, sameCheckedFileDevice } from "./contract.js";
import {
  CodexSecurityError,
  ScanInterruptedError,
  errorMessage,
} from "./errors.js";
import {
  bindImportedFindings,
  parseImportedFindings,
} from "./findings-import.js";
import { ScanResult } from "./result.js";
import {
  bundledPluginRoot,
  cleanupSdkDirectory,
  codexSecurityStateDirectory,
  expandHome,
  pluginMetadata,
  prepareScanRegistrationOutput,
  preparePersistentOutputRoot,
  requireOutputOutsideRepository,
  requirePrivateOutputDirectory,
  requireSecureOutputAncestry,
  resolvePluginPath,
  resolvePluginPython,
  runWorkbench,
  validateOutputDir,
  type ProcessEnvironment,
  type WorkbenchCommandOptions,
} from "./runtime.js";

export interface ImportScanOptions {
  sourcePath: string;
  format: "csv" | "json";
  config?: CodexSecurityConfig;
  outputDir?: string;
  archiveExisting?: boolean;
  dryRun?: boolean;
  parentScanId?: string;
  signal?: AbortSignal;
}

export interface ImportScanPreview {
  dryRun: true;
  inputPath: string;
  format: "csv" | "json";
  findingCount: number;
}

export interface ImportScanDependencies {
  environment?: ProcessEnvironment;
  runWorkbench?: typeof runWorkbench;
  resolvePluginPython?: typeof resolvePluginPython;
  onWarning?: (warning: string) => void;
}

const IMPORT_DESCRIPTION =
  "Imported findings; no security analysis was performed. Coverage is unknown. Source locations describe the imported reports.";

async function readImportSource(
  inputPath: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  signal?.throwIfAborted();
  const selected = await lstat(inputPath, { bigint: true });
  if (!selected.isFile()) {
    throw new CodexSecurityError("Import source must be a regular file.");
  }
  for (let parent = dirname(inputPath); ; parent = dirname(parent)) {
    signal?.throwIfAborted();
    if ((await lstat(parent)).isSymbolicLink()) {
      throw new CodexSecurityError(
        "Import source must not traverse directory links. Use the direct filesystem path.",
      );
    }
    if (dirname(parent) === parent) break;
  }
  const path = join(await realpath(dirname(inputPath)), basename(inputPath));
  const file = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  );
  try {
    signal?.throwIfAborted();
    const opened = await file.stat({ bigint: true });
    const current = await lstat(path, { bigint: true });
    if (
      !opened.isFile() ||
      !current.isFile() ||
      current.dev !== selected.dev ||
      current.ino !== selected.ino ||
      !(await sameCheckedFileDevice(file, { path, metadata: selected }, opened))
    ) {
      throw new CodexSecurityError(
        "Import source must remain the selected regular file.",
      );
    }
    return await file.readFile({ signal });
  } finally {
    await file.close();
  }
}

/** Save supplied findings through the normal scan completion and indexing flow. */
export async function importScan(
  options: ImportScanOptions,
  dependencies: ImportScanDependencies = {},
): Promise<ScanResult | ImportScanPreview> {
  const { signal } = options;
  const environment = dependencies.environment ?? process.env;
  const inputPath = resolve(expandHome(options.sourcePath, environment));
  const source = await readImportSource(inputPath, signal);
  const workspace = await mkdtemp(
    join(await realpath(tmpdir()), "codex-security-import-"),
  );
  const workbench = dependencies.runWorkbench ?? runWorkbench;
  let activeScan: { id: string; options: WorkbenchCommandOptions } | undefined;
  let scanDir = "";
  try {
    const pluginRoot = await resolvePluginPath(
      options.config?.pluginPath,
      workspace,
      signal,
    );
    const findings = await parseImportedFindings(
      new TextDecoder("utf-8", { fatal: true }).decode(source),
      options.format,
      pluginRoot,
    );
    const helper = (
      await import(
        pathToFileURL(join(await bundledPluginRoot(), "mcp/helpers.mjs")).href
      )
    ).default;
    try {
      helper.parseCurrentFindings(
        findings.map((finding) => {
          // Import assigns new identities and retains source metadata as provenance.
          const { findingId, occurrenceId, fingerprints, writeup, ...content } =
            finding;
          return {
            ...content,
            provenance: { source: `${options.format}_import` },
          };
        }),
      );
    } catch (error) {
      throw new CodexSecurityError(
        `Imported findings do not match the current scan-draft finding contract: ${errorMessage(error)}`,
        { cause: error },
      );
    }
    signal?.throwIfAborted();
    await validateOutputDir(options.outputDir, options.archiveExisting);
    if (options.dryRun) {
      return {
        dryRun: true,
        inputPath,
        format: options.format,
        findingCount: findings.length,
      };
    }
    const plugin = await pluginMetadata(pluginRoot);
    const stateDirectory = codexSecurityStateDirectory(environment);
    const digest = createHash("sha256")
      .update(options.format)
      .update("\0")
      .update(source)
      .digest("hex");
    // A retained input directory is the scan target, independent of the caller's repository.
    const repository = await preparePersistentOutputRoot(
      stateDirectory,
      "imports",
      `${options.format}-${digest}`,
    );
    requirePrivateOutputDirectory(await lstat(repository), repository);
    await requireSecureOutputAncestry(repository);
    const sourcePath = join(repository, `source.${options.format}`);
    try {
      await writeFile(sourcePath, source, { flag: "wx", signal });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (!(await readFile(sourcePath, { signal })).equals(source)) {
        throw new CodexSecurityError("The retained import source has changed.");
      }
    }
    const python = await (
      dependencies.resolvePluginPython ?? resolvePluginPython
    )({
      configuredPath: options.config?.pythonPath,
      environment,
      protectedRoot: repository,
      signal,
    });
    const outputRoot =
      options.outputDir === undefined
        ? await preparePersistentOutputRoot(stateDirectory, "scans", "imports")
        : undefined;
    scanDir = await prepareScanRegistrationOutput(
      options.outputDir,
      "import",
      outputRoot,
      (path) => requireOutputOutsideRepository(repository, path),
      options.archiveExisting,
    );
    const workbenchOptions: WorkbenchCommandOptions = {
      python,
      pluginRoot,
      environment: { ...environment, CODEX_SECURITY_STATE_DIR: stateDirectory },
      signal,
      failureMessage: "Could not save the imported scan",
    };
    signal?.throwIfAborted();
    const registration = await workbench(
      workbenchOptions,
      workbenchArgs("register-cli-scan", {
        repository,
        scanDir,
        registrationJsonStdin: true,
        archiveExisting: Boolean(options.archiveExisting),
        parentScanId: options.parentScanId,
      }),
      JSON.stringify({
        recipe: {
          repository,
          target: { kind: "repository", paths: [] },
          mode: "standard",
          pluginVersion: plugin.version,
          config: {},
          import: { format: options.format, sourcePath },
        },
      }),
    );
    const scanId = registration["scanId"];
    const targetId = registration["targetId"];
    if (
      typeof scanId !== "string" ||
      typeof targetId !== "string" ||
      registration["scanDir"] !== scanDir
    ) {
      throw new CodexSecurityError(
        "The workbench returned an invalid import scan registration.",
      );
    }
    activeScan = { id: scanId, options: workbenchOptions };
    signal?.throwIfAborted();
    const bound = bindImportedFindings(
      findings,
      options.format,
      scanId,
      targetId,
    );
    const sourceRef = `artifacts/import/source.${options.format}`;
    await mkdir(join(scanDir, "artifacts", "import"), { recursive: true });
    await writeFile(join(scanDir, sourceRef), source, { flag: "wx", signal });
    const documents: Record<string, unknown> = {
      "scan-manifest.json": {
        scan: {
          target: { kind: "directory_snapshot" },
          scope: {
            summary: IMPORT_DESCRIPTION,
            runtimeStatus: "imported",
            limitations: [IMPORT_DESCRIPTION],
          },
          mode: "repository",
          reviewState: {
            surfaces: findings.length
              ? [
                  {
                    id: "import",
                    label: basename(inputPath),
                    disposition: "reported",
                    receiptRefs: [sourceRef],
                    notes: IMPORT_DESCRIPTION,
                  },
                ]
              : [],
            explicitExclusions: [],
            deferred: [],
          },
          extensions: {
            import: {
              format: options.format,
              sourceRef,
              findingCount: findings.length,
            },
          },
        },
      },
      "findings.json": { findings: bound },
    };
    for (const [name, document] of Object.entries(documents)) {
      await writeFile(
        join(scanDir, name),
        `${JSON.stringify(document, null, 2)}\n`,
        { flag: "wx", signal },
      );
    }
    await workbench(
      workbenchOptions,
      workbenchArgs("prepare-scan-completion", { scanId }),
    );
    // Finalization normally recovers partial output. An import must retain every supplied row.
    const contract = await loadContract(scanDir, {
      pluginRoot,
      expectedScanId: scanId,
      workbenchValidated: true,
      signal,
    });
    const expectedIds = new Set(bound.map((finding) => finding.findingId));
    if (
      contract.findings.findings.length !== findings.length ||
      contract.findings.findings.some(
        (finding) => !expectedIds.delete(finding.findingId),
      )
    ) {
      throw new CodexSecurityError(
        "Import finalization did not preserve every input finding; the scan was not completed.",
      );
    }
    await workbench(workbenchOptions, ["complete-scan", "--scan-id", scanId]);
    activeScan = undefined;
    return new ScanResult({
      ...contract,
      scanDir,
      threadId: "",
      turnResult: {
        status: "completed",
        imported: true,
        finalResponse: IMPORT_DESCRIPTION,
      },
    });
  } catch (error) {
    if (activeScan !== undefined) {
      await workbench({ ...activeScan.options, signal: undefined }, [
        "fail-scan",
        "--scan-id",
        activeScan.id,
        `--message=${errorMessage(error)}`,
      ]).catch(() => undefined);
    }
    if (signal?.aborted) {
      throw new ScanInterruptedError(
        "Codex Security import was interrupted.",
        scanDir,
        { cause: error },
      );
    }
    throw error;
  } finally {
    await cleanupSdkDirectory(workspace).catch((error: unknown) => {
      void Promise.resolve()
        .then(() =>
          dependencies.onWarning?.(
            `Could not clean up after the Codex Security import: ${errorMessage(error)}`,
          ),
        )
        .catch(() => {});
    });
  }
}
