import { randomUUID } from "node:crypto";
import { rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  classifySeverityInternal,
  validateSeverityClassification,
  type ClassifySeverityOptions,
  type SeverityClassification,
} from "./classify-severity.js";
import { loadContractWithScanDirectory } from "./contract.js";
import { CodexSecurityError } from "./errors.js";
import type { Finding } from "./models.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
} from "./runtime.js";
import {
  resolveCompletedScan,
  type SavedScanDependencies,
} from "./saved-scan.js";
import { SeverityStore } from "./severity-store.js";

const CLASSIFICATION_FILE = "severity-classification.json";
export interface ScanSeverityClassification extends SeverityClassification {
  scanId: string;
}

export interface ClassifyScanSeverityOptions extends ClassifySeverityOptions {
  /** Exact selection, such as dedupe's uniqueFindingIds. Omit to classify all findings. */
  findingIds?: readonly string[];
  /** Reclassify selected findings even when their saved assessment matches the inputs. */
  reprocess?: boolean;
  expectedScanId?: string;
}

/** Resolve a saved scan ID, unique prefix, or latest and save its classification. */
export async function classifyScanSeverity(
  scanId: string,
  options: ClassifyScanSeverityOptions = {},
): Promise<ScanSeverityClassification> {
  return classifyScanSeverityInternal(scanId, options);
}

/** @internal */
export async function classifyScanSeverityInternal(
  scanId: string,
  options: ClassifyScanSeverityOptions = {},
  dependencies: Partial<SavedScanDependencies> = {},
  surface: "sdk" | "cli" = "sdk",
): Promise<ScanSeverityClassification> {
  options.signal?.throwIfAborted();
  const environment = options.environment ?? process.env;
  const pluginRoot = await bundledPluginRoot();
  const scan = await resolveCompletedScan(scanId, {
    currentDirectory: dependencies.currentDirectory ?? (() => process.cwd()),
    runWorkbench:
      dependencies.runWorkbench ??
      (async (args) => {
        const stateEnvironment = {
          ...environment,
          CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(environment),
        };
        return runWorkbench(
          {
            environment: stateEnvironment,
            pluginRoot,
            python: await resolvePluginPython({
              environment: stateEnvironment,
            }),
            signal: options.signal,
            failureMessage: "Could not read Codex Security scan history",
          },
          args,
        );
      }),
  });
  if (
    options.expectedScanId !== undefined &&
    options.expectedScanId !== scan.scanId
  ) {
    throw new CodexSecurityError("Saved scan does not match expectedScanId.");
  }
  return classifyScanDirectorySeverityInternal(
    scan.scanDir,
    { ...options, expectedScanId: scan.scanId },
    surface,
  );
}

/** Classify a sealed scan directory and save a separate assessment without changing its artifacts. */
export async function classifyScanDirectorySeverity(
  scanDirectory: string,
  options: ClassifyScanSeverityOptions = {},
): Promise<ScanSeverityClassification> {
  return classifyScanDirectorySeverityInternal(scanDirectory, options);
}

/** @internal */
export async function classifyScanDirectorySeverityInternal(
  requestedDirectory: string,
  options: ClassifyScanSeverityOptions = {},
  surface: "sdk" | "cli" = "sdk",
): Promise<ScanSeverityClassification> {
  const { contract, scanDirectory } = await loadContractWithScanDirectory(
    requestedDirectory,
    {
      pluginRoot: await bundledPluginRoot(),
      expectedScanId: options.expectedScanId,
      signal: options.signal,
    },
  );
  const findings = selectClassificationFindings(
    contract.findings.findings,
    options.findingIds,
  );
  const store = new SeverityStore(
    options.environment ?? process.env,
    scanDirectory,
    options.signal,
  );
  const result: ScanSeverityClassification = {
    ...(await classifySeverityInternal(
      findings,
      options,
      surface,
      store.checkpoint(
        contract.manifest.scan.id,
        findings.map(({ findingId }) => findingId),
        options.reprocess ?? false,
      ),
    )),
    scanId: contract.manifest.scan.id,
  };
  options.signal?.throwIfAborted();
  const temporary = join(
    scanDirectory,
    `.severity-classification-${randomUUID()}.json`,
  );
  try {
    await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
      signal: options.signal,
    });
    options.signal?.throwIfAborted();
    await rename(temporary, join(scanDirectory, CLASSIFICATION_FILE));
  } finally {
    await rm(temporary, { force: true });
  }
  return result;
}

/** @internal */
export function selectClassificationFindings(
  findings: readonly Finding[],
  findingIds?: readonly string[],
): readonly Finding[] {
  if (findingIds === undefined) return findings;
  const selected = new Set(findingIds);
  const result = findings.filter((finding) => selected.has(finding.findingId));
  if (result.length !== selected.size) {
    throw new CodexSecurityError(
      "Selected finding IDs must belong to the supplied scan.",
    );
  }
  return result;
}

/** @internal */
export async function readScanSeverityClassification(
  scanDirectory: string,
  scanId: string,
  findings: readonly Finding[],
  signal?: AbortSignal,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<SeverityClassification | undefined> {
  const classification = await new SeverityStore(
    environment,
    scanDirectory,
    signal,
  ).read(scanId);
  return classification === undefined
    ? undefined
    : validateSeverityClassification(classification, findings);
}
