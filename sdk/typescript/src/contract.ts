import { constants, type BigIntStats, type Stats } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ContractValidationError, abortReason } from "./errors.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import type { NormalizedTarget, ScanMode } from "./targets.js";
import { bundledPluginRoot } from "./runtime.js";
import { safeScopePath as sharedSafeScopePath } from "./contract-values.js";
export {
  deriveFindingIdentity,
  hasRequiredFindingText,
} from "./contract-values.js";
/** @internal */
export { sha256Text } from "./contract-values.js";

const PRODUCER_NAME = "codex-security-plugin";
export interface ScanExpectation {
  repository: string;
  repositoryRevision: string | null;
  target: NormalizedTarget;
  mode: ScanMode;
  pluginVersion: string;
}

export interface LoadedContract {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
}

export class ContractSchemaError extends ContractValidationError {}

type LoadContractOptions = {
  pluginRoot: string;
  expectedScanId?: string;
  expectation?: ScanExpectation;
  workbenchValidated?: boolean;
  signal?: AbortSignal;
};

async function contractHelper() {
  return (
    await import(
      pathToFileURL(join(await bundledPluginRoot(), "mcp/helpers.mjs")).href
    )
  ).default;
}

async function translateContractError<T>(
  operation: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (signal?.aborted) throw abortReason(signal);
    if (error instanceof ContractValidationError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    if (error instanceof Error && error.name === "SealedContractSchemaError")
      throw new ContractSchemaError(message, { cause: error.cause });
    throw new ContractValidationError(message, {
      cause:
        error instanceof Error && error.name === "SealedContractError"
          ? error.cause
          : error,
    });
  }
}

export async function loadContract(
  scanDirectory: string,
  options: LoadContractOptions,
): Promise<LoadedContract> {
  return (await loadContractWithScanDirectory(scanDirectory, options)).contract;
}

export async function loadContractWithScanDirectory(
  scanDirectory: string,
  options: LoadContractOptions,
): Promise<{ contract: LoadedContract; scanDirectory: string }> {
  return translateContractError(async () => {
    const helper = await contractHelper();
    const result = (await helper.loadSealedContract(scanDirectory, {
      pluginRoot: options.pluginRoot,
      expectedScanId: options.expectedScanId,
      signal: options.signal,
    })) as { contract: LoadedContract; scanDirectory: string };
    if (options.expectation !== undefined)
      validateExpectation(
        result.contract.manifest,
        result.contract.coverage,
        options.expectation,
        options.workbenchValidated === true,
      );
    return result;
  }, options.signal);
}

export async function requireScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<string> {
  return translateContractError(
    async () =>
      (await contractHelper()).requireSealedScanFile(
        scanDirectory,
        relativePath,
        context,
        signal,
      ),
    signal,
  );
}

export async function readScanFile(
  scanDirectory: string,
  relativePath: string,
  context: string,
  signal?: AbortSignal,
): Promise<Buffer> {
  return translateContractError(
    async () =>
      (await contractHelper()).readSealedScanFile(
        scanDirectory,
        relativePath,
        context,
        signal,
      ),
    signal,
  );
}

export function safeScopePath(value: string): string {
  try {
    return sharedSafeScopePath(value);
  } catch (error) {
    throw new ContractValidationError(
      error instanceof Error ? error.message : String(error),
      { cause: error },
    );
  }
}

function validateExpectation(
  manifest: ScanManifest,
  coverage: CoverageDocument,
  expectation: ScanExpectation,
  workbenchValidated = false,
): void {
  const scan = manifest.scan;
  if (scan.producer.name !== PRODUCER_NAME) {
    throw new ContractValidationError(
      `Manifest producer must be ${PRODUCER_NAME}, got ${scan.producer.name}.`,
    );
  }
  if (scan.producer.version !== expectation.pluginVersion) {
    throw new ContractValidationError(
      "Manifest producer version does not match the installed Codex Security plugin.",
    );
  }

  const expectedMode = expectedCoverageMode(
    expectation.target,
    expectation.mode,
  );
  if (coverage.mode !== expectedMode) {
    throw new ContractValidationError(
      `Coverage mode must be ${expectedMode}, got ${coverage.mode}.`,
    );
  }

  const requested = expectation.target;
  if (!workbenchValidated) {
    const target = scan.target;
    if (requested.kind === "refs" || requested.kind === "working_tree") {
      if (target.kind !== "git_diff") {
        throw new ContractValidationError(
          "Diff scan manifest target must be git_diff.",
        );
      }
      if (target.baseRevision !== requested.base) {
        throw new ContractValidationError(
          "Diff scan base revision does not match the request.",
        );
      }
      if (target.headRevision !== requested.head) {
        throw new ContractValidationError(
          "Diff scan head revision does not match the request.",
        );
      }
    } else if (target.kind === "git_diff") {
      throw new ContractValidationError(
        "Repository scan manifest target must not be git_diff.",
      );
    } else if (
      target.kind !== "directory_snapshot" &&
      expectation.repositoryRevision !== null &&
      target.revision !== expectation.repositoryRevision
    ) {
      throw new ContractValidationError(
        "Scan target revision does not match the repository.",
      );
    }
  }

  if (requested.kind === "paths") {
    const actualPaths = scan.scope.includePaths.map(safeScopePath);
    const actual = new Set(actualPaths);
    if (actualPaths.length === actual.size) {
      const expected = new Set(requested.paths);
      if (actual.size === expected.size && actual.isSubsetOf(expected)) return;
    }
    throw new ContractValidationError(
      "Manifest include paths do not match the requested path target.",
    );
  }
}

function expectedCoverageMode(
  target: NormalizedTarget,
  mode: ScanMode,
): CoverageDocument["mode"] {
  if (target.kind === "paths") return "scoped_path";
  if (target.kind === "refs") return "branch_diff";
  if (target.kind === "working_tree") return "working_tree";
  return mode === "deep" ? "deep_repository" : "repository";
}

export async function sameCheckedFileDevice(
  file: FileHandle,
  checked: { path: string; metadata: Pick<Stats | BigIntStats, "dev" | "ino"> },
  opened: Pick<Stats | BigIntStats, "dev" | "ino">,
  platform: NodeJS.Platform = process.platform,
  openReference: (path: string, flags: number) => Promise<FileHandle> = open,
): Promise<boolean> {
  if (opened.ino !== checked.metadata.ino) return false;
  if (opened.dev === checked.metadata.dev) return true;
  if (platform !== "win32") return false;

  const [openedIdentity, checkedIdentity] = await Promise.all([
    file.stat({ bigint: true }),
    lstat(checked.path, { bigint: true }),
  ]);
  if (
    !openedIdentity.isFile() ||
    !checkedIdentity.isFile() ||
    openedIdentity.ino !== checkedIdentity.ino
  ) {
    return false;
  }

  const reference = await openReference(
    checked.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const referenceIdentity = await reference.stat({ bigint: true });
    return (
      referenceIdentity.isFile() &&
      openedIdentity.dev === referenceIdentity.dev &&
      openedIdentity.ino === referenceIdentity.ino
    );
  } finally {
    await reference.close();
  }
}
