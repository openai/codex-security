import { stat } from "node:fs/promises";
import { InvalidTargetError } from "./errors.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
} from "./external-import-contract.js";
import {
  EXTERNAL_FINDINGS_PROVIDERS,
  type ExternalFindingsReaderOptions,
  readExternalFindings,
} from "./external-findings-read.js";
import {
  distinctSourceRepositories,
  prepareLocalImport,
  type LocalExternalImportDependencies,
  type NormalizedLocalImportOptions,
} from "./external-findings-local.js";
import {
  snapshotImportOptions,
  snapshotSourceRepositories,
} from "./external-findings.js";
import { resolveInputPath } from "./runtime.js";
import { abortable } from "./targets.js";

export interface LocalExternalImportOptions
  extends
    Omit<NormalizedLocalImportOptions, "provider">,
    ExternalFindingsReaderOptions {}

/** Read an installed vendor format and prepare it for the local workbench. */
export async function prepareLocalExternalImport(
  path: string,
  options: LocalExternalImportOptions,
  dependencies: LocalExternalImportDependencies = {},
) {
  dependencies.signal?.throwIfAborted();
  const settings = snapshotImportOptions(options);
  const readerSources = distinctSourceRepositories(
    snapshotSourceRepositories(dependencies.sourceRepositories),
  );
  const requested = resolveInputPath(
    settings.repository,
    process.cwd(),
    dependencies.environment,
  );
  const selected = await abortable(
    () => stat(requested, { bigint: true }).catch(() => null),
    dependencies.signal,
  );
  const parsed = await abortable(
    () => readExternalFindings(path, settings, "local", readerSources),
    dependencies.signal,
  );
  const normalizedOptions = {
    ...settings,
    provider: EXTERNAL_FINDINGS_PROVIDERS[settings.provider],
  };
  let sourceRepositories = parsed.sourceRepositories ?? [];
  if (
    normalizedOptions.provider === "semgrep" &&
    parsed.sourceRepositories &&
    settings.sourceRepositoryUrl
  ) {
    // The Cloud reader allows custom GitHub casing. Local provenance must also
    // agree with the caller's source URL when the checkout has no remote.
    const source = settings.sourceRepositoryUrl;
    const knownGitHub = readerSources.some(
      ({ url, platform }) =>
        platform === "github" &&
        cloudRepositoryUrlKey(url) === cloudRepositoryUrlKey(source),
    );
    const key = knownGitHub ? cloudRepositoryUrlKey : repositoryUrlKey;
    sourceRepositories = distinctSourceRepositories(sourceRepositories);
    for (const reference of sourceRepositories) {
      if (key(reference.url) !== key(source))
        throw new Error(
          "SARIF source repository does not match the declared source repository URL.",
        );
    }
    if (knownGitHub)
      sourceRepositories = [
        { url: source, platform: "github" },
        ...sourceRepositories.map((reference) => ({
          ...reference,
          platform: "github" as const,
        })),
      ];
  }
  const { environment, runWorkbench, signal } = dependencies;
  const prepared = await prepareLocalImport(
    parsed.findings,
    normalizedOptions,
    { environment, runWorkbench, signal },
    readerSources,
    sourceRepositories,
  );
  const destination = await abortable(
    () => stat(prepared.preview.repository, { bigint: true }),
    dependencies.signal,
  );
  if (
    !selected ||
    selected.dev !== destination.dev ||
    selected.ino !== destination.ino
  )
    throw new InvalidTargetError(
      `Repository path changed while reading external findings: ${requested}`,
    );
  return prepared;
}
