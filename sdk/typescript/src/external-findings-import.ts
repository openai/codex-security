import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
} from "./external-import-contract.js";
import {
  EXTERNAL_FINDINGS_PROVIDERS,
  readExternalFindings,
} from "./external-findings-read.js";
import {
  prepareLocalImport,
  type LocalExternalImportDependencies,
} from "./external-findings-local.js";
import {
  snapshotImportOptions,
  snapshotSourceRepositories,
} from "./external-findings.js";
import { abortable } from "./targets.js";
import { requireExternalImports } from "./external-imports-feature.js";

/** Read an installed vendor format and prepare it for the local workbench. */
export async function prepareLocalExternalImport(
  path: string,
  options: ExternalPublicationOptions,
  dependencies: LocalExternalImportDependencies = {},
) {
  const { signal } = dependencies;
  signal?.throwIfAborted();
  requireExternalImports(dependencies.environment);
  const runWorkbench = dependencies.runWorkbench;
  const settings = snapshotImportOptions(options);
  const readerSources = snapshotSourceRepositories(
    dependencies.sourceRepositories,
  );
  const parsed = await abortable(
    () => readExternalFindings(path, settings, "local", readerSources),
    signal,
  );
  const normalizedOptions = {
    ...settings,
    provider: EXTERNAL_FINDINGS_PROVIDERS[settings.provider],
  };
  let sourceRepositories = parsed.sourceRepositories ?? [];
  if (
    normalizedOptions.provider === "semgrep" &&
    !parsed.findings.sourceRepositoryUrl
  ) {
    // The Cloud reader allows custom GitHub casing. Local provenance must also
    // agree with the caller's source URL when the checkout has no remote.
    const source = settings.sourceRepositoryUrl!;
    sourceRepositories = [{ url: source }, ...sourceRepositories];
    const knownGitHub = readerSources.some(
      ({ url, platform }) =>
        platform === "github" &&
        cloudRepositoryUrlKey(url) === cloudRepositoryUrlKey(source),
    );
    const key = knownGitHub ? cloudRepositoryUrlKey : repositoryUrlKey;
    for (const reference of sourceRepositories) {
      if (key(reference.url) !== key(source))
        throw new Error(
          "SARIF source repository does not match the declared source repository URL.",
        );
    }
    if (knownGitHub)
      sourceRepositories = sourceRepositories.map(({ url }) => ({
        url,
        platform: "github",
      }));
  }
  return prepareLocalImport(
    parsed.findings,
    normalizedOptions,
    { environment: dependencies.environment, signal, runWorkbench },
    readerSources,
    sourceRepositories,
  );
}
