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
  prepareNormalizedLocalImport,
  type LocalExternalImportDependencies,
} from "./external-findings-local.js";
import { abortable } from "./targets.js";

/** Read an installed vendor format and prepare it for the local workbench. */
export async function prepareLocalExternalImport(
  path: string,
  options: ExternalPublicationOptions,
  dependencies: LocalExternalImportDependencies = {},
) {
  dependencies.signal?.throwIfAborted();
  const parsed = await abortable(
    () => readExternalFindings(path, options, "local"),
    dependencies.signal,
  );
  const normalizedOptions = {
    ...options,
    provider: EXTERNAL_FINDINGS_PROVIDERS[options.provider],
  };
  let sourceRepositories = parsed.sourceRepositories ?? [];
  if (normalizedOptions.provider === "semgrep") {
    // The Cloud reader allows custom GitHub casing. Local provenance must also
    // agree with the caller's source URL when the checkout has no remote.
    const source = options.sourceRepositoryUrl!;
    const knownGitHub = dependencies.sourceRepositories?.some(
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
      sourceRepositories = [
        { url: source, platform: "github" },
        ...sourceRepositories.map((reference) => ({
          ...reference,
          platform: "github" as const,
        })),
      ];
  }
  return prepareNormalizedLocalImport(parsed.findings, normalizedOptions, {
    ...dependencies,
    sourceRepositories: [
      ...(dependencies.sourceRepositories ?? []),
      ...sourceRepositories,
    ],
  });
}
