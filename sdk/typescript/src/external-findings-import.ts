import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import { readExternalFindings } from "./external-findings-read.js";
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
    () => readExternalFindings(path, options),
    dependencies.signal,
  );
  return prepareNormalizedLocalImport(parsed.findings, options, {
    ...dependencies,
    sourceRepositories: [
      ...(dependencies.sourceRepositories ?? []),
      ...(parsed.sourceRepositories ?? []),
    ],
  });
}
