import type { Provider } from "./external-import-models.js";
import {
  type ExternalImportTarget,
  cloudRepositoryUrlKey,
  repositoryUrlKey,
} from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import { requiredText } from "./scanner-import.js";

function repositorySegment(
  encoded: string,
  allowEncodedQueryAndFragment: boolean,
): boolean {
  try {
    const segment = decodeURIComponent(encoded);
    return (
      Boolean(segment) &&
      segment.trim() === segment &&
      !["", ".", ".."].includes(segment.replace(/\.git$/iu, "")) &&
      !/[/\\\p{Cc}]|%[\da-f]{2}/iu.test(segment) &&
      (allowEncodedQueryAndFragment || !/[?#]/u.test(segment))
    );
  } catch {
    return false;
  }
}

export function validScannerRepositoryUrl(
  source: string,
  target: ExternalImportTarget,
  allowEncodedQueryAndFragment = false,
): boolean {
  const url = URL.parse(source);
  const parts = /^https?:\/\/([^/?#\\]+)\/([^?#\\]+)$/iu.exec(source);
  const segments = parts?.[2]?.replace(/\/$/u, "").split("/") ?? [];
  return !(
    !url ||
    !parts ||
    parts[1]!.includes("@") ||
    /[\s\p{Cc}]/u.test(source) ||
    url.username ||
    url.password ||
    segments.length < (target === "local" ? 1 : 2) ||
    !segments.every((segment) =>
      repositorySegment(segment, allowEncodedQueryAndFragment),
    )
  );
}

export function declaredScannerRepositoryUrl(
  value: unknown,
  provider: string,
  target: ExternalImportTarget = "cloud",
  {
    allowEncodedQueryAndFragment = false,
  }: { allowEncodedQueryAndFragment?: boolean } = {},
): string {
  const source = requiredText(value, `${provider} --source-repository-url`);
  if (!validScannerRepositoryUrl(source, target, allowEncodedQueryAndFragment))
    throw new Error(
      `${provider} --source-repository-url requires an HTTP(S) repository path without credentials, query, fragment, or ambiguous path segments.`,
    );
  return source;
}

/** A native application or project version maps to one source repository per report. */
export function repositoryScopeValidator(
  scanner: { provider: Provider; label: string; scope: string },
  retainedRepository: (
    provider: Provider,
    finding: ExternalFinding,
    target: ExternalImportTarget,
  ) => { url: string; scope?: string } | undefined,
) {
  return (
    provider: Provider,
    findings: readonly ExternalFinding[],
    target: ExternalImportTarget,
    sameRepositories: (urls: Iterable<string>) => boolean = (urls) =>
      new Set(
        Array.from(
          urls,
          target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey,
        ),
      ).size <= 1,
  ): Map<string, ExternalSourceRepository> => {
    const repositories = new Map<string, ExternalSourceRepository>();
    const wholeReport =
      provider === "blackduck" && scanner.provider === provider;
    const scopes = new Set<string>();
    const sources = new Set<string>();
    for (const finding of findings) {
      const { source_finding_id: id, evidence } = finding;
      const retained = retainedRepository(provider, finding, target);
      const declared = evidence.details?.repository?.url;
      // A Black Duck BOM binds its entire report. A Veracode application binds its native rows.
      if (wholeReport || retained?.scope) {
        if (declared) sources.add(declared);
        if (retained) sources.add(retained.url);
      }
      if (!retained) continue;
      if (retained.scope) scopes.add(retained.scope);
      if (
        declared &&
        declared !== retained.url &&
        !sameRepositories([declared, retained.url])
      )
        throw new Error(
          "Retained scanner repository does not match the normalized evidence repository.",
        );
      repositories.set(id, { url: retained.url });
    }
    if (
      scopes.size > 1 ||
      ((scopes.size > 0 || (wholeReport && target === "local")) &&
        sources.size > 1 &&
        !sameRepositories(sources))
    )
      throw new Error(
        `${scanner.label} occurrences must belong to the same ${scanner.scope} and source repository.`,
      );
    return repositories;
  };
}
