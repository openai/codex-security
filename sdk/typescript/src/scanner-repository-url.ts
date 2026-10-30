import type { ExternalImportTarget } from "./external-import-contract.js";
import { requiredText } from "./scanner-import.js";

function repositorySegment(encoded: string): boolean {
  try {
    const segment = decodeURIComponent(encoded);
    return (
      Boolean(segment) &&
      segment.trim() === segment &&
      !["", ".", ".."].includes(segment.replace(/\.git$/iu, "")) &&
      !/[/\\?#\p{Cc}]|%[\da-f]{2}/iu.test(segment)
    );
  } catch {
    return false;
  }
}

export function declaredScannerRepositoryUrl(
  value: unknown,
  provider: string,
  target: ExternalImportTarget = "cloud",
): string {
  const source = requiredText(value, `${provider} --source-repository-url`);
  const url = URL.parse(source);
  const parts = /^https?:\/\/([^/?#\\]+)\/([^?#\\]+)$/iu.exec(source);
  const segments = parts?.[2]?.replace(/\/$/u, "").split("/") ?? [];
  if (
    !url ||
    !parts ||
    parts[1]!.includes("@") ||
    /[\s\p{Cc}]/u.test(source) ||
    url.username ||
    url.password ||
    segments.length < (target === "local" ? 1 : 2) ||
    !segments.every(repositorySegment)
  )
    throw new Error(
      `${provider} --source-repository-url requires an HTTP(S) repository path without credentials, query, fragment, or ambiguous path segments.`,
    );
  return source;
}
