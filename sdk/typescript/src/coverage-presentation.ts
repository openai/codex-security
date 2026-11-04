import type { CoverageDocument } from "./models.js";

export type CoverageSummary = Pick<
  CoverageDocument,
  "mode" | "includePaths" | "excludePaths"
> &
  Partial<Pick<CoverageDocument, "explicitExclusions">>;

export function formatScopePath(path: string): string {
  if (path.length > 0 && !/[\s,;'"\\\u0000-\u001f\u007f-\u009f]/u.test(path)) {
    return path;
  }
  return JSON.stringify(path).replace(
    /[\u007f-\u009f]/gu,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function scopePathParts(paths: readonly string[], finalSuffix = ""): string[] {
  return paths.map(
    (path, index) =>
      `${formatScopePath(path)}${index < paths.length - 1 ? "," : finalSuffix}`,
  );
}

export function formatCoverageScopeParts(coverage: CoverageSummary): string[] {
  const mode =
    coverage.mode === "scoped_path"
      ? "scoped paths"
      : coverage.mode.replaceAll("_", " ");
  const exclusions = [
    ...new Set([
      ...coverage.excludePaths,
      ...(coverage.explicitExclusions ?? []).map(({ pattern }) => pattern),
    ]),
  ];
  const suffix = exclusions.length > 0 ? ";" : "";
  return [
    `${mode}:`,
    ...(coverage.includePaths.length > 0
      ? scopePathParts(coverage.includePaths, suffix)
      : [`(no included paths)${suffix}`]),
    ...(exclusions.length > 0
      ? ["excluding", ...scopePathParts(exclusions)]
      : []),
  ];
}

export function formatCoverageScope(coverage: CoverageSummary): string {
  return formatCoverageScopeParts(coverage).join(" ");
}
