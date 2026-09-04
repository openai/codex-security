import type { CoverageDocument } from "./models.js";

export type CoverageSummary = Pick<
  CoverageDocument,
  "mode" | "completeness" | "includePaths" | "excludePaths"
> &
  Partial<Pick<CoverageDocument, "explicitExclusions">>;

export function formatScopePath(path: string): string {
  const normalizationSensitive = path.normalize("NFC") !== path;
  if (
    path.length > 0 &&
    !normalizationSensitive &&
    !/[\s,;'"\\\u0000-\u001f\u007f-\u009f\p{Cf}\p{Default_Ignorable_Code_Point}]/u.test(
      path,
    )
  ) {
    return path;
  }
  return JSON.stringify(path).replace(
    normalizationSensitive
      ? /[^\u0020-\u007e]/gu
      : /[\u007f-\u009f\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\p{Cf}\p{Default_Ignorable_Code_Point}]/gu,
    (character) =>
      character
        .split("")
        .map((unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`)
        .join(""),
  );
}

function scopePathParts(paths: readonly string[], finalSuffix = ""): string[] {
  return paths.map(
    (path, index) =>
      `${formatScopePath(path)}${index < paths.length - 1 ? "," : finalSuffix}`,
  );
}

export function formatCoverageScopeParts(
  coverage: Omit<CoverageSummary, "completeness">,
): string[] {
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

export function formatCoverageScope(
  coverage: Omit<CoverageSummary, "completeness">,
): string {
  return formatCoverageScopeParts(coverage).join(" ");
}
