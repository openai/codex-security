import { formatScanCost, formatUsd } from "./cost-model.js";
import type { ScaMatch, ScaResult } from "./sca-types.js";

function severity(match: ScaMatch): number {
  const value = match.severity?.toUpperCase();
  if (value === undefined) return -1;
  const labels: Record<string, number> = {
    CRITICAL: 9,
    HIGH: 7,
    MODERATE: 4,
    MEDIUM: 4,
    LOW: 0,
  };
  return labels[value] ?? (Number.isFinite(Number(value)) ? Number(value) : -1);
}

/** Preserve the first occurrence when reading a saved result, as Array.find does. */
function firstBy<T>(
  items: readonly T[],
  key: (item: T) => string,
): Map<string, T> {
  const index = new Map<string, T>();
  for (const item of items) {
    const id = key(item);
    if (!index.has(id)) index.set(id, item);
  }
  return index;
}

/** Source severity is a scheduling hint, not an exploitability verdict. */
export function prioritizedDependencyMatches(
  result: ScaResult,
  components = firstBy(result.components, (component) => component.id),
): ScaMatch[] {
  const devOnly = (match: ScaMatch) => {
    const groups = components.get(match.componentId)?.dependencyGroups ?? [];
    return groups.length > 0 && groups.every((group) => group === "dev")
      ? 1
      : 0;
  };
  return [...result.matches].sort(
    (a, b) =>
      severity(b) - severity(a) ||
      devOnly(a) - devOnly(b) ||
      a.id.localeCompare(b.id),
  );
}

export function dependencyAssessmentCounts(result: ScaResult) {
  const counts = {
    confirmed: 0,
    notActionable: 0,
    inconclusive: 0,
    failed: 0,
    unfinished: 0,
  };
  const assessments = firstBy(result.assessments, (item) => item.matchId);
  for (const match of result.matches) {
    const assessment = assessments.get(match.id);
    if (assessment?.status === "completed") {
      if (assessment.verdict === "confirmed") counts.confirmed++;
      else if (assessment.verdict === "not_actionable") counts.notActionable++;
      else counts.inconclusive++;
    } else if (assessment?.status === "failed") counts.failed++;
    else counts.unfinished++;
  }
  return counts;
}

export function dependencyAssessmentSummary(result: ScaResult): string {
  const counts = dependencyAssessmentCounts(result);
  return `${counts.confirmed} confirmed, ${counts.notActionable} not actionable, ${counts.inconclusive} inconclusive, ${counts.failed} failed, ${counts.unfinished} unfinished`;
}

export function dependencyInventorySummary(
  result: ScaResult,
  format: (value: string) => string = (value) => value,
): string[] {
  const components = firstBy(result.components, (component) => component.id);
  const matches = prioritizedDependencyMatches(result, components);
  const byComponent = Map.groupBy(matches, (match) => match.componentId);
  const contexts = firstBy(
    result.packageContexts ?? [],
    (context) => context.componentId,
  );
  const lines = [
    `Matching: ${result.coverage.inputs.filter((input) => input.status === "scanned").length} dependency files checked; ${matches.length} advisory matches across ${byComponent.size} package occurrences.`,
  ];
  for (const [id, selected] of byComponent) {
    const component = components.get(id)!;
    const context = contexts.get(id);
    lines.push(
      `${format(component.name)}@${format(component.version ?? "unknown")} — ${format(component.sourcePath)}${context?.projectName ? ` (project: ${format(context.projectName)}${context.private ? ", private" : ""})` : ""}`,
    );
    if (context?.dependencyChain.length)
      lines.push(
        `  Local chain: ${context.dependencyChain.map((entry) => `${format(entry.name)}@${format(entry.version)}`).join(" → ")}`,
      );
    for (const match of selected)
      lines.push(
        `  ${match.advisoryIds.map(format).join(", ")} · severity ${format(match.severity ?? "unknown")} · candidate fixes: ${match.fixedVersions.map(format).join(", ") || "none supplied"}`,
      );
  }
  return lines;
}

export function dependencyCostSummary(result: ScaResult): string {
  if (result.model.costPending)
    return "unavailable (assessment usage not fully checkpointed)";
  if (result.model.cost) return formatScanCost(result.model.cost);
  return result.model.costUsd === null
    ? "unavailable"
    : `${formatUsd(result.model.costUsd)} (legacy estimate, context unknown)`;
}
