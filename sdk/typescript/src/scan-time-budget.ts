import { readFile } from "node:fs/promises";
import { join } from "node:path";

export interface ScanTimeBudget {
  budgetMinutes: number;
  startedAt: string;
  deadlineAt: string;
}

export function readScanTimeBudgetPolicy(pluginRoot: string): Promise<string> {
  return readFile(
    join(pluginRoot, "references", "investigation-time-budget.md"),
    "utf8",
  );
}

export function scanTimeBudget(
  maxTimeMinutes: number,
  startedMs = Date.now(),
): ScanTimeBudget {
  return {
    budgetMinutes: maxTimeMinutes,
    startedAt: new Date(startedMs).toISOString(),
    deadlineAt: new Date(startedMs + maxTimeMinutes * 60_000).toISOString(),
  };
}

export function renderScanTimeBudgetPolicy(
  template: string,
  timing: ScanTimeBudget,
): string {
  return template.replace(
    /\{\{(budgetMinutes|startedAt|deadlineAt)\}\}/gu,
    (_, key: keyof ScanTimeBudget) => String(timing[key]),
  );
}
