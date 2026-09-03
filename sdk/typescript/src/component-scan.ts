import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import {
  CodexSecurity,
  scanAuthentication,
  selectedScanEnvironment,
  type ScanOptions,
} from "./api.js";
import {
  normalizeComponentPlan,
  planComponents,
  type ComponentPlan,
  type ComponentPlanningOptions,
} from "./component-plan.js";
import {
  mergedCodexConfig,
  scanModelProvider,
  type CodexSecurityConfig,
} from "./config.js";
import type { ScanCost, ScanSessionEvent } from "./cost.js";
import { safeErrorMessage } from "./errors.js";
import type { CoverageCompleteness, Finding } from "./models.js";
import type { ScanResult } from "./result.js";
import type { ScanActivity } from "./scan-activity.js";
import type { ScanProgress, ScanWorkerStatus } from "./worker-progress.js";
import {
  matchScanFindings,
  type ScanComparisonResult,
} from "./scan-comparison.js";
import { prepareOutputDir, requireOutputOutsideRepository } from "./runtime.js";
import { enclosingGitWorktreeRoot, normalizeRepository } from "./targets.js";

export interface ComponentScanOptions {
  repository: string;
  outputDir: string;
  components?: ComponentPlan["components"];
  auto?: boolean;
  planOnly?: boolean;
  workers?: number;
  config?: CodexSecurityConfig;
  scanOptions?: Pick<
    ScanOptions,
    | "auth"
    | "knowledgeBasePaths"
    | "scanPrompt"
    | "postScanPrompt"
    | "maxCostUsd"
  >;
  signal?: AbortSignal;
  createSecurity?: (
    config: CodexSecurityConfig,
  ) => Pick<CodexSecurity, "run" | "close">;
  planComponents?: (
    repository: string,
    options: ComponentPlanningOptions,
  ) => Promise<ComponentPlan>;
  environment?: NodeJS.ProcessEnv;
  /** @internal */
  matchFindings?: typeof matchScanFindings;
  onPlan?: (components: ComponentReceipt[]) => void;
  onScanEvent?: (event: ComponentScanEvent) => void;
  onComplete?: (result: ComponentScanResult) => void;
  onDeduplicationStarted?: () => void;
  onProgress?: (component: ComponentReceipt) => void;
}

export interface ComponentReceipt {
  id: string;
  name: string;
  paths: string[];
  status: "pending" | "started" | "completed" | "incomplete" | "failed";
  outputDir: string;
  scanId?: string;
  coverage?: CoverageCompleteness;
  findingCount?: number;
  cost?: Readonly<ScanCost>;
  error?: string;
}

type ComponentScanUpdate =
  | { type: "progress"; value: ScanProgress }
  | { type: "activity"; value: ScanActivity }
  | { type: "session"; value: ScanSessionEvent }
  | { type: "cost"; value: Readonly<ScanCost> }
  | { type: "workers"; value: ScanWorkerStatus }
  | { type: "warning"; value: string };

export type ComponentScanEvent = ComponentScanUpdate & { componentId: string };

interface FindingSource {
  componentId: string;
  scanId: string;
  occurrenceId: string;
  scanDir: string;
}

interface CombinedFinding {
  finding: Finding;
  sources: FindingSource[];
}

export interface ComponentDeduplicationSummary {
  status: "completed" | "incomplete";
  confirmedGroups: number;
  uncertainPairs: number;
  error?: string;
}

export interface ComponentScanResult {
  total: number;
  completed: number;
  incomplete: number;
  failed: number;
  planPath: string;
  summaryPath?: string;
  findingsPath?: string;
  reportPath?: string;
  retryPlanPath?: string;
  findingCount?: number;
  sourceFindingCount?: number;
  deduplication?: ComponentDeduplicationSummary;
}

export async function runComponentScans(
  options: ComponentScanOptions,
): Promise<ComponentScanResult> {
  const workers = options.workers ?? 4;
  if (!Number.isSafeInteger(workers) || workers < 1)
    throw new Error("Component workers must be a positive integer.");
  if (Boolean(options.auto) === (options.components !== undefined))
    throw new Error("Choose components or automatic planning, not both.");
  const auth = options.scanOptions?.auth;
  let environment = options.environment;
  if (auth !== undefined && auth !== "auto") {
    const source = environment ?? process.env;
    const provider = scanModelProvider(
      await mergedCodexConfig(options.config ?? {}),
    );
    scanAuthentication(source, auth, provider);
    environment = selectedScanEnvironment(source, auth, provider);
  }
  const repository = await normalizeRepository(
    options.repository,
    options.signal,
  );
  const protectedRoot =
    (await enclosingGitWorktreeRoot(repository, options.signal)) ?? repository;
  const output = await prepareOutputDir(
    options.outputDir,
    basename(repository),
    undefined,
    (path) => requireOutputOutsideRepository(protectedRoot, path),
  );
  const plan = await normalizeComponentPlan(
    repository,
    options.auto
      ? await (options.planComponents ?? planComponents)(repository, {
          auth,
          config: options.config,
          environment,
          signal: options.signal,
        })
      : { components: options.components },
    options.signal,
  );
  const planPath = join(output, "components.json");
  await writeJson(planPath, plan);
  const base = {
    total: plan.components.length,
    completed: 0,
    incomplete: 0,
    failed: 0,
    planPath,
  };
  if (options.planOnly) return base;

  const receipts: ComponentReceipt[] = plan.components.map(
    (component, index) => ({
      ...component,
      id: `component-${index + 1}`,
      status: "pending",
      outputDir: join(output, `component-${index + 1}`),
    }),
  );
  notify(() =>
    options.onPlan?.(
      receipts.map((receipt) => ({ ...receipt, paths: [...receipt.paths] })),
    ),
  );
  const results = new Map<string, ScanResult>();
  let next = 0;
  const settled = await Promise.allSettled(
    Array.from({ length: Math.min(workers, receipts.length) }, async () => {
      const security = (
        options.createSecurity ?? ((config) => new CodexSecurity(config))
      )(options.config ?? {});
      try {
        while (!options.signal?.aborted) {
          const receipt = receipts[next++];
          if (receipt === undefined) return;
          receipt.status = "started";
          notify(() =>
            options.onProgress?.({ ...receipt, paths: [...receipt.paths] }),
          );
          const emit = (event: ComponentScanUpdate): void =>
            notify(() =>
              options.onScanEvent?.({ ...event, componentId: receipt.id }),
            );
          const observers: ScanOptions =
            options.onScanEvent === undefined
              ? {}
              : {
                  onProgress: (value) => emit({ type: "progress", value }),
                  onActivity: (value) => emit({ type: "activity", value }),
                  onSessionEvent: (value) => emit({ type: "session", value }),
                  onCost: (value) => emit({ type: "cost", value }),
                  onWorkerStatus: (value) => emit({ type: "workers", value }),
                  onWarning: (value) => emit({ type: "warning", value }),
                };
          try {
            const result = await security.run(repository, {
              ...options.scanOptions,
              ...observers,
              mode: "standard",
              target: receipt.paths,
              outputDir: receipt.outputDir,
              signal: options.signal,
            });
            results.set(receipt.id, result);
            receipt.scanId = result.manifest.scan.id;
            receipt.coverage = result.coverage.completeness;
            receipt.findingCount = result.findings.findings.length;
            if (result.cost !== null) receipt.cost = result.cost;
            receipt.status =
              receipt.coverage === "complete" ? "completed" : "incomplete";
          } catch (error) {
            receipt.status = "failed";
            receipt.error = safeErrorMessage(error);
          }
          notify(() =>
            options.onProgress?.({ ...receipt, paths: [...receipt.paths] }),
          );
        }
      } finally {
        await security.close();
      }
    }),
  );
  const failed = settled.find((result) => result.status === "rejected");
  for (const receipt of receipts) {
    if (receipt.status === "pending" || receipt.status === "started") {
      receipt.status = "failed";
      receipt.error = options.signal?.aborted
        ? "Scan canceled."
        : "Component scan did not finish.";
      notify(() =>
        options.onProgress?.({ ...receipt, paths: [...receipt.paths] }),
      );
    }
  }
  const { findings, matches, uncertain, related, error } =
    await deduplicateFindings(receipts, results, { ...options, environment });
  const deduplication: ComponentDeduplicationSummary = {
    status: error === undefined ? "completed" : "incomplete",
    confirmedGroups: matches.length,
    uncertainPairs: uncertain.length,
    ...(error === undefined ? {} : { error }),
  };
  const retryComponents = receipts
    .filter(({ status }) => status === "failed" || status === "incomplete")
    .map(({ name, paths }) => ({ name, paths }));
  const retryPlanPath =
    retryComponents.length === 0
      ? undefined
      : join(output, "retry-components.json");
  if (retryPlanPath !== undefined)
    await writeJson(retryPlanPath, { components: retryComponents });
  const summary = {
    ...base,
    completed: receipts.filter(({ status }) => status === "completed").length,
    incomplete: receipts.filter(({ status }) => status === "incomplete").length,
    failed: receipts.filter(({ status }) => status === "failed").length,
    summaryPath: join(output, "summary.json"),
    findingsPath: join(output, "findings.json"),
    reportPath: join(output, "report.md"),
    ...(retryPlanPath === undefined ? {} : { retryPlanPath }),
    findingCount: findings.length,
    sourceFindingCount: findings.reduce(
      (total, finding) => total + finding.sources.length,
      0,
    ),
    deduplication,
  };
  await writeJson(summary.findingsPath, {
    documentType: "codex-security.component-findings",
    schemaVersion: "1.0",
    findings,
    deduplication: { ...deduplication, matches, uncertain, related },
  });
  await writeJson(summary.summaryPath, {
    ...summary,
    repository,
    components: receipts,
    completeness:
      summary.failed ||
      summary.incomplete ||
      deduplication.status === "incomplete"
        ? "partial"
        : "complete",
  });
  await writeFile(
    summary.reportPath,
    renderReport(summary, receipts, findings),
    { flag: "wx", mode: 0o600 },
  );
  notify(() => options.onComplete?.(summary));
  options.signal?.throwIfAborted();
  if (failed?.status === "rejected") throw failed.reason;
  return summary;
}

async function deduplicateFindings(
  receipts: ComponentReceipt[],
  results: Map<string, ScanResult>,
  options: ComponentScanOptions,
): Promise<
  ScanComparisonResult & { findings: CombinedFinding[]; error?: string }
> {
  const scans = receipts.flatMap((receipt) => {
    const findings = results.get(receipt.id)?.findings.findings ?? [];
    return findings.length ? [{ receipt, findings }] : [];
  });
  let findings: CombinedFinding[] = scans.flatMap(({ receipt, findings }) =>
    findings.map((finding) => ({
      finding,
      sources: [
        {
          componentId: receipt.id,
          scanId: receipt.scanId!,
          occurrenceId: finding.occurrenceId,
          scanDir: receipt.outputDir,
        },
      ],
    })),
  );
  const matching: ScanComparisonResult = { matches: [], uncertain: [] };
  const [first, ...remaining] = scans;
  const componentFindings = ({
    receipt,
    findings,
  }: (typeof scans)[number]): Finding[] =>
    findings.map((finding) => ({
      ...finding,
      findingId: `${receipt.id}:${finding.findingId}`,
    }));
  const previous = first === undefined ? [] : componentFindings(first);
  let error: string | undefined;
  try {
    options.signal?.throwIfAborted();
    if (remaining.length) notify(() => options.onDeduplicationStarted?.());
    for (const component of remaining) {
      const current = componentFindings(component);
      const comparison = await (options.matchFindings ?? matchScanFindings)(
        { before: [...previous], after: current },
        {
          allowHistoricalUncertainty: true,
          auth: options.scanOptions?.auth,
          config: options.config ?? {},
          environment: options.environment,
          signal: options.signal,
          workingDirectory: tmpdir(),
        },
      );
      matching.matches.push(...comparison.matches);
      matching.uncertain.push(...comparison.uncertain);
      if (comparison.related !== undefined) {
        matching.related ??= [];
        matching.related.push(...comparison.related);
      }
      for (const match of comparison.matches) {
        findings = mergeFindingGroups(
          findings,
          new Set([...match.beforeOccurrenceIds, ...match.afterOccurrenceIds]),
        );
      }
      previous.push(...current);
    }
  } catch (failure) {
    error = options.signal?.aborted
      ? "Cross-component matching was canceled."
      : safeErrorMessage(failure);
  }
  const remainSeparate = ({
    beforeOccurrenceId,
    afterOccurrenceId,
  }: ScanComparisonResult["uncertain"][number]): boolean =>
    !findings.some(
      ({ sources }) =>
        sources.some(
          ({ occurrenceId }) => occurrenceId === beforeOccurrenceId,
        ) &&
        sources.some(({ occurrenceId }) => occurrenceId === afterOccurrenceId),
    );
  matching.uncertain = matching.uncertain.filter(remainSeparate);
  if (matching.related !== undefined) {
    matching.related = matching.related.filter(remainSeparate);
  }
  return { findings, ...matching, ...(error === undefined ? {} : { error }) };
}

function notify(callback: () => unknown): void {
  try {
    void Promise.resolve(callback()).catch(() => {});
  } catch {}
}

function mergeFindingGroups(
  findings: CombinedFinding[],
  occurrenceIds: Set<string>,
): CombinedFinding[] {
  const selected = findings.filter(({ sources }) =>
    sources.some(({ occurrenceId }) => occurrenceIds.has(occurrenceId)),
  );
  if (selected.length < 2) return findings;
  const merged = {
    finding: selected.map(({ finding }) => finding).reduce(strongerFinding),
    sources: selected.flatMap(({ sources }) => sources),
  };
  return findings.flatMap((group) =>
    group === selected[0] ? [merged] : selected.includes(group) ? [] : [group],
  );
}

function strongerFinding(first: Finding, second: Finding): Finding {
  const levels = ["critical", "high", "medium", "low", "informational"];
  return levels.indexOf(second.severity.level) <
    levels.indexOf(first.severity.level)
    ? second
    : first;
}

function renderReport(
  summary: ComponentScanResult,
  receipts: ComponentReceipt[],
  findings: CombinedFinding[],
): string {
  return [
    "# Component scan report",
    "",
    `${summary.completed} complete, ${summary.incomplete} incomplete, ${summary.failed} failed. ${findings.length} finding groups.`,
    ...(summary.deduplication?.status === "incomplete"
      ? [
          "",
          `Cross-component matching is incomplete: ${summary.deduplication.error}`,
        ]
      : []),
    ...(summary.deduplication?.uncertainPairs
      ? [
          "",
          `${summary.deduplication.uncertainPairs} possible duplicate pairs remain separate. See findings.json.`,
        ]
      : []),
    "",
    "Coverage applies only to the selected components. See each scan for exclusions and deferred work.",
    ...(summary.retryPlanPath === undefined
      ? []
      : [
          "",
          "[Retry plan for failed or incomplete components](./retry-components.json)",
        ]),
    "",
    "## Components",
    "",
    ...receipts.map(
      (receipt) =>
        `- ${JSON.stringify(receipt.name)}: ${receipt.status}. [Scan files](./${receipt.id}/)${receipt.error ? ` — ${receipt.error}` : ""}`,
    ),
    "",
    "## Findings",
    "",
    ...findings.map(
      ({ finding, sources }) =>
        `- ${finding.severity.level}: ${finding.title} (${sources.map(({ componentId }) => `[${componentId}](./${componentId}/report.md)`).join(", ")})`,
    ),
    "",
  ].join("\n");
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}
