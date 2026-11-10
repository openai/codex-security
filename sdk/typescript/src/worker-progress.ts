import { isRecord } from "./record.js";
import { parseJson } from "./value.js";
import { z } from "zod";

const WORKER_STATUS_PREFIX = "CODEX_SECURITY_WORKER_STATUS ";
const SCAN_PROGRESS_PREFIX = "CODEX_SECURITY_SCAN_PROGRESS ";
const workerPhaseSchema = z.enum([
  "ranking",
  "file_review",
  "validation",
  "attack_path",
]);

export type ScanWorkerPhase = z.infer<typeof workerPhaseSchema>;

export const scanPhaseSchema = z.enum([
  "preflight",
  "threat_model",
  "discovery",
  "validation",
  "attack_path",
  "reporting",
]);
export type ScanPhase = z.infer<typeof scanPhaseSchema>;

const count = z.number().int().nonnegative();
const scanProgressSchema = z
  .object({ phase: scanPhaseSchema, filesCompleted: count, filesTotal: count })
  .refine(({ filesCompleted, filesTotal }) => filesCompleted <= filesTotal);
const dispatchSchema = z
  .object({ phase: workerPhaseSchema, planned: count, started: count })
  .refine(({ started, planned }) => started <= planned);

export interface ScanProgress extends z.infer<typeof scanProgressSchema> {
  /** Saved reviews or coverage surfaces; these are not necessarily files. */
  reviewItems?: { completed: number; total: number };
}

export function scanProgressCount(progress: ScanProgress): {
  label: "files" | "reviews";
  completed: number;
  total: number;
} {
  if (progress.reviewItems !== undefined && progress.reviewItems.total > 0) {
    return { label: "reviews", ...progress.reviewItems };
  }
  return {
    label: "files",
    completed: progress.filesCompleted,
    total: progress.filesTotal,
  };
}

export function scanPhaseLabel(value: ScanWorkerPhase | ScanPhase): string {
  return {
    preflight: "preflight",
    threat_model: "building threat model",
    discovery: "reviewing files",
    ranking: "ranking scan targets",
    file_review: "reviewing files",
    validation: "validating findings",
    attack_path: "analyzing attack paths",
    reporting: "writing report",
  }[value];
}

/** Dispatch counts depend on model-emitted markers. */
export type ScanWorkerStatus = {
  kind: "dispatch";
} & z.infer<typeof dispatchSchema>;

export function workerStatusFromEvent(
  event: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (event["type"] !== "item.completed" || !isRecord(event["item"])) {
    return null;
  }
  const item = event["item"];
  if (item["type"] === "agent_message") return dispatchStatus(item);
  return null;
}

export function scanProgressUpdatesFromEvent(
  event: Readonly<Record<string, unknown>>,
): ScanProgress[] {
  if (event["type"] !== "item.completed" || !isRecord(event["item"])) {
    return [];
  }
  const item = event["item"];
  const output =
    item["type"] === "agent_message"
      ? item["text"]
      : item["type"] === "command_execution"
        ? item["aggregated_output"]
        : null;
  return typeof output === "string" ? scanProgressUpdatesFromText(output) : [];
}

export function scanProgressUpdatesFromText(output: string): ScanProgress[] {
  const updates: ScanProgress[] = [];
  for (const line of linesOutsideFences(output)) {
    if (!line.startsWith(SCAN_PROGRESS_PREFIX)) continue;
    const progress = scanProgressFromMarker(line);
    if (progress !== null) updates.push(progress);
  }
  return updates;
}

/** Return lines outside Markdown fences so quoted markers are not read as live. */
function linesOutsideFences(text: string): string[] {
  const lines: string[] = [];
  let fence: { marker: string; length: number } | null = null;
  for (const line of text.split(/\r?\n/u)) {
    const delimiter = /^\s*(`{3,}|~{3,})(.*)$/u.exec(line);
    if (delimiter !== null) {
      const run = delimiter[1]!;
      if (fence === null) {
        fence = { marker: run[0]!, length: run.length };
      } else if (
        run[0] === fence.marker &&
        run.length >= fence.length &&
        delimiter[2]!.trim() === ""
      ) {
        fence = null;
      }
      continue;
    }
    if (fence === null) lines.push(line);
  }
  return lines;
}

function scanProgressFromMarker(marker: string): ScanProgress | null {
  const parsed = scanProgressSchema.safeParse(
    parseJson(() => marker.slice(SCAN_PROGRESS_PREFIX.length)),
  );
  return parsed.success ? parsed.data : null;
}

function dispatchStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (typeof item["text"] !== "string") return null;
  const markers = linesOutsideFences(item["text"]).filter((line) =>
    line.startsWith(WORKER_STATUS_PREFIX),
  );
  const marker = markers[0];
  if (markers.length !== 1 || marker === undefined) return null;
  const parsed = dispatchSchema.safeParse(
    parseJson(() => marker.slice(WORKER_STATUS_PREFIX.length)),
  );
  return parsed.success ? { kind: "dispatch", ...parsed.data } : null;
}

/** Runtime dispatch counts derived from live spawn_agent tool calls. */
export type ScanWorkerRuntimeEvent =
  | ({ kind: "dispatch" } & z.infer<typeof dispatchSchema>)
  | {
      kind: "failed";
      phase: ScanWorkerPhase;
      planned: number;
      started: number;
      reason: string;
    };

const DEFAULT_SPAWN_PHASE = "file_review" satisfies ScanWorkerPhase;

/** Accumulate runtime worker starts from live Codex item events. */
export function createWorkerDispatchMonitor(): {
  observe(
    event: Readonly<Record<string, unknown>>,
  ): ScanWorkerRuntimeEvent | null;
} {
  const startedIds = new Set<string>();
  const failedIds = new Set<string>();
  let started = 0;

  const snapshot = (kind: "dispatch" | "failed", reason?: string) => {
    const event = {
      kind,
      phase: DEFAULT_SPAWN_PHASE,
      planned: started,
      started,
      ...(kind === "failed"
        ? { reason: reason ?? "Delegated worker failed to start." }
        : {}),
    };
    return event as ScanWorkerRuntimeEvent;
  };

  return {
    observe(
      event: Readonly<Record<string, unknown>>,
    ): ScanWorkerRuntimeEvent | null {
      const spawn = spawnAgentCallFromEvent(event);
      if (spawn === null) return null;
      if (spawn.status === "started") {
        if (startedIds.has(spawn.id)) return null;
        startedIds.add(spawn.id);
        started += 1;
        return snapshot("dispatch");
      }
      if (failedIds.has(spawn.id)) return null;
      failedIds.add(spawn.id);
      if (!startedIds.has(spawn.id)) {
        startedIds.add(spawn.id);
        started += 1;
      }
      return snapshot("failed", spawn.reason);
    },
  };
}

function spawnAgentCallFromEvent(
  event: Readonly<Record<string, unknown>>,
): { id: string; status: "started" | "failed"; reason?: string } | null {
  if (
    (event["type"] !== "item.started" && event["type"] !== "item.completed") ||
    !isRecord(event["item"])
  ) {
    return null;
  }
  const item = event["item"];
  if (
    typeof item["id"] !== "string" ||
    !isSpawnAgentTool(toolNameFromItem(item))
  ) {
    return null;
  }
  if (event["type"] === "item.started") {
    return { id: item["id"], status: "started" };
  }
  if (item["status"] !== "failed") return null;
  return { id: item["id"], status: "failed", reason: spawnFailureReason(item) };
}

function toolNameFromItem(
  item: Readonly<Record<string, unknown>>,
): string | null {
  for (const value of [item["tool"], item["name"], item["function"]]) {
    if (typeof value === "string") return value;
    if (isRecord(value) && typeof value["name"] === "string")
      return value["name"];
  }
  return null;
}

function isSpawnAgentTool(name: string | null): name is string {
  if (name === null || name === "") return false;
  const separator = name.lastIndexOf("__");
  const local = separator === -1 ? name : name.slice(separator + 2);
  return local === "spawn_agent";
}

function spawnFailureReason(item: Readonly<Record<string, unknown>>): string {
  const error = item["error"];
  if (typeof error === "string" && error.trim() !== "") return error;
  if (isRecord(error) && typeof error["message"] === "string") {
    const message = error["message"].trim();
    if (message !== "") return message;
  }
  return "Delegated worker failed to start.";
}
