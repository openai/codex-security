import { isRecord } from "./record.js";
import { isSafeNonNegativeInteger, parseJson } from "./value.js";
import { z } from "zod";

const WORKER_STATUS_PREFIX = "CODEX_SECURITY_WORKER_STATUS ";
const SCAN_PROGRESS_PREFIX = "CODEX_SECURITY_SCAN_PROGRESS ";
const PREFLIGHT_COMMAND = /(?:^|[\\/])config_preflight\.py(?=$|["'\s])/u;
const workerPhaseSchema = z.enum([
  "ranking",
  "file_review",
  "validation",
  "attack_path",
]);

export type ScanWorkerPhase = z.infer<typeof workerPhaseSchema>;

const scanPhaseSchema = z.enum([
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

export interface ScanProgress extends z.infer<typeof scanProgressSchema> {}

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

/** Preflight is tool-derived; dispatch counts depend on model-emitted markers. */
export type ScanWorkerStatus =
  | {
      kind: "preflight";
      delegation: "available" | "unavailable" | "unknown";
      configuredSlots: number | null;
    }
  | ({ kind: "dispatch" } & z.infer<typeof dispatchSchema>);

export function workerStatusFromEvent(
  event: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (event["type"] !== "item.completed" || !isRecord(event["item"])) {
    return null;
  }
  const item = event["item"];
  if (item["type"] === "command_execution") return preflightStatus(item);
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

function preflightStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (
    typeof item["command"] !== "string" ||
    !PREFLIGHT_COMMAND.test(item["command"]) ||
    typeof item["aggregated_output"] !== "string"
  ) {
    return null;
  }
  const payload = parseJson(() => item["aggregated_output"] as string);
  if (
    !isRecord(payload) ||
    (payload["profile"] !== "security_scan" &&
      payload["profile"] !== "security_diff_scan") ||
    !Array.isArray(payload["results"])
  ) {
    return null;
  }
  const results = payload["results"];
  const delegated = results.filter(
    (result): result is Record<string, unknown> =>
      isRecord(result) && result["capability"] === "delegated_workers",
  );
  const delegatedResult = delegated[0];
  if (delegated.length !== 1 || delegatedResult === undefined) return null;
  const delegation =
    delegatedResult["status"] === "pass"
      ? "available"
      : delegatedResult["status"] === "fail"
        ? "unavailable"
        : delegatedResult["status"] === "unknown"
          ? "unknown"
          : null;
  if (delegation === null) return null;
  const capacity = results.filter(
    (result): result is Record<string, unknown> =>
      isRecord(result) &&
      typeof result["capability"] === "string" &&
      result["capability"].startsWith("usable_worker_slots_"),
  );
  if (capacity.length > 1) return null;
  const capacityResult = capacity[0];
  const configuredSlots =
    capacityResult !== undefined &&
    isSafeNonNegativeInteger(capacityResult["actual"])
      ? capacityResult["actual"]
      : null;
  return { kind: "preflight", delegation, configuredSlots };
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
