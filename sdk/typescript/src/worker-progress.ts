const WORKER_STATUS_PREFIX = "CODEX_SECURITY_WORKER_STATUS ";
const SCAN_PROGRESS_PREFIX = "CODEX_SECURITY_SCAN_PROGRESS ";
const PREFLIGHT_COMMAND = /(?:^|[\\/])config_preflight\.py(?=$|["'\s])/u;
const WORKER_PHASES = new Set([
  "ranking",
  "file_review",
  "validation",
  "attack_path",
]);

export type ScanWorkerPhase =
  | "ranking"
  | "file_review"
  | "validation"
  | "attack_path";

export type ScanPhase =
  | "preflight"
  | "threat_model"
  | "discovery"
  | "validation"
  | "attack_path"
  | "reporting";

export interface ScanProgress {
  phase: ScanPhase;
  filesCompleted: number;
  filesTotal: number;
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

export type ScanWorkerStatus =
  | {
      kind: "preflight";
      delegation: "available" | "unavailable" | "unknown";
      configuredSlots: number | null;
    }
  | {
      kind: "dispatch";
      phase: ScanWorkerPhase;
      planned: number;
      started: number;
    };

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
  if (typeof output !== "string") return [];
  const updates: ScanProgress[] = [];
  let codeFence = false;
  for (const line of output.split(/\r?\n/u)) {
    if (/^\s*```/u.test(line)) {
      codeFence = !codeFence;
      continue;
    }
    if (codeFence || !line.startsWith(SCAN_PROGRESS_PREFIX)) continue;
    const progress = scanProgressFromMarker(line);
    if (progress !== null) updates.push(progress);
  }
  return updates;
}

function scanProgressFromMarker(marker: string): ScanProgress | null {
  let payload: unknown;
  try {
    payload = JSON.parse(marker.slice(SCAN_PROGRESS_PREFIX.length));
  } catch {
    return null;
  }
  if (
    !isRecord(payload) ||
    !isScanPhase(payload["phase"]) ||
    !isProgressCount(payload["filesCompleted"]) ||
    !isProgressCount(payload["filesTotal"]) ||
    payload["filesCompleted"] > payload["filesTotal"]
  ) {
    return null;
  }
  return {
    phase: payload["phase"],
    filesCompleted: payload["filesCompleted"],
    filesTotal: payload["filesTotal"],
  };
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
  let payload: unknown;
  try {
    payload = JSON.parse(item["aggregated_output"]);
  } catch {
    return null;
  }
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
    capacity.length === 1 &&
    capacityResult !== undefined &&
    isProgressCount(capacityResult["actual"])
      ? capacityResult["actual"]
      : null;
  return { kind: "preflight", delegation, configuredSlots };
}

function dispatchStatus(
  item: Readonly<Record<string, unknown>>,
): ScanWorkerStatus | null {
  if (typeof item["text"] !== "string") return null;
  const markers = item["text"]
    .split(/\r?\n/u)
    .filter((line) => line.startsWith(WORKER_STATUS_PREFIX));
  const marker = markers[0];
  if (markers.length !== 1 || marker === undefined) return null;
  let payload: unknown;
  try {
    payload = JSON.parse(marker.slice(WORKER_STATUS_PREFIX.length));
  } catch {
    return null;
  }
  if (
    !isRecord(payload) ||
    typeof payload["phase"] !== "string" ||
    !WORKER_PHASES.has(payload["phase"]) ||
    !isProgressCount(payload["planned"]) ||
    !isProgressCount(payload["started"]) ||
    payload["started"] > payload["planned"]
  ) {
    return null;
  }
  return {
    kind: "dispatch",
    phase: payload["phase"] as ScanWorkerPhase,
    planned: payload["planned"],
    started: payload["started"],
  };
}

function isProgressCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isScanPhase(value: unknown): value is ScanPhase {
  return (
    value === "preflight" ||
    value === "threat_model" ||
    value === "discovery" ||
    value === "validation" ||
    value === "attack_path" ||
    value === "reporting"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
