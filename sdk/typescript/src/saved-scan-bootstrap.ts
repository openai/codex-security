import { isRecord } from "./record.js";
import type { JsonValue } from "./config.js";
import { environmentEntry } from "./auth.js";
import { inspectTrustedExecutable } from "./trusted-executable.js";
import { access } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import {
  gitHistoryIdentity,
  gitMarkerRoot,
  gitProtectionRoots,
} from "./targets.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { SavedScanDependencies } from "./saved-scan.js";
import {
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
  sameFile,
  workbenchEnvironment,
  type ProcessEnvironment,
  sqliteDatabaseOpener,
  type RuntimeDatabase,
} from "./runtime.js";

interface ScanTarget {
  id: string;
  target_path: string;
  repository_generation?: string | null;
  originFallback?: boolean;
  protectPython?: boolean;
}

interface SavedCheckout {
  target_path: string;
  checkout_root: string | null;
}

interface SavedBoundaries {
  byTarget: Map<string, string | null>;
  roots: string[];
  complete: boolean;
}

export interface SavedToolDiscovery {
  protectedRoots: readonly string[];
  allowPathLookup: boolean;
}

/** Read saved checkout boundaries before starting tools. The workbench validates the scan. */
export async function savedScanWorkbench(
  requestedId: string | { workflowId: string },
  options: {
    environment: ProcessEnvironment;
    pluginRoot: string;
    currentDirectory: string;
    signal?: AbortSignal;
  },
): Promise<
  SavedScanDependencies["runWorkbench"] & {
    environment: ProcessEnvironment;
    readonly protectedRoots: readonly string[];
    readonly nodeDiscovery: SavedToolDiscovery;
  }
> {
  options.signal?.throwIfAborted();
  const environment: ProcessEnvironment = workbenchEnvironment(
    options.environment,
  );
  const { targets, checkouts } = await readTargets(
    requestedId,
    environment,
    options.currentDirectory,
    options.signal,
  );
  const latest = requestedId === "latest" || typeof requestedId !== "string";
  if (targets.length === 0)
    throw new CodexSecurityError(
      typeof requestedId !== "string"
        ? `Workflow ${requestedId.workflowId} has no saved scan. Start it with scan --workflow-id ${requestedId.workflowId}.`
        : latest
          ? "No completed saved scan was found for this repository."
          : "Codex Security scan not found.",
    );
  if (!latest && targets.length > 1)
    throw new CodexSecurityError(
      `Scan ID prefix "${requestedId}" matches multiple scans; use a longer prefix.`,
    );
  if (
    targets.some(
      (target) =>
        typeof target.target_path !== "string" ||
        !isAbsolute(target.target_path),
    )
  )
    throw new CodexSecurityError(
      "Saved scan history has no absolute repository target.",
    );

  const callerRoots = await gitProtectionRoots(
    options.currentDirectory,
    options.signal,
  );
  const liveTargets = targets.filter(
    (target) => target.protectPython !== false,
  );
  const protectedRoots = [
    ...callerRoots,
    ...liveTargets.flatMap((row) => {
      const root = checkouts.byTarget.get(row.target_path);
      return root ? [root] : [];
    }),
    ...liveTargets.map((row) => row.target_path),
    ...(
      await Promise.all(
        liveTargets.map((row) =>
          gitProtectionRoots(row.target_path, options.signal),
        ),
      )
    ).flat(),
  ];
  const discoveryProtectedRoots = await savedDiscoveryRoots(
    checkouts,
    [options.currentDirectory, ...targets.map((row) => row.target_path)],
    options.signal,
  );
  let python: string | undefined;
  const workbench: SavedScanDependencies["runWorkbench"] = async (
    args,
    input,
    signal = options.signal,
  ) => {
    signal?.throwIfAborted();
    const selectingLatest =
      requestedId === "latest" && args[0] === "list-scans";
    const target =
      args[0] === "get-scan"
        ? latest
          ? targets.find((row) => row.id === args[2])
          : targets[0]
        : undefined;
    if (args[0] === "get-scan" && !target)
      throw new CodexSecurityError(
        "Saved scan history changed during lookup. Retry the command.",
      );
    // Pin one interpreter; ambient discovery also excludes historical candidate paths.
    python ??= await resolvePluginPython({
      environment,
      protectedRoot: protectedRoots,
      discoveryProtectedRoots,
      allowPathLookup: checkouts.complete,
      currentDirectory: options.currentDirectory,
      signal,
    });
    environment["PYTHON"] = python;
    const execute = (command: readonly string[]) =>
      runWorkbench(
        {
          environment,
          pluginRoot: options.pluginRoot,
          python,
          signal,
          protectedRoot: protectedRoots,
          currentDirectory: options.currentDirectory,
          failureMessage: "Could not read Codex Security scan history",
        },
        command,
        input,
      );
    if (selectingLatest) {
      // Let the workbench enforce the caller's persisted generation and component scope,
      // including history whose original linked worktree has since been removed.
      const scoped = new Map<string, JsonValue[]>();
      const scansAt = async (repository: string): Promise<JsonValue[]> => {
        let scans = scoped.get(repository);
        if (scans === undefined) {
          const result = await execute([
            "list-scans",
            "--repository",
            repository,
            "--status",
            "complete",
          ]);
          scans = Array.isArray(result["scans"]) ? result["scans"] : [];
          scoped.set(repository, scans);
        }
        return scans;
      };
      const callerScans = await scansAt(options.currentDirectory);
      for (const candidate of targets) {
        let selected = callerScans.find(
          (scan) => isRecord(scan) && scan["scanId"] === candidate.id,
        );
        // Dedupe also accepts the same component of an independent same-origin clone.
        // Validate that clone's current ownership before using its saved history.
        if (selected === undefined && candidate.originFallback) {
          selected = (await scansAt(candidate.target_path)).find(
            (scan) => isRecord(scan) && scan["scanId"] === candidate.id,
          );
        }
        if (selected !== undefined) return { scans: [selected] };
      }
      if (environment["CODEX_SECURITY_GIT"] === "") {
        throw new CodexSecurityError(
          "Could not verify the saved checkout automatically without a trusted Git executable. Use an explicit saved scan ID: codex-security dedupe --scan SCAN_ID",
        );
      }
      return { scans: [] };
    }
    const result = await execute(
      target ? ["get-scan", "--scan-id", target.id, "--metadata-only"] : args,
    );
    if (typeof requestedId !== "string" && args[0] === "finding-workflow") {
      const workflow = result["workflow"];
      if (!isRecord(workflow) || workflow["scanId"] !== targets[0]!.id)
        throw new CodexSecurityError(
          "Saved workflow changed during lookup. Retry the command.",
        );
    }
    if (target) {
      const scan = result["scan"];
      if (
        !isRecord(scan) ||
        scan["scanId"] !== target.id ||
        typeof scan["targetPath"] !== "string" ||
        resolve(scan["targetPath"]) !== resolve(target.target_path)
      )
        throw new CodexSecurityError(
          "Saved scan history changed during lookup. Retry the command.",
        );
    }
    return result;
  };
  return Object.assign(workbench, {
    environment,
    protectedRoots: [options.currentDirectory, ...protectedRoots],
    nodeDiscovery: {
      protectedRoots: discoveryProtectedRoots,
      allowPathLookup: checkouts.complete,
    },
  });
}

async function readTargets(
  requestedId: string | { workflowId: string },
  environment: ProcessEnvironment,
  currentDirectory: string,
  signal?: AbortSignal,
): Promise<{ targets: ScanTarget[]; checkouts: SavedBoundaries }> {
  try {
    const latest = requestedId === "latest";
    const snapshot = readSnapshot(
      workbenchDatabasePath(environment),
      (database) => {
        const targets = latest
          ? completedScans(database)
          : exactTargets(database, requestedId);
        const checkouts = savedCheckouts(database);
        return { targets, checkouts };
      },
    );
    if (latest)
      snapshot.targets = await latestTargets(
        snapshot.targets,
        currentDirectory,
        environment,
        snapshot.checkouts,
        signal,
      );
    return snapshot;
  } catch (error) {
    signal?.throwIfAborted();
    if (error instanceof CodexSecurityError) throw error;
    throw new CodexSecurityError(
      `Could not read saved scan targets before Python discovery: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

function workbenchDatabasePath(environment: ProcessEnvironment): string {
  return join(codexSecurityStateDirectory(environment), "workbench.sqlite3");
}

/** @internal Read executable exclusions before launching an ordinary history command. */
export async function savedCheckoutBoundaries(
  environment: ProcessEnvironment,
): Promise<SavedBoundaries | undefined> {
  const path = workbenchDatabasePath(environment);
  try {
    await access(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  return readSnapshot(path, (database) => savedCheckouts(database));
}

/** @internal Exclude both recorded checkout roots and the currently visible checkouts. */
export async function savedDiscoveryRoots(
  checkouts: SavedBoundaries | undefined,
  paths: readonly string[],
  signal?: AbortSignal,
): Promise<string[]> {
  const targets = [...new Set([...paths, ...(checkouts?.roots ?? [])])];
  const currentRoots = await Promise.all(
    targets.map((path) => gitProtectionRoots(path, signal)),
  );
  return [...new Set([...targets, ...currentRoots.flat()])];
}

export function readSavedScanLifecycle(
  environment: ProcessEnvironment,
  scanId: string,
): unknown {
  return readSnapshot(
    workbenchDatabasePath(environment),
    (database) => {
      const [row] = readRows<{ snapshot: string }>(
        database,
        "SELECT snapshot FROM scan_lifecycles WHERE scan_id = ?",
        scanId,
      );
      return row && JSON.parse(row.snapshot);
    },
    0,
  );
}

function readSnapshot<T>(
  path: string,
  select: (database: RuntimeDatabase) => T,
  timeout: 0 | 5000 = 5000,
): T {
  const database = sqliteDatabaseOpener("read-existing")(path);
  try {
    database.exec(`PRAGMA busy_timeout = ${timeout}`);
    database.exec("PRAGMA query_only = ON");
    // Select scans and their saved boundaries from the same snapshot.
    database.exec("BEGIN");
    return select(database);
  } finally {
    database.close();
  }
}

function exactTargets(
  database: RuntimeDatabase,
  requestedId: string | { workflowId: string },
): ScanTarget[] {
  if (typeof requestedId !== "string") {
    const scanId = tableColumns(database, "finding_workflows").has("scan_id")
      ? "workflow.scan_id"
      : "json_extract(workflow.state_json, '$.scanId')";
    return readRows<ScanTarget>(
      database,
      `SELECT scans.id, scans.target_path FROM scans
        JOIN finding_workflows AS workflow ON scans.id = ${scanId} WHERE workflow.id = ?`,
      requestedId.workflowId,
    );
  }
  // Match uuid.UUID's accepted full-ID spellings before considering a prefix.
  const compact = trimBoundary(
    requestedId.replaceAll("urn:", "").replaceAll("uuid:", ""),
    "{",
    "}",
  ).replaceAll("-", "");
  if (/^[0-9a-f]{32}$/i.test(compact)) {
    const id = compact
      .toLowerCase()
      .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
    return readRows<ScanTarget>(
      database,
      "SELECT id, target_path FROM scans WHERE id = ?",
      id,
    );
  }
  if (requestedId.length < 8)
    throw new CodexSecurityError(
      "Scan ID prefixes must be at least eight characters.",
    );
  return readRows<ScanTarget>(
    database,
    "SELECT id, target_path FROM scans WHERE substr(id, 1, ?) = ? LIMIT 2",
    requestedId.length,
    requestedId.toLowerCase(),
  );
}

function tableColumns(database: RuntimeDatabase, table: string): Set<string> {
  return new Set(
    readRows<{ name: string }>(database, `PRAGMA table_info(${table})`).map(
      (row) => row.name,
    ),
  );
}

/** Read registered boundaries without assuming an unversioned scan was outside Git. */
function savedCheckouts(database: RuntimeDatabase): SavedBoundaries {
  const scan = tableColumns(database, "scans");
  const registry = tableColumns(database, "security_targets");
  const workspace = tableColumns(database, "workspaces");
  const sources = [];
  if (scan.has("target_path"))
    sources.push("SELECT target_path, NULL AS checkout_root FROM scans");
  if (workspace.has("target_path")) {
    const validated = workspace.has("target_path_unvalidated")
      ? " AND (target_path_unvalidated = 0 OR target_id IS NOT NULL)"
      : "";
    sources.push(`SELECT target_path, NULL AS checkout_root FROM workspaces
      WHERE target_path IS NOT NULL${validated}`);
  }
  if (registry.has("current_path")) {
    sources.push(`SELECT current_path AS target_path,
      ${registry.has("git_checkout_root") ? "git_checkout_root" : "NULL"} AS checkout_root
      FROM security_targets`);
  }
  const rows =
    sources.length === 0
      ? []
      : readRows<SavedCheckout>(
          database,
          `SELECT target_path, MAX(checkout_root) AS checkout_root
     FROM (${sources.join(" UNION ALL ")}) GROUP BY target_path`,
        );
  const saved = workspace.has("rejected_checkout_roots_json")
    ? "rejected_checkout_roots_json"
    : "NULL";
  const rejected = workspace.has("target_path_unvalidated")
    ? readRows<{ root: string | null }>(
        database,
        `SELECT DISTINCT value AS root FROM workspaces LEFT JOIN json_each(${saved})
         WHERE ${saved} IS NOT NULL OR
             (target_path IS NOT NULL AND target_path_unvalidated = 1 AND target_id IS NULL)`,
      ).map((row) => row.root)
    : [];
  const roots = [...rows.map((row) => row.checkout_root), ...rejected];
  return {
    byTarget: new Map(rows.map((row) => [row.target_path, row.checkout_root])),
    roots: roots.filter((root): root is string => root !== null),
    complete: !roots.includes(null),
  };
}

function readRows<T>(
  database: RuntimeDatabase,
  sql: string,
  ...parameters: (string | number)[]
): T[] {
  const statement = database.prepare(sql);
  try {
    return statement.all(...parameters) as T[];
  } finally {
    // Bun's manually prepared statements otherwise retain Windows file locks after close.
    // Node finalizes its statements when DatabaseSync.close() runs.
    statement.finalize?.();
  }
}

function completedScans(database: RuntimeDatabase): ScanTarget[] {
  const columns = tableColumns(database, "scans");
  return readRows<
    ScanTarget & {
      updated_at: string;
      progress_updated_at: string;
      started_at: string;
    }
  >(
    database,
    `SELECT scans.id, scans.target_path, scans.updated_at, scans.started_at,
        progress.updated_at AS progress_updated_at,
        ${columns.has("repository_generation") ? "scans.repository_generation" : "NULL"} AS repository_generation
      FROM scans JOIN scan_progress AS progress ON progress.scan_id = scans.id
      WHERE scans.status = 'complete' ${columns.has("canceled_at") ? "AND scans.canceled_at IS NULL" : ""}`,
  )
    .map((scan) => {
      const updated = timestampOrderKey(scan.updated_at);
      const progress = timestampOrderKey(scan.progress_updated_at);
      return {
        ...scan,
        updatedKey: updated > progress ? updated : progress,
        startedKey: timestampOrderKey(scan.started_at),
      };
    })
    .sort(
      (left, right) =>
        compareOrderKeys(right.updatedKey, left.updatedKey) ||
        compareOrderKeys(right.startedKey, left.startedKey) ||
        compareOrderKeys(left.id, right.id),
    );
}

async function latestTargets(
  scans: ScanTarget[],
  directory: string,
  environment: ProcessEnvironment,
  checkouts: SavedBoundaries,
  signal?: AbortSignal,
): Promise<ScanTarget[]> {
  const paths = [...new Set(scans.map((scan) => scan.target_path))];
  const related = new Map<string, { originFallback: boolean }>();
  for (const path of paths)
    if (await sameFile(path, directory))
      related.set(path, { originFallback: false });
  const protectedAncestorPaths = new Set<string>();
  let gitMatchingUnavailable = false;
  const caller = await gitMarkerRoot(directory, signal, "outermost");
  if (caller !== null) {
    // Resolve metadata with a host Git, never a Git executable from any candidate checkout.
    const protectedRoots = await savedDiscoveryRoots(
      checkouts,
      [directory, ...checkouts.byTarget.keys()],
      signal,
    );
    const configured = environmentEntry(environment, "CODEX_SECURITY_GIT");
    const inspected =
      configured === "" ||
      (!checkouts.complete && !isAbsolute(configured ?? ""))
        ? { executable: null, environment }
        : await inspectTrustedExecutable(
            configured ?? "git",
            environment,
            protectedRoots,
          );
    for (const key of Object.keys(environment))
      if (key.toUpperCase() === "CODEX_SECURITY_GIT") delete environment[key];
    environment["CODEX_SECURITY_GIT"] = inspected.executable ?? "";
    gitMatchingUnavailable = inspected.executable === null;
    if (inspected.executable !== null) {
      const git = {
        executable: inspected.executable,
        environment: inspected.environment,
      };
      const identity = await gitHistoryIdentity(directory, git, signal);
      const origin = repositoryOrigin(identity.origin);
      for (const path of paths) {
        signal?.throwIfAborted();
        if (related.has(path)) continue;
        const candidate = await gitHistoryIdentity(path, git, signal);
        if (
          candidate.commonDirectory === null &&
          identity.commonDirectory !== null
        ) {
          const enclosing = await gitMarkerRoot(path, signal, "outermost");
          if (enclosing !== null) {
            const ancestor = await gitHistoryIdentity(enclosing, git, signal);
            if (
              ancestor.commonDirectory !== null &&
              (await sameFile(
                identity.commonDirectory,
                ancestor.commonDirectory,
              ))
            )
              protectedAncestorPaths.add(path);
          }
        }
        if (
          identity.relativePath === null ||
          candidate.relativePath !== identity.relativePath
        )
          continue;
        const common =
          identity.commonDirectory !== null &&
          candidate.commonDirectory !== null &&
          (await sameFile(identity.commonDirectory, candidate.commonDirectory));
        const clone =
          !common &&
          identity.commonDirectory !== null &&
          candidate.commonDirectory !== null &&
          origin !== null &&
          repositoryOrigin(candidate.origin) === origin;
        if (common || clone) related.set(path, { originFallback: clone });
      }
    }
  }
  const selected: ScanTarget[] = [];
  for (const scan of scans) {
    signal?.throwIfAborted();
    const match = related.get(scan.target_path);
    // Scan generations survive legacy unbound registry rows and removed or reused paths.
    // The caller-scoped workbench query remains authoritative for membership.
    if (match || (caller !== null && scan.repository_generation != null))
      selected.push({
        ...scan,
        originFallback: match?.originFallback ?? false,
        // An existing path unrelated to the caller no longer supplies its source.
        // Keep the historical binding for lookup without trusting it as a live target.
        protectPython:
          match !== undefined || protectedAncestorPaths.has(scan.target_path),
      });
  }
  if (related.size === 0 && gitMatchingUnavailable)
    throw new CodexSecurityError(
      "No completed saved scan matched this exact path, and Git-based matching across worktrees or clones is unavailable. Use an explicit saved scan ID: codex-security dedupe --scan SCAN_ID",
    );
  return selected;
}

function timestampOrderKey(value: string): string {
  const match =
    /^(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2})(?:\.([0-9]+))?([Zz]|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  const seconds = match
    ? Date.parse(`${match[1]}${match[3]}`.toUpperCase())
    : NaN;
  // Legacy naive or malformed rows retain opaque text ordering. The scoped
  // workbench query still owns their diagnostics, without using the host timezone.
  if (!Number.isFinite(seconds)) return `0${value}`;
  const instant = new Date(seconds);
  const whole = instant.toISOString().slice(0, -5);
  // An offset can carry a supported four-digit local year into UTC year 10000.
  const year = String(instant.getUTCFullYear()).padStart(5, "0");
  const digits = match![2] ?? "";
  let fractionEnd = digits.length;
  while (fractionEnd > 0 && digits[fractionEnd - 1] === "0") fractionEnd--;
  const fraction = digits.slice(0, fractionEnd);
  return `${year}${whole.slice(whole.indexOf("-"))}${fraction ? `.${fraction}` : ""}`;
}

function compareOrderKeys(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

// Match the workbench history's host/path identity across HTTPS and SSH origins.
function repositoryOrigin(remote: string | null): string | null {
  if (!remote) return null;
  let host: string;
  let path: string;
  if (remote.includes("://")) {
    let parsed: URL;
    try {
      parsed = new URL(remote);
    } catch {
      return null;
    }
    if (
      !["https:", "ssh:"].includes(parsed.protocol) ||
      parsed.search ||
      parsed.hash
    )
      return null;
    host = parsed.hostname.replace(/^\[|\]$/g, "");
    if (
      parsed.port &&
      parsed.port !== (parsed.protocol === "https:" ? "443" : "22")
    )
      host += `:${parsed.port}`;
    path = remote.match(/^[^:]+:\/\/[^/?#]*([^?#]*)/)?.[1] ?? "";
  } else {
    const colon = remote.indexOf(":");
    if (colon < 0 || /[?#]/.test(remote)) return null;
    host = remote.slice(0, colon).split("@").at(-1)!;
    path = remote.slice(colon + 1);
  }
  path = trimBoundary(path, "/", "/").replace(/\.git$/, "");
  return host && path ? JSON.stringify([host.toLowerCase(), path]) : null;
}

function trimBoundary(
  value: string,
  leading: string,
  trailing: string,
): string {
  let start = 0;
  let end = value.length;
  while (value[start] === leading) start++;
  while (end > start && value[end - 1] === trailing) end--;
  return value.slice(start, end);
}
