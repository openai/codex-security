import { environmentEntry } from "./auth.js";
import { inspectTrustedExecutable } from "./trusted-executable.js";
import { realpath } from "node:fs/promises";
import { createRequire } from "node:module";
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
  workbenchEnvironment,
  type ProcessEnvironment,
} from "./runtime.js";

interface ScanTarget {
  id: string;
  target_path: string;
  target_id?: string | null;
}

interface BootstrapDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): {
    all(...parameters: (string | number)[]): unknown[];
    finalize?(): void;
  };
  close(): void;
}

/** Read only enough history to protect Python discovery; the workbench still validates the scan. */
export async function savedScanWorkbench(
  requestedId: string | { workflowId: string },
  options: {
    environment: ProcessEnvironment;
    pluginRoot: string;
    currentDirectory: string;
    signal?: AbortSignal;
  },
): Promise<
  SavedScanDependencies["runWorkbench"] & { environment: ProcessEnvironment }
> {
  options.signal?.throwIfAborted();
  const environment: ProcessEnvironment = workbenchEnvironment(
    options.environment,
  );
  const targets = await readTargets(
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
  const protectedRoots = [
    ...callerRoots,
    ...targets.map((row) => row.target_path),
    ...(
      await Promise.all(
        targets.map((row) =>
          gitProtectionRoots(row.target_path, options.signal),
        ),
      )
    ).flat(),
  ];
  let python: string | undefined;
  const workbench: SavedScanDependencies["runWorkbench"] = async (
    args,
    input,
    signal = options.signal,
  ) => {
    signal?.throwIfAborted();
    // Return the selected ID directly: probing Python must not revisit unrelated history.
    if (requestedId === "latest" && args[0] === "list-scans")
      return { scans: targets.map((target) => ({ scanId: target.id })) };
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
    // Pin the interpreter selected with every candidate and the caller checkout protected.
    python ??= await resolvePluginPython({
      environment,
      protectedRoot: protectedRoots,
      currentDirectory: options.currentDirectory,
      signal,
    });
    environment["PYTHON"] = python;
    const result = await runWorkbench(
      {
        environment,
        pluginRoot: options.pluginRoot,
        python,
        signal,
        protectedRoot: protectedRoots,
        currentDirectory: options.currentDirectory,
        failureMessage: "Could not read Codex Security scan history",
      },
      target ? ["get-scan", "--scan-id", target.id] : args,
      input,
    );
    if (typeof requestedId !== "string" && args[0] === "finding-workflow") {
      const workflow = result["workflow"];
      if (
        typeof workflow !== "object" ||
        workflow === null ||
        Array.isArray(workflow) ||
        workflow["scanId"] !== targets[0]!.id
      )
        throw new CodexSecurityError(
          "Saved workflow changed during lookup. Retry the command.",
        );
    }
    if (target) {
      const scan = result["scan"];
      if (
        typeof scan !== "object" ||
        scan === null ||
        Array.isArray(scan) ||
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
  return Object.assign(workbench, { environment });
}

async function readTargets(
  requestedId: string | { workflowId: string },
  environment: ProcessEnvironment,
  currentDirectory: string,
  signal?: AbortSignal,
): Promise<ScanTarget[]> {
  const require = createRequire(import.meta.url);
  const bun = process.versions["bun"] !== undefined;
  const Database = (
    bun ? require("bun:sqlite").Database : require("node:sqlite").DatabaseSync
  ) as new (
    path: string,
    options: {
      readonly?: boolean;
      readOnly?: boolean;
      readwrite?: boolean;
      create?: boolean;
    },
  ) => BootstrapDatabase;
  let database: BootstrapDatabase | undefined;
  try {
    database = new Database(
      join(codexSecurityStateDirectory(environment), "workbench.sqlite3"),
      // Apple's SQLite cannot initialize absent WAL sidecars through a read-only handle.
      // Open only an existing file there; query_only still prevents SQL data/schema writes.
      bun
        ? {
            readonly: process.platform !== "darwin",
            readwrite: process.platform === "darwin",
            create: false,
          }
        : { readOnly: true },
    );
    database.exec("PRAGMA busy_timeout = 5000");
    database.exec("PRAGMA query_only = ON");
    if (typeof requestedId !== "string") {
      const columns = readRows<{ name: string }>(
        database,
        "PRAGMA table_info(finding_workflows)",
      );
      const scanId = columns.some((column) => column.name === "scan_id")
        ? "workflow.scan_id"
        : "json_extract(workflow.state_json, '$.scanId')";
      return readRows<ScanTarget>(
        database,
        `SELECT scans.id, scans.target_path FROM scans
        JOIN finding_workflows AS workflow ON scans.id = ${scanId} WHERE workflow.id = ?`,
        requestedId.workflowId,
      );
    }
    if (requestedId === "latest")
      return await latestTargets(
        database,
        currentDirectory,
        environment,
        signal,
      );
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
  } catch (error) {
    signal?.throwIfAborted();
    if (error instanceof CodexSecurityError) throw error;
    throw new CodexSecurityError(
      `Could not read saved scan targets before Python discovery: ${errorMessage(error)}`,
      { cause: error },
    );
  } finally {
    database?.close();
  }
}

function readRows<T>(
  database: BootstrapDatabase,
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

async function latestTargets(
  database: BootstrapDatabase,
  directory: string,
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<ScanTarget[]> {
  const current = await pathKey(directory);
  const columns = new Set(
    readRows<{ name: string }>(database, "PRAGMA table_info(scans)").map(
      (column) => column.name,
    ),
  );
  // The workbench migrates after discovery; schemas before v16 have no target registry.
  const hasTargets =
    readRows(database, "PRAGMA table_info(security_targets)").length > 0;
  const registered = readRows<ScanTarget>(
    database,
    hasTargets
      ? "SELECT id, current_path AS target_path FROM security_targets"
      : "SELECT DISTINCT target_path AS id, target_path FROM scans",
  );
  const related = new Set<string>();
  for (const target of registered)
    if ((await pathKey(target.target_path)) === current) related.add(target.id);
  let gitMatchingUnavailable = false;
  const caller = await gitMarkerRoot(directory, signal, "outermost");
  if (caller !== null) {
    // Resolve metadata with a host Git, never a Git executable from any candidate checkout.
    const roots = await Promise.all(
      registered.map((target) =>
        gitProtectionRoots(target.target_path, signal),
      ),
    );
    const protectedRoots = [
      ...(await gitProtectionRoots(directory, signal)),
      ...registered.map((target) => target.target_path),
      ...roots.flat(),
    ];
    const configured = environmentEntry(environment, "CODEX_SECURITY_GIT");
    const inspected =
      configured === ""
        ? { executable: null, environment }
        : await inspectTrustedExecutable(
            configured ?? "git",
            environment,
            protectedRoots,
          );
    // Keep subsequent workbench operations on this host Git without changing Python's PATH.
    for (const key of Object.keys(environment))
      if (key.toUpperCase() === "CODEX_SECURITY_GIT") delete environment[key];
    environment["CODEX_SECURITY_GIT"] = inspected.executable ?? "";
    gitMatchingUnavailable = inspected.executable === null;
    const git =
      inspected.executable === null
        ? null
        : {
            executable: inspected.executable,
            environment: inspected.environment,
          };
    const identity =
      git === null
        ? { commonDirectory: null, origin: null }
        : await gitHistoryIdentity(directory, git, signal);
    const common =
      identity.commonDirectory === null
        ? null
        : await pathKey(identity.commonDirectory);
    const origin = repositoryOrigin(identity.origin);
    for (const [index, target] of registered.entries()) {
      signal?.throwIfAborted();
      if (related.has(target.id) || roots[index] === null || git === null)
        continue;
      const candidate = await gitHistoryIdentity(
        target.target_path,
        git,
        signal,
      );
      if (
        (common !== null &&
          candidate.commonDirectory !== null &&
          (await pathKey(candidate.commonDirectory)) === common) ||
        (origin !== null && repositoryOrigin(candidate.origin) === origin)
      )
        related.add(target.id);
    }
  }
  const scans = readRows<ScanTarget>(
    database,
    `SELECT scans.id, scans.target_path,
        ${columns.has("target_id") ? "scans.target_id" : "scans.target_path"} AS target_id
      FROM scans JOIN scan_progress AS progress ON progress.scan_id = scans.id
      WHERE scans.status = 'complete' ${columns.has("canceled_at") ? "AND scans.canceled_at IS NULL" : ""}
      ORDER BY MAX(scans.updated_at, progress.updated_at) DESC,
        scans.started_at DESC, scans.id`,
  );
  for (const scan of scans) {
    signal?.throwIfAborted();
    if (
      related.has(scan.target_id ?? "") ||
      (await pathKey(scan.target_path)) === current
    )
      return [scan];
  }
  if (gitMatchingUnavailable)
    throw new CodexSecurityError(
      "No completed saved scan matched this exact path, and Git-based matching across worktrees or clones is unavailable. Use an explicit saved scan ID: codex-security dedupe --scan SCAN_ID",
    );
  return [];
}

async function pathKey(path: string): Promise<string> {
  const canonical = await realpath(path).catch(() => resolve(path));
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
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
