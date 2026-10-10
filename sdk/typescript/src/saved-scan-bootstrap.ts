import { isRecord } from "./record.js";
import type { JsonValue } from "./config.js";
import { environmentEntry } from "./auth.js";
import { inspectTrustedExecutable } from "./trusted-executable.js";
import { stat } from "node:fs/promises";
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
  sameFile,
  workbenchEnvironment,
  type ProcessEnvironment,
} from "./runtime.js";

interface ScanTarget {
  id: string;
  target_path: string;
  repository_generation?: string | null;
  originFallback?: boolean;
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
    // Pin the interpreter selected with every candidate and the caller checkout protected.
    python ??= await resolvePluginPython({
      environment,
      protectedRoot: protectedRoots,
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
      target ? ["get-scan", "--scan-id", target.id] : args,
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
  const columns = new Set(
    readRows<{ name: string }>(database, "PRAGMA table_info(scans)").map(
      (column) => column.name,
    ),
  );
  const scans = readRows<ScanTarget>(
    database,
    `SELECT scans.id, scans.target_path,
        ${columns.has("repository_generation") ? "scans.repository_generation" : "NULL"} AS repository_generation
      FROM scans JOIN scan_progress AS progress ON progress.scan_id = scans.id
      WHERE scans.status = 'complete' ${columns.has("canceled_at") ? "AND scans.canceled_at IS NULL" : ""}
      ORDER BY MAX(scans.updated_at, progress.updated_at) DESC,
        scans.started_at DESC, scans.id`,
  );
  const paths = [...new Set(scans.map((scan) => scan.target_path))];
  const related = new Map<string, { originFallback: boolean }>();
  for (const path of paths)
    if (await sameFile(path, directory))
      related.set(path, { originFallback: false });
  let gitMatchingUnavailable = false;
  const caller = await gitMarkerRoot(directory, signal, "outermost");
  if (caller !== null) {
    // Resolve metadata with a host Git, never a Git executable from any candidate checkout.
    const hasTargets =
      readRows(database, "PRAGMA table_info(security_targets)").length > 0;
    const protectedPaths = readRows<{ target_path: string }>(
      database,
      hasTargets
        ? "SELECT current_path AS target_path FROM security_targets UNION SELECT target_path FROM scans"
        : "SELECT DISTINCT target_path FROM scans",
    ).map((target) => target.target_path);
    const protectedRoots = [
      ...(await gitProtectionRoots(directory, signal)),
      ...protectedPaths,
      ...(
        await Promise.all(
          protectedPaths.map((path) => gitProtectionRoots(path, signal)),
        )
      ).flat(),
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
    // A removed worktree cannot supply live Git metadata. Keep its persisted candidate
    // until the caller-scoped workbench query decides whether that generation belongs here.
    const missing =
      caller !== null &&
      scan.repository_generation != null &&
      (await stat(scan.target_path).then(
        () => false,
        (error: NodeJS.ErrnoException) => error.code === "ENOENT",
      ));
    if (match || missing)
      selected.push({
        ...scan,
        originFallback: match?.originFallback ?? false,
      });
  }
  if (selected.length === 0 && gitMatchingUnavailable)
    throw new CodexSecurityError(
      "No completed saved scan matched this exact path, and Git-based matching across worktrees or clones is unavailable. Use an explicit saved scan ID: codex-security dedupe --scan SCAN_ID",
    );
  return selected;
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
