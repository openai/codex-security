import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export class SecurityError extends Error {
  constructor(message, options = {}) {
    super(message, options.cause === undefined ? {} : { cause: options.cause });
    this.name = "SecurityError";
    this.exitCode = options.exitCode ?? 1;
  }
}

/** Raised when the scan produced no sealable contract. Exit code matches the Codex CLI. */
export class IncompleteScanError extends SecurityError {
  constructor(message, options = {}) {
    super(message, { ...options, exitCode: options.exitCode ?? 2 });
    this.name = "IncompleteScanError";
  }
}

export const PACKAGE_ROOT = resolve(
  fileURLToPath(new URL("../", import.meta.url)),
);

export const PLUGIN_ROOT = join(PACKAGE_ROOT, "plugin");

export function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function expandHome(value) {
  if (value === "~") return homedir();
  if (value.startsWith(`~${sep}`) || value.startsWith("~/")) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

/**
 * Persistent state for the workbench SQLite database and scan history.
 *
 * The Python workbench reads CODEX_HOME to derive its own default, so this
 * resolves the same directory the helpers will pick and exports it explicitly
 * rather than letting the two disagree.
 */
export function stateDirectory(environment = process.env) {
  const override = environment["CLAUDE_SECURITY_STATE_DIR"];
  if (typeof override === "string" && override.trim() !== "") {
    return resolve(expandHome(override.trim()));
  }
  const home = environment["CLAUDE_CONFIG_DIR"] ?? join(homedir(), ".claude");
  return resolve(expandHome(home), "state", "plugins", "claude-security");
}

export function scanRootDirectory(repositoryName, environment = process.env) {
  const override = environment["CLAUDE_SECURITY_SCAN_ROOT"];
  const base =
    typeof override === "string" && override.trim() !== ""
      ? resolve(expandHome(override.trim()))
      : join(tmpdir(), "claude-security-scans");
  return join(base, safeSegment(repositoryName));
}

export function safeSegment(value) {
  const cleaned = value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return cleaned === "" ? "repository" : cleaned.slice(0, 64);
}

export function shortDigest(value, length = 12) {
  return createHash("sha256").update(value).digest("hex").slice(0, length);
}

export async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

export async function isDirectory(path) {
  try {
    return (await lstat(path)).isDirectory();
  } catch {
    return false;
  }
}

export async function isFile(path) {
  try {
    const stats = await lstat(path);
    return stats.isFile() && !stats.isSymbolicLink();
  } catch {
    return false;
  }
}

export async function ensureDirectory(path, mode = 0o700) {
  await mkdir(path, { recursive: true, mode });
  return path;
}

export async function readJson(path) {
  const raw = await readFile(path, "utf8");
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new SecurityError(`Invalid JSON in ${path}`, { cause: error });
  }
}

export async function readJsonIfPresent(path) {
  if (!(await pathExists(path))) return null;
  return await readJson(path);
}

/**
 * Results must never land inside the repository being scanned: the scan writes
 * evidence files, and a scan that pollutes its own target invalidates the next
 * diff and can leak findings into a commit.
 */
export async function requireOutsideRepository(outputDir, repositoryRoot, label) {
  const canonicalOutput = await canonicalPath(outputDir);
  const canonicalRepository = await canonicalPath(repositoryRoot);
  if (canonicalOutput === canonicalRepository || isInside(canonicalRepository, canonicalOutput)) {
    throw new SecurityError(
      `The ${label} directory must be outside the scanned repository: ${outputDir}`,
    );
  }
}

export function isInside(parent, child) {
  const rel = relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

export async function canonicalPath(path) {
  try {
    return await realpath(path);
  } catch {
    return resolve(path);
  }
}

export function formatDuration(milliseconds) {
  const totalSeconds = Math.max(0, Math.round(milliseconds / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(value);
}

const SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"];

export function severityRank(level) {
  const index = SEVERITY_ORDER.indexOf(String(level).toLowerCase());
  return index === -1 ? -1 : index;
}

export function severityAtLeast(level, threshold) {
  return severityRank(level) >= severityRank(threshold);
}

export const SEVERITY_LEVELS = [...SEVERITY_ORDER].reverse();

/**
 * Anything read back out of a scan directory can contain repository-controlled
 * text, so error messages that travel to the terminal get absolute paths and
 * control characters stripped before they are printed.
 */
export function redactMessage(value) {
  const text =
    value instanceof Error ? (value.message ?? String(value)) : String(value);
  return text
    .replaceAll(homedir(), "~")
    .split("")
    .map((character) =>
      character.codePointAt(0) < 0x20 || character.codePointAt(0) === 0x7f
        ? " "
        : character,
    )
    .join("")
    .trim();
}
