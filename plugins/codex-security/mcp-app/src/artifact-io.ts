import { canonicalDirectory } from "./artifact-context.js";
import { isRecord } from "./record.js";
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, isAbsolute, join, sep } from "node:path";

export interface DeepReducerWorkerContext {
  id: string;
  resultPath: string;
}

export interface DeepReducerContext {
  scanRoot: string;
  claimedWorkers: DeepReducerWorkerContext[];
  previousReducerResultPath?: string;
}

/**
 * Host-bound artifact state. Never construct this object from model tool input.
 */
export interface ArtifactContext {
  root: string;
  repoRoot: string;
  layout: "scan" | "worker" | "reducer";
  scanId?: string;
  scope?: string;
  pluginRoot?: string;
  pythonCommand?: string;
  targetContract?: Readonly<Record<string, unknown>>;
  targetRevision?: string;
  handoffClaimToken?: string;
  status?: string;
  mode?: string;
  deepReducer?: DeepReducerContext;
}

export interface ArtifactPage {
  cursor?: string;
  limit?: number;
}

export interface ArtifactPageResult<Row> {
  rows: Row[];
  nextCursor?: string;
}

export interface ArtifactRowSchema<Row> {
  safeParse(
    value: unknown,
  ): { success: true; data: Row } | { success: false; error?: unknown };
}

/**
 * Components are fixed, internal operation constants, not model-facing paths.
 */
export async function readArtifactText(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<string> {
  const canonical = await artifactSourcePath(context, components, label);
  try {
    return await fs.readFile(canonical, "utf8");
  } catch (error) {
    throw new Error(
      `${label}: the requested artifact cannot be read: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

export async function readArtifactTextWithMetadata(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<{ contents: string; modifiedMs: number }> {
  const canonical = await artifactSourcePath(context, components, label);
  try {
    const handle = await fs.open(canonical, "r");
    try {
      const contents = await handle.readFile("utf8");
      const metadata = await handle.stat();
      return { contents, modifiedMs: Number(metadata.mtimeMs) };
    } finally {
      await handle.close();
    }
  } catch (error) {
    throw new Error(
      `${label}: the requested artifact cannot be read: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

export async function artifactSourcePath(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<string> {
  validateArtifactComponents(components, label);
  const root = await requireArtifactRoot(context.root, label);
  let current = root;

  for (const [index, component] of components.entries()) {
    current = join(current, component);
    const metadata = await inspectOptionalPath(current, label);
    if (!metadata) {
      throw new Error(label + ": the requested artifact is unavailable.");
    }
    const isLast = index === components.length - 1;
    if (isLast ? !metadata.isFile() : !metadata.isDirectory()) {
      throw new Error(
        label + ": the requested artifact is not a safe regular file.",
      );
    }
  }

  const canonical = await fs.realpath(current).catch(() => undefined);
  if (!canonical || !canonical.startsWith(root + sep)) {
    throw new Error(
      label + ": the requested artifact escaped its bound context.",
    );
  }
  return canonical;
}

export async function readArtifactJsonObject(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<Record<string, unknown>> {
  const source = await readArtifactText(context, components, label);
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(label + ": stored JSON is malformed.");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(label + ": stored JSON must contain an object.");
  }
  return value as Record<string, unknown>;
}

export async function readArtifactJsonl<Row>(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
  rowSchema: ArtifactRowSchema<Row>,
): Promise<Row[]> {
  const source = await readArtifactText(context, components, label);
  const rows: Row[] = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    if (!line.trim()) continue;

    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new Error(label + ": row " + (index + 1) + " is not valid JSON.");
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(
        label + ": row " + (index + 1) + " must be a JSON object.",
      );
    }
    const parsed = rowSchema.safeParse(value);
    if (!parsed.success) {
      throw new Error(
        label +
          ": row " +
          (index + 1) +
          " does not match its artifact schema" +
          formatRowSchemaError(parsed.error),
      );
    }
    rows.push(parsed.data);
  }
  return rows;
}

export function paginateArtifactRows<Row>(
  rows: readonly Row[],
  page: ArtifactPage,
  label: string,
): ArtifactPageResult<Row> {
  const cursor = page.cursor ?? "0";
  if (!/^(?:0|[1-9][0-9]*)$/u.test(cursor)) {
    throw new Error(label + ": cursor must be a non-negative integer string.");
  }
  const start = Number(cursor);
  if (!Number.isSafeInteger(start) || start > rows.length) {
    throw new Error(label + ": cursor is outside the available rows.");
  }

  const limit = page.limit ?? 200;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new Error(label + ": limit must be an integer from 1 through 1000.");
  }

  const end = Math.min(rows.length, start + limit);
  return {
    rows: rows.slice(start, end),
    ...(end < rows.length ? { nextCursor: String(end) } : {}),
  };
}

/**
 * Resolve one operation-owned destination inside its bound scan or worker root.
 */
export async function artifactDestination(
  context: ArtifactContext,
  components: readonly string[],
  label: string,
): Promise<string> {
  validateArtifactComponents(components, label);
  const root = await requireArtifactRoot(context.root, label);
  let directory = root;

  for (const component of components.slice(0, -1)) {
    directory = join(directory, component);
    let metadata = await inspectOptionalPath(directory, label);
    if (!metadata) {
      try {
        await fs.mkdir(directory, { mode: 0o700 });
      } catch (error) {
        if (!isNodeError(error) || error.code !== "EEXIST") {
          throw new Error(label + ": destination directory cannot be created.");
        }
      }
      metadata = await inspectOptionalPath(directory, label);
    }
    if (!metadata || !metadata.isDirectory()) {
      throw new Error(
        label + ": destination directory is not a regular directory.",
      );
    }
    const canonical = await fs.realpath(directory).catch(() => undefined);
    if (!canonical || !canonical.startsWith(root + sep)) {
      throw new Error(label + ": destination escaped its bound context.");
    }
  }

  const destination = join(root, ...components);
  if (!destination.startsWith(root + sep)) {
    throw new Error(label + ": destination escaped its bound context.");
  }
  if ((await inspectOptionalPath(destination, label))?.isFile() === false) {
    throw new Error(label + ": destination is not a regular file.");
  }
  return destination;
}

export async function replaceArtifactText(
  path: string,
  content: string,
): Promise<void> {
  const temporary = join(dirname(path), "." + randomUUID() + ".tmp");
  try {
    await fs.writeFile(temporary, content, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    await fs.rename(temporary, path);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

export async function replaceArtifactJson(
  path: string,
  value: unknown,
): Promise<void> {
  await replaceArtifactText(path, JSON.stringify(value, null, 2) + "\n");
}

export async function replaceArtifactJsonl(
  path: string,
  rows: readonly unknown[],
): Promise<void> {
  const content = rows.length
    ? rows.map((row) => JSON.stringify(row)).join("\n") + "\n"
    : "";
  await replaceArtifactText(path, content);
}

function validateArtifactComponents(
  components: readonly string[],
  label: string,
): void {
  if (components.length === 0) {
    throw new Error(label + ": a fixed artifact destination is required.");
  }
  for (const component of components) {
    if (
      !component ||
      component === "." ||
      component === ".." ||
      component.includes("/") ||
      component.includes("\\") ||
      component.includes("\0")
    ) {
      throw new Error(label + ": the artifact destination is unsafe.");
    }
  }
}

export function requireArtifactRoot(
  artifactRoot: string,
  label: string,
): Promise<string> {
  if (!artifactRoot || !isAbsolute(artifactRoot)) {
    return Promise.reject(
      new Error(label + ": artifact context must have an absolute bound root."),
    );
  }
  return canonicalDirectory(artifactRoot, label + ": artifact context");
}

async function inspectOptionalPath(
  path: string,
  label: string,
): Promise<Awaited<ReturnType<typeof fs.lstat>> | undefined> {
  try {
    return await fs.lstat(path);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw new Error(
      `${label}: artifact path cannot be inspected: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

function formatRowSchemaError(error: unknown): string {
  if (!isRecord(error) || !Array.isArray(error.issues)) return ".";
  const issue: unknown = error.issues[0];
  if (!isRecord(issue)) return ".";
  const issuePath = Array.isArray(issue.path)
    ? issue.path.map(String).join(".")
    : "";
  const message = typeof issue.message === "string" ? issue.message : "";
  if (!issuePath && !message) return ".";
  return ": " + (issuePath ? issuePath + ": " : "") + message;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}
