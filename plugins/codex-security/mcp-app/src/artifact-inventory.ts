import { randomUUID } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import * as z from "zod/v4";
import { join } from "node:path";
import {
  artifactDestination,
  artifactSourcePath,
  paginateArtifactRows,
  type ArtifactContext,
  type ArtifactPage,
} from "./artifact-io.js";
import { artifactSchemaDocuments } from "./artifact-contracts.js";
import { decodeUtf8 } from "./helpers/utf8.js";
import { runTool } from "./helpers/inventory-git";
import { environmentValue } from "./helpers/helper-files";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path";

const inventoryComponents = ["artifacts", "02_discovery", "in_scope_files.txt"];
const preflightComponents = [
  "artifacts",
  "deep_discovery",
  "source_preflight.jsonl",
];
const label = "review_items";

const definitions = artifactSchemaDocuments["tools/review-items"].$defs;
export type ReviewItem = z.infer<typeof definitions.reviewItem>;
export const {
  prepareInput: prepareReviewItemsInputSchema,
  reviewItemsInput: reviewItemsReaderInputSchema,
  reviewItem: reviewItemSchema,
} = definitions;

/** Build the selected repository or diff inventory from host-bound scan context. */
export async function prepareCodexSecurityReviewItems(
  context: ArtifactContext,
  signal?: AbortSignal,
) {
  requireInventoryPreparationContext(context);

  const destination = await artifactDestination(
    context,
    inventoryComponents,
    label,
  );
  const windows = process.platform === "win32";
  const arguments_ = [
    "generate-in-scope-files",
    `--repo=${context.repoRoot}`,
    `--scope=${context.scope ?? "."}`,
    `--out=${destination}`,
  ];

  if (context.mode === "diff") {
    const target = context.targetContract?.diffTarget;
    if (!target || typeof target !== "object" || Array.isArray(target)) {
      throw new Error(
        `${label}: the diff scan has no authoritative change set.`,
      );
    }
    const diffTarget = target as Record<string, unknown>;
    const { kind, baseRevision, headRevision } = diffTarget;
    if (
      (kind !== "working_tree" && kind !== "commit" && kind !== "range") ||
      typeof baseRevision !== "string" ||
      !baseRevision ||
      typeof headRevision !== "string" ||
      !headRevision
    ) {
      throw new Error(
        `${label}: the diff scan has an invalid authoritative change set.`,
      );
    }
    arguments_.push(
      `--diff-base=${baseRevision}`,
      `--diff-head=${headRevision}`,
      `--diff-mode=${kind === "working_tree" ? "local-patch" : "revisions"}`,
    );
  }

  await runInventoryHelper(context, arguments_, signal);

  return { reviewItemsTotal: (await readReviewItems(context)).length };
}

/** Establish fresh non-diff source existence without rewriting review items. */
export async function preflightCodexSecurityReviewItems(
  context: ArtifactContext,
  signal?: AbortSignal,
) {
  requireInventoryPreparationContext(context);
  if (context.mode === "diff")
    return prepareCodexSecurityReviewItems(context, signal);

  const destination = await artifactDestination(
    context,
    preflightComponents,
    label,
  );
  const suffix = randomUUID();
  const scopesFile = `${destination}.${suffix}.scopes.json`;
  const output = `${destination}.${suffix}.tmp`;
  try {
    await writeFile(scopesFile, JSON.stringify(authoritativeScope(context)), {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
      signal,
    });
    await runInventoryHelper(
      context,
      [
        "make-repo-scope-input",
        `--repo=${context.repoRoot}`,
        `--scopes-file=${scopesFile}`,
        `--out=${output}`,
      ],
      signal,
    );
    const reviewItemsTotal = parsePreflightItems(
      await readFile(output, { encoding: "utf8", signal }),
    ).length;
    signal?.throwIfAborted();
    return { reviewItemsTotal };
  } finally {
    await Promise.all([
      rm(scopesFile, { force: true }),
      rm(output, { force: true }),
    ]);
  }
}

function requireInventoryPreparationContext(context: ArtifactContext): void {
  if (context.layout !== "scan") {
    throw new Error(
      `${label}: only a parent scan can prepare its shared inventory.`,
    );
  }
  if (!context.pluginRoot) {
    throw new Error(`${label}: the scan has no bound plugin context.`);
  }
}

async function runInventoryHelper(
  context: ArtifactContext,
  arguments_: string[],
  signal?: AbortSignal,
): Promise<void> {
  try {
    signal?.throwIfAborted();
    if (arguments_.some((argument) => argument.includes("\0")))
      throw new TypeError("Process arguments must not contain NUL bytes");
    const helper = join(context.pluginRoot!, "mcp", "helpers.mjs");
    const home = environmentValue("HOME");
    const windows = process.platform === "win32";
    const input = windows
      ? undefined
      : Buffer.from(
          encodePosixPath(
            [home === undefined ? "" : "1", home ?? "", ...arguments_, ""].join(
              "\0",
            ),
          ).toString("hex"),
        );
    const result = await runTool(
      process.execPath,
      windows ? [helper, ...arguments_] : [helper, "--helper"],
      // Relative NODE_OPTIONS preloads use the MCP process's current directory.
      undefined,
      input,
      windows ? 0 : 3,
      signal,
    );
    if (result.status !== 0)
      throw new Error(
        result.stderr.trim() ||
          (result.signal
            ? `Inventory helper terminated by ${result.signal}`
            : `Inventory helper exited with status ${result.status}`),
      );
  } catch (error) {
    if (signal?.aborted) throw error;
    const details = error instanceof Error ? error.message : String(error);
    throw new Error(
      `${label}: the scan inventory helper failed${details ? `: ${details}` : "."}`,
      { cause: error },
    );
  }
}

function authoritativeScope(context: ArtifactContext): {
  paths: string[];
  filePaths?: string[];
} {
  const scope = context.targetContract?.scope;
  if (scope === undefined) return { paths: [context.scope ?? "."] };
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    throw new Error(`${label}: the authoritative scope is invalid.`);
  }
  const saved = scope as Record<string, unknown>;
  const includePaths = saved.requiredIncludePaths;
  if (includePaths === undefined) return { paths: [context.scope ?? "."] };
  if (
    !Array.isArray(includePaths) ||
    includePaths.length === 0 ||
    includePaths.some((entry) => typeof entry !== "string" || !entry)
  ) {
    throw new Error(
      `${label}: the authoritative included scope must contain a nonempty array of paths.`,
    );
  }
  const paths = [...new Set(includePaths)];
  const filePaths = saved.filePaths;
  if (filePaths === undefined) return { paths };
  if (
    !Array.isArray(filePaths) ||
    filePaths.some(
      (entry) => typeof entry !== "string" || !entry || !paths.includes(entry),
    )
  ) {
    throw new Error(`${label}: the authoritative file scope is invalid.`);
  }
  return { paths, filePaths: [...new Set(filePaths)] };
}

/** Return bounded source paths from the fixed scan or worker inventory. */
export async function listCodexSecurityReviewItems(
  context: ArtifactContext,
  page: ArtifactPage = {},
) {
  const result = paginateArtifactRows(
    await readReviewItems(context),
    page,
    label,
  );
  return {
    items: result.rows,
    ...(result.nextCursor ? { nextCursor: result.nextCursor } : {}),
  };
}

async function readReviewItems(
  context: ArtifactContext,
): Promise<ReviewItem[]> {
  const path = await artifactSourcePath(context, inventoryComponents, label);
  const contents = await readFile(path).catch((error: unknown) => {
    throw new Error(
      `${label}: the requested artifact cannot be read: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  });
  const source =
    process.platform === "win32"
      ? decodeUtf8(contents)
      : decodePosixBytes(contents);
  const rows: ReviewItem[] = [];

  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    if (!line) continue;

    const parsed = reviewItemSchema.safeParse({ path: line });
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const correction = issue?.message ? `: ${issue.message}` : ".";
      throw new Error(
        `${label}: inventory row ${index + 1} has an unsafe repository path${correction}`,
      );
    }
    rows.push(parsed.data);
  }

  return rows;
}

function parsePreflightItems(source: string): ReviewItem[] {
  const rows: ReviewItem[] = [];
  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    if (!line) continue;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new Error(
        `${label}: source preflight row ${index + 1} is invalid.`,
      );
    }
    const parsed = reviewItemSchema.safeParse(value);
    if (!parsed.success) {
      throw new Error(
        `${label}: source preflight row ${index + 1} has an unsafe repository path.`,
      );
    }
    rows.push(parsed.data);
  }
  return rows;
}
