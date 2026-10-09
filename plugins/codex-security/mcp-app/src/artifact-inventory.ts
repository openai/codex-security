import { readFile } from "node:fs/promises";
import * as z from "zod/v4";
import { join } from "node:path";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import reviewItemsSchema from "../../schemas/tools/review-items.schema.json";
import {
  artifactDestination,
  artifactSourcePath,
  paginateArtifactRows,
  type ArtifactContext,
  type ArtifactPage,
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";
import { decodeUtf8 } from "./helpers/utf8.js";
import { runTool } from "./helpers/inventory-git";
import { environmentValue } from "./helpers/helper-files";
import { encodePosixPath } from "./helpers/posix-path";

const documents = [commonSchema, reviewItemsSchema] as SchemaDocument[];
const inventoryComponents = ["artifacts", "02_discovery", "in_scope_files.txt"];
const label = "review_items";

export interface ReviewItem {
  path: string;
}

export const prepareReviewItemsInputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "prepareInput",
) as z.ZodType<{ scanId: string; handoffClaimToken?: string }>;

export const reviewItemsReaderInputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "reviewItemsInput",
) as z.ZodType<{ scanId: string; handoffClaimToken?: string } & ArtifactPage>;

const reviewItemSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "reviewItem",
) as z.ZodType<ReviewItem>;

/** Build the selected repository or diff inventory from host-bound scan context. */
export async function prepareCodexSecurityReviewItems(
  context: ArtifactContext,
) {
  if (context.layout !== "scan") {
    throw new Error(
      `${label}: only a parent scan can prepare its shared inventory.`,
    );
  }
  if (!context.pluginRoot) {
    throw new Error(`${label}: the scan has no bound plugin context.`);
  }

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

  try {
    if (arguments_.some((argument) => argument.includes("\0")))
      throw new TypeError("Process arguments must not contain NUL bytes");
    const helper = join(context.pluginRoot, "mcp", "helpers.mjs");
    const home = environmentValue("HOME");
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
      windows ? process.execPath : "/bin/sh",
      windows
        ? [helper, ...arguments_]
        : [
            "-c",
            'exec "$1" "$2" --helper 3<&0 0</dev/null',
            "inventory-helper",
            process.execPath,
            helper,
          ],
      // Relative NODE_OPTIONS preloads use the MCP process's current directory.
      undefined,
      input,
    );
    if (result.status !== 0)
      throw new Error(
        result.stderr.trim() ||
          (result.signal
            ? `Inventory helper terminated by ${result.signal}`
            : `Inventory helper exited with status ${result.status}`),
      );
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    throw new Error(
      `${label}: the scan inventory helper failed${details ? `: ${details}` : "."}`,
      { cause: error },
    );
  }

  return { reviewItemsTotal: (await readReviewItems(context)).length };
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
  const source = decodeUtf8(contents);
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
