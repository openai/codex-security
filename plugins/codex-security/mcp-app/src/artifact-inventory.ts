import { execFile as nodeExecFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";
import * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import reviewItemsSchema from "../../schemas/tools/review-items.schema.json";
import {
  artifactDestination,
  paginateArtifactRows,
  readArtifactText,
  type ArtifactContext,
  type ArtifactPage
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument
} from "./artifact-schema-loader.js";
import {
  missingPythonHelperMessage,
  resolvePythonCommand
} from "./python_command.js";

const execFile = promisify(nodeExecFile);
const documents = [commonSchema, reviewItemsSchema] as SchemaDocument[];
const inventoryComponents = ["artifacts", "02_discovery", "in_scope_files.txt"];
const label = "review_items";

export interface ReviewItem {
  path: string;
}

export interface ReviewItemsResult {
  items: ReviewItem[];
  nextCursor?: string;
}

export interface PreparedReviewItems {
  reviewItemsTotal: number;
}

export const prepareReviewItemsInputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "prepareInput"
) as z.ZodType<{ scanId: string; handoffClaimToken?: string }>;

export const prepareReviewItemsOutputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "prepareOutput"
) as z.ZodType<PreparedReviewItems>;

export const reviewItemsReaderInputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "reviewItemsInput"
) as z.ZodType<{ scanId: string; handoffClaimToken?: string } & ArtifactPage>;

export const reviewItemsWorkerReaderInputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "reviewItemsWorkerInput"
) as z.ZodType<ArtifactPage>;

export const reviewItemsReaderOutputSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "reviewItemsOutput"
) as z.ZodType<ReviewItemsResult>;

const reviewItemSchema = loadArtifactZodSchema(
  documents,
  reviewItemsSchema.$id,
  "reviewItem"
) as z.ZodType<ReviewItem>;

/** Build the selected repository or diff inventory from host-bound scan context. */
export async function prepareCodexSecurityReviewItems(
  context: ArtifactContext
): Promise<PreparedReviewItems> {
  if (context.layout !== "scan") {
    throw new Error(`${label}: only a parent scan can prepare its shared inventory.`);
  }
  if (!context.pluginRoot) {
    throw new Error(`${label}: the scan has no bound plugin context.`);
  }

  const destination = await artifactDestination(context, inventoryComponents, label);
  const pythonCommand = context.pythonCommand ?? await resolvePythonCommand();
  const helper = join(context.pluginRoot, "scripts", "generate_in_scope_files.py");
  const arguments_ = [
    helper,
    "--repo",
    context.repoRoot,
    "--scope",
    context.scope ?? ".",
    "--out",
    destination
  ];

  if (context.mode === "diff") {
    const target = context.targetContract?.diffTarget;
    if (!target || typeof target !== "object" || Array.isArray(target)) {
      throw new Error(`${label}: the diff scan has no authoritative change set.`);
    }
    const diffTarget = target as Record<string, unknown>;
    const { kind, baseRevision, headRevision } = diffTarget;
    if (
      (kind !== "working_tree" && kind !== "commit" && kind !== "range")
      || typeof baseRevision !== "string" || !baseRevision
      || typeof headRevision !== "string" || !headRevision
    ) {
      throw new Error(`${label}: the diff scan has an invalid authoritative change set.`);
    }
    arguments_.push(
      "--diff-base", baseRevision,
      "--diff-head", headRevision,
      "--diff-mode", kind === "working_tree" ? "local-patch" : "revisions"
    );
  }

  try {
    await execFile(
      pythonCommand,
      arguments_,
      {
        cwd: context.pluginRoot,
        encoding: "utf8",
        shell: false
      }
    );
  } catch (error) {
    const missingPython = missingPythonHelperMessage(error, pythonCommand);
    if (missingPython) {
      throw new Error(`${label}: ${missingPython}`, { cause: error });
    }
    const details = helperError(error);
    throw new Error(
      `${label}: the scan inventory helper failed${details ? `: ${details}` : "."}`,
      { cause: error }
    );
  }

  return { reviewItemsTotal: (await readReviewItems(context)).length };
}

/** Return bounded source paths from the fixed scan or worker inventory. */
export async function listCodexSecurityReviewItems(
  context: ArtifactContext,
  page: ArtifactPage = {}
): Promise<ReviewItemsResult> {
  const result = paginateArtifactRows(await readReviewItems(context), page, label);
  return {
    items: result.rows,
    ...(result.nextCursor ? { nextCursor: result.nextCursor } : {})
  };
}

async function readReviewItems(context: ArtifactContext): Promise<ReviewItem[]> {
  const source = await readArtifactText(context, inventoryComponents, label);
  const rows: ReviewItem[] = [];

  for (const [index, line] of source.split(/\r?\n/u).entries()) {
    if (!line) continue;

    const parsed = reviewItemSchema.safeParse({ path: line });
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const correction = issue?.message ? `: ${issue.message}` : ".";
      throw new Error(`${label}: inventory row ${index + 1} has an unsafe repository path${correction}`);
    }
    rows.push(parsed.data);
  }

  return rows;
}

function helperError(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("stderr" in error)) return undefined;
  const stderr = error.stderr;
  if (typeof stderr === "string") return stderr.trim() || undefined;
  if (Buffer.isBuffer(stderr)) return stderr.toString("utf8").trim() || undefined;
  return undefined;
}
