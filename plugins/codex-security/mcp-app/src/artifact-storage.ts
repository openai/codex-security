import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import * as z from "zod/v4";
import {
  readArtifactBytes,
  requireArtifactRoot,
  type ArtifactContext
} from "./artifact-io.js";
import type { RunArtifactWorkbench } from "./artifact-context.js";
import { handoffClaimTokenSchema } from "./server/handoff-tools.js";

const locationShape = {
  scanId: z.string().uuid().optional(),
  targetPath: z.string().min(1).optional(),
  handoffClaimToken: handoffClaimTokenSchema.optional(),
  storage: z.enum(["temporary", "persistent"]),
  path: z.string().min(1).optional()
};

export const saveArtifactInputSchema = z.object({
  ...locationShape,
  content: z.string().optional(),
  sourcePath: z.string().min(1).optional()
}).strict();

export const readArtifactInputSchema = z.object({
  ...locationShape,
  path: z.string().min(1),
  encoding: z.enum(["utf8", "base64"]).default("utf8")
}).strict();

export type ArtifactLocation = z.infer<typeof saveArtifactInputSchema>;

/** Keep plugin defaults aligned with the SDK without changing SDK-owned outputs. */
export function persistentScanRoot(pluginRoot: string, environment: NodeJS.ProcessEnv = process.env): string {
  const configured = environment.CODEX_SECURITY_SCAN_ROOT?.trim();
  if (configured) return expandHome(configured, pluginRoot);
  const state = environment.CODEX_SECURITY_STATE_DIR?.trim();
  return join(state ? expandHome(state, pluginRoot) : join(
    expandHome(environment.CODEX_HOME?.trim() || join(homedir(), ".codex"), pluginRoot),
    "state", "plugins", "codex-security"
  ), "scans");
}

function expandHome(value: string, base: string): string {
  return resolve(base, value === "~" ? homedir()
    : /^~[/\\]/.test(value) ? join(homedir(), value.slice(2)) : value);
}

/** Standalone phase documents share a target-bound collection, not a running scan. */
export async function standaloneArtifactContext(
  targetPath: string,
  runWorkbench: RunArtifactWorkbench,
  create: boolean,
  scanRoot: string,
  storage: ArtifactLocation["storage"]
): Promise<ArtifactContext> {
  const target = await runWorkbench(["inspect-target", "--target-path", targetPath]);
  if (typeof target.targetPath !== "string") throw new Error("Missing artifact target.");
  const repoRoot = await fs.realpath(target.targetPath);
  const name = basename(repoRoot).replace(/[^a-zA-Z0-9._-]+/g, "-") || "repository";
  const identity = createHash("sha256").update(repoRoot).digest("hex");
  const root = join(scanRoot, name, `artifacts-${identity}`);
  if (storage === "temporary") {
    // Resolve existing ancestors for stable imports without creating or requiring
    // the persistent collection. storageContext prepares the temporary root.
    return { root: await resolveStoragePath(root), repoRoot, layout: "scan" };
  }
  const existingRoot = await fs.realpath(scanRoot).catch(() => scanRoot);
  if (existingRoot === repoRoot || existingRoot.startsWith(repoRoot + sep)) {
    throw new Error("Artifact storage must be outside the target repository.");
  }
  if (create) await fs.mkdir(root, { recursive: true, mode: 0o700 });
  return { root: await requireArtifactRoot(root, "Standalone artifacts"), repoRoot, layout: "scan" };
}

async function resolveStoragePath(path: string): Promise<string> {
  try {
    return await fs.realpath(path);
  } catch {
    const parent = dirname(path);
    return parent === path ? path : join(await resolveStoragePath(parent), basename(path));
  }
}

async function storageContext(
  context: ArtifactContext,
  storage: ArtifactLocation["storage"],
  create: boolean
): Promise<ArtifactContext> {
  if (storage === "persistent") return context;
  const identity = createHash("sha256").update(context.root).digest("hex");
  const root = join(await fs.realpath(tmpdir()), `codex-security-artifacts-${identity}`);
  if (create) await fs.mkdir(root, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "EEXIST") throw error;
  });
  return { ...context, root };
}

function components(path: string): string[] {
  const parts = path.split("/");
  if (parts.some((part) => !part || part === "." || part === ".."
    || /[<>:"\\|?*\x00-\x1f]/.test(part) || /[. ]$/.test(part)
    || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) {
    throw new Error("Artifact path must be a portable relative file path.");
  }
  return parts;
}

function supplementalPath(input: ArtifactLocation, context: ArtifactContext): string[] {
  const parts = components(input.path!);
  if (input.storage === "temporary") return parts;
  const path = parts.join("/").toLowerCase();
  const allowed = (parts.length > 1 && ["artifacts", "findings", "hardening"].includes(parts[0]!))
    || path === "report_validation.md" || (!context.scanId && path === "threat_model.md");
  if (!allowed || path === "artifacts/deep_discovery" || path.startsWith("artifacts/deep_discovery/")
    || path === "artifacts/02_discovery/candidate_ledger.jsonl"
    || path === "artifacts/02_discovery/in_scope_files.txt"
    || path === "artifacts/01_context/false_positive_feedback.json") {
    throw new Error("Use the existing scan tools for canonical artifacts, ledgers and checkpoints.");
  }
  return parts;
}

export async function saveCodexSecurityArtifact(
  context: ArtifactContext,
  input: z.infer<typeof saveArtifactInputSchema>,
  runWorkbench: RunArtifactWorkbench
): Promise<Record<string, unknown>> {
  const hasContent = input.content !== undefined;
  const hasSource = input.sourcePath !== undefined;
  if (input.path === undefined ? hasContent || hasSource : hasContent === hasSource) {
    throw new Error("Omit path to prepare the directory, or provide path and exactly one of content or sourcePath.");
  }
  const parts = input.path === undefined ? undefined : supplementalPath(input, context);
  const selected = await storageContext(context, input.storage, true);
  selected.root = await requireArtifactRoot(selected.root, "Artifact storage");
  if (!parts) return { storage: input.storage, directory: selected.root };

  let bytes: Buffer;
  if (input.sourcePath !== undefined) {
    if (input.storage !== "persistent") throw new Error("Import retained files into persistent storage.");
    const scratch = await storageContext(context, "temporary", false);
    const source = relative(scratch.root, resolve(input.sourcePath));
    if (isAbsolute(source) || source === ".." || source.startsWith(".." + sep)) {
      throw new Error("Import source must be inside this artifact context's temporary directory.");
    }
    bytes = await readArtifactBytes(scratch, components(source.split(sep).join("/")), "Artifact import");
  } else {
    bytes = Buffer.from(input.content!, "utf8");
  }
  const destination = join(selected.root, ...parts);
  if (input.storage === "persistent" && context.scanId) {
    await runWorkbench([
      "save-scan-artifact", "--scan-id", context.scanId,
      "--artifact-path", parts.join("/"),
      ...(context.handoffClaimToken ? ["--claim-token", context.handoffClaimToken] : [])
    ], bytes);
  } else {
    await runWorkbench([
      "save-artifact", "--artifact-root", selected.root, "--artifact-path", parts.join("/")
    ], bytes);
  }
  return {
    storage: input.storage,
    directory: selected.root,
    path: destination,
    relativePath: parts.join("/"),
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

export async function readCodexSecurityArtifact(
  context: ArtifactContext,
  input: z.infer<typeof readArtifactInputSchema>
): Promise<Record<string, unknown>> {
  const parts = supplementalPath(input, context);
  const selected = await storageContext(context, input.storage, false);
  const bytes = await readArtifactBytes(selected, parts, "Saved artifact");
  return {
    storage: input.storage,
    directory: selected.root,
    path: join(selected.root, ...parts),
    relativePath: parts.join("/"),
    encoding: input.encoding,
    content: bytes.toString(input.encoding)
  };
}
