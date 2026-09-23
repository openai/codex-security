import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as z from "zod/v4";
import { CodexSdkWorkerExecutor } from "../deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../deep-scan/parent-sandbox.js";
import type { CodexWorkerExecutor } from "../deep-scan/types.js";

export interface DependencyEstimationSetup {
  targetPath: string;
  scope: string;
  mode: "diff" | "standard" | "deep" | "dependency_update" | "full_dependency";
  diffTarget?: {
    kind: "working_tree" | "commit" | "range";
    baseRevision?: string;
    headRevision?: string;
    contentDigest?: string;
  };
}

interface DependencyEstimationOptions {
  pluginRoot: string;
  setup: DependencyEstimationSetup;
  parentSandbox: DeepWorkerParentSandbox;
  modelSettings?: { model?: string; reasoningEffort?: string };
  signal?: AbortSignal;
  executor?: CodexWorkerExecutor;
}

const dependencyEstimateSchema = z
  .object({
    depthCounts: z.array(z.number().int().nonnegative()),
  })
  .strict();

export async function estimateDependencyDepthCounts(
  options: DependencyEstimationOptions,
): Promise<{ depthCounts: number[] }> {
  const signal = options.signal ?? new AbortController().signal;
  signal.throwIfAborted();

  const temporaryDirectory = await fs.mkdtemp(
    join(tmpdir(), "codex-security-dependency-estimate-"),
  );
  try {
    const promptPath = join(temporaryDirectory, "dependency-estimation.md");
    await fs.writeFile(promptPath, estimationPrompt(options), { mode: 0o600 });
    const executor =
      options.executor ??
      new CodexSdkWorkerExecutor({
        ...options.modelSettings,
        parentSandbox: options.parentSandbox,
      });
    const result = await executor.run({
      kind: "discovery",
      promptPath,
      workingDirectory: options.setup.targetPath,
      subagents: 0,
      signal,
    });

    let parsed: unknown;
    try {
      parsed = JSON.parse(result.finalResponse);
    } catch (error) {
      const unavailable = result.finalResponse
        .trim()
        .startsWith("Dependency estimation unavailable:");
      throw new Error(
        unavailable
          ? "Dependency estimation could not run: the required package-manager resolver or installed-tree tool is unavailable or could not establish the exact selected offline dependency tree."
          : "Dependency estimation did not return an exact package-depth histogram.",
        { cause: error },
      );
    }
    const estimate = dependencyEstimateSchema.safeParse(parsed);
    if (!estimate.success) {
      throw new Error(
        "Dependency estimation did not return an exact package-depth histogram.",
      );
    }
    return estimate.data;
  } finally {
    await fs.rm(temporaryDirectory, { force: true, recursive: true });
  }
}

function estimationPrompt(options: DependencyEstimationOptions): string {
  const skillPath = join(
    options.pluginRoot,
    "skills",
    "dependency-resolution",
    "SKILL.md",
  );
  return [
    "Calculate the exact published-artifact dependency-depth histogram as quickly as possible for the authorized local setup below.",
    `Read and follow the dependency-resolution skill at ${JSON.stringify(skillPath)}.`,
    `The validated setup is ${JSON.stringify(options.setup)}.`,
    "This is a trusted top-level, read-only dependency-count calculation, not an artifact scan. Skip the artifact-recursion environment check entirely; invoke the native resolver immediately.",
    "After identifying the appropriate ecosystem-native package-manager dependency-resolution or installed-tree tool, use your FIRST Bash tool invocation to run that native resolver immediately in offline, read-only mode.",
    "If its output establishes the exact complete effective dependency graph, mechanically calculate the package-depth histogram and return the required JSON immediately.",
    "Do not narrate progress or perform separate integrity, hash, provenance, project/user/global/system configuration, manifest, revision, metadata, registry, source, tool-availability, or preflight checks unless the native resolver fails or its output cannot establish the exact required graph.",
    "Classify public, private, and workspace dependencies using only the native resolver's already-emitted graph and source identity; published-artifact acquisition owns independent integrity and provenance verification.",
    "Dependency calculation is strictly offline; only if fallback inspection is required after the native resolver fails or its output proves insufficient, inspect only already-existing local repository manifests, lockfiles, workspace/build metadata, and local Git objects for the exact checked-in revisions or selected working-tree snapshot.",
    "Only if native resolver output is insufficient, read already-existing installed package metadata and hidden or ignored package-manager lockfiles in read-only mode only when they correspond to the exact selected current dependency snapshot and workspace; unrelated source-only working-tree changes do not invalidate matching installed dependency state; for historical Git revisions, use only revision-matching evidence and never substitute current installed state.",
    "Use Bash to invoke the ecosystem's actual package-manager dependency-resolution or installed-tree tooling, or its documented native resolver library/API, in strictly offline, read-only mode; machine-compute the exact version-qualified direct and transitive dependency graph, shortest dependency depths, and package-count histogram exclusively from actual package-manager tool or native resolver output.",
    "Require the same effective dependency tree the repository's package manager actually sees, including hoisting, peer and optional dependencies, workspaces, aliases, platform selection, and lockfile or installation policy.",
    "Never manually reconstruct a dependency graph or use an ad-hoc, hand-written, or generic lockfile graph parser or traversal; local scripts are permitted only when they invoke the ecosystem's documented native resolver library/API and mechanically process its actual output.",
    "A package-manager inspection command is permitted only when offline and read-only, without repository, installed-state, cache, or log writes. Do not contact package registries or network services, fetch or download remote metadata, install dependencies, update lockfiles, or mutate repository files or local installed state; these offline restrictions override optional registry-query guidance in the general dependency-resolution skill.",
    "If the required package-manager resolver or installed-tree tooling is unavailable, cannot run offline and read-only, or cannot establish the exact selected snapshot, explicitly report the blocker as `Dependency estimation unavailable: <resolver or tooling reason>`; include no package identities, repository paths, URLs, credentials, or secrets, and never return guessed, inferred, stale, or inconsistent counts.",
    "Never mentally calculate, infer, approximate, or guess package identities, versions, graph edges, dependency depths, or counts.",
    "Resolve the complete relevant dependency graph across every ecosystem and workspace actually present, preserving the exact repository scope and, for a change review, the exact provided Git revisions or working-tree content digest.",
    "Count only public package versions eligible for the existing published-artifact scan: the complete current graph for repository scans, or actual additions and version changes for change scans.",
    "Deduplicate using the complete normalized ecosystem, registry, package, oldVersion, and newVersion identity. Never merge different versions of the same package.",
    "For each eligible identity, derive its shortest real dependency chain from a first-party project or workspace; a direct dependency has depth one. Do not infer depth from dependency-type labels, invent graph edges, or substitute a different revision.",
    'Return only a JSON object shaped exactly like {"depthCounts":[24,149,226]}. Array index zero is depth one, every later index is its actual depth, and zero-count intermediate depths remain present.',
    'For a resolver-confirmed empty graph, return {"depthCounts":[]}. If an identity or real chain cannot be established, explain the blocker instead of inventing an estimate.',
    "Do not start or submit a security scan, perform advisory checks, create findings, modify the repository, or include package identities, paths, or dependency chains in your final response.",
  ].join("\n");
}
