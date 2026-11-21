import { createHash } from "node:crypto";
import { posix } from "node:path";
import { z } from "zod";
import {
  dependencyPathExcluded,
  type DependencyDiscoveryBoundary,
} from "./dependency-caller-scope.js";
import type { DependencyPackage } from "./dependency-advisory.js";
import {
  readNpmManifests,
  readPythonRequirements,
  pythonDistributionName,
  type DependencyManifest,
} from "./dependency-manifests.js";
import {
  traceDependencyCalls,
  type DependencyTrace,
  type TraceSource,
} from "./dependency-source-trace.js";
import { gitOutput } from "./targets.js";
import { isRecord } from "./record.js";

const runtimeObservation = z.strictObject({
  service: z.string().min(1),
  package: z.strictObject({
    ecosystem: z.string().min(1),
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  revision: z
    .string()
    .regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u)
    .optional(),
  coverage: z.enum(["complete", "partial", "unknown"]),
  evidence: z.string().trim().min(1),
  access: z
    .strictObject({
      caller: z.string().trim().min(1),
      evidence: z.string().trim().min(1),
    })
    .optional(),
});

export interface RuntimeReceiptInput {
  source: string;
  payload: string;
}
export interface RuntimeReceipt extends RuntimeReceiptInput {
  sha256: string;
  observation?: z.infer<typeof runtimeObservation>;
}

export interface DependencyCaller {
  path: string;
  line: number;
  project?: string;
  manifest?: string;
  version?: string;
}
export interface RepositoryDiscovery {
  revision: string;
  package: DependencyPackage;
  manifests: DependencyManifest[];
  callers: DependencyCaller[];
  dependencyFiles: string[];
  sourceLeads?: string[];
  buildFiles: string[];
  traces: DependencyTrace[];
  runtime: RuntimeReceipt[];
  coverage: { status: "partial" | "unknown"; gaps: string[] };
}

function regexEscape(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
function samePackage(left: DependencyPackage, right: DependencyPackage) {
  const normalize = (pkg: DependencyPackage) =>
    pkg.ecosystem === "PyPI" ? pythonDistributionName(pkg.name) : pkg.name;
  return (
    left.ecosystem === right.ecosystem && normalize(left) === normalize(right)
  );
}
function readReceipt(
  input: RuntimeReceiptInput,
  pkg: DependencyPackage,
): RuntimeReceipt {
  const receipt = {
    source: input.source,
    payload: input.payload,
    sha256: createHash("sha256").update(input.payload).digest("hex"),
  };
  let value: unknown;
  try {
    value = JSON.parse(input.payload);
  } catch {
    return receipt;
  }
  const result = runtimeObservation.safeParse(value);
  return result.success && samePackage(result.data.package, pkg)
    ? { ...receipt, observation: result.data }
    : receipt;
}

function knownDependencyFile(path: string) {
  return /^(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(?:\.lock)?|requirements[^/]*\.(?:txt|in|lock)|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|pom\.xml|Gemfile(?:\.lock)?)$/iu.test(
    posix.basename(path),
  );
}

const sourcePath =
  /\.(?:[cm]?[jt]sx?|py|go|rs|rb|java|kt|php|swift|c|cc|cpp|cs)$/iu;
const buildPath =
  /^(?:Dockerfile(?:\..+)?|Containerfile(?:\..+)?|.+\.(?:Dockerfile|Containerfile)|(?:docker-)?compose(?:\..+)?\.ya?ml)$/iu;

function sourceReferences(
  path: string,
  text: string,
  pkg: DependencyPackage,
  symbols: readonly string[],
) {
  const bindings = new Set<string>();
  const lines: number[] = [];
  const python = path.endsWith(".py") && pkg.ecosystem === "PyPI";
  const javascript = /\.[cm]?[jt]sx?$/iu.test(path) && pkg.ecosystem === "npm";
  if (!python && !javascript) return { lines, bindings: [] };
  const roots = new Set([
    pkg.name.replace(/-/gu, "_"),
    ...symbols
      .map((symbol) => symbol.split(".")[0]!)
      .filter((s) => /^[A-Za-z_]\w*$/u.test(s)),
  ]);
  const pattern = python
    ? new RegExp(
        `^\\s*(?:from|import)\\s+(?:${[...roots].map(regexEscape).join("|")})(?:[.\\s,]|$)`,
        "iu",
      )
    : new RegExp(
        `(?:\\bfrom\\s*|\\b(?:import|require)\\s*\\(\\s*|\\bimport\\s*)["']${regexEscape(pkg.name)}(?:/[^"']*)?["']`,
        "u",
      );
  for (const [index, line] of text.split(/\r?\n/u).entries()) {
    if (!pattern.test(line)) continue;
    lines.push(index + 1);
    const local = python
      ? line.match(/\bimport\s+(\w+)(?:\s+as\s+(\w+))?/u)
      : line.match(
          /\bimport\s+(?:\*\s+as\s+)?([\w$]+)|\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\b/u,
        );
    if (local) bindings.add(local[2] ?? local[1]!);
    if (!python) {
      const names = /\bimport\s*\{([^}]*)\}/u.exec(line)?.[1];
      for (const name of names?.split(",") ?? []) {
        const localName = name
          .trim()
          .split(/\s+as\s+/u)
          .at(-1);
        if (localName) bindings.add(localName);
      }
    }
  }
  return { lines, bindings: [...bindings] };
}

/** Discover candidates at a single commit. An import, version pin or scanner hit alone proves no deployment or reachability. */
export async function discoverDependencyRepository(options: {
  repository: string;
  revision?: string;
  package: DependencyPackage;
  symbols?: readonly string[];
  runtimeReceipts?: readonly RuntimeReceiptInput[];
  callerBoundary?: DependencyDiscoveryBoundary;
  environment?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}): Promise<RepositoryDiscovery> {
  const { package: pkg, signal } = options;
  if (!pkg.name.trim() || !pkg.ecosystem.trim())
    throw new Error("Expected a package name and ecosystem.");
  const symbols = options.symbols ?? [];
  const localGit = {
    GIT_NO_LAZY_FETCH: "1",
    GIT_ALLOW_PROTOCOL: "",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
  };
  const repository = await gitOutput(
    options.repository,
    ["rev-parse", "--show-toplevel"],
    signal,
    localGit,
  );
  const revision = await gitOutput(
    repository,
    [
      "rev-parse",
      "--verify",
      "--end-of-options",
      `${options.revision ?? "HEAD"}^{commit}`,
    ],
    signal,
    localGit,
  );
  const tree = await gitOutput(
    repository,
    ["ls-tree", "-r", "-z", revision],
    signal,
    localGit,
  );
  const blobs = new Map<string, string>();
  const searchPatterns = new Set<string>();
  const policyPaths = new Set<string>();
  for (const record of tree.split("\0")) {
    const policy =
      /^(?:100(?:644|755)|120000) blob [a-f0-9]+\t((?:[\s\S]*\/)?SECURITY\.md)$/u.exec(
        record,
      );
    if (policy) policyPaths.add(policy[1]!);
    const entry = /^100(?:644|755) blob ([a-f0-9]+)\t([\s\S]+)$/u.exec(record);
    if (!entry) continue;
    const path = entry[2]!;
    const base = posix.basename(path);
    const source = sourcePath.test(path);
    if (
      !source &&
      !knownDependencyFile(base) &&
      !buildPath.test(base) &&
      base !== "bun.lockb"
    )
      continue;
    if (path.split("/").includes("node_modules")) continue;
    blobs.set(path, entry[1]!);
    // Only ask Git to decompress file types used below. Derive the path
    // patterns from the admitted paths, including their original casing.
    const suffix = source ? base.slice(base.lastIndexOf(".")) : base;
    if (source) searchPatterns.add("*" + suffix);
    else if (/^requirements/iu.test(base))
      searchPatterns.add(":(icase)*requirements*");
    else if (buildPath.test(base))
      searchPatterns.add(
        /dockerfile/iu.test(base)
          ? ":(icase)*dockerfile*"
          : /containerfile/iu.test(base)
            ? ":(icase)*containerfile*"
            : ":(icase)*compose*",
      );
    else searchPatterns.add("*" + suffix);
  }
  const paths = new Set(blobs.keys());
  const inBoundary = (path: string) =>
    !options.callerBoundary ||
    !dependencyPathExcluded(path, policyPaths, options.callerBoundary);
  const read = async (path: string) =>
    gitOutput(
      repository,
      ["cat-file", "blob", blobs.get(path)!],
      signal,
      localGit,
      repository,
      "buffer",
    );

  // Use Git's object database for both search and snippets, including a dirty checkout.
  const needles = new Set([pkg.name]);
  if (pkg.ecosystem === "PyPI") {
    needles.add(pkg.name.replace(/-/gu, "_"));
    for (const symbol of symbols)
      if (symbol.includes(".")) needles.add(symbol.split(".")[0]!);
  }
  let matches: string[] = [];
  try {
    const output = await gitOutput(
      repository,
      [
        "grep",
        "--full-name",
        pkg.ecosystem === "PyPI" ? "-E" : "-F",
        "-I",
        "-l",
        "-z",
        ...(pkg.ecosystem === "PyPI" ? ["-i"] : []),
        ...[...needles].filter(Boolean).flatMap((value) => [
          "-e",
          pkg.ecosystem === "PyPI"
            ? value
                .split(/[-_.]+/u)
                .map(regexEscape)
                .join("[-_.]+")
            : value,
        ]),
        revision,
        "--",
        ...searchPatterns,
      ],
      signal,
      localGit,
    );
    matches = output
      .split("\0")
      .filter((p) => p.startsWith(revision + ":"))
      .map((p) => p.slice(revision.length + 1))
      .filter((p) => paths.has(p) && inBoundary(p));
  } catch (error) {
    signal?.throwIfAborted();
    if (!isRecord(error) || error["code"] !== 1) throw error;
  }
  const gaps: string[] = [];
  const dependencyFiles = matches.filter(knownDependencyFile);
  const readText = async (path: string) => (await read(path)).toString("utf8");
  const manifests =
    pkg.ecosystem === "npm"
      ? await readNpmManifests(
          paths,
          dependencyFiles.filter((p) => posix.basename(p) === "package.json"),
          pkg.name,
          readText,
          gaps,
        )
      : pkg.ecosystem === "PyPI"
        ? await readPythonRequirements(
            dependencyFiles,
            pkg.name,
            readText,
            gaps,
          )
        : [];
  if (!manifests.length)
    gaps.push(
      "A requesting manifest and installed dependency copy were not established.",
    );
  const projects = new Map(manifests.map((m) => [m.path, m]));
  const callers: DependencyCaller[] = [];
  const sources: TraceSource[] = [];
  for (const path of matches.filter(
    (p) =>
      (pkg.ecosystem === "PyPI" && p.endsWith(".py")) ||
      (pkg.ecosystem === "npm" && /\.[cm]?[jt]sx?$/iu.test(p)),
  )) {
    const bytes = await read(path);
    const { lines, bindings } = sourceReferences(
      path,
      bytes.toString("utf8"),
      pkg,
      symbols,
    );
    if (!lines.length) continue;
    let directory = posix.dirname(path);
    let owner: DependencyManifest | undefined;
    while (true) {
      const manifest = posix.join(directory, "package.json");
      if (pkg.ecosystem === "npm" && paths.has(manifest)) {
        owner = projects.get(manifest);
        break;
      }
      if (pkg.ecosystem === "PyPI") {
        const primary = ["requirements.txt", "requirements.lock"]
          .map((base) => posix.join(directory, base))
          .filter((p) => paths.has(p) && inBoundary(p));
        if (
          primary.length ||
          paths.has(posix.join(directory, "pyproject.toml"))
        ) {
          if (primary.length === 1) owner = projects.get(primary[0]!);
          break;
        }
      }
      if (directory === ".") break;
      directory = posix.dirname(directory);
    }
    if (!owner)
      gaps.push(
        `The build or manifest that owns the caller in ${path} is unresolved.`,
      );
    for (const line of lines)
      callers.push({
        path,
        line,
        ...(owner && {
          project: owner.project,
          manifest: owner.path,
          ...(owner.selection && { version: owner.selection.version }),
        }),
      });
    sources.push({ path, bytes, bindings });
  }
  if (!callers.length)
    gaps.push(
      "No direct importing caller was identified from these package and symbol names.",
    );
  const inspected = new Set(sources.map((source) => source.path));
  const sourceLeads = matches.filter(
    (path) => sourcePath.test(path) && !inspected.has(path),
  );
  if (sourceLeads.length)
    gaps.push(
      "Other source text matches need inspection before they can be identified as callers.",
    );
  const evidencePaths = [
    ...dependencyFiles,
    ...callers.map((c) => c.path),
    ...sourceLeads,
  ];
  const matchedPaths = new Set(matches);
  const buildFiles = [...paths]
    .filter((p) => buildPath.test(posix.basename(p)))
    .filter(inBoundary)
    .filter((p) => {
      const directory = posix.dirname(p);
      return (
        matchedPaths.has(p) ||
        directory === "." ||
        evidencePaths.some((source) => source.startsWith(directory + "/"))
      );
    });
  const { traces, gaps: traceGaps } = await traceDependencyCalls(
    repository,
    sources,
    symbols,
    options.environment ?? process.env,
    signal,
  );
  gaps.push(...traceGaps);
  const runtime = (options.runtimeReceipts ?? []).map((input) =>
    readReceipt(input, pkg),
  );
  if (!runtime.length) gaps.push("No runtime observations were supplied.");
  for (const receipt of runtime) {
    if (receipt.observation?.coverage !== "complete")
      gaps.push(
        `Runtime coverage from ${receipt.source} is ${receipt.observation?.coverage ?? "unknown"}.`,
      );
    if (receipt.observation && receipt.observation.revision !== revision)
      gaps.push(
        `The runtime observation from ${receipt.source} is not bound to this source revision.`,
      );
  }
  gaps.push(
    "Static import and call candidates do not establish dynamic callers, argument flow or deployment.",
  );
  return {
    revision,
    package: pkg,
    manifests,
    callers,
    dependencyFiles,
    ...(sourceLeads.length && { sourceLeads }),
    buildFiles,
    traces,
    runtime,
    coverage: {
      status:
        callers.length || manifests.length || runtime.some((r) => r.observation)
          ? "partial"
          : "unknown",
      gaps,
    },
  };
}
