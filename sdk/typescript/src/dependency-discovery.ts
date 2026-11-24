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

// Keep source lines intact when excluding comments and literal text.
function newlinesIn(value: string): string {
  return value.replace(/[^\n]+/gu, "");
}

// Only package string literals survive as "@". Template expressions stay
// visible, since they can contain real calls to require() or import().
function javascriptCode(text: string, pkg: string): string {
  // Consume truncated literals too, so escaped quotes never restart the scan.
  const tokens =
    /\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|$)|'(?:\\[\s\S]|[^'\\\n])*'?|"(?:\\[\s\S]|[^"\\\n])*"?|[\w$]+|=>|\+\+|--|\s+|[^\s]/gu;
  const templateChunk = /(?:\\[\s\S]|[^`\\$]|\$(?!\{))*(?:`|\$\{)?/uy;
  const regexBody = /(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\[\n])+\/[a-z]*/uy;
  const templateDepth: number[] = [];
  let braces = 0;
  let previous = "";
  let regexAllowed = true;
  let code = "";
  for (let match; (match = tokens.exec(text));) {
    let token = match[0];
    if (token.startsWith("//") || token.startsWith("/*")) {
      code += " " + newlinesIn(token);
      continue;
    }
    if (!token.trim()) {
      code += token;
      continue;
    }
    if (token === "/" && regexAllowed) {
      regexBody.lastIndex = tokens.lastIndex;
      if (regexBody.test(text)) {
        tokens.lastIndex = regexBody.lastIndex;
        token = "0";
      }
    }
    if (token === "`" || (token === "}" && braces === templateDepth.at(-1))) {
      if (token === "}") templateDepth.pop();
      templateChunk.lastIndex = tokens.lastIndex;
      const chunk = templateChunk.exec(text)?.[0] ?? "";
      tokens.lastIndex += chunk.length;
      if (chunk.endsWith("${")) {
        templateDepth.push(braces);
        code += newlinesIn(chunk);
        token = ";";
      } else if (token === "}") {
        code += newlinesIn(chunk);
        token = ")";
      } else token += chunk;
    } else if (token === "{") braces++;
    else if (token === "}") braces--;

    if (/^['"`]/u.test(token)) {
      const value = token.slice(1, -1);
      const matches = value === pkg || value.startsWith(pkg + "/");
      code += matches && token.at(-1) === token[0] ? '"@"' : '""';
      code += newlinesIn(token);
      regexAllowed = false;
    } else {
      code += token;
      regexAllowed =
        previous !== "." &&
        /^(?:[=(:,;!?&|{\[~*+%-]|=>|await|case|delete|in|instanceof|new|of|return|throw|typeof|void|yield)$/u.test(
          token,
        );
    }
    previous = token;
  }
  return code;
}

function pythonCode(text: string): string {
  const code = text.replace(
    /#[^\n]*|'''(?:\\[\s\S]|(?!''')[^\\])*(?:''')?|"""(?:\\[\s\S]|(?!""")[^\\])*(?:""")?|'(?:\\[\s\S]|[^'\\\n])*'?|"(?:\\[\s\S]|[^"\\\n])*"?/gu,
    (token) => " " + newlinesIn(token),
  );
  if (!/\b(?:from|import)[ \t]+typing(?:_extensions)?\b/u.test(code))
    return code;
  let guardIndent = Infinity;
  return code
    .split("\n")
    .map((line) => {
      const indent = line.search(/\S/u);
      if (indent < 0 || indent > guardIndent) return "";
      guardIndent =
        /^\s*(?:if|elif)\s+(?:typing\.)?TYPE_CHECKING\s*:\s*$/u.test(line)
          ? indent
          : Infinity;
      return line;
    })
    .join("\n");
}

function importNames(clause: string) {
  return clause
    .replace(/[{}]/gu, "")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
}

// Both an ES import and a destructured require can bind an alias.
function localNames(names: string[]) {
  return names.flatMap((name) => {
    const binding = name.split("=", 1)[0]!.trim();
    const local = /(?:^|\bas\s+|:\s*|\.\.\.\s*)([A-Za-z_$][\w$]*)$/u.exec(
      binding,
    );
    return local ? [local[1]!] : [];
  });
}

/** @internal */
export function sourceReferences(
  path: string,
  text: string,
  pkg: DependencyPackage,
  symbols: readonly string[],
) {
  const python = path.endsWith(".py") && pkg.ecosystem === "PyPI";
  const javascript =
    pkg.ecosystem === "npm" &&
    /\.[cm]?[jt]sx?$/iu.test(path) &&
    !/\.d\.[cm]?ts$/iu.test(path);
  if (!python && !javascript) return { lines: [], bindings: [] };

  const matches: { offset: number; bindings: string[] }[] = [];
  text = text.replace(/\r\n/gu, "\n");
  let sanitized: string;

  if (python) {
    sanitized = pythonCode(text);
    const roots = [
      pkg.name.replace(/-/gu, "_"),
      ...symbols.map((symbol) => symbol.split(".")[0]!).filter(Boolean),
    ].map((root) => root.toLowerCase());
    const matchesRoot = (name: string) => {
      const lower = name.toLowerCase();
      return roots.some(
        (root) => lower === root || lower.startsWith(root + "."),
      );
    };

    for (const match of sanitized.matchAll(
      /(?:^|;)[ \t]*((?:from(?:[ \t]|\\\n)+([\w.]+)(?:[ \t]|\\\n)+)?import\b(?:[ \t]|\\\n)*(\([^();]*\)|(?:\\\n|[^\n;])+))/gmu,
    )) {
      const from = match[2];
      if (from && !matchesRoot(from)) continue;
      const names = match[3]!.replace(/^\(|\)$/gu, "").replace(/\\\n/gu, " ");
      const bindings = names.split(",").flatMap((name) => {
        const parsed = /^([\w.]+)(?:\s+as\s+(\w+))?$/u.exec(name.trim());
        if (!parsed || (!from && !matchesRoot(parsed[1]!))) return [];
        return [parsed[2] ?? parsed[1]!.split(".")[0]!];
      });
      if (from || bindings.length) {
        matches.push({
          offset: match.index + match[0].indexOf(match[1]!),
          bindings,
        });
      }
    }
  } else {
    sanitized = javascriptCode(text, pkg.name);
    for (const match of sanitized.matchAll(
      /(?<![.$\w])(import|export)\b\s*(?:((?:type\s*)?(?:[\w$]+\s*,\s*)?(?:[\w$]+|\*(?:\s*as\s+[\w$]+)?|\{[^{};()]*\}))\s*from\s*)?"@"/gu,
    )) {
      const clause = match[2] ?? "";
      if (/^type(?:\s+[\w$]|\s*[{*])/u.test(clause)) continue;
      const names = importNames(clause);
      // "type Foo" is erased, but "type as foo" imports a value named type.
      const values = names.filter(
        (name) => !/^type\s/u.test(name) || /^type\s+as\s+[\w$]+$/u.test(name),
      );
      if (names.length && !values.length) continue;
      matches.push({
        offset: match.index,
        bindings: match[1] === "export" ? [] : localNames(values),
      });
    }

    const declaration =
      /((?<![.$\w])(?:import\s+type|type|const|let|var|import)\b|,)\s*([\w$]+|\{[^{};()]*\})\s*=\s*(?:\(\s*)?(?:(await|typeof)\s+)?/u;
    const call =
      /(?<![.$\w])(require|import)\s*\(\s*"@"\s*(?:(?:,\s*)?\)(?:\s*\))?(?:\s*\.\s*[\w$]+)?|,)/u;
    const loads = new RegExp(`(?:${declaration.source})?${call.source}`, "gu");
    const chained = /\s*[.(\[]/uy;
    for (const match of sanitized.matchAll(loads)) {
      const [, kind, target, operator, load] = match;
      if (kind?.endsWith("type")) continue;
      // Track the imported value, not a promise or the result of calling it.
      chained.lastIndex = match.index + match[0].length;
      const binds =
        target &&
        operator !== "typeof" &&
        (load === "require" || operator === "await") &&
        !chained.test(sanitized);
      matches.push({
        offset:
          kind === "," ? match.index + match[0].indexOf(target!) : match.index,
        bindings: binds ? localNames(importNames(target)) : [],
      });
    }
  }

  matches.sort((a, b) => a.offset - b.offset);
  const lines = new Set<number>();
  const bindings = new Set<string>();
  let offset = 0;
  let line = 1;
  for (const item of matches) {
    while (offset < item.offset) if (sanitized[offset++] === "\n") line++;
    lines.add(line);
    for (const binding of item.bindings) bindings.add(binding);
  }
  return { lines: [...lines], bindings: [...bindings] };
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
  const policyPaths = new Set<string>();
  for (const record of tree.split("\0")) {
    const policy =
      /^(?:100(?:644|755)|120000) blob [a-f0-9]+\t((?:[\s\S]*\/)?SECURITY\.md)$/u.exec(
        record,
      );
    if (policy) policyPaths.add(policy[1]!);
    const entry = /^100(?:644|755) blob ([a-f0-9]+)\t([\s\S]+)$/u.exec(record);
    if (entry && !entry[2]!.split("/").includes("node_modules"))
      blobs.set(entry[2]!, entry[1]!);
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
  for (const path of matches.filter((p) =>
    /\.(?:[cm]?[jt]sx?|py)$/iu.test(p),
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
    (path) =>
      /\.(?:[cm]?[jt]sx?|py|go|rs|rb|java|kt|php|swift|c|cc|cpp|cs)$/iu.test(
        path,
      ) && !inspected.has(path),
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
    .filter(inBoundary)
    .filter((p) =>
      /^(?:Dockerfile(?:\..+)?|Containerfile(?:\..+)?|.+\.(?:Dockerfile|Containerfile)|(?:docker-)?compose(?:\..+)?\.ya?ml)$/iu.test(
        posix.basename(p),
      ),
    )
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
