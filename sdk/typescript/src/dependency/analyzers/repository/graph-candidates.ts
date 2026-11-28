import { posix } from "node:path";
import { portableRelativePath } from "../../../contract-values.js";
import {
  investigationServer,
  type DependencyEvidenceRecord,
} from "../../evidence-sources.js";
import { isRecord } from "../../../record.js";
import type { Scope } from "./claims.js";
import { gitOutput } from "../../../targets.js";

export type DependencyGraphCandidate = {
  path: string;
  line: number;
  kind: "caller" | "dependency";
  package?: string;
};
export type GraphCandidates = ReadonlyMap<
  string,
  readonly DependencyGraphCandidate[]
>;

export function observedDependencyCandidates(
  receipt: DependencyEvidenceRecord,
): DependencyGraphCandidate[] {
  if (
    receipt.server !== investigationServer ||
    !["trace_codex_security_code", "query_codex_security_graph"].includes(
      receipt.tool,
    )
  )
    return [];
  const data = receipt.result["structuredContent"];
  if (!isRecord(data)) return [];
  const result: DependencyGraphCandidate[] = [];
  function append(fact: unknown, source: unknown, line: unknown) {
    if (
      !isRecord(fact) ||
      typeof source !== "string" ||
      typeof line !== "number" ||
      !Number.isSafeInteger(line) ||
      line <= 0
    )
      return;
    if (
      !["candidate_call", "candidate_flow", "depends_on"].includes(
        String(fact["relation"]),
      )
    )
      return;
    let path: string;
    try {
      path = portableRelativePath(source, "Trace source");
    } catch {
      return;
    }
    const target = fact["to"];
    const dependency = fact["relation"] === "depends_on";
    result.push({
      path,
      line,
      kind: dependency ? "dependency" : "caller",
      ...(dependency &&
        isRecord(target) &&
        target["kind"] === "package" &&
        typeof target["name"] === "string" && { package: target["name"] }),
    });
  }
  if (Array.isArray(data["trace"]))
    for (const step of data["trace"]) {
      if (!isRecord(step) || !Array.isArray(step["evidence"])) continue;
      for (const ref of step["evidence"])
        if (isRecord(ref) && Array.isArray(ref["lines"]))
          for (const line of ref["lines"]) append(step, ref["source"], line);
    }
  for (const key of ["paths", "evidence"])
    if (Array.isArray(data[key]))
      for (const fact of data[key])
        if (isRecord(fact)) append(fact, fact["source"], fact["line"]);
  return result;
}

/** Bind native structural locations to the nearest requesting manifest in the pinned tree. */
export async function dependencyGraphCandidates(
  scopes: Scope[],
  candidates: readonly DependencyGraphCandidate[],
  directory: string,
  signal: AbortSignal,
): Promise<GraphCandidates> {
  const revision = scopes[0]?.discovery.revision;
  const byScope = new Map<string, DependencyGraphCandidate[]>();
  if (!revision || !candidates.length) return byScope;
  const manifests = (dir: string) =>
    [
      "package.json",
      "requirements.txt",
      "requirements.lock",
      "pyproject.toml",
    ].map((p) => posix.join(dir, p));
  const paths = new Set<string>();
  for (const { path } of candidates) {
    paths.add(path);
    let dir = posix.dirname(path);
    for (;;) {
      for (const file of manifests(dir)) paths.add(file);
      if (dir === ".") break;
      dir = posix.dirname(dir);
    }
  }
  const regular = new Map<string, string>(),
    dirty = new Set<string>();
  const files = [...paths];
  const env = {
    GIT_LITERAL_PATHSPECS: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
  };
  for (let i = 0; i < files.length; i += 128) {
    const batch = files.slice(i, i + 128);
    const [tree, changed] = await Promise.all([
      gitOutput(
        directory,
        ["ls-tree", "-z", "--full-tree", revision, "--", ...batch],
        signal,
        env,
      ),
      gitOutput(
        directory,
        [
          "diff",
          "--no-ext-diff",
          "--no-textconv",
          "--name-only",
          "-z",
          revision,
          "--",
          ...batch,
        ],
        signal,
        env,
      ),
    ]);
    for (const entry of tree.split("\0")) {
      const match = /^100(?:644|755) blob ([0-9a-f]+)\t([\s\S]+)$/u.exec(entry);
      if (match) regular.set(match[2]!, match[1]!);
    }
    for (const file of changed.split("\0")) dirty.add(file);
  }
  const lineCounts = new Map<string, number>();
  for (const candidate of candidates) {
    const blob = regular.get(candidate.path);
    if (!blob || dirty.has(candidate.path)) continue;
    let count = lineCounts.get(blob);
    if (count === undefined) {
      const bytes = await gitOutput(
        directory,
        ["cat-file", "blob", blob],
        signal,
        env,
        directory,
        "buffer",
      );
      count = bytes.length && bytes.at(-1) !== 10 ? 1 : 0;
      for (let i = bytes.indexOf(10); i !== -1; i = bytes.indexOf(10, i + 1))
        count++;
      lineCounts.set(blob, count);
    }
    if (candidate.line > count) continue;
    const owners = scopes.filter((scope) => {
      if (
        (candidate.package && candidate.package !== scope.component) ||
        (scope.manifest && dirty.has(scope.manifest))
      )
        return false;
      if (
        scope.discovery.callers.some(
          (c) => c.path === candidate.path && c.manifest === scope.manifest,
        )
      )
        return true;
      if (!scope.manifest) return candidate.package === scope.component;
      if (
        candidate.path === scope.manifest ||
        candidate.path === scope.selection?.lockfile
      )
        return true;
      let dir = posix.dirname(candidate.path);
      for (;;) {
        let names = manifests(dir);
        if (scope.discovery.package.ecosystem === "npm")
          names = names.slice(0, 1);
        else if (scope.discovery.package.ecosystem === "PyPI")
          names = names.slice(1);
        else return false;
        const boundary = names.filter((f) => regular.has(f));
        if (boundary.length) return boundary.includes(scope.manifest);
        if (dir === ".") return false;
        dir = posix.dirname(dir);
      }
    });
    if (owners.length !== 1) continue;
    const id = owners[0]!.id;
    const matches = byScope.get(id) ?? [];
    matches.push(candidate);
    byScope.set(id, matches);
  }
  return byScope;
}
