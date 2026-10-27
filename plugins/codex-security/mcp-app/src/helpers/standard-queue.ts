import { createHash } from "node:crypto";
import { join } from "node:path";
import { artifactDestination, replaceArtifactJson } from "../artifact-io.js";
import { loadScopes, scopedSourceFiles } from "./generate-inventory";
import { environmentValue, readFile, resolvedPathText } from "./helper-files";
import { append, exists } from "./inventory-paths";

interface Rule {
  path?: string;
  content?: string;
}

interface Queue {
  rules: Rule[];
  batches: string[][];
  reviewed: string[];
  returns?: { file: string; count: number }[];
}

const readJson = (file: string) => JSON.parse(readFile(file).toString("utf8"));

export async function standardQueue(args: string[], home?: string) {
  const [command, scanDir, ...values] = args;
  if (!scanDir)
    throw new Error(
      "Expected standard-queue <build|pending|reviewed|check> <scan_dir> [arguments]",
    );
  const context = join(scanDir, "artifacts", "01_context");
  const destination = (name: string) =>
    artifactDestination(
      { root: scanDir },
      name.split("/"),
      "Standard file queue",
    );
  const file = await destination("artifacts/01_context/standard-queue.json");
  let queue: Queue;
  if (command === "build") {
    if (exists(file))
      throw new Error("Queue already built. Use pending to resume.");
    const [root, ...requested] = values;
    const repo = resolvedPathText(root);
    const scopeFile = environmentValue("CODEX_SECURITY_TARGET_PATHS_FILE");
    const scopes = scopeFile ? loadScopes(scopeFile) : requested;
    if (!scopes.length)
      throw new Error(
        "Supply the registered scopes, or . for a whole repository.",
      );
    const rules: Rule[] = readJson(join(context, "standard-rules.json"));
    if (!Array.isArray(rules) || !rules.length)
      throw new Error("Expected a nonempty array of search rules.");
    const matchers = rules.map(({ path, content }) => {
      if (!path && !content)
        throw new Error("Each search rule needs a path or content pattern.");
      return {
        path: path && new RegExp(path, "u"),
        content: content && new RegExp(content, "mu"),
      };
    });
    const matches = new Set<string>();
    for await (const { name, explicit } of scopedSourceFiles(
      repo,
      scopes,
      home,
    )) {
      if (explicit) matches.add(name);
      if (matches.has(name)) continue;
      let source: string | undefined;
      for (const rule of matchers) {
        if (rule.path && !rule.path.test(name)) continue;
        if (rule.content) {
          source ??= readFile(append(repo, name)).toString("utf8");
          if (!rule.content.test(source)) continue;
        }
        matches.add(name);
        break;
      }
    }
    const paths = [...matches].sort();
    queue = { rules, batches: [], reviewed: [], returns: [] };
    for (let i = 0; i < paths.length; i += 5)
      queue.batches.push(paths.slice(i, i + 5));
    await replaceArtifactJson(file, queue);
  } else {
    queue = readJson(file);
  }
  const paths = new Set(queue.batches.flat());
  const reviewed = new Set(queue.reviewed);
  if (command === "reviewed") {
    const batch = Number(values[0]);
    const assigned = queue.batches[batch - 1];
    if (!assigned) throw new Error("Expected the assigned file batch ID.");
    const { reviewed_files, findings, resolved_questions } = JSON.parse(
      readFile(0).toString("utf8"),
    );
    if (![reviewed_files, findings, resolved_questions].every(Array.isArray))
      throw new Error("Expected the worker's complete JSON return.");
    for (const path of reviewed_files) {
      if (!assigned.includes(path))
        throw new Error(`File is outside batch ${batch}: ${path}`);
      reviewed.add(path);
    }
    const result = { batch, reviewed_files, findings, resolved_questions };
    const digest = createHash("sha256")
      .update(JSON.stringify(result))
      .digest("hex");
    const returned = `artifacts/02_discovery/standard-returns/${digest}.json`;
    queue.returns ??= [];
    if (!queue.returns.some((saved) => saved.file === returned)) {
      await replaceArtifactJson(await destination(returned), result);
      queue.returns.push({ file: returned, count: findings.length });
    }
    queue.reviewed = [...reviewed].sort();
    await replaceArtifactJson(file, queue);
  } else if (!["build", "pending", "check"].includes(command)) {
    throw new Error(`Unknown queue operation: ${command}`);
  }
  const remaining = paths.size - reviewed.size;
  if (command === "check" && remaining)
    throw new Error(
      `${remaining} Standard target files still need review. Resume with standard-queue pending.`,
    );
  const summary = {
    files: paths.size,
    batches: queue.batches.length,
    reviewed: reviewed.size,
    remaining,
  };
  if (command !== "pending") return summary;
  const after = Number(values[0] ?? 0);
  const limit = Number(values[1] ?? 1);
  const batches = queue.batches
    .map((batch, i) => ({
      id: i + 1,
      files: batch.filter((path) => !reviewed.has(path)),
    }))
    .filter((batch) => batch.id > after && batch.files.length)
    .slice(0, limit);
  return { ...summary, pending: batches };
}
