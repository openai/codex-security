import { createHash } from "node:crypto";
import { readdir } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { artifactDestination, replaceArtifactJson } from "../artifact-io.js";
import { normalizedScanRelativePath } from "../contract-values.js";
import { sqliteFilename } from "../windows-path";
import { loadScopes, scopedSourceFiles } from "./generate-inventory";
import { environmentValue, readFile, resolvedPathText } from "./helper-files";
import { append, exists, fsPath } from "./inventory-paths";
import { contentMatcherForFile } from "./source-preview";

interface Rule {
  path?: string;
  content?: string;
}

interface Queue {
  rules: Rule[];
  batches: string[][];
  reviewed: string[];
  returns?: { file: string; count: number; id?: string }[];
}

const readJson = (file: string) => JSON.parse(readFile(file).toString("utf8"));

// The file stays in the reserved returns directory so every helper locks the
// same inode. SQLite releases the transaction even if its process exits.
async function withQueueWriteLock<T>(file: string, write: () => Promise<T>) {
  const { DatabaseSync } = await import("node:sqlite");
  const guard = new DatabaseSync(sqliteFilename(file));
  try {
    for (;;) {
      try {
        guard.exec("BEGIN IMMEDIATE");
        break;
      } catch (error) {
        // A paused writer still owns its transaction. Wait without blocking
        // the event loop, including when helpers run in the same process.
        if (
          !(error instanceof Error) ||
          !("errcode" in error) ||
          ![5, 6].includes(Number(error.errcode) & 0xff)
        )
          throw error;
        await delay(50);
      }
    }
    return await write();
  } finally {
    guard.close();
  }
}

export async function standardQueue(args: string[], home?: string) {
  const [command, scanDir, ...values] = args;
  if (!scanDir)
    throw new Error(
      "Expected standard-queue <build|pending|reviewed|check> <scan_dir> [arguments]",
    );
  const destination = (name: string) =>
    artifactDestination(
      { root: scanDir },
      name.split("/"),
      "Standard file queue",
    );
  const file = await destination("artifacts/01_context/standard-queue.json");
  const lockFile = () =>
    destination("artifacts/02_discovery/standard-returns/queue.lock.sqlite");
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
    const rules: Rule[] = readJson(
      await destination("artifacts/01_context/standard-rules.json"),
    );
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
      {
        file: await destination(
          scopeFile
            ? "scoped-source-input.jsonl"
            : "artifacts/02_discovery/in_scope_files.txt",
        ),
        scoped: Boolean(scopeFile),
      },
    )) {
      if (explicit) matches.add(name);
      if (matches.has(name)) continue;
      let matchesContent: ((pattern: RegExp) => boolean) | undefined;
      for (const rule of matchers) {
        if (rule.path && !rule.path.test(name)) continue;
        if (rule.content) {
          matchesContent ??= contentMatcherForFile(append(repo, name));
          if (!matchesContent(rule.content)) continue;
        }
        matches.add(name);
        break;
      }
    }
    const paths = [...matches].sort();
    queue = { rules, batches: [], reviewed: [], returns: [] };
    for (let i = 0; i < paths.length; i += 5)
      queue.batches.push(paths.slice(i, i + 5));
    const guardPath = await lockFile();
    await withQueueWriteLock(guardPath, async () => {
      if (exists(file))
        throw new Error("Queue already built. Use pending to resume.");
      const saved = await readdir(fsPath(dirname(guardPath)));
      if (
        saved.some((name) => name.endsWith(".json")) ||
        exists(
          await destination("artifacts/04_validation/standard-decisions.json"),
        )
      )
        throw new Error(
          "The Standard file queue is missing but review data remains. Restore the queue before resuming.",
        );
      await replaceArtifactJson(file, queue);
    });
  } else {
    queue = readJson(file);
  }
  if (command === "reviewed") {
    const batch = Number(values[0]);
    const assigned = queue.batches[batch - 1];
    if (!assigned) throw new Error("Expected the assigned file batch ID.");
    const {
      reviewed_files,
      findings,
      resolved_questions,
      batch: _workerBatch,
      ...details
    } = JSON.parse(readFile(0).toString("utf8"));
    if (![reviewed_files, findings, resolved_questions].every(Array.isArray))
      throw new Error("Expected the worker's complete JSON return.");
    for (const path of reviewed_files) {
      if (
        typeof path !== "string" ||
        (!assigned.includes(path) &&
          normalizedScanRelativePath(path) === undefined)
      )
        throw new Error(
          "Expected repository-relative paths in reviewed_files.",
        );
    }
    // Original receipts were identified by these fields alone. Keep that ID
    // for queue accounting even when an extended receipt has different bytes.
    const original = { batch, reviewed_files, findings, resolved_questions };
    const result = { ...original, ...details };
    const digest = (receipt: object) =>
      createHash("sha256").update(JSON.stringify(receipt)).digest("hex");
    const id = digest(original);
    const receiptFile = (hash: string) =>
      `artifacts/02_discovery/standard-returns/${hash}.json`;
    const originalFile = receiptFile(id);
    const returned = Object.keys(details).length
      ? receiptFile(digest(result))
      : originalFile;
    await withQueueWriteLock(await lockFile(), async () => {
      queue = readJson(file);
      queue.returns ??= [];
      const saved = queue.returns.find(
        (row) => row.id === id || row.file === originalFile,
      );
      if (
        !saved ||
        (saved.file === originalFile && returned !== originalFile)
      ) {
        await replaceArtifactJson(await destination(returned), result);
        if (saved) {
          // Enrich the old receipt without changing its candidate offsets.
          saved.file = returned;
          saved.id = id;
        } else {
          queue.returns.push({ file: returned, count: findings.length, id });
        }
      }
      queue.reviewed = [
        ...new Set([
          ...queue.reviewed,
          ...assigned.filter((path) => reviewed_files.includes(path)),
        ]),
      ].sort();
      await replaceArtifactJson(file, queue);
    });
  } else if (!["build", "pending", "check"].includes(command)) {
    throw new Error(`Unknown queue operation: ${command}`);
  }
  const paths = new Set(queue.batches.flat());
  const reviewed = new Set(queue.reviewed);
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
