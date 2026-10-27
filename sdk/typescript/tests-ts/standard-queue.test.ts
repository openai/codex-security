import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { nodeCommand } from "./support/shell.js";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";

const temporary = createTemporaryDirectoriesSync(true);
afterEach(temporary.cleanup);

test("Standard schedules every scoped match once and retains unfinished paths", () => {
  const root = temporary.create("standard-queue-");
  const repo = join(root, "repository");
  const scan = join(root, "scan");
  const context = join(scan, "artifacts", "01_context");
  mkdirSync(join(repo, "src"), { recursive: true });
  mkdirSync(context, { recursive: true });
  const matched = Array.from({ length: 6 }, (_, i) => `src/route-${i}.ts`);
  for (const path of [...matched, "outside.ts", "src/example.txt"])
    writeFileSync(join(repo, path), "registerWebhook(handler)");
  for (const path of ["selected.txt", "src/unused.ts"])
    writeFileSync(join(repo, path), "ordinary source");
  writeFileSync(
    join(context, "standard-rules.json"),
    JSON.stringify([
      { path: "[.]ts$", content: "registerWebhook" },
      { path: "^src/route-0" },
    ]),
  );
  const run = (command: string, values: string[], input?: string) =>
    spawnSync(
      nodeCommand().command,
      [
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        "standard-queue",
        command,
        scan,
        ...values,
      ],
      { encoding: "utf8", input },
    );
  const success = (command: string, ...values: string[]) => {
    const result = run(command, values);
    expect(result.status, result.stderr).toBe(0);
    return JSON.parse(result.stdout);
  };

  expect(success("build", repo, "src", "selected.txt")).toEqual({
    files: 7,
    batches: 2,
    reviewed: 0,
    remaining: 7,
  });
  const [first, second] = success("pending", "0", "2").pending;
  expect(first.files).toEqual(["selected.txt", ...matched.slice(0, 4)]);
  expect(second.files).toEqual(matched.slice(4));
  const reviewed = (id: number, paths: string[], findings: unknown[] = []) =>
    run(
      "reviewed",
      [String(id)],
      JSON.stringify({
        reviewed_files: paths,
        findings,
        resolved_questions: [],
      }),
    );
  const partial = () =>
    reviewed(first.id, first.files.slice(1), [{ title: "Retained claim" }]);
  expect(partial().status).toBe(0);
  expect(partial().status).toBe(0);
  expect(reviewed(second.id, second.files).status).toBe(0);
  expect(success("pending", "0", "2").pending).toEqual([
    { id: 1, files: ["selected.txt"] },
  ]);
  expect(run("check", []).status).toBe(1);
  expect(run("build", [repo, "."]).status).toBe(1);
  expect(run("reviewed", [String(first.id)], "{}").status).toBe(1);
  expect(reviewed(first.id, second.files).status).toBe(1);
  expect(reviewed(first.id, ["selected.txt"]).status).toBe(0);
  expect(success("check").remaining).toBe(0);
  const queue = JSON.parse(
    readFileSync(join(context, "standard-queue.json"), "utf8"),
  );
  expect(queue.returns.map((row: { count: number }) => row.count)).toEqual([
    1, 0, 0,
  ]);
  const saved = JSON.parse(
    readFileSync(join(scan, queue.returns[0].file), "utf8"),
  );
  expect(saved.findings).toEqual([{ title: "Retained claim" }]);
});
