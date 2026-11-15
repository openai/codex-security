import { afterEach, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
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

  if (process.platform !== "win32") {
    const rulesFile = join(context, "standard-rules.json");
    const external = join(root, "other-rules.json");
    renameSync(rulesFile, external);
    symlinkSync(external, rulesFile);
    const redirected = run("build", [repo, "src"]);
    expect(redirected.status).toBe(1);
    expect(redirected.stderr).toContain("not a regular file");
    unlinkSync(rulesFile);
    renameSync(external, rulesFile);
  }
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
  const worker = {
    batch: second.id,
    count: 99,
    findings: [{ title: "Retained claim" }],
    reviewed_files: [
      ...first.files.slice(1),
      "src/unused.ts",
      "outside.ts",
      second.files[0],
    ],
    resolved_questions: ["The supporting file guards one caller."],
    notes: "One assigned file still needs review.",
  };
  const partial = () =>
    run("reviewed", [String(first.id)], JSON.stringify(worker));
  const acknowledgement = partial();
  expect(acknowledgement.status, acknowledgement.stderr).toBe(0);
  expect(partial().status).toBe(0);
  expect(success("pending", "0", "2").pending).toEqual([
    { id: first.id, files: ["selected.txt"] },
    second,
  ]);
  expect(reviewed(second.id, second.files).status).toBe(0);
  expect(
    run(
      "reviewed",
      [String(second.id)],
      JSON.stringify({
        findings: [],
        resolved_questions: [],
        reviewed_files: second.files,
      }),
    ).status,
  ).toBe(0);
  expect(success("pending", "0", "2").pending).toEqual([
    { id: 1, files: ["selected.txt"] },
  ]);
  expect(run("check", []).status).toBe(1);
  expect(run("build", [repo, "."]).status).toBe(1);
  expect(run("reviewed", [String(first.id)], "{}").status).toBe(1);
  expect(reviewed(first.id, ["../outside.ts"]).status).toBe(1);
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
  expect(saved).toEqual({ ...worker, batch: first.id });
  const legacyDigest = createHash("sha256")
    .update(
      JSON.stringify({
        batch: second.id,
        reviewed_files: second.files,
        findings: [],
        resolved_questions: [],
      }),
    )
    .digest("hex");
  expect(queue.returns[1].file).toBe(
    `artifacts/02_discovery/standard-returns/${legacyDigest}.json`,
  );
  unlinkSync(join(context, "standard-queue.json"));
  expect(run("build", [repo, "src", "selected.txt"]).stderr).toContain(
    "Restore the queue before resuming",
  );
});

test("overlapping Standard returns keep both batches and candidate offsets", async () => {
  // Keep each component valid while taking the SQLite guard beyond MAX_PATH.
  const scan = join(
    temporary.create("standard-queue-ack-"),
    "batch".repeat(24),
    "state".repeat(24),
  );
  const context = join(scan, "artifacts", "01_context");
  mkdirSync(context, { recursive: true });
  const queueFile = join(context, "standard-queue.json");
  writeFileSync(
    queueFile,
    JSON.stringify({
      rules: [{ path: ".*" }],
      batches: [["a.py"], ["b.py"]],
      reviewed: [],
      returns: [],
    }),
  );
  // Hold two helpers at their stdin reads so their invocations overlap on every platform.
  const preloader = join(scan, "ready.cjs");
  writeFileSync(
    preloader,
    `const fs = require("node:fs");
    const read = fs.readFileSync;
    fs.readFileSync = function (file, ...args) {
      if (file === 0) process.send("ready");
      return read.call(this, file, ...args);
    };`,
  );
  const start = (batch: number) => {
    const child = spawn(
      nodeCommand().command,
      [
        "--require",
        preloader,
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        "standard-queue",
        "reviewed",
        scan,
        String(batch),
      ],
      { stdio: ["pipe", "ignore", "pipe", "ipc"] },
    );
    const closed = once(child, "close");
    const ready = Promise.race([
      once(child, "message"),
      closed.then(([code]) => {
        throw new Error(`Helper exited before reading stdin: ${code}`);
      }),
    ]);
    const finish = async (path: string) => {
      child.stdin!.end(
        JSON.stringify({
          reviewed_files: [path],
          findings: [{ title: path }],
          resolved_questions: [],
        }),
      );
      expect((await closed)[0]).toBe(0);
    };
    return { child, ready, finish };
  };
  const first = start(1);
  const second = start(2);
  try {
    await Promise.all([first.ready, second.ready]);
    // Python assigns candidate IDs by acknowledgement order, including on resume.
    await second.finish("b.py");
    await first.finish("a.py");
    const queue = JSON.parse(readFileSync(queueFile, "utf8"));
    expect(queue.reviewed).toEqual(["a.py", "b.py"]);
    expect(
      queue.returns.map((row: { file: string; count: number }) => {
        expect(row.count).toBe(1);
        return JSON.parse(readFileSync(join(scan, row.file), "utf8"))
          .findings[0].title;
      }),
    ).toEqual(["b.py", "a.py"]);
  } finally {
    first.child.kill();
    second.child.kill();
  }
});

test("Standard retries retain candidate IDs across original and extended receipts", () => {
  const scan = temporary.create("standard-queue-retry-");
  const context = join(scan, "artifacts", "01_context");
  const returns = "artifacts/02_discovery/standard-returns";
  mkdirSync(context, { recursive: true });
  mkdirSync(join(scan, returns), { recursive: true });
  const receipt = (batch: number, path: string) => ({
    batch,
    reviewed_files: [path],
    findings: [{ title: path }],
    resolved_questions: [],
  });
  const original = receipt(1, "old.py");
  const next = receipt(2, "new.py");
  const fileFor = (value: object) =>
    `${returns}/${createHash("sha256").update(JSON.stringify(value)).digest("hex")}.json`;
  const originalFile = fileFor(original);
  const originalBytes = JSON.stringify(original);
  writeFileSync(join(scan, originalFile), originalBytes);
  const queuePath = join(context, "standard-queue.json");
  writeFileSync(
    queuePath,
    JSON.stringify({
      batches: [["old.py"], ["new.py"]],
      reviewed: ["old.py"],
      returns: [{ file: originalFile, count: 1 }],
    }),
  );
  const submit = (batch: number, payload: object) => {
    const result = spawnSync(
      nodeCommand().command,
      [
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        "standard-queue",
        "reviewed",
        scan,
        String(batch),
      ],
      { encoding: "utf8", input: JSON.stringify(payload) },
    );
    expect(result.status, result.stderr).toBe(0);
  };
  // Add a second candidate before enriching the existing acknowledgement.
  for (const worker of [next, original]) {
    submit(worker.batch, {
      ...worker,
      notes: "Initial notes",
      evidence: "Supporting source",
    });
    submit(worker.batch, worker);
    submit(worker.batch, {
      ...worker,
      evidence: "Supporting source",
      notes: "Initial notes",
    });
  }
  const queue = JSON.parse(readFileSync(queuePath, "utf8"));
  expect(queue.returns.map((row: { count: number }) => row.count)).toEqual([
    1, 1,
  ]);
  for (const [index, worker] of [original, next].entries()) {
    const extended = {
      ...worker,
      notes: "Initial notes",
      evidence: "Supporting source",
    };
    expect(queue.returns[index].file).toBe(fileFor(extended));
    expect(
      JSON.parse(readFileSync(join(scan, queue.returns[index].file), "utf8")),
    ).toEqual(extended);
  }
  expect(readFileSync(join(scan, originalFile), "utf8")).toBe(originalBytes);
});
