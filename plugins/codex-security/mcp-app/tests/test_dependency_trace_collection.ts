import { available, nativeRules } from "./support/native-trace-rules.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { delimiter, join, extname } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { localProvider } from "../src/dependency-trace/provider.ts";
import { traceInputSchema } from "../src/dependency-trace/schema.ts";
import {
  boundTraceResponse,
  traceResponse,
} from "../src/dependency-trace/response.ts";
import {
  createDependencyTracer,
  processTrace,
} from "../src/dependency-trace/trace.ts";
import type { TraceScope } from "../src/dependency-trace/types.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

async function matchingFiles(root: string, count: number) {
  const files = Array.from(
    { length: count },
    (_, index) => "consumer-" + String(index).padStart(4, "0") + ".py",
  );
  for (const file of files)
    await writeFile(
      join(root, file),
      "from image_lib import decode\ndecode(data)\n",
    );
  return files;
}

async function trackedIgnoredFiles(root: string, count: number) {
  const files = await matchingFiles(root, count);
  // These two files must not combine into one multiline discovery match.
  const nonmatches = ["consumer-import-only.py", "consumer-call-only.py"];
  await writeFile(
    join(root, nonmatches[0]),
    "from image_lib import safe_operation\n",
  );
  await writeFile(join(root, nonmatches[1]), "decode(data)\n");
  await writeFile(join(root, ".gitignore"), "consumer-*.py\n");
  const git = promisify(execFile);
  await git("git", ["init", "-q", root]);
  await git("git", [
    "-C",
    root,
    "add",
    "--force",
    "--",
    ...files,
    ...nonmatches,
  ]);
  return { files, nonmatches };
}

function imageSearch(): TraceScope {
  return {
    kind: "search",
    package: "image-package",
    symbol: "decode",
    rules: nativeRules("decode"),
    source_terms: ["image_lib"],
    path: ".",
  };
}

function fileTrace(files: string[], time_budget_ms: number, max_hops = 0) {
  return {
    package: "image-package",
    symbol: "decode",
    rules: nativeRules("decode"),
    files,
    source_only: true,
    max_hops,
    time_budget_ms,
  };
}

test("trace requests accept complete discovered file and directory lists", () => {
  for (const key of ["files", "paths"] as const) {
    const scope = Array.from({ length: 65 }, (_, index) => `src/unit-${index}`);
    const request = traceInputSchema.parse({
      package: "image-package",
      symbol: "decode",
      rules: nativeRules("decode"),
      [key]: scope,
      source_only: true,
      max_hops: 0,
      time_budget_ms: 60000,
    });
    assert.deepEqual(request[key], scope);
  }
});

test("native OpenGrep accepts an exact-file census through the request schema", async (t) => {
  if (!(await available("opengrep"))) return t.skip("opengrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-exact-file-census-");
  const files = await matchingFiles(root, 65);
  const provider = localProvider(root);
  const run = provider.run.bind(provider);
  let scans = 0;
  provider.run = (scope, signal) => {
    if (scope.kind === "source_batch") scans++;
    return run(scope, signal);
  };
  const tracer = createDependencyTracer(root, provider, 2);
  t.after(() => tracer.close());
  const request = traceInputSchema.parse(fileTrace(files, 60000));
  const result = await tracer.trace(request);
  assert.equal(result.complete, true, result.limits.join(", "));
  assert.deepEqual(
    new Set(
      result.scopes.flatMap(({ evidence }) =>
        evidence.map(({ source }) => source),
      ),
    ),
    new Set(files),
  );
  assert.deepEqual(traceResponse(result).coverage.source_batches, {
    scheduled: 5,
    completed: 5,
    files: 65,
  });
  assert.equal(scans, 5);
  assert.equal((await tracer.trace(request)).complete, true);
  assert.equal(scans, 5, "unchanged complete source batches are cached");
  await writeFile(join(root, files[0]), "from image_lib import decode\n");
  const edited = await tracer.trace(request);
  assert.equal(edited.complete, true);
  assert.equal(scans, 6, "a changed file invalidates only its source batch");
  assert.deepEqual(
    new Set(
      edited.scopes.flatMap(({ evidence }) =>
        evidence.map(({ source }) => source),
      ),
    ),
    new Set(files.slice(1)),
  );
});

test("directory discovery batches every matching file beyond the old cutoff", async (t) => {
  if (!(await available("rg"))) return t.skip("rg required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-all-matching-files-");
  const files = await matchingFiles(root, 641);
  const result = await localProvider(root).run(
    imageSearch(),
    new AbortController().signal,
  );
  assert.equal(result.complete, true, result.reason ?? "incomplete discovery");
  assert.deepEqual(
    result.next.flatMap(({ files }) => files),
    files,
  );
  assert.ok(
    result.next.every(
      ({ kind, files }) => kind === "source_batch" && files!.length <= 16,
    ),
  );
});

test("native OpenGrep processes every matching file across source batches", async (t) => {
  for (const tool of ["rg", "opengrep"]) {
    if (!(await available(tool))) return t.skip(tool + " required");
  }
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-native-all-files-");
  const files = await matchingFiles(root, 641);
  const tracer = createDependencyTracer(root, localProvider(root), 2);
  t.after(() => tracer.close());
  const result = await tracer.trace({
    package: "image-package",
    source_terms: ["image_lib"],
    symbol: "decode",
    rules: nativeRules("decode"),
    paths: ["."],
    source_only: true,
    max_hops: 0,
    time_budget_ms: 60000,
  });
  assert.equal(result.complete, true, result.limits.join(", "));
  assert.deepEqual(
    new Set(
      result.scopes.flatMap(({ evidence }) =>
        evidence.map(({ source }) => source),
      ),
    ),
    new Set(files),
  );
  assert.equal(
    result.scopes.flatMap(({ evidence }) => evidence).length,
    files.length,
  );
  assert.deepEqual(traceResponse(result).coverage.source_batches, {
    scheduled: 41,
    completed: 41,
    files: 641,
  });
});

test("tracked ignored discovery includes matches after the old cutoff", async (t) => {
  for (const tool of ["git", "rg"]) {
    if (!(await available(tool))) return t.skip(tool + " required");
  }
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-all-ignored-files-");
  const { files } = await trackedIgnoredFiles(root, 641);
  const result = await localProvider(root).run(
    imageSearch(),
    new AbortController().signal,
  );
  assert.equal(
    result.complete,
    true,
    result.reason ?? "incomplete ignored-file discovery",
  );
  assert.deepEqual(
    new Set(result.next.flatMap(({ files = [] }) => files)),
    new Set(files),
  );
});

test("all source batches and evidence survive collection while model replies stay bounded", async () => {
  const files = Array.from(
    { length: 4097 },
    (_, index) => `src/consumer-${index}.py`,
  );
  const visited: string[] = [];
  let active = 0;
  let peak = 0;
  const result = await processTrace(
    {
      package: "image-package",
      symbol: "decode",
      rules: nativeRules("decode"),
      source_terms: ["image_lib"],
      paths: ["."],
      source_only: true,
      max_hops: 0,
      time_budget_ms: 10000,
    },
    async (scope) => {
      if (scope.kind === "search") {
        const next: TraceScope[] = [];
        for (let offset = 0; offset < files.length; offset += 16)
          next.push({
            ...scope,
            kind: "source_batch",
            files: files.slice(offset, offset + 16),
          });
        return { complete: true, evidence: [], next };
      }
      assert.equal(scope.kind, "source_batch");
      peak = Math.max(peak, ++active);
      await new Promise<void>((resolve) => setImmediate(resolve));
      active--;
      visited.push(...scope.files!);
      return {
        complete: true,
        next: [],
        evidence: scope.files!.map((source) => ({
          source,
          line: 2,
          step: {
            from: { kind: "file", name: source },
            relation: "candidate_call",
            calleeText: "decode",
          },
        })),
        textMatches: scope.files!.map((source) => ({
          source,
          line: 1,
          text: "image_lib",
        })),
      };
    },
    3,
  );
  assert.equal(result.complete, true, result.limits.join(", "));
  assert.deepEqual(new Set(visited), new Set(files));
  assert.equal(peak, 3);
  assert.equal(result.scopes.length, 258);
  const batches = result.scopes.filter(
    ({ scope }) => scope.kind === "source_batch",
  );
  assert.equal(batches.length, 257);
  assert.ok(batches.every(({ hops }) => hops === 0));
  assert.deepEqual(result.frontier, []);
  assert.equal(
    result.scopes.flatMap(({ evidence }) => evidence).length,
    files.length,
  );
  assert.equal(
    result.scopes.flatMap(({ textMatches = [] }) => textMatches).length,
    files.length,
  );
  const full = traceResponse(result);
  assert.equal(full.trace.length, files.length);
  assert.equal(full.textMatches.length, files.length);
  const view = boundTraceResponse(full);
  assert.equal(view.coverage.complete, true);
  assert.equal(view.truncated, true);
  assert.ok(Buffer.byteLength(JSON.stringify(view)) <= 32 * 1024);
  assert.ok(view.trace.length <= 128);
  assert.equal(full.trace.length, files.length);
});

test("filename discovery is not cut off by the native diagnostic byte budget", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX executable fixture");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-long-filename-list-");
  const tools = await dirs.create("trace-filename-tool-");
  const linked = await dirs.create("trace-linked-tool-");
  const inheritedPath = join(tools, "inherited-path");
  await writeFile(join(root, "rg"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
  await symlink(join(root, "rg"), join(linked, "rg"));
  await writeFile(
    join(tools, "rg"),
    `#!${process.execPath}\n` +
      `process.getBuiltinModule("node:fs").writeFileSync(${JSON.stringify(inheritedPath)}, process.env.PATH);\n` +
      "const root = process.argv.at(-1);\n" +
      'const prefix = "component-".repeat(20);\n' +
      'const files = Array.from({length:8000},(_,i)=>root+"/"+prefix+"/"+prefix+"/consumer-"+i+".py");\n' +
      'process.stdout.write(files.join("\\0")+"\\0");\n',
    { mode: 0o755 },
  );
  const originalPath = process.env.PATH;
  process.env.PATH = [root, tools, linked, originalPath].join(delimiter);
  t.after(() => {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  });
  const result = await localProvider(root).run(
    imageSearch(),
    new AbortController().signal,
  );
  assert.equal(
    result.complete,
    true,
    result.reason ?? "incomplete filename discovery",
  );
  const inherited = (await readFile(inheritedPath, "utf8")).split(delimiter);
  assert.equal(inherited[0], tools);
  assert.ok(!inherited.includes(root));
  assert.ok(!inherited.includes(linked));
  const files = result.next.flatMap(({ files = [] }) => files);
  assert.equal(files.length, 8000);
  assert.ok(files.at(-1)?.endsWith("consumer-999.py"));
});

async function descriptorLauncherFixture(
  t: TestContext,
  mode: "closing" | "unrelated" | "abort",
) {
  for (const tool of ["git", "rg"]) {
    if (!(await available(tool))) {
      t.skip(tool + " required");
      return;
    }
  }
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-descriptor-source-");
  const tools = await dirs.create("trace-descriptor-launcher-");
  const { files, nonmatches } = await trackedIgnoredFiles(root, 20);
  const originalPath = process.env.PATH;
  const log = join(tools, "calls.jsonl");
  const started = join(tools, "stdin-started");
  await writeFile(join(tools, "package.json"), '{"type":"commonjs"}\n');
  await writeFile(
    join(tools, "rg"),
    "#!/usr/bin/env node\n" +
      'const fs = require("node:fs");\n' +
      'const {spawnSync} = require("node:child_process");\n' +
      "const args = process.argv.slice(2);\n" +
      "const fds = args.filter(arg => /^\\/dev\\/fd\\/\\d+$/.test(arg));\n" +
      'const stdin = args.includes("-");\n' +
      "fs.appendFileSync(" +
      JSON.stringify(log) +
      ', JSON.stringify({batch:fds.length>0,stdin})+"\\n");\n' +
      (mode === "unrelated"
        ? 'if(fds.length){process.stderr.write("synthetic unrelated rg failure: /dev/fd/999: Bad file descriptor (os error 9)\\n");process.exit(2);}\n'
        : // Advance inherited file positions before the forwarding process closes them.
          'for(const name of fds){fs.readSync(Number(name.split("/").at(-1)),Buffer.alloc(4096),0,4096,null);}\n') +
      (mode === "abort"
        ? "if(stdin){fs.writeFileSync(" +
          JSON.stringify(started) +
          ',"ready");setInterval(()=>{},1000);}else{\n'
        : "") +
      'const result=spawnSync("rg",args,{stdio:"inherit",env:{...process.env,PATH:' +
      JSON.stringify(originalPath) +
      "}});\n" +
      "process.exit(result.status??1);\n" +
      (mode === "abort" ? "}\n" : ""),
    { mode: 0o755 },
  );
  process.env.PATH = tools + delimiter + originalPath;
  t.after(() => {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  });
  const identities = await Promise.all(
    [...files, ...nonmatches].map((file) => stat(join(root, file))),
  );
  return {
    root,
    files,
    started,
    calls: async () =>
      (await readFile(log, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { batch: boolean; stdin: boolean }),
    async assertClosed() {
      for (const fd of await readdir("/dev/fd")) {
        const info = await stat("/dev/fd/" + fd).catch(() => undefined);
        assert.ok(
          !info ||
            !identities.some(
              (source) => source.dev === info.dev && source.ino === info.ino,
            ),
          "source descriptor remained open",
        );
      }
    },
  };
}

const descriptorSearch: TraceScope = imageSearch();

test("tracked ignored descriptor fallback preserves offset-zero matches and caches launcher support", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX descriptor launcher");
  const fixture = await descriptorLauncherFixture(t, "closing");
  if (!fixture) return;
  const result = await localProvider(fixture.root).run(
    descriptorSearch,
    new AbortController().signal,
  );
  assert.equal(result.complete, true, result.reason ?? "incomplete discovery");
  assert.deepEqual(
    new Set(result.next.flatMap(({ files = [] }) => files)),
    new Set(fixture.files),
  );
  const calls = await fixture.calls();
  assert.equal(calls.filter((call) => call.batch).length, 1);
  assert.equal(calls.filter((call) => call.stdin).length, 22);
  await fixture.assertClosed();
});

test("tracked ignored descriptor errors do not retry an unrelated tool failure", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX descriptor launcher");
  const fixture = await descriptorLauncherFixture(t, "unrelated");
  if (!fixture) return;
  const result = await localProvider(fixture.root).run(
    descriptorSearch,
    new AbortController().signal,
  );
  assert.equal(result.complete, false);
  assert.match(result.reason ?? "", /synthetic unrelated rg failure/);
  const calls = await fixture.calls();
  assert.equal(calls.filter((call) => call.batch).length, 1);
  assert.equal(calls.filter((call) => call.stdin).length, 0);
  await fixture.assertClosed();
});

test(
  "tracked ignored descriptor fallback propagates cancellation and closes source handles",
  { timeout: 10000 },
  async (t) => {
    if (process.platform === "win32")
      return t.skip("POSIX descriptor launcher");
    const fixture = await descriptorLauncherFixture(t, "abort");
    if (!fixture) return;
    const controller = new AbortController();
    t.after(() => controller.abort());
    const pending = localProvider(fixture.root).run(
      descriptorSearch,
      controller.signal,
    );
    const deadline = Date.now() + 5000;
    while (!(await stat(fixture.started).catch(() => undefined))) {
      assert.ok(Date.now() < deadline, "stdin fallback did not start");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    controller.abort();
    await assert.rejects(pending, { name: "AbortError" });
    await fixture.assertClosed();
  },
);

test("supplied rules batch exact targets by language while manifests stay direct", async () => {
  const python = Array.from(
    { length: 65 },
    (_, index) => `src/use-${index}.py`,
  );
  const files = [
    ...python,
    python[0],
    "src/use.js",
    "package.json",
    "README.md",
  ];
  const seen: TraceScope[] = [];
  const input = fileTrace(files, 10000);
  const result = await processTrace(
    input,
    async (scope) => {
      seen.push(scope);
      return { evidence: [], next: [], complete: true };
    },
    2,
  );
  assert.equal(result.complete, true);
  const batches = seen.filter(({ kind }) => kind === "source_batch");
  assert.equal(batches.length, 7);
  assert.deepEqual(
    new Set(batches.flatMap(({ files }) => files!)),
    new Set([...python, "src/use.js", "README.md"]),
  );
  assert.ok(
    batches.every(
      ({ files }) =>
        files!.length <= 16 &&
        files!.every((file) => extname(file) === extname(files![0])),
    ),
  );
  assert.deepEqual(
    seen.filter(({ kind }) => kind === "file").map(({ path }) => path),
    ["package.json"],
  );
  const noSymbol: TraceScope[] = [];
  await processTrace(
    {
      ...input,
      symbol: undefined,
      rules: undefined,
      files: ["package.json", "README.md"],
    },
    async (scope) => {
      noSymbol.push(scope);
      return { evidence: [], next: [], complete: true };
    },
    2,
  );
  assert.deepEqual(
    noSymbol.map(({ path, kind }) => ({ path, kind })),
    ["package.json", "README.md"].map((path) => ({ path, kind: "file" })),
  );
});

test("exact source batches retain path and size failures alongside valid evidence", async (t) => {
  if (!(await available("opengrep"))) return t.skip("opengrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-batch-invalid-");
  await writeFile(
    join(root, "valid.py"),
    "def caller(data):\n    return decode(data)\n",
  );
  await writeFile(join(root, "large.py"), Buffer.alloc(1024 * 1024 + 1));
  await writeFile(
    join(root, "package.json"),
    '{"dependencies":{"image-package":"1.0.0"}}',
  );
  await writeFile(join(root, "README.md"), "image-package");
  const tracer = createDependencyTracer(root, localProvider(root), 2);
  t.after(() => tracer.close());
  const result = await tracer.trace(
    fileTrace(
      ["valid.py", "large.py", "../outside.py", "package.json", "README.md"],
      60000,
    ),
  );
  assert.equal(result.complete, false);
  const batch = result.scopes.find(
    ({ scope }) => scope.kind === "source_batch",
  )!;
  assert.equal(batch.complete, false);
  assert.match(batch.reason ?? "", /exceeds/);
  assert.match(batch.reason ?? "", /checkout/);
  assert.deepEqual(
    new Set(batch.evidence.map(({ source }) => source)),
    new Set(["valid.py"]),
  );
  const manifest = result.scopes.find(
    ({ scope }) => scope.path === "package.json",
  )!;
  assert.equal(manifest.complete, true);
  assert.ok(
    manifest.evidence.some(({ step }) => step.relation === "depends_on"),
  );
  assert.match(
    result.scopes.find(({ scope }) => scope.files?.includes("README.md"))!
      .reason ?? "",
    /skipped/,
  );
});

test("cancellation reaches exact-file source batches at zero hops", async () => {
  const controller = new AbortController();
  let observed = false;
  setImmediate(() => controller.abort(new Error("cancelled")));
  await assert.rejects(
    processTrace(
      fileTrace(["a.py", "b.py"], 10000),
      async (scope, signal) => {
        assert.equal(scope.kind, "source_batch");
        await new Promise<void>((resolve) =>
          signal.addEventListener(
            "abort",
            () => {
              observed = true;
              resolve();
            },
            { once: true },
          ),
        );
        return { evidence: [], next: [], complete: true };
      },
      2,
      controller.signal,
    ).finally(() => assert.equal(observed, true)),
    /cancelled/,
  );
});

test("exact-file batches expose caller-rule followups and reject changed source before caching", async (t) => {
  if (!(await available("opengrep"))) return t.skip("opengrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-batch-followups-");
  await writeFile(
    join(root, "chain.py"),
    "def inner(data):\n    return decode(data)\n\ndef outer(data):\n    return inner(data)\n",
  );
  const tracer = createDependencyTracer(root, localProvider(root), 2);
  t.after(() => tracer.close());
  const request = fileTrace(["chain.py"], 60000, 2);
  const result = await tracer.trace(request);
  assert.equal(result.complete, false);
  assert.ok(
    result.scopes.some(
      ({ scope, reason }) =>
        scope.symbol === "inner" && /model-authored rules/.test(reason ?? ""),
    ),
  );
  const followed = await tracer.trace({
    ...request,
    symbol: "inner",
    rules: nativeRules("inner"),
    max_hops: 0,
  });
  assert.ok(
    followed.scopes.some(({ evidence }) =>
      evidence.some(
        ({ step }) => step.from.name === "outer" && step.calleeText === "inner",
      ),
    ),
  );
  await writeFile(join(root, "mutable.py"), "decode(data)\n");
  const provider = localProvider(root);
  const run = provider.run.bind(provider);
  let mutate = true;
  let reads = 0;
  provider.run = async (scope, signal) => {
    reads++;
    const value = await run(scope, signal);
    if (mutate)
      await writeFile(
        join(root, "mutable.py"),
        "# changed after native analysis\n",
      );
    return value;
  };
  const changing = createDependencyTracer(root, provider, 2);
  t.after(() => changing.close());
  const direct = { ...request, files: ["mutable.py"], max_hops: 0 };
  const stale = await changing.trace(direct);
  assert.equal(stale.complete, false);
  assert.match(stale.scopes[0].reason ?? "", /Source changed/);
  mutate = false;
  const current = await changing.trace(direct);
  assert.equal(current.complete, true);
  assert.equal(reads, 2, "the incomplete changed-byte result was not cached");
  assert.deepEqual(
    current.scopes.flatMap(({ evidence }) => evidence),
    [],
  );
});
