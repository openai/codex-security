import { tmpdir } from "node:os";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { ScanCostTracker, sessionFiles } from "../src/cost.js";
import {
  projectScanMergeWriteups,
  type ScanMergeInput,
} from "../src/scan-merge.js";

const scratch = tmpdir();
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots
      .splice(0)
      .map((path) => fs.rm(path, { recursive: true, force: true })),
  );
});
async function directory() {
  await fs.mkdir(scratch, { recursive: true });
  const path = await fs.mkdtemp(join(scratch, "bounded-io-"));
  roots.push(path);
  return path;
}
const usage = (input_tokens: number) =>
  JSON.stringify({
    type: "event_msg",
    payload: {
      type: "token_count",
      info: { total_token_usage: { input_tokens, output_tokens: 1 } },
    },
  }) + "\n";
async function session(home: string, id: string, parent_thread_id?: string) {
  const folder = join(home, "sessions");
  await fs.mkdir(folder, { recursive: true });
  const path = join(folder, `${id}.jsonl`);
  await fs.writeFile(
    path,
    JSON.stringify({
      type: "session_meta",
      payload: { id, parent_thread_id },
    }) +
      "\n" +
      usage(10),
  );
  return path;
}
function tracker(home: string, thread = "main") {
  const result = new ScanCostTracker({ codexHome: home, model: "gpt-5.6-sol" });
  result.start(thread);
  return result;
}

test("cached polls see partial records, late workers and independent tracker usage", async () => {
  const home = await directory();
  const path = await session(home, "main");
  const unrelated = await session(home, "unrelated");
  for (let i = 0; i < 10; i++) await session(home, `old-${i}`);
  const first = tracker(home);
  const second = tracker(home, "unrelated");
  expect((await first.refresh()).cost?.inputTokens).toBe(10);
  const open = spyOn(fs, "open");
  try {
    await first.refresh();
    expect(open).not.toHaveBeenCalled();
    const next = JSON.parse(usage(150));
    next.padding = "é".repeat(40000);
    await fs.appendFile(path, JSON.stringify(next));
    // Reusing this slot for later files must not overwrite the pending fragments.
    expect((await first.refresh()).cost?.inputTokens).toBe(10);
    open.mockClear();
    await first.refresh();
    expect(open).not.toHaveBeenCalled();
    await fs.appendFile(path, "\n");
    await fs.appendFile(unrelated, usage(90));
    await session(home, "worker", "main");
    expect((await first.stop()).cost?.inputTokens).toBe(160);
    expect((await second.stop()).cost?.inputTokens).toBe(90);
  } finally {
    open.mockRestore();
  }
});

test("changed metadata and failed closes cannot hide subsequent access failures", async () => {
  const home = await directory();
  const path = await session(home, "main");
  const cost = tracker(home);
  await cost.refresh();
  const failure = new Error("synthetic access failure");
  const statOriginal = fs.stat;
  const openOriginal = fs.open;
  let mode = "deny";
  const stat = spyOn(fs, "stat").mockImplementation((async (
    ...args: Parameters<typeof statOriginal>
  ) => {
    const info = await statOriginal(...args);
    // Model a metadata-only permission change even when running as root.
    if (args[0] === path && info && typeof info.mode === "number")
      info.mode ^= 0o400;
    return info;
  }) as typeof fs.stat);
  const open = spyOn(fs, "open").mockImplementation(async (...args) => {
    if (mode === "deny") throw failure;
    const file = await openOriginal(...args);
    const close = file.close.bind(file);
    file.close = async () => {
      await close();
      if (mode === "close") throw failure;
    };
    return file;
  });
  try {
    await expect(cost.refresh()).rejects.toBe(failure);
    mode = "close";
    await expect(cost.refresh()).rejects.toBe(failure);
    mode = "ok";
    open.mockClear();
    expect((await cost.refresh()).cost?.inputTokens).toBe(10);
    expect(open).toHaveBeenCalledTimes(1);
    open.mockClear();
    await cost.stop();
    expect(open).not.toHaveBeenCalled();
  } finally {
    stat.mockRestore();
    open.mockRestore();
  }
});

test("session batches bound handles, reuse buffers, and retain discovery-order worker IDs", async () => {
  const home = await directory();
  await session(home, "main");
  for (let i = 0; i < 24; i++) await session(home, `worker-${i}`, "main");
  const paths: string[] = [];
  for await (const path of sessionFiles(join(home, "sessions")))
    paths.push(path);
  const release = Promise.withResolvers<void>();
  const openOriginal = fs.open;
  const buffers = new Set<unknown>();
  let active = 0;
  let maximum = 0;
  const open = spyOn(fs, "open").mockImplementation(async (...args) => {
    const file = await openOriginal(...args);
    active++;
    maximum = Math.max(maximum, active);
    const read = file.read.bind(file);
    file.read = ((...readArgs: unknown[]) => {
      buffers.add(readArgs[0]);
      return Reflect.apply(read, file, readArgs);
    }) as typeof file.read;
    const close = file.close.bind(file);
    file.close = async () => {
      if (args[0] === paths[0]) await release.promise;
      await close();
      active--;
      if (args[0] === paths[7]) release.resolve();
    };
    return file;
  });
  const cost = tracker(home);
  try {
    expect((await cost.stop()).cost?.inputTokens).toBe(250);
    expect(active).toBe(0);
    expect(maximum).toBeGreaterThan(1);
    expect(maximum).toBeLessThanOrEqual(8);
    expect(buffers.size).toBeLessThanOrEqual(8);
    let worker = 0;
    for (const path of paths) {
      const id = JSON.parse((await fs.readFile(path, "utf8")).split("\n")[0]!)
        .payload.id;
      if (id !== "main") expect(cost.workerNumber(id)).toBe(++worker);
    }
  } finally {
    release.resolve();
    open.mockRestore();
  }
});

test.each([false, true])(
  "session failure drains pending closes (directory=%s)",
  async (directoryFailure) => {
    const home = await directory();
    const main = await session(home, "main");
    await session(home, "second");
    const nested = join(home, "sessions", "nested");
    if (directoryFailure) await fs.mkdir(nested);
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const failure = new Error("synthetic read failure");
    const originalOpen = fs.open;
    const originalReaddir = fs.readdir;
    let active = 0;
    let finished = false;
    const readdir = spyOn(fs, "readdir").mockImplementation((async (
      ...args: Parameters<typeof originalReaddir>
    ) => {
      if (args[0] === nested) {
        await entered.promise;
        throw failure;
      }
      const entries = await originalReaddir(...args);
      if (args[0] === join(home, "sessions"))
        entries.sort(
          (a, b) => Number(a.isDirectory()) - Number(b.isDirectory()),
        );
      return entries;
    }) as typeof fs.readdir);
    const open = spyOn(fs, "open").mockImplementation(async (...args) => {
      if (!directoryFailure && args[0] !== main) throw failure;
      const file = await originalOpen(...args);
      active++;
      const close = file.close.bind(file);
      file.close = async () => {
        entered.resolve();
        await release.promise;
        await close();
        active--;
      };
      return file;
    });
    const cost = tracker(home);
    const result = cost
      .refresh()
      .then(
        () => null,
        (error) => error,
      )
      .finally(() => {
        finished = true;
      });
    try {
      await entered.promise;
      expect(active).toBeGreaterThan(0);
      expect(finished).toBe(false);
      release.resolve();
      expect(await result).toBe(failure);
      expect(active).toBe(0);
    } finally {
      release.resolve();
      readdir.mockRestore();
      open.mockRestore();
      await result;
    }
    expect((await cost.stop()).cost?.inputTokens).toBe(10);
  },
);

async function reports(names: string[]): Promise<ScanMergeInput> {
  const scanDir = await directory();
  const findings = [];
  for (const [index, name] of names.entries()) {
    const folder = `source-${index}/${name}`;
    await fs.mkdir(join(scanDir, folder, "evidence"), { recursive: true });
    await fs.writeFile(join(scanDir, folder, "report.md"), String(index));
    await fs.writeFile(
      join(scanDir, folder, "evidence/data"),
      Buffer.from([index, 0, 255]),
    );
    findings.push({ writeup: { reportPath: `${folder}/report.md` } });
  }
  return {
    scanId: "child",
    scanDir,
    draft: { scanId: "parent", findings, coverage: {} },
    sourceFindings: structuredClone(findings),
  };
}

test("report aliases preserve byte and overwrite order across batch boundaries", async () => {
  const input = await reports(
    Array.from({ length: 18 }, (_, i) => ["Caf\u00e9", "cafe\u0301"][i % 2]!),
  );
  const before = structuredClone(input);
  const bytes: Buffer[] = [];
  const result = await projectScanMergeWriteups(input, {
    async restore(_path, content) {
      bytes.push(Buffer.from(content));
    },
  });
  expect(bytes).toEqual(
    Array.from({ length: 18 }, (_, i) => [
      Buffer.from(String(i)),
      Buffer.from([i, 0, 255]),
    ]).flat(),
  );
  expect(input).toEqual(before);
  expect(result.sourceFindings).toEqual(before.sourceFindings);
});

test.each([false, true])(
  "report failure drains writers and reports input-order error (cancel=%s)",
  async (cancel) => {
    const input = await reports(
      Array.from({ length: 20 }, (_, i) => `item-${i}`),
    );
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const failed = Promise.withResolvers<void>();
    const controller = new AbortController();
    const first = new Error("first report error");
    const second = new Error("second report error");
    let active = 0;
    let maximum = 0;
    let finished = false;
    const paths: string[] = [];
    const result = projectScanMergeWriteups(
      input,
      {
        async restore(path) {
          paths.push(path);
          active++;
          maximum = Math.max(maximum, active);
          try {
            if (path.endsWith("child-item-0.md")) {
              entered.resolve();
              await release.promise;
              if (cancel) controller.abort(first);
              throw first;
            }
            await entered.promise;
            failed.resolve();
            throw second;
          } finally {
            active--;
          }
        },
      },
      controller.signal,
    )
      .then(
        () => null,
        (error) => error,
      )
      .finally(() => {
        finished = true;
      });
    try {
      await failed.promise;
      expect(finished).toBe(false);
      expect(active).toBeGreaterThan(0);
    } finally {
      release.resolve();
    }
    expect(await result).toBe(first);
    expect(active).toBe(0);
    expect(maximum).toBeLessThanOrEqual(8);
    expect(paths.every((path) => !path.includes("item-8/"))).toBe(true);
  },
);

test("a report-path setup error still drains an earlier writer", async () => {
  const input = await reports(["first", "second"]);
  input.draft.findings[1]!["writeup"] = { reportPath: null };
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  let finished = false;
  let active = 0;
  const result = projectScanMergeWriteups(input, {
    async restore() {
      active++;
      entered.resolve();
      await release.promise;
      active--;
    },
  })
    .then(
      () => null,
      (error) => error,
    )
    .finally(() => {
      finished = true;
    });
  try {
    await entered.promise;
    // Give a prematurely rejected projection a chance to settle.
    await Promise.resolve();
    expect(finished).toBe(false);
    expect(active).toBe(1);
  } finally {
    release.resolve();
  }
  expect(await result).toBeInstanceOf(TypeError);
  expect(active).toBe(0);
});
