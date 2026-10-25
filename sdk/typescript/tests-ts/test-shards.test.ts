import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { expect, test } from "bun:test";
import { partitionTests, type TestTimings } from "../scripts/test-shards.mts";
import { readSubprocess } from "./support/shell.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

async function copyRunner(root: string, timings: TestTimings = {}) {
  for (const name of ["run-ci-tests.mts", "test-shards.mts"]) {
    await copyFile(
      new URL(`../scripts/${name}`, import.meta.url),
      join(root, "scripts", name),
    );
  }
  await writeFile(
    join(root, "scripts", "test-timings.json"),
    JSON.stringify(timings),
  );
}

test.each(["linux", "darwin", "win32"] as const)(
  "balances whole files using %s durations without depending on discovery order",
  (platform) => {
    const files = ["a", "b", "c", "d", "e", "f"];
    const timings = Object.fromEntries(
      files.map((file, index) => [file, { [platform]: 100 - index * 10 }]),
    );
    const shards = partitionTests(files, 3, timings, platform);
    expect(shards).toEqual([
      ["a", "f"],
      ["b", "e"],
      ["c", "d"],
    ]);
    expect(partitionTests(files.toReversed(), 3, timings, platform)).toEqual(
      shards,
    );
    expect(files).toEqual(["a", "b", "c", "d", "e", "f"]);
  },
);

test("uses each platform's history and includes new files without selecting deleted files", () => {
  const files = ["a", "b", "c", "new"];
  const timings = {
    a: { linux: 100, win32: 1 },
    b: { linux: 1, win32: 100 },
    c: { linux: 1, win32: 1 },
    deleted: { linux: 1_000, win32: 1_000 },
  };
  expect(partitionTests(files, 2, timings, "linux")).toEqual([
    ["a"],
    ["b", "c", "new"],
  ]);
  expect(partitionTests(files, 2, timings, "win32")).toEqual([
    ["b"],
    ["a", "c", "new"],
  ]);
  expect(partitionTests(files, 2, {}, "darwin").flat().sort()).toEqual(files);
});

test.each([3, 6, 7, 14])(
  "runs each eligible file once across %i native shards, including new files",
  async (count) => {
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const root = await temporaryDirectory("codex-security-native-shards-");
    try {
      await mkdir(join(root, "scripts"));
      await mkdir(join(root, "tests-ts"));
      await copyRunner(root, {
        "probe-0.test.ts": { linux: 100, darwin: 100, win32: 100 },
        "probe-1.test.ts": { linux: 80, darwin: 80, win32: 80 },
        "deleted.test.ts": { linux: 1_000, darwin: 1_000, win32: 1_000 },
      });
      const files = [
        ...Array.from({ length: 20 }, (_, index) => `probe-${index}.test.ts`),
        "newly-added.test.ts",
      ];
      const executionLog = join(root, "executed.txt");
      for (const file of files) {
        await writeFile(
          join(root, "tests-ts", file),
          `import { appendFileSync } from "node:fs";
import { test } from "bun:test";
test(${JSON.stringify(file)}, () => {
  appendFileSync(${JSON.stringify(executionLog)}, ${JSON.stringify(`${file}\n`)});
});\n`,
        );
      }
      await writeFile(
        join(root, "tests-ts", "windows-machine-policy.test.ts"),
        'throw new Error("Machine policy test must run separately");\n',
      );
      const executed: string[] = [];
      for (let shard = 1; shard <= count; shard++) {
        await writeFile(executionLog, "");
        const child = Bun.spawn({
          cmd: [
            node!,
            "--experimental-strip-types",
            join(root, "scripts", "run-ci-tests.mts"),
            `${shard}/${count}`,
          ],
          env: {
            ...process.env,
            PATH: `${dirname(process.execPath)}${delimiter}${process.env["PATH"] ?? ""}`,
          },
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
          timeout: 30_000,
          windowsHide: true,
        });
        const { status, stdout, stderr } = await readSubprocess(child);
        expect(status, stderr).toBe(0);
        const shardFiles = (await readFile(executionLog, "utf8"))
          .trim()
          .split("\n");
        expect(stdout).toContain(
          `Test shard ${shard}/${count}: ${shardFiles.sort().join(" ")}`,
        );
        executed.push(...shardFiles);
      }
      expect(executed.sort()).toEqual(files.sort());
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("rejects an empty shard while allowing a nonempty shard with the same count", async () => {
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const fixture = await temporaryDirectory("codex-security-empty-shard-");
  const root = join(fixture, "sdk", "typescript");
  try {
    await mkdir(join(root, "scripts"), { recursive: true });
    await mkdir(join(root, "tests-ts"));
    await copyRunner(root);
    const worker = "deep-scan-worker-shutdown.test.ts";
    await copyFile(
      new URL(worker, import.meta.url),
      join(root, "tests-ts", worker),
    );
    const mcpApp = join(fixture, "plugins", "codex-security", "mcp-app");
    const executor = join(mcpApp, "tests", "test_deep_scan_executor.ts");
    const executed = join(root, "worker-ran");
    await mkdir(dirname(executor), { recursive: true });
    await writeFile(join(mcpApp, "package.json"), '{"type":"module"}\n');
    await writeFile(
      executor,
      `import { writeFileSync } from "node:fs";
import { test } from "node:test";
test("Deep worker lifecycle", () => writeFileSync(${JSON.stringify(executed)}, "ran"));\n`,
    );
    await writeFile(
      join(root, "tests-ts", "windows-machine-policy.test.ts"),
      'throw new Error("Machine policy test must run separately");\n',
    );
    for (const [shard, separateMcp, runsWorker] of [
      [1, false, true],
      [2, false, false],
      [1, true, process.platform !== "linux"],
    ] as const) {
      await rm(executed, { force: true });
      const child = Bun.spawn({
        cmd: [
          node!,
          "--experimental-strip-types",
          join(root, "scripts", "run-ci-tests.mts"),
          `${shard}/2`,
          "-t",
          "Deep worker lifecycle",
        ],
        env: {
          ...process.env,
          CODEX_SECURITY_TEST_MCP_WORKERS_SEPARATE: String(separateMcp),
          PATH: `${dirname(process.execPath)}${delimiter}${process.env["PATH"] ?? ""}`,
        },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        timeout: 30_000,
        windowsHide: true,
      });
      const { status, stdout, stderr } = await readSubprocess(child);
      expect(status, stderr).toBe(shard === 1 ? 0 : 1);
      expect(await Bun.file(executed).exists()).toBe(runsWorker);
      if (shard === 1) {
        expect(stdout).toContain(`Test shard 1/2: ${worker}`);
      } else {
        expect(stderr).toContain(`Test shard ${shard}/2 is empty.`);
      }
    }
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test("propagates a subprocess exit after successful test assertions", async () => {
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const root = await temporaryDirectory("codex-security-shard-exit-");
  const completed = join(root, "assertion-completed");
  try {
    await mkdir(join(root, "scripts"));
    await mkdir(join(root, "tests-ts"));
    await copyRunner(root);
    await writeFile(
      join(root, "tests-ts", "probe.test.ts"),
      `import { writeFileSync } from "node:fs";
import { afterAll, expect, test } from "bun:test";
test("completed shard assertion", () => {
  expect(1).toBe(1);
  writeFileSync(${JSON.stringify(completed)}, "completed");
});
afterAll(() => { process.exit(7); });
`,
    );
    const child = Bun.spawn({
      cmd: [
        node!,
        "--experimental-strip-types",
        join(root, "scripts", "run-ci-tests.mts"),
        "1/1",
      ],
      env: {
        ...process.env,
        PATH: `${dirname(process.execPath)}${delimiter}${process.env["PATH"] ?? ""}`,
      },
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      timeout: 30_000,
      windowsHide: true,
    });
    const { status, stderr } = await readSubprocess(child);
    expect(await readFile(completed, "utf8")).toBe("completed");
    expect(status, stderr).toBe(7);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

const defaultTimeoutMs = process.platform === "win32" ? "120000" : "30000";

test.each([
  [defaultTimeoutMs, [], "available", false],
  [defaultTimeoutMs, [], "available", true],
  [defaultTimeoutMs, [], "blocked directory", false],
  [defaultTimeoutMs, [], "blocked directory", true],
  ["5000", ["--timeout", "5000"], "available", false],
  ["5000", ["--timeout=5000"], "available", false],
  ["5000", ["--timeout", "9000", "--timeout=5000"], "available", false],
  ["5000", ["--timeout=9000", "--timeout", "5000"], "available", false],
  [defaultTimeoutMs, ["--", "--timeout", "5000"], "available", false],
  [defaultTimeoutMs, ["-t", "--timeout=5000"], "available", false],
  [defaultTimeoutMs, ["--grep", "--timeout=5000"], "available", false],
  [
    defaultTimeoutMs,
    ["--test-name-pattern", "--timeout=5000"],
    "available",
    false,
  ],
  ["7000", ["--timeout", "7000", "-t", "--timeout=5000"], "available", false],
  [defaultTimeoutMs, ["--coverage-dir", "--timeout=5000"], "available", false],
  [defaultTimeoutMs, ["--title", "--timeout=5000"], "available", false],
  ["7000", ["--config", "--timeout=7000"], "available", false],
  ["7000", ["-c", "--timeout=7000"], "available", false],
  ["7000", ["--bail", "--timeout=7000"], "available", false],
] as const)(
  "uses timeout %s with %p, %s reports and failure=%p",
  async (timeout, options, report, fail) => {
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const root = await mkdtemp(join(tmpdir(), "codex-security-shard-report-"));
    try {
      await mkdir(join(root, "scripts"));
      await mkdir(join(root, "tests-ts"));
      await copyRunner(root);
      await writeFile(
        join(root, "tests-ts", "probe.test.ts"),
        `import { expect, test } from "bun:test";
test("synthetic report probe --timeout=5000", () => {
  expect(process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"]).toBe(${JSON.stringify(timeout)});
  expect(true).toBe(${!fail});
});\n`,
      );
      if (report === "blocked directory") {
        await writeFile(join(root, "reports"), "synthetic blocker");
      }
      const child = Bun.spawn({
        cmd: [
          node!,
          "--experimental-strip-types",
          join(root, "scripts", "run-ci-tests.mts"),
          "1/1",
          ...options,
        ],
        env: {
          ...process.env,
          CODEX_SECURITY_TEST_TIMEOUT_MS: "1",
          PATH: `${dirname(process.execPath)}${delimiter}${process.env["PATH"] ?? ""}`,
        },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        timeout: 30_000,
      });
      const { status, stdout, stderr } = await readSubprocess(child);
      expect(status, stderr).toBe(fail ? 1 : 0);
      expect(stdout).toContain("Test shard 1/1: probe.test.ts");
      expect(stderr).toContain("synthetic report probe");
      if (report === "available") {
        const xml = await readFile(
          join(root, "reports", "junit-1.xml"),
          "utf8",
        );
        expect(xml).toContain("<testcase ");
        expect(xml.includes("<failure ")).toBe(fail);
      } else {
        expect(stderr).toContain("JUnitReportFailed");
        expect(await readFile(join(root, "reports"), "utf8")).toBe(
          "synthetic blocker",
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("preserves the configured timeout in isolated test subprocesses", async () => {
  const directory = await temporaryDirectory("codex-security-test-timeout-");
  const fixture = join(directory, "isolated.test.ts");
  const helper = new URL("./support/test-subprocess.ts", import.meta.url).href;
  await writeFile(
    fixture,
    `import { test } from "bun:test";
import { runTestInSubprocess } from ${JSON.stringify(helper)};
test("isolated timeout", async () => {
  if (runTestInSubprocess(import.meta.path, "isolated timeout")) return;
  await Bun.sleep(1_000);
});
`,
  );

  try {
    const child = Bun.spawn({
      cmd: [process.execPath, "test", "--timeout", "30000", fixture],
      env: { ...process.env, CODEX_SECURITY_TEST_TIMEOUT_MS: "100" },
      stdin: "ignore",
      stdout: "ignore",
      stderr: "pipe",
      timeout: 30_000,
      windowsHide: true,
    });
    const { status, stderr } = await readSubprocess(child);
    expect(status, stderr).toBe(1);
    expect(stderr).toContain("this test timed out after 100ms");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
