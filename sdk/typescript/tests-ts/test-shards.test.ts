import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
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

test.each([3, 7])(
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
            "--parallel=2",
            "--parallel-delay=0",
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
  const root = await temporaryDirectory("codex-security-empty-shard-");
  try {
    await mkdir(join(root, "scripts"));
    await mkdir(join(root, "tests-ts"));
    await copyRunner(root);
    await writeFile(
      join(root, "tests-ts", "probe.test.ts"),
      'import { test } from "bun:test"; test("synthetic shard probe", () => {});\n',
    );
    await writeFile(
      join(root, "tests-ts", "windows-machine-policy.test.ts"),
      'throw new Error("Machine policy test must run separately");\n',
    );
    for (const shard of [1, 2]) {
      const child = Bun.spawn({
        cmd: [
          node!,
          "--experimental-strip-types",
          join(root, "scripts", "run-ci-tests.mts"),
          `${shard}/2`,
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
      expect(status, stderr).toBe(shard === 1 ? 0 : 1);
      if (shard === 1) {
        expect(stdout).toContain("Test shard 1/2: probe.test.ts");
        expect(stderr).toContain("synthetic shard probe");
      } else {
        expect(stderr).toContain("Test shard 2/2 is empty.");
      }
    }
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

test("parallel workers preserve failures, skips, inherited timeouts, and covered lines", async () => {
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const root = await temporaryDirectory("codex-security-parallel-report-");
  try {
    await mkdir(join(root, "scripts"));
    await mkdir(join(root, "tests-ts"));
    await copyRunner(root);
    await writeFile(
      join(root, "shared.ts"),
      `export function first() {
  return "first";
}
export function second() {
  return "second";
}
`,
    );
    for (const [name, body] of [
      ["pass", 'expect(first()).toBe("first");'],
      ["fail", 'expect(second()).toBe("deliberate failure");'],
      ["skip", ""],
    ]) {
      await writeFile(
        join(root, "tests-ts", `${name}.test.ts`),
        `import { expect, test } from "bun:test";
import { readdir, writeFile } from "node:fs/promises";
import { first, second } from "../shared.ts";
test${name === "skip" ? ".skip" : ""}("synthetic ${name}", async () => {
  if (process.env["CODEX_SECURITY_PARALLEL_PROBE"] === "parallel") {
    const worker = process.env["BUN_TEST_WORKER_ID"];
    expect(worker).toBeDefined();
    const workers = ${JSON.stringify(join(root, "workers"))};
    await writeFile(workers + "/" + worker, "");
    while ((await readdir(workers)).length < 2) {
      await new Promise(setImmediate);
    }
  }
  expect(process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"]).toBe("5000");
  ${body}
});
`,
      );
    }
    const workers = join(root, "workers");
    await mkdir(workers);
    const covered = new Map<string, string[]>();
    for (const mode of ["baseline", "parallel"]) {
      const child = Bun.spawn({
        cmd: [
          node!,
          "--experimental-strip-types",
          join(root, "scripts", "run-ci-tests.mts"),
          "1/1",
          ...(mode === "parallel"
            ? ["--parallel=2", "--parallel-delay=0"]
            : []),
          "--timeout=5000",
          "--coverage",
          "--coverage-reporter=lcov",
          `--coverage-dir=reports/${mode}`,
          `--reporter-outfile=reports/${mode}.xml`,
        ],
        env: {
          ...process.env,
          CODEX_SECURITY_PARALLEL_PROBE: mode,
          PATH: `${dirname(process.execPath)}${delimiter}${process.env["PATH"] ?? ""}`,
        },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        timeout: 30_000,
        windowsHide: true,
      });
      const { status, stderr } = await readSubprocess(child);
      expect(status, stderr).toBe(1);
      const xml = await readFile(join(root, "reports", `${mode}.xml`), "utf8");
      expect(xml.match(/<testcase /gu)).toHaveLength(3);
      expect(xml.match(/<failure /gu)).toHaveLength(1);
      expect(xml.match(/<skipped/gu)).toHaveLength(1);
      for (const name of ["pass", "fail", "skip"]) {
        expect(xml).toContain(`name="synthetic ${name}"`);
      }
      const lcov = await readFile(
        join(root, "reports", mode, "lcov.info"),
        "utf8",
      );
      const source = lcov
        .split("end_of_record")
        .find((record) =>
          /^SF:.*shared\.ts$/mu.test(record.replaceAll("\r", "")),
        );
      expect(source).toBeDefined();
      covered.set(
        mode,
        [...source!.matchAll(/^DA:(\d+),([1-9]\d*)$/gmu)].map(
          (match) => match[1]!,
        ),
      );
    }
    expect((await readdir(workers)).sort()).toEqual(["1", "2"]);
    expect(covered.get("baseline")).toContain("2");
    expect(covered.get("baseline")).toContain("5");
    expect(covered.get("parallel")).toEqual(covered.get("baseline"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
