import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { expect, test } from "bun:test";
import { shardTestFiles } from "../scripts/test-shards.mjs";

test("balances measured work and includes new files without mutating the inventory", () => {
  const files = [
    "new.test.ts",
    "small.test.ts",
    "medium.test.ts",
    "slow.test.ts",
  ];
  const shards = shardTestFiles(files, 2, {
    "slow.test.ts": 100,
    "medium.test.ts": 70,
    "small.test.ts": 30,
  });
  expect(shards.map(({ seconds }) => seconds)).toEqual([101, 100]);
  expect(shards.flatMap(({ files }) => files).sort()).toEqual(
    [...files].sort(),
  );
  expect(files[0]).toBe("new.test.ts");
  expect(
    shardTestFiles([...files].reverse(), 2, {
      "slow.test.ts": 100,
      "medium.test.ts": 70,
      "small.test.ts": 30,
    }),
  ).toEqual(shards);
});

test.each([0, -1, 1.5, Number.NaN])(
  "rejects an invalid shard count %p",
  (count) => {
    expect(() => shardTestFiles(["a.test.ts"], count)).toThrow(
      "positive integer",
    );
  },
);

test.each([
  ["unix", 3],
  ["windows", 7],
] as const)("covers every shared test once on %s", async (platform, count) => {
  const tests = (await readdir(new URL("./", import.meta.url)))
    .filter(
      (file) =>
        file.endsWith(".test.ts") && file !== "windows-machine-policy.test.ts",
    )
    .sort();
  const timings = JSON.parse(
    await readFile(
      new URL("../scripts/ci-test-durations.json", import.meta.url),
      "utf8",
    ),
  );
  const shards = shardTestFiles(tests, count, timings[platform]);
  expect(shards.every(({ files }) => files.length > 0)).toBe(true);
  expect(shards.flatMap(({ files }) => files).sort()).toEqual(tests);
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
      for (const file of [
        "run-ci-tests.mjs",
        "test-shards.mjs",
        "ci-test-durations.json",
      ]) {
        await copyFile(
          new URL(`../scripts/${file}`, import.meta.url),
          join(root, "scripts", file),
        );
      }
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
          join(root, "scripts", "run-ci-tests.mjs"),
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
      const [status, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      expect(status, stderr).toBe(fail ? 1 : 0);
      expect(stdout).toContain("probe.test.ts");
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
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-test-timeout-")),
  );
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
    const result = spawnSync(
      process.execPath,
      ["test", "--timeout", "30000", fixture],
      {
        encoding: "utf8",
        env: { ...process.env, CODEX_SECURITY_TEST_TIMEOUT_MS: "100" },
        timeout: 30_000,
        windowsHide: true,
      },
    );
    expect(result.status, result.stderr || result.error?.message).toBe(1);
    expect(result.stderr).toContain("this test timed out after 100ms");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
