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
import { readSubprocess } from "./support/shell.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

test.each([3, 7])(
  "runs each eligible file once across %i native shards, including new files",
  async (count) => {
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const root = await temporaryDirectory("codex-security-native-shards-");
    try {
      await mkdir(join(root, "scripts"));
      await mkdir(join(root, "tests-ts"));
      await copyFile(
        new URL("../scripts/run-ci-tests.mts", import.meta.url),
        join(root, "scripts", "run-ci-tests.mts"),
      );
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
  const root = await temporaryDirectory("codex-security-empty-shard-");
  try {
    await mkdir(join(root, "scripts"));
    await mkdir(join(root, "tests-ts"));
    await copyFile(
      new URL("../scripts/run-ci-tests.mts", import.meta.url),
      join(root, "scripts", "run-ci-tests.mts"),
    );
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
      await copyFile(
        new URL("../scripts/run-ci-tests.mts", import.meta.url),
        join(root, "scripts", "run-ci-tests.mts"),
      );
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
