import {
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
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

test.each([
  ["available", false],
  ["available", true],
  ["blocked directory", false],
  ["blocked directory", true],
] as const)(
  "preserves the test result with %s reports and failure=%p",
  async (report, fail) => {
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
        `import { expect, test } from "bun:test"; test("synthetic report probe", () => expect(true).toBe(${!fail}));\n`,
      );
      if (report === "blocked directory") {
        await writeFile(join(root, "reports"), "synthetic blocker");
      }
      const child = Bun.spawn({
        cmd: [node!, join(root, "scripts", "run-ci-tests.mjs"), "1/1"],
        env: {
          ...process.env,
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
