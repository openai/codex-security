import { readdir, readFile } from "node:fs/promises";
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

test("rejects a duplicate test inventory", () => {
  expect(() => shardTestFiles(["a.test.ts", "a.test.ts"], 2)).toThrow("unique");
});

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
