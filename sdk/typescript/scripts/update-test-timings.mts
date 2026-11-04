import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SaxesParser } from "saxes";
import type { TestTimings } from "./test-shards.mts";

export function updateTestTimings(
  previous: TestTimings,
  platform: "linux" | "darwin" | "win32",
  reports: readonly string[],
): TestTimings {
  const samples = new Map<string, number[]>();
  for (const report of reports) {
    const totals = new Map<string, number>();
    let sawTestcase = false;
    let current: { file: string; seconds: number } | undefined;
    const parser = new SaxesParser({ xmlns: false });
    parser.on("opentag", ({ name, attributes }) => {
      if (
        name === "failure" ||
        name === "error" ||
        Number(attributes["failures"] ?? 0) > 0 ||
        Number(attributes["errors"] ?? 0) > 0
      ) {
        throw new Error(
          "Use successful JUnit reports to refresh test timings.",
        );
      }
      if (name === "skipped") current = undefined;
      if (name !== "testcase") return;
      sawTestcase = true;
      const file = attributes["file"]?.replaceAll("\\", "/").split("/").at(-1);
      const seconds = Number(attributes["time"] ?? 0);
      if (!file || !Number.isFinite(seconds) || seconds < 0) {
        throw new Error(
          "JUnit testcase needs a file and a nonnegative duration.",
        );
      }
      current = { file, seconds };
    });
    parser.on("closetag", ({ name }) => {
      if (name !== "testcase" || !current) return;
      const { file, seconds } = current;
      totals.set(file, (totals.get(file) ?? 0) + seconds);
      current = undefined;
    });
    parser.write(report).close();
    if (!sawTestcase) throw new Error("JUnit report contains no test cases.");
    for (const [file, seconds] of totals) {
      const values = samples.get(file) ?? [];
      values.push(seconds);
      samples.set(file, values);
    }
  }

  const updated = { ...previous };
  for (const [file, values] of samples) {
    values.sort((left, right) => left - right);
    const middle = Math.floor(values.length / 2);
    const median =
      values.length % 2
        ? values[middle]!
        : (values[middle - 1]! + values[middle]!) / 2;
    updated[file] = {
      ...previous[file],
      [platform]: Math.max(0.1, Math.round(median * 10) / 10),
    };
  }
  return Object.fromEntries(
    Object.keys(updated)
      .sort()
      .map((file) => [file, updated[file]!]),
  );
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  const [platform, ...paths] = process.argv.slice(2);
  if (
    !paths.length ||
    (platform !== "linux" && platform !== "darwin" && platform !== "win32")
  ) {
    throw new Error(
      "Usage: node --experimental-strip-types scripts/update-test-timings.mts <linux|darwin|win32> <junit.xml> [...]",
    );
  }
  const target = new URL("./test-timings.json", import.meta.url);
  const previous = JSON.parse(await readFile(target, "utf8")) as TestTimings;
  const reports = await Promise.all(
    paths.map((path) => readFile(path, "utf8")),
  );
  const updated = updateTestTimings(previous, platform, reports);
  await writeFile(target, `${JSON.stringify(updated, null, 2)}\n`);
}
