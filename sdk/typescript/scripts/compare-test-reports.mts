// Compare Bun JUnit inventories before changing the required CI runner.
import { lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, join, sep } from "node:path";
import { parseArgs } from "node:util";
import { minimatch } from "minimatch";
import { SaxesParser, type SaxesTagNS } from "saxes";

type TestStatus = "passed" | "skipped" | "failed";
type TestIdentity = [file: string, classname: string, name: string];
type TestOutcome = [...TestIdentity, status: TestStatus];
type TestRecord = {
  attributes: SaxesTagNS["attributes"];
  status: TestStatus;
};
type TestReport = {
  cases: Map<string, number>;
  duration: number;
  failed: boolean;
};

function matchingReports(pattern: string): string[] {
  // Python glob treats ** as one component and does not expand braces/extglobs.
  const directoriesOnly =
    pattern.endsWith(sep) ||
    (process.platform === "win32" && pattern.endsWith("/"));
  if (!/[*?[]/u.test(pattern)) {
    try {
      const stat = directoriesOnly ? statSync(pattern) : lstatSync(pattern);
      return !directoriesOnly || stat.isDirectory() ? [pattern] : [];
    } catch {
      return [];
    }
  }
  const parent = dirname(pattern);
  const namePattern = basename(pattern);
  const directories = /[*?[]/u.test(parent)
    ? matchingReports(parent)
    : [parent];
  return directories.flatMap((directory) => {
    let names: string[];
    try {
      names = readdirSync(directory);
    } catch {
      return [];
    }
    return names
      .filter(
        (name) =>
          (!name.startsWith(".") || namePattern.startsWith(".")) &&
          minimatch(
            name,
            namePattern.replaceAll("\\", "\\\\").replaceAll("[^", "[\\^"),
            {
              dot: true,
              nobrace: true,
              noext: true,
              noglobstar: true,
              nonegate: true,
              nocomment: true,
              nocase: process.platform === "win32",
            },
          ),
      )
      .map((name) => join(directory, name))
      .filter((path) => {
        if (!directoriesOnly) return true;
        try {
          return statSync(path).isDirectory();
        } catch {
          return false;
        }
      });
  });
}

function integer(value: string): bigint {
  if (!/^[+-]?\d(?:_?\d)*$/u.test(value.trim())) {
    throw new Error(`invalid integer: ${value}`);
  }
  return BigInt(value.replaceAll("_", "").trim());
}

function seconds(value: string): number {
  const number = value.trim().replaceAll(/(?<=\d)_(?=\d)/gu, "");
  if (
    !/^[+-]?(?:(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?|inf(?:inity)?|nan)$/iu.test(
      number,
    )
  ) {
    throw new Error(`invalid duration: ${value}`);
  }
  return Number(number.replace(/inf(?:inity)?/iu, "Infinity"));
}

function readReport(path: string): TestReport {
  const parser = new SaxesParser({ xmlns: true, fileName: path });
  let root: SaxesTagNS | undefined;
  const stack: Array<{ record: TestRecord | undefined }> = [];
  const records: TestRecord[] = [];
  const suites: SaxesTagNS[] = [];
  parser.on("opentag", (node) => {
    root ??= node;
    const name = node.uri ? `{${node.uri}}${node.local}` : node.local;
    const parent = stack.at(-1);
    if (parent?.record) {
      if (name === "failure" || name === "error")
        parent.record.status = "failed";
      else if (name === "skipped" && parent.record.status === "passed")
        parent.record.status = "skipped";
    }
    let record: TestRecord | undefined;
    if (name === "testcase") {
      record = { attributes: node.attributes, status: "passed" };
      records.push(record);
    }
    if (name === "testsuite" || name === "testsuites") suites.push(node);
    stack.push({ record });
  });
  parser.on("closetag", () => stack.pop());
  const content = new TextDecoder("utf-8", { fatal: true }).decode(
    readFileSync(path),
  );
  parser.write(content).close();

  const cases = new Map<string, TestStatus>();
  for (const { attributes, status } of records) {
    const identity: TestIdentity = [
      (attributes["file"]?.value ?? "")
        .replaceAll("\\", "/")
        .replace(/^\.\//u, ""),
      attributes["classname"]?.value ?? "",
      attributes["name"]?.value ?? "",
    ];
    const key = JSON.stringify(identity);
    if (cases.has(key))
      throw new Error(
        `${path}: duplicate test identity: ${identity.join(" > ")}`,
      );
    cases.set(key, status);
  }
  if (!cases.size) throw new Error(`${path}: no test cases`);
  if (
    integer(root!.attributes["tests"]?.value ?? String(cases.size)) !==
    BigInt(cases.size)
  ) {
    throw new Error(`${path}: reported test count does not match test cases`);
  }
  const failed =
    [...cases.values()].includes("failed") ||
    suites.some((node) =>
      ["failures", "errors"].some(
        (field) => integer(node.attributes[field]?.value ?? "0") !== 0n,
      ),
    );
  if (failed) console.error(`${path}: test run failed`);
  const duration = seconds(root!.attributes["time"]?.value ?? "0");
  const skipped = [...cases.values()].filter(
    (status) => status === "skipped",
  ).length;
  console.log(
    `| ${basename(path)} | ${cases.size} | ${skipped} | ${duration.toFixed(2)} |`,
  );
  return {
    cases: new Map(
      [...cases].map(([identity, status]) => [
        JSON.stringify([...(JSON.parse(identity) as TestIdentity), status]),
        1,
      ]),
    ),
    duration,
    failed,
  };
}

function main(): number {
  let args: { values: { help?: boolean }; positionals: string[] };
  try {
    args = parseArgs({
      options: { help: { type: "boolean", short: "h" } },
      allowPositionals: true,
    });
    if (!args.values.help && args.positionals.length < 2)
      throw new Error(
        "a baseline and at least one candidate report are required",
      );
  } catch (error) {
    console.error((error as Error).message);
    return 2;
  }
  if (args.values.help) {
    console.log(
      "Compare Bun JUnit inventories before changing the required CI runner.\n\nUsage: node compare-test-reports.mjs baseline candidates [candidates ...]\nCandidates are JUnit files or glob patterns.",
    );
    return 0;
  }
  console.log("| Report | Cases | Skipped | Seconds |");
  console.log("| --- | ---: | ---: | ---: |");
  const baseline = readReport(args.positionals[0]!);
  let failed = baseline.failed;
  const candidates = new Map<string, number>();
  const durations: number[] = [];
  for (const pattern of args.positionals.slice(1)) {
    const paths = matchingReports(pattern).sort((a, b) =>
      Buffer.compare(Buffer.from(a), Buffer.from(b)),
    );
    if (!paths.length) throw new Error(`No reports match ${pattern}`);
    for (const path of paths) {
      const report = readReport(path);
      failed ||= report.failed;
      for (const [identity, count] of report.cases)
        candidates.set(identity, (candidates.get(identity) ?? 0) + count);
      durations.push(report.duration);
    }
  }
  for (const [label, left, right] of [
    ["Missing", baseline.cases, candidates],
    ["Extra", candidates, baseline.cases],
  ] as const) {
    const differences = [...left]
      .map(([identity, count]): [TestOutcome, number] => [
        JSON.parse(identity) as TestOutcome,
        count - (right.get(identity) ?? 0),
      ])
      .filter(([, count]) => count > 0)
      .sort(([a], [b]) => {
        for (let index = 0; index < a.length; index++) {
          const order = Buffer.compare(
            Buffer.from(a[index]!),
            Buffer.from(b[index]!),
          );
          if (order) return order;
        }
        return 0;
      });
    for (const [identity, count] of differences) {
      failed = true;
      console.error(`${label} (${count}): ${identity.join(" > ")}`);
    }
  }
  if (failed) return 1;
  console.log(
    `\nIdentical test inventory and outcomes. Slowest candidate: ${Math.max(...durations).toFixed(2)}s; combined test time: ${durations.reduce((sum, duration) => sum + duration, 0).toFixed(2)}s.\n`,
  );
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error((error as Error).message);
  process.exitCode = 1;
}
