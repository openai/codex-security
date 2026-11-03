// Compare Bun JUnit inventories before changing the required CI runner.
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { parseArgs } from "node:util";
import { SaxesParser, type SaxesTagNS } from "saxes";

type Output = Pick<Console, "log" | "error">;
type TestStatus = "passed" | "skipped" | "failed";
type TestIdentity = [file: string, classname: string, name: string];
type TestOutcome = [
  ...TestIdentity,
  status: TestStatus,
  assertions: string | null,
];
type TestRecord = {
  attributes: SaxesTagNS["attributes"];
  status: TestStatus;
};

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

function readReport(path: string, output: Output) {
  const parser = new SaxesParser({ xmlns: true, fileName: path });
  let root: SaxesTagNS | undefined;
  const stack: Array<TestRecord | undefined> = [];
  const records: TestRecord[] = [];
  const suites: SaxesTagNS[] = [];
  parser.on("opentag", (node) => {
    root ??= node;
    const name = node.uri ? `{${node.uri}}${node.local}` : node.local;
    const parent = stack.at(-1);
    if (parent) {
      if (name === "failure" || name === "error") parent.status = "failed";
      else if (name === "skipped" && parent.status === "passed")
        parent.status = "skipped";
    }
    let record: TestRecord | undefined;
    if (name === "testcase") {
      record = { attributes: node.attributes, status: "passed" };
      records.push(record);
    }
    if (name === "testsuite" || name === "testsuites") suites.push(node);
    stack.push(record);
  });
  parser.on("closetag", () => stack.pop());
  const content = new TextDecoder("utf-8", { fatal: true }).decode(
    readFileSync(path),
  );
  parser.write(content).close();

  const cases = new Map<string, number>();
  for (const { attributes, status } of records) {
    const identity: TestIdentity = [
      (attributes["file"]?.value ?? "")
        .replaceAll("\\", "/")
        .replace(/^\.\//u, ""),
      attributes["classname"]?.value ?? "",
      attributes["name"]?.value ?? "",
    ];
    const reportedAssertions = attributes["assertions"]?.value;
    const assertions =
      reportedAssertions === undefined
        ? null
        : integer(reportedAssertions).toString();
    const key = JSON.stringify([...identity, status, assertions]);
    cases.set(key, (cases.get(key) ?? 0) + 1);
  }
  if (!cases.size) throw new Error(`${path}: no test cases`);
  if (
    integer(root!.attributes["tests"]?.value ?? String(records.length)) !==
    BigInt(records.length)
  ) {
    throw new Error(`${path}: reported test count does not match test cases`);
  }
  const failed =
    records.some(({ status }) => status === "failed") ||
    suites.some((node) =>
      ["failures", "errors"].some(
        (field) => integer(node.attributes[field]?.value ?? "0") !== 0n,
      ),
    );
  if (failed) output.error(`${path}: test run failed`);
  const duration = seconds(root!.attributes["time"]?.value ?? "0");
  const skipped = records.filter(({ status }) => status === "skipped").length;
  output.log(
    `| ${basename(path)} | ${records.length} | ${skipped} | ${duration.toFixed(2)} |`,
  );
  return {
    cases,
    duration,
    failed,
  };
}

function readReports(paths: string[], group: string, output: Output) {
  if (!paths.length) throw new Error(`No ${group} reports supplied`);
  const cases = new Map<string, number>();
  const durations: number[] = [];
  let failed = false;
  for (const path of paths) {
    const report = readReport(path, output);
    failed ||= report.failed;
    for (const [identity, count] of report.cases)
      cases.set(identity, (cases.get(identity) ?? 0) + count);
    durations.push(report.duration);
  }
  return { cases, durations, failed };
}

function compareGroups(
  baselinePaths: string[],
  candidatePaths: string[],
  output: Output,
): number {
  output.log("| Report | Cases | Skipped | Seconds |");
  output.log("| --- | ---: | ---: | ---: |");
  const baseline = readReports(baselinePaths, "baseline", output);
  const candidate = readReports(candidatePaths, "candidate", output);
  let failed = baseline.failed || candidate.failed;
  for (const [label, left, right] of [
    ["Missing", baseline.cases, candidate.cases],
    ["Extra", candidate.cases, baseline.cases],
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
            Buffer.from(a[index] ?? ""),
            Buffer.from(b[index] ?? ""),
          );
          if (order) return order;
        }
        return 0;
      });
    for (const [identity, count] of differences) {
      failed = true;
      const [file, classname, name, status, assertions] = identity;
      const description = [file, classname, name, status];
      if (assertions !== null) description.push(`assertions=${assertions}`);
      output.error(`${label} (${count}): ${description.join(" > ")}`);
    }
  }
  if (failed) return 1;
  if (baseline.durations.length > 1) {
    output.log(
      `\nBaseline shards: slowest ${Math.max(...baseline.durations).toFixed(2)}s; combined test time: ${baseline.durations.reduce((sum, duration) => sum + duration, 0).toFixed(2)}s.`,
    );
  }
  output.log(
    `\nIdentical test inventory and outcomes. Slowest candidate: ${Math.max(...candidate.durations).toFixed(2)}s; combined test time: ${candidate.durations.reduce((sum, duration) => sum + duration, 0).toFixed(2)}s.\n`,
  );
  return 0;
}

export function compareTestReports(
  argv: string[],
  output: Output = console,
): number {
  const separator = argv.indexOf("--");
  let args: { values: { help?: boolean }; positionals: string[] };
  try {
    args = parseArgs({
      args: separator === -1 ? argv : argv.slice(0, separator),
      options: { help: { type: "boolean", short: "h" } },
      allowPositionals: true,
    });
  } catch (error) {
    output.error((error as Error).message);
    return 2;
  }
  if (args.values.help) {
    output.log(
      "Compare Bun JUnit inventories before changing the required CI runner.\n\nUsage: node --experimental-strip-types compare-test-reports.mts baseline candidate [candidate ...]\n   or: node --experimental-strip-types compare-test-reports.mts baseline [baseline ...] -- candidate [candidate ...]\nPass JUnit filenames. Your shell can expand wildcard patterns.",
    );
    return 0;
  }
  if (separator === -1 && args.positionals.length < 2) {
    output.error("a baseline and at least one candidate report are required");
    return 2;
  }
  const baselinePaths =
    separator === -1 ? args.positionals.slice(0, 1) : args.positionals;
  const candidatePaths =
    separator === -1 ? args.positionals.slice(1) : argv.slice(separator + 1);
  try {
    return compareGroups(baselinePaths, candidatePaths, output);
  } catch (error) {
    output.error((error as Error).message);
    return 1;
  }
}
