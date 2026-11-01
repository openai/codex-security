import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { compareTestReports } from "../scripts/test-report-comparison.mts";
import { bashCommand, runCommand } from "./support/shell.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

// Node 22.13 emits this upstream notice when executing TypeScript directly.
const typeStrippingNotice =
  /^(?:\(node:\d+\) ExperimentalWarning: Type Stripping is an experimental feature and might change at any time\n\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)\n)?$/u;

const bash = bashCommand();
const comparator = join(
  import.meta.dirname,
  "..",
  "scripts",
  "compare-test-reports.mts",
);
const directories = createTemporaryDirectories(false);
afterEach(directories.cleanup);

async function fixtures() {
  const root = await directories.create("codex-security-test-reports-");
  return {
    root,
    async report(
      name: string,
      cases: string[],
      failures = 0,
      count = cases.length,
    ) {
      const path = join(root, name);
      await writeFile(
        path,
        `<testsuites tests="${count}" failures="${failures}" time="1.25"><testsuite>${cases.join("")}</testsuite></testsuites>`,
      );
      return path;
    },
  };
}

async function workflowFixtures() {
  const fixture = await fixtures();
  const workflow = Bun.YAML.parse(
    await readFile(
      new URL("../../../.github/workflows/test-quality.yml", import.meta.url),
      "utf8",
    ),
  ) as {
    jobs: {
      runner: {
        strategy: {
          matrix: {
            target: Array<{
              os: string;
              shard: number;
              count: number;
              mode: string;
            }>;
          };
        };
      };
      compare: { steps: Array<{ name?: string; run?: string }> };
    };
  };
  await mkdir(join(fixture.root, "reports"));
  const { target } = workflow.jobs.runner.strategy.matrix;
  await Promise.all(
    target.map(({ os, shard, count, mode }) => {
      const totalCases = Math.max(
        ...target.filter((item) => item.os === os).map((item) => item.count),
      );
      const casesPerShard = totalCases / count;
      return fixture.report(
        `reports/runner-${os}-${mode}-${shard}.xml`,
        Array.from({ length: casesPerShard }, (_, index) =>
          testcase(`${os} case ${(shard - 1) * casesPerShard + index + 1}`),
        ),
      );
    }),
  );
  return {
    ...fixture,
    script: workflow.jobs.compare.steps.find(
      (step) => step.name === "Compare inventories and outcomes",
    )!.run!,
  };
}

function testcase(name: string, status = "", assertions?: string) {
  const assertionAttribute =
    assertions === undefined ? "" : ` assertions="${assertions}"`;
  return `<testcase file="tests-ts/example.test.ts" classname="example" name="${name}"${assertionAttribute}>${status}</testcase>`;
}

function compare(...paths: string[]) {
  let stdout = "",
    stderr = "";
  const status = compareTestReports(paths, {
    log: (line) => {
      stdout += line + "\n";
    },
    error: (line) => {
      stderr += line + "\n";
    },
  });
  return { status, stdout, stderr };
}

function compareCli(...paths: string[]) {
  return runCommand("node", [
    "--experimental-strip-types",
    comparator,
    ...paths,
  ]);
}

async function runWorkflow(
  fixture: Awaited<ReturnType<typeof workflowFixtures>>,
  node: string,
  env?: NodeJS.ProcessEnv,
) {
  const summary = join(fixture.root, "summary.md");
  await writeFile(summary, "");
  const result = await runCommand(
    bash,
    ["-e", "-o", "pipefail", "-c", node + "\n" + fixture.script],
    {
      cwd: fixture.root,
      env: { ...process.env, GITHUB_STEP_SUMMARY: "summary.md", ...env },
    },
  );
  return { ...result, summary: await readFile(summary, "utf8") };
}

describe("JUnit inventory comparison", () => {
  test("runs every workflow comparison before reporting a mismatch", async () => {
    const fixture = await workflowFixtures();
    const expected = ["ubuntu-latest", "macos-latest", "windows-latest"].map(
      (os) =>
        `reports/runner-${os}-baseline-*.xml|reports/runner-${os}-expanded-*.xml`,
    );
    const mock = `node() {
  printf '%s\\n' "$3|$4"
  [[ "$3|$4" != "$CODEX_SECURITY_TEST_FAIL_REPORT" ]]
}`;
    for (const failedReport of ["", expected[0]!]) {
      const { status, stderr, summary } = await runWorkflow(fixture, mock, {
        CODEX_SECURITY_TEST_FAIL_REPORT: failedReport,
      });
      expect(status, stderr).toBe(failedReport === "" ? 0 : 1);
      expect(summary.trim().split(/\r?\n/u)).toEqual(expected);
    }
  });

  test("requires complete workflow reports even when incomplete unions match", async () => {
    const fixture = await workflowFixtures();
    for (const incomplete of [false, true]) {
      if (incomplete) {
        // Both unions lose the same two cases, so only completeness catches this.
        for (const name of ["baseline-3", "expanded-5", "expanded-6"]) {
          await rm(
            join(fixture.root, `reports/runner-ubuntu-latest-${name}.xml`),
          );
        }
      }
      const { status, stderr, summary } = await runWorkflow(
        fixture,
        'node() { command node --experimental-strip-types "$CODEX_SECURITY_TEST_COMPARATOR" "$3" "$4"; }',
        { CODEX_SECURITY_TEST_COMPARATOR: comparator },
      );
      expect(status, stderr).toBe(incomplete ? 1 : 0);
      expect(
        summary.match(/Identical test inventory and outcomes/gu),
      ).toHaveLength(3);
      expect(summary).toContain("runner-windows-latest-expanded-14.xml");
      if (incomplete) {
        expect(stderr).toContain("Missing shard report:");
      } else {
        expect(summary).toContain("runner-ubuntu-latest-expanded-6.xml");
      }
    }
  });

  for (const [name, os, mode, count, issue] of [
    ["missing baseline Linux shard", "ubuntu-latest", "baseline", 3, "missing"],
    ["missing expanded Linux shard", "ubuntu-latest", "expanded", 6, "missing"],
    [
      "missing baseline Windows shard",
      "windows-latest",
      "baseline",
      7,
      "missing",
    ],
    [
      "missing expanded Windows shard",
      "windows-latest",
      "expanded",
      14,
      "missing",
    ],
    [
      "missing baseline shard replaced by an unexpected index",
      "ubuntu-latest",
      "baseline",
      3,
      "replaced",
    ],
    [
      "missing expanded shard replaced by an unexpected index",
      "ubuntu-latest",
      "expanded",
      6,
      "replaced",
    ],
    ["extra baseline shard", "windows-latest", "baseline", 7, "extra"],
    ["extra expanded shard", "windows-latest", "expanded", 14, "extra"],
  ] as const) {
    test(`rejects incomplete workflow groups: ${name}`, async () => {
      const fixture = await workflowFixtures();
      const prefix = `reports/runner-${os}-${mode}-`;
      if (issue !== "extra")
        await rm(join(fixture.root, `${prefix}${count}.xml`));
      if (issue !== "missing")
        await fixture.report(`${prefix}${count + 1}.xml`, [
          testcase("unexpected shard"),
        ]);
      const { status, stderr, summary } = await runWorkflow(
        fixture,
        `node() { printf '%s\\n' "$3|$4"; }`,
      );
      expect(status, stderr).toBe(1);
      expect(stderr).toContain(
        issue !== "extra"
          ? `Missing shard report: ${prefix}${count}.xml`
          : `Expected ${count} reports for ${os}/${mode}, found ${count + 1}`,
      );
      // Missing artifacts must not prevent the other OS/mode diagnostics.
      expect(summary.trim().split(/\r?\n/u)).toHaveLength(3);
    });
  }

  test("merges native shards without depending on test order", async () => {
    const fixture = await fixtures();
    const passed = testcase("accepts &amp; preserves");
    const skipped = testcase("platform-only", "<skipped/>");
    const baseline = await fixture.report("baseline.xml", [passed, skipped]);
    await fixture.report("shard-1.xml", [skipped]);
    await fixture.report("shard-2.xml", [passed]);
    const result = await compareCli(
      baseline,
      join(fixture.root, "shard-*.xml"),
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toMatch(typeStrippingNotice);
    expect(result.stdout).toBe(
      "| Report | Cases | Skipped | Seconds |\n" +
        "| --- | ---: | ---: | ---: |\n" +
        "| baseline.xml | 2 | 1 | 1.25 |\n" +
        "| shard-1.xml | 1 | 1 | 1.25 |\n" +
        "| shard-2.xml | 1 | 0 | 1.25 |\n" +
        "\nIdentical test inventory and outcomes. Slowest candidate: 1.25s; combined test time: 2.50s.\n\n",
    );
  });

  test("parses XML entities while ignoring comments and CDATA markup", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("a &amp; &quot; &apos; &lt; &gt;"),
    ]);
    const candidate = join(fixture.root, "candidate.xml");
    await writeFile(
      candidate,
      `<?xml version="1.0"?>
<testsuites tests="1" time="1.25"><testsuite>
<!-- <testcase name="comment"><failure/></testcase> -->
<system-out><![CDATA[<testcase name="log"><failure/></testcase>]]></system-out>
${testcase("&#97; &#38; &#x22; &#39; &#60; &#62;")}
</testsuite></testsuites>`,
    );
    const result = compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toMatch(typeStrippingNotice);
  });

  test("normalizes report paths and rejects duplicates across candidate files", async () => {
    const fixture = await fixtures();
    const original = testcase("portable");
    const baseline = await fixture.report("baseline.xml", [original]);
    const candidate = await fixture.report("candidate.xml", [
      original.replace(
        "tests-ts/example.test.ts",
        "./tests-ts\\example.test.ts",
      ),
    ]);
    expect(compare(baseline, candidate).status).toBe(0);
    const result = await compareCli(baseline, candidate, candidate);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Extra (1): tests-ts/example.test.ts > example > portable > passed",
    );
  });

  test("preserves file, character-class, hidden-file, and nonrecursive glob matching", async () => {
    const fixture = await fixtures();
    const cases = [testcase("portable")];
    const baseline = await fixture.report("baseline.xml", cases);
    const directory = join(fixture.root, "reports with spaces");
    await mkdir(directory);
    await fixture.report("reports with spaces/shard-a.xml", cases);
    await fixture.report("reports with spaces/.hidden.xml", [
      testcase("hidden"),
    ]);
    await mkdir(join(directory, "nested"));
    await fixture.report("reports with spaces/nested/shard-b.xml", [
      testcase("nested"),
    ]);
    for (const pattern of [
      "reports with spaces/shard-?.xml",
      "reports with spaces/shard-[ab].xml",
      "reports with spaces/shard-[!b].xml",
      "reports with spaces/*.xml",
      "**/shard-*.xml",
    ]) {
      const result = compare(baseline, join(fixture.root, pattern));
      expect(result.status, `${pattern}: ${result.stderr}`).toBe(0);
    }
    const hidden = await fixture.report("hidden-baseline.xml", [
      testcase("hidden"),
    ]);
    expect(compare(hidden, join(directory, ".*.xml")).status).toBe(0);
    for (const name of ["{a,b}.xml", "!report.xml", "@(shard).xml"]) {
      const path = await fixture.report(name, cases);
      expect(compare(baseline, path).status, name).toBe(0);
    }
  });

  test("detects error status and nested summary failures with failure overriding skipped", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("example"),
    ]);
    for (const status of ["<error/><skipped/>", "<skipped/><error/>"]) {
      const candidate = await fixture.report("error.xml", [
        testcase("example", status),
      ]);
      const result = compare(baseline, candidate);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("test run failed");
      expect(result.stderr).toContain("example > example > failed");
      expect(result.stderr).not.toContain("example > example > skipped");
    }
    const nested = join(fixture.root, "nested.xml");
    await writeFile(
      nested,
      `<testsuites tests="1"><testsuite><testsuite errors="1">${testcase("example")}</testsuite></testsuite></testsuites>`,
    );
    const result = compare(baseline, nested);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("test run failed");
  });

  test("rejects malformed XML and invalid report numbers", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("example"),
    ]);
    for (const xml of [
      "<testsuite><testcase></testsuite>",
      "<testsuite><testcase/>",
      '<testsuite><testcase name="a" name="b"/></testsuite>',
      '<testsuite><testcase name="&missing;"/></testsuite>',
      "<testsuite><testcase/></testsuite><extra/>",
      '<testsuite tests="1.0"><testcase/></testsuite>',
      '<testsuite failures="invalid"><testcase/></testsuite>',
      '<testsuite time="1oops"><testcase/></testsuite>',
    ]) {
      const candidate = join(fixture.root, "invalid.xml");
      await writeFile(candidate, xml);
      const result =
        xml === "<testsuite><testcase/></testsuite><extra/>"
          ? await compareCli(baseline, candidate)
          : compare(baseline, candidate);
      expect(result.status, xml).toBe(1);
      expect(result.stdout).not.toContain("Identical test inventory");
    }
  });

  test("uses count and timing defaults and only direct unqualified status children", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("example"),
    ]);
    const candidate = join(fixture.root, "defaults.xml");
    await writeFile(
      candidate,
      `<testsuite xmlns:other="urn:example">${testcase("example", "<properties><failure/></properties><other:error/>")}</testsuite>`,
    );
    const result = compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("| defaults.xml | 1 | 0 | 0.00 |");
  });

  test("preserves repeated parameterized identities and their outcome counts", async () => {
    const fixture = await fixtures();
    const passed = testcase("same parameterized name");
    const skipped = testcase("same parameterized name", "<skipped/>");
    const baseline = await fixture.report("baseline.xml", [
      passed,
      passed,
      skipped,
    ]);
    const candidate = await fixture.report("candidate.xml", [
      skipped,
      passed,
      passed,
    ]);
    const result = compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("| baseline.xml | 3 | 1 | 1.25 |");
    for (const [name, cases, diagnostic] of [
      ["missing", [passed, skipped], "Missing (1)"],
      ["extra", [passed, passed, passed, skipped], "Extra (1)"],
      ["changed", [passed, skipped, skipped], "Missing (1)"],
    ] as const) {
      const changed = await fixture.report(`${name}.xml`, [...cases]);
      const comparison = compare(baseline, changed);
      expect(comparison.status, name).toBe(1);
      expect(comparison.stderr).toContain(diagnostic);
    }
  });

  test("compares complete baseline and candidate shard groups", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const repeated = testcase("parameterized name");
    await fixture.report("baseline-1.xml", [first, repeated]);
    await fixture.report("baseline-2.xml", [repeated]);
    await fixture.report("candidate-1.xml", [repeated, repeated]);
    await fixture.report("candidate-2.xml", [first]);
    const baseline = join(fixture.root, "baseline-*.xml");
    const candidate = join(fixture.root, "candidate-*.xml");
    const result = compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(
      "Baseline shards: slowest 1.25s; combined test time: 2.50s.",
    );
    expect(result.stdout).toContain(
      "Slowest candidate: 1.25s; combined test time: 2.50s.",
    );
    const extra = await fixture.report("extra.xml", [repeated]);
    const duplicated = compare(baseline, candidate, extra);
    expect(duplicated.status).toBe(1);
    expect(duplicated.stderr).toContain("Extra (1)");
    const missing = compare(baseline, join(fixture.root, "candidate-1.xml"));
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("Missing (1)");
    expect(compare(join(fixture.root, "absent-*.xml"), candidate).status).toBe(
      1,
    );
  });

  test("preserves assertion counts for repeated identities across different shard layouts", async () => {
    const fixture = await fixtures();
    const repeated = (assertions: string) =>
      testcase("same parameterized name", "", assertions);
    await fixture.report("baseline-1.xml", [repeated("2"), repeated("5")]);
    await fixture.report("baseline-2.xml", [repeated("5")]);
    await fixture.report("candidate-1.xml", [repeated("5")]);
    await fixture.report("candidate-2.xml", [repeated("2")]);
    await fixture.report("candidate-3.xml", [repeated("05")]);
    const baseline = join(fixture.root, "baseline-*.xml");
    const candidate = join(fixture.root, "candidate-*.xml");
    const matching = compare(baseline, candidate);
    expect(matching.status, matching.stderr).toBe(0);

    await fixture.report("candidate-1.xml", [repeated("4")]);
    const changed = compare(baseline, candidate);
    expect(changed.status).toBe(1);
    expect(changed.stderr).toContain(
      "Missing (1): tests-ts/example.test.ts > example > same parameterized name > passed > assertions=5",
    );
    expect(changed.stderr).toContain(
      "Extra (1): tests-ts/example.test.ts > example > same parameterized name > passed > assertions=4",
    );
  });

  test("distinguishes missing assertion counts from reported zero assertions", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("without assertions", "", "0"),
    ]);
    const candidate = await fixture.report("candidate.xml", [
      testcase("without assertions"),
    ]);
    const result = compare(baseline, candidate);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Missing (1): tests-ts/example.test.ts > example > without assertions > passed > assertions=0",
    );
    expect(result.stderr).toContain(
      "Extra (1): tests-ts/example.test.ts > example > without assertions > passed",
    );
  });

  test("reports every shard's timing even when an earlier shard fails", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    const failed = await fixture.report("shard-1.xml", [
      testcase("first", "<failure/>"),
    ]);
    const passed = await fixture.report("shard-2.xml", [second]);
    const result = compare(baseline, failed, passed);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("test run failed");
    expect(result.stdout).toContain("shard-1.xml");
    expect(result.stdout).toContain("shard-2.xml");
  });

  test("rejects dropped, duplicated, skipped, failed, or incomplete results", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    for (const [name, cases, failures, count] of [
      ["missing", [first], 0, 1],
      ["duplicate", [first, second, second], 0, 3],
      ["skipped", [first, testcase("second", "<skipped/>")], 0, 2],
      ["failed", [first, testcase("second", "<failure/>")], 1, 2],
      ["summary-failed", [first, second], 1, 2],
      ["incomplete", [first], 0, 2],
      ["empty", [], 0, 0],
    ] as const) {
      const candidate = await fixture.report(
        `${name}.xml`,
        [...cases],
        failures,
        count,
      );
      expect(compare(baseline, candidate).status, name).toBe(1);
    }
    expect(compare(baseline, join(fixture.root, "absent-*.xml")).status).toBe(
      1,
    );
  });
});
