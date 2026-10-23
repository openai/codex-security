import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { bashCommand, readSubprocess } from "./support/shell.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

// Node 22.13 emits this upstream notice when executing TypeScript directly.
const typeStrippingNotice =
  /^(?:\(node:\d+\) ExperimentalWarning: Type Stripping is an experimental feature and might change at any time\n\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)\n)?$/u;

const bash = bashCommand();
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
            target: Array<{ os: string; shard: number }>;
            mode: Array<{ name: string }>;
          };
        };
      };
      compare: { steps: Array<{ name?: string; run?: string }> };
    };
  };
  await mkdir(join(fixture.root, "reports"));
  const { target, mode } = workflow.jobs.runner.strategy.matrix;
  for (const { os, shard } of target) {
    for (const { name } of mode) {
      await fixture.report(`reports/runner-${os}-${name}-${shard}.xml`, [
        testcase(`${os} shard ${shard}`),
      ]);
    }
  }
  return {
    ...fixture,
    script: workflow.jobs.compare.steps.find(
      (step) => step.name === "Compare inventories and outcomes",
    )!.run!,
  };
}

function testcase(name: string, status = "") {
  return `<testcase file="tests-ts/example.test.ts" classname="example" name="${name}">${status}</testcase>`;
}

async function compare(baseline: string, ...candidates: string[]) {
  const child = Bun.spawn({
    cmd: [
      "node",
      "--experimental-strip-types",
      join(import.meta.dirname, "..", "scripts", "compare-test-reports.mts"),
      baseline,
      ...candidates,
    ],
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  return readSubprocess(child);
}

describe("JUnit inventory comparison", () => {
  test("runs every workflow comparison before reporting a mismatch", async () => {
    const fixture = await workflowFixtures();
    const script = fixture.script;
    const expected = [
      "ubuntu-latest",
      "macos-latest",
      "windows-latest",
    ].flatMap((os) =>
      ["isolated", "parallel"].map(
        (mode) =>
          `reports/runner-${os}-baseline-*.xml|reports/runner-${os}-${mode}-*.xml`,
      ),
    );
    const mock = `node() {
  printf '%s\\n' "$3|$4"
  [[ "$3|$4" != "$CODEX_SECURITY_TEST_FAIL_REPORT" ]]
}`;
    const summary = join(fixture.root, "summary.md");
    for (const failedReport of ["", expected[0]!]) {
      await writeFile(summary, "");
      const child = Bun.spawn({
        cmd: [bash, "-e", "-o", "pipefail", "-c", `${mock}\n${script}`],
        cwd: fixture.root,
        stdin: "ignore",
        stdout: "ignore",
        stderr: "pipe",
        env: {
          ...process.env,
          GITHUB_STEP_SUMMARY: "summary.md",
          CODEX_SECURITY_TEST_FAIL_REPORT: failedReport,
        },
        timeout: 10_000,
      });
      const { status, stderr } = await readSubprocess(child);
      expect(status, stderr).toBe(failedReport === "" ? 0 : 1);
      expect((await readFile(summary, "utf8")).trim().split(/\r?\n/u)).toEqual(
        expected,
      );
    }
  });

  for (const scenario of [
    { name: "missing Linux shard", os: "ubuntu-latest", missing: 3 },
    { name: "missing Windows shard", os: "windows-latest", missing: 7 },
    {
      name: "missing shard replaced by an unexpected index",
      os: "ubuntu-latest",
      missing: 3,
      extra: 4,
    },
    { name: "extra shard", os: "windows-latest", extra: 12 },
  ]) {
    test(`rejects identically incomplete workflow groups: ${scenario.name}`, async () => {
      const fixture = await workflowFixtures();
      for (const mode of ["baseline", "isolated", "parallel"]) {
        if (scenario.missing !== undefined) {
          await rm(
            join(
              fixture.root,
              `reports/runner-${scenario.os}-${mode}-${scenario.missing}.xml`,
            ),
          );
        }
        if (scenario.extra !== undefined) {
          await fixture.report(
            `reports/runner-${scenario.os}-${mode}-${scenario.extra}.xml`,
            [testcase("unexpected shard")],
          );
        }
      }
      const child = Bun.spawn({
        cmd: [
          bash,
          "-e",
          "-o",
          "pipefail",
          "-c",
          `node() { printf '%s\\n' "$3|$4"; }\n${fixture.script}`,
        ],
        cwd: fixture.root,
        stdin: "ignore",
        stdout: "ignore",
        stderr: "pipe",
        env: { ...process.env, GITHUB_STEP_SUMMARY: "summary.md" },
        timeout: 10_000,
      });
      const { status, stderr } = await readSubprocess(child);
      expect(status, stderr).toBe(1);
      if (scenario.missing !== undefined) {
        expect(stderr).toContain(
          `Missing shard report: reports/runner-${scenario.os}-baseline-${scenario.missing}.xml`,
        );
      } else {
        expect(stderr).toContain(
          `Expected 11 reports for ${scenario.os}/baseline, found 12`,
        );
      }
      // Missing artifacts must not prevent the other OS/mode diagnostics.
      expect(
        (await readFile(join(fixture.root, "summary.md"), "utf8"))
          .trim()
          .split(/\r?\n/u),
      ).toHaveLength(6);
    });
  }

  test("merges native shards without depending on test order", async () => {
    const fixture = await fixtures();
    const passed = testcase("accepts &amp; preserves");
    const skipped = testcase("platform-only", "<skipped/>");
    const baseline = await fixture.report("baseline.xml", [passed, skipped]);
    await fixture.report("shard-1.xml", [skipped]);
    await fixture.report("shard-2.xml", [passed]);
    const result = await compare(baseline, join(fixture.root, "shard-*.xml"));
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
    const result = await compare(baseline, candidate);
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
    expect((await compare(baseline, candidate)).status).toBe(0);
    const result = await compare(baseline, candidate, candidate);
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
      const result = await compare(baseline, join(fixture.root, pattern));
      expect(result.status, `${pattern}: ${result.stderr}`).toBe(0);
    }
    const hidden = await fixture.report("hidden-baseline.xml", [
      testcase("hidden"),
    ]);
    expect((await compare(hidden, join(directory, ".*.xml"))).status).toBe(0);
    for (const name of ["{a,b}.xml", "!report.xml", "@(shard).xml"]) {
      const path = await fixture.report(name, cases);
      expect((await compare(baseline, path)).status, name).toBe(0);
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
      const result = await compare(baseline, candidate);
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
    const result = await compare(baseline, nested);
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
      const result = await compare(baseline, candidate);
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
    const result = await compare(baseline, candidate);
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
    const result = await compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("| baseline.xml | 3 | 1 | 1.25 |");
    for (const [name, cases, diagnostic] of [
      ["missing", [passed, skipped], "Missing (1)"],
      ["extra", [passed, passed, passed, skipped], "Extra (1)"],
      ["changed", [passed, skipped, skipped], "Missing (1)"],
    ] as const) {
      const changed = await fixture.report(`${name}.xml`, [...cases]);
      const comparison = await compare(baseline, changed);
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
    const result = await compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(
      "Baseline shards: slowest 1.25s; combined test time: 2.50s.",
    );
    expect(result.stdout).toContain(
      "Slowest candidate: 1.25s; combined test time: 2.50s.",
    );
    const extra = await fixture.report("extra.xml", [repeated]);
    const duplicated = await compare(baseline, candidate, extra);
    expect(duplicated.status).toBe(1);
    expect(duplicated.stderr).toContain("Extra (1)");
    const missing = await compare(
      baseline,
      join(fixture.root, "candidate-1.xml"),
    );
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("Missing (1)");
    expect(
      (await compare(join(fixture.root, "absent-*.xml"), candidate)).status,
    ).toBe(1);
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
    const result = await compare(baseline, failed, passed);

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
      expect((await compare(baseline, candidate)).status, name).toBe(1);
    }
    expect(
      (await compare(baseline, join(fixture.root, "absent-*.xml"))).status,
    ).toBe(1);
  });
});
